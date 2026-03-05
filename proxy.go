package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

const (
	maxRequestBody  = 10 * 1024 * 1024  // 10 MB
	maxResponseBody = 128 * 1024 * 1024 // 128 MB
	clientTimeout   = 60 * time.Second
	dialTimeout     = 5 * time.Second
)

// Route patterns for container operations.
var (
	containerCreateRe = regexp.MustCompile(`^(/v[\d.]+)?/containers/create$`)
	containerListRe   = regexp.MustCompile(`^(/v[\d.]+)?/containers/json$`)
	containerOpRe     = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)(/([^/]+))?$`)
	pingRe            = regexp.MustCompile(`^(/v[\d.]+)?/_ping$`)
	versionRe         = regexp.MustCompile(`^(/v[\d.]+)?/version$`)
)

// allowedContainerActions is the whitelist of per-container sub-operations.
// Everything not in this set is blocked (exec, update, archive, copy, export, etc.).
var allowedContainerActions = map[string]bool{
	"":        true, // inspect (GET) or delete (DELETE) with no action
	"start":   true,
	"stop":    true,
	"kill":    true,
	"wait":    true,
	"logs":    true,
	"json":    true, // inspect
	"top":     true,
	"stats":   true,
	"rename":  true,
	"resize":  true,
	"pause":   true,
	"unpause": true,
	"remove":  true,
}

// Proxy is the HTTP handler that enforces policy and forwards to podman.
type Proxy struct {
	PodmanSocket string
	Policy       *Policy
	Ownership    *Ownership
	AgentID      string
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Always allow ping and version — harmless info endpoints.
	if pingRe.MatchString(path) || versionRe.MatchString(path) {
		p.forward(w, r, nil)
		return
	}

	// Container create.
	if containerCreateRe.MatchString(path) && r.Method == http.MethodPost {
		p.handleCreate(w, r)
		return
	}

	// Container list.
	if containerListRe.MatchString(path) && r.Method == http.MethodGet {
		p.handleList(w, r)
		return
	}

	// Per-container operations.
	if m := containerOpRe.FindStringSubmatch(path); m != nil {
		containerRef := m[2]
		action := m[4] // empty string if no sub-action

		// Guard: "create" and "json" as container refs are routing artifacts.
		if containerRef == "create" || containerRef == "json" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		p.handleContainerOp(w, r, containerRef, action)
		return
	}

	// Everything else is forbidden.
	log.Printf("[%s] BLOCKED %s %s", p.AgentID, r.Method, path)
	http.Error(w, "forbidden: endpoint not allowed", http.StatusForbidden)
}

func (p *Proxy) handleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	sanitized, err := p.Policy.ValidateAndSanitize(body)
	if err != nil {
		log.Printf("[%s] CREATE BLOCKED: %v", p.AgentID, err)
		http.Error(w, fmt.Sprintf("policy violation: %v", err), http.StatusForbidden)
		return
	}

	// Forward with sanitized body.
	resp, respBody, err := p.doForward(r, sanitized)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}

	// Track the container on any 2xx response.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var createResp struct {
			Id string `json:"Id"`
		}
		if json.Unmarshal(respBody, &createResp) == nil && createResp.Id != "" {
			p.Ownership.Add(createResp.Id)
			// Track name if provided in query parameter.
			if name := r.URL.Query().Get("name"); name != "" {
				p.Ownership.SetName(createResp.Id, name)
			}
			short := createResp.Id
			if len(short) > 12 {
				short = short[:12]
			}
			log.Printf("[%s] CREATED container %s", p.AgentID, short)
		}
	}

	writeResponse(w, resp, respBody)
}

func (p *Proxy) handleList(w http.ResponseWriter, r *http.Request) {
	resp, respBody, err := p.doForward(r, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusOK {
		writeResponse(w, resp, respBody)
		return
	}

	// Filter to only owned containers — by ID only, not by name.
	// Name-based matching could leak cross-tenant containers via prefix confusion.
	var containers []json.RawMessage
	if err := json.Unmarshal(respBody, &containers); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]"))
		return
	}

	filtered := make([]json.RawMessage, 0, len(containers))
	for _, c := range containers {
		var info struct {
			Id string `json:"Id"`
		}
		if json.Unmarshal(c, &info) != nil {
			continue
		}
		if p.Ownership.Owns(info.Id) {
			filtered = append(filtered, c)
		}
	}

	result, _ := json.Marshal(filtered)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Del("Content-Length")
	w.WriteHeader(http.StatusOK)
	w.Write(result)
}

func (p *Proxy) handleContainerOp(w http.ResponseWriter, r *http.Request, containerRef, action string) {
	// Check action is in the whitelist.
	if !allowedContainerActions[action] {
		log.Printf("[%s] BLOCKED action %q on container %s", p.AgentID, action, containerRef)
		http.Error(w, fmt.Sprintf("forbidden: action %q not allowed", action), http.StatusForbidden)
		return
	}

	// Check ownership.
	if !p.Ownership.Owns(containerRef) {
		log.Printf("[%s] BLOCKED access to unowned container %s", p.AgentID, containerRef)
		http.Error(w, "forbidden: container not owned by this agent", http.StatusForbidden)
		return
	}

	// Determine if this is a remove operation.
	isRemove := r.Method == http.MethodDelete ||
		(r.Method == http.MethodPost && action == "remove")

	// Forward and capture response to check status before untracking.
	resp, respBody, err := p.doForward(r, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}

	writeResponse(w, resp, respBody)

	// Only untrack on successful remove (2xx).
	if isRemove && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fullID := p.Ownership.FullID(containerRef)
		if fullID != "" {
			p.Ownership.Remove(fullID)
			short := fullID
			if len(short) > 12 {
				short = short[:12]
			}
			log.Printf("[%s] REMOVED container %s", p.AgentID, short)
		}
	}
}

// forward sends the request to the podman socket and writes the response back.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	resp, respBody, err := p.doForward(r, body)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	writeResponse(w, resp, respBody)
}

// doForward performs the actual HTTP request to the podman socket.
func (p *Proxy) doForward(r *http.Request, overrideBody []byte) (*http.Response, []byte, error) {
	client := &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: dialTimeout}
				return d.DialContext(ctx, "unix", p.PodmanSocket)
			},
		},
	}

	var bodyReader io.Reader
	if overrideBody != nil {
		bodyReader = bytes.NewReader(overrideBody)
	} else if r.Body != nil {
		bodyData, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
		r.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("reading request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyData)
	}

	reqURL := "http://podman" + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, reqURL, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("creating forward request: %w", err)
	}

	for _, h := range []string{"Content-Type", "Accept", "X-Registry-Auth"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	if overrideBody != nil {
		req.ContentLength = int64(len(overrideBody))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("forwarding to podman: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, nil, fmt.Errorf("reading podman response: %w", err)
	}

	return resp, respBody, nil
}

// writeResponse copies an upstream response back to the client.
func writeResponse(w http.ResponseWriter, resp *http.Response, body []byte) {
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// CleanupContainers stops and removes all owned containers via the podman socket.
func (p *Proxy) CleanupContainers() {
	ids := p.Ownership.IDs()
	if len(ids) == 0 {
		return
	}
	log.Printf("[%s] Cleaning up %d owned containers...", p.AgentID, len(ids))

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: dialTimeout}
				return d.DialContext(ctx, "unix", p.PodmanSocket)
			},
		},
	}

	for _, id := range ids {
		short := id
		if len(short) > 12 {
			short = short[:12]
		}
		escaped := url.PathEscape(id)

		// Stop (ignore errors — container may already be stopped).
		stopURL := fmt.Sprintf("http://podman/v4.0.0/containers/%s/stop?t=5", escaped)
		req, _ := http.NewRequest(http.MethodPost, stopURL, nil)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}

		// Remove with force and volumes.
		rmURL := fmt.Sprintf("http://podman/v4.0.0/containers/%s?force=true&v=true", escaped)
		req, _ = http.NewRequest(http.MethodDelete, rmURL, nil)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			log.Printf("[%s] Cleaned up container %s", p.AgentID, short)
		} else {
			log.Printf("[%s] Failed to clean up container %s: %v", p.AgentID, short, err)
		}

		p.Ownership.Remove(id)
	}
}
