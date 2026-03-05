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
	"regexp"
	"strings"
)

// route patterns for container operations
var (
	// POST /v{version}/containers/create or /containers/create
	containerCreateRe = regexp.MustCompile(`^(/v[\d.]+)?/containers/create$`)
	// GET /v{version}/containers/json or /containers/json
	containerListRe = regexp.MustCompile(`^(/v[\d.]+)?/containers/json$`)
	// Operations on a specific container: /v{version}/containers/{id}/{action}
	containerOpRe = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)(/(.+))?$`)
	// Version ping
	pingRe = regexp.MustCompile(`^(/v[\d.]+)?/_ping$`)
	// Version endpoint
	versionRe = regexp.MustCompile(`^(/v[\d.]+)?/version$`)
)

// Proxy is the HTTP handler that enforces policy and forwards to podman.
type Proxy struct {
	PodmanSocket string
	Policy       *Policy
	Ownership    *Ownership
	AgentID      string
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Always allow ping and version — they're harmless info endpoints.
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
		// "json" on its own would be caught by the list regex above, so if we get
		// here it's a specific container reference. But guard against "create".
		if containerRef == "create" || containerRef == "json" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		p.handleContainerOp(w, r, containerRef)
		return
	}

	// Everything else is forbidden.
	log.Printf("[%s] BLOCKED %s %s", p.AgentID, r.Method, path)
	http.Error(w, "forbidden: endpoint not allowed", http.StatusForbidden)
}

func (p *Proxy) handleCreate(w http.ResponseWriter, r *http.Request) {
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

	// If podman created it successfully, track the container ID.
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		var createResp struct {
			Id string `json:"Id"`
		}
		if json.Unmarshal(respBody, &createResp) == nil && createResp.Id != "" {
			p.Ownership.Add(createResp.Id)
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

	// Filter to only owned containers.
	var containers []json.RawMessage
	if err := json.Unmarshal(respBody, &containers); err != nil {
		// If we can't parse, return empty list rather than leaking.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]"))
		return
	}

	filtered := make([]json.RawMessage, 0, len(containers))
	for _, c := range containers {
		var info struct {
			Id    string   `json:"Id"`
			Names []string `json:"Names"`
		}
		if json.Unmarshal(c, &info) != nil {
			continue
		}
		if p.Ownership.Owns(info.Id) {
			filtered = append(filtered, c)
			continue
		}
		// Also check by name.
		for _, name := range info.Names {
			// Names may have leading "/".
			clean := strings.TrimPrefix(name, "/")
			if p.Ownership.Owns(clean) {
				filtered = append(filtered, c)
				break
			}
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

func (p *Proxy) handleContainerOp(w http.ResponseWriter, r *http.Request, containerRef string) {
	if !p.Ownership.Owns(containerRef) {
		log.Printf("[%s] BLOCKED access to unowned container %s", p.AgentID, containerRef)
		http.Error(w, "forbidden: container not owned by this agent", http.StatusForbidden)
		return
	}

	// For delete/remove, also untrack.
	path := r.URL.Path
	isRemove := r.Method == http.MethodDelete ||
		(r.Method == http.MethodPost && strings.HasSuffix(path, "/remove"))

	p.forward(w, r, nil)

	if isRemove {
		// Find and remove the full ID that matched this ref.
		for _, id := range p.Ownership.IDs() {
			if id == containerRef || strings.HasPrefix(id, containerRef) {
				p.Ownership.Remove(id)
				log.Printf("[%s] REMOVED container %s", p.AgentID, id[:min(12, len(id))])
				break
			}
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
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", p.PodmanSocket)
			},
		},
	}

	var bodyReader io.Reader
	if overrideBody != nil {
		bodyReader = bytes.NewReader(overrideBody)
	} else if r.Body != nil {
		bodyData, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("reading request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyData)
	}

	// Build the forwarded request — target is http://podman/<path>.
	url := "http://podman" + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, url, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("creating forward request: %w", err)
	}

	// Copy relevant headers.
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

	respBody, err := io.ReadAll(resp.Body)
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
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", p.PodmanSocket)
			},
		},
	}

	for _, id := range ids {
		short := id[:min(12, len(id))]

		// Stop (ignore errors — container may already be stopped).
		stopURL := fmt.Sprintf("http://podman/v4.0.0/containers/%s/stop?t=5", id)
		req, _ := http.NewRequest(http.MethodPost, stopURL, nil)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}

		// Remove with force and volumes.
		rmURL := fmt.Sprintf("http://podman/v4.0.0/containers/%s?force=true&v=true", id)
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

