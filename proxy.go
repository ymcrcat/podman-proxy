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
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxRequestBody      = 10 * 1024 * 1024  // 10 MB
	maxResponseBody     = 128 * 1024 * 1024 // 128 MB
	maxStreamBytes      = 512 * 1024 * 1024 // 512 MB per streaming connection
	clientTimeout       = 60 * time.Second
	dialTimeout         = 5 * time.Second
	maxConcurrentStream = 20 // max simultaneous streaming connections (logs, stats)
)

// Route patterns for container operations.
var (
	containerCreateRe = regexp.MustCompile(`^(/v[\d.]+)?/containers/create$`)
	containerListRe   = regexp.MustCompile(`^(/v[\d.]+)?/containers/json$`)
	containerOpRe     = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)(/([^/]+))?$`)
	pingRe            = regexp.MustCompile(`^(/v[\d.]+)?/_ping$`)
	versionRe         = regexp.MustCompile(`^(/v[\d.]+)?/version$`)
	containerIDRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	containerNameRe   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,253}$`)
)

// allowedActionMethods maps each allowed container action to its permitted HTTP methods.
// Everything not in this map is blocked (exec, update, archive, copy, export, etc.).
var allowedActionMethods = map[string][]string{
	"":        {http.MethodGet, http.MethodDelete}, // inspect (GET) or delete (DELETE)
	"start":   {http.MethodPost},
	"stop":    {http.MethodPost},
	"kill":    {http.MethodPost},
	"wait":    {http.MethodPost},
	"logs":    {http.MethodGet},
	"json":    {http.MethodGet}, // inspect
	"top":     {http.MethodGet},
	"stats":   {http.MethodGet},
	"rename":  {http.MethodPost},
	"resize":  {http.MethodPost},
	"pause":   {http.MethodPost},
	"unpause": {http.MethodPost},
	"remove":  {http.MethodDelete, http.MethodPost},
}

// allowedActionParams defines the query parameters allowed per container action.
// Any parameter not in this map is stripped before forwarding to Podman.
// Actions not listed here have all query params stripped.
var allowedActionParams = map[string]map[string]bool{
	"":        {"force": true, "v": true},                        // inspect (GET, no params used) or delete (DELETE)
	"start":   {},                                               // no params
	"stop":    {"t": true},                                      // timeout (validated below)
	"kill":    {"signal": true},                                 // validated below
	"wait":    {"condition": true},                               // next-exit, not-running, removed, stopped
	"logs":    {"follow": true, "stdout": true, "stderr": true, "since": true, "until": true, "timestamps": true, "tail": true},
	"json":    {},                                               // inspect
	"top":     {},                                               // strip ps_args
	"stats":   {"stream": true},
	"rename":  {"name": true},
	"resize":  {"h": true, "w": true},
	"pause":   {},
	"unpause": {},
	"remove":  {"force": true, "v": true},                       // strip depend
}

// allowedKillSignals is the set of signals allowed for the kill action.
var allowedKillSignals = map[string]bool{
	"SIGTERM": true, "TERM": true, "15": true,
	"SIGKILL": true, "KILL": true, "9": true,
	"SIGINT": true, "INT": true, "2": true,
	"SIGQUIT": true, "QUIT": true, "3": true,
	"SIGHUP": true, "HUP": true, "1": true,
	"SIGUSR1": true, "USR1": true, "10": true,
	"SIGUSR2": true, "USR2": true, "12": true,
}

// allowedResponseHeaders is the set of upstream headers forwarded to clients.
// Everything else is stripped to avoid leaking infrastructure details.
var allowedResponseHeaders = map[string]bool{
	"Content-Type":           true,
	"Content-Length":         true,
	"Docker-Experimental":   true,
	"Api-Version":           true,
	"Ostype":                true,
	"Date":                  true,
	"Transfer-Encoding":     true,
}

// streamingActions are container actions that produce unbounded streaming output.
// These are piped directly to the client instead of being buffered in memory.
// "wait" is included because it blocks until the container exits, which can be
// indefinitely — without the semaphore it would allow goroutine exhaustion DoS.
var streamingActions = map[string]bool{
	"logs":  true,
	"stats": true,
	"wait":  true,
}

// Proxy is the HTTP handler that enforces policy and forwards to podman.
type Proxy struct {
	PodmanSocket string
	Policy       *Policy
	Ownership    *Ownership
	AgentID      string
	transportMu  sync.Once
	transport    *http.Transport
	streamSem    chan struct{} // limits concurrent streaming connections; nil = no limit
}

func (p *Proxy) getTransport() *http.Transport {
	p.transportMu.Do(func() {
		p.transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: dialTimeout}
				return d.DialContext(ctx, "unix", p.PodmanSocket)
			},
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			MaxIdleConnsPerHost: 10,
		}
	})
	return p.transport
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Allow ping and version — harmless read-only info endpoints.
	// Restrict to GET/HEAD and strip query parameters.
	if pingRe.MatchString(path) || versionRe.MatchString(path) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		stripped := *r
		strippedURL := *r.URL
		strippedURL.RawQuery = ""
		stripped.URL = &strippedURL
		stripped.Body = http.NoBody
		stripped.ContentLength = 0
		p.forward(w, &stripped, nil)
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
		versionPrefix := m[1] // e.g. "/v4.0.0" or ""
		containerRef := m[2]
		action := m[4] // empty string if no sub-action

		// Guard: "create" and "json" as container refs are routing artifacts.
		if containerRef == "create" || containerRef == "json" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// Validate containerRef format before use in ownership lookup and logs.
		// Prevents log injection via newlines/escape sequences in URL path.
		if !containerIDRe.MatchString(containerRef) && !containerNameRe.MatchString(containerRef) {
			http.Error(w, "forbidden: invalid container reference", http.StatusForbidden)
			return
		}

		p.handleContainerOp(w, r, versionPrefix, containerRef, action)
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

	// Validate and sanitize query parameters before forwarding.
	// Only the "name" parameter is meaningful for create; strip everything else.
	name := r.URL.Query().Get("name")
	if name != "" && !containerNameRe.MatchString(name) {
		http.Error(w, "forbidden: invalid container name", http.StatusForbidden)
		return
	}
	createReq := *r
	createURL := *r.URL
	q := url.Values{}
	if name != "" {
		q.Set("name", name)
	}
	createURL.RawQuery = q.Encode()
	createReq.URL = &createURL

	// Forward with sanitized body and sanitized query params.
	resp, respBody, err := p.doForward(&createReq, sanitized)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}

	// Track the container on any 2xx response.
	// Name was already validated above before forwarding.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var createResp struct {
			Id string `json:"Id"`
		}
		if json.Unmarshal(respBody, &createResp) == nil && createResp.Id != "" {
			if !containerIDRe.MatchString(createResp.Id) {
				log.Printf("[%s] WARNING: ignoring invalid container ID format from podman: %.24s...", p.AgentID, createResp.Id)
			} else {
				p.Ownership.Add(createResp.Id, name)
				short := createResp.Id[:12]
				log.Printf("[%s] CREATED container %s", p.AgentID, short)
			}
		}
	}

	writeResponse(w, resp, respBody)
}

func (p *Proxy) handleList(w http.ResponseWriter, r *http.Request) {
	// Only pass allowlisted query parameters. Strip filters (tenant-controlled JSON
	// forwarded to Podman's filter parser), size (forces disk usage computation),
	// and any other unknown parameters.
	listReq := *r
	listURL := *r.URL
	q := listURL.Query()
	allowedListParams := map[string]bool{"all": true, "limit": true}
	for k := range q {
		if !allowedListParams[k] {
			q.Del(k)
		}
	}
	// Validate "all" is a proper boolean value.
	if allVal := q.Get("all"); allVal != "" && allVal != "true" && allVal != "1" {
		q.Del("all")
	}
	// Validate limit is a reasonable positive integer to prevent host-wide
	// container enumeration DoS on Podman.
	if limitStr := q.Get("limit"); limitStr != "" {
		n, err := strconv.ParseInt(limitStr, 10, 64)
		if err != nil || n <= 0 || n > 100 {
			q.Del("limit")
		}
	}
	listURL.RawQuery = q.Encode()
	listReq.URL = &listURL

	resp, respBody, err := p.doForward(&listReq, nil)
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
	writeFilteredResponse(w, resp, result, "application/json")
}

func (p *Proxy) handleContainerOp(w http.ResponseWriter, r *http.Request, versionPrefix, containerRef, action string) {
	// Check action and HTTP method against the allowlist.
	allowedMethods, actionAllowed := allowedActionMethods[action]
	if !actionAllowed {
		log.Printf("[%s] BLOCKED action %q on container %s", p.AgentID, action, containerRef)
		http.Error(w, fmt.Sprintf("forbidden: action %q not allowed", action), http.StatusForbidden)
		return
	}
	methodOK := false
	for _, m := range allowedMethods {
		if r.Method == m {
			methodOK = true
			break
		}
	}
	if !methodOK {
		log.Printf("[%s] BLOCKED %s %s on container %s (method not allowed)", p.AgentID, r.Method, action, containerRef)
		http.Error(w, "forbidden: method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Resolve to canonical full ID. This ensures the proxy checks ownership
	// and forwards to podman using the exact same container identity,
	// preventing cross-tenant access via name=ID-prefix injection.
	fullID := p.Ownership.FullID(containerRef)
	if fullID == "" {
		log.Printf("[%s] BLOCKED access to unowned container %s", p.AgentID, containerRef)
		http.Error(w, "forbidden: container not owned by this agent", http.StatusForbidden)
		return
	}

	// Validate rename name before forwarding to prevent Podman/proxy ownership
	// desync if Podman accepts a name the proxy's regex rejects.
	if action == "rename" {
		newName := r.URL.Query().Get("name")
		if !containerNameRe.MatchString(newName) {
			http.Error(w, "forbidden: invalid container name", http.StatusForbidden)
			return
		}
	}

	// Sanitize query parameters: only forward params allowed for this action.
	sanitizedQuery := url.Values{}
	if allowed, ok := allowedActionParams[action]; ok {
		for k, vv := range r.URL.Query() {
			if allowed[k] && len(vv) > 0 {
				sanitizedQuery.Set(k, vv[0]) // only forward first value to match validation
			}
		}
	}
	// Validate specific dangerous params.
	if action == "stop" {
		if tStr := sanitizedQuery.Get("t"); tStr != "" {
			t, err := strconv.ParseInt(tStr, 10, 64)
			if err != nil || t < 0 || t > 300 {
				sanitizedQuery.Del("t")
			}
		}
	}
	if action == "kill" {
		sig := strings.ToUpper(sanitizedQuery.Get("signal"))
		if sig != "" && !allowedKillSignals[sig] {
			sanitizedQuery.Del("signal")
		}
	}
	if action == "resize" {
		for _, dim := range []string{"h", "w"} {
			if v := sanitizedQuery.Get(dim); v != "" {
				n, err := strconv.ParseInt(v, 10, 64)
				if err != nil || n < 1 || n > 65535 {
					sanitizedQuery.Del(dim)
				}
			}
		}
	}
	if action == "wait" {
		if cond := sanitizedQuery.Get("condition"); cond != "" {
			validConditions := map[string]bool{
				"next-exit": true, "not-running": true, "removed": true, "stopped": true,
			}
			if !validConditions[cond] {
				sanitizedQuery.Del("condition")
			}
		}
	}
	if action == "logs" {
		if tail := sanitizedQuery.Get("tail"); tail != "" && tail != "all" {
			n, err := strconv.ParseInt(tail, 10, 64)
			if err != nil || n < 0 || n > 100000 {
				sanitizedQuery.Del("tail")
			}
		}
		// Validate since/until as Unix timestamps in a reasonable range.
		for _, param := range []string{"since", "until"} {
			if v := sanitizedQuery.Get(param); v != "" {
				n, err := strconv.ParseInt(v, 10, 64)
				if err != nil || n < 0 || n > 9999999999 {
					sanitizedQuery.Del(param)
				}
			}
		}
	}

	// Build rewritten path structurally from regex captures — never use
	// string replacement, which can replace the wrong segment if the
	// container name matches part of the version prefix or action.
	newPath := versionPrefix + "/containers/" + url.PathEscape(fullID)
	if action != "" {
		newPath += "/" + action
	}
	rewrittenURL := *r.URL
	rewrittenURL.Path = newPath
	rewrittenURL.RawPath = "" // force use of Path
	rewrittenURL.RawQuery = sanitizedQuery.Encode()
	rewritten := *r
	rewritten.URL = &rewrittenURL

	// Determine if this is a remove operation.
	isRemove := r.Method == http.MethodDelete ||
		(r.Method == http.MethodPost && action == "remove")

	// Streaming endpoints (logs, stats, wait) are piped directly to avoid
	// buffering unbounded output in memory. Discard the request body —
	// these endpoints use query params only, and forwarding bodies could
	// bypass query param validation.
	if streamingActions[action] {
		rewritten.Body = http.NoBody
		rewritten.ContentLength = 0
		p.streamForward(w, &rewritten)
		return
	}

	// Forward with empty body — non-create actions should not have meaningful
	// request bodies, and forwarding them could bypass query param validation
	// (e.g. kill signal in body instead of query param).
	resp, respBody, err := p.doForward(&rewritten, []byte{})
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}

	writeResponse(w, resp, respBody)

	// Only untrack on successful remove (2xx).
	if isRemove && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		p.Ownership.Remove(fullID)
		short := fullID
		if len(short) > 12 {
			short = short[:12]
		}
		log.Printf("[%s] REMOVED container %s", p.AgentID, short)
	}

	// Update ownership table after successful rename.
	// Name was already validated before forwarding.
	if action == "rename" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		newName := r.URL.Query().Get("name")
		p.Ownership.Rename(fullID, newName)
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
		Timeout:   clientTimeout,
		Transport: p.getTransport(),
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

	// Only forward safe headers — X-Registry-Auth is intentionally excluded
	// to prevent tenants from supplying credentials for private registries.
	for _, h := range []string{"Content-Type", "Accept"} {
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

// streamForward pipes the upstream response directly to the client without buffering.
// Used for streaming endpoints (logs, stats) that produce unbounded output.
func (p *Proxy) streamForward(w http.ResponseWriter, r *http.Request) {
	// Limit concurrent streaming connections to prevent goroutine/socket exhaustion.
	if p.streamSem != nil {
		select {
		case p.streamSem <- struct{}{}:
			defer func() { <-p.streamSem }()
		default:
			http.Error(w, "too many streaming connections", http.StatusServiceUnavailable)
			return
		}
	}

	client := &http.Client{
		Transport: p.getTransport(),
	}

	var bodyReader io.Reader
	if r.Body != nil {
		bodyData, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
		r.Body.Close()
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		bodyReader = bytes.NewReader(bodyData)
	}

	// Bound stream duration to prevent one tenant from holding semaphore
	// slots indefinitely by stalling reads.
	streamCtx, streamCancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer streamCancel()

	reqURL := "http://podman" + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(streamCtx, r.Method, reqURL, bodyReader)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}

	for _, h := range []string{"Content-Type", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyFilteredHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	// Flush-aware copy for streaming with per-connection byte limit.
	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	var totalWritten int64
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			totalWritten += int64(n)
			if totalWritten > maxStreamBytes {
				log.Printf("[%s] stream byte limit exceeded (%d bytes), closing", p.AgentID, maxStreamBytes)
				break
			}
			w.Write(buf[:n])
			if canFlush {
				flusher.Flush()
			}
		}
		if readErr != nil {
			break
		}
	}
}

// copyFilteredHeaders writes only allowlisted upstream headers to the response.
func copyFilteredHeaders(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		if !allowedResponseHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Del("Content-Length")
}

// writeResponse copies an upstream response back to the client.
// Only allowlisted headers are forwarded to avoid leaking infrastructure details.
func writeResponse(w http.ResponseWriter, resp *http.Response, body []byte) {
	copyFilteredHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// writeFilteredResponse writes a response with allowlisted headers and an overridden content type.
func writeFilteredResponse(w http.ResponseWriter, resp *http.Response, body []byte, contentType string) {
	copyFilteredHeaders(w, resp)
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
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
		Timeout:   30 * time.Second,
		Transport: p.getTransport(),
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
