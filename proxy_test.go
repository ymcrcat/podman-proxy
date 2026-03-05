package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

var sockCounter atomic.Int64

// testSockPath returns a short socket path to avoid unix socket path length limits
// and sandbox restrictions on t.TempDir().
// sockDir can be overridden via SOCK_DIR env var for sandbox environments.
func testSockPath(t *testing.T, suffix string) string {
	t.Helper()
	n := sockCounter.Add(1)
	dir := os.Getenv("SOCK_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "pp-test")
	}
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, fmt.Sprintf("%s%d.sock", suffix, n))
	t.Cleanup(func() { os.Remove(path) })
	return path
}

// mockPodman starts a mock podman API server on a unix socket.
// It returns the socket path and a cleanup function.
func mockPodman(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	sockPath := testSockPath(t, "p")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	return sockPath, func() {
		server.Close()
		listener.Close()
	}
}

// startProxy starts the proxy on a unix socket talking to a mock podman.
func startProxy(t *testing.T, podmanSock string, policy *Policy) (string, func()) {
	t.Helper()
	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       policy,
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	return sockPath, func() {
		server.Close()
		listener.Close()
	}
}

func unixClient(sockPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
	}
}

func defaultPolicy() *Policy {
	return &Policy{
		Workspace: "/workspace",
		MaxMemory: 2 * 1024 * 1024 * 1024,
		MaxCPUs:   2.0,
	}
}

// --- Policy unit tests ---

func TestBlockPrivileged(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Privileged":true}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for privileged container")
	}
	if !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBlockHostNetwork(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"NetworkMode":"host"}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for host network")
	}
}

func TestBlockHostPid(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"PidMode":"host"}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for host PID")
	}
}

func TestBlockBindOutsideWorkspace(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Binds":["/etc/passwd:/mnt/passwd"]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for bind outside workspace")
	}
}

func TestAllowBindInsideWorkspace(t *testing.T) {
	// Use a temp dir as workspace that actually exists.
	ws := t.TempDir()
	p := &Policy{Workspace: ws, MaxMemory: 2e9, MaxCPUs: 2.0}
	body := `{"Image":"alpine","HostConfig":{"Binds":["` + ws + `/data:/data"]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestImageAllowlist(t *testing.T) {
	p := &Policy{
		Workspace:     "/workspace",
		AllowedImages: []string{"alpine", "ubuntu:22.04"},
	}
	// Allowed.
	_, err := p.ValidateAndSanitize([]byte(`{"Image":"alpine"}`))
	if err != nil {
		t.Fatalf("alpine should be allowed: %v", err)
	}
	// Blocked.
	_, err = p.ValidateAndSanitize([]byte(`{"Image":"evil:latest"}`))
	if err == nil {
		t.Fatal("expected error for disallowed image")
	}
}

func TestStripDangerousCaps(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"CapAdd":["NET_BIND_SERVICE","SYS_ADMIN","NET_RAW"]}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed struct {
		HostConfig struct {
			CapAdd []string `json:"CapAdd"`
		} `json:"HostConfig"`
	}
	json.Unmarshal(result, &parsed)
	if len(parsed.HostConfig.CapAdd) != 1 || parsed.HostConfig.CapAdd[0] != "NET_BIND_SERVICE" {
		t.Fatalf("expected only NET_BIND_SERVICE, got %v", parsed.HostConfig.CapAdd)
	}
}

func TestStripDevices(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed struct {
		HostConfig struct {
			Devices []interface{} `json:"Devices"`
		} `json:"HostConfig"`
	}
	json.Unmarshal(result, &parsed)
	if len(parsed.HostConfig.Devices) != 0 {
		t.Fatalf("expected devices to be stripped, got %v", parsed.HostConfig.Devices)
	}
}

func TestCapMemory(t *testing.T) {
	p := &Policy{Workspace: "/workspace", MaxMemory: 1024, MaxCPUs: 2.0}
	body := `{"Image":"alpine","HostConfig":{"Memory":9999}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed struct {
		HostConfig struct {
			Memory int64 `json:"Memory"`
		} `json:"HostConfig"`
	}
	json.Unmarshal(result, &parsed)
	if parsed.HostConfig.Memory != 1024 {
		t.Fatalf("expected memory capped to 1024, got %d", parsed.HostConfig.Memory)
	}
}

func TestCapNanoCpus(t *testing.T) {
	p := &Policy{Workspace: "/workspace", MaxMemory: 2e9, MaxCPUs: 1.0}
	body := `{"Image":"alpine","HostConfig":{"NanoCpus":4000000000}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed struct {
		HostConfig struct {
			NanoCpus int64 `json:"NanoCpus"`
		} `json:"HostConfig"`
	}
	json.Unmarshal(result, &parsed)
	if parsed.HostConfig.NanoCpus != 1e9 {
		t.Fatalf("expected NanoCpus capped to 1e9, got %d", parsed.HostConfig.NanoCpus)
	}
}

func TestPassthroughUnchangedFields(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","Cmd":["echo","hello"],"Env":["FOO=bar"]}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Ensure fields pass through.
	var parsed map[string]interface{}
	json.Unmarshal(result, &parsed)
	if parsed["Image"] != "alpine" {
		t.Fatal("Image field lost")
	}
	cmd := parsed["Cmd"].([]interface{})
	if len(cmd) != 2 || cmd[0] != "echo" {
		t.Fatal("Cmd field lost")
	}
}

// --- Ownership tests ---

func TestOwnershipPrefixMatch(t *testing.T) {
	o := NewOwnership()
	o.Add("abc123def456")
	if !o.Owns("abc123def456") {
		t.Fatal("exact match failed")
	}
	if !o.Owns("abc123") {
		t.Fatal("prefix match failed")
	}
	if o.Owns("xyz") {
		t.Fatal("non-owned matched")
	}
}

// --- End-to-end proxy tests ---

func TestProxyCreateAndList(t *testing.T) {
	// Mock podman: accepts creates, returns container list.
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			id := "abc123def456789"
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": id})
			return
		}
		if strings.Contains(r.URL.Path, "/containers/json") {
			containers := []map[string]interface{}{
				{"Id": "abc123def456789", "Names": []string{"/my-container"}},
				{"Id": "other999888777", "Names": []string{"/not-mine"}},
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(containers)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Create a container.
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","Cmd":["echo","hello"]}`),
	)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// List containers — should only see the one we created.
	resp, err = client.Get("http://localhost/v4.0.0/containers/json")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close()
	var listed []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&listed)
	if len(listed) != 1 {
		t.Fatalf("expected 1 container in list, got %d", len(listed))
	}
	if listed[0]["Id"] != "abc123def456789" {
		t.Fatalf("unexpected container in list: %v", listed[0]["Id"])
	}
}

func TestProxyBlocksPrivilegedCreate(t *testing.T) {
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach podman")
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"Privileged":true}}`),
	)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxyBlocksUnownedContainer(t *testing.T) {
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach podman")
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)
	resp, err := client.Post("http://localhost/v4.0.0/containers/unknown123/start", "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxyBlocksForbiddenEndpoints(t *testing.T) {
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach podman")
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	endpoints := []string{
		"http://localhost/v4.0.0/system/info",
		"http://localhost/v4.0.0/volumes/json",
		"http://localhost/v4.0.0/networks/json",
		"http://localhost/v4.0.0/images/json",
	}
	for _, url := range endpoints {
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("request to %s: %v", url, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for %s, got %d", url, resp.StatusCode)
		}
	}
}

func TestProxyAllowsPing(t *testing.T) {
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)
	resp, err := client.Get("http://localhost/v4.0.0/_ping")
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for ping, got %d", resp.StatusCode)
	}
}

func TestProxyAllowsOwnedContainerOps(t *testing.T) {
	containerID := "abc123def456789"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		// All other container ops succeed.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Create first.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// Now start it — should be allowed (owned).
	resp, err := client.Post("http://localhost/v4.0.0/containers/"+containerID+"/start", "", nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for start, got %d", resp.StatusCode)
	}

	// Short prefix should also work.
	resp, err = client.Post("http://localhost/v4.0.0/containers/abc123/start", "", nil)
	if err != nil {
		t.Fatalf("start with prefix: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for prefix start, got %d", resp.StatusCode)
	}
}

func TestProxyResourceCapping(t *testing.T) {
	var receivedBody map[string]json.RawMessage
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"Id": "test123"})
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	policy := &Policy{
		Workspace: "/workspace",
		MaxMemory: 1024,
		MaxCPUs:   1.0,
	}
	proxySock, cleanup2 := startProxy(t, podmanSock, policy)
	defer cleanup2()

	client := unixClient(proxySock)
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"Memory":9999,"NanoCpus":4000000000,"CapAdd":["SYS_ADMIN","NET_BIND_SERVICE"],"Devices":[{"PathOnHost":"/dev/sda"}]}}`),
	)
	resp.Body.Close()

	// Check what podman received.
	var hc hostConfig
	json.Unmarshal(receivedBody["HostConfig"], &hc)

	if hc.Memory != 1024 {
		t.Fatalf("expected memory 1024, got %d", hc.Memory)
	}
	if hc.NanoCpus != 1e9 {
		t.Fatalf("expected NanoCpus 1e9, got %d", hc.NanoCpus)
	}
	if len(hc.CapAdd) != 1 || hc.CapAdd[0] != "NET_BIND_SERVICE" {
		t.Fatalf("expected only NET_BIND_SERVICE cap, got %v", hc.CapAdd)
	}
	if len(hc.Devices) != 0 {
		t.Fatalf("expected devices stripped, got %v", hc.Devices)
	}
}

func TestProxyContainerRemoveUntracks(t *testing.T) {
	containerID := "abc123def456789"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Create.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// Delete via DELETE method.
	req, _ := http.NewRequest(http.MethodDelete, "http://localhost/v4.0.0/containers/"+containerID, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Now trying to access it should 403 (no longer owned).
	resp, err = client.Post("http://localhost/v4.0.0/containers/"+containerID+"/start", "", nil)
	if err != nil {
		t.Fatalf("start after delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 after removal, got %d", resp.StatusCode)
	}
}

// TestPolicyValidateBindsTraversal tests that ".." traversal is caught.
func TestPolicyValidateBindsTraversal(t *testing.T) {
	ws := t.TempDir()
	p := &Policy{Workspace: ws}
	body := `{"Image":"alpine","HostConfig":{"Binds":["` + ws + `/../etc/passwd:/mnt"]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
}

func init() {
	// Suppress log output during tests.
	_ = os.Stderr
}
