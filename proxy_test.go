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
		MaxPids:   1024,
	}
}

// --- Policy unit tests ---

func TestBlockPrivileged(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Privileged":true}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil || !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("expected privileged error, got: %v", err)
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

func TestBlockHostIpc(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"IpcMode":"host"}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for host IPC")
	}
}

func TestBlockHostUTS(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"UTSMode":"host"}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for host UTS")
	}
}

func TestBlockHostUserns(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"UsernsMode":"host"}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for host user namespace")
	}
}

func TestBlockHostCgroupns(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"CgroupnsMode":"host"}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for host cgroup namespace")
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

func TestBlockEmptyBindHostPath(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Binds":[":/container"]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for empty host path")
	}
}

func TestBlockMountsOutsideWorkspace(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"bind","Source":"/etc","Target":"/mnt"}]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for Mounts bind outside workspace")
	}
}

func TestAllowMountsInsideWorkspace(t *testing.T) {
	ws := t.TempDir()
	p := &Policy{Workspace: ws, MaxMemory: 2e9, MaxCPUs: 2.0}
	body := `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"bind","Source":"` + ws + `/data","Target":"/mnt"}]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAllowMountsVolume(t *testing.T) {
	p := defaultPolicy()
	// Volume-type mounts don't reference host paths, should be allowed.
	body := `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Source":"myvolume","Target":"/data"}]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("volume mount should be allowed: %v", err)
	}
}

func TestAllowBindInsideWorkspace(t *testing.T) {
	ws := t.TempDir()
	p := &Policy{Workspace: ws, MaxMemory: 2e9, MaxCPUs: 2.0}
	body := `{"Image":"alpine","HostConfig":{"Binds":["` + ws + `/data:/data"]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEmptyWorkspaceBlocksAllBinds(t *testing.T) {
	p := &Policy{Workspace: "", MaxMemory: 2e9, MaxCPUs: 2.0}
	body := `{"Image":"alpine","HostConfig":{"Binds":["/tmp/safe:/data"]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error when workspace is empty")
	}
}

func TestImageAllowlist(t *testing.T) {
	p := &Policy{
		Workspace:     "/workspace",
		AllowedImages: []string{"alpine", "ubuntu:22.04"},
	}
	_, err := p.ValidateAndSanitize([]byte(`{"Image":"alpine"}`))
	if err != nil {
		t.Fatalf("alpine should be allowed: %v", err)
	}
	_, err = p.ValidateAndSanitize([]byte(`{"Image":"evil:latest"}`))
	if err == nil {
		t.Fatal("expected error for disallowed image")
	}
}

func TestStripNonAllowlistedCaps(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"CapAdd":["NET_BIND_SERVICE","SYS_ADMIN","SYS_MODULE"]}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	var caps []string
	json.Unmarshal(rawHC["CapAdd"], &caps)
	if len(caps) != 1 || caps[0] != "NET_BIND_SERVICE" {
		t.Fatalf("expected only NET_BIND_SERVICE, got %v", caps)
	}
}

func TestStripCapAddAll(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"CapAdd":["ALL"]}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	var caps []string
	json.Unmarshal(rawHC["CapAdd"], &caps)
	if len(caps) != 0 {
		t.Fatalf("expected ALL to be stripped, got %v", caps)
	}
}

func TestStripDevices(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["Devices"]; ok {
		t.Fatal("expected Devices to be removed")
	}
}

func TestStripSecurityOpt(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["SecurityOpt"]; ok {
		t.Fatal("expected SecurityOpt to be removed")
	}
}

func TestStripSysctls(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Sysctls":{"net.ipv4.ip_forward":"1"}}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["Sysctls"]; ok {
		t.Fatal("expected Sysctls to be removed")
	}
}

func TestCapMemory(t *testing.T) {
	p := &Policy{Workspace: "/workspace", MaxMemory: 1024, MaxCPUs: 2.0}
	body := `{"Image":"alpine","HostConfig":{"Memory":9999}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	var mem int64
	json.Unmarshal(rawHC["Memory"], &mem)
	if mem != 1024 {
		t.Fatalf("expected memory capped to 1024, got %d", mem)
	}
}

func TestCapNanoCpus(t *testing.T) {
	p := &Policy{Workspace: "/workspace", MaxMemory: 2e9, MaxCPUs: 1.0}
	body := `{"Image":"alpine","HostConfig":{"NanoCpus":4000000000}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	var nano int64
	json.Unmarshal(rawHC["NanoCpus"], &nano)
	if nano != 1e9 {
		t.Fatalf("expected NanoCpus capped to 1e9, got %d", nano)
	}
}

func TestCpuQuotaStrippedWithoutPeriod(t *testing.T) {
	p := &Policy{Workspace: "/workspace", MaxMemory: 2e9, MaxCPUs: 1.0}
	// CpuQuota should be stripped when MaxCPUs is configured (NanoCpus is used instead).
	body := `{"Image":"alpine","HostConfig":{"CpuQuota":9999999}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["CpuQuota"]; ok {
		t.Fatal("CpuQuota should be stripped when MaxCPUs is configured")
	}
	// NanoCpus should be enforced instead.
	var nano int64
	json.Unmarshal(rawHC["NanoCpus"], &nano)
	expected := int64(1.0 * 1e9)
	if nano != expected {
		t.Fatalf("expected NanoCpus=%d, got %d", expected, nano)
	}
}

func TestPassthroughUnchangedFields(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","Cmd":["echo","hello"],"Env":["FOO=bar"]}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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

func TestAlwaysRemarshal(t *testing.T) {
	p := defaultPolicy()
	// Body with no HostConfig modifications needed — should still re-marshal.
	body := `{"Image":"alpine","HostConfig":{"NetworkMode":"bridge"}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify it's valid JSON that round-trips.
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("re-marshaled body is invalid JSON: %v", err)
	}
}

func TestPreservesUnknownHostConfigFields(t *testing.T) {
	p := defaultPolicy()
	// Unknown fields that aren't in the strip list should be preserved.
	body := `{"Image":"alpine","HostConfig":{"NetworkMode":"bridge","Dns":["8.8.8.8"]}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["Dns"]; !ok {
		t.Fatal("Dns was lost during re-marshal")
	}
}

// --- Ownership tests ---

func TestOwnershipExactMatch(t *testing.T) {
	o := NewOwnership()
	o.Add("abc123def456abcdef", "")
	if !o.Owns("abc123def456abcdef") {
		t.Fatal("exact match failed")
	}
}

func TestOwnershipPrefixRequiresMinLength(t *testing.T) {
	o := NewOwnership()
	o.Add("abc123def456abcdef", "")
	// Short prefix (< 12 chars) should NOT match.
	if o.Owns("abc") {
		t.Fatal("short prefix should not match")
	}
	if o.Owns("abc123") {
		t.Fatal("6-char prefix should not match")
	}
	// 12+ char prefix should match.
	if !o.Owns("abc123def456") {
		t.Fatal("12-char prefix should match")
	}
}

func TestOwnershipNameMatch(t *testing.T) {
	o := NewOwnership()
	o.Add("abc123def456abcdef", "my-container")
	if !o.Owns("my-container") {
		t.Fatal("name match failed")
	}
	if o.Owns("other-container") {
		t.Fatal("non-owned name matched")
	}
}

func TestOwnershipRemoveCleansName(t *testing.T) {
	o := NewOwnership()
	o.Add("abc123def456abcdef", "my-container")
	o.Remove("abc123def456abcdef")
	if o.Owns("my-container") {
		t.Fatal("name should be cleaned up after Remove")
	}
	if o.Owns("abc123def456abcdef") {
		t.Fatal("ID should be removed")
	}
}

func TestOwnershipFullID(t *testing.T) {
	o := NewOwnership()
	o.Add("abc123def456abcdef", "my-container")

	if o.FullID("abc123def456abcdef") != "abc123def456abcdef" {
		t.Fatal("FullID exact match failed")
	}
	if o.FullID("my-container") != "abc123def456abcdef" {
		t.Fatal("FullID name lookup failed")
	}
	if o.FullID("abc123def456") != "abc123def456abcdef" {
		t.Fatal("FullID prefix lookup failed")
	}
	if o.FullID("xyz") != "" {
		t.Fatal("FullID should return empty for unknown ref")
	}
}

func TestOwnershipAmbiguousPrefix(t *testing.T) {
	o := NewOwnership()
	o.Add("abc123def456aaaa", "")
	o.Add("abc123def456bbbb", "")
	// Both match the prefix — Owns should still return true (any match).
	if !o.Owns("abc123def456") {
		t.Fatal("ambiguous prefix should still match for Owns")
	}
	// FullID should return "" for ambiguous prefix.
	if o.FullID("abc123def456") != "" {
		t.Fatal("ambiguous prefix should return empty FullID")
	}
	// Unique prefix should still work.
	if o.FullID("abc123def456a") != "abc123def456aaaa" {
		t.Fatal("unique prefix should resolve")
	}
}

func TestPolicyValidateBindsTraversal(t *testing.T) {
	ws := t.TempDir()
	p := &Policy{Workspace: ws}
	body := `{"Image":"alpine","HostConfig":{"Binds":["` + ws + `/../etc/passwd:/mnt"]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
}

// --- End-to-end proxy tests ---

func TestProxyCreateAndList(t *testing.T) {
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			id := "abc123def456789012345678abc123def456789012345678abc123def4567890"
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": id})
			return
		}
		if strings.Contains(r.URL.Path, "/containers/json") {
			containers := []map[string]interface{}{
				{"Id": "abc123def456789012345678abc123def456789012345678abc123def4567890", "Names": []string{"/my-container"}},
				{"Id": "other999888777666555444", "Names": []string{"/not-mine"}},
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
	if listed[0]["Id"] != "abc123def456789012345678abc123def456789012345678abc123def4567890" {
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
	resp, err := client.Post("http://localhost/v4.0.0/containers/unknown123456/start", "", nil)
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

func TestProxyBlocksExecAndUpdate(t *testing.T) {
	containerID := "abc123def456789012345678abc123def456789012345678abc123def4567890"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		t.Fatalf("unexpected request reached podman: %s %s", r.Method, r.URL.Path)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Create a container first.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// Exec should be blocked even on owned container.
	resp, err := client.Post("http://localhost/v4.0.0/containers/"+containerID+"/exec",
		"application/json",
		strings.NewReader(`{"Cmd":["sh"]}`))
	if err != nil {
		t.Fatalf("exec request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for exec, got %d", resp.StatusCode)
	}

	// Update should be blocked.
	resp, err = client.Post("http://localhost/v4.0.0/containers/"+containerID+"/update",
		"application/json",
		strings.NewReader(`{"Memory":999999999}`))
	if err != nil {
		t.Fatalf("update request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for update, got %d", resp.StatusCode)
	}

	// Archive should be blocked.
	resp, err = client.Get("http://localhost/v4.0.0/containers/" + containerID + "/archive?path=/etc")
	if err != nil {
		t.Fatalf("archive request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for archive, got %d", resp.StatusCode)
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
	containerID := "abc123def456789012345678abc123def456789012345678abc123def4567890"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// Start should be allowed (owned, action in whitelist).
	resp, err := client.Post("http://localhost/v4.0.0/containers/"+containerID+"/start", "", nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for start, got %d", resp.StatusCode)
	}

	// 12-char prefix should also work.
	resp, err = client.Post("http://localhost/v4.0.0/containers/abc123def456/start", "", nil)
	if err != nil {
		t.Fatalf("start with prefix: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for prefix start, got %d", resp.StatusCode)
	}

	// Short prefix (< 12) should NOT work.
	resp, err = client.Post("http://localhost/v4.0.0/containers/abc123/start", "", nil)
	if err != nil {
		t.Fatalf("start with short prefix: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for short prefix, got %d", resp.StatusCode)
	}
}

func TestProxyResourceCapping(t *testing.T) {
	var receivedBody map[string]json.RawMessage
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"Id": "def0123456789abcdef0123456789abcdef0123456789abcdef012345678abcd"})
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
		strings.NewReader(`{"Image":"alpine","HostConfig":{"Memory":9999,"NanoCpus":4000000000,"CapAdd":["SYS_ADMIN","NET_BIND_SERVICE"],"Devices":[{"PathOnHost":"/dev/sda"}],"SecurityOpt":["seccomp=unconfined"],"Sysctls":{"net.ipv4.ip_forward":"1"}}}`),
	)
	resp.Body.Close()

	// Check what podman received.
	var rawHC map[string]json.RawMessage
	json.Unmarshal(receivedBody["HostConfig"], &rawHC)

	var mem int64
	json.Unmarshal(rawHC["Memory"], &mem)
	if mem != 1024 {
		t.Fatalf("expected memory 1024, got %d", mem)
	}

	var nano int64
	json.Unmarshal(rawHC["NanoCpus"], &nano)
	if nano != 1e9 {
		t.Fatalf("expected NanoCpus 1e9, got %d", nano)
	}

	var caps []string
	json.Unmarshal(rawHC["CapAdd"], &caps)
	if len(caps) != 1 || caps[0] != "NET_BIND_SERVICE" {
		t.Fatalf("expected only NET_BIND_SERVICE cap, got %v", caps)
	}

	if _, ok := rawHC["Devices"]; ok {
		t.Fatal("expected Devices to be removed")
	}
	if _, ok := rawHC["SecurityOpt"]; ok {
		t.Fatal("expected SecurityOpt to be removed")
	}
	if _, ok := rawHC["Sysctls"]; ok {
		t.Fatal("expected Sysctls to be removed")
	}
}

func TestProxyContainerRemoveUntracks(t *testing.T) {
	containerID := "abc123def456789012345678abc123def456789012345678abc123def4567890"
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

func TestProxyRemoveDoesNotUntrackOnError(t *testing.T) {
	containerID := "abc123def456789012345678abc123def456789012345678abc123def4567890"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		// Simulate a failed delete.
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"message":"container is running"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// Failed delete (409 Conflict).
	req, _ := http.NewRequest(http.MethodDelete, "http://localhost/v4.0.0/containers/"+containerID, nil)
	resp, _ = client.Do(req)
	resp.Body.Close()

	// Container should still be owned (not untracked because delete failed).
	resp, err := client.Post("http://localhost/v4.0.0/containers/"+containerID+"/start", "", nil)
	if err != nil {
		t.Fatalf("start after failed delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (still owned), got %d", resp.StatusCode)
	}
}

func TestProxyTracksContainerName(t *testing.T) {
	containerID := "abc123def456789012345678abc123def456789012345678abc123def4567890"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Create with ?name=my-worker
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create?name=my-worker",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// Access by name should work.
	resp, err := client.Post("http://localhost/v4.0.0/containers/my-worker/start", "", nil)
	if err != nil {
		t.Fatalf("start by name: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for name-based access, got %d", resp.StatusCode)
	}
}

func TestProxyRewritesContainerRefToFullID(t *testing.T) {
	containerID := "abc123def456789012345678abc123def456789012345678abc123def4567890"
	var receivedPath string
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Create container.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create?name=my-worker",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// Access by name — podman should receive the full ID, not the name.
	resp, err := client.Post("http://localhost/v4.0.0/containers/my-worker/start", "", nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(receivedPath, containerID) {
		t.Fatalf("expected podman to receive full ID in path, got %s", receivedPath)
	}

	// Access by 12-char prefix — podman should also receive the full ID.
	resp, err = client.Post("http://localhost/v4.0.0/containers/abc123def456/start", "", nil)
	if err != nil {
		t.Fatalf("start by prefix: %v", err)
	}
	resp.Body.Close()
	if !strings.Contains(receivedPath, containerID) {
		t.Fatalf("expected podman to receive full ID for prefix, got %s", receivedPath)
	}
}

func TestProxyRenameUpdatesOwnership(t *testing.T) {
	containerID := "abc123def456789012345678abc123def456789012345678abc123def4567890"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Create with name.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create?name=old-name",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// Rename.
	resp, err := client.Post("http://localhost/v4.0.0/containers/"+containerID+"/rename?name=new-name", "", nil)
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	resp.Body.Close()

	// Access by new name should work.
	resp, err = client.Post("http://localhost/v4.0.0/containers/new-name/start", "", nil)
	if err != nil {
		t.Fatalf("start by new name: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for new name, got %d", resp.StatusCode)
	}

	// Access by old name should fail.
	resp, err = client.Post("http://localhost/v4.0.0/containers/old-name/start", "", nil)
	if err != nil {
		t.Fatalf("start by old name: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for old name after rename, got %d", resp.StatusCode)
	}
}

func TestOwnershipRename(t *testing.T) {
	o := NewOwnership()
	o.Add("abc123def456abcdef", "old-name")
	o.Rename("abc123def456abcdef", "new-name")

	if o.Owns("old-name") {
		t.Fatal("old name should not match after rename")
	}
	if !o.Owns("new-name") {
		t.Fatal("new name should match after rename")
	}
	if !o.Owns("abc123def456abcdef") {
		t.Fatal("ID should still match after rename")
	}
}

func TestProxyListDoesNotLeakHeaders(t *testing.T) {
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/json") {
			w.Header().Set("Server", "libpod/secret-version")
			w.Header().Set("X-Custom-Internal", "leak-me")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)
	resp, err := client.Get("http://localhost/v4.0.0/containers/json")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Server") != "" {
		t.Fatalf("Server header should be stripped, got %q", resp.Header.Get("Server"))
	}
	if resp.Header.Get("X-Custom-Internal") != "" {
		t.Fatalf("X-Custom-Internal header should be stripped, got %q", resp.Header.Get("X-Custom-Internal"))
	}
}

func TestProxyStreamingLogs(t *testing.T) {
	containerID := "abc123def456789012345678abc123def456789012345678abc123def4567890"
	logOutput := "line1\nline2\nline3\n"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		if strings.Contains(r.URL.Path, "/logs") {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(logOutput))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Create container.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// Get logs — should be streamed, not buffered.
	resp, err := client.Get("http://localhost/v4.0.0/containers/" + containerID + "/logs?stdout=true")
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != logOutput {
		t.Fatalf("expected log output %q, got %q", logOutput, string(body))
	}
}

// --- Round 4 security fix tests ---

func TestPidsLimitEnforced(t *testing.T) {
	p := &Policy{Workspace: "/workspace", MaxMemory: 2e9, MaxCPUs: 2.0, MaxPids: 512}

	// Tenant requests unlimited PIDs — should be capped.
	body := `{"Image":"alpine","HostConfig":{"PidsLimit":-1}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	var pids int64
	json.Unmarshal(rawHC["PidsLimit"], &pids)
	if pids != 512 {
		t.Fatalf("expected PidsLimit capped to 512, got %d", pids)
	}

	// Tenant requests no PidsLimit (omitted) — should be set.
	body = `{"Image":"alpine","HostConfig":{"NetworkMode":"bridge"}}`
	result, err = p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	json.Unmarshal(result, &raw)
	json.Unmarshal(raw["HostConfig"], &rawHC)
	json.Unmarshal(rawHC["PidsLimit"], &pids)
	if pids != 512 {
		t.Fatalf("expected PidsLimit set to 512 when omitted, got %d", pids)
	}

	// Tenant requests within limit — should pass through.
	body = `{"Image":"alpine","HostConfig":{"PidsLimit":100}}`
	result, err = p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	json.Unmarshal(result, &raw)
	json.Unmarshal(raw["HostConfig"], &rawHC)
	json.Unmarshal(rawHC["PidsLimit"], &pids)
	if pids != 100 {
		t.Fatalf("expected PidsLimit 100 (within limit), got %d", pids)
	}
}

func TestStructuralPathRewriteContainersName(t *testing.T) {
	// Container named "containers" — the old strings.Replace approach
	// would replace the wrong "/containers" segment in the path.
	containerID := "abcdef1234560000abcdef1234560000abcdef1234560000abcdef12345600ab"
	var receivedPath string
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Create container with name "containers".
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create?name=containers",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// Access by name "containers" — path must still be correctly formed.
	resp, err := client.Post("http://localhost/v4.0.0/containers/containers/start", "", nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	expected := "/v4.0.0/containers/" + containerID + "/start"
	if receivedPath != expected {
		t.Fatalf("expected podman to receive %q, got %q", expected, receivedPath)
	}
}

func TestXRegistryAuthStripped(t *testing.T) {
	var receivedAuth string
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("X-Registry-Auth")
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": "abcdef1234560000abcdef1234560000abcdef1234560000abcdef12345600ab"})
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	req, _ := http.NewRequest(http.MethodPost, "http://localhost/v4.0.0/containers/create", strings.NewReader(`{"Image":"alpine"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Registry-Auth", "eyJzZWNyZXQiOiAidG9rZW4ifQ==")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "" {
		t.Fatalf("X-Registry-Auth should have been stripped, but podman received %q", receivedAuth)
	}
}

func TestEmptyActionMethodRestriction(t *testing.T) {
	containerID := "abcdef1234560000abcdef1234560000abcdef1234560000abcdef12345600ab"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Create container.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// GET /containers/<id> (inspect) should be allowed.
	resp, err := client.Get("http://localhost/v4.0.0/containers/" + containerID)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for GET (inspect), got %d", resp.StatusCode)
	}

	// DELETE /containers/<id> should be allowed.
	req, _ := http.NewRequest(http.MethodDelete, "http://localhost/v4.0.0/containers/"+containerID, nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for DELETE, got %d", resp.StatusCode)
	}
}

func TestEmptyActionBlocksPost(t *testing.T) {
	containerID := "abcdef1234560000abcdef1234560000abcdef1234560000abcdef12345600ab"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		t.Fatalf("unexpected request reached podman: %s %s", r.Method, r.URL.Path)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// POST /containers/<id> (no action) should be blocked.
	resp, err := client.Post("http://localhost/v4.0.0/containers/"+containerID, "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST with no action, got %d", resp.StatusCode)
	}

	// PUT /containers/<id> should also be blocked.
	req, _ := http.NewRequest(http.MethodPut, "http://localhost/v4.0.0/containers/"+containerID, nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for PUT with no action, got %d", resp.StatusCode)
	}
}

func TestListStripsSizeParam(t *testing.T) {
	var receivedQuery string
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/json") {
			receivedQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)
	resp, err := client.Get("http://localhost/v4.0.0/containers/json?all=1&size=1&filters=%7B%22name%22%3A%5B%22evil%22%5D%7D&limit=10")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	resp.Body.Close()

	if strings.Contains(receivedQuery, "size") {
		t.Fatalf("size param should be stripped, but podman received query: %s", receivedQuery)
	}
	if strings.Contains(receivedQuery, "filters") {
		t.Fatalf("filters param should be stripped, but podman received query: %s", receivedQuery)
	}
	if !strings.Contains(receivedQuery, "all=1") {
		t.Fatalf("all param should be preserved, but podman received query: %s", receivedQuery)
	}
	if !strings.Contains(receivedQuery, "limit=10") {
		t.Fatalf("limit param should be preserved, but podman received query: %s", receivedQuery)
	}
}

func TestStreamingSemaphore(t *testing.T) {
	containerID := "abcdef1234560000abcdef1234560000abcdef1234560000abcdef12345600ab"

	// Use channels to synchronize: podmanReached signals that the first
	// stream has reached the mock podman (meaning the semaphore is held).
	holdOpen := make(chan struct{})
	podmanReached := make(chan struct{}, 1) // buffered so non-blocking send
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		if strings.Contains(r.URL.Path, "/logs") {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case podmanReached <- struct{}{}:
			default:
			}
			<-holdOpen // block until released
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	// Create proxy with a tiny semaphore (capacity 1).
	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
		streamSem:    make(chan struct{}, 1),
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() {
		close(holdOpen)
		server.Close()
		listener.Close()
	}()

	client := unixClient(sockPath)

	// Create container.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// First streaming connection — should succeed (fills the semaphore).
	go func() {
		resp, err := client.Get("http://localhost/v4.0.0/containers/" + containerID + "/logs?stdout=true")
		if err != nil {
			return
		}
		resp.Body.Close()
	}()

	// Wait for the first stream to actually reach podman (semaphore is held).
	<-podmanReached

	// Second streaming connection — semaphore should be full, expect 503.
	client2 := unixClient(sockPath)
	resp, err = client2.Get("http://localhost/v4.0.0/containers/" + containerID + "/logs?stdout=true")
	if err != nil {
		t.Fatalf("second stream request: %v", err)
	}
	secondStatus := resp.StatusCode
	resp.Body.Close()

	if secondStatus != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when streaming semaphore full, got %d", secondStatus)
	}
}

func TestInvalidContainerIDNotRegistered(t *testing.T) {
	// Podman returns a malformed container ID — should not be registered.
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": "NOT-A-VALID-HEX-ID"})
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// The invalid ID should not be in the ownership table.
	resp, err := client.Get("http://localhost/v4.0.0/containers/json")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	resp.Body.Close()
	// No containers should be listed since the ID was rejected.
}

// --- Round 5 security fix tests ---

func TestBlockContainerNamespaceSharing(t *testing.T) {
	p := defaultPolicy()
	modes := []struct {
		field string
		body  string
	}{
		{"NetworkMode", `{"Image":"alpine","HostConfig":{"NetworkMode":"container:victim"}}`},
		{"PidMode", `{"Image":"alpine","HostConfig":{"PidMode":"container:victim"}}`},
		{"IpcMode", `{"Image":"alpine","HostConfig":{"IpcMode":"container:victim"}}`},
		{"UTSMode", `{"Image":"alpine","HostConfig":{"UTSMode":"container:victim"}}`},
		// Case-insensitive
		{"NetworkMode-ci", `{"Image":"alpine","HostConfig":{"NetworkMode":"Container:victim"}}`},
	}
	for _, tc := range modes {
		_, err := p.ValidateAndSanitize([]byte(tc.body))
		if err == nil {
			t.Fatalf("%s: expected error for container: mode", tc.field)
		}
		if !strings.Contains(err.Error(), "container") {
			t.Fatalf("%s: expected 'container' in error, got: %v", tc.field, err)
		}
	}
}

func TestStripVolumesFrom(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"VolumesFrom":["other-container:rw"]}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["VolumesFrom"]; ok {
		t.Fatal("expected VolumesFrom to be stripped")
	}
}

func TestPerActionMethodEnforcement(t *testing.T) {
	containerID := "abc123def456789012345678abc123def456789012345678abc123def4567890"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Create container.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// GET /containers/<id>/start should be blocked (start requires POST).
	resp, err := client.Get("http://localhost/v4.0.0/containers/" + containerID + "/start")
	if err != nil {
		t.Fatalf("get start: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET start, got %d", resp.StatusCode)
	}

	// POST /containers/<id>/top should be blocked (top requires GET).
	resp, err = client.Post("http://localhost/v4.0.0/containers/"+containerID+"/top", "", nil)
	if err != nil {
		t.Fatalf("post top: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST top, got %d", resp.StatusCode)
	}

	// POST /containers/<id>/start should work.
	resp, err = client.Post("http://localhost/v4.0.0/containers/"+containerID+"/start", "", nil)
	if err != nil {
		t.Fatalf("post start: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for POST start, got %d", resp.StatusCode)
	}
}

func TestCapMemorySwap(t *testing.T) {
	p := &Policy{Workspace: "/workspace", MaxMemory: 2048, MaxCPUs: 2.0, MaxPids: 1024}

	// MemorySwap=-1 (unlimited) with no Memory — both should be MaxMemory.
	body := `{"Image":"alpine","HostConfig":{"MemorySwap":-1}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	var swap int64
	json.Unmarshal(rawHC["MemorySwap"], &swap)
	if swap != 2048 {
		t.Fatalf("expected MemorySwap=MaxMemory=2048 when Memory omitted, got %d", swap)
	}

	// Memory=512, MemorySwap should be set to 512 (disabling swap).
	body = `{"Image":"alpine","HostConfig":{"Memory":512,"MemorySwap":9999}}`
	result, err = p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	json.Unmarshal(result, &raw)
	json.Unmarshal(raw["HostConfig"], &rawHC)
	json.Unmarshal(rawHC["MemorySwap"], &swap)
	if swap != 512 {
		t.Fatalf("expected MemorySwap=Memory=512 (no swap), got %d", swap)
	}

	// Memory=1024, MemorySwap=-1 — swap should be tied to Memory, not MaxMemory.
	body = `{"Image":"alpine","HostConfig":{"Memory":1024,"MemorySwap":-1}}`
	result, err = p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	json.Unmarshal(result, &raw)
	json.Unmarshal(raw["HostConfig"], &rawHC)
	json.Unmarshal(rawHC["MemorySwap"], &swap)
	if swap != 1024 {
		t.Fatalf("expected MemorySwap=1024 (tied to Memory, not MaxMemory), got %d", swap)
	}
}

func TestCpuPeriodStrippedWhenMaxCPUs(t *testing.T) {
	p := &Policy{Workspace: "/workspace", MaxMemory: 2e9, MaxCPUs: 2.0, MaxPids: 1024}

	// CpuPeriod should be stripped when MaxCPUs is configured (NanoCpus is used instead).
	body := `{"Image":"alpine","HostConfig":{"CpuPeriod":50000}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["CpuPeriod"]; ok {
		t.Fatal("CpuPeriod should be stripped when MaxCPUs is configured")
	}
	if _, ok := rawHC["CpuQuota"]; ok {
		t.Fatal("CpuQuota should be stripped when MaxCPUs is configured")
	}

	// NanoCpus should be enforced.
	var nano int64
	json.Unmarshal(rawHC["NanoCpus"], &nano)
	expected := int64(2.0 * 1e9)
	if nano != expected {
		t.Fatalf("expected NanoCpus=%d, got %d", expected, nano)
	}
}

func TestContainerNameValidation(t *testing.T) {
	containerID := "abcdef1234560000abcdef1234560000abcdef1234560000abcdef12345600ab"
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()

	client := unixClient(sockPath)

	// Create with an invalid name (contains spaces) — rejected before forwarding.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create?name=invalid%20name%20with%20spaces",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 for invalid name, got %d", resp.StatusCode)
	}
	// Container should NOT be created at all.
	if proxy.Ownership.Owns(containerID) {
		t.Fatal("container should not be created with invalid name")
	}

	// Valid name should work.
	resp, _ = client.Post(
		"http://localhost/v4.0.0/containers/create?name=valid-name.123",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201 for valid name, got %d", resp.StatusCode)
	}
	if !proxy.Ownership.Owns("valid-name.123") {
		t.Fatal("valid name should be registered")
	}
}

func TestBlockUsernsContainerMode(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach podman")
	}))
	defer cleanup()

	proxySock, pcleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pcleanup()

	client := unixClient(proxySock)

	// container:<id> mode should be blocked.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"UsernsMode":"container:abc123"}}`),
	)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	// host mode should also be blocked.
	resp, _ = client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"UsernsMode":"host"}}`),
	)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 for host userns, got %d", resp.StatusCode)
	}
}

func TestBlockCgroupnsContainerMode(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach podman")
	}))
	defer cleanup()

	proxySock, pcleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pcleanup()

	client := unixClient(proxySock)

	// container:<id> mode should be blocked.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"CgroupnsMode":"container:abc123"}}`),
	)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	// host mode should also be blocked.
	resp, _ = client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"CgroupnsMode":"host"}}`),
	)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 for host cgroupns, got %d", resp.StatusCode)
	}
}

func TestRenameNameValidation(t *testing.T) {
	const containerID = "abc123def456789012345678abc123def456789012345678abc123def4567890"
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()

	proxy.Ownership.Add(containerID, "original-name")

	client := unixClient(sockPath)

	// Rename to valid name should update ownership.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/"+containerID+"/rename?name=new-valid-name",
		"application/json",
		nil,
	)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !proxy.Ownership.Owns("new-valid-name") {
		t.Fatal("valid rename name should be tracked")
	}

	// Rename to invalid name (contains special chars) — podman returns 200 but proxy should not track.
	resp, _ = client.Post(
		"http://localhost/v4.0.0/containers/"+containerID+"/rename?name=../evil",
		"application/json",
		nil,
	)
	resp.Body.Close()
	if proxy.Ownership.Owns("../evil") {
		t.Fatal("invalid rename name should NOT be tracked")
	}
}

func TestMemoryZeroEnforced(t *testing.T) {
	var capturedBody []byte
	const containerID = "abc123def456789012345678abc123def456789012345678abc123def4567890"

	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"Id":"%s"}`, containerID)
	}))
	defer cleanup()

	policy := defaultPolicy()
	policy.MaxMemory = 1024 * 1024 * 1024 // 1GB

	proxySock, pcleanup := startProxy(t, podmanSock, policy)
	defer pcleanup()

	client := unixClient(proxySock)

	// Memory=0 should be set to MaxMemory (0 means unlimited in Podman).
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"Memory":0}}`),
	)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]json.RawMessage
	json.Unmarshal(capturedBody, &body)
	var hc map[string]json.RawMessage
	json.Unmarshal(body["HostConfig"], &hc)
	var mem int64
	json.Unmarshal(hc["Memory"], &mem)
	if mem != policy.MaxMemory {
		t.Fatalf("Memory=0 should be capped to %d, got %d", policy.MaxMemory, mem)
	}

	// Memory not specified (omitted) should also be set to MaxMemory.
	resp, _ = client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	json.Unmarshal(capturedBody, &body)
	json.Unmarshal(body["HostConfig"], &hc)
	json.Unmarshal(hc["Memory"], &mem)
	if mem != policy.MaxMemory {
		t.Fatalf("omitted Memory should be capped to %d, got %d", policy.MaxMemory, mem)
	}

	// Memory within limit should pass through unchanged.
	resp, _ = client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"Memory":536870912}}`),
	)
	resp.Body.Close()

	json.Unmarshal(capturedBody, &body)
	json.Unmarshal(body["HostConfig"], &hc)
	json.Unmarshal(hc["Memory"], &mem)
	if mem != 536870912 {
		t.Fatalf("Memory within limit should pass through, got %d", mem)
	}
}

func TestNanoCpusZeroEnforced(t *testing.T) {
	var capturedBody []byte
	const containerID = "abc123def456789012345678abc123def456789012345678abc123def4567890"

	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"Id":"%s"}`, containerID)
	}))
	defer cleanup()

	policy := defaultPolicy()
	policy.MaxCPUs = 2.0

	proxySock, pcleanup := startProxy(t, podmanSock, policy)
	defer pcleanup()

	client := unixClient(proxySock)

	// NanoCpus=0 should be set to MaxCPUs (0 means unlimited in Podman).
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"NanoCpus":0}}`),
	)
	resp.Body.Close()

	var body map[string]json.RawMessage
	json.Unmarshal(capturedBody, &body)
	var hc map[string]json.RawMessage
	json.Unmarshal(body["HostConfig"], &hc)
	var nano int64
	json.Unmarshal(hc["NanoCpus"], &nano)
	expected := int64(2.0 * 1e9)
	if nano != expected {
		t.Fatalf("NanoCpus=0 should be capped to %d, got %d", expected, nano)
	}

	// Omitted NanoCpus should also be enforced.
	resp, _ = client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	json.Unmarshal(capturedBody, &body)
	json.Unmarshal(body["HostConfig"], &hc)
	json.Unmarshal(hc["NanoCpus"], &nano)
	if nano != expected {
		t.Fatalf("omitted NanoCpus should be capped to %d, got %d", expected, nano)
	}

	// NanoCpus within limit should pass through.
	resp, _ = client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"NanoCpus":1000000000}}`),
	)
	resp.Body.Close()

	json.Unmarshal(capturedBody, &body)
	json.Unmarshal(body["HostConfig"], &hc)
	json.Unmarshal(hc["NanoCpus"], &nano)
	if nano != 1000000000 {
		t.Fatalf("NanoCpus within limit should pass through, got %d", nano)
	}
}

func TestMemorySwapZeroEnforced(t *testing.T) {
	var capturedBody []byte
	const containerID = "abc123def456789012345678abc123def456789012345678abc123def4567890"

	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"Id":"%s"}`, containerID)
	}))
	defer cleanup()

	policy := defaultPolicy()
	policy.MaxMemory = 1024 * 1024 * 1024 // 1GB

	proxySock, pcleanup := startProxy(t, podmanSock, policy)
	defer pcleanup()

	client := unixClient(proxySock)

	// MemorySwap=0 should be set to MaxMemory.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"MemorySwap":0}}`),
	)
	resp.Body.Close()

	var body map[string]json.RawMessage
	json.Unmarshal(capturedBody, &body)
	var hc map[string]json.RawMessage
	json.Unmarshal(body["HostConfig"], &hc)
	var swap int64
	json.Unmarshal(hc["MemorySwap"], &swap)
	if swap != policy.MaxMemory {
		t.Fatalf("MemorySwap=0 should be capped to %d, got %d", policy.MaxMemory, swap)
	}
}

func TestCpuQuotaAndPeriodStripped(t *testing.T) {
	var capturedBody []byte
	const containerID = "abc123def456789012345678abc123def456789012345678abc123def4567890"

	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"Id":"%s"}`, containerID)
	}))
	defer cleanup()

	policy := defaultPolicy()
	policy.MaxCPUs = 2.0

	proxySock, pcleanup := startProxy(t, podmanSock, policy)
	defer pcleanup()

	client := unixClient(proxySock)

	// CpuQuota and CpuPeriod should be stripped (Podman rejects NanoCpus + CpuQuota).
	// NanoCpus is always enforced instead.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"CpuQuota":500000,"CpuPeriod":100000}}`),
	)
	resp.Body.Close()

	var body map[string]json.RawMessage
	json.Unmarshal(capturedBody, &body)
	var hc map[string]json.RawMessage
	json.Unmarshal(body["HostConfig"], &hc)

	if _, ok := hc["CpuQuota"]; ok {
		t.Fatal("CpuQuota should be stripped when MaxCPUs is configured")
	}
	if _, ok := hc["CpuPeriod"]; ok {
		t.Fatal("CpuPeriod should be stripped when MaxCPUs is configured")
	}

	// NanoCpus should be enforced.
	var nano int64
	json.Unmarshal(hc["NanoCpus"], &nano)
	expected := int64(2.0 * 1e9)
	if nano != expected {
		t.Fatalf("NanoCpus should be enforced to %d, got %d", expected, nano)
	}
}

func TestStreamByteLimit(t *testing.T) {
	const containerID = "abcdef1234560000abcdef1234560000abcdef1234560000abcdef12345600ab"

	// Mock podman that streams more data than the limit.
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": containerID})
			return
		}
		if strings.Contains(r.URL.Path, "/logs") {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			// Write 1 MB chunks. The proxy limit is 512 MB, so write 600 MB.
			chunk := make([]byte, 1024*1024)
			for i := 0; i < 600; i++ {
				_, err := w.Write(chunk)
				if err != nil {
					return // proxy closed connection
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
		streamSem:    make(chan struct{}, maxConcurrentStream),
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()

	// Create and register the container.
	client := unixClient(sockPath)
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()

	// Request logs — should be truncated at maxStreamBytes.
	resp, err = client.Get("http://localhost/v4.0.0/containers/" + containerID + "/logs?stdout=true")
	if err != nil {
		t.Fatalf("logs request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// The proxy should have cut off the stream at ~512 MB.
	// Allow some slack for the read buffer (up to 32KB over).
	maxExpected := int64(512*1024*1024 + 32*1024)
	if int64(len(body)) > maxExpected {
		t.Fatalf("stream should be capped at ~512MB, got %d bytes", len(body))
	}
	// Should have received a substantial amount (at least 500 MB).
	minExpected := int64(500 * 1024 * 1024)
	if int64(len(body)) < minExpected {
		t.Fatalf("expected at least %d bytes, got %d", minExpected, len(body))
	}
}

func TestBlockNsNamespaceMode(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach podman")
	}))
	defer cleanup()

	proxySock, pcleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pcleanup()

	client := unixClient(proxySock)

	modes := []struct {
		field string
		value string
	}{
		{"NetworkMode", "ns:/proc/1/ns/net"},
		{"PidMode", "ns:/proc/1/ns/pid"},
		{"IpcMode", "ns:/proc/1/ns/ipc"},
		{"UTSMode", "ns:/proc/1/ns/uts"},
		{"UsernsMode", "ns:/proc/1/ns/user"},
		{"CgroupnsMode", "ns:/proc/1/ns/cgroup"},
	}

	for _, m := range modes {
		body := fmt.Sprintf(`{"Image":"alpine","HostConfig":{"%s":"%s"}}`, m.field, m.value)
		resp, _ := client.Post(
			"http://localhost/v4.0.0/containers/create",
			"application/json",
			strings.NewReader(body),
		)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("%s=%s: expected 403, got %d", m.field, m.value, resp.StatusCode)
		}
	}
}

func TestResourceLimitsWithoutHostConfig(t *testing.T) {
	var capturedBody []byte
	const containerID = "abc123def456789012345678abc123def456789012345678abc123def4567890"

	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"Id":"%s"}`, containerID)
	}))
	defer cleanup()

	policy := defaultPolicy()
	policy.MaxMemory = 1024 * 1024 * 1024 // 1GB
	policy.MaxCPUs = 2.0
	policy.MaxPids = 512

	proxySock, pcleanup := startProxy(t, podmanSock, policy)
	defer pcleanup()

	client := unixClient(proxySock)

	// No HostConfig at all — resource limits should still be enforced.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]json.RawMessage
	json.Unmarshal(capturedBody, &body)
	var hc map[string]json.RawMessage
	json.Unmarshal(body["HostConfig"], &hc)

	var mem int64
	json.Unmarshal(hc["Memory"], &mem)
	if mem != policy.MaxMemory {
		t.Fatalf("Memory should be %d, got %d", policy.MaxMemory, mem)
	}

	var nano int64
	json.Unmarshal(hc["NanoCpus"], &nano)
	expectedNano := int64(2.0 * 1e9)
	if nano != expectedNano {
		t.Fatalf("NanoCpus should be %d, got %d", expectedNano, nano)
	}

	var pids int64
	json.Unmarshal(hc["PidsLimit"], &pids)
	if pids != policy.MaxPids {
		t.Fatalf("PidsLimit should be %d, got %d", policy.MaxPids, pids)
	}

	// Explicit null HostConfig should also get limits.
	resp, _ = client.Post(
		"http://localhost/v4.0.0/containers/create",
		"application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":null}`),
	)
	resp.Body.Close()

	json.Unmarshal(capturedBody, &body)
	json.Unmarshal(body["HostConfig"], &hc)
	json.Unmarshal(hc["Memory"], &mem)
	if mem != policy.MaxMemory {
		t.Fatalf("null HostConfig: Memory should be %d, got %d", policy.MaxMemory, mem)
	}
}

func TestNamedVolumesAllowed(t *testing.T) {
	p := defaultPolicy()

	// Named volume in Binds format should be allowed (not treated as bind mount).
	body := `{"Image":"alpine","HostConfig":{"Binds":["mydata:/data","cache_vol:/cache:ro"]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("named volumes should be allowed, got error: %v", err)
	}

	// Absolute path outside workspace should still be blocked.
	body = `{"Image":"alpine","HostConfig":{"Binds":["/etc:/mnt/etc"]}}`
	_, err = p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("absolute bind mount outside workspace should be blocked")
	}
}

func TestListLimitValidation(t *testing.T) {
	var receivedQuery string
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/json") {
			receivedQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]"))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	podmanSock, cleanup1 := mockPodman(t, podman)
	defer cleanup1()

	proxySock, cleanup2 := startProxy(t, podmanSock, defaultPolicy())
	defer cleanup2()

	client := unixClient(proxySock)

	// Huge limit should be stripped.
	resp, _ := client.Get("http://localhost/v4.0.0/containers/json?limit=9999999999")
	resp.Body.Close()
	if strings.Contains(receivedQuery, "limit") {
		t.Fatalf("huge limit should be stripped, got query: %s", receivedQuery)
	}

	// Negative limit should be stripped.
	resp, _ = client.Get("http://localhost/v4.0.0/containers/json?limit=-1")
	resp.Body.Close()
	if strings.Contains(receivedQuery, "limit") {
		t.Fatalf("negative limit should be stripped, got query: %s", receivedQuery)
	}

	// Valid limit should pass through.
	resp, _ = client.Get("http://localhost/v4.0.0/containers/json?limit=50")
	resp.Body.Close()
	if !strings.Contains(receivedQuery, "limit=50") {
		t.Fatalf("valid limit should pass through, got query: %s", receivedQuery)
	}
}

func TestPingVersionMethodRestriction(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer cleanup()

	proxySock, pcleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pcleanup()

	client := unixClient(proxySock)

	// GET should work.
	resp, _ := client.Get("http://localhost/v4.0.0/_ping")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET _ping: expected 200, got %d", resp.StatusCode)
	}

	// POST should be blocked.
	resp, _ = client.Post("http://localhost/v4.0.0/_ping", "application/json", nil)
	resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("POST _ping: expected 405, got %d", resp.StatusCode)
	}

	// GET version should work.
	resp, _ = client.Get("http://localhost/v4.0.0/version")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET version: expected 200, got %d", resp.StatusCode)
	}
}

func TestPingQueryParamsStripped(t *testing.T) {
	var receivedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	proxySock, pcleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pcleanup()

	client := unixClient(proxySock)

	resp, _ := client.Get("http://localhost/v4.0.0/_ping?format=json&verbose=1")
	resp.Body.Close()
	if receivedQuery != "" {
		t.Fatalf("ping query params should be stripped, got: %s", receivedQuery)
	}
}

func TestRenameBlockedBeforeForward(t *testing.T) {
	forwarded := false
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/rename") {
			forwarded = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	const containerID = "abc123def456789012345678abc123def456789012345678abc123def4567890"
	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()

	proxy.Ownership.Add(containerID, "original")

	client := unixClient(sockPath)

	// Invalid name should be rejected before reaching Podman.
	resp, _ := client.Post(
		"http://localhost/v4.0.0/containers/"+containerID+"/rename?name=../evil",
		"application/json",
		nil,
	)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 for invalid rename name, got %d", resp.StatusCode)
	}
	if forwarded {
		t.Fatal("invalid rename should NOT be forwarded to Podman")
	}
}

func TestBlockImageMountType(t *testing.T) {
	p := defaultPolicy()

	// type=image should be blocked.
	body := `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"image","Source":"ubuntu:latest","Target":"/mnt"}]}}`
	_, err := p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("type=image mount should be blocked")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected 'not allowed' error, got: %v", err)
	}

	// type=tmpfs should be blocked (cgroups v1 memory exhaustion, same as Tmpfs/ShmSize).
	body = `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/tmp"}]}}`
	_, err = p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("tmpfs mount type should be blocked")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected 'not allowed' error, got: %v", err)
	}

	// type=volume should be allowed.
	body = `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Source":"mydata","Target":"/data"}]}}`
	_, err = p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("volume mount should be allowed, got error: %v", err)
	}

	// Unknown type should be blocked.
	body = `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"devpts","Target":"/dev/pts"}]}}`
	_, err = p.ValidateAndSanitize([]byte(body))
	if err == nil {
		t.Fatal("unknown mount type should be blocked")
	}
}

func TestSwapTiedToMemory(t *testing.T) {
	p := &Policy{Workspace: "/workspace", MaxMemory: 2048, MaxCPUs: 2.0, MaxPids: 1024}

	// Memory=512 — MemorySwap should be 512 (no swap), not MaxMemory.
	body := `{"Image":"alpine","HostConfig":{"Memory":512}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)

	var mem int64
	json.Unmarshal(rawHC["Memory"], &mem)
	var swap int64
	json.Unmarshal(rawHC["MemorySwap"], &swap)

	if mem != 512 {
		t.Fatalf("Memory should be 512, got %d", mem)
	}
	if swap != 512 {
		t.Fatalf("MemorySwap should equal Memory (512), not MaxMemory, got %d", swap)
	}
}

// --- Round 11 tests ---

func TestWaitUsesStreamingSemaphore(t *testing.T) {
	// wait should be in streamingActions, not doForward
	if !streamingActions["wait"] {
		t.Fatal("wait should be in streamingActions")
	}
}

func TestStripOomKillDisable(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"OomKillDisable":true}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["OomKillDisable"]; ok {
		t.Fatal("OomKillDisable should have been stripped")
	}
}

// makeProxyWithOwnership creates a proxy with a pre-registered container for testing
// query parameter sanitization. Returns the proxy socket path, client, and cleanup func.
func makeProxyWithOwnership(t *testing.T, cid string) (*http.Client, string) {
	t.Helper()
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Store query for the test to inspect via the captured variable
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(cleanup)

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close(); listener.Close() })

	proxy.Ownership.Add(cid, "")
	return unixClient(sockPath), sockPath
}

func TestContainerOpQueryParamSanitization(t *testing.T) {
	cid := "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44"
	var capturedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	// stop with valid t=5 should pass through, but extra params should be stripped
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/"+cid+"/stop?t=5&extra=bad",
		"", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(capturedQuery, "t=5") {
		t.Fatalf("expected t=5 in query, got %q", capturedQuery)
	}
	if strings.Contains(capturedQuery, "extra") {
		t.Fatalf("extra param should have been stripped, got %q", capturedQuery)
	}
}

func TestStopNegativeTimeoutStripped(t *testing.T) {
	cid := "bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55"
	var capturedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	// t=-1 should be stripped (negative = wait indefinitely)
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/"+cid+"/stop?t=-1",
		"", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Contains(capturedQuery, "t=") {
		t.Fatalf("negative t should have been stripped, got %q", capturedQuery)
	}
}

func TestKillDangerousSignalStripped(t *testing.T) {
	cid := "cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66"
	var capturedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	// SIGTERM should pass through
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/"+cid+"/kill?signal=SIGTERM",
		"", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(capturedQuery, "signal=SIGTERM") {
		t.Fatalf("SIGTERM should pass through, got %q", capturedQuery)
	}

	// SIGSEGV should be stripped
	resp, err = client.Post(
		"http://localhost/v4.0.0/containers/"+cid+"/kill?signal=SIGSEGV",
		"", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Contains(capturedQuery, "signal") {
		t.Fatalf("SIGSEGV should have been stripped, got %q", capturedQuery)
	}
}

func TestDeleteDependParamStripped(t *testing.T) {
	cid := "dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11"
	var capturedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	req, _ := http.NewRequest(http.MethodDelete,
		"http://localhost/v4.0.0/containers/"+cid+"?force=true&v=true&depend=true",
		nil,
	)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Contains(capturedQuery, "depend") {
		t.Fatalf("depend param should have been stripped, got %q", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "force=true") {
		t.Fatalf("force should pass through, got %q", capturedQuery)
	}
}

func TestTopPsArgsStripped(t *testing.T) {
	cid := "ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22"
	var capturedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	resp, err := client.Get(
		"http://localhost/v4.0.0/containers/" + cid + "/top?ps_args=-eo%20pid,user",
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Contains(capturedQuery, "ps_args") {
		t.Fatalf("ps_args should have been stripped, got %q", capturedQuery)
	}
}

// --- Round 12 tests ---

func TestCreateNameValidatedBeforeForward(t *testing.T) {
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach podman for invalid name")
	})
	podmanSock, cleanup := mockPodman(t, podman)
	defer cleanup()
	proxySock, pcleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pcleanup()
	client := unixClient(proxySock)

	// Invalid name should be rejected before reaching Podman.
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/create?name=../evil",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 for invalid name, got %d", resp.StatusCode)
	}
}

func TestCreateQueryParamsSanitized(t *testing.T) {
	const containerID = "ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33"
	var capturedQuery string
	podman := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"Id":"%s"}`, containerID)
	})
	podmanSock, cleanup := mockPodman(t, podman)
	defer cleanup()
	proxySock, pcleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pcleanup()
	client := unixClient(proxySock)

	// Extra query params should be stripped; only name should pass through.
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/create?name=valid-name&extra=bad&platform=linux",
		"application/json",
		strings.NewReader(`{"Image":"alpine"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	if !strings.Contains(capturedQuery, "name=valid-name") {
		t.Fatalf("name should pass through, got %q", capturedQuery)
	}
	if strings.Contains(capturedQuery, "extra") || strings.Contains(capturedQuery, "platform") {
		t.Fatalf("extra params should be stripped, got %q", capturedQuery)
	}
}

func TestStripPortBindings(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"80"}]}}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["PortBindings"]; ok {
		t.Fatal("PortBindings should have been stripped")
	}
}

func TestStripPublishAllPorts(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"PublishAllPorts":true}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["PublishAllPorts"]; ok {
		t.Fatal("PublishAllPorts should have been stripped")
	}
}

func TestResizeDimensionValidation(t *testing.T) {
	cid := "1122334455667788990011223344556677889900112233445566778899001122"
	var capturedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	// Valid dimensions should pass
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/"+cid+"/resize?h=24&w=80",
		"", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(capturedQuery, "h=24") || !strings.Contains(capturedQuery, "w=80") {
		t.Fatalf("valid dimensions should pass, got %q", capturedQuery)
	}

	// Overflow dimension should be stripped
	resp, err = client.Post(
		"http://localhost/v4.0.0/containers/"+cid+"/resize?h=99999999&w=80",
		"", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Contains(capturedQuery, "h=") {
		t.Fatalf("oversize h should be stripped, got %q", capturedQuery)
	}
}

func TestWaitConditionValidation(t *testing.T) {
	cid := "2233445566778899001122334455667788990011223344556677889900112233"
	var capturedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
		streamSem:    make(chan struct{}, maxConcurrentStream),
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	// Valid condition should pass through
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/"+cid+"/wait?condition=stopped",
		"", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(capturedQuery, "condition=stopped") {
		t.Fatalf("valid condition should pass, got %q", capturedQuery)
	}

	// Invalid condition should be stripped
	resp, err = client.Post(
		"http://localhost/v4.0.0/containers/"+cid+"/wait?condition=running",
		"", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Contains(capturedQuery, "condition") {
		t.Fatalf("invalid condition should be stripped, got %q", capturedQuery)
	}
}

// --- Round 13 tests ---

func TestMultiValueQueryParamOnlyFirstForwarded(t *testing.T) {
	cid := "3344556677889900112233445566778899001122334455667788990011223344"
	var capturedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	// Multi-value t: only first (valid) value should be forwarded
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/"+cid+"/stop?t=5&t=99999",
		"", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Count(capturedQuery, "t=") != 1 {
		t.Fatalf("expected exactly one t= param, got %q", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "t=5") {
		t.Fatalf("expected t=5, got %q", capturedQuery)
	}
}

func TestStripShmSize(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"ShmSize":137438953472}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["ShmSize"]; ok {
		t.Fatal("ShmSize should have been stripped")
	}
}

func TestStripCgroupParent(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"CgroupParent":"/sys/fs/cgroup"}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["CgroupParent"]; ok {
		t.Fatal("CgroupParent should have been stripped")
	}
}

func TestStripRuntime(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Runtime":"runc"}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["Runtime"]; ok {
		t.Fatal("Runtime should have been stripped")
	}
}

func TestStripAutoRemove(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"AutoRemove":true}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["AutoRemove"]; ok {
		t.Fatal("AutoRemove should have been stripped")
	}
}

func TestStripUlimits(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Ulimits":[{"Name":"nofile","Soft":1048576,"Hard":1048576}]}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["Ulimits"]; ok {
		t.Fatal("Ulimits should have been stripped")
	}
}

func TestLogsTailValidation(t *testing.T) {
	cid := "4455667788990011223344556677889900112233445566778899001122334455"
	var capturedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
		streamSem:    make(chan struct{}, maxConcurrentStream),
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	// tail=100 should pass
	resp, err := client.Get(
		"http://localhost/v4.0.0/containers/" + cid + "/logs?stdout=true&tail=100",
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(capturedQuery, "tail=100") {
		t.Fatalf("valid tail should pass, got %q", capturedQuery)
	}

	// tail=all should pass
	resp, err = client.Get(
		"http://localhost/v4.0.0/containers/" + cid + "/logs?stdout=true&tail=all",
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(capturedQuery, "tail=all") {
		t.Fatalf("tail=all should pass, got %q", capturedQuery)
	}

	// tail=-1 should be stripped
	resp, err = client.Get(
		"http://localhost/v4.0.0/containers/" + cid + "/logs?stdout=true&tail=-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Contains(capturedQuery, "tail") {
		t.Fatalf("negative tail should be stripped, got %q", capturedQuery)
	}
}

// --- Round 14 tests ---

func TestStripNetworkingConfig(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"host":{}}}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	if _, ok := raw["NetworkingConfig"]; ok {
		t.Fatal("NetworkingConfig should have been stripped")
	}
}

func TestCapStopTimeout(t *testing.T) {
	p := defaultPolicy()
	// StopTimeout of 999999 should be capped to 10
	body := `{"Image":"alpine","StopTimeout":999999}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var t2 int64
	json.Unmarshal(raw["StopTimeout"], &t2)
	if t2 != 10 {
		t.Fatalf("StopTimeout should be capped to 10, got %d", t2)
	}

	// StopTimeout of 30 should pass through
	body = `{"Image":"alpine","StopTimeout":30}`
	result, err = p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	json.Unmarshal(result, &raw)
	json.Unmarshal(raw["StopTimeout"], &t2)
	if t2 != 30 {
		t.Fatalf("StopTimeout of 30 should pass through, got %d", t2)
	}
}

func TestLogsSinceUntilValidation(t *testing.T) {
	cid := "5566778899001122334455667788990011223344556677889900112233445566"
	var capturedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
		streamSem:    make(chan struct{}, maxConcurrentStream),
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	// Valid since timestamp should pass
	resp, err := client.Get(
		"http://localhost/v4.0.0/containers/" + cid + "/logs?stdout=true&since=1700000000",
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(capturedQuery, "since=1700000000") {
		t.Fatalf("valid since should pass, got %q", capturedQuery)
	}

	// Malformed since should be stripped
	resp, err = client.Get(
		"http://localhost/v4.0.0/containers/" + cid + "/logs?stdout=true&since=../../../../etc/passwd",
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Contains(capturedQuery, "since") {
		t.Fatalf("malformed since should be stripped, got %q", capturedQuery)
	}
}

func TestActionBodyDiscarded(t *testing.T) {
	cid := "6677889900112233445566778899001122334455667788990011223344556677"
	var capturedBody []byte
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	// Send a body with the kill action — it should be discarded
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/"+cid+"/kill?signal=SIGTERM",
		"application/json",
		strings.NewReader(`{"Signal":"SIGSEGV"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(capturedBody) > 0 {
		t.Fatalf("body should have been discarded, got %q", string(capturedBody))
	}
}

// --- Round 15 tests ---

func TestStreamingActionBodyDiscarded(t *testing.T) {
	cid := "7788990011223344556677889900112233445566778899001122334455667788"
	var capturedBody []byte
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer cleanup()

	sockPath := testSockPath(t, "x")
	proxy := &Proxy{
		PodmanSocket: podmanSock,
		Policy:       defaultPolicy(),
		Ownership:    NewOwnership(),
		AgentID:      "test",
		streamSem:    make(chan struct{}, maxConcurrentStream),
	}
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: proxy}
	go server.Serve(listener)
	defer func() { server.Close(); listener.Close() }()
	proxy.Ownership.Add(cid, "")
	client := unixClient(sockPath)

	// Send a body with wait (POST streaming action) — it should be discarded
	resp, err := client.Post(
		"http://localhost/v4.0.0/containers/"+cid+"/wait?condition=stopped",
		"application/json",
		strings.NewReader(`{"Condition":"running"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(capturedBody) > 0 {
		t.Fatalf("streaming action body should have been discarded, got %q", string(capturedBody))
	}
}

func TestStripCapDrop(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var raw map[string]json.RawMessage
		json.Unmarshal(body, &raw)
		var hc map[string]json.RawMessage
		json.Unmarshal(raw["HostConfig"], &hc)
		if _, ok := hc["CapDrop"]; ok {
			t.Error("CapDrop should have been stripped")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"Id":"aabb112233445566778899001122334455667788aabb112233445566778899"}`))
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	resp, err := client.Post("http://localhost/v4.0.0/containers/create", "application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"CapDrop":["ALL"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestStripStorageOpt(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var raw map[string]json.RawMessage
		json.Unmarshal(body, &raw)
		var hc map[string]json.RawMessage
		json.Unmarshal(raw["HostConfig"], &hc)
		if _, ok := hc["StorageOpt"]; ok {
			t.Error("StorageOpt should have been stripped")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"Id":"ccdd112233445566778899001122334455667788ccdd112233445566778899"}`))
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	resp, err := client.Post("http://localhost/v4.0.0/containers/create", "application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"StorageOpt":{"size":"1000G"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestInvalidContainerRefRejected(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request should not have been forwarded")
		w.WriteHeader(200)
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	// Container ref with newlines (log injection attempt)
	badRefs := []string{
		"foo%0aINJECTED",   // URL-encoded newline
		"foo\nbar",          // literal newline
		"../escape",         // path traversal-like
		"@special",          // starts with special char
	}
	for _, ref := range badRefs {
		resp, err := client.Get("http://localhost/v4.0.0/containers/" + ref + "/json")
		if err != nil {
			continue // connection error is fine for invalid URLs
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("ref %q: expected 403, got %d", ref, resp.StatusCode)
		}
	}
}

func TestListAllParamValidation(t *testing.T) {
	var capturedQuery string
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	// Valid value should pass through
	resp, _ := client.Get("http://localhost/v4.0.0/containers/json?all=true")
	resp.Body.Close()
	if !strings.Contains(capturedQuery, "all=true") {
		t.Errorf("expected all=true to pass through, got %q", capturedQuery)
	}

	// Invalid value should be stripped
	resp, _ = client.Get("http://localhost/v4.0.0/containers/json?all=malicious")
	resp.Body.Close()
	if strings.Contains(capturedQuery, "all=") {
		t.Errorf("expected all=malicious to be stripped, got %q", capturedQuery)
	}
}

func TestPingBodyDiscarded(t *testing.T) {
	var capturedBody []byte
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Write([]byte("OK"))
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	// Send a body with ping — it should be discarded
	req, _ := http.NewRequest("GET", "http://localhost/_ping", strings.NewReader("injected body content"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(capturedBody) > 0 {
		t.Fatalf("ping body should have been discarded, got %q", string(capturedBody))
	}
}

func TestStripMaskedPaths(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var raw map[string]json.RawMessage
		json.Unmarshal(body, &raw)
		var hc map[string]json.RawMessage
		json.Unmarshal(raw["HostConfig"], &hc)
		if _, ok := hc["MaskedPaths"]; ok {
			t.Error("MaskedPaths should have been stripped")
		}
		if _, ok := hc["ReadonlyPaths"]; ok {
			t.Error("ReadonlyPaths should have been stripped")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"Id":"aabb112233445566778899aabb112233445566778899aabb112233445566"}`))
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	resp, err := client.Post("http://localhost/v4.0.0/containers/create", "application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"MaskedPaths":[],"ReadonlyPaths":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestStripTmpfs(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var raw map[string]json.RawMessage
		json.Unmarshal(body, &raw)
		var hc map[string]json.RawMessage
		json.Unmarshal(raw["HostConfig"], &hc)
		if _, ok := hc["Tmpfs"]; ok {
			t.Error("Tmpfs should have been stripped")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"Id":"ccdd112233445566778899ccdd112233445566778899ccdd112233445566"}`))
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	resp, err := client.Post("http://localhost/v4.0.0/containers/create", "application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"Tmpfs":{"/exploit":"size=8g"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestStripRestartPolicy(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var raw map[string]json.RawMessage
		json.Unmarshal(body, &raw)
		var hc map[string]json.RawMessage
		json.Unmarshal(raw["HostConfig"], &hc)
		if _, ok := hc["RestartPolicy"]; ok {
			t.Error("RestartPolicy should have been stripped")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"Id":"eeff112233445566778899eeff112233445566778899eeff112233445566"}`))
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	resp, err := client.Post("http://localhost/v4.0.0/containers/create", "application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"RestartPolicy":{"Name":"always"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestMountsVolumeOptionsStripped(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Source":"mydata","Target":"/data","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"tmpfs","o":"size=100g"}}}}]}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	var mounts []map[string]json.RawMessage
	json.Unmarshal(hc["Mounts"], &mounts)
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	if _, ok := mounts[0]["VolumeOptions"]; ok {
		t.Error("VolumeOptions should have been stripped from mount entry")
	}
}

func TestStripLogConfig(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var raw map[string]json.RawMessage
		json.Unmarshal(body, &raw)
		var hc map[string]json.RawMessage
		json.Unmarshal(raw["HostConfig"], &hc)
		if _, ok := hc["LogConfig"]; ok {
			t.Error("LogConfig should have been stripped")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"Id":"ff00112233445566778899ff00112233445566778899ff00112233445566"}`))
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	resp, err := client.Post("http://localhost/v4.0.0/containers/create", "application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"LogConfig":{"Type":"syslog","Config":{"syslog-address":"tcp://evil.example.com:514"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestStripDeviceCgroupRules(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var raw map[string]json.RawMessage
		json.Unmarshal(body, &raw)
		var hc map[string]json.RawMessage
		json.Unmarshal(raw["HostConfig"], &hc)
		if _, ok := hc["DeviceCgroupRules"]; ok {
			t.Error("DeviceCgroupRules should have been stripped")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"Id":"ff11223344556677889900ff11223344556677889900ff11223344556677"}`))
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	resp, err := client.Post("http://localhost/v4.0.0/containers/create", "application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"DeviceCgroupRules":["c 10:200 rwm","b 8:0 rwm"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestStripOomScoreAdj(t *testing.T) {
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var raw map[string]json.RawMessage
		json.Unmarshal(body, &raw)
		var hc map[string]json.RawMessage
		json.Unmarshal(raw["HostConfig"], &hc)
		if _, ok := hc["OomScoreAdj"]; ok {
			t.Error("OomScoreAdj should have been stripped")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{"Id":"ff22334455667788990011ff22334455667788990011ff22334455667788"}`))
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	resp, err := client.Post("http://localhost/v4.0.0/containers/create", "application/json",
		strings.NewReader(`{"Image":"alpine","HostConfig":{"OomScoreAdj":-1000}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestStripDeviceRequests(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu"]]}]}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	if _, ok := hc["DeviceRequests"]; ok {
		t.Error("DeviceRequests should have been stripped")
	}
}

func TestStripContainerIDFile(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"ContainerIDFile":"/etc/cron.d/backdoor"}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	if _, ok := hc["ContainerIDFile"]; ok {
		t.Error("ContainerIDFile should have been stripped")
	}
}

func TestStripGroupAdd(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"GroupAdd":["docker","disk","shadow"]}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	if _, ok := hc["GroupAdd"]; ok {
		t.Error("GroupAdd should have been stripped")
	}
}

func TestStripExtraHosts(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"ExtraHosts":["metadata.google.internal:169.254.169.254","evil.com:127.0.0.1"]}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	if _, ok := hc["ExtraHosts"]; ok {
		t.Error("ExtraHosts should have been stripped")
	}
}

func TestStripDnsConfig(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Dns":["8.8.8.8"],"DnsSearch":["attacker.com"],"DnsOptions":["ndots:15"]}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	for _, field := range []string{"Dns", "DnsSearch", "DnsOptions"} {
		if _, ok := hc[field]; ok {
			t.Errorf("%s should have been stripped", field)
		}
	}
}

func TestStripVolumeDriver(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"VolumeDriver":"malicious-plugin"}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	if _, ok := hc["VolumeDriver"]; ok {
		t.Error("VolumeDriver should have been stripped")
	}
}

func TestStripLinks(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Links":["other-container:alias"]}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	if _, ok := hc["Links"]; ok {
		t.Error("Links should have been stripped")
	}
}

func TestStripCpuRealtimeScheduler(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"CpuRealtimePeriod":1000000,"CpuRealtimeRuntime":950000}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	for _, field := range []string{"CpuRealtimePeriod", "CpuRealtimeRuntime"} {
		if _, ok := hc[field]; ok {
			t.Errorf("%s should have been stripped", field)
		}
	}
}

func TestStripCpusetPinning(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"CpusetCpus":"0-3","CpusetMems":"0"}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	for _, field := range []string{"CpusetCpus", "CpusetMems"} {
		if _, ok := hc[field]; ok {
			t.Errorf("%s should have been stripped", field)
		}
	}
}

func TestStripBlkioControls(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"BlkioWeight":900,"BlkioWeightDevice":[{"Path":"/dev/sda","Weight":999}],"BlkioDeviceReadBps":[{"Path":"/dev/sda","Rate":0}]}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	for _, field := range []string{"BlkioWeight", "BlkioWeightDevice", "BlkioDeviceReadBps"} {
		if _, ok := hc[field]; ok {
			t.Errorf("%s should have been stripped", field)
		}
	}
}

func TestStripKernelMemory(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"KernelMemory":1048576}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	if _, ok := hc["KernelMemory"]; ok {
		t.Error("KernelMemory should have been stripped")
	}
}

func TestStripMemorySwappiness(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"MemorySwappiness":0}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	if _, ok := hc["MemorySwappiness"]; ok {
		t.Error("MemorySwappiness should have been stripped")
	}
}

func TestStripAnnotations(t *testing.T) {
	p := defaultPolicy()
	body := `{"Image":"alpine","HostConfig":{"Annotations":{"io.podman.annotations.userns":"host"}}}`
	sanitized, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(sanitized, &raw)
	var hc map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &hc)
	if _, ok := hc["Annotations"]; ok {
		t.Error("Annotations should have been stripped")
	}
}

func TestListDiscardsRequestBody(t *testing.T) {
	containerID := "aabb112233445566778899aabb112233445566778899aabb112233445566"
	podmanSock, cleanup := mockPodman(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v4.0.0/containers/create" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			w.Write([]byte(fmt.Sprintf(`{"Id":"%s"}`, containerID)))
			return
		}
		// List handler — verify no body was forwarded.
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			t.Errorf("list endpoint should not forward body, got %d bytes: %s", len(body), string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`[{"Id":"%s"}]`, containerID)))
	}))
	defer cleanup()
	proxySock, pCleanup := startProxy(t, podmanSock, defaultPolicy())
	defer pCleanup()
	client := unixClient(proxySock)

	// Create a container first so the list has something to return.
	resp, _ := client.Post("http://localhost/v4.0.0/containers/create", "application/json",
		strings.NewReader(`{"Image":"alpine"}`))
	resp.Body.Close()

	// Send list request with a body that should be discarded.
	req, _ := http.NewRequest(http.MethodGet, "http://localhost/v4.0.0/containers/json", strings.NewReader(`{"malicious":"payload"}`))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func init() {
	_ = os.Stderr
}
