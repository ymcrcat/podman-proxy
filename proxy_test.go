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

func TestCapCpuQuotaWithoutPeriod(t *testing.T) {
	p := &Policy{Workspace: "/workspace", MaxMemory: 2e9, MaxCPUs: 1.0}
	// CpuQuota without CpuPeriod — should be capped using kernel default period (100000).
	body := `{"Image":"alpine","HostConfig":{"CpuQuota":9999999}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	var quota int64
	json.Unmarshal(rawHC["CpuQuota"], &quota)
	// MaxCPUs=1.0, default period=100000, so max quota = 100000
	if quota != 100000 {
		t.Fatalf("expected CpuQuota capped to 100000, got %d", quota)
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
	// PortBindings is not in our hostConfig struct — it should be preserved.
	body := `{"Image":"alpine","HostConfig":{"NetworkMode":"bridge","PortBindings":{"80/tcp":[{"HostPort":"8080"}]}}}`
	result, err := p.ValidateAndSanitize([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(result, &raw)
	var rawHC map[string]json.RawMessage
	json.Unmarshal(raw["HostConfig"], &rawHC)
	if _, ok := rawHC["PortBindings"]; !ok {
		t.Fatal("PortBindings was lost during re-marshal")
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
			id := "abc123def456789012345678"
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"Id": id})
			return
		}
		if strings.Contains(r.URL.Path, "/containers/json") {
			containers := []map[string]interface{}{
				{"Id": "abc123def456789012345678", "Names": []string{"/my-container"}},
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
	if listed[0]["Id"] != "abc123def456789012345678" {
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
	containerID := "abc123def456789012345678"
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
	containerID := "abc123def456789012345678"
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
		json.NewEncoder(w).Encode(map[string]string{"Id": "test1234567890ab"})
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
	containerID := "abc123def456789012345678"
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
	containerID := "abc123def456789012345678"
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
	containerID := "abc123def456789012345678"
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
	containerID := "abc123def456789012345678"
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
	containerID := "abc123def456789012345678"
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
	containerID := "abc123def456789012345678"
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

func init() {
	_ = os.Stderr
}
