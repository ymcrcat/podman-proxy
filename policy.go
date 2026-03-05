package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Policy holds the security configuration for the proxy.
type Policy struct {
	Workspace     string
	AllowedImages []string // empty = allow all
	MaxMemory     int64    // bytes, 0 = no limit
	MaxCPUs       float64  // 0 = no limit
	MaxPids       int64    // 0 = no limit
}

// allowedCaps is the allowlist of capabilities that may be added to containers.
// Any capability not in this set (including "ALL") is stripped.
var allowedCaps = map[string]bool{
	"AUDIT_WRITE":       true,
	"CHOWN":             true,
	"DAC_OVERRIDE":      true,
	"FOWNER":            true,
	"FSETID":            true,
	"KILL":              true,
	"NET_BIND_SERVICE":  true,
	"SETFCAP":           true,
	"SETGID":            true,
	"SETPCAP":           true,
	"SETUID":            true,
	"SYS_CHROOT":        true,
	"NET_RAW":           true,
}

// hostConfig is the subset of HostConfig fields we inspect for validation.
// We use a separate raw map to preserve unknown fields during re-marshaling.
type hostConfig struct {
	Privileged   bool     `json:"Privileged,omitempty"`
	NetworkMode  string   `json:"NetworkMode,omitempty"`
	PidMode      string   `json:"PidMode,omitempty"`
	IpcMode      string   `json:"IpcMode,omitempty"`
	UTSMode      string   `json:"UTSMode,omitempty"`
	UsernsMode   string   `json:"UsernsMode,omitempty"`
	CgroupnsMode string   `json:"CgroupnsMode,omitempty"`
	Binds        []string `json:"Binds,omitempty"`
	CapAdd       []string `json:"CapAdd,omitempty"`
	Memory       int64    `json:"Memory,omitempty"`
	MemorySwap   int64    `json:"MemorySwap,omitempty"`
	NanoCpus     int64    `json:"NanoCpus,omitempty"`
	CpuPeriod    int64    `json:"CpuPeriod,omitempty"`
	CpuQuota     int64    `json:"CpuQuota,omitempty"`
	PidsLimit    int64    `json:"PidsLimit,omitempty"`
}

// mountEntry is the subset of a Mounts entry we validate.
type mountEntry struct {
	Type   string `json:"Type"`
	Source string `json:"Source"`
}

// isUnsafeMode returns true if the namespace mode would share namespaces with
// the host or another entity. Blocks three forms:
//   - "host" — shares the host's namespace directly
//   - "container:<id>" — shares another container's namespace
//   - "ns:<path>" — joins a namespace by filesystem path (e.g. /proc/1/ns/net)
func isUnsafeMode(mode string) bool {
	lower := strings.ToLower(mode)
	return lower == "host" ||
		strings.HasPrefix(lower, "container:") ||
		strings.HasPrefix(lower, "ns:")
}

// ValidateAndSanitize checks the container create body against the policy.
// It always re-marshals through parsed maps to collapse duplicate JSON keys,
// preventing smuggling attacks where Go and Podman parse duplicates differently.
func (p *Policy) ValidateAndSanitize(body []byte) ([]byte, error) {
	// Parse top-level into raw map — collapses duplicate top-level keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}

	// Parse Image for allowlist check.
	var image struct {
		Image string `json:"Image"`
	}
	if err := json.Unmarshal(body, &image); err != nil {
		return nil, fmt.Errorf("invalid container create body: %w", err)
	}

	// Image allowlist check.
	// NOTE: uses exact string match. Callers must use the same format
	// (e.g., "alpine" vs "docker.io/library/alpine:latest") in both the
	// allowlist and create requests.
	if len(p.AllowedImages) > 0 {
		allowed := false
		for _, img := range p.AllowedImages {
			if img == image.Image {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("image %q not in allowlist", image.Image)
		}
	}

	// Parse HostConfig if present. When absent or null, create an empty one
	// so that resource limits (Memory, CPU, PIDs) are still enforced below.
	hcRaw, hcPresent := raw["HostConfig"]
	if !hcPresent || string(hcRaw) == "null" {
		hcRaw = json.RawMessage(`{}`)
	}

	// Parse HostConfig into its own raw map to preserve unknown fields.
	var rawHC map[string]json.RawMessage
	if err := json.Unmarshal(hcRaw, &rawHC); err != nil {
		return nil, fmt.Errorf("invalid HostConfig: %w", err)
	}

	// Parse into typed struct for validation.
	var hc hostConfig
	if err := json.Unmarshal(hcRaw, &hc); err != nil {
		return nil, fmt.Errorf("invalid HostConfig fields: %w", err)
	}

	// --- Hard blocks ---

	if hc.Privileged {
		return nil, fmt.Errorf("privileged containers are not allowed")
	}

	if isUnsafeMode(hc.NetworkMode) {
		return nil, fmt.Errorf("host/container network mode is not allowed")
	}
	if isUnsafeMode(hc.PidMode) {
		return nil, fmt.Errorf("host/container PID mode is not allowed")
	}
	if isUnsafeMode(hc.IpcMode) {
		return nil, fmt.Errorf("host/container IPC mode is not allowed")
	}
	if isUnsafeMode(hc.UTSMode) {
		return nil, fmt.Errorf("host/container UTS mode is not allowed")
	}
	if isUnsafeMode(hc.UsernsMode) {
		return nil, fmt.Errorf("host/container user namespace mode is not allowed")
	}
	if isUnsafeMode(hc.CgroupnsMode) {
		return nil, fmt.Errorf("host/container cgroup namespace mode is not allowed")
	}

	// Validate bind mounts (legacy Binds format).
	if err := p.validateBinds(hc.Binds); err != nil {
		return nil, err
	}

	// Validate structured Mounts (modern format — same workspace rules).
	if err := p.validateMounts(rawHC); err != nil {
		return nil, err
	}

	// --- Silent sanitization (written back into rawHC) ---

	// Strip capabilities not in the allowlist (including "ALL").
	if len(hc.CapAdd) > 0 {
		filtered := make([]string, 0, len(hc.CapAdd))
		for _, cap := range hc.CapAdd {
			if allowedCaps[strings.ToUpper(cap)] {
				filtered = append(filtered, cap)
			}
		}
		b, _ := json.Marshal(filtered)
		rawHC["CapAdd"] = b
	}

	// Strip all device mappings.
	delete(rawHC, "Devices")

	// Strip SecurityOpt (blocks seccomp=unconfined, apparmor=unconfined, etc.).
	delete(rawHC, "SecurityOpt")

	// Strip Sysctls (blocks arbitrary kernel parameter modification).
	delete(rawHC, "Sysctls")

	// Strip VolumesFrom — allows mounting volumes from arbitrary containers,
	// bypassing workspace bind-mount restrictions.
	delete(rawHC, "VolumesFrom")

	// Strip OomKillDisable — on cgroups v1, disabling the OOM killer causes
	// the kernel to kill arbitrary host processes when the container exhausts
	// its memory limit.
	delete(rawHC, "OomKillDisable")

	// Strip PortBindings — prevents agents from binding to host ports,
	// which could expose services on external interfaces or steal ports
	// from other host services.
	delete(rawHC, "PortBindings")

	// Strip PublishAllPorts — same rationale as PortBindings.
	delete(rawHC, "PublishAllPorts")

	// Strip ShmSize — on cgroups v1, /dev/shm tmpfs memory is not counted
	// against the cgroup Memory limit, allowing memory exhaustion beyond MaxMemory.
	delete(rawHC, "ShmSize")

	// Strip CgroupParent — prevents agents from placing containers in
	// arbitrary cgroup hierarchies, bypassing resource accounting.
	delete(rawHC, "CgroupParent")

	// Strip Runtime — prevents agents from downgrading to a less secure
	// OCI runtime if the operator configured a secure default.
	delete(rawHC, "Runtime")

	// Strip AutoRemove — containers that self-remove leave stale entries
	// in the ownership table. Agents should use explicit DELETE instead.
	delete(rawHC, "AutoRemove")

	// Strip Ulimits — prevents RLIMIT_NOFILE exhaustion and other
	// per-container resource limit manipulation.
	delete(rawHC, "Ulimits")

	// Strip CapDrop — agents should not manipulate which capabilities are
	// dropped from the default set. On some runtimes an empty CapDrop can
	// re-grant capabilities that the default OCI profile drops.
	delete(rawHC, "CapDrop")

	// Strip StorageOpt — prevents agents from setting unbounded container
	// storage quotas (e.g. size=1000G) that could exhaust host disk space.
	delete(rawHC, "StorageOpt")

	// Strip MaskedPaths and ReadonlyPaths — setting these to empty arrays
	// removes the OCI default masking of /proc/kcore, /proc/sched_debug,
	// /sys/firmware, etc. Tenants must not expose sensitive kernel interfaces.
	delete(rawHC, "MaskedPaths")
	delete(rawHC, "ReadonlyPaths")

	// Strip Tmpfs — on cgroups v1, tmpfs memory is not counted against the
	// cgroup Memory limit, allowing memory exhaustion beyond MaxMemory.
	// Same rationale as ShmSize.
	delete(rawHC, "Tmpfs")

	// Strip RestartPolicy — containers with "always" restart policy survive
	// proxy shutdown, evading cleanup and running without ownership tracking.
	delete(rawHC, "RestartPolicy")

	// Cap memory. Always enforce when MaxMemory is configured (Memory=0 means
	// unlimited in Podman, which would bypass the limit).
	effectiveMemory := hc.Memory
	if p.MaxMemory > 0 {
		if hc.Memory <= 0 || hc.Memory > p.MaxMemory {
			effectiveMemory = p.MaxMemory
			b, _ := json.Marshal(p.MaxMemory)
			rawHC["Memory"] = b
		}
	}

	// Disable swap by setting MemorySwap == effectiveMemory. In Linux cgroups,
	// MemorySwap is the total memory+swap limit, so setting it equal to Memory
	// means zero swap. Previously this was set to MaxMemory, which allowed
	// (MaxMemory - Memory) bytes of swap when Memory < MaxMemory.
	if p.MaxMemory > 0 && effectiveMemory > 0 {
		b, _ := json.Marshal(effectiveMemory)
		rawHC["MemorySwap"] = b
	}

	// Cap CPUs via NanoCpus. Always enforce when MaxCPUs is configured
	// (NanoCpus=0 means unlimited in Podman, which would bypass the limit).
	// Delete CpuQuota and CpuPeriod since Podman rejects requests that set
	// both NanoCpus and CpuQuota/CpuPeriod simultaneously. NanoCpus is the
	// higher-level API that Podman converts to CFS parameters internally.
	if p.MaxCPUs > 0 {
		maxNano := int64(p.MaxCPUs * 1e9)
		if hc.NanoCpus <= 0 || hc.NanoCpus > maxNano {
			b, _ := json.Marshal(maxNano)
			rawHC["NanoCpus"] = b
		}
		// Remove CpuQuota/CpuPeriod to prevent conflict with NanoCpus.
		// This also closes the CpuQuota<=0 bypass since NanoCpus is always enforced.
		delete(rawHC, "CpuQuota")
		delete(rawHC, "CpuPeriod")
	}

	// Enforce PidsLimit to prevent fork bomb DoS.
	// Always set a limit when MaxPids is configured, even if the tenant
	// didn't request one (PidsLimit=0 or -1 means unlimited in Podman).
	if p.MaxPids > 0 {
		if hc.PidsLimit <= 0 || hc.PidsLimit > p.MaxPids {
			b, _ := json.Marshal(p.MaxPids)
			rawHC["PidsLimit"] = b
		}
	}

	// Write sanitized HostConfig back into the top-level raw map.
	hcBytes, err := json.Marshal(rawHC)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal HostConfig: %w", err)
	}
	raw["HostConfig"] = hcBytes

	// --- Top-level field sanitization ---

	// Strip NetworkingConfig — allows joining arbitrary host networks,
	// bypassing the HostConfig.NetworkMode restriction.
	delete(raw, "NetworkingConfig")

	// Cap StopTimeout — controls how long Podman waits for SIGTERM before
	// SIGKILL. Extreme values can delay container cleanup on shutdown.
	if v, ok := raw["StopTimeout"]; ok && string(v) != "null" {
		var t int64
		if json.Unmarshal(v, &t) == nil && (t < 0 || t > 300) {
			b, _ := json.Marshal(int64(10))
			raw["StopTimeout"] = b
		}
	}

	// Always re-marshal to collapse any duplicate keys.
	result, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal body: %w", err)
	}
	return result, nil
}

// validateBinds checks that all bind mounts (legacy Binds format) are under the workspace.
func (p *Policy) validateBinds(binds []string) error {
	for _, bind := range binds {
		// Bind format: "host_path:container_path[:options]"
		// Named volume format: "volume_name:container_path[:options]"
		// Anonymous volume format: "container_path" (no colon)
		parts := strings.SplitN(bind, ":", 2)
		if len(parts) < 2 {
			continue // anonymous volume — no host path
		}
		hostPath := parts[0]
		if hostPath == "" {
			return fmt.Errorf("empty host path in bind mount")
		}
		// Named volumes have no leading slash — they are managed by the
		// container runtime, not host filesystem paths.
		if !filepath.IsAbs(hostPath) {
			continue
		}
		if err := p.validateHostPath(hostPath); err != nil {
			return err
		}
	}
	return nil
}

// validateMounts checks Mounts using an allowlist of safe types and sanitizes
// mount options. Only bind (with workspace path validation) and volume are
// permitted. Tmpfs and other types are rejected.
func (p *Policy) validateMounts(rawHC map[string]json.RawMessage) error {
	mountsRaw, ok := rawHC["Mounts"]
	if !ok || len(mountsRaw) == 0 || string(mountsRaw) == "null" {
		return nil
	}
	var mounts []mountEntry
	if err := json.Unmarshal(mountsRaw, &mounts); err != nil {
		return fmt.Errorf("invalid Mounts field: %w", err)
	}
	for _, m := range mounts {
		switch strings.ToLower(m.Type) {
		case "bind":
			if m.Source == "" {
				return fmt.Errorf("empty source in bind mount")
			}
			if err := p.validateHostPath(m.Source); err != nil {
				return err
			}
		case "volume":
			// Named volumes — no host path to validate. Volume management
			// endpoints are blocked so agents can't create arbitrary volumes.
			// VolumeOptions/DriverConfig stripped below.
		case "tmpfs":
			// Rejected — on cgroups v1, tmpfs memory is not counted against
			// the cgroup Memory limit. Same rationale as stripping the Tmpfs
			// HostConfig field and ShmSize.
			return fmt.Errorf("mount type %q is not allowed (use container defaults)", m.Type)
		default:
			return fmt.Errorf("mount type %q is not allowed", m.Type)
		}
	}

	// Sanitize mount options: strip VolumeOptions (DriverConfig can create
	// tmpfs-backed volumes bypassing memory limits), BindOptions (propagation
	// control), and TmpfsOptions from all entries.
	var rawMounts []map[string]json.RawMessage
	if err := json.Unmarshal(mountsRaw, &rawMounts); err != nil {
		return fmt.Errorf("invalid Mounts field: %w", err)
	}
	for _, entry := range rawMounts {
		delete(entry, "VolumeOptions")
		delete(entry, "BindOptions")
		delete(entry, "TmpfsOptions")
	}
	sanitized, _ := json.Marshal(rawMounts)
	rawHC["Mounts"] = sanitized

	return nil
}

// validateHostPath checks that a host path is under the workspace prefix.
func (p *Policy) validateHostPath(hostPath string) error {
	// Empty workspace = block all bind mounts (fail-safe).
	if p.Workspace == "" {
		return fmt.Errorf("bind mount %q not allowed: no workspace configured", hostPath)
	}

	wsAbs, err := filepath.Abs(p.Workspace)
	if err != nil {
		return fmt.Errorf("failed to resolve workspace path: %w", err)
	}
	wsReal, err := filepath.EvalSymlinks(wsAbs)
	if err != nil {
		wsReal = wsAbs
	}

	absPath, err := filepath.Abs(hostPath)
	if err != nil {
		return fmt.Errorf("invalid bind mount path %q: %w", hostPath, err)
	}

	// Reject if the user-supplied path itself is a symlink (pre-resolution).
	// This reduces the TOCTOU window where a directory could be swapped for
	// a symlink between validation and the actual mount by podman.
	if info, err := os.Lstat(absPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("bind mount %q is a symlink (not allowed)", hostPath)
		}
	}

	// Resolve symlinks to get canonical path.
	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		// Path may not exist yet — resolve the nearest existing ancestor.
		realPath = resolvePartial(absPath)
	}

	if !isSubpath(wsReal, realPath) {
		return fmt.Errorf("bind mount %q is outside workspace %q", hostPath, p.Workspace)
	}
	return nil
}

// resolvePartial resolves symlinks on the longest existing prefix of a path,
// then appends the remaining unresolved tail. This handles cases like
// /tmp/foo/nonexistent where /tmp is a symlink to /private/tmp.
func resolvePartial(p string) string {
	clean := filepath.Clean(p)
	tail := ""
	cur := clean
	for cur != "/" && cur != "." {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			if tail == "" {
				return resolved
			}
			return filepath.Join(resolved, tail)
		}
		tail = filepath.Join(filepath.Base(cur), tail)
		cur = filepath.Dir(cur)
	}
	return clean
}

// isSubpath returns true if child is equal to or under parent.
func isSubpath(parent, child string) bool {
	parentSlash := parent
	if !strings.HasSuffix(parentSlash, string(filepath.Separator)) {
		parentSlash += string(filepath.Separator)
	}
	return child == parent || strings.HasPrefix(child, parentSlash)
}

// minPrefixLen is the minimum length for prefix-based container ID matching.
// This prevents single-character prefixes from matching unrelated containers
// in multi-tenant deployments.
const minPrefixLen = 12

// Ownership tracks which containers were created through this proxy.
type Ownership struct {
	mu       sync.RWMutex
	ids      map[string]bool   // full container IDs
	names    map[string]string // container name -> full ID
	idToName map[string]string // full ID -> container name
}

func NewOwnership() *Ownership {
	return &Ownership{
		ids:      make(map[string]bool),
		names:    make(map[string]string),
		idToName: make(map[string]string),
	}
}

// Add registers a container ID as owned, with an optional name.
// Passing an empty name registers the ID only.
func (o *Ownership) Add(id, name string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ids[id] = true
	if name != "" {
		o.names[name] = id
		o.idToName[id] = name
	}
}

// Rename updates the name associated with a container ID.
// Removes the old name mapping and sets the new one.
func (o *Ownership) Rename(id, newName string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	// Remove old name mapping.
	if oldName, ok := o.idToName[id]; ok {
		delete(o.names, oldName)
		delete(o.idToName, id)
	}
	// Set new name if provided.
	if newName != "" {
		o.names[newName] = id
		o.idToName[id] = newName
	}
}

// Remove unregisters a container ID and its associated name.
func (o *Ownership) Remove(id string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.ids, id)
	if name, ok := o.idToName[id]; ok {
		delete(o.names, name)
		delete(o.idToName, id)
	}
}

// Owns checks if the given reference (full ID, name, or ID prefix) matches an owned container.
func (o *Ownership) Owns(ref string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()

	// Exact ID match.
	if o.ids[ref] {
		return true
	}
	// Name match.
	if _, ok := o.names[ref]; ok {
		return true
	}
	// Prefix match — only if ref is long enough to avoid cross-tenant collisions.
	if len(ref) >= minPrefixLen {
		for id := range o.ids {
			if strings.HasPrefix(id, ref) {
				return true
			}
		}
	}
	return false
}

// FullID resolves a reference to a full container ID, or returns "" if not owned.
// Returns "" if the prefix is ambiguous (matches multiple owned containers).
func (o *Ownership) FullID(ref string) string {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.ids[ref] {
		return ref
	}
	if id, ok := o.names[ref]; ok {
		return id
	}
	if len(ref) >= minPrefixLen {
		var match string
		for id := range o.ids {
			if strings.HasPrefix(id, ref) {
				if match != "" {
					return "" // ambiguous prefix
				}
				match = id
			}
		}
		return match
	}
	return ""
}

// IDs returns a copy of all owned container IDs.
func (o *Ownership) IDs() []string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	ids := make([]string, 0, len(o.ids))
	for id := range o.ids {
		ids = append(ids, id)
	}
	return ids
}
