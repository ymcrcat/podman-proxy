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
	NanoCpus     int64    `json:"NanoCpus,omitempty"`
	CpuPeriod    int64    `json:"CpuPeriod,omitempty"`
	CpuQuota     int64    `json:"CpuQuota,omitempty"`
}

// mountEntry is the subset of a Mounts entry we validate.
type mountEntry struct {
	Type   string `json:"Type"`
	Source string `json:"Source"`
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

	// Parse HostConfig if present.
	hcRaw, hcPresent := raw["HostConfig"]
	if !hcPresent || string(hcRaw) == "null" {
		// No HostConfig — still re-marshal to collapse duplicate top-level keys.
		return json.Marshal(raw)
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

	if strings.EqualFold(hc.NetworkMode, "host") {
		return nil, fmt.Errorf("host network mode is not allowed")
	}
	if strings.EqualFold(hc.PidMode, "host") {
		return nil, fmt.Errorf("host PID mode is not allowed")
	}
	if strings.EqualFold(hc.IpcMode, "host") {
		return nil, fmt.Errorf("host IPC mode is not allowed")
	}
	if strings.EqualFold(hc.UTSMode, "host") {
		return nil, fmt.Errorf("host UTS mode is not allowed")
	}
	if strings.EqualFold(hc.UsernsMode, "host") {
		return nil, fmt.Errorf("host user namespace mode is not allowed")
	}
	if strings.EqualFold(hc.CgroupnsMode, "host") {
		return nil, fmt.Errorf("host cgroup namespace mode is not allowed")
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

	// Cap memory.
	if p.MaxMemory > 0 && hc.Memory > p.MaxMemory {
		b, _ := json.Marshal(p.MaxMemory)
		rawHC["Memory"] = b
	}

	// Cap CPUs via NanoCpus.
	if p.MaxCPUs > 0 {
		maxNano := int64(p.MaxCPUs * 1e9)
		if hc.NanoCpus > maxNano {
			b, _ := json.Marshal(maxNano)
			rawHC["NanoCpus"] = b
		}
		// Also cap CpuQuota relative to CpuPeriod.
		// When CpuPeriod is 0 the kernel defaults to 100000µs.
		if hc.CpuQuota > 0 {
			period := hc.CpuPeriod
			if period <= 0 {
				period = 100000 // kernel default
			}
			maxQuota := int64(p.MaxCPUs * float64(period))
			if hc.CpuQuota > maxQuota {
				b, _ := json.Marshal(maxQuota)
				rawHC["CpuQuota"] = b
			}
		}
	}

	// Write sanitized HostConfig back into the top-level raw map.
	hcBytes, err := json.Marshal(rawHC)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal HostConfig: %w", err)
	}
	raw["HostConfig"] = hcBytes

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
		parts := strings.SplitN(bind, ":", 2)
		if len(parts) < 2 {
			continue // named volume, not a host path bind
		}
		hostPath := parts[0]
		if hostPath == "" {
			return fmt.Errorf("empty host path in bind mount")
		}
		if err := p.validateHostPath(hostPath); err != nil {
			return err
		}
	}
	return nil
}

// validateMounts checks that all bind-type Mounts have sources under the workspace.
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
		if strings.EqualFold(m.Type, "bind") {
			if m.Source == "" {
				return fmt.Errorf("empty source in bind mount")
			}
			if err := p.validateHostPath(m.Source); err != nil {
				return err
			}
		}
	}
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
