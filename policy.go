package main

import (
	"encoding/json"
	"fmt"
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

// dangerousCaps are capabilities that must always be stripped.
var dangerousCaps = map[string]bool{
	"SYS_ADMIN":  true,
	"SYS_PTRACE": true,
	"NET_ADMIN":  true,
	"NET_RAW":    true,
	"SYS_RAWIO":  true,
	"MKNOD":      true,
}

// containerCreate is the subset of the container create body we inspect.
// Unknown fields pass through untouched since we re-marshal only what we parse.
type containerCreate struct {
	Image      string      `json:"Image"`
	HostConfig *hostConfig `json:"HostConfig,omitempty"`
	// We keep the raw JSON so we can patch and forward the rest opaquely.
}

type hostConfig struct {
	Privileged  bool          `json:"Privileged,omitempty"`
	NetworkMode string        `json:"NetworkMode,omitempty"`
	PidMode     string        `json:"PidMode,omitempty"`
	Binds       []string      `json:"Binds,omitempty"`
	CapAdd      []string      `json:"CapAdd,omitempty"`
	Devices     []interface{} `json:"Devices,omitempty"`
	Memory      int64         `json:"Memory,omitempty"`
	NanoCpus    int64         `json:"NanoCpus,omitempty"`
	CpuPeriod   int64         `json:"CpuPeriod,omitempty"`
	CpuQuota    int64         `json:"CpuQuota,omitempty"`
}

// ValidateAndSanitize checks the container create body against the policy.
// It returns the (possibly modified) body bytes, or an error describing the violation.
func (p *Policy) ValidateAndSanitize(body []byte) ([]byte, error) {
	// Parse into a generic map so we can modify and re-marshal without losing fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}

	// Also parse into our struct for typed access.
	var cc containerCreate
	if err := json.Unmarshal(body, &cc); err != nil {
		return nil, fmt.Errorf("invalid container create body: %w", err)
	}

	// Image allowlist check.
	if len(p.AllowedImages) > 0 {
		allowed := false
		for _, img := range p.AllowedImages {
			if img == cc.Image {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("image %q not in allowlist", cc.Image)
		}
	}

	if cc.HostConfig == nil {
		return body, nil
	}

	hc := cc.HostConfig

	// Block privileged.
	if hc.Privileged {
		return nil, fmt.Errorf("privileged containers are not allowed")
	}

	// Block host network and pid modes.
	if strings.EqualFold(hc.NetworkMode, "host") {
		return nil, fmt.Errorf("host network mode is not allowed")
	}
	if strings.EqualFold(hc.PidMode, "host") {
		return nil, fmt.Errorf("host PID mode is not allowed")
	}

	// Restrict volume mounts.
	if err := p.validateBinds(hc.Binds); err != nil {
		return nil, err
	}

	// Now we apply silent mutations — resource caps, capability stripping, device removal.
	modified := false

	// Strip dangerous capabilities.
	if len(hc.CapAdd) > 0 {
		filtered := make([]string, 0, len(hc.CapAdd))
		for _, cap := range hc.CapAdd {
			if !dangerousCaps[strings.ToUpper(cap)] {
				filtered = append(filtered, cap)
			}
		}
		if len(filtered) != len(hc.CapAdd) {
			hc.CapAdd = filtered
			modified = true
		}
	}

	// Strip devices.
	if len(hc.Devices) > 0 {
		hc.Devices = nil
		modified = true
	}

	// Cap memory.
	if p.MaxMemory > 0 && hc.Memory > p.MaxMemory {
		hc.Memory = p.MaxMemory
		modified = true
	}

	// Cap CPUs (NanoCpus takes precedence, then CpuQuota/CpuPeriod).
	if p.MaxCPUs > 0 {
		maxNano := int64(p.MaxCPUs * 1e9)
		if hc.NanoCpus > maxNano {
			hc.NanoCpus = maxNano
			modified = true
		}
		// Also cap CpuQuota relative to CpuPeriod.
		if hc.CpuPeriod > 0 && hc.CpuQuota > 0 {
			maxQuota := int64(p.MaxCPUs * float64(hc.CpuPeriod))
			if hc.CpuQuota > maxQuota {
				hc.CpuQuota = maxQuota
				modified = true
			}
		}
	}

	if !modified {
		return body, nil
	}

	// Re-marshal the HostConfig back into the raw map.
	hcBytes, err := json.Marshal(hc)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal HostConfig: %w", err)
	}
	raw["HostConfig"] = hcBytes

	result, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal body: %w", err)
	}
	return result, nil
}

// validateBinds checks that all bind mounts are under the workspace prefix.
func (p *Policy) validateBinds(binds []string) error {
	if p.Workspace == "" {
		return nil
	}
	wsAbs, err := filepath.Abs(p.Workspace)
	if err != nil {
		return fmt.Errorf("failed to resolve workspace path: %w", err)
	}
	// Evaluate symlinks on the workspace itself.
	wsReal, err := filepath.EvalSymlinks(wsAbs)
	if err != nil {
		// If workspace doesn't exist yet, use the absolute path.
		wsReal = wsAbs
	}

	for _, bind := range binds {
		// Bind format: "host_path:container_path[:options]"
		parts := strings.SplitN(bind, ":", 2)
		if len(parts) < 2 {
			continue // named volume, not a host path bind
		}
		hostPath := parts[0]
		absPath, err := filepath.Abs(hostPath)
		if err != nil {
			return fmt.Errorf("invalid bind mount path %q: %w", hostPath, err)
		}
		// Resolve symlinks and ".." to get canonical path.
		realPath, err := filepath.EvalSymlinks(absPath)
		if err != nil {
			// Path may not exist yet — resolve the nearest existing ancestor
			// to handle symlinks like /tmp -> /private/tmp on macOS.
			realPath = resolvePartial(absPath)
		}
		if !isSubpath(wsReal, realPath) {
			return fmt.Errorf("bind mount %q is outside workspace %q", hostPath, p.Workspace)
		}
	}
	return nil
}

// resolvePartial resolves symlinks on the longest existing prefix of a path,
// then appends the remaining unresolved tail. This handles cases like
// /tmp/foo/nonexistent where /tmp is a symlink to /private/tmp.
func resolvePartial(p string) string {
	clean := filepath.Clean(p)
	// Walk up until we find a path that exists and can be resolved.
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
	// Nothing resolved — return cleaned path.
	return clean
}

// isSubpath returns true if child is equal to or under parent.
func isSubpath(parent, child string) bool {
	// Ensure parent ends with separator for prefix check.
	parentSlash := parent
	if !strings.HasSuffix(parentSlash, string(filepath.Separator)) {
		parentSlash += string(filepath.Separator)
	}
	return child == parent || strings.HasPrefix(child, parentSlash)
}

// Ownership tracks which containers were created through this proxy.
type Ownership struct {
	mu         sync.RWMutex
	containers map[string]bool // full container IDs
}

func NewOwnership() *Ownership {
	return &Ownership{
		containers: make(map[string]bool),
	}
}

// Add registers a container ID as owned.
func (o *Ownership) Add(id string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.containers[id] = true
}

// Remove unregisters a container ID.
func (o *Ownership) Remove(id string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.containers, id)
}

// Owns checks if the given ID or name prefix matches any owned container.
func (o *Ownership) Owns(ref string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()

	// Exact match first.
	if o.containers[ref] {
		return true
	}
	// Prefix match (podman allows short IDs).
	for id := range o.containers {
		if strings.HasPrefix(id, ref) {
			return true
		}
	}
	return false
}

// IDs returns a copy of all owned container IDs.
func (o *Ownership) IDs() []string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	ids := make([]string, 0, len(o.containers))
	for id := range o.containers {
		ids = append(ids, id)
	}
	return ids
}
