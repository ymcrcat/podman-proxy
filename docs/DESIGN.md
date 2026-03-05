# Design

## Problem

Containers that need to create other containers (e.g. CI runners, orchestrators, AI agents) typically get the host's container socket mounted in. This gives them full, unrestricted access to the container runtime: they can create privileged containers, mount arbitrary host paths, access the host network, and see or kill every container on the host.

podman-proxy solves this by intercepting the socket API. Each tenant gets its own proxy process with its own policy and its own view of the world.

## Architecture

```
tenant container           proxy process             podman socket
      |                         |                         |
      |-- HTTP/unix ----------> |                         |
      |                         |  route classify         |
      |                         |  policy check           |
      |                         |  body sanitize          |
      |                         |-- HTTP/unix ----------> |
      |                         | <--- response --------- |
      |                         |  ownership track        |
      |                         |  response filter        |
      | <--- response --------- |                         |
```

One proxy per tenant. Each proxy:
- Listens on its own Unix socket (mounted into the tenant container as `/var/run/docker.sock`)
- Forwards allowed requests to the real podman socket
- Tracks which containers it created (in-memory)
- Filters list responses to only show owned containers
- Cleans up owned containers on shutdown

Multiple proxies share the same podman socket. They don't coordinate with each other; isolation comes from each proxy only knowing about (and allowing access to) containers it created.

```
                    +-------------+
tenant-1 container  |  proxy-1   |
/var/run/docker.sock|  tenant-1  |--+
                    +-------------+  |
                                     |
                    +-------------+  |  +--------------+
tenant-2 container  |  proxy-2   |  +--| podman.sock  |
/var/run/docker.sock|  tenant-2  |--+  +--------------+
                    +-------------+  |
                                     |
                    +-------------+  |
tenant-3 container  |  proxy-3   |  |
/var/run/docker.sock|  tenant-3  |--+
                    +-------------+
```

## Request lifecycle

### Container create (`POST /containers/create`)

1. Read and parse the JSON body
2. Re-marshal through `map[string]json.RawMessage` to collapse duplicate keys (prevents JSON smuggling)
3. Check image against allowlist (if configured)
4. Parse `HostConfig` into a typed struct for validation and a raw map for pass-through
5. Hard-block: privileged, host namespace modes (network, PID, IPC, UTS, userns, cgroupns)
6. Hard-block: bind mounts outside workspace (both legacy `Binds` and modern `Mounts`)
7. Silent sanitize: strip non-allowlisted capabilities, devices, SecurityOpt, Sysctls
8. Silent sanitize: cap memory and CPU to configured limits
9. Re-marshal and forward sanitized body to podman
10. On 2xx response, register the container ID (and name, if provided) in the ownership tracker

### Container operations (`/containers/{id}/{action}`)

1. Check action against the allowlist (start, stop, kill, wait, logs, inspect, top, stats, rename, resize, pause, unpause, remove)
2. Block exec, update, archive, copy, export, attach
3. Check container reference against ownership tracker (exact ID, name, or 12+ char prefix)
4. Forward to podman
5. On successful remove (2xx), unregister from ownership tracker

### Container list (`GET /containers/json`)

1. Forward to podman
2. Parse response as `[]json.RawMessage`
3. Filter to only containers whose `Id` is in the ownership tracker
4. Return filtered list

### Everything else

Blocked with 403. This includes system info, volumes, networks, images, and any unrecognized endpoint. The catch-all also blocks the libpod-native API paths.

## Security model

### Threat model

The tenant is untrusted. It can send arbitrary HTTP requests to the proxy socket. The proxy must prevent:

- **Privilege escalation**: creating privileged containers, adding dangerous capabilities, mounting host devices
- **Host filesystem access**: bind-mounting paths outside the workspace
- **Host namespace escape**: host network, PID, IPC, UTS, user, or cgroup namespace modes
- **Cross-tenant interference**: accessing, listing, or modifying containers owned by other tenants (or created outside the proxy)
- **Resource abuse**: unlimited memory or CPU consumption
- **Kernel parameter modification**: arbitrary sysctls or seccomp overrides

### Defense layers

**Hard blocks** (request rejected with 403):
- Privileged containers
- All host namespace modes (network, PID, IPC, UTS, userns, cgroupns)
- Bind mounts outside workspace (symlinks and `..` resolved; symlink source paths rejected)
- Images not in allowlist (when configured)
- Operations on containers not created through this proxy
- All non-container endpoints
- Blocked container actions (exec, update, archive, copy, export, attach)

**Silent sanitization** (request modified, not rejected):
- Capabilities: allowlist-based; only default Docker capabilities pass through (`AUDIT_WRITE`, `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `NET_BIND_SERVICE`, `NET_RAW`, `SETFCAP`, `SETGID`, `SETPCAP`, `SETUID`, `SYS_CHROOT`). Everything else stripped, including `ALL`.
- Device mappings: removed
- SecurityOpt: removed (blocks `seccomp=unconfined`, `apparmor=unconfined`)
- Sysctls: removed
- Memory: capped to `--max-memory`
- CPU: capped via NanoCpus and CpuQuota/CpuPeriod to `--max-cpus`

**Response filtering**:
- Container list filtered by ownership (ID match only, not name, to prevent cross-tenant leaks via prefix confusion)
- Response headers allowlisted (strips server version, infrastructure details)

### JSON smuggling prevention

Go's `encoding/json` and Podman may handle duplicate JSON keys differently (first-wins vs last-wins). An attacker could craft a body like `{"Privileged": false, "Privileged": true}` where the proxy sees `false` but Podman sees `true`.

The proxy always re-marshals through `map[string]json.RawMessage`, which collapses duplicates to a single key (Go's last-wins). The re-marshaled body is what gets forwarded to Podman.

### Bind mount path validation

1. Reject if workspace is empty (fail-safe: no workspace = no bind mounts)
2. Resolve workspace path to canonical form (`filepath.Abs` + `filepath.EvalSymlinks`)
3. For each bind mount source path:
   - `Lstat` the user-supplied path to reject symlinks at the mount point
   - Resolve to canonical form via `EvalSymlinks` (or `resolvePartial` for non-existent paths)
   - Check that the resolved path is equal to or under the resolved workspace
4. This handles `..` traversal, intermediate symlinks, and the macOS `/tmp` -> `/private/tmp` symlink

**Known limitation**: There is an inherent TOCTOU (time-of-check-time-of-use) window between the proxy's validation and Podman's actual mount. An attacker who can atomically replace a directory with a symlink in that window could escape the workspace. The `Lstat` check on the original path reduces but cannot eliminate this window. Full mitigation requires kernel-level support (e.g., mount namespaces or bind-before-validate).

### Ownership tracking

The `Ownership` struct maintains three maps protected by `sync.RWMutex`:
- `ids`: full container ID -> bool
- `names`: container name -> full ID
- `idToName`: full ID -> container name

Container references are resolved in order: exact ID match, name match, then 12+ character prefix match. Short prefixes (< 12 chars) are rejected to prevent cross-tenant collisions. Ambiguous prefixes (matching multiple owned containers) return empty from `FullID`.

Registration is atomic: `Add(id, name)` acquires the lock once and sets both the ID and name mapping.

## File structure

```
podman-proxy/
  go.mod           Module definition (Go 1.21, no external dependencies)
  main.go          CLI flags, Unix socket listener, graceful shutdown
  proxy.go         HTTP handler, route classification, forwarding, cleanup
  policy.go        Policy validation, sanitization, ownership tracking
  proxy_test.go    Unit and end-to-end tests with mock podman
  docs/
    DESIGN.md      This file
```

No external dependencies. Everything uses the Go standard library (`net/http`, `encoding/json`, `flag`, `sync`, `path/filepath`).

## Graceful shutdown

On `SIGTERM` or `SIGINT`:

1. `server.Shutdown()` stops accepting new connections and waits for in-flight requests to drain (10s timeout)
2. `proxy.CleanupContainers()` stops and force-removes all owned containers
3. Main goroutine waits on a `done` channel (no sleep-based polling)

This ensures no containers are orphaned when the proxy exits.

## Resource limits

CPU limiting works through two mechanisms:
- `NanoCpus`: directly capped to `maxCPUs * 1e9`
- `CpuQuota`/`CpuPeriod`: quota capped relative to period. When `CpuPeriod` is 0 (unset), the kernel default of 100,000 microseconds is assumed to prevent bypass.

Memory is capped by replacing `Memory` values exceeding the configured maximum. Values within limits pass through unchanged.

## Design decisions

**Manual HTTP forwarding, not `httputil.ReverseProxy`**: Need full control over request and response bodies for validation, sanitization, and filtering. A reverse proxy would require hooks at every stage.

**No Podman Go SDK**: The SDK is large and pulls in many dependencies. The proxy only needs to parse a handful of JSON fields; everything else passes through as opaque `json.RawMessage`.

**Cap resources instead of rejecting**: Less surprising for the caller. Matches Kubernetes LimitRange behavior. The caller doesn't need to know the exact limits to make a valid request.

**Capability allowlist instead of blocklist**: A blocklist can never be complete (new capabilities get added to the kernel). The allowlist contains the 13 default Docker capabilities; everything else is stripped.

**Shared HTTP transport**: A single `http.Transport` is reused across all requests to the podman socket, providing connection pooling and preventing file descriptor exhaustion under high load.

**Prefix match minimum length**: Container ID prefix matching requires at least 12 characters. Docker's default short ID is 12 hex chars, giving roughly 2^48 possible values. This prevents accidental cross-container collisions while still supporting the standard short ID convention.
