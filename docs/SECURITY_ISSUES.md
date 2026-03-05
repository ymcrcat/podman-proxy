# Security Issues Found

69 issues found and fixed across 10 rounds of security review. All issues were found through automated code review and fixed with corresponding tests.

## Round 1 — 22 issues (foundational hardening)

Established the core security model.

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Privilege | No check for `Privileged: true` | CRITICAL |
| 2 | Namespace | No check for `NetworkMode: "host"` | CRITICAL |
| 3 | Namespace | No check for `PidMode: "host"` | CRITICAL |
| 4 | Namespace | No check for `IpcMode: "host"` | CRITICAL |
| 5 | Namespace | No check for `UTSMode: "host"` | CRITICAL |
| 6 | Namespace | No check for `UsernsMode: "host"` | CRITICAL |
| 7 | Namespace | No check for `CgroupnsMode: "host"` | CRITICAL |
| 8 | Filesystem | No bind mount path validation | CRITICAL |
| 9 | Filesystem | No symlink resolution on bind mount sources | CRITICAL |
| 10 | Filesystem | No `..` traversal prevention | CRITICAL |
| 11 | Filesystem | No Mounts (modern format) validation | CRITICAL |
| 12 | Capabilities | No capability filtering — any cap allowed | CRITICAL |
| 13 | Capabilities | `CAP_ALL` not blocked | CRITICAL |
| 14 | Devices | Device mappings passed through | IMPORTANT |
| 15 | Kernel | SecurityOpt passed through (`seccomp=unconfined`, `apparmor=unconfined`) | IMPORTANT |
| 16 | Kernel | Sysctls passed through (arbitrary kernel params) | IMPORTANT |
| 17 | Resources | No memory limit enforcement | IMPORTANT |
| 18 | Resources | No CPU limit enforcement | IMPORTANT |
| 19 | Images | No image allowlist | IMPORTANT |
| 20 | Isolation | No container ownership tracking | CRITICAL |
| 21 | Isolation | Container list not filtered by ownership | CRITICAL |
| 22 | API surface | Forbidden endpoints not blocked (system, volumes, networks, images) | IMPORTANT |

## Round 2 — 9 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Smuggling | JSON smuggling via duplicate keys (`{"Privileged":false,"Privileged":true}`) | CRITICAL |
| 2 | Info leak | Response headers leaked server version and infrastructure details | IMPORTANT |
| 3 | Filesystem | Empty workspace allowed all bind mounts (should fail-safe to deny) | IMPORTANT |
| 4 | Filesystem | Empty host path in bind mounts not rejected | IMPORTANT |
| 5 | API surface | Blocked container actions (exec, update, archive, copy, export, attach) not comprehensive | IMPORTANT |
| 6 | Filesystem | `Lstat` check missing on bind mount source (symlink at mount point) | IMPORTANT |
| 7 | Filesystem | Partial path resolution for non-existent bind mount targets | LOW |
| 8 | Filesystem | macOS `/tmp` to `/private/tmp` symlink not handled | LOW |
| 9 | Isolation | Ownership prefix match minimum length not enforced | LOW |

## Round 3 — 6 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Isolation | Container name not tracked in ownership (access by name bypassed checks) | CRITICAL |
| 2 | Isolation | Container reference not rewritten to full ID before forwarding | CRITICAL |
| 3 | Isolation | Rename didn't update ownership tracker | IMPORTANT |
| 4 | Isolation | Ambiguous prefix matches not rejected | IMPORTANT |
| 5 | Isolation | Short prefix (< 12 chars) allowed cross-tenant collisions | IMPORTANT |
| 6 | Isolation | Remove didn't untrack from ownership on success | IMPORTANT |

## Round 4 — 7 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Smuggling | `strings.Replace` URL rewrite could substitute wrong path segment | CRITICAL |
| 2 | Resources | PidsLimit not enforced — fork bomb DoS | CRITICAL |
| 3 | Info leak | `X-Registry-Auth` header forwarded to Podman (credential leak) | CRITICAL |
| 4 | API surface | Empty action (inspect/delete) allowed all HTTP methods | IMPORTANT |
| 5 | DoS | `size=1` in list query forced expensive disk usage computation | IMPORTANT |
| 6 | DoS | No limit on concurrent streaming connections (goroutine/FD exhaustion) | IMPORTANT |
| 7 | Validation | Container ID from Podman response not validated before registration | IMPORTANT |

## Round 5 — 6 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Namespace | `container:<id>` namespace sharing for NetworkMode, PidMode, IpcMode, UTSMode | CRITICAL |
| 2 | Filesystem | `VolumesFrom` passed through — mounts volumes from arbitrary containers | CRITICAL |
| 3 | API surface | No per-action HTTP method enforcement (GET on start, POST on logs) | IMPORTANT |
| 4 | Resources | MemorySwap uncapped — swap-based memory limit bypass | IMPORTANT |
| 5 | Resources | CpuPeriod not validated — values outside kernel range (1000-1000000 us) | IMPORTANT |
| 6 | Validation | Container name not validated on create (arbitrary strings in ownership tracker) | IMPORTANT |

## Round 6 — 4 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Namespace | `UsernsMode: "container:<id>"` not blocked (only checked for "host") | CRITICAL |
| 2 | Namespace | `CgroupnsMode: "container:<id>"` not blocked (same miss) | CRITICAL |
| 3 | Validation | Rename stored unvalidated name in ownership tracker | IMPORTANT |
| 4 | Resources | `Memory=0` bypassed MaxMemory (0 means unlimited in Podman) | IMPORTANT |

## Round 7 — 6 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Resources | `NanoCpus=0` bypassed MaxCPUs (0 means unlimited in Podman) | CRITICAL |
| 2 | Resources | `MemorySwap=0` not capped (only caught -1 and overflow) | CRITICAL |
| 3 | Resources | `CpuQuota<=0` not enforced — second CPU bypass path via CFS scheduler | IMPORTANT |
| 4 | DoS | Streaming responses (logs/stats) had no per-connection byte limit | IMPORTANT |
| 5 | DoS | `filters` query param in list forwarded to Podman unsanitized | IMPORTANT |
| 6 | Config | Unix socket created 0666 (world-writable on host) | IMPORTANT |

## Round 8 — 3 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Namespace | `ns:<path>` namespace mode bypasses all 6 namespace restrictions (`isUnsafeMode` only blocked `host` and `container:`, missing Podman's `ns:/proc/1/ns/net` syntax) | CRITICAL |
| 2 | Resources | Resource limits (Memory, CPU, PIDs) not applied when `HostConfig` absent or null — early return skipped all enforcement | CRITICAL |
| 3 | Filesystem | `validateBinds` treated named volumes (`mydata:/data`) as bind mounts, incorrectly blocking them | IMPORTANT |

## Round 9 — 4 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | DoS | `limit` query param forwarded to Podman without bounds — host-wide container enumeration | IMPORTANT |
| 2 | DoS | Streaming connections can hold all 20 semaphore slots for full WriteTimeout — sustained streaming DoS | IMPORTANT |
| 3 | API surface | `ping`/`version` endpoints had no HTTP method restriction, passed through all query params and body | IMPORTANT |
| 4 | Isolation | `rename` forwarded invalid name to Podman before validation — proxy/Podman ownership desync | IMPORTANT |

## Round 10 — 2 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Filesystem | `type=image` mounts bypass image allowlist — `validateMounts` only checked `bind` type | IMPORTANT |
| 2 | Resources | `MemorySwap` cap did not disable swap when `Memory < MaxMemory` — swap = MaxMemory - Memory bytes available | IMPORTANT |

## Summary by category

| Category | Count | Rounds |
|----------|-------|--------|
| Resource limits (CPU/memory/PIDs/swap) | 14 | 1, 4, 5, 6, 7, 8, 10 |
| Namespace escape | 11 | 1, 5, 6, 8 |
| Filesystem/bind mounts | 8 | 1, 2, 8, 10 |
| Ownership/isolation | 8 | 1, 3, 9 |
| Capability/kernel | 5 | 1, 2 |
| Request smuggling/injection | 4 | 2, 4 |
| API surface/method control | 6 | 1, 4, 5, 9 |
| Information leaks | 3 | 2, 4, 7 |
| DoS vectors | 7 | 4, 5, 7, 9 |
| Input validation | 3 | 5, 6, 7 |

**Totals: 24 CRITICAL, 38 IMPORTANT, 7 LOW.**

## Recurring patterns

Several issue patterns recurred across multiple rounds:

**Zero means unlimited.** Podman treats `0` as "no limit" for Memory, MemorySwap, NanoCpus, CpuQuota, and PidsLimit. Code that only caps values exceeding the maximum misses the zero case entirely. This pattern was found in rounds 4 (PidsLimit), 6 (Memory), and 7 (NanoCpus, MemorySwap, CpuQuota).

**Namespace modes have three unsafe forms.** Each namespace mode (`NetworkMode`, `PidMode`, etc.) can be set to `"host"`, `"container:<id>"`, or `"ns:<path>"`. The initial implementation only blocked `"host"`, missing the container-sharing and filesystem-path forms. Found in rounds 5 (4 modes with `container:`), 6 (2 modes with `container:`), and 8 (all 6 modes with `ns:`).

**String manipulation on URLs is fragile.** Using `strings.Replace` to rewrite container references in URL paths can match the wrong segment if the container ID appears elsewhere in the path. Structural path building from regex captures is the correct approach. Found in round 4.

**Allowlists are safer than blocklists.** Capabilities, response headers, container actions, and query parameters all use allowlists. Every time a blocklist was used instead, new bypass vectors emerged. The capability allowlist (13 default Docker caps) and per-action method map are examples of this principle applied correctly.
