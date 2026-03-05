# Security Issues Found

119 issues found and fixed across 20 rounds of security review. All issues were found through automated code review and fixed with corresponding tests.

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

## Round 11 — 3 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | DoS | `wait` action not protected by streaming semaphore — goroutine exhaustion via concurrent blocking calls | IMPORTANT |
| 2 | Policy bypass | `OomKillDisable` passed through unsanitized — on cgroups v1, disables OOM killer causing host-wide kills | IMPORTANT |
| 3 | Input validation | Query parameters forwarded unsanitized for container operations — `stop?t=-1`, `kill?signal=SIGSEGV`, `delete?depend=true`, `top?ps_args=` | IMPORTANT |

## Round 12 — 4 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Isolation | `name` query param forwarded to Podman before validation on create — proxy/Podman name desync | IMPORTANT |
| 2 | Networking | `PortBindings` and `PublishAllPorts` passed through unrestricted — host port squatting and external interface exposure | IMPORTANT |
| 3 | Input validation | `resize?h`/`w` not validated as bounded integers (0–65535) before forwarding to kernel ioctl | LOW |
| 4 | Input validation | `wait?condition` not validated against documented allowlist | LOW |

## Round 13 — 7 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Input validation | Multi-value query parameter bypass — `?t=5&t=99999` forwards both values, only first validated | IMPORTANT |
| 2 | Resources | `ShmSize` passes through — tmpfs memory exhaustion beyond cgroup Memory limit on cgroups v1 | IMPORTANT |
| 3 | Isolation | `CgroupParent` passes through — cgroup hierarchy escape, resource accounting bypass | IMPORTANT |
| 4 | Policy bypass | `Runtime` passes through — OCI runtime downgrade to less secure runtime | IMPORTANT |
| 5 | Isolation | `AutoRemove` not stripped — stale ownership entries, unbounded memory growth | IMPORTANT |
| 6 | Resources | `Ulimits` passes through — `RLIMIT_NOFILE` exhaustion | LOW |
| 7 | Input validation | `logs?tail` not validated — unbounded integer forwarded to Podman | LOW |

## Summary by category

| Category | Count | Rounds |
|----------|-------|--------|
| Resource limits (CPU/memory/PIDs/swap) | 30 | 1, 4, 5, 6, 7, 8, 10, 13, 16, 17, 18, 19, 20 |
| Namespace escape | 11 | 1, 5, 6, 8 |
| Filesystem/bind mounts | 9 | 1, 2, 8, 10, 20 |
| Ownership/isolation | 13 | 1, 3, 9, 12, 13, 17, 20 |
| Capability/kernel | 9 | 1, 2, 11, 16, 17, 20 |
| Request smuggling/injection | 5 | 2, 4, 13 |
| API surface/method control | 6 | 1, 4, 5, 9 |
| Networking | 3 | 12, 20 |
| Information leaks | 3 | 2, 4, 7 |
| DoS vectors | 8 | 4, 5, 7, 9, 11 |
| Input validation | 10 | 5, 6, 7, 11, 12, 13, 16 |
| Policy bypass | 6 | 13, 15, 16, 20 |
| Devices | 3 | 20 |
| Privilege escalation | 2 | 20 |

## Round 14 — 5 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Policy bypass | `StopTimeout` top-level field unvalidated — can delay container cleanup indefinitely | IMPORTANT |
| 2 | Networking | `NetworkingConfig` top-level field bypasses `NetworkMode` restriction — can join arbitrary host networks | IMPORTANT |
| 3 | Input validation | `logs` `since`/`until` params forwarded unvalidated to Podman's filter parser | IMPORTANT |
| 4 | DoS | `WriteTimeout: 120s` silently overrides 10-min `streamCtx` — fixed to 11 minutes | IMPORTANT |
| 5 | Policy bypass | Non-create action endpoints forward request body verbatim — body-based signal/param bypass | IMPORTANT |

**Totals: 24 CRITICAL, 55 IMPORTANT, 9 LOW.**

## Round 15 — 1 issue

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Policy bypass | `streamForward` forwards request body for `wait` (POST streaming action) — violates body-discard invariant | IMPORTANT |

**Totals: 24 CRITICAL, 56 IMPORTANT, 9 LOW.**

## Round 16 — 5 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Capability | `CapDrop` not sanitized — agents can manipulate default capability drop list | CRITICAL |
| 2 | Input validation | `containerRef` not validated before log output — log injection via newlines/escape sequences | IMPORTANT |
| 3 | Input validation | `all` query param in list forwarded without value validation | IMPORTANT |
| 4 | Policy bypass | Ping/version forwards original request body to Podman (unnecessary data channel) | IMPORTANT |
| 5 | Resources | `StorageOpt` not stripped from HostConfig — container disk quota manipulation | IMPORTANT |

**Totals: 25 CRITICAL, 60 IMPORTANT, 9 LOW.**

## Round 17 — 3 issues

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Kernel | `MaskedPaths`/`ReadonlyPaths` pass through — removes OCI default masking of `/proc/kcore`, `/proc/sched_debug`, `/sys/firmware` | CRITICAL |
| 2 | Resources | `Tmpfs` map passes through — cgroups v1 memory exhaustion beyond MaxMemory (same bypass as ShmSize) | CRITICAL |
| 3 | Isolation | `RestartPolicy` passes through — containers with `always` survive proxy shutdown without ownership tracking | IMPORTANT |

**Totals: 27 CRITICAL, 61 IMPORTANT, 9 LOW.**

## Round 18 — 1 issue

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Resources | `tmpfs` mount type allowed in `Mounts` — same cgroups v1 memory bypass as stripped `Tmpfs` HostConfig and `ShmSize` | CRITICAL |

**Totals: 28 CRITICAL, 61 IMPORTANT, 9 LOW.**

## Round 19 — 1 issue

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Resources | `VolumeOptions.DriverConfig` in Mounts passes through — tmpfs-via-driver memory limit bypass on cgroups v1 | IMPORTANT |

**Totals: 28 CRITICAL, 62 IMPORTANT, 9 LOW.**

## Round 20 — 20 issues

Comprehensive HostConfig field audit — every Docker/Podman compat API field reviewed against security impact.

| # | Category | Issue | Severity |
|---|----------|-------|----------|
| 1 | Kernel | `LogConfig` passes through — log driver SSRF via syslog/fluentd custom address, host journal flooding via journald driver | IMPORTANT |
| 2 | Devices | `DeviceCgroupRules` passes through — cgroup device allow rules like `"c 10:200 rwm"` bypass `Devices` stripping | IMPORTANT |
| 3 | Policy bypass | List endpoint forwards request body to Podman (`nil` body override in `doForward`) — violates body-discard invariant | LOW |
| 4 | Resources | `OomScoreAdj` passes through — negative values make container immune to OOM killer on rootful Podman, same class as stripped `OomKillDisable` | IMPORTANT |
| 5 | Devices | `DeviceRequests` passes through — GPU/device driver requests; documented container escape CVEs (CVE-2024-0132, CVE-2025-23266) via NVIDIA Container Toolkit | CRITICAL |
| 6 | Filesystem | `ContainerIDFile` passes through — daemon writes container ID to attacker-controlled host path (path traversal file overwrite) | IMPORTANT |
| 7 | Privilege | `GroupAdd` passes through — supplementary groups like `docker`, `disk`, `shadow` escalate privileges with bind-mounted host files | IMPORTANT |
| 8 | Networking | `ExtraHosts` passes through — /etc/hosts injection enables SSRF by remapping cloud IMDS (169.254.169.254) or internal services | IMPORTANT |
| 9 | Networking | `Dns`/`DnsSearch`/`DnsOptions` pass through — attacker-controlled DNS resolver enables exfiltration, rebinding, and SSRF | IMPORTANT |
| 10 | Privilege | `VolumeDriver` passes through — arbitrary volume driver plugins execute with elevated privileges, can bind-mount host paths | IMPORTANT |
| 11 | Isolation | `Links` passes through — deprecated Docker feature injects env vars and /etc/hosts entries from other containers | LOW |
| 12 | Policy bypass | `Annotations` passes through — OCI annotations trigger runtime behavior in Podman (e.g., `io.podman.annotations.userns`) | IMPORTANT |
| 13 | Resources | `CpuRealtimePeriod`/`CpuRealtimeRuntime` pass through — real-time CPU scheduler starves host processes at kernel level | IMPORTANT |
| 14 | Resources | `CpusetCpus`/`CpusetMems` pass through — CPU/NUMA pinning starves other tenants on specific cores | LOW |
| 15 | Resources | `KernelMemory` passes through — deprecated; on old kernels with cgroups v1, hitting kmem limit causes host-wide OOM | LOW |
| 16 | Resources | `MemorySwappiness` passes through — manipulates kernel swap preference, affects other containers' memory reclaim | LOW |
| 17 | Resources | `MemoryReservation` passes through — soft memory limit affects kernel reclaim priority between containers | LOW |
| 18 | Resources | `BlkioWeight` and per-device I/O controls pass through — I/O scheduling unfairness, host device topology leak | LOW |
| 19 | Resources | `CpuShares` passes through — extreme values affect relative CPU scheduling priority under contention | LOW |
| 20 | Resources | `Cgroup` field passes through (distinct from CgroupParent) — cgroup controller/mode manipulation | LOW |

**Totals: 29 CRITICAL, 72 IMPORTANT, 18 LOW.**

## Recurring patterns

Several issue patterns recurred across multiple rounds:

**Zero means unlimited.** Podman treats `0` as "no limit" for Memory, MemorySwap, NanoCpus, CpuQuota, and PidsLimit. Code that only caps values exceeding the maximum misses the zero case entirely. This pattern was found in rounds 4 (PidsLimit), 6 (Memory), and 7 (NanoCpus, MemorySwap, CpuQuota).

**Namespace modes have three unsafe forms.** Each namespace mode (`NetworkMode`, `PidMode`, etc.) can be set to `"host"`, `"container:<id>"`, or `"ns:<path>"`. The initial implementation only blocked `"host"`, missing the container-sharing and filesystem-path forms. Found in rounds 5 (4 modes with `container:`), 6 (2 modes with `container:`), and 8 (all 6 modes with `ns:`).

**String manipulation on URLs is fragile.** Using `strings.Replace` to rewrite container references in URL paths can match the wrong segment if the container ID appears elsewhere in the path. Structural path building from regex captures is the correct approach. Found in round 4.

**Allowlists are safer than blocklists.** Capabilities, response headers, container actions, and query parameters all use allowlists. Every time a blocklist was used instead, new bypass vectors emerged. The capability allowlist (13 default Docker caps) and per-action method map are examples of this principle applied correctly.

**HostConfig has a vast attack surface.** The Docker/Podman HostConfig object has 50+ fields, many with security implications. Round 20 found 20 unstripped fields in a single audit, including `DeviceRequests` (documented container escape CVEs), `ContainerIDFile` (host file overwrites), `ExtraHosts` (SSRF), and `Dns*` (DNS poisoning). The current blocklist approach requires manually enumerating every dangerous field. A future refactor to an allowlist (keeping only known-safe fields) would be more robust.
