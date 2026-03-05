# podman-proxy

A thin Go proxy that sits between containers and the real podman socket, enforcing security policies and tracking container ownership.

Each proxy instance exposes a Unix socket that looks like a standard Docker/Podman API endpoint, but restricts what callers can do: no privileged containers, no host filesystem access outside a designated workspace directory, no dangerous capabilities, and each caller can only see and manage containers it created. Run one proxy per tenant to get per-tenant isolation without giving anyone unrestricted access to the podman socket.

## Architecture

Each tenant container gets its own proxy process and socket. They don't share — each proxy tracks its own set of created containers independently.

```
                        ┌─────────────┐
  tenant-1 container    │  proxy-1    │
  /var/run/docker.sock ─┤  tenant-1   ├──┐
                        └─────────────┘  │
                                         │
                        ┌─────────────┐  │  ┌────────────────┐
  tenant-2 container    │  proxy-2    │  ├──┤ podman.sock    │
  /var/run/docker.sock ─┤  tenant-2   ├──┤  └────────────────┘
                        └─────────────┘  │
                                         │
                        ┌─────────────┐  │
  tenant-3 container    │  proxy-3    │  │
  /var/run/docker.sock ─┤  tenant-3   ├──┘
                        └─────────────┘
```

All proxies forward to the same podman socket — podman handles the actual container lifecycle. The proxies gate what each tenant is allowed to ask for, and filter responses so tenants only see their own containers.

## Build

Requires Go 1.21+. No external dependencies.

```bash
go build -o podman-proxy .
go test -v ./...
```

## Quick start

Start the podman socket if it isn't already running:

```bash
systemctl --user start podman.socket
```

Find your podman socket path:

```bash
podman info --format '{{.Host.RemoteSocket.Path}}'
# e.g. /run/user/1000/podman/podman.sock
```

Start the proxy:

```bash
./podman-proxy \
  --listen /tmp/tenant-1.sock \
  --podman-socket /run/user/1000/podman/podman.sock \
  --workspace /home/user/workspace \
  --agent-id tenant-1
```

Test it with curl:

```bash
# Should work — create a container
curl --unix-socket /tmp/tenant-1.sock -X POST http://localhost/v4.0.0/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["echo","hello"]}'

# Should be blocked — privileged container
curl --unix-socket /tmp/tenant-1.sock -X POST http://localhost/v4.0.0/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","HostConfig":{"Privileged":true}}'
```

## Using from inside a container

Mount the proxy socket into a container as `/var/run/docker.sock` so standard Docker/Podman clients work without configuration:

```bash
# Start a proxy
./podman-proxy \
  --listen /tmp/tenant-1.sock \
  --podman-socket /run/user/1000/podman/podman.sock \
  --workspace /tmp/workspace \
  --agent-id tenant-1 &

# Run a container with the proxy socket mounted
podman run --rm -it \
  -v /tmp/tenant-1.sock:/var/run/docker.sock \
  alpine sh

# Inside the container, create and manage worker containers:
apk add curl
curl --unix-socket /var/run/docker.sock -X POST \
  http://localhost/v4.0.0/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["echo","hello from nested"]}'
```

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `/tmp/podman-proxy.sock` | Unix socket path the proxy listens on |
| `--podman-socket` | `/run/podman/podman.sock` | Real podman socket path |
| `--workspace` | `/workspace` | Allowed host path prefix for bind mounts |
| `--allowed-images` | *(empty = all)* | Comma-separated image allowlist |
| `--max-memory` | `2147483648` (2 GB) | Max memory per container in bytes |
| `--max-cpus` | `2.0` | Max CPUs per container |
| `--agent-id` | `agent` | Identifier for logging |

## Security policies

**Hard blocks** (request rejected with 403):
- Privileged containers
- Host network or PID mode
- Bind mounts outside the workspace directory (symlinks and `..` resolved)
- Images not in the allowlist (when configured)
- Operations on containers not created through this proxy
- All non-container endpoints (system info, volumes, networks, images)

**Silent sanitization** (request modified, not rejected):
- Dangerous capabilities stripped: `SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `NET_RAW`, `SYS_RAWIO`, `MKNOD`
- Device mappings removed
- Memory and CPU limits capped to configured maximums

**Allowed endpoints:**
- `/_ping`, `/version` — always forwarded
- `POST /containers/create` — validated and sanitized
- `GET /containers/json` — forwarded, filtered to owned containers
- Per-container operations (start, stop, logs, exec, inspect, remove) — ownership checked

## Graceful shutdown

On `SIGTERM` or `SIGINT`, the proxy stops and removes all containers it created to prevent orphans.
