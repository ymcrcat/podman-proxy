# podman-proxy

A thin Go proxy that sits between AI agent containers and the real podman socket, enforcing per-agent security policies and container ownership tracking.

Agents get a Unix socket that looks like a standard Docker/Podman API endpoint, but the proxy restricts what they can do: no privileged containers, no host filesystem access outside a workspace directory, no dangerous capabilities, and each agent can only see and manage containers it created.

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
  --listen /tmp/agent-1.sock \
  --podman-socket /run/user/1000/podman/podman.sock \
  --workspace /home/user/agent-workspace \
  --agent-id agent-1
```

Test it with curl:

```bash
# Should work — create a container
curl --unix-socket /tmp/agent-1.sock -X POST http://localhost/v4.0.0/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["echo","hello"]}'

# Should be blocked — privileged container
curl --unix-socket /tmp/agent-1.sock -X POST http://localhost/v4.0.0/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","HostConfig":{"Privileged":true}}'
```

## Using with an agent container

Mount the proxy socket into the agent container as `/var/run/docker.sock` so standard Docker/Podman clients work without configuration:

```bash
# Start a proxy for this agent
./podman-proxy \
  --listen /tmp/agent-1.sock \
  --podman-socket /run/user/1000/podman/podman.sock \
  --workspace /tmp/workspace \
  --agent-id agent-1 &

# Run the agent container with the proxy socket mounted
podman run --rm -it \
  -v /tmp/agent-1.sock:/var/run/docker.sock \
  alpine sh

# Inside the container, the agent can create worker containers:
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
