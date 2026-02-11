# Deployment Guide (Isolation-First)

This repository includes a containerized "Sentinel Sandbox" deployment that combines:

1. Application guardrails (Python policy engine)
2. Container hardening (read-only rootfs, dropped capabilities, seccomp, no-new-privileges)

For hard isolation of untrusted agents, prefer the dedicated runner:

```bash
sentinel-isolate --build-if-missing -- python your_agent.py
```

## Files

- `Dockerfile`: builds the Sentinel runtime image
- `docker-compose.yml`: hardened run profiles (`standard`, `strict`)
- `seccomp/sentinel-seccomp.json`: additional syscall deny rules
- `scripts/entrypoint.sh`: ensures `/workspace` and default `sentinel.yaml` exist

## Prerequisites

- Docker Engine
- Docker Compose v2 (`docker compose`)

## Build

```bash
docker compose build
```

## Run Modes

### 1) Standard Mode

Uses normal container networking with Sentinel policy checks active.

```bash
docker compose --profile standard run --rm sentinel-standard
```

### 2) Strict Mode

Disables all container networking (`network_mode: none`) as an OS-level fail-safe.

```bash
docker compose --profile strict run --rm sentinel-strict
```

### 3) Isolated Arbitrary Command (Recommended)

```bash
sentinel-isolate \
  --workspace ./sandbox-workspace \
  --policy ./sentinel.yaml \
  --network none \
  -- python your_agent.py
```

## Sandbox Workspace

Host directory `./sandbox-workspace` is mounted to `/workspace` in the container.

- Sentinel runs from `/workspace`
- `audit.log` is written to `/workspace/audit.log`
- Policy file is loaded from `/workspace/sentinel.yaml`
- Allowed path `./workspace` resolves to `/workspace/workspace`

## Security Controls Applied

- `read_only: true`
- `cap_drop: [ALL]`
- `security_opt: no-new-privileges:true`
- custom seccomp deny list (`seccomp/sentinel-seccomp.json`)
- `tmpfs` for `/tmp` and `/run`
- process/memory/CPU limits

## Socket Fail-Safe (Default On)

Low-level network interception across non-HTTP libraries is enabled by default:

```yaml
network_failsafe:
  socket_connect: true
  allow_private_network: false
  blocked_hosts: []
  blocked_ips: []
  allowed_ips: []
```

This catches non-`requests` clients via `socket.socket.connect`, but only has host/IP/port context (not full URLs).

## Notes

- Keep `allowed_commands` strict.
- Avoid whitelisting interpreters (`python`, `bash`, `sh`); Sentinel has a fail-safe denylist, but least-privilege policy is still recommended.
