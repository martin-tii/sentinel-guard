# Quickstart

## Prerequisites

- Docker Engine
- Docker Compose v2 (`docker compose`)
- Docker daemon running

## 5-Minute Start

1. Open terminal in the project root.
2. Run:

```bash
./run_demo.sh
```

This builds the image (first run), launches strict isolation (`network none`), and runs the demo workload.

## Common Runs

- Strict (recommended):

```bash
docker compose --profile strict run --rm sentinel-strict
```

- Standard (networked):

```bash
docker compose --profile standard run --rm sentinel-standard
```

- Proxied (networked with sidecar egress control):

```bash
docker compose --profile proxied up --build --abort-on-container-exit sentinel-proxied
```

- Arbitrary command in isolated sandbox:

```bash
sentinel-isolate --build-if-missing -- python your_agent.py
```

## If Something Fails

- Docker missing: install Docker Desktop.
- Docker daemon stopped: start Docker Desktop and wait until engine is ready.
- `docker compose` unavailable: update Docker Desktop / Compose.
- Seccomp denial symptoms: rerun with `--seccomp-mode log`, then inspect:

```bash
dmesg | tail -n 100
```

Then tighten back to `--seccomp-mode enforce` once syscall requirements are known.

For ML/data-science workloads that need broader syscall coverage, use:

```bash
sentinel-isolate --seccomp-profile datasci --build-if-missing -- python your_agent.py
```
