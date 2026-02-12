# Step-by-Step OpenClaw Integration

OpenClaw is the new name (formerly Moltbot / Clawdbot).

## Compatibility at a Glance

- Official OpenClaw install from [openclaw.ai](https://openclaw.ai/) (CLI commands like `openclaw onboard`, `openclaw gateway`): the Python wrapper is **not directly compatible**.
- Python-based OpenClaw entrypoint (`openclaw.py`): `examples/openclaw_wrapper.py` works.
- Official OpenClaw CLI can be run through Sentinel isolation using `sentinel-openclaw`.

Reason: `activate_sentinel()` applies Python in-process hooks. The official OpenClaw runtime is CLI/Gateway-first and runs outside that Python process.

## Path A (Python Entrypoint): Use the OpenClaw Wrapper

Use this path only if your OpenClaw workload is a Python entry script.

### 1) Open Terminal in `sentinel-guard`

Make sure your current folder is the project root where `README.md` exists.

### 2) Activate the project Python environment

If you use conda:

```bash
conda activate sentinel-guard
```

### 3) Install the project

```bash
python -m pip install -e .
```

### 4) Place your OpenClaw Python file

Default expected file:

- `sentinel-guard/openclaw.py`

Or set a custom path via env var:

```bash
OPENCLAW_PATH="agents/openclaw.py" python examples/openclaw_wrapper.py
```

### 5) Run through Sentinel

```bash
python examples/openclaw_wrapper.py
```

You should see:

- `[Sentinel] Initializing...`
- `[Sentinel] Active. Launching OpenClaw Python entrypoint...`

### 6) Review security logs

Sentinel writes events to:

- `audit.log`

## Path B (Official OpenClaw CLI/Gateway): Use External Isolation

For standard OpenClaw installs from openclaw.ai/docs:

- Use OpenClaw's normal CLI workflow (`openclaw onboard`, `openclaw gateway`, etc.).
- Do **not** rely on `examples/openclaw_wrapper.py` for containment of that CLI process.
- Apply hard boundaries with container/VM/network topology controls.

If you use Sentinel isolation for networked workloads, prefer topology-enforced proxy routing (gold standard) over bridge + env-proxy enforcement.

## Path C (Official OpenClaw CLI): Sentinel Launcher

Use Sentinel's OpenClaw launcher for Node CLI style workflows:

```bash
sentinel-openclaw --publish 18789:18789 -- gateway --port 18789
```

Other examples:

```bash
sentinel-openclaw -- onboard
sentinel-openclaw -- doctor
sentinel-openclaw --network bridge --enforce-proxy --proxy http://sentinel-proxy:3128 -- gateway
```

Notes:

- `sentinel-openclaw` runs OpenClaw inside Sentinel's isolated Docker runtime.
- Default image is `openclaw:local`. Build it first from the OpenClaw repo:

```bash
docker build -t openclaw:local -f Dockerfile .
```

- By default, the launcher sets `HOME=/workspace` inside the container so OpenClaw state persists under the mounted workspace.
- Override the executable with `--openclaw-bin` if needed.
- If you want to access the Gateway UI from your host browser, you must publish the port via `--publish`.

## Backward Compatibility

- `examples/moltbot_wrapper.py` is kept as a deprecated shim and forwards to `examples/openclaw_wrapper.py`.

## Troubleshooting

### Wrapper says target file not found

- Confirm `OPENCLAW_PATH` points to the right Python file.
- If unsure, use an absolute path.

### OpenClaw CLI actions are not being intercepted by the wrapper

Expected for non-Python OpenClaw runtime. Use container/VM isolation for hard security boundaries.
