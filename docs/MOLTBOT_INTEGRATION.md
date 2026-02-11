# Step-by-Step Moltbot Integration

This guide is written for non-technical users and gives a copy/paste path to run Moltbot behind Sentinel.

## What You Need

- Docker Desktop installed and running
- This repository downloaded
- Your Moltbot script file (example: `moltbot.py`)

## Recommended Path: Wrapper (No Moltbot Code Changes)

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

### 4) Put your Moltbot file in this folder

Example target location:

- `sentinel-guard/moltbot.py`

If your file is elsewhere, note the full path.

### 5) Set the Moltbot path in the wrapper

Open:

- `examples/moltbot_wrapper.py`

Find this line and change it if needed:

```python
MOLTBOT_PATH = "moltbot.py"
```

Examples:

- Same folder: `MOLTBOT_PATH = "moltbot.py"`
- Subfolder: `MOLTBOT_PATH = "agents/moltbot.py"`
- Absolute path: `MOLTBOT_PATH = "/Users/you/path/to/moltbot.py"`

### 6) Run Moltbot through Sentinel

```bash
python examples/moltbot_wrapper.py
```

You should see:

- `[Sentinel] Initializing...`
- `[Sentinel] Active. Launching Moltbot...`

### 7) Check security logs

Sentinel writes events to:

- `audit.log`

Review this file to see blocked or approved actions.

## Alternative Path: Add Sentinel Directly to Moltbot

Use this only if you are comfortable changing Moltbot code.

At the very top of Moltbot entrypoint, add:

```python
from src.core import activate_sentinel

activate_sentinel()
```

Important:

- This must be the first thing that runs, before other imports that perform network/command/file actions.

## Keep It Secure (Recommended Defaults)

Use strict defaults in `sentinel.yaml`:

- Minimal `allowed_paths`
- Minimal `allowed_commands`
- Minimal `allowed_hosts`
- Keep `network_failsafe.socket_connect: true`

When possible, run untrusted workloads with container isolation:

```bash
sentinel-isolate --build-if-missing -- python moltbot.py
```

## Troubleshooting

### `ModuleNotFoundError` or import errors

Run:

```bash
python -m pip install -e .
```

inside this project folder.

### Wrapper says Moltbot file not found

- Confirm `MOLTBOT_PATH` points to the correct file.
- If unsure, use an absolute path.

### `python` uses wrong environment

If conda is installed:

```bash
conda activate sentinel-guard
python --version
```

Then rerun the wrapper.

### Too many blocks for normal usage

Adjust `sentinel.yaml` carefully:

- Add only the exact paths, commands, and hosts you need.
- Avoid broad wildcards.
