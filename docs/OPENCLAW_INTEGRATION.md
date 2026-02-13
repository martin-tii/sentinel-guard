# OpenClaw Integration (Harden OpenClaw Docker Sandbox)

Use this when you want OpenClaw sandbox hardening + Sentinel proxy topology without changing OpenClaw's normal install/onboard flow.

## At a Glance

- ✅ Recommended: `python scripts/install_openclaw_with_sentinel.py`
- 🛠 Advanced: manual `openclaw config set --json ...` sandbox commands
- ⚠ Not included: Sentinel Python in-process hooks (`activate_sentinel()`) for OpenClaw Gateway runtime

## Scope

What you get:
- OpenClaw tool execution runs inside a hardened Docker sandbox (OpenClaw-native).
- Optional network egress controls via Sentinel's proxy topology (internal Docker network + allowlisted Squid proxy).

What you do NOT get:
- Sentinel Python in-process guardrails (`activate_sentinel()`) do not apply to the OpenClaw Gateway runtime.
- Sentinel `audit.log` does not automatically include OpenClaw actions unless OpenClaw is executing Sentinel code.

## Prereqs

- Docker Desktop installed and running (with your home directory shared with Docker).
- OpenClaw installed (`openclaw --version` works).

## Quickstart (Recommended)

1. From the Sentinel repo root:

```bash
cd sentinel-guard
```

2. Run the transparent installer flow:

```bash
python scripts/install_openclaw_with_sentinel.py
```

3. When prompted, approve Sentinel hardening:
- `Enable Sentinel security hardening now? [Y/n]` -> `Y`

4. Verify applied settings:

```bash
openclaw sandbox explain --json
openclaw sandbox list
```

Expected outcome:
- Hardened sandbox config + Sentinel proxy topology are applied for OpenClaw tool sandboxes.

## Non-Interactive / CI

Canonical headless command:

```bash
cd sentinel-guard
python scripts/install_openclaw_with_sentinel.py \
  --non-interactive \
  --enable-sentinel yes \
  --sentinel-network sentinel-sandbox_sentinel-internal
```

Useful flags:
- `--non-interactive`: disables prompts.
- `--enable-sentinel yes|no|ask`: hardening behavior (`ask` defaults to `yes` in non-interactive mode).
- `--skip-openclaw-install`: skip installer even if `openclaw` is missing.
- `--openclaw-install-url <url>`: override installer source (default `https://openclaw.ai/install.sh`).
- `--sentinel-network <name>`: override Docker network name used for sandbox containers.

## If You Hit Config Errors

If setup fails with config invalid/unknown keys, run:

```bash
openclaw doctor --fix
```

Then confirm config is clean:

```bash
openclaw doctor --non-interactive
```

Note:
- On OpenClaw `2026.2.9`, one observed issue is unknown key `channels.telegram.token`, which can break `openclaw config ...` commands until fixed.
- Reconfigure Telegram via the current OpenClaw-supported flow if needed: [OpenClaw CLI docs](https://docs.openclaw.ai/cli)

## What the Installer Configures

When Sentinel hardening is enabled, the helper configures:
- Proxy topology startup:
  - `docker compose --profile proxied up -d sentinel-proxy`
- Seccomp profile installation:
  - `~/.openclaw/seccomp/sentinel-seccomp-datasci.json`
- OpenClaw sandbox defaults:
  - `agents.defaults.sandbox` + `agents.defaults.sandbox.docker`
- Sandbox lifecycle refresh:
  - `openclaw sandbox recreate --all`

## Advanced / Manual Override

Use this if you need explicit control instead of the transparent installer.

1) Start Sentinel proxy topology (gold standard for networked sandboxes):

```bash
cd sentinel-guard
docker compose --profile proxied up -d sentinel-proxy
```

By default, OpenClaw sandboxes should attach to:
- `sentinel-sandbox_sentinel-internal`

If your Compose project name differs, discover your internal network:

```bash
docker network ls | rg sentinel-internal
```

2) Install Sentinel seccomp profile for OpenClaw:

```bash
mkdir -p ~/.openclaw/seccomp
cp seccomp/sentinel-seccomp-datasci.json ~/.openclaw/seccomp/sentinel-seccomp-datasci.json
```

3) Apply sandbox configuration with helper script:

```bash
python scripts/openclaw_configure_sentinel_sandbox.py
```

Optional network override:

```bash
SENTINEL_OPENCLAW_DOCKER_NETWORK="<your-internal-network>" \
  python scripts/openclaw_configure_sentinel_sandbox.py
```

Manual equivalent (OpenClaw `2026.2.9`):

```bash
openclaw config set --json agents.defaults.sandbox '{"mode":"non-main","scope":"agent","workspaceAccess":"rw"}'
openclaw config set --json agents.defaults.sandbox.docker '{
  "readOnlyRoot": true,
  "capDrop": ["ALL"],
  "tmpfs": ["/tmp", "/var/tmp", "/run"],
  "pidsLimit": 256,
  "memory": "512m",
  "cpus": 1.0,
  "network": "sentinel-sandbox_sentinel-internal",
  "env": {
    "HTTP_PROXY": "http://sentinel-proxy:3128",
    "HTTPS_PROXY": "http://sentinel-proxy:3128",
    "NO_PROXY": "localhost,127.0.0.1,sentinel-proxy"
  },
  "seccompProfile": "~/.openclaw/seccomp/sentinel-seccomp-datasci.json"
}'
```

4) Restart/recreate if needed:

```bash
openclaw gateway restart
openclaw sandbox recreate --all
```

## Verification Checklist (Pass/Fail)

1) ✅ Sandbox settings are present:

```bash
openclaw sandbox explain --json
```

Pass when:
- `mode=non-main`, `scope=agent`, `workspaceAccess=rw`
- docker hardening fields are present (`readOnlyRoot`, `capDrop`, `seccompProfile`, proxy env, network)

2) ✅ Sandbox containers appear after tool invocation:

```bash
openclaw sandbox list
```

Pass when:
- At least one sandbox appears after a tool action in a sandboxed session.

Note:
- `openclaw sandbox list` can show `0` before the first tool invocation; this is expected.

3) ✅ Container hardening is effective:

```bash
docker inspect <openclaw-sandbox-container>
```

Pass when:
- `ReadonlyRootfs=true`
- seccomp profile points to `~/.openclaw/seccomp/sentinel-seccomp-datasci.json`
- container network includes your Sentinel internal network (for example `sentinel-sandbox_sentinel-internal`)

4) ✅ Network enforcement behaves as expected:

Pass when:
- Direct egress from sandbox fails on internal network topology.
- Proxied egress succeeds only for domains allowlisted in:
  - `sentinel-guard/proxy/allowed-domains.txt`
