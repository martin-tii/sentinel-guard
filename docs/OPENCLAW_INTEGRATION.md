# OpenClaw Integration (Harden OpenClaw Docker Sandbox)

Use this when you want OpenClaw sandbox hardening + Sentinel proxy topology without changing OpenClaw's normal install/onboard flow.

## At a Glance

- ✅ Recommended: `python scripts/install_openclaw_with_sentinel.py`
- 🛠 Advanced: manual `openclaw config set --json ...` sandbox commands
- ⚠ Not included: Sentinel Python in-process hooks (`activate_sentinel()`) for OpenClaw Gateway runtime
- ⚠ OpenClaw `2026.2.12`: `before_tool_call` plugin interception is not guaranteed across all agent execution paths.

For guaranteed enforcement, rely on sandbox hardening + approvals/allowlists; plugin interception is defense-in-depth.

## Scope

What you get:
- OpenClaw tool execution runs inside a hardened Docker sandbox (OpenClaw-native).
- Optional network egress controls via Sentinel's proxy topology (internal Docker network + allowlisted Squid proxy).
- Sentinel pre-execution interception for risky tools via OpenClaw plugin (`before_tool_call`).
- Sentinel injection/jailbreak detection via Llama Prompt Guard + Llama Guard plugin path.

What you do NOT get:
- Sentinel Python in-process guardrails (`activate_sentinel()`) do not apply to the OpenClaw Gateway runtime.
- Sentinel `audit.log` does not automatically include OpenClaw actions unless OpenClaw is executing Sentinel code.

## Prereqs

- Docker Desktop installed and running (with your home directory shared with Docker).
- OpenClaw optional: if missing, the installer can bootstrap it automatically.

## Quickstart (Recommended)

1. From the Sentinel repo root:

```bash
cd sentinel-guard
```

2. Run the transparent installer flow:

```bash
python scripts/install_openclaw_with_sentinel.py
```

Install fallback behavior:
- First try: `https://openclaw.ai/install.sh`
- If that fails: `https://openclaw.ai/install-cli.sh`
- If that fails: `npm install -g openclaw@latest` (with onboarding in interactive mode)

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
- `--openclaw-install-sha256 <sha256>`: require installer digest match before execution.
- `--allow-untrusted-installer-url`: allow non-default installer hosts (controlled environments only).
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

## OpenClaw Security Audit (Recommended)

After onboarding and after major config changes, run:

```bash
openclaw security audit --deep
```

How this relates to Sentinel:
- OpenClaw audit checks OpenClaw configuration posture and gateway/channel exposure.
- Sentinel enforces runtime containment and policy controls during execution.

Use both for defense in depth.

## OpenClaw Approvals vs Sentinel

OpenClaw native approvals ([docs](https://docs.openclaw.ai/cli/approvals)) and Sentinel controls are complementary, not duplicates:

- OpenClaw approvals:
  - Native `exec` approval policy (`openclaw approvals ...`, `exec-approvals.json`).
  - Host-aware targeting (`local`, `--gateway`, `--node`).
  - Primary built-in approval plane for command execution.

- Sentinel layers:
  - Runtime hardening around OpenClaw (sandbox network topology, seccomp, cap-drop, read-only root).
  - Tool allowlist hardening (`tools.sandbox.tools.allow`) beyond only `exec`.
  - Pre-exec interception + popup fallback + injection guard for defense-in-depth.

Recommended model:
- Treat OpenClaw approvals as the native `exec` policy source of truth.
- Keep Sentinel enabled for containment and additional controls if OpenClaw callbacks or channels vary by runtime path.

## What the Installer Configures

When Sentinel hardening is enabled, the helper configures:
- Proxy topology startup:
  - `docker compose --profile proxied up -d sentinel-proxy`
- Seccomp profile installation:
  - `~/.openclaw/seccomp/sentinel-seccomp-datasci.json`
- OpenClaw sandbox defaults:
  - `agents.defaults.sandbox` + `agents.defaults.sandbox.docker`
- OpenClaw exec approvals baseline (default prompt-on-exec):
  - `openclaw approvals set --file ...`
  - Baseline: `ask=always`, `askFallback=deny`, `autoAllowSkills=false`
- Sentinel pre-execution plugin:
  - `openclaw-plugins/sentinel-preexec/index.js`
  - Installs into `~/.openclaw/extensions/sentinel-preexec`
  - Enabled via `plugins.entries.sentinel-preexec.enabled=true`
  - Registers `before_tool_call` interception
  - Prompts allow/block before risky tools execute
  - Default risky tools: `exec`, `process`, `write`, `edit`, `apply_patch`
- Sentinel injection guard plugin:
  - `openclaw-plugins/sentinel-injection-guard/index.js`
  - Installs into `~/.openclaw/extensions/sentinel-injection-guard`
  - Enabled via `plugins.entries.sentinel-injection-guard.enabled=true`
  - Uses `prompt-guard` + `llama-guard3` via Ollama endpoint (`http://localhost:11434/api/generate`)
  - On detection, enforces strict tool profile and flags session as high risk
  - Fallback cleanup: if flagged session still executes `write`, plugin deletes created file in workspace
- Sentinel popup guard fallback service:
  - `scripts/openclaw_popup_guard.py`
  - Optional defense-in-depth if plugin is disabled or unavailable
- Sandbox lifecycle refresh:
  - `openclaw sandbox recreate --all`

## Advanced / Manual Override

Use this if you need explicit control instead of the transparent installer.

1) Start Sentinel proxy topology (Gold standard (topology-enforced proxy routing)):

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

## Appendix: Plugin and Popup Enforcement Details

### Pre-Exec Interception Behavior

The Sentinel pre-exec plugin is the primary enforcement path:
- It runs before tool execution (`before_tool_call`).
- Default risky tools:
  - `exec`, `process`, `write`, `edit`, `apply_patch`
- It asks via popup and terminal (if available); first response wins.
- To reduce popup bursts, recent operator decisions are cached per tool for a short cooldown window (default: 15s).
- `Block` denies the call before execution.
- Popup and terminal prompts run in parallel; the first response wins.
- Timeout/fallback behavior is secure-by-default (`block`).

Current OpenClaw reality check (`2026.2.12`):
- The plugin is installed and loaded, but interception behavior can vary depending on runtime path/fallback mode.
- Do not rely on `before_tool_call` alone for hard guarantees yet.
- Keep strict allowlist + approvals as primary hard controls.
- The same caveat applies to injection-guard callback paths (`before_agent_start`/`before_tool_call`) in this version.

Environment overrides:

```bash
export SENTINEL_OPENCLAW_INTERCEPT_TOOLS="exec,process,write,edit,apply_patch"
export SENTINEL_OPENCLAW_INTERCEPT_TIMEOUT_SECONDS="120"
export SENTINEL_OPENCLAW_INTERCEPT_FALLBACK="block"
export SENTINEL_OPENCLAW_INTERCEPT_DECISION_COOLDOWN_SECONDS="15"
```

`SENTINEL_OPENCLAW_INTERCEPT_DECISION_COOLDOWN_SECONDS`:
- `15` (default): reuse recent allow/block decisions briefly per tool to avoid repeated popups.
- `0`: disable decision caching (prompt every matching tool call).

### Popup Guard Fallback

The log-based popup guard remains installed as fallback defense-in-depth.

If you do not see OpenClaw UI approvals in the browser due to token mismatch/reconnect issues, this popup guard still provides a visible local alert path.

Recent hardening for popup spam control:
- Singleton lock: only one popup-guard process can run at a time.
- Fallback suppression: popup guard stays quiet when primary pre-exec approvals are available.

### Popup Catalog (What Is Highlighted/Shown)

1. `Sentinel OpenClaw Guard`
- Trigger: risky tool activity (`exec`, `process`, `write`, `edit`, `apply_patch`).
- UI choices: `Block Tool` or `Ignore`.
- Effect: `Block Tool` removes the detected tool from allowlist (future runs).

2. `Sentinel Injection Alert`
- Trigger: prompt injection / jailbreak detection in `sentinel-injection-guard`.
- UI: warning popup (or terminal alert fallback).
- Effect: strict tool profile is enforced immediately.

3. `[Sentinel Alert] ...` terminal/log alert
- Trigger: same events when desktop popup cannot be shown.
- Effect: operator-visible alert in terminal/gateway logs.

### Alternatives to `before_tool_call` Today

When you need enforcement now (without relying on experimental pre-exec hooks), use:
- Tool allowlist hardening (`tools.sandbox.tools.allow`) to remove risky writers by default.
- OpenClaw approvals baseline (`ask=always`, `askFallback=deny`) for explicit gate behavior.
- Sentinel popup guard for visible alerts and fast operator response.
- Sentinel injection guard strict mode (`sentinel-injection-guard`) to auto-downgrade tool access when prompt injection/jailbreak is detected.

### Isolation Healthcheck

Run the built-in live verification script:

```bash
./scripts/openclaw_isolation_healthcheck.sh
```

What it checks:
- OpenClaw sandbox network config (`agents.defaults.sandbox.docker.network`)
- Docker network exists and is `Internal=true`
- Sandbox and proxy containers are both attached to the expected internal network
- Direct sandbox egress test is blocked
- Proxy endpoint reachability from sandbox is allowed

Exit codes:
- `0`: all checks passed
- `1`: one or more isolation checks failed
- `2`: prerequisites missing (`openclaw`, `docker`, `python3`)

Strict no-write profile example (recommended for high assurance):

```bash
openclaw config set --json tools.sandbox.tools.allow '[
  "read",
  "image",
  "sessions_list",
  "sessions_history",
  "sessions_send",
  "sessions_spawn",
  "session_status"
]'
openclaw sandbox recreate --all
```

If a write slips through anyway:
- Delete newly created files immediately in the OpenClaw workspace.
- Restore modified files from your VCS/backup baseline.
- Recreate sandboxes to clear transient state.
- `sentinel-injection-guard` automates deletion for `write` outputs in flagged sessions.

## Validation

- Installer fallback chain and non-interactive hardening behavior.
  - Validation: Tested by `tests/test_install_openclaw_with_sentinel.py::InstallOpenClawWithSentinelTests`.
- Sandbox configuration payload defaults and hardening fields.
  - Validation: Tested by `tests/test_openclaw_sandbox_configure.py::OpenClawSandboxConfigureTests`.
- Sentinel network override (`--sentinel-network` / `SENTINEL_OPENCLAW_DOCKER_NETWORK`) propagation.
  - Validation: Tested by `tests/test_install_openclaw_with_sentinel.py::InstallOpenClawWithSentinelTests`, `tests/test_openclaw_sandbox_configure.py::OpenClawSandboxConfigureTests`.
- Popup guard risky-tool detection, regex parsing, first-responder decision, timeout fail-safe, and dedupe/debounce behavior.
  - Validation: Tested by `tests/test_openclaw_popup_guard.py::OpenClawPopupGuardTests`.
- Pre-exec plugin risky-tool resolution and fallback controls.
  - Validation: Tested by `openclaw-plugins/sentinel-preexec/tests/preexec.test.mjs`.
- Injection guard heuristic detection, strict-tool enforcement helpers, and workspace-safe deletion path resolution.
  - Validation: Tested by `openclaw-plugins/sentinel-injection-guard/tests/injection-guard.test.mjs`.
- Version caveats and operational recommendations.
  - Validation: Non-executable rationale.
