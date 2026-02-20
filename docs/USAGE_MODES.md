# Usage Modes

Sentinel Guard supports two modes with different trust boundaries.

## When to Choose Each Mode

| Mode | Use it when | Security boundary |
| --- | --- | --- |
| Isolation Mode | Running untrusted code or unknown third-party agents | Strongest boundary (container/process isolation) |
| Compatibility Mode | Running trusted code and you need in-process guardrails | Guardrails only (not hard containment) |

## 1) Isolation Mode (Recommended for Untrusted Code)

`sentinel-isolate` runs commands in a hardened Docker container.

```bash
sentinel-isolate --build-if-missing -- python your_agent.py
```

For networked high-assurance runs, use Gold standard (topology-enforced proxy routing):
- [Deployment: Proxied Mode](./DEPLOYMENT.md#3-proxied-mode-gold-standard-for-networked-isolation)

For OpenClaw-specific hardening:
- [OpenClaw Integration](./OPENCLAW_INTEGRATION.md)

### Key flags

```bash
sentinel-isolate \
  --workspace ./sandbox-workspace \
  --policy ./sentinel.yaml \
  --network bridge \
  --enforce-proxy \
  --proxy http://sentinel-proxy:3128 \
  --seccomp-profile strict \
  --seccomp-mode enforce \
  -- python your_agent.py
```

- `--network none|bridge|host`
- `--enforce-proxy` requires a proxy for networked runs
- `--proxy` / `--no-proxy` for controlled egress
- `--seccomp-profile strict|datasci|custom`
- `--seccomp-mode enforce|log|off`

### Networked isolation levels

Gold standard (topology-enforced proxy routing):

```bash
docker compose --profile proxied up --build --abort-on-container-exit sentinel-proxied
```

- Mechanism: Docker network topology + proxy sidecar.
- Security effect: direct egress is blocked by topology, not just app-level env vars.

Lower-assurance bridge + proxy env:

```bash
sentinel-isolate --network bridge --enforce-proxy --proxy http://sentinel-proxy:3128 --build-if-missing -- python your_agent.py
```

- Mechanism: proxy environment variables inside container.
- Security effect: malicious payloads can attempt to unset/ignore proxy vars and try direct egress if topology/firewall allows it.

### Seccomp onboarding pattern

1. Start with `--seccomp-mode log` on a new workload.
2. Capture denied syscalls from kernel logs.
3. Tune profile.
4. Move back to `--seccomp-mode enforce`.

For broader compatibility on scientific/ML stacks, use `--seccomp-profile datasci`.

## 2) Compatibility Mode (Guardrails in Same Process)

Use runtime hooks for accidental/buggy behavior prevention when you cannot isolate.

```python
from src.core import activate_sentinel, deactivate_sentinel

activate_sentinel()
# run your app
# ...
deactivate_sentinel()
```

Important: Compatibility mode is not hard containment against determined malicious code in the same interpreter.

### Automatic Prompt-Injection Scan (Compatibility Mode)

When compatibility mode is active, Sentinel automatically scans untrusted text from:

- `builtins.input()` values
- text file reads through patched `open`/`io.open`/`Path.open`
- text-like HTTP response bodies through patched `requests` and `urlopen`

Behavior is configured under `judge.injection_scan`:

- `on_detection: approval` (default) escalates to approval handler.
- `on_detection: block` denies immediately.
- `on_detection: audit` logs but allows.

If no approval handler is available in headless mode, approval flow rejects by default.

## Approval Handlers

```python
from src.core import set_approval_handler, tkinter_approval_handler
set_approval_handler(tkinter_approval_handler)
```

You can also use `console_approval_handler` or a custom callback.

![Sentinel approval popup](./images/approval-popup.png)

Default approval UX now shows clear choices:
- `Allow once`
- `Always allow this app` (saves a reusable local rule)
- `Block`

Saved approval rules are stored at `~/.sentinel-guard/approval-rules.json` by default
(override path with `SENTINEL_APPROVAL_RULES_PATH`).
Blocked events also include plain-English explanations: what happened, why it was blocked, and what to do next.

If no handler is explicitly set, Sentinel can still prompt by default:

```bash
export SENTINEL_APPROVAL_MODE=auto   # auto | tkinter | console | reject
# or explicitly prefer native desktop popups:
export SENTINEL_APPROVAL_MODE=popup  # popup | tkinter | console | reject
```

## Verification

```bash
pytest -q
```

Performance benchmark (tamper-check interval impact):

```bash
python scripts/benchmark_integrity.py
```

## Validation

Validation mapping is centralized in [VALIDATION_MATRIX.md](./VALIDATION_MATRIX.md).
Run `pytest -q` for full coverage.
