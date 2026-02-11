# Project Sentinel: Security Framework for AI Agents

Sentinel Guard is a security sidecar for AI agents.

It provides:
- Input safety checks (keywords + AI judge)
- Runtime action controls (file/command/network policies)
- Human-approval escalation
- Isolation-first execution with hardened Docker (`sentinel-isolate`)

## Recommended Path

Use isolation mode for untrusted workloads:

```bash
sentinel-isolate --build-if-missing -- python your_agent.py
```

If you are onboarding a new workload, start with seccomp complain mode, then tighten:

```bash
sentinel-isolate --seccomp-mode log --build-if-missing -- python your_agent.py
```

## Important Security Note

Compatibility mode (`activate_sentinel()` in-process hooks) is guardrails for accidental/buggy behavior, not a hard containment boundary against determined malicious code.

Use `sentinel-isolate` for hard process/container boundaries.

Blocked actions can default to user-approval prompts when no custom handler is set:
- `SENTINEL_APPROVAL_MODE=auto` (default), `tkinter`, `console`, or `reject`.

## Documentation Map

- Start here: [docs/README.md](docs/README.md)
- Quickstart: [docs/QUICKSTART.md](docs/QUICKSTART.md)
- Usage modes: [docs/USAGE_MODES.md](docs/USAGE_MODES.md)
- Configuration and env vars: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
- Deployment hardening: [DEPLOYMENT.md](DEPLOYMENT.md)
- Security posture: [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md)
- Moltbot integration: [docs/MOLTBOT_INTEGRATION.md](docs/MOLTBOT_INTEGRATION.md)

## Approval UI Preview

![Sentinel approval popup](docs/images/approval-popup.png)

## Development

```bash
pip install -e .
pytest -q
```
