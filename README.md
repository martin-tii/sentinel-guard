# Project Sentinel: Security Framework for AI Agents

Sentinel Guard is a security sidecar for AI agents.

It provides:
- Input safety checks (keywords + AI judge)
- Prompt Guard layer for prompt injection/jailbreak detection (default on)
- Runtime action controls (file/command/network policies)
- Human-approval escalation
- Isolation-first execution with hardened Docker (`sentinel-isolate`)

## Recommended Path

Use isolation mode for untrusted workloads:

```bash
sentinel-isolate --build-if-missing -- python your_agent.py
```

For official OpenClaw CLI workloads, use:

```bash
sentinel-openclaw -- gateway --port 18789
```

If you are onboarding a new workload, start with seccomp complain mode, then tighten:

```bash
sentinel-isolate --seccomp-mode log --build-if-missing -- python your_agent.py
```

For networked workloads, use the Docker Compose proxied profile as the gold standard:

```bash
docker compose --profile proxied up --build --abort-on-container-exit sentinel-proxied
```

`sentinel-isolate --network bridge --enforce-proxy --proxy ...` is a lower-assurance option.
It relies on proxy environment variables inside the container. A malicious payload with code execution
can attempt direct egress if host/network topology does not block it.

## Input Guard Layers

Sentinel can use both models as a layered defense:

- Prompt Guard (`meta-llama/Prompt-Guard-86M` via Hugging Face `transformers`):
  - Specialized detector for prompt injection and jailbreak patterns.
- Llama Guard (configured through the existing judge endpoint):
  - Broader safety classification layer.

They overlap partially, but are not identical. Prompt Guard is a specialized pre-filter; Llama Guard remains the broader policy check.

By default, Sentinel also performs automatic prompt-injection scanning on:
- `builtins.input()` values
- text file reads in intercepted `open`/`io.open`/`Path.open`
- text-like HTTP response bodies from intercepted `requests`/`urlopen`

Detection handling defaults to approval-required (`judge.injection_scan.on_detection: approval`), which fails safe to reject in headless/no-handler environments.

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
- OpenClaw integration: [docs/OPENCLAW_INTEGRATION.md](docs/OPENCLAW_INTEGRATION.md)
- Integrity/performance benchmark: [scripts/benchmark_integrity.py](scripts/benchmark_integrity.py)

## Approval UI Preview

![Sentinel approval popup](docs/images/approval-popup.png)

## Development

```bash
pip install -e .
pytest -q
```

To enable Prompt Guard support:

```bash
pip install -e ".[prompt-guard]"
# plus an inference backend such as PyTorch if not already installed
```

When Prompt Guard is enabled in `sentinel.yaml` (default), make sure model access is available in your environment:
- You may need Hugging Face authentication/access approval for Meta model artifacts.
- Use `huggingface-cli login` (or `HF_TOKEN`) where required.
