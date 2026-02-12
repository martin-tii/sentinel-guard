# Sentinel Guard Docs

Use this page as the documentation entry point.

## Start Here

- New user: [Quickstart](./QUICKSTART.md)
- Choosing execution model: [Usage Modes](./USAGE_MODES.md)
- Policy and env vars: [Configuration](./CONFIGURATION.md)

## Security and Operations

- Deployment hardening: [../DEPLOYMENT.md](../DEPLOYMENT.md)
- Security posture and residual risks: [../SECURITY_ASSESSMENT.md](../SECURITY_ASSESSMENT.md)
- OpenClaw integration: [OPENCLAW_INTEGRATION.md](./OPENCLAW_INTEGRATION.md)
- Approval UI details: [Usage Modes](./USAGE_MODES.md#approval-handlers)

## Approval UI

![Sentinel approval popup](./images/approval-popup.png)

## Typical Paths

- Safest default (no network):
  - `sentinel-isolate --build-if-missing -- python your_agent.py`
- Networked isolation (gold standard):
  - `docker compose --profile proxied up --build --abort-on-container-exit sentinel-proxied`
- Networked isolated run (lower assurance):
  - `sentinel-isolate --network bridge --enforce-proxy --proxy http://sentinel-proxy:3128 --build-if-missing -- python your_agent.py`
- Compatibility mode (guardrails only):
  - call `activate_sentinel()` early in your process.
- OpenClaw CLI in Sentinel isolation:
  - `sentinel-openclaw -- gateway --port 18789`

## Prompt Injection Defense

Sentinel supports an optional Prompt Guard pre-filter for prompt injection/jailbreak detection.
This is separate from the broad AI judge (Llama Guard) and can be layered.

See:
- Configuration: [Configuration](./CONFIGURATION.md)
