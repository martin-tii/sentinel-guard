# Sentinel Guard Docs

Use this page as the documentation entry point.

## Start Here

- New user: [Quickstart](./QUICKSTART.md)
- Choosing execution model: [Usage Modes](./USAGE_MODES.md)
- Policy and env vars: [Configuration](./CONFIGURATION.md)

## Security and Operations

- Deployment hardening: [../DEPLOYMENT.md](../DEPLOYMENT.md)
- Security posture and residual risks: [../SECURITY_ASSESSMENT.md](../SECURITY_ASSESSMENT.md)
- Moltbot integration: [MOLTBOT_INTEGRATION.md](./MOLTBOT_INTEGRATION.md)
- Approval UI details: [Usage Modes](./USAGE_MODES.md#approval-handlers)

## Approval UI

![Sentinel approval popup](./images/approval-popup.png)

## Typical Paths

- Safest default (no network):
  - `sentinel-isolate --build-if-missing -- python your_agent.py`
- Networked isolated run with controlled egress:
  - `sentinel-isolate --network bridge --proxy http://proxy.internal:8080 --build-if-missing -- python your_agent.py`
- Compatibility mode (guardrails only):
  - call `activate_sentinel()` early in your process.
