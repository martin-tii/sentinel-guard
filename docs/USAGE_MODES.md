# Usage Modes

Sentinel Guard supports two modes with different trust boundaries.

## 1) Isolation Mode (Recommended for Untrusted Code)

`sentinel-isolate` runs commands in a hardened Docker container.

```bash
sentinel-isolate --build-if-missing -- python your_agent.py
```

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

Gold standard for networked isolation:

```bash
docker compose --profile proxied up --build --abort-on-container-exit sentinel-proxied
```

- Mechanism: Docker network topology + proxy sidecar.
- Security effect: direct egress is blocked by topology, not just app-level env vars.

Lower-assurance alternative:

```bash
sentinel-isolate --network bridge --enforce-proxy --proxy http://sentinel-proxy:3128 --build-if-missing -- python your_agent.py
```

- Mechanism: proxy environment variables inside container.
- Security effect: a malicious payload can try to unset/ignore proxy vars and attempt direct egress if topology/firewall allows it.

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

Important: compatibility mode is not a hard containment boundary against determined malicious code in the same interpreter.

## Approval Handlers

```python
from src.core import set_approval_handler, tkinter_approval_handler
set_approval_handler(tkinter_approval_handler)
```

You can also use `console_approval_handler` or a custom callback.

![Sentinel approval popup](./images/approval-popup.png)

If no handler is explicitly set, Sentinel can still prompt by default:

```bash
export SENTINEL_APPROVAL_MODE=auto   # auto | tkinter | console | reject
```

## Verification

```bash
pytest -q
```

Performance benchmark (tamper-check interval impact):

```bash
python scripts/benchmark_integrity.py
```
