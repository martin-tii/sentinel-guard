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
  --network none \
  --seccomp-mode enforce \
  -- python your_agent.py
```

- `--network none|bridge|host`
- `--seccomp-mode enforce|log|off`
- `--proxy` / `--no-proxy` for controlled egress in networked runs

### Seccomp onboarding pattern

1. Start with `--seccomp-mode log` on a new workload.
2. Capture denied syscalls from kernel logs.
3. Tune profile.
4. Move back to `--seccomp-mode enforce`.

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

## Verification

```bash
pytest -q
```
