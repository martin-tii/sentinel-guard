# Project Sentinel: Security Framework for AI Agents

> **"Zero Trust Agency"**: Treat the Agent as a potentially compromised entity that must be monitored and restricted.

Project Sentinel is a "Sidecar Supervisor" middleware designed to protect users and systems from the risks associated with autonomous AI agents. It intercepts all agent actions and enforces strict security policies.

## 🛡️ Architecture: The Pillars of Protection

1.  **The Airlock (Input Sanitization)**
    *   **Keyword Filtering**: Blocks legacy prompt injection patterns.
    *   **AI Judge (New)**: Uses **LlamaGuard 3** to semantically analyze input for malicious intent.
2.  **The Jail (Runtime Isolation)**
    *   **Isolation-First Mode (New)**: Run untrusted agent commands in a separate Docker sandbox via `sentinel-isolate`.
    *   In-process monkey patches remain available for compatibility, but are not a hard security boundary.
3.  **The Governor (Action Firewall)**
    *   **Action Interception**: Patches `subprocess.run`, `subprocess.Popen`, `os.system`, `requests` session requests, `urllib.request.urlopen`, `http.client` requests, and `builtins.open`.
    *   **Optional Socket Fail-Safe (V2)**: Can patch `socket.socket.connect` as a low-level fallback for non-standard clients.
    *   **Static Whitelisting**: Only allows approved commands and network hosts.
    *   **Shell-Aware Command Policy**: Applies strict operator blocking for `shell=True` and command-base whitelisting for argv/list execution.
    *   **Phishing Guard (New)**: Heuristic detection of suspicious URLs and brand impersonation.
    *   **Smart Heuristics**: Blocks dangerous patterns like `wget | sh` or destructive shell chaining.

## 🚀 Getting Started (Isolation-First)

### Prerequisites

- Docker Engine
- Docker Compose v2 (`docker compose`)
- Docker daemon running (Docker Desktop started, or `dockerd` active)

### Quickstart

One-command demo:

```bash
./run_demo.sh
```

`run_demo.sh` uses strict mode (`network_mode: none`) by default.

Build:

```bash
docker compose build
```

Run strict sandbox mode (recommended default):

```bash
docker compose --profile strict run --rm sentinel-strict
```

Run standard sandbox mode (only when networking is required):

```bash
docker compose --profile standard run --rm sentinel-standard
```

Run an arbitrary agent command in isolated mode (recommended):

```bash
sentinel-isolate --build-if-missing -- python your_agent.py
```

## 🧪 Local Development Setup

### Prerequisites

- Python 3.11+
- [Ollama](https://ollama.com/) (Required for AI Judge / LlamaGuard 3)
- pip

### Installation

1.  Install from package:
    ```bash
    pip install sentinel-guard
    ```

2.  Optional (development from source):
    ```bash
    git clone https://github.com/yourusername/sentinel-guard.git
    cd sentinel-guard
    pip install -e .
    ```

3.  Ensure Ollama is running LlamaGuard:
    ```bash
    ollama run llama-guard3
    ```

## ⚙️ Configuration

Policies are defined in `sentinel.yaml`.

```yaml
allowed_paths:
  - "./workspace"
allowed_commands:
  - "echo"
  - "ls"
host_match_mode: "exact"   # exact | subdomain
allowed_hosts:
  - host: "api.openai.com"
    match: "exact"
    schemes: ["https"]
    ports: [443]
  - "pypi.org"  # inherits host_match_mode and allows default ports

policy_integrity:
  tamper_detection: true

# 🧠 AI JUDGE CONFIG
judge:
  enabled: true
  provider: "ollama"
  model: "llama-guard3"
  endpoint: "http://localhost:11434/api/generate"
  runtime_judge_threshold: 0.4  # model adjudication starts at this heuristic risk
  risk_threshold: 0.7
  fail_open: false  # high-risk runtime actions fail-closed when judge is unavailable

# 🎣 ANTI-PHISHING
phishing:
  enabled: true
  blocked_tlds: [".xyz", ".top", ".zip"] 

# 🔒 FAIL-SAFE COMMAND BASE DENYLIST
# These are blocked even if accidentally added to allowed_commands.
blocked_command_bases:
  - "python"
  - "bash"
  - "sh"

# 🌐 SOCKET FAIL-SAFE (V2)
network_failsafe:
  socket_connect: true       # enabled by default for low-level egress checks
  allow_private_network: false
  blocked_hosts: []          # optional host/domain denylist
  blocked_ips: []            # optional IP/CIDR denylist
  allowed_ips: []            # optional IP/CIDR allowlist
```

### Environment Variable Controls

Emergency kill switch:

```bash
export SENTINEL_DISABLE=true
```

Disable now requires explicit dual control:

```bash
export SENTINEL_DISABLE=true
export SENTINEL_ALLOW_DISABLE=true
```

If `SENTINEL_DISABLE` is set without `SENTINEL_ALLOW_DISABLE=true`,
Sentinel raises a runtime error and stays enforced.

Inject policy from environment (useful in Docker/Kubernetes):

```bash
export SENTINEL_POLICY_CONTENT="$(cat sentinel.yaml)"
```

When `SENTINEL_POLICY_CONTENT` is present, Sentinel loads policy from that value first,
then falls back to file-based `sentinel.yaml` if env YAML is invalid.

High-assurance policy integrity controls:

```bash
# Verify exact policy hash at startup.
export SENTINEL_POLICY_SHA256="<sha256-of-policy-content>"

# Optional HMAC-based signature verification.
export SENTINEL_POLICY_HMAC_KEY="<shared-secret>"
export SENTINEL_POLICY_HMAC_SHA256="<hmac-sha256-of-policy-content>"

# Detect policy drift at runtime (fail-closed when changed).
export SENTINEL_POLICY_IMMUTABLE=true
```

Production hard-fail mode:

```bash
export SENTINEL_PRODUCTION=true
```

When production mode is enabled, Sentinel requires:
- signed policy verification (`SENTINEL_POLICY_SHA256` or `SENTINEL_POLICY_HMAC_SHA256`)
- immutable policy checks (`SENTINEL_POLICY_IMMUTABLE=true`)

For isolated execution in production, networking is blocked by default.
To explicitly allow a networked exception:

```bash
export SENTINEL_ALLOW_NETWORK_IN_PRODUCTION=true
```

## 🕹️ Usage

### Isolation-First Execution (Recommended)

```bash
# Runs in a separate container with read-only rootfs, dropped caps,
# no-new-privileges, seccomp profile, and network disabled by default.
sentinel-isolate --build-if-missing -- python your_agent.py
```

Optional flags:

```bash
sentinel-isolate \
  --workspace ./sandbox-workspace \
  --policy ./sentinel.yaml \
  --network none \
  -- python your_agent.py
```

### In-Process Integration (Compatibility Mode)

```python
from src.core import (
  activate_sentinel,
  deactivate_sentinel,
  set_approval_handler,
  clear_approval_handler,
  console_approval_handler,
)

# 🛡️ Activate protections early (compatibility mode only)
activate_sentinel()
# Safe to call more than once (idempotent)
activate_sentinel()

# Blocked by Phishing Guard
import requests
requests.get("http://google.com.verify.xyz") 

# Blocked by AI Judge Heuristics
import subprocess
subprocess.run("rm -rf /", shell=True)

# Restore original runtime behavior when needed
deactivate_sentinel()
```

Compatibility mode note:
- In-process hooks improve safety but cannot provide zero-breach guarantees against code that can execute in the same interpreter.
- Use `sentinel-isolate` for hard process/container boundaries.

### Standard Integration Pattern (Moltbot / Any Agent)

Install Sentinel in the same environment as the agent:

```bash
pip install sentinel-guard
```

Recommended startup pattern:

```python
# 1) Initialize guardrails before any tool/network/file calls.
from src.core import activate_sentinel, set_approval_handler, tkinter_approval_handler

activate_sentinel()
set_approval_handler(tkinter_approval_handler)

# 2) Run your agent loop normally.
def run_agent(agent):
    while True:
        task = agent.next_task()
        if task is None:
            break
        agent.handle(task)
```

Recommended shutdown pattern:

```python
from src.core import deactivate_sentinel

deactivate_sentinel()
```

### User Approval Workflow (Popup Hook)

When Sentinel blocks an action, you can decide in real time with an approval callback.
Use this to wire a minimal popup with **Approve** / **Reject** in your host app.

```python
from src.core import (
  set_approval_handler,
  clear_approval_handler,
  tkinter_approval_handler,
  console_approval_handler,
)

def my_popup_handler(alert):
    # alert.action, alert.target, alert.reason, alert.recommendation
    # return True to approve override, False to reject
    return show_security_popup(alert)  # host UI function

set_approval_handler(my_popup_handler)
# ...
clear_approval_handler()
```

Built-in minimal popup:

```python
set_approval_handler(tkinter_approval_handler)
```

Example popup:

<img src="docs/images/approval-popup.png" alt="Sentinel approval popup" width="860" />

For terminal-only usage, use `console_approval_handler`.

### Interaction Examples

Example 1: blocked command (default reject)

```text
[BLOCKED (Shell Injection Risk)] EXEC_COMMAND: ls && echo 'Hacked'
[REJECTED] SECURITY_ALERT: command_execution -> ls && echo 'Hacked'
Reason: Complex shell chaining/redirection/substitution is not allowed.
```

Example 2: approval popup reject

```text
Action: file_access
Target: /tmp/sentinel-approval-test.txt
Recommendation: Reject unless the file path is expected for this task.
User Decision: Reject
Result: PermissionError
```

Example 3: approval popup approve

```text
Action: file_access
Target: /tmp/sentinel-approval-test.txt
User Decision: Approve
[APPROVED] SECURITY_OVERRIDE: file_access -> /tmp/sentinel-approval-test.txt
Result: write completed
```

### Running Verification Tests

#### Basic Test
```bash
python tests/verify_fixes.py
```

#### Smart Test (AI Judge + Phishing)
```bash
python examples/smart_test.py
```

> [!NOTE]  
> On some systems, `python3` may point to a different global installation. Ensure you use `python` while the `sentinel-guard` conda environment is active.

> [!NOTE]
> Sentinel now loads `sentinel.yaml` independent of your current working directory. You can run tests from either the project root or inside `sentinel-guard`.

> [!NOTE]
> Activation is idempotent. Repeated `activate_sentinel()` calls do not stack patches, and `deactivate_sentinel()` restores original functions.

> [!NOTE]
> Socket fail-safe gives broader coverage but lower context. At socket layer Sentinel sees host/IP and port, not full URL paths.

## 📝 Audit Logging

All actions are logged to `audit.log` for real-time monitoring and forensics.

## 🤖 Integration with Moltbot (or any Agent)

There are two ways to protect your agent.

### Method A: The Wrapper (Recommended)

Use this method to protect an agent without modifying its source code.

1. Install Sentinel:
   ```bash
   pip install -e .
   ```

2. Run your agent via the wrapper:
   ```bash
   python examples/moltbot_wrapper.py
   ```

### Method B: Direct Code Injection

Add these lines to the very top of your agent's entry point (for example, `main.py`):

```python
from src.core import activate_sentinel

# Must be the first thing that runs!
activate_sentinel()

# ... rest of your agent code ...
```

## 🚢 Deployment

Containerized sandbox deployment assets and hardening details are documented in `DEPLOYMENT.md`.
