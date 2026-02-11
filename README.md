# Project Sentinel: Security Framework for AI Agents

> **"Zero Trust Agency"**: Treat the Agent as a potentially compromised entity that must be monitored and restricted.

Project Sentinel is a "Sidecar Supervisor" middleware designed to protect users and systems from the risks associated with autonomous AI agents. It intercepts all agent actions and enforces strict security policies.

## 🛡️ Architecture: The Pillars of Protection

1.  **The Airlock (Input Sanitization)**
    *   **Keyword Filtering**: Blocks legacy prompt injection patterns.
    *   **AI Judge (New)**: Uses **LlamaGuard 3** to semantically analyze input for malicious intent.
2.  **The Jail (Runtime Isolation)**
    *   Restricts file system access to a specific `./workspace`.
    *   Blocks access to sensitive files like `.env`, `.ssh`, and system directories.
3.  **The Governor (Action Firewall)**
    *   **Action Interception**: Patches `subprocess.run`, `subprocess.Popen`, `os.system`, `requests` session requests, `urllib.request.urlopen`, `http.client` requests, and `builtins.open`.
    *   **Optional Socket Fail-Safe (V2)**: Can patch `socket.socket.connect` as a low-level fallback for non-standard clients.
    *   **Static Whitelisting**: Only allows approved commands and network hosts.
    *   **Shell-Aware Command Policy**: Applies strict operator blocking for `shell=True` and command-base whitelisting for argv/list execution.
    *   **Phishing Guard (New)**: Heuristic detection of suspicious URLs and brand impersonation.
    *   **Smart Heuristics**: Blocks dangerous patterns like `wget | sh` or destructive shell chaining.

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- [Ollama](https://ollama.com/) (Required for AI Judge / LlamaGuard 3)
- Conda (Recommended)

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/sentinel-guard.git
    cd sentinel-guard
    ```

2.  Create and activate the environment:
    ```bash
    conda create -n sentinel-guard python=3.11 -y
    conda activate sentinel-guard
    pip install -r requirements.txt
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
allowed_hosts:
  - "api.openai.com"

# 🧠 AI JUDGE CONFIG
judge:
  enabled: true
  provider: "ollama"
  model: "llama-guard3"
  endpoint: "http://localhost:11434/api/generate"
  risk_threshold: 0.7
  fail_open: false  # default is fail-closed when judge is unavailable

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

# 🌐 OPTIONAL SOCKET FAIL-SAFE (V2)
network_failsafe:
  socket_connect: false      # enable to patch socket.socket.connect
  allow_private_network: false
  blocked_hosts: []          # optional host/domain denylist
  blocked_ips: []            # optional IP/CIDR denylist
  allowed_ips: []            # optional IP/CIDR allowlist
```

## 🕹️ Usage

### Integrating with an Agent

```python
from src.core import (
  activate_sentinel,
  deactivate_sentinel,
  set_approval_handler,
  clear_approval_handler,
  console_approval_handler,
)

# 🛡️ Activate protections early
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

![Sentinel approval popup](docs/images/approval-popup.png)

For terminal-only usage, use `console_approval_handler`.

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
