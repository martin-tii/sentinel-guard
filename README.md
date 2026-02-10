# Project Sentinel: Security Framework for AI Agents

> **"Zero Trust Agency"**: Treat the Agent as a potentially compromised entity that must be monitored and restricted.

Project Sentinel is a "Sidecar Supervisor" middleware designed to protect users and systems from the risks associated with autonomous AI agents. It intercepts all agent actions and enforces strict security policies.

## 🛡️ Architecture: The Three Pillars

1.  **The Airlock (Input Sanitization)**
    *   Strips hidden text and instructions from incoming data.
    *   Prevents indirect prompt injection attacks.
2.  **The Jail (Runtime Isolation)**
    *   Restricts file system access to a specific `./workspace`.
    *   Blocks access to sensitive files like `.env`, `.ssh`, and system directories.
3.  **The Governor (Action Firewall)**
    *   Intercepts tool calls (`os.system`, `subprocess`, `requests`).
    *   Enforces policies (e.g., only allow `curl` to whitelisted domains).

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Conda (optional but recommended)

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
    pip install requests pyyaml
    ```

## ⚙️ Configuration

Policies are defined in `sentinel.yaml`. You can customize:

-   `allowed_paths`: Directories the agent can read/write.
-   `blocked_paths`: Explicitly forbidden paths.
-   `allowed_commands`: Whitelisted shell commands.
-   `allowed_hosts`: Whitelisted network domains.
-   `blocked_keywords`: Terms to filter from input (e.g., "ignore previous instructions").

**Example `sentinel.yaml`**:
```yaml
allowed_paths:
  - "./workspace"
blocked_paths:
  - "/etc"
  - "~/.ssh"
allowed_commands:
  - "echo"
  - "ls"
allowed_hosts:
  - "api.openai.com"
```

## 🕹️ Usage

### Integrating with an Agent

Import `activate_sentinel` at the very beginning of your agent's script.

```python
from src.core import activate_sentinel

# 🛡️ Activate protections correctly
activate_sentinel()

# Any subsequent risky calls will be intercepted
with open("/etc/passwd", "r") as f: # -> PermissionError: Access blocked
    pass
```

### Running the Example

We provide a `risky_agent.py` script that simulates a compromised agent attempting dangerous actions.

```bash
python examples/risky_agent.py
```

Check the `audit.log` file to see the blocked attempts.

```text
[BLOCKED] FILE_ACCESS: /etc/passwd
[BLOCKED] EXEC_COMMAND: rm -rf /
[BLOCKED] NETWORK_ACCESS: http://evil.com
```

## 📝 Audit Logging

All actions (allowed and blocked) are logged to `audit.log` and the console for real-time monitoring.

---
*Built for the AI Safety Community.*
