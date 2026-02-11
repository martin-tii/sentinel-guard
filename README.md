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
    *   **Action Interception**: Patches `subprocess.run`, `subprocess.Popen`, `os.system`, `requests` session requests, and `builtins.open`.
    *   **Static Whitelisting**: Only allows approved commands and network hosts.
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
```

## 🕹️ Usage

### Integrating with an Agent

```python
from src.core import activate_sentinel, deactivate_sentinel

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

## 📝 Audit Logging

All actions are logged to `audit.log` for real-time monitoring and forensics.
