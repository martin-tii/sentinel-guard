import builtins
import subprocess
import requests # Assuming requests is used, we'll patch it
from .policy import PolicyEnforcer
from .utils import audit, is_phishing_url
from .judge import AIJudge

# Initialize Components
policy = PolicyEnforcer()

# In a real app, config would come from sentinel.yaml
judge_config = {
    "endpoint": "http://localhost:11434/api/generate",
    "model": "llama-guard3",
    "risk_threshold": 0.7
}
ai_judge = AIJudge(judge_config)

# --- Interceptors ---

# 1. File System Interceptor (The Jail)
_original_open = builtins.open

def sentinel_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    # 1. Static Policy Check (The Law)
    try:
        policy.check_file_access(file)
    except PermissionError as e:
        raise e
        
    return _original_open(file, mode, buffering, encoding, errors, newline, closefd, opener)

# 2. Command Execution Interceptor (The Governor)
_original_system = subprocess.run

def sentinel_run(*args, **kwargs):
    command = args[0] if args else kwargs.get('args')
    if isinstance(command, list):
        command = " ".join(command)
    
    # 1. Static Policy Check (The Law)
    try:
        policy.check_command(command)
    except PermissionError as e:
        raise e

    # 2. AI Judge Check (The Spirit of the Law)
    # We ask LlamaGuard/Heuristics if this specific command looks dangerous
    verdict = ai_judge.evaluate_action("subprocess.run", command)
    
    if not verdict["safe"]:
        audit("AI_JUDGE", f"Flagged action: {command} | Reason: {verdict.get('reason')}", "FLAGGED")
        
        # In this MVP, we block automatically if flagged high risk.
        # In a full UI, this would trigger the "Ask Human" popup.
        if verdict.get("needs_human"):
            print(f"\n[⚖️ AI JUDGE ALERT] Blocked: {verdict['reason']}")
            raise PermissionError(f"AI Judge blocked this action: {verdict['reason']}")

    return _original_system(*args, **kwargs)

# 3. Network Interceptor (The Governor + Phishing Guard)
_original_get = requests.get

def sentinel_get(url, params=None, **kwargs):
    # 1. Phishing Check (Sandbox Event)
    is_phish, reason = is_phishing_url(url)
    if is_phish:
        audit("PHISHING_BLOCK", f"{url} -> {reason}", "BLOCKED")
        raise PermissionError(f"Phishing Risk Detected: {reason}")

    # 2. Static Policy Check (Allow/Block Lists)
    try:
        policy.check_network(url)
    except PermissionError as e:
        raise e
        
    # (Optional) We could also add AI Judge here for semantic URL analysis
    
    return _original_get(url, params=params, **kwargs)


# --- Activation ---

def activate_sentinel():
    """Activates the Sentinel monitoring system."""
    audit("SYSTEM", "Sentinel Activated. Monitoring engaged.", "INFO")
    
    # Monkey Patching
    builtins.open = sentinel_open
    subprocess.run = sentinel_run
    requests.get = sentinel_get

    # Airlock is passive, used when processing input explicitly
    
def scan_input(text):
    """
    Public API for the Airlock.
    Now checks LlamaGuard FIRST, then keywords.
    """
    # 1. AI Safety Check (LlamaGuard)
    safety = ai_judge.check_input_safety(text)
    if not safety["safe"]:
         raise ValueError(f"🛡️ LlamaGuard Blocked Input: {safety['reason']}")

    # 2. Keyword Check (Legacy/Fast)
    return policy.check_input(text)