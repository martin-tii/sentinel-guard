import builtins
import os
import subprocess
import requests # Assuming requests is used, we'll patch it
from urllib.parse import urlparse
from .policy import PolicyEnforcer
from .utils import audit, is_phishing_url
from .judge import AIJudge

# Initialize Components
policy = PolicyEnforcer()

judge_config = policy.policy.get("judge", {})
judge_config.setdefault("endpoint", "http://localhost:11434/api/generate")
judge_config.setdefault("model", "llama-guard3")
judge_config.setdefault("risk_threshold", 0.7)
judge_config.setdefault("fail_open", False)
ai_judge = AIJudge(judge_config)
phishing_config = policy.policy.get("phishing", {})

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
_original_run = subprocess.run
_original_popen = subprocess.Popen
_original_os_system = os.system

def _normalize_command(command):
    if isinstance(command, list):
        return " ".join(str(part) for part in command)
    return str(command)

def sentinel_run(*args, **kwargs):
    command = args[0] if args else kwargs.get('args')
    shell = kwargs.get("shell", False)
    command_str = _normalize_command(command)
    
    # 1. Static Policy Check (The Law)
    policy.check_command(command, shell=shell)

    # 2. AI Judge Check (The Spirit of the Law)
    # We ask LlamaGuard/Heuristics if this specific command looks dangerous
    verdict = ai_judge.evaluate_action("subprocess.run", command_str)
    
    if not verdict["safe"]:
        audit("AI_JUDGE", f"Flagged action: {command_str} | Reason: {verdict.get('reason')}", "FLAGGED")
        
        # In this MVP, we block automatically if flagged high risk.
        # In a full UI, this would trigger the "Ask Human" popup.
        if verdict.get("needs_human"):
            print(f"\n[⚖️ AI JUDGE ALERT] Blocked: {verdict['reason']}")
            raise PermissionError(f"AI Judge blocked this action: {verdict['reason']}")

    return _original_run(*args, **kwargs)

def sentinel_popen(*args, **kwargs):
    command = args[0] if args else kwargs.get("args")
    shell = kwargs.get("shell", False)
    command_str = _normalize_command(command)
    policy.check_command(command, shell=shell)
    verdict = ai_judge.evaluate_action("subprocess.Popen", command_str)
    if not verdict["safe"] and verdict.get("needs_human"):
        audit("AI_JUDGE", f"Flagged action: {command_str} | Reason: {verdict.get('reason')}", "FLAGGED")
        raise PermissionError(f"AI Judge blocked this action: {verdict['reason']}")
    return _original_popen(*args, **kwargs)

def sentinel_system(command):
    normalized = _normalize_command(command)
    policy.check_command(normalized, shell=True)
    verdict = ai_judge.evaluate_action("os.system", normalized)
    if not verdict["safe"] and verdict.get("needs_human"):
        audit("AI_JUDGE", f"Flagged action: {normalized} | Reason: {verdict.get('reason')}", "FLAGGED")
        raise PermissionError(f"AI Judge blocked this action: {verdict['reason']}")
    return _original_os_system(command)

# 3. Network Interceptor (The Governor + Phishing Guard)
_original_session_request = requests.sessions.Session.request
_sentinel_active = False

def _is_internal_judge_endpoint(url):
    try:
        judge_host = urlparse(ai_judge.endpoint).hostname
        target_host = urlparse(url).hostname
        return bool(judge_host and target_host and judge_host == target_host)
    except Exception:
        return False

def _enforce_network_policy(url):
    # 1. Phishing Check (Sandbox Event)
    is_phish, reason = is_phishing_url(url, phishing_config)
    if is_phish:
        audit("PHISHING_BLOCK", f"{url} -> {reason}", "BLOCKED")
        raise PermissionError(f"Phishing Risk Detected: {reason}")

    # Allow AI Judge's own model endpoint to avoid self-blocking.
    if _is_internal_judge_endpoint(url):
        audit("NETWORK_ACCESS", f"{url} (AI Judge endpoint)", "ALLOWED")
        return

    # 2. Static Policy Check (Allow/Block Lists)
    policy.check_network(url)

def sentinel_session_request(self, method, url, **kwargs):
    _enforce_network_policy(url)
    return _original_session_request(self, method, url, **kwargs)

# --- Activation ---

def activate_sentinel():
    """Activates the Sentinel monitoring system."""
    global _sentinel_active
    if _sentinel_active:
        audit("SYSTEM", "Sentinel already active. Skipping re-patch.", "INFO")
        return

    audit("SYSTEM", "Sentinel Activated. Monitoring engaged.", "INFO")
    
    # Monkey Patching
    builtins.open = sentinel_open
    subprocess.run = sentinel_run
    subprocess.Popen = sentinel_popen
    os.system = sentinel_system
    requests.sessions.Session.request = sentinel_session_request
    _sentinel_active = True

    # Airlock is passive, used when processing input explicitly

def deactivate_sentinel():
    """Restores original runtime functions and disables Sentinel interception."""
    global _sentinel_active
    if not _sentinel_active:
        audit("SYSTEM", "Sentinel already inactive. Nothing to restore.", "INFO")
        return

    builtins.open = _original_open
    subprocess.run = _original_run
    subprocess.Popen = _original_popen
    os.system = _original_os_system
    requests.sessions.Session.request = _original_session_request
    _sentinel_active = False
    audit("SYSTEM", "Sentinel Deactivated. Original runtime restored.", "INFO")
    
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
