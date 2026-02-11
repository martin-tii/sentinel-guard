import builtins
import os
import subprocess
import requests # Assuming requests is used, we'll patch it
import urllib.request as urllib_request
import http.client as http_client
from urllib.parse import urlparse
from .policy import PolicyEnforcer
from .utils import audit, is_phishing_url
from .judge import AIJudge
from .approval import (
    SecurityAlert,
    request_user_approval,
    set_approval_handler,
    clear_approval_handler,
    console_approval_handler,
    tkinter_approval_handler,
)

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


def _enforce_or_escalate(action, target, reason, recommendation):
    alert = SecurityAlert(
        action=action,
        target=str(target),
        reason=str(reason),
        recommendation=recommendation,
    )
    if request_user_approval(alert):
        audit("SECURITY_OVERRIDE", f"{action} -> {target}", "APPROVED")
        return
    raise PermissionError(str(reason))


def sentinel_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    # 1. Static Policy Check (The Law)
    try:
        policy.check_file_access(file)
    except PermissionError as e:
        _enforce_or_escalate(
            action="file_access",
            target=file,
            reason=e,
            recommendation="Reject unless the file path is expected for this task.",
        )

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
    try:
        policy.check_command(command, shell=shell)
    except PermissionError as e:
        _enforce_or_escalate(
            action="command_execution",
            target=command_str,
            reason=e,
            recommendation="Reject unless this command is required and understood.",
        )

    # 2. AI Judge Check (The Spirit of the Law)
    verdict = ai_judge.evaluate_action("subprocess.run", command_str)

    if not verdict["safe"]:
        audit("AI_JUDGE", f"Flagged action: {command_str} | Reason: {verdict.get('reason')}", "FLAGGED")

        if verdict.get("needs_human"):
            _enforce_or_escalate(
                action="command_execution",
                target=command_str,
                reason=f"AI Judge blocked this action: {verdict['reason']}",
                recommendation="Reject unless you explicitly trust this high-risk command.",
            )

    return _original_run(*args, **kwargs)


def sentinel_popen(*args, **kwargs):
    command = args[0] if args else kwargs.get("args")
    shell = kwargs.get("shell", False)
    command_str = _normalize_command(command)
    try:
        policy.check_command(command, shell=shell)
    except PermissionError as e:
        _enforce_or_escalate(
            action="command_execution",
            target=command_str,
            reason=e,
            recommendation="Reject unless this command is required and understood.",
        )

    verdict = ai_judge.evaluate_action("subprocess.Popen", command_str)
    if not verdict["safe"] and verdict.get("needs_human"):
        audit("AI_JUDGE", f"Flagged action: {command_str} | Reason: {verdict.get('reason')}", "FLAGGED")
        _enforce_or_escalate(
            action="command_execution",
            target=command_str,
            reason=f"AI Judge blocked this action: {verdict['reason']}",
            recommendation="Reject unless you explicitly trust this high-risk command.",
        )
    return _original_popen(*args, **kwargs)


def sentinel_system(command):
    normalized = _normalize_command(command)
    try:
        policy.check_command(normalized, shell=True)
    except PermissionError as e:
        _enforce_or_escalate(
            action="command_execution",
            target=normalized,
            reason=e,
            recommendation="Reject unless this command is required and understood.",
        )

    verdict = ai_judge.evaluate_action("os.system", normalized)
    if not verdict["safe"] and verdict.get("needs_human"):
        audit("AI_JUDGE", f"Flagged action: {normalized} | Reason: {verdict.get('reason')}", "FLAGGED")
        _enforce_or_escalate(
            action="command_execution",
            target=normalized,
            reason=f"AI Judge blocked this action: {verdict['reason']}",
            recommendation="Reject unless you explicitly trust this high-risk command.",
        )
    return _original_os_system(command)


# 3. Network Interceptor (The Governor + Phishing Guard)
_original_session_request = requests.sessions.Session.request
_original_urlopen = urllib_request.urlopen
_original_http_request = http_client.HTTPConnection.request
_original_https_request = http_client.HTTPSConnection.request
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
        _enforce_or_escalate(
            action="network_access",
            target=url,
            reason=f"Phishing Risk Detected: {reason}",
            recommendation="Reject unless the URL is verified and trusted.",
        )

    # Allow AI Judge's own model endpoint to avoid self-blocking.
    if _is_internal_judge_endpoint(url):
        audit("NETWORK_ACCESS", f"{url} (AI Judge endpoint)", "ALLOWED")
        return

    # 2. Static Policy Check (Allow/Block Lists)
    try:
        policy.check_network(url)
    except PermissionError as e:
        _enforce_or_escalate(
            action="network_access",
            target=url,
            reason=e,
            recommendation="Reject unless this host is explicitly trusted.",
        )


def sentinel_session_request(self, method, url, **kwargs):
    _enforce_network_policy(url)
    return _original_session_request(self, method, url, **kwargs)


def _extract_urllib_url(target):
    if isinstance(target, urllib_request.Request):
        return target.full_url
    return str(target)


def sentinel_urlopen(url, *args, **kwargs):
    _enforce_network_policy(_extract_urllib_url(url))
    return _original_urlopen(url, *args, **kwargs)


def _normalize_http_target(scheme, host, url):
    if isinstance(url, str) and (url.startswith("http://") or url.startswith("https://")):
        return url
    path = str(url)
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{host}{path}"


def sentinel_http_request(self, method, url, body=None, headers=None, *, encode_chunked=False):
    target = _normalize_http_target("http", getattr(self, "host", ""), url)
    _enforce_network_policy(target)
    return _original_http_request(
        self,
        method,
        url,
        body=body,
        headers=headers if headers is not None else {},
        encode_chunked=encode_chunked,
    )


def sentinel_https_request(self, method, url, body=None, headers=None, *, encode_chunked=False):
    target = _normalize_http_target("https", getattr(self, "host", ""), url)
    _enforce_network_policy(target)
    return _original_https_request(
        self,
        method,
        url,
        body=body,
        headers=headers if headers is not None else {},
        encode_chunked=encode_chunked,
    )


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
    urllib_request.urlopen = sentinel_urlopen
    http_client.HTTPConnection.request = sentinel_http_request
    http_client.HTTPSConnection.request = sentinel_https_request
    _sentinel_active = True


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
    urllib_request.urlopen = _original_urlopen
    http_client.HTTPConnection.request = _original_http_request
    http_client.HTTPSConnection.request = _original_https_request
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
        _enforce_or_escalate(
            action="input_safety",
            target="user_input",
            reason=f"🛡️ LlamaGuard Blocked Input: {safety['reason']}",
            recommendation="Reject unless you intentionally need to process unsafe input.",
        )

    # 2. Keyword Check (Legacy/Fast)
    try:
        return policy.check_input(text)
    except ValueError as e:
        _enforce_or_escalate(
            action="input_safety",
            target="user_input",
            reason=e,
            recommendation="Reject unless you intentionally need to process restricted content.",
        )
        return text
