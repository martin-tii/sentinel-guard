import builtins
import errno
import io
import os
import pathlib
import sys
import random
import threading
import subprocess
import requests # Assuming requests is used, we'll patch it
import urllib.request as urllib_request
import http.client as http_client
import socket
import time
from urllib.parse import urlparse
from .policy import PolicyEnforcer
from .utils import audit, is_phishing_url
from .judge import AIJudge
from .approval import (
    SecurityAlert,
    explain_security_alert,
    in_approval_prompt,
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
judge_config.setdefault("runtime_judge_threshold", 0.4)
judge_config.setdefault("fail_open", False)
prompt_guard_cfg = judge_config.setdefault("prompt_guard", {})
if isinstance(prompt_guard_cfg, dict):
    prompt_guard_cfg.setdefault("enabled", True)
    prompt_guard_cfg.setdefault("model", "meta-llama/Prompt-Guard-86M")
    prompt_guard_cfg.setdefault("threshold", 0.8)
    prompt_guard_cfg.setdefault("fail_open", False)

_DEFAULT_INJECTION_TEXT_CONTENT_TYPES = [
    "text/*",
    "application/json",
    "application/*+json",
    "application/xml",
    "application/*+xml",
    "application/javascript",
    "application/x-www-form-urlencoded",
]

injection_scan_cfg = judge_config.setdefault("injection_scan", {})
if not isinstance(injection_scan_cfg, dict):
    injection_scan_cfg = {}
    judge_config["injection_scan"] = injection_scan_cfg

injection_scan_cfg.setdefault("enabled", True)
injection_scan_cfg.setdefault("on_detection", "approval")
injection_scan_cfg.setdefault("max_chars_per_source", 65536)
injection_scan_cfg.setdefault("chunk_chars", 8192)

injection_scan_file_cfg = injection_scan_cfg.setdefault("file_reads", {})
if not isinstance(injection_scan_file_cfg, dict):
    injection_scan_file_cfg = {}
    injection_scan_cfg["file_reads"] = injection_scan_file_cfg
injection_scan_file_cfg.setdefault("enabled", True)
injection_scan_file_cfg.setdefault("allowlist_paths", [])

injection_scan_network_cfg = injection_scan_cfg.setdefault("network_responses", {})
if not isinstance(injection_scan_network_cfg, dict):
    injection_scan_network_cfg = {}
    injection_scan_cfg["network_responses"] = injection_scan_network_cfg
injection_scan_network_cfg.setdefault("enabled", True)
injection_scan_network_cfg.setdefault("allowlist_hosts", [])
injection_scan_network_cfg.setdefault("text_content_types", list(_DEFAULT_INJECTION_TEXT_CONTENT_TYPES))

ai_judge = AIJudge(judge_config)
phishing_config = policy.policy.get("phishing", {})
network_failsafe_config = policy.policy.get("network_failsafe", {})
socket_failsafe_enabled = bool(network_failsafe_config.get("socket_connect", False))
policy_integrity_config = policy.policy.get("policy_integrity", {})
tamper_detection_enabled = bool(policy_integrity_config.get("tamper_detection", True))

_injection_scan_enabled = bool(injection_scan_cfg.get("enabled", True))
_injection_scan_on_detection = str(injection_scan_cfg.get("on_detection", "approval")).strip().lower()
if _injection_scan_on_detection not in ("block", "approval", "audit"):
    _injection_scan_on_detection = "approval"

try:
    _injection_scan_max_chars = max(1, int(injection_scan_cfg.get("max_chars_per_source", 65536)))
except (TypeError, ValueError):
    _injection_scan_max_chars = 65536
try:
    _injection_scan_chunk_chars = max(1, int(injection_scan_cfg.get("chunk_chars", 8192)))
except (TypeError, ValueError):
    _injection_scan_chunk_chars = 8192

_injection_scan_file_reads_enabled = bool(injection_scan_file_cfg.get("enabled", True))
_file_allow_raw = injection_scan_file_cfg.get("allowlist_paths", [])
if isinstance(_file_allow_raw, (list, tuple, set)):
    _injection_scan_file_allowlist_paths_raw = list(_file_allow_raw)
elif _file_allow_raw:
    _injection_scan_file_allowlist_paths_raw = [str(_file_allow_raw)]
else:
    _injection_scan_file_allowlist_paths_raw = []

_injection_scan_network_responses_enabled = bool(injection_scan_network_cfg.get("enabled", True))
_net_host_allow_raw = injection_scan_network_cfg.get("allowlist_hosts", [])
if isinstance(_net_host_allow_raw, (list, tuple, set)):
    _injection_scan_network_allowlist_hosts_raw = list(_net_host_allow_raw)
elif _net_host_allow_raw:
    _injection_scan_network_allowlist_hosts_raw = [str(_net_host_allow_raw)]
else:
    _injection_scan_network_allowlist_hosts_raw = []
_text_content_raw = injection_scan_network_cfg.get("text_content_types", _DEFAULT_INJECTION_TEXT_CONTENT_TYPES)
if not isinstance(_text_content_raw, (list, tuple, set)):
    _text_content_raw = [_text_content_raw]
_injection_scan_text_content_types = tuple(
    str(item).strip().lower()
    for item in _text_content_raw
    if str(item).strip()
)


def _is_truthy(value):
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _env_float(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return float(default)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return float(default)


def _integrity_interval_seconds():
    interval_ms = _env_float("SENTINEL_TAMPER_CHECK_INTERVAL_MS", 250.0)
    if interval_ms <= 0:
        return 0.0
    return interval_ms / 1000.0


def _integrity_sample_rate():
    rate = _env_float("SENTINEL_TAMPER_CHECK_SAMPLE_RATE", 0.0)
    if rate < 0:
        return 0.0
    if rate > 1:
        return 1.0
    return rate


def _should_run_integrity_check(force=False):
    global _last_integrity_check_at
    with _integrity_schedule_lock:
        if force:
            _last_integrity_check_at = time.monotonic()
            return True

        sample_rate = _integrity_sample_rate()
        if sample_rate > 0.0 and random.random() < sample_rate:
            _last_integrity_check_at = time.monotonic()
            return True

        interval = _integrity_interval_seconds()
        if interval <= 0:
            _last_integrity_check_at = time.monotonic()
            return True

        now = time.monotonic()
        if (now - _last_integrity_check_at) >= interval:
            _last_integrity_check_at = now
            return True
        return False


def _resolve_scan_path(value):
    if value is None or isinstance(value, int):
        return None
    try:
        return pathlib.Path(os.fspath(value)).expanduser().resolve()
    except Exception:
        return None


def _resolve_allowlist_paths(entries):
    resolved = []
    for entry in entries:
        path = _resolve_scan_path(entry)
        if path is not None:
            resolved.append(path)
    return tuple(resolved)


def _normalize_host_allowlist(entries):
    rules = []
    for entry in entries:
        host = ""
        match = "exact"
        if isinstance(entry, dict):
            host = str(entry.get("host", "")).strip().lower().strip(".")
            if str(entry.get("match", "exact")).strip().lower() == "subdomain":
                match = "subdomain"
        else:
            host = str(entry).strip().lower().strip(".")
        if host:
            rules.append((host, match))
    return tuple(rules)


_injection_scan_file_allowlist_paths = _resolve_allowlist_paths(_injection_scan_file_allowlist_paths_raw)
_injection_scan_network_allowlist_hosts = _normalize_host_allowlist(_injection_scan_network_allowlist_hosts_raw)


def _should_skip_scan_for_path(path):
    if not _injection_scan_file_reads_enabled:
        return True
    candidate = _resolve_scan_path(path)
    if candidate is None:
        return False
    for allowed in _injection_scan_file_allowlist_paths:
        try:
            candidate.relative_to(allowed)
            return True
        except ValueError:
            continue
    return False


def _should_skip_scan_for_host(host):
    host_text = str(host or "").strip().lower().strip(".")
    if not host_text:
        return False
    for allowed_host, mode in _injection_scan_network_allowlist_hosts:
        if host_text == allowed_host:
            return True
        if mode == "subdomain" and host_text.endswith("." + allowed_host):
            return True
    return False


def _is_text_like_content_type(content_type):
    raw = str(content_type or "").strip().lower()
    if not raw:
        return False
    content = raw.split(";", 1)[0].strip()
    if not content:
        return False
    for allowed in _injection_scan_text_content_types:
        if allowed.endswith("/*"):
            if content.startswith(allowed[:-1]):
                return True
        elif allowed.startswith("application/*+") and content.startswith("application/"):
            suffix = allowed[len("application/*") :]
            if content.endswith(suffix):
                return True
        elif content == allowed:
            return True
    return False


def _truncate_for_scan(text, max_chars):
    if text is None:
        return ""
    normalized = str(text)
    if len(normalized) <= max_chars:
        return normalized
    return normalized[:max_chars]


def _scan_target(source, metadata):
    target = str(source)
    if isinstance(metadata, dict):
        details = []
        for key in ("path", "host", "url", "content_type"):
            value = metadata.get(key)
            if value:
                details.append(f"{key}={value}")
        if details:
            target = f"{target} ({', '.join(details)})"
    return target


def _raise_blocked_injection(reason, target):
    audit("PROMPT_INJECTION", f"{target} | {reason}", "BLOCKED")
    raise PermissionError(reason)


def scan_untrusted_text(text, source, metadata=None):
    """
    Public helper for prompt-injection screening of untrusted text sources.
    Intended for host integrations where automatic monkey patches are bypassed.
    """
    _assert_runtime_integrity()
    if not _injection_scan_enabled:
        return text
    sample = _truncate_for_scan(text, _injection_scan_max_chars)
    if not sample:
        return text

    result = ai_judge.check_prompt_injection(sample, source=source)
    if not result.get("ok", True):
        audit(
            "PROMPT_INJECTION",
            f"{_scan_target(source, metadata)} | detector unavailable: {result.get('reason', 'unknown')}",
            "WARNING",
        )
        return text
    if result.get("safe", True):
        return text

    target = _scan_target(source, metadata)
    label = result.get("label")
    score = result.get("score")
    threshold = getattr(ai_judge.prompt_guard, "threshold", None)
    reason = (
        f"{result.get('reason', 'Prompt injection detected')} "
        f"[source={source}, label={label}, score={score}, threshold={threshold}]"
    )

    if _injection_scan_on_detection == "audit":
        audit("PROMPT_INJECTION", f"{target} | {reason}", "BLOCKED")
        return text

    if _injection_scan_on_detection == "block":
        _raise_blocked_injection(reason, target)

    _enforce_or_escalate(
        action="input_safety",
        target=target,
        reason=reason,
        recommendation="Reject unless this untrusted text source is verified and expected.",
    )
    return text

# --- Interceptors ---

# 1. File System Interceptor (The Jail)
_original_open = builtins.open
_original_io_open = io.open
_original_path_open = pathlib.Path.open
_original_os_open = os.open
_original_input = builtins.input


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
    raise PermissionError(explain_security_alert(alert))


def _is_runtime_internal_path(path_text):
    value = str(path_text or "").strip()
    if not value:
        return False
    try:
        candidate = pathlib.Path(value).expanduser().resolve()
    except Exception:
        return False

    roots = []
    for raw in (
        sys.prefix,
        sys.base_prefix,
        sys.exec_prefix,
        pathlib.Path(sys.executable).resolve().parent,
        pathlib.Path(os.__file__).resolve().parents[1] if getattr(os, "__file__", None) else None,
    ):
        if not raw:
            continue
        try:
            root = pathlib.Path(raw).expanduser().resolve()
            roots.append(root)
        except Exception:
            continue

    for root in roots:
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _should_bypass_file_policy(target, *, mode=None, flags=None):
    # io.open is also used by stdlib internals with raw file descriptors.
    if isinstance(target, int):
        return True

    # Avoid recursive breakage when Python loads internal runtime/stdlib files
    # (tracebacks, codecs, zipimport, site-packages) after a blocked action.
    is_write = False
    if flags is not None:
        is_write = _is_write_flags(flags)
    elif mode is not None:
        is_write = _is_write_mode(mode)

    if not is_write and _is_runtime_internal_path(target):
        return True

    return False


def _normalize_alert_path(target):
    if isinstance(target, int):
        return str(target)
    try:
        return str(pathlib.Path(os.fspath(target)).expanduser().resolve())
    except Exception:
        return str(target)


def _is_write_mode(mode):
    mode_text = str(mode or "")
    return any(marker in mode_text for marker in ("w", "a", "x", "+"))


def _file_action_from_mode(mode):
    return "file_write" if _is_write_mode(mode) else "file_access"


def _is_write_flags(flags):
    write_mask = 0
    for name in ("O_WRONLY", "O_RDWR", "O_APPEND", "O_CREAT", "O_TRUNC"):
        write_mask |= int(getattr(os, name, 0))
    try:
        return bool(int(flags) & write_mask)
    except Exception:
        return False


def _mode_reads_text(mode):
    mode_text = str(mode or "")
    if "b" in mode_text:
        return False
    if not mode_text:
        return True
    return ("r" in mode_text) or ("+" in mode_text)


def _iter_scan_chunks(text, max_chars, chunk_chars):
    if not text:
        return
    remaining = max_chars
    cursor = 0
    size = len(text)
    while remaining > 0 and cursor < size:
        take = min(chunk_chars, remaining, size - cursor)
        if take <= 0:
            break
        yield text[cursor : cursor + take]
        cursor += take
        remaining -= take


class SentinelTextReadProxy:
    def __init__(self, handle, source, metadata=None):
        self._handle = handle
        self._source = source
        self._metadata = metadata or {}
        self._scanned_chars = 0

    def _scan_text(self, value):
        if not _injection_scan_enabled or not _injection_scan_file_reads_enabled:
            return
        if not isinstance(value, str) or not value:
            return
        if self._scanned_chars >= _injection_scan_max_chars:
            return
        remaining = _injection_scan_max_chars - self._scanned_chars
        for chunk in _iter_scan_chunks(value, remaining, _injection_scan_chunk_chars):
            scan_untrusted_text(chunk, source=self._source, metadata=self._metadata)
            self._scanned_chars += len(chunk)
            if self._scanned_chars >= _injection_scan_max_chars:
                break

    def read(self, *args, **kwargs):
        data = self._handle.read(*args, **kwargs)
        self._scan_text(data)
        return data

    def readline(self, *args, **kwargs):
        data = self._handle.readline(*args, **kwargs)
        self._scan_text(data)
        return data

    def readlines(self, *args, **kwargs):
        lines = self._handle.readlines(*args, **kwargs)
        for line in lines:
            self._scan_text(line)
        return lines

    def __iter__(self):
        return self

    def __next__(self):
        value = next(self._handle)
        self._scan_text(value)
        return value

    def __enter__(self):
        self._handle.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._handle.__exit__(exc_type, exc, tb)

    def __getattr__(self, name):
        return getattr(self._handle, name)


def _wrap_text_reader_if_needed(handle, mode, path, source):
    if not _injection_scan_enabled:
        return handle
    if not _mode_reads_text(mode):
        return handle
    resolved_path = _resolve_scan_path(path)
    if resolved_path is None:
        return handle
    if _should_skip_scan_for_path(resolved_path):
        return handle
    metadata = {"path": str(resolved_path)}
    return SentinelTextReadProxy(handle, source=source, metadata=metadata)


def sentinel_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    _assert_runtime_integrity()
    # 1. Static Policy Check (The Law)
    bypass = _should_bypass_file_policy(file, mode=mode)
    if not bypass:
        action = _file_action_from_mode(mode)
        alert_target = _normalize_alert_path(file)
        try:
            policy.check_file_access(file)
        except PermissionError as e:
            # Safety net: if runtime internals still reached policy check for reads,
            # allow to avoid recursive approval loops while rendering exceptions/logs.
            if action != "file_write" and _is_runtime_internal_path(alert_target):
                return _original_open(file, mode, buffering, encoding, errors, newline, closefd, opener)
            _enforce_or_escalate(
                action=action,
                target=alert_target,
                reason=e,
                recommendation="Reject unless this exact file path and operation are expected.",
            )

    handle = _original_open(file, mode, buffering, encoding, errors, newline, closefd, opener)
    return _wrap_text_reader_if_needed(handle, mode, file, "file_read:open")


def sentinel_io_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    _assert_runtime_integrity()
    bypass = _should_bypass_file_policy(file, mode=mode)
    if not bypass:
        action = _file_action_from_mode(mode)
        alert_target = _normalize_alert_path(file)
        try:
            policy.check_file_access(file)
        except PermissionError as e:
            if action != "file_write" and _is_runtime_internal_path(alert_target):
                return _original_io_open(file, mode, buffering, encoding, errors, newline, closefd, opener)
            _enforce_or_escalate(
                action=action,
                target=alert_target,
                reason=e,
                recommendation="Reject unless this exact file path and operation are expected.",
            )

    handle = _original_io_open(file, mode, buffering, encoding, errors, newline, closefd, opener)
    return _wrap_text_reader_if_needed(handle, mode, file, "file_read:io.open")


def sentinel_path_open(self, mode='r', buffering=-1, encoding=None, errors=None, newline=None):
    _assert_runtime_integrity()
    bypass = _should_bypass_file_policy(self, mode=mode)
    if not bypass:
        action = _file_action_from_mode(mode)
        alert_target = _normalize_alert_path(self)
        try:
            policy.check_file_access(self)
        except PermissionError as e:
            if action != "file_write" and _is_runtime_internal_path(alert_target):
                return _original_path_open(self, mode, buffering, encoding, errors, newline)
            _enforce_or_escalate(
                action=action,
                target=alert_target,
                reason=e,
                recommendation="Reject unless this exact file path and operation are expected.",
            )

    handle = _original_path_open(self, mode, buffering, encoding, errors, newline)
    return _wrap_text_reader_if_needed(handle, mode, self, "file_read:path.open")


def _normalize_os_open_path(path):
    try:
        return os.fsdecode(path)
    except Exception:
        return str(path)


def sentinel_os_open(path, flags, mode=0o777, *, dir_fd=None):
    _assert_runtime_integrity()
    action = "file_write" if _is_write_flags(flags) else "file_access"
    alert_target = _normalize_alert_path(path)
    if dir_fd is not None:
        _enforce_or_escalate(
            action=action,
            target=alert_target,
            reason="os.open with dir_fd is not permitted under Sentinel policy.",
            recommendation="Reject and use normal absolute/relative paths without dir_fd.",
        )

    normalized_path = _normalize_os_open_path(path)
    bypass = _should_bypass_file_policy(normalized_path, flags=flags)
    if not bypass:
        try:
            policy.check_file_access(normalized_path)
        except PermissionError as e:
            if action != "file_write" and _is_runtime_internal_path(alert_target):
                return _original_os_open(path, flags, mode)
            _enforce_or_escalate(
                action=action,
                target=alert_target,
                reason=e,
                recommendation="Reject unless this exact file path and operation are expected.",
            )

    return _original_os_open(path, flags, mode)


def sentinel_input(prompt=""):
    _assert_runtime_integrity()
    if in_approval_prompt():
        return _original_input(prompt)
    value = _original_input(prompt)
    return scan_untrusted_text(value, source="user_input:builtins.input", metadata={"path": "stdin"})


# 2. Command Execution Interceptor (The Governor)
_original_run = subprocess.run
_original_popen = subprocess.Popen
_original_popen_init = subprocess.Popen.__init__
_original_os_system = os.system
_original_posix_spawn = getattr(os, "posix_spawn", None)
_original_posix_spawnp = getattr(os, "posix_spawnp", None)
_ORIGINAL_EXEC_FNS = {
    "execv": getattr(os, "execv", None),
    "execve": getattr(os, "execve", None),
    "execvp": getattr(os, "execvp", None),
    "execvpe": getattr(os, "execvpe", None),
    "execl": getattr(os, "execl", None),
    "execle": getattr(os, "execle", None),
    "execlp": getattr(os, "execlp", None),
    "execlpe": getattr(os, "execlpe", None),
}
_ORIGINAL_SPAWN_FNS = {
    "spawnv": getattr(os, "spawnv", None),
    "spawnve": getattr(os, "spawnve", None),
    "spawnvp": getattr(os, "spawnvp", None),
    "spawnvpe": getattr(os, "spawnvpe", None),
    "spawnl": getattr(os, "spawnl", None),
    "spawnle": getattr(os, "spawnle", None),
    "spawnlp": getattr(os, "spawnlp", None),
    "spawnlpe": getattr(os, "spawnlpe", None),
}


def _normalize_command(command):
    if isinstance(command, list):
        return " ".join(str(part) for part in command)
    return str(command)


def sentinel_run(*args, **kwargs):
    _assert_runtime_integrity()
    if in_approval_prompt():
        return _original_run(*args, **kwargs)
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


def _enforce_popen_policy(command, shell, tool_name):
    _assert_runtime_integrity()
    if in_approval_prompt():
        return
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

    verdict = ai_judge.evaluate_action(tool_name, command_str)
    if not verdict["safe"] and verdict.get("needs_human"):
        audit("AI_JUDGE", f"Flagged action: {command_str} | Reason: {verdict.get('reason')}", "FLAGGED")
        _enforce_or_escalate(
            action="command_execution",
            target=command_str,
            reason=f"AI Judge blocked this action: {verdict['reason']}",
            recommendation="Reject unless you explicitly trust this high-risk command.",
        )


def sentinel_popen(*args, **kwargs):
    command = args[0] if args else kwargs.get("args")
    shell = kwargs.get("shell", False)
    _enforce_popen_policy(command, shell, "subprocess.Popen")
    return _original_popen(*args, **kwargs)


def sentinel_popen_init(self, *args, **kwargs):
    command = args[0] if args else kwargs.get("args")
    shell = kwargs.get("shell", False)
    _enforce_popen_policy(command, shell, "subprocess.Popen")
    return _original_popen_init(self, *args, **kwargs)


def sentinel_system(command):
    _assert_runtime_integrity()
    if in_approval_prompt():
        return _original_os_system(command)
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


def _normalize_argv_command(argv_or_command, fallback=None):
    if isinstance(argv_or_command, (list, tuple)):
        if argv_or_command:
            return [str(part) for part in argv_or_command]
        return [str(fallback)] if fallback is not None else []
    if argv_or_command is None:
        return [str(fallback)] if fallback is not None else []
    return [str(argv_or_command)]


def _enforce_exec_policy(action_name, argv_or_command, *, fallback=None):
    _assert_runtime_integrity()
    argv = _normalize_argv_command(argv_or_command, fallback=fallback)
    command_str = " ".join(argv) if argv else str(fallback or "")
    try:
        policy.check_command(argv, shell=False)
    except PermissionError as e:
        _enforce_or_escalate(
            action="command_execution",
            target=command_str,
            reason=e,
            recommendation="Reject unless this command is required and understood.",
        )

    verdict = ai_judge.evaluate_action(action_name, command_str)
    if not verdict["safe"] and verdict.get("needs_human"):
        audit("AI_JUDGE", f"Flagged action: {command_str} | Reason: {verdict.get('reason')}", "FLAGGED")
        _enforce_or_escalate(
            action="command_execution",
            target=command_str,
            reason=f"AI Judge blocked this action: {verdict['reason']}",
            recommendation="Reject unless you explicitly trust this high-risk command.",
        )


def sentinel_posix_spawn(path, argv, env, **kwargs):
    _enforce_exec_policy("os.posix_spawn", argv, fallback=path)
    return _original_posix_spawn(path, argv, env, **kwargs)


def sentinel_posix_spawnp(path, argv, env, **kwargs):
    _enforce_exec_policy("os.posix_spawnp", argv, fallback=path)
    return _original_posix_spawnp(path, argv, env, **kwargs)


def _split_trailing_env(args):
    if args and isinstance(args[-1], dict):
        return args[:-1], args[-1]
    return args, None


def _call_original(name, *args):
    fn = _ORIGINAL_EXEC_FNS.get(name) or _ORIGINAL_SPAWN_FNS.get(name)
    if fn is None:
        raise RuntimeError(f"os.{name} is unavailable on this platform.")
    return fn(*args)


def sentinel_execv(path, argv):
    _enforce_exec_policy("os.execv", argv, fallback=path)
    return _call_original("execv", path, argv)


def sentinel_execve(path, argv, env):
    _enforce_exec_policy("os.execve", argv, fallback=path)
    return _call_original("execve", path, argv, env)


def sentinel_execvp(file, argv):
    _enforce_exec_policy("os.execvp", argv, fallback=file)
    return _call_original("execvp", file, argv)


def sentinel_execvpe(file, argv, env):
    _enforce_exec_policy("os.execvpe", argv, fallback=file)
    return _call_original("execvpe", file, argv, env)


def sentinel_execl(path, *args):
    _enforce_exec_policy("os.execl", args, fallback=path)
    return _call_original("execl", path, *args)


def sentinel_execle(path, *args):
    argv, env = _split_trailing_env(args)
    if env is None:
        raise TypeError("execle() requires an env mapping as the last argument")
    _enforce_exec_policy("os.execle", argv, fallback=path)
    return _call_original("execle", path, *argv, env)


def sentinel_execlp(file, *args):
    _enforce_exec_policy("os.execlp", args, fallback=file)
    return _call_original("execlp", file, *args)


def sentinel_execlpe(file, *args):
    argv, env = _split_trailing_env(args)
    if env is None:
        raise TypeError("execlpe() requires an env mapping as the last argument")
    _enforce_exec_policy("os.execlpe", argv, fallback=file)
    return _call_original("execlpe", file, *argv, env)


def sentinel_spawnv(mode, path, argv):
    _enforce_exec_policy("os.spawnv", argv, fallback=path)
    return _call_original("spawnv", mode, path, argv)


def sentinel_spawnve(mode, path, argv, env):
    _enforce_exec_policy("os.spawnve", argv, fallback=path)
    return _call_original("spawnve", mode, path, argv, env)


def sentinel_spawnvp(mode, file, argv):
    _enforce_exec_policy("os.spawnvp", argv, fallback=file)
    return _call_original("spawnvp", mode, file, argv)


def sentinel_spawnvpe(mode, file, argv, env):
    _enforce_exec_policy("os.spawnvpe", argv, fallback=file)
    return _call_original("spawnvpe", mode, file, argv, env)


def sentinel_spawnl(mode, path, *args):
    _enforce_exec_policy("os.spawnl", args, fallback=path)
    return _call_original("spawnl", mode, path, *args)


def sentinel_spawnle(mode, path, *args):
    argv, env = _split_trailing_env(args)
    if env is None:
        raise TypeError("spawnle() requires an env mapping as the last argument")
    _enforce_exec_policy("os.spawnle", argv, fallback=path)
    return _call_original("spawnle", mode, path, *argv, env)


def sentinel_spawnlp(mode, file, *args):
    _enforce_exec_policy("os.spawnlp", args, fallback=file)
    return _call_original("spawnlp", mode, file, *args)


def sentinel_spawnlpe(mode, file, *args):
    argv, env = _split_trailing_env(args)
    if env is None:
        raise TypeError("spawnlpe() requires an env mapping as the last argument")
    _enforce_exec_policy("os.spawnlpe", argv, fallback=file)
    return _call_original("spawnlpe", mode, file, *argv, env)


# 3. Network Interceptor (The Governor + Phishing Guard)
_original_session_request = requests.sessions.Session.request
_original_urlopen = urllib_request.urlopen
_original_http_request = http_client.HTTPConnection.request
_original_https_request = http_client.HTTPSConnection.request
_original_socket_connect = socket.socket.connect
_original_socket_connect_ex = socket.socket.connect_ex
_original_socket_sendto = socket.socket.sendto
_sentinel_active = False
_socket_patch_active = False
_integrity_check_in_progress = False
_expected_runtime_bindings = {}
_last_integrity_check_at = 0.0
_integrity_schedule_lock = threading.Lock()


def _is_production_mode():
    return _is_truthy(os.environ.get("SENTINEL_PRODUCTION", ""))


def _runtime_binding_getters():
    getters = {
        "builtins.open": lambda: builtins.open,
        "builtins.input": lambda: builtins.input,
        "io.open": lambda: io.open,
        "pathlib.Path.open": lambda: pathlib.Path.open,
        "os.open": lambda: os.open,
        "subprocess.run": lambda: subprocess.run,
        "subprocess.Popen": lambda: subprocess.Popen,
        "subprocess.Popen.__init__": lambda: _original_popen.__init__,
        "os.system": lambda: os.system,
        "requests.sessions.Session.request": lambda: requests.sessions.Session.request,
        "urllib.request.urlopen": lambda: urllib_request.urlopen,
        "http.client.HTTPConnection.request": lambda: http_client.HTTPConnection.request,
        "http.client.HTTPSConnection.request": lambda: http_client.HTTPSConnection.request,
        "core.request_user_approval": lambda: request_user_approval,
        "core.policy": lambda: policy,
        "core.ai_judge": lambda: ai_judge,
        "core._enforce_or_escalate": lambda: _enforce_or_escalate,
    }

    if _original_posix_spawn is not None:
        getters["os.posix_spawn"] = lambda: os.posix_spawn
    if _original_posix_spawnp is not None:
        getters["os.posix_spawnp"] = lambda: os.posix_spawnp

    for name, fn in _ORIGINAL_EXEC_FNS.items():
        if fn is not None:
            getters[f"os.{name}"] = lambda n=name: getattr(os, n)
    for name, fn in _ORIGINAL_SPAWN_FNS.items():
        if fn is not None:
            getters[f"os.{name}"] = lambda n=name: getattr(os, n)

    if _socket_patch_active:
        getters["socket.socket.connect"] = lambda: socket.socket.connect
        getters["socket.socket.connect_ex"] = lambda: socket.socket.connect_ex
        getters["socket.socket.sendto"] = lambda: socket.socket.sendto
    return getters


def _record_expected_runtime_bindings():
    global _expected_runtime_bindings
    getters = _runtime_binding_getters()
    _expected_runtime_bindings = {name: getter() for name, getter in getters.items()}


def _assert_runtime_integrity(force=False):
    global _integrity_check_in_progress
    if not _sentinel_active or not tamper_detection_enabled:
        return
    if _integrity_check_in_progress:
        return
    if not _should_run_integrity_check(force=force):
        return

    _integrity_check_in_progress = True
    try:
        try:
            policy.verify_policy_immutability()
        except Exception as e:
            audit("TAMPER_DETECT", f"Policy integrity violation: {e}", "CRITICAL")
            raise PermissionError(f"Policy integrity violation: {e}")

        if not _expected_runtime_bindings:
            return

        getters = _runtime_binding_getters()
        mismatches = []
        for name, expected in _expected_runtime_bindings.items():
            getter = getters.get(name)
            if getter is None:
                mismatches.append(f"{name} (missing)")
                continue
            current = getter()
            if current is not expected:
                mismatches.append(name)

        if mismatches:
            summary = ", ".join(mismatches)
            audit("TAMPER_DETECT", f"Runtime hook drift detected: {summary}", "CRITICAL")
            raise PermissionError(f"Sentinel runtime integrity violation: {summary}")
    finally:
        _integrity_check_in_progress = False


def _assert_production_integrity_requirements():
    if not _is_production_mode():
        return
    attestation = policy.attestation()
    if attestation.get("signature_mode") == "none":
        raise RuntimeError(
            "Production mode requires signed policy verification "
            "(SENTINEL_POLICY_SHA256 or SENTINEL_POLICY_HMAC_SHA256)."
        )
    if not attestation.get("immutable_policy"):
        raise RuntimeError("Production mode requires SENTINEL_POLICY_IMMUTABLE=true.")


def _emit_startup_attestation():
    details = policy.attestation()
    audit(
        "ATTESTATION",
        (
            f"production={details.get('production_mode')} "
            f"tamper_detection={tamper_detection_enabled} "
            f"policy_source={details.get('policy_source')} "
            f"signature_mode={details.get('signature_mode')} "
            f"immutable={details.get('immutable_policy')} "
            f"policy_sha256={details.get('policy_sha256')}"
        ),
        "INFO",
    )


def _is_internal_judge_endpoint(url):
    try:
        judge = urlparse(ai_judge.endpoint)
        target = urlparse(url)
        judge_host = judge.hostname
        target_host = target.hostname
        if not judge_host or not target_host:
            return False
        if target_host != judge_host:
            return False

        judge_scheme = (judge.scheme or "").lower()
        target_scheme = (target.scheme or "").lower()
        if judge_scheme != target_scheme:
            return False

        default_port = 443 if judge_scheme == "https" else 80
        judge_port = judge.port or default_port
        target_port = target.port or default_port
        if judge_port != target_port:
            return False

        judge_path = (judge.path or "/").rstrip("/") or "/"
        target_path = (target.path or "/").rstrip("/") or "/"
        return target_path == judge_path
    except Exception:
        return False


def _is_internal_judge_socket_target(host, port):
    try:
        judge = urlparse(ai_judge.endpoint)
        judge_host = judge.hostname
        if not judge_host:
            return False
        judge_scheme = (judge.scheme or "").lower()
        default_port = 443 if judge_scheme == "https" else 80
        judge_port = judge.port or default_port
        if int(port) != int(judge_port):
            return False
        host_text = str(host).strip()
        if host_text == judge_host:
            return True

        try:
            host_ips = {info[4][0] for info in socket.getaddrinfo(host_text, None)}
            judge_ips = {info[4][0] for info in socket.getaddrinfo(judge_host, None)}
            return bool(host_ips & judge_ips)
        except Exception:
            return False
    except Exception:
        return False


def _enforce_network_policy(url):
    _assert_runtime_integrity()
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


def _extract_content_type(headers):
    if headers is None:
        return ""
    try:
        value = headers.get("Content-Type")
        if value:
            return str(value)
    except Exception:
        pass
    try:
        value = headers.get("content-type")
        if value:
            return str(value)
    except Exception:
        pass
    return ""


def _extract_charset(content_type):
    raw = str(content_type or "")
    for part in raw.split(";")[1:]:
        segment = part.strip()
        if segment.lower().startswith("charset="):
            return segment.split("=", 1)[1].strip().strip('"').strip("'")
    return "utf-8"


def _decode_text_payload(payload, content_type):
    if isinstance(payload, str):
        return payload
    if not isinstance(payload, (bytes, bytearray)):
        return None
    charset = _extract_charset(content_type)
    try:
        return bytes(payload).decode(charset, errors="replace")
    except Exception:
        try:
            return bytes(payload).decode("utf-8", errors="replace")
        except Exception:
            return None


def _response_host(url):
    try:
        return (urlparse(str(url)).hostname or "").strip().lower()
    except Exception:
        return ""


class SentinelRequestsResponseProxy:
    def __init__(self, response, source_url):
        self._response = response
        self._url = getattr(response, "url", source_url)
        self._host = _response_host(self._url)
        self._content_type = _extract_content_type(getattr(response, "headers", {}))
        self._scanned_chars = 0
        self._can_scan = (
            _injection_scan_enabled
            and _injection_scan_network_responses_enabled
            and not _should_skip_scan_for_host(self._host)
            and _is_text_like_content_type(self._content_type)
        )

    def _scan(self, text, source):
        if not self._can_scan:
            return
        if not isinstance(text, str) or not text:
            return
        if self._scanned_chars >= _injection_scan_max_chars:
            return
        remaining = _injection_scan_max_chars - self._scanned_chars
        metadata = {
            "host": self._host,
            "url": str(self._url),
            "content_type": self._content_type,
        }
        for chunk in _iter_scan_chunks(text, remaining, _injection_scan_chunk_chars):
            scan_untrusted_text(chunk, source=source, metadata=metadata)
            self._scanned_chars += len(chunk)
            if self._scanned_chars >= _injection_scan_max_chars:
                break

    @property
    def text(self):
        value = self._response.text
        self._scan(value, "network_response:requests.text")
        return value

    def json(self, *args, **kwargs):
        value = self._response.json(*args, **kwargs)
        try:
            raw = self._response.text
        except Exception:
            raw = ""
        self._scan(raw, "network_response:requests.json")
        return value

    def iter_lines(self, *args, **kwargs):
        for line in self._response.iter_lines(*args, **kwargs):
            self._scan(_decode_text_payload(line, self._content_type), "network_response:requests.iter_lines")
            yield line

    def iter_content(self, *args, **kwargs):
        decode_unicode = bool(kwargs.get("decode_unicode", False))
        for chunk in self._response.iter_content(*args, **kwargs):
            if decode_unicode:
                self._scan(
                    _decode_text_payload(chunk, self._content_type),
                    "network_response:requests.iter_content",
                )
            yield chunk

    def __iter__(self):
        return iter(self._response)

    def __enter__(self):
        if hasattr(self._response, "__enter__"):
            self._response.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        if hasattr(self._response, "__exit__"):
            return self._response.__exit__(exc_type, exc, tb)
        return False

    def __getattr__(self, name):
        return getattr(self._response, name)


class SentinelUrlopenResponseProxy:
    def __init__(self, response, source_url):
        self._response = response
        self._url = source_url or getattr(response, "url", "")
        try:
            if hasattr(response, "geturl"):
                self._url = response.geturl() or self._url
        except Exception:
            pass
        self._host = _response_host(self._url)
        headers = getattr(response, "headers", None)
        if headers is None:
            try:
                headers = response.info()
            except Exception:
                headers = {}
        self._content_type = _extract_content_type(headers)
        self._scanned_chars = 0
        self._can_scan = (
            _injection_scan_enabled
            and _injection_scan_network_responses_enabled
            and not _should_skip_scan_for_host(self._host)
            and _is_text_like_content_type(self._content_type)
        )

    def _scan(self, payload, source):
        if not self._can_scan:
            return
        text = _decode_text_payload(payload, self._content_type)
        if not text:
            return
        if self._scanned_chars >= _injection_scan_max_chars:
            return
        remaining = _injection_scan_max_chars - self._scanned_chars
        metadata = {
            "host": self._host,
            "url": str(self._url),
            "content_type": self._content_type,
        }
        for chunk in _iter_scan_chunks(text, remaining, _injection_scan_chunk_chars):
            scan_untrusted_text(chunk, source=source, metadata=metadata)
            self._scanned_chars += len(chunk)
            if self._scanned_chars >= _injection_scan_max_chars:
                break

    def read(self, *args, **kwargs):
        value = self._response.read(*args, **kwargs)
        self._scan(value, "network_response:urlopen.read")
        return value

    def readline(self, *args, **kwargs):
        value = self._response.readline(*args, **kwargs)
        self._scan(value, "network_response:urlopen.readline")
        return value

    def readlines(self, *args, **kwargs):
        lines = self._response.readlines(*args, **kwargs)
        for line in lines:
            self._scan(line, "network_response:urlopen.readlines")
        return lines

    def __iter__(self):
        return self

    def __next__(self):
        value = next(self._response)
        self._scan(value, "network_response:urlopen.iter")
        return value

    def __enter__(self):
        if hasattr(self._response, "__enter__"):
            self._response.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        if hasattr(self._response, "__exit__"):
            return self._response.__exit__(exc_type, exc, tb)
        return False

    def __getattr__(self, name):
        return getattr(self._response, name)


def _maybe_wrap_requests_response(response, source_url):
    if not _injection_scan_enabled or not _injection_scan_network_responses_enabled:
        return response
    return SentinelRequestsResponseProxy(response, source_url)


def _maybe_wrap_urlopen_response(response, source_url):
    if not _injection_scan_enabled or not _injection_scan_network_responses_enabled:
        return response
    return SentinelUrlopenResponseProxy(response, source_url)


def sentinel_session_request(self, method, url, **kwargs):
    _enforce_network_policy(url)
    response = _original_session_request(self, method, url, **kwargs)
    return _maybe_wrap_requests_response(response, url)


def _extract_urllib_url(target):
    if isinstance(target, urllib_request.Request):
        return target.full_url
    return str(target)


def sentinel_urlopen(url, *args, **kwargs):
    target_url = _extract_urllib_url(url)
    _enforce_network_policy(target_url)
    response = _original_urlopen(url, *args, **kwargs)
    return _maybe_wrap_urlopen_response(response, target_url)


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


def sentinel_socket_connect(self, address):
    _assert_runtime_integrity()
    if isinstance(address, tuple) and len(address) >= 2:
        host = address[0]
        port = address[1]
    else:
        # Non-INET socket types (e.g., unix sockets) are passed through.
        return _original_socket_connect(self, address)

    if _is_internal_judge_socket_target(host, port):
        audit("SOCKET_CONNECT", f"{host}:{port} (AI Judge endpoint)", "ALLOWED")
        return _original_socket_connect(self, address)

    try:
        policy.check_socket_connect(host, port)
    except PermissionError as e:
        _enforce_or_escalate(
            action="network_access",
            target=f"socket://{host}:{port}",
            reason=e,
            recommendation="Reject unless this socket destination is explicitly trusted.",
        )
    return _original_socket_connect(self, address)


def sentinel_socket_connect_ex(self, address):
    _assert_runtime_integrity()
    if isinstance(address, tuple) and len(address) >= 2:
        host = address[0]
        port = address[1]
    else:
        return _original_socket_connect_ex(self, address)

    if _is_internal_judge_socket_target(host, port):
        audit("SOCKET_CONNECT_EX", f"{host}:{port} (AI Judge endpoint)", "ALLOWED")
        return _original_socket_connect_ex(self, address)

    try:
        policy.check_socket_connect(host, port)
    except PermissionError as e:
        try:
            _enforce_or_escalate(
                action="network_access",
                target=f"socket://{host}:{port}",
                reason=e,
                recommendation="Reject unless this socket destination is explicitly trusted.",
            )
        except PermissionError:
            return errno.EACCES

    return _original_socket_connect_ex(self, address)


def _extract_sendto_address(args):
    # sendto(data, address) or sendto(data, flags, address)
    if len(args) == 1:
        return args[0]
    if len(args) >= 2:
        return args[1]
    return None


def sentinel_socket_sendto(self, data, *args):
    _assert_runtime_integrity()
    address = _extract_sendto_address(args)
    if isinstance(address, tuple) and len(address) >= 2:
        host = address[0]
        port = address[1]

        if _is_internal_judge_socket_target(host, port):
            audit("SOCKET_SENDTO", f"{host}:{port} (AI Judge endpoint)", "ALLOWED")
        else:
            try:
                policy.check_socket_connect(host, port)
            except PermissionError as e:
                _enforce_or_escalate(
                    action="network_access",
                    target=f"socket://{host}:{port}",
                    reason=e,
                    recommendation="Reject unless this socket destination is explicitly trusted.",
                )

    return _original_socket_sendto(self, data, *args)


# --- Activation ---

def activate_sentinel():
    """Activates the Sentinel monitoring system."""
    global _sentinel_active, _socket_patch_active, _last_integrity_check_at

    # Emergency kill switch for production incidents.
    disable_requested = _is_truthy(os.environ.get("SENTINEL_DISABLE", ""))
    if disable_requested:
        disable_allowed = _is_truthy(os.environ.get("SENTINEL_ALLOW_DISABLE", ""))
        if not disable_allowed:
            audit(
                "SYSTEM",
                "Disable requested but blocked: set SENTINEL_ALLOW_DISABLE=true to permit disable.",
                "CRITICAL",
            )
            raise RuntimeError(
                "SENTINEL_DISABLE requested but not permitted. "
                "Set SENTINEL_ALLOW_DISABLE=true to allow disabling Sentinel."
            )

        audit("SYSTEM", "Sentinel disabled via explicit dual-control environment flags.", "WARNING")
        return

    if _sentinel_active:
        audit("SYSTEM", "Sentinel already active. Skipping re-patch.", "INFO")
        return

    _last_integrity_check_at = 0.0
    _assert_production_integrity_requirements()
    audit("SYSTEM", "Sentinel Activated. Monitoring engaged.", "INFO")
    audit(
        "SYSTEM",
        "Compatibility mode active: runtime hooks are guardrails, not a hard isolation boundary.",
        "WARNING",
    )

    # Monkey Patching
    builtins.open = sentinel_open
    builtins.input = sentinel_input
    io.open = sentinel_io_open
    pathlib.Path.open = sentinel_path_open
    os.open = sentinel_os_open
    subprocess.run = sentinel_run
    _original_popen.__init__ = sentinel_popen_init
    subprocess.Popen = _original_popen
    os.system = sentinel_system
    if _original_posix_spawn is not None:
        os.posix_spawn = sentinel_posix_spawn
    if _original_posix_spawnp is not None:
        os.posix_spawnp = sentinel_posix_spawnp
    if _ORIGINAL_EXEC_FNS["execv"] is not None:
        os.execv = sentinel_execv
    if _ORIGINAL_EXEC_FNS["execve"] is not None:
        os.execve = sentinel_execve
    if _ORIGINAL_EXEC_FNS["execvp"] is not None:
        os.execvp = sentinel_execvp
    if _ORIGINAL_EXEC_FNS["execvpe"] is not None:
        os.execvpe = sentinel_execvpe
    if _ORIGINAL_EXEC_FNS["execl"] is not None:
        os.execl = sentinel_execl
    if _ORIGINAL_EXEC_FNS["execle"] is not None:
        os.execle = sentinel_execle
    if _ORIGINAL_EXEC_FNS["execlp"] is not None:
        os.execlp = sentinel_execlp
    if _ORIGINAL_EXEC_FNS["execlpe"] is not None:
        os.execlpe = sentinel_execlpe
    if _ORIGINAL_SPAWN_FNS["spawnv"] is not None:
        os.spawnv = sentinel_spawnv
    if _ORIGINAL_SPAWN_FNS["spawnve"] is not None:
        os.spawnve = sentinel_spawnve
    if _ORIGINAL_SPAWN_FNS["spawnvp"] is not None:
        os.spawnvp = sentinel_spawnvp
    if _ORIGINAL_SPAWN_FNS["spawnvpe"] is not None:
        os.spawnvpe = sentinel_spawnvpe
    if _ORIGINAL_SPAWN_FNS["spawnl"] is not None:
        os.spawnl = sentinel_spawnl
    if _ORIGINAL_SPAWN_FNS["spawnle"] is not None:
        os.spawnle = sentinel_spawnle
    if _ORIGINAL_SPAWN_FNS["spawnlp"] is not None:
        os.spawnlp = sentinel_spawnlp
    if _ORIGINAL_SPAWN_FNS["spawnlpe"] is not None:
        os.spawnlpe = sentinel_spawnlpe
    requests.sessions.Session.request = sentinel_session_request
    urllib_request.urlopen = sentinel_urlopen
    http_client.HTTPConnection.request = sentinel_http_request
    http_client.HTTPSConnection.request = sentinel_https_request
    if socket_failsafe_enabled:
        socket.socket.connect = sentinel_socket_connect
        socket.socket.connect_ex = sentinel_socket_connect_ex
        socket.socket.sendto = sentinel_socket_sendto
        _socket_patch_active = True
    _sentinel_active = True
    _record_expected_runtime_bindings()
    _assert_runtime_integrity(force=True)
    _emit_startup_attestation()


def deactivate_sentinel():
    """Restores original runtime functions and disables Sentinel interception."""
    global _sentinel_active, _socket_patch_active, _expected_runtime_bindings, _last_integrity_check_at
    if not _sentinel_active:
        audit("SYSTEM", "Sentinel already inactive. Nothing to restore.", "INFO")
        return

    builtins.open = _original_open
    builtins.input = _original_input
    io.open = _original_io_open
    pathlib.Path.open = _original_path_open
    os.open = _original_os_open
    subprocess.run = _original_run
    _original_popen.__init__ = _original_popen_init
    subprocess.Popen = _original_popen
    os.system = _original_os_system
    if _original_posix_spawn is not None:
        os.posix_spawn = _original_posix_spawn
    if _original_posix_spawnp is not None:
        os.posix_spawnp = _original_posix_spawnp
    if _ORIGINAL_EXEC_FNS["execv"] is not None:
        os.execv = _ORIGINAL_EXEC_FNS["execv"]
    if _ORIGINAL_EXEC_FNS["execve"] is not None:
        os.execve = _ORIGINAL_EXEC_FNS["execve"]
    if _ORIGINAL_EXEC_FNS["execvp"] is not None:
        os.execvp = _ORIGINAL_EXEC_FNS["execvp"]
    if _ORIGINAL_EXEC_FNS["execvpe"] is not None:
        os.execvpe = _ORIGINAL_EXEC_FNS["execvpe"]
    if _ORIGINAL_EXEC_FNS["execl"] is not None:
        os.execl = _ORIGINAL_EXEC_FNS["execl"]
    if _ORIGINAL_EXEC_FNS["execle"] is not None:
        os.execle = _ORIGINAL_EXEC_FNS["execle"]
    if _ORIGINAL_EXEC_FNS["execlp"] is not None:
        os.execlp = _ORIGINAL_EXEC_FNS["execlp"]
    if _ORIGINAL_EXEC_FNS["execlpe"] is not None:
        os.execlpe = _ORIGINAL_EXEC_FNS["execlpe"]
    if _ORIGINAL_SPAWN_FNS["spawnv"] is not None:
        os.spawnv = _ORIGINAL_SPAWN_FNS["spawnv"]
    if _ORIGINAL_SPAWN_FNS["spawnve"] is not None:
        os.spawnve = _ORIGINAL_SPAWN_FNS["spawnve"]
    if _ORIGINAL_SPAWN_FNS["spawnvp"] is not None:
        os.spawnvp = _ORIGINAL_SPAWN_FNS["spawnvp"]
    if _ORIGINAL_SPAWN_FNS["spawnvpe"] is not None:
        os.spawnvpe = _ORIGINAL_SPAWN_FNS["spawnvpe"]
    if _ORIGINAL_SPAWN_FNS["spawnl"] is not None:
        os.spawnl = _ORIGINAL_SPAWN_FNS["spawnl"]
    if _ORIGINAL_SPAWN_FNS["spawnle"] is not None:
        os.spawnle = _ORIGINAL_SPAWN_FNS["spawnle"]
    if _ORIGINAL_SPAWN_FNS["spawnlp"] is not None:
        os.spawnlp = _ORIGINAL_SPAWN_FNS["spawnlp"]
    if _ORIGINAL_SPAWN_FNS["spawnlpe"] is not None:
        os.spawnlpe = _ORIGINAL_SPAWN_FNS["spawnlpe"]
    requests.sessions.Session.request = _original_session_request
    urllib_request.urlopen = _original_urlopen
    http_client.HTTPConnection.request = _original_http_request
    http_client.HTTPSConnection.request = _original_https_request
    if _socket_patch_active:
        socket.socket.connect = _original_socket_connect
        socket.socket.connect_ex = _original_socket_connect_ex
        socket.socket.sendto = _original_socket_sendto
        _socket_patch_active = False
    _expected_runtime_bindings = {}
    _last_integrity_check_at = 0.0
    _sentinel_active = False
    audit("SYSTEM", "Sentinel Deactivated. Original runtime restored.", "INFO")


def scan_input(text):
    """
    Public API for the Airlock.
    Checks Prompt Guard + LlamaGuard, then keywords.
    """
    _assert_runtime_integrity()
    # 1. Prompt-injection screening with configured detection behavior.
    scan_untrusted_text(text, source="user_input:scan_input", metadata={"path": "api"})

    # 2. LlamaGuard broad safety check.
    safety = ai_judge.check_input_safety(text, include_prompt_guard=False)
    if not safety["safe"]:
        _enforce_or_escalate(
            action="input_safety",
            target="user_input",
            reason=f"AI input guard blocked input: {safety['reason']}",
            recommendation="Reject unless you intentionally need to process unsafe input.",
        )

    # 3. Keyword Check (Legacy/Fast)
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
