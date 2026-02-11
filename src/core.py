import builtins
import errno
import io
import os
import pathlib
import subprocess
import requests # Assuming requests is used, we'll patch it
import urllib.request as urllib_request
import http.client as http_client
import socket
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
network_failsafe_config = policy.policy.get("network_failsafe", {})
socket_failsafe_enabled = bool(network_failsafe_config.get("socket_connect", False))

# --- Interceptors ---

# 1. File System Interceptor (The Jail)
_original_open = builtins.open
_original_io_open = io.open
_original_path_open = pathlib.Path.open
_original_os_open = os.open


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


def _should_bypass_file_policy(target):
    # io.open is also used by stdlib internals with raw file descriptors.
    if isinstance(target, int):
        return True

    try:
        target_path = pathlib.Path(target).resolve()
        policy_path = pathlib.Path(policy.policy_path).resolve()
        return target_path == policy_path
    except Exception:
        return False


def sentinel_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    # 1. Static Policy Check (The Law)
    if not _should_bypass_file_policy(file):
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


def sentinel_io_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    if not _should_bypass_file_policy(file):
        try:
            policy.check_file_access(file)
        except PermissionError as e:
            _enforce_or_escalate(
                action="file_access",
                target=file,
                reason=e,
                recommendation="Reject unless the file path is expected for this task.",
            )

    return _original_io_open(file, mode, buffering, encoding, errors, newline, closefd, opener)


def sentinel_path_open(self, mode='r', buffering=-1, encoding=None, errors=None, newline=None):
    if not _should_bypass_file_policy(self):
        try:
            policy.check_file_access(self)
        except PermissionError as e:
            _enforce_or_escalate(
                action="file_access",
                target=self,
                reason=e,
                recommendation="Reject unless the file path is expected for this task.",
            )

    return _original_path_open(self, mode, buffering, encoding, errors, newline)


def _normalize_os_open_path(path):
    try:
        return os.fsdecode(path)
    except Exception:
        return str(path)


def sentinel_os_open(path, flags, mode=0o777, *, dir_fd=None):
    if dir_fd is not None:
        _enforce_or_escalate(
            action="file_access",
            target=path,
            reason="os.open with dir_fd is not permitted under Sentinel policy.",
            recommendation="Reject and use normal absolute/relative paths without dir_fd.",
        )

    normalized_path = _normalize_os_open_path(path)
    if not _should_bypass_file_policy(normalized_path):
        try:
            policy.check_file_access(normalized_path)
        except PermissionError as e:
            _enforce_or_escalate(
                action="file_access",
                target=normalized_path,
                reason=e,
                recommendation="Reject unless the file path is expected for this task.",
            )

    return _original_os_open(path, flags, mode)


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


def sentinel_socket_connect(self, address):
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
    global _sentinel_active, _socket_patch_active

    # Emergency kill switch for production incidents.
    if os.environ.get("SENTINEL_DISABLE", "").lower() in ("true", "1", "yes"):
        audit("SYSTEM", "Sentinel disabled via SENTINEL_DISABLE env var.", "WARNING")
        return

    if _sentinel_active:
        audit("SYSTEM", "Sentinel already active. Skipping re-patch.", "INFO")
        return

    audit("SYSTEM", "Sentinel Activated. Monitoring engaged.", "INFO")

    # Monkey Patching
    builtins.open = sentinel_open
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


def deactivate_sentinel():
    """Restores original runtime functions and disables Sentinel interception."""
    global _sentinel_active, _socket_patch_active
    if not _sentinel_active:
        audit("SYSTEM", "Sentinel already inactive. Nothing to restore.", "INFO")
        return

    builtins.open = _original_open
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
