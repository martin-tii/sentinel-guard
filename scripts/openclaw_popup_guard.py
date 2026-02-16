#!/usr/bin/env python3

from __future__ import annotations

import os
import re
import shutil
import shlex
import subprocess
import tempfile
import queue
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Deque


TOOL_START_RE = re.compile(r"embedded run tool start: .*tool=([^\s]+)(?: .*toolCallId=([^\s]+))?")
TOOL_FAIL_RE = re.compile(r"\[tools\] ([^\s]+) failed:")
DEFAULT_RISKY_TOOLS = ("exec", "process", "write", "edit", "apply_patch")
_TOOL_DETAIL_KEYS = (
    "command",
    "cmd",
    "argv",
    "args",
    "program",
    "target",
    "path",
    "file",
    "input",
)


def _is_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _risky_tools() -> set[str]:
    raw = os.environ.get("SENTINEL_OPENCLAW_POPUP_TOOLS", "")
    if not raw.strip():
        return set(DEFAULT_RISKY_TOOLS)
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


def _find_openclaw_bin() -> str:
    env_bin = os.environ.get("OPENCLAW_BIN", "").strip()
    if env_bin:
        return env_bin
    found = shutil.which("openclaw")
    if found:
        return found
    # Common macOS install locations.
    for candidate in ("/opt/homebrew/bin/openclaw", "/usr/local/bin/openclaw"):
        if os.path.exists(candidate):
            return candidate
    return "openclaw"


def _run(cmd: list[str], *, check: bool = True):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr}")
    return result


def _resolve_lock_path() -> str:
    root = os.environ.get("SENTINEL_OPENCLAW_POPUP_GUARD_LOCK_DIR", "").strip()
    if not root:
        root = os.path.join(tempfile.gettempdir(), "sentinel-openclaw")
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, "popup-guard.lock")


def _is_process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _acquire_singleton_lock(lock_path: str) -> bool:
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(str(os.getpid()))
            return True
        except FileExistsError:
            try:
                with open(lock_path, "r", encoding="utf-8") as handle:
                    owner_pid = int(handle.read().strip() or "0")
            except Exception:
                owner_pid = 0
            if owner_pid and _is_process_alive(owner_pid):
                return False
            try:
                os.unlink(lock_path)
            except FileNotFoundError:
                pass
            except Exception:
                return False


def _release_singleton_lock(lock_path: str):
    try:
        with open(lock_path, "r", encoding="utf-8") as handle:
            owner_pid = int(handle.read().strip() or "0")
        if owner_pid != os.getpid():
            return
    except Exception:
        return
    try:
        os.unlink(lock_path)
    except Exception:
        pass


def _primary_approvals_available(openclaw_bin: str) -> bool:
    if _is_truthy(os.environ.get("SENTINEL_OPENCLAW_POPUP_GUARD_FORCE")):
        return False
    result = _run(
        [openclaw_bin, "config", "get", "plugins.entries.sentinel-preexec.enabled", "--json"],
        check=False,
    )
    if result.returncode == 0:
        value = (result.stdout or "").strip().lower()
        if value in ("true", "1"):
            return True
    return False


def _extract_tool_context(line: str, tool_name: str) -> str | None:
    text = str(line or "")
    if tool_name == "exec":
        exec_hint = _extract_exec_hint(text)
        if exec_hint:
            return exec_hint

    for key in _TOOL_DETAIL_KEYS:
        match = re.search(rf"{key}=((\"[^\"]*\")|('[^']*')|(\[[^\]]*\])|(\{{[^}}]*\}})|([^\s]+))", text)
        if match:
            value = (match.group(1) or "").strip().strip("\"'")
            if value:
                context = f"{key}={value}"
                return context if len(context) <= 220 else f"{context[:217]}..."
    tool_call_match = re.search(r"toolCallId=([^\s]+)", text)
    if tool_call_match:
        hint = _format_tool_call_id_hint(tool_call_match.group(1), tool_name=tool_name)
        if hint:
            return hint
    if tool_name == "exec":
        exec_match = re.search(r"exec(?:ute)?\s+(.+)$", text, flags=re.IGNORECASE)
        if exec_match:
            context = exec_match.group(1).strip()
            if context:
                exe = _extract_first_token(context)
                if exe:
                    return f"Executable hint: {exe} (full command: {context[:170]})"
                return context if len(context) <= 220 else f"{context[:217]}..."
    return None


def _extract_first_token(command: str) -> str | None:
    value = str(command or "").strip()
    if not value:
        return None
    try:
        parts = shlex.split(value)
    except Exception:
        parts = value.split()
    if not parts:
        return None
    return os.path.basename(parts[0]) or parts[0]


def _extract_exec_hint(text: str) -> str | None:
    patterns = [
        r'command="([^"]+)"',
        r"command='([^']+)'",
        r"\bcommand=([^\s]+)",
        r'"command"\s*:\s*"([^"]+)"',
        r'"cmd"\s*:\s*"([^"]+)"',
        r"\bcmd=([^\s]+)",
        r'"program"\s*:\s*"([^"]+)"',
        r"\bprogram=([^\s]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if not match:
            continue
        command = (match.group(1) or "").strip()
        if not command:
            continue
        exe = _extract_first_token(command)
        if exe:
            return f"Executable hint: {exe} (full command: {command[:170]})"
    argv_json = re.search(r'"argv"\s*:\s*\[([^\]]+)\]', text)
    if argv_json:
        raw = argv_json.group(1)
        first = re.search(r'"([^"]+)"', raw)
        if first:
            token = first.group(1).strip()
            if token:
                return f"Executable hint: {os.path.basename(token) or token} (from argv)"
    return None


def _format_tool_call_id_hint(tool_call_id: str, *, tool_name: str = "") -> str | None:
    value = str(tool_call_id or "").strip()
    if not value:
        return None
    match = re.match(r"^[^_]+_(\d{10,16})_(\d+)$", value)
    if not match:
        if tool_name == "exec":
            return f"No executable details yet. Invocation ID: {value}"
        return f"Invocation ID: {value}"
    raw_epoch = match.group(1)
    seq = match.group(2)
    epoch = int(raw_epoch)
    if len(raw_epoch) > 10:
        ts_seconds = epoch / 1000.0
    else:
        ts_seconds = float(epoch)
    dt = datetime.fromtimestamp(ts_seconds, tz=timezone.utc)
    ts = dt.isoformat().replace("+00:00", "Z")
    if tool_name == "exec":
        return f"No executable details yet. Invocation ID: {value} (started UTC: {ts})"
    return f"Invocation ID: {value} (started UTC: {ts}, seq: {seq})"


def _get_allow_tools(openclaw_bin: str) -> list[str] | None:
    result = _run([openclaw_bin, "config", "get", "tools.sandbox.tools.allow", "--json"], check=False)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    # Output is JSON array text.
    import json

    try:
        parsed = json.loads(result.stdout)
    except Exception:
        return None
    if not isinstance(parsed, list):
        return None
    return [str(x) for x in parsed]


def _default_allow_tools() -> list[str]:
    return [
        "read",
        "write",
        "edit",
        "apply_patch",
        "image",
        "sessions_list",
        "sessions_history",
        "sessions_send",
        "sessions_spawn",
        "session_status",
    ]


def _block_tool_globally(tool_name: str, openclaw_bin: str) -> bool:
    tool_name = (tool_name or "").strip().lower()
    if not tool_name:
        return False
    tools = _get_allow_tools(openclaw_bin)
    if tools is None:
        # Fail closed on state-read failure to avoid broadening policy.
        return False
    filtered = [t for t in tools if t != tool_name]
    if tools and filtered == tools:
        return True
    if not tools:
        # Empty configured allowlist: keep it empty rather than broadening defaults.
        return True
    import json

    payload = json.dumps(filtered, separators=(",", ":"))
    set_result = _run(
        [openclaw_bin, "config", "set", "--json", "tools.sandbox.tools.allow", payload],
        check=False,
    )
    if set_result.returncode != 0:
        return False
    recreate_result = _run([openclaw_bin, "sandbox", "recreate", "--all"], check=False)
    return recreate_result.returncode == 0


def _popup_decision(tool_name: str, context: str | None = None) -> str | None:
    """
    Returns:
      - "block" when user chooses blocking action
      - "ignore" when user dismisses/ignores
      - None when popup channel is unavailable
    """
    detail_line = f"\n\nDetails: {context}" if context else ""
    tool_line = (
        "Tool: exec (runs OS commands)"
        if tool_name == "exec"
        else f"Tool: {tool_name}"
    )
    msg = (
        f"Sentinel Alert: OpenClaw risky tool activity detected ({tool_name}).\n\n"
        f"{tool_line}\n\n"
        f"Block {tool_name} removes it from sandbox allowlist globally."
        f"{detail_line}"
    )
    system = os.uname().sysname.lower() if hasattr(os, "uname") else os.name

    if system == "darwin":
        script = (
            'display dialog "{}" with title "Sentinel OpenClaw Guard" '
            'buttons {{"Ignore","Block Tool"}} default button "Block Tool"'
        ).format(msg.replace('"', '\\"'))
        result = _run(["osascript", "-e", script], check=False)
        output = (result.stdout or "") + (result.stderr or "")
        return "block" if "Block Tool" in output else "ignore"

    if system == "linux":
        if not shutil.which("zenity"):
            return None
        result = _run(
            [
                "zenity",
                "--question",
                "--title=Sentinel OpenClaw Guard",
                f"--text={msg}",
                "--ok-label=Block Tool",
                "--cancel-label=Ignore",
            ],
            check=False,
        )
        return "block" if result.returncode == 0 else "ignore"

    if os.name == "nt":
        escaped_msg = msg.replace("'", "''")
        ps = (
            "[void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); "
            "$r=[System.Windows.Forms.MessageBox]::Show("
            f"'{escaped_msg}',"
            "'Sentinel OpenClaw Guard',"
            "[System.Windows.Forms.MessageBoxButtons]::YesNo,"
            "[System.Windows.Forms.MessageBoxIcon]::Warning); "
            "if ($r -eq [System.Windows.Forms.DialogResult]::Yes) { exit 0 } else { exit 1 }"
        )
        result = _run(["powershell", "-NoProfile", "-Command", ps], check=False)
        return "block" if result.returncode == 0 else "ignore"
    return None


def _terminal_decision(tool_name: str, context: str | None = None) -> str | None:
    # Terminal prompt only makes sense for interactive invocations.
    if not sys.stdin or not sys.stdin.isatty():
        return None
    try:
        detail_line = f"\nDetails: {context}" if context else ""
        print(
            f"\n[Sentinel OpenClaw Guard] risky tool detected: {tool_name}{detail_line}\n"
            f"Type 'block' to disable '{tool_name}' globally, or 'ignore' to continue.",
            flush=True,
        )
        raw = input("> ").strip().lower()
    except Exception:
        return None
    if raw in ("block", "b", "yes", "y"):
        return "block"
    return "ignore"


def _alert_and_decide(tool_name: str, context: str | None = None) -> str:
    """
    Run popup and terminal prompts in parallel; first responder wins.
    Returns "block" or "ignore".
    """
    decisions: "queue.Queue[str]" = queue.Queue()

    def run_popup():
        decision = _popup_decision(tool_name, context=context)
        if decision:
            decisions.put(decision)

    def run_terminal():
        decision = _terminal_decision(tool_name, context=context)
        if decision:
            decisions.put(decision)

    threads = [
        threading.Thread(target=run_popup, daemon=True),
        threading.Thread(target=run_terminal, daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        return decisions.get(timeout=120)
    except queue.Empty:
        # Fail-safe default when nobody answers.
        return "block"


def _handle_tool_alert(tool_name: str, openclaw_bin: str, context: str | None = None):
    decision = _alert_and_decide(tool_name, context=context)
    if decision == "block":
        blocked = _block_tool_globally(tool_name, openclaw_bin)
        if not blocked:
            print(
                f"[Sentinel OpenClaw Guard] failed to block tool '{tool_name}' "
                "(could not read or update allowlist).",
                file=sys.stderr,
                flush=True,
            )


def main() -> int:
    lock_path = _resolve_lock_path()
    if not _acquire_singleton_lock(lock_path):
        print("[Sentinel OpenClaw Guard] another popup-guard instance is already running; exiting.", file=sys.stderr)
        return 0

    openclaw_bin = _find_openclaw_bin()
    try:
        proc = subprocess.Popen(
            [
                openclaw_bin,
                "logs",
                "--follow",
                "--plain",
                "--interval",
                "1000",
                "--timeout",
                "86400000",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        recent: Deque[str] = deque(maxlen=20)
        recent_tool_call_ids: Deque[str] = deque(maxlen=200)
        last_popup_at = 0.0
        risky_tools = _risky_tools()
        check_interval = 30.0
        try:
            check_interval = max(
                5.0,
                float(os.environ.get("SENTINEL_OPENCLAW_POPUP_GUARD_PRIMARY_CHECK_SECONDS", "30")),
            )
        except Exception:
            check_interval = 30.0
        primary_available = _primary_approvals_available(openclaw_bin)
        last_primary_check_at = time.time()

        assert proc.stdout is not None
        for line in proc.stdout:
            text = line.strip()
            if not text:
                continue
            event_key = text[-180:]
            if event_key in recent:
                continue
            recent.append(event_key)

            start = TOOL_START_RE.search(text)
            fail = TOOL_FAIL_RE.search(text)
            tool_name = ""
            call_id = ""
            if start:
                tool_name = (start.group(1) or "").lower()
                call_id = start.group(2) or ""
            elif fail:
                tool_name = (fail.group(1) or "").lower()
            if tool_name and tool_name in risky_tools:
                # Prefer stable toolCallId to avoid duplicate prompts from
                # start/fail events of the same tool invocation.
                if call_id:
                    if call_id in recent_tool_call_ids:
                        continue
                    recent_tool_call_ids.append(call_id)
                now = time.time()
                if now - last_primary_check_at >= check_interval:
                    primary_available = _primary_approvals_available(openclaw_bin)
                    last_primary_check_at = now
                # Fallback popup guard should stay quiet when primary approvals are available.
                if primary_available:
                    continue
                # Debounce popups to avoid spam loops.
                if now - last_popup_at < 8:
                    continue
                last_popup_at = now
                _handle_tool_alert(tool_name, openclaw_bin, context=_extract_tool_context(text, tool_name))
        return 0
    finally:
        _release_singleton_lock(lock_path)


if __name__ == "__main__":
    raise SystemExit(main())
