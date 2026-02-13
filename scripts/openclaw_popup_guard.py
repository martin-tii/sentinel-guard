#!/usr/bin/env python3

from __future__ import annotations

import re
import os
import sys
import shutil
import subprocess
import time
import threading
import queue
from collections import deque
from typing import Deque


EXEC_START_RE = re.compile(r"embedded run tool start: .*tool=exec(?: .*toolCallId=(\S+))?")
TOOL_START_RE = re.compile(r"embedded run tool start: .*tool=(\w+)(?: .*toolCallId=(\S+))?")
TOOL_FAIL_RE = re.compile(r"\[tools\] (\w+) failed:")
DEFAULT_RISKY_TOOLS = ("exec", "process", "write", "edit", "apply_patch")


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


def _get_allow_tools() -> list[str]:
    result = _run(["openclaw", "config", "get", "tools.sandbox.tools.allow", "--json"], check=False)
    if result.returncode != 0 or not result.stdout.strip():
        return []
    # Output is JSON array text.
    import json

    try:
        parsed = json.loads(result.stdout)
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
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


def _block_tool_globally(tool_name: str):
    tool_name = (tool_name or "").strip().lower()
    if not tool_name:
        return
    tools = _get_allow_tools()
    filtered = [t for t in tools if t != tool_name]
    if tools and filtered == tools:
        return
    if not tools:
        # Conservative fallback if key is missing.
        filtered = [t for t in _default_allow_tools() if t != tool_name]
    import json

    payload = json.dumps(filtered, separators=(",", ":"))
    _run(["openclaw", "config", "set", "--json", "tools.sandbox.tools.allow", payload], check=False)
    _run(["openclaw", "sandbox", "recreate", "--all"], check=False)


def _popup_exec_alert(event_text: str):
    msg = (
        "Sentinel Alert: OpenClaw exec tool activity detected.\n\n"
        "Choose 'Block Exec' to remove exec from sandbox allowlist globally."
    )
    system = os.uname().sysname.lower() if hasattr(os, "uname") else os.name

    # macOS: AppleScript modal dialog.
    if system == "darwin":
        script = (
            'display dialog "{}" with title "Sentinel OpenClaw Guard" '
            'buttons {{"Ignore","Block Exec"}} default button "Block Exec"'
        ).format(msg.replace('"', '\\"'))
        result = _run(["osascript", "-e", script], check=False)
        output = (result.stdout or "") + (result.stderr or "")
        if "Block Exec" in output:
            _block_exec_globally()
        return

    # Linux: zenity if available.
    if system == "linux":
        if shutil.which("zenity"):
            result = _run(
                [
                    "zenity",
                    "--question",
                    "--title=Sentinel OpenClaw Guard",
                    f"--text={msg}",
                    "--ok-label=Block Exec",
                    "--cancel-label=Ignore",
                ],
                check=False,
            )
            if result.returncode == 0:
                _block_exec_globally()
        return

    # Windows: PowerShell MessageBox (best-effort).
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
        if result.returncode == 0:
            _block_tool_globally("exec")
        return


def _popup_decision(tool_name: str) -> str | None:
    """
    Returns:
      - "block" when user chooses blocking action
      - "ignore" when user dismisses/ignores
      - None when popup channel is unavailable
    """
    msg = (
        f"Sentinel Alert: OpenClaw risky tool activity detected ({tool_name}).\n\n"
        f"Block {tool_name} removes it from sandbox allowlist globally."
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


def _terminal_decision(tool_name: str) -> str | None:
    # Terminal prompt only makes sense for interactive invocations.
    if not sys.stdin or not sys.stdin.isatty():
        return None
    try:
        print(
            f"\n[Sentinel OpenClaw Guard] risky tool detected: {tool_name}\n"
            f"Type 'block' to disable '{tool_name}' globally, or 'ignore' to continue.",
            flush=True,
        )
        raw = input("> ").strip().lower()
    except Exception:
        return None
    if raw in ("block", "b", "yes", "y"):
        return "block"
    return "ignore"


def _alert_and_decide(tool_name: str) -> str:
    """
    Run popup and terminal prompts in parallel; first responder wins.
    Returns "block" or "ignore".
    """
    decisions: "queue.Queue[str]" = queue.Queue()

    def run_popup():
        decision = _popup_decision(tool_name)
        if decision:
            decisions.put(decision)

    def run_terminal():
        decision = _terminal_decision(tool_name)
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


def _handle_tool_alert(tool_name: str):
    decision = _alert_and_decide(tool_name)
    if decision == "block":
        _block_tool_globally(tool_name)


def main() -> int:
    openclaw_bin = _find_openclaw_bin()
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
            # Debounce popups to avoid spam loops.
            if now - last_popup_at < 8:
                continue
            last_popup_at = now
            _handle_tool_alert(tool_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
