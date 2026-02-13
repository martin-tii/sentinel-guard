#!/usr/bin/env python3

from __future__ import annotations

import os
import re
import shutil
import subprocess
import queue
import sys
import threading
import time
from collections import deque
from typing import Deque


TOOL_START_RE = re.compile(r"embedded run tool start: .*tool=([^\s]+)(?: .*toolCallId=([^\s]+))?")
TOOL_FAIL_RE = re.compile(r"\[tools\] ([^\s]+) failed:")
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


def _handle_tool_alert(tool_name: str, openclaw_bin: str):
    decision = _alert_and_decide(tool_name)
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
            _handle_tool_alert(tool_name, openclaw_bin)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
