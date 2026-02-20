from dataclasses import dataclass
from typing import Callable, Optional
import builtins
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from urllib.parse import urlparse
from .utils import audit


@dataclass
class SecurityAlert:
    action: str
    target: str
    reason: str
    recommendation: str
    severity: str = "high"


ApprovalHandler = Callable[[SecurityAlert], bool]
_approval_handler: Optional[ApprovalHandler] = None
_always_allow_rules: set[str] = set()
_rules_loaded = False
_approval_prompt_depth = 0


def _enter_approval_prompt():
    global _approval_prompt_depth
    _approval_prompt_depth += 1


def _exit_approval_prompt():
    global _approval_prompt_depth
    _approval_prompt_depth = max(0, _approval_prompt_depth - 1)


def in_approval_prompt() -> bool:
    return _approval_prompt_depth > 0


def _approval_rules_path() -> pathlib.Path:
    raw = str(os.environ.get("SENTINEL_APPROVAL_RULES_PATH", "")).strip()
    if raw:
        return pathlib.Path(raw).expanduser()
    return pathlib.Path.home() / ".sentinel-guard" / "approval-rules.json"


def _load_always_allow_rules():
    global _rules_loaded
    if _rules_loaded:
        return
    _rules_loaded = True
    path = _approval_rules_path()
    try:
        if not path.exists():
            return
        payload = json.loads(path.read_text(encoding="utf-8"))
        entries = payload.get("always_allow") if isinstance(payload, dict) else []
        if isinstance(entries, list):
            for item in entries:
                value = str(item).strip()
                if value:
                    _always_allow_rules.add(value)
    except Exception as exc:
        audit("APPROVAL_RULES", f"Failed to load approval rules: {exc}", "WARNING")


def _save_always_allow_rules():
    path = _approval_rules_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        body = {"always_allow": sorted(_always_allow_rules)}
        path.write_text(json.dumps(body, indent=2), encoding="utf-8")
    except Exception as exc:
        audit("APPROVAL_RULES", f"Failed to save approval rules: {exc}", "WARNING")


def _extract_executable(target: str) -> str:
    text = str(target or "").strip()
    if not text:
        return ""
    try:
        parts = re.split(r"\s+", text)
    except Exception:
        parts = [text]
    if not parts:
        return ""
    first = parts[0].strip().strip('"').strip("'")
    first = os.path.basename(first)
    return first.lower()


def _extract_host(target: str) -> str:
    text = str(target or "").strip()
    if not text:
        return ""
    try:
        parsed = urlparse(text)
        host = (parsed.hostname or "").strip().lower()
        if host:
            return host
    except Exception:
        pass
    return text.lower()


def _rule_key_for_alert(alert: SecurityAlert) -> str:
    action = str(alert.action or "").strip().lower()
    target = str(alert.target or "").strip()
    if action == "command_execution":
        executable = _extract_executable(target)
        if executable:
            return f"{action}:exe:{executable}"
    if action == "network_access":
        host = _extract_host(target)
        if host:
            return f"{action}:host:{host}"
    return f"{action}:target:{target.lower()}"


def _set_always_allow(alert: SecurityAlert):
    _load_always_allow_rules()
    key = _rule_key_for_alert(alert)
    if not key:
        return
    _always_allow_rules.add(key)
    _save_always_allow_rules()


def _is_always_allow(alert: SecurityAlert) -> bool:
    _load_always_allow_rules()
    key = _rule_key_for_alert(alert)
    return bool(key and key in _always_allow_rules)


def _friendly_reason_parts(alert: SecurityAlert) -> tuple[str, str, str]:
    action = str(alert.action or "").strip().lower()
    reason = str(alert.reason or "").strip()
    reason_lower = reason.lower()

    if "outside the allowed workspace" in reason_lower or "file" in action:
        return (
            "Sentinel stopped a file access outside your approved workspace.",
            "This protects against reading or changing files that are not part of this task.",
            "Use 'Allow once' only if this file is expected, or update allowed_paths in sentinel.yaml.",
        )
    if "not allowed" in reason_lower and ("command" in reason_lower or "command_execution" in action):
        return (
            "Sentinel blocked a command that is not on your safe command list.",
            "This prevents high-risk commands from running unexpectedly.",
            "Use 'Allow once' if you trust it now, or add the command to allowed_commands.",
        )
    if "shell chaining" in reason_lower or "injection risk" in reason_lower:
        return (
            "Sentinel blocked a command pattern that looks like command injection.",
            "Chained shell operators can hide unsafe behavior.",
            "Run a simple single command instead, or block this action.",
        )
    if "host" in reason_lower or "url" in reason_lower or "network" in action:
        return (
            "Sentinel blocked a network request to a host that is not approved.",
            "This prevents data exfiltration and accidental calls to unknown services.",
            "Use 'Allow once' only for trusted destinations, or add the host to allowed_hosts.",
        )
    if "phishing risk" in reason_lower:
        return (
            "Sentinel flagged this URL as a phishing risk.",
            "The destination matches known phishing indicators.",
            "Block unless you have independent verification that this URL is safe.",
        )
    if "policy integrity violation" in reason_lower or "runtime integrity violation" in reason_lower:
        return (
            "Sentinel detected a security integrity issue and stopped execution.",
            "Security hooks or policy validation changed unexpectedly.",
            "Block and investigate runtime/policy tampering before continuing.",
        )
    if "seccomp" in reason_lower:
        return (
            "Sentinel blocked a low-level system call in strict sandbox mode.",
            "The process requested an operation outside the sandbox's allowed syscall set.",
            "Retry with seccomp log mode to inspect needs, then tighten policy again.",
        )
    return (
        f"Sentinel paused this action: {alert.action}.",
        "The action matched a protection rule and now needs your explicit decision.",
        "Use 'Allow once' if expected, 'Always allow this app' for trusted repeats, otherwise 'Block'.",
    )


def explain_security_alert(alert: SecurityAlert) -> str:
    what_happened, why_blocked, next_step = _friendly_reason_parts(alert)
    return (
        f"What happened: {what_happened} "
        f"Why: {why_blocked} "
        f"What to do next: {next_step} "
        f"Technical reason: {alert.reason}"
    )


def set_approval_handler(handler: ApprovalHandler):
    """Registers a callback used to approve or reject blocked actions."""
    global _approval_handler
    _approval_handler = handler
    audit("APPROVAL_HANDLER", "Custom approval handler registered", "INFO")


def clear_approval_handler():
    """Clears the custom approval callback."""
    global _approval_handler
    _approval_handler = None
    audit("APPROVAL_HANDLER", "Custom approval handler cleared", "INFO")


def get_approval_handler() -> Optional[ApprovalHandler]:
    return _approval_handler


def _default_approval_mode() -> str:
    mode = str(os.environ.get("SENTINEL_APPROVAL_MODE", "auto")).strip().lower()
    if mode not in ("auto", "popup", "tkinter", "console", "reject"):
        return "auto"
    return mode


def _platform_popup_available() -> bool:
    if sys.platform == "darwin":
        return shutil.which("osascript") is not None
    if sys.platform.startswith("linux"):
        return shutil.which("zenity") is not None
    if os.name == "nt":
        return shutil.which("powershell") is not None or shutil.which("pwsh") is not None
    return False


def _can_try_tkinter_popup() -> bool:
    if os.name == "nt":
        return True
    if sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _resolve_default_handler() -> Optional[ApprovalHandler]:
    mode = _default_approval_mode()
    if mode == "reject":
        return None
    if mode == "popup":
        if _platform_popup_available():
            return native_popup_approval_handler
        if _can_try_tkinter_popup():
            return tkinter_approval_handler
        return None
    if mode == "tkinter":
        return tkinter_approval_handler
    if mode == "console":
        if getattr(sys.stdin, "isatty", lambda: False)():
            return console_approval_handler
        return None

    # auto mode: native popup first, tkinter fallback, then console.
    if _platform_popup_available():
        return native_popup_approval_handler
    if _can_try_tkinter_popup():
        return tkinter_approval_handler
    if getattr(sys.stdin, "isatty", lambda: False)():
        return console_approval_handler
    return None


def _popup_message(alert: SecurityAlert) -> str:
    what_happened, why_blocked, next_step = _friendly_reason_parts(alert)
    lines = [
        "Sentinel Security Decision Required",
        "",
        f"Action: {alert.action}",
        f"Target: {alert.target}",
        "",
        f"What happened: {what_happened}",
        f"Why: {why_blocked}",
        f"What to do next: {next_step}",
        "",
        f"Technical reason: {alert.reason}",
    ]
    return "\n".join(lines)


def _decision_from_text(text: str) -> str:
    normalized = str(text or "").strip().lower()
    if "always allow this app" in normalized:
        return "always"
    if "allow once" in normalized:
        return "allow"
    if "block" in normalized:
        return "block"
    return "block"


def native_popup_approval_handler(alert: SecurityAlert) -> bool:
    message = _popup_message(alert)

    if sys.platform == "darwin":
        script = (
            'display dialog "{}" with title "Sentinel Security Approval" '
            'buttons {{"Block","Allow once","Always allow this app"}} '
            'default button "Block"'
        ).format(message.replace('"', '\\"'))
        result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
        output = (result.stdout or "") + (result.stderr or "")
        decision = _decision_from_text(output)
    elif sys.platform.startswith("linux"):
        if not shutil.which("zenity"):
            return False
        result = subprocess.run(
            [
                "zenity",
                "--question",
                "--title=Sentinel Security Approval",
                f"--text={message}",
                "--ok-label=Allow once",
                "--cancel-label=Block",
                "--extra-button=Always allow this app",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            decision = "allow"
        else:
            decision = _decision_from_text((result.stdout or "") + (result.stderr or ""))
    elif os.name == "nt":
        ps = shutil.which("powershell") or shutil.which("pwsh")
        if not ps:
            return False
        escaped = message.replace("'", "''")
        cmd = (
            "Add-Type -AssemblyName System.Windows.Forms; "
            "$f=New-Object System.Windows.Forms.Form; "
            "$f.Text='Sentinel Security Approval'; $f.Width=920; $f.Height=520; "
            "$t=New-Object System.Windows.Forms.TextBox; $t.Multiline=$true; $t.ReadOnly=$true; "
            "$t.ScrollBars='Vertical'; $t.Width=880; $t.Height=410; $t.Left=10; $t.Top=10; "
            f"$t.Text='{escaped}'; $f.Controls.Add($t); "
            "$b1=New-Object System.Windows.Forms.Button; $b1.Text='Allow once'; $b1.Left=410; $b1.Top=430; "
            "$b2=New-Object System.Windows.Forms.Button; $b2.Text='Always allow this app'; $b2.Left=520; $b2.Top=430; "
            "$b3=New-Object System.Windows.Forms.Button; $b3.Text='Block'; $b3.Left=730; $b3.Top=430; "
            "$global:sentinelDecision='block'; "
            "$b1.Add_Click({$global:sentinelDecision='allow'; $f.Close()}); "
            "$b2.Add_Click({$global:sentinelDecision='always'; $f.Close()}); "
            "$b3.Add_Click({$global:sentinelDecision='block'; $f.Close()}); "
            "$f.Controls.Add($b1); $f.Controls.Add($b2); $f.Controls.Add($b3); "
            "$f.Add_Shown({$f.Activate()}); [void]$f.ShowDialog(); Write-Output $global:sentinelDecision"
        )
        result = subprocess.run([ps, "-NoProfile", "-Command", cmd], capture_output=True, text=True)
        decision = _decision_from_text((result.stdout or "") + (result.stderr or ""))
    else:
        return False

    if decision == "always":
        _set_always_allow(alert)
        return True
    return decision == "allow"


def console_approval_handler(alert: SecurityAlert) -> bool:
    """
    Simple terminal fallback. Host apps can replace this with a UI popup.
    """
    what_happened, why_blocked, next_step = _friendly_reason_parts(alert)
    print("\n[SECURITY DECISION REQUIRED]")
    print(f"Action: {alert.action}")
    print(f"Target: {alert.target}")
    print(f"What happened: {what_happened}")
    print(f"Why: {why_blocked}")
    print(f"What to do next: {next_step}")
    print(f"Technical reason: {alert.reason}")
    print("\nChoose:")
    print("1) Allow once")
    print("2) Always allow this app")
    print("3) Block")
    decision = builtins.input("Selection [3]: ").strip().lower()
    if decision in ("1", "allow", "allow once", "a", "yes", "y"):
        return True
    if decision in ("2", "always", "always allow", "always allow this app"):
        _set_always_allow(alert)
        return True
    return False


def tkinter_approval_handler(alert: SecurityAlert) -> bool:
    """
    Minimal desktop popup approval dialog using tkinter.
    Returns True for Approve, False for Reject/close/error.
    """
    try:
        import tkinter as tk
        from tkinter import scrolledtext
    except Exception as e:
        audit("APPROVAL_HANDLER", f"tkinter unavailable: {e}", "WARNING")
        return False

    try:
        approved = {"value": False}
        persist_allow = {"value": False}
        root = tk.Tk()
        root.title("Sentinel Security Approval")
        root.resizable(False, False)
        root.attributes("-topmost", True)

        frame = tk.Frame(root, padx=12, pady=12)
        frame.pack(fill="both", expand=True)

        what_happened, why_blocked, next_step = _friendly_reason_parts(alert)

        tk.Label(frame, text="Security decision required", font=("TkDefaultFont", 11, "bold")).pack(anchor="w")
        tk.Label(frame, text=f"Action: {alert.action}").pack(anchor="w", pady=(6, 0))
        tk.Label(frame, text=f"Target: {alert.target}").pack(anchor="w")
        severity_key = str(alert.severity).strip().lower()
        severity_colors = {
            "critical": "#b91c1c",
            "high": "#dc2626",
            "medium": "#d97706",
            "low": "#16a34a",
        }
        sev_color = severity_colors.get(severity_key, "#6b7280")

        sev_row = tk.Frame(frame)
        sev_row.pack(anchor="w", pady=(0, 2))
        tk.Label(sev_row, text="Severity: ").pack(side="left")
        tk.Label(
            sev_row,
            text=str(alert.severity).upper(),
            bg=sev_color,
            fg="white",
            padx=8,
            pady=2,
        ).pack(side="left")

        tk.Label(frame, text="What happened:").pack(anchor="w", pady=(8, 0))
        reason_box = scrolledtext.ScrolledText(frame, width=80, height=4, wrap="word")
        reason_box.insert("1.0", what_happened)
        reason_box.configure(state="disabled")
        reason_box.pack(fill="both", expand=True)

        tk.Label(frame, text="Why:").pack(anchor="w", pady=(8, 0))
        why_box = scrolledtext.ScrolledText(frame, width=80, height=3, wrap="word")
        why_box.insert("1.0", why_blocked)
        why_box.configure(state="disabled")
        why_box.pack(fill="both", expand=True)

        tk.Label(frame, text="What to do next:").pack(anchor="w", pady=(8, 0))
        recommendation_box = scrolledtext.ScrolledText(frame, width=80, height=3, wrap="word")
        recommendation_box.insert("1.0", next_step)
        recommendation_box.configure(state="disabled")
        recommendation_box.pack(fill="both", expand=True)

        tk.Label(frame, text="Technical reason:").pack(anchor="w", pady=(8, 0))
        technical_box = scrolledtext.ScrolledText(frame, width=80, height=2, wrap="word")
        technical_box.insert("1.0", str(alert.reason))
        technical_box.configure(state="disabled")
        technical_box.pack(fill="both", expand=True)

        button_row = tk.Frame(frame, pady=10)
        button_row.pack(anchor="e")

        def approve():
            approved["value"] = True
            root.destroy()

        def approve_always():
            approved["value"] = True
            persist_allow["value"] = True
            root.destroy()

        def reject():
            approved["value"] = False
            root.destroy()

        def make_action_chip(parent, text, bg, active_bg, callback):
            chip = tk.Label(
                parent,
                text=text,
                bg=bg,
                fg="white",
                width=20,
                padx=10,
                pady=8,
                cursor="hand2",
                relief="flat",
            )

            def on_enter(_event):
                chip.configure(bg=active_bg)

            def on_leave(_event):
                chip.configure(bg=bg)

            chip.bind("<Enter>", on_enter)
            chip.bind("<Leave>", on_leave)
            chip.bind("<Button-1>", lambda _event: callback())
            return chip

        block_chip = make_action_chip(
            button_row,
            text="Block",
            bg="#dc2626",
            active_bg="#b91c1c",
            callback=reject,
        )
        allow_once_chip = make_action_chip(
            button_row,
            text="Allow Once",
            bg="#16a34a",
            active_bg="#15803d",
            callback=approve,
        )
        allow_always_chip = make_action_chip(
            button_row,
            text="Always Allow This App",
            bg="#2563eb",
            active_bg="#1d4ed8",
            callback=approve_always,
        )

        block_chip.pack(side="right", padx=(8, 0))
        allow_always_chip.pack(side="right", padx=(8, 0))
        allow_once_chip.pack(side="right")

        root.protocol("WM_DELETE_WINDOW", reject)
        root.bind("<Escape>", lambda _event: reject())
        root.bind("<Return>", lambda _event: approve())
        root.mainloop()
        if approved["value"] and persist_allow["value"]:
            _set_always_allow(alert)
        return approved["value"]
    except Exception as e:
        audit("APPROVAL_HANDLER", f"tkinter dialog error: {e}", "WARNING")
        return False


def request_user_approval(alert: SecurityAlert) -> bool:
    """
    Uses registered handler to decide whether a blocked action can proceed.
    Defaults to reject when no handler is configured.
    """
    if _is_always_allow(alert):
        audit(
            "SECURITY_ALERT",
            f"{alert.action} -> {alert.target} | auto-approved by saved 'always allow' rule",
            "APPROVED",
        )
        return True

    handler = get_approval_handler()
    default_mode = _default_approval_mode()
    using_default_handler = False
    if handler is None:
        handler = _resolve_default_handler()
        using_default_handler = handler is not None

    if handler is None:
        audit(
            "SECURITY_ALERT",
            f"{alert.action} -> {alert.target} | No approval handler configured (mode={default_mode})",
            "REJECTED",
        )
        return False

    _enter_approval_prompt()
    try:
        approved = bool(handler(alert))
    except Exception as e:
        audit(
            "SECURITY_ALERT",
            f"{alert.action} -> {alert.target} | Handler error: {e}",
            "REJECTED",
        )
        return False
    finally:
        _exit_approval_prompt()

    status = "APPROVED" if approved else "REJECTED"
    if using_default_handler:
        audit(
            "SECURITY_ALERT",
            f"{alert.action} -> {alert.target} | {alert.reason} | default_mode={default_mode}",
            status,
        )
    else:
        audit("SECURITY_ALERT", f"{alert.action} -> {alert.target} | {alert.reason}", status)
    return approved
