from dataclasses import dataclass
from typing import Callable, Optional
import builtins
import os
import sys
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
    if mode not in ("auto", "tkinter", "console", "reject"):
        return "auto"
    return mode


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
    if mode == "tkinter":
        return tkinter_approval_handler
    if mode == "console":
        if getattr(sys.stdin, "isatty", lambda: False)():
            return console_approval_handler
        return None

    # auto mode: popup first, then console if interactive terminal exists.
    if _can_try_tkinter_popup():
        return tkinter_approval_handler
    if getattr(sys.stdin, "isatty", lambda: False)():
        return console_approval_handler
    return None


def console_approval_handler(alert: SecurityAlert) -> bool:
    """
    Simple terminal fallback. Host apps can replace this with a UI popup.
    """
    print("\n[SECURITY APPROVAL REQUIRED]")
    print(f"Action: {alert.action}")
    print(f"Target: {alert.target}")
    print(f"Reason: {alert.reason}")
    print(f"Recommendation: {alert.recommendation}")
    decision = builtins.input("Approve anyway? [y/N]: ").strip().lower()
    return decision in ("y", "yes")


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
        root = tk.Tk()
        root.title("Sentinel Security Approval")
        root.resizable(False, False)
        root.attributes("-topmost", True)

        frame = tk.Frame(root, padx=12, pady=12)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="Security approval required", font=("TkDefaultFont", 11, "bold")).pack(anchor="w")
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

        tk.Label(frame, text="Reason:").pack(anchor="w", pady=(8, 0))
        reason_box = scrolledtext.ScrolledText(frame, width=80, height=4, wrap="word")
        reason_box.insert("1.0", alert.reason)
        reason_box.configure(state="disabled")
        reason_box.pack(fill="both", expand=True)

        tk.Label(frame, text="Recommendation:").pack(anchor="w", pady=(8, 0))
        recommendation_box = scrolledtext.ScrolledText(frame, width=80, height=3, wrap="word")
        recommendation_box.insert("1.0", alert.recommendation)
        recommendation_box.configure(state="disabled")
        recommendation_box.pack(fill="both", expand=True)

        button_row = tk.Frame(frame, pady=10)
        button_row.pack(anchor="e")

        def approve():
            approved["value"] = True
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
                width=14,
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

        reject_chip = make_action_chip(
            button_row,
            text="Reject",
            bg="#dc2626",
            active_bg="#b91c1c",
            callback=reject,
        )
        approve_chip = make_action_chip(
            button_row,
            text="Approve",
            bg="#16a34a",
            active_bg="#15803d",
            callback=approve,
        )

        reject_chip.pack(side="right", padx=(8, 0))
        approve_chip.pack(side="right")

        root.protocol("WM_DELETE_WINDOW", reject)
        root.bind("<Escape>", lambda _event: reject())
        root.bind("<Return>", lambda _event: approve())
        root.mainloop()
        return approved["value"]
    except Exception as e:
        audit("APPROVAL_HANDLER", f"tkinter dialog error: {e}", "WARNING")
        return False


def request_user_approval(alert: SecurityAlert) -> bool:
    """
    Uses registered handler to decide whether a blocked action can proceed.
    Defaults to reject when no handler is configured.
    """
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

    try:
        approved = bool(handler(alert))
    except Exception as e:
        audit(
            "SECURITY_ALERT",
            f"{alert.action} -> {alert.target} | Handler error: {e}",
            "REJECTED",
        )
        return False

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
