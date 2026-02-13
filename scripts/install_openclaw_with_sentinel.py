#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence
from urllib.parse import urlparse


REPO_ROOT = Path(__file__).resolve().parents[1]
SENTINEL_HELPER = REPO_ROOT / "scripts" / "openclaw_configure_sentinel_sandbox.py"
POPUP_GUARD = REPO_ROOT / "scripts" / "openclaw_popup_guard.py"
POPUP_GUARD_LABEL = "com.sentinel.openclaw.popup-guard"
PREEXEC_PLUGIN_ID = "sentinel-preexec"
PREEXEC_PLUGIN_SRC = REPO_ROOT / "openclaw-plugins" / PREEXEC_PLUGIN_ID
INJECTION_GUARD_PLUGIN_ID = "sentinel-injection-guard"
INJECTION_GUARD_PLUGIN_SRC = REPO_ROOT / "openclaw-plugins" / INJECTION_GUARD_PLUGIN_ID
DEFAULT_INSTALL_URL = "https://openclaw.ai/install.sh"
INSTALL_CLI_URL = "https://openclaw.ai/install-cli.sh"
TRUSTED_INSTALL_HOSTS = {"openclaw.ai"}


def _run(
    cmd: list[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
    check: bool = True,
) -> int:
    rc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env).returncode
    if check and rc != 0:
        raise RuntimeError(f"Command failed ({rc}): {' '.join(cmd)}")
    return int(rc)


def _run_capture(cmd: list[str], *, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
    )


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Install OpenClaw (official flow) and optionally enable Sentinel security "
            "hardening as a wizard-adjacent step."
        )
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Do not prompt. Defaults to --enable-sentinel=yes when unset.",
    )
    parser.add_argument(
        "--enable-sentinel",
        choices=["yes", "no", "ask"],
        default="ask",
        help=(
            "Whether to enable Sentinel hardening after install/onboard. "
            "In --non-interactive mode, 'ask' is treated as 'yes'."
        ),
    )
    parser.add_argument(
        "--skip-openclaw-install",
        action="store_true",
        help="Skip OpenClaw install step even if openclaw is not found in PATH.",
    )
    parser.add_argument(
        "--openclaw-install-url",
        default=DEFAULT_INSTALL_URL,
        help=f"OpenClaw installer script URL (default: {DEFAULT_INSTALL_URL}).",
    )
    parser.add_argument(
        "--openclaw-install-sha256",
        default=os.environ.get("SENTINEL_OPENCLAW_INSTALL_SHA256", ""),
        help=(
            "Optional expected SHA-256 for the --openclaw-install-url script. "
            "When set, installer execution is blocked if digest mismatch occurs."
        ),
    )
    parser.add_argument(
        "--allow-untrusted-installer-url",
        action="store_true",
        default=str(os.environ.get("SENTINEL_ALLOW_UNTRUSTED_INSTALLER_URL", "")).strip().lower() in ("1", "true", "yes", "on"),
        help=(
            "Allow installer URLs outside trusted hosts. "
            "Use only in controlled environments."
        ),
    )
    parser.add_argument(
        "--sentinel-network",
        default="",
        help=(
            "Optional Docker network override passed as SENTINEL_OPENCLAW_DOCKER_NETWORK "
            "to the Sentinel helper."
        ),
    )
    return parser.parse_args(argv)


def _is_openclaw_installed() -> bool:
    if shutil.which("openclaw") is None:
        return False
    rc = subprocess.run(["openclaw", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    return rc == 0


def _validate_installer_url(install_url: str, *, allow_untrusted_urls: bool):
    parsed = urlparse(str(install_url).strip())
    if parsed.scheme.lower() != "https":
        raise RuntimeError(f"Installer URL must use HTTPS: {install_url}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise RuntimeError(f"Installer URL must include a valid hostname: {install_url}")
    if not allow_untrusted_urls and host not in TRUSTED_INSTALL_HOSTS:
        allowed = ", ".join(sorted(TRUSTED_INSTALL_HOSTS))
        raise RuntimeError(
            f"Installer URL host '{host}' is not trusted. Allowed hosts: {allowed}. "
            "Use --allow-untrusted-installer-url to override."
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _run_remote_installer(
    install_url: str,
    *,
    installer_args: Optional[list[str]] = None,
    expected_sha256: str = "",
    allow_untrusted_urls: bool = False,
):
    _validate_installer_url(install_url, allow_untrusted_urls=allow_untrusted_urls)
    with tempfile.NamedTemporaryFile(prefix="openclaw-install-", suffix=".sh", delete=False) as tmp:
        script_path = Path(tmp.name)
    try:
        _run(
            [
                "curl",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--retry",
                "3",
                "--retry-delay",
                "1",
                "--connect-timeout",
                "20",
                "-fsSL",
                install_url,
                "-o",
                str(script_path),
            ]
        )
        expected = str(expected_sha256 or "").strip().lower()
        if expected:
            actual = _sha256_file(script_path).lower()
            if actual != expected:
                raise RuntimeError(
                    "Installer SHA-256 mismatch. "
                    f"expected={expected} actual={actual}"
                )
        cmd = ["bash", str(script_path)]
        if installer_args:
            cmd.extend(["-s", "--"])
            cmd.extend(installer_args)
        _run(cmd)
    finally:
        try:
            script_path.unlink(missing_ok=True)
        except Exception:
            pass


def _install_openclaw_via_npm(*, run_onboard: bool):
    env = os.environ.copy()
    # Recommended by OpenClaw docs to avoid sharp/libvips build issues.
    env["SHARP_IGNORE_GLOBAL_LIBVIPS"] = "1"
    _run(["npm", "install", "-g", "openclaw@latest"], env=env)
    if run_onboard:
        _run(["openclaw", "onboard", "--install-daemon"])


def _install_openclaw(
    install_url: str,
    *,
    run_onboard: bool,
    installer_sha256: str = "",
    allow_untrusted_urls: bool = False,
):
    errors: list[str] = []
    attempts = [
        ("installer", install_url, [], str(installer_sha256 or "").strip()),
        ("installer-cli", INSTALL_CLI_URL, ["--onboard"] if run_onboard else ["--no-onboard"], ""),
    ]

    for label, url, extra_args, expected_sha256 in attempts:
        try:
            _run_remote_installer(
                url,
                installer_args=extra_args if label == "installer-cli" else None,
                expected_sha256=expected_sha256,
                allow_untrusted_urls=allow_untrusted_urls,
            )
            return
        except RuntimeError as exc:
            errors.append(f"{label} ({url}): {exc}")

    try:
        _install_openclaw_via_npm(run_onboard=run_onboard)
        return
    except RuntimeError as exc:
        errors.append(f"npm fallback: {exc}")

    message = "All OpenClaw installation methods failed:\n- " + "\n- ".join(errors)
    raise RuntimeError(message)


def _prompt_yes_no(question: str, *, default_yes: bool = True) -> bool:
    default_label = "Y/n" if default_yes else "y/N"
    while True:
        raw = input(f"{question} [{default_label}] ").strip().lower()
        if not raw:
            return default_yes
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("Please answer 'y' or 'n'.")


def _resolve_enable_choice(args: argparse.Namespace) -> bool:
    if args.enable_sentinel == "yes":
        return True
    if args.enable_sentinel == "no":
        return False
    if args.non_interactive:
        return True
    return _prompt_yes_no("Enable Sentinel security hardening now?", default_yes=True)


def _run_sentinel_helper(sentinel_network: str) -> int:
    env = os.environ.copy()
    if sentinel_network.strip():
        env["SENTINEL_OPENCLAW_DOCKER_NETWORK"] = sentinel_network.strip()
    return _run([sys.executable, str(SENTINEL_HELPER)], cwd=REPO_ROOT, env=env, check=False)


def build_default_exec_approvals() -> dict:
    # Force approval prompts for exec by default, with deny fallback.
    return {
        "version": 1,
        "socket": {},
        "defaults": {
            "security": "allowlist",
            "ask": "always",
            "askFallback": "deny",
            "autoAllowSkills": False,
        },
        "agents": {
            "main": {
                "security": "allowlist",
                "ask": "always",
                "askFallback": "deny",
                "autoAllowSkills": False,
                "allowlist": [],
            }
        },
    }


def _apply_secure_exec_approvals() -> int:
    payload = build_default_exec_approvals()
    with tempfile.NamedTemporaryFile(prefix="openclaw-approvals-", suffix=".json", mode="w", delete=False) as tmp:
        tmp.write(json.dumps(payload, separators=(",", ":")))
        tmp_path = tmp.name
    try:
        return _run(["openclaw", "approvals", "set", "--file", tmp_path], check=False)
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except Exception:
            pass


def _print_next_steps():
    print("\nNext steps:")
    print("  openclaw sandbox explain --json")
    print("  openclaw sandbox list")


def _resolve_openclaw_workspace_dir() -> Path:
    proc = _run_capture(["openclaw", "config", "get", "agents.defaults.workspace", "--json"])
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            value = json.loads(proc.stdout)
            if isinstance(value, str) and value.strip():
                return Path(value.strip()).expanduser()
        except Exception:
            pass
    return Path.home() / ".openclaw" / "workspace"


def _install_preexec_plugin() -> Path:
    if not PREEXEC_PLUGIN_SRC.exists():
        raise RuntimeError(f"Missing pre-exec plugin source: {PREEXEC_PLUGIN_SRC}")

    plugin_dst = Path.home() / ".openclaw" / "extensions" / PREEXEC_PLUGIN_ID
    plugin_dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(plugin_dst, ignore_errors=True)
    shutil.copytree(PREEXEC_PLUGIN_SRC, plugin_dst)

    _run(["openclaw", "config", "set", "--json", "plugins.enabled", "true"], check=False)
    _run(
        [
            "openclaw",
            "config",
            "set",
            "--json",
            f"plugins.entries.{PREEXEC_PLUGIN_ID}",
            '{"enabled":true}',
        ],
        check=False,
    )
    return plugin_dst


def _install_injection_guard_plugin() -> Path:
    if not INJECTION_GUARD_PLUGIN_SRC.exists():
        raise RuntimeError(f"Missing injection guard plugin source: {INJECTION_GUARD_PLUGIN_SRC}")

    plugin_dst = Path.home() / ".openclaw" / "extensions" / INJECTION_GUARD_PLUGIN_ID
    plugin_dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(plugin_dst, ignore_errors=True)
    shutil.copytree(INJECTION_GUARD_PLUGIN_SRC, plugin_dst)

    entry_payload = {
        "enabled": True,
        "config": {
            "enabled": True,
            "ollamaEndpoint": "http://localhost:11434/api/generate",
            "promptGuardModel": "prompt-guard",
            "llamaGuardModel": "llama-guard3",
            "failMode": "closed",
            "riskyTools": ["exec", "process", "write", "edit", "apply_patch"],
            "strictTools": [
                "read",
                "image",
                "sessions_list",
                "sessions_history",
                "sessions_send",
                "sessions_spawn",
                "session_status",
            ],
        },
    }

    _run(["openclaw", "config", "set", "--json", "plugins.enabled", "true"], check=False)
    _run(
        [
            "openclaw",
            "config",
            "set",
            "--json",
            f"plugins.entries.{INJECTION_GUARD_PLUGIN_ID}",
            json.dumps(entry_payload, separators=(",", ":")),
        ],
        check=False,
    )
    return plugin_dst


def _install_popup_guard_launch_agent():
    launch_agents = Path.home() / "Library" / "LaunchAgents"
    launch_agents.mkdir(parents=True, exist_ok=True)
    plist_path = launch_agents / f"{POPUP_GUARD_LABEL}.plist"
    openclaw_bin = shutil.which("openclaw") or "/opt/homebrew/bin/openclaw"
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{POPUP_GUARD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{sys.executable}</string>
    <string>{POPUP_GUARD}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>OPENCLAW_BIN</key><string>{openclaw_bin}</string>
  </dict>
  <key>StandardOutPath</key><string>{str((Path.home() / '.openclaw' / 'logs' / 'sentinel-popup-guard.log'))}</string>
  <key>StandardErrorPath</key><string>{str((Path.home() / '.openclaw' / 'logs' / 'sentinel-popup-guard.err.log'))}</string>
</dict>
</plist>
"""
    plist_path.write_text(plist, encoding="utf-8")
    _run(["launchctl", "unload", str(plist_path)], check=False)
    _run(["launchctl", "load", str(plist_path)], check=False)


def _install_popup_guard_systemd_user():
    openclaw_bin = shutil.which("openclaw") or "/usr/local/bin/openclaw"
    user_systemd = Path.home() / ".config" / "systemd" / "user"
    user_systemd.mkdir(parents=True, exist_ok=True)
    service_name = f"{POPUP_GUARD_LABEL}.service"
    service_path = user_systemd / service_name
    log_dir = Path.home() / ".openclaw" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    service = f"""[Unit]
Description=Sentinel OpenClaw Popup Guard
After=default.target

[Service]
Type=simple
Environment=OPENCLAW_BIN={openclaw_bin}
ExecStart={sys.executable} {POPUP_GUARD}
Restart=always
RestartSec=2
StandardOutput=append:{log_dir / 'sentinel-popup-guard.log'}
StandardError=append:{log_dir / 'sentinel-popup-guard.err.log'}

[Install]
WantedBy=default.target
"""
    service_path.write_text(service, encoding="utf-8")
    _run(["systemctl", "--user", "daemon-reload"], check=False)
    rc = _run(["systemctl", "--user", "enable", "--now", service_name], check=False)
    if rc != 0:
        raise RuntimeError("systemd --user service install failed for popup guard.")


def _install_popup_guard_background() -> str:
    system = platform.system().lower()
    if system == "darwin":
        _install_popup_guard_launch_agent()
        return "launch-agent"
    if system == "linux":
        _install_popup_guard_systemd_user()
        return "systemd-user"
    raise RuntimeError("Auto-install for popup guard is not supported on this OS.")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        if not _is_openclaw_installed():
            if args.skip_openclaw_install:
                print(
                    "OpenClaw is not installed and --skip-openclaw-install was provided.\n"
                    "Install OpenClaw first, then re-run this command.",
                    file=sys.stderr,
                )
                return 1
            print(f"OpenClaw not found. Installing from: {args.openclaw_install_url}")
            _install_openclaw(
                args.openclaw_install_url,
                run_onboard=not args.non_interactive,
                installer_sha256=args.openclaw_install_sha256,
                allow_untrusted_urls=args.allow_untrusted_installer_url,
            )
        else:
            print("OpenClaw detected in PATH. Skipping install.")

        enable_sentinel = _resolve_enable_choice(args)
        if enable_sentinel:
            print("Applying Sentinel security hardening...")
            helper_rc = _run_sentinel_helper(args.sentinel_network)
            if helper_rc != 0:
                return helper_rc
            print("Applying secure OpenClaw exec-approval defaults...")
            approvals_rc = _apply_secure_exec_approvals()
            if approvals_rc != 0:
                print(
                    "Failed to apply OpenClaw exec approvals baseline. "
                    "Run `openclaw approvals set --file <path>` manually.",
                    file=sys.stderr,
                )
                return approvals_rc
            plugin_path = _install_preexec_plugin()
            print(f"Installed Sentinel pre-exec interception plugin: {plugin_path}")
            injection_plugin_path = _install_injection_guard_plugin()
            print(f"Installed Sentinel injection guard plugin: {injection_plugin_path}")
            _run(["openclaw", "gateway", "restart"], check=False)
            try:
                mode = _install_popup_guard_background()
                print(f"Installed Sentinel popup guard ({mode}) as fallback.")
            except Exception as exc:
                print(f"Warning: could not install popup guard launch agent: {exc}", file=sys.stderr)
                print(
                    "Run popup guard manually:\n"
                    f"  {sys.executable} {POPUP_GUARD}",
                    file=sys.stderr,
                )
        else:
            print("Sentinel hardening skipped.")
            print("Enable later with:")
            print(f"  {sys.executable} {SENTINEL_HELPER}")

        _print_next_steps()
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        print(
            "OpenClaw install failed after trying installer and npm fallback methods. "
            "Check network/npm access and re-run.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
