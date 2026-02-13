#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
SENTINEL_HELPER = REPO_ROOT / "scripts" / "openclaw_configure_sentinel_sandbox.py"
DEFAULT_INSTALL_URL = "https://openclaw.ai/install.sh"


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


def _install_openclaw(install_url: str):
    with tempfile.NamedTemporaryFile(prefix="openclaw-install-", suffix=".sh", delete=False) as tmp:
        script_path = Path(tmp.name)
    try:
        _run(["curl", "-fsSL", install_url, "-o", str(script_path)])
        _run(["bash", str(script_path)])
    finally:
        try:
            script_path.unlink(missing_ok=True)
        except Exception:
            pass


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


def _print_next_steps():
    print("\nNext steps:")
    print("  openclaw sandbox explain --json")
    print("  openclaw sandbox list")


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
            _install_openclaw(args.openclaw_install_url)
        else:
            print("OpenClaw detected in PATH. Skipping install.")

        enable_sentinel = _resolve_enable_choice(args)
        if enable_sentinel:
            print("Applying Sentinel security hardening...")
            helper_rc = _run_sentinel_helper(args.sentinel_network)
            if helper_rc != 0:
                return helper_rc
        else:
            print("Sentinel hardening skipped.")
            print("Enable later with:")
            print(f"  {sys.executable} {SENTINEL_HELPER}")

        _print_next_steps()
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        if args.openclaw_install_url in str(exc):
            print(
                "OpenClaw installer download/execution failed. "
                "Check network access and re-run.",
                file=sys.stderr,
            )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

