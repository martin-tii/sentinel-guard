#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict


REPO_ROOT = Path(__file__).resolve().parents[1]


def build_openclaw_sandbox_config(*, network_name: str, seccomp_profile_path: str) -> Dict[str, Any]:
    """
    OpenClaw config payload for `agents.defaults.sandbox`.

    Verified against OpenClaw 2026.2.9:
    - `agents.defaults.sandbox` controls mode/scope/workspaceAccess.
    - `agents.defaults.sandbox.docker` controls Docker runtime hardening.
    """
    return {
        "mode": "non-main",
        "scope": "agent",
        "workspaceAccess": "rw",
        "docker": build_openclaw_docker_config(
            network_name=network_name,
            seccomp_profile_path=seccomp_profile_path,
        ),
    }


def build_openclaw_docker_config(*, network_name: str, seccomp_profile_path: str) -> Dict[str, Any]:
    return {
        "readOnlyRoot": True,
        "capDrop": ["ALL"],
        "tmpfs": ["/tmp", "/var/tmp", "/run"],
        "pidsLimit": 256,
        "memory": "512m",
        # OpenClaw expects a JSON number here (not a string).
        "cpus": 1.0,
        "network": network_name,
        "env": {
            "HTTP_PROXY": "http://sentinel-proxy:3128",
            "HTTPS_PROXY": "http://sentinel-proxy:3128",
            "NO_PROXY": "localhost,127.0.0.1,sentinel-proxy",
        },
        "seccompProfile": seccomp_profile_path,
    }


def _run(cmd: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}\n"
        )
    return proc


def _openclaw_version() -> str:
    proc = _run(["openclaw", "--version"], check=False)
    version = (proc.stdout or proc.stderr or "").strip()
    return version or "<unknown>"


def _openclaw_config_is_valid() -> bool:
    proc = _run(["openclaw", "doctor", "--non-interactive"], check=False)
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if "Config invalid" in combined:
        return False
    if "Unknown config keys" in combined:
        return False
    # Some invalid configs exit non-zero even if the banner is missing.
    if proc.returncode != 0 and "Invalid config" in combined:
        return False
    return proc.returncode == 0


def _ensure_sentinel_proxy_running():
    # Use the existing proxied profile. This creates the internal network:
    # sentinel-sandbox_sentinel-internal
    _run(
        ["docker", "compose", "--profile", "proxied", "up", "-d", "sentinel-proxy"],
        cwd=REPO_ROOT,
    )


def _install_seccomp_profile() -> Path:
    src = REPO_ROOT / "seccomp" / "sentinel-seccomp-datasci.json"
    if not src.exists():
        raise RuntimeError(f"Missing seccomp profile: {src}")

    dst_dir = Path.home() / ".openclaw" / "seccomp"
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / "sentinel-seccomp-datasci.json"
    shutil.copyfile(src, dst)
    return dst


def _apply_openclaw_config(*, sandbox_cfg: Dict[str, Any]):
    # OpenClaw config set expects JSON5/JSON when --json is provided.
    payload = json.dumps(sandbox_cfg, separators=(",", ":"))
    _run(["openclaw", "config", "set", "--json", "agents.defaults.sandbox", payload])


def _recreate_sandboxes():
    _run(["openclaw", "sandbox", "recreate", "--all"])


def main() -> int:
    print(f"[openclaw] version: {_openclaw_version()}")

    if not _openclaw_config_is_valid():
        print(
            "OpenClaw config is invalid.\n"
            "Run `openclaw doctor --fix` first (it will remove unknown keys like channels.telegram.token),\n"
            "then re-run this script.",
            file=sys.stderr,
        )
        return 2

    _ensure_sentinel_proxy_running()
    seccomp_path = _install_seccomp_profile()

    network_name = os.environ.get("SENTINEL_OPENCLAW_DOCKER_NETWORK", "sentinel-sandbox_sentinel-internal")
    sandbox_cfg = build_openclaw_sandbox_config(
        network_name=network_name,
        seccomp_profile_path=str(seccomp_path),
    )
    _apply_openclaw_config(sandbox_cfg=sandbox_cfg)
    _recreate_sandboxes()

    print("\nNext steps:")
    print("  openclaw sandbox explain --json")
    print("  openclaw sandbox list")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

