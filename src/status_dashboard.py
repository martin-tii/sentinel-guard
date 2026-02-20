import argparse
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

import yaml


@dataclass(frozen=True)
class StatusItem:
    label: str
    value: str
    state: str  # ok | warn | error


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _home_dir() -> Path:
    return Path.home()


def _approval_rules_path() -> Path:
    raw = str(os.environ.get("SENTINEL_APPROVAL_RULES_PATH", "")).strip()
    if raw:
        return Path(raw).expanduser()
    return _home_dir() / ".sentinel-guard" / "approval-rules.json"


def _backups_dir() -> Path:
    return _home_dir() / ".sentinel-guard" / "backups"


def _policy_path() -> Path:
    env_config = str(os.environ.get("SENTINEL_CONFIG", "")).strip()
    if env_config:
        candidate = Path(env_config).expanduser()
        if not candidate.is_absolute():
            candidate = (_repo_root() / candidate).resolve()
        return candidate
    return (_repo_root() / "sentinel.yaml").resolve()


def _load_policy(path: Path) -> dict:
    try:
        if not path.exists():
            return {}
        raw = path.read_text(encoding="utf-8")
        loaded = yaml.safe_load(raw)
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


def _docker_binary_status() -> StatusItem:
    docker = shutil.which("docker")
    if docker:
        return StatusItem("Docker binary", docker, "ok")
    return StatusItem("Docker binary", "Not found in PATH", "error")


def _docker_daemon_status() -> StatusItem:
    if shutil.which("docker") is None:
        return StatusItem("Docker Engine", "Not checked (docker missing)", "warn")
    result = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if result.returncode == 0:
        return StatusItem("Docker Engine", "Running", "ok")
    detail = (result.stderr or result.stdout or "Not running").strip().splitlines()[0]
    return StatusItem("Docker Engine", detail, "warn")


def _policy_status(path: Path, policy: dict) -> StatusItem:
    if not path.exists():
        return StatusItem("Policy file", f"Missing: {path}", "error")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    if not policy:
        return StatusItem("Policy file", f"Unreadable or empty: {path} (sha={digest})", "warn")
    return StatusItem("Policy file", f"Loaded: {path} (sha={digest})", "ok")


def _approval_status() -> StatusItem:
    mode = str(os.environ.get("SENTINEL_APPROVAL_MODE", "auto")).strip().lower() or "auto"
    rules_path = _approval_rules_path()
    if not rules_path.exists():
        return StatusItem("Approval mode", f"{mode} (saved rules: 0)", "ok")
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
        rules = payload.get("always_allow") if isinstance(payload, dict) else []
        count = len(rules) if isinstance(rules, list) else 0
        return StatusItem("Approval mode", f"{mode} (saved rules: {count})", "ok")
    except Exception:
        return StatusItem("Approval mode", f"{mode} (rules unreadable: {rules_path})", "warn")


def _guard_status(policy: dict) -> list[StatusItem]:
    judge = policy.get("judge", {}) if isinstance(policy, dict) else {}
    prompt_guard = judge.get("prompt_guard", {}) if isinstance(judge, dict) else {}
    injection_scan = judge.get("injection_scan", {}) if isinstance(judge, dict) else {}

    pg_enabled = bool(prompt_guard.get("enabled", True))
    pg_state = "ok" if pg_enabled else "warn"
    pg_value = "Enabled" if pg_enabled else "Disabled"

    scan_enabled = bool(injection_scan.get("enabled", True))
    detection_mode = str(injection_scan.get("on_detection", "approval")) if isinstance(injection_scan, dict) else "approval"
    scan_state = "ok" if scan_enabled else "warn"
    scan_value = f"{'Enabled' if scan_enabled else 'Disabled'} (on detection: {detection_mode})"

    return [
        StatusItem("Prompt Guard", pg_value, pg_state),
        StatusItem("Injection scan", scan_value, scan_state),
    ]


def _workspace_status(policy: dict) -> StatusItem:
    env_workspace = str(os.environ.get("SENTINEL_WORKSPACE_ROOT", "")).strip()
    if env_workspace:
        first = Path(env_workspace).expanduser()
    else:
        first = (_repo_root() / "workspace").resolve()
    if first.exists():
        return StatusItem("Workspace path", str(first), "ok")
    return StatusItem("Workspace path", f"Missing: {first}", "warn")


def _backup_status() -> StatusItem:
    root = _backups_dir()
    if not root.exists():
        return StatusItem("Config backups", f"0 backups (folder: {root})", "warn")
    backups = sorted(root.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not backups:
        return StatusItem("Config backups", f"0 backups (folder: {root})", "warn")
    latest = backups[0]
    return StatusItem("Config backups", f"{len(backups)} backups (latest: {latest.name})", "ok")


def _openclaw_status() -> StatusItem:
    exe = shutil.which("openclaw")
    runtime = (_home_dir() / ".openclaw" / "sentinel-runtime")
    if exe and runtime.exists():
        return StatusItem("OpenClaw integration", "Installed and Sentinel runtime present", "ok")
    if exe:
        return StatusItem("OpenClaw integration", "OpenClaw detected, Sentinel runtime missing", "warn")
    return StatusItem("OpenClaw integration", "OpenClaw not detected", "warn")


def _state_tag(state: str) -> str:
    normalized = str(state or "warn").lower()
    if normalized == "ok":
        return "[OK]"
    if normalized == "error":
        return "[ERR]"
    return "[WARN]"


def _render_dashboard(items: list[StatusItem]) -> str:
    lines = []
    lines.append("Sentinel Status Dashboard")
    lines.append("=" * 26)
    for item in items:
        lines.append(f"{_state_tag(item.state):6} {item.label:22} {item.value}")
    lines.append("")
    lines.append("Recommended next actions:")
    lines.append("- Run 'sentinel-setup' if any [ERR]/[WARN] item is unexpected.")
    lines.append("- Run 'sentinel-config backup' before policy changes.")
    return "\n".join(lines)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Show a one-screen Sentinel health dashboard.")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Print raw status JSON.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    policy_path = _policy_path()
    policy = _load_policy(policy_path)

    items = [
        _docker_binary_status(),
        _docker_daemon_status(),
        _policy_status(policy_path, policy),
        _workspace_status(policy),
        _approval_status(),
        *_guard_status(policy),
        _backup_status(),
        _openclaw_status(),
    ]

    if args.as_json:
        payload = [item.__dict__ for item in items]
        print(json.dumps(payload, indent=2))
    else:
        print(_render_dashboard(items))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
