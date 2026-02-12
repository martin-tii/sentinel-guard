import argparse
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence


class IsolationError(RuntimeError):
    """Raised when isolated execution cannot be prepared or started."""


@dataclass(frozen=True)
class IsolationConfig:
    image: str = "sentinel-guard:local"
    workspace: str = "./sandbox-workspace"
    policy: str = "./sentinel.yaml"
    seccomp: str = "./seccomp/sentinel-seccomp.json"
    seccomp_profile: str = "strict"  # strict | datasci | custom
    seccomp_mode: str = "enforce"  # enforce | log | off
    network_mode: str = "none"
    pids_limit: int = 256
    memory: str = "512m"
    cpus: str = "1.0"
    proxy: str = ""
    no_proxy: str = ""
    enforce_proxy: bool = False
    build_if_missing: bool = False
    docker_binary: str = "docker"


def _is_truthy(value: str) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _enforce_production_network_policy(cfg: IsolationConfig):
    if not _is_truthy(os.environ.get("SENTINEL_PRODUCTION", "")):
        return
    if cfg.network_mode == "none":
        return
    if _is_truthy(os.environ.get("SENTINEL_ALLOW_NETWORK_IN_PRODUCTION", "")):
        return
    raise IsolationError(
        "Production mode requires --network none. "
        "Set SENTINEL_ALLOW_NETWORK_IN_PRODUCTION=true to allow a networked exception."
    )


def _enforce_proxy_policy(cfg: IsolationConfig):
    if cfg.network_mode == "none":
        return

    enforce_proxy = cfg.enforce_proxy or _is_truthy(os.environ.get("SENTINEL_ENFORCE_PROXY", ""))
    if not enforce_proxy:
        return

    if not str(cfg.proxy).strip():
        raise IsolationError(
            "Networked isolation with --enforce-proxy requires --proxy (or SENTINEL_PROXY)."
        )


def _default_seccomp_for_profile(profile: str) -> str:
    mapping = {
        "strict": "./seccomp/sentinel-seccomp.json",
        "datasci": "./seccomp/sentinel-seccomp-datasci.json",
    }
    return mapping.get(profile, "./seccomp/sentinel-seccomp.json")


def _effective_seccomp_path(cfg: IsolationConfig) -> str:
    profile = str(cfg.seccomp_profile).strip().lower()
    # Backward-compatible behavior: if user provided a non-default --seccomp path
    # without selecting a profile, prefer that explicit path.
    if profile == "strict" and cfg.seccomp != IsolationConfig.seccomp:
        return cfg.seccomp
    if profile in ("strict", "datasci"):
        return _default_seccomp_for_profile(profile)
    return cfg.seccomp


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_path(path: str) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (_repo_root() / candidate).resolve()


def _ensure_existing_dir(path: Path, label: str):
    if not path.exists():
        raise IsolationError(f"{label} does not exist: {path}")
    if not path.is_dir():
        raise IsolationError(f"{label} is not a directory: {path}")


def _ensure_existing_file(path: Path, label: str):
    if not path.exists():
        raise IsolationError(f"{label} does not exist: {path}")
    if not path.is_file():
        raise IsolationError(f"{label} is not a file: {path}")


def _ensure_docker_available(binary: str):
    if shutil.which(binary) is None:
        raise IsolationError(f"Docker binary not found in PATH: {binary}")


def _ensure_image_available(cfg: IsolationConfig):
    inspect_cmd = [cfg.docker_binary, "image", "inspect", cfg.image]
    check = subprocess.run(inspect_cmd, capture_output=True, text=True)
    if check.returncode == 0:
        return

    if not cfg.build_if_missing:
        raise IsolationError(
            f"Docker image '{cfg.image}' not found. Build it first or use --build-if-missing."
        )

    build_cmd = [cfg.docker_binary, "build", "-t", cfg.image, str(_repo_root())]
    build = subprocess.run(build_cmd)
    if build.returncode != 0:
        raise IsolationError(f"Failed to build image '{cfg.image}'.")


def _build_log_seccomp_profile(base_profile: Path) -> Path:
    try:
        raw = json.loads(base_profile.read_text(encoding="utf-8"))
    except Exception as exc:
        raise IsolationError(f"Failed to parse seccomp profile for log mode: {base_profile} ({exc})")

    if not isinstance(raw, dict):
        raise IsolationError("Seccomp profile must be a JSON object.")

    raw["defaultAction"] = "SCMP_ACT_LOG"
    tmp = tempfile.NamedTemporaryFile(prefix="sentinel-seccomp-log-", suffix=".json", delete=False)
    try:
        with open(tmp.name, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
    finally:
        tmp.close()
    return Path(tmp.name)


def build_docker_run_command(
    command: Sequence[str],
    cfg: Optional[IsolationConfig] = None,
    *,
    seccomp_profile_override: Optional[Path] = None,
) -> list[str]:
    if cfg is None:
        cfg = IsolationConfig()
    if not command:
        raise IsolationError("A command to execute inside the sandbox is required.")

    workspace = _resolve_path(cfg.workspace)
    policy = _resolve_path(cfg.policy)
    seccomp_profile = str(cfg.seccomp_profile).strip().lower()
    seccomp = _resolve_path(_effective_seccomp_path(cfg))

    _ensure_existing_dir(workspace, "Workspace")
    _ensure_existing_file(policy, "Policy file")

    if cfg.network_mode not in ("none", "bridge", "host"):
        raise IsolationError("network_mode must be one of: none, bridge, host")
    _enforce_production_network_policy(cfg)
    _enforce_proxy_policy(cfg)
    if cfg.seccomp_mode not in ("enforce", "log", "off"):
        raise IsolationError("seccomp_mode must be one of: enforce, log, off")
    if seccomp_profile not in ("strict", "datasci", "custom"):
        raise IsolationError("seccomp_profile must be one of: strict, datasci, custom")

    run_cmd = [
        cfg.docker_binary,
        "run",
        "--rm",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        str(cfg.pids_limit),
        "--memory",
        cfg.memory,
        "--cpus",
        cfg.cpus,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--tmpfs",
        "/run:rw,noexec,nosuid,size=16m",
        "--network",
        cfg.network_mode,
        "--volume",
        f"{workspace}:/workspace:rw",
        "--volume",
        f"{policy}:/workspace/sentinel.yaml:ro",
        "--workdir",
        "/workspace",
    ]

    effective_proxy = str(cfg.proxy).strip() or str(os.environ.get("SENTINEL_PROXY", "")).strip()
    if effective_proxy:
        run_cmd.extend(["--env", f"HTTP_PROXY={effective_proxy}"])
        run_cmd.extend(["--env", f"HTTPS_PROXY={effective_proxy}"])
        run_cmd.extend(["--env", f"http_proxy={effective_proxy}"])
        run_cmd.extend(["--env", f"https_proxy={effective_proxy}"])
        no_proxy = str(cfg.no_proxy).strip() or os.environ.get("NO_PROXY") or os.environ.get("no_proxy", "")
        if no_proxy:
            run_cmd.extend(["--env", f"NO_PROXY={no_proxy}"])
            run_cmd.extend(["--env", f"no_proxy={no_proxy}"])

    if cfg.seccomp_mode == "off":
        run_cmd.extend(["--security-opt", "seccomp=unconfined"])
    else:
        effective_seccomp = seccomp_profile_override or seccomp
        _ensure_existing_file(effective_seccomp, "Seccomp profile")
        run_cmd.extend(["--security-opt", f"seccomp={effective_seccomp}"])

    run_cmd.append(cfg.image)
    run_cmd.extend(command)
    return run_cmd


def run_isolated(
    command: Sequence[str],
    cfg: Optional[IsolationConfig] = None,
    *,
    check: bool = True,
):
    if cfg is None:
        cfg = IsolationConfig()

    _ensure_docker_available(cfg.docker_binary)
    _ensure_image_available(cfg)
    seccomp_override = None
    seccomp_path_input = _effective_seccomp_path(cfg)

    if cfg.seccomp_mode == "log":
        seccomp_path = _resolve_path(seccomp_path_input)
        _ensure_existing_file(seccomp_path, "Seccomp profile")
        seccomp_override = _build_log_seccomp_profile(seccomp_path)

    run_cmd = build_docker_run_command(command, cfg, seccomp_profile_override=seccomp_override)

    try:
        result = subprocess.run(run_cmd)
        if check and result.returncode != 0:
            raise IsolationError(
                f"Isolated command failed with return code {result.returncode}."
            )
        return result
    finally:
        if seccomp_override is not None:
            try:
                seccomp_override.unlink(missing_ok=True)
            except Exception:
                pass


def _parse_args(argv: Optional[Sequence[str]] = None):
    parser = argparse.ArgumentParser(
        description="Run a command inside Sentinel's isolated Docker sandbox."
    )
    parser.add_argument(
        "--workspace",
        default="./sandbox-workspace",
        help="Host workspace directory to mount as /workspace.",
    )
    parser.add_argument(
        "--policy",
        default="./sentinel.yaml",
        help="Policy file to mount as /workspace/sentinel.yaml.",
    )
    parser.add_argument(
        "--seccomp",
        default="./seccomp/sentinel-seccomp.json",
        help="Seccomp profile file path (used when --seccomp-profile custom).",
    )
    parser.add_argument(
        "--seccomp-profile",
        default=os.environ.get("SENTINEL_SECCOMP_PROFILE", "strict"),
        choices=["strict", "datasci", "custom"],
        help="Seccomp profile preset: strict, datasci, or custom path via --seccomp.",
    )
    parser.add_argument(
        "--seccomp-mode",
        default=os.environ.get("SENTINEL_SECCOMP_MODE", "enforce"),
        choices=["enforce", "log", "off"],
        help="Seccomp mode: enforce (strict), log (complain/audit), or off.",
    )
    parser.add_argument(
        "--image",
        default="sentinel-guard:local",
        help="Docker image to run.",
    )
    parser.add_argument(
        "--network",
        default="none",
        choices=["none", "bridge", "host"],
        help="Container network mode. Use 'none' for strongest isolation.",
    )
    parser.add_argument(
        "--proxy",
        default=os.environ.get("SENTINEL_PROXY", ""),
        help="Optional outbound proxy URL passed as HTTP(S)_PROXY inside the container.",
    )
    parser.add_argument(
        "--no-proxy",
        default=os.environ.get("SENTINEL_NO_PROXY", ""),
        help="Optional NO_PROXY value to pass into container when --proxy is used.",
    )
    parser.add_argument(
        "--enforce-proxy",
        action="store_true",
        help="When network is enabled, require proxy configuration and fail otherwise.",
    )
    parser.add_argument(
        "--build-if-missing",
        action="store_true",
        help="Build the image if it does not exist locally.",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to execute inside container. Prefix with -- to separate options.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise IsolationError("No command provided. Example: sentinel-isolate -- python app.py")

    cfg = IsolationConfig(
        image=args.image,
        workspace=args.workspace,
        policy=args.policy,
        seccomp=args.seccomp,
        seccomp_profile=args.seccomp_profile,
        seccomp_mode=args.seccomp_mode,
        network_mode=args.network,
        proxy=args.proxy,
        no_proxy=args.no_proxy,
        enforce_proxy=args.enforce_proxy,
        build_if_missing=args.build_if_missing,
    )
    result = run_isolated(command, cfg, check=False)
    return int(result.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
