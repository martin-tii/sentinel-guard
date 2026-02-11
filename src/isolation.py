import argparse
import os
import shutil
import subprocess
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
    network_mode: str = "none"
    pids_limit: int = 256
    memory: str = "512m"
    cpus: str = "1.0"
    build_if_missing: bool = False
    docker_binary: str = "docker"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
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


def build_docker_run_command(command: Sequence[str], cfg: Optional[IsolationConfig] = None) -> list[str]:
    if cfg is None:
        cfg = IsolationConfig()
    if not command:
        raise IsolationError("A command to execute inside the sandbox is required.")

    workspace = _resolve_path(cfg.workspace)
    policy = _resolve_path(cfg.policy)
    seccomp = _resolve_path(cfg.seccomp)

    _ensure_existing_dir(workspace, "Workspace")
    _ensure_existing_file(policy, "Policy file")
    _ensure_existing_file(seccomp, "Seccomp profile")

    if cfg.network_mode not in ("none", "bridge", "host"):
        raise IsolationError("network_mode must be one of: none, bridge, host")

    run_cmd = [
        cfg.docker_binary,
        "run",
        "--rm",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--security-opt",
        f"seccomp={seccomp}",
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
        cfg.image,
    ]
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
    run_cmd = build_docker_run_command(command, cfg)

    result = subprocess.run(run_cmd)
    if check and result.returncode != 0:
        raise IsolationError(
            f"Isolated command failed with return code {result.returncode}."
        )
    return result


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
        help="Seccomp profile file.",
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
        network_mode=args.network,
        build_if_missing=args.build_if_missing,
    )
    result = run_isolated(command, cfg, check=False)
    return int(result.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
