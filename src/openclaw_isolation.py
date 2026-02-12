import argparse
import os
from pathlib import Path
from typing import Optional, Sequence

from .isolation import IsolationConfig, IsolationError, run_isolated


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_path(path: str) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (_repo_root() / candidate).resolve()


def _parse_args(argv: Optional[Sequence[str]] = None):
    parser = argparse.ArgumentParser(
        description="Run OpenClaw CLI commands inside Sentinel isolation."
    )
    parser.add_argument(
        "--workspace",
        default=os.environ.get("SENTINEL_OPENCLAW_WORKSPACE", "./sandbox-workspace/openclaw-home"),
        help="Host directory mounted as /workspace (also used as HOME by default).",
    )
    parser.add_argument(
        "--policy",
        default=os.environ.get("SENTINEL_CONFIG", "./sentinel.yaml"),
        help="Policy file path mounted as /workspace/sentinel.yaml.",
    )
    parser.add_argument(
        "--seccomp",
        default="./seccomp/sentinel-seccomp.json",
        help="Seccomp profile path (used when --seccomp-profile custom).",
    )
    parser.add_argument(
        "--seccomp-profile",
        default=os.environ.get("SENTINEL_OPENCLAW_SECCOMP_PROFILE", "datasci"),
        choices=["strict", "datasci", "custom"],
        help="Seccomp preset for OpenClaw workloads.",
    )
    parser.add_argument(
        "--seccomp-mode",
        default=os.environ.get("SENTINEL_OPENCLAW_SECCOMP_MODE", "enforce"),
        choices=["enforce", "log", "off"],
        help="Seccomp mode: enforce, log, or off.",
    )
    parser.add_argument(
        "--image",
        default=os.environ.get("SENTINEL_OPENCLAW_IMAGE", "openclaw:local"),
        help="Docker image containing OpenClaw CLI.",
    )
    parser.add_argument(
        "--network",
        default=os.environ.get("SENTINEL_OPENCLAW_NETWORK", "bridge"),
        choices=["none", "bridge", "host"],
        help="Container network mode.",
    )
    parser.add_argument(
        "--proxy",
        default=os.environ.get("SENTINEL_PROXY", ""),
        help="Optional outbound proxy URL passed as HTTP(S)_PROXY in container.",
    )
    parser.add_argument(
        "--no-proxy",
        default=os.environ.get("SENTINEL_NO_PROXY", ""),
        help="Optional NO_PROXY value passed into container.",
    )
    parser.add_argument(
        "--enforce-proxy",
        action="store_true",
        help="Require proxy configuration when network mode is not none.",
    )
    parser.add_argument(
        "--docker-binary",
        default="docker",
        help="Docker executable name/path.",
    )
    parser.add_argument(
        "--openclaw-bin",
        default=os.environ.get("SENTINEL_OPENCLAW_BIN", "openclaw"),
        help="OpenClaw executable inside the container.",
    )
    parser.add_argument(
        "--no-home-redirect",
        action="store_true",
        help="Do not force HOME=/workspace in the container.",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="OpenClaw CLI arguments. Prefix with -- to separate launcher options.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    openclaw_args = list(args.command)
    if openclaw_args and openclaw_args[0] == "--":
        openclaw_args = openclaw_args[1:]
    if not openclaw_args:
        raise IsolationError(
            "No OpenClaw command provided. Example: sentinel-openclaw -- gateway --port 18789"
        )

    workspace = _resolve_path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    command = []
    if args.no_home_redirect:
        command.append(args.openclaw_bin)
    else:
        # Persist OpenClaw state under /workspace by redirecting HOME.
        command.extend(["env", "HOME=/workspace", args.openclaw_bin])
    command.extend(openclaw_args)

    cfg = IsolationConfig(
        image=args.image,
        workspace=str(workspace),
        policy=args.policy,
        seccomp=args.seccomp,
        seccomp_profile=args.seccomp_profile,
        seccomp_mode=args.seccomp_mode,
        network_mode=args.network,
        proxy=args.proxy,
        no_proxy=args.no_proxy,
        enforce_proxy=args.enforce_proxy,
        build_if_missing=False,
        docker_binary=args.docker_binary,
    )

    try:
        result = run_isolated(command, cfg, check=False)
    except IsolationError as exc:
        message = str(exc)
        if "not found" in message and args.image in message:
            raise IsolationError(
                f"Docker image '{args.image}' not found. Build your OpenClaw image first "
                f"(for example from the OpenClaw repo: "
                f"`docker build -t {args.image} -f Dockerfile .`)."
            ) from exc
        raise

    return int(result.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
