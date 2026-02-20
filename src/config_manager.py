import argparse
import io
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence


MANIFEST_NAME = "manifest.json"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _home_dir() -> Path:
    return Path.home()


def _backup_root() -> Path:
    return _home_dir() / ".sentinel-guard" / "backups"


def _approval_rules_path() -> Path:
    raw = ""
    try:
        import os

        raw = str(os.environ.get("SENTINEL_APPROVAL_RULES_PATH", "")).strip()
    except Exception:
        raw = ""
    if raw:
        return Path(raw).expanduser()
    return _home_dir() / ".sentinel-guard" / "approval-rules.json"


def _default_scope_entries() -> list[dict]:
    repo = _repo_root()
    home = _home_dir()
    approval_rules = _approval_rules_path()

    entries = [
        {"scope": "repo", "path": "sentinel.yaml"},
        {"scope": "repo", "path": "docker-compose.yml"},
        {"scope": "repo", "path": "proxy/allowed-domains.txt"},
        {"scope": "repo", "path": "seccomp/sentinel-seccomp.json"},
        {"scope": "repo", "path": "seccomp/sentinel-seccomp-datasci.json"},
        {"scope": "home", "path": str(approval_rules.relative_to(home)) if approval_rules.is_absolute() else str(approval_rules)},
    ]
    return entries


def _resolve_scope_path(scope: str, rel_path: str) -> Path:
    if scope == "repo":
        return (_repo_root() / rel_path).resolve()
    if scope == "home":
        return (_home_dir() / rel_path).expanduser().resolve()
    raise ValueError(f"Unsupported scope: {scope}")


def _safe_member_name(scope: str, rel_path: str) -> str:
    clean = str(Path(rel_path)).replace("\\", "/").lstrip("/")
    return f"{scope}/{clean}"


def _parse_member_name(name: str) -> tuple[str, str]:
    text = str(name).replace("\\", "/").lstrip("/")
    parts = text.split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid archive member: {name}")
    scope, rel_path = parts[0], parts[1]
    if scope not in ("repo", "home"):
        raise ValueError(f"Invalid scope in member: {name}")
    if ".." in Path(rel_path).parts:
        raise ValueError(f"Unsafe path in member: {name}")
    return scope, rel_path


def _create_backup_path(output: Optional[str]) -> Path:
    if output:
        out = Path(output).expanduser()
        if out.suffixes[-2:] != [".tar", ".gz"]:
            if out.suffix != ".gz":
                out = out.with_suffix(".tar.gz")
        return out
    root = _backup_root()
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return root / f"sentinel-config-{stamp}.tar.gz"


def backup_config(output: Optional[str] = None) -> Path:
    archive_path = _create_backup_path(output)
    archive_path.parent.mkdir(parents=True, exist_ok=True)

    entries = []
    manifest_files = []
    for item in _default_scope_entries():
        scope = item["scope"]
        rel_path = item["path"]
        try:
            resolved = _resolve_scope_path(scope, rel_path)
        except Exception:
            continue
        if resolved.exists() and resolved.is_file():
            member = _safe_member_name(scope, rel_path)
            entries.append((resolved, member))
            manifest_files.append({"scope": scope, "path": rel_path, "member": member})

    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "format": 1,
        "files": manifest_files,
    }

    with tarfile.open(archive_path, mode="w:gz") as tar:
        for resolved, member in entries:
            tar.add(str(resolved), arcname=member, recursive=False)

        raw_manifest = json.dumps(manifest, indent=2).encode("utf-8")
        info = tarfile.TarInfo(name=MANIFEST_NAME)
        info.size = len(raw_manifest)
        tar.addfile(info, fileobj=io.BytesIO(raw_manifest))

    return archive_path


def _load_manifest(tar: tarfile.TarFile) -> dict:
    member = tar.getmember(MANIFEST_NAME)
    with tar.extractfile(member) as fh:
        raw = fh.read().decode("utf-8")
    payload = json.loads(raw)
    return payload if isinstance(payload, dict) else {}


def restore_config(archive: str, force: bool = False) -> list[Path]:
    archive_path = Path(archive).expanduser().resolve()
    if not archive_path.exists():
        raise FileNotFoundError(f"Backup archive not found: {archive_path}")

    restored = []
    with tarfile.open(archive_path, mode="r:gz") as tar:
        manifest = _load_manifest(tar)
        files = manifest.get("files", []) if isinstance(manifest, dict) else []

        for item in files:
            scope = str(item.get("scope", "")).strip()
            rel_path = str(item.get("path", "")).strip()
            member_name = str(item.get("member", "")).strip() or _safe_member_name(scope, rel_path)
            parsed_scope, parsed_rel_path = _parse_member_name(member_name)
            if parsed_scope != scope:
                raise ValueError(f"Scope mismatch for member: {member_name}")
            if Path(parsed_rel_path) != Path(rel_path):
                raise ValueError(f"Path mismatch for member: {member_name}")

            target = _resolve_scope_path(scope, rel_path)
            if target.exists() and not force:
                raise FileExistsError(
                    f"Refusing to overwrite existing file without --force: {target}"
                )

            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = tar.extractfile(member_name)
            if extracted is None:
                continue
            data = extracted.read()
            target.write_bytes(data)
            restored.append(target)

    return restored


def list_backups() -> list[Path]:
    root = _backup_root()
    if not root.exists():
        return []
    return sorted(root.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Backup and restore Sentinel configuration.")
    sub = parser.add_subparsers(dest="command", required=True)

    backup_parser = sub.add_parser("backup", help="Create a configuration backup archive.")
    backup_parser.add_argument("--output", default="", help="Output archive path (default: ~/.sentinel-guard/backups).")

    restore_parser = sub.add_parser("restore", help="Restore configuration from a backup archive.")
    restore_parser.add_argument("archive", help="Path to the backup archive (.tar.gz).")
    restore_parser.add_argument("--force", action="store_true", help="Overwrite existing files.")

    sub.add_parser("list", help="List available backup archives.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    if args.command == "backup":
        archive = backup_config(output=args.output or None)
        print(f"Backup created: {archive}")
        return 0

    if args.command == "restore":
        restored = restore_config(args.archive, force=bool(args.force))
        print("Restore complete.")
        if restored:
            print("Restored files:")
            for path in restored:
                print(f"- {path}")
        else:
            print("No files were restored from this archive.")
        return 0

    if args.command == "list":
        backups = list_backups()
        if not backups:
            print("No backups found.")
            return 0
        print("Available backups:")
        for path in backups:
            print(f"- {path}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
