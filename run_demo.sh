#!/bin/bash
set -euo pipefail

# A simple wrapper to launch the secure sandbox

echo "[Sentinel] Starting sandbox..."
echo "  - Mode: Standard (Network Allowed)"
echo "  - RootFS: Read-Only"
echo "  - User: sentinel (Non-Root)"

if ! command -v docker >/dev/null 2>&1; then
  echo "[Sentinel] Error: docker is not installed or not in PATH." >&2
  exit 1
fi

# Ensure workspace exists so bind mount path is owned by current user.
mkdir -p ./sandbox-workspace

# Build image if needed, then run demo.
docker compose build
exec docker compose --profile standard run --rm sentinel-standard
