#!/usr/bin/env bash
set -euo pipefail

MODE="strict"
PROFILE="strict"
SERVICE="sentinel-strict"

if [[ "${1:-}" == "--standard" ]]; then
  MODE="standard"
  PROFILE="standard"
  SERVICE="sentinel-standard"
fi

log() {
  echo "[Sentinel] $*"
}

fail() {
  echo "[Sentinel] Error: $*" >&2
  exit 1
}

log "Starting sandbox..."
if [[ "$MODE" == "strict" ]]; then
  log "Mode: Strict (network disabled)"
else
  log "Mode: Standard (network enabled)"
fi
log "RootFS: Read-Only"
log "User: sentinel (non-root)"

if ! command -v docker >/dev/null 2>&1; then
  fail "Docker is not installed. Install Docker Desktop, open it, then run this script again."
fi

if ! docker compose version >/dev/null 2>&1; then
  fail "Docker Compose v2 is not available. Update Docker Desktop and retry."
fi

if ! docker info >/dev/null 2>&1; then
  fail "Docker daemon is not running. Start Docker Desktop and wait until it says 'Engine running'."
fi

# Ensure workspace exists so bind mount path is owned by current user.
mkdir -p ./sandbox-workspace

log "Building container image (first run may take a few minutes)..."
docker compose build

log "Launching sandbox. Press Ctrl+C to stop."
exec docker compose --profile "$PROFILE" run --rm "$SERVICE"
