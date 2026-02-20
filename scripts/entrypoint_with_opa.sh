#!/bin/sh
set -eu

mkdir -p /workspace/workspace

if [ ! -f /workspace/sentinel.yaml ]; then
  cp /opt/sentinel/sentinel.yaml /workspace/sentinel.yaml
fi

_truthy() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

OPA_ENABLED="${SENTINEL_EMBED_OPA_ENABLED:-true}"
if _truthy "$OPA_ENABLED"; then
  OPA_BIN="${SENTINEL_OPA_BIN:-/usr/local/bin/opa}"
  OPA_POLICIES_DIR="${SENTINEL_OPA_POLICIES_DIR:-/opt/sentinel/policies/rego}"
  OPA_ADDR="${SENTINEL_OPA_ADDR:-127.0.0.1:8181}"

  if [ ! -x "$OPA_BIN" ]; then
    echo "[entrypoint_with_opa] OPA binary not found at $OPA_BIN" >&2
    exit 1
  fi
  if [ ! -d "$OPA_POLICIES_DIR" ]; then
    echo "[entrypoint_with_opa] OPA policies dir not found at $OPA_POLICIES_DIR" >&2
    exit 1
  fi

  export SENTINEL_OPA_ENABLED="${SENTINEL_OPA_ENABLED:-true}"
  export SENTINEL_OPA_URL="${SENTINEL_OPA_URL:-http://127.0.0.1:8181}"
  export SENTINEL_OPA_DECISION_PATH="${SENTINEL_OPA_DECISION_PATH:-/v1/data/sentinel/authz/decision}"

  "$OPA_BIN" run --server --addr="$OPA_ADDR" --set=decision_logs.console=true "$OPA_POLICIES_DIR" >/tmp/opa.log 2>&1 &
  OPA_PID=$!

  cleanup() {
    kill "$OPA_PID" 2>/dev/null || true
  }
  trap cleanup EXIT INT TERM

  python - <<'PY'
import time
import urllib.request

url = "http://127.0.0.1:8181/health?plugins"
last_err = None
for _ in range(30):
    try:
        with urllib.request.urlopen(url, timeout=0.5) as resp:
            if 200 <= int(resp.status) < 300:
                raise SystemExit(0)
    except Exception as exc:  # pragma: no cover - startup probe
        last_err = exc
    time.sleep(0.1)

print(f"[entrypoint_with_opa] OPA health check failed: {last_err}")
raise SystemExit(1)
PY
fi

cd /workspace
exec "$@"
