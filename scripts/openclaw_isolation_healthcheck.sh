#!/usr/bin/env bash

set -u

PASS_COUNT=0
FAIL_COUNT=0

pass() {
  printf '[PASS] %s\n' "$1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
  printf '[FAIL] %s\n' "$1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

require_cmd() {
  if command -v "$1" >/dev/null 2>&1; then
    pass "Required command available: $1"
  else
    fail "Missing required command: $1"
  fi
}

json_read() {
  python3 -c 'import json,sys; print(json.load(sys.stdin))'
}

json_read_key() {
  local key="$1"
  python3 - "$key" <<'PY'
import json
import sys

key = sys.argv[1]
obj = json.load(sys.stdin)
if isinstance(obj, dict):
    print(obj.get(key, ""))
else:
    print("")
PY
}

print_header() {
  printf '\n== %s ==\n' "$1"
}

require_cmd "openclaw"
require_cmd "docker"
require_cmd "python3"

if [ "$FAIL_COUNT" -gt 0 ]; then
  printf '\nHealthcheck aborted: missing prerequisites.\n'
  exit 2
fi

print_header "OpenClaw Config"

OPENCLAW_VERSION="$(openclaw --version 2>/dev/null | head -n 1 || true)"
if [ -n "$OPENCLAW_VERSION" ]; then
  pass "OpenClaw version detected: $OPENCLAW_VERSION"
else
  fail "Could not read OpenClaw version."
fi

NETWORK_JSON="$(openclaw config get agents.defaults.sandbox.docker.network --json 2>/dev/null || true)"
if [ -z "$NETWORK_JSON" ]; then
  fail "Could not read agents.defaults.sandbox.docker.network from OpenClaw config."
  EXPECTED_NETWORK=""
else
  EXPECTED_NETWORK="$(printf '%s' "$NETWORK_JSON" | json_read 2>/dev/null | tr -d '\n')"
  if [ -n "$EXPECTED_NETWORK" ]; then
    pass "Configured OpenClaw sandbox network: $EXPECTED_NETWORK"
  else
    fail "OpenClaw sandbox network config is empty."
  fi
fi

TOOLS_JSON="$(openclaw config get tools.sandbox.tools.allow --json 2>/dev/null || true)"
if [ -n "$TOOLS_JSON" ]; then
  if printf '%s' "$TOOLS_JSON" | grep -Eq '"exec"|"process"|"write"|"edit"|"apply_patch"'; then
    fail "Risky tools are present in tools.sandbox.tools.allow."
  else
    pass "Strict tools allowlist active (no exec/process/write/edit/apply_patch)."
  fi
else
  fail "Could not read tools.sandbox.tools.allow."
fi

print_header "Docker Topology"

if [ -n "$EXPECTED_NETWORK" ]; then
  if docker network inspect "$EXPECTED_NETWORK" >/dev/null 2>&1; then
    pass "Docker network exists: $EXPECTED_NETWORK"
    INTERNAL_FLAG="$(docker network inspect "$EXPECTED_NETWORK" --format '{{.Internal}}' 2>/dev/null || true)"
    if [ "$INTERNAL_FLAG" = "true" ]; then
      pass "Network is Internal=true (no direct external gateway)."
    else
      fail "Network is not internal (Internal=$INTERNAL_FLAG)."
    fi
  else
    fail "Configured Docker network does not exist: $EXPECTED_NETWORK"
  fi
fi

SANDBOX_CONTAINER="${SENTINEL_HEALTHCHECK_SANDBOX_CONTAINER:-}"
if [ -z "$SANDBOX_CONTAINER" ]; then
  SANDBOX_CONTAINER="$(docker ps --format '{{.Names}}' | grep '^openclaw-sbx-' | head -n 1 || true)"
fi

if [ -z "$SANDBOX_CONTAINER" ]; then
  fail "Could not find running OpenClaw sandbox container (name starts with openclaw-sbx-)."
else
  pass "Using sandbox container: $SANDBOX_CONTAINER"
fi

PROXY_CONTAINER="${SENTINEL_HEALTHCHECK_PROXY_CONTAINER:-}"
if [ -z "$PROXY_CONTAINER" ]; then
  PROXY_CONTAINER="$(docker ps --format '{{.Names}}' | grep 'sentinel-proxy' | head -n 1 || true)"
fi

if [ -z "$PROXY_CONTAINER" ]; then
  fail "Could not find running Sentinel proxy container (name contains sentinel-proxy)."
else
  pass "Using proxy container: $PROXY_CONTAINER"
fi

if [ -n "$EXPECTED_NETWORK" ] && [ -n "$SANDBOX_CONTAINER" ]; then
  SANDBOX_NETS="$(docker inspect "$SANDBOX_CONTAINER" --format '{{json .NetworkSettings.Networks}}' 2>/dev/null || true)"
  if printf '%s' "$SANDBOX_NETS" | grep -q "\"$EXPECTED_NETWORK\""; then
    pass "Sandbox container attached to expected network."
  else
    fail "Sandbox container not attached to expected network."
  fi
fi

if [ -n "$EXPECTED_NETWORK" ] && [ -n "$PROXY_CONTAINER" ]; then
  PROXY_NETS="$(docker inspect "$PROXY_CONTAINER" --format '{{json .NetworkSettings.Networks}}' 2>/dev/null || true)"
  if printf '%s' "$PROXY_NETS" | grep -q "\"$EXPECTED_NETWORK\""; then
    pass "Proxy container attached to expected network."
  else
    fail "Proxy container not attached to expected network."
  fi
fi

print_header "Live Egress Checks"

PROXY_HOST="${SENTINEL_HEALTHCHECK_PROXY_HOST:-sentinel-proxy}"
PROXY_PORT="${SENTINEL_HEALTHCHECK_PROXY_PORT:-3128}"
DIRECT_TEST_HOST="${SENTINEL_HEALTHCHECK_DIRECT_TEST_HOST:-1.1.1.1}"
DIRECT_TEST_PORT="${SENTINEL_HEALTHCHECK_DIRECT_TEST_PORT:-53}"

if [ -n "$SANDBOX_CONTAINER" ]; then
  DIRECT_RESULT="$(
    docker exec "$SANDBOX_CONTAINER" bash -lc "
      if command -v timeout >/dev/null 2>&1; then
        timeout 3 bash -c 'cat < /dev/null > /dev/tcp/$DIRECT_TEST_HOST/$DIRECT_TEST_PORT' >/dev/null 2>&1
      else
        bash -c 'cat < /dev/null > /dev/tcp/$DIRECT_TEST_HOST/$DIRECT_TEST_PORT' >/dev/null 2>&1
      fi
      rc=\$?
      if [ \$rc -eq 0 ]; then echo DIRECT_OK; else echo DIRECT_FAIL; fi
    " 2>/dev/null || true
  )"
  if [ "$DIRECT_RESULT" = "DIRECT_FAIL" ]; then
    pass "Direct egress from sandbox appears blocked ($DIRECT_TEST_HOST:$DIRECT_TEST_PORT)."
  else
    fail "Direct egress from sandbox appears allowed ($DIRECT_TEST_HOST:$DIRECT_TEST_PORT)."
  fi

  PROXY_RESULT="$(
    docker exec "$SANDBOX_CONTAINER" bash -lc "
      if command -v timeout >/dev/null 2>&1; then
        timeout 3 bash -c 'cat < /dev/null > /dev/tcp/$PROXY_HOST/$PROXY_PORT' >/dev/null 2>&1
      else
        bash -c 'cat < /dev/null > /dev/tcp/$PROXY_HOST/$PROXY_PORT' >/dev/null 2>&1
      fi
      rc=\$?
      if [ \$rc -eq 0 ]; then echo PROXY_OK; else echo PROXY_FAIL; fi
    " 2>/dev/null || true
  )"
  if [ "$PROXY_RESULT" = "PROXY_OK" ]; then
    pass "Sandbox can reach proxy endpoint ($PROXY_HOST:$PROXY_PORT)."
  else
    fail "Sandbox cannot reach proxy endpoint ($PROXY_HOST:$PROXY_PORT)."
  fi
fi

print_header "Summary"
printf 'Pass: %s\n' "$PASS_COUNT"
printf 'Fail: %s\n' "$FAIL_COUNT"

if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
exit 0
