#!/bin/sh
set -eu

mkdir -p /workspace/workspace

if [ ! -f /workspace/sentinel.yaml ]; then
  cp /opt/sentinel/sentinel.yaml /workspace/sentinel.yaml
fi

cd /workspace
exec "$@"
