#!/bin/bash
# Check engine/app import boundary.
# Engine packages should not import app packages, except the middleware glue layer.
set -e

VIOLATIONS=$(grep -r '"github.com/soapbucket/proxy/internal/app/' \
  internal/engine/ internal/cache/ internal/security/ internal/extension/ \
  internal/platform/ internal/httpkit/ internal/loader/ internal/request/ \
  internal/transformer/ \
  --include="*.go" 2>/dev/null \
  | grep -v '_test.go' \
  | grep -v 'internal/engine/middleware/' \
  || true)

if [ -n "$VIOLATIONS" ]; then
  echo "FAIL: Engine packages import app packages (excluding middleware glue):"
  echo "$VIOLATIONS"
  exit 1
fi

echo "OK: Engine/app boundary clean"
