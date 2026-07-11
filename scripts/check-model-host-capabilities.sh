#!/usr/bin/env bash
# Verify the checked-in model-host capability matrix matches the
# executable registry in sbproxy-model-host (WOR-1836).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED="$ROOT_DIR/docs/model-host-capabilities.md"
ACTUAL="$(mktemp -t sbproxy-model-host-capabilities.XXXXXX)"
trap 'rm -f "$ACTUAL"' EXIT

cd "$ROOT_DIR"
cargo run -q -p sbproxy-model-host --bin generate-model-host-capabilities > "$ACTUAL"

if [ ! -f "$EXPECTED" ]; then
  echo "model-host capability matrix is missing: $EXPECTED" >&2
  echo "regenerate with: cargo run -q -p sbproxy-model-host --bin generate-model-host-capabilities > docs/model-host-capabilities.md" >&2
  exit 1
fi

if ! cmp -s "$EXPECTED" "$ACTUAL"; then
  echo "docs/model-host-capabilities.md is stale" >&2
  diff -u "$EXPECTED" "$ACTUAL" >&2 || true
  echo "regenerate with: cargo run -q -p sbproxy-model-host --bin generate-model-host-capabilities > docs/model-host-capabilities.md" >&2
  exit 1
fi

echo "docs/model-host-capabilities.md is up to date"
