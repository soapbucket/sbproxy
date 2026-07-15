#!/usr/bin/env bash
# Verify docs/metrics-stability.md matches the executable metric registry in
# sbproxy-observe (WOR-1897 / WOR-1912). The catalogue is generated, so a code
# change that adds or reclassifies a metric must regenerate it.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED="$ROOT_DIR/docs/metrics-stability.md"
ACTUAL="$(mktemp -t sbproxy-metrics-stability.XXXXXX)"
trap 'rm -f "$ACTUAL"' EXIT

cd "$ROOT_DIR"
cargo run -q -p sbproxy-observe --bin generate-metrics-stability > "$ACTUAL"

if [ ! -f "$EXPECTED" ]; then
  echo "metrics stability catalogue is missing: $EXPECTED" >&2
  echo "regenerate with: cargo run -q -p sbproxy-observe --bin generate-metrics-stability > docs/metrics-stability.md" >&2
  exit 1
fi

if ! cmp -s "$EXPECTED" "$ACTUAL"; then
  echo "docs/metrics-stability.md is stale" >&2
  diff -u "$EXPECTED" "$ACTUAL" >&2 || true
  echo "regenerate with: cargo run -q -p sbproxy-observe --bin generate-metrics-stability > docs/metrics-stability.md" >&2
  exit 1
fi

echo "docs/metrics-stability.md is up to date"
