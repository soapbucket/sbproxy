#!/usr/bin/env bash
# Verify docs/decision-records.md matches the executable decision contract in
# sbproxy-observe (WOR-2448). The page is a promise to SIEM consumers about
# which decision events publish and what fields their records carry, so a code
# change that wires an emitter, reclassifies an event, or renames a detail
# field must regenerate it.
#
# The failure this exists to prevent has already happened once in prose: the
# coverage statement in docs/observability.md claimed `waf` was unwired for
# months while every WAF denial was on the bus, because nothing compared the
# sentence to the code.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED="$ROOT_DIR/docs/decision-records.md"
ACTUAL="$(mktemp -t sbproxy-decision-contract.XXXXXX)"
trap 'rm -f "$ACTUAL"' EXIT

cd "$ROOT_DIR"
# shellcheck source=scripts/lib/workspace-bin.sh
. "$ROOT_DIR/scripts/lib/workspace-bin.sh"
run_workspace_bin generate-decision-contract \
  -p sbproxy-observe --bin generate-decision-contract > "$ACTUAL"

if [ ! -f "$EXPECTED" ]; then
  echo "decision record contract is missing: $EXPECTED" >&2
  echo "regenerate with: cargo run -q -p sbproxy-observe --bin generate-decision-contract > docs/decision-records.md" >&2
  exit 1
fi

if ! cmp -s "$EXPECTED" "$ACTUAL"; then
  echo "docs/decision-records.md is stale" >&2
  diff -u "$EXPECTED" "$ACTUAL" >&2 || true
  echo "regenerate with: cargo run -q -p sbproxy-observe --bin generate-decision-contract > docs/decision-records.md" >&2
  exit 1
fi

echo "docs/decision-records.md is up to date"
