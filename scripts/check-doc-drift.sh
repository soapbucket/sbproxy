#!/usr/bin/env bash
#
# scripts/check-doc-drift.sh
#
# Guard against regression of provider-count and routing-strategy claims
# in user-facing docs. Code reality:
#
#   - crates/sbproxy-ai/data/ai_providers.yml has 43 entries.
#   - crates/sbproxy-ai/src/routing.rs defines 10 routing strategies
#     (RoundRobin, Weighted, FallbackChain, Random, LowestLatency,
#     LeastConnections, CostOptimized, TokenRate, Sticky, Race).
#   - crates/sbproxy-modules/src/action/routing/ ships two built-in
#     RoutingStrategy implementations: first-healthy and lora-aware.
#
# The strings below previously appeared in docs and went stale. If any
# reappears, this check fails so the offending PR can fix the count
# before merge.
#
# Usage:
#   scripts/check-doc-drift.sh            # scan default targets, exit 1 on hit
#   scripts/check-doc-drift.sh --root .   # explicit repo root
#
# Exit codes:
#   0  no stale strings found
#   1  one or more stale strings found
#   2  invalid CLI usage

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,30p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Targets we actively police. Adding a new doc surface that should be
# guarded is a one-line addition here.
TARGETS=(
  "$ROOT_DIR/docs"
  "$ROOT_DIR/llms.txt"
  "$ROOT_DIR/README.md"
)

# Substrings that must never reappear. Each entry is a fixed (-F) string
# so YAML / table escapes do not matter.
STALE_STRINGS=(
  "20 native"
  "9 routing strategies"
  "one trivial built-in strategy"
  "36 OpenAI-compatible"
)

rc=0
for needle in "${STALE_STRINGS[@]}"; do
  for target in "${TARGETS[@]}"; do
    [ -e "$target" ] || continue
    if hits=$(grep -RFn --binary-files=without-match \
                 --include='*.md' --include='*.txt' \
                 -e "$needle" "$target" 2>/dev/null); then
      echo "stale string found: '$needle'" >&2
      echo "$hits" | sed 's/^/  /' >&2
      rc=1
    fi
  done
done

if [ "$rc" -eq 0 ]; then
  echo "doc-drift: ok"
fi

exit "$rc"
