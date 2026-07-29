#!/usr/bin/env bash
# WOR-528: Spec citation hygiene check.
#
# Greps the docs trees for known-bad spec citations. Exits non-zero on
# the first hit so docs CI fails the PR until the citation is corrected.
#
# Closed list of bad strings (audit 2026-05-15):
#
#   "April 2026 MCP"      -> the actual spec revision is MCP 2025-11-25.
#   "2026-04 MCP"         -> same.
#   "Coinbase x402"       -> x402 moved to a Linux Foundation project on
#                            2026-04-02; cite "x402 (Linux Foundation)".
#                            Note: "Coinbase-hosted reference facilitator"
#                            is still accurate and is preserved by the
#                            exemption below.
#
# CIMD source filenames + identifiers in `.rs` files are intentionally
# out of scope (the rename is covered by WOR-518). The check therefore
# only walks the docs/ trees, not the source tree.
#
# Usage:
#   bash scripts/check-spec-citations.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ $# -ne 0 ]; then
  echo "usage: bash scripts/check-spec-citations.sh" >&2
  exit 2
fi

# Patterns to ban. Each entry is `regex|explanation`. The regex is fed
# to `grep -E` so escape accordingly.
declare -a BAD_PATTERNS=(
  'April 2026 MCP|use "MCP 2025-11-25" (or cite SEPs at modelcontextprotocol.io/specification/draft/)'
  '2026-04 MCP|use "MCP 2025-11-25"'
  'MCP 2026-04|use "MCP 2025-11-25"'
)

# Coinbase x402 is checked separately so we can exempt the legitimate
# "Coinbase-hosted reference facilitator" phrase.
COINBASE_X402_HINT='use "x402 (Linux Foundation)" (x402 moved to LF on 2026-04-02; "Coinbase-hosted reference facilitator" is the one acceptable phrasing)'

fail=0

check_tree() {
  local root="$1"
  local label="$2"
  local docs="$root/docs"
  if [ ! -d "$docs" ]; then
    echo "skip: $label has no docs/ directory at $docs"
    return 0
  fi
  for entry in "${BAD_PATTERNS[@]}"; do
    local pat="${entry%%|*}"
    local hint="${entry#*|}"
    local hits
    hits=$(grep -RInE "$pat" "$docs" 2>/dev/null || true)
    if [ -n "$hits" ]; then
      echo "error: $label docs contain banned citation '$pat'"
      echo "       $hint"
      echo "$hits" | sed 's/^/  /'
      fail=1
    fi
  done
  # Coinbase x402: hit when "Coinbase x402" appears outside of the
  # "Coinbase-hosted" phrase.
  local cx_hits
  cx_hits=$(grep -RIn 'Coinbase x402' "$docs" 2>/dev/null | grep -v 'Coinbase-hosted' || true)
  if [ -n "$cx_hits" ]; then
    echo "error: $label docs contain 'Coinbase x402' outside the reference-facilitator exemption"
    echo "       $COINBASE_X402_HINT"
    echo "$cx_hits" | sed 's/^/  /'
    fail=1
  fi
}

check_tree "$RUST_ROOT" "sbproxy"

if [ "$fail" -eq 0 ]; then
  echo "ok: no banned spec citations found"
fi
exit $fail
