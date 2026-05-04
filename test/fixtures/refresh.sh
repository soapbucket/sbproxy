#!/usr/bin/env bash
# Fixture refresh tooling (Q2.13).
#
# Regenerates the signed agent-registry feed (G2.1), the KYA token
# placeholder (Wave 5), and the Web Bot Auth directory JWS samples
# (A1.3) used by the e2e test pack. Outputs are deterministic
# byte-for-byte: running this script twice produces a clean
# `git diff --exit-code`.
#
# When to run:
#
# - A test seed in `test/fixtures/.../keys.json` rotates.
# - The wire format pinned by an ADR changes.
# - CI's fixture-freshness job (`.github/workflows/fixture-freshness.yml`)
#   reports a diff after a refresh-tool source edit.
#
# Usage:
#
#     bash test/fixtures/refresh.sh
#
# CI usage (the freshness check):
#
#     bash test/fixtures/refresh.sh
#     git diff --exit-code test/fixtures/ e2e/fixtures/
#
# Implementation lives in `test/fixtures/refresh-tool/` so the
# crypto-heavy dependency tree stays out of the proxy's `Cargo.lock`.

set -euo pipefail

# Resolve the workspace root from this script's location so the
# tool runs the same way whether invoked from CI, an IDE, or a
# developer's shell.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOL_MANIFEST="$SCRIPT_DIR/refresh-tool/Cargo.toml"

if [[ ! -f "$TOOL_MANIFEST" ]]; then
    echo "error: fixture-refresh tool manifest missing at $TOOL_MANIFEST" >&2
    exit 1
fi

cd "$WORKSPACE_ROOT"

# Build + run. Release profile so the tool's run time is bounded
# regardless of how often a developer invokes it; the build cost
# itself is bounded by the standalone Cargo.lock that lives next
# to the tool's manifest.
exec cargo run --release --manifest-path "$TOOL_MANIFEST" --quiet -- "$@"
