#!/bin/bash
# Run the in-tree conformance suite against the Rust sbproxy binary.
#
# Usage:
#   ./scripts/run-e2e.sh              # Run the maintained smoke set
#   ./scripts/run-e2e.sh --all        # Audit all 93 historical cases
#   ./scripts/run-e2e.sh 01 14 37     # Run specific cases
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
# The conformance suite is vendored and always runs from this workspace.
CONFORMANCE="$WORKSPACE/e2e/conformance"

if [ ! -d "$CONFORMANCE" ]; then
  echo "Conformance directory not found at $CONFORMANCE" >&2
  exit 1
fi

# Build Rust binary
echo "=== Building Rust sbproxy ==="
cd "$WORKSPACE"
cargo build --release -p sbproxy 2>&1 | tail -1

# Run tests
echo ""
echo "=== Running conformance tests ==="
cd "$CONFORMANCE"
exec env SBPROXY_BIN="$WORKSPACE/target/release/sbproxy" ./run-tests.sh "$@"
