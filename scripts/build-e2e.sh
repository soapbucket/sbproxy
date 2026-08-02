#!/bin/bash
# Build the Rust sbproxy binary for the in-tree conformance suite.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
# The conformance suite is vendored and always runs from this workspace.
CONFORMANCE="$WORKSPACE/e2e/conformance"

if [ ! -d "$CONFORMANCE" ]; then
  echo "Conformance directory not found at $CONFORMANCE" >&2
  exit 1
fi

echo "Building sbproxy (release)..."
cd "$WORKSPACE"
cargo build --release -p sbproxy

echo "Done. Binary at: $WORKSPACE/target/release/sbproxy"
echo "Run smoke set: cd $CONFORMANCE && ./run-tests.sh"
echo "Audit full catalog: cd $CONFORMANCE && ./run-tests.sh --all"
