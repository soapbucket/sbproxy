#!/bin/bash
# Build the Rust sbproxy binary and symlink it where the Go e2e runner expects it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
# Default to the in-tree vendored copy of the Go e2e suite. Override with
# GO_E2E_DIR=... to run against an external clone (e.g. soapbucket/sbproxy-go).
GO_E2E="${GO_E2E_DIR:-$WORKSPACE/e2e/conformance}"

if [ ! -d "$GO_E2E" ]; then
  echo "Go e2e directory not found at $GO_E2E" >&2
  echo "Set GO_E2E_DIR=/path/to/e2e or use the in-tree default at e2e/conformance/." >&2
  exit 1
fi

echo "Building sbproxy (release)..."
cd "$WORKSPACE"
cargo build --release -p sbproxy

echo "Symlinking binary to Go e2e/sbproxy..."
rm -f "$GO_E2E/sbproxy"
ln -s "$WORKSPACE/target/release/sbproxy" "$GO_E2E/sbproxy"

echo "Done. Binary at: $GO_E2E/sbproxy -> $WORKSPACE/target/release/sbproxy"
echo "Run: cd $GO_E2E && ./run-tests.sh"
