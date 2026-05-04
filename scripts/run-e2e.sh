#!/bin/bash
# Run the Go e2e test suite against the Rust sbproxy binary.
#
# Usage:
#   ./scripts/run-e2e.sh              # Run all 71 cases
#   ./scripts/run-e2e.sh 01 14 37     # Run specific cases
set -eo pipefail

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

# Build Rust binary
echo "=== Building Rust sbproxy ==="
cd "$WORKSPACE"
cargo build --release -p sbproxy 2>&1 | tail -1

# Symlink binary where Go runner expects it (cp breaks macOS code signing)
rm -f "$GO_E2E/sbproxy"
ln -s "$WORKSPACE/target/release/sbproxy" "$GO_E2E/sbproxy"
echo "Binary symlinked at $GO_E2E/sbproxy"

# Create a patched runner that skips the Go build step
PATCHED="$GO_E2E/run-tests-rust.sh"
cp "$GO_E2E/run-tests.sh" "$PATCHED"
sed -i '' 's|^if go build -o "$SBPROXY_BIN" \./cmd/sbproxy/; then|if true; then|' "$PATCHED"
sed -i '' 's|^cd "$SBPROXY_SRC"|# skip cd to Go source|' "$PATCHED"
chmod +x "$PATCHED"

# Run tests
echo ""
echo "=== Running e2e tests ==="
cd "$GO_E2E"
exec ./run-tests-rust.sh "$@"
