#!/bin/bash
# Full-catalog entry point for the in-tree conformance runner.
#
# With no arguments this audits all 93 historical cases. Case numbers may be
# supplied for a selective diagnostic run, matching scripts/run-e2e.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ $# -eq 0 ]]; then
  exec "$SCRIPT_DIR/run-e2e.sh" --all
fi
exec "$SCRIPT_DIR/run-e2e.sh" "$@"
