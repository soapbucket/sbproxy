#!/bin/bash
# Build the uppercase WASM module via TinyGo.
#
# Output: ./uppercase.wasm
#
# Usage:
#     ./build.sh              # build via Docker (default)
#     LOCAL=1 ./build.sh      # build directly with the host TinyGo

set -euo pipefail

cd "$(dirname "$0")"

if [ "${LOCAL:-0}" = "1" ]; then
  tinygo build -o uppercase.wasm -target=wasi -no-debug main.go
else
  docker run --rm \
    -v "$(pwd):/work" \
    -w /work \
    tinygo/tinygo:0.34.0 \
    tinygo build -o uppercase.wasm -target=wasi -no-debug main.go
fi

ls -la uppercase.wasm
echo "built: uppercase.wasm"
