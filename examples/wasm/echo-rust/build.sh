#!/bin/bash
# Build the echo WASM module via a one-shot Docker container so contributors
# do not need to install rustup / wasm32-wasi locally.
#
# Output: ./target/wasm32-wasi/release/echo.wasm
#
# Usage:
#     ./build.sh              # build via Docker (default)
#     LOCAL=1 ./build.sh      # build directly with the host toolchain

set -euo pipefail

cd "$(dirname "$0")"

if [ "${LOCAL:-0}" = "1" ]; then
  rustup target add wasm32-wasi
  cargo build --release --target wasm32-wasi
else
  docker run --rm \
    -v "$(pwd):/work" \
    -w /work \
    rust:1.82 \
    bash -c "rustup target add wasm32-wasi && cargo build --release --target wasm32-wasi"
fi

OUT="target/wasm32-wasi/release/echo.wasm"
ls -la "$OUT"
echo "built: $OUT"
