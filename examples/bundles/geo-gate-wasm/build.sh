#!/bin/bash
# Build the geo-gate WASM module via a one-shot Docker container so
# contributors do not need to install rustup / wasm32-wasip1 locally.
# Mirrors examples/wasm/echo-rust/build.sh.
#
# Output: ./target/wasm32-wasip1/release/geo_gate.wasm
#
# Usage:
#     ./build.sh              # build via Docker (default)
#     LOCAL=1 ./build.sh      # build directly with the host toolchain

set -euo pipefail

cd "$(dirname "$0")"

if [ "${LOCAL:-0}" = "1" ]; then
  rustup target add wasm32-wasip1
  cargo build --release --target wasm32-wasip1
else
  docker run --rm \
    -v "$(pwd):/work" \
    -w /work \
    rust:1.82 \
    bash -c "rustup target add wasm32-wasip1 && cargo build --release --target wasm32-wasip1"
fi

OUT="target/wasm32-wasip1/release/geo_gate.wasm"
ls -la "$OUT"
echo "built: $OUT"
