#!/bin/bash
# Build the geo-gate-proxy-wasm module via a one-shot Docker container so
# contributors do not need to install rustup / wasm32-unknown-unknown
# locally. Mirrors examples/wasm/echo-rust/build.sh.
#
# Note the target: wasm32-unknown-unknown, not wasm32-wasi — proxy-wasm
# modules use no WASI; all I/O goes through host-imported functions the
# proxy-wasm ABI defines.
#
# Output: ./target/wasm32-unknown-unknown/release/geo_gate_proxy_wasm.wasm
#
# Usage:
#     ./build.sh              # build via Docker (default)
#     LOCAL=1 ./build.sh      # build directly with the host toolchain

set -euo pipefail

cd "$(dirname "$0")"

if [ "${LOCAL:-0}" = "1" ]; then
  rustup target add wasm32-unknown-unknown
  cargo build --release --target wasm32-unknown-unknown
else
  docker run --rm \
    -v "$(pwd):/work" \
    -w /work \
    rust:1.82 \
    bash -c "rustup target add wasm32-unknown-unknown && cargo build --release --target wasm32-unknown-unknown"
fi

OUT="target/wasm32-unknown-unknown/release/geo_gate_proxy_wasm.wasm"
ls -la "$OUT"
echo "built: $OUT"
