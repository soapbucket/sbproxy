#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

if ! command -v wat2wasm >/dev/null 2>&1; then
  echo "wat2wasm is required to rebuild the worked-example WASM files" >&2
  exit 1
fi

wat2wasm \
  "$script_dir/bundles/queued-envelope-wasm/action.wat" \
  -o "$script_dir/bundles/queued-envelope-wasm/action.wasm"
wat2wasm \
  "$script_dir/bundles/ai-stream-proxy-wasm/filter.wat" \
  -o "$script_dir/bundles/ai-stream-proxy-wasm/filter.wasm"

echo "rebuilt envelope WASM and Proxy-Wasm artifacts"
echo "recalculate each sha256 value from the final .wasm bytes"
