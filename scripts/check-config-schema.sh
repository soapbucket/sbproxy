#!/usr/bin/env bash
# WOR-1081: gate that the committed `schemas/sb-config.schema.json`
# is byte-for-byte what `cargo run -p sbproxy-config --bin
# generate-schema` produces. The generator reads the Rust types in
# `crates/sbproxy-config/src/types.rs`; a Rust type change that does
# not regenerate the schema (or vice versa) makes the editor-tooling
# layer drift, which is what the hand-rolled schema problem was. The
# gate fails with a diff so the operator sees exactly which fields
# need a refresh.
set -euo pipefail

cd "$(dirname "$0")/.."

GENERATED=$(mktemp)
trap 'rm -f "$GENERATED"' EXIT

cargo run --quiet -p sbproxy-config --bin generate-schema >"$GENERATED"

if diff -u schemas/sb-config.schema.json "$GENERATED" >/dev/null; then
    echo "schemas/sb-config.schema.json is up to date."
    exit 0
fi

echo "schemas/sb-config.schema.json is out of date. Regenerate with:"
echo
echo "    cargo run -p sbproxy-config --bin generate-schema > schemas/sb-config.schema.json"
echo
echo "Diff (committed vs generated):"
diff -u schemas/sb-config.schema.json "$GENERATED" || true
exit 1
