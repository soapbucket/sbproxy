#!/usr/bin/env bash
# WOR-1081 / WOR-1686: gate that the committed JSON schemas are
# byte-for-byte what their generators produce. Each generator reads Rust
# types; a type change that does not regenerate the schema (or vice
# versa) makes the editor-tooling layer drift, which is what the
# hand-rolled schema problem was. The gate fails with a diff so the
# operator sees exactly which fields need a refresh.
#
#   schemas/sb-config.schema.json      <- sbproxy-config ConfigFile (WOR-1081)
#   schemas/ai-proxy-provider.schema.json <- sbproxy-ai ProviderConfig,
#       incl. the serve: block (WOR-1686). Kept separate from the top
#       level because origins[].action is a deliberately opaque
#       polymorphic node (see the generator's module docs).
#   schemas/ai-compression.schema.json <- sbproxy-ai CompressionPolicy
set -euo pipefail

cd "$(dirname "$0")/.."

# schema file : "cargo run" args that regenerate it
schemas=(
    "schemas/sb-config.schema.json|-p sbproxy-config --bin generate-schema"
    "schemas/ai-proxy-provider.schema.json|-p sbproxy-ai --bin generate-ai-provider-schema"
    "schemas/ai-compression.schema.json|-p sbproxy-ai --bin generate-ai-compression-schema"
)

GENERATED=$(mktemp)
trap 'rm -f "$GENERATED"' EXIT

status=0
for entry in "${schemas[@]}"; do
    file="${entry%%|*}"
    args="${entry#*|}"
    # shellcheck disable=SC2086
    cargo run --quiet $args >"$GENERATED"
    if diff -u "$file" "$GENERATED" >/dev/null; then
        echo "$file is up to date."
    else
        status=1
        echo "$file is out of date. Regenerate with:"
        echo
        echo "    cargo run $args > $file"
        echo
        echo "Diff (committed vs generated):"
        diff -u "$file" "$GENERATED" || true
    fi
done

exit "$status"
