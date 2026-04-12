#!/usr/bin/env bash
# update-embedded-data.sh
#
# Downloads and updates the embedded data files for the sbproxy binary.
# Compresses each file with gzip -9, computes SHA256 hashes, and writes
# internal/embedded/version.json.
#
# Usage:
#   ./scripts/update-embedded-data.sh              # Update all files
#   ./scripts/update-embedded-data.sh --hash-only  # Recompute hashes only (no downloads)
#
# Requirements: bash, curl, gzip, sha256sum (or shasum on macOS), python3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="$REPO_ROOT/internal/embedded/data"
VERSION_JSON="$REPO_ROOT/internal/embedded/version.json"
HASH_ONLY="${1:-}"

# Portable SHA256 command
if command -v sha256sum &>/dev/null; then
    sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum &>/dev/null; then
    sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    echo "ERROR: sha256sum or shasum is required but not found." >&2
    exit 1
fi

# Portable file size
filesize() {
    if [[ "$(uname)" == "Darwin" ]]; then
        stat -f%z "$1"
    else
        stat -c%s "$1"
    fi
}

compress_and_hash() {
    local name="$1"
    local src="$2"

    if [[ ! -f "$src" ]]; then
        echo "  SKIP: source file not found: $src"
        return 1
    fi

    local gz_out="$DATA_DIR/${name}.gz"
    local raw_size
    raw_size=$(filesize "$src")

    gzip -9 -c "$src" > "$gz_out"
    local gz_size
    gz_size=$(filesize "$gz_out")

    local hash
    hash=$(sha256 "$src")

    echo "  compressed: $gz_out (${raw_size} -> ${gz_size} bytes, sha256=${hash})"

    RESULT_HASH="$hash"
    RESULT_SIZE="$raw_size"
    RESULT_GZ_SIZE="$gz_size"
}

TODAY=$(date -u +%Y-%m-%d)
GENERATED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "==> Updating embedded data files"
echo "    Data dir: $DATA_DIR"
echo ""

declare -A FILE_HASH FILE_SIZE FILE_GZ_SIZE

# --------------------------------------------------------------------------
# regexes.yml - from ua-parser/uap-core (Apache 2.0)
# https://github.com/ua-parser/uap-core
# --------------------------------------------------------------------------
echo "[1/2] regexes.yml (ua-parser/uap-core)"
if [[ "$HASH_ONLY" != "--hash-only" ]]; then
    REGEXES_URL="https://raw.githubusercontent.com/ua-parser/uap-core/master/regexes.yaml"
    TMP_REGEXES=$(mktemp /tmp/regexes.XXXXXX.yml)
    echo "  Downloading from $REGEXES_URL ..."
    curl -fsSL "$REGEXES_URL" -o "$TMP_REGEXES"
    SRC="$TMP_REGEXES"
else
    TMP_REGEXES=$(mktemp /tmp/regexes.XXXXXX.yml)
    gzip -d -c "$DATA_DIR/regexes.yml.gz" > "$TMP_REGEXES" 2>/dev/null || true
    SRC="$TMP_REGEXES"
fi
if compress_and_hash "regexes.yml" "$SRC"; then
    FILE_HASH["regexes.yml"]="$RESULT_HASH"
    FILE_SIZE["regexes.yml"]="$RESULT_SIZE"
    FILE_GZ_SIZE["regexes.yml"]="$RESULT_GZ_SIZE"
fi
rm -f "$TMP_REGEXES"

# --------------------------------------------------------------------------
# ai_providers.yml - internal sbproxy provider registry
# --------------------------------------------------------------------------
echo ""
echo "[2/2] ai_providers.yml (internal)"
INTERNAL_SRC="$REPO_ROOT/data/ai_providers.yml"
if [[ "$HASH_ONLY" == "--hash-only" ]]; then
    TMP_PROV=$(mktemp /tmp/ai_providers.XXXXXX.yml)
    gzip -d -c "$DATA_DIR/ai_providers.yml.gz" > "$TMP_PROV" 2>/dev/null || true
    INTERNAL_SRC="$TMP_PROV"
    CLEANUP_PROV=1
else
    CLEANUP_PROV=0
fi
if compress_and_hash "ai_providers.yml" "$INTERNAL_SRC"; then
    FILE_HASH["ai_providers.yml"]="$RESULT_HASH"
    FILE_SIZE["ai_providers.yml"]="$RESULT_SIZE"
    FILE_GZ_SIZE["ai_providers.yml"]="$RESULT_GZ_SIZE"
fi
[[ "$CLEANUP_PROV" == "1" ]] && rm -f "$INTERNAL_SRC"

# --------------------------------------------------------------------------
# Write version.json
# --------------------------------------------------------------------------
echo ""
echo "==> Writing $VERSION_JSON"

python3 - <<PYEOF
import json

version = {
    "generated_at": "$GENERATED_AT",
    "files": {}
}

files = {
$(for name in "ai_providers.yml" "regexes.yml"; do
    if [[ -n "${FILE_HASH[$name]+x}" ]]; then
        echo "    \"$name\": (\"${FILE_HASH[$name]}\", ${FILE_SIZE[$name]}, ${FILE_GZ_SIZE[$name]}),"
    fi
done)
}

for name, (h, s, gs) in files.items():
    version["files"][name] = {
        "sha256": h,
        "size": int(s),
        "compressed_size": int(gs),
        "updated_at": "$TODAY"
    }

with open("$VERSION_JSON", "w") as f:
    json.dump(version, f, indent=2)
    f.write("\n")

print("  Written:", "$VERSION_JSON")
PYEOF

echo ""
echo "Done. Review $VERSION_JSON and commit the updated data files."
