#!/bin/bash

# Combine all origin fixture JSON files into a single origins.json file
# This script merges all JSON files in the fixtures/origins directory

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="${PROXY_ROOT}/test/fixtures/origins/origins.json"

echo "🔗 Combining origin fixture files..."
echo "   Output: $OUTPUT_FILE"
echo ""

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed."
    echo "Install with: brew install jq (macOS) or apt-get install jq (Linux)"
    exit 1
fi

# Start with empty JSON object
echo "{}" > "$OUTPUT_FILE"

# Merge all JSON files in order (both 2-digit and 3-digit numbers)
FIXTURES_DIR="${PROXY_ROOT}/test/fixtures/origins"
for json_file in $(ls "${FIXTURES_DIR}"/[0-9]*-*.json 2>/dev/null | grep -E '/[0-9]+-.*\.json$' | sort -V); do
    if [ -f "$json_file" ]; then
        echo "   Merging: $(basename "$json_file")"
        # Merge the JSON objects
        jq -s '.[0] * .[1]' "$OUTPUT_FILE" "$json_file" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
    fi
done

# Count origins
ORIGIN_COUNT=$(jq 'length' "$OUTPUT_FILE")

echo ""
echo "✅ Combined $ORIGIN_COUNT origins into $OUTPUT_FILE"
echo ""
echo "📋 Origin hostnames:"
jq -r 'keys[]' "$OUTPUT_FILE" | sort | sed 's/^/   - /'

