#!/usr/bin/env bash
# Download LiteLLM model pricing JSON for cost-optimized routing.
# Source: https://github.com/BerriAI/litellm
#
# Usage:
#   ./scripts/download_pricing.sh                    # default: data/model_pricing.json
#   ./scripts/download_pricing.sh /path/to/output.json

set -euo pipefail

URL="https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
OUTPUT="${1:-data/model_pricing.json}"

echo "Downloading LiteLLM pricing data..."
curl -fsSL "$URL" -o "$OUTPUT.tmp"

# Validate JSON
if ! python3 -c "import json; json.load(open('$OUTPUT.tmp'))" 2>/dev/null; then
    echo "ERROR: Downloaded file is not valid JSON" >&2
    rm -f "$OUTPUT.tmp"
    exit 1
fi

# Count models
MODEL_COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT.tmp'))))")

mv "$OUTPUT.tmp" "$OUTPUT"
echo "Saved $MODEL_COUNT models to $OUTPUT"
