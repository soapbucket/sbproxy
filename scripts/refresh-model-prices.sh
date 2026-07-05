#!/usr/bin/env bash
# Refresh a model price rate card for the AI gateway (WOR-1707).
#
# Downloads the LiteLLM model_prices_and_context_window.json, the
# ecosystem's canonical rate card (2,900+ models, 123 providers, MIT),
# to a local file. Point an ai_proxy `rate_card:` config entry at that
# file; sbproxy loads it at config load and never fetches at runtime, so
# an egress-restricted host is unaffected. Re-run this out of band to
# refresh prices.
#
# Usage:
#   scripts/refresh-model-prices.sh [OUTPUT_PATH]
# Defaults to ./model_prices.json. Set RATE_CARD_URL to use models.dev
# or a mirror instead.
set -euo pipefail

OUT="${1:-model_prices.json}"
URL="${RATE_CARD_URL:-https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json}"

echo "fetching $URL"
if ! curl -fSL --max-time 60 "$URL" -o "$OUT.tmp"; then
  echo "download failed (egress blocked?); leaving any existing $OUT untouched" >&2
  rm -f "$OUT.tmp"
  exit 1
fi

# Sanity-check it parses as a JSON object before replacing the vendored copy.
if ! python3 -c "import json,sys; d=json.load(open('$OUT.tmp')); sys.exit(0 if isinstance(d, dict) and len(d) > 1 else 1)"; then
  echo "downloaded file is not a valid rate card; not replacing $OUT" >&2
  rm -f "$OUT.tmp"
  exit 1
fi

mv "$OUT.tmp" "$OUT"
COUNT=$(python3 -c "import json; print(len(json.load(open('$OUT'))))")
echo "wrote $OUT ($COUNT entries). Reference it from an ai_proxy provider:"
echo "  rate_card: $OUT"
