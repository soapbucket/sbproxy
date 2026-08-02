#!/usr/bin/env bash
# One settled payment serves the article exactly once.
#
# Runs the five steps of the settlement gate against the local stack and
# prints the status code and the origin's own hit counter after each one.
# The counter is the load-bearing observable: the proxy can claim
# whatever it likes about a payment, but only the origin knows how many
# times it actually served the content.
#
# Usage (with fixture.py and a payments-featured sbproxy already up):
#   bash examples/settlement-gate-local/bin/settle-once.sh

set -euo pipefail

PROXY="${PROXY:-http://127.0.0.1:8080}"
ORIGIN="${ORIGIN:-http://127.0.0.1:18080}"
HOST="${HOST:-blog.local}"
CRAWLER_UA="${CRAWLER_UA:-GPTBot/1.0}"
READER_UA="${READER_UA:-Mozilla/5.0}"

headers="$(mktemp)"
trap 'rm -f "$headers"' EXIT

hits() {
  curl -sS "$ORIGIN/__hits" | tr -cd '0-9'
}

crawl() {
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Host: $HOST" -H "User-Agent: $CRAWLER_UA" "$@" "$PROXY/article"
}

# Forget any earlier invoice and zero the counter so the run is
# self-contained however many times it is repeated.
curl -sS -o /dev/null -X POST "$ORIGIN/__reset"

# 1. An unpaid crawler is challenged. The 402 carries the invoice and the
#    signed quote token, and the origin sees nothing.
challenge_status="$(
  curl -sS -D "$headers" -o /dev/null -w '%{http_code}' \
    -H "Host: $HOST" -H "User-Agent: $CRAWLER_UA" "$PROXY/article"
)"
token="$(tr -d '\r' <"$headers" | awk '/^crawler-payment:/ {print $2}')"
printf '1 challenge, unpaid crawler   status=%s origin_hits=%s\n' \
  "$challenge_status" "$(hits)"

# 2. Retrying before the invoice is paid is verified-but-not-settled,
#    which is a 503 with Retry-After, never origin access.
printf '2 retry before payment        status=%s origin_hits=%s\n' \
  "$(crawl -H "crawler-payment: $token")" "$(hits)"

# 3. The payer settles out of band, exactly as a Lightning wallet would.
curl -sS -o /dev/null -X POST "$ORIGIN/__pay"
printf '3 retry after payment         status=%s origin_hits=%s\n' \
  "$(crawl -H "crawler-payment: $token")" "$(hits)"

# 4. The same settled quote presented again authorizes nothing further.
printf '4 replay of the settled quote status=%s origin_hits=%s\n' \
  "$(crawl -H "crawler-payment: $token")" "$(hits)"

# 5. A reader was never in this story.
printf '5 reader, never challenged    status=%s origin_hits=%s\n' \
  "$(curl -sS -o /dev/null -w '%{http_code}' \
      -H "Host: $HOST" -H "User-Agent: $READER_UA" "$PROXY/article")" "$(hits)"
