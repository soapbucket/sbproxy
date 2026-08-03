#!/usr/bin/env bash
# One settled payment serves the article exactly once.
#
# Runs the five steps of the settlement gate against the local stack and
# prints the status code and the origin's own hit counter after each one.
# The counter is the load-bearing observable: the proxy can claim
# whatever it likes about a payment, but only the origin knows how many
# times it actually served the content.
#
# Step 3 polls instead of asking once, and the reason is a real property
# of the gate rather than a timing fudge. The early retry in step 2
# leaves the intent in `needs_reconciliation`: the rail verified the
# payment and did not settle it. The request path never retries from
# there, by design, because a second attempt is how a payer gets charged
# twice, so only the recovery worker moves that intent on. The retry
# that reaches the origin is whichever one lands after a sweep, which is
# exactly what the 503's own `Retry-After` asks a client to do.
#
# Every step is asserted. A run that cannot reach the expected outcome
# fails and says what it wanted, rather than printing a 503 as if it
# were the answer.
#
# Usage (with fixture.py and a payments-featured sbproxy already up):
#   bash examples/settlement-gate-local/bin/settle-once.sh

set -euo pipefail

PROXY="${PROXY:-http://127.0.0.1:8080}"
ORIGIN="${ORIGIN:-http://127.0.0.1:18080}"
HOST="${HOST:-blog.local}"
CRAWLER_UA="${CRAWLER_UA:-GPTBot/1.0}"
READER_UA="${READER_UA:-Mozilla/5.0}"

# Where sb.yml keeps the authoritative state. Read only to explain a
# failure; nothing on the happy path touches it.
STATE_DB="${STATE_DB:-/tmp/sbproxy-settlement/payments.sqlite3}"

# The bound on step 3, as attempts times seconds. The default is 20s
# against the 1000 ms `worker.reconcile_interval_ms` this example
# configures, so running out means the worker is not sweeping rather
# than that it was slow.
SETTLE_ATTEMPTS="${SETTLE_ATTEMPTS:-100}"
SETTLE_INTERVAL="${SETTLE_INTERVAL:-0.2}"

headers="$(mktemp)"
trap 'rm -f "$headers"' EXIT

hits() {
  curl -sS "$ORIGIN/__hits" | tr -cd '0-9'
}

crawl() {
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Host: $HOST" -H "User-Agent: $CRAWLER_UA" "$@" "$PROXY/article"
}

# Re-presents the paid quote until the gate stops answering "outcome not
# yet known". Prints the status it settled on, or explains what it was
# waiting for and fails.
await_settlement() {
  local attempt=0 status=""
  while [ "$attempt" -lt "$SETTLE_ATTEMPTS" ]; do
    status="$(crawl -H "crawler-payment: $token")"
    if [ "$status" != "503" ]; then
      printf '%s' "$status"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep "$SETTLE_INTERVAL"
  done

  {
    printf 'settle-once: the paid quote never left 503 after %s attempts.\n' \
      "$SETTLE_ATTEMPTS"
    printf 'The intent is stranded in needs_reconciliation, and only the recovery\n'
    printf 'worker clears that. Check that the worker is sweeping and that the rail\n'
    printf 'can still reach the node.\n'
    if command -v sqlite3 >/dev/null 2>&1 && [ -r "$STATE_DB" ]; then
      printf 'intent status: %s\n' \
        "$(sqlite3 "$STATE_DB" 'select status from payment_intents order by created_at_ms')"
    fi
  } >&2
  return 1
}

# Fails the run rather than letting a wrong status print as if it were
# the expected one.
expect() {
  local label="$1" want="$2" got="$3"
  if [ "$want" != "$got" ]; then
    printf 'settle-once: %s expected status %s, got %s\n' "$label" "$want" "$got" >&2
    return 1
  fi
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
#    which is a 503 with Retry-After, never origin access. It also
#    strands the intent, so from here only the worker can move it on.
early_status="$(crawl -H "crawler-payment: $token")"
printf '2 retry before payment        status=%s origin_hits=%s\n' \
  "$early_status" "$(hits)"

# 3. The payer settles out of band, exactly as a Lightning wallet would,
#    and the crawler retries until the worker has reconciled the intent
#    step 2 stranded.
curl -sS -o /dev/null -X POST "$ORIGIN/__pay"
if ! settled_status="$(await_settlement)"; then
  exit 1
fi
settled_hits="$(hits)"
printf '3 retry after payment         status=%s origin_hits=%s\n' \
  "$settled_status" "$settled_hits"

# 4. The same settled quote presented again authorizes nothing further.
replay_status="$(crawl -H "crawler-payment: $token")"
replay_hits="$(hits)"
printf '4 replay of the settled quote status=%s origin_hits=%s\n' \
  "$replay_status" "$replay_hits"

# 5. A reader was never in this story.
reader_status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Host: $HOST" -H "User-Agent: $READER_UA" "$PROXY/article"
)"
printf '5 reader, never challenged    status=%s origin_hits=%s\n' \
  "$reader_status" "$(hits)"

expect 'the unpaid challenge' 402 "$challenge_status"
expect 'the retry before payment' 503 "$early_status"
expect 'the retry after payment' 200 "$settled_status"
expect 'the replay of the settled quote' 402 "$replay_status"
expect 'the reader' 200 "$reader_status"

if [ "$settled_hits" != "1" ] || [ "$replay_hits" != "1" ]; then
  printf 'settle-once: one settled payment must serve the article exactly once, ' >&2
  printf 'and the origin counted %s then %s\n' "$settled_hits" "$replay_hits" >&2
  exit 1
fi
