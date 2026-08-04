#!/usr/bin/env bash
# Mint a governed key that names a Stripe customer, then bill one AI call
# to it and show what landed on the durable queue.
#
# The customer is on the credential, never on the request, so the mint has
# to happen before the call. The token the admin API returns is one-shot:
# it is shown once at mint time and hashed at rest.
#
# Usage (with fixture.py and a payments-featured sbproxy already up):
#   bash examples/usage-bridge-queue/bin/bill-one-call.sh

set -euo pipefail

ADMIN="${ADMIN:-http://127.0.0.1:9090}"
ADMIN_AUTH="${ADMIN_AUTH:-admin:demo-change-me}"
PROXY="${PROXY:-http://127.0.0.1:8080}"
HOST="${HOST:-billing.local}"
MODEL="${MODEL:-gpt-4o-mini}"
CUSTOMER="${CUSTOMER:-cus_demo_usage_bridge}"
STATE="${STATE:-/tmp/sbproxy-usage-bridge/payments.sqlite3}"

if ! command -v sqlite3 >/dev/null 2>&1; then
  printf 'sqlite3 is not on PATH, and the queue this script reports on is a\n' >&2
  printf 'table in %s\n' "$STATE" >&2
  exit 1
fi

# Both calls below keep the response body and the status code together, and
# check the status before reading the body. `curl -sS` exits 0 on a 401 or a
# 409 as readily as on a 201, so a script that trusts the exit code alone
# feeds an error document to its JSON parser and reports a missing field
# instead of the refusal that caused it.
if ! mint="$(
  curl -sS -w $'\n%{http_code}' -u "$ADMIN_AUTH" -H 'Content-Type: application/json' \
    -d "{\"name\":\"usage-bridge-demo\",\"tenant\":\"tenant-a\",\"metadata\":{\"stripe_customer_id\":\"$CUSTOMER\"}}" \
    "$ADMIN/admin/keys"
)"; then
  printf 'mint failed: no answer from %s/admin/keys\n' "$ADMIN" >&2
  printf 'is a payments-featured sbproxy serving examples/usage-bridge-queue/sb.yml?\n' >&2
  exit 1
fi

mint_status="${mint##*$'\n'}"
mint_body="${mint%$'\n'*}"
if [ "$mint_status" != 201 ]; then
  printf 'mint failed: POST %s/admin/keys returned HTTP %s\n' "$ADMIN" "$mint_status" >&2
  printf '%s\n' "$mint_body" >&2
  exit 1
fi

token="$(printf '%s' "$mint_body" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
printf 'minted a governed key naming customer=%s\n' "$CUSTOMER"

if ! chat="$(
  curl -sS -w $'\n%{http_code}' \
    -H "Host: $HOST" -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"bill this\"}]}" \
    "$PROXY/v1/chat/completions"
)"; then
  printf 'chat completion failed: no answer from %s\n' "$PROXY" >&2
  exit 1
fi

status="${chat##*$'\n'}"
printf 'chat completion               status=%s\n' "$status"
if [ "$status" != 200 ]; then
  printf 'the call was not served, so it produced no billable unit:\n' >&2
  printf '%s\n' "${chat%$'\n'*}" >&2
  exit 1
fi

# The row is written in the proxy's logging phase, which runs after the
# response has already reached the client, so reading the file the instant
# curl returns races the writer.
rows=0
for _ in $(seq 1 40); do
  rows="$(sqlite3 "$STATE" 'select count(*) from usage_reports')"
  if [ "$rows" -gt 0 ]; then
    break
  fi
  sleep 0.1
done
printf 'rows on the usage queue       %s\n' "$rows"
