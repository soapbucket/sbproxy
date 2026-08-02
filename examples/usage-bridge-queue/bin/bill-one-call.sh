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
CUSTOMER="${CUSTOMER:-cus_demo_usage_bridge}"
STATE="${STATE:-/tmp/sbproxy-usage-bridge/payments.sqlite3}"

mint="$(
  curl -sS -u "$ADMIN_AUTH" -H 'Content-Type: application/json' \
    -d "{\"name\":\"usage-bridge-demo\",\"tenant\":\"tenant-a\",\"metadata\":{\"stripe_customer_id\":\"$CUSTOMER\"}}" \
    "$ADMIN/admin/keys"
)"
token="$(printf '%s' "$mint" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
printf 'minted a governed key naming customer=%s\n' "$CUSTOMER"

status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Host: $HOST" -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"bill this"}]}' \
    "$PROXY/v1/chat/completions"
)"
printf 'chat completion               status=%s\n' "$status"

printf 'rows on the usage queue       %s\n' \
  "$(sqlite3 "$STATE" 'select count(*) from usage_reports')"
