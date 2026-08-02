#!/usr/bin/env bash
# Walk one workspace up its cap and print what happened in each band.
#
# Soft landing compares a threshold against the live window fraction
# before the request is dispatched, so the demo has to place that
# fraction rather than guess it. It does that by measuring: one call of a
# known token count, read the gauge before and after, and every step
# after that is arithmetic. Nothing here assumes a price table or a
# conversion factor, so the ladder lands in the right band even if either
# changes.
#
# The four printed rows are the four bands. `preflight` is the fraction
# the gateway compared the thresholds against, read immediately before
# the call. The steps between them are spent silently; they are plumbing,
# not the story.
#
# The budget tracker is in-memory and cleared only by a restart, so run
# this against a fresh process.
#
# Usage:
#   bash examples/ai-predictive-budget/bin/soft-landing.sh

set -euo pipefail

PROXY="${PROXY:-http://127.0.0.1:8080}"
HOST="${HOST:-ai.local}"

# Read the live workspace fraction. Absent until the first call is
# recorded, which reads as 0.
fraction() {
  local value
  value="$(
    curl -sS "$PROXY/metrics" |
      awk '$0 ~ /^sbproxy_ai_budget_utilization_ratio/ && $0 ~ /scope="workspace"/ {print $NF}' |
      tail -n1
  )"
  printf '%s' "${value:-0}"
}

# One chat completion asking for `gpt-4o` and naming the tokens it wants
# billed. Prints "<status> <served model or error type>".
chat() {
  local spend="$1" raw status body
  raw="$(
    curl -sS -w $'\n%{http_code}' -H "Host: $HOST" -H 'Content-Type: application/json' \
      -d "{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"spend=$spend\"}]}" \
      "$PROXY/v1/chat/completions"
  )"
  status="${raw##*$'\n'}"
  body="${raw%$'\n'*}"
  printf '%s %s' "$status" "$(
    printf '%s' "$body" | python3 -c '
import json, sys
try:
    payload = json.load(sys.stdin)
except Exception:
    print("-")
    sys.exit()
error = payload.get("error")
if isinstance(error, dict):
    print(error.get("type", "-"))
elif error:
    print(str(error)[:40])
else:
    print(payload.get("model", "-"))
'
  )"
}

row() {
  printf '%-24s preflight=%-8s status=%-4s served=%s\n' "$1" "$2" "$3" "$4"
}

# --- 1. Below warn_at, and the calibration that makes the rest exact ---
before="$(fraction)"
read -r status served <<<"$(chat 1)"
after="$(fraction)"
row "1 below warn_at" "$before" "$status" "$served"

per_token="$(awk -v a="$after" -v b="$before" 'BEGIN { printf "%.12f", a - b }')"
if awk -v p="$per_token" 'BEGIN { exit !(p <= 0) }'; then
  echo "the utilization gauge did not move; is the budget block configured?" >&2
  exit 1
fi

# Tokens needed to move the fraction from where it is to `target`.
tokens_to() {
  awk -v target="$1" -v now="$(fraction)" -v per="$per_token" \
    'BEGIN { n = int((target - now) / per); if (n < 1) n = 1; print n }'
}

# --- 2. The warn band -------------------------------------------------
chat "$(tokens_to 0.85)" >/dev/null
before="$(fraction)"
read -r status served <<<"$(chat 1)"
row "2 past warn_at" "$before" "$status" "$served"

# --- 3. The downgrade band -------------------------------------------
chat "$(tokens_to 0.97)" >/dev/null
before="$(fraction)"
read -r status served <<<"$(chat 1)"
row "3 past downgrade_at" "$before" "$status" "$served"

# --- 4. At the cap ----------------------------------------------------
# Deliberately unbounded rather than computed: this step is dispatched in
# the downgrade band, so it is billed at the cheaper model's rate and a
# figure derived from the expensive one would fall short.
chat 100000000 >/dev/null
before="$(fraction)"
read -r status served <<<"$(chat 1)"
row "4 at the cap" "$before" "$status" "$served"
