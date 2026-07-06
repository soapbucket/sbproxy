#!/usr/bin/env bash
# Run the model-host Definition-of-Done certification on a GPU host
# (WOR-1652). Run this ON the provisioned L4 box, after vLLM is
# installed and sbproxy is built (the GPU features are in the binary's
# default feature set; `sbproxy doctor` on the box confirms the probe
# sees the card):
#
#   cargo build --release -p sbproxy
#
# It drives the DoD checklist against a running sbproxy that has a
# `serve:` block, and prints PASS/FAIL per item. It does not provision
# anything and makes no cloud calls; it is the on-box acceptance test.
#
# Env:
#   SB_URL     sbproxy base URL           (default http://127.0.0.1:8080)
#   SB_HOST    Host header / origin       (default ai.local)
#   MODEL      model to request           (default qwen3-8b)
#   ENGINE_PID pid of the supervised engine, for the kill-9 test
set -uo pipefail

SB_URL="${SB_URL:-http://127.0.0.1:8080}"
SB_HOST="${SB_HOST:-ai.local}"
MODEL="${MODEL:-qwen3-8b}"

pass=0 fail=0
ok()   { echo "PASS: $1"; pass=$((pass+1)); }
bad()  { echo "FAIL: $1"; fail=$((fail+1)); }

req() {
  curl -sS -m "${1:-120}" -o /tmp/cert-resp.json -w '%{http_code} %{time_total}' \
    "$SB_URL/v1/chat/completions" \
    -H "Host: $SB_HOST" -H 'Content-Type: application/json' \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hi in one word.\"}]}"
}

echo "== Model-host certification against $SB_URL ($MODEL) =="

# 1. First call returns tokens (cold: allow a long timeout for load).
read -r code t1 < <(req 600)
if [ "$code" = "200" ] && grep -q '"content"' /tmp/cert-resp.json; then
  ok "cold first call returns tokens (${t1}s)"
else
  bad "cold first call (http $code)"; cat /tmp/cert-resp.json | head -c 400; echo
fi

# 2. Second call is fast (warm; already resident).
read -r code t2 < <(req 120)
if [ "$code" = "200" ]; then
  ok "warm second call returns tokens (${t2}s)"
  # Warm should be materially faster than the cold load.
  awk -v a="$t1" -v b="$t2" 'BEGIN{exit !(b+0 < a+0)}' \
    && ok "warm faster than cold ($t2 < $t1)" \
    || bad "warm not faster than cold ($t2 vs $t1)"
else
  bad "warm second call (http $code)"
fi

# 3. kill -9 the engine; sbproxy should bring it back and serve again.
if [ -n "${ENGINE_PID:-}" ]; then
  echo "Killing engine pid $ENGINE_PID ..."
  kill -9 "$ENGINE_PID" 2>/dev/null || true
  sleep 3
  read -r code t3 < <(req 600)
  [ "$code" = "200" ] && ok "recovers after kill -9 (${t3}s)" || bad "no recovery after kill -9 (http $code)"
else
  echo "SKIP: set ENGINE_PID to run the kill -9 recovery check"
fi

# 4. Capability gate: an FP8-only request on a non-FP8 card must be
#    refused with a capability message, not a generic error. On an L4
#    (FP8-capable) an FP8 model must instead succeed.
CAP="${CAP_MODEL:-}"
if [ -n "$CAP" ]; then
  read -r code _ < <(MODEL="$CAP" req 600)
  echo "Capability probe for $CAP: http $code"
  grep -qi "fp8\|capab" /tmp/cert-resp.json && echo "  (capability message present)"
fi

echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
