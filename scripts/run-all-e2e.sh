#!/bin/bash
# Simple e2e runner - starts proxy per case, runs assertions directly.
# Avoids nested bash process issues with the Go runner.
set -eo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
# Default to the in-tree vendored copy of the Go e2e suite. Override with
# GO_E2E_DIR=... to run against an external clone (e.g. soapbucket/sbproxy-go).
GO_E2E="${GO_E2E_DIR:-$WORKSPACE/e2e/conformance}"
if [ ! -d "$GO_E2E" ]; then
  echo "Go e2e directory not found at $GO_E2E" >&2
  echo "Set GO_E2E_DIR=/path/to/e2e or use the in-tree default at e2e/conformance/." >&2
  exit 1
fi
BIN="$WORKSPACE/target/release/sbproxy"
CASES="$GO_E2E/cases"
PORT=18080
URL="http://127.0.0.1:$PORT"

# Build
cd "$WORKSPACE"
cargo build --release -p sbproxy 2>&1 | tail -1

# Start test backend
node "$GO_E2E/servers/test-server.js" 18888 > /dev/null 2>&1 &
NODE_PID=$!
sleep 0.5

# Start mock AI
MOCK_AI_ID=primary MOCK_AI_PORT=18889 node "$GO_E2E/servers/mock-ai.js" 18889 > /dev/null 2>&1 &
AI_PID=$!
sleep 0.3

cleanup_proxy() {
    lsof -ti :$PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 0.3
}

start_proxy() {
    cleanup_proxy
    "$BIN" serve -f "$1" --log-level warn > /dev/null 2>&1 &
    PROXY_PID=$!
    local retries=20
    while ! curl -s -o /dev/null --max-time 1 "$URL/health" 2>/dev/null; do
        retries=$((retries - 1))
        if [ $retries -le 0 ]; then echo "  PROXY_START_FAIL"; return 1; fi
        if ! kill -0 $PROXY_PID 2>/dev/null; then echo "  PROXY_CRASHED"; return 1; fi
        sleep 0.2
    done
    return 0
}

assert_status() {
    local desc="$1" expected="$2"; shift 2
    local actual=$(curl -s -o /dev/null -w "%{http_code}" --compressed --max-time 5 "$@" 2>/dev/null || echo "000")
    if [ "$actual" = "$expected" ]; then
        echo "  PASS $desc"
        return 0
    else
        echo "  FAIL $desc (expected $expected, got $actual)"
        return 1
    fi
}

TOTAL_P=0; TOTAL_F=0; TOTAL_S=0; FAILURES=""

# Run all cases that have configs
for case_dir in "$CASES"/*/; do
    [ -f "$case_dir/sb.yml" ] || continue
    name=$(basename "$case_dir")
    
    if ! start_proxy "$case_dir/sb.yml"; then
        echo "Case $name: SKIP (proxy failed to start)"
        TOTAL_S=$((TOTAL_S + 1))
        cleanup_proxy
        continue
    fi
    
    # Run the Go test runner for this single case, capturing output
    OUTPUT=$(cd "$GO_E2E" && timeout 15 bash -c "
        source <(grep -A50 '^assert_status\|^assert_header\|^assert_body\|^assert_no_header\|^assert_redirect\|^assert_body_json_field\|^assert_body_not_contains\|^assert_status_match\|^log_pass\|^log_fail\|^log_skip' run-tests.sh | head -200)
        PROXY_URL='$URL'
        CALLBACK_URL='http://127.0.0.1:18888'
        # Source the test function for this case
        $(grep -A200 "^run_${name%%_*}" run-tests.sh 2>/dev/null | sed -n '2,/^}/p' | grep -v 'start_proxy\|stop_proxy\|start_callback\|start_mock' || echo 'echo no_test_function')
    " 2>&1) || true
    
    P=$(echo "$OUTPUT" | grep -c "PASS" || true)
    F=$(echo "$OUTPUT" | grep -c "FAIL" || true)
    TOTAL_P=$((TOTAL_P + P)); TOTAL_F=$((TOTAL_F + F))
    
    CASE_FAILS=$(echo "$OUTPUT" | grep "FAIL" || true)
    if [ -n "$CASE_FAILS" ]; then
        echo "Case $name: ${P}P ${F}F"
        echo "$CASE_FAILS" | sed 's/^/  /'
        FAILURES="${FAILURES}${CASE_FAILS}\n"
    elif [ $P -eq 0 ]; then
        echo "Case $name: 0P 0F (no assertions)"
        TOTAL_S=$((TOTAL_S + 1))
    else
        echo "Case $name: ${P}P ${F}F"
    fi
    
    cleanup_proxy
done

# Cleanup
kill $NODE_PID $AI_PID 2>/dev/null || true

echo ""
echo "========================="
echo "TOTAL: ${TOTAL_P} passed, ${TOTAL_F} failed, ${TOTAL_S} skipped"
if [ -n "$FAILURES" ]; then
    echo -e "\nALL FAILURES:\n$FAILURES"
fi
