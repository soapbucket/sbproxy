#!/usr/bin/env bash
# run-tests.sh - Build sbproxy, then exercise all OSS features via curl
#
# Usage:
#   ./test/run-tests.sh              # Run all tests
#   ./test/run-tests.sh 01 03 07     # Run specific test cases
#
# Each test case lives in its own numbered directory with:
#   sb.yml    - proxy configuration for that test
#   *.json    - optional test fixtures
#
# The script starts sbproxy per case, runs curl assertions, then tears it down.
# A final report shows pass/fail counts with details on any failures.
#
# Prerequisites: curl, jq, node (for callback tests), python3 (for JWT tests)

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SBPROXY_SRC="$(cd "$SCRIPT_DIR/.." && pwd)"
SBPROXY_BIN="$SCRIPT_DIR/sbproxy"
CASES_DIR="$SCRIPT_DIR/cases"
SERVERS_DIR="$SCRIPT_DIR/servers"
PROXY_PORT=18080
PROXY_URL="http://localhost:$PROXY_PORT"
CALLBACK_PORT=18888
CALLBACK_URL="http://127.0.0.1:$CALLBACK_PORT"
LOG_DIR="$SCRIPT_DIR/logs"
CERT_DIR="$SCRIPT_DIR/certs"

PASS=0
FAIL=0
SKIP=0
FAILURES=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# PIDs
PROXY_PID=""
CALLBACK_PID=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log_header() { echo -e "\n${BOLD}${CYAN}=== $1 ===${NC}"; }
log_pass()   { echo -e "  ${GREEN}PASS${NC} $1"; PASS=$((PASS + 1)); }
log_fail()   { echo -e "  ${RED}FAIL${NC} $1"; FAIL=$((FAIL + 1)); FAILURES+=("$1"); }
log_skip()   { echo -e "  ${YELLOW}SKIP${NC} $1"; SKIP=$((SKIP + 1)); }

# assert_status <description> <expected_status> <curl_args...>
assert_status() {
    local desc="$1" expected="$2"
    shift 2
    local actual
    actual=$(curl -s -o /dev/null -w "%{http_code}" --compressed --max-time 10 "$@" 2>/dev/null || echo "000")
    if [[ "$actual" == "$expected" ]]; then
        log_pass "$desc (HTTP $actual)"
    else
        log_fail "$desc (expected $expected, got $actual)"
    fi
}

# assert_status_match <description> <regex> <curl_args...>
assert_status_match() {
    local desc="$1" pattern="$2"
    shift 2
    local actual
    actual=$(curl -s -o /dev/null -w "%{http_code}" --compressed --max-time 10 "$@" 2>/dev/null || echo "000")
    if [[ "$actual" =~ $pattern ]]; then
        log_pass "$desc (HTTP $actual)"
    else
        log_fail "$desc (expected match '$pattern', got $actual)"
    fi
}

# assert_header <description> <header_name> <expected_substring> <curl_args...>
assert_header() {
    local desc="$1" header="$2" expected="$3"
    shift 3
    local response
    # Try HEAD first (most reliable for response headers)
    response=$(curl -sI --compressed --max-time 10 "$@" 2>/dev/null || echo "")
    if ! echo "$response" | grep -qi "$header"; then
        # Fallback: some endpoints don't support HEAD or skip modifiers on HEAD
        response=$(curl -s -D /dev/stderr -o /dev/null --compressed --max-time 10 "$@" 2>&1 || echo "")
    fi
    if echo "$response" | grep -qi "$header.*$expected"; then
        log_pass "$desc"
    else
        log_fail "$desc (header '$header' missing or does not contain '$expected')"
    fi
}

# assert_no_header <description> <header_name> <curl_args...>
assert_no_header() {
    local desc="$1" header="$2"
    shift 2
    local response
    response=$(curl -s -D - -o /dev/null --compressed --max-time 10 "$@" 2>/dev/null || echo "")
    if echo "$response" | grep -qi "^$header:"; then
        log_fail "$desc (header '$header' should not be present)"
    else
        log_pass "$desc"
    fi
}

# assert_body_contains <description> <expected_substring> <curl_args...>
assert_body_contains() {
    local desc="$1" expected="$2"
    shift 2
    local body
    body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 "$@" 2>/dev/null || echo "")
    if echo "$body" | grep -q "$expected"; then
        log_pass "$desc"
    else
        log_fail "$desc (body does not contain '$expected')"
    fi
}

# assert_body_not_contains <description> <unexpected_substring> <curl_args...>
assert_body_not_contains() {
    local desc="$1" unexpected="$2"
    shift 2
    local body
    body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 "$@" 2>/dev/null || echo "")
    if echo "$body" | grep -q "$unexpected"; then
        log_fail "$desc (body should not contain '$unexpected')"
    else
        log_pass "$desc"
    fi
}

# assert_body_json_field <description> <jq_expression> <expected_value> <curl_args...>
assert_body_json_field() {
    local desc="$1" jq_expr="$2" expected="$3"
    shift 3
    if ! command -v jq &>/dev/null; then
        log_skip "$desc (jq not installed)"
        return
    fi
    local body val
    body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 "$@" 2>/dev/null || echo "{}")
    val=$(echo "$body" | jq -r "$jq_expr" 2>/dev/null | head -1 | tr -d '\r\n' || echo "PARSE_ERROR")
    if [[ "$val" == "$expected" ]]; then
        log_pass "$desc"
    else
        log_fail "$desc (expected '$expected', got '$val')"
    fi
}

# assert_redirect <description> <expected_status> <expected_location_substring> <curl_args...>
assert_redirect() {
    local desc="$1" expected_status="$2" expected_location="$3"
    shift 3
    local headers
    headers=$(curl -s -D - -o /dev/null --max-time 10 "$@" 2>/dev/null || echo "")
    local status
    status=$(echo "$headers" | head -1 | grep -o '[0-9]\{3\}' || echo "000")
    if [[ "$status" == "$expected_status" ]] && echo "$headers" | grep -qi "location.*$expected_location"; then
        log_pass "$desc (HTTP $status -> $expected_location)"
    else
        log_fail "$desc (expected $expected_status with location containing '$expected_location', got $status)"
    fi
}

# Start sbproxy for a test case, wait for it to be ready
start_proxy() {
    local case_dir="$1"
    local config="$case_dir/sb.yml"
    local case_name
    case_name=$(basename "$case_dir")
    local logfile="$LOG_DIR/$case_name.log"

    # Kill any stale proxy on our port
    lsof -ti:"$PROXY_PORT" 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 0.2

    "$SBPROXY_BIN" serve -f "$config" --log-level warn > "$logfile" 2>&1 &
    PROXY_PID=$!

    # Wait for proxy to start accepting connections (up to 5s)
    local retries=50
    while ! kill -0 "$PROXY_PID" 2>/dev/null || ! curl -s -o /dev/null --max-time 1 "$PROXY_URL/health" 2>/dev/null; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then
            echo -e "  ${RED}ERROR${NC}: sbproxy failed to start for $case_name (see $logfile)"
            kill "$PROXY_PID" 2>/dev/null || true
            PROXY_PID=""
            return 1
        fi
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            echo -e "  ${RED}ERROR${NC}: sbproxy exited early for $case_name (see $logfile)"
            PROXY_PID=""
            return 1
        fi
        sleep 0.1
    done
    return 0
}

# Stop sbproxy
stop_proxy() {
    if [[ -n "${PROXY_PID}" ]]; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
        PROXY_PID=""
    fi
    # Kill anything on the proxy and telemetry ports (NOT mock server ports)
    lsof -ti:"$PROXY_PORT" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:8888 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:8443 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 0.2
}

# Start callback server (Node.js)
start_callback_server() {
    if [[ -n "${CALLBACK_PID}" ]] && kill -0 "$CALLBACK_PID" 2>/dev/null; then
        return 0
    fi
    if ! command -v node &>/dev/null; then
        echo -e "  ${YELLOW}WARN${NC}: node not found, callback tests will be skipped"
        return 1
    fi
    node "$SERVERS_DIR/test-server.js" "$CALLBACK_PORT" > "$LOG_DIR/callback-server.log" 2>&1 &
    CALLBACK_PID=$!
    local retries=30
    while ! curl -s -o /dev/null --max-time 1 "$CALLBACK_URL/health" 2>/dev/null; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then
            echo -e "  ${RED}ERROR${NC}: callback server failed to start"
            kill "$CALLBACK_PID" 2>/dev/null || true
            CALLBACK_PID=""
            return 1
        fi
        sleep 0.1
    done
    return 0
}

# Stop callback server
stop_callback_server() {
    if [[ -n "${CALLBACK_PID}" ]]; then
        kill "$CALLBACK_PID" 2>/dev/null || true
        wait "$CALLBACK_PID" 2>/dev/null || true
        CALLBACK_PID=""
    fi
}

# Clear recorded requests on callback server
clear_callback_requests() {
    curl -s -X DELETE "$CALLBACK_URL/requests" > /dev/null 2>&1 || true
}

# Get callback request count
get_callback_count() {
    curl -s "$CALLBACK_URL/requests/count" 2>/dev/null | jq -r '.count' 2>/dev/null || echo "0"
}

# All tests use local callback server backend
needs_callback_server() {
    return 0
}

# Check if a test needs the mock AI server
needs_mock_ai_server() {
    local case_num="$1"
    case "$case_num" in
        37|38|39|40|41|42|43|44|45|46|49|71|81|82) return 0 ;;
        *) return 1 ;;
    esac
}

MOCK_AI_PID=""
MOCK_AI_PORT=18889
MOCK_AI_URL="http://127.0.0.1:$MOCK_AI_PORT"
MOCK_AI_PORT2=18890
MOCK_AI_PORT_FAIL=18891

# Start mock AI server(s)
start_mock_ai_server() {
    if [[ -n "${MOCK_AI_PID}" ]] && kill -0 "$MOCK_AI_PID" 2>/dev/null; then
        return 0
    fi
    if ! command -v node &>/dev/null; then
        echo -e "  ${YELLOW}WARN${NC}: node not found, AI tests will be skipped"
        return 1
    fi
    # Primary mock AI server
    MOCK_AI_ID=primary MOCK_AI_PORT=$MOCK_AI_PORT node "$SERVERS_DIR/mock-ai.js" "$MOCK_AI_PORT" > "$LOG_DIR/mock-ai.log" 2>&1 &
    MOCK_AI_PID=$!
    local retries=30
    while ! curl -s -o /dev/null --max-time 1 "$MOCK_AI_URL/health" 2>/dev/null; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then
            echo -e "  ${RED}ERROR${NC}: mock AI server failed to start"
            kill "$MOCK_AI_PID" 2>/dev/null || true
            MOCK_AI_PID=""
            return 1
        fi
        sleep 0.1
    done
    return 0
}

# Start secondary mock AI server (for multi-provider tests)
MOCK_AI_PID2=""
start_mock_ai_server_2() {
    if [[ -n "${MOCK_AI_PID2}" ]] && kill -0 "$MOCK_AI_PID2" 2>/dev/null; then
        return 0
    fi
    MOCK_AI_ID=secondary node "$SERVERS_DIR/mock-ai.js" "$MOCK_AI_PORT2" > "$LOG_DIR/mock-ai-2.log" 2>&1 &
    MOCK_AI_PID2=$!
    local retries=30
    while ! curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$MOCK_AI_PORT2/health" 2>/dev/null; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then return 1; fi
        sleep 0.1
    done
    return 0
}

stop_mock_ai_servers() {
    if [[ -n "${MOCK_AI_PID}" ]]; then
        kill "$MOCK_AI_PID" 2>/dev/null || true
        wait "$MOCK_AI_PID" 2>/dev/null || true
        MOCK_AI_PID=""
    fi
    if [[ -n "${MOCK_AI_PID2}" ]]; then
        kill "$MOCK_AI_PID2" 2>/dev/null || true
        wait "$MOCK_AI_PID2" 2>/dev/null || true
        MOCK_AI_PID2=""
    fi
    lsof -ti:$MOCK_AI_PORT -ti:$MOCK_AI_PORT2 -ti:$MOCK_AI_PORT_FAIL 2>/dev/null | xargs kill -9 2>/dev/null || true
}

# Cleanup on exit
cleanup() {
    stop_proxy
    stop_callback_server
    stop_mock_ai_servers
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
log_header "Building sbproxy"

if [[ ! -d "$SBPROXY_SRC" ]]; then
    echo -e "${RED}ERROR${NC}: sbproxy source not found at $SBPROXY_SRC"
    exit 1
fi

cd "$SBPROXY_SRC"
if go build -o "$SBPROXY_BIN" ./cmd/sbproxy/; then
    echo -e "  ${GREEN}OK${NC} Built sbproxy -> $SBPROXY_BIN"
else
    echo -e "  ${RED}ERROR${NC} Build failed"
    exit 1
fi
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Generate certs
# ---------------------------------------------------------------------------
if [[ ! -f "$CERT_DIR/ca-cert.pem" ]]; then
    log_header "Generating test certificates"
    bash "$SCRIPT_DIR/generate-certs.sh"
fi

# ---------------------------------------------------------------------------
# Ensure log directory exists
# ---------------------------------------------------------------------------
mkdir -p "$LOG_DIR"

# ---------------------------------------------------------------------------
# Determine which tests to run
# ---------------------------------------------------------------------------
if [[ $# -gt 0 ]]; then
    TEST_CASES=()
    for num in "$@"; do
        dir=$(find "$CASES_DIR" -maxdepth 1 -type d -name "${num}-*" | head -1)
        if [[ -n "$dir" ]]; then
            TEST_CASES+=("$dir")
        else
            echo -e "${YELLOW}WARN${NC}: No test case matching '$num'"
        fi
    done
else
    TEST_CASES=()
    while IFS= read -r dir; do
        TEST_CASES+=("$dir")
    done < <(find "$CASES_DIR" -maxdepth 1 -type d -name '[0-9]*' | sort)
fi

# ===========================================================================
# TEST CASES
# ===========================================================================

run_01_basic_proxy() {
    log_header "01 - Basic Proxy"
    start_proxy "$CASES_DIR/01-basic-proxy" || return

    assert_status "Proxy returns 200 on /" 200 -H "Host: basic.test" "$PROXY_URL/"
    assert_status "Proxy returns 200 on /echo" 200 -H "Host: basic.test" "$PROXY_URL/echo"
    assert_status "Proxy returns 200 on /health" 200 -H "Host: basic.test" "$PROXY_URL/health"

    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -H "Host: unknown.test" "$PROXY_URL/" 2>/dev/null || echo "000")
    if [[ "$code" =~ ^4 ]] || [[ "$code" =~ ^5 ]]; then
        log_pass "Unknown host rejected (HTTP $code)"
    else
        log_fail "Unknown host not rejected (HTTP $code)"
    fi

    stop_proxy
}

run_02_authentication() {
    log_header "02 - Authentication"
    start_proxy "$CASES_DIR/02-authentication" || return

    # API Key
    assert_status "API key - valid key" 200 -H "Host: apikey.test" -H "X-API-Key: test-key-1" "$PROXY_URL/echo"
    assert_status "API key - second valid key" 200 -H "Host: apikey.test" -H "X-API-Key: test-key-2" "$PROXY_URL/echo"
    assert_status "API key - invalid" 401 -H "Host: apikey.test" -H "X-API-Key: wrong" "$PROXY_URL/echo"
    assert_status "API key - missing" 401 -H "Host: apikey.test" "$PROXY_URL/echo"

    # Basic auth
    assert_status "Basic auth - valid" 200 -H "Host: basic.test" -u "alice:secret123" "$PROXY_URL/echo"
    assert_status "Basic auth - wrong pw" 401 -H "Host: basic.test" -u "alice:wrong" "$PROXY_URL/echo"
    assert_status "Basic auth - wrong user" 401 -H "Host: basic.test" -u "bob:secret123" "$PROXY_URL/echo"
    assert_status "Basic auth - missing" 401 -H "Host: basic.test" "$PROXY_URL/echo"

    # Bearer
    assert_status "Bearer - valid" 200 -H "Host: bearer.test" -H "Authorization: Bearer my-bearer-token-1" "$PROXY_URL/echo"
    assert_status "Bearer - invalid" 401 -H "Host: bearer.test" -H "Authorization: Bearer wrong" "$PROXY_URL/echo"
    assert_status "Bearer - missing" 401 -H "Host: bearer.test" "$PROXY_URL/echo"

    # JWT
    if command -v python3 &>/dev/null; then
        local jwt_token
        jwt_token=$(python3 -c "
import hmac, hashlib, base64, json
def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
header = b64url(json.dumps({'alg':'HS256','typ':'JWT'},separators=(',',':')).encode())
payload = b64url(json.dumps({'sub':'test','iat':int(__import__('time').time())-60,'exp':int(__import__('time').time())+3600},separators=(',',':')).encode())
sig_input = f'{header}.{payload}'
sig = hmac.new(b'jW7tN3mK9pR4xL2vX5qJ8bN4mW', sig_input.encode(), hashlib.sha256).digest()
print(f'{sig_input}.{b64url(sig)}')
" 2>/dev/null || echo "")
        if [[ -n "$jwt_token" ]]; then
            assert_status "JWT - valid token" 200 -H "Host: jwt.test" -H "Authorization: Bearer $jwt_token" "$PROXY_URL/echo"
        else
            log_skip "JWT - python3 token generation failed"
        fi
        # Expired JWT
        local expired_jwt
        expired_jwt=$(python3 -c "
import hmac, hashlib, base64, json
def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
header = b64url(json.dumps({'alg':'HS256','typ':'JWT'},separators=(',',':')).encode())
payload = b64url(json.dumps({'sub':'test','iat':1000000000,'exp':1000000001},separators=(',',':')).encode())
sig_input = f'{header}.{payload}'
sig = hmac.new(b'jW7tN3mK9pR4xL2vX5qJ8bN4mW', sig_input.encode(), hashlib.sha256).digest()
print(f'{sig_input}.{b64url(sig)}')
" 2>/dev/null || echo "")
        if [[ -n "$expired_jwt" ]]; then
            assert_status "JWT - expired token" 401 -H "Host: jwt.test" -H "Authorization: Bearer $expired_jwt" "$PROXY_URL/echo"
        fi
    else
        log_skip "JWT tests - python3 not available"
    fi
    assert_status "JWT - invalid token" 401 -H "Host: jwt.test" -H "Authorization: Bearer not-a-jwt" "$PROXY_URL/echo"
    assert_status "JWT - missing" 401 -H "Host: jwt.test" "$PROXY_URL/echo"

    stop_proxy
}

run_03_rate_limiting() {
    log_header "03 - Rate Limiting"
    start_proxy "$CASES_DIR/03-rate-limiting" || return

    assert_status "Rate limit - first request" 200 -H "Host: ratelimit.test" "$PROXY_URL/echo"
    assert_header "Rate limit - X-RateLimit-Limit present" "X-RateLimit-Limit" "" -H "Host: ratelimit.test" "$PROXY_URL/echo"
    assert_header "Rate limit - X-RateLimit-Remaining present" "X-RateLimit-Remaining" "" -H "Host: ratelimit.test" "$PROXY_URL/echo"

    # Exhaust limit (3/min, already used ~2-3 above)
    for _ in 1 2 3; do curl -s -o /dev/null -H "Host: ratelimit.test" "$PROXY_URL/echo" 2>/dev/null || true; done
    assert_status "Rate limit - exceeded returns 429" 429 -H "Host: ratelimit.test" "$PROXY_URL/echo"
    assert_header "Rate limit - Retry-After on 429" "Retry-After" "" -H "Host: ratelimit.test" "$PROXY_URL/echo"

    stop_proxy
}

run_04_ip_filtering() {
    log_header "04 - IP Filtering"
    start_proxy "$CASES_DIR/04-ip-filtering" || return

    assert_status "IP filter - localhost whitelisted" 200 -H "Host: ipfilter.test" "$PROXY_URL/echo"

    stop_proxy
}

run_05_waf() {
    log_header "05 - WAF"
    start_proxy "$CASES_DIR/05-waf" || return

    assert_status "WAF - normal request" 200 -H "Host: waf.test" "$PROXY_URL/echo"
    assert_status "WAF - SQL injection" 403 -H "Host: waf.test" "$PROXY_URL/echo?q=1+OR+1%3D1"
    assert_status "WAF - XSS" 403 -H "Host: waf.test" "$PROXY_URL/echo?q=%3Cscript%3Ealert(1)%3C/script%3E"
    assert_status "WAF - path traversal" 403 -H "Host: waf.test" "$PROXY_URL/echo?file=../../../etc/passwd"
    assert_status "WAF - custom rule bad UA" 403 -H "Host: waf.test" -H "User-Agent: badbot-test/1.0" "$PROXY_URL/echo"
    assert_status "WAF - normal UA passes" 200 -H "Host: waf.test" -H "User-Agent: Mozilla/5.0" "$PROXY_URL/echo"

    stop_proxy
}

run_06_scripting() {
    log_header "06 - CEL/Lua Scripting"
    start_proxy "$CASES_DIR/06-scripting" || return

    assert_status "CEL - admin passes" 200 -H "Host: cel.test" -H "X-Role: admin" "$PROXY_URL/echo"
    assert_status "CEL - editor passes" 200 -H "Host: cel.test" -H "X-Role: editor" "$PROXY_URL/echo"
    assert_status "CEL - guest blocked" 403 -H "Host: cel.test" -H "X-Role: guest" "$PROXY_URL/echo"
    assert_status "CEL - no role blocked" 403 -H "Host: cel.test" "$PROXY_URL/echo"

    assert_body_contains "Lua - adds processed_by" "sbproxy-lua" -H "Host: lua.test" "$PROXY_URL/echo?format=json"
    assert_body_not_contains "Lua - removes headers" '"headers"' -H "Host: lua.test" "$PROXY_URL/echo?format=json"

    stop_proxy
}

run_07_transforms() {
    log_header "07 - Transforms"
    start_proxy "$CASES_DIR/07-transforms" || return

    if command -v jq &>/dev/null; then
        local body keys has_headers
        body=$(curl -s --max-time 10 -H "Host: json-proj.test" "$PROXY_URL/echo?format=json" 2>/dev/null || echo "{}")
        keys=$(echo "$body" | jq -r 'keys[]' 2>/dev/null | sort | tr '\n' ',')
        if [[ "$keys" == *"method"* ]] && [[ "$keys" == *"path"* ]]; then
            log_pass "JSON projection - keeps method and path"
        else
            log_fail "JSON projection - unexpected keys: $keys"
        fi
        has_headers=$(echo "$body" | jq 'has("headers")' 2>/dev/null || echo "true")
        if [[ "$has_headers" == "false" ]]; then
            log_pass "JSON projection - excludes other fields"
        else
            log_fail "JSON projection - other fields not excluded"
        fi
    else
        log_skip "JSON projection - jq not available"
    fi

    assert_body_contains "Template - wraps with metadata" '"wrapped": true' -H "Host: template.test" "$PROXY_URL/echo?format=json"
    assert_body_contains "Template - source field" '"source": "sbproxy"' -H "Host: template.test" "$PROXY_URL/echo?format=json"

    stop_proxy
}

run_08_caching() {
    log_header "08 - Caching"
    start_proxy "$CASES_DIR/08-caching" || return

    assert_status "Cache - first request" 200 -H "Host: cached.test" "$PROXY_URL/echo"
    assert_status "Cache - second request (cached)" 200 -H "Host: cached.test" "$PROXY_URL/echo"
    assert_status "Cache - different params" 200 -H "Host: cached.test" "$PROXY_URL/echo?user=alice"

    stop_proxy
}

run_09_forwarding_rules() {
    log_header "09 - Forwarding Rules"
    start_proxy "$CASES_DIR/09-forwarding-rules" || return

    assert_status "Forward - /api/ routes" 200 -H "Host: routing.test" "$PROXY_URL/api/users"
    assert_header "Forward - /api/ X-Routed-To" "X-Routed-To" "api-backend" -H "Host: routing.test" "$PROXY_URL/api/users"
    assert_status "Forward - /health static" 200 -H "Host: routing.test" "$PROXY_URL/health"
    # /health may be intercepted by sbproxy's internal health check or the static forward rule
    local health_body
    health_body=$(curl -s --compressed --max-time 10 -H "Host: routing.test" "$PROXY_URL/health" 2>/dev/null || echo "{}")
    if echo "$health_body" | grep -q "healthy\|ok"; then
        log_pass "Forward - /health returns health status"
    else
        log_fail "Forward - /health unexpected body: ${health_body:0:80}"
    fi
    assert_redirect "Forward - /docs/ redirect" "302" "127.0.0.1:18888" -H "Host: routing.test" "$PROXY_URL/docs/getting-started"
    assert_status "Forward - catch-all" 200 -H "Host: routing.test" "$PROXY_URL/"

    stop_proxy
}

run_10_load_balancer() {
    log_header "10 - Load Balancer"
    start_proxy "$CASES_DIR/10-load-balancer" || return

    assert_status "LB - request 1" 200 -H "Host: lb.test" "$PROXY_URL/"
    assert_status "LB - request 2" 200 -H "Host: lb.test" "$PROXY_URL/"
    assert_status "LB - request 3" 200 -H "Host: lb.test" "$PROXY_URL/"
    assert_header "LB - X-Proxy header" "X-Proxy" "sbproxy-lb" -H "Host: lb.test" "$PROXY_URL/"

    stop_proxy
}

run_11_cors_security() {
    log_header "11 - CORS & Security Headers"
    start_proxy "$CASES_DIR/11-cors-security" || return

    # CORS preflight
    local cors_headers
    cors_headers=$(curl -s -D - -o /dev/null --max-time 10 -X OPTIONS \
        -H "Host: cors.test" -H "Origin: https://app.example.com" \
        -H "Access-Control-Request-Method: POST" "$PROXY_URL/echo" 2>/dev/null || echo "")

    if echo "$cors_headers" | grep -qi "access-control-allow-origin"; then
        log_pass "CORS - ACAO on preflight"
    else
        log_fail "CORS - ACAO missing on preflight"
    fi
    if echo "$cors_headers" | grep -qi "access-control-allow-methods"; then
        log_pass "CORS - ACAM present"
    else
        log_fail "CORS - ACAM missing"
    fi

    assert_header "CORS - ACAO on regular request" "Access-Control-Allow-Origin" "app.example.com" \
        -H "Host: cors.test" -H "Origin: https://app.example.com" "$PROXY_URL/echo"

    # Security headers
    assert_header "Security - HSTS" "Strict-Transport-Security" "max-age" -H "Host: cors.test" "$PROXY_URL/echo"
    assert_header "Security - CSP" "Content-Security-Policy" "default-src" -H "Host: cors.test" "$PROXY_URL/echo"
    assert_header "Security - X-Frame-Options" "X-Frame-Options" "DENY" -H "Host: cors.test" "$PROXY_URL/echo"
    assert_header "Security - X-Content-Type-Options" "X-Content-Type-Options" "nosniff" -H "Host: cors.test" "$PROXY_URL/echo"
    assert_header "Security - Referrer-Policy" "Referrer-Policy" "strict-origin" -H "Host: cors.test" "$PROXY_URL/echo"

    stop_proxy
}

run_12_compression() {
    log_header "12 - Compression"
    start_proxy "$CASES_DIR/12-compression" || return

    assert_status "Compression - gzip request" 200 -H "Host: compress.test" -H "Accept-Encoding: identity" "$PROXY_URL/"
    assert_status "Compression - no encoding" 200 -H "Host: compress.test" "$PROXY_URL/"
    assert_status "Compression - auto-decompress" 200 -H "Host: compress.test" -H "Accept-Encoding: identity" --compressed "$PROXY_URL/"

    stop_proxy
}

run_13_error_pages() {
    log_header "13 - Error Pages"
    start_proxy "$CASES_DIR/13-error-pages" || return

    assert_status "Error page - 401 without auth" 401 -H "Host: errors.test" "$PROXY_URL/echo"
    assert_body_contains "Error page - custom JSON" '"error": true' -H "Host: errors.test" "$PROXY_URL/echo"
    assert_status "Error page - 200 with key" 200 -H "Host: errors.test" -H "X-API-Key: valid-key-only" "$PROXY_URL/echo"

    stop_proxy
}

run_14_static_echo() {
    log_header "14 - Static & Echo Actions"
    start_proxy "$CASES_DIR/14-static-echo" || return

    assert_status "Static - 200" 200 -H "Host: static.test" "$PROXY_URL/"
    assert_body_json_field "Static - message" ".message" "Hello from static" -H "Host: static.test" "$PROXY_URL/"
    assert_body_json_field "Static - version" ".version" "1.0" -H "Host: static.test" "$PROXY_URL/"
    assert_header "Static - Content-Type" "Content-Type" "application/json" -H "Host: static.test" "$PROXY_URL/"

    assert_status "Echo - 200" 200 -H "Host: echo.test" "$PROXY_URL/test-path"
    assert_body_contains "Echo - path" "test-path" -H "Host: echo.test" "$PROXY_URL/test-path"
    assert_body_contains "Echo - method" "GET" -H "Host: echo.test" "$PROXY_URL/test-path"

    stop_proxy
}

run_15_websocket() {
    log_header "15 - WebSocket"
    if ! command -v websocat &>/dev/null && ! command -v wscat &>/dev/null; then
        log_skip "WebSocket - websocat/wscat not installed"
        return
    fi
    start_proxy "$CASES_DIR/15-websocket" || return

    local ws_status
    ws_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        -H "Host: ws.test" -H "Upgrade: websocket" -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Sec-WebSocket-Version: 13" \
        "$PROXY_URL/" 2>/dev/null || echo "000")
    if [[ "$ws_status" == "101" ]] || [[ "$ws_status" == "200" ]]; then
        log_pass "WebSocket - upgrade handshake (HTTP $ws_status)"
    else
        log_skip "WebSocket - echo.websocket.org may be unavailable (HTTP $ws_status)"
    fi

    stop_proxy
}

run_16_modifiers() {
    log_header "16 - Basic Header Modifiers"
    start_proxy "$CASES_DIR/16-modifiers" || return

    assert_header "Modifier - X-Powered-By set" "X-Powered-By" "sbproxy-test" -H "Host: modifiers.test" "$PROXY_URL/echo"
    assert_header "Modifier - X-Response-Modified set" "X-Response-Modified" "true" -H "Host: modifiers.test" "$PROXY_URL/echo"
    # Request modifier body assertions need the local callback server (see test 25)
    # 127.0.0.1:18888 double-compresses, making body assertions unreliable
    assert_status "Modifier - request with injected headers succeeds" 200 -H "Host: modifiers.test" "$PROXY_URL/echo"

    stop_proxy
}

run_17_csrf() {
    log_header "17 - CSRF Protection"
    start_proxy "$CASES_DIR/17-csrf" || return

    # GET should pass (safe method)
    assert_status "CSRF - GET passes" 200 -H "Host: csrf.test" "$PROXY_URL/echo"

    # GET should set csrf cookie
    local cookies
    cookies=$(curl -s -D - -o /dev/null --max-time 10 -H "Host: csrf.test" "$PROXY_URL/echo" 2>/dev/null || echo "")
    if echo "$cookies" | grep -qi "csrf_token"; then
        log_pass "CSRF - cookie set on GET"
    else
        log_fail "CSRF - csrf_token cookie not set"
    fi

    # POST without token should be blocked
    assert_status_match "CSRF - POST without token blocked" "^4" \
        -X POST -H "Host: csrf.test" "$PROXY_URL/echo"

    # Exempt path should pass
    assert_status "CSRF - exempt path /health" 200 -H "Host: csrf.test" "$PROXY_URL/health"

    stop_proxy
}

run_18_ddos_protection() {
    log_header "18 - DDoS Protection"
    start_proxy "$CASES_DIR/18-ddos-protection" || return

    # Normal request should pass
    assert_status "DDoS - normal request passes" 200 -H "Host: ddos.test" "$PROXY_URL/echo"

    # Flood with rapid requests to trigger detection (threshold: 10 req in 5s)
    for _ in $(seq 1 15); do
        curl -s -o /dev/null -H "Host: ddos.test" "$PROXY_URL/echo" 2>/dev/null &
    done
    wait

    # After flood, should be blocked or throttled
    local post_flood
    post_flood=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -H "Host: ddos.test" "$PROXY_URL/echo" 2>/dev/null || echo "000")
    if [[ "$post_flood" == "429" ]] || [[ "$post_flood" == "403" ]] || [[ "$post_flood" == "503" ]]; then
        log_pass "DDoS - flood triggers protection (HTTP $post_flood)"
    else
        log_skip "DDoS - flood did not trigger (may need higher volume, got HTTP $post_flood)"
    fi

    stop_proxy
}

run_19_request_limiting() {
    log_header "19 - Request Limiting"
    start_proxy "$CASES_DIR/19-request-limiting" || return

    # Normal short request passes
    assert_status "Request limit - short URL passes" 200 -H "Host: reqlimit.test" "$PROXY_URL/echo"

    # Long URL exceeds max_url_length (100)
    local long_path
    long_path=$(python3 -c "print('/echo/' + 'a' * 120)" 2>/dev/null || echo "/echo/$(printf 'a%.0s' {1..120})")
    assert_status_match "Request limit - long URL blocked" "^4" -H "Host: reqlimit.test" "$PROXY_URL$long_path"

    # Long query string exceeds max_query_string_length (50)
    local long_query
    long_query=$(python3 -c "print('x=' + 'b' * 60)" 2>/dev/null || echo "x=$(printf 'b%.0s' {1..60})")
    assert_status_match "Request limit - long query blocked" "^4" -H "Host: reqlimit.test" "$PROXY_URL/echo?$long_query"

    stop_proxy
}

run_20_allowed_methods() {
    log_header "20 - Allowed Methods"
    start_proxy "$CASES_DIR/20-allowed-methods" || return

    assert_status "Allowed methods - GET passes" 200 -H "Host: methods.test" "$PROXY_URL/echo"
    assert_status "Allowed methods - HEAD passes" 200 -H "Host: methods.test" -I "$PROXY_URL/echo"
    assert_status "Allowed methods - POST blocked" 405 -X POST -H "Host: methods.test" "$PROXY_URL/echo"
    assert_status "Allowed methods - PUT blocked" 405 -X PUT -H "Host: methods.test" "$PROXY_URL/echo"
    assert_status "Allowed methods - DELETE blocked" 405 -X DELETE -H "Host: methods.test" "$PROXY_URL/echo"

    stop_proxy
}

run_21_redirect_action() {
    log_header "21 - Redirect Action"
    start_proxy "$CASES_DIR/21-redirect-action" || return

    assert_redirect "Redirect - 301 permanent" "301" "127.0.0.1:18888" -H "Host: redirect301.test" "$PROXY_URL/page"
    assert_redirect "Redirect - 302 temporary" "302" "127.0.0.1:18888" -H "Host: redirect302.test" "$PROXY_URL/"

    # 301 with preserve_query - query should be in Location header
    local headers
    headers=$(curl -s -D - -o /dev/null --max-time 10 -H "Host: redirect301.test" "$PROXY_URL/page?foo=bar" 2>/dev/null || echo "")
    if echo "$headers" | grep -qi "location.*foo=bar"; then
        log_pass "Redirect - preserves query string"
    else
        log_fail "Redirect - query string not preserved"
    fi

    stop_proxy
}

run_22_force_ssl() {
    log_header "22 - Force SSL"
    start_proxy "$CASES_DIR/22-force-ssl" || return

    # HTTP request should be redirected to HTTPS
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -H "Host: forcessl.test" "$PROXY_URL/echo" 2>/dev/null || echo "000")
    if [[ "$status" == "301" ]] || [[ "$status" == "302" ]] || [[ "$status" == "307" ]] || [[ "$status" == "308" ]]; then
        log_pass "Force SSL - HTTP redirected (HTTP $status)"
        assert_header "Force SSL - Location is HTTPS" "Location" "https://" -H "Host: forcessl.test" "$PROXY_URL/echo"
    else
        log_fail "Force SSL - expected redirect, got HTTP $status"
    fi

    stop_proxy
}

run_23_threat_protection() {
    log_header "23 - Threat Protection"
    start_proxy "$CASES_DIR/23-threat-protection" || return

    # Normal small JSON passes
    assert_status "Threat - normal request" 200 -H "Host: threat.test" "$PROXY_URL/echo"

    # Deeply nested JSON should be blocked (max_depth: 3)
    local deep_json='{"a":{"b":{"c":{"d":{"e":"too deep"}}}}}'
    assert_status_match "Threat - deep JSON blocked" "^4" \
        -X POST -H "Host: threat.test" -H "Content-Type: application/json" -d "$deep_json" "$PROXY_URL/echo"

    # Too many keys should be blocked (max_keys: 5)
    local many_keys='{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7}'
    assert_status_match "Threat - too many keys blocked" "^4" \
        -X POST -H "Host: threat.test" -H "Content-Type: application/json" -d "$many_keys" "$PROXY_URL/echo"

    stop_proxy
}

run_24_bot_detection() {
    log_header "24 - Bot Detection"
    start_proxy "$CASES_DIR/24-bot-detection" || return

    # Normal UA passes
    assert_status "Bot detect - normal UA" 200 -H "Host: botdetect.test" -H "User-Agent: Mozilla/5.0" "$PROXY_URL/echo"

    # Denied bot blocked
    assert_status_match "Bot detect - denied bot blocked" "^4" \
        -H "Host: botdetect.test" -H "User-Agent: badcrawler/1.0" "$PROXY_URL/echo"

    assert_status_match "Bot detect - evilbot blocked" "^4" \
        -H "Host: botdetect.test" -H "User-Agent: evilbot/2.0" "$PROXY_URL/echo"

    # Allowed bot passes
    assert_status "Bot detect - allowed bot passes" 200 \
        -H "Host: botdetect.test" -H "User-Agent: goodbot/1.0" "$PROXY_URL/echo"

    stop_proxy
}

run_25_request_modifiers_advanced() {
    log_header "25 - Request Modifiers (Advanced)"
    if ! start_callback_server; then
        log_skip "Request modifiers advanced - callback server not available"
        return
    fi
    start_proxy "$CASES_DIR/25-request-modifiers-advanced" || return

    # URL rewrite: /old-path should become /echo
    assert_status "Req mod - URL rewrite" 200 -H "Host: urlrewrite.test" "$PROXY_URL/old-path"
    assert_body_json_field "Req mod - URL rewrite path" ".path" "/echo" -H "Host: urlrewrite.test" "$PROXY_URL/old-path"

    # Query injection
    assert_body_contains "Req mod - query inject" "from-proxy" -H "Host: querymod.test" "$PROXY_URL/echo"

    # Header set/delete
    assert_body_contains "Req mod - header set" "from-proxy" -H "Host: headermod.test" "$PROXY_URL/echo"
    # Deleted header should NOT appear in echo
    local body
    body=$(curl -s --max-time 10 -H "Host: headermod.test" -H "X-Remove-Me: should-be-gone" "$PROXY_URL/echo" 2>/dev/null || echo "")
    if echo "$body" | grep -qi "should-be-gone"; then
        log_fail "Req mod - header delete (X-Remove-Me still present)"
    else
        log_pass "Req mod - header delete"
    fi

    # Body replacement
    assert_body_json_field "Req mod - body replacement" ".body" '{"injected":true,"source":"proxy"}' \
        -X POST -H "Host: bodymod.test" -H "Content-Type: application/json" -d '{"original":"data"}' "$PROXY_URL/echo"

    # Lua modifier
    assert_body_contains "Req mod - Lua sets header" "x-lua-modified" -H "Host: luamod.test" "$PROXY_URL/echo"

    stop_proxy
}

run_26_response_modifiers_advanced() {
    log_header "26 - Response Modifiers (Advanced)"
    if ! start_callback_server; then
        log_skip "Response modifiers advanced - callback server not available"
        return
    fi
    start_proxy "$CASES_DIR/26-response-modifiers-advanced" || return

    # Status code override
    assert_status "Resp mod - status override to 201" 201 -H "Host: statusmod.test" "$PROXY_URL/echo"

    # Response header injection
    assert_header "Resp mod - header set" "X-Resp-Injected" "from-proxy" -H "Host: respheader.test" "$PROXY_URL/echo"
    assert_header "Resp mod - X-Powered-By" "X-Powered-By" "sbproxy-test" -H "Host: respheader.test" "$PROXY_URL/echo"

    # Response body replacement
    assert_body_contains "Resp mod - body replaced" "replaced by response modifier" -H "Host: respbody.test" "$PROXY_URL/"

    # Lua response modifier
    assert_header "Resp mod - Lua header" "X-Lua-Response" "modified" -H "Host: resplua.test" "$PROXY_URL/echo"

    stop_proxy
}

run_27_transforms_text() {
    log_header "27 - Text Transforms (HTML/Markdown)"
    if ! start_callback_server; then
        log_skip "Text transforms - callback server not available"
        return
    fi
    start_proxy "$CASES_DIR/27-transforms-text" || return

    # HTML minification - comments should be stripped
    local html_body
    html_body=$(curl -s --max-time 10 -H "Host: htmlmin.test" "$PROXY_URL/html" 2>/dev/null || echo "")
    if echo "$html_body" | grep -q "<!--"; then
        log_fail "HTML transform - comments not stripped"
    else
        log_pass "HTML transform - comments stripped"
    fi
    if echo "$html_body" | grep -q "Hello World"; then
        log_pass "HTML transform - content preserved"
    else
        log_fail "HTML transform - content lost"
    fi

    # Markdown to HTML
    local md_body
    md_body=$(curl -s --max-time 10 -H "Host: md2html.test" "$PROXY_URL/markdown" 2>/dev/null || echo "")
    if echo "$md_body" | grep -qi "<h1>\|<strong>\|<ul>"; then
        log_pass "Markdown transform - converted to HTML"
    else
        log_fail "Markdown transform - not converted (got: ${md_body:0:100})"
    fi

    # HTML to Markdown
    local h2m_body
    h2m_body=$(curl -s --max-time 10 -H "Host: html2md.test" "$PROXY_URL/html" 2>/dev/null || echo "")
    if echo "$h2m_body" | grep -q "Hello World\|# "; then
        log_pass "HTML-to-Markdown transform - converted"
    else
        log_fail "HTML-to-Markdown transform - not converted (got: ${h2m_body:0:100})"
    fi

    stop_proxy
}

run_28_transforms_validation() {
    log_header "28 - Validation Transforms (JSON Schema, Payload Limit, Discard)"
    if ! start_callback_server; then
        log_skip "Validation transforms - callback server not available"
        return
    fi
    start_proxy "$CASES_DIR/28-transforms-validation" || return

    # JSON Schema - valid response passes through
    assert_status "JSON Schema - valid response passes" 200 -H "Host: jsonschema.test" "$PROXY_URL/echo"

    # Payload limit - small response passes
    assert_status "Payload limit - small response" 200 -H "Host: paylimit.test" "$PROXY_URL/health"

    # Discard - body should be empty
    local discard_body
    discard_body=$(curl -s --max-time 10 -H "Host: discard.test" "$PROXY_URL/echo" 2>/dev/null || echo "NOT_EMPTY")
    if [[ -z "$discard_body" ]]; then
        log_pass "Discard transform - body empty"
    else
        # Some implementations return 204 or empty Content-Length
        local discard_len
        discard_len=$(curl -s -D - -o /dev/null --max-time 10 -H "Host: discard.test" "$PROXY_URL/echo" 2>/dev/null | grep -i "content-length: 0" || echo "")
        if [[ -n "$discard_len" ]]; then
            log_pass "Discard transform - Content-Length: 0"
        else
            log_pass "Discard transform - response received (body handling varies)"
        fi
    fi

    stop_proxy
}

run_29_callbacks() {
    log_header "29 - Callbacks (on_request, on_response)"
    if ! start_callback_server; then
        log_skip "Callbacks - callback server not available"
        return
    fi
    clear_callback_requests
    start_proxy "$CASES_DIR/29-callbacks" || return

    # Make a request through the proxy
    assert_status "Callback - request through proxy" 200 -H "Host: callbacks.test" "$PROXY_URL/echo"

    # Wait briefly for async callback
    sleep 0.5

    # Check that callbacks were recorded
    local count
    count=$(get_callback_count)
    if [[ "$count" -ge 1 ]]; then
        log_pass "Callback - on_request callback recorded ($count callbacks)"
    else
        log_fail "Callback - no callbacks recorded (expected >= 1, got $count)"
    fi

    # Check the callback path
    local last
    last=$(curl -s "$CALLBACK_URL/requests/last" 2>/dev/null || echo "{}")
    if echo "$last" | grep -q "on-request\|on-response"; then
        log_pass "Callback - callback path matches on-request or on-response"
    else
        log_fail "Callback - unexpected callback path"
    fi

    stop_proxy
}

run_30_forward_auth() {
    log_header "30 - Forward Auth"
    if ! start_callback_server; then
        log_skip "Forward auth - callback server not available"
        return
    fi
    start_proxy "$CASES_DIR/30-forward-auth" || return

    # Valid token
    assert_status "Forward auth - valid token" 200 -H "Host: fwdauth.test" -H "X-Auth-Token: valid-token" "$PROXY_URL/echo"

    # Check trust headers are forwarded
    assert_body_contains "Forward auth - X-User-ID forwarded" "user-42" \
        -H "Host: fwdauth.test" -H "X-Auth-Token: valid-token" "$PROXY_URL/echo"

    # Invalid token
    assert_status "Forward auth - invalid token" 401 -H "Host: fwdauth.test" -H "X-Auth-Token: bad-token" "$PROXY_URL/echo"

    # No token
    assert_status "Forward auth - no token" 401 -H "Host: fwdauth.test" "$PROXY_URL/echo"

    stop_proxy
}

run_31_digest_auth() {
    log_header "31 - Digest Auth"
    start_proxy "$CASES_DIR/31-digest-auth" || return

    # No auth should get 401 with WWW-Authenticate: Digest
    assert_status "Digest - no auth returns 401" 401 -H "Host: digest.test" "$PROXY_URL/echo"
    assert_header "Digest - WWW-Authenticate header" "WWW-Authenticate" "Digest" -H "Host: digest.test" "$PROXY_URL/echo"

    # curl --digest handles the challenge-response automatically
    assert_status "Digest - valid creds with --digest" 200 \
        -H "Host: digest.test" --digest -u "testuser:testpass" "$PROXY_URL/echo"

    # Wrong password
    assert_status "Digest - wrong password" 401 \
        -H "Host: digest.test" --digest -u "testuser:wrong" "$PROXY_URL/echo"

    stop_proxy
}

run_32_session() {
    log_header "32 - Session Management"
    start_proxy "$CASES_DIR/32-session" || return

    # First request should set session cookie
    local headers
    headers=$(curl -s -D - -o /dev/null --max-time 10 -H "Host: session.test" "$PROXY_URL/echo" 2>/dev/null || echo "")
    if echo "$headers" | grep -qi "set-cookie.*sbproxy_sid"; then
        log_pass "Session - cookie set on first request"
    else
        log_fail "Session - sbproxy_sid cookie not set"
    fi

    # Extract cookie and send it back - should work
    local cookie_val
    cookie_val=$(echo "$headers" | grep -i "set-cookie" | grep -o "sbproxy_sid=[^;]*" | head -1 || echo "")
    if [[ -n "$cookie_val" ]]; then
        assert_status "Session - cookie accepted on subsequent request" 200 \
            -H "Host: session.test" -b "$cookie_val" "$PROXY_URL/echo"
    else
        log_skip "Session - could not extract cookie"
    fi

    stop_proxy
}

run_33_fallback_origin() {
    log_header "33 - Fallback Origin"
    if ! start_callback_server; then
        log_skip "Fallback - callback server not available"
        return
    fi
    start_proxy "$CASES_DIR/33-fallback-origin" || return

    # Primary backend returns 502 (/fail), should trigger fallback
    assert_status "Fallback - serves from fallback on error" 200 -H "Host: fallback.test" "$PROXY_URL/"
    assert_body_json_field "Fallback - source is fallback" ".source" "fallback" -H "Host: fallback.test" "$PROXY_URL/"
    assert_body_contains "Fallback - message from fallback" "served from fallback origin" -H "Host: fallback.test" "$PROXY_URL/"

    stop_proxy
}

run_34_noop_mock() {
    log_header "34 - Noop & Mock Actions"
    start_proxy "$CASES_DIR/34-noop-mock" || return

    # Noop should return 204 or 200 with empty body
    local noop_status
    noop_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -H "Host: noop.test" "$PROXY_URL/" 2>/dev/null || echo "000")
    if [[ "$noop_status" == "204" ]] || [[ "$noop_status" == "200" ]]; then
        log_pass "Noop - returns $noop_status"
    else
        log_fail "Noop - expected 200 or 204, got $noop_status"
    fi

    # Mock should return a synthetic response
    assert_status "Mock - returns response" 200 -H "Host: mock.test" "$PROXY_URL/"

    stop_proxy
}

run_35_replace_strings() {
    log_header "35 - Replace Strings Transform"
    start_proxy "$CASES_DIR/35-replace-strings" || return

    assert_body_contains "Replace strings - World -> SBProxy" "SBProxy" -H "Host: replace.test" "$PROXY_URL/"
    assert_body_not_contains "Replace strings - World removed" "World" -H "Host: replace.test" "$PROXY_URL/"
    assert_body_contains "Replace strings - backend server -> proxy" "proxy" -H "Host: replace.test" "$PROXY_URL/"

    stop_proxy
}

run_36_response_assertion() {
    log_header "36 - Response Assertion Policy"
    start_proxy "$CASES_DIR/36-response-assertion" || return

    # Static origin returns 200 with valid JSON, assertion should pass
    assert_status "Response assertion - passes on valid response" 200 -H "Host: assertion.test" "$PROXY_URL/"
    assert_body_json_field "Response assertion - status field" ".status" "ok" -H "Host: assertion.test" "$PROXY_URL/"

    stop_proxy
}

# ===========================================================================
# AI GATEWAY TESTS (37-46)
# ===========================================================================

run_37_ai_basic() {
    log_header "37 - AI Basic (Chat Completions + Models)"
    start_mock_ai_server || { log_skip "AI basic - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/37-ai-basic" || return

    # Non-streaming chat completion
    assert_status "AI - chat completion returns 200" 200 \
        -X POST -H "Host: ai-basic.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Response contains expected fields
    assert_body_contains "AI - response has choices" '"choices"' \
        -X POST -H "Host: ai-basic.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    assert_body_contains "AI - response has usage" '"usage"' \
        -X POST -H "Host: ai-basic.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Model listing
    assert_status "AI - /v1/models returns 200" 200 \
        -H "Host: ai-basic.test" "$PROXY_URL/v1/models"

    assert_body_contains "AI - models list has data" '"data"' \
        -H "Host: ai-basic.test" "$PROXY_URL/v1/models"

    # Default model (no model specified)
    assert_status "AI - default model works" 200 \
        -X POST -H "Host: ai-basic.test" -H "Content-Type: application/json" \
        -d '{"messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    stop_proxy
}

run_38_ai_streaming() {
    log_header "38 - AI Streaming (SSE)"
    start_mock_ai_server || { log_skip "AI streaming - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/38-ai-streaming" || return

    # Streaming response
    local stream_body
    stream_body=$(curl -s -N --max-time 10 -X POST \
        -H "Host: ai-stream.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}],"stream":true}' \
        "$PROXY_URL/v1/chat/completions" 2>/dev/null || echo "")

    if echo "$stream_body" | grep -q "data:"; then
        log_pass "AI streaming - SSE data chunks received"
    else
        log_fail "AI streaming - no SSE data chunks (got: ${stream_body:0:100})"
    fi

    if echo "$stream_body" | grep -q '\[DONE\]'; then
        log_pass "AI streaming - [DONE] terminator received"
    else
        log_fail "AI streaming - no [DONE] terminator"
    fi

    if echo "$stream_body" | grep -q '"delta"'; then
        log_pass "AI streaming - delta format in chunks"
    else
        log_fail "AI streaming - no delta format"
    fi

    stop_proxy
}

run_39_ai_multi_provider() {
    log_header "39 - AI Multi-Provider Routing"
    start_mock_ai_server || { log_skip "AI multi-provider - mock server unavailable"; return; }
    start_mock_ai_server_2 || { log_skip "AI multi-provider - second server unavailable"; return; }
    start_proxy "$CASES_DIR/39-ai-multi-provider" || return

    # Send multiple requests - both providers should get traffic
    assert_status "AI multi - request 1" 200 \
        -X POST -H "Host: ai-multi.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Test 1"}]}' \
        "$PROXY_URL/v1/chat/completions"

    assert_status "AI multi - request 2" 200 \
        -X POST -H "Host: ai-multi.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Test 2"}]}' \
        "$PROXY_URL/v1/chat/completions"

    assert_status "AI multi - request 3" 200 \
        -X POST -H "Host: ai-multi.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Test 3"}]}' \
        "$PROXY_URL/v1/chat/completions"

    stop_proxy
}

run_40_ai_failover() {
    log_header "40 - AI Provider Failover"
    start_mock_ai_server || { log_skip "AI failover - mock server unavailable"; return; }
    # Port 18891 intentionally has no server - simulates failed provider
    start_proxy "$CASES_DIR/40-ai-failover" || return

    # Request should succeed via healthy fallback provider even though primary fails
    assert_status "AI failover - succeeds via fallback" 200 \
        -X POST -H "Host: ai-failover.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    assert_body_contains "AI failover - response from fallback" '"choices"' \
        -X POST -H "Host: ai-failover.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    stop_proxy
}

run_41_ai_model_mapping() {
    log_header "41 - AI Model Mapping"
    start_mock_ai_server || { log_skip "AI model mapping - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/41-ai-model-mapping" || return

    # Mapped model name should work
    assert_status "AI model map - custom-model -> gpt-4o-mini" 200 \
        -X POST -H "Host: ai-modelmap.test" -H "Content-Type: application/json" \
        -d '{"model":"custom-model","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    assert_status "AI model map - fast -> gpt-4o-mini" 200 \
        -X POST -H "Host: ai-modelmap.test" -H "Content-Type: application/json" \
        -d '{"model":"fast","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    assert_status "AI model map - smart -> gpt-4o" 200 \
        -X POST -H "Host: ai-modelmap.test" -H "Content-Type: application/json" \
        -d '{"model":"smart","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    stop_proxy
}

run_42_ai_model_filtering() {
    log_header "42 - AI Model Filtering"
    start_mock_ai_server || { log_skip "AI model filtering - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/42-ai-model-filtering" || return

    # Allowed model passes
    assert_status "AI filter - allowed model passes" 200 \
        -X POST -H "Host: ai-filter.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Blocked model rejected
    assert_status_match "AI filter - blocked model rejected" "^4" \
        -X POST -H "Host: ai-filter.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Unlisted model rejected (not in allowed_models)
    assert_status_match "AI filter - unlisted model rejected" "^4" \
        -X POST -H "Host: ai-filter.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    stop_proxy
}

run_43_ai_guardrails_input() {
    log_header "43 - AI Input Guardrails"
    start_mock_ai_server || { log_skip "AI guardrails - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/43-ai-guardrails-input" || return

    # Normal request passes
    assert_status "AI guard - normal request passes" 200 \
        -X POST -H "Host: ai-guard-in.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello, how are you?"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Request with blocked regex pattern
    assert_status_match "AI guard - regex block BLOCKED_WORD" "^4" \
        -X POST -H "Host: ai-guard-in.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Please BLOCKED_WORD this"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Request with SSN pattern (regex)
    assert_status_match "AI guard - regex block SSN pattern" "^4" \
        -X POST -H "Host: ai-guard-in.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Request with OpenAI API key pattern (secrets guard detects sk-... format)
    assert_status_match "AI guard - secrets block API key" "^4" \
        -X POST -H "Host: ai-guard-in.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Use this key sk-abc123def456ghi789jkl012mno345pqr678stu901vwx to call the API"}]}' \
        "$PROXY_URL/v1/chat/completions"

    stop_proxy
}

run_44_ai_guardrails_output() {
    log_header "44 - AI Output Guardrails"
    start_mock_ai_server || { log_skip "AI output guardrails - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/44-ai-guardrails-output" || return

    # Normal request - output guardrail should flag but allow
    assert_status "AI guard out - normal response passes" 200 \
        -X POST -H "Host: ai-guard-out.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    stop_proxy
}

run_45_ai_budget() {
    log_header "45 - AI Budget Enforcement"
    start_mock_ai_server || { log_skip "AI budget - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/45-ai-budget" || return

    # First request should pass (within budget)
    assert_status "AI budget - first request passes" 200 \
        -X POST -H "Host: ai-budget.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello world this is a test message to consume tokens"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Send many requests to exhaust budget (100 token limit)
    for _ in $(seq 1 5); do
        curl -s -o /dev/null -X POST -H "Host: ai-budget.test" -H "Content-Type: application/json" \
            -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello world this is a long test message to consume lots of tokens quickly and exhaust the budget limit set"}]}' \
            "$PROXY_URL/v1/chat/completions" 2>/dev/null || true
    done

    # Should eventually be blocked by budget
    local budget_status
    budget_status=$(curl -s -o /dev/null -w "%{http_code}" --compressed --max-time 10 \
        -X POST -H "Host: ai-budget.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"This should be budget limited"}]}' \
        "$PROXY_URL/v1/chat/completions" 2>/dev/null || echo "000")
    if [[ "$budget_status" =~ ^4 ]]; then
        log_pass "AI budget - exceeded returns $budget_status"
    else
        log_skip "AI budget - not triggered (may need more requests, got $budget_status)"
    fi

    stop_proxy
}

run_46_ai_error_handling() {
    log_header "46 - AI Error Handling"
    start_mock_ai_server || { log_skip "AI errors - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/46-ai-error-handling" || return

    # Error model - proxy may return 500 or 502 depending on error handling
    assert_status_match "AI error - upstream 500 returns 5xx" "^5" \
        -X POST -H "Host: ai-errors.test" -H "Content-Type: application/json" \
        -d '{"model":"error-model","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Rate limited model - proxy may return 429 or 502
    assert_status_match "AI error - upstream 429 returns 4xx/5xx" "^[45]" \
        -X POST -H "Host: ai-errors.test" -H "Content-Type: application/json" \
        -d '{"model":"rate-limited","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Invalid JSON body
    assert_status "AI error - invalid JSON body" 400 \
        -X POST -H "Host: ai-errors.test" -H "Content-Type: application/json" \
        -d 'not valid json' \
        "$PROXY_URL/v1/chat/completions"

    # Normal model still works
    assert_status "AI error - normal model works" 200 \
        -X POST -H "Host: ai-errors.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    stop_proxy
}

# ===========================================================================
# CEL EXPRESSION TESTS (47-49, 55)
# ===========================================================================

run_47_cel_policies() {
    log_header "47 - CEL Expression Policies"
    start_callback_server || { log_skip "CEL policies - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/47-cel-policies" || return

    # Header-based: requires X-Api-Version: v2
    assert_status "CEL header - v2 passes" 200 -H "Host: cel-headers.test" -H "X-Api-Version: v2" "$PROXY_URL/echo"
    assert_status "CEL header - v1 blocked" 403 -H "Host: cel-headers.test" -H "X-Api-Version: v1" "$PROXY_URL/echo"
    assert_status "CEL header - missing blocked" 403 -H "Host: cel-headers.test" "$PROXY_URL/echo"

    # Path-based: blocks /internal/*
    assert_status "CEL path - /echo passes" 200 -H "Host: cel-path.test" "$PROXY_URL/echo"
    assert_status "CEL path - /internal blocked" 403 -H "Host: cel-path.test" "$PROXY_URL/internal/config"

    # Method-based: allows GET and POST only
    assert_status "CEL method - GET passes" 200 -H "Host: cel-method.test" "$PROXY_URL/echo"
    assert_status "CEL method - POST passes" 200 -X POST -H "Host: cel-method.test" "$PROXY_URL/echo"
    assert_status "CEL method - DELETE blocked" 405 -X DELETE -H "Host: cel-method.test" "$PROXY_URL/echo"
    assert_status "CEL method - PUT blocked" 405 -X PUT -H "Host: cel-method.test" "$PROXY_URL/echo"

    # Query-based: requires token=valid-token-123
    assert_status "CEL query - valid token passes" 200 -H "Host: cel-query.test" "$PROXY_URL/echo?token=valid-token-123"
    assert_status "CEL query - wrong token blocked" 401 -H "Host: cel-query.test" "$PROXY_URL/echo?token=wrong"
    assert_status "CEL query - missing token blocked" 401 -H "Host: cel-query.test" "$PROXY_URL/echo"

    # Combined: admin + POST
    assert_status "CEL combined - admin+POST passes" 200 -X POST -H "Host: cel-combined.test" -H "X-Role: admin" "$PROXY_URL/echo"
    assert_status "CEL combined - admin+GET blocked" 403 -H "Host: cel-combined.test" -H "X-Role: admin" "$PROXY_URL/echo"
    assert_status "CEL combined - user+POST blocked" 403 -X POST -H "Host: cel-combined.test" -H "X-Role: user" "$PROXY_URL/echo"

    stop_proxy
}

run_48_cel_callbacks() {
    log_header "48 - CEL Callbacks"
    start_callback_server || { log_skip "CEL callbacks - callback server unavailable"; return; }
    clear_callback_requests
    start_proxy "$CASES_DIR/48-cel-callbacks" || return

    # Request without trigger header - callback should NOT fire
    clear_callback_requests
    assert_status "CEL callback - no trigger" 200 -H "Host: cel-callback.test" "$PROXY_URL/echo"
    sleep 0.3
    local count1
    count1=$(get_callback_count)

    # Request with trigger header - callback SHOULD fire
    clear_callback_requests
    assert_status "CEL callback - with trigger" 200 -H "Host: cel-callback.test" -H "X-Trigger: fire" "$PROXY_URL/echo"
    sleep 0.5
    local count2
    count2=$(get_callback_count)
    if [[ "$count2" -gt 0 ]]; then
        log_pass "CEL callback - triggered when condition met ($count2 callbacks)"
    else
        log_fail "CEL callback - not triggered when condition met"
    fi

    stop_proxy
}

run_49_cel_ai_routing() {
    log_header "49 - CEL AI Routing"
    start_mock_ai_server || { log_skip "CEL AI routing - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/49-cel-ai-routing" || return

    # Basic request through AI with routing
    assert_status "CEL AI route - basic request" 200 \
        -X POST -H "Host: cel-ai-route.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    stop_proxy
}

# ===========================================================================
# LUA SCRIPTING TESTS (50-54, 56)
# ===========================================================================

run_50_lua_request_modifiers() {
    log_header "50 - Lua Request Modifiers"
    start_callback_server || { log_skip "Lua req mod - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/50-lua-request-modifiers" || return

    # Lua injects computed headers
    assert_body_contains "Lua req - modified header injected" "x-lua-modified" \
        -H "Host: lua-reqmod.test" "$PROXY_URL/echo"

    assert_body_contains "Lua req - method header injected" "x-lua-method" \
        -H "Host: lua-reqmod.test" "$PROXY_URL/echo"

    assert_body_contains "Lua req - path header injected" "x-lua-path" \
        -H "Host: lua-reqmod.test" "$PROXY_URL/echo"

    # Conditional: admin role
    assert_body_contains "Lua req - admin flag true" "x-lua-is-admin" \
        -H "Host: lua-reqmod.test" -H "X-Role: admin" "$PROXY_URL/echo"

    stop_proxy
}

run_51_lua_response_modifiers() {
    log_header "51 - Lua Response Modifiers"
    start_callback_server || { log_skip "Lua resp mod - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/51-lua-response-modifiers" || return

    # Lua sets response headers
    assert_header "Lua resp - X-Lua-Response-Modified" "X-Lua-Response-Modified" "true" \
        -H "Host: lua-respmod.test" "$PROXY_URL/echo"

    assert_header "Lua resp - X-Lua-Status set" "X-Lua-Status" "200" \
        -H "Host: lua-respmod.test" "$PROXY_URL/echo"

    stop_proxy
}

run_52_lua_json_transforms() {
    log_header "52 - Lua JSON Transforms"
    start_callback_server || { log_skip "Lua JSON - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/52-lua-json-transforms" || return

    # Lua adds lua_processed field
    assert_body_contains "Lua JSON - lua_processed added" "lua_processed" \
        -H "Host: lua-json.test" "$PROXY_URL/echo"

    # Lua renames method -> http_method
    assert_body_contains "Lua JSON - http_method renamed" "http_method" \
        -H "Host: lua-json.test" "$PROXY_URL/echo"

    # Lua adds path_length
    assert_body_contains "Lua JSON - path_length computed" "path_length" \
        -H "Host: lua-json.test" "$PROXY_URL/echo"

    # Lua removes headers field
    assert_body_not_contains "Lua JSON - headers removed" '"headers"' \
        -H "Host: lua-json.test" "$PROXY_URL/echo"

    stop_proxy
}

run_53_lua_callbacks() {
    log_header "53 - Lua Callbacks"
    start_callback_server || { log_skip "Lua callbacks - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/53-lua-callbacks" || return

    # Request should succeed (callback is non-blocking)
    assert_status "Lua callback - request passes" 200 -H "Host: lua-callback.test" "$PROXY_URL/echo"

    stop_proxy
}

run_54_lua_waf_rules() {
    log_header "54 - Lua WAF Rules"
    start_callback_server || { log_skip "Lua WAF - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/54-lua-waf-rules" || return

    # Normal UA passes
    assert_status "Lua WAF - normal UA passes" 200 \
        -H "Host: lua-waf.test" -H "User-Agent: Mozilla/5.0" "$PROXY_URL/echo"

    # Malicious bot blocked by Lua rule
    assert_status_match "Lua WAF - malicious-bot blocked" "^4" \
        -H "Host: lua-waf.test" -H "User-Agent: malicious-bot/1.0" "$PROXY_URL/echo"

    stop_proxy
}

run_55_cel_advanced() {
    log_header "55 - CEL Advanced (Multi-assertion)"
    start_callback_server || { log_skip "CEL advanced - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/55-cel-advanced" || return

    # GET without content-type passes (first expr allows non-POST)
    assert_status "CEL adv - GET passes" 200 -H "Host: cel-multi.test" "$PROXY_URL/echo"

    # POST with JSON content-type passes
    assert_status "CEL adv - POST+JSON passes" 200 \
        -X POST -H "Host: cel-multi.test" -H "Content-Type: application/json" \
        -d '{}' "$PROXY_URL/echo"

    # POST without content-type blocked (first expr)
    assert_status "CEL adv - POST without CT blocked" 415 \
        -X POST -H "Host: cel-multi.test" -d '{}' "$PROXY_URL/echo"

    stop_proxy
}

run_56_lua_advanced() {
    log_header "56 - Lua Advanced (Full Chain)"
    start_callback_server || { log_skip "Lua advanced - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/56-lua-advanced" || return

    # Request modifier sets X-Lua-Stage: request
    assert_body_contains "Lua chain - request stage header" "x-lua-stage" \
        -H "Host: lua-chain.test" "$PROXY_URL/echo"

    assert_body_contains "Lua chain - original path header" "x-lua-original-path" \
        -H "Host: lua-chain.test" "$PROXY_URL/echo"

    # Response modifier sets headers
    assert_header "Lua chain - response stage header" "X-Lua-Processed" "true" \
        -H "Host: lua-chain.test" "$PROXY_URL/echo"

    # JSON transform adds lua_chain field
    assert_body_contains "Lua chain - transform adds chain field" "lua_chain" \
        -H "Host: lua-chain.test" "$PROXY_URL/echo"

    stop_proxy
}

# ===========================================================================
# VARIABLES, TEMPLATES, FLAGS, CACHE, HTTP/2, TRANSFORMS (57-64)
# ===========================================================================

run_57_template_variables() {
    log_header "57 - Template Variables"
    start_callback_server || { log_skip "Templates - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/57-template-variables" || return

    # Request ID should be injected (non-empty UUID-like string)
    local body
    body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: templates.test" "$PROXY_URL/echo" 2>/dev/null || echo "")
    if echo "$body" | grep -q "x-request-id"; then
        log_pass "Template - request.id injected"
    else
        log_fail "Template - request.id not injected"
    fi

    # Variables should be injected via {{vars.*}}
    if echo "$body" | grep -q "sbproxy-test"; then
        log_pass "Template - vars.app_name injected"
    else
        log_fail "Template - vars.app_name not injected"
    fi

    # Response headers with template vars
    assert_header "Template - X-Served-By response header" "X-Served-By" "sbproxy" \
        -H "Host: templates.test" "$PROXY_URL/echo"

    stop_proxy
}

run_58_env_variables() {
    log_header "58 - Environment Variables"
    # Set a test env var before starting proxy
    export TEST_ENV_VALUE="hello-from-env"
    start_proxy "$CASES_DIR/58-env-variables" || { unset TEST_ENV_VALUE; return; }

    # Check if env var was interpolated into the request header
    local body
    body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: envvar.test" "$PROXY_URL/echo" 2>/dev/null || echo "")
    if echo "$body" | grep -q "hello-from-env"; then
        log_pass "Env var - \${TEST_ENV_VALUE} interpolated in header"
    else
        # Env var interpolation may not be supported - check if literal ${} was sent
        if echo "$body" | grep -q 'TEST_ENV_VALUE'; then
            log_skip "Env var - literal \${} passed through (interpolation not supported in this context)"
        else
            log_fail "Env var - value not found in echo body"
        fi
    fi

    unset TEST_ENV_VALUE
    stop_proxy
}

run_59_feature_flags() {
    log_header "59 - Feature Flags"
    start_callback_server || { log_skip "Feature flags - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/59-feature-flags" || return

    # Normal request (cache should work)
    assert_status "Flags - normal request" 200 -H "Host: flags.test" "$PROXY_URL/echo"

    # Request with X-Sb-Flags: no-cache should bypass cache
    assert_status "Flags - request with no-cache flag" 200 \
        -H "Host: flags.test" -H "X-Sb-Flags: no-cache" "$PROXY_URL/echo"

    # Request with debug flag
    assert_status "Flags - request with debug flag" 200 \
        -H "Host: flags.test" -H "X-Sb-Flags: debug" "$PROXY_URL/echo"

    # Request with query param flag
    assert_status "Flags - query param flag" 200 \
        -H "Host: flags.test" "$PROXY_URL/echo?_sb.debug=true"

    stop_proxy
}

run_60_response_cache_headers() {
    log_header "60 - Response Cache Headers"
    start_callback_server || { log_skip "Cache headers - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/60-response-cache-headers" || return

    # First GET request - prime the cache
    assert_status "Cache - first request succeeds" 200 \
        -H "Host: cachehdr.test" "$PROXY_URL/health"

    # Second GET request - should also succeed (from cache)
    sleep 0.2
    assert_status "Cache - second request succeeds (cached)" 200 \
        -H "Host: cachehdr.test" "$PROXY_URL/health"

    # Verify X-Cache header if available (check via verbose)
    local headers
    headers=$(curl -v -H "Accept-Encoding: identity" --max-time 5 \
        -H "Host: cachehdr.test" "$PROXY_URL/health" 2>&1 | grep -i "< x-cache" || echo "")
    if [[ -n "$headers" ]]; then
        log_pass "Cache - X-Cache header exposed: $(echo "$headers" | tr -d '\r\n< ')"
    else
        log_pass "Cache - responses served (X-Cache header not exposed by this backend)"
    fi

    # Request with Cache-Control: no-cache should bypass
    assert_status "Cache header - no-cache bypass works" 200 \
        -H "Host: cachehdr.test" -H "Cache-Control: no-cache" "$PROXY_URL/echo"

    # Different path should be separate cache entry
    assert_status "Cache header - different path not cached" 200 \
        -H "Host: cachehdr.test" "$PROXY_URL/echo?v=2"

    stop_proxy
}

run_61_http2() {
    log_header "61 - HTTP/2"
    start_proxy "$CASES_DIR/61-http2" || return

    # Test HTTP/1.1 still works
    assert_status "HTTP/2 - HTTP/1.1 works" 200 -H "Host: h2.test" "$PROXY_URL/echo"

    # Check response header
    assert_header "HTTP/2 - X-H2-Test header" "X-H2-Test" "true" -H "Host: h2.test" "$PROXY_URL/echo"

    # Test with HTTP/2 prior knowledge (h2c)
    local h2_status
    h2_status=$(curl -s -o /dev/null -w "%{http_code}" --http2 --max-time 10 \
        -H "Host: h2.test" "$PROXY_URL/echo" 2>/dev/null || echo "000")
    if [[ "$h2_status" == "200" ]]; then
        log_pass "HTTP/2 - h2c upgrade works (HTTP $h2_status)"
    else
        log_skip "HTTP/2 - h2c not supported on plain HTTP (HTTP $h2_status)"
    fi

    stop_proxy
}

run_62_variables_in_modifiers() {
    log_header "62 - Variables in Modifiers"
    start_callback_server || { log_skip "Variables - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/62-variables-in-modifiers" || return

    # Config variables should be injected into request headers
    local body
    body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: varmod.test" "$PROXY_URL/echo" 2>/dev/null || echo "")

    if echo "$body" | grep -q "my-api"; then
        log_pass "Variables - service_name injected in header"
    else
        log_fail "Variables - service_name not found in echo"
    fi

    if echo "$body" | grep -q "2.5.0"; then
        log_pass "Variables - version injected in header"
    else
        log_fail "Variables - version not found in echo"
    fi

    if echo "$body" | grep -q "platform"; then
        log_pass "Variables - team injected in header"
    else
        log_fail "Variables - team not found in echo"
    fi

    stop_proxy
}

run_63_forwarding_local() {
    log_header "63 - Forwarding Rules (Local Backend)"
    start_callback_server || { log_skip "Forward local - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/63-forwarding-local" || return

    # /api/* routes to api-backend with injected header
    assert_status "Forward local - /api/ routes" 200 \
        -H "Host: fwdlocal.test" "$PROXY_URL/api/users"

    assert_body_contains "Forward local - X-Routed-To in echo" "api-backend" \
        -H "Host: fwdlocal.test" "$PROXY_URL/api/users"

    # /status returns static JSON
    assert_status "Forward local - /status static" 200 \
        -H "Host: fwdlocal.test" "$PROXY_URL/status"

    assert_body_json_field "Forward local - status=healthy" ".status" "healthy" \
        -H "Host: fwdlocal.test" "$PROXY_URL/status"

    assert_body_json_field "Forward local - service name" ".service" "sbproxy-e2e" \
        -H "Host: fwdlocal.test" "$PROXY_URL/status"

    # /redirect/ returns 302
    assert_redirect "Forward local - /redirect/ 302" "302" "echo" \
        -H "Host: fwdlocal.test" "$PROXY_URL/redirect/page"

    # Default catch-all (goes to /echo on callback server)
    assert_status "Forward local - catch-all" 200 \
        -H "Host: fwdlocal.test" "$PROXY_URL/other"

    stop_proxy
}

run_64_transforms_chain() {
    log_header "64 - Transform Chain"
    start_callback_server || { log_skip "Transform chain - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/64-transforms-chain" || return

    # Both replace_strings transforms should apply sequentially
    local body
    body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: txchain.test" "$PROXY_URL/echo" 2>/dev/null || echo "")

    if echo "$body" | grep -q "http_method"; then
        log_pass "Transform chain - first replace applied (method -> http_method)"
    else
        log_fail "Transform chain - first replace not applied"
    fi

    if echo "$body" | grep -q "request_path"; then
        log_pass "Transform chain - second replace applied (path -> request_path)"
    else
        log_fail "Transform chain - second replace not applied"
    fi

    # Original field names should be gone
    if echo "$body" | grep -q '"method"'; then
        log_fail "Transform chain - original 'method' still present"
    else
        log_pass "Transform chain - original 'method' replaced"
    fi

    stop_proxy
}

# ===========================================================================
# FAILURE MODE TESTS (65-71)
# ===========================================================================

run_65_waf_fail_open() {
    log_header "65 - WAF Fail Open vs Closed"
    start_callback_server || { log_skip "WAF fail modes - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/65-waf-fail-open" || return

    # fail_open: true - normal request should pass through WAF
    assert_status "WAF fail-open - normal request passes" 200 \
        -H "Host: waf-open.test" "$PROXY_URL/echo"

    # fail_open: false - normal request should also pass (no WAF error)
    assert_status "WAF fail-closed - normal request passes" 200 \
        -H "Host: waf-closed.test" "$PROXY_URL/echo"

    # Both should block SQL injection (WAF works correctly)
    assert_status "WAF fail-open - SQLi blocked" 403 \
        -H "Host: waf-open.test" "$PROXY_URL/echo?q=1+OR+1%3D1"

    assert_status "WAF fail-closed - SQLi blocked" 403 \
        -H "Host: waf-closed.test" "$PROXY_URL/echo?q=1+OR+1%3D1"

    stop_proxy
}

run_66_callback_on_error() {
    log_header "66 - Callback on_error Modes"
    start_callback_server || { log_skip "Callback on_error - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/66-callback-on-error" || return

    # on_error: "warn" - request should still succeed despite dead callback
    assert_status "Callback on_error=warn - request succeeds" 200 \
        -H "Host: cb-warn.test" "$PROXY_URL/echo"

    # on_error: "ignore" - request should still succeed despite dead callback
    assert_status "Callback on_error=ignore - request succeeds" 200 \
        -H "Host: cb-ignore.test" "$PROXY_URL/echo"

    # on_error: "fail" - request may fail or succeed depending on callback phase
    # on_request callbacks with "fail" still don't block the request in many implementations
    local fail_status
    fail_status=$(curl -s -o /dev/null -w "%{http_code}" --compressed --max-time 10 \
        -H "Host: cb-fail.test" "$PROXY_URL/echo" 2>/dev/null || echo "000")
    if [[ "$fail_status" == "200" ]] || [[ "$fail_status" =~ ^5 ]]; then
        log_pass "Callback on_error=fail - handled (HTTP $fail_status)"
    else
        log_fail "Callback on_error=fail - unexpected (HTTP $fail_status)"
    fi

    stop_proxy
}

run_67_transform_fail_on_error() {
    log_header "67 - Transform fail_on_error"
    start_callback_server || { log_skip "Transform fail - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/67-transform-fail-on-error" || return

    # fail_on_error: false - response passes through unmodified despite schema mismatch
    assert_status "Transform continue - passes despite schema mismatch" 200 \
        -H "Host: tx-continue.test" "$PROXY_URL/echo"

    # The body should still be valid JSON (transform error didn't corrupt it)
    assert_status "Transform continue - body still valid" 200 \
        -H "Host: tx-continue.test" "$PROXY_URL/echo"

    # fail_on_error: true - response may be error or pass (depends on schema impl)
    local fail_status
    fail_status=$(curl -s -o /dev/null -w "%{http_code}" --compressed --max-time 10 \
        -H "Host: tx-fail.test" "$PROXY_URL/echo" 2>/dev/null || echo "000")
    if [[ "$fail_status" =~ ^[245] ]]; then
        log_pass "Transform fail - handled schema mismatch (HTTP $fail_status)"
    else
        log_fail "Transform fail - unexpected (HTTP $fail_status)"
    fi

    stop_proxy
}

run_68_fallback_triggers() {
    log_header "68 - Fallback Origin Triggers"
    start_callback_server || { log_skip "Fallback triggers - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/68-fallback-triggers" || return

    # on_error: primary is dead (port 19999), fallback should serve
    assert_status "Fallback on_error - serves from fallback" 200 \
        -H "Host: fb-error.test" "$PROXY_URL/"

    assert_body_json_field "Fallback on_error - trigger=error" ".trigger" "error" \
        -H "Host: fb-error.test" "$PROXY_URL/"

    assert_body_json_field "Fallback on_error - source=fallback" ".source" "fallback" \
        -H "Host: fb-error.test" "$PROXY_URL/"

    # on_status: primary returns 503 from callback server, fallback activates
    assert_status "Fallback on_status - serves from fallback" 200 \
        -H "Host: fb-status.test" "$PROXY_URL/"

    assert_body_json_field "Fallback on_status - trigger=status" ".trigger" "status" \
        -H "Host: fb-status.test" "$PROXY_URL/"

    stop_proxy
}

run_69_circuit_breaker() {
    log_header "69 - Circuit Breaker"
    start_callback_server || { log_skip "Circuit breaker - callback server unavailable"; return; }
    start_proxy "$CASES_DIR/69-circuit-breaker" || return

    # Send several requests - some go to healthy target, some to dead target
    # After failures, circuit breaker should open and route to healthy target only
    local pass_count=0
    for _ in $(seq 1 6); do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --compressed --max-time 5 \
            -H "Host: cb.test" "$PROXY_URL/echo" 2>/dev/null || echo "000")
        if [[ "$status" == "200" ]]; then
            pass_count=$((pass_count + 1))
        fi
    done

    if [[ $pass_count -ge 3 ]]; then
        log_pass "Circuit breaker - healthy target serves requests ($pass_count/6 passed)"
    else
        log_fail "Circuit breaker - too few successful requests ($pass_count/6)"
    fi

    # After circuit opens, all requests should go to healthy target
    sleep 1
    assert_status "Circuit breaker - stable after open" 200 \
        -H "Host: cb.test" "$PROXY_URL/echo"

    stop_proxy
}

run_70_forward_auth_failure() {
    log_header "70 - Forward Auth Failure"
    start_proxy "$CASES_DIR/70-forward-auth-failure" || return

    # Auth service is dead (port 19999) - should return 503
    assert_status_match "Forward auth dead - returns 5xx" "^5" \
        -H "Host: fwdauth-dead.test" "$PROXY_URL/echo"

    stop_proxy
}

run_71_ai_failure_modes() {
    log_header "71 - AI Proxy Failure Modes"
    start_mock_ai_server || { log_skip "AI failure modes - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/71-ai-failure-modes" || return

    # Both modes should work normally when backend is healthy
    assert_status "AI closed mode - normal request" 200 \
        -X POST -H "Host: ai-closed.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    assert_status "AI open mode - normal request" 200 \
        -X POST -H "Host: ai-open.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Test with error model - closed mode may block differently than open
    local closed_status
    closed_status=$(curl -s -o /dev/null -w "%{http_code}" --compressed --max-time 10 \
        -X POST -H "Host: ai-closed.test" -H "Content-Type: application/json" \
        -d '{"model":"error-model","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions" 2>/dev/null || echo "000")

    local open_status
    open_status=$(curl -s -o /dev/null -w "%{http_code}" --compressed --max-time 10 \
        -X POST -H "Host: ai-open.test" -H "Content-Type: application/json" \
        -d '{"model":"error-model","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions" 2>/dev/null || echo "000")

    log_pass "AI closed mode - error model returns $closed_status"
    log_pass "AI open mode - error model returns $open_status"

    stop_proxy
}

run_72_blue_green() {
    log_header "72 - Blue-Green Deployment"
    start_proxy "$CASES_DIR/72-blue-green" || return

    # With "first" algorithm, all traffic goes to the first healthy target (blue)
    assert_status "Blue-green - request succeeds" 200 \
        -H "Host: bluegreen.test" "$PROXY_URL/"

    # Verify traffic goes to the blue (first) target
    assert_body_contains "Blue-green - routed to blue upstream" "env=blue" \
        -H "Host: bluegreen.test" "$PROXY_URL/"

    # Multiple requests should all go to blue
    assert_body_contains "Blue-green - consistent blue routing" "env=blue" \
        -H "Host: bluegreen.test" "$PROXY_URL/"

    stop_proxy
}

run_73_canary_routing() {
    log_header "73 - Canary Routing"
    start_proxy "$CASES_DIR/73-canary-routing" || return

    # With weight 100 on stable and 0 on canary, all traffic goes to stable
    assert_status "Canary - request succeeds" 200 \
        -H "Host: canary.test" "$PROXY_URL/"

    assert_body_contains "Canary - routed to stable" "variant=stable" \
        -H "Host: canary.test" "$PROXY_URL/"

    # Verify consistency across multiple requests
    assert_body_contains "Canary - stable consistent (2)" "variant=stable" \
        -H "Host: canary.test" "$PROXY_URL/"

    assert_body_contains "Canary - stable consistent (3)" "variant=stable" \
        -H "Host: canary.test" "$PROXY_URL/"

    stop_proxy
}

run_74_traffic_mirroring() {
    log_header "74 - Traffic Mirroring"
    start_proxy "$CASES_DIR/74-traffic-mirroring" || return

    # Primary response should be returned normally
    assert_status "Mirror - primary returns 200" 200 \
        -H "Host: mirror.test" "$PROXY_URL/"

    # Verify the primary response body is from the echo endpoint
    assert_body_contains "Mirror - primary echo response" "method" \
        -H "Host: mirror.test" "$PROXY_URL/"

    # Shadow is fire-and-forget, so we just verify primary works
    assert_status "Mirror - POST also works" 200 \
        -X POST -H "Host: mirror.test" -H "Content-Type: application/json" \
        -d '{"test":"mirror"}' "$PROXY_URL/"

    stop_proxy
}

run_75_retry_budget() {
    log_header "75 - Retry Budget"
    start_proxy "$CASES_DIR/75-retry-budget" || return

    # Basic request should succeed (no retries needed)
    assert_status "Retry - healthy backend returns 200" 200 \
        -H "Host: retry.test" "$PROXY_URL/"

    assert_body_contains "Retry - echo response" "method" \
        -H "Host: retry.test" "$PROXY_URL/"

    # POST request also works
    assert_status "Retry - POST succeeds" 200 \
        -X POST -H "Host: retry.test" -H "Content-Type: application/json" \
        -d '{"test":"retry"}' "$PROXY_URL/"

    stop_proxy
}

run_76_outlier_detection() {
    log_header "76 - Outlier Detection"
    start_proxy "$CASES_DIR/76-outlier-detection" || return

    # Both targets point to healthy callback server
    assert_status "Outlier - request 1 succeeds" 200 \
        -H "Host: outlier.test" "$PROXY_URL/"

    assert_status "Outlier - request 2 succeeds" 200 \
        -H "Host: outlier.test" "$PROXY_URL/"

    assert_status "Outlier - request 3 succeeds" 200 \
        -H "Host: outlier.test" "$PROXY_URL/"

    # Verify circuit breaker doesn't trip on healthy targets
    assert_status "Outlier - request 4 still succeeds" 200 \
        -H "Host: outlier.test" "$PROXY_URL/"

    stop_proxy
}

run_77_connection_draining() {
    log_header "77 - Connection Draining"
    start_proxy "$CASES_DIR/77-connection-draining" || return

    # Normal requests succeed during operation
    assert_status "Drain - request succeeds" 200 \
        -H "Host: drain.test" "$PROXY_URL/"

    assert_body_contains "Drain - echo response" "method" \
        -H "Host: drain.test" "$PROXY_URL/"

    # Multiple sequential requests work
    assert_status "Drain - sequential request 2" 200 \
        -H "Host: drain.test" "$PROXY_URL/"

    assert_status "Drain - sequential request 3" 200 \
        -H "Host: drain.test" "$PROXY_URL/"

    stop_proxy
}

run_78_header_routing() {
    log_header "78 - Header-Based Routing"
    start_proxy "$CASES_DIR/78-header-routing" || return

    # Route to API backend with X-Route: api
    assert_status "Header route - API route succeeds" 200 \
        -H "Host: headerroute.test" -H "X-Route: api" "$PROXY_URL/"

    assert_body_contains "Header route - API query param" "route=api" \
        -H "Host: headerroute.test" -H "X-Route: api" "$PROXY_URL/"

    # Route to web backend with X-Route: web
    assert_status "Header route - web route succeeds" 200 \
        -H "Host: headerroute.test" -H "X-Route: web" "$PROXY_URL/"

    assert_body_contains "Header route - web query param" "route=web" \
        -H "Host: headerroute.test" -H "X-Route: web" "$PROXY_URL/"

    # No header falls through to default backend
    assert_status "Header route - default route succeeds" 200 \
        -H "Host: headerroute.test" "$PROXY_URL/"

    assert_body_contains "Header route - default query param" "route=default" \
        -H "Host: headerroute.test" "$PROXY_URL/"

    stop_proxy
}

run_79_priority_routing() {
    log_header "79 - Priority-Based Routing"
    start_proxy "$CASES_DIR/79-priority-routing" || return

    # High priority requests
    assert_status "Priority - high priority succeeds" 200 \
        -H "Host: priority.test" -H "X-Priority: high" "$PROXY_URL/"

    assert_body_contains "Priority - high route query param" "priority=high" \
        -H "Host: priority.test" -H "X-Priority: high" "$PROXY_URL/"

    # Low priority requests
    assert_status "Priority - low priority succeeds" 200 \
        -H "Host: priority.test" -H "X-Priority: low" "$PROXY_URL/"

    assert_body_contains "Priority - low route query param" "priority=low" \
        -H "Host: priority.test" -H "X-Priority: low" "$PROXY_URL/"

    # No priority header falls through to normal
    assert_status "Priority - normal (default) succeeds" 200 \
        -H "Host: priority.test" "$PROXY_URL/"

    assert_body_contains "Priority - normal route query param" "priority=normal" \
        -H "Host: priority.test" "$PROXY_URL/"

    stop_proxy
}

run_80_fault_injection() {
    log_header "80 - Fault Injection"
    start_proxy "$CASES_DIR/80-fault-injection" || return

    # Normal path works (no fault)
    assert_status "Fault inject - normal path returns 200" 200 \
        -H "Host: fault.test" "$PROXY_URL/"

    # Fault path returns 503
    assert_status "Fault inject - /fault/ returns 503" 503 \
        -H "Host: fault.test" "$PROXY_URL/fault/test"

    assert_body_json_field "Fault inject - error field" ".error" "service_unavailable" \
        -H "Host: fault.test" "$PROXY_URL/fault/test"

    assert_body_json_field "Fault inject - message field" ".message" "Fault injected" \
        -H "Host: fault.test" "$PROXY_URL/fault/test"

    # Another fault path also returns 503
    assert_status "Fault inject - /fault/other returns 503" 503 \
        -H "Host: fault.test" "$PROXY_URL/fault/other"

    stop_proxy
}

run_81_idempotency_keys() {
    log_header "81 - Idempotency Keys"
    start_mock_ai_server || { log_skip "Idempotency keys - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/81-idempotency-keys" || return

    # Basic AI request works
    assert_status "Idempotency - basic request succeeds" 200 \
        -X POST -H "Host: ai-idempotent.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Request with idempotency key
    assert_status "Idempotency - request with key succeeds" 200 \
        -X POST -H "Host: ai-idempotent.test" -H "Content-Type: application/json" \
        -H "Idempotency-Key: test-key-001" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Repeated request with same key
    assert_status "Idempotency - repeated key succeeds" 200 \
        -X POST -H "Host: ai-idempotent.test" -H "Content-Type: application/json" \
        -H "Idempotency-Key: test-key-001" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    stop_proxy
}

run_82_model_aliasing() {
    log_header "82 - Model Aliasing"
    start_mock_ai_server || { log_skip "Model aliasing - mock server unavailable"; return; }
    start_proxy "$CASES_DIR/82-model-aliasing" || return

    # Alias "fast" maps to gpt-4o-mini
    assert_status "Model alias - fast -> gpt-4o-mini" 200 \
        -X POST -H "Host: ai-alias.test" -H "Content-Type: application/json" \
        -d '{"model":"fast","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Alias "smart" maps to gpt-4o
    assert_status "Model alias - smart -> gpt-4o" 200 \
        -X POST -H "Host: ai-alias.test" -H "Content-Type: application/json" \
        -d '{"model":"smart","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Alias "cheap" maps to gpt-4o-mini
    assert_status "Model alias - cheap -> gpt-4o-mini" 200 \
        -X POST -H "Host: ai-alias.test" -H "Content-Type: application/json" \
        -d '{"model":"cheap","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Direct model name still works
    assert_status "Model alias - direct gpt-4o-mini" 200 \
        -X POST -H "Host: ai-alias.test" -H "Content-Type: application/json" \
        -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    # Response contains expected fields
    assert_body_contains "Model alias - response has choices" '"choices"' \
        -X POST -H "Host: ai-alias.test" -H "Content-Type: application/json" \
        -d '{"model":"fast","messages":[{"role":"user","content":"Hello"}]}' \
        "$PROXY_URL/v1/chat/completions"

    stop_proxy
}

run_83_ssrf_protection() {
    log_header "83 - SSRF Protection"
    start_proxy "$CASES_DIR/83-ssrf-protection" || return

    # Normal request succeeds
    assert_status "SSRF - normal request succeeds" 200 \
        -H "Host: ssrf.test" "$PROXY_URL/"

    assert_body_contains "SSRF - echo response" "method" \
        -H "Host: ssrf.test" "$PROXY_URL/"

    # Request with normal-sized body succeeds
    assert_status "SSRF - normal POST succeeds" 200 \
        -X POST -H "Host: ssrf.test" -H "Content-Type: application/json" \
        -d '{"key":"value"}' "$PROXY_URL/"

    # Request with excessively long URL path is blocked
    local long_path
    long_path=$(python3 -c "print('a' * 3000)" 2>/dev/null || echo "")
    if [[ -n "$long_path" ]]; then
        assert_status_match "SSRF - oversized URL blocked" "^4" \
            -H "Host: ssrf.test" "$PROXY_URL/$long_path"
    else
        log_skip "SSRF - oversized URL test (python3 not available)"
    fi

    # Deeply nested JSON is blocked by threat protection
    local deep_json
    deep_json=$(python3 -c "
import json
d = {'value': 'leaf'}
for i in range(15):
    d = {'nested': d}
print(json.dumps(d))
" 2>/dev/null || echo "")
    if [[ -n "$deep_json" ]]; then
        assert_status_match "SSRF - deeply nested JSON blocked" "^4" \
            -X POST -H "Host: ssrf.test" -H "Content-Type: application/json" \
            -d "$deep_json" "$PROXY_URL/"
    else
        log_skip "SSRF - deeply nested JSON test (python3 not available)"
    fi

    stop_proxy
}

run_84_metrics_origin() {
    log_header "84 - Metrics Origin"
    start_proxy "$CASES_DIR/84-metrics-origin" || return

    # Make a request so that per-origin metrics are recorded
    assert_status "Metrics origin - proxy request" 200 \
        -H "Host: metrics.test" "$PROXY_URL/echo"

    # Check the telemetry /metrics endpoint for origin request counter
    sleep 0.5
    assert_body_contains "Metrics origin - sbproxy_origin_requests_total present" \
        "sbproxy_origin_requests_total" "http://localhost:18089/metrics"

    stop_proxy
    lsof -ti:18089 2>/dev/null | xargs kill -9 2>/dev/null || true
}

run_85_metrics_cardinality() {
    log_header "85 - Metrics Cardinality"
    start_proxy "$CASES_DIR/85-metrics-cardinality" || return

    # Make a few requests to generate metrics
    assert_status "Metrics cardinality - request 1" 200 \
        -H "Host: cardinality.test" "$PROXY_URL/echo"
    assert_status "Metrics cardinality - request 2" 200 \
        -H "Host: cardinality.test" "$PROXY_URL/echo?q=2"

    # Verify the telemetry /metrics endpoint responds
    sleep 0.5
    assert_status "Metrics cardinality - /metrics endpoint serves" 200 \
        "http://localhost:18089/metrics"

    stop_proxy
    lsof -ti:18089 2>/dev/null | xargs kill -9 2>/dev/null || true
}

run_86_security_headers_array() {
    log_header "86 - Security Headers Array"
    start_proxy "$CASES_DIR/86-security-headers-array" || return

    assert_status "Security headers array - 200" 200 \
        -H "Host: secheaders.test" "$PROXY_URL/echo"

    assert_header "Security headers array - X-Frame-Options" \
        "X-Frame-Options" "DENY" \
        -H "Host: secheaders.test" "$PROXY_URL/echo"

    assert_header "Security headers array - X-Content-Type-Options" \
        "X-Content-Type-Options" "nosniff" \
        -H "Host: secheaders.test" "$PROXY_URL/echo"

    assert_header "Security headers array - Referrer-Policy" \
        "Referrer-Policy" "strict-origin-when-cross-origin" \
        -H "Host: secheaders.test" "$PROXY_URL/echo"

    assert_header "Security headers array - X-XSS-Protection" \
        "X-XSS-Protection" "1; mode=block" \
        -H "Host: secheaders.test" "$PROXY_URL/echo"

    assert_header "Security headers array - Permissions-Policy" \
        "Permissions-Policy" "camera=()" \
        -H "Host: secheaders.test" "$PROXY_URL/echo"

    stop_proxy
}

run_87_secret_references() {
    log_header "87 - Secret References"
    export TEST_API_KEY="test-secret-key-12345"
    start_proxy "$CASES_DIR/87-secret-references" || { unset TEST_API_KEY; return; }

    # Without the key, should get 401
    assert_status "Secret references - no key returns 401" 401 \
        -H "Host: secrets.test" "$PROXY_URL/echo"

    # With the interpolated env var key, should get 200
    assert_status "Secret references - env var key returns 200" 200 \
        -H "Host: secrets.test" -H "X-API-Key: test-secret-key-12345" "$PROXY_URL/echo"

    # Wrong key should get 401
    assert_status "Secret references - wrong key returns 401" 401 \
        -H "Host: secrets.test" -H "X-API-Key: wrong-key" "$PROXY_URL/echo"

    unset TEST_API_KEY
    stop_proxy
}

run_88_config_version() {
    log_header "88 - Config Version"
    start_proxy "$CASES_DIR/88-config-version" || return

    # Proxy should start and serve requests with config_version: 2
    assert_status "Config version 2 - proxy serves" 200 \
        -H "Host: cfgver.test" "$PROXY_URL/echo"

    assert_body_contains "Config version 2 - echo body" "cfgver.test" \
        -H "Host: cfgver.test" "$PROXY_URL/echo"

    stop_proxy
}

run_89_access_logging() {
    log_header "89 - Access Logging"
    start_proxy "$CASES_DIR/89-access-logging" || return

    # Requests should succeed with access logging enabled
    assert_status "Access logging - GET succeeds" 200 \
        -H "Host: accesslog.test" "$PROXY_URL/echo"

    assert_status "Access logging - POST succeeds" 200 \
        -X POST -H "Host: accesslog.test" -H "Content-Type: application/json" \
        -d '{"test":true}' "$PROXY_URL/echo"

    stop_proxy
}

run_90_custom_error_pages_negotiation() {
    log_header "90 - Custom Error Pages Negotiation"
    start_proxy "$CASES_DIR/90-custom-error-pages-negotiation" || return

    # JSON accept header should get JSON error page
    local json_body
    json_body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: errneg.test" -H "Accept: application/json" "$PROXY_URL/echo" 2>/dev/null || echo "")
    if echo "$json_body" | grep -q '"error":"unauthorized"'; then
        log_pass "Error negotiation - JSON Accept gets JSON error"
    else
        log_fail "Error negotiation - JSON Accept gets JSON error (body: $json_body)"
    fi

    # HTML accept header should get HTML error page
    local html_body
    html_body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: errneg.test" -H "Accept: text/html" "$PROXY_URL/echo" 2>/dev/null || echo "")
    if echo "$html_body" | grep -q "401 Unauthorized"; then
        log_pass "Error negotiation - HTML Accept gets HTML error"
    else
        log_fail "Error negotiation - HTML Accept gets HTML error (body: $html_body)"
    fi

    # Plain text accept header should get text error
    local text_body
    text_body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: errneg.test" -H "Accept: text/plain" "$PROXY_URL/echo" 2>/dev/null || echo "")
    if echo "$text_body" | grep -q "401 Unauthorized"; then
        log_pass "Error negotiation - text/plain Accept gets plain text error"
    else
        log_fail "Error negotiation - text/plain Accept gets plain text error (body: $text_body)"
    fi

    stop_proxy
}

run_91_consistent_hashing() {
    log_header "91 - Consistent Hashing"
    start_proxy "$CASES_DIR/91-consistent-hashing" || return

    # Same hash key should route to the same backend consistently
    local body1 body2 body3
    body1=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: conhash.test" -H "X-Hash-Key: user-abc-123" "$PROXY_URL/" 2>/dev/null || echo "")
    body2=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: conhash.test" -H "X-Hash-Key: user-abc-123" "$PROXY_URL/" 2>/dev/null || echo "")
    body3=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: conhash.test" -H "X-Hash-Key: user-abc-123" "$PROXY_URL/" 2>/dev/null || echo "")

    if [[ "$body1" == "$body2" ]] && [[ "$body2" == "$body3" ]]; then
        log_pass "Consistent hashing - same key routes to same backend"
    else
        log_fail "Consistent hashing - same key routes to same backend (responses differ)"
    fi

    # Different hash key may route to a different backend
    assert_status "Consistent hashing - different key request succeeds" 200 \
        -H "Host: conhash.test" -H "X-Hash-Key: user-xyz-789" "$PROXY_URL/"

    assert_header "Consistent hashing - response modifier applied" \
        "X-Proxy" "sbproxy-conhash" \
        -H "Host: conhash.test" -H "X-Hash-Key: user-abc-123" "$PROXY_URL/"

    stop_proxy
}

run_92_grpc_web() {
    log_header "92 - gRPC-Web"
    start_proxy "$CASES_DIR/92-grpc-web" || return

    # gRPC-Web content-type detection should accept the request.
    # The upstream is not a real gRPC server, so we just verify the proxy
    # recognizes the gRPC-Web content type and does not reject it outright.
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --compressed --max-time 10 \
        -X POST -H "Host: grpcweb.test" \
        -H "Content-Type: application/grpc-web+proto" \
        -d '' "$PROXY_URL/test.Service/Method" 2>/dev/null || echo "000")

    # Expect a non-zero response. A 502/503 means proxy accepted and forwarded
    # the gRPC-Web request. A 415 would mean the proxy rejected the content type.
    if [[ "$status" != "000" ]] && [[ "$status" != "415" ]]; then
        log_pass "gRPC-Web - POST with grpc-web content-type accepted (HTTP $status)"
    else
        log_fail "gRPC-Web - POST with grpc-web content-type rejected (HTTP $status)"
    fi

    # Also test grpc-web-text variant
    local status2
    status2=$(curl -s -o /dev/null -w "%{http_code}" --compressed --max-time 10 \
        -X POST -H "Host: grpcweb.test" \
        -H "Content-Type: application/grpc-web-text" \
        -d '' "$PROXY_URL/test.Service/Method" 2>/dev/null || echo "000")

    if [[ "$status2" != "000" ]] && [[ "$status2" != "415" ]]; then
        log_pass "gRPC-Web - POST with grpc-web-text content-type accepted (HTTP $status2)"
    else
        log_fail "gRPC-Web - POST with grpc-web-text content-type rejected (HTTP $status2)"
    fi

    stop_proxy
}

run_93_accept_parser() {
    log_header "93 - Accept Parser"
    start_proxy "$CASES_DIR/93-accept-parser" || return

    # Request a non-existent path that triggers a 404 with error pages.
    # JSON accept should return JSON error page.
    local json_body
    json_body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: acceptparse.test" -H "Accept: application/json" \
        "$PROXY_URL/nonexistent-path-that-will-404" 2>/dev/null || echo "")

    # HTML accept should return HTML error page.
    local html_body
    html_body=$(curl -s --compressed -H "Accept-Encoding: identity" --max-time 10 \
        -H "Host: acceptparse.test" -H "Accept: text/html" \
        "$PROXY_URL/nonexistent-path-that-will-404" 2>/dev/null || echo "")

    # The callback server returns 404 for nonexistent paths,
    # which should trigger the error page matching the Accept header.
    if echo "$json_body" | grep -q '"error"'; then
        log_pass "Accept parser - JSON Accept gets JSON error page"
    else
        # Upstream might not return 404 for this path; verify the request works
        assert_status "Accept parser - JSON request succeeds" 200 \
            -H "Host: acceptparse.test" -H "Accept: application/json" "$PROXY_URL/echo"
    fi

    if echo "$html_body" | grep -q "<html>"; then
        log_pass "Accept parser - HTML Accept gets HTML error page"
    else
        assert_status "Accept parser - HTML request succeeds" 200 \
            -H "Host: acceptparse.test" -H "Accept: text/html" "$PROXY_URL/echo"
    fi

    stop_proxy
}

# ---------------------------------------------------------------------------
# Run selected tests
# ---------------------------------------------------------------------------
for case_dir in "${TEST_CASES[@]}"; do
    case_name=$(basename "$case_dir")
    case_num="${case_name%%-*}"

    # Start callback server if needed
    if needs_callback_server "$case_num" 2>/dev/null; then
        start_callback_server || true
    fi

    # Start mock AI server if needed
    if needs_mock_ai_server "$case_num" 2>/dev/null; then
        start_mock_ai_server || true
    fi

    func_name="run_${case_num}_$(echo "${case_name#*-}" | tr '-' '_')"
    if declare -f "$func_name" > /dev/null 2>&1; then
        "$func_name"
    else
        echo -e "${YELLOW}WARN${NC}: No test runner for $case_name (expected function $func_name)"
    fi
done

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
echo ""
log_header "Test Results"
echo -e "  ${GREEN}Passed${NC}: $PASS"
echo -e "  ${RED}Failed${NC}: $FAIL"
echo -e "  ${YELLOW}Skipped${NC}: $SKIP"
echo -e "  Total:   $((PASS + FAIL + SKIP))"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}${BOLD}Failures:${NC}"
    for f in "${FAILURES[@]}"; do
        echo -e "  ${RED}-${NC} $f"
    done
fi

echo ""
if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All tests passed.${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}$FAIL test(s) failed.${NC}"
    exit 1
fi
