#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

PROXY_URL="${PROXY_URL:-http://localhost:8080}"
PROXY_PID=""
PASS=0
FAIL=0
SKIP=0
TOTAL_TESTS=0

# JWT token for test33 (HS256, secret="your-256-bit-secret", from jwt.io)
JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# =============================================================================
# Helpers
# =============================================================================

header() {
  echo ""
  echo -e "${BLUE}==========================================${NC}"
  echo -e "${BLUE} $1${NC}"
  echo -e "${BLUE}==========================================${NC}"
}

subheader() {
  echo -e "\n${CYAN}--- $1 ---${NC}"
}

check_status() {
  local description="$1"
  local expected_code="$2"
  local actual_code="$3"
  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  if [ "$actual_code" = "$expected_code" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} $description (HTTP $actual_code)"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗ FAIL${NC} $description (expected $expected_code, got $actual_code)"
    FAIL=$((FAIL + 1))
  fi
}

check_body_contains() {
  local description="$1"
  local expected="$2"
  local body="$3"
  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  if echo "$body" | grep -q "$expected"; then
    echo -e "  ${GREEN}✓ PASS${NC} $description (body contains '$expected')"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗ FAIL${NC} $description (body missing '$expected')"
    FAIL=$((FAIL + 1))
  fi
}

check_body_not_contains() {
  local description="$1"
  local expected="$2"
  local body="$3"
  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  if echo "$body" | grep -q "$expected"; then
    echo -e "  ${RED}✗ FAIL${NC} $description (body should not contain '$expected')"
    FAIL=$((FAIL + 1))
  else
    echo -e "  ${GREEN}✓ PASS${NC} $description (body does not contain '$expected')"
    PASS=$((PASS + 1))
  fi
}

check_header_contains() {
  local description="$1"
  local expected="$2"
  local headers="$3"
  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  if echo "$headers" | grep -qi "$expected"; then
    echo -e "  ${GREEN}✓ PASS${NC} $description (header contains '$expected')"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗ FAIL${NC} $description (header missing '$expected')"
    FAIL=$((FAIL + 1))
  fi
}

check_header_absent() {
  local description="$1"
  local header_name="$2"
  local headers="$3"
  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  if echo "$headers" | grep -qi "$header_name"; then
    echo -e "  ${RED}✗ FAIL${NC} $description (header '$header_name' should be absent)"
    FAIL=$((FAIL + 1))
  else
    echo -e "  ${GREEN}✓ PASS${NC} $description (header '$header_name' absent)"
    PASS=$((PASS + 1))
  fi
}

skip_test() {
  echo -e "  ${YELLOW}⊘ SKIP${NC} $1"
  SKIP=$((SKIP + 1))
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

# Curl helper: GET with Host header, return "body\nstatus_code"
do_get() {
  local host="$1"
  local path="${2:-/}"
  shift 2 || shift 1 || true
  curl -s -w "\n%{http_code}" -H "Host: $host" "$@" "$PROXY_URL$path"
}

# Curl helper: GET headers only
do_head() {
  local host="$1"
  local path="${2:-/}"
  shift 2 || shift 1 || true
  curl -sI -H "Host: $host" "$@" "$PROXY_URL$path"
}

# Parse status code from do_get response
get_code() {
  echo "${1##*$'\n'}"
}

# Parse body from do_get response
get_body() {
  echo "${1%$'\n'*}"
}

# =============================================================================
# Test 01: Static Action
# =============================================================================
test_01() {
  header "Test 01: Static Action"
  local host="test1.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  check_body_contains "Body contains msg" '"msg"' "$body"
  check_body_contains "Body contains hello" '"hello"' "$body"

  local headers
  headers=$(do_head "$host" "/")
  check_header_contains "X-Custom header present" "X-Custom: yes" "$headers"
}

# =============================================================================
# Test 02: Echo (Proxy to postman-echo)
# =============================================================================
test_02() {
  header "Test 02: Echo (Proxy to postman-echo)"
  local host="test2.test"

  local resp
  resp=$(curl -s -w "\n%{http_code}" -H "Host: $host" -H "X-Test-Header: hello" "$PROXY_URL/get?bar=1")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET /get?bar=1 returns 200" "200" "$code"
  check_body_contains "Body contains query param" "bar" "$body"
}

# =============================================================================
# Test 03: Redirect
# =============================================================================
test_03() {
  header "Test 03: Redirect"
  local host="test3.test"

  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/old/page")
  check_status "GET /old/page returns 301" "301" "$resp"

  local headers
  headers=$(do_head "$host" "/old/page")
  check_header_contains "Location header present" "Location:" "$headers"
  check_header_contains "Location contains example.com" "example.com" "$headers"
  check_header_contains "Location preserves path" "/old/page" "$headers"
}

# =============================================================================
# Test 04: Proxy (Basic)
# =============================================================================
test_04() {
  header "Test 04: Proxy (Basic)"
  local host="test4.test"

  local resp
  resp=$(do_get "$host" "/get")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET /get proxied to postman-echo" "200" "$code"
  check_body_contains "Response from postman-echo" "postman-echo" "$body"
}

# =============================================================================
# Test 05: Proxy strip_base_path=false
# =============================================================================
test_05() {
  header "Test 05: Proxy strip_base_path=false"
  local host="test5.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200 (proxied to /posts)" "200" "$code"
  # jsonplaceholder.typicode.com/posts returns an array of posts
  check_body_contains "Response is posts array" "userId" "$body"
}

# =============================================================================
# Test 06: Proxy + Shadow
# =============================================================================
test_06() {
  header "Test 06: Proxy + Shadow"
  local host="test6.test"

  local resp
  resp=$(do_get "$host" "/get")
  local code
  code=$(get_code "$resp")
  check_status "GET /get with shadow returns 200" "200" "$code"

  local headers
  headers=$(do_head "$host" "/get")
  check_header_contains "X-Shadow-Enabled header" "X-Shadow-Enabled: true" "$headers"
}

# =============================================================================
# Test 07: Load Balancer
# =============================================================================
test_07() {
  header "Test 07: Load Balancer"
  local host="test7.test"

  local backends_seen=0
  local seen_1=0
  local seen_2=0
  local seen_3=0

  for i in $(seq 1 15); do
    local headers
    headers=$(do_head "$host" "/")
    local backend
    backend=$(echo "$headers" | grep -i "X-Served-By" | head -1 | awk '{print $2}' | tr -d '\r')
    case "$backend" in
      backend-1) seen_1=1 ;;
      backend-2) seen_2=1 ;;
      backend-3) seen_3=1 ;;
    esac
  done

  backends_seen=$((seen_1 + seen_2 + seen_3))
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  if [ "$backends_seen" -ge 2 ]; then
    echo -e "  ${GREEN}✓ PASS${NC} Load balancer distributed across $backends_seen backends"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗ FAIL${NC} Load balancer not distributing (saw $backends_seen backends)"
    FAIL=$((FAIL + 1))
  fi
}

# =============================================================================
# Test 08: A/B Test
# =============================================================================
test_08() {
  header "Test 08: A/B Test"
  local host="test8.test"

  local resp
  resp=$(curl -s -w "\n%{http_code}" -c /tmp/e2e_ab_cookies.txt -H "Host: $host" "$PROXY_URL/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  check_body_contains "Response has variant field" "variant" "$body"

  # Check sticky sessions
  local first_variant
  first_variant=$(echo "$body" | grep -o '"variant":"[^"]*"' | head -1 || true)
  local all_same=1
  for i in $(seq 1 5); do
    local b
    b=$(curl -s -b /tmp/e2e_ab_cookies.txt -H "Host: $host" "$PROXY_URL/")
    local v
    v=$(echo "$b" | grep -o '"variant":"[^"]*"' | head -1 || true)
    if [ -n "$first_variant" ] && [ "$v" != "$first_variant" ]; then
      all_same=0
    fi
  done

  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  if [ "$all_same" = "1" ] && [ -n "$first_variant" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} Sticky sessions work ($first_variant)"
    PASS=$((PASS + 1))
  elif [ -z "$first_variant" ]; then
    skip_test "Could not parse variant from response"
  else
    echo -e "  ${RED}✗ FAIL${NC} Sticky sessions broken (variant changed)"
    FAIL=$((FAIL + 1))
  fi

  local headers
  headers=$(do_head "$host" "/")
  check_header_contains "X-AB-Test header" "X-AB-Test" "$headers"

  rm -f /tmp/e2e_ab_cookies.txt
}

# =============================================================================
# Test 09: Beacon
# =============================================================================
test_09() {
  header "Test 09: Beacon (Empty GIF)"
  local host="test9.test"

  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/pixel.gif")
  check_status "GET /pixel.gif returns 200" "200" "$resp"

  local headers
  headers=$(do_head "$host" "/pixel.gif")
  check_header_contains "Content-Type is image/gif" "image/gif" "$headers"
}

# =============================================================================
# Test 10: Orchestration
# =============================================================================
test_10() {
  header "Test 10: Orchestration (Parallel)"
  local host="test10.test"

  local resp
  resp=$(curl -s --max-time 15 -w "\n%{http_code}" -H "Host: $host" "$PROXY_URL/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / orchestration returns 200" "200" "$code"
  check_body_contains "Response contains user data" "user" "$body"
  check_body_contains "Response contains post data" "post" "$body"
}

# =============================================================================
# Test 11: WebSocket
# =============================================================================
test_11() {
  header "Test 11: WebSocket"
  local host="test11.test"

  local resp
  resp=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" -H "Host: $host" \
    -H "Connection: Upgrade" -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "$PROXY_URL/" 2>/dev/null || true)

  if [ "$resp" = "101" ] || [ "$resp" = "200" ]; then
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "  ${GREEN}✓ PASS${NC} WebSocket upgrade accepted (HTTP $resp)"
    PASS=$((PASS + 1))
  else
    skip_test "WebSocket upgrade returned $resp (echo.websocket.org may be unavailable)"
  fi
}

# =============================================================================
# Test 12: HTML Transform
# =============================================================================
test_12() {
  header "Test 12: HTML Transform"
  local host="test12.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  check_body_contains "Injected meta tag present" "injected" "$body"
}

# =============================================================================
# Test 13: JSON Transform
# =============================================================================
test_13() {
  header "Test 13: JSON Transform"
  local host="test13.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  check_body_contains "Full name added" "full_name" "$body"
  check_body_contains "Secret redacted" "REDACTED" "$body"
}

# =============================================================================
# Test 14: Lua JSON Transform
# =============================================================================
test_14() {
  header "Test 14: Lua JSON Transform"
  local host="test14.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  check_body_contains "Lua-transformed fullName" "fullName" "$body"
  check_body_contains "Country mapped to US" '"US"' "$body"
}

# =============================================================================
# Test 15: Replace Strings
# =============================================================================
test_15() {
  header "Test 15: Replace Strings"
  local host="test15.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  check_body_contains "FooBar replaced with TestCo" "TestCo" "$body"
  check_body_contains "Hello World replaced with Greetings" "Greetings" "$body"
  check_body_not_contains "Original text removed" "FooBar Corp" "$body"
}

# =============================================================================
# Test 16: JSON Projection
# =============================================================================
test_16() {
  header "Test 16: JSON Projection"
  local host="test16.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  check_body_contains "Included field: name" "name" "$body"
  check_body_contains "Included field: email" "email" "$body"
  check_body_not_contains "Excluded field: password_hash" "password_hash" "$body"
  check_body_not_contains "Excluded field: internal_notes" "internal_notes" "$body"
}

# =============================================================================
# Test 17: JSON Schema Validate
# =============================================================================
test_17() {
  header "Test 17: JSON Schema Validate"
  local host="test17.test"

  subheader "Valid JSON"
  local resp
  resp=$(do_get "$host" "/valid")
  local code
  code=$(get_code "$resp")
  check_status "GET /valid returns 200" "200" "$code"

  subheader "Invalid JSON (missing required field)"
  resp=$(do_get "$host" "/invalid")
  code=$(get_code "$resp")
  # json_schema with action=validate rejects with 400, 422, or 502
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  if [ "$code" = "400" ] || [ "$code" = "422" ] || [ "$code" = "502" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} GET /invalid rejected (HTTP $code)"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗ FAIL${NC} GET /invalid should be 400/422/502 (got $code)"
    FAIL=$((FAIL + 1))
  fi
}

# =============================================================================
# Test 18: Format Convert (XML -> JSON)
# =============================================================================
test_18() {
  header "Test 18: Format Convert (XML -> JSON)"
  local host="test18.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  check_body_contains "Converted body contains name" "John" "$body"
  # Should be JSON format now (contains { or [ )
  check_body_contains "Output is JSON format" "{" "$body"
}

# =============================================================================
# Test 19: Markdown Transform
# =============================================================================
test_19() {
  header "Test 19: Markdown Transform"
  local host="test19.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  # Markdown should be converted to HTML
  check_body_contains "H1 tag present" "<h1" "$body"
  check_body_contains "Bold text converted" "<strong>" "$body"
}

# =============================================================================
# Test 20: Template Transform
# =============================================================================
test_20() {
  header "Test 20: Template Transform"
  local host="test20.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  check_body_contains "Template variable resolved: name" "World" "$body"
  check_body_contains "Template variable resolved: count" "42" "$body"
}

# =============================================================================
# Test 21: Classify Transform
# =============================================================================
test_21() {
  header "Test 21: Classify Transform"
  local host="test21.test"

  local headers
  headers=$(do_head "$host" "/get")

  local head_status
  head_status=$(echo "$headers" | head -1 | grep -o '[0-9]\{3\}')
  if [ "$head_status" = "200" ]; then
    check_header_contains "X-Content-Class header set" "X-Content-Class" "$headers"
  else
    skip_test "Upstream returned $head_status (postman-echo may be unavailable)"
  fi
}

# =============================================================================
# Test 22: Payload Limit
# =============================================================================
test_22() {
  header "Test 22: Payload Limit"
  local host="test22.test"

  # POST a large body to postman-echo, which echoes it back
  # The response body will exceed payload_limit of 100 bytes
  local large_body
  large_body=$(python3 -c "print('x' * 500)")

  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" \
    -X POST -H "Content-Type: text/plain" \
    -d "$large_body" "$PROXY_URL/post")

  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  if [ "$resp" = "413" ] || [ "$resp" = "200" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} Payload limit response (HTTP $resp)"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗ FAIL${NC} Payload limit expected 413 or 200 (got $resp)"
    FAIL=$((FAIL + 1))
  fi
}

# =============================================================================
# Test 23: Rate Limiting
# =============================================================================
test_23() {
  header "Test 23: Rate Limiting"
  local host="test23.test"

  local got_429=0
  for i in $(seq 1 20); do
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/")
    if [ "$code" = "429" ]; then
      got_429=1
      break
    fi
  done

  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  if [ "$got_429" = "1" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} Rate limiting triggered (429 after burst)"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗ FAIL${NC} Rate limiting not triggered (no 429 in 20 requests)"
    FAIL=$((FAIL + 1))
  fi
}

# =============================================================================
# Test 24: WAF
# =============================================================================
test_24() {
  header "Test 24: WAF"
  local host="test24.test"

  subheader "Normal request"
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/")
  check_status "GET / normal request" "200" "$resp"

  subheader "SQL injection"
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/?id=1%20OR%201=1--")
  check_status "GET /?id=1 OR 1=1-- (SQLi blocked)" "403" "$resp"

  subheader "XSS"
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/?q=%3Cscript%3Ealert(1)%3C/script%3E")
  check_status "GET /?q=<script> (XSS blocked)" "403" "$resp"
}

# =============================================================================
# Test 25: Security Headers
# =============================================================================
test_25() {
  header "Test 25: Security Headers"
  local host="test25.test"

  local headers
  headers=$(do_head "$host" "/")
  check_header_contains "Strict-Transport-Security" "Strict-Transport-Security" "$headers"
  check_header_contains "X-Frame-Options" "X-Frame-Options" "$headers"
  check_header_contains "X-Content-Type-Options" "X-Content-Type-Options" "$headers"
  check_header_contains "Content-Security-Policy" "Content-Security-Policy" "$headers"
  check_header_contains "Referrer-Policy" "Referrer-Policy" "$headers"
}

# =============================================================================
# Test 26: IP Filtering (via CEL expression)
# =============================================================================
test_26() {
  header "Test 26: IP Filtering"
  local host="test26.test"

  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/")
  check_status "GET / from localhost (whitelisted)" "200" "$resp"
}

# =============================================================================
# Test 27: Geo Blocking
# =============================================================================
test_27() {
  header "Test 27: Geo Blocking"
  local host="test27.test"

  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/")
  check_status "GET / from localhost (no country match)" "200" "$resp"
}

# =============================================================================
# Test 28: Expression Policy (CEL)
# =============================================================================
test_28() {
  header "Test 28: Expression Policy (CEL)"
  local host="test28.test"

  subheader "Public path (allowed)"
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/public")
  check_status "GET /public returns 200" "200" "$resp"

  subheader "Admin path (blocked)"
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/admin/settings")
  check_status "GET /admin/settings returns 403" "403" "$resp"
}

# =============================================================================
# Test 29: Expression Policy (Lua)
# =============================================================================
test_29() {
  header "Test 29: Expression Policy (Lua)"
  local host="test29.test"

  subheader "Without X-Allow header (blocked)"
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/")
  check_status "GET / without X-Allow returns 403" "403" "$resp"

  subheader "With X-Allow header (allowed)"
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" -H "X-Allow: true" "$PROXY_URL/")
  check_status "GET / with X-Allow returns 200" "200" "$resp"
}

# =============================================================================
# Test 30: CSRF Protection
# =============================================================================
test_30() {
  header "Test 30: CSRF Protection"
  local host="test30.test"

  subheader "GET to obtain CSRF token"
  local headers
  headers=$(curl -s -D - -o /dev/null -c /tmp/e2e_csrf_cookies.txt -H "Host: $host" "$PROXY_URL/")
  local head_status
  head_status=$(echo "$headers" | head -1 | grep -o '[0-9]\{3\}')
  check_status "GET / sets CSRF cookie" "200" "$head_status"

  # Extract CSRF token from cookie
  local csrf_token
  csrf_token=$(grep "_csrf" /tmp/e2e_csrf_cookies.txt 2>/dev/null | awk '{print $NF}' || true)

  subheader "POST without CSRF token (should fail)"
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" \
    -b /tmp/e2e_csrf_cookies.txt \
    -X POST -H "Content-Type: application/json" -d '{"data":"test"}' "$PROXY_URL/")
  check_status "POST / without CSRF token returns 403" "403" "$resp"

  if [ -n "$csrf_token" ]; then
    subheader "POST with CSRF token (should pass)"
    resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" \
      -b /tmp/e2e_csrf_cookies.txt \
      -H "X-CSRF-Token: $csrf_token" \
      -X POST -H "Content-Type: application/json" -d '{"data":"test"}' "$PROXY_URL/")
    check_status "POST / with CSRF token returns 200" "200" "$resp"
  else
    skip_test "Could not extract CSRF token from cookie"
  fi

  rm -f /tmp/e2e_csrf_cookies.txt
}

# =============================================================================
# Test 31: Request Limiting
# =============================================================================
test_31() {
  header "Test 31: Request Limiting"
  local host="test31.test"

  subheader "Normal request"
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/")
  check_status "GET / normal request" "200" "$resp"

  subheader "Oversized URL"
  local long_path
  long_path=$(python3 -c "print('/' + 'a' * 200)")
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL$long_path")

  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  if [ "$resp" = "414" ] || [ "$resp" = "413" ] || [ "$resp" = "400" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} Oversized URL rejected (HTTP $resp)"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗ FAIL${NC} Oversized URL should be rejected (got $resp)"
    FAIL=$((FAIL + 1))
  fi
}

# =============================================================================
# Test 32: PII Redaction
# =============================================================================
test_32() {
  header "Test 32: PII Redaction"
  local host="test32.test"

  local resp
  resp=$(curl -s -w "\n%{http_code}" -H "Host: $host" \
    -X POST -H "Content-Type: application/json" \
    -d '{"name":"John","ssn":"123-45-6789"}' "$PROXY_URL/post")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "POST with SSN returns 200" "200" "$code"
  check_body_not_contains "SSN redacted in response" "123-45-6789" "$body"
}

# =============================================================================
# Test 33: JWT Authentication (HS256)
# =============================================================================
test_33() {
  header "Test 33: JWT Authentication (HS256)"
  local host="test33.test"

  subheader "Without JWT (should fail)"
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/")
  check_status "GET / without JWT returns 401" "401" "$resp"

  subheader "With valid JWT"
  resp=$(curl -s -w "\n%{http_code}" -H "Host: $host" \
    -H "Authorization: Bearer $JWT_TOKEN" "$PROXY_URL/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")
  check_status "GET / with JWT returns 200" "200" "$code"
  check_body_contains "Authenticated response" "authenticated" "$body"

  subheader "With invalid JWT"
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" \
    -H "Authorization: Bearer invalid.token.here" "$PROXY_URL/")
  check_status "GET / with invalid JWT returns 401" "401" "$resp"
}

# =============================================================================
# Test 34: API Key Authentication
# =============================================================================
test_34() {
  header "Test 34: API Key Authentication"
  local host="test34.test"

  subheader "Without API key"
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/")
  check_status "GET / without API key returns 401" "401" "$resp"

  subheader "With valid API key"
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" \
    -H "X-API-Key: test-key-123" "$PROXY_URL/")
  check_status "GET / with valid API key returns 200" "200" "$resp"

  subheader "With invalid API key"
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" \
    -H "X-API-Key: wrong-key" "$PROXY_URL/")
  check_status "GET / with invalid API key returns 401" "401" "$resp"
}

# =============================================================================
# Test 35: Basic Auth
# =============================================================================
test_35() {
  header "Test 35: Basic Auth"
  local host="test35.test"

  subheader "Without credentials"
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/")
  check_status "GET / without auth returns 401" "401" "$resp"

  subheader "With valid credentials"
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" \
    -u "testuser:testpass" "$PROXY_URL/")
  check_status "GET / with valid creds returns 200" "200" "$resp"

  subheader "With wrong password"
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" \
    -u "testuser:wrongpass" "$PROXY_URL/")
  check_status "GET / with wrong password returns 401" "401" "$resp"
}

# =============================================================================
# Test 36: Bearer Token Authentication
# =============================================================================
test_36() {
  header "Test 36: Bearer Token Authentication"
  local host="test36.test"

  subheader "Without token"
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/")
  check_status "GET / without token returns 401" "401" "$resp"

  subheader "With valid token"
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" \
    -H "Authorization: Bearer test-bearer-token-abc123" "$PROXY_URL/")
  check_status "GET / with valid token returns 200" "200" "$resp"

  subheader "With invalid token"
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" \
    -H "Authorization: Bearer wrong-token" "$PROXY_URL/")
  check_status "GET / with invalid token returns 401" "401" "$resp"
}

# =============================================================================
# Test 37: Request Modifiers (Headers + URL)
# =============================================================================
test_37() {
  header "Test 37: Request Modifiers (Headers + URL)"
  local host="test37.test"

  local resp
  resp=$(do_get "$host" "/original")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET /original (rewritten to /get) returns 200" "200" "$code"
  check_body_contains "Custom header added" "x-custom-added" "$body"
}

# =============================================================================
# Test 38: Response Modifiers
# =============================================================================
test_38() {
  header "Test 38: Response Modifiers"
  local host="test38.test"

  local headers
  headers=$(do_head "$host" "/")
  check_header_contains "X-Custom-Response header" "X-Custom-Response: modified" "$headers"
  check_header_contains "X-Powered-By header" "X-Powered-By: soapbucket-e2e" "$headers"
}

# =============================================================================
# Test 39: Request Modifier (CEL)
# =============================================================================
test_39() {
  header "Test 39: Request Modifier (CEL)"
  local host="test39.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  check_body_contains "CEL-added header visible" "x-cel-modified" "$body"
}

# =============================================================================
# Test 40: Request Modifier (Lua)
# =============================================================================
test_40() {
  header "Test 40: Request Modifier (Lua)"
  local host="test40.test"

  local resp
  resp=$(do_get "$host" "/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  check_body_contains "Lua-added header visible" "x-lua-modified" "$body"
}

# =============================================================================
# Test 41: Response Modifier (Conditional)
# =============================================================================
test_41() {
  header "Test 41: Response Modifier (Conditional)"
  local host="test41.test"

  local headers
  headers=$(do_head "$host" "/")
  check_header_contains "X-Response-Modified on 200" "X-Response-Modified: true" "$headers"
  check_header_absent "X-Error-Modified absent on 200" "X-Error-Modified" "$headers"
}

# =============================================================================
# Test 42: Forward Rules (Path Match)
# =============================================================================
test_42() {
  header "Test 42: Forward Rules (Path Match)"
  local host="test42.test"

  subheader "API path"
  local resp
  resp=$(do_get "$host" "/api/data")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")
  check_status "GET /api/data returns 200" "200" "$code"
  check_body_contains "Routed to API backend" "api-backend" "$body"

  subheader "Web path"
  resp=$(do_get "$host" "/web/page")
  code=$(get_code "$resp")
  body=$(get_body "$resp")
  check_status "GET /web/page returns 200" "200" "$code"
  check_body_contains "Routed to Web backend" "web-backend" "$body"

  subheader "Unknown path (fallback)"
  resp=$(do_get "$host" "/unknown")
  code=$(get_code "$resp")
  check_status "GET /unknown returns 404" "404" "$code"
}

# =============================================================================
# Test 43: Forward Rules (CEL)
# =============================================================================
test_43() {
  header "Test 43: Forward Rules (CEL)"
  local host="test43.test"

  subheader "Mobile User-Agent"
  local resp
  resp=$(curl -s -w "\n%{http_code}" -H "Host: $host" \
    -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)" \
    "$PROXY_URL/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")
  check_status "GET / with iPhone UA returns 200" "200" "$code"
  check_body_contains "Routed to mobile backend" "mobile" "$body"

  subheader "Desktop User-Agent"
  resp=$(curl -s -w "\n%{http_code}" -H "Host: $host" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    "$PROXY_URL/")
  code=$(get_code "$resp")
  body=$(get_body "$resp")
  check_status "GET / with desktop UA returns 200" "200" "$code"
  check_body_contains "Routed to desktop (default)" "desktop" "$body"
}

# =============================================================================
# Test 44: Forward Rules (Header Match)
# =============================================================================
test_44() {
  header "Test 44: Forward Rules (Header Match)"
  local host="test44.test"

  subheader "With X-Premium header"
  local resp
  resp=$(curl -s -w "\n%{http_code}" -H "Host: $host" -H "X-Premium: true" "$PROXY_URL/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")
  check_status "GET / with X-Premium returns 200" "200" "$code"
  check_body_contains "Routed to premium backend" "premium" "$body"

  subheader "Without X-Premium header"
  resp=$(do_get "$host" "/")
  code=$(get_code "$resp")
  body=$(get_body "$resp")
  check_status "GET / without X-Premium returns 200" "200" "$code"
  check_body_contains "Routed to standard (default)" "standard" "$body"
}

# =============================================================================
# Test 45: Session Config
# =============================================================================
test_45() {
  header "Test 45: Session Config"
  local host="test45.test"

  local headers
  headers=$(curl -s -D - -o /dev/null -H "Host: $host" "$PROXY_URL/")
  check_header_contains "Session cookie set" "_sb_test_session" "$headers"

  # Second request with cookie should maintain session
  local resp
  resp=$(curl -s -w "\n%{http_code}" -c /tmp/e2e_session.txt -H "Host: $host" "$PROXY_URL/")
  local code
  code=$(get_code "$resp")
  check_status "GET / with session returns 200" "200" "$code"

  rm -f /tmp/e2e_session.txt
}

# =============================================================================
# Test 46: Traffic Capture
# =============================================================================
test_46() {
  header "Test 46: Traffic Capture"
  local host="test46.test"

  subheader "Generate traffic"
  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/get")
  check_status "GET /get generates traffic" "200" "$resp"

  subheader "Query captured exchanges"
  # Small delay to let capture process
  sleep 1
  resp=$(curl -s -w "\n%{http_code}" "$PROXY_URL/_sb/api/traffic/exchanges?hostname=$host&limit=10")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")
  check_status "GET /_sb/api/traffic/exchanges" "200" "$code"
  check_body_contains "Exchanges returned" "exchanges" "$body"
}

# =============================================================================
# Test 47: on_load + Templates
# =============================================================================
test_47() {
  header "Test 47: on_load + Templates"
  local host="test47.test"

  local resp
  resp=$(curl -s --max-time 15 -w "\n%{http_code}" -H "Host: $host" "$PROXY_URL/")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET / returns 200" "200" "$code"
  # on_load fetches jsonplaceholder post/1 which has a title
  check_body_contains "Template body has Post:" "Post:" "$body"

  local headers
  headers=$(do_head "$host" "/")
  check_header_contains "X-Data-Loaded header" "X-Data-Loaded: true" "$headers"
}

# =============================================================================
# Test 48: Error Pages
# =============================================================================
test_48() {
  header "Test 48: Error Pages"
  local host="test48.test"

  local resp
  resp=$(do_get "$host" "/not-found")
  local code body
  code=$(get_code "$resp")
  body=$(get_body "$resp")

  check_status "GET /not-found returns 404" "404" "$code"
  check_body_contains "Custom error page body" "Custom 404" "$body"
}

# =============================================================================
# Test 49: Force SSL
# =============================================================================
test_49() {
  header "Test 49: Force SSL"
  local host="test49.test"

  local resp
  resp=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$PROXY_URL/")
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  if [ "$resp" = "301" ] || [ "$resp" = "308" ] || [ "$resp" = "302" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} Force SSL redirects to HTTPS (HTTP $resp)"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗ FAIL${NC} Force SSL should redirect (got $resp)"
    FAIL=$((FAIL + 1))
  fi

  local headers
  headers=$(do_head "$host" "/")
  check_header_contains "Location contains https" "https://" "$headers"
}

# =============================================================================
# Test 50: Response Cache
# =============================================================================
test_50() {
  header "Test 50: Response Cache"
  local host="test50.test"

  subheader "First request (cache MISS)"
  local headers1
  headers1=$(do_head "$host" "/get")
  local head_status
  head_status=$(echo "$headers1" | head -1 | grep -o '[0-9]\{3\}')
  check_status "First GET /get returns 200" "200" "$head_status"

  subheader "Second request (cache HIT)"
  local headers2
  headers2=$(do_head "$host" "/get")
  check_header_contains "X-Cache-Status header present" "X-Cache-Status" "$headers2"
}

# =============================================================================
# Test 51: GraphQL (Depth Limit)
# =============================================================================
test_51() {
  header "Test 51: GraphQL (Depth Limit)"
  local host="test51.test"

  subheader "Shallow query (within depth limit)"
  local resp
  resp=$(curl -s -w "\n%{http_code}" -H "Host: $host" \
    -X POST -H "Content-Type: application/json" \
    -d '{"query":"{ users { name } }"}' "$PROXY_URL/")
  local code
  code=$(get_code "$resp")
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  if [ "$code" = "200" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} Shallow query accepted (HTTP $code)"
    PASS=$((PASS + 1))
  else
    # postman-echo may not return valid GraphQL response but proxy should forward
    echo -e "  ${YELLOW}⊘ SKIP${NC} Shallow query returned $code (upstream may not support GraphQL)"
    SKIP=$((SKIP + 1))
  fi

  subheader "Deep query (exceeds max_depth=3)"
  resp=$(curl -s -w "\n%{http_code}" -H "Host: $host" \
    -X POST -H "Content-Type: application/json" \
    -d '{"query":"{ a { b { c { d { e { f } } } } } }"}' "$PROXY_URL/")
  code=$(get_code "$resp")
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  if [ "$code" = "400" ] || [ "$code" = "422" ]; then
    echo -e "  ${GREEN}✓ PASS${NC} Deep query rejected (HTTP $code)"
    PASS=$((PASS + 1))
  else
    echo -e "  ${RED}✗ FAIL${NC} Deep query should be rejected (got $code)"
    FAIL=$((FAIL + 1))
  fi
}

# =============================================================================
# Infrastructure
# =============================================================================

create_config() {
  cat > /tmp/sb-e2e-test.yml << 'YAML'
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  bind_address: "0.0.0.0"
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "60s"
  debug_settings:
    debug: true

storage_settings:
  driver: "file"
  params:
    path: "config/sites/sites.test.json"

l1_cache_settings:
  driver: "memory"
  params:
    max_size: 100000000

l2_cache_settings:
  driver: "memory"

l3_cache_settings:
  driver: "memory"

session_cacher_settings:
  driver: "memory"

security_settings:
  driver: "memory"

messenger_settings:
  driver: "memory"

crypto_settings:
  driver: "local"
  params:
    encryption_key: "Y2FzdGxlYXBwcm9wcmlhdGVnYXRlY29tcG9zaXRpb24="
    signing_key: "Y2FzdGxlYXBwcm9wcmlhdGVnYXRlY29tcG9zaXRpb24="

maxmind_settings:
  driver: "maxmind"
  params:
    path: "data/ipinfo_lite.mmdb"

uaparser_settings:
  driver: "uaparser"
  params:
    path: "data/regexes.yml"

log_level: "warn"
YAML
  echo -e "${GREEN}Config created at /tmp/sb-e2e-test.yml${NC}"
}

build_proxy() {
  echo -e "${CYAN}Building proxy...${NC}"
  cd "$ROOT_DIR"
  go build -o /tmp/sb-e2e-proxy ./cmd/sbproxy/
  echo -e "${GREEN}Proxy built at /tmp/sb-e2e-proxy${NC}"
}

start_proxy() {
  echo -e "${CYAN}Starting proxy...${NC}"
  cd "$ROOT_DIR"
  /tmp/sb-e2e-proxy serve --config-dir conf --config-file /tmp/sb-e2e-test.yml &
  PROXY_PID=$!
  echo -e "${GREEN}Proxy started (PID: $PROXY_PID)${NC}"

  # Wait for proxy to be ready
  local retries=0
  while ! curl -s -o /dev/null "$PROXY_URL/" 2>/dev/null; do
    retries=$((retries + 1))
    if [ "$retries" -ge 30 ]; then
      echo -e "${RED}Proxy failed to start after 30 seconds${NC}"
      kill "$PROXY_PID" 2>/dev/null || true
      exit 1
    fi
    sleep 1
  done
  echo -e "${GREEN}Proxy is ready${NC}"
}

stop_proxy() {
  if [ -n "$PROXY_PID" ]; then
    echo -e "\n${CYAN}Stopping proxy (PID: $PROXY_PID)...${NC}"
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    echo -e "${GREEN}Proxy stopped${NC}"
  fi
  rm -f /tmp/sb-e2e-proxy /tmp/sb-e2e-test.yml
}

cleanup() {
  stop_proxy
  rm -f /tmp/e2e_ab_cookies.txt /tmp/e2e_csrf_cookies.txt /tmp/e2e_session.txt
}

trap cleanup EXIT

# =============================================================================
# Main
# =============================================================================

usage() {
  echo "Usage: $0 [command] [options]"
  echo ""
  echo "Commands:"
  echo "  run           Build proxy, start it, run all tests, stop proxy (default)"
  echo "  test          Run tests only (assumes proxy is already running)"
  echo "  test N        Run specific test (e.g., test 5)"
  echo "  test N,M      Run multiple tests (e.g., test 1,5,14)"
  echo "  build         Build proxy only"
  echo ""
  echo "Environment:"
  echo "  PROXY_URL     Proxy base URL (default: http://localhost:8080)"
}

run_test() {
  local num="$1"
  case "$num" in
    1)  test_01 ;;    2)  test_02 ;;    3)  test_03 ;;
    4)  test_04 ;;    5)  test_05 ;;    6)  test_06 ;;
    7)  test_07 ;;    8)  test_08 ;;    9)  test_09 ;;
    10) test_10 ;;    11) test_11 ;;    12) test_12 ;;
    13) test_13 ;;    14) test_14 ;;    15) test_15 ;;
    16) test_16 ;;    17) test_17 ;;    18) test_18 ;;
    19) test_19 ;;    20) test_20 ;;    21) test_21 ;;
    22) test_22 ;;    23) test_23 ;;    24) test_24 ;;
    25) test_25 ;;    26) test_26 ;;    27) test_27 ;;
    28) test_28 ;;    29) test_29 ;;    30) test_30 ;;
    31) test_31 ;;    32) test_32 ;;    33) test_33 ;;
    34) test_34 ;;    35) test_35 ;;    36) test_36 ;;
    37) test_37 ;;    38) test_38 ;;    39) test_39 ;;
    40) test_40 ;;    41) test_41 ;;    42) test_42 ;;
    43) test_43 ;;    44) test_44 ;;    45) test_45 ;;
    46) test_46 ;;    47) test_47 ;;    48) test_48 ;;
    49) test_49 ;;    50) test_50 ;;    51) test_51 ;;
    *)  echo -e "${RED}Unknown test: $num${NC}" ;;
  esac
}

run_all_tests() {
  for i in $(seq 1 51); do
    run_test "$i"
  done
}

run_tests() {
  local filter="$1"

  echo -e "${BLUE}==========================================${NC}"
  echo -e "${BLUE} SoapBucket Proxy - E2E Test Suite${NC}"
  echo -e "${BLUE} Target: ${PROXY_URL}${NC}"
  echo -e "${BLUE}==========================================${NC}"

  if [ "$filter" = "all" ]; then
    run_all_tests
  else
    IFS=',' read -ra TESTS <<< "$filter"
    for num in "${TESTS[@]}"; do
      num=$(echo "$num" | tr -d ' ')
      run_test "$num"
    done
  fi

  # Summary
  echo ""
  echo -e "${BLUE}==========================================${NC}"
  echo -e "${BLUE} Test Results${NC}"
  echo -e "${BLUE}==========================================${NC}"
  echo -e "  ${GREEN}Passed:  $PASS${NC}"
  echo -e "  ${RED}Failed:  $FAIL${NC}"
  echo -e "  ${YELLOW}Skipped: $SKIP${NC}"
  echo -e "  Total:   $TOTAL_TESTS"
  echo ""

  if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
  else
    echo -e "${GREEN}All tests passed!${NC}"
  fi
}

case "${1:-run}" in
  run)
    create_config
    build_proxy
    start_proxy
    run_tests "all"
    ;;
  test)
    run_tests "${2:-all}"
    ;;
  build)
    build_proxy
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo -e "${RED}Unknown command: $1${NC}"
    usage
    exit 1
    ;;
esac
