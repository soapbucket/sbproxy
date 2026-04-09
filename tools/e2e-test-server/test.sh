#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

# Configuration
HTTP_URL="http://localhost:8090"
HTTPS_URL="https://localhost:8443"
WS_URL="ws://localhost:8091"
GRAPHQL_URL="http://localhost:8092"

echo "🧪 E2E Test Server - Test Suite"
echo "================================"
echo ""

# Helper function to test HTTP endpoints
test_http() {
  local name=$1
  local url=$2
  local expected_status=$3
  local extra_args=${4:-}
  
  echo -n "Testing: $name ... "
  
  response=$(curl -s -w "\n%{http_code}" $extra_args "$url" 2>/dev/null || echo "ERROR")
  
  if [ "$response" = "ERROR" ]; then
    echo -e "${RED}❌ FAIL${NC} (connection error)"
    ((FAILED++))
    return
  fi
  
  status=$(echo "$response" | tail -n 1)
  body=$(echo "$response" | head -n -1)
  
  if [ "$status" -eq "$expected_status" ]; then
    echo -e "${GREEN}✅ PASS${NC}"
    ((PASSED++))
  else
    echo -e "${RED}❌ FAIL${NC} (expected $expected_status, got $status)"
    ((FAILED++))
  fi
}

# Health checks
echo "📋 Health Checks"
echo "----------------"
test_http "HTTP Server Health" "$HTTP_URL/health" 200
test_http "HTTPS Server Health" "$HTTPS_URL/health" 200 "-k"
test_http "WebSocket Server Health" "http://localhost:8091/health" 200
test_http "GraphQL Server Health" "$GRAPHQL_URL/health" 200
echo ""

# Basic HTTP tests
echo "📋 Basic HTTP Tests"
echo "-------------------"
test_http "Root Endpoint" "$HTTP_URL/" 200
test_http "Simple 200" "$HTTP_URL/test/simple-200" 200
test_http "Not Found" "$HTTP_URL/test/not-found" 404
test_http "Error 500" "$HTTP_URL/test/error-500" 500
test_http "Rate Limited" "$HTTP_URL/test/rate-limited" 429
test_http "Custom Headers" "$HTTP_URL/test/custom-headers" 200
test_http "Large Payload" "$HTTP_URL/test/large-payload" 200
echo ""

# Error status code tests
echo "📋 Error Status Code Tests"
echo "--------------------------"
test_http "Error 400" "$HTTP_URL/test/error-400" 400
test_http "Error 401" "$HTTP_URL/test/error-401" 401
test_http "Error 403" "$HTTP_URL/test/error-403" 403
test_http "Error 408" "$HTTP_URL/test/error-408" 408
test_http "Error 410" "$HTTP_URL/test/error-410" 410
test_http "Error 413" "$HTTP_URL/test/error-413" 413
test_http "Error 414" "$HTTP_URL/test/error-414" 414
test_http "Error 415" "$HTTP_URL/test/error-415" 415
test_http "Error 422" "$HTTP_URL/test/error-422" 422
test_http "Error 451" "$HTTP_URL/test/error-451" 451
test_http "Error 502" "$HTTP_URL/test/error-502" 502
test_http "Error 504" "$HTTP_URL/test/error-504" 504
test_http "Error 507" "$HTTP_URL/test/error-507" 507
test_http "Error 508" "$HTTP_URL/test/error-508" 508
test_http "Error 510" "$HTTP_URL/test/error-510" 510
test_http "Error 511" "$HTTP_URL/test/error-511" 511
echo ""

# Error callback endpoint tests
echo "📋 Error Callback Endpoint Tests"
echo "--------------------------------"
echo -n "Error Callback 404 ... "
error_response=$(curl -s "$HTTP_URL/error/404")
if echo "$error_response" | grep -q "Error Page from Callback"; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi

echo -n "Error Callback 500 ... "
error_response=$(curl -s "$HTTP_URL/error/500")
if echo "$error_response" | grep -q "Error Page from Callback"; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi

echo -n "Error Callback JSON ... "
error_response=$(curl -s "$HTTP_URL/error/404?content_type=application/json")
if echo "$error_response" | grep -q "Error Page from Callback"; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi

echo -n "Error Callback XML ... "
error_response=$(curl -s "$HTTP_URL/error/500?content_type=application/xml")
if echo "$error_response" | grep -q "Error Page from Callback"; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi

echo -n "Error Callback Plain Text ... "
error_response=$(curl -s "$HTTP_URL/error/503?content_type=text/plain")
if echo "$error_response" | grep -q "Error Page from Callback"; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi

echo -n "Error Callback Failure ... "
error_response=$(curl -s "$HTTP_URL/error/404?fail=true")
if echo "$error_response" | grep -q "Callback endpoint failed"; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi
echo ""

# Callback tests
echo "📋 Callback Tests"
echo "-----------------"
echo -n "Session Callback ... "
session_response=$(curl -s -X POST "$HTTP_URL/callback/session")
if echo "$session_response" | grep -q "user_preferences"; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi

echo -n "Auth Callback ... "
auth_response=$(curl -s -X POST "$HTTP_URL/callback/auth" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com"}')
if echo "$auth_response" | grep -q "roles"; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi
echo ""

# API tests
echo "📋 API Tests"
echo "------------"
test_http "Echo Endpoint" "$HTTP_URL/api/echo" 200 "-X POST -d '{\"test\":\"data\"}'"
test_http "Headers Endpoint" "$HTTP_URL/api/headers" 200
test_http "Status 200" "$HTTP_URL/api/status/200" 200
test_http "Status 404" "$HTTP_URL/api/status/404" 404
echo ""

# Delayed response test
echo "📋 Performance Tests"
echo "--------------------"
echo -n "Delayed Response (500ms) ... "
start_time=$(date +%s%N)
curl -s "$HTTP_URL/api/delay?ms=500" > /dev/null
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))
if [ $duration -ge 500 ] && [ $duration -le 1000 ]; then
  echo -e "${GREEN}✅ PASS${NC} (${duration}ms)"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC} (expected ~500ms, got ${duration}ms)"
  ((FAILED++))
fi
echo ""

# GraphQL tests
echo "📋 GraphQL Tests"
echo "----------------"
echo -n "GraphQL Users Query ... "
graphql_response=$(curl -s -X POST "$GRAPHQL_URL/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { id name email } }"}')
if echo "$graphql_response" | grep -q "data"; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi

echo -n "GraphQL User Query ... "
graphql_response=$(curl -s -X POST "$GRAPHQL_URL/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: \"1\") { name email } }"}')
if echo "$graphql_response" | grep -q "Alice"; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi

echo -n "GraphQL Posts Query ... "
graphql_response=$(curl -s -X POST "$GRAPHQL_URL/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ posts { id title } }"}')
if echo "$graphql_response" | grep -q "data"; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi
echo ""

# WebSocket tests (if websocat is available)
if command -v websocat &> /dev/null; then
  echo "📋 WebSocket Tests"
  echo "------------------"
  
  echo -n "WebSocket Echo ... "
  ws_response=$(echo "test message" | timeout 2 websocat "$WS_URL/echo" 2>/dev/null || echo "")
  if [ "$ws_response" = "test message" ]; then
    echo -e "${GREEN}✅ PASS${NC}"
    ((PASSED++))
  else
    echo -e "${RED}❌ FAIL${NC}"
    ((FAILED++))
  fi
  
  echo -n "WebSocket Timestamp ... "
  ws_timestamp=$(timeout 2 websocat -n1 "$WS_URL/timestamp" 2>/dev/null || echo "")
  if echo "$ws_timestamp" | grep -q "timestamp"; then
    echo -e "${GREEN}✅ PASS${NC}"
    ((PASSED++))
  else
    echo -e "${RED}❌ FAIL${NC}"
    ((FAILED++))
  fi
  echo ""
else
  echo -e "${YELLOW}⚠️  Skipping WebSocket tests (websocat not installed)${NC}"
  echo ""
fi

# Validation test
echo "📋 Validation Tests"
echo "-------------------"
echo -n "Response Validation ... "
validate_response=$(curl -s -X POST "$HTTP_URL/validate" \
  -H "Content-Type: application/json" \
  -d '{
    "scenario_id": "simple-200",
    "response": {
      "status": 200,
      "headers": {
        "Content-Type": "application/json"
      }
    }
  }')
if echo "$validate_response" | grep -q '"valid":true'; then
  echo -e "${GREEN}✅ PASS${NC}"
  ((PASSED++))
else
  echo -e "${RED}❌ FAIL${NC}"
  ((FAILED++))
fi
echo ""

# Summary
echo "================================"
echo "📊 Test Summary"
echo "================================"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo "Total:  $((PASSED + FAILED))"
echo ""

if [ $FAILED -eq 0 ]; then
  echo -e "${GREEN}✅ All tests passed!${NC}"
  exit 0
else
  echo -e "${RED}❌ Some tests failed${NC}"
  exit 1
fi

