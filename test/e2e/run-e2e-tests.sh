#!/usr/bin/env bash
# E2E Test Suite Runner
#
# This script runs the Go-based E2E test suite against a running proxy + test server environment.
#
# Prerequisites:
#   - Proxy running on http://localhost:8080 (HTTP) and https://localhost:8443 (HTTPS)
#   - E2E test server running on http://localhost:8090
#   - Proxy telemetry endpoint at http://localhost:8888
#   - All test fixtures loaded into the proxy origin storage
#
# Environment Variables (all optional, shown with defaults):
#   E2E_PROXY_HTTP_URL=http://localhost:8080
#   E2E_PROXY_HTTPS_URL=https://localhost:8443
#   E2E_PROXY_TELEMETRY_URL=http://localhost:8888
#   E2E_TEST_SERVER_URL=http://localhost:8090
#
# Usage:
#   ./run-e2e-tests.sh                     # Run all tests
#   ./run-e2e-tests.sh -run TestBasicProxy  # Run specific test
#   ./run-e2e-tests.sh -v                  # Verbose output
#   ./run-e2e-tests.sh -count 1            # Disable test caching

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "E2E Test Suite"
echo "=============="
echo ""
echo "Proxy HTTP:       ${E2E_PROXY_HTTP_URL:-http://localhost:8080}"
echo "Proxy HTTPS:      ${E2E_PROXY_HTTPS_URL:-https://localhost:8443}"
echo "Proxy Telemetry:  ${E2E_PROXY_TELEMETRY_URL:-http://localhost:8888}"
echo "Test Server:      ${E2E_TEST_SERVER_URL:-http://localhost:8090}"
echo ""

# Check if proxy is reachable
TELEMETRY_URL="${E2E_PROXY_TELEMETRY_URL:-http://localhost:8888}"
echo "Checking proxy availability..."
if curl -sf "${TELEMETRY_URL}/metrics" > /dev/null 2>&1; then
    echo "Proxy is reachable"
else
    echo "WARNING: Proxy is not reachable at ${TELEMETRY_URL}/metrics"
    echo "Tests will be skipped if infrastructure is not available."
    echo ""
fi

# Check if test server is reachable
TEST_SERVER_URL="${E2E_TEST_SERVER_URL:-http://localhost:8090}"
echo "Checking test server availability..."
if curl -sf "${TEST_SERVER_URL}/health" > /dev/null 2>&1; then
    echo "Test server is reachable"
else
    echo "WARNING: Test server is not reachable at ${TEST_SERVER_URL}/health"
    echo "Tests will be skipped if infrastructure is not available."
    echo ""
fi

echo ""
echo "Running E2E tests..."
echo ""

# Run the Go test suite
cd "$PROXY_ROOT"
go test ./test/e2e/... -timeout 120s "$@"

echo ""
echo "E2E tests completed."
