#!/bin/bash
# Performance comparison: Rust sbproxy vs Go sbproxy
#
# Runs identical load tests against both binaries and compares results.
# Requires: oha (HTTP load generator), or falls back to curl-based timing.
#
# Usage:
#   ./scripts/perf-compare.sh              # Run all scenarios
#   ./scripts/perf-compare.sh basic        # Run specific scenario

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
PORT=18080
DURATION=10  # seconds per test

RUST_BIN="$WORKSPACE/target/release/sbproxy"
GO_BIN="${GO_SBPROXY:-}"  # Set GO_SBPROXY env var to Go binary path

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

cleanup() {
    lsof -ti :$PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti :18888 2>/dev/null | xargs kill -9 2>/dev/null || true
}

# Check prerequisites
if ! command -v curl &>/dev/null; then
    echo "Error: curl required"
    exit 1
fi

HAS_OHA=false
if command -v oha &>/dev/null; then
    HAS_OHA=true
fi

# Build Rust binary
echo "Building Rust binary..."
cd "$WORKSPACE"
cargo build --release -p sbproxy 2>&1 | tail -1

if [ -z "$GO_BIN" ]; then
    echo ""
    echo -e "${YELLOW}NOTE: GO_SBPROXY not set. Running Rust-only benchmarks.${NC}"
    echo "Set GO_SBPROXY=/path/to/go/sbproxy to enable comparison."
    echo ""
fi

# Create test configs
cat > /tmp/perf-basic.yml << 'YAML'
proxy:
  http_bind_port: 18080
origins:
  "bench.test":
    action:
      type: static
      status: 200
      body: '{"status":"ok","timestamp":1234567890}'
      content_type: application/json
YAML

cat > /tmp/perf-middleware.yml << 'YAML'
proxy:
  http_bind_port: 18080
origins:
  "bench.test":
    action:
      type: static
      status: 200
      body: '{"status":"ok"}'
      content_type: application/json
    authentication:
      type: api_key
      api_keys: ["bench-key-1"]
    policies:
      - type: rate_limiting
        requests_per_second: 100000
        burst: 100000
    cors:
      allowed_origins: ["*"]
      allowed_methods: ["GET", "POST"]
    hsts:
      max_age: 31536000
    response_modifiers:
      - headers:
          set:
            x-bench: "true"
YAML

cat > /tmp/perf-echo.yml << 'YAML'
proxy:
  http_bind_port: 18080
origins:
  "bench.test":
    action:
      type: echo
YAML

run_benchmark() {
    local name="$1" config="$2" binary="$3" label="$4"
    shift 4
    local extra_curl_args=("$@")

    cleanup
    "$binary" --config "$config" 2>/dev/null &
    local pid=$!
    sleep 0.5

    if ! kill -0 "$pid" 2>/dev/null; then
        echo "  $label: FAILED TO START"
        return
    fi

    if $HAS_OHA; then
        local result
        result=$(oha -z "${DURATION}s" -c 64 --no-tui \
            -H "Host: bench.test" \
            "${extra_curl_args[@]}" \
            "http://127.0.0.1:$PORT/" 2>&1 || true)

        local rps=$(echo "$result" | grep "Requests/sec" | awk '{print $2}' || echo "N/A")
        local p50=$(echo "$result" | grep "50%" | awk '{print $2}' || echo "N/A")
        local p99=$(echo "$result" | grep "99%" | awk '{print $2}' || echo "N/A")

        printf "  %-8s RPS: %-10s p50: %-10s p99: %-10s\n" "$label" "$rps" "$p50" "$p99"
    else
        # Fallback: measure with curl timing
        local total=0
        local count=100
        for i in $(seq 1 $count); do
            local time_ms
            time_ms=$(curl -s -o /dev/null -w '%{time_total}' \
                -H "Host: bench.test" \
                "${extra_curl_args[@]}" \
                "http://127.0.0.1:$PORT/" 2>/dev/null)
            total=$(echo "$total + $time_ms" | bc)
        done
        local avg=$(echo "scale=3; $total / $count" | bc)
        local est_rps=$(echo "scale=0; 1 / $avg" | bc 2>/dev/null || echo "N/A")
        printf "  %-8s avg_latency: %ss  est_rps: ~%s (curl, %d samples)\n" "$label" "$avg" "$est_rps" "$count"
    fi

    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    cleanup
}

run_scenario() {
    local name="$1" config="$2"
    shift 2
    local extra_args=(); [ $# -gt 0 ] && extra_args=("$@")

    echo -e "\n${BOLD}=== $name ===${NC}"

    run_benchmark "$name" "$config" "$RUST_BIN" "Rust" "${extra_args[@]}"

    if [ -n "$GO_BIN" ] && [ -f "$GO_BIN" ]; then
        run_benchmark "$name" "$config" "$GO_BIN" "Go" "${extra_args[@]}"
    fi
}

# Determine which scenarios to run
scenarios="${1:-all}"

echo -e "${BOLD}Performance Comparison${NC}"
echo "Duration: ${DURATION}s per test"
echo "Concurrency: 64"
if $HAS_OHA; then
    echo "Tool: oha"
else
    echo "Tool: curl (install oha for accurate results)"
fi

if [ "$scenarios" = "basic" ] || [ "$scenarios" = "all" ]; then
    run_scenario "Basic Static" "/tmp/perf-basic.yml"
fi
if [ "$scenarios" = "middleware" ] || [ "$scenarios" = "all" ]; then
    run_scenario "Full Middleware" "/tmp/perf-middleware.yml" -H "X-Api-Key: bench-key-1"
fi
if [ "$scenarios" = "echo" ] || [ "$scenarios" = "all" ]; then
    run_scenario "Echo Action" "/tmp/perf-echo.yml"
fi

# Memory comparison
echo -e "\n${BOLD}=== Memory Usage ===${NC}"
cleanup
"$RUST_BIN" --config /tmp/perf-basic.yml 2>/dev/null &
RUST_PID=$!
sleep 1
if kill -0 "$RUST_PID" 2>/dev/null; then
    RUST_RSS=$(ps -o rss= -p "$RUST_PID" 2>/dev/null | tr -d ' ')
    RUST_RSS_MB=$(echo "scale=1; $RUST_RSS / 1024" | bc 2>/dev/null || echo "N/A")
    echo "  Rust RSS: ${RUST_RSS_MB} MB (idle)"

    # Send some requests then check again
    for i in $(seq 1 100); do
        curl -s -o /dev/null -H "Host: bench.test" "http://127.0.0.1:$PORT/" 2>/dev/null
    done
    sleep 0.5
    RUST_RSS_LOADED=$(ps -o rss= -p "$RUST_PID" 2>/dev/null | tr -d ' ')
    RUST_RSS_LOADED_MB=$(echo "scale=1; $RUST_RSS_LOADED / 1024" | bc 2>/dev/null || echo "N/A")
    echo "  Rust RSS: ${RUST_RSS_LOADED_MB} MB (after 1K requests)"

    kill "$RUST_PID" 2>/dev/null; wait "$RUST_PID" 2>/dev/null
fi

cleanup
echo -e "\n${BOLD}Done.${NC}"
