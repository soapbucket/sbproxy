#!/bin/bash
# Performance benchmark for the Rust sbproxy binary
#
# Runs identical load tests against the release binary.
# Requires: oha (HTTP load generator), or falls back to curl-based timing.
#
# Usage:
#   ./scripts/perf-compare.sh              # Run all scenarios
#   ./scripts/perf-compare.sh basic        # Run specific scenario

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
PORT=18080
DURATION="${DURATION:-10}"  # seconds per test

BUILD_TARGET_DIR="${CARGO_TARGET_DIR:-$WORKSPACE/target}"
BUILD_BINARY=true
if [ -n "${SBPROXY_BIN:-}" ]; then
    BUILD_BINARY=false
else
    SBPROXY_BIN="$BUILD_TARGET_DIR/release/sbproxy"
fi
PERF_TMP_DIR=""
ACTIVE_PID=""

BOLD='\033[1m'
NC='\033[0m'

stop_pid() {
    local pid="$1"
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        return
    fi
    kill "$pid" 2>/dev/null || true
    for _ in {1..20}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

stop_active() {
    if [ -n "$ACTIVE_PID" ]; then
        stop_pid "$ACTIVE_PID"
        ACTIVE_PID=""
    fi
}

reject_occupied_port() {
    local owners
    owners="$(lsof -ti ":$PORT" 2>/dev/null || true)"
    if [ -n "$owners" ]; then
        echo "Error: benchmark port $PORT is occupied by PID(s): $(echo "$owners" | tr '\n' ' ')" >&2
        return 1
    fi
}

cleanup() {
    stop_active
    if [ -n "$PERF_TMP_DIR" ] && [ -d "$PERF_TMP_DIR" ]; then
        rm -f -- \
            "$PERF_TMP_DIR/perf-basic.yml" \
            "$PERF_TMP_DIR/perf-middleware.yml" \
            "$PERF_TMP_DIR/perf-echo.yml"
        rmdir -- "$PERF_TMP_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Check prerequisites
if ! command -v curl &>/dev/null; then
    echo "Error: curl required"
    exit 1
fi

HAS_OHA=false
if command -v oha &>/dev/null; then
    HAS_OHA=true
fi

PERF_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-perf.XXXXXX")"

# Build Rust binary
if $BUILD_BINARY; then
    echo "Building Rust binary..."
    cd "$WORKSPACE"
    cargo build --release -p sbproxy 2>&1 | tail -1
else
    if [ ! -x "$SBPROXY_BIN" ]; then
        echo "Error: SBPROXY_BIN is not executable: $SBPROXY_BIN" >&2
        exit 1
    fi
    echo "Using Rust binary: $SBPROXY_BIN"
fi

# Create test configs
cat > "$PERF_TMP_DIR/perf-basic.yml" << 'YAML'
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

cat > "$PERF_TMP_DIR/perf-middleware.yml" << 'YAML'
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

cat > "$PERF_TMP_DIR/perf-echo.yml" << 'YAML'
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

    stop_active
    reject_occupied_port || return 1
    "$binary" serve -f "$config" >/dev/null 2>&1 &
    local pid=$!
    ACTIVE_PID="$pid"

    local ready=false
    for _ in $(seq 1 40); do
        if curl -sS -o /dev/null --max-time 1 \
            -H "Host: bench.test" "http://127.0.0.1:$PORT/" 2>/dev/null; then
            ready=true
            break
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    if ! $ready; then
        echo "  $label: FAILED TO START"
        stop_active
        return 1
    fi

    if $HAS_OHA; then
        local result
        if ! result=$(NO_COLOR=true oha -z "${DURATION}s" -c 64 --no-tui \
            -H "Host: bench.test" \
            "${extra_curl_args[@]}" \
            "http://127.0.0.1:$PORT/" 2>&1); then
            echo "  $label: oha failed: $result" >&2
            stop_active
            return 1
        fi

        local rps
        local p50
        local p99
        rps=$(echo "$result" | awk '$1 == "Requests/sec:" {print $2; exit}')
        p50=$(echo "$result" | awk '$1 == "50.00%" || $1 == "50%" {print $3 $4; exit}')
        p99=$(echo "$result" | awk '$1 == "99.00%" || $1 == "99%" {print $3 $4; exit}')
        rps="${rps:-N/A}"
        p50="${p50:-N/A}"
        p99="${p99:-N/A}"

        printf "  %-8s RPS: %-10s p50: %-10s p99: %-10s\n" "$label" "$rps" "$p50" "$p99"
    else
        # Fallback: measure with curl timing
        local total=0
        local count=100
        for _ in $(seq 1 $count); do
            local time_ms
            time_ms=$(curl -s -o /dev/null -w '%{time_total}' \
                -H "Host: bench.test" \
                "${extra_curl_args[@]}" \
                "http://127.0.0.1:$PORT/" 2>/dev/null)
            total=$(echo "$total + $time_ms" | bc)
        done
        local avg
        local est_rps
        avg=$(echo "scale=3; $total / $count" | bc)
        est_rps=$(echo "scale=0; 1 / $avg" | bc 2>/dev/null || echo "N/A")
        printf "  %-8s avg_latency: %ss  est_rps: ~%s (curl, %d samples)\n" "$label" "$avg" "$est_rps" "$count"
    fi

    stop_active
}

run_scenario() {
    local name="$1" config="$2"
    shift 2
    local extra_args=(); [ $# -gt 0 ] && extra_args=("$@")

    echo -e "\n${BOLD}=== $name ===${NC}"

    run_benchmark "$name" "$config" "$SBPROXY_BIN" "sbproxy" "${extra_args[@]}"
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
    run_scenario "Basic Static" "$PERF_TMP_DIR/perf-basic.yml"
fi
if [ "$scenarios" = "middleware" ] || [ "$scenarios" = "all" ]; then
    run_scenario "Full Middleware" "$PERF_TMP_DIR/perf-middleware.yml" -H "X-Api-Key: bench-key-1"
fi
if [ "$scenarios" = "echo" ] || [ "$scenarios" = "all" ]; then
    run_scenario "Echo Action" "$PERF_TMP_DIR/perf-echo.yml"
fi

# Memory benchmark
echo -e "\n${BOLD}=== Memory Usage ===${NC}"
stop_active
reject_occupied_port
"$SBPROXY_BIN" serve -f "$PERF_TMP_DIR/perf-basic.yml" --log-level error >/dev/null 2>&1 &
SBPROXY_PID=$!
ACTIVE_PID="$SBPROXY_PID"
sleep 1
if kill -0 "$SBPROXY_PID" 2>/dev/null; then
    SBPROXY_RSS=$(ps -o rss= -p "$SBPROXY_PID" 2>/dev/null | tr -d ' ')
    SBPROXY_RSS_MB=$(echo "scale=1; $SBPROXY_RSS / 1024" | bc 2>/dev/null || echo "N/A")
    echo "  sbproxy RSS: ${SBPROXY_RSS_MB} MB (idle)"

    # Send some requests then check again
    for _ in $(seq 1 100); do
        curl -s -o /dev/null -H "Host: bench.test" "http://127.0.0.1:$PORT/" 2>/dev/null
    done
    sleep 0.5
    SBPROXY_RSS_LOADED=$(ps -o rss= -p "$SBPROXY_PID" 2>/dev/null | tr -d ' ')
    SBPROXY_RSS_LOADED_MB=$(echo "scale=1; $SBPROXY_RSS_LOADED / 1024" | bc 2>/dev/null || echo "N/A")
    echo "  sbproxy RSS: ${SBPROXY_RSS_LOADED_MB} MB (after 100 requests)"

    stop_active
fi

stop_active
echo -e "\n${BOLD}Done.${NC}"
