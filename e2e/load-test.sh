#!/usr/bin/env bash
# load-test.sh - Compare direct vs proxied request latency through sbproxy
#
# Usage:
#   ./load-test.sh [-n requests] [-c concurrency] [-q quiet]
#
# Examples:
#   ./load-test.sh              # 100 requests, 10 concurrency
#   ./load-test.sh -n 500 -c 20 # 500 requests, 20 concurrency

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NUM_REQUESTS="${NUM_REQUESTS:-100}"
CONCURRENCY="${CONCURRENCY:-10}"
QUIET=0

PROXY_PORT=18080
ORIGIN_PORT=18889
PROXY_HOST="loadtest.test"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_DIR="$SCRIPT_DIR/load-test-tmp"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while getopts "n:c:q" opt; do
    case $opt in
        n) NUM_REQUESTS="$OPTARG" ;;
        c) CONCURRENCY="$OPTARG" ;;
        q) QUIET=1 ;;
        *) echo "Usage: $0 [-n requests] [-c concurrency] [-q]"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------
PIDS_TO_KILL=()

cleanup() {
    echo ""
    echo -e "${DIM}Cleaning up...${RESET}"
    for pid in "${PIDS_TO_KILL[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo -e "${BLUE}>>>${RESET} $*"; }
warn() { echo -e "${YELLOW}WARNING:${RESET} $*"; }
err() { echo -e "${RED}ERROR:${RESET} $*" >&2; }

wait_for_port() {
    local port=$1 name=$2 tries=30
    while ! curl -sf "http://127.0.0.1:$port/health" >/dev/null 2>&1 && \
          ! curl -sf "http://127.0.0.1:$port/echo" >/dev/null 2>&1; do
        tries=$((tries - 1))
        if [ "$tries" -le 0 ]; then
            err "$name did not start on port $port"
            exit 1
        fi
        sleep 0.2
    done
}

# Calculate percentile from sorted file of numbers.
# Usage: percentile <file> <p> (p in 0-100)
percentile() {
    local file=$1 p=$2
    local count
    count=$(wc -l < "$file" | tr -d ' ')
    if [ "$count" -eq 0 ]; then echo "0"; return; fi
    local idx
    idx=$(awk "BEGIN { printf \"%d\", ($p / 100.0) * $count + 0.5 }")
    [ "$idx" -lt 1 ] && idx=1
    [ "$idx" -gt "$count" ] && idx="$count"
    sed -n "${idx}p" "$file"
}

avg() {
    local file=$1
    awk '{ sum += $1; n++ } END { if (n>0) printf "%.3f", sum/n; else print "0" }' "$file"
}

sum() {
    local file=$1
    awk '{ sum += $1 } END { printf "%.3f", sum }' "$file"
}

# ---------------------------------------------------------------------------
# Step 0: Prepare temp directory
# ---------------------------------------------------------------------------
mkdir -p "$TMP_DIR"

# ---------------------------------------------------------------------------
# Step 1: Build sbproxy
# ---------------------------------------------------------------------------
log "Building sbproxy..."
cd "$PROJECT_DIR"
go build -o "$SCRIPT_DIR/sbproxy" ./cmd/sbproxy/
log "Build complete."

# ---------------------------------------------------------------------------
# Step 2: Create sb.yml config
# ---------------------------------------------------------------------------
cat > "$TMP_DIR/sb.yml" <<'YAML'
proxy:
  http_bind_port: 18080
origins:
  "loadtest.test":
    action:
      type: proxy
      url: http://127.0.0.1:18889
YAML

# ---------------------------------------------------------------------------
# Step 3: Start callback server (origin) on port 18889
# ---------------------------------------------------------------------------
log "Starting origin server on port $ORIGIN_PORT..."
TEST_SERVER_PORT=$ORIGIN_PORT node "$SCRIPT_DIR/servers/test-server.js" &
PIDS_TO_KILL+=($!)
wait_for_port "$ORIGIN_PORT" "Origin server"
log "Origin server ready."

# ---------------------------------------------------------------------------
# Step 4: Start sbproxy on port 18080
# ---------------------------------------------------------------------------
log "Starting sbproxy on port $PROXY_PORT..."
"$SCRIPT_DIR/sbproxy" serve -f "$TMP_DIR/sb.yml" --log-level error >"$TMP_DIR/proxy.log" 2>&1 &
PIDS_TO_KILL+=($!)
sleep 0.5
wait_for_port "$PROXY_PORT" "sbproxy"
log "sbproxy ready."

# ---------------------------------------------------------------------------
# Step 5: Detect best load testing tool
# ---------------------------------------------------------------------------
TOOL="curl"
if command -v hey >/dev/null 2>&1; then
    TOOL="hey"
elif command -v wrk >/dev/null 2>&1; then
    TOOL="wrk"
fi

echo ""
echo -e "${BOLD}============================================================${RESET}"
echo -e "${BOLD}  Load Test: Direct vs Proxied${RESET}"
echo -e "${BOLD}============================================================${RESET}"
echo -e "  Tool:        ${CYAN}$TOOL${RESET}"
echo -e "  Requests:    ${CYAN}$NUM_REQUESTS${RESET}"
echo -e "  Concurrency: ${CYAN}$CONCURRENCY${RESET}"
echo -e "  Origin:      ${CYAN}http://127.0.0.1:$ORIGIN_PORT/echo${RESET}"
echo -e "  Proxy:       ${CYAN}http://127.0.0.1:$PROXY_PORT/echo${RESET} (Host: $PROXY_HOST)"
echo -e "${BOLD}============================================================${RESET}"
echo ""

# ---------------------------------------------------------------------------
# Run with hey
# ---------------------------------------------------------------------------
if [ "$TOOL" = "hey" ]; then
    log "Running direct requests with hey..."
    hey -n "$NUM_REQUESTS" -c "$CONCURRENCY" -o csv \
        "http://127.0.0.1:$ORIGIN_PORT/echo" > "$TMP_DIR/direct_hey.csv" 2>/dev/null

    log "Running proxied requests with hey..."
    hey -n "$NUM_REQUESTS" -c "$CONCURRENCY" -o csv \
        -host "$PROXY_HOST" \
        "http://127.0.0.1:$PROXY_PORT/echo" > "$TMP_DIR/proxy_hey.csv" 2>/dev/null

    # hey CSV columns: response-time(sec), status-code, offset, ...
    # Extract response times (skip header), convert to ms, sort
    tail -n +2 "$TMP_DIR/direct_hey.csv" | awk -F',' '{ printf "%.3f\n", $1 * 1000 }' | sort -n > "$TMP_DIR/direct_times.txt"
    tail -n +2 "$TMP_DIR/proxy_hey.csv"  | awk -F',' '{ printf "%.3f\n", $1 * 1000 }' | sort -n > "$TMP_DIR/proxy_times.txt"

# ---------------------------------------------------------------------------
# Run with wrk
# ---------------------------------------------------------------------------
elif [ "$TOOL" = "wrk" ]; then
    # wrk does not easily emit per-request latencies, so run it for summary and
    # fall back to curl for percentile data.
    DURATION="5s"
    log "Running direct requests with wrk (${DURATION})..."
    wrk -t2 -c"$CONCURRENCY" -d"$DURATION" \
        "http://127.0.0.1:$ORIGIN_PORT/echo" > "$TMP_DIR/direct_wrk.txt" 2>&1

    log "Running proxied requests with wrk (${DURATION})..."
    wrk -t2 -c"$CONCURRENCY" -d"$DURATION" \
        -H "Host: $PROXY_HOST" \
        "http://127.0.0.1:$PROXY_PORT/echo" > "$TMP_DIR/proxy_wrk.txt" 2>&1

    echo ""
    echo -e "${BOLD}--- Direct (wrk) ---${RESET}"
    cat "$TMP_DIR/direct_wrk.txt"
    echo ""
    echo -e "${BOLD}--- Proxied (wrk) ---${RESET}"
    cat "$TMP_DIR/proxy_wrk.txt"
    echo ""

    # Also run curl-based for percentile comparison
    log "Running curl-based benchmark for percentile stats..."
    TOOL="curl"
fi

# ---------------------------------------------------------------------------
# Run with curl (fallback or wrk supplement)
# ---------------------------------------------------------------------------
if [ "$TOOL" = "curl" ]; then
    CURL_FORMAT='%{time_total}\n'

    # -- Direct --
    log "Running $NUM_REQUESTS direct requests (concurrency $CONCURRENCY)..."
    direct_start=$(date +%s%3N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1000))')

    seq 1 "$NUM_REQUESTS" | xargs -P "$CONCURRENCY" -I{} \
        curl -sf -o /dev/null -w "$CURL_FORMAT" "http://127.0.0.1:$ORIGIN_PORT/echo" \
        >> "$TMP_DIR/direct_raw.txt" 2>/dev/null

    direct_end=$(date +%s%3N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1000))')

    # -- Proxied --
    log "Running $NUM_REQUESTS proxied requests (concurrency $CONCURRENCY)..."
    proxy_start=$(date +%s%3N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1000))')

    seq 1 "$NUM_REQUESTS" | xargs -P "$CONCURRENCY" -I{} \
        curl -sf -o /dev/null -w "$CURL_FORMAT" \
        -H "Host: $PROXY_HOST" \
        "http://127.0.0.1:$PROXY_PORT/echo" \
        >> "$TMP_DIR/proxy_raw.txt" 2>/dev/null

    proxy_end=$(date +%s%3N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1000))')

    # Convert seconds to ms, sort
    awk '{ printf "%.3f\n", $1 * 1000 }' "$TMP_DIR/direct_raw.txt" | sort -n > "$TMP_DIR/direct_times.txt"
    awk '{ printf "%.3f\n", $1 * 1000 }' "$TMP_DIR/proxy_raw.txt"  | sort -n > "$TMP_DIR/proxy_times.txt"
fi

# ---------------------------------------------------------------------------
# Step 6: Compute and display stats
# ---------------------------------------------------------------------------
if [ -f "$TMP_DIR/direct_times.txt" ] && [ -f "$TMP_DIR/proxy_times.txt" ]; then

    d_count=$(wc -l < "$TMP_DIR/direct_times.txt" | tr -d ' ')
    p_count=$(wc -l < "$TMP_DIR/proxy_times.txt" | tr -d ' ')

    d_avg=$(avg "$TMP_DIR/direct_times.txt")
    p_avg=$(avg "$TMP_DIR/proxy_times.txt")

    d_p50=$(percentile "$TMP_DIR/direct_times.txt" 50)
    d_p95=$(percentile "$TMP_DIR/direct_times.txt" 95)
    d_p99=$(percentile "$TMP_DIR/direct_times.txt" 99)

    p_p50=$(percentile "$TMP_DIR/proxy_times.txt" 50)
    p_p95=$(percentile "$TMP_DIR/proxy_times.txt" 95)
    p_p99=$(percentile "$TMP_DIR/proxy_times.txt" 99)

    d_min=$(head -1 "$TMP_DIR/direct_times.txt")
    d_max=$(tail -1 "$TMP_DIR/direct_times.txt")
    p_min=$(head -1 "$TMP_DIR/proxy_times.txt")
    p_max=$(tail -1 "$TMP_DIR/proxy_times.txt")

    d_total=$(sum "$TMP_DIR/direct_times.txt")
    p_total=$(sum "$TMP_DIR/proxy_times.txt")

    # Wall-clock time and rps (only available for curl mode)
    if [ -n "${direct_start:-}" ] && [ -n "${direct_end:-}" ]; then
        d_wall=$(awk "BEGIN { printf \"%.1f\", ($direct_end - $direct_start) / 1000.0 }")
        p_wall=$(awk "BEGIN { printf \"%.1f\", ($proxy_end - $proxy_start) / 1000.0 }")
        d_rps=$(awk "BEGIN { w = ($direct_end - $direct_start) / 1000.0; if (w>0) printf \"%.1f\", $d_count / w; else print \"N/A\" }")
        p_rps=$(awk "BEGIN { w = ($proxy_end - $proxy_start) / 1000.0; if (w>0) printf \"%.1f\", $p_count / w; else print \"N/A\" }")
    else
        d_wall="N/A"
        p_wall="N/A"
        d_rps=$(awk "BEGIN { t = $d_total / 1000.0; if (t>0) printf \"%.1f\", $d_count / t; else print \"N/A\" }")
        p_rps=$(awk "BEGIN { t = $p_total / 1000.0; if (t>0) printf \"%.1f\", $p_count / t; else print \"N/A\" }")
    fi

    # Overhead calculations
    oh_avg=$(awk "BEGIN { printf \"%.3f\", $p_avg - $d_avg }")
    oh_p50=$(awk "BEGIN { printf \"%.3f\", $p_p50 - $d_p50 }")
    oh_p95=$(awk "BEGIN { printf \"%.3f\", $p_p95 - $d_p95 }")
    oh_p99=$(awk "BEGIN { printf \"%.3f\", $p_p99 - $d_p99 }")
    oh_pct=$(awk "BEGIN { if ($d_avg > 0) printf \"%.1f\", (($p_avg - $d_avg) / $d_avg) * 100; else print \"N/A\" }")

    # Print results table
    echo ""
    echo -e "${BOLD}============================================================${RESET}"
    echo -e "${BOLD}  Results (all times in ms)${RESET}"
    echo -e "${BOLD}============================================================${RESET}"
    echo ""
    printf "  ${BOLD}%-14s %12s %12s %12s${RESET}\n" "Metric" "Direct" "Proxied" "Overhead"
    printf "  %-14s %12s %12s %12s\n"                 "--------------" "------------" "------------" "------------"
    printf "  %-14s %12s %12s\n"                       "Requests"       "$d_count"     "$p_count"
    printf "  %-14s %12s %12s %12s\n"                  "Avg"            "$d_avg"       "$p_avg"       "$oh_avg"
    printf "  %-14s %12s %12s %12s\n"                  "p50"            "$d_p50"       "$p_p50"       "$oh_p50"
    printf "  %-14s %12s %12s %12s\n"                  "p95"            "$d_p95"       "$p_p95"       "$oh_p95"
    printf "  %-14s %12s %12s %12s\n"                  "p99"            "$d_p99"       "$p_p99"       "$oh_p99"
    printf "  %-14s %12s %12s\n"                       "Min"            "$d_min"       "$p_min"
    printf "  %-14s %12s %12s\n"                       "Max"            "$d_max"       "$p_max"
    printf "  %-14s %12s %12s\n"                       "Wall (s)"       "$d_wall"      "$p_wall"
    printf "  %-14s %12s %12s\n"                       "Req/s"          "$d_rps"       "$p_rps"
    echo ""
    echo -e "  ${BOLD}Proxy overhead: ${CYAN}${oh_avg}ms${RESET} avg (${oh_pct}% increase)${RESET}"
    echo ""
    echo -e "${BOLD}============================================================${RESET}"

    # Color-coded verdict
    overhead_ok=$(awk "BEGIN { print ($p_avg < $d_avg * 2) ? 1 : 0 }")
    if [ "$overhead_ok" -eq 1 ]; then
        echo -e "  ${GREEN}Proxy overhead is within acceptable range.${RESET}"
    else
        echo -e "  ${RED}Proxy overhead is high - investigate sbproxy performance.${RESET}"
    fi
    echo -e "${BOLD}============================================================${RESET}"
    echo ""
fi

log "Done. Proxy log: $TMP_DIR/proxy.log"
