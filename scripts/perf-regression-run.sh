#!/usr/bin/env bash
# perf-regression-run.sh - run one bench iteration, emit a JSON line.
#
# WOR-32. Used by .github/workflows/perf-regression.yml on PRs that
# touch the hot-path crates. The script:
#
#   1. Builds the sbproxy binary in --release at the current checkout.
#   2. Boots it with a minimal static-200 config on a non-default port.
#   3. Samples idle RSS via `ps`.
#   4. Runs `oha` against it for $DURATION_SECS at concurrency $OHA_CONNS.
#   5. Samples max RSS during the run (best-effort poll).
#   6. Tears the proxy down and emits the JSON file consumed by
#      `perf-regression-comment.py`.
#
# The bench-synthetic crate at the workspace root is a 402-correctness
# probe, not a perf bench, so this script drives `oha` directly. Output
# JSON shape is documented at the top of `perf-regression-comment.py`.
#
# Usage:
#   scripts/perf-regression-run.sh OUT_JSON [LABEL]
#
# Environment overrides (defaults in parens):
#   DURATION_SECS  (10)   - seconds of steady-state load
#   WARMUP_SECS    (3)    - seconds of warm-up before measurement
#   OHA_CONNS      (32)   - concurrency
#   PROXY_PORT     (28080)- listen port for the bench proxy
#   RSS_POLL_MS    (200)  - max-RSS sampling cadence in milliseconds

set -euo pipefail

OUT_JSON="${1:?usage: perf-regression-run.sh OUT_JSON [LABEL]}"
LABEL="${2:-bench}"

DURATION_SECS="${DURATION_SECS:-10}"
WARMUP_SECS="${WARMUP_SECS:-3}"
OHA_CONNS="${OHA_CONNS:-32}"
PROXY_PORT="${PROXY_PORT:-28080}"
RSS_POLL_MS="${RSS_POLL_MS:-200}"

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
TMP_DIR="$(mktemp -d -t perf-regression-XXXXXX)"
CONFIG="${TMP_DIR}/config.yml"
OHA_OUT="${TMP_DIR}/oha.json"
PID_FILE="${TMP_DIR}/proxy.pid"
RSS_LOG="${TMP_DIR}/rss.log"

cleanup() {
    if [ -f "${PID_FILE}" ]; then
        local pid
        pid="$(cat "${PID_FILE}" 2>/dev/null || echo)"
        if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
        fi
    fi
    # Stray listener cleanup. lsof may not exist (e.g. minimal CI image),
    # so this is best-effort.
    if command -v lsof >/dev/null 2>&1; then
        lsof -ti ":${PROXY_PORT}" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    fi
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "[perf-regression-run] label=${LABEL} workspace=${WORKSPACE}"
echo "[perf-regression-run] duration=${DURATION_SECS}s warmup=${WARMUP_SECS}s connections=${OHA_CONNS} port=${PROXY_PORT}"

# --- Build the binary ---
echo "[perf-regression-run] cargo build --release -p sbproxy"
( cd "${WORKSPACE}" && cargo build --release -p sbproxy --locked )

PROXY_BIN="${WORKSPACE}/target/release/sbproxy"
if [ ! -x "${PROXY_BIN}" ]; then
    echo "ERROR: ${PROXY_BIN} not found or not executable" >&2
    exit 1
fi

# --- Bench config ---
# Minimal static-200 origin. Same shape as scripts/perf-compare.sh.
# Static action means the bench measures the proxy's hot path and not
# any upstream. Hostname is `bench.test` so requests need a Host header.
cat > "${CONFIG}" <<YAML
proxy:
  http_bind_port: ${PROXY_PORT}
origins:
  "bench.test":
    action:
      type: static
      status: 200
      body: '{"status":"ok"}'
      content_type: application/json
YAML

# --- Boot the proxy ---
"${PROXY_BIN}" --config "${CONFIG}" >"${TMP_DIR}/proxy.stdout" 2>"${TMP_DIR}/proxy.stderr" &
PROXY_PID=$!
echo "${PROXY_PID}" > "${PID_FILE}"

# Wait for listener up to 10s. Probe with curl; the static action returns
# 200, so a successful curl means the proxy is serving.
ready=0
for _ in $(seq 1 50); do
    if curl -sf -o /dev/null -H "Host: bench.test" "http://127.0.0.1:${PROXY_PORT}/" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.2
done
if [ "${ready}" != "1" ]; then
    echo "[perf-regression-run] proxy never became ready, dumping stderr:"
    sed -n '1,80p' "${TMP_DIR}/proxy.stderr" >&2 || true
    exit 1
fi

# --- Idle RSS sample ---
# `ps -o rss=` returns kilobytes on Linux (the GitHub runners we target).
# macOS local runs also report kB, so the unit is portable for our use.
IDLE_RSS_KB="$(ps -o rss= -p "${PROXY_PID}" 2>/dev/null | tr -d ' ' || echo 0)"
IDLE_RSS_KB="${IDLE_RSS_KB:-0}"
echo "[perf-regression-run] idle_rss_kb=${IDLE_RSS_KB}"

# --- Background RSS sampler for max-RSS ---
# Poll RSS every $RSS_POLL_MS during the load run. The python step at
# the end reduces the log to a max. Polling instead of relying on
# /proc/<pid>/status VmHWM keeps the script portable to non-Linux test
# runs (the GH workflow is ubuntu-latest, so VmHWM would also work).
( while kill -0 "${PROXY_PID}" 2>/dev/null; do
    ps -o rss= -p "${PROXY_PID}" 2>/dev/null | tr -d ' ' >> "${RSS_LOG}" || true
    # Convert ms to seconds for `sleep`.
    sleep "$(awk -v ms="${RSS_POLL_MS}" 'BEGIN{print ms/1000}')"
  done ) &
SAMPLER_PID=$!

# --- Warm-up: short oha run that we discard ---
echo "[perf-regression-run] warming up for ${WARMUP_SECS}s"
oha -z "${WARMUP_SECS}s" -c "${OHA_CONNS}" --no-tui \
    -H "Host: bench.test" \
    "http://127.0.0.1:${PROXY_PORT}/" >/dev/null 2>&1 || true

# --- Measured run ---
echo "[perf-regression-run] running for ${DURATION_SECS}s"
oha -z "${DURATION_SECS}s" -c "${OHA_CONNS}" --no-tui --json \
    -H "Host: bench.test" \
    "http://127.0.0.1:${PROXY_PORT}/" > "${OHA_OUT}"

# --- Stop the sampler, read max RSS ---
kill "${SAMPLER_PID}" 2>/dev/null || true
wait "${SAMPLER_PID}" 2>/dev/null || true
MAX_RSS_KB="$(awk 'BEGIN{m=0} {if ($1+0 > m) m=$1+0} END{print m+0}' "${RSS_LOG}" 2>/dev/null || echo 0)"
if [ "${MAX_RSS_KB}" = "0" ]; then
    # Sampler never landed a sample; fall back to the idle reading so the
    # downstream gate still has a non-zero baseline to compare against.
    MAX_RSS_KB="${IDLE_RSS_KB}"
fi
echo "[perf-regression-run] max_rss_kb=${MAX_RSS_KB}"

# --- Render the bench JSON ---
# `oha --json` shape (oha 1.x): top-level "summary" with "requestsPerSec",
# and "latencyPercentiles" with p50/p95/p99 in seconds. Convert to ms.
# We use python so any future oha shape change is a one-spot fix.
python3 - "${OHA_OUT}" "${OUT_JSON}" "${IDLE_RSS_KB}" "${MAX_RSS_KB}" <<'PY'
import json, sys
oha_path, out_path, idle_rss, max_rss = sys.argv[1:]
data = json.loads(open(oha_path).read())
summary = data.get("summary", {})
percentiles = data.get("latencyPercentiles", {})
# oha emits seconds. Convert to ms with 3-decimal precision; downstream
# script formats the printed value, but we keep full float here.
def ms(v):
    try:
        return float(v) * 1000.0
    except (TypeError, ValueError):
        return 0.0
out = {
    "rps": float(summary.get("requestsPerSec", 0.0)),
    "p50_ms": ms(percentiles.get("p50")),
    "p95_ms": ms(percentiles.get("p95")),
    "p99_ms": ms(percentiles.get("p99")),
    "idle_rss_kb": int(idle_rss),
    "max_rss_kb": int(max_rss),
    "schema_version": "1",
}
open(out_path, "w").write(json.dumps(out, indent=2))
print(json.dumps(out))
PY

echo "[perf-regression-run] wrote ${OUT_JSON}"
