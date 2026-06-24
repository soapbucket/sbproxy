#!/usr/bin/env bash
# Record VHS cassettes for sbproxy examples.
#
# Each tape under docs/tapes/ declares the config it should run against with a
# `# CONFIG: <path>` directive near the top. This script starts the release
# binary with that config (provider keys sourced from the environment), waits
# for the admin readiness probe, records the tape against the live proxy, then
# stops it. Provider keys stay in the environment and are never typed on screen.
#
# Usage:
#   scripts/record-tapes.sh                 # record every tape in docs/tapes/
#   scripts/record-tapes.sh ai-gateway      # record docs/tapes/ai-gateway.tape
#   scripts/record-tapes.sh docs/tapes/ai-fallback.tape
#
# Environment:
#   SBPROXY_BIN        proxy binary (default: ./target/release/sbproxy)
#   SBPROXY_DEMO_ENV   env file with provider keys (default: ../test/.env)
#
# Requires: vhs, ttyd, ffmpeg, curl, jq (brew install vhs jq).
set -euo pipefail

cd "$(dirname "$0")/.."

BIN="${SBPROXY_BIN:-./target/release/sbproxy}"
ENV_FILE="${SBPROXY_DEMO_ENV:-../test/.env}"
REC_LOG="/tmp/sbproxy-rec.log"
export SBPROXY_REC_LOG="$REC_LOG"

if [ ! -x "$BIN" ]; then
  echo "error: $BIN not found. Build it first: make build-release" >&2
  exit 1
fi
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
  echo "loaded provider keys from $ENV_FILE"
else
  echo "note: $ENV_FILE not found; relying on keys already in the environment"
fi

free_ports() {
  local p pids
  for p in 8080 9090; do
    pids="$(lsof -ti "tcp:$p" 2>/dev/null || true)"
    [ -n "$pids" ] && kill -9 $pids 2>/dev/null || true
  done
  sleep 0.3
}

record() {
  local tape="$1"
  [ -f "$tape" ] || tape="docs/tapes/${tape%.tape}.tape"
  if [ ! -f "$tape" ]; then echo "skip: no such tape $tape" >&2; return 1; fi

  local cfg
  cfg="$(sed -n 's/^# CONFIG:[[:space:]]*//p' "$tape" | head -n1)"
  if [ -z "$cfg" ]; then echo "skip: $tape has no '# CONFIG:' directive" >&2; return 1; fi
  if [ ! -f "$cfg" ]; then echo "skip: config $cfg (from $tape) missing" >&2; return 1; fi

  # Examples bind the data listener on http_bind_port (default 8080) and do
  # not start the optional admin server, so readiness is probed on the data
  # port: any HTTP response (even a 404) means the listener is accepting.
  local port
  port="$(sed -n 's/^[[:space:]]*http_bind_port:[[:space:]]*//p' "$cfg" | head -n1)"
  port="${port:-8080}"

  # A tape may raise the proxy log level (e.g. the fallback demo greps the
  # log for a failover WARN). Default to error so the log stays quiet.
  local loglevel
  loglevel="$(sed -n 's/^# LOGLEVEL:[[:space:]]*//p' "$tape" | head -n1)"
  loglevel="${loglevel:-error}"

  echo "==> $tape   (config: $cfg, port: $port, log: $loglevel)"
  free_ports
  RUST_LOG="$loglevel" NO_COLOR=1 "$BIN" "$cfg" >"$REC_LOG" 2>&1 &
  local pid=$!

  local ready=""
  for _ in $(seq 1 80); do
    if curl -s -o /dev/null --max-time 2 "localhost:$port" >/dev/null 2>&1; then ready=1; break; fi
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 0.25
  done
  if [ -z "$ready" ]; then
    echo "error: proxy never became ready for $cfg; see $REC_LOG" >&2
    tail -n 5 "$REC_LOG" >&2 || true
    kill "$pid" 2>/dev/null || true
    return 1
  fi

  vhs "$tape"
  local rc=$?

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return $rc
}

tapes=("$@")
if [ ${#tapes[@]} -eq 0 ]; then
  # default order: headline cassettes first, then the rest
  tapes=(ai-gateway ai-fallback semantic-cache ai-guardrails)
  for t in docs/tapes/*.tape; do
    case " ${tapes[*]} " in *" $(basename "$t" .tape) "*) : ;; *) tapes+=("$t") ;; esac
  done
fi

failed=0
for t in "${tapes[@]}"; do
  record "$t" || failed=$((failed + 1))
done

free_ports
if [ "$failed" -gt 0 ]; then
  echo "done with $failed failure(s)" >&2
  exit 1
fi
echo "done; GIFs written to docs/assets/"
