#!/usr/bin/env bash
# Live managed-serve certification lane (SH-18 / SH-23).
#
# Automates the procedure docs/model-host-certification.md describes by
# hand, so the Apple Metal and NVIDIA single-GPU lanes are a command with
# an exit code rather than a checklist someone reads. Drives the real
# binary against a real catalog model on this host and asserts, in order:
#
#   1. cold start reaches ready (pull + digest verification included)
#   2. a completion returns nonempty assistant content
#   3. the echoed `model` field is the public name, never a weights path
#   4. status reports engine, engine version, selected devices, a memory
#      breakdown, the engine port, and the verified artifact digest
#   5. stop drains, reaps the engine process, and keeps the snapshot
#   6. SIGINT exits the gateway cleanly and leaves no engine orphaned
#   7. a second run reuses the cache: same digest, no re-download, and
#      materially faster to ready
#
# Usage: cert-lane-managed-serve.sh <model> <variant> <accel-label>
#
# Env:
#   SBPROXY_BIN     binary under test. Default target/debug/sbproxy.
#   CERT_PORT       public port.  Default 48123.
#   CERT_ADMIN_PORT admin port.   Default 48124.
#   CERT_CACHE_DIR  weight cache. Default: sbproxy's own default, so the
#                   lane exercises the cache an operator actually gets.
#   CERT_ENGINE_PROC engine process name to check for orphans.
#                    Default llama-server.
set -uo pipefail

MODEL="${1:?usage: cert-lane-managed-serve.sh <model> <variant> <accel>}"
VARIANT="${2:?variant required}"
ACCEL="${3:-auto}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SBPROXY_BIN="${SBPROXY_BIN:-$REPO_ROOT/target/debug/sbproxy}"
CERT_PORT="${CERT_PORT:-48123}"
CERT_ADMIN_PORT="${CERT_ADMIN_PORT:-48124}"
CERT_ENGINE_PROC="${CERT_ENGINE_PROC:-llama-server}"
WORK="$(mktemp -d)"

pass=0
fail=0
ok()  { echo "  PASS $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL $1"; fail=$((fail + 1)); }

# Always leave the box the way we found it: no gateway, no engine. A
# certification lane that leaks a GPU-holding child process poisons every
# lane after it.
PROXY_PID=""
cleanup() {
  if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
    # SIGINT, not SIGKILL: graceful stop is what reaps the engine
    # children. SIGKILL orphans them.
    kill -INT "$PROXY_PID" 2>/dev/null || true
    for _ in $(seq 1 30); do
      kill -0 "$PROXY_PID" 2>/dev/null || break
      sleep 1
    done
    kill -9 "$PROXY_PID" 2>/dev/null || true
  fi
  pkill -f "$CERT_ENGINE_PROC" 2>/dev/null || true
}
trap cleanup EXIT

cache_args=()
[ -n "${CERT_CACHE_DIR:-}" ] && cache_args=(--cache-dir "$CERT_CACHE_DIR")

# Start a managed run and block until the ready banner appears. Echoes
# the seconds it took, so the caller can compare cold against warm.
start_run() {
  local log="$1" deadline="$2" start
  start="$(date +%s)"
  "$SBPROXY_BIN" run "$MODEL" \
    --variant "$VARIANT" \
    --port "$CERT_PORT" \
    --admin-port "$CERT_ADMIN_PORT" \
    "${cache_args[@]}" >"$log" 2>&1 &
  PROXY_PID=$!
  while [ "$(( $(date +%s) - start ))" -lt "$deadline" ]; do
    if grep -q "is ready on" "$log" 2>/dev/null; then
      echo "$(( $(date +%s) - start ))"
      return 0
    fi
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
      echo "-1"
      return 1
    fi
    sleep 1
  done
  echo "-1"
  return 1
}

admin_env() {
  local log="$1" password
  password="$(grep -m1 'Admin password:' "$log" | awk '{print $3}')"
  export SB_ADMIN_URL="http://127.0.0.1:$CERT_ADMIN_PORT"
  export SB_ADMIN_USERNAME=admin
  export SB_ADMIN_PASSWORD="$password"
  [ -n "$password" ]
}

echo "== managed serve lane: $MODEL:$VARIANT on $ACCEL =="
echo "   binary: $("$SBPROXY_BIN" --version 2>/dev/null | head -1)"
echo "   work:   $WORK"

# --- 1. cold start ------------------------------------------------------
cold_secs="$(start_run "$WORK/cold.log" 900)"
if [ "$cold_secs" = "-1" ]; then
  bad "cold start never reached ready"
  echo "--- last 40 lines of the run log ---"
  tail -40 "$WORK/cold.log"
  echo "== $pass passed, $fail failed =="
  exit 1
fi
ok "cold start reached ready in ${cold_secs}s"

if ! admin_env "$WORK/cold.log"; then
  bad "the ready banner did not carry an admin password"
  echo "== $pass passed, $fail failed =="
  exit 1
fi

# --- 2/3. completion ----------------------------------------------------
http_code="$(curl -sS -m 180 "http://127.0.0.1:$CERT_PORT/v1/chat/completions" \
  -H 'content-type: application/json' \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Return only the word ready.\"}]}" \
  -o "$WORK/completion.json" -w '%{http_code}')"
if [ "$http_code" = "200" ]; then
  content="$(python3 -c "
import json,sys
d = json.load(open('$WORK/completion.json'))
print(d['choices'][0]['message'].get('content') or '')
" 2>/dev/null)"
  if [ -n "${content// /}" ]; then
    ok "completion returned nonempty content: $(printf '%q' "$content")"
  else
    bad "completion returned empty assistant content"
  fi
  echoed="$(python3 -c "
import json
print(json.load(open('$WORK/completion.json')).get('model',''))
" 2>/dev/null)"
  if [ "$echoed" = "$MODEL" ]; then
    ok "echoed model field is the public name ($echoed)"
  else
    bad "echoed model field is '$echoed', expected '$MODEL' (a weights path must never reach a client)"
  fi
else
  bad "completion returned http $http_code"
  head -c 400 "$WORK/completion.json"; echo
fi

# --- 4. status truth ----------------------------------------------------
if "$SBPROXY_BIN" models ps --format json >"$WORK/ps-ready.json" 2>&1; then
  python3 - "$WORK/ps-ready.json" <<'PY' >"$WORK/ps-ready.txt" 2>&1
import json, sys
report = json.load(open(sys.argv[1]))
deployments = report.get("deployments") or []
if not deployments:
    print("FAIL no deployment in status")
    raise SystemExit(1)
d = deployments[0]
missing = [
    field
    for field in ("engine", "engine_version", "selected_devices", "memory", "port", "artifact_digest")
    if not d.get(field)
]
if missing:
    print(f"FAIL status omits {', '.join(missing)}")
    raise SystemExit(1)
if d.get("state") != "ready":
    print(f"FAIL state is {d.get('state')}, expected ready")
    raise SystemExit(1)
if not report.get("serving"):
    print("FAIL top-level serving is not true while a deployment is ready")
    raise SystemExit(1)
print(
    "OK engine={engine} {version} devices={devices} port={port} digest={digest}".format(
        engine=d["engine"],
        version=d["engine_version"],
        devices=d["selected_devices"],
        port=d["port"],
        digest=d["artifact_digest"],
    )
)
PY
  if grep -q '^OK' "$WORK/ps-ready.txt"; then
    ok "status is complete and truthful: $(sed 's/^OK //' "$WORK/ps-ready.txt")"
    DIGEST="$(python3 -c "
import json
print(json.load(open('$WORK/ps-ready.json'))['deployments'][0]['artifact_digest'])
")"
  else
    bad "$(cat "$WORK/ps-ready.txt")"
    DIGEST=""
  fi
else
  bad "models ps failed"
  DIGEST=""
fi

# --- 5. stop drains and reaps ------------------------------------------
engines_before="$(pgrep -f "$CERT_ENGINE_PROC" 2>/dev/null | wc -l | tr -d ' ')"
if "$SBPROXY_BIN" models stop local --format json >"$WORK/stop.json" 2>&1; then
  # Stop is a job; give the supervisor a bounded window to reap.
  reaped=false
  for _ in $(seq 1 30); do
    if [ "$(pgrep -f "$CERT_ENGINE_PROC" 2>/dev/null | wc -l | tr -d ' ')" -eq 0 ]; then
      reaped=true
      break
    fi
    sleep 1
  done
  if [ "$engines_before" -eq 0 ]; then
    # A container-mode engine is not a host process; the state assertion
    # below is the real check in that case.
    ok "stop accepted (engine runs out of process on this host)"
  elif [ "$reaped" = true ]; then
    ok "stop reaped the engine process (was $engines_before)"
  else
    bad "stop left $(pgrep -f "$CERT_ENGINE_PROC" | wc -l | tr -d ' ') engine process(es) running"
  fi
  if "$SBPROXY_BIN" models ps --format json >"$WORK/ps-stopped.json" 2>&1; then
    state="$(python3 -c "
import json
d = json.load(open('$WORK/ps-stopped.json'))
deps = d.get('deployments') or [{}]
print(deps[0].get('state', 'absent'), d.get('serving'))
")"
    case "$state" in
      "stopped False") ok "status reports stopped and serving: false" ;;
      *) bad "status after stop reads '$state', expected 'stopped False'" ;;
    esac
  else
    bad "models ps failed after stop"
  fi
else
  bad "models stop failed"
fi

# --- 6. clean shutdown --------------------------------------------------
kill -INT "$PROXY_PID" 2>/dev/null
exit_secs=-1
for i in $(seq 1 60); do
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    exit_secs=$i
    break
  fi
  sleep 1
done
if [ "$exit_secs" -ge 0 ]; then
  ok "SIGINT exited the gateway cleanly in ${exit_secs}s"
else
  bad "the gateway did not exit within 60s of SIGINT"
fi
leftover="$(pgrep -f "$CERT_ENGINE_PROC" 2>/dev/null | wc -l | tr -d ' ')"
if [ "$leftover" -eq 0 ]; then
  ok "no engine process orphaned after shutdown"
else
  bad "$leftover engine process(es) orphaned after shutdown"
fi
PROXY_PID=""

# --- 7. cache reuse ----------------------------------------------------
warm_secs="$(start_run "$WORK/warm.log" 600)"
if [ "$warm_secs" = "-1" ]; then
  bad "the second run never reached ready"
else
  ok "second run reached ready in ${warm_secs}s"
  if [ "$warm_secs" -lt "$cold_secs" ]; then
    ok "warm start is faster than cold (${warm_secs}s < ${cold_secs}s)"
  else
    bad "warm start (${warm_secs}s) is not faster than cold (${cold_secs}s); the cache may not be reused"
  fi
  downloads="$(grep -ci "downloading\|download started" "$WORK/warm.log" 2>/dev/null || true)"
  if [ "${downloads:-0}" -eq 0 ]; then
    ok "no weight download on the second run"
  else
    bad "the second run logged $downloads download line(s); the cache was not reused"
  fi
  if admin_env "$WORK/warm.log" \
    && "$SBPROXY_BIN" models ps --format json >"$WORK/ps-warm.json" 2>&1; then
    warm_digest="$(python3 -c "
import json
print(json.load(open('$WORK/ps-warm.json'))['deployments'][0]['artifact_digest'])
" 2>/dev/null)"
    if [ -n "$DIGEST" ] && [ "$warm_digest" = "$DIGEST" ]; then
      ok "artifact digest is identical across runs ($warm_digest)"
    else
      bad "digest changed across runs: '$DIGEST' then '$warm_digest'"
    fi
  else
    bad "could not read status on the second run"
  fi
fi

echo
echo "== $pass passed, $fail failed =="
echo "evidence: $WORK"
[ "$fail" -eq 0 ]
