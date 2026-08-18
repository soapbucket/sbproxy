#!/usr/bin/env bash
# Record VHS cassettes for sbproxy examples.
#
# Each tape under docs/tapes/ declares the config it should run against with a
# `# CONFIG: <path>` directive near the top. This script starts the release
# binary with that config (provider keys sourced from the environment), waits
# for the data listener, records the tape against the live proxy, then
# stops it. Provider keys stay in the environment and are never typed on screen.
#
# A tape whose example needs a local upstream fixture (a small stdlib HTTP
# server the example's origin proxies to) declares it with a
# `# FIXTURE: <path relative to repo root>` directive. This script starts it
# with `python3 <path>` before the proxy, and stops it in the same cleanup
# pass as the proxy itself. An optional `# FIXTURE_PORT: <port>` directive
# waits for that port to accept connections before recording; without it,
# the script just sleeps 1s (fine for a fixture with no dependents at
# startup).
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
ACTIVE_PIDS=()
ACTIVE_WORKSPACES=()

if [ ! -x "$BIN" ]; then
  echo "error: $BIN not found. Build it first: make build-release" >&2
  exit 1
fi
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
  echo "loaded provider keys from $ENV_FILE"
else
  echo "note: $ENV_FILE not found; relying on keys already in the environment"
fi

stop_pid() {
  local pid="$1" _
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  wait "$pid" 2>/dev/null || true
}

stop_active_from() {
  local start="$1" i
  for ((i=${#ACTIVE_PIDS[@]} - 1; i >= start; i--)); do
    stop_pid "${ACTIVE_PIDS[$i]}"
  done
  ACTIVE_PIDS=("${ACTIVE_PIDS[@]:0:start}")
}

remove_workspace() {
  local workspace="$1"
  [ -n "$workspace" ] || return
  rm -f -- "$workspace/main.log" "$workspace/aux.log" "$workspace/fixture.log" 2>/dev/null || true
  rmdir -- "$workspace" 2>/dev/null || true
}

remove_workspaces_from() {
  local start="$1" i
  for ((i=${#ACTIVE_WORKSPACES[@]} - 1; i >= start; i--)); do
    remove_workspace "${ACTIVE_WORKSPACES[$i]}"
  done
  ACTIVE_WORKSPACES=("${ACTIVE_WORKSPACES[@]:0:start}")
}

cleanup() {
  stop_active_from 0
  remove_workspaces_from 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

config_port() {
  local cfg="$1" port
  port="$(sed -n 's/^[[:space:]]*http_bind_port:[[:space:]]*//p' "$cfg" | head -n1)"
  printf '%s\n' "${port:-8080}"
}

config_admin_block() {
  # Print only the lines that belong to the proxy.admin: mapping: from the
  # `admin:` key (exclusive) to the next line at the same or shallower
  # indentation (exclusive), or EOF. Scoping to the block (rather than
  # grepping the whole file for the first `port:` / `enabled:`) means a
  # `port:` key elsewhere in the config, or `enabled:` not being the first
  # key under `admin:`, cannot be mistaken for the admin block's own keys.
  local cfg="$1"
  awk '
    !in_block {
      if ($0 ~ /^[[:space:]]*admin:[[:space:]]*$/) {
        in_block = 1
        match($0, /^[[:space:]]*/)
        indent = RLENGTH
      }
      next
    }
    /^[[:space:]]*$/ { print; next }
    {
      match($0, /^[[:space:]]*/)
      if (RLENGTH <= indent) { exit }
      print
    }
  ' "$cfg"
}

config_admin_enabled() {
  local cfg="$1"
  config_admin_block "$cfg" | grep -qE 'enabled:[[:space:]]*true'
}

config_admin_port() {
  local cfg="$1" port
  port="$(config_admin_block "$cfg" | sed -n 's/^[[:space:]]*port:[[:space:]]*//p' | head -n1)"
  printf '%s\n' "${port:-9090}"
}

reject_occupied_port() {
  local port="$1" owners
  owners="$(lsof -ti "tcp:$port" 2>/dev/null || true)"
  if [ -n "$owners" ]; then
    echo "error: required port $port is already occupied (PID(s): $(echo "$owners" | tr '\n' ' '))" >&2
    return 1
  fi
}

start_proxy() {
  local cfg="$1" log="$2" loglevel="$3"
  # The child receives its own stdout path for tape commands that inspect logs.
  # shellcheck disable=SC2094
  RUST_LOG="$loglevel" NO_COLOR=1 SBPROXY_REC_LOG="$log" \
    "$BIN" serve -f "$cfg" >"$log" 2>&1 &
  ACTIVE_PIDS+=("$!")
}

start_fixture() {
  local script="$1" log="$2"
  python3 "$script" >"$log" 2>&1 &
  ACTIVE_PIDS+=("$!")
}

wait_ready() {
  local pid="$1" port="$2"
  for _ in $(seq 1 80); do
    if curl -s -o /dev/null --max-time 2 "localhost:$port" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.25
  done
  return 1
}

record() {
  local tape="$1"
  [ -f "$tape" ] || tape="docs/tapes/${tape%.tape}.tape"
  if [ ! -f "$tape" ]; then echo "skip: no such tape $tape" >&2; return 1; fi

  # A directive missing its space (`#FIXTURE:` where `# FIXTURE:` was
  # meant) is silently not a directive at all, so a typo records a tape
  # with no fixture instead of erroring. Refuse it.
  if grep -qE '^#(CONFIG|AUX_CONFIG|FIXTURE|FIXTURE_PORT|LOGLEVEL):' "$tape"; then
    echo "skip: $tape has a malformed directive (missing space after '#')" >&2
    return 1
  fi

  local cfg aux_cfg
  cfg="$(sed -n 's/^# CONFIG:[[:space:]]*//p' "$tape" | head -n1)"
  if [ -z "$cfg" ]; then echo "skip: $tape has no '# CONFIG:' directive" >&2; return 1; fi
  if [ ! -f "$cfg" ]; then echo "skip: config $cfg (from $tape) missing" >&2; return 1; fi
  aux_cfg="$(sed -n 's/^# AUX_CONFIG:[[:space:]]*//p' "$tape" | head -n1)"
  if [ -n "$aux_cfg" ] && [ ! -f "$aux_cfg" ]; then
    echo "skip: auxiliary config $aux_cfg (from $tape) missing" >&2
    return 1
  fi

  local fixture fixture_port
  fixture="$(sed -n 's/^# FIXTURE:[[:space:]]*//p' "$tape" | head -n1)"
  # Repo-relative only: a tape is repo content, and `# FIXTURE:` names a
  # python program this script runs, so an absolute or parent-escaping
  # path has no business here.
  case "$fixture" in
    /* | *..*)
      echo "skip: fixture path $fixture (from $tape) must be repo-relative" >&2
      return 1
      ;;
  esac
  if [ -n "$fixture" ] && [ ! -f "$fixture" ]; then
    echo "skip: fixture $fixture (from $tape) missing" >&2
    return 1
  fi
  fixture_port="$(sed -n 's/^# FIXTURE_PORT:[[:space:]]*//p' "$tape" | head -n1)"

  # Examples bind the data listener on http_bind_port (default 8080); any
  # HTTP response (even a 404) means that listener is accepting. Admin bind
  # failure is non-fatal in the proxy itself (it logs and keeps serving data
  # traffic), so a config that turns on proxy.admin: also needs its own
  # readiness wait and stale-occupant check on the admin port -- otherwise a
  # leftover process on that port silently blanks every admin payoff in the
  # recording (curl -s prints nothing on connect failure, and jq on empty
  # stdin exits 0 without complaint).
  local port aux_port=""
  port="$(config_port "$cfg")"
  if [ -n "$aux_cfg" ]; then
    aux_port="$(config_port "$aux_cfg")"
  fi

  local admin_port="" aux_admin_port=""
  if config_admin_enabled "$cfg"; then
    admin_port="$(config_admin_port "$cfg")"
  fi
  if [ -n "$aux_cfg" ] && config_admin_enabled "$aux_cfg"; then
    aux_admin_port="$(config_admin_port "$aux_cfg")"
  fi

  # A tape may raise the proxy log level (e.g. the fallback demo greps the
  # log for a failover WARN). Default to error so the log stays quiet.
  local loglevel
  loglevel="$(sed -n 's/^# LOGLEVEL:[[:space:]]*//p' "$tape" | head -n1)"
  loglevel="${loglevel:-error}"

  reject_occupied_port "$port" || return 1
  if [ -n "$aux_port" ]; then
    if [ "$aux_port" = "$port" ]; then
      echo "error: main and auxiliary configs both require port $port" >&2
      return 1
    fi
    reject_occupied_port "$aux_port" || return 1
  fi
  if [ -n "$admin_port" ]; then
    reject_occupied_port "$admin_port" || return 1
  fi
  if [ -n "$aux_admin_port" ]; then
    reject_occupied_port "$aux_admin_port" || return 1
  fi
  if [ -n "$fixture_port" ]; then
    local taken
    for taken in "$port" "$aux_port" "$admin_port" "$aux_admin_port"; do
      if [ -n "$taken" ] && [ "$fixture_port" = "$taken" ]; then
        echo "error: fixture port $fixture_port collides with a proxy port required by $tape" >&2
        return 1
      fi
    done
    reject_occupied_port "$fixture_port" || return 1
  fi

  local workspace main_log aux_log fixture_log start_index workspace_start main_pid aux_pid fixture_pid
  workspace="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-record.XXXXXX")"
  workspace_start=${#ACTIVE_WORKSPACES[@]}
  ACTIVE_WORKSPACES+=("$workspace")
  # The admin API needs the password its config resolves. Examples stopped
  # shipping a literal one in #769 and moved to ${SB_ADMIN_PASSWORD:-...},
  # but the tapes kept sending `admin:admin`, so every admin call in a
  # re-record 401s and the demo silently degrades. The GIFs did not change
  # because nothing re-records them, which is how it stayed hidden.
  export SB_ADMIN_PASSWORD="${SB_ADMIN_PASSWORD:-demo-admin-password}"
  main_log="$workspace/main.log"
  aux_log="$workspace/aux.log"
  fixture_log="$workspace/fixture.log"
  start_index=${#ACTIVE_PIDS[@]}

  echo "==> $tape   (config: $cfg, port: $port${admin_port:+, admin: $admin_port}${fixture:+, fixture: $fixture}, log: $loglevel)"
  if [ -n "$fixture" ]; then
    start_fixture "$fixture" "$fixture_log"
    fixture_pid="${ACTIVE_PIDS[${#ACTIVE_PIDS[@]} - 1]}"
    if [ -n "$fixture_port" ]; then
      if ! wait_ready "$fixture_pid" "$fixture_port"; then
        echo "error: fixture $fixture never became ready on port $fixture_port" >&2
        stop_active_from "$start_index"
        remove_workspaces_from "$workspace_start"
        return 1
      fi
    else
      # No FIXTURE_PORT declared: a fixture the example's origin only calls
      # per-request (rather than something the proxy dials at startup) has
      # nothing to probe readiness against, so a fixed settle time stands in.
      sleep 1
      # The settle time is not a liveness check. A fixture that died at
      # startup (its port already held by a leaked listener, a syntax
      # error) would otherwise be invisible: the tape records against a
      # dead fixture and reports success, and only the committed GIF
      # shows the 502s. Fail the tape by name instead.
      if ! kill -0 "$fixture_pid" 2>/dev/null; then
        echo "error: fixture $fixture exited during startup (no FIXTURE_PORT to probe); log follows" >&2
        sed -n '1,20p' "$fixture_log" >&2 || true
        stop_active_from "$start_index"
        remove_workspaces_from "$workspace_start"
        return 1
      fi
    fi
  fi
  if [ -n "$aux_cfg" ]; then
    start_proxy "$aux_cfg" "$aux_log" "$loglevel"
    aux_pid="${ACTIVE_PIDS[${#ACTIVE_PIDS[@]} - 1]}"
    if ! wait_ready "$aux_pid" "$aux_port"; then
      echo "error: auxiliary proxy never became ready on port $aux_port for $aux_cfg" >&2
      stop_active_from "$start_index"
      remove_workspaces_from "$workspace_start"
      return 1
    fi
    if [ -n "$aux_admin_port" ] && ! wait_ready "$aux_pid" "$aux_admin_port"; then
      echo "error: auxiliary proxy's admin server never became ready on port $aux_admin_port for $aux_cfg" >&2
      stop_active_from "$start_index"
      remove_workspaces_from "$workspace_start"
      return 1
    fi
  fi

  start_proxy "$cfg" "$main_log" "$loglevel"
  main_pid="${ACTIVE_PIDS[${#ACTIVE_PIDS[@]} - 1]}"
  if ! wait_ready "$main_pid" "$port"; then
    echo "error: proxy never became ready on port $port for $cfg" >&2
    stop_active_from "$start_index"
    remove_workspaces_from "$workspace_start"
    return 1
  fi
  if [ -n "$admin_port" ] && ! wait_ready "$main_pid" "$admin_port"; then
    echo "error: proxy's admin server never became ready on port $admin_port for $cfg" >&2
    stop_active_from "$start_index"
    remove_workspaces_from "$workspace_start"
    return 1
  fi

  export SBPROXY_REC_LOG="$main_log"
  set +e
  vhs "$tape"
  local rc=$?
  set -e

  stop_active_from "$start_index"
  remove_workspaces_from "$workspace_start"
  unset SBPROXY_REC_LOG
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

if [ "$failed" -gt 0 ]; then
  echo "done with $failed failure(s)" >&2
  exit 1
fi
echo "done; GIFs written to docs/assets/"
