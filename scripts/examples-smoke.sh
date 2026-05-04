#!/usr/bin/env bash
# Wave 1 / Q1.11 - Examples-in-CI smoke runner.
#
# For each directory under examples/ that contains a `docker-compose.yml`,
# this script:
#   1. `docker compose up -d --wait`
#   2. Polls <admin_port><health_path> for liveness; expects 200.
#   3. Hits each entry in `feature_endpoints[]` on <data_plane_port>;
#      expects 2xx.
#   4. Optionally asserts an audit-log entry exists (gated on the
#      `audit_check` flag in smoke.json; defaults off until Wave 2
#      lands the OSS admin endpoint).
#   5. `docker compose down -v`.
#
# Examples without a docker-compose.yml are skipped silently. Examples
# without a smoke.json fall back to safe defaults: data_plane_port is
# discovered from docker-compose.yml's first published port,
# admin_port is the same, health_path is /healthz. With those defaults
# only the liveness probe is asserted.
#
# Companion workflow: `.github/workflows/examples-smoke.yml` (B1.8).
#
# Usage:
#   scripts/examples-smoke.sh
#   scripts/examples-smoke.sh examples/00-basic-proxy
#   scripts/examples-smoke.sh --filter '01-*'
#
# Env knobs:
#   COMPOSE_BIN       docker-compose CLI (default: `docker compose`)
#   CURL_TIMEOUT_S    per-curl timeout (default: 10)
#   STARTUP_WAIT_S    healthz polling window (default: 60)
#   ENTERPRISE_ROOT   path to sbproxy-enterprise repo (default: ../sbproxy-enterprise)
#
# smoke.json schema (see scripts/README.md for the full reference):
#   {
#     "admin_port":        9090,           # /healthz lives on the admin
#                                          #   listener; sbproxy serves
#                                          #   /healthz only when
#                                          #   admin.enabled is true.
#     "data_plane_port":   8080,           # user traffic listener.
#     "health_path":       "/healthz",     # admin liveness probe path.
#     "feature_endpoints": ["/preview/x"], # data-plane GETs to assert 2xx.
#     "audit_check":       false           # Wave 1 OSS has no audit
#                                          #   admin endpoint; flip to
#                                          #   true once Wave 2 ships
#                                          #   /api/audit/recent.
#   }

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENTERPRISE_ROOT="${ENTERPRISE_ROOT:-$RUST_ROOT/../sbproxy-enterprise}"

COMPOSE_BIN="${COMPOSE_BIN:-docker compose}"
CURL_TIMEOUT_S="${CURL_TIMEOUT_S:-10}"
STARTUP_WAIT_S="${STARTUP_WAIT_S:-60}"

# --- Argument parsing ------------------------------------------------

EXAMPLE_FILTER=""
SPECIFIC_EXAMPLES=()

while [ $# -gt 0 ]; do
  case "$1" in
    --filter) EXAMPLE_FILTER="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,40p' "$0"
      exit 0
      ;;
    *)
      if [ -d "$1" ]; then
        SPECIFIC_EXAMPLES+=("$1")
        shift
      else
        echo "unknown arg or missing dir: $1" >&2
        exit 2
      fi
      ;;
  esac
done

# --- Example discovery -----------------------------------------------

declare -a EXAMPLES=()
if [ ${#SPECIFIC_EXAMPLES[@]} -gt 0 ]; then
  EXAMPLES=("${SPECIFIC_EXAMPLES[@]}")
else
  for root in "$RUST_ROOT/examples" "$ENTERPRISE_ROOT/examples"; do
    [ -d "$root" ] || continue
    while IFS= read -r dir; do
      EXAMPLES+=("$dir")
    done < <(find "$root" -mindepth 1 -maxdepth 2 -type f -name 'docker-compose.yml' -exec dirname {} \; | sort -u)
  done
fi

if [ -n "$EXAMPLE_FILTER" ]; then
  filtered=()
  for ex in "${EXAMPLES[@]}"; do
    case "$(basename "$ex")" in
      $EXAMPLE_FILTER) filtered+=("$ex") ;;
    esac
  done
  EXAMPLES=("${filtered[@]}")
fi

if [ ${#EXAMPLES[@]} -eq 0 ]; then
  echo "[examples-smoke] no examples to test" >&2
  exit 0
fi

# --- smoke.json reader -----------------------------------------------
#
# `read_smoke_field DIR FIELD DEFAULT` returns the value of FIELD from
# the example's smoke.json, or DEFAULT if the file or field is
# missing. Uses jq when available; falls back to a small Python
# helper otherwise (CI runners always have python3, but operators on
# minimal Alpines may not).

read_smoke_field() {
  local dir="$1" field="$2" default="$3"
  local sj="$dir/smoke.json"
  if [ ! -f "$sj" ]; then
    echo "$default"
    return 0
  fi
  if command -v jq >/dev/null 2>&1; then
    # Distinguish "field absent / null" from "field present but
    # falsy (false, 0, empty string)". `// empty` treats both as
    # absent, which loses the explicit-false case. We instead use
    # `has(field)` and only fall back to the default when the key
    # is missing or the value is null.
    local present
    present=$(jq -r "has(\"$field\")" "$sj")
    if [ "$present" != "true" ]; then
      echo "$default"
      return 0
    fi
    local val
    val=$(jq -r ".$field" "$sj")
    if [ "$val" = "null" ]; then
      echo "$default"
    else
      echo "$val"
    fi
    return 0
  fi
  python3 - "$sj" "$field" "$default" <<'PY'
import json, sys
sj, field, default = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(sj) as f:
        data = json.load(f)
    if field not in data:
        print(default)
    else:
        val = data[field]
        if val is None:
            print(default)
        elif isinstance(val, bool):
            print("true" if val else "false")
        else:
            print(val)
except Exception:
    print(default)
PY
}

# `read_smoke_array DIR FIELD` prints each entry of the array FIELD on
# its own line, or nothing if the field or file is missing.
read_smoke_array() {
  local dir="$1" field="$2"
  local sj="$dir/smoke.json"
  [ -f "$sj" ] || return 0
  if command -v jq >/dev/null 2>&1; then
    jq -r ".${field}[]?" "$sj"
    return 0
  fi
  python3 - "$sj" "$field" <<'PY'
import json, sys
sj, field = sys.argv[1], sys.argv[2]
try:
    with open(sj) as f:
        data = json.load(f)
    for entry in data.get(field, []) or []:
        print(entry)
except Exception:
    pass
PY
}

# Discover the example's data-plane port. Reads smoke.json's
# `data_plane_port` if set, else falls back to scanning
# docker-compose.yml for the first `published:` port. Returns "" if
# nothing usable found.
discover_data_plane_port() {
  local dir="$1"
  local from_json
  from_json=$(read_smoke_field "$dir" data_plane_port "")
  if [ -n "$from_json" ]; then
    echo "$from_json"
    return 0
  fi
  # Legacy field for back-compat with smoke.json files that predate
  # the admin_port / data_plane_port split.
  from_json=$(read_smoke_field "$dir" port "")
  if [ -n "$from_json" ]; then
    echo "$from_json"
    return 0
  fi
  grep -E '^[[:space:]]*-[[:space:]]*"?[0-9]+:[0-9]+' "$dir/docker-compose.yml" \
    | head -n1 \
    | sed -E 's/[^0-9]*([0-9]+):.*/\1/'
}

# Discover the example's admin port. Defaults to the data-plane port
# when smoke.json does not set `admin_port`. The proxy serves
# /healthz on the admin listener; examples that do not enable the
# admin server can still pass the smoke check by pointing
# `admin_port` at any container listener that returns 200 on
# `health_path` (some examples mount nginx on 8080 and rely on that
# instead of the proxy's own /healthz).
discover_admin_port() {
  local dir="$1"
  local from_json
  from_json=$(read_smoke_field "$dir" admin_port "")
  if [ -n "$from_json" ]; then
    echo "$from_json"
    return 0
  fi
  discover_data_plane_port "$dir"
}

# --- Per-example runner ----------------------------------------------

# `cleanup_example DIR` is the one place that touches docker compose
# down. Always called via `trap` so a failing assertion still tears
# the stack down.
cleanup_example() {
  local dir="$1"
  echo "[examples-smoke] $dir: docker compose down -v"
  ( cd "$dir" && $COMPOSE_BIN down -v --remove-orphans >/dev/null 2>&1 || true )
}

# Hit health_path on $port. Polls until 200 or STARTUP_WAIT_S
# elapses.
wait_for_healthz() {
  local port="$1" path="$2"
  local deadline=$(( $(date +%s) + STARTUP_WAIT_S ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS --max-time "$CURL_TIMEOUT_S" "http://127.0.0.1:$port$path" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Asks the proxy admin endpoint for recent audit entries. Returns 0
# if at least one entry is present; non-zero otherwise. The endpoint
# does not exist in Wave 1 OSS; gated behind `audit_check: true` in
# smoke.json. Wave 2 (R1.2) ships /api/audit/recent.
assert_audit_emitted() {
  local port="$1"
  local body
  body=$(curl -fsS --max-time "$CURL_TIMEOUT_S" \
    "http://127.0.0.1:$port/api/audit/recent?limit=1" 2>/dev/null || true)
  if [ -z "$body" ]; then
    return 1
  fi
  case "$body" in
    "[]"|"") return 1 ;;
    *) return 0 ;;
  esac
}

run_example() {
  local dir="$1"
  echo "[examples-smoke] === $dir ==="

  trap "cleanup_example '$dir'" EXIT INT TERM

  ( cd "$dir" && $COMPOSE_BIN up -d --wait >/dev/null )

  # --- Resolve smoke.json knobs ---
  local data_port admin_port health_path audit_check
  data_port="$(discover_data_plane_port "$dir")"
  admin_port="$(discover_admin_port "$dir")"
  health_path="$(read_smoke_field "$dir" health_path /healthz)"
  audit_check="$(read_smoke_field "$dir" audit_check false)"

  if [ -z "$data_port" ]; then
    echo "[examples-smoke] $dir: SKIP - could not discover data_plane_port"
    cleanup_example "$dir"
    trap - EXIT INT TERM
    return 0
  fi
  if [ -z "$admin_port" ]; then
    admin_port="$data_port"
  fi

  # --- Liveness probe ---
  if ! wait_for_healthz "$admin_port" "$health_path"; then
    echo "[examples-smoke] $dir: FAIL - $health_path never returned 200 on :$admin_port" >&2
    return 1
  fi
  echo "[examples-smoke] $dir: $health_path on :$admin_port -> OK"

  # --- Feature endpoints (optional per smoke.json) ---
  # Endpoints can be declared under `feature_endpoints[]` (preferred)
  # or `endpoints[]` (legacy). Both are read; entries are de-duped by
  # path string.
  local endpoints_file
  endpoints_file="$(mktemp -t examples-smoke-endpoints-XXXXXX)"
  read_smoke_array "$dir" feature_endpoints >> "$endpoints_file"
  read_smoke_array "$dir" endpoints >> "$endpoints_file"

  if [ -s "$endpoints_file" ]; then
    local seen_file
    seen_file="$(mktemp -t examples-smoke-seen-XXXXXX)"
    while IFS= read -r ep; do
      [ -z "$ep" ] && continue
      if grep -Fxq -- "$ep" "$seen_file" 2>/dev/null; then
        continue
      fi
      echo "$ep" >> "$seen_file"

      local code
      code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$CURL_TIMEOUT_S" \
        "http://127.0.0.1:$data_port$ep" || true)
      case "$code" in
        2*)
          echo "[examples-smoke] $dir: $ep on :$data_port -> $code OK"
          ;;
        *)
          echo "[examples-smoke] $dir: FAIL - $ep on :$data_port returned $code (expected 2xx)" >&2
          rm -f "$endpoints_file" "$seen_file"
          return 1
          ;;
      esac
    done < "$endpoints_file"
    rm -f "$seen_file"
  else
    echo "[examples-smoke] $dir: no feature_endpoints declared, skipping data-plane probes"
  fi
  rm -f "$endpoints_file"

  # --- Audit-log assertion (gated on audit_check) ---
  case "$audit_check" in
    true|True|TRUE|1|yes)
      if ! assert_audit_emitted "$admin_port"; then
        echo "[examples-smoke] $dir: FAIL - no audit-log entry observed on :$admin_port" >&2
        return 1
      fi
      echo "[examples-smoke] $dir: audit-log on :$admin_port -> OK"
      ;;
    *)
      echo "[examples-smoke] $dir: audit_check disabled (default until Wave 2 ships /api/audit/recent)"
      ;;
  esac

  echo "[examples-smoke] $dir: PASS"
  cleanup_example "$dir"
  trap - EXIT INT TERM
  return 0
}

# --- Driver ----------------------------------------------------------

overall=0
declare -a passed=()
declare -a failed=()

for ex in "${EXAMPLES[@]}"; do
  if run_example "$ex"; then
    passed+=("$ex")
  else
    failed+=("$ex")
    overall=1
  fi
done

echo
echo "[examples-smoke] summary: ${#passed[@]} passed, ${#failed[@]} failed"
if [ ${#failed[@]} -gt 0 ]; then
  printf '  FAIL %s\n' "${failed[@]}" >&2
fi

exit "$overall"
