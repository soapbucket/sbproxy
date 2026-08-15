#!/usr/bin/env bash
# Self-host certification matrix (SH-23 / WOR-1858).
#
# One reproducible command per lane in the environment certification
# table, each with a recorded expected result and captured version
# metadata, so a release claim can point at evidence instead of a
# recollection.
#
# The rule this enforces: a lane is `pass` only when its command ran on
# this host and succeeded. A host that cannot provide what a lane needs
# reports `unsupported` with the reason, never `pass`. There is no state
# in between, and nothing is skipped silently: every selected lane
# appears in the summary with a verdict.
#
# Usage:
#   scripts/certify-selfhost.sh list
#   scripts/certify-selfhost.sh metadata
#   scripts/certify-selfhost.sh run all
#   scripts/certify-selfhost.sh run apple_metal nvidia_single_gpu
#   scripts/certify-selfhost.sh run local          # every no-hardware lane
#
# Env:
#   SBPROXY_CERT_DIR   evidence directory. Default:
#                      .cert-evidence/<utc-timestamp>
#   SBPROXY_E2E_BIN    proxy binary the e2e harness drives. Default:
#                      target/debug/sbproxy (built if absent)
#   CERT_MODEL         catalog model for the live serve lanes.
#                      Default: qwen2.5-0.5b-instruct
#   CERT_VARIANT       variant for the live serve lanes. Default: q4_k_m
#   CERT_GPU_MODEL     model for the NVIDIA lanes. Default: Qwen/Qwen3-0.6B
#
# Exit: 0 when no selected lane failed, 1 when any lane failed. An
# `unsupported` lane does not fail the run; it is recorded as a gap.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

STAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
CERT_DIR="${SBPROXY_CERT_DIR:-$REPO_ROOT/.cert-evidence/$STAMP}"
CERT_MODEL="${CERT_MODEL:-qwen2.5-0.5b-instruct}"
CERT_VARIANT="${CERT_VARIANT:-q4_k_m}"
CERT_GPU_MODEL="${CERT_GPU_MODEL:-Qwen/Qwen3-0.6B}"
SUMMARY=""

# --- lane table ---------------------------------------------------------
#
# id|expected result
#
# The expected result is recorded with the evidence so a reader six
# months from now knows what the lane was asserting, not just that it
# exited zero.
LANES="
deterministic|Every no-hardware model-host suite passes: artifact selection, engine argv, container isolation, per-device capacity, bounded queues, atomic rollback, status shape, CLI contracts.
cpu|The CPU admission path serves and refuses correctly with no accelerator present.
apple_metal_probe|The Metal probe compiles with gpu-apple, reports one unified-memory device, and a 0.5B Q4 plan fits the working-set budget.
apple_metal|A managed GGUF model reaches ready on Metal, returns nonempty assistant content through the gateway, reports truthful status, the planned memory envelope contains live RSS within 25% overshoot, stops cleanly, and reuses the cache on a second run.
nvidia_single_gpu|One NVIDIA device serves a real completion through the gateway; the NVML probe, fit plan, and FP8 gate agree with the hardware.
nvidia_multi_gpu|A deployment spanning two or more NVIDIA devices places disjoint device groups and serves. Requires two visible devices.
air_gapped|Offline, manual, and file pull policies short-circuit transport, and a digest mismatch fails closed.
split_cluster|A gateway and two workers prove authenticated dispatch, logical discovery, unary and SSE responses, coordinated cold start, and pre-output failover.
symmetric_cluster|Four real processes converge on one directory and assignment, with signed gossip, node-specific mTLS, and controller restart fencing.
three_node_kill|Removing the assigned worker excludes it from model eligibility, keeps it in the roster, raises an unhealthy-node alert, and fails over before first output.
rolling_update|A rolling deployment update prepares and observes the target before removing the prior replica, and does not restart an unrelated engine.
key_revoke|A key revoked on one gateway is refused by a peer gateway within two seconds.
strict_budget|Two gateways under concurrency never admit more than the shared strict request limit.
external_provider|A managed cold start falls through to a cloud provider in the same array rather than failing the request.
startup_gate|The managed-worker startup gate refuses a config this host cannot serve, and names each blocker.
capability_matrix|The generated capability matrix matches the registry, so no doc claims a support level the code does not.
"

lane_ids() { printf '%s\n' "$LANES" | sed '/^$/d' | cut -d'|' -f1; }
lane_expected() {
  printf '%s\n' "$LANES" | sed '/^$/d' | awk -F'|' -v id="$1" '$1==id {print $2}'
}

# --- host metadata ------------------------------------------------------

# Everything a reader needs to know the evidence came from this exact
# tree on this exact box. Retained per run, never regenerated later.
write_metadata() {
  local out="$1"
  local git_rev git_dirty binary_version
  git_rev="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    git_dirty=true
  else
    git_dirty=false
  fi
  binary_version="$("$SBPROXY_BIN" --version 2>/dev/null | head -1 || echo unknown)"

  {
    printf '{\n'
    printf '  "recorded_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "git_revision": "%s",\n' "$git_rev"
    printf '  "git_dirty": %s,\n' "$git_dirty"
    printf '  "binary": "%s",\n' "$binary_version"
    printf '  "os": "%s",\n' "$(uname -s)"
    printf '  "os_release": "%s",\n' "$(uname -r)"
    printf '  "arch": "%s",\n' "$(uname -m)"
    if [ "$(uname -s)" = "Darwin" ]; then
      printf '  "macos_version": "%s",\n' "$(sw_vers -productVersion 2>/dev/null)"
      printf '  "macos_build": "%s",\n' "$(sw_vers -buildVersion 2>/dev/null)"
      printf '  "chip": "%s",\n' "$(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
      printf '  "memory_bytes": %s,\n' "$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
    fi
    printf '  "nvidia_driver": "%s",\n' "$(nvidia_driver_version)"
    printf '  "cuda": "%s",\n' "$(cuda_version)"
    printf '  "container_runtime": "%s",\n' "$(container_version)"
    printf '  "redis_server": "%s",\n' "$(redis-server --version 2>/dev/null | head -1 || echo absent)"
    printf '  "visible_nvidia_devices": %s\n' "$(nvidia_device_count)"
    printf '}\n'
  } >"$out"
}

nvidia_driver_version() {
  command -v nvidia-smi >/dev/null 2>&1 || { echo absent; return; }
  nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 || echo unknown
}

cuda_version() {
  command -v nvidia-smi >/dev/null 2>&1 || { echo absent; return; }
  nvidia-smi --query-gpu=cuda_version --format=csv,noheader 2>/dev/null | head -1 || echo unknown
}

container_version() {
  if command -v docker >/dev/null 2>&1; then
    docker --version 2>/dev/null | head -1
  elif command -v podman >/dev/null 2>&1; then
    podman --version 2>/dev/null | head -1
  else
    echo absent
  fi
}

# Count devices the *proxy* can see, not what nvidia-smi lists: the
# probe is what admission uses, and a container handed no devices has an
# answering driver and zero usable cards.
nvidia_device_count() {
  local json
  json="$("$SBPROXY_BIN" doctor --format json 2>/dev/null)" || { echo 0; return; }
  printf '%s' "$json" \
    | jq '[.gpus[]? | select(.vendor == "Nvidia")] | length' 2>/dev/null \
    || echo 0
}

# --- lane bookkeeping ---------------------------------------------------

record() {
  local lane="$1" status="$2" detail="$3"
  SUMMARY="${SUMMARY}${lane}\t${status}\t${detail}\n"
  printf '%s\t%s\t%s\n' "$lane" "$status" "$detail" >>"$CERT_DIR/summary.tsv"
  case "$status" in
    pass) printf '\033[32mPASS\033[0m %-20s %s\n' "$lane" "$detail" ;;
    fail) printf '\033[31mFAIL\033[0m %-20s %s\n' "$lane" "$detail" ;;
    *)    printf '\033[33m%-4s\033[0m %-20s %s\n' "UNSUP" "$lane" "$detail" ;;
  esac
}

# Run a command with its output retained, and report pass/fail from its
# real exit code (captured directly, never through a pipe).
run_lane_command() {
  local lane="$1"; shift
  local log="$CERT_DIR/$lane.log"
  {
    echo "# lane: $lane"
    echo "# expected: $(lane_expected "$lane")"
    echo "# command: $*"
    echo "# started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
  } >"$log"
  "$@" >>"$log" 2>&1
  local status=$?
  echo "# finished: $(date -u +%Y-%m-%dT%H:%M:%SZ) exit=$status" >>"$log"
  return $status
}

simple_lane() {
  local lane="$1"; shift
  if run_lane_command "$lane" "$@"; then
    record "$lane" pass "$lane.log"
  else
    record "$lane" fail "exit nonzero; see $lane.log"
  fi
}

# --- lanes --------------------------------------------------------------

lane_deterministic() {
  simple_lane deterministic env PATH="$HOME/.cargo/bin:$PATH" \
    cargo nextest run --profile ci \
      -p sbproxy-model-host -p sbproxy-capability \
      --no-fail-fast
}

lane_cpu() {
  simple_lane cpu env PATH="$HOME/.cargo/bin:$PATH" \
    cargo nextest run --profile ci -p sbproxy-model-host \
      --test local_admission --test cold_start_policy --no-fail-fast
}

lane_apple_metal_probe() {
  if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
    record apple_metal_probe unsupported "not an Apple Silicon host (found $(uname -s)/$(uname -m))"
    return
  fi
  simple_lane apple_metal_probe "$REPO_ROOT/scripts/cert-lane-metal-probe.sh"
}

lane_apple_metal() {
  if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
    record apple_metal unsupported "not an Apple Silicon host (found $(uname -s)/$(uname -m))"
    return
  fi
  simple_lane apple_metal env \
    CERT_RECORD="$CERT_DIR/record.json" \
    CERT_HOST_JSON="$CERT_DIR/metadata.json" \
    PATH="$HOME/.cargo/bin:$PATH" \
    "$REPO_ROOT/scripts/cert-lane-managed-serve.sh" \
    "$CERT_MODEL" "$CERT_VARIANT" metal
}

lane_nvidia_single_gpu() {
  local devices
  devices="$(nvidia_device_count)"
  if [ "${devices:-0}" -lt 1 ]; then
    record nvidia_single_gpu unsupported \
      "no NVIDIA device visible to the probe (driver: $(nvidia_driver_version))"
    return
  fi
  simple_lane nvidia_single_gpu env PATH="$HOME/.cargo/bin:$PATH" \
    cargo run --release --example gpu_cert -p sbproxy-model-host \
      --features gpu-nvidia,weights -- serve "$CERT_GPU_MODEL" 8000
}

lane_nvidia_multi_gpu() {
  local devices
  devices="$(nvidia_device_count)"
  if [ "${devices:-0}" -lt 2 ]; then
    record nvidia_multi_gpu unsupported \
      "needs 2+ visible NVIDIA devices, this host has ${devices:-0}"
    return
  fi
  simple_lane nvidia_multi_gpu env PATH="$HOME/.cargo/bin:$PATH" \
    cargo nextest run --profile ci -p sbproxy-model-host \
      --test runtime_replicas --test placement --no-fail-fast
}

lane_air_gapped() {
  simple_lane air_gapped env PATH="$HOME/.cargo/bin:$PATH" \
    cargo nextest run --profile ci -p sbproxy-model-host \
      --test artifact_policy --test artifact_manager --no-fail-fast
}

lane_split_cluster() {
  simple_lane split_cluster env PATH="$HOME/.cargo/bin:$PATH" \
    SBPROXY_E2E_BIN="$SBPROXY_BIN" \
    cargo test -p sbproxy-e2e --test model_cluster_dispatch -- --nocapture
}

lane_symmetric_cluster() {
  simple_lane symmetric_cluster env PATH="$HOME/.cargo/bin:$PATH" \
    SBPROXY_E2E_BIN="$SBPROXY_BIN" \
    cargo test -p sbproxy-e2e --test model_cluster_control -- --nocapture
}

# The kill test and the rolling update are assertions *inside* the two
# cluster suites, so they are named lanes that re-run the owning test by
# name rather than pretending to be separate binaries. Naming them
# separately is the point: SH-23 lists them as distinct claims.
lane_three_node_kill() {
  simple_lane three_node_kill env PATH="$HOME/.cargo/bin:$PATH" \
    SBPROXY_E2E_BIN="$SBPROXY_BIN" \
    cargo test -p sbproxy-e2e --test model_cluster_control \
      cluster_converges_and_admin_calls_out_an_unhealthy_worker -- --nocapture
}

lane_rolling_update() {
  simple_lane rolling_update env PATH="$HOME/.cargo/bin:$PATH" \
    cargo nextest run --profile ci -p sbproxy-model-host \
      --test runtime_reconcile --no-fail-fast
}

lane_key_revoke() {
  if ! command -v redis-server >/dev/null 2>&1; then
    record key_revoke unsupported "redis-server is not on PATH; the lane spawns its own instance"
    return
  fi
  simple_lane key_revoke env PATH="$HOME/.cargo/bin:$PATH" \
    SBPROXY_E2E_BIN="$SBPROXY_BIN" SBPROXY_E2E_REQUIRE_REDIS=1 \
    cargo test -p sbproxy-e2e --test key_replicas -- --nocapture
}

lane_strict_budget() {
  if ! command -v redis-server >/dev/null 2>&1; then
    record strict_budget unsupported "redis-server is not on PATH; the lane spawns its own instance"
    return
  fi
  simple_lane strict_budget env PATH="$HOME/.cargo/bin:$PATH" \
    SBPROXY_E2E_BIN="$SBPROXY_BIN" SBPROXY_E2E_REQUIRE_REDIS=1 \
    cargo test -p sbproxy-e2e --test governance_strict -- --nocapture
}

lane_external_provider() {
  simple_lane external_provider env PATH="$HOME/.cargo/bin:$PATH" \
    SBPROXY_E2E_BIN="$SBPROXY_BIN" \
    cargo test -p sbproxy-e2e --test model_cluster_dispatch \
      managed_cold_fallback_advances_a_non_fallback_router -- --nocapture
}

lane_startup_gate() {
  simple_lane startup_gate "$REPO_ROOT/scripts/cert-lane-startup-gate.sh" "$SBPROXY_BIN"
}

lane_capability_matrix() {
  simple_lane capability_matrix "$REPO_ROOT/scripts/check-model-host-capabilities.sh"
}

# Lanes that need no accelerator and no cloud account. `run local` is
# the pre-hardware gate: it must be green before a GPU box is billed.
LOCAL_LANES="deterministic cpu air_gapped split_cluster symmetric_cluster three_node_kill rolling_update key_revoke strict_budget external_provider startup_gate capability_matrix"

# --- driver -------------------------------------------------------------

resolve_binary() {
  SBPROXY_BIN="${SBPROXY_E2E_BIN:-$REPO_ROOT/target/debug/sbproxy}"
  # Always invoke cargo when certifying the default binary; its freshness
  # check makes this a no-op on a current build. Gating on existence once
  # certified a two-day-old binary and hid a real lane failure (WOR-2167).
  if [ -z "${SBPROXY_E2E_BIN:-}" ]; then
    echo "[certify] building $SBPROXY_BIN"
    (cd "$REPO_ROOT" && PATH="$HOME/.cargo/bin:$PATH" cargo build -p sbproxy --bin sbproxy) \
      || { echo "[certify] cannot build the proxy binary" >&2; exit 1; }
  elif [ ! -x "$SBPROXY_BIN" ]; then
    echo "[certify] SBPROXY_E2E_BIN=$SBPROXY_BIN is not executable" >&2
    exit 1
  fi
  export SBPROXY_BIN
}

case "${1:-}" in
  list)
    printf '%-22s %s\n' LANE EXPECTED
    lane_ids | while read -r id; do
      printf '%-22s %s\n' "$id" "$(lane_expected "$id")"
    done
    exit 0
    ;;
  metadata)
    resolve_binary
    mkdir -p "$CERT_DIR"
    write_metadata "$CERT_DIR/metadata.json"
    cat "$CERT_DIR/metadata.json"
    exit 0
    ;;
  run)
    shift
    ;;
  *)
    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac

selected=""
for arg in "$@"; do
  case "$arg" in
    all)   selected="$selected $(lane_ids | tr '\n' ' ')" ;;
    local) selected="$selected $LOCAL_LANES" ;;
    *)
      if lane_ids | grep -qx "$arg"; then
        selected="$selected $arg"
      else
        echo "[certify] unknown lane '$arg'; run 'list' for the table" >&2
        exit 2
      fi
      ;;
  esac
done
if [ -z "${selected// /}" ]; then
  echo "[certify] no lanes selected; try 'run all' or 'run local'" >&2
  exit 2
fi

resolve_binary
mkdir -p "$CERT_DIR"
: >"$CERT_DIR/summary.tsv"
write_metadata "$CERT_DIR/metadata.json"

echo "== self-host certification =="
echo "evidence: $CERT_DIR"
echo "binary:   $("$SBPROXY_BIN" --version 2>/dev/null | head -1)"
echo "host:     $(uname -s) $(uname -r) $(uname -m)"
echo "devices:  $(nvidia_device_count) NVIDIA visible to the probe"
echo

for lane in $selected; do
  "lane_$lane"
done

fails="$(awk -F'\t' '$2=="fail"' "$CERT_DIR/summary.tsv" | wc -l | tr -d ' ')"
unsup="$(awk -F'\t' '$2=="unsupported"' "$CERT_DIR/summary.tsv" | wc -l | tr -d ' ')"
passes="$(awk -F'\t' '$2=="pass"' "$CERT_DIR/summary.tsv" | wc -l | tr -d ' ')"

echo
echo "== $passes passed, $fails failed, $unsup unsupported =="
echo "evidence retained in $CERT_DIR"
[ "$fails" -eq 0 ]
