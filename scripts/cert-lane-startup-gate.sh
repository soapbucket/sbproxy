#!/usr/bin/env bash
# Startup-gate certification lane (SH-19 / SH-23).
#
# Proves `sbproxy doctor --strict` behaves as the managed-worker boot gate
# on *this* host: it refuses a config this box cannot serve, names each
# blocker, and exits 3; and it passes a config this box can serve.
#
# Deliberately host-shape-agnostic. Rather than asserting "the driver
# check fails" (true on a Mac, false on an L4), it asserts the invariants
# that must hold on every host:
#
#   * a config demanding hardware the probe does not see fails, exit 3
#   * every failure names its check id, so a bootstrap can grep for one
#   * an unsatisfiable model-plane identity always fails, on any host
#   * a config that asks for nothing local passes, exit 0
#   * every check reports a status, so nothing is silently dropped
#
# Usage: cert-lane-startup-gate.sh [path-to-sbproxy]
set -uo pipefail

SBPROXY_BIN="${1:-${SBPROXY_BIN:-target/debug/sbproxy}}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok()  { echo "  PASS $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL $1"; fail=$((fail + 1)); }

CHECK_IDS="driver visible_devices cuda_compatibility shared_memory cache_mount model_plane_identity unpinned_weights"
# Derived, so adding a check does not silently weaken this lane.
EXPECTED_CHECKS="$(printf '%s\n' $CHECK_IDS | wc -l | tr -d ' ')"

echo "== startup gate lane =="
echo "   binary: $("$SBPROXY_BIN" --version 2>/dev/null | head -1)"

# --- an impossible config must be refused -------------------------------
#
# Asks for more shared memory and more cache than any real box has, plus
# mTLS material that does not exist. Nothing here is host-specific: it
# fails on a Mac, on an L4, and in a container.
cat >"$WORK/impossible.yml" <<'YAML'
proxy:
  cluster:
    cluster_id: cert-fleet
    node_id: cert-worker
    roles: [worker]
    security:
      mode: mtls
      cert_file: /nonexistent/cert-lane/worker.crt
origins:
  ai.local:
    action:
      providers:
        - name: local
          serve:
            cache_budget_gib: 999999
            engines:
              vllm:
                launch: container
                image: vllm/vllm-openai@sha256:05a31dc4185b042e91f4d2183689ac8a87bd845713d5c3f987563c5899878271
                shm_size_gib: 4096
            models:
              - model: qwen3-8b
                engine: vllm
YAML

"$SBPROXY_BIN" doctor --strict "$WORK/impossible.yml" >"$WORK/impossible.txt" 2>&1
impossible_exit=$?
if [ "$impossible_exit" -eq 3 ]; then
  ok "an unsatisfiable config exits 3 (the startup-blocker code)"
else
  bad "an unsatisfiable config exited $impossible_exit, expected 3"
fi

if grep -q "verdict: FAIL" "$WORK/impossible.txt"; then
  ok "the gate prints a FAIL verdict line"
else
  bad "no FAIL verdict line in the gate output"
fi

# Each blocker must be attributed to a named check, or a bootstrap cannot
# act on it.
for expected in shared_memory cache_mount model_plane_identity; do
  if grep -qE "^  ${expected} +fail" "$WORK/impossible.txt"; then
    ok "check '$expected' failed and is named"
  else
    bad "check '$expected' did not fail on a config that cannot be satisfied anywhere"
  fi
done

# The unreadable identity file has to appear by path: "it failed" without
# saying which file is not actionable at 3am.
if grep -q "worker.crt" "$WORK/impossible.txt"; then
  ok "the identity failure names the unreadable path"
else
  bad "the identity failure does not name the file it could not read"
fi

# --- JSON form carries the same verdict ---------------------------------
"$SBPROXY_BIN" doctor --strict --format json "$WORK/impossible.yml" >"$WORK/impossible.json" 2>&1
json_exit=$?
if [ "$json_exit" -eq 3 ]; then
  ok "the JSON form exits 3 as well"
else
  bad "the JSON form exited $json_exit, expected 3"
fi
if python3 - "$WORK/impossible.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
checks = report.get("strict_checks")
assert checks, "strict_checks missing from the JSON report"
ids = {c["check"] for c in checks}
expected = {
    "driver",
    "visible_devices",
    "cuda_compatibility",
    "shared_memory",
    "cache_mount",
    "model_plane_identity",
    "unpinned_weights",
}
missing = expected - ids
assert not missing, f"JSON report omits checks: {sorted(missing)}"
for check in checks:
    assert check["status"] in {"pass", "fail", "skip"}, check
    assert check["detail"], f"check {check['check']} has no detail"
demand = report.get("serve_demand", {})
assert demand.get("requires_cuda") is True, "a vLLM engine must register as a CUDA demand"
PY
then
  ok "the JSON report carries every check with a status and a detail"
else
  bad "the JSON report is missing checks, statuses, or details"
fi

# --- a config that asks for nothing local must pass ---------------------
cat >"$WORK/gateway-only.yml" <<'YAML'
origins:
  api.local:
    upstream: https://test.sbproxy.dev
YAML

"$SBPROXY_BIN" doctor --strict "$WORK/gateway-only.yml" >"$WORK/gateway.txt" 2>&1
gateway_exit=$?
if [ "$gateway_exit" -eq 0 ]; then
  ok "a gateway-only config passes the gate (exit 0)"
else
  bad "a gateway-only config exited $gateway_exit, expected 0"
  cat "$WORK/gateway.txt"
fi

# Nothing may be silently dropped: every check reports, and on a
# gateway-only config every one of them is a skip, not a hollow pass.
missing_ids=""
for id in $CHECK_IDS; do
  grep -qE "^  ${id} " "$WORK/gateway.txt" || missing_ids="$missing_ids $id"
done
if [ -z "${missing_ids// /}" ]; then
  ok "all ${EXPECTED_CHECKS} checks report a status even when none applies"
else
  bad "checks absent from the report:${missing_ids}"
fi
skips="$(grep -cE "^  [a-z_]+ +skip" "$WORK/gateway.txt" || true)"
if [ "${skips:-0}" -eq "$EXPECTED_CHECKS" ]; then
  ok "a gateway-only config skips every check rather than claiming a pass"
else
  bad "expected ${EXPECTED_CHECKS} skips on a gateway-only config, found ${skips:-0}"
fi

echo
echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
