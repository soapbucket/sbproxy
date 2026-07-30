#!/usr/bin/env bash
# Worker-image entrypoint (SH-19). Runs the startup gate, then execs
# whatever the image was asked to run.
#
# The gate is `sbproxy doctor --strict <config>`, which validates the
# conditions no later retry can fix:
#
#   driver               a CUDA config on a box with no NVIDIA driver
#   visible_devices      a driver but no device (the `--gpus` omission)
#   cuda_compatibility   a configured model with no viable engine here
#   shared_memory        /dev/shm smaller than engines.*.shm_size_gib
#   cache_mount          a mount that cannot hold serve.cache_budget_gib
#   model_plane_identity mTLS or shared-key material that is not readable
#
# Failing here is deliberate. A worker that boots into a broken GPU
# configuration joins gossip, advertises itself as eligible, and then
# fails every dispatch, which reads as a routing bug from the gateway.
# Refusing to start turns that into one legible line in `docker logs`.
#
# Env:
#   SBPROXY_CONFIG_FILE       config the gate reads. Default
#                             /etc/sbproxy/sb.yml.
#   SBPROXY_SKIP_STARTUP_GATE 1 to skip the gate entirely (debugging a
#                             box the gate is wrong about).
set -euo pipefail

SBPROXY_CONFIG_FILE="${SBPROXY_CONFIG_FILE:-/etc/sbproxy/sb.yml}"

if [ "${SBPROXY_SKIP_STARTUP_GATE:-0}" = "1" ]; then
  echo "[startup-gate] skipped (SBPROXY_SKIP_STARTUP_GATE=1)"
elif [ ! -f "$SBPROXY_CONFIG_FILE" ]; then
  # No config yet is not a gate failure: an operator may mount one over
  # this path, or be running a one-off command (`--version`, `doctor`).
  echo "[startup-gate] skipped: no config at $SBPROXY_CONFIG_FILE"
else
  # `|| true` so the gate's own exit code, not `set -e`, decides. The
  # text form goes to the container log because that is where an
  # operator looks first.
  gate_status=0
  /usr/local/bin/sbproxy doctor --strict "$SBPROXY_CONFIG_FILE" || gate_status=$?
  if [ "$gate_status" -ne 0 ]; then
    echo "[startup-gate] refusing to start: the startup gate failed (exit ${gate_status})." >&2
    echo "[startup-gate] fix the named blockers above, or set SBPROXY_SKIP_STARTUP_GATE=1 to boot anyway." >&2
    exit "$gate_status"
  fi
  echo "[startup-gate] passed"
fi

exec /usr/local/bin/sbproxy "$@"
