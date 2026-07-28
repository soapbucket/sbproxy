#!/usr/bin/env bash
# Cloud-agnostic one-command GPU box bootstrap. Installs the released
# sbproxy binary via the curl installer, validates the host through
# `sbproxy doctor --format json` (no ad hoc nvidia-smi parsing), installs
# a systemd unit, and starts it. NO source build, NO Node/UI build, and
# NO hand-built llama.cpp: sbproxy acquires the inference engine itself
# from the `serve.engines.*.acquire` block in the config, so the box
# reaches a served model on the first request with no manual engine step.
#
# Requires a released binary with `gpu-nvidia` + `model-weights`
# (v1.5.0+). The NVIDIA driver is expected to be image-provided (a GCP
# Deep Learning VM, an AWS DLAMI, an Azure NVads image, ...).
#
# This script has no cloud-specific input resolution: every input below
# comes from an environment variable the caller sets before sourcing or
# exec'ing this file. `startup-release.sh` is the GCP wrapper that
# resolves these from the instance metadata server; `cloud-init.yaml`
# sets them directly since it already writes the config statically.
#
#   INSTALL_URL          curl-installer URL. Default: https://download.sbproxy.dev
#   SBPROXY_CONFIG_FILE  Path to the already-rendered sb.yml. The caller
#                        is responsible for writing this file (Terraform
#                        renders it from metadata; cloud-init writes it
#                        via write_files). Default: /etc/sbproxy/sb.yml
#   SBPROXY_PUBLIC_HOST  Real public IP/host to substitute for a literal
#                        SBPROXY_PUBLIC_HOST sentinel inside the config
#                        (plain-HTTP mode, where the origin is keyed to
#                        an IP Terraform cannot know at plan time). Unset
#                        or empty skips the substitution.
#   AUTO_START           "true" to start sbproxy immediately (plain-HTTP
#                        demo mode); "false" to install and leave it
#                        stopped (TLS mode waits for DNS). Default: true
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

INSTALL_URL="${INSTALL_URL:-https://download.sbproxy.dev}"
SBPROXY_CONFIG_FILE="${SBPROXY_CONFIG_FILE:-/etc/sbproxy/sb.yml}"
SBPROXY_PUBLIC_HOST="${SBPROXY_PUBLIC_HOST:-}"
AUTO_START="${AUTO_START:-true}"

# 1. Runtime deps only. The curl installer needs curl and jq (doctor
#    validation below parses its JSON report); `unzip` is used by
#    sbproxy to unpack the acquired llama.cpp release; the acquired
#    Vulkan llama.cpp build needs the NVIDIA Vulkan ICD (mesa-vulkan is
#    the portable loader). vLLM (safetensors) instead needs a container
#    runtime; install docker if you serve a catalog/safetensors model.
apt-get update -y
apt-get install -y curl unzip jq libvulkan1 vulkan-tools
# vLLM (the GPU path via `uvx`) JIT-compiles a Triton CUDA shim at engine
# startup, which needs a C toolchain and the Python dev headers; without
# them vLLM's engine core fails to initialize. (llama.cpp needs neither.)
apt-get install -y build-essential python3-dev

# 2. Install the released sbproxy binary to /usr/local/bin (the systemd
#    unit runs it from there). The installer drops it in a per-user dir;
#    SBPROXY_INSTALL_DIR overrides that, and we symlink as a fallback.
export SBPROXY_INSTALL_DIR=/usr/local/bin
curl -fsSL "$INSTALL_URL" | sh || {
  echo "[bootstrap] installer failed; retrying once"; sleep 5
  curl -fsSL "$INSTALL_URL" | sh
}
if [ ! -x /usr/local/bin/sbproxy ]; then
  # Fall back to wherever the installer put it.
  found="$(command -v sbproxy || find /root /home -maxdepth 4 -name sbproxy -type f 2>/dev/null | head -1)"
  [ -n "$found" ] && install -m 0755 "$found" /usr/local/bin/sbproxy
fi
/usr/local/bin/sbproxy --version || { echo "[bootstrap] sbproxy not installed"; exit 1; }

# 3. Config + state dirs. The config itself is the caller's
#    responsibility (see SBPROXY_CONFIG_FILE above); this only creates
#    the directories the model host writes weights and the acquired
#    engine under, and substitutes a plain-HTTP public-host sentinel
#    when the caller resolved one.
install -d /etc/sbproxy /var/lib/sbproxy/certs /var/lib/sbproxy/models
if [ ! -f "$SBPROXY_CONFIG_FILE" ]; then
  echo "[bootstrap] SBPROXY_CONFIG_FILE ($SBPROXY_CONFIG_FILE) does not exist"; exit 1
fi
if [ -n "$SBPROXY_PUBLIC_HOST" ] && grep -q SBPROXY_PUBLIC_HOST "$SBPROXY_CONFIG_FILE"; then
  # Bash pattern substitution rather than sed: SBPROXY_PUBLIC_HOST can be
  # an IPv6 address or a hostname containing sed's own delimiter or
  # replacement metacharacters (/, &, \); ${var//pattern/replacement}
  # treats the replacement as a literal string, so none of those need
  # escaping here.
  config_content="$(cat "$SBPROXY_CONFIG_FILE")"
  printf '%s\n' "${config_content//SBPROXY_PUBLIC_HOST/$SBPROXY_PUBLIC_HOST}" >"$SBPROXY_CONFIG_FILE"
fi

# 4. Driver + host validation through `sbproxy doctor`, not ad hoc
#    nvidia-smi parsing: doctor is the one detection layer engine
#    acquisition, `sbproxy run`, and the CLI already share (see
#    crates/sbproxy-core/src/doctor.rs), so this box never disagrees
#    with sbproxy itself about what hardware it has. Informational only
#    (`|| true`): a missing engine here is still recoverable by
#    acquisition at the first request, so this must not fail the boot.
DOCTOR_JSON="$(/usr/local/bin/sbproxy doctor "$SBPROXY_CONFIG_FILE" --format json || true)"
if [ -n "$DOCTOR_JSON" ]; then
  echo "$DOCTOR_JSON" | jq -r '
    "[doctor] gpus: " + (.gpus | length | tostring)
    + ", nvidia driver: " + (.drivers.nvidia_driver // "none")
    + ", shared memory: " + (.shared_memory.total_bytes // 0 | tostring) + " bytes"
    + ", local serving ready: " + (.local_serving.ready | tostring)
  '
  echo "$DOCTOR_JSON" | jq -r '.local_serving.blockers[]? | "[doctor] blocker: " + .'
  if echo "$DOCTOR_JSON" | jq -e '.cache_budget_check.sufficient == false' >/dev/null 2>&1; then
    echo "[doctor] warning: the weight-cache mount does not have enough free space for the configured cache_budget_gib"
  fi
else
  echo "[bootstrap] sbproxy doctor produced no output"
fi

# 5. systemd unit. Binds :80/:443 via CAP_NET_BIND_SERVICE; the model
#    host fetches weights + the engine over HTTPS, so raise NOFILE.
#    Unquoted heredoc delimiter (deliberate, unlike other heredocs in
#    this script): ExecStart must honor the caller's actual
#    SBPROXY_CONFIG_FILE, not a hardcoded default, so it runs the wrong
#    config for a caller that overrode it.
cat >/etc/systemd/system/sbproxy.service <<UNIT
[Unit]
Description=sbproxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sbproxy ${SBPROXY_CONFIG_FILE}
Restart=on-failure
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
Environment=RUST_LOG=info
# Add HF_TOKEN=... here to serve a gated model.

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable sbproxy

# 6. Auto-start. With no ACME domain (plain-HTTP demo) there is nothing
#    to wait for, so start now: the first request acquires the engine,
#    pulls the weights, and serves. With a domain, issuance needs DNS to
#    resolve to this box first, so leave it stopped for the runbook to
#    start.
if [ "$AUTO_START" = "true" ]; then
  systemctl start sbproxy
  echo "[bootstrap] sbproxy started. First request will acquire the engine + pull weights."
else
  echo "[bootstrap] done. After DNS resolves the ACME domain: systemctl start sbproxy"
fi
