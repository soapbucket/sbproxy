#!/usr/bin/env bash
# One-command GPU box (WOR-1806): install the released sbproxy binary via
# the curl installer, write the Terraform-rendered config, and start it.
# NO source build, NO Node/UI build, and NO hand-built llama.cpp: sbproxy
# acquires the inference engine itself from the `serve.engines.*.acquire`
# block in the config (WOR-1801), so the box reaches a served model on the
# first request with no manual engine step.
#
# Requires a released binary with `gpu-nvidia` + `model-weights` (v1.5.0+).
# The NVIDIA driver is image-provided (Deep Learning VM).
#
# Static (no Terraform templating) so bash ${...} needs no escaping;
# inputs come from the instance metadata server.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > >(tee -a /var/log/sbproxy-bootstrap.log) 2>&1
echo "[bootstrap] start $(date -u)"

meta() {
  curl -s -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"
}

# 1. Runtime deps only. The curl installer needs curl; `unzip` is used by
#    sbproxy to unpack the acquired llama.cpp release; the acquired Vulkan
#    llama.cpp build needs the NVIDIA Vulkan ICD (mesa-vulkan is the
#    portable loader). vLLM (safetensors) instead needs a container
#    runtime; install docker if you serve a catalog/safetensors model.
apt-get update -y
apt-get install -y curl unzip libvulkan1 vulkan-tools

# 2. Install the released sbproxy binary to /usr/local/bin (the systemd
#    unit runs it from there). The installer drops it in a per-user dir;
#    SBPROXY_INSTALL_DIR overrides that, and we symlink as a fallback.
INSTALL_URL="$(meta install-url)"
: "${INSTALL_URL:=https://download.sbproxy.dev}"
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

# 3. Config + state dirs. The model host writes weights + the acquired
#    engine under the cache dir; /var/lib/sbproxy is the service default.
install -d /etc/sbproxy /var/lib/sbproxy/certs /var/lib/sbproxy/models
meta sbproxy-config >/etc/sbproxy/sb.yml
# Plain-HTTP mode keys the origin on the public IP, which Terraform cannot
# know at plan time, so it left a sentinel: substitute the real IP here.
if grep -q SBPROXY_PUBLIC_HOST /etc/sbproxy/sb.yml; then
  PUBLIC_IP="$(curl -s -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)"
  sed -i "s/SBPROXY_PUBLIC_HOST/${PUBLIC_IP}/g" /etc/sbproxy/sb.yml
fi

# Report what the box can do before serving; also verifies the config.
/usr/local/bin/sbproxy doctor /etc/sbproxy/sb.yml || true

# 4. systemd unit. Binds :80/:443 via CAP_NET_BIND_SERVICE; the model
#    host fetches weights + the engine over HTTPS, so raise NOFILE.
cat >/etc/systemd/system/sbproxy.service <<'UNIT'
[Unit]
Description=sbproxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sbproxy /etc/sbproxy/sb.yml
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

# 5. Auto-start. With no ACME domain (plain-HTTP demo) there is nothing to
#    wait for, so start now: the first request acquires the engine, pulls
#    the weights, and serves. With a domain, issuance needs DNS to resolve
#    to this box first, so leave it stopped for the runbook to start.
AUTO_START="$(meta auto-start || echo true)"
if [ "$AUTO_START" = "true" ]; then
  systemctl start sbproxy
  echo "[bootstrap] sbproxy started. First request will acquire the engine + pull weights."
else
  echo "[bootstrap] done. After DNS resolves the ACME domain: systemctl start sbproxy"
fi
