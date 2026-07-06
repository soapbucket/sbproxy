#!/usr/bin/env bash
# Builds sbproxy from source, writes the config rendered by Terraform
# (fetched from instance metadata), and installs a systemd unit. It does
# NOT start sbproxy: ACME issuance needs the demo domain resolving to
# this box first, so start it from the deploy runbook after DNS.
#
# Static (no Terraform templating) so bash ${...} needs no escaping;
# inputs come from the metadata server.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec > >(tee -a /var/log/sbproxy-bootstrap.log) 2>&1
echo "[bootstrap] start $(date -u)"

meta() {
  curl -s -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"
}

# 1. Build toolchain. The Deep Learning VM image already carries the
#    NVIDIA driver + CUDA toolkit; add Rust, Node, and C build deps.
apt-get update -y
apt-get install -y build-essential cmake pkg-config libssl-dev git curl

if ! command -v npm >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi

export CARGO_HOME=/opt/cargo RUSTUP_HOME=/opt/rustup
export PATH="$CARGO_HOME/bin:$PATH"
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
fi

# 2. Clone + build sbproxy. Default features include GPU + local model
#    serving; add embed-admin-ui so the dashboard is bundled.
REPO_URL="$(meta repo-url)"
install -d /opt
cd /opt
[ -d sbproxy ] || git clone --depth 1 "$REPO_URL" sbproxy
cd sbproxy
( cd ui && npm ci && npm run build )
cargo build --release -p sbproxy --features embed-admin-ui
install -m 0755 target/release/sbproxy /usr/local/bin/sbproxy

# 3. Config + state dirs.
install -d /etc/sbproxy /var/lib/sbproxy/certs /var/lib/sbproxy/models
meta sbproxy-config >/etc/sbproxy/sb.yml

# 4. systemd unit. Binds :80/:443 via CAP_NET_BIND_SERVICE.
cat >/etc/systemd/system/sbproxy.service <<'UNIT'
[Unit]
Description=sbproxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sbproxy /etc/sbproxy/sb.yml
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
Environment=RUST_LOG=info
# Add HF_TOKEN here if serving a gated model.

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable sbproxy
echo "[bootstrap] done. After DNS resolves the ACME domain: systemctl start sbproxy"
