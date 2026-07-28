#!/usr/bin/env bash
# GCP wrapper around the cloud-agnostic bootstrap-generic.sh. Every
# install/validate/start step now lives there; this file's only job is
# the GCP-specific part -- resolving each input bootstrap-generic.sh
# needs from the GCE instance metadata server -- and handing off.
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

# meta() needs curl before anything else does; every other runtime dep
# (unzip, jq, libvulkan1, build-essential, ...) is bootstrap-generic.sh's
# concern, not this wrapper's.
command -v curl >/dev/null 2>&1 || { apt-get update -y && apt-get install -y curl; }

# 1. Fetch the cloud-agnostic bootstrap script itself. Terraform embeds
#    its content as its own metadata attribute (see main.tf's
#    bootstrap-generic-script) since GCE only delivers one file's
#    content as the instance startup-script, not the rest of the repo.
meta bootstrap-generic-script >/tmp/bootstrap-generic.sh

# 2. Config. The rendered sb.yml is metadata too (main.tf's
#    sbproxy-config); write it to bootstrap-generic.sh's default
#    SBPROXY_CONFIG_FILE path before handing off.
install -d /etc/sbproxy
meta sbproxy-config >/etc/sbproxy/sb.yml

# 3. Plain-HTTP mode keys the origin on the public IP, which Terraform
#    cannot know at plan time, so it left a sentinel in the config;
#    resolve the real IP here and pass it through for the generic
#    script to substitute.
PUBLIC_IP="$(curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)"

# 4. Hand off. Every input the generic script needs, resolved from GCP
#    metadata. `bash` (not a direct exec of the file) so this still
#    works if /tmp is ever mounted noexec. Everything after this point
#    is identical on any cloud -- see deploy/aws/README.md and
#    deploy/azure/README.md, which pass the same script the same inputs
#    through their own user-data / custom-data mechanism.
INSTALL_URL="$(meta install-url)" \
SBPROXY_PUBLIC_HOST="$PUBLIC_IP" \
AUTO_START="$(meta auto-start || echo true)" \
exec bash /tmp/bootstrap-generic.sh
