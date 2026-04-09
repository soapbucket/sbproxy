#!/bin/bash
# Generate self-signed TLS certificates for PROXY_SETUP scenarios.
# Creates certs for all hostnames in sites.setup.json (from PROXY_SITES.md).
#
# Usage: ./scripts/setup_proxy_certs.sh
#
# Output: test/certs/{hostname}.crt, test/certs/{hostname}.key for each hostname

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CERT_DIR="${PROXY_ROOT}/test/certs"

# Hostnames from config/sites/sites.setup.json (PROXY_SITES.md scenarios)
# backend-news and backend-api are internal; clients connect via router.localhost
HOSTNAMES=(
  "localhost"
  "hn.local"
  "transform.localhost"
  "api.localhost"
  "router.localhost"
  "secure.localhost"
  "auth.localhost"
  "cached.localhost"
  "maintenance.localhost"
  "old-site.localhost"
  "internal-api.localhost"
)

mkdir -p "$CERT_DIR"

echo "🔒 Generating TLS certificates for PROXY_SETUP scenarios"
echo "   Output directory: $CERT_DIR"
echo ""

for hostname in "${HOSTNAMES[@]}"; do
  CRT_FILE="${CERT_DIR}/${hostname}.crt"
  KEY_FILE="${CERT_DIR}/${hostname}.key"

  if [ -f "$CRT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "⏭️  Skipping $hostname (certs already exist)"
    continue
  fi

  echo "📝 Generating certificate for $hostname..."
  CSR_FILE="${CERT_DIR}/${hostname}.csr"
  openssl genrsa -out "$KEY_FILE" 2048
  openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -subj "/CN=${hostname}/O=SoapBucket Proxy Dev/C=US"
  openssl x509 -req -days 365 -in "$CSR_FILE" -signkey "$KEY_FILE" -out "$CRT_FILE" \
    -extensions v3_req -extfile <(
      cat <<EOF
[req]
distinguished_name = req_distinguished_name
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = $hostname
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    )
  rm -f "$CSR_FILE"

  echo "   ✅ $hostname.crt and $hostname.key created"
done

echo ""
echo "✅ Certificate setup complete"
echo ""
echo "📋 Add to /etc/hosts for local testing:"
echo "   127.0.0.1 hn.local transform.localhost api.localhost router.localhost secure.localhost auth.localhost cached.localhost maintenance.localhost old-site.localhost internal-api.localhost"
echo ""
echo "🔗 Test endpoints (after starting proxy):"
echo "   curl -H 'Host: hn.local' http://localhost:8080/"
echo "   curl -H 'Host: api.localhost' http://localhost:8080/get"
echo "   curl -k -H 'Host: hn.local' https://localhost:8443/"
