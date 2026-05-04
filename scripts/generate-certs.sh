#!/usr/bin/env bash
# generate-certs.sh
#
# Generates self-signed development certificates for testing mTLS, HTTPS,
# and client certificate authentication. These are NOT for production use.
#
# Output directory: certs/
#   ca-cert.pem, ca-key.pem       - Certificate Authority
#   server-cert.pem, server-key.pem - Server certificate (localhost + *.test)
#   client-cert.pem, client-key.pem - Client certificate for mTLS testing
#
# Usage:
#   ./scripts/generate-certs.sh
#   make certs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/certs"

mkdir -p "$CERT_DIR"

echo "==> Generating development certificates in $CERT_DIR"

# CA
echo "[1/3] Generating CA..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/ca-key.pem" \
    -out "$CERT_DIR/ca-cert.pem" \
    -days 3650 \
    -subj "/CN=sbproxy Dev CA/O=sbproxy" \
    2>/dev/null

# Server cert
echo "[2/3] Generating server certificate..."
openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/server-key.pem" \
    -out "$CERT_DIR/server.csr" \
    -subj "/CN=localhost/O=sbproxy" \
    2>/dev/null

cat > "$CERT_DIR/server-ext.cnf" <<EOF
subjectAltName=DNS:localhost,DNS:*.test,DNS:*.localhost,IP:127.0.0.1,IP:::1
EOF

openssl x509 -req \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/server-cert.pem" \
    -days 3650 \
    -extfile "$CERT_DIR/server-ext.cnf" \
    2>/dev/null

# Client cert
echo "[3/3] Generating client certificate..."
openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERT_DIR/client-key.pem" \
    -out "$CERT_DIR/client.csr" \
    -subj "/CN=test-client/O=sbproxy" \
    2>/dev/null

openssl x509 -req \
    -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/client-cert.pem" \
    -days 3650 \
    2>/dev/null

# Cleanup temp files
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.cnf "$CERT_DIR"/*.srl

echo ""
echo "Done. Certificates written to $CERT_DIR/"
echo "  CA:     ca-cert.pem, ca-key.pem"
echo "  Server: server-cert.pem, server-key.pem (localhost, *.test, *.localhost)"
echo "  Client: client-cert.pem, client-key.pem (for mTLS testing)"
echo ""
echo "These are for development only. Do not use in production."
