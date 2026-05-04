#!/usr/bin/env bash
# Generate a self-signed CA, server cert, and client cert for the
# mTLS example. All output lives under ./certs/ next to this script.
#
# Run once:
#   bash examples/85-mtls-client-auth/generate-certs.sh
#
# Then start the proxy:
#   make run CONFIG=examples/85-mtls-client-auth/sb.yml
#
# And exercise it:
#   curl --cacert examples/85-mtls-client-auth/certs/ca.pem \
#        --cert  examples/85-mtls-client-auth/certs/client.pem \
#        --key   examples/85-mtls-client-auth/certs/client.key \
#        -H 'Host: localhost' \
#        https://127.0.0.1:8443/headers

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$DIR"
cd "$DIR"

# 1. Root CA used to sign both the server cert and any client certs.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout ca.key -out ca.pem \
    -subj "/CN=sbproxy-mtls-test-ca" >/dev/null 2>&1

# 2. Server cert with a SAN for 127.0.0.1 + localhost so curl is happy.
openssl req -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr \
    -subj "/CN=localhost" >/dev/null 2>&1

cat > server-ext.cnf <<'EOF'
subjectAltName = DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out server.pem -days 365 -extfile server-ext.cnf >/dev/null 2>&1

# 3. Client cert with a CN the upstream sees in X-Client-Cert-CN, plus
#    a DNS SAN that lands in X-Client-Cert-SAN.
openssl req -newkey rsa:2048 -nodes \
    -keyout client.key -out client.csr \
    -subj "/CN=alice@example.com/O=test-org" >/dev/null 2>&1

cat > client-ext.cnf <<'EOF'
subjectAltName = DNS:alice.local,email:alice@example.com
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out client.pem -days 365 -extfile client-ext.cnf >/dev/null 2>&1

# Drop the intermediate CSR/ext files so the cert dir has only what
# the proxy and curl need.
rm -f server.csr server-ext.cnf client.csr client-ext.cnf ca.srl

echo "Generated certs under $DIR:"
ls -1 "$DIR"
