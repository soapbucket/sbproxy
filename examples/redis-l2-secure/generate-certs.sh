#!/usr/bin/env bash

set -euo pipefail

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cert_dir="${example_dir}/certs"
redis_password="${REDIS_PASSWORD:-development-only-password}"

for required_command in openssl awk; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        echo "missing required command: ${required_command}" >&2
        exit 1
    fi
done

umask 077
mkdir -p "${cert_dir}"

server_csr="${cert_dir}/server.csr"
server_ext="${cert_dir}/server-ext.cnf"
client_csr="${cert_dir}/client.csr"
client_ext="${cert_dir}/client-ext.cnf"
ca_serial="${cert_dir}/ca.srl"

cleanup() {
    rm -f "${server_csr}" "${server_ext}" "${client_csr}" "${client_ext}" "${ca_serial}"
}
trap cleanup EXIT
cleanup

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
    -keyout "${cert_dir}/ca.key" \
    -out "${cert_dir}/ca.pem" \
    -subj "/CN=sbproxy-redis-development-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    >/dev/null 2>&1

openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "${cert_dir}/server.key" \
    -out "${server_csr}" \
    -subj "/CN=localhost" \
    >/dev/null 2>&1

printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:localhost,DNS:redis,IP:127.0.0.1' \
    >"${server_ext}"

openssl x509 -req -sha256 -days 30 \
    -in "${server_csr}" \
    -CA "${cert_dir}/ca.pem" \
    -CAkey "${cert_dir}/ca.key" \
    -CAcreateserial \
    -out "${cert_dir}/server.pem" \
    -extfile "${server_ext}" \
    >/dev/null 2>&1

openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "${cert_dir}/client.key" \
    -out "${client_csr}" \
    -subj "/CN=sbproxy-redis-development-client" \
    >/dev/null 2>&1

printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=clientAuth' \
    >"${client_ext}"

openssl x509 -req -sha256 -days 30 \
    -in "${client_csr}" \
    -CA "${cert_dir}/ca.pem" \
    -CAkey "${cert_dir}/ca.key" \
    -CAserial "${ca_serial}" \
    -out "${cert_dir}/client.pem" \
    -extfile "${client_ext}" \
    >/dev/null 2>&1

# A second CA is useful for the documented trust-failure check. It never signs
# the Redis server identity.
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
    -keyout "${cert_dir}/wrong-ca.key" \
    -out "${cert_dir}/wrong-ca.pem" \
    -subj "/CN=sbproxy-redis-wrong-development-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    >/dev/null 2>&1

# Redis ACL files accept SHA-256 password hashes. Keeping even the development
# password out of the generated file makes accidental inspection less harmful.
password_hash="$(printf '%s' "${redis_password}" | openssl dgst -sha256 -r | awk '{print $1}')"
printf 'user default on #%s ~* &* +@all\n' "${password_hash}" >"${cert_dir}/users.acl"

chmod 0600 \
    "${cert_dir}/ca.key" \
    "${cert_dir}/server.key" \
    "${cert_dir}/client.key" \
    "${cert_dir}/wrong-ca.key" \
    "${cert_dir}/users.acl"
chmod 0644 \
    "${cert_dir}/ca.pem" \
    "${cert_dir}/server.pem" \
    "${cert_dir}/client.pem" \
    "${cert_dir}/wrong-ca.pem"

openssl verify -purpose sslserver -CAfile "${cert_dir}/ca.pem" "${cert_dir}/server.pem"
openssl verify -purpose sslclient -CAfile "${cert_dir}/ca.pem" "${cert_dir}/client.pem"

echo
echo "Generated development-only Redis TLS fixtures in ${cert_dir}"
echo "Do not use these certificates, keys, or the example password in production."
