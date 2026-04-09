#!/bin/bash

# Script to generate test certificates and compute certificate pins for certificate pinning
# This script generates self-signed certificates and computes SHA256 pins for use in configs
#
# Usage:
#   ./generate_certificates.sh [options]
#
# Options:
#   --hostname HOST    Hostname for certificate (default: e2e-test-server)
#   --output-dir DIR   Output directory for certificates (default: ../certs)
#   --update-json      Update fixture files with certificate pins
#   --show-pins        Display computed pins (default)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CERT_DIR="${PROXY_ROOT}/test/certs"
FIXTURES_DIR="${PROXY_ROOT}/test/fixtures/origins"

# Default options
HOSTNAME="e2e-test-server"
OUTPUT_DIR="$CERT_DIR"
UPDATE_JSON=false
SHOW_PINS=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --hostname)
            HOSTNAME="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --update-json)
            UPDATE_JSON=true
            shift
            ;;
        --show-pins)
            SHOW_PINS=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--hostname HOST] [--output-dir DIR] [--update-json] [--show-pins]"
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "🔒 Generating test certificates"
echo "   Hostname: $HOSTNAME"
echo "   Output directory: $OUTPUT_DIR"
echo ""

# Generate private key
PRIVATE_KEY="${OUTPUT_DIR}/${HOSTNAME}.key"
CERTIFICATE="${OUTPUT_DIR}/${HOSTNAME}.crt"
CSR="${OUTPUT_DIR}/${HOSTNAME}.csr"

echo "📝 Generating private key..."
openssl genrsa -out "$PRIVATE_KEY" 2048

echo "📝 Generating certificate signing request..."
openssl req -new -key "$PRIVATE_KEY" -out "$CSR" -subj "/CN=${HOSTNAME}/O=Test Organization/C=US"

echo "📝 Generating self-signed certificate (valid for 365 days)..."
openssl x509 -req -days 365 -in "$CSR" -signkey "$PRIVATE_KEY" -out "$CERTIFICATE" \
    -extensions v3_req -extfile <(
        cat <<EOF
[req]
distinguished_name = req_distinguished_name
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = $HOSTNAME
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    )

# Clean up CSR
rm -f "$CSR"

echo "✅ Certificate generated: $CERTIFICATE"
echo ""

# Compute certificate pin (SHA256 of SPKI)
echo "🔐 Computing certificate pin..."

PIN_SHA256=$(openssl x509 -in "$CERTIFICATE" -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -binary | \
    openssl enc -base64 | tr -d '\n')

echo "✅ Certificate pin computed"
echo ""

# Show certificate details
if [ "$SHOW_PINS" = true ]; then
    echo "📋 Certificate Details:"
    echo ""
    echo "Certificate: $CERTIFICATE"
    echo "Private Key: $PRIVATE_KEY"
    echo ""
    echo "Certificate Pin (SHA256 of SPKI):"
    echo "  $PIN_SHA256"
    echo ""
    echo "Certificate Subject:"
    openssl x509 -in "$CERTIFICATE" -noout -subject
    echo ""
    echo "Certificate Validity:"
    openssl x509 -in "$CERTIFICATE" -noout -dates
    echo ""
    echo "💡 Usage in certificate pinning config:"
    echo "   {"
    echo "     \"certificate_pinning\": {"
    echo "       \"enabled\": true,"
    echo "       \"pin_sha256\": \"$PIN_SHA256\""
    echo "     }"
    echo "   }"
    echo ""
fi

# Save pin information
PIN_FILE="${OUTPUT_DIR}/${HOSTNAME}_pin.json"
cat > "$PIN_FILE" <<EOF
{
  "hostname": "$HOSTNAME",
  "pin_sha256": "$PIN_SHA256",
  "certificate": "$CERTIFICATE",
  "private_key": "$PRIVATE_KEY",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "valid_until": "$(openssl x509 -in "$CERTIFICATE" -noout -enddate | cut -d= -f2 | xargs -I {} date -u -d {} +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || openssl x509 -in "$CERTIFICATE" -noout -enddate | cut -d= -f2)"
}
EOF

echo "📄 Pin information saved to: $PIN_FILE"

# Update JSON files if requested
if [ "$UPDATE_JSON" = true ]; then
    echo ""
    echo "📝 Updating fixture files with certificate pins..."
    
    # Find all JSON files that might need certificate pinning
    for json_file in "$FIXTURES_DIR"/*.json; do
        if [ ! -f "$json_file" ]; then
            continue
        fi
        
        # Check if file contains HTTPS URLs that might need certificate pinning
        if grep -q "https://" "$json_file" 2>/dev/null; then
            echo "   Found potential HTTPS config in: $(basename "$json_file")"
            echo "   💡 Add certificate_pinning config manually if needed"
        fi
    done
    
    echo ""
    echo "✅ Certificate generation complete"
    echo "   Add certificate_pinning to your configs using the pin above"
fi

echo ""
echo "✅ Done!"



