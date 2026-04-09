#!/bin/bash

# Script to generate JWT tokens for testing and update JSON fixture files
# This script generates tokens and inserts them into the authentication.json file
#
# Usage:
#   ./generate_jwt_tokens.sh [options]
#
# Options:
#   --update-json    Update the authentication.json file with generated tokens
#   --show-tokens    Display generated tokens (default)
#   --secret KEY     Use custom secret for HMAC (default: auto-generate)
#   --algorithm ALG  Algorithm to use: RS256, HS256 (default: HS256 for simple testing)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="${PROXY_ROOT}/test/fixtures/origins"
AUTH_FILE="${FIXTURES_DIR}/authentication.json"
TOKENS_FILE="${PROXY_ROOT}/test/fixtures/jwt_tokens.json"

# Default options
UPDATE_JSON=false
SHOW_TOKENS=true
ALGORITHM="HS256"
SECRET=""

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed."
    echo "Install with: brew install jq (macOS) or apt-get install jq (Linux)"
    exit 1
fi

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --update-json)
            UPDATE_JSON=true
            shift
            ;;
        --show-tokens)
            SHOW_TOKENS=true
            shift
            ;;
        --secret)
            SECRET="$2"
            shift 2
            ;;
        --algorithm)
            ALGORITHM="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--update-json] [--show-tokens] [--secret KEY] [--algorithm ALG]"
            exit 1
            ;;
    esac
done

# Generate a random secret if not provided
if [ -z "$SECRET" ]; then
    SECRET=$(openssl rand -base64 32 | tr -d '\n')
fi

echo "🔐 Generating JWT tokens for testing"
echo "   Algorithm: $ALGORITHM"
echo "   Secret: ${SECRET:0:20}... (truncated)"
echo ""

# Function to generate JWT token using Python (more portable than requiring Go tool)
generate_jwt_token() {
    local sub="$1"
    local email="$2"
    local name="$3"
    local roles="$4"
    local exp_hours="${5:-24}"
    
    python3 <<EOF
import json
import base64
import hmac
import hashlib
import sys
import time
from datetime import datetime, timedelta

algorithm = "$ALGORITHM"
secret = "$SECRET"
subject = "$sub"
email = "$email"
name = "$name"
roles = "$roles".split(",") if "$roles" else []
exp_hours = $exp_hours

# Create header
header = {
    "alg": algorithm,
    "typ": "JWT"
}

# Create payload
now = int(time.time())
payload = {
    "sub": subject,
    "iss": "test-issuer",
    "aud": "test-audience",
    "iat": now,
    "email": email,
    "name": name,
    "roles": roles
}

if exp_hours > 0:
    payload["exp"] = now + (exp_hours * 3600)

# Encode header and payload
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

# Create signature
message = f"{header_b64}.{payload_b64}"
if algorithm.startswith("HS"):
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
else:
    print("Error: Only HS256 is supported in this script. Use tools/jwt-generator for RS256.", file=sys.stderr)
    exit(1)

token = f"{header_b64}.{payload_b64}.{signature_b64}"
print(token)
EOF
}

# Generate test tokens
echo "📝 Generating test tokens..."

ADMIN_TOKEN=$(generate_jwt_token "admin-001" "admin@test.com" "Admin User" "admin,superuser" 24)
USER_TOKEN=$(generate_jwt_token "user-123" "user@test.com" "Test User" "user" 24)
SERVICE_TOKEN=$(generate_jwt_token "service-api" "service@test.com" "Service Account" "service" 0)

# Create tokens JSON file
cat > "$TOKENS_FILE" <<EOF
{
  "tokens": {
    "admin": {
      "token": "$ADMIN_TOKEN",
      "description": "Admin user token with admin and superuser roles",
      "claims": {
        "sub": "admin-001",
        "email": "admin@test.com",
        "name": "Admin User",
        "roles": ["admin", "superuser"]
      }
    },
    "user": {
      "token": "$USER_TOKEN",
      "description": "Regular user token",
      "claims": {
        "sub": "user-123",
        "email": "user@test.com",
        "name": "Test User",
        "roles": ["user"]
      }
    },
    "service": {
      "token": "$SERVICE_TOKEN",
      "description": "Service account token (no expiry)",
      "claims": {
        "sub": "service-api",
        "email": "service@test.com",
        "name": "Service Account",
        "roles": ["service"]
      }
    }
  },
  "secret": "$SECRET",
  "algorithm": "$ALGORITHM",
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

echo "✅ Tokens generated and saved to: $TOKENS_FILE"
echo ""

# Show tokens if requested
if [ "$SHOW_TOKENS" = true ]; then
    echo "📋 Generated Tokens:"
    echo ""
    echo "Admin Token:"
    echo "  $ADMIN_TOKEN"
    echo ""
    echo "User Token:"
    echo "  $USER_TOKEN"
    echo ""
    echo "Service Token:"
    echo "  $SERVICE_TOKEN"
    echo ""
    echo "💡 Usage example:"
    echo "   curl -H 'Authorization: Bearer $ADMIN_TOKEN' \\"
    echo "        -H 'Host: jwt-auth.test' \\"
    echo "        http://localhost:8080/test/auth-required"
    echo ""
fi

# Update JSON file if requested
if [ "$UPDATE_JSON" = true ]; then
    if [ ! -f "$AUTH_FILE" ]; then
        echo "⚠️  Warning: authentication.json not found at $AUTH_FILE"
        exit 1
    fi
    
    echo "📝 Updating authentication.json with secret..."
    
    # Update JWT auth secret
    jq --arg secret "$SECRET" \
       '.jwt-auth.test.auth.secret = $secret' \
       "$AUTH_FILE" > "${AUTH_FILE}.tmp" && mv "${AUTH_FILE}.tmp" "$AUTH_FILE"
    
    echo "✅ Updated authentication.json"
    echo "   Secret updated for jwt-auth.test"
    echo ""
fi

echo "📄 Token details saved to: $TOKENS_FILE"
echo "   Use this file to reference tokens in your tests"

