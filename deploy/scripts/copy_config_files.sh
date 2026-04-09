#!/bin/bash

# Script to copy necessary configuration files from main proxy conf directory
# This ensures test environment has access to regexes.yaml and ipinfo_lite.mmdb

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_DIR="${PROXY_ROOT}/test"
PROXY_DIR="${PROXY_ROOT}"

echo "📋 Copying configuration files..."
echo ""

# Create conf directory if it doesn't exist
mkdir -p "$TEST_DIR/conf"

# Copy regexes.yml if it exists
if [ -f "$PROXY_DIR/data/regexes.yml" ]; then
    echo "📄 Copying regexes.yml..."
    cp "$PROXY_DIR/data/regexes.yml" "$TEST_DIR/conf/regexes.yml"
    echo "✅ regexes.yml copied"
else
    echo "⚠️  Warning: regexes.yml not found at $PROXY_DIR/data/regexes.yml"
    echo "   You may need to copy it manually or download from uaparser project"
fi

# Copy ipinfo_lite.mmdb if it exists
if [ -f "$PROXY_DIR/data/ipinfo_lite.mmdb" ]; then
    echo "📄 Copying ipinfo_lite.mmdb..."
    cp "$PROXY_DIR/data/ipinfo_lite.mmdb" "$TEST_DIR/conf/ipinfo_lite.mmdb"
    echo "✅ ipinfo_lite.mmdb copied"
else
    echo "⚠️  Warning: ipinfo_lite.mmdb not found at $PROXY_DIR/data/ipinfo_lite.mmdb"
    echo "   You may need to download it from MaxMind or copy from main data directory"
fi

echo ""
echo "✅ Configuration files copied"

