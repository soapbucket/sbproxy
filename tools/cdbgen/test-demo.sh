#!/bin/bash

set -e

echo "=== CDB Generator and Reader Demo ==="
echo ""

# Build the tool
echo "1. Building cdbgen..."
go build -o cdbgen main.go
echo "✓ Built cdbgen"
echo ""

# Show help
echo "2. Showing help..."
./cdbgen -h
echo ""

# Generate CDB file
echo "3. Generating CDB file from configs.example.txt..."
./cdbgen -i configs.example.txt -o demo-output.cdb
echo ""

# Test reading specific configurations
echo "4. Reading specific configurations..."
echo ""

echo "--- api.soapbucket.com ---"
./cdbgen -f demo-output.cdb -g api.soapbucket.com
echo ""

echo "--- api.soapbucket.com:8443 ---"
./cdbgen -f demo-output.cdb -g api.soapbucket.com:8443
echo ""

echo "--- cdn.example.com ---"
./cdbgen -f demo-output.cdb -g cdn.example.com
echo ""

# Test non-existent hostname
echo "5. Testing non-existent hostname (should fail)..."
./cdbgen -f demo-output.cdb -g nonexistent.example.com 2>&1 || echo "✓ Correctly returned error"
echo ""

# Dump all configurations
echo "6. Dumping all configurations..."
./cdbgen -f demo-output.cdb -dump
echo ""

# Show CDB file info
echo "7. CDB file information:"
ls -lh demo-output.cdb
echo ""

echo "=== Demo Complete ==="
echo ""
echo "To use the generated CDB file:"
echo "  export STORAGE_DSN='cdb://$(pwd)/demo-output.cdb'"
echo "  # or"
echo "  ./your-proxy -storage-dsn 'cdb://$(pwd)/demo-output.cdb'"

