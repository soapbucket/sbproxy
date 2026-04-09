#!/bin/bash
set -e

echo "🔨 Building E2E Test Server"
echo "============================"

# Get dependencies
echo "📦 Downloading dependencies..."
go mod download

# Build binary
echo "🔧 Building binary..."
go build -o e2e-test-server

echo "✅ Build complete: ./e2e-test-server"
echo ""
echo "Run with:"
echo "  ./e2e-test-server"
echo ""
echo "Or with custom config:"
echo "  ./e2e-test-server -config=my-config.json"

