#!/bin/bash

# Script to load origin configurations into PostgreSQL database
# This script combines fixtures and loads them into the database

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="${PROXY_ROOT}/test"

echo "💾 Loading database with origin configurations"
echo ""

# Combine fixtures first
echo "🔗 Combining origin fixtures..."
cd "$TEST_DIR/fixtures/origins"
if [ -f "${SCRIPT_DIR}/combine-fixtures.sh" ]; then
    "${SCRIPT_DIR}/combine-fixtures.sh"
else
    echo "❌ Error: combine-fixtures.sh not found"
    exit 1
fi

# Check if origins.json exists
if [ ! -f "origins.json" ]; then
    echo "❌ Error: origins.json not found after combining fixtures"
    exit 1
fi

echo "✅ Fixtures combined"
echo ""

# Load into database
# Check if using Docker or local PostgreSQL
if docker ps | grep -q test-postgres; then
    echo "📦 Using Docker PostgreSQL..."
    "${SCRIPT_DIR}/populate_from_docker.sh" "$TEST_DIR/fixtures/origins/origins.json"
else
    echo "💻 Using local PostgreSQL..."
    "${SCRIPT_DIR}/populate_origins.sh" "$TEST_DIR/fixtures/origins/origins.json"
fi

echo ""
echo "✅ Database loaded successfully"

