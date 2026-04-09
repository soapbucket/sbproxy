#!/bin/bash

# Demo script for config-loader tool

set -e

TOOL="./config-loader"
DB="/tmp/demo-origins.db"
DSN="sqlite://$DB"

echo "========================================"
echo "Config Loader Tool Demo"
echo "========================================"
echo ""

# Clean up any existing database
rm -f "$DB"

echo "1. Loading configurations from example file..."
$TOOL -dsn "$DSN" -load configs.example.txt
echo ""

echo "2. Viewing loaded configurations..."
sqlite3 "$DB" "SELECT key, substr(value, 1, 50) || '...' as config FROM config_storage"
echo ""

echo "3. Viewing UUIDs generated..."
sqlite3 "$DB" "SELECT id, key FROM config_storage"
echo ""

echo "4. Testing update (re-loading same configs - should preserve UUIDs)..."
$TOOL -dsn "$DSN" -load configs.example.txt
echo ""

echo "5. Verifying UUIDs are preserved..."
sqlite3 "$DB" "SELECT id, key FROM config_storage"
echo ""

echo "6. Deleting specific hostname..."
$TOOL -dsn "$DSN" -delete localhost:8443
echo ""

echo "7. Remaining configs..."
sqlite3 "$DB" "SELECT key FROM config_storage"
echo ""

echo "8. Testing empty prefix protection (should fail)..."
$TOOL -dsn "$DSN" -delete-prefix '' || echo "✓ Empty prefix correctly rejected"
echo ""

echo "9. Testing short prefix protection (should fail)..."
$TOOL -dsn "$DSN" -delete-prefix 'a' || echo "✓ Short prefix correctly rejected"
echo ""

echo "10. Deleting by prefix (with auto-confirmation)..."
echo "y" | $TOOL -dsn "$DSN" -delete-prefix 'api.'
echo ""

echo "11. Final state..."
sqlite3 "$DB" "SELECT key FROM config_storage" || echo "(No records remaining)"
echo ""

echo "========================================"
echo "Demo Complete!"
echo "========================================"
echo ""
echo "Database location: $DB"
echo "You can inspect it with: sqlite3 $DB"

