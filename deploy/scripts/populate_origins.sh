#!/bin/bash

# Script to populate PostgreSQL database with origin configurations from origins.json
# This script reads the origins.json file and generates SQL INSERT statements
#
# Usage:
#   ./populate_origins.sh [origins.json path] [database connection string]
#
# Examples:
#   ./populate_origins.sh ../fixtures/origins/origins.json
#   ./populate_origins.sh ../fixtures/origins/origins.json "postgres://proxy:proxy@localhost:5432/proxy?sslmode=disable"

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ORIGINS_FILE="${1:-${PROXY_ROOT}/test/fixtures/origins/origins.json}"
DB_CONN="${2:-postgres://proxy:proxy@localhost:5432/proxy?sslmode=disable}"

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed."
    echo "Install with: brew install jq (macOS) or apt-get install jq (Linux)"
    exit 1
fi

# Check if origins.json exists
if [ ! -f "$ORIGINS_FILE" ]; then
    echo "Error: Origins file not found: $ORIGINS_FILE"
    echo "Run scripts/combine-fixtures.sh first to create origins.json"
    exit 1
fi

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo "Error: psql is required but not installed."
    echo "Install PostgreSQL client tools"
    exit 1
fi

echo "📦 Populating PostgreSQL database with origin configurations"
echo "   Origins file: $ORIGINS_FILE"
echo "   Database: $DB_CONN"
echo ""

# Initialize schema first
echo "🔧 Initializing database schema..."
psql "$DB_CONN" -f "${PROXY_ROOT}/sql/init_schema.sql" > /dev/null 2>&1 || {
    echo "Warning: Schema initialization may have failed (table might already exist)"
}

# Create temporary SQL file
TEMP_SQL=$(mktemp)
trap "rm -f $TEMP_SQL" EXIT

# Start transaction
echo "BEGIN;" > "$TEMP_SQL"

# Count origins
ORIGIN_COUNT=$(jq 'keys | length' "$ORIGINS_FILE")
echo "📝 Found $ORIGIN_COUNT origins to insert"
echo ""

# Process each origin
INSERTED=0
UPDATED=0
SKIPPED=0

while IFS= read -r hostname; do
    if [ -z "$hostname" ] || [ "$hostname" = "null" ]; then
        continue
    fi
    
    # Extract the origin configuration for this hostname
    origin_config=$(jq -c --arg host "$hostname" '.[$host]' "$ORIGINS_FILE")
    
    if [ "$origin_config" = "null" ] || [ -z "$origin_config" ]; then
        echo "⚠️  Skipping invalid hostname: $hostname"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    
    # Escape single quotes in JSON for SQL (backslashes are fine with $$ delimiters)
    escaped_config=$(echo "$origin_config" | sed "s/'/''/g")
    
    # Generate UPSERT statement (INSERT ... ON CONFLICT DO UPDATE)
    # Note: We need to check if key exists, so we'll use a subquery approach
    # Since config_storage doesn't have a UNIQUE constraint on key, we'll use
    # a DELETE + INSERT approach, or check if we should use UPDATE first
    # Use convert_to() for proper bytea conversion (same as populate_from_docker.sh)
    
    # Use $$ delimiters for DO block (standard PostgreSQL dollar-quoting)
    cat >> "$TEMP_SQL" <<EOF
-- Insert/Update origin: $hostname
DO \$\$
BEGIN
    IF EXISTS (SELECT 1 FROM config_storage WHERE key = '$hostname') THEN
        UPDATE config_storage 
        SET value = convert_to('$escaped_config', 'UTF8'),
            updated_at = CURRENT_TIMESTAMP
        WHERE key = '$hostname';
    ELSE
        INSERT INTO config_storage (key, value)
        VALUES ('$hostname', convert_to('$escaped_config', 'UTF8'));
    END IF;
END \$\$;

EOF
    
    INSERTED=$((INSERTED + 1))
    if [ $((INSERTED % 10)) -eq 0 ]; then
        echo "   Processed $INSERTED origins..."
    fi
done < <(jq -r 'keys[]' "$ORIGINS_FILE")

# Commit transaction
echo "COMMIT;" >> "$TEMP_SQL"

# Execute SQL
echo "💾 Executing SQL statements..."
SQL_OUTPUT=$(psql "$DB_CONN" -f "$TEMP_SQL" 2>&1)
SQL_EXIT_CODE=$?

if [ $SQL_EXIT_CODE -eq 0 ]; then
    echo ""
    echo "✅ Successfully populated database!"
    echo "   Inserted/Updated: $INSERTED origins"
    if [ $SKIPPED -gt 0 ]; then
        echo "   Skipped: $SKIPPED origins"
    fi
    echo ""
    echo "📊 Verification:"
    psql "$DB_CONN" -c "SELECT COUNT(*) as total_origins FROM config_storage;"
    echo ""
    echo "Sample hostnames in database:"
    psql "$DB_CONN" -c "SELECT key FROM config_storage ORDER BY key LIMIT 10;"
else
    echo ""
    echo "❌ Error executing SQL statements"
    echo ""
    echo "Error output:"
    echo "$SQL_OUTPUT" | tail -20
    echo ""
    echo "SQL file location: $TEMP_SQL"
    echo "You can inspect the SQL file to see the generated statements"
    exit 1
fi



