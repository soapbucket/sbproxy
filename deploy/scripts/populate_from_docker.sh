#!/bin/bash

# Convenience script to populate PostgreSQL database from Docker test environment
# This script connects to the postgres container and populates it with test fixtures
#
# Usage:
#   ./populate_from_docker.sh [origins.json path]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ORIGINS_FILE="${1:-${PROXY_ROOT}/test/fixtures/origins/origins.json}"

# Check if docker-compose is running
# Try to find docker-compose.yml in docker directory
COMPOSE_FILE="${PROXY_ROOT}/docker/docker-compose.yml"

if ! docker ps | grep -q "test-postgres"; then
    echo "❌ Error: PostgreSQL container 'test-postgres' is not running"
    echo "Start the test environment first:"
    echo "  cd test && docker-compose up -d"
    exit 1
fi

echo "🐳 Populating PostgreSQL database in Docker container..."
echo ""

# Use docker exec to run the populate script inside the container
# First, we need to copy the origins.json file into the container or use a volume
# For simplicity, we'll use docker exec with psql directly

# Check if origins.json exists
if [ ! -f "$ORIGINS_FILE" ]; then
    echo "❌ Error: Origins file not found: $ORIGINS_FILE"
    echo "Run scripts/combine-fixtures.sh first to create origins.json"
    exit 1
fi

# Copy origins.json and init_schema.sql to temporary locations in the container
echo "📋 Copying files to container..."
docker cp "$ORIGINS_FILE" test-postgres:/tmp/origins.json
docker cp "${PROXY_ROOT}/sql/init_schema.sql" test-postgres:/tmp/init_schema.sql

# Run the populate script inside the container
echo "💾 Populating database..."
docker exec -i test-postgres bash -c "
    set -e
    
    # Verify psql is available
    if ! command -v psql &> /dev/null 2>&1; then
        echo '❌ Error: psql command not found in container'
        exit 1
    fi
    
    # Check if jq is installed (might need to install it)
    if ! command -v jq &> /dev/null 2>&1; then
        echo 'Installing jq...'
        apk add --no-cache jq > /dev/null 2>&1 || (apt-get update && apt-get install -y jq) || (echo '❌ Error: Could not install jq' && exit 1)
    fi
    
    # Initialize schema
    echo '📋 Initializing database schema...'
    psql -U proxy -d proxy -f /tmp/init_schema.sql 2>&1 || echo '⚠️  Schema already exists or error (continuing...)'
    
    # Count total hostnames in JSON
    total_hostnames=\$(jq 'keys | length' /tmp/origins.json)
    echo \"📊 Found \$total_hostnames hostnames in origins.json\"
    echo ''
    
    # Track insertion results
    inserted=0
    updated=0
    errors=0
    
    # Generate and execute INSERT statements
    # Note: origins.json has format {\"hostname\": {config}}, we need to extract just the inner config
    jq -r 'keys[]' /tmp/origins.json | while read hostname; do
        if [ -n \"\$hostname\" ] && [ \"\$hostname\" != \"null\" ]; then
            # Extract just the inner config object (not the wrapper)
            origin_config=\$(jq -c --arg host \"\$hostname\" '.[\$host]' /tmp/origins.json)
            if [ \"\$origin_config\" != \"null\" ] && [ -n \"\$origin_config\" ]; then
                # Escape single quotes for SQL
                escaped_config=\$(echo \"\$origin_config\" | sed \"s/'/''/g\")
                
                # Check if config already exists
                exists=\$(psql -U proxy -d proxy -t -c \"SELECT COUNT(*) FROM config_storage WHERE key = '\$hostname';\" 2>&1 | tr -d ' ')
                
                # Convert to bytea via jsonb (ensures valid JSON)
                SQL_ERROR=\$(psql -U proxy -d proxy -c \"
                    DO \\\$\\\$
                    BEGIN
                        IF EXISTS (SELECT 1 FROM config_storage WHERE key = '\$hostname') THEN
                            UPDATE config_storage 
                            SET value = convert_to('\$escaped_config', 'UTF8'),
                                updated_at = CURRENT_TIMESTAMP
                            WHERE key = '\$hostname';
                        ELSE
                            INSERT INTO config_storage (key, value)
                            VALUES ('\$hostname', convert_to('\$escaped_config', 'UTF8'));
                        END IF;
                    END \\\$\\\$;
                \" 2>&1)
                if [ \$? -eq 0 ]; then
                    if [ \"\$exists\" = \"1\" ]; then
                        updated=\$((updated + 1))
                    else
                        inserted=\$((inserted + 1))
                    fi
                else
                    echo \"❌ Error inserting/updating config for: \$hostname\" >&2
                    echo \"   Error: \$SQL_ERROR\" >&2
                    errors=\$((errors + 1))
                fi
            else
                echo \"⚠️  Warning: Empty or null config for: \$hostname\" >&2
            fi
        fi
    done
    
    echo ''
    echo '✅ Database populated successfully!'
    echo ''
    echo '📊 Summary:'
    echo \"   Inserted: \$inserted\"
    echo \"   Updated:  \$updated\"
    echo \"   Errors:   \$errors\"
    echo ''
    psql -U proxy -d proxy -c 'SELECT COUNT(*) as total_origins FROM config_storage;'
    
    # Verify critical configs exist
    echo ''
    echo '🔍 Verifying critical configs...'
    critical_configs=('forward-rules-complex.test' 'api-v1-backend.test' 'old-service-backend.test')
    for config in \"\${critical_configs[@]}\"; do
        count=\$(psql -U proxy -d proxy -t -c \"SELECT COUNT(*) FROM config_storage WHERE key = '\$config';\" 2>&1 | tr -d ' ')
        if [ \"\$count\" = \"1\" ]; then
            echo \"   ✓ \$config\"
        else
            echo \"   ✗ \$config (NOT FOUND)\"
        fi
    done
"

# Clean up
docker exec test-postgres rm -f /tmp/origins.json /tmp/init_schema.sql

echo ""
echo "✅ Done!"

