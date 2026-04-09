#!/bin/bash
# ClickHouse entrypoint wrapper
# This script initializes the ClickHouse database on first run

set -e

# Start ClickHouse server in the background
/entrypoint.sh &
CLICKHOUSE_PID=$!

# Wait for ClickHouse to be ready
echo "Waiting for ClickHouse to be ready..."
MAX_RETRIES=30
RETRY_COUNT=0

until clickhouse-client --query "SELECT 1" > /dev/null 2>&1; do
  RETRY_COUNT=$((RETRY_COUNT + 1))
  if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
    echo "ClickHouse failed to start after $MAX_RETRIES attempts"
    exit 1
  fi
  echo "ClickHouse is not ready yet. Waiting... (attempt $RETRY_COUNT/$MAX_RETRIES)"
  sleep 2
done

echo "ClickHouse is ready!"

# Check if database already exists
DB_EXISTS=$(clickhouse-client --query "EXISTS DATABASE proxy_logs" 2>/dev/null || echo "0")

if [ "$DB_EXISTS" = "0" ]; then
  echo "Initializing ClickHouse database..."
  
  # Run initialization script
  if [ -f /docker-entrypoint-initdb.d/init.sql ]; then
    echo "Running initialization script..."
    clickhouse-client --queries-file /docker-entrypoint-initdb.d/init.sql
    echo "ClickHouse database initialized successfully!"
  else
    echo "Warning: No initialization script found at /docker-entrypoint-initdb.d/init.sql"
  fi
else
  echo "ClickHouse database already exists. Skipping initialization."
fi

# Wait for the ClickHouse server process
wait $CLICKHOUSE_PID
