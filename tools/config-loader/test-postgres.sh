#!/bin/bash

# Test config-loader with PostgreSQL

set -e

echo "========================================="
echo "Config Loader - PostgreSQL Test"
echo "========================================="
echo ""

# Start PostgreSQL in Docker
echo "1. Starting PostgreSQL..."
docker run -d --name config-test-pg \
  -e POSTGRES_PASSWORD=secret \
  -p 5433:5432 \
  postgres:16-alpine

# Wait for PostgreSQL to be ready
echo "2. Waiting for PostgreSQL to be ready..."
sleep 3

DSN="postgres://postgres:secret@localhost:5433/postgres?sslmode=disable"

echo "3. Loading configurations..."
./config-loader -dsn "$DSN" -load configs.example.txt
echo ""

echo "4. Querying database..."
docker exec config-test-pg psql -U postgres -c "SELECT id, key FROM config_storage"
echo ""

echo "5. Testing delete..."
./config-loader -dsn "$DSN" -delete localhost:8443
echo ""

echo "6. Final state..."
docker exec config-test-pg psql -U postgres -c "SELECT key FROM config_storage"
echo ""

# Cleanup
echo "7. Cleaning up..."
docker stop config-test-pg
docker rm config-test-pg

echo ""
echo "========================================="
echo "PostgreSQL Test Complete!"
echo "========================================="

