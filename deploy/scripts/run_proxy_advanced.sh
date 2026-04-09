#!/bin/bash
# Run proxy in Advanced mode (full stack: Redis, Postgres, ClickHouse, Elasticsearch, Kibana, Grafana, Prometheus).
#
# Prerequisites:
#   - Run scripts/setup_proxy_certs.sh for HTTPS
#   - Add to /etc/hosts: 127.0.0.1 example.local api.local
#
# Usage: ./scripts/run_proxy_advanced.sh [--detach|--build]
#
# Access:
#   Proxy:     http://localhost:8080
#   Grafana:   http://localhost:3000 (admin/admin)
#   Kibana:    http://localhost:5601
#   Prometheus: http://localhost:9090

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$PROXY_ROOT/deploy/docker/docker-compose.yml"

DETACH="-d"
BUILD=false
for arg in "$@"; do
  case $arg in
    --foreground|-f) DETACH="" ;;
    --build|-b) BUILD=true ;;
  esac
done

# Ensure certs exist
if [ ! -f "$PROXY_ROOT/test/certs/example.local.crt" ] || [ ! -f "$PROXY_ROOT/test/certs/example.local.key" ]; then
  echo "🔒 Generating TLS certificates..."
  "$SCRIPT_DIR/setup_proxy_certs.sh"
fi

# Use sites.setup.json for PROXY_SETUP scenarios
export STORAGE_FILE_PATH="${STORAGE_FILE_PATH:-/app/config/sites.setup.json}"

# Build image if requested
if [ "$BUILD" = true ]; then
  echo "📦 Building proxy image..."
  docker build -t soapbucket/proxy:local -f "$PROXY_ROOT/deploy/docker/Dockerfile" "$PROXY_ROOT"
fi

echo "🚀 Starting proxy (Advanced mode: full observability stack)"
echo "   Proxy:     http://localhost:8080"
echo "   HTTPS:     https://localhost:8443"
echo "   Metrics:   http://localhost:8888/health"
echo "   Grafana:   http://localhost:3000 (admin/admin)"
echo "   Kibana:    http://localhost:5601"
echo "   Prometheus: http://localhost:9090"
echo ""

cd "$PROXY_ROOT"
docker compose -f "$COMPOSE_FILE" up $DETACH

echo ""
echo "✅ Full stack running"
echo "   Stop: docker compose -f docker/docker-compose.yml down"
