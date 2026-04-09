#!/bin/bash
# Run proxy in General mode (Proxy + Redis).
#
# Prerequisites:
#   - Run scripts/setup_proxy_certs.sh for HTTPS
#   - Add to /etc/hosts: 127.0.0.1 example.local api.local
#
# Usage: ./scripts/run_proxy_general.sh [--detach|--build]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$PROXY_ROOT/deploy/docker/docker-compose.general.yml"

DETACH=""
BUILD=false
for arg in "$@"; do
  case $arg in
    --detach|-d) DETACH="-d" ;;
    --build|-b) BUILD=true ;;
  esac
done

# Ensure certs exist
if [ ! -f "$PROXY_ROOT/test/certs/example.local.crt" ] || [ ! -f "$PROXY_ROOT/test/certs/example.local.key" ]; then
  echo "🔒 Generating TLS certificates..."
  "$SCRIPT_DIR/setup_proxy_certs.sh"
fi

# Build image if requested
if [ "$BUILD" = true ]; then
  echo "📦 Building proxy image..."
  docker build -t soapbucket/proxy:local -f "$PROXY_ROOT/deploy/docker/Dockerfile" "$PROXY_ROOT"
fi

# Enable debug logging by default for troubleshooting
export SB_LOG_LEVEL="${SB_LOG_LEVEL:-debug}"

echo "🚀 Starting proxy (General mode: Proxy + Redis)"
echo "   HTTP:  http://localhost:8080"
echo "   HTTPS: https://localhost:8443"
echo "   Metrics: http://localhost:8888/health"
echo "   Redis: localhost:6379"
echo ""

cd "$PROXY_ROOT"
docker compose -f "$COMPOSE_FILE" up $DETACH

if [ -n "$DETACH" ]; then
  echo ""
  echo "✅ Proxy running in background"
  echo "   Stop: docker compose -f docker/docker-compose.general.yml down"
fi
