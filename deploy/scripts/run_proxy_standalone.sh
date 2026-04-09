#!/bin/bash
# Run proxy in Standalone mode (single container, no external dependencies).
#
# Prerequisites:
#   - Docker image built: docker build -t soapbucket/proxy:local -f docker/Dockerfile .
#   - Run scripts/setup_proxy_certs.sh for HTTPS (optional)
#   - Add to /etc/hosts: 127.0.0.1 hn.local example.local api.local
#
# Usage: ./scripts/run_proxy_standalone.sh [--detach] [--verbose]
#
# --verbose  Enable GODEBUG=http2debug=1 for TLS/HTTP2 frame logging (very noisy)
#
# HTTP/3 (QUIC) note for macOS + Docker (Colima):
#   Docker on macOS routes traffic through a Linux VM. TCP ports are tunneled via
#   SSH and work fine with localhost. UDP (required for HTTP/3/QUIC) is NOT
#   forwarded through the SSH tunnel, so HTTP/3 via localhost will always fail.
#
#   To test HTTP/3 locally you have two options:
#
#   Option A - Colima with --network-address (VM gets a real routable IP):
#     colima start --network-address
#     VM_IP=$(colima list --json | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['address'])")
#     Use $VM_IP instead of localhost:  curl https://$VM_IP:8443/ --http3 -vks
#
#   Option B - Run the proxy natively (no Docker, no VM):
#     go run . serve

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DETACH=false
VERBOSE=false
for arg in "$@"; do
  case $arg in
    --detach|-d) DETACH=true ;;
    --verbose|-v) VERBOSE=true ;;
  esac
done

# Ensure certs exist (create placeholder if missing for HTTP-only)
if [ ! -d "$PROXY_ROOT/test/certs" ]; then
  mkdir -p "$PROXY_ROOT/test/certs"
fi

# Ensure sites config exists
if [ ! -f "$PROXY_ROOT/deploy/config/sites/sites.setup.json" ]; then
  echo "❌ config/sites/sites.setup.json not found. Run from project root."
  exit 1
fi

# Build image if needed
if ! docker images soapbucket/proxy:local --format '{{.Repository}}' 2>/dev/null | grep -q proxy; then
  echo "📦 Building proxy image..."
  docker build -t soapbucket/proxy:local -f "$PROXY_ROOT/deploy/docker/Dockerfile" "$PROXY_ROOT"
fi

echo "🚀 Starting proxy (Standalone mode)"
echo "   HTTP:  http://localhost:8080"
echo "   HTTPS: https://localhost:8443"
echo "   Health:  http://localhost:8888/healthz"
echo "   Metrics: http://localhost:8888/metrics"
echo "   Debug:  SB_LOG_LEVEL=debug (verbose TLS, config, request logging)"
echo ""

DOCKER_OPTS=(
  --rm
  -p 8080:8080
  -p 8443:8443/tcp   # HTTPS (HTTP/2, HTTP/1.1)
  -p 8443:8443/udp   # HTTP/3 (QUIC)
  -p 8888:8888
  -v "$PROXY_ROOT/config:/app/config:ro"
  -v "$PROXY_ROOT/data:/app/data:ro"
  -v "$PROXY_ROOT/test/certs:/app/certs:ro"
  -e SB_CONFIG_FILE=/app/config/server/sb.standalone.yml
  -e SB_CONFIG_DIR=/app/config
  -e SB_STORAGE_SETTINGS__PARAMS__PATH=/app/config/sites/sites.setup.json
  -e SB_LOG_LEVEL=debug
)

if [ "$VERBOSE" = true ]; then
  DOCKER_OPTS+=(-e "GODEBUG=http2debug=1")
  echo "   Verbose: GODEBUG=http2debug=1 (TLS/HTTP2 frame logging)"
fi

if [ "$DETACH" = true ]; then
  docker run -d --name proxy-standalone "${DOCKER_OPTS[@]}" soapbucket/proxy:local
  echo "✅ Proxy running in background (container: proxy-standalone)"
  echo "   Stop: docker stop proxy-standalone"
else
  docker run "${DOCKER_OPTS[@]}" soapbucket/proxy:local
fi
