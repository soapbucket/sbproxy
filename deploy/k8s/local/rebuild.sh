#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REGISTRY_PORT="5111"
NAMESPACE="soapbucket"
IMAGE_TAG="dev"

echo "=== Rebuilding proxy image and restarting pods ==="

echo "[1/3] Building proxy image..."
docker build -t "localhost:${REGISTRY_PORT}/soapbucket/proxy:${IMAGE_TAG}" \
  -f "$PROXY_DIR/docker/Dockerfile" "$PROXY_DIR"
docker push "localhost:${REGISTRY_PORT}/soapbucket/proxy:${IMAGE_TAG}"

echo "[2/3] Restarting shared fleet..."
kubectl rollout restart deployment/proxy-shared-fleet -n "$NAMESPACE"
kubectl rollout status deployment/proxy-shared-fleet -n "$NAMESPACE" --timeout=90s

echo "[3/3] Restarting dedicated workspace deployments..."
for deploy in $(kubectl get deployments -n "$NAMESPACE" -l tier=dedicated -o name 2>/dev/null); do
  echo "  Restarting $deploy..."
  kubectl rollout restart "$deploy" -n "$NAMESPACE"
  kubectl rollout status "$deploy" -n "$NAMESPACE" --timeout=90s
done

echo ""
echo "=== Rebuild Complete ==="
kubectl get pods -n "$NAMESPACE"
