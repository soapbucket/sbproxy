#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$(cd "$SCRIPT_DIR/../../../app.soapbucket.com/docker" && pwd)/docker-compose.k8s.yaml"
CLUSTER_NAME="soapbucket-dev"
REGISTRY_NAME="k3d-soapbucket-registry.localhost"

echo "=== SoapBucket K8s Local Environment Teardown ==="

echo "[1/3] Deleting k3d cluster..."
k3d cluster delete "$CLUSTER_NAME" 2>/dev/null || echo "  Cluster does not exist"

echo "[2/3] Deleting k3d registry..."
k3d registry delete "$REGISTRY_NAME" 2>/dev/null || echo "  Registry does not exist"

echo "[3/3] Stopping infrastructure and observability stack..."
docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || echo "  Compose stack not running"

echo ""
echo "=== Teardown Complete ==="
echo ""
echo "To keep infrastructure data, use 'down' without -v:"
echo "  docker compose -f $COMPOSE_FILE down"
