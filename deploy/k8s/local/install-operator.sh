#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OPERATOR_DIR="$ROOT_DIR/operator"
CHART_DIR="$OPERATOR_DIR/charts/workspace-operator"
REGISTRY_PORT="${REGISTRY_PORT:-5111}"
NAMESPACE="${NAMESPACE:-soapbucket}"
IMAGE_TAG="${IMAGE_TAG:-dev}"

echo "=== Installing Workspace Operator ==="

docker build -t "localhost:${REGISTRY_PORT}/soapbucket/workspace-operator:${IMAGE_TAG}" \
  -f "$OPERATOR_DIR/Dockerfile" "$OPERATOR_DIR"
docker push "localhost:${REGISTRY_PORT}/soapbucket/workspace-operator:${IMAGE_TAG}"

kubectl create namespace "$NAMESPACE" 2>/dev/null || true

helm upgrade --install workspace-operator "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  --create-namespace \
  -f "$CHART_DIR/values-local-k3d.yaml" \
  --set image.repository="localhost:${REGISTRY_PORT}/soapbucket/workspace-operator" \
  --set image.tag="${IMAGE_TAG}" \
  --wait --timeout 180s

kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=workspace-operator -n "$NAMESPACE" --timeout=120s

echo "Workspace operator installed in namespace $NAMESPACE"
