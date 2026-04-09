#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$(cd "$SCRIPT_DIR/../../../app.soapbucket.com/docker" && pwd)/docker-compose.k8s.yaml"
REGISTRY_NAME="soapbucket-registry.localhost"
REGISTRY_PORT="5111"
CLUSTER_NAME="soapbucket-dev"
NAMESPACE="soapbucket"
IMAGE_TAG="dev"
PROXY_CHART_DIR="$PROXY_DIR/charts/soapbucket-proxy"

echo "=== SoapBucket K8s Local Environment Setup ==="
echo ""
echo "Architecture:"
echo "  Docker Compose  ->  Redis, Postgres, ClickHouse, Vault, Prometheus, Loki, Grafana"
echo "  k3d / K8s       ->  Proxy shared fleet + dedicated workspace pods"
echo "  k3d pods reach host services via host.k3d.internal"
echo "  Prometheus scrapes k8s pods via kubeconfig service discovery"
echo ""
echo "Compose file: $COMPOSE_FILE"
echo ""

# 1. Infrastructure via Docker Compose (start data stores first, observability after cluster)
echo "[1/8] Starting data stores (Redis, Postgres, ClickHouse, Vault)..."
docker compose -f "$COMPOSE_FILE" up -d redis postgres clickhouse vault --wait
echo "  Redis:      localhost:6379"
echo "  Postgres:   localhost:5432"
echo "  ClickHouse: localhost:8123 (HTTP) / localhost:9000 (native)"
echo "  Vault:      http://localhost:8200  (token: dev-root-token)"

# 2. Registry
echo "[2/8] Creating k3d registry..."
k3d registry create "$REGISTRY_NAME" --port "$REGISTRY_PORT" 2>/dev/null || echo "  Registry already exists"

# 3. Cluster
echo "[3/8] Creating k3d cluster..."
k3d cluster create "$CLUSTER_NAME" \
  --port "8080:80@loadbalancer" \
  --port "8443:443@loadbalancer" \
  --registry-use "k3d-${REGISTRY_NAME}:${REGISTRY_PORT}" \
  --agents 2 \
  --k3s-arg "--disable=traefik@server:0" 2>/dev/null || echo "  Cluster already exists"

echo "  Waiting for cluster to be ready..."
kubectl wait --for=condition=ready node --all --timeout=60s

# 4. Build proxy image
echo "[4/8] Building and pushing proxy image..."
docker build -t "localhost:${REGISTRY_PORT}/soapbucket/proxy:${IMAGE_TAG}" \
  -f "$PROXY_DIR/docker/Dockerfile" "$PROXY_DIR"
docker push "localhost:${REGISTRY_PORT}/soapbucket/proxy:${IMAGE_TAG}"

# 5. Namespace
echo "[5/8] Creating namespace..."
kubectl create namespace "$NAMESPACE" 2>/dev/null || echo "  Namespace already exists"

# 6. NGINX Ingress
echo "[6/8] Installing NGINX Ingress controller..."
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx 2>/dev/null || true
helm repo update >/dev/null 2>&1
helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace \
  --set controller.publishService.enabled=true \
  --wait --timeout 120s

# 7. Shared fleet
echo "[7/8] Deploying shared proxy fleet via Helm..."
helm upgrade --install soapbucket-proxy "$PROXY_CHART_DIR" \
  --namespace "$NAMESPACE" \
  -f "$PROXY_CHART_DIR/values-local-k3d.yaml" \
  --set image.repository="localhost:${REGISTRY_PORT}/soapbucket/proxy" \
  --set image.tag="${IMAGE_TAG}" \
  --wait --timeout 180s

echo "  Waiting for proxy pods..."
kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=soapbucket-proxy -n "$NAMESPACE" --timeout=120s

# 8. Start observability stack (after cluster is up so kubeconfig works)
echo "[8/8] Starting Prometheus, Loki, Promtail, and Grafana..."
docker compose -f "$COMPOSE_FILE" up -d prometheus loki promtail grafana --wait
echo "  Prometheus: http://localhost:9090  (metrics)"
echo "  Loki:       http://localhost:3100  (logs)"
echo "  Grafana:    http://localhost:3000  (dashboards, admin / admin)"

# Verify
echo ""
echo "  Pods:"
kubectl get pods -n "$NAMESPACE" -o wide
echo ""
echo "  Services:"
kubectl get svc -n "$NAMESPACE"
echo ""

echo "=== Setup Complete ==="
echo ""
echo "Infrastructure (Docker Compose):"
echo "  docker compose -f $COMPOSE_FILE ps"
echo ""
echo "Observability:"
echo "  Prometheus: http://localhost:9090/targets  (metrics)"
echo "  Loki:       http://localhost:3100/ready    (logs)"
echo "  Grafana:    http://localhost:3000           (dashboards, admin / admin)"
echo ""
echo "Test the shared fleet:"
echo "  curl -H 'Host: test.local' http://localhost:8080/health"
echo ""
echo "Deploy a dedicated workspace:"
echo "  $SCRIPT_DIR/install-operator.sh"
echo "  kubectl apply -f $SCRIPT_DIR/workspaceproxy-ws-alpha.yaml"
echo ""
echo "Run the local smoke test:"
echo "  $SCRIPT_DIR/smoke-test.sh"
echo ""
echo "Legacy dedicated fixture:"
echo "  kubectl apply -f $SCRIPT_DIR/dedicated-ws-alpha.yaml"
echo ""
echo "Rebuild after code changes:"
echo "  $SCRIPT_DIR/rebuild.sh"
echo ""
echo "Tear down everything:"
echo "  $SCRIPT_DIR/teardown.sh"
