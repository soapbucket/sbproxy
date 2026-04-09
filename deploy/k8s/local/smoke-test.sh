#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${NAMESPACE:-soapbucket}"

echo "=== SoapBucket Local Cluster Smoke Test ==="

echo "[1/5] Verifying shared fleet health"
curl -fsS -H "Host: test.local" http://localhost:8080/health >/dev/null

echo "[2/5] Installing operator"
"$SCRIPT_DIR/install-operator.sh"

echo "[3/5] Applying sample WorkspaceProxy"
kubectl apply -f "$SCRIPT_DIR/workspaceproxy-ws-alpha.yaml"

echo "[4/5] Waiting for dedicated workspace resources"
kubectl wait --for=condition=ready pod -l workspace=ws-alpha -n "$NAMESPACE" --timeout=180s

echo "[5/5] Verifying dedicated workspace route"
curl -fsS -H "Host: ws-alpha.local" http://localhost:8080/health >/dev/null

echo "Smoke test passed"
