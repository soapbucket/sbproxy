# Local Kubernetes Flow

This directory contains the chart-driven local Kubernetes workflow for SoapBucket clusters.

## Quick Start

```bash
cd proxy
./k8s/local/setup.sh
./k8s/local/smoke-test.sh
```

## What it installs

- Host infrastructure from `app.soapbucket.com/docker/docker-compose.k8s.yaml`
- A local `k3d` cluster and registry
- `ingress-nginx`
- The shared proxy fleet via `proxy/charts/soapbucket-proxy`
- The workspace operator via `operator/charts/workspace-operator`

## Operator-driven dedicated workspace test

```bash
./k8s/local/install-operator.sh
kubectl apply -f ./k8s/local/workspaceproxy-ws-alpha.yaml
curl -H "Host: ws-alpha.local" http://localhost:8080/health
```

## Notes

- The local flow standardizes on `SB_WORKSPACE_MODE` and `SB_WORKSPACE_ID`
- The shared fleet is now installed from Helm instead of raw manifests
- The legacy raw manifests are still present as references and debugging aids
