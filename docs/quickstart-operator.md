# Kubernetes operator quickstart

*Last modified: 2026-07-28*

This is a Kubernetes follow-on, not the first SBproxy exercise. Complete [Getting started](getting-started.md) first so you have seen an origin and `sbproxy validate` work on one machine.

Before you begin, make sure you have:

- A reachable Kubernetes cluster.
- `kubectl` pointed at the intended context.
- Helm 3.
- Permission to create the namespace, namespaced RBAC resources, and the
  cluster-scoped `sbproxies.sbproxy.dev` and `sbproxyconfigs.sbproxy.dev`
  CRDs.
- Registry access from each node to pull
  `ghcr.io/soapbucket/sbproxy:1.9.0`.

The operator watches its own namespace by default. Install another operator
when you need a separate namespace boundary.

```bash
kubectl config current-context
kubectl get nodes
helm version
```

## Install the operator

Run this from an SBproxy checkout. It installs the CRDs, operator Deployment, ServiceAccount, and namespaced RBAC:

```bash
helm upgrade --install sbproxy ./deploy/helm/sbproxy \
  --namespace sbproxy-system \
  --create-namespace

kubectl rollout status deployment/sbproxy-k8s-operator -n sbproxy-system
```

If the deployment name differs in your chart version, use `kubectl get deployments -n sbproxy-system` and pass that name to `kubectl rollout status`.

## Create a small proxy

Save this manifest as `demo.yaml`. Validate the same `sb.yml` with `sbproxy validate` before embedding a production configuration. The `SBProxyConfig` contains the proxy configuration. The `SBProxy` selects that config, image, listener port, and replica count.

```yaml
apiVersion: sbproxy.dev/v1alpha1
kind: SBProxyConfig
metadata:
  name: demo-config
  namespace: sbproxy-system
spec:
  config: |
    origins:
      "demo.example.com":
        action:
          type: mock
          status: 200
          body: "hello from sbproxy\\n"
---
apiVersion: sbproxy.dev/v1alpha1
kind: SBProxy
metadata:
  name: demo
  namespace: sbproxy-system
spec:
  image: ghcr.io/soapbucket/sbproxy:1.9.0
  configRef: demo-config
  replicas: 1
  port: 8080
```

The `origins` map keys the client-facing hostname. The mock action makes this smoke check independent of an external backend. Replace the image tag with the release you have approved before using this shape outside a test cluster.

```bash
kubectl apply -n sbproxy-system -f demo.yaml
kubectl rollout status -n sbproxy-system deployment/demo-proxy
kubectl get -n sbproxy-system sbproxy,sbproxyconfig,pods,svc
```

Kubernetes stores the embedded document in a ConfigMap and the proxy compiles it when the operator creates the workload.

## Verify client traffic

In one terminal, forward the generated Service:

```bash
kubectl port-forward -n sbproxy-system svc/demo-svc 8080:8080
```

In another terminal, call the data plane:

```bash
curl -i -H 'Host: demo.example.com' http://127.0.0.1:8080/
```

Expect HTTP 200 and `hello from sbproxy`. Check the operator when the workload does not appear or the proxy rejects the configuration:

```bash
kubectl logs -n sbproxy-system deployment/sbproxy-k8s-operator
kubectl describe -n sbproxy-system sbproxy demo
kubectl logs -n sbproxy-system deployment/demo-proxy
```

## What changes do

Updating the `SBProxyConfig` applies the new `sb.yml`. Without `adminAuthSecretRef`, the operator updates a config hash and Kubernetes performs a rolling restart. With an enabled admin server and matching admin-auth Secret, the operator can request `POST /admin/reload` and preserve running pods. [kubernetes.md](kubernetes.md) documents the auth Secret, clustering, CRD fields, and fallback behavior.

## Remove the smoke test

```bash
kubectl delete -n sbproxy-system -f demo.yaml
helm uninstall sbproxy -n sbproxy-system
```

Delete the namespace only when nothing else uses it:

```bash
kubectl delete namespace sbproxy-system
```
