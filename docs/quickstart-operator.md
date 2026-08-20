# Kubernetes operator quickstart

*Last modified: 2026-08-19*

This is a Kubernetes follow-on, not the first SBproxy exercise. Complete [Getting started](getting-started.md) first so you have seen an origin and `sbproxy validate` work on one machine.

[`examples/k8s-gateway/`](../examples/k8s-gateway/) pairs primarily with
[kubernetes.md](kubernetes.md), but it is a runnable config with the same
data-plane shape the operator manages here (trusted proxies, service
discovery, host override), so it is worth a look while working through this
quickstart too.

Before you begin, make sure you have:

- A reachable Kubernetes cluster.
- `kubectl` pointed at the intended context.
- Helm 3.
- Permission to create the namespace, namespaced RBAC resources, and the
  cluster-scoped `sbproxies.sbproxy.dev` and `sbproxyconfigs.sbproxy.dev`
  CRDs.
- Registry access from each node to pull
  `ghcr.io/soapbucket/sbproxy:1.13.0`.
- An operator image you have built and pushed yourself. There is not a
  published one; see "Build the operator image first" below.

The operator watches its own namespace by default. Install another operator
when you need a separate namespace boundary.

```bash
kubectl config current-context
kubectl get nodes
helm version
```

## Build the operator image first

The data plane image ships on every release. The operator image does not: the release workflow pushes `ghcr.io/soapbucket/sbproxy` and `docker.io/soapbucket/sbproxy`, nothing under `sbproxy-k8s-operator`, so the chart's default `image.repository` of `ghcr.io/soapbucket/sbproxy-k8s-operator` is a path that does not resolve. Install the chart unchanged and the operator pod sits in `ImagePullBackOff`.

That is the one piece of this quickstart you have to supply. Build the image from the checkout and push it where your nodes can reach it:

```bash
# A registry your cluster nodes can pull from.
export OPERATOR_REPO=registry.example.com/soapbucket/sbproxy-k8s-operator
export OPERATOR_TAG=1.13.0

docker build -t "$OPERATOR_REPO:$OPERATOR_TAG" \
  -f crates/sbproxy-k8s-operator/Dockerfile.ci .
docker push "$OPERATOR_REPO:$OPERATOR_TAG"
```

To try the operator without a registry at all, `make k8s-operator-smoke` builds the same image, loads it into a local kind cluster, and installs this chart against it. [kubernetes.md](kubernetes.md) covers that path.

## Install the operator

Run this from an SBproxy checkout. It installs the CRDs, operator Deployment, ServiceAccount, and namespaced RBAC, pointed at the image you just pushed:

```bash
helm upgrade --install sbproxy ./deploy/helm/sbproxy \
  --namespace sbproxy-system \
  --create-namespace \
  --set "image.repository=$OPERATOR_REPO" \
  --set "image.tag=$OPERATOR_TAG"

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
          body: "hello from sbproxy"
---
apiVersion: sbproxy.dev/v1alpha1
kind: SBProxy
metadata:
  name: demo
  namespace: sbproxy-system
spec:
  image: ghcr.io/soapbucket/sbproxy:1.13.0
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

Expect HTTP 200 and a body of `"hello from sbproxy"`, quotes included: the mock action always JSON-encodes `body`, so a plain string comes back as a quoted JSON string with a `Content-Type: application/json` header. Check the operator when the workload does not appear or the proxy rejects the configuration:

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
