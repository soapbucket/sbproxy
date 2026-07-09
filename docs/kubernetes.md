# Running sbproxy on Kubernetes

*Last modified: 2026-07-09*

The OSS Kubernetes operator at `crates/sbproxy-k8s-operator/` reconciles two CustomResources into a running proxy: an `SBProxy` describes the deployment shape, and an `SBProxyConfig` carries the `sb.yml` document the proxy reads on startup. The operator owns a Deployment, Service, and ConfigMap per `SBProxy`.

If this is your first production bring-up, start with
[`quickstart-operator.md`](quickstart-operator.md). This page is the longer
reference for CRDs, hot reload, leader election, and local smoke testing.

## Install the chart

The Helm chart lives at `deploy/helm/sbproxy/`. It installs the CRDs, the operator Deployment, the ServiceAccount, and the RBAC the operator needs. By default that RBAC is a namespaced Role and RoleBinding, so the operator can only touch its own namespace.

```bash
helm install sbproxy ./deploy/helm/sbproxy \
  --namespace sbproxy-system \
  --create-namespace
```

Key values:

| Value | Meaning |
| --- | --- |
| `image.repository`, `image.tag` | Operator image. Pin a tag when shipping. |
| `rbac.scope` | `namespace` (default) grants a namespaced Role and watches only the operator's own namespace. `cluster` grants a ClusterRole and watches every namespace. |
| `watchNamespace` | Cluster scope only: narrow the watch to one namespace while keeping the cluster-wide grant. Ignored under `rbac.scope: namespace`. |
| `logLevel` | Maps to `--log-level` and `RUST_LOG`. Try `kube=debug,sbproxy_k8s_operator=debug` while validating. |
| `installCrds` | Set to `false` if CRDs are managed out of band (e.g. argo or flux). |

### RBAC scope

The chart defaults to `rbac.scope: namespace`: a Role and RoleBinding in the operator's namespace, and the operator watches only that namespace. A compromised operator pod cannot read or write SBProxy configs anywhere else, which matters because an `SBProxyConfig` holds the full `sb.yml` and its upstream credentials. To manage several namespaces this way, install one operator per namespace.

Set `rbac.scope: cluster` only when you need a single operator across the whole cluster. That grants a ClusterRole and watches every namespace; set `watchNamespace` alongside it to narrow the watch without narrowing the grant.

## Define an `SBProxyConfig`

The `spec.config` field is the same `sb.yml` you would feed the proxy on disk. The operator does not deeply validate it; the proxy itself rejects malformed input on reload.

```yaml
apiVersion: sbproxy.dev/v1alpha1
kind: SBProxyConfig
metadata:
  name: demo-config
  namespace: default
spec:
  config: |
    origins:
      "demo.example.com":
        action:
          type: mock
          status: 200
          body: "hello from sbproxy\n"
```

`origins` is a map keyed by hostname, not a list. Check the embedded document with `sbproxy validate` before applying it; the operator does not deeply validate it.

## Define an `SBProxy`

```yaml
apiVersion: sbproxy.dev/v1alpha1
kind: SBProxy
metadata:
  name: demo
  namespace: default
spec:
  image: ghcr.io/soapbucket/sbproxy:1.5.0
  configRef: demo-config
  replicas: 2
  port: 8080
```

`configRef` must name an `SBProxyConfig` in the same namespace.

## Hot-reload (recommended)

When the proxy's admin server is enabled and `SBProxy.spec.adminAuthSecretRef` points at a Secret carrying the basic-auth header, the operator hot-reloads each running pod by issuing `POST /admin/reload` directly to the pod IPs. The Deployment is left alone, so pods are not restarted and in-flight connections are preserved. The proxy serialises the reload via an internal single-flight guard so simultaneous reloads (file watcher plus admin route) never race.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: demo-admin
  namespace: default
type: Opaque
stringData:
  # Full basic-auth header value. Keep this secret out of version control.
  authorization: "Basic YWRtaW46c2VjcmV0"
---
apiVersion: sbproxy.dev/v1alpha1
kind: SBProxy
metadata:
  name: demo
  namespace: default
spec:
  image: ghcr.io/soapbucket/sbproxy:1.5.0
  configRef: demo-config
  replicas: 2
  port: 8080
  adminPort: 9090
  adminAuthSecretRef:
    name: demo-admin
    key: authorization
```

The `sb.yml` mounted into pods must enable the admin server on `adminPort` for hot-reload to work, with the same credentials encoded in the Secret:

```yaml
proxy:
  admin:
    enabled: true
    port: 9090
    username: admin
    password: secret
```

If the admin endpoint returns anything other than `200` (admin port not bound, Secret missing, single-flight conflict, parse error), the operator falls back to the rollout-restart path so the cluster is never left in a half-reloaded state.

## Rollout-restart fallback

When `adminAuthSecretRef` is absent the operator behaves as before: updating the `SBProxyConfig` stamps a new `sbproxy.dev/config-hash` annotation on the Deployment's pod template, which triggers a rolling restart so pods pick up the new config. Use this mode if you do not want to expose an admin port inside the cluster.

## Reach the proxy

The operator names the Service `<sbproxy-name>-svc`. Port-forward for a quick check:

```bash
kubectl port-forward svc/demo-svc 8080:8080
curl http://127.0.0.1:8080/
```

In production, expose the Service via an Ingress, a LoadBalancer Service, or a Gateway API Gateway.

![a request with a spoofable X-Forwarded-For sent through the cluster-edge config, showing which forwarded headers reach the upstream](assets/k8s-gateway.gif)

The dataplane shape behind an Ingress: trusted_proxies, service_discovery, host_override, and a threaded X-Request-Id ([config](../examples/k8s-gateway/)).

## Leader election

The operator runs more than one replica safely. Each replica races for a `coordination.k8s.io/v1` Lease named `sbproxy-operator-leader` in its own namespace. The replica that wins the race runs the reconciler; the others wait. When the leader's pod is deleted, restarted, or partitioned from the API server, the renew loop fails, the leader exits with code 0, and a standby replica wins the next acquire pass within ~15s (the lease duration).

The chart enables leader election by default:

```yaml
# values.yaml
replicaCount: 2
leaderElection:
  enabled: true
```

Disable the lock for single-replica installs or for `cargo run` against a kind cluster:

```bash
helm install sbproxy ./deploy/helm/sbproxy --set leaderElection.enabled=false
```

That value flips to a `--no-leader-election` flag on the operator process.

The Lease's holder identity follows the convention `<pod-name>_<8 hex chars>`. Inspect it with:

```bash
kubectl get lease sbproxy-operator-leader -n sbproxy-system -o yaml
```

The chart grants the verbs the lock requires. The operator's Role (or ClusterRole under `rbac.scope: cluster`) includes:

```yaml
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
```

The Lease lives in the operator's own namespace, so the namespaced Role covers it.

The Lease namespace is discovered in this order: `K8S_NAMESPACE` env var (the chart wires this from the downward API), the service-account namespace file at `/var/run/secrets/kubernetes.io/serviceaccount/namespace`, then the literal string `default` as a last resort.

The lease timing matches client-go defaults: `leaseDurationSeconds=15`, renew every 5s, retry every 2s, abort the renew loop after a 10s API call timeout.

## Graceful shutdown

Both `sbproxy` and `sbproxy-k8s-operator` install handlers for
SIGTERM and SIGINT. The kubelet sends SIGTERM at the start of pod
termination and waits up to `terminationGracePeriodSeconds`
(default 30s) before sending SIGKILL. Each process drains in-flight
work up to its own grace budget and exits with code `0` on a clean
drain or `1` when the budget is exceeded.

| Component | Grace budget env var | Default | What it drains |
| --- | --- | --- | --- |
| `sbproxy` | `SBPROXY_SHUTDOWN_GRACE_MS` | `30000` (30s) | In-flight HTTP requests, WebSocket frames, AI streams |
| `sbproxy-k8s-operator` | `SBPROXY_SHUTDOWN_GRACE_MS` | `30000` (30s) | In-flight reconcile passes, leader lease step-down |

Set both pod specs' `terminationGracePeriodSeconds` to at least the
drain budget plus a small buffer. Without that headroom the kubelet
will SIGKILL the process mid-drain and any in-flight requests will
drop.

```yaml
spec:
  terminationGracePeriodSeconds: 60
  containers:
  - name: sbproxy
    env:
      - name: SBPROXY_SHUTDOWN_GRACE_MS
        value: "45000"
```

When a shutdown signal arrives, both binaries emit a structured
`shutdown_signal_received` tracing event including the signal name
and resolved grace budget. Grep for it during incident response to
confirm the drain started before the kubelet's hard kill window
expired.

## Local smoke test

`make k8s-operator-smoke` runs the full install / hot-reload / leader-election flow against a local kind cluster. This is intentionally local-only because it builds release binaries, creates Docker images, and boots a kind cluster; there is no CI workflow that runs it.

The target:

1. Builds the proxy and operator binaries with `cargo build --profile release-fast -p sbproxy -p sbproxy-k8s-operator --locked`.
2. Wraps each binary in a small image (`Dockerfile.ci` and `crates/sbproxy-k8s-operator/Dockerfile.ci`).
3. Creates a kind cluster (`kindest/node:v1.30.0`), loads both images with `kind load docker-image`, helm-installs the chart, and runs `deploy/helm/sbproxy/test/smoke.sh`.

The Make target wraps the manual sequence below:

```bash
# from the repo root
cargo build --profile release-fast -p sbproxy -p sbproxy-k8s-operator
docker build -t sbproxy:ci -f Dockerfile.ci .
docker build -t sbproxy-operator:ci -f crates/sbproxy-k8s-operator/Dockerfile.ci .
kind create cluster --name sbproxy-smoke --image kindest/node:v1.30.0
kind load docker-image sbproxy:ci sbproxy-operator:ci --name sbproxy-smoke
SKIP_KIND_CREATE=1 NO_CLEANUP=1 \
  PROXY_IMAGE=sbproxy:ci OPERATOR_IMAGE=sbproxy-operator:ci \
  bash deploy/helm/sbproxy/test/smoke.sh
```

Use the target directly for the common case:

```bash
make k8s-operator-smoke
```

The script verifies, in order:

1. `helm install` brings up the operator and the proxy Deployment becomes Available.
2. The proxy responds to a curl through its Service.
3. Updating the `SBProxyConfig` either hot-reloads the pod (when `adminAuthSecretRef` is set) without bumping its restart count, or rolls the Deployment via the config-hash annotation (the default).
4. Killing the leader operator pod hands the Lease off to the standby replica within 30s.

A failed run leaves the kind cluster in place (the manual sequence sets `NO_CLEANUP=1`), so you can inspect pods and operator logs before deleting the cluster with `kind delete cluster --name sbproxy-smoke`.
