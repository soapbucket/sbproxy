# Running sbproxy on Kubernetes

*Last modified: 2026-08-15*

The Kubernetes operator at `crates/sbproxy-k8s-operator/` reconciles two CustomResources into a running proxy: an `SBProxy` describes the deployment shape, and an `SBProxyConfig` carries the `sb.yml` document the proxy reads on startup. The operator owns a Deployment, Service, and ConfigMap per `SBProxy`. With `spec.clustering.enabled: true` the Deployment is replaced by a StatefulSet plus a headless Service and a shared-key Secret, and the replicas form a gossip mesh; see "Clustered proxies" below. Everything else on this page applies to both shapes.

If this is your first production bring-up, start with
[`quickstart-operator.md`](quickstart-operator.md). This page is the longer
reference for CRDs, hot reload, leader election, and local smoke testing.

## Install the chart

The Helm chart lives at `deploy/helm/sbproxy/`. It installs the CRDs, the operator Deployment, the ServiceAccount, and the RBAC the operator needs. By default that RBAC is a namespaced Role and RoleBinding, so the operator can only touch its own namespace.

Read "The operator image is not published" below before the first install. The chart's default `image.repository` is not a path you can pull from today, so the command that follows leaves the operator pod in `ImagePullBackOff` until you point it at an image you built.

```bash
helm install sbproxy ./deploy/helm/sbproxy \
  --namespace sbproxy-system \
  --create-namespace
```

Key values:

| Value | Meaning |
| --- | --- |
| `image.repository`, `image.tag` | Operator image. `image.tag` defaults to the chart's `appVersion`. See "The operator image is not published" below. |
| `rbac.scope` | `namespace` (default) grants a namespaced Role and watches only the operator's own namespace. `cluster` grants a ClusterRole and watches every namespace. |
| `watchNamespace` | Cluster scope only: narrow the watch to one namespace while keeping the cluster-wide grant. Ignored under `rbac.scope: namespace`. |
| `logLevel` | Maps to `--log-level` and `RUST_LOG`. Try `kube=debug,sbproxy_k8s_operator=debug` while validating. |
| `installCrds` | Set to `false` if CRDs are managed out of band (e.g. argo or flux). |

### The operator image is not published

No release publishes an operator image. The release workflow builds and pushes the data plane, `ghcr.io/soapbucket/sbproxy` and `docker.io/soapbucket/sbproxy`, and nothing else. The chart's default `image.repository` of `ghcr.io/soapbucket/sbproxy-k8s-operator` names where an operator image would live if one shipped; pulling it today fails.

So the install above cannot be completed against a stock chart. Building the image yourself is the path that works, and it is the same path the smoke test takes.

`make k8s-operator-smoke` does the whole thing locally against kind: it builds the operator image (compiling inside Docker so the binary is Linux-native), loads that image into a kind cluster, and installs this chart pointed at it. See [Local smoke test](#local-smoke-test) for what it asserts.

For a cluster of your own, build the image, push it somewhere your nodes can reach, and point the chart at it:

```bash
# A registry your cluster nodes can pull from, and a tag you choose.
export OPERATOR_REPO=registry.example.com/soapbucket/sbproxy-k8s-operator
export OPERATOR_TAG=1.10.0

docker build -t "$OPERATOR_REPO:$OPERATOR_TAG" \
  -f crates/sbproxy-k8s-operator/Dockerfile.ci .
docker push "$OPERATOR_REPO:$OPERATOR_TAG"

helm install sbproxy ./deploy/helm/sbproxy \
  --namespace sbproxy-system --create-namespace \
  --set "image.repository=$OPERATOR_REPO" \
  --set "image.tag=$OPERATOR_TAG"
```

Only the operator's own image is missing. The data plane image that the `SBProxy` resources below reference is published on every release and pulls normally.

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
  image: soapbucket/sbproxy:1.10.0
  configRef: demo-config
  replicas: 2
  port: 8080
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 256Mi
```

`configRef` must name an `SBProxyConfig` in the same namespace.

### Always set `resources`

`spec.resources` is optional and has no default. Leave it out and the operator reconciles a container with empty requests and empty limits, which Kubernetes classifies as BestEffort: the pod is first in line for eviction under node pressure, and nothing caps how far it can grow before the node does. Neither is a property you want on a data plane.

The figures above are a starting point rather than a recommendation. The only resident-set measurement in this project is an idle process on a minimal config, so the headroom in that block is reasoned, not observed, and two features invalidate it outright (a filled response cache, and a local ONNX classifier that can reach 200 MiB by itself). [capacity-planning.md](capacity-planning.md) shows the arithmetic behind each number and the commands that replace them with a reading from your own traffic.

## Hot-reload (recommended)

When the proxy's admin server is enabled and `SBProxy.spec.adminAuthSecretRef` points at a Secret carrying the basic-auth header, the operator hot-reloads each running pod by issuing `POST /admin/reload` directly to the pod IPs. The Deployment is left alone, so pods are not restarted and in-flight connections are preserved. The proxy serializes the reload via an internal single-flight guard so simultaneous reloads (file watcher plus admin route) never race.

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
  image: soapbucket/sbproxy:1.10.0
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

## Clustered proxies

A single `SBProxy` with `replicas: 2` or more runs independent pods by default: each one has its own in-memory state, so features that share state across replicas (the dynamic key mesh cache, cluster-wide admin views) do not see each other. Setting `spec.clustering.enabled: true` makes the operator wire the replicas into a gossip mesh with no hand-written peer configuration.

```yaml
apiVersion: sbproxy.dev/v1alpha1
kind: SBProxyConfig
metadata:
  name: demo-config
  namespace: default
spec:
  config: |
    proxy:
      admin:
        enabled: true
        port: 9090
        username: admin
        password: secret
    origins:
      "demo.example.com":
        action:
          type: mock
          status: 200
          body: "hello from sbproxy\n"
---
apiVersion: sbproxy.dev/v1alpha1
kind: SBProxy
metadata:
  name: demo
  namespace: default
spec:
  image: soapbucket/sbproxy:1.10.0
  configRef: demo-config
  replicas: 3
  port: 8080
  clustering:
    enabled: true
```

The optional clustering knobs, all defaulted: `gossipPort` (7946, UDP), `transportPort` (8946, TCP), `clusterSecretRef` (bring your own key Secret), and `clusterDomain` (`cluster.local`, only relevant on clusters with a custom DNS domain).

### What the operator creates

For the manifest above the operator reconciles, instead of a Deployment:

| Object | Name | Purpose |
| --- | --- | --- |
| StatefulSet | `demo-proxy` | Stable pod names (`demo-proxy-0` ... `demo-proxy-2`) that survive rescheduling |
| Headless Service | `demo-mesh` | Stable per-pod DNS records for gossip and mesh transport |
| Secret | `demo-cluster-key` | Shared cluster key, generated once and reused |
| ConfigMap | `demo-config` | Your `sb.yml` with an operator-rendered `proxy.cluster` block injected |
| Service | `demo-svc` | Client traffic, unchanged from the non-clustered path |

A StatefulSet rather than a Deployment because mesh peers need identities that survive rescheduling. A Deployment pod gets a random name and a fresh IP every time it is replaced, so any seed list written against it rots. A StatefulSet pod keeps its ordinal name and, through the headless Service, a stable DNS record like `demo-proxy-0.demo-mesh.default.svc.cluster.local`. The rendered configuration seeds every pod with the full list of those DNS names, one per ordinal; each proxy filters its own address out at bootstrap and joins whichever peers are up. A replica count above 128 is rejected because the cluster configuration caps the seed list there.

The injected block sets, per pod: `cluster_id` (the SBProxy name), `node_id` and `advertise_addr` from the pod's own name via the downward API, the seed list, both ports, a writable `state_dir` on an emptyDir volume, and shared-key security. One ConfigMap serves every pod; the per-pod values resolve from the `SBPROXY_POD_NAME` environment variable at startup. While clustering is enabled, any `proxy.cluster` block you write in the `SBProxyConfig` yourself is replaced by the rendered one, so the mesh topology always matches the StatefulSet. The rendered block does not enable the replicated state substrate described in [mesh-replication.md](mesh-replication.md); that remains a hand-managed configuration.

### The shared-key Secret

The mesh supports two peer-security modes. Mutual TLS needs per-node certificates from a CA, and the enrollment authority flow (`sbproxy cluster init` plus one-time tokens redeemed at `/admin/cluster/enroll`) is built for hand-managed fleets where a human enrolls each node once. Neither survives a pod being rescheduled by Kubernetes, because the replacement pod would need a fresh certificate or a fresh token that nothing is standing by to mint. Operator-managed clusters therefore use shared-key mode: the key lives in a Kubernetes Secret, every pod (including any future replacement) reads it through a `secretKeyRef`, and gossip plus transport traffic is encrypted with it. The config schema marks this mode with an explicit `development: true` acknowledgment; within a single trusted cluster network it is the mode an operator can actually manage. Anyone with read access to Secrets in the namespace can read the key, so scope namespace RBAC accordingly.

The operator generates `<name>-cluster-key` once, with 32 random bytes under the `cluster-key` entry, and never overwrites it. To supply your own key instead, create a Secret with a `cluster-key` entry and point `clustering.clusterSecretRef` at it. To rotate a generated key, delete the Secret and restart the StatefulSet (`kubectl rollout restart statefulset/demo-proxy`); the next reconcile generates a fresh key and the restart picks it up. Flipping clustering off retains the Secret so a later re-enable rejoins with the same key.

### Verify the mesh formed

With the admin server enabled in your config (as in the example above), ask any pod for the cluster status:

```bash
kubectl port-forward pod/demo-proxy-0 9090:9090
curl -u admin:secret http://127.0.0.1:9090/admin/cluster/status
```

The response lists every node with its health; `summary.total_nodes` should equal your replica count. Without the admin server, check the `mesh_peer_count` metric on each pod's `/metrics` endpoint: on a formed three-node mesh every pod reports two alive peers.

### Rolling updates

The StatefulSet uses `podManagementPolicy: OrderedReady` and the `RollingUpdate` strategy, so a config change or image bump replaces pods one at a time, highest ordinal first. A readiness probe on the data plane's unrouted-Host `/health` fallback gates each step: the kubelet's pod-IP Host is not one of the configured application origins, and the roll does not proceed until the replacement listener answers. At no point are two mesh members down at once, so the surviving majority keeps the mesh formed and the restarted pod rejoins under its same identity through the seed list. The mesh wire format is not versioned across releases, so run the same sbproxy release on all replicas and roll upgrades one StatefulSet at a time as usual (see [upgrade.md](upgrade.md)).

Config-only changes still prefer hot-reload when `adminAuthSecretRef` is set. Changes to the cluster topology itself (replica count, ports) always take the rollout path, because the proxy treats cluster identity and listeners as process-owned and refuses to swap them on a live reload.

Flipping `clustering.enabled` in either direction is a workload replacement, not a rolling change: the operator deletes the old workload kind before applying the new one, so the fleet restarts briefly. Plan the flip like a restart.

## Reach the proxy

The operator names the Service `<sbproxy-name>-svc`. Port-forward for a quick check:

```bash
kubectl port-forward svc/demo-svc 8080:8080
curl http://127.0.0.1:8080/
```

In production, expose the Service via an Ingress, a LoadBalancer Service, or a Gateway API Gateway.

![a request with a spoofable X-Forwarded-For sent through the cluster-edge config, showing which forwarded headers reach the upstream](assets/k8s-gateway.gif)

The dataplane shape behind an Ingress: trusted_proxies, service_discovery, host_override, and a threaded X-Request-Id ([config](../examples/k8s-gateway/)).

## TLS certificates

On Kubernetes, issue certificates with [cert-manager](https://cert-manager.io/) and terminate TLS at the Ingress. Leave the proxy's own ACME client off.

That is a recommendation about the platform, not a verdict on the feature. Dataplane ACME works, and [When dataplane ACME is the right answer](#when-dataplane-acme-is-the-right-answer) below says where it is the better choice. On Kubernetes it is the wrong tool for three reasons.

**Challenge routing.** HTTP-01 means the CA fetches `http://<hostname>/.well-known/acme-challenge/<token>` on port 80, and whatever fronts the Service picks a replica for that request. cert-manager operates at the Ingress, which is where the routing decision already gets made: for each order it creates a temporary solver pod, a Service, and an Ingress rule scoped to the challenge path, then deletes all three when the order completes. The proxy never sees the challenge. Solving it from the dataplane instead means every replica sharing one certificate store so whichever pod receives the fetch can answer it, plus an Ingress that does not redirect port 80 to HTTPS for that one path. Both are doable, and neither is something you should have to set up.

**DNS-01, and therefore wildcards.** Our ACME client drives `http-01` and nothing else. Let's Encrypt does not issue wildcard certificates over HTTP-01; DNS-01 is the only challenge type it accepts for a name like `*.example.com`. So a wildcard is not something the proxy can obtain at any replica count or any storage backend. cert-manager ships DNS-01 solvers for Route53, Cloud DNS, Azure DNS, Cloudflare, and others, plus a webhook interface for providers with no built-in solver.

**It is what the cluster already runs.** cert-manager is the standard certificate layer on Kubernetes. Its `Certificate` objects, renewal timers, and failure events are what the people operating the cluster already know how to read, and if the cluster has TLS anywhere else, its issuers are already wired to your CA. A second issuance path living inside the dataplane is one more thing to learn, monitor, and keep under the same rate limit. Competing with that is not a good use of the dataplane.

### A worked example

Three objects: an issuer, a certificate, and an Ingress that uses the Secret. Install cert-manager first (its own [installation docs](https://cert-manager.io/docs/installation/) cover that).

A `ClusterIssuer` is cluster-scoped, so every namespace can reference it. Use a namespaced `Issuer` with the same `spec` if you would rather confine the ACME account to one namespace.

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: ops@example.com
    # cert-manager creates this Secret itself and stores the ACME account
    # key in it. Do not create it by hand.
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
      - http01:
          ingress:
            ingressClassName: nginx
```

Then ask for a certificate. `secretName` is the Secret cert-manager writes the issued certificate into, and it rewrites that Secret in place on every renewal.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: demo-tls
  namespace: default
spec:
  secretName: demo-tls
  dnsNames:
    - demo.example.com
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
    group: cert-manager.io
```

The Secret is a standard `kubernetes.io/tls` Secret with `tls.crt` and `tls.key` entries, which is exactly what an Ingress `spec.tls` expects. That is how it reaches the proxy: the Ingress terminates TLS with it and forwards cleartext to the Service the operator created.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: demo
  namespace: default
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - demo.example.com
      secretName: demo-tls
  rules:
    - host: demo.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: demo-svc
                port:
                  number: 8080
```

`demo-svc` on port 8080 is what the operator reconciles for an `SBProxy` named `demo` with the default `spec.port`. The matching `SBProxyConfig` has no `acme` block, no `https_bind_port`, and no `tls_cert_file`:

```yaml
apiVersion: sbproxy.dev/v1alpha1
kind: SBProxyConfig
metadata:
  name: demo-config
  namespace: default
spec:
  config: |
    proxy:
      http_bind_port: 8080
    origins:
      "demo.example.com":
        action:
          type: proxy
          url: https://backend.internal:8080
```

Watch the order complete with `kubectl describe certificate demo-tls`; the `Ready` condition flips to `True` and the events name each step. While it is pending, `kubectl get challenges` shows the outstanding authorization and why it is stuck.

The `Certificate` object above is optional. Annotate the Ingress with `cert-manager.io/cluster-issuer: letsencrypt-prod` and cert-manager's ingress-shim writes the equivalent Certificate for you from `spec.tls[].hosts` and `spec.tls[].secretName`. Two objects instead of three. Write the Certificate explicitly when you want fields the annotation cannot express, such as `duration`, `renewBefore`, or a specific `privateKey.algorithm`. Those two duration fields take Go duration strings and reject a `d` suffix, so a 90 day certificate renewed 15 days early is `duration: 2160h` and `renewBefore: 360h`.

### Wildcards and DNS-01

Swap the issuer's HTTP-01 solver for a DNS-01 one, then name the wildcard on the Certificate. Both blocks below are fragments of the objects above, not whole manifests.

```yaml
# Fragment: replaces spec.acme.solvers on the ClusterIssuer.
    solvers:
      - selector:
          dnsZones:
            - example.com
        dns01:
          route53:
            region: us-east-1
            hostedZoneID: Z2E3EXAMPLEZONE
            accessKeyID: AKIAEXAMPLE
            secretAccessKeySecretRef:
              name: route53-credentials
              key: secret-access-key
```

```yaml
# Fragment: the spec of a Certificate, same apiVersion and kind as above.
spec:
  secretName: wildcard-tls
  dnsNames:
    - "*.example.com"
    - example.com
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
    group: cert-manager.io
```

The `selector.dnsZones` field routes each zone to the solver that can answer for it, so one issuer can carry an HTTP-01 solver as a catch-all and DNS-01 solvers for the zones you control. Each provider has its own credential fields; on EKS you can drop `accessKeyID` and the Secret reference entirely and let the solver assume a role through IRSA. See cert-manager's [DNS-01 documentation](https://cert-manager.io/docs/configuration/acme/dns01/) for the provider list.

### Terminating TLS at the proxy instead

If you want the proxy itself to hold the certificate rather than the Ingress, the Secret has to be mounted into the proxy pod, and the operator cannot do that today. `SBProxy.spec` carries `image`, `configRef`, `replicas`, `port`, `resources`, `adminPort`, `adminAuthSecretRef`, and `clustering`. There is no volume, volumeMount, or pod-template field, so there is nowhere to attach the `secret` volume this needs.

That shape means deploying the proxy from your own Deployment manifest instead of an `SBProxy`, mounting the cert-manager Secret, and pointing the config at the mounted files:

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  tls_cert_file: /etc/sbproxy/tls/tls.crt
  tls_key_file: /etc/sbproxy/tls/tls.key
```

The proxy opens those files when the HTTPS listener starts and does not watch them afterwards. The kubelet does refresh a `secret` volume's contents after cert-manager rewrites the Secret, but the running process keeps serving the certificate it loaded at boot, so a renewal needs a pod restart to take effect. Most people should let the Ingress terminate and skip this.

### When dataplane ACME is the right answer

The recommendation above is scoped to Kubernetes with an Ingress. Outside that, `proxy.acme` is the better answer and the one to reach for:

- **A single node.** One host, one binary, a real hostname, ports 80 and 443 open. There is no Ingress to route a challenge through and no cluster to install a certificate controller into. The proxy answers HTTP-01 on its own listener and keeps the certificate in a local `redb` file across restarts. This is the case the feature is built for. See [self-hosting.md](self-hosting.md#a-public-endpoint-with-lets-encrypt).
- **No Kubernetes at all.** A VM, a bare-metal box, a container on a single Docker host, an appliance. cert-manager is a Kubernetes controller and has nothing to run on.
- **Kubernetes with nothing in front of the proxy.** A `LoadBalancer` Service pointed straight at the pods, no Ingress, no Gateway. There is no ingress for cert-manager's HTTP-01 solver to attach to, so if you also cannot use DNS-01, dataplane ACME on a shared store is the path that works. The next section is the setup.

The field reference, the full backend table, and the fleet behavior are in [configuration.md](configuration.md#acme--auto-tls).

### Running dataplane ACME on Kubernetes anyway

The operator templates nothing into an `acme` block and will roll out an `SBProxyConfig` that enables one. What it does decide is where pod state lives, and that default is wrong for certificates in both workload shapes.

**Nothing at `/var/lib/sbproxy` survives the pod.** `acme.storage_path` defaults to `/var/lib/sbproxy/certs` with `storage_backend: redb`. Neither shape backs that path with durable storage:

- The plain Deployment mounts only the config ConfigMap, at `/etc/sbproxy`. Nothing is mounted at `/var/lib/sbproxy`, so the cert store lands in the container's writable layer and goes away with the pod.
- The clustered StatefulSet mounts an `emptyDir` at `/var/lib/sbproxy` for mesh state. An `emptyDir` lives exactly as long as the pod, and the operator declares no `volumeClaimTemplates`, so the cert store goes away at the same moment.

Do not read the StatefulSet's mount as persistence. It is a writable scratch directory, deliberately so, because mesh node identity is pinned by an explicit `node_id` rather than by anything on disk. Certificates have no such fallback. Every rollout, node drain, and crash loop asks the CA for a fresh one, and Let's Encrypt caps duplicate certificates for the same hostname set at 5 per week. A handful of restarts is enough to rate-limit the domain for days, at which point the proxy is serving its self-signed bootstrap certificate to real traffic.

The operator exposes no field for attaching a PersistentVolumeClaim, and one would not be the fix anyway. A PVC solves persistence for a single replica and does nothing for the next paragraph's problem, which is that any replica has to be able to answer a challenge any other replica started. A shared store solves both at once. Point `storage_backend` at something outside the pod:

```yaml
apiVersion: sbproxy.dev/v1alpha1
kind: SBProxyConfig
metadata:
  name: demo-config
  namespace: default
spec:
  config: |
    proxy:
      http_bind_port: 8080
      acme:
        enabled: true
        email: ops@example.com
        storage_backend: redis
        storage_path: redis.default.svc.cluster.local:6379
    origins:
      "api.example.com":
        action:
          type: proxy
          url: https://backend.internal:8080
```

`s3`, `gcs`, and `azure` work the same way with a bucket URL in `storage_path` and credentials from the pod environment. `file` works too if you can mount one RWX volume across every replica. The full table is in [configuration.md](configuration.md#certificate-store-backends).

**The operator refuses a fleet on a pod-local store.** Persistence is only half of what the shared backend buys. The CA's HTTP-01 fetch is load-balanced across every ready pod, and the pod that receives it is rarely the pod that opened the order. A shared store closes that gap: the issuing replica publishes the token to it and any replica can serve the answer. On separate local stores the fetch lands on a pod that has never heard of the token.

So when `spec.replicas` is above 1 and the referenced config enables ACME on `redb`, `sqlite`, `memory`, or an omitted `storage_backend` (which parses as `redb`), the operator refuses to reconcile. It records the reason in `status.lastError` and requeues without touching the workload, so `kubectl describe sbproxy demo` shows why nothing moved:

```yaml
status:
  lastError: >-
    spec.replicas is 2 and proxy.acme.enabled is true with storage_backend
    "redb", which is local to one pod. Each replica would open its own order
    for the same hostname, and an HTTP-01 challenge load-balanced to a replica
    that did not open it cannot be answered. Use a shared store (file on an
    RWX volume, redis, s3, gcs, or azure), set spec.replicas to 1, or issue
    certificates with cert-manager and leave proxy.acme disabled. See
    docs/kubernetes.md.
```

The check lives in the operator rather than in config validation because the replica count is on the `SBProxy` and the backend is in the `sb.yml`. Nothing else sees both. Set a shared `storage_backend`, scale to one replica, or move to cert-manager, and the next reconcile clears `lastError` and proceeds.

**Let the challenge reach the pods.** The operator's Service exposes a single port, `spec.port` (default 8080), named `http`. The CA always fetches the challenge over plain HTTP on port 80, so whatever sits in front of the Service has to route port 80 for that hostname through to the proxy's port, at least for the `/.well-known/acme-challenge/` prefix. An Ingress that redirects all of port 80 to HTTPS fails every order until you exempt that path. If you have an Ingress capable of that, you have an Ingress cert-manager can solve against, which is the argument for using it.

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

1. Builds both images inside Docker (`Dockerfile.ci` for the data plane, `crates/sbproxy-k8s-operator/Dockerfile.ci` for the operator). The operator Dockerfile compiles in a Linux builder stage, so a macOS or Windows host still produces a runnable Linux binary.
2. Creates a kind cluster (`kindest/node:v1.30.0`), loads both images with `kind load docker-image`, helm-installs the chart, and runs `deploy/helm/sbproxy/test/smoke.sh`.

The Make target wraps the manual sequence below:

```bash
# from the repo root
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
