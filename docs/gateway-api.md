# Gateway API controller

*Last modified: 2026-08-21*

`sbproxy-k8s-controller` watches `gateway.networking.k8s.io/v1` resources and renders them into a single `sb.yml` the data plane reads. You write `Gateway` and `HTTPRoute` objects; it writes the config file.

**This implements a subset of Gateway API v1 and has not been run against the upstream conformance suite. No conformance is claimed.** The [Unsupported](#unsupported) section lists everything it does not do, and it is longer than the supported list. Read it before you decide this is the right tool for your cluster.

It is also a different thing from the operator in [`kubernetes.md`](kubernetes.md). The operator reconciles `SBProxy` and `SBProxyConfig` custom resources into a running deployment and never looks at Gateway API. This controller only produces a config document, which you mount into the data plane pod directly. Do not paste that document into an `SBProxyConfig`; see [The operator will reject this document](#the-operator-will-reject-this-document).

## How ownership works

A `GatewayClass` is how an implementation announces itself, and it is the piece people skip. This controller claims `sbproxy.dev/gateway-controller`. Until a class naming it exists in the cluster, every `Gateway` belongs to somebody else and the rendered config stays empty, however many listeners you declare.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: sbproxy
spec:
  controllerName: sbproxy.dev/gateway-controller
```

Confirm it took ownership before debugging anything else:

```bash
kubectl get gatewayclass sbproxy -o jsonpath='{.status.conditions}'
```

By default the controller serves every class naming it. Pass `--gateway-class=<name>` to scope one replica to a single class, which is how you run two controllers over one cluster without them fighting. A class the flag excludes gets no status write at all, so the other replica's write survives.

## Install

Manifests live in [`deploy/k8s/gateway-controller/`](../deploy/k8s/gateway-controller/). Install the upstream Gateway API CRDs first; the controller refuses to start without all four kinds registered and watchable, because a missing CRD otherwise looks exactly like an empty cluster.

The CRDs come from the upstream project's standard channel, at whatever release your cluster is on:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/<version>/standard-install.yaml
kubectl apply -f deploy/k8s/gateway-controller/rbac.yaml
kubectl apply -f deploy/k8s/gateway-controller/deployment.yaml
kubectl apply -f deploy/k8s/gateway-controller/sample.yaml
```

The experimental channel installs the same four kinds plus the ones listed under [Unsupported](#unsupported), so it works, and the extra kinds sit there unwatched.

No release publishes a controller image. Build one from `crates/sbproxy-k8s-controller/Dockerfile.ci`, push it where your nodes can pull from, and edit `image:` in the Deployment:

```bash
cargo build --profile release-fast -p sbproxy-k8s-controller --locked
docker build -t registry.example.com/sbproxy-k8s-controller:dev \
  -f crates/sbproxy-k8s-controller/Dockerfile.ci .
docker push registry.example.com/sbproxy-k8s-controller:dev
```

### RBAC

The ClusterRole grants read on the four Gateway API kinds and write on their `/status` subresources, nothing else. The controller never mutates a spec.

The `/status` rules are the ones worth checking. Without them the controller still renders correct traffic config and still logs what it decided, but `kubectl describe gateway` shows no conditions and you have no way to tell a working route from a silently dropped one. A missing permission shows up as a warn log per reconcile and on `sbproxy_gateway_status_writes_total{result="error"}`, so the failure is visible rather than silent.

Note what is *not* in there. The controller does not read `Service` or `Endpoints`. It renders the cluster DNS name for a `backendRef` (`<name>.<namespace>.svc.cluster.local:<port>`) and lets kube-proxy resolve it, so a `backendRef` naming a Service that does not exist renders happily and fails at request time with a connection error.

## Configuration

| Flag | Environment | Default | What it does |
| --- | --- | --- | --- |
| `--config-out` | `SBPROXY_CONFIG_OUT` | `/etc/sbproxy/sb.yml` | Where the rendered document is written. |
| `--gateway-class` | `SBPROXY_GATEWAY_CLASS` | unset | Serve one class instead of every class naming this controller. |
| `--watch-namespace` | `SBPROXY_WATCH_NAMESPACE` | unset | Narrow the Gateway and route watches. `GatewayClass` is cluster scoped and is never narrowed. |
| `--tls-mount-dir` | `SBPROXY_TLS_MOUNT_DIR` | `/etc/sbproxy/tls` | Where Gateway TLS Secrets are mounted, one subdirectory per Secret name. |
| `--cluster-domain` | `SBPROXY_CLUSTER_DOMAIN` | `cluster.local` | DNS domain used to build Service addresses. |
| `--health-addr` | `SBPROXY_HEALTH_ADDR` | `0.0.0.0:8081` | Serves `/healthz`, `/readyz`, and `/metrics`. |
| `--reconcile-interval-secs` | `SBPROXY_RECONCILE_INTERVAL_SECS` | `300` | Full resync timer, as a defense against a missed watch event. Floored at 10 seconds. |
| `--verify-crds` | `SBPROXY_VERIFY_CRDS` | `true` | Check the CRDs are installed before starting the watchers. |
| `--leader-election` | `SBPROXY_LEADER_ELECTION` | `false` | Take a Lease before reconciling. Required above one replica. |
| `--lease-name` | `SBPROXY_LEASE_NAME` | `sbproxy-gateway-controller` | Lease name. |
| `--lease-namespace` | `SBPROXY_LEASE_NAMESPACE` | `sbproxy-system` | Lease namespace. |

## What it translates

| Gateway API | Renders as |
| --- | --- |
| Listener `protocol: HTTP` | `proxy.http_bind_port` |
| Listener `protocol: HTTPS`, `mode: Terminate` | `proxy.https_bind_port` plus `tls_cert_file` and `tls_key_file` under `--tls-mount-dir` |
| Listener `hostname` | Intersected with each attached route's `hostnames` |
| Route `hostnames`, including a leading `*.` | One `origins:` key each |
| `parentRefs`, with or without `sectionName` | Which listeners a route attaches to |
| `matches[].path` `Exact` / `PathPrefix` / `RegularExpression` | `forward_rules[].rules[].path.exact` / `.prefix` / `.regex` |
| `matches[].method` | `forward_rules[].rules[].method` |
| First `Exact` entry in `matches[].headers` | `forward_rules[].rules[].header` |
| First `Exact` entry in `matches[].queryParams` | `forward_rules[].rules[].query` |
| One `backendRef` | `action: {type: proxy}` on an HTTPRoute, `{type: grpc}` on a GRPCRoute |
| Several weighted `backendRefs` | `action: {type: load_balancer, algorithm: weighted_random}` |
| `RequestHeaderModifier` filter | `request_modifiers[].headers.set` / `.add` / `.remove` |
| GRPCRoute `method: {service, method}` | An exact path of `/<service>/<method>` |
| GRPCRoute `method: {service}` alone | A path prefix of `/<service>/` |

Every match becomes its own forward rule carrying one matcher, and the rules are sorted by Gateway API match precedence: exact path first, then longest prefix, then a method predicate, then header count, then query count. The origin's own `action` is always a 404, which is what Gateway API asks for when nothing matches.

### Worked example

The sample manifest declares a `GatewayClass`, one HTTP listener on port 8080, and a route with two rules:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: sample-route
  namespace: default
spec:
  parentRefs:
    - name: sbproxy-sample
  hostnames:
    - sample.sbproxy.test
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api
        - path:
            type: PathPrefix
            value: /api/v2
          method: POST
      filters:
        - type: RequestHeaderModifier
          requestHeaderModifier:
            set:
              - name: X-Gateway
                value: sbproxy
      backendRefs:
        - name: api-blue
          port: 8080
          weight: 90
        - name: api-green
          port: 8080
          weight: 10
    - matches:
        - path:
            type: Exact
            value: /healthz
      backendRefs:
        - name: health-svc
          port: 8080
```

That renders to the shape below. Three matches, three forward rules, ordered by precedence rather than by the order you wrote them: the exact `/healthz` comes first, then the longer `/api/v2` prefix, then `/api`. The exact bytes are pinned by the golden tests in `crates/sbproxy-k8s-controller/src/config_writer.rs`, which push every generated document through the real config compiler.

<!-- sbproxy-config-excerpt -->
```yaml
proxy:
  http_bind_port: 8080
origins:
  sample.sbproxy.test:
    action:
      body: "no matching route\n"
      content_type: text/plain; charset=utf-8
      status: 404
      type: static
    forward_rules:
    - rules:
      - path:
          exact: /healthz
      origin:
        action:
          type: proxy
          url: http://health-svc.default.svc.cluster.local:8080
    - rules:
      - path:
          prefix: /api/v2
        method: POST
      origin:
        action:
          algorithm: weighted_random
          targets:
          - url: http://api-blue.default.svc.cluster.local:8080
            weight: 90
          - url: http://api-green.default.svc.cluster.local:8080
            weight: 10
          type: load_balancer
        request_modifiers:
        - headers:
            set:
              X-Gateway: sbproxy
    - rules:
      - path:
          prefix: /api
      origin:
        action:
          algorithm: weighted_random
          targets:
          - url: http://api-blue.default.svc.cluster.local:8080
            weight: 90
          - url: http://api-green.default.svc.cluster.local:8080
            weight: 10
          type: load_balancer
        request_modifiers:
        - headers:
            set:
              X-Gateway: sbproxy
```

## Status conditions

Every resource the controller looks at gets `status` written back with `observedGeneration`, so you can tell a current condition from a stale one. `lastTransitionTime` only moves when the answer changes, not on every resync.

| Resource | Conditions |
| --- | --- |
| `GatewayClass` | `Accepted` |
| `Gateway` | `Accepted`, `Programmed` |
| `Gateway` listener | `Accepted`, `Programmed`, `ResolvedRefs` |
| `HTTPRoute` and `GRPCRoute`, per `parentRef` | `Accepted`, `ResolvedRefs` |

A listener can be `Accepted: True` and `Programmed: False` at the same time. That combination means the listener's own configuration is fine but it lost the single HTTP or HTTPS bind port to an earlier Gateway (see [One process, one HTTP port](#one-process-one-http-port)). Losing a race is not a defect in your manifest, and saying `Accepted: False` there would send you looking in the wrong place.

`ResolvedRefs: False` on a route means the rules were rendered but something in them was dropped. The message names it: a second header predicate, a `RegularExpression` header match, an unimplemented filter, a cross-namespace `backendRef`. Traffic still flows through whatever did translate, which is why this is a separate condition from `Accepted`.

A route attached to Gateways from several implementations keeps everyone's status. The controller reads the existing `status.parents`, carries forward every entry whose `controllerName` is not its own byte for byte, and appends its own.

## Behavior worth knowing before you rely on it

### The config file is replaced, never rewritten in place

Each reconcile writes the rendered document to a temporary file in the same directory, flushes it to disk, renames it over `sb.yml`, and syncs the directory. The rename is the atomic step. A data plane reading the file during a publish sees either the previous complete document or the new one, and a controller pod killed mid-publish leaves the previous document byte for byte intact rather than a truncated one the proxy cannot boot on.

Two limits are worth knowing. The guarantee is the filesystem's: a rename is atomic within one filesystem, which is why the temporary is written beside `sb.yml` rather than in `/tmp`, and on an NFS-backed `PersistentVolume` both the rename and the `fsync` are the server's promise rather than the kernel's. A mount that refuses the directory `fsync` outright, as some network and FUSE-backed volumes do, gets a logged warning naming the path and a publish still reported as successful: the rename has already taken effect by then, so the document is live and only its survival of a power cut is in question. And a mode you set on the published file is carried across each publish, so `chmod 640 sb.yml` on the shared volume survives the next reconcile.

### A watch relist swaps in a complete set

The API server ends watches routinely. An etcd compaction answers the next read with `410 Gone`, an apiserver rolls, and kube-rs reconnects and replays every object of that kind from the top. The controller collects the replay in a buffer beside the snapshot it is already serving and swaps the two when the replay finishes, so a reconcile that lands halfway through renders the set from before the disconnect rather than the three routes that have arrived so far. One relist produces one reconcile, at the swap. A route deleted while the watch was down is gone from the document at that same moment, because the replayed list is the whole answer.

The first document a fresh controller publishes waits for all four kinds to finish their first list. A restarting pod finds a complete `sb.yml` on the shared volume already, and publishing as soon as the `GatewayClass` watcher had listed would replace it with a perfectly valid document carrying zero origins until the route watchers caught up. If some kind never lists at all, because its watch is failing, the resync timer publishes without it once it fires, and `sbproxy_gateway_watch_errors_total` names the kind that was missing.

### One process, one HTTP port

sbproxy binds one HTTP port and one HTTPS port for the whole process. Gateway API lets you declare as many listeners on as many ports as you like. Listeners are visited in a stable order (Gateway namespace, then name, then declaration order); the first HTTP listener and the first HTTPS listener win, and any later listener asking for a *different* port reports `Programmed: False` with a message naming the port that beat it. Several listeners on the *same* port are all programmed, which is the usual pattern of one listener per hostname.

### TLS Secrets are mounted, not read

The controller never reads a Secret. A listener with `certificateRefs: [{name: api-cert}]` renders `tls_cert_file: /etc/sbproxy/tls/api-cert/tls.crt` and the matching `.key`, and something else has to put the Secret there. The Deployment manifest has a commented projected volume showing the layout: one subdirectory per Secret name.

An HTTPS listener with no `certificateRefs` is deliberately **not** programmed, and `https_bind_port` is left out of the document entirely. Emitting the port without a certificate compiles fine and then stops the data plane from starting at all, which is a much worse outcome than one unprogrammed listener.

Only the first `certificateRef` is used. sbproxy serves one certificate per listener, so the rest are ignored and the listener says so in `ResolvedRefs`.

### One header and one query predicate per match

An sbproxy forward rule carries a single header predicate and a single query predicate. Gateway API allows a list of each, ANDed. The first `Exact` entry of each is used, the rest are dropped, and the route reports `ResolvedRefs: False` naming what went. A `RegularExpression` header or query match is refused outright rather than silently treated as exact.

### The upstream sees the Service hostname

The rendered `proxy` action sends the upstream URL's own hostname as the `Host` header, which is the Kubernetes Service name, not the client's `Host`. Most Gateway API implementations preserve the client value. If your backend routes by `Host`, that difference will bite you. The original value is available to the backend as `X-Forwarded-Host`.

### The operator will reject this document

`sbproxy-config` ships a semantic linter on top of the config compiler. It reports `orphan-forward-rule-target` at error severity for every forward rule this controller writes, because that rule fires when a forward rule's action URL names a host that is not itself an `origins:` key. In a hand-written config that is a genuine dangling reference. For a Kubernetes Service address it never will be one.

The data plane's config compiler does not run that linter, so mounting the file into an sbproxy pod works. The operator does run it, in the preview validation that guards a rollout, and it refuses to roll out any `SBProxyConfig` carrying an error-severity finding. So a document this controller writes will be rejected if you route it through an `SBProxyConfig` resource. Mount the file into the data plane pod instead, either as a shared volume or by running the two as containers in one pod.

A golden test asserts that this is the only error-severity finding the generated document produces, and that it is still produced. When the linter learns about cluster-local names, that test fails and this section gets deleted.

### Route precedence across routes

Within one route, match precedence follows the spec. Across two routes that collide on the same match, Gateway API breaks the tie on `creationTimestamp` and this controller does not read it. It uses namespace and name instead, so the order is stable and reproducible but can differ from a conformance implementation. Do not build a deliberate override on top of two colliding routes.

<a id="unsupported"></a>

## Unsupported

Not implemented. Anything in this list is either ignored or reported through a status condition; nothing here silently half-works.

**Whole resource kinds.** `TLSRoute`, `TCPRoute`, `UDPRoute`, `ReferenceGrant`, `BackendTLSPolicy`, `BackendLBPolicy`, and the experimental channel generally. `GRPCRoute` and `HTTPRoute` are the only route kinds read.

**Cross-namespace references.** `ReferenceGrant` is not read at all. A `backendRef` or `certificateRef` naming another namespace is reported on `ResolvedRefs`; the backend address is still rendered, the certificate is not.

**Route filters other than `RequestHeaderModifier`.** `RequestRedirect`, `ResponseHeaderModifier`, `URLRewrite`, `RequestMirror`, `ExtensionRef`, and `CORS` are all reported as unimplemented on `ResolvedRefs`. `backendRefs[].filters`, the per-backend filter chain, is not read.

**Listener gating.** `allowedRoutes` is accepted and ignored, both the namespace selector and the kind list. Any route whose `parentRefs` name a Gateway attaches to it. If you were relying on `allowedRoutes.namespaces.from: Same` as a boundary, this controller does not enforce it.

**Listener and Gateway extras.** `spec.addresses`, `spec.infrastructure`, `status.addresses`, and TLS `options` are ignored. TLS `mode: Passthrough` is refused with `UnsupportedProtocol`. Listener protocols other than `HTTP` and `HTTPS` are refused the same way.

**Match features.** Regular-expression header and query matches. More than one header or query predicate per match. `HTTPRouteMatch` on `RegularExpression` paths is translated, but sbproxy's regex dialect is Rust's `regex` crate, not RE2 with the exact semantics the spec names.

**Traffic splitting on GRPCRoute.** Weighted `backendRefs` work on `HTTPRoute` only. A GRPCRoute with several backends uses the first with a non-zero weight and reports the rest as dropped.

**Conditions this controller never sets.** Listener `Conflicted` and `Overlapping`, Gateway `AddressNotAssigned`, route `PartiallyInvalid`. It also never emits Kubernetes `Event` objects; everything goes to conditions, logs, and metrics.

**Everything else about conformance.** Gateway API defines a large behavioral contract beyond field translation: precedence tie-breaking on `creationTimestamp`, `PartiallyInvalid` semantics, exactly which status transitions happen in which order. This controller has not been measured against any of it.

## Operations

### Probes

`/healthz` answers 200 while the process is alive. `/readyz` answers 503 until the first reconcile has written a document, so a rollout does not retire the old replica before the new one has produced anything.

### Metrics

`/metrics` on the same port, Prometheus text format.

| Metric | Labels | Answers |
| --- | --- | --- |
| `sbproxy_gateway_reconcile_total` | `kind`, `result` | Is the loop running, and is it succeeding |
| `sbproxy_gateway_reconcile_duration_seconds` | `kind` | Is a reconcile outrunning the resync interval |
| `sbproxy_gateway_watch_errors_total` | `kind` | Is a watch stuck on auth or a missing CRD |
| `sbproxy_gateway_status_writes_total` | `kind`, `result` | Is RBAC missing a `/status` subresource |

`kind` is one of `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute`, or `periodic`. A rising `watch_errors_total` with a flat `reconcile_total` means the controller is blind rather than broken.

### More than one replica

One replica writes one file. Two replicas without leader election write the same file and fight over it. Set `--leader-election=true` and apply the namespaced Role in `rbac.yaml`; the loser blocks on the Lease and reconciles nothing until it wins.

Leadership is a lifecycle, not a one-shot claim. The leader renews a 15 second Lease every 5 seconds. A standby may take the Lease over only after a full lease duration has passed since the last successful renewal, and the takeover is conditional on the Lease's `resourceVersion`, so two standbys racing the same expired Lease see exactly one winner. A leader whose renewals keep failing fences itself after 10 seconds: it stops writing the document and Gateway API status, fails its readiness probe, and exits so the Deployment restarts it as a standby.

The self-fence deadline (10s) is strictly inside the takeover threshold (15s), so a deposed leader has stopped writing before its successor can start, and two details are what make that arithmetic true rather than approximately true. Both replicas measure from the same instant: the Lease's `renewTime` is stamped when a renewal *begins*, so the leader measures its own deadline from the start of its last successful renewal rather than from when that call returned. And the deadline is enforced from inside the wait, not checked after the API call returns, so an API server that hangs instead of erroring cannot push the fence out by however long it hangs. What is left over, a full renewal period, is the margin for clock skew between the two replicas.

### Reading the log

Every controller line carries `target: k8s_audit`, so `RUST_LOG=sbproxy_k8s_controller=debug` narrows to the reconcile path. A successful pass logs the origin count and the number of owned Gateways, which is the fastest check that ownership resolved.

## See also

- [kubernetes.md](kubernetes.md) for the `SBProxy` operator, which is a different thing.
- [configuration.md](configuration.md) for the `sb.yml` schema this controller writes.
- [`deploy/k8s/gateway-controller/`](../deploy/k8s/gateway-controller/) for the manifests.
