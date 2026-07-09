# Sidecar deployment

*Last modified: 2026-07-09*

SBproxy is north-south first: most operators run it as a
top-of-rack gateway in front of an LLM provider or an internal
API. This guide covers the second supported deployment shape, the
**sidecar**, where one sbproxy container ships per workload pod
and intercepts traffic on the pod's local network namespace.

Use the sidecar shape when you need policy at the workload
boundary: agent fingerprinting on a developer pod, per-pod
budget enforcement on an east-west MCP client, or tamper-evident
audit envelopes for a tool-calling agent's outbound traffic.

## When to pick sidecar over gateway

| You want... | Pick |
|---|---|
| One enforcement point in front of every LLM provider | gateway |
| Identity-aware policy on east-west traffic between pods | sidecar |
| Per-pod telemetry that follows the workload | sidecar |
| Centralised key rotation, no per-pod config drift | gateway |
| Audit envelopes scoped to the workload that emitted the call | sidecar |

The two are not mutually exclusive: a typical mature deployment
runs a north-south gateway in front of providers, plus sidecars
on the workload pods that drive sensitive agentic flows. The
gateway enforces the macro budget, the sidecar enforces the
workload-scoped policy and emits the audit envelope tagged with
the pod identity.

## Deployment shape

The pod runs three containers:

1. **Init container** that configures traffic redirection so the
   workload's outbound traffic lands on sbproxy. The two
   supported patterns are iptables (Istio sidecar pattern) and
   eBPF (Cilium pattern); see [Traffic capture](#traffic-capture)
   below.
2. **sbproxy container** that runs the proxy with the
   sidecar-tuned config.
3. **Workload container** that runs the application or agent.

Only the first two are sbproxy concerns. The workload container
is unchanged from its non-sidecar form; the redirect handles the
hand-off transparently.

### Minimal pod spec

A sample manifest lives at
[`deploy/k8s/sidecar/`](../deploy/k8s/sidecar/). The pod template
looks like this:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: agent-pod
  annotations:
    sbproxy.dev/sidecar-injected: "true"
spec:
  initContainers:
    - name: sbproxy-init
      image: ghcr.io/soapbucket/sbproxy-redirect-init:1.0.0
      securityContext:
        capabilities:
          add: ["NET_ADMIN", "NET_RAW"]
      env:
        - name: SBPROXY_PORT
          value: "15001"
        - name: REDIRECT_PORTS
          value: "443,80"
  containers:
    - name: sbproxy
      image: ghcr.io/soapbucket/sbproxy:1.0.0
      args: ["--config", "/etc/sbproxy/sb.yml"]
      ports:
        - containerPort: 15001
          name: sbproxy
      resources:
        requests:
          cpu: 100m
          memory: 64Mi
        limits:
          cpu: 1000m
          memory: 256Mi
      volumeMounts:
        - name: config
          mountPath: /etc/sbproxy
          readOnly: true
    - name: workload
      image: example/agent:latest
  volumes:
    - name: config
      configMap:
        name: agent-pod-sbproxy-config
```

The redirect init container is the only privileged piece; the
sbproxy container itself runs unprivileged.

## Traffic capture

The init container's only job is to redirect the workload's
outbound traffic onto the sbproxy port. The two supported
patterns:

### iptables (Istio-compatible)

The init container writes `iptables` rules in the pod's network
namespace that DNAT outbound TCP on the listed ports to
`127.0.0.1:15001`. This is the proven Istio pattern; it works on
any conformant Kubernetes cluster, requires only `NET_ADMIN` and
`NET_RAW`, and survives pod restart cleanly because the network
namespace is fresh on each restart.

The redirect-init image is a thin wrapper around `iptables`; you
can substitute Istio's own `istio-iptables` binary if the pod is
already in a mesh and you want one fewer image to maintain.

### eBPF (Cilium-compatible)

In a Cilium-enabled cluster, the redirect can be expressed as a
`CiliumNetworkPolicy` that hooks the socket layer instead of the
network layer. This avoids the per-packet iptables traversal
overhead and is the recommended pattern at high request volume.

See [Cilium sidecar redirection
docs](https://docs.cilium.io/en/stable/network/servicemesh/)
for the policy template; sbproxy itself does not need to know
which redirect pattern was used.

### Explicit loopback (no redirect)

If you cannot grant `NET_ADMIN` to an init container, or if you
prefer the workload to know about sbproxy, configure the workload
to point at `http://127.0.0.1:15001` directly. This drops the
init container and the redirect rules entirely; the trade-off is
that the workload must be configured for it.

## Cold-start and footprint targets

The sidecar pattern is sensitive to per-pod overhead. SBproxy's
sidecar-tuned defaults aim for:

| Metric | Target | How to verify |
|---|---|---|
| Cold start | under 500ms on 1 vCPU | start `sbproxy serve -f sb.yml` and time the first successful `curl http://127.0.0.1:15001/health` |
| Resident set at idle | under 80MB | `ps -o rss= -p $(pgrep sbproxy)` |
| Required external dependencies | none | `sbproxy validate sb.yml` compiles the config; it needs no network or backing store |

The sample sidecar config in
[`examples/sidecar/sb.yml`](../examples/sidecar/sb.yml) is tuned
for these targets: no Redis or Postgres dependency, no
agent-skills crawl on startup, no preloaded classifier models.
You can opt back into any of those once you have measured the
overhead they add on your workload mix.

## Sidecar-tuned config

The full annotated example lives at
[`examples/sidecar/sb.yml`](../examples/sidecar/sb.yml). Its
content:

```yaml
proxy:
  # The init container DNATs outbound TCP onto 15001. Bind here.
  http_bind_port: 15001

origins:
  # Catch-all hostname. The sidecar instruments every outbound
  # call the workload makes; layer policy on top without
  # rewriting the destination.
  "*":
    action:
      type: proxy
      url: https://test.sbproxy.dev

    policies:
      # Per-pod outbound rate limit. Sized to the workload's
      # expected steady-state; bursts above this return 429 to
      # the workload, which is the signal an agent loop should
      # treat as a back-pressure hint.
      - type: rate_limiting
        requests_per_minute: 3000
        burst: 100
        headers:
          enabled: true
          include_retry_after: true

      # IP allow-list keeps the workload from reaching arbitrary
      # destinations. The default below admits everything; in
      # production narrow this to the LLM provider CIDRs you
      # have authorised.
      - type: ip_filter
        whitelist:
          - 0.0.0.0/0
```

The knobs, in order:

* `proxy.http_bind_port: 15001` is the port the init container's
  redirect rules DNAT outbound TCP onto. The proxy keeps all
  state in memory by default, so nothing else is needed at the
  `proxy` level: no Redis, no Postgres, no separate metrics
  listener. `/health` and `/metrics` are served on this same
  port.
* The `"*"` origin is a catch-all hostname, so every outbound
  call the workload makes hits the same policy stack regardless
  of destination. Point `action.url` at the upstream you want to
  front; for local experiments the example uses the hosted test
  origin.
* `rate_limiting` is the per-pod outbound budget.
  `requests_per_minute` sizes the steady state, `burst` absorbs
  spikes, and the `headers` block emits rate-limit headers
  (including `Retry-After`) so an agent loop can back off
  instead of hammering a closed window.
* `ip_filter` bounds where the workload can connect. The
  shipped `0.0.0.0/0` whitelist admits everything; narrow it to
  the provider CIDRs you have authorised before production.

## Service-mesh integration

### Istio

Istio's sidecar injection writes its own `istio-init` and
`istio-proxy` containers. To layer sbproxy on top:

1. Disable Istio's outbound capture for the ports sbproxy
   handles, using
   `traffic.sidecar.istio.io/excludeOutboundPorts` on the pod.
2. Add the sbproxy containers to the pod template with the
   kustomize patch from `deploy/k8s/sidecar/base/`. There is no
   shipped Istio webhook manifest yet;
   `deploy/k8s/sidecar/istio/` holds integration notes only.
3. Order matters: the sbproxy init container must run **after**
   `istio-init` so its redirect rules take precedence on the
   ports it owns.

### Linkerd

Linkerd's `linkerd-proxy` runs at L7 and does not consume the
same iptables chain, so the two coexist without exclusion. Add
sbproxy with the same kustomize patch used in the bare-pod
pattern; no Linkerd-specific configuration is required.

### Bare pod (no mesh)

The kustomize overlay at
`deploy/k8s/sidecar/base/` is the no-mesh template. Apply with:

```bash
kubectl apply -k deploy/k8s/sidecar/base/
```

## Identity

The sidecar inherits the pod's Kubernetes service account by
default. For workloads that need workload-scoped identity beyond
the service-account boundary (per-binary attestation, signed
audit envelopes), a SPIFFE SVID from the local SPIRE agent is
the natural fit, but sbproxy has no SPIFFE integration yet.

Today the sidecar relies on the pod's mounted service-account
token for east-west auth and on file-backed certificates
(mounted from a Secret) for mTLS via `proxy.mtls`.

## Telemetry shape

The sidecar is a per-pod data plane. The recommended scrape shape
is:

* **Metrics**: each pod exposes `/metrics` on the sbproxy
  serving port (`15001` in the shipped config); a `PodMonitor`
  (Prometheus Operator) or static scrape config picks them up.
  No central aggregator on the hot path.
* **Logs**: access logs are JSON lines on the container's
  stdout/stderr (or a rotating file via `access_log.output`); a
  DaemonSet log shipper (Fluent Bit, Vector, OpenTelemetry
  Collector) forwards them off-pod.
* **Traces**: each pod's sbproxy points
  `proxy.observability.telemetry.endpoint` at a node-local OTLP
  collector; the collector batches and forwards.

The control plane (your central Prometheus, Loki, Tempo) is
**not** on the request path. A control-plane outage degrades
observability, not policy enforcement.

## Sample workload

A worked example deploying a representative agentic workload
behind the sidecar lives at `deploy/k8s/sidecar/example/`. It
deploys a small client pod with the sidecar injected, configures
the sidecar to enforce a per-pod rate limit on outbound LLM
calls, and exposes the metrics endpoint for scrape.

To run it against a local kind cluster:

```bash
kind create cluster
kubectl apply -k deploy/k8s/sidecar/example/
kubectl port-forward pod/agent-pod 15001:15001
curl -s http://127.0.0.1:15001/metrics | grep sbproxy_requests
```

## Failure modes and degraded operation

| Failure | Sidecar behaviour | Operator action |
|---|---|---|
| Workload sends traffic before sbproxy is ready | Connections are refused until the listener binds (subsecond); the workload should retry on startup | none; standard startup retry logic covers it |
| sbproxy container crashes | Pod restarts; init container reinstalls redirect on fresh netns | check `kubectl logs -p` for the cause |
| Config ConfigMap update | the file watcher sees the mounted file change and hot-reloads in place | none; reload is non-disruptive |
| Log volume full | writes to a full file sink fail; stdout logging and serving continue | rotate the volume or shrink retention |
| External LLM provider unreachable | sbproxy returns the upstream error to the workload | inspect provider; sidecar is not the cause |

The hot path **never** depends on a control-plane component
being reachable. This is the design property that makes the
sidecar shape safe to run in a per-pod fanout.

## What's not covered yet

* Helm chart packaging for the sidecar deployment (the existing
  chart at `deploy/helm/sbproxy/` is operator-only). The
  kustomize overlay is the supported install path today.
* SPIFFE SVID binding for sidecar identity. Today the sidecar
  uses the pod's service-account token plus file-backed mTLS
  certs; SPIRE integration is a separate workstream.
* Automatic sidecar injection via a packaged mutating webhook.
  No webhook manifests ship yet; `deploy/k8s/sidecar/webhook/`
  holds a README describing the intended shape. Until they
  land, patch pods explicitly with the kustomize base.
