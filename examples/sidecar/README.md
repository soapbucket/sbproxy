# sidecar

*Last modified: 2026-06-04*

Sidecar-tuned `sbproxy` config for the per-pod fanout case: small
RSS, fast cold start, no required external dependencies. Run on the
workload pod's loopback interface; an init container redirects the
workload's outbound traffic onto this port.

This `sb.yml` is the in-config half. For the full Kubernetes wire-up
(init container, pod spec, service-mesh integration notes,
worked example, kustomize overlay), see
[`docs/sidecar-deployment.md`](../../docs/sidecar-deployment.md) and
the manifests at [`deploy/k8s/sidecar/`](../../deploy/k8s/sidecar/).

## When to pick this shape over the top-of-rack gateway

| You want... | Pick |
|---|---|
| One enforcement point in front of every LLM provider | gateway (`basic-proxy` example) |
| Identity-aware policy on east-west traffic between pods | sidecar (this example) |
| Per-pod telemetry that follows the workload | sidecar |
| Audit envelopes scoped to the workload that emitted the call | sidecar |

The two are not mutually exclusive: a typical mature deployment runs
a north-south gateway in front of providers, plus sidecars on the
workload pods that drive sensitive agentic flows.

## Run (locally, no k8s)

```bash
make run CONFIG=examples/sidecar/sb.yml
```

## Test

```bash
curl -H 'Host: any.host' http://127.0.0.1:15001/
```

Observe the `rate_limiting` (3000/min cap, burst 100) and
`ip_filter` (allow `0.0.0.0/0` by default) policies in the access
log. In production the IP allow-list narrows to the LLM provider
CIDRs you have authorised.

## What the config tunes

| Knob | Sidecar default | Why |
|---|---|---|
| `proxy.http_bind_port` | `15001` | The init container DNATs outbound TCP onto this port. |
| `rate_limiting.requests_per_minute` | `3000` | Per-pod cap sized to a single workload's steady-state. Bursts above this return 429, which an agent loop should treat as back-pressure. |
| `rate_limiting.burst` | `100` | Small burst to absorb a workload-level spike without 429-storm. |
| `ip_filter.whitelist` | `0.0.0.0/0` | Demo accepts all; production narrows to the authorised CIDRs. |

## See also

- [`docs/sidecar-deployment.md`](../../docs/sidecar-deployment.md) - operator guide (traffic capture options, service-mesh integration, footprint targets, telemetry shape, failure modes).
- [`deploy/k8s/sidecar/`](../../deploy/k8s/sidecar/) - kustomize overlay + worked example manifest + Istio integration notes + mutating-webhook scaffold.
