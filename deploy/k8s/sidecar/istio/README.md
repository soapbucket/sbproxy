# Layering sbproxy on top of Istio

Istio's sidecar injection already writes `istio-init` and
`istio-proxy` into the pod. Running sbproxy alongside requires
two adjustments so the two redirects do not stomp on each other.

## 1. Exclude sbproxy's ports from Istio's outbound capture

Add the annotation to the pod template:

```yaml
metadata:
  annotations:
    traffic.sidecar.istio.io/excludeOutboundPorts: "15001"
```

This tells `istio-init` not to install iptables rules for the
port sbproxy listens on, so the sbproxy init container's rules
take precedence on that port without contention.

## 2. Order the init containers

Kubernetes runs init containers in the order they are declared.
The required order is:

1. `istio-init` (writes Istio's iptables baseline)
2. `sbproxy-init` (writes sbproxy's redirect for its ports)

If sbproxy is injected via a webhook, ensure the webhook's
ordering hook fires **after** Istio's. The simplest way is to
configure the sbproxy webhook with `reinvocationPolicy: IfNeeded`
and a `failurePolicy: Fail` so a misordered application fails
loudly instead of silently producing a broken pod.

## What you get

* Istio handles east-west mTLS, retries, and the L7 telemetry
  Istio is good at.
* sbproxy handles agent identity, prompt-linked audit, and
  per-pod budget enforcement that Istio does not surface.

The two are complementary, not competing.
