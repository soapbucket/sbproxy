# Kubernetes gateway pattern

*Last modified: 2026-07-09*

![Kubernetes gateway pattern](../../docs/assets/k8s-gateway.gif)

Realistic config when SBproxy runs behind a Kubernetes Ingress (or any cluster-edge load balancer) and proxies to backend Pods that scale up and down independently. `trusted_proxies` honours XFF only from cluster-internal source ranges and rejects spoofed XFF from anywhere else. `service_discovery` re-resolves the upstream hostname every `refresh_secs` so endpoint rotation is picked up automatically without restarting the proxy. `host_override` sends the Service hostname to the upstream when Pods route by Host header for multi-tenant or vhost dispatch. `correlation_id` threads `X-Request-Id` through the proxy, upstream, response, and webhooks so trace IDs survive the cluster boundary. `concurrent_limit` keyed by IP protects upstream Pods from a thundering herd. The Ingress, K8s Operator, and HTTPRoute fixtures from `docs/kubernetes.md` produce this exact shape on the dataplane.

## Run

```bash
sbproxy serve -f sb.yml
```

In a real K8s deployment the Operator generates this YAML from a `Gateway` and `HTTPRoute` pair. The example uses `test.sbproxy.dev` as a stand-in for the cluster Service so it runs locally; the inline comments show the Service DNS name (`backend.namespace.svc.cluster.local:8080`) that production configs use for both `url` and `host_override`. The live `host_override` is `test.sbproxy.dev` because the shared test upstream routes by Host and serves no other name.

## Try it

```bash
# Simulate a request coming through the Ingress for a real client at
# 203.0.113.7. The curl peer (127.0.0.1) is inside trusted_proxies, so
# the proxy honours the inbound X-Forwarded-For and treats 203.0.113.7
# as the client IP for rate limits and logs. The response carries the
# freshly minted X-Request-Id. (The hosted echo runs behind a CDN that
# rewrites forwarding headers with its own values, so verify via the
# X-Request-Id response header rather than the echoed XFF.)
curl -i -H 'Host: api.example.com' \
     -H 'X-Forwarded-For: 203.0.113.7' \
     http://127.0.0.1:8080/headers
```

```bash
# Reuse the request id end-to-end. The proxy honours the inbound
# X-Request-Id rather than generating a new one.
curl -i -H 'Host: api.example.com' \
     -H 'X-Request-Id: client-supplied-1234' \
     http://127.0.0.1:8080/headers
```

```bash
# Trust boundaries: X-Forwarded-For is only as trustworthy as the peer
# that sends it. This config lists 127.0.0.1 in trusted_proxies (so the
# example is testable locally), which means a local curl is a trusted
# peer and its X-Forwarded-For value IS honoured; the call below makes
# the proxy treat 8.8.8.8 as the client IP.
curl -i -H 'Host: api.example.com' \
     -H 'X-Forwarded-For: 8.8.8.8' \
     http://127.0.0.1:8080/headers

# Had the same request arrived from a peer outside trusted_proxies
# (any non-listed source IP), the proxy would discard the inbound
# header and replace it with the peer's real socket address, so a
# spoofed XFF from the open internet never reaches rate limits, logs,
# or the upstream. In production, keep trusted_proxies down to the
# CIDRs your Ingress actually uses and drop the loopback entry.
```

## What this exercises

- `proxy.trusted_proxies` - CIDR list of allowed XFF sources (Pod CIDR, Service CIDR, loopback)
- `proxy.correlation_id` - honour inbound `X-Request-Id`, generate when absent, echo on response
- `service_discovery` on a Service hostname so endpoint rotation is picked up automatically
- `host_override` so the upstream sees the hostname it routes by (the Service hostname in production; `test.sbproxy.dev` in this live demo), not the public Host header
- `retry` on `connect_error`, `timeout`, and numeric status codes with bounded attempts and backoff
- `concurrent_limit` keyed by IP so one client cannot exhaust upstream concurrency

## See also

- [docs/kubernetes.md](../../docs/kubernetes.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
