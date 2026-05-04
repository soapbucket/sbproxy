# Kubernetes gateway pattern

*Last modified: 2026-04-27*

Realistic config when SBproxy runs behind a Kubernetes Ingress (or any cluster-edge load balancer) and proxies to backend Pods that scale up and down independently. `trusted_proxies` honours XFF only from cluster-internal source ranges and rejects spoofed XFF from anywhere else. `service_discovery` re-resolves the upstream hostname every `refresh_secs` so endpoint rotation is picked up automatically without restarting the proxy. `host_override` sends the Service hostname to the upstream when Pods route by Host header for multi-tenant or vhost dispatch. `correlation_id` threads `X-Request-Id` through the proxy, upstream, response, and webhooks so trace IDs survive the cluster boundary. `concurrent_limit` keyed by IP protects upstream Pods from a thundering herd. The Ingress, K8s Operator, and HTTPRoute fixtures from `docs/kubernetes.md` produce this exact shape on the dataplane.

## Run

```bash
sb run -c sb.yml
```

In a real K8s deployment the Operator generates this YAML from a `Gateway` and `HTTPRoute` pair. The example uses `httpbin.org` as a stand-in for the cluster Service so it runs locally; the inline comments show the Service DNS name (`backend.namespace.svc.cluster.local:8080`) that production configs use.

## Try it

```bash
# Simulate a request coming through the Ingress (10.0.0.5) for a real
# client at 203.0.113.7. trusted_proxies recovers the client IP from
# X-Forwarded-For; the upstream sees the recovered XFF and the new
# X-Request-Id which is also echoed on the response.
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
# A spoofed XFF from outside the trusted_proxies range gets stripped.
# The upstream sees the proxy's IP, not the spoofed value.
curl -i -H 'Host: api.example.com' \
     -H 'X-Forwarded-For: 8.8.8.8' \
     http://127.0.0.1:8080/headers
```

## What this exercises

- `proxy.trusted_proxies` - CIDR list of allowed XFF sources (Pod CIDR, Service CIDR, loopback)
- `proxy.correlation_id` - honour inbound `X-Request-Id`, generate when absent, echo on response
- `service_discovery` on a Service hostname so endpoint rotation is picked up automatically
- `host_override` so the upstream sees the Service hostname, not the public Host header
- `retry` on `connect_error` / `timeout` with bounded attempts and backoff
- `concurrent_limit` keyed by IP so one client cannot exhaust upstream concurrency

## See also

- [docs/kubernetes.md](../../docs/kubernetes.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
