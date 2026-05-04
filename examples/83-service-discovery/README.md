# DNS-based service discovery

*Last modified: 2026-04-27*

Demonstrates `service_discovery` on a `proxy` action. Without service discovery, Pingora resolves the upstream hostname once when a connection is established and the connection pool reuses that connection (and that IP) for the lifetime of the pool. With `service_discovery: { enabled: true }`, the proxy re-resolves the hostname every `refresh_secs` (default 30s) and rotates through the current A/AAAA set round-robin. The hostname stays as the SNI/Host header so TLS verification continues to match the certificate. In production, point this at a Kubernetes Service hostname (for example `backend.namespace.svc.cluster.local:8080`) and the proxy picks up new pods within `refresh_secs` of them entering the Endpoints list.

## Run

```bash
sb run -c sb.yml
```

No setup required. The example points at `httpbin.org` so the rotation happens against whatever IPs that host advertises.

## Try it

```bash
# Repeated requests spread across the upstream's current IP set.
for i in 1 2 3 4; do
  curl -s -H 'Host: localhost' http://127.0.0.1:8080/ip
done
```

```bash
# Confirm the SNI / Host header is preserved (httpbin echoes the Host).
curl -s -H 'Host: localhost' http://127.0.0.1:8080/headers | jq '.headers.Host'
```

```bash
# Drop AAAA records on dual-stack hosts by setting ipv6: false in sb.yml,
# then restart and verify only IPv4 addresses are dialed.
curl -s -H 'Host: localhost' http://127.0.0.1:8080/ip
```

## What this exercises

- `service_discovery.enabled` - turn DNS re-resolution on for a single proxy action
- `service_discovery.refresh_secs` - how often the resolver runs in the background
- `service_discovery.ipv6` - opt out of AAAA records on dual-stack hosts
- Round-robin selection across the resolved IP set with the original hostname preserved as SNI

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/kubernetes.md](../../docs/kubernetes.md)
