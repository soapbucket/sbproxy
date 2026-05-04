# Trusted proxies

*Last modified: 2026-04-27*

When sbproxy sits behind another LB or CDN (Cloudflare, AWS ALB, Fly.io edge, internal LB), the immediate TCP peer is the LB, not the real client. The real client IP lives in the inbound `X-Forwarded-For` chain. `proxy.trusted_proxies` is the allowlist of source ranges whose forwarding headers the proxy trusts. Connections from inside the allowlist keep their `X-Forwarded-*`, `X-Real-IP`, and `Forwarded` headers; connections from outside have those headers stripped on ingress so external clients cannot spoof a source identity. IPv6 CIDRs work the same way.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Localhost is in 127.0.0.1/32, so XFF is honoured.
curl -s -H 'Host: localhost' \
     -H 'X-Forwarded-For: 203.0.113.7' \
     http://127.0.0.1:8080/headers | jq '.headers["X-Forwarded-For"], .headers["X-Real-Ip"]'
# "203.0.113.7, 127.0.0.1"
# "203.0.113.7"

# A request from outside the trust list (simulate by removing 127.0.0.1/32
# and reloading) would see XFF stripped before processing:
# {"X-Forwarded-For": "127.0.0.1", "X-Real-Ip": "127.0.0.1"}

# IPv6 example. The config also trusts 2001:db8::/32.
curl -s -H 'Host: localhost' \
     -H 'Forwarded: for="[2001:db8::1]"' \
     http://127.0.0.1:8080/headers | jq '.headers["Forwarded"]'
# "for=\"[2001:db8::1]\""
```

## What this exercises

- `proxy.trusted_proxies` CIDR allowlist
- IPv4 + IPv6 CIDR support
- Inbound XFF / X-Real-IP / Forwarded header sanitization for untrusted peers
- Anti-spoofing on ingress

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
