# Trusted proxies

*Last modified: 2026-08-16*

![Trusted proxies](../../docs/assets/trusted-proxies.gif)

When SBproxy sits behind another LB or CDN (Cloudflare, AWS ALB, Fly.io edge, internal LB), the immediate TCP peer is the LB, not the real client. The real client IP lives in the inbound `X-Forwarded-For` chain. `proxy.trusted_proxies` is the allowlist of source ranges whose forwarding headers the proxy trusts. Connections from inside the allowlist keep their `X-Forwarded-*`, `X-Real-IP`, and `Forwarded` headers; connections from outside have those headers stripped on ingress so external clients cannot spoof a source identity. IPv6 CIDRs work the same way.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Localhost is in 127.0.0.1/32, so XFF is honoured.
curl -s -H 'Host: localhost' \
     -H 'X-Forwarded-For: 203.0.113.7' \
     http://127.0.0.1:8080/headers | jq '.headers["x-forwarded-for"], .headers["x-real-ip"]'
# "203.0.113.7, 127.0.0.1"
# "203.0.113.7"

# A request from outside the trust list (simulate by removing 127.0.0.1/32
# and reloading) would see XFF stripped before processing:
# {"x-forwarded-for": "127.0.0.1", "x-real-ip": "127.0.0.1"}

# IPv6 example. The config also trusts 2001:db8::/32.
curl -s -H 'Host: localhost' \
     -H 'Forwarded: for="[2001:db8::1]"' \
     http://127.0.0.1:8080/headers | jq '.headers["forwarded"]'
# "for=\"[2001:db8::1]\""
```

Note: `test.sbproxy.dev` runs behind a hosting CDN that treats `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, and `X-Forwarded-Proto` as security-sensitive and overwrites them with its own edge-observed values before building the JSON body. So the live response from the commands above will show the CDN's values, not sbproxy's, even though sbproxy applied the trust-list logic correctly on its own hop (confirmed by reading the forwarding-header code directly). To see sbproxy's own resolved values rather than the upstream's echo of them, point the origin at a backend you control and inspect what it receives, or check sbproxy's access log, which records the resolved `client_ip` for every request.

## What this exercises

- `proxy.trusted_proxies` CIDR allowlist
- IPv4 + IPv6 CIDR support
- Inbound XFF / X-Real-IP / Forwarded header sanitization for untrusted peers
- Anti-spoofing on ingress

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
