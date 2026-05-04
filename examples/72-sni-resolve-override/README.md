# SNI and resolve overrides

*Last modified: 2026-04-27*

Two siblings of `action.url` change how the proxy reaches the upstream without touching the URL itself. `sni_override: cdn.provider.net` sends that name in the TLS ClientHello SNI extension and validates the upstream cert against it; useful when the cert hostname differs from the URL host (typical SaaS-fronting pattern). `resolve_override: 203.0.113.7:443` pins the connect address, equivalent to `curl --connect-to`; the request line and `Host` header still use the URL host. The two are independent and compose with `host_override`.

## Run

```bash
sbproxy serve -f sb.yml
```

This config points at a synthetic IP (`203.0.113.7`) so the request will not actually succeed; the example documents the wire-level behaviour rather than a working roundtrip.

## Try it

```bash
# Request, with the proxy verbose log on a separate terminal, shows:
#   - TLS SNI: cdn.provider.net    (from sni_override)
#   - TCP peer: 203.0.113.7:443    (from resolve_override)
#   - HTTP Host: api.example.com   (from the URL; would be overridden if host_override were set)
curl -sv -H 'Host: api.local' http://127.0.0.1:8080/get 2>&1 | head -20

# Verify with openssl that the cert SAN matches sni_override on a real CDN.
# (Substitute the real CDN endpoint to see a successful handshake.)
echo | openssl s_client -connect cdn.provider.net:443 -servername cdn.provider.net 2>/dev/null | openssl x509 -noout -subject

# resolve_override accepts ip, ip:port, [ipv6]:port, and host:port forms.
# IPv6 example (config edit, then restart):
#   resolve_override: "[2001:db8::7]:443"
```

## What this exercises

- `action.sni_override` for TLS ClientHello SNI and cert verification
- `action.resolve_override` to pin the connect address (DNS bypass)
- Independence from `host_override` and the URL's host

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
