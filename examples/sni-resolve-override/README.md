# SNI and resolve overrides

*Last modified: 2026-08-16*

![SNI and resolve overrides](../../docs/assets/sni-resolve-override.gif)

Two siblings of `action.url` change how the proxy reaches the upstream without touching the URL itself. `sni_override: cdn.provider.net` sends that name in the TLS ClientHello SNI extension and validates the upstream cert against it; useful when the cert hostname differs from the URL host (typical SaaS-fronting pattern). `resolve_override: 203.0.113.7:443` pins the connect address, equivalent to `curl --connect-to`; the request line and `Host` header still use the URL host. The two are independent and compose with `host_override`.

## Run

```bash
sbproxy serve -f sb.yml --log-level debug
```

`--log-level debug` (or `SB_LOG_LEVEL=debug`) is required to see the routing line below; the
default `info` level does not print it. This config points at a synthetic IP (`203.0.113.7`)
so the request will not actually succeed (it 504s after the connect attempt times out); the
example documents the wire-level behaviour rather than a working roundtrip.

## Try it

```bash
# The request 504s, but the proxy log (debug level) shows the resolved wire-level facts
# in one line before the connect attempt times out:
#   routing request to upstream hostname=api.local upstream_host=api.example.com \
#     upstream_port=443 upstream_addr=203.0.113.7:443 upstream_sni=cdn.provider.net tls=true
#
#   - upstream_sni=cdn.provider.net   (from sni_override)
#   - upstream_addr=203.0.113.7:443   (from resolve_override)
#   - upstream_host=api.example.com   (the URL's host; this is also the HTTP Host header
#                                      sent upstream by default; would be overridden if
#                                      host_override were set)
curl -sv --max-time 8 -H 'Host: api.local' http://127.0.0.1:8080/get 2>&1 | head -20

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
