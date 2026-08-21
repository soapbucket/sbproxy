# Security headers

*Last modified: 2026-08-21*

![Security headers](../../docs/assets/security-headers.gif)

Demonstrates the `security_headers` policy. Every response from the `test.sbproxy.dev` upstream gains the standard browser hardening set: `Strict-Transport-Security`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`. The origin is reachable on `127.0.0.1:8080` via the `sec.local` Host header.

The `Content-Security-Policy` comes from the structured `content_security_policy` block rather than a `headers:` entry, so report-only mode, a report URI, per-request nonces, and per-route overrides are all one edit away. The block composes with the `headers:` array; set the CSP in one place or the other, and a config that sets it in both is refused at compile.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# The whole hardening set, attached on top of the upstream response.
$ curl -sI -H 'Host: sec.local' http://127.0.0.1:8080/get | grep -iE 'strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|content-security'
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy: default-src 'self'; script-src 'self'
```

```bash
# Same headers regardless of the upstream path.
$ curl -sI -H 'Host: sec.local' http://127.0.0.1:8080/anything | grep -i content-security
content-security-policy: default-src 'self'; script-src 'self'
```

To watch a policy before enforcing it, set `report_only: true` on the block:
the header becomes `content-security-policy-report-only` and browsers report
violations instead of blocking them. Add `report_uri` to say where. Neither
needs `enable_nonce`.

## What this exercises

- `security_headers` policy with the typed `headers` list and structured `content_security_policy` block
- HSTS, framing, MIME sniffing, referrer policy, and permissions policy all set in one place
- Composition with a `proxy` action so the headers are layered on top of a real upstream response
- A structured `content_security_policy` block composing with the `headers:` array, rather than one silently replacing the other

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
