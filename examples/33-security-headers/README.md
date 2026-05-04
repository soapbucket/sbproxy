# Security headers

*Last modified: 2026-04-27*

Demonstrates the `security_headers` policy. Every response from the `httpbin.org` upstream gains the standard browser hardening set: `Strict-Transport-Security`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`. A structured `content_security_policy` block adds `Content-Security-Policy` with `default-src 'self'; script-src 'self'`; `enable_nonce` and `report_only` are wired so the same policy block can flip into report-only or nonce-injecting modes later. The origin is reachable on `127.0.0.1:8080` via the `sec.local` Host header.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# All hardening headers attached on top of the upstream response
$ curl -i -H 'Host: sec.local' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy: default-src 'self'; script-src 'self'

{
  "args": {},
  "headers": { ... },
  "origin": "...",
  "url": "https://httpbin.org/get"
}
```

```bash
# Same headers regardless of the upstream path
$ curl -sI -H 'Host: sec.local' http://127.0.0.1:8080/anything | grep -iE 'strict-transport|x-frame|csp|content-security'
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
content-security-policy: default-src 'self'; script-src 'self'
```

## What this exercises

- `security_headers` policy with the typed `headers` list and structured `content_security_policy` block
- HSTS, framing, MIME sniffing, referrer policy, permissions policy, and CSP all set in one place
- Composition with a `proxy` action so the headers are layered on top of a real upstream response

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
