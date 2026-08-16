# Security headers

*Last modified: 2026-08-16*

![Security headers](../../docs/assets/security-headers.gif)

Demonstrates the `security_headers` policy. Every response from the `test.sbproxy.dev` upstream gains the standard browser hardening set: `Strict-Transport-Security`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`. The origin is reachable on `127.0.0.1:8080` via the `sec.local` Host header.

**Known limitation:** this `sb.yml` also configures a structured `content_security_policy` block alongside the canonical `headers:` array, intending to add `Content-Security-Policy: default-src 'self'; script-src 'self'`. As currently built, that combination does not emit a CSP header at all: `SecHeadersPolicy::resolved_headers()` only falls through to the `content_security_policy` field when the canonical `headers:` list is empty, and the richer per-request path that *would* build the CSP header only runs when `enable_nonce: true` or `dynamic_routes` is set (see `crates/sbproxy-modules/src/policy/sec_headers.rs`, `resolved_headers` and `resolved_headers_for_request`). With `headers:` populated (as below) and a plain `policy:` string with `enable_nonce: false`, the CSP header is silently dropped. Setting `enable_nonce: true` routes around it (it forces the rich path, at the cost of also injecting a nonce), which is reflected in the CSP-nonce line below.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Hardening headers attached on top of the upstream response. No
# content-security-policy header (see "Known limitation" above).
$ curl -i -H 'Host: sec.local' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()

{"method":"GET","url":"/get","headers":{...},"query":{},"timestamp":"..."}
```

```bash
# Same headers regardless of the upstream path
$ curl -sI -H 'Host: sec.local' http://127.0.0.1:8080/anything | grep -iE 'strict-transport|x-frame|csp|content-security'
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
```

To see a working `content-security-policy` header with this policy shape, add
`enable_nonce: true` to the `content_security_policy` block:

```bash
$ curl -sI -H 'Host: sec.local' http://127.0.0.1:8080/get | grep -i content-security
content-security-policy: default-src 'self'; script-src 'self' 'nonce-<random>'
```

## What this exercises

- `security_headers` policy with the typed `headers` list and structured `content_security_policy` block
- HSTS, framing, MIME sniffing, referrer policy, and permissions policy all set in one place
- Composition with a `proxy` action so the headers are layered on top of a real upstream response
- The `content_security_policy` + `headers:` interaction bug documented above under "Known limitation"

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
