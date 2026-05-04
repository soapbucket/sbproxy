# Defense in depth

*Last modified: 2026-04-27*

Layered authentication, authorisation, and inspection on a single origin. The chain answers a different question at each layer: `ip_filter` (is this source on the allow list?), WAF (does the request body or URI look benign?), `rate_limiting` (is this IP within its RPS budget?), `concurrent_limit` (is this IP within its in-flight cap?), JWT auth (is this user authenticated?), `request_validator` (does the body match the contract?), security headers and CORS injected on the response. The layers run in policy / auth / transform order. A failure in any layer short-circuits with the configured status; the upstream only sees requests that survived everything. mTLS is intentionally not enabled here (see example 85 standalone); pair the two by setting `proxy.mtls` when the deployment requires certificate-based service identity in addition to JWT user auth.

## Run

```bash
sbproxy serve -f sb.yml
```

No setup required. The example uses an HMAC JWT with a placeholder secret; replace `secret`, `audience`, and `issuer` for a real deployment.

## Try it

```bash
# Missing JWT - 401 from the auth layer.
curl -i -H 'Host: localhost' \
     -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":30}' \
     http://127.0.0.1:8080/anything
```

```bash
# Valid JWT, valid body shape - 200 reaches the upstream.
curl -i -H 'Host: localhost' \
     -H 'Authorization: Bearer <jwt>' \
     -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":30}' \
     http://127.0.0.1:8080/anything
```

```bash
# Valid JWT but body fails request_validator JSON Schema - 400.
curl -i -H 'Host: localhost' \
     -H 'Authorization: Bearer <jwt>' \
     -H 'Content-Type: application/json' \
     -d '{"name":""}' \
     http://127.0.0.1:8080/anything
```

```bash
# CORS preflight from the allowed origin - returns the allowed methods / headers.
curl -i -X OPTIONS \
     -H 'Host: localhost' \
     -H 'Origin: https://app.example.com' \
     -H 'Access-Control-Request-Method: POST' \
     http://127.0.0.1:8080/anything
```

## What this exercises

- `ip_filter` policy with whitelist CIDRs
- `waf` policy with OWASP CRS and `fail_open: false`
- `rate_limiting` policy keyed by client IP
- `concurrent_limit` policy keyed by client IP
- `request_validator` policy enforcing a JSON Schema on the request body
- `authentication.type: jwt` with HS256 and audience / issuer claims
- `cors` and `hsts` middleware on the response

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
