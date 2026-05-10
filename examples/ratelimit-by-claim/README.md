# Rate limit by JWT claim

*Last modified: 2026-04-27*

Per-tenant rate limiting keyed on a JWT claim. The `rate_limiting` policy on `api.local` accepts a `key:` CEL expression that runs against the request context. `jwt.claims.tenant_id` is auto-populated from `Authorization: Bearer <jwt>` without signature verification (`JwtAuth` handles that on a separate path). Two tenants with different `tenant_id` claims get independent 100-rpm token buckets with a burst of 20. When the expression returns empty, the policy falls back to client IP. Retry-After headers are emitted on rejection.

## Run

```bash
sbproxy serve -f sb.yml
```

You can mint test JWTs with any HS256 toolchain. The signature is irrelevant here since this policy reads claims without verifying them.

## Try it

```bash
# Tenant A: { "tenant_id": "acme" }. Header value is a base64-url JWT with
# that claim.
TOKEN_A='eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJhY21lIn0.SIG'

# Tenant B: { "tenant_id": "globex" }.
TOKEN_B='eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJnbG9iZXgifQ.SIG'

# Tenant A burns through its bucket. The first 20 (burst) succeed instantly,
# then the limiter throttles to 100/min steady state.
for i in $(seq 1 25); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'Host: api.local' -H "Authorization: Bearer $TOKEN_A" \
    http://127.0.0.1:8080/anything
done
# 200 200 200 ... 200 (20x)
# 429 429 ...
# Last 429 carries: Retry-After: 1
# X-Ratelimit-Limit: 100  X-Ratelimit-Remaining: 0

# Tenant B's bucket is untouched. It still has its full burst.
for i in $(seq 1 5); do
  curl -s -o /dev/null -w '%{http_code}\n' \
    -H 'Host: api.local' -H "Authorization: Bearer $TOKEN_B" \
    http://127.0.0.1:8080/anything
done
# 200 200 200 200 200

# No JWT -> falls back to client IP keying.
curl -i -H 'Host: api.local' http://127.0.0.1:8080/anything | head -1
# HTTP/1.1 200 OK
```

## What this exercises

- `policies[].type: rate_limiting` with a CEL `key:` expression
- `jwt.claims.*` context (no signature verification)
- Independent token buckets per tenant
- `requests_per_minute` + `burst` budget
- `headers.include_retry_after` on rejection

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
- [docs/scripting.md](../../docs/scripting.md)
