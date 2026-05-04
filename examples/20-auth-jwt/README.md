# JWT authentication

*Last modified: 2026-04-27*

Validates HS256 JWTs against a static HMAC secret (`dev-secret-change-me`). The JWT must carry the configured issuer (`https://issuer.local`) and audience (`sbproxy-demo`); requests with a missing, malformed, or wrong-issuer token are rejected with 401 inside the proxy. Valid tokens flow through to `httpbin.org` unchanged. Rotate the secret out of YAML in production via `${ENV_VAR}` interpolation; the static value is here only so the example is reproducible.

## Run

```bash
make run CONFIG=examples/20-auth-jwt/sb.yml
```

No env vars required.

## Try it

No token, request rejected:

```bash
$ curl -i -H 'Host: jwt.local' http://127.0.0.1:8080/get
HTTP/1.1 401 Unauthorized
content-type: text/plain

unauthorized
```

Valid token, request forwarded. The example token below is signed with the example secret and carries the expected issuer/audience:

```bash
$ TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5sb2NhbCIsImF1ZCI6InNicHJveHktZGVtbyIsInN1YiI6ImFsaWNlIn0.AYI4MIxc70VQ8kxGmAHPJiV5KrYJFzFRZkAJC4ahXUQ'

$ curl -i -H 'Host: jwt.local' -H "Authorization: Bearer $TOKEN" \
       http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{"args":{},"headers":{"Authorization":"Bearer eyJ...","Host":"httpbin.org",...},"url":"https://httpbin.org/get"}
```

Token signed with the wrong secret, rejected:

```bash
$ BAD='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5sb2NhbCIsImF1ZCI6InNicHJveHktZGVtbyJ9.totally-bogus-signature'

$ curl -is -H 'Host: jwt.local' -H "Authorization: Bearer $BAD" \
       http://127.0.0.1:8080/get | head -n 1
HTTP/1.1 401 Unauthorized
```

## What this exercises

- `authentication.type: jwt` - HS256 validation with a static secret
- `issuer` and `audience` claim checks - both must match
- `algorithms: [HS256]` allowlist - only the listed algorithms are accepted
- Pre-upstream rejection - 401s never reach `httpbin.org`

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
