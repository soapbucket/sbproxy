# JWT authentication

*Last modified: 2026-07-09*

Validates HS256 JWTs against a static HMAC secret (`dev-secret-change-me`). The JWT must carry the configured issuer (`https://issuer.local`) and audience (`sbproxy-demo`); requests with a missing, malformed, or wrong-issuer token are rejected with 401 inside the proxy. Valid tokens flow through to `test.sbproxy.dev` unchanged. Rotate the secret out of YAML in production via `${ENV_VAR}` interpolation; the static value is here only so the example is reproducible.

## Run

```bash
make run CONFIG=examples/auth-jwt/sb.yml
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

Valid token, request forwarded. The example token below is signed with the example secret, carries the expected issuer/audience, and has `exp: 4102444800` (2100-01-01, far enough out that the example keeps working):

```bash
$ TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5sb2NhbCIsImF1ZCI6InNicHJveHktZGVtbyIsInN1YiI6ImFsaWNlIiwiZXhwIjo0MTAyNDQ0ODAwfQ.syTwsoUALYR9V1TQCcdrRzGe1_Oj4IE9mMNeESMTWnQ'

$ curl -i -H 'Host: jwt.local' -H "Authorization: Bearer $TOKEN" \
       http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{"method":"GET","url":"/get","headers":{"authorization":"Bearer eyJ...","host":"test.sbproxy.dev",...},"query":{},"timestamp":"2026-07-09T19:29:58.060Z"}
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
- Pre-upstream rejection - 401s never reach `test.sbproxy.dev`

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
