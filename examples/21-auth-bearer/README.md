# Bearer token authentication

*Last modified: 2026-04-27*

Accepts a fixed allowlist of opaque service tokens in the `Authorization: Bearer <token>` header. Pick this when callers are services that already manage shared tokens and you do not need the JWT validation surface. The two configured tokens (`svc-token-alpha`, `svc-token-beta`) are matched verbatim. Unknown or missing tokens are rejected with 401 before `httpbin.org` is contacted.

## Run

```bash
make run CONFIG=examples/21-auth-bearer/sb.yml
```

No env vars required.

## Try it

Missing token, request rejected:

```bash
$ curl -i -H 'Host: bearer.local' http://127.0.0.1:8080/get
HTTP/1.1 401 Unauthorized
content-type: text/plain

unauthorized
```

Valid token, request forwarded:

```bash
$ curl -i -H 'Host: bearer.local' \
       -H 'Authorization: Bearer svc-token-alpha' \
       http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{"args":{},"headers":{"Authorization":"Bearer svc-token-alpha","Host":"httpbin.org",...},"url":"https://httpbin.org/get"}
```

The second token works the same way:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' \
       -H 'Host: bearer.local' \
       -H 'Authorization: Bearer svc-token-beta' \
       http://127.0.0.1:8080/get
200
```

Wrong scheme, rejected:

```bash
$ curl -is -H 'Host: bearer.local' \
       -H 'Authorization: Token svc-token-alpha' \
       http://127.0.0.1:8080/get | head -n 1
HTTP/1.1 401 Unauthorized
```

## What this exercises

- `authentication.type: bearer` - opaque token allowlist
- `tokens` - canonical field name for the allowed tokens
- Strict `Bearer` scheme parsing - only `Authorization: Bearer <token>` matches

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
