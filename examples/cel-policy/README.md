# CEL expression policy

*Last modified: 2026-04-27*

Demonstrates the `expression` policy, which evaluates a CEL expression per request and decides whether to allow it. This config admits requests only when the `X-Tenant` header equals `acme`. CEL header keys are normalised to lowercase with hyphens converted to underscores, so the access path is `request.headers["x-tenant"]`. Anything else returns `403` with the body `tenant not allowed`. Useful for custom access control beyond simple IP or API-key checks. The origin matches the `cel.local` Host header on `127.0.0.1:8080`.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# No tenant header - denied
$ curl -i -H 'Host: cel.local' http://127.0.0.1:8080/get
HTTP/1.1 403 Forbidden
content-type: text/plain

tenant not allowed
```

```bash
# Wrong tenant - denied
$ curl -i -H 'Host: cel.local' -H 'X-Tenant: other' http://127.0.0.1:8080/get
HTTP/1.1 403 Forbidden
content-type: text/plain

tenant not allowed
```

```bash
# Allowed tenant - 200, request reaches httpbin.org
$ curl -i -H 'Host: cel.local' -H 'X-Tenant: acme' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json

{
  "args": {},
  "headers": {
    "Host": "httpbin.org",
    "X-Tenant": "acme",
    ...
  },
  "url": "https://httpbin.org/get"
}
```

## What this exercises

- `expression` policy - CEL evaluation with custom `deny_status` and `deny_message`
- `request.headers["x-tenant"]` - normalised header lookup (lowercase, underscores for hyphens)
- Synchronous deny before the `proxy` action runs

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/scripting.md](../../docs/scripting.md) - CEL, Lua, and JavaScript reference
