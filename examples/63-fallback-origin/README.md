# Fallback origin

*Last modified: 2026-04-27*

The primary action proxies to `httpbin.org/status/503`, which always returns 503. The `fallback_origin` block defines a backup origin served when the primary returns a status listed in `on_status` (502, 503, 504) or fails at the transport level (`on_error: true`). Clients see the fallback's static action: a 200 response carrying a friendly degraded JSON body. `add_debug_header: true` stamps an `X-Fallback` header so callers can tell when the fallback path was taken.

## Run

```bash
sbproxy serve -f sb.yml
```

The primary upstream `httpbin.org/status/503` is reachable from the public internet, so no local backend is needed.

## Try it

```bash
# Primary returns 503; the proxy substitutes the fallback's static action.
curl -sv -H 'Host: api.local' http://127.0.0.1:8080/ 2>&1 | grep -E '^< HTTP|x-fallback'
# < HTTP/1.1 200 OK
# < x-fallback: true

# Inspect the degraded response body.
curl -s -H 'Host: api.local' http://127.0.0.1:8080/
# {"status":"degraded","message":"primary upstream temporarily unavailable, serving degraded response","retry_after_secs":30}

# The X-Fallback header is the fingerprint that the fallback path fired.
curl -sI -H 'Host: api.local' http://127.0.0.1:8080/ | grep -i x-fallback
# x-fallback: true
```

## What this exercises

- `fallback_origin` block at origin level (sibling of `action`)
- `on_status` list of upstream codes that trigger the fallback
- `on_error: true` for transport-level failure handling
- `add_debug_header` for observability of fallback dispatch
- Inline fallback origin spec with its own `action`

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
