# Header injection and CORS

*Last modified: 2026-04-27*

Combines three sibling blocks on one origin: `request_modifiers` injects `X-Forwarded-By: sbproxy` and a freshly generated `X-Trace-Id` (from the `uuid()` template helper) onto outbound requests while stripping the `Cookie` header; `response_modifiers` stamps `X-Served-By: sbproxy` and overrides `Cache-Control` on the way back; and `cors` handles preflight `OPTIONS` requests for browser clients on `https://example.com`. The CORS block allowlists three methods and two headers and caches preflight results for 600 seconds.

## Run

```bash
make run CONFIG=examples/05-headers-and-cors/sb.yml
```

No env vars required. Uses `httpbin.org` so you can see the modified request headers reflected back.

## Try it

Inspect what the upstream sees, including the injected request headers:

```bash
$ curl -s -H 'Host: api.local' -H 'Cookie: should-be-stripped=1' \
       http://127.0.0.1:8080/headers
{
  "headers": {
    "Host": "httpbin.org",
    "X-Forwarded-By": "sbproxy",
    "X-Trace-Id": "5b1e9b8a-2c4f-4d2a-9c4e-1f3a8e7d6c5b"
  }
}
```

The `Cookie` header is absent because `request_modifiers.delete` stripped it.

Inspect the response headers added by SBproxy:

```bash
$ curl -is -H 'Host: api.local' http://127.0.0.1:8080/get | head -n 6
HTTP/1.1 200 OK
content-type: application/json
x-served-by: sbproxy
cache-control: public, max-age=60
```

CORS preflight from a browser-style origin:

```bash
$ curl -is -X OPTIONS -H 'Host: api.local' \
       -H 'Origin: https://example.com' \
       -H 'Access-Control-Request-Method: POST' \
       -H 'Access-Control-Request-Headers: Content-Type' \
       http://127.0.0.1:8080/headers
HTTP/1.1 204 No Content
access-control-allow-origin: https://example.com
access-control-allow-methods: GET, POST, OPTIONS
access-control-allow-headers: Content-Type, Authorization
access-control-max-age: 600
```

## What this exercises

- `request_modifiers.headers.set` and `delete` - rewrite outbound request headers
- `{{ uuid() }}` template helper - generate a per-request trace ID
- `response_modifiers.headers.set` - stamp response headers, including overriding `Cache-Control`
- `cors` - preflight handling, allowlisted origins, methods, headers, and `max_age_seconds`

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
