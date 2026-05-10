# Forward rules

*Last modified: 2026-04-27*

A single origin on `gateway.local` dispatches incoming requests to three different inline child origins based on path. Requests to `/api/*` proxy to `dummyjson.com` with the `/api` prefix stripped, `/admin/*` returns a static JSON banner, and anything else falls through to the default action that proxies to `httpbin.org/anything`. Forward rules are evaluated in order; first match wins. Each rule embeds a full child origin via the `origin:` field so rules can carry their own action and request modifiers.

## Run

```bash
sbproxy serve -f sb.yml
```

The proxy binds to `127.0.0.1:8080`. Use the `Host: gateway.local` header to land on this origin.

## Try it

```bash
# /api/* rule -> dummyjson.com/products/1 (the /api/ prefix is rewritten away).
curl -s -H 'Host: gateway.local' http://127.0.0.1:8080/api/products/1
# { "id": 1, "title": "Essence Mascara Lash Princess", ... }

# /admin/* rule -> static JSON banner.
curl -s -H 'Host: gateway.local' http://127.0.0.1:8080/admin/dashboard
# {"section":"admin","message":"admin area placeholder","authenticated":false}

# No rule matches -> default action proxies to httpbin.org/anything.
curl -s -H 'Host: gateway.local' http://127.0.0.1:8080/health
# {"args":{},"data":"","headers":{...},"method":"GET","url":"https://httpbin.org/anything/health"}

# Verify the X-Routed-By header set by the /api/* child origin.
curl -s -H 'Host: gateway.local' http://127.0.0.1:8080/api/products/1 -o /dev/null -w '%{http_code}\n'
# 200
```

## What this exercises

- `forward_rules` - path-based dispatch to inline child origins
- `path.prefix` rule matcher
- Inline child `origin:` blocks with their own `action` and `request_modifiers`
- `static` action as a non-proxy default for stub responses
- URL path rewriting via `request_modifiers.url.path.replace`

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
