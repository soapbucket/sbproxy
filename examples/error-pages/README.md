# Error pages

*Last modified: 2026-08-21*

![Error pages](../../docs/assets/error-pages.gif)

The origin on `api.local` is protected by API key authentication (`X-Api-Key: secret-key`). Requests that miss the key get a 401 from the proxy, which then runs through the `error_pages` table. Two 401 entries cover JSON and HTML representations using `Accept` content negotiation, and a 403 entry catches forbidden responses. Templated entries interpolate `{{ status_code }}` and `{{ request.path }}`. `error_pages` only intercepts errors the proxy itself generates on this origin (authentication denials and `policies:` refusals), not upstream-returned status codes. The 404 for a `Host` matching no origin is outside it too: that answer is written before any origin's config is resolved.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Successful path: the upstream is reached when the API key is present.
curl -sv -H 'Host: api.local' -H 'X-Api-Key: secret-key' http://127.0.0.1:8080/get 2>&1 | grep '^< HTTP'
# < HTTP/1.1 200 OK

# 401 with Accept: application/json -> JSON entry, templated.
curl -s -H 'Host: api.local' -H 'Accept: application/json' http://127.0.0.1:8080/get
# {"error":"unauthorized","status":401,"path":"/get"}

# 401 with Accept: text/html -> HTML entry, templated.
curl -s -H 'Host: api.local' -H 'Accept: text/html' http://127.0.0.1:8080/get
# <!doctype html>
# <html><head><title>Unauthorized</title></head>
# <body>
#   <h1>401 unauthorized</h1>
#   <p>The request to /get requires an X-Api-Key header.</p>
# </body></html>

# 401 with no Accept header -> JSON wins by default.
curl -s -H 'Host: api.local' http://127.0.0.1:8080/get
# {"error":"unauthorized","status":401,"path":"/get"}
```

## What this exercises

- `error_pages` table on the origin
- Content negotiation by `content_type` and `Accept`
- `template: true` with `{{ status_code }}` and `{{ request.path }}` interpolation
- Status list shorthand (`status: [403]`)
- Composition with `authentication.api_key`

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
