# Request modifiers

*Last modified: 2026-04-27*

Demonstrates the full typed shape of `request_modifiers`. On the way to the upstream, the proxy sets `X-Source: sbproxy` and `Content-Type: application/json`, adds `X-Trace-Id: trace-001`, and removes `X-Internal-Token`. The URL path swap rewrites `/old/` to `/new/`, the query block sets `tenant=prod`, adds `extra=1`, and strips `debug`. The method is overridden to `POST` and the body is replaced with `{"injected":true,"source":"proxy"}`. The upstream is `httpbin.org`, which echoes back what it observed so each rewrite is verifiable. Origin is reached on `127.0.0.1:8080` via the `api.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Send a GET to /old/anything?debug=1&keep=yes; httpbin echoes back what it
# actually received after the modifier ran.
$ curl -s -H 'Host: api.local' -H 'X-Internal-Token: secret' \
       'http://127.0.0.1:8080/old/anything?debug=1&keep=yes' | jq
{
  "args": {
    "extra": "1",
    "keep": "yes",
    "tenant": "prod"
  },
  "data": "{\"injected\":true,\"source\":\"proxy\"}",
  "headers": {
    "Content-Type": "application/json",
    "Host": "httpbin.org",
    "X-Source": "sbproxy",
    "X-Trace-Id": "trace-001"
  },
  "json": {
    "injected": true,
    "source": "proxy"
  },
  "method": "POST",
  "url": "https://httpbin.org/new/anything?tenant=prod&keep=yes&extra=1"
}
```

```bash
# Path swap is visible in the echoed URL
$ curl -s -H 'Host: api.local' 'http://127.0.0.1:8080/old/anything' | jq -r '.url'
https://httpbin.org/new/anything?tenant=prod&extra=1
```

```bash
# Method was rewritten from GET to POST
$ curl -s -H 'Host: api.local' 'http://127.0.0.1:8080/old/anything' | jq -r '.method'
POST
```

```bash
# X-Internal-Token was stripped, X-Source and X-Trace-Id were attached
$ curl -s -H 'Host: api.local' -H 'X-Internal-Token: secret' \
       'http://127.0.0.1:8080/old/anything' \
  | jq '.headers | with_entries(select(.key | test("X-(Internal|Source|Trace)")))'
{
  "X-Source": "sbproxy",
  "X-Trace-Id": "trace-001"
}
```

## What this exercises

- `request_modifiers.headers` - `set`, `add`, and `remove` operations
- `request_modifiers.url.path.replace` - in-place path rewrite
- `request_modifiers.query` - `set`, `add`, and `remove` for query parameters
- `request_modifiers.method` - HTTP method override
- `request_modifiers.body.replace_json` - whole-body JSON replacement
- Composition with the `proxy` action - all rewrites apply before the upstream is contacted

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
