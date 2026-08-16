# Request modifiers

*Last modified: 2026-08-16*

![Request modifiers](../../docs/assets/request-modifiers.gif)

Demonstrates the full typed shape of `request_modifiers`. On the way to the upstream, the proxy sets `X-Source: sbproxy` and `Content-Type: application/json`, adds `X-Trace-Id: trace-001`, and removes `X-Internal-Token`. The URL path swap rewrites `/old/` to the upstream's real `/anything/` echo route, the query block sets `tenant=prod`, adds `extra=1`, and strips `debug`. The method is overridden to `POST` and the body is replaced with `{"injected":true,"source":"proxy"}`. The upstream is `test.sbproxy.dev`, which echoes back the method, URL, and headers it observed, so every rewrite except the body is directly verifiable from the response (it does not echo the request body back). Origin is reached on `127.0.0.1:8080` via the `api.local` Host header.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

The upstream's echo response has the shape `{method, url, headers, query, timestamp}` (not `args`/`data`/`json`, and it does not echo the request body back at all), and it reports header names lowercased. `test.sbproxy.dev/anything/<segment>` is itself a dynamic route on the upstream that captures `<segment>` into a `path` query parameter; that extra `path=anything` in the query below comes from the upstream's own routing, not from this example's `request_modifiers`.

```bash
# Send a GET to /old/anything?debug=1&keep=yes; the test service echoes what it
# actually received after the modifier ran. Filtered to the fields under test;
# `.headers` carries dozens of upstream-injected x-vercel-* entries otherwise.
$ curl -s -H 'Host: api.local' -H 'X-Internal-Token: secret' \
       'http://127.0.0.1:8080/old/anything?debug=1&keep=yes' \
  | jq '{method, url, query, headers: (.headers | with_entries(select(.key | test("^x-(source|trace-id|internal-token)$"))))}'
{
  "method": "POST",
  "url": "/anything/anything?keep=yes&tenant=prod&extra=1&path=anything",
  "query": {
    "keep": "yes",
    "tenant": "prod",
    "extra": "1",
    "path": "anything"
  },
  "headers": {
    "x-trace-id": "trace-001",
    "x-source": "sbproxy"
  }
}
```

```bash
# Path swap is visible in the echoed URL (still relative; the upstream doesn't
# echo scheme/host)
$ curl -s -H 'Host: api.local' 'http://127.0.0.1:8080/old/anything' | jq -r '.url'
/anything/anything?tenant=prod&extra=1&path=anything
```

```bash
# Method was rewritten from GET to POST
$ curl -s -H 'Host: api.local' 'http://127.0.0.1:8080/old/anything' | jq -r '.method'
POST
```

```bash
# X-Internal-Token was stripped, X-Source and X-Trace-Id were attached.
# Header names come back lowercased, so the filter matches on that case.
$ curl -s -H 'Host: api.local' -H 'X-Internal-Token: secret' \
       'http://127.0.0.1:8080/old/anything' \
  | jq '.headers | with_entries(select(.key | test("x-(internal|source|trace)")))'
{
  "x-trace-id": "trace-001",
  "x-source": "sbproxy"
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
