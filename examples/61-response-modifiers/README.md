# Response modifiers

*Last modified: 2026-04-27*

Demonstrates the full typed shape of `response_modifiers` across two origins on `127.0.0.1:8080`. `api.local` keeps the upstream `200`, sets `X-Served-By: sbproxy` and `Cache-Control: public, max-age=60`, adds `X-Trace-Id: trace-002`, removes `Content-Length` / `Server` / `X-Powered-By`, and replaces the body with `{"ok":true,"replaced_by":"sbproxy"}`. `text.local` overrides the status line to `418 I am a teapot`, switches `Content-Type` to `text/plain; charset=utf-8`, removes `Content-Length`, and replaces the body with the literal string `short and stout`. Both upstreams are `httpbin.org`.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# JSON path: upstream status preserved, headers rewritten, body replaced with JSON
$ curl -i -H 'Host: api.local' http://127.0.0.1:8080/get
HTTP/1.1 200 OK
content-type: application/json
x-served-by: sbproxy
cache-control: public, max-age=60
x-trace-id: trace-002

{"ok":true,"replaced_by":"sbproxy"}
```

```bash
# Original upstream Server / X-Powered-By / Content-Length are gone
$ curl -sI -H 'Host: api.local' http://127.0.0.1:8080/get | grep -iE '^(server|x-powered-by|content-length):'
# (no output - all three were stripped by the modifier)
```

```bash
# Text path: status line rewritten to 418, body is a literal plaintext string
$ curl -i -H 'Host: text.local' http://127.0.0.1:8080/get
HTTP/1.1 418 I am a teapot
content-type: text/plain; charset=utf-8

short and stout
```

```bash
# Confirm the new status line
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: text.local' http://127.0.0.1:8080/get
418
```

## What this exercises

- `response_modifiers.headers` - `set`, `add`, and `remove` operations
- `response_modifiers.status` - `code` and `text` override of the response status line
- `response_modifiers.body.replace_json` and `response_modifiers.body.replace` - JSON and string body replacement
- Dropping `Content-Length` when rewriting the body so the response falls back to chunked transfer
- Two origins on the same listener differentiated by Host header

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
