# Static and mock responses

*Last modified: 2026-04-27*

Three origins demonstrating the two upstream-free actions. `hello.local` uses the `static` action to return a fixed plain-text body. `api.local` uses the `mock` action to return a structured JSON object after a 50 ms simulated delay with a custom `X-Mock` header. `health.local` uses `static` again, this time with `json_body` to emit a JSON health document. Both actions short-circuit the request before any network call, so they are useful for stubbing dependencies during local development or wiring up a placeholder service ahead of a real implementation.

## Run

```bash
make run CONFIG=examples/01-static-and-mock/sb.yml
```

No upstream service required. All responses are generated inside sbproxy.

## Try it

```bash
$ curl -i -H 'Host: hello.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: text/plain
content-length: 19

Hello from sbproxy
```

```bash
$ curl -i -H 'Host: api.local' http://127.0.0.1:8080/users/42
HTTP/1.1 200 OK
content-type: application/json
x-mock: true

{"id":42,"name":"ada","role":"admin"}
```

The response is delayed roughly 50 ms by the configured `delay_ms`.

```bash
$ curl -i -H 'Host: health.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: application/json

{"status":"ok","version":"1.0"}
```

## What this exercises

- `static` action - returns a fixed `body` with the configured `status` and `content_type`
- `static` action with `json_body` - emits a serialised JSON document with `application/json` content type
- `mock` action - structured JSON response with `delay_ms` and `headers` injection for simulated latency and custom response headers

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
