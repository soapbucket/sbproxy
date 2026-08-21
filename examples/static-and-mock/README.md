# Static and mock responses

*Last modified: 2026-08-16*

![Static and mock responses](../../docs/assets/static-and-mock.gif)

Three origins demonstrating the two upstream-free actions. `hello.local` uses the `static` action to return a fixed plain-text body. `api.local` uses the `mock` action to return a structured JSON object with a custom `X-Mock` header and a configured (currently not applied; see below) 50 ms simulated delay. `health.local` uses `static` again, this time with `json_body` to emit a JSON health document. Both actions short-circuit the request before any network call, so they are useful for stubbing dependencies during local development or wiring up a placeholder service ahead of a real implementation.

## Run

```bash
make run CONFIG=examples/static-and-mock/sb.yml
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
content-length: 37
X-Mock: true

{"id":42,"name":"ada","role":"admin"}
```

**SUSPECTED PRODUCT BUG (confirmed, not fixed here):** `delay_ms` currently
does nothing on this request path. Repro: hit the `api.local` origin above
several times with `curl -s -o /dev/null -w '%{time_total}\n' ...`; response
times stay under ~1.2ms regardless of `delay_ms: 50`. The sleep is
implemented in `Action::Mock`'s HTTP/3 handler
(`crates/sbproxy-core/src/dispatch.rs`, ~line 293:
`if let Some(delay_ms) = m.delay_ms { tokio::time::sleep(...).await; }`),
but the HTTP/1.1 and HTTP/2 dispatch path actually serving this example
(`crates/sbproxy-core/src/server/action_dispatch.rs`, `Action::Mock` arm)
never reads `m.delay_ms` at all. HTTP/3 config parses but has no listener in
this build, so `delay_ms` is a no-op in practice today.

```bash
$ curl -i -H 'Host: health.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: application/json

{"status":"ok","version":"1.0"}
```

## What this exercises

- `static` action - returns a fixed `body` with the configured `status` and `content_type`
- `static` action with `json_body` - emits a serialized JSON document with `application/json` content type
- `mock` action - structured JSON response with `headers` injection for custom response headers, and `delay_ms` for simulated latency (currently a no-op on the HTTP/1.1 and HTTP/2 dispatch path; see the bug note above)

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
