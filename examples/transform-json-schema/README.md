# JSON Schema validation transform

*Last modified: 2026-08-20*

![JSON Schema validation transform](../../docs/assets/transform-json-schema.gif)

Demonstrates the `json_schema` transform. The response body is validated against a JSON Schema compiled once at config-load time (remote `$ref` resolution is disabled, so the schema must be self-contained). Two origins on `127.0.0.1:8080` make the difference visible: `schema-ok.local` returns a body that satisfies the schema, while `schema-bad.local` returns a body whose `id` and `title` fields have the wrong types.

Both origins carry `fail_on_error: true`, which resolves to the `closed` failure posture. A `closed` transform's contract is that the client never sees the untransformed body, and that now holds on a `static` action as well as a proxied one. Earlier builds caught the failure on a `static` action, logged a warning, and served the invalid body with its configured `200` anyway; the transcripts below are the current behavior.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

Every block below carries a `CAPTURE` marker, so `scripts/check-doc-captures.py`
replays the command against a real build and diffs it against the output shown.
This page is the reason that matters: it spent an unknown stretch documenting
the opposite of what the code did, and no lane could tell.

A valid body. All fields match their types and every required key is present,
so the transform passes it through untouched:

<!-- CAPTURE: curl -is -H 'Host: schema-ok.local' http://127.0.0.1:8080/ -->

```text
HTTP/1.1 200 OK
content-type: application/json
content-length: 40
Date: <DATE>
Connection: keep-alive

{"id":1,"title":"valid post","userId":1}
```

An invalid body. `id` is a string, `title` is an integer, and `userId` is
missing. The transform detects the violation and the `closed` posture refuses
the response; the invalid body is never written:

<!-- CAPTURE: curl -is -H 'Host: schema-bad.local' http://127.0.0.1:8080/ -->

```text
HTTP/1.1 500 Internal Server Error
content-type: application/json
content-length: 33
x-sbproxy-transform-error: json_schema
Date: <DATE>
Connection: keep-alive

{"error":"internal server error"}
```

`x-sbproxy-transform-error` names the transform that refused, so a caller
looking at a generic error envelope can still tell which one it was. The
matching log line names the origin and the exact schema path that failed:

```
WARN generated-response transform failed; response failed by failure_posture
     hostname=schema-bad.local transform="json_schema"
     error=json schema validation failed at /id failure_posture="closed"
```

A second hit, to show the rejection is consistent rather than first-request
luck:

<!-- CAPTURE: curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: schema-bad.local' http://127.0.0.1:8080/ -->

```text
500
```

For comparison, the same `json_schema` + `fail_on_error: true` transform on a
`type: proxy` origin also refuses, but with a different status and body. This
one runs against a different config (a `type: proxy` origin pointed at an
upstream that serves the same invalid body), so it is shown rather than
replayed here; `e2e/tests/transform_json.rs` is what holds it:

```text
HTTP/1.1 502 Bad Gateway
content-type: text/plain; charset=utf-8
content-length: 11

bad gateway
```

The difference is where the refusal happens, not whether it happens. A
`static` action answers in the request phase, so the status line is still the
proxy's to write and it writes a `500` with the attribution header. A proxied
response has already had the upstream's headers committed by the time the
transform runs on the buffered body, so the only safe refusal is to end the
stream, which pingora renders as its generic `502` synthetic page. Neither
one leaks the offending payload, which is the property that matters.

## What this exercises

- `json_schema` transform with an inline `schema` object
- `fail_on_error: true`, the legacy spelling of `failure_posture: closed`, enforced on a `static` action and on a `proxy` one
- The `x-sbproxy-transform-error` attribution header on a refused generated response
- Required fields, primitive type checks (`integer`, `string`)
- Two origins on the same listener differentiated by Host header

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
- [docs/transforms.md](../../docs/transforms.md) - failure postures across every transform type
