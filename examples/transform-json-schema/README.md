# JSON Schema validation transform

*Last modified: 2026-08-16*

![JSON Schema validation transform](../../docs/assets/transform-json-schema.gif)

Demonstrates the `json_schema` transform. The response body is validated against a JSON Schema compiled once at config-load time (remote `$ref` resolution is disabled, so the schema must be self-contained). Two origins on `127.0.0.1:8080` make the difference visible: `schema-ok.local` returns a body that satisfies the schema, while `schema-bad.local` returns a body whose `id` and `title` fields have the wrong types.

**Known limitation:** with `fail_on_error: true` on a `proxy` action, a schema violation does reject the response with a `502` (verified separately against a real upstream). But both origins in this example use `type: static`, and on a `static` action every transform error (including a `json_schema` failure) is caught, logged as a warning, and discarded: the original (unvalidated) static body is still served with its configured `200` status. See `crates/sbproxy-core/src/server/action_dispatch.rs`, the `Action::Static` arm around the `apply_transform_with_ctx` call (`"static action transform failed, continuing"`). In this build, `fail_on_error` has no effect on `static` actions, so `schema-bad.local` below returns `200` with the invalid body, not `502`.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Valid - all fields match types and required keys are present
$ curl -i -H 'Host: schema-ok.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: application/json

{"id":1,"title":"valid post","userId":1}
```

```bash
# Invalid - id is a string, title is an integer, userId is missing.
# The transform runs, detects the violation, logs a warning ... and the
# static action serves the original body anyway. See "Known limitation"
# above: fail_on_error does not currently reject on a static action.
$ curl -i -H 'Host: schema-bad.local' http://127.0.0.1:8080/
HTTP/1.1 200 OK
content-type: application/json

{"id":"should-be-int-but-is-string","title":42}
```

```bash
# A second hit confirms the (non-)rejection is consistent.
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: schema-bad.local' http://127.0.0.1:8080/
200
```

For comparison, the same `json_schema` + `fail_on_error: true` transform on a `type: proxy`
origin does reject correctly:

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: some-proxy-origin.local' http://127.0.0.1:8080/get
502
```

The 502 body in that case is Pingora's generic synthetic error page
(`content-type: text/plain; charset=utf-8`, body `bad gateway`), not a
`json_schema`-specific message: no source string like "upstream response
failed json_schema validation" exists anywhere in this codebase.

## What this exercises

- `json_schema` transform with an inline `schema` object
- `fail_on_error: true` - short-circuits to a 502 on a `proxy` action; currently a no-op on a `static` action (see "Known limitation")
- Required fields, primitive type checks (`integer`, `string`)
- Two origins on the same listener differentiated by Host header

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
