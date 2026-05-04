# JSON Schema validation transform

*Last modified: 2026-04-27*

Demonstrates the `json_schema` transform. The upstream JSON response body is validated against a JSON Schema compiled once at config-load time (remote `$ref` resolution is disabled, so the schema must be self-contained). Two origins on `127.0.0.1:8080` make the difference visible: `schema-ok.local` returns a body that satisfies the schema, while `schema-bad.local` returns a body whose `id` and `title` fields have the wrong types. With `fail_on_error: true`, a schema violation rejects the response and the proxy returns a synthetic `502`.

## Run

```bash
sb run -c sb.yml
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
# The transform runs after the static action, sees the violation, and
# rewrites the response to a 502.
$ curl -i -H 'Host: schema-bad.local' http://127.0.0.1:8080/
HTTP/1.1 502 Bad Gateway
content-type: text/plain

upstream response failed json_schema validation
```

```bash
# A second hit confirms the failure is consistent.
$ curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: schema-bad.local' http://127.0.0.1:8080/
502
```

## What this exercises

- `json_schema` transform with an inline `schema` object
- `fail_on_error: true` - violations short-circuit to a synthetic 502 instead of passing through
- Required fields, primitive type checks (`integer`, `string`)
- Two origins on the same listener differentiated by Host header

## See also

- [docs/features.md](../../docs/features.md) - full feature reference
- [docs/configuration.md](../../docs/configuration.md) - configuration schema
