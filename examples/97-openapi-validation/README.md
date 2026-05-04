# OpenAPI 3.0 schema validation

*Last modified: 2026-04-27*

The `openapi_validation` policy loads an inline OpenAPI document at startup and validates each request body against the matching operation's `requestBody` schema. Requests whose path and method are not described in the spec, or whose `Content-Type` has no schema, are passed through unchanged. `mode: enforce` (default) returns the configured `status` on validation failure; `mode: log` writes a structured warn under the `sbproxy::openapi_validation` tracing target and forwards the request anyway. Useful for shifting body validation out of every backend service and into the edge.

## Run

```bash
sb run -c sb.yml
```

The example serves a static `{"ok":true}` response for any path that passes validation, so you can exercise the policy without a real backend.

## Try it

```bash
# Valid body matches the schema (name string, age in range) - 200.
curl -i -H 'Host: api.local' \
     -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":30}' \
     http://127.0.0.1:8080/users/42
# HTTP/1.1 200 OK
# {"ok":true}
```

```bash
# Missing required field `name` - 400 with schema-violation details.
curl -i -H 'Host: api.local' \
     -H 'Content-Type: application/json' \
     -d '{"age":30}' \
     http://127.0.0.1:8080/users/42
# HTTP/1.1 400 Bad Request
# {"error":"openapi validation failed","details":[
#   {"path":"/","keyword":"required","message":"missing field: name"}
# ]}
```

```bash
# Type violation (age must be an integer) - 400.
curl -i -H 'Host: api.local' \
     -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":"thirty"}' \
     http://127.0.0.1:8080/users/42
```

```bash
# Path not described in the spec - passes through untouched.
curl -i -H 'Host: api.local' http://127.0.0.1:8080/health
# HTTP/1.1 200 OK
```

## What this exercises

- `policy.type: openapi_validation` with `mode: enforce`
- Inline `spec` (OpenAPI 3.0.3) with a single `POST /users/{id}` operation
- JSON Schema validation of `requestBody.content.application/json.schema` (required, additionalProperties, type, range)
- Pass-through for paths or content types not described in the spec

## See also

- [docs/openapi-validation.md](../../docs/openapi-validation.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
