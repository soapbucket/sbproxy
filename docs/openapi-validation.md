# OpenAPI schema validation

*Last modified: 2026-07-09*

The `openapi_validation` policy loads an OpenAPI 3.0 document at startup and validates each incoming request body against the matching operation's `requestBody` schema. Requests whose path + method are not described in the spec, or whose `Content-Type` has no schema, are passed through untouched, with one exception: when the matched operation declares `requestBody.required: true`, a request whose `Content-Type` matches no schema is rejected rather than passed through.

Use it to:

- Block malformed payloads at the edge before they reach a backend.
- Enforce additive schema discipline: a new field or a tightened `enum` that does not roll out everywhere yet still rejects bad calls in production.
- Run in `log` mode against a staging deployment to learn which clients are out of contract before turning enforcement on.

## Policy fields

| Field | Default | Description |
|-------|---------|-------------|
| `spec` | (required, or `spec_file`) | Inline OpenAPI 3.0 document as a YAML object. |
| `spec_file` | (required, or `spec`) | Path to a JSON or YAML OpenAPI document. The file is read once at startup. |
| `mode` | `enforce` | `enforce` rejects mismatched bodies; `log` writes a warning and forwards the request. |
| `status` | `400` | Status code returned in `enforce` mode when validation fails. |
| `error_body` | (auto) | Optional fixed body for the rejection response. Defaults to a JSON object naming the failing JSON pointer. |
| `error_content_type` | `application/json` | `Content-Type` for the rejection body. |

## How requests are matched

OpenAPI path templates like `/users/{id}` are compiled to anchored regexes (`^/users/[^/]+$`) at startup. A request matches when:

1. Its path matches one of the compiled templates.
2. The corresponding operation has the request method.
3. The request `Content-Type` (leading media type, parameters stripped) matches a key under that operation's `requestBody.content`.

If any of these is missing, the policy treats the request as out of scope and forwards it without inspection, with one exception: when the operation's spec declares `requestBody.required: true`, a matched path + method whose `Content-Type` matches no schema (absent, wrong, or unsupported) fails validation instead of passing through. Otherwise a client could skip the body contract by sending an unexpected `Content-Type`.

## Schema enforcement

JSON Schema validation runs through the `jsonschema` crate with remote `$ref` resolution disabled, so an attacker-controlled spec cannot become an SSRF primitive. Schemas are compiled once at config-load time, which keeps the per-request hot path cheap.

The rejection body lists the failing JSON pointer (e.g. `/age`) but never echoes the offending value back to the caller, so a probing client cannot use error messages to confirm guesses.

## Example

![a spec-conformant JSON body accepted, then a body missing a required field rejected at the edge](assets/openapi-validation.gif)

Paths and methods outside the spec pass through untouched ([config](../examples/openapi-validation/)).

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: "https://backend.internal"
    policies:
      - type: openapi_validation
        mode: enforce
        status: 422
        spec:
          openapi: "3.0.3"
          info: {title: my-api, version: "1.0"}
          paths:
            "/users/{id}":
              post:
                requestBody:
                  required: true
                  content:
                    application/json:
                      schema:
                        type: object
                        required: [name]
                        additionalProperties: false
                        properties:
                          name: {type: string, minLength: 1}
                          age:  {type: integer, minimum: 0, maximum: 150}
```

A clean `POST /users/42` with `{"name":"alice","age":30}` is forwarded; `{"age":30}` is rejected with `422` and a JSON body naming `/name`.

A working example config lives at `examples/openapi-validation/sb.yml`.

## Limitations

- Only `requestBody` schemas are enforced. `parameters` (path / query / header) are not yet validated by this policy.
- `$ref` resolution is local to the document. External `$ref` URLs are not fetched.
- The first failing JSON pointer is returned. The full error list is suppressed to keep the surface area an attacker can probe small.
