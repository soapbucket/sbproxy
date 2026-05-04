# Request validator

*Last modified: 2026-04-27*

The `request_validator` policy on `localhost` validates inbound JSON request bodies against a JSON Schema before they reach the upstream. The schema is compiled at config load, so each request is a cheap dispatch. Only requests whose `Content-Type` matches `application/json` are validated; other media types pass through untouched. The schema requires `name` (string, 1-100 chars) and `age` (integer, 0-150) with no additional properties. Empty bodies and non-JSON bodies are rejected. Remote `$ref` resolution is disabled at the workspace level so a malicious schema cannot become an SSRF primitive. The rejection response includes the validation failure location (JSON path) but never the offending value.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Valid payload -> upstream sees it.
curl -i -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":30}' \
     http://127.0.0.1:8080/anything
# HTTP/1.1 200 OK
# (httpbin echoes the request)

# Missing required field -> 400.
curl -i -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"age":30}' \
     http://127.0.0.1:8080/anything
# HTTP/1.1 400 Bad Request
# content-type: application/json
#
# {"error":"validation_failed","location":"/name","reason":"required"}

# Type mismatch.
curl -i -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":"thirty"}' \
     http://127.0.0.1:8080/anything
# HTTP/1.1 400 Bad Request
# {"error":"validation_failed","location":"/age","reason":"type"}

# Out-of-range integer.
curl -i -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":300}' \
     http://127.0.0.1:8080/anything
# HTTP/1.1 400 Bad Request
# {"error":"validation_failed","location":"/age","reason":"maximum"}

# additionalProperties: false rejects unknown fields.
curl -i -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":30,"role":"admin"}' \
     http://127.0.0.1:8080/anything
# HTTP/1.1 400 Bad Request
# {"error":"validation_failed","location":"/role","reason":"additionalProperties"}

# Non-JSON content type -> validator skips, upstream sees it.
curl -i -H 'Host: localhost' -H 'Content-Type: text/plain' \
     -d 'plaintext' \
     http://127.0.0.1:8080/anything
# HTTP/1.1 200 OK
```

## What this exercises

- `policies[].type: request_validator`
- `content_types` allowlist (only matching types are validated)
- `schema` block compiled once at config load
- `status` and `error_content_type` on rejection
- JSON-path location reporting without leaking attacker-controlled values
- Workspace-level remote `$ref` blocking (SSRF prevention)

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
