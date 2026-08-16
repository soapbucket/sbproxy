# Request validator

*Last modified: 2026-08-16*

![Request validator](../../docs/assets/request-validator.gif)

The `request_validator` policy on `localhost` validates inbound JSON request bodies against a JSON Schema before they reach the upstream. The schema is compiled at config load, so each request is a cheap dispatch. Only requests whose `Content-Type` matches `application/json` are validated; other media types pass through untouched. The schema requires `name` (string, 1-100 chars) and `age` (integer, 0-150) with no additional properties. Empty bodies and non-JSON bodies are rejected. Remote `$ref` resolution is disabled at the workspace level so a malicious schema cannot become an SSRF primitive. The rejection response is `{"error":"request body validation failed","detail":"..."}`, where `detail` embeds the validation failure's JSON path when the schema keyword that failed reports one (`/age` for a type or range mismatch); a `required` or `additionalProperties` failure has no path of its own, since the offending property is missing or extra, so `detail` reports the root. The offending value itself is never echoed back.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Valid payload -> upstream sees it.
curl -i -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":30}' \
     http://127.0.0.1:8080/anything
# HTTP/1.1 200 OK
# (the shared test.sbproxy.dev fixture returns 200 for any /anything
# path; it does not currently echo the request body)

# Missing required field -> 400. The failure location lands in
# `detail`, embedded in the message rather than a separate field; a
# `required` failure has no instance path of its own (the missing
# property does not exist in the body), so it reports the root.
curl -i -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"age":30}' \
     http://127.0.0.1:8080/anything
# HTTP/1.1 400 Bad Request
# content-type: application/json
#
# {"error":"request body validation failed","detail":"request body failed schema validation at "}

# Type mismatch.
curl -i -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":"thirty"}' \
     http://127.0.0.1:8080/anything
# HTTP/1.1 400 Bad Request
# {"error":"request body validation failed","detail":"request body failed schema validation at /age"}

# Out-of-range integer.
curl -i -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":300}' \
     http://127.0.0.1:8080/anything
# HTTP/1.1 400 Bad Request
# {"error":"request body validation failed","detail":"request body failed schema validation at /age"}

# additionalProperties: false rejects unknown fields. Like the
# `required` case, this fails at the object root, so `detail` again
# reports an empty location.
curl -i -H 'Host: localhost' -H 'Content-Type: application/json' \
     -d '{"name":"alice","age":30,"role":"admin"}' \
     http://127.0.0.1:8080/anything
# HTTP/1.1 400 Bad Request
# {"error":"request body validation failed","detail":"request body failed schema validation at "}

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
