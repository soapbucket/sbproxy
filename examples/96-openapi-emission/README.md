# OpenAPI 3.0 emission

*Last modified: 2026-04-27*

The gateway publishes an OpenAPI 3.0 document describing the routes it exposes, derived from the live config. Three things land together: rich path matchers (`template` for `/users/{id}`, `regex` as the escape hatch, plus `prefix` and `exact`, with per-segment regex constraints supported inline as `{id:[0-9]+}`); OpenAPI Parameter Object declarations on each forward rule that mirror the spec verbatim and pass through directly into `parameters[]`; and two emit surfaces, one admin-only at `GET /api/openapi.{json,yaml}` (basic auth, all hosts) and one per-host at `GET /.well-known/openapi.{json,yaml}` opt-in via `expose_openapi: true` on the origin. Prefix matchers carry the `x-sbproxy-prefix-match` extension because OpenAPI has no native concept of "starts-with"; whole-path regex matchers carry `x-sbproxy-regex-path` and named captures become path parameters.

## Run

```bash
sb run -c sb.yml
```

The example enables the admin listener on port 9090 (defaults `admin:changeme`) and opts the origin into per-host emission.

## Try it

```bash
# Per-host emission (public, opt-in via expose_openapi: true).
curl -s -H 'Host: api.localhost' \
  http://127.0.0.1:8080/.well-known/openapi.json | jq '.paths | keys'
# [
#   "/health",
#   "/users/{id}/posts/{post_id}",
#   "/static/{rest}",
#   "/v{version}/items"
# ]
```

```bash
# Truncated JSON for a single path showing the Parameter Objects.
curl -s -H 'Host: api.localhost' \
  http://127.0.0.1:8080/.well-known/openapi.json \
  | jq '.paths."/users/{id}/posts/{post_id}".get.parameters'
# [
#   { "name": "id", "in": "path", "required": true,
#     "schema": { "type": "integer", "format": "int64" } },
#   { "name": "post_id", "in": "path", "required": true,
#     "schema": { "type": "string" } },
#   { "name": "include", "in": "query", "required": false,
#     "schema": { "type": "string" } }
# ]
```

```bash
# Admin emission (basic auth, all hosts).
curl -s -u admin:changeme http://127.0.0.1:9090/api/openapi.json | jq '.info'
```

```bash
# Exercise the templated route. The :[0-9]+ constraint validates `id`
# at request time; non-numeric ids fall through to the next rule.
curl -s -H 'Host: api.localhost' \
     http://127.0.0.1:8080/users/42/posts/abc | jq .url
```

## What this exercises

- `expose_openapi: true` per-origin opt-in for `/.well-known/openapi.{json,yaml}`
- `proxy.admin` admin listener serving `/api/openapi.{json,yaml}` with basic auth
- Templated path matchers (`template: /users/{id:[0-9]+}/posts/{post_id}`) with per-segment regex constraints
- Catch-all matchers (`template: /static/{*rest}`) and whole-path regex (`regex: ^/v(?P<version>[0-9]+)/items`)
- Parameter Object declarations on forward rules passed through verbatim into the emitted spec
- Vendor extensions `x-sbproxy-prefix-match` and `x-sbproxy-regex-path` for non-standard matcher shapes

## See also

- [docs/openapi-emission.md](../../docs/openapi-emission.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
