# OpenAPI 3.0 emission

*Last modified: 2026-08-27*

The gateway publishes an OpenAPI 3.0 document describing the routes it exposes, derived from the live config. Three things land together: rich path matchers (`template` for `/users/{id}`, `regex` as the escape hatch, plus `prefix` and `exact`, with per-segment regex constraints supported inline as `{id:[0-9]+}`); OpenAPI Parameter Object declarations on each forward rule that mirror the spec verbatim and pass through directly into `parameters[]`; and two emit surfaces, one admin-only at `GET /api/openapi.{json,yaml}` (basic auth, all hosts) and one per-host at `GET /.well-known/openapi.{json,yaml}` opt-in via `expose_openapi: true` on the origin. Prefix matchers carry the `x-sbproxy-prefix-match` extension because OpenAPI has no native concept of "starts-with"; whole-path regex matchers carry `x-sbproxy-regex-path` and named captures become path parameters.

## Run

```bash
sbproxy serve -f sb.yml
```

The example enables the admin listener on port 9090 (defaults `admin:changeme`) and opts the origin into per-host emission.

## Try it

```bash
# Per-host emission (public, opt-in via expose_openapi: true).
curl -s -H 'Host: api.localhost' \
  http://127.0.0.1:8080/.well-known/openapi.json | jq '.paths | keys'
# [
#   "/__regex__/^_v(?P<version>[0-9]+)_items",
#   "/api/",
#   "/health",
#   "/static/{*rest}",
#   "/users/{id:[0-9]+}/posts/{post_id}"
# ]
```

Template and prefix matchers land in `paths` verbatim, regex constraints included (`{id:[0-9]+}`, `{*rest}`); the `regex:` matcher has no standard OpenAPI path syntax to borrow, so it gets a synthetic `/__regex__/<pattern>` key carrying the raw pattern in `x-sbproxy-regex-path`, and the prefix matcher (`/api/`) gets `x-sbproxy-prefix-match: true`.

```bash
# Truncated JSON for a single path showing the Parameter Objects.
curl -s -H 'Host: api.localhost' \
  http://127.0.0.1:8080/.well-known/openapi.json \
  | jq '.paths."/users/{id:[0-9]+}/posts/{post_id}".get.parameters'
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

```bash
# The second host carries an `authentication:` block, so its document
# publishes the scheme a caller has to satisfy: the header name, and
# nothing else from the auth config.
curl -s -H 'Host: secure.localhost' \
     http://127.0.0.1:8080/.well-known/openapi.json \
  | jq '.components.securitySchemes'
# {
#   "secure-localhost_auth": {
#     "type": "apiKey",
#     "in": "header",
#     "name": "X-Acme-Key",
#     "x-sbproxy-auth-type": "api_key"
#   }
# }
```

The keys themselves are not in there, and nothing else in this document
is either: `/.well-known/openapi.json` is served unauthenticated, so a
mapper publishes only what a client cannot call the API without.

## What this exercises

- `expose_openapi: true` per-origin opt-in for `/.well-known/openapi.{json,yaml}`
- `proxy.admin` admin listener serving `/api/openapi.{json,yaml}` with basic auth
- Templated path matchers (`template: /users/{id:[0-9]+}/posts/{post_id}`) with per-segment regex constraints
- Catch-all matchers (`template: /static/{*rest}`) and whole-path regex (`regex: ^/v(?P<version>[0-9]+)/items`)
- Parameter Object declarations on forward rules passed through verbatim into the emitted spec
- Vendor extensions `x-sbproxy-prefix-match` and `x-sbproxy-regex-path` for non-standard matcher shapes
- `securitySchemes` emission from an `authentication:` block, on the `secure.localhost` host

## See also

- [docs/openapi-emission.md](../../docs/openapi-emission.md)
- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
