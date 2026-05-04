# OpenAPI Emission
*Last modified: 2026-05-03*

SBproxy documents and governs your API. It does not just proxy it.

When you put SBproxy in front of an upstream service, the gateway already knows the routes, the auth schemes, the rate limits, and the response cache. OpenAPI emission turns that knowledge into a published OpenAPI 3.0 document that buyers can consume with standard tooling (Postman, Swagger UI, ReadMe.io, Stainless, SDK generators) without ever seeing your YAML config or talking to the upstream.

The result: SBproxy is the single source of truth for what your API looks like, on the wire, right now.

## What gets emitted

The gateway derives every part of the document from its compiled config. Each row maps a configuration source to its OpenAPI target.

| Source                                        | OpenAPI target                                |
|-----------------------------------------------|-----------------------------------------------|
| `CompiledOrigin.hostname`                     | `servers[].url`                               |
| Forward rule `template` matcher               | `paths` key (template syntax verbatim)        |
| Forward rule `exact` matcher                  | `paths` key                                   |
| Forward rule `prefix` matcher                 | `paths` key + `x-sbproxy-prefix-match: true`  |
| Forward rule `regex` matcher                  | Synthetic key + `x-sbproxy-regex-path` extension |
| `allowed_methods`                             | `Operation` per method                        |
| Rule-level `parameters`                       | `parameters[]` per operation                  |
| `auth_config`                                 | `securitySchemes` + `security`                |
| `response_cache.cacheable_status`             | `responses` keys                              |
| `error_pages` keys                            | `responses` keys                              |
| `cors`                                        | `x-sbproxy-cors` extension                    |

Coverage is bounded by what the gateway config knows. Upstream request and response body schemas are not described unless you declare them explicitly (or feed in an upstream OpenAPI spec via the existing consumption path).

## Where to read it

Two surfaces are available.

### Admin endpoint (all hosts, basic auth)

```bash
curl -s -u admin:changeme http://127.0.0.1:9090/api/openapi.json | jq
curl -s -u admin:changeme http://127.0.0.1:9090/api/openapi.yaml
```

Requires `proxy.admin.enabled: true`. The rendered document is cached per pipeline revision; reloads invalidate the cache, idle requests cost nothing. This is the surface most operators use.

### Per-host (public, opt-in)

```bash
curl -s -H 'Host: api.localhost' \
  http://127.0.0.1:8080/.well-known/openapi.json
```

Off by default. Set `expose_openapi: true` on the origin to publish. Useful for SDK generators, contract testing, and buyer-side discovery without coupling consumers to the admin API.

```yaml
origins:
  "api.example.com":
    expose_openapi: true
    action: { type: proxy, url: http://upstream }
```

## Path matchers

Forward rules accept four matcher shapes, ordered cheapest-first on the hot path:

```yaml
forward_rules:
  - rules:
      # Exact: byte-for-byte equality with the request path.
      - path: { exact: /health }

      # Prefix: starts-with check. Annotated as `x-sbproxy-prefix-match`
      # in the emitted spec since OpenAPI has no native concept.
      - path: { prefix: /api/ }

      # Template: OpenAPI-style path template. Named segments,
      # catch-all (`{*rest}`), and per-segment regex constraints
      # (`{id:[0-9]+}`). Lands as a `paths` key verbatim.
      - path: { template: /users/{id:[0-9]+}/posts/{post_id} }

      # Regex: whole-path escape hatch. Lands under a synthetic path
      # key with the pattern preserved as an `x-sbproxy-regex-path`
      # extension. Use named captures (`?P<name>`) to surface params.
      - path: { regex: '^/v(?P<version>[0-9]+)/items' }
    origin:
      action: { type: proxy, url: http://upstream }
```

Captured params (template named segments, regex named captures) flow into the request context as `path_params` and become available to request modifiers, CEL expressions, Lua / JavaScript / WASM scripts, and metrics labels.

## Parameter declarations

Each forward rule may carry a list of OpenAPI 3.0 Parameter Objects that describe its parameters. Field names mirror the spec verbatim:

```yaml
forward_rules:
  - rules:
      - path: { template: /users/{id} }
    parameters:
      - name: id
        in: path
        required: true
        description: Numeric user identifier.
        schema:
          type: integer
          format: int64
      - name: include
        in: query
        required: false
        description: Comma-separated list of related resources to embed.
        schema:
          type: string
    origin:
      action: { type: proxy, url: http://upstream }
```

Supported `in:` values are `path`, `query`, and `header`. Cookie parameters are not yet captured.

## Auth scheme mappings

Auth blocks turn into OpenAPI `securitySchemes` and a `security` requirement attached to each operation. The mapping covers every auth type the gateway implements:

| Auth type           | OpenAPI shape                                                      |
|---------------------|--------------------------------------------------------------------|
| `api_keys`          | `apiKey` in header (uses `header:` from config)                    |
| `basic_auth`        | `http` scheme `basic`                                              |
| `bearer`            | `http` scheme `bearer`                                             |
| `jwt`               | `http` scheme `bearer` + `bearerFormat: JWT`                       |
| `digest`            | `http` scheme `digest`                                             |
| `oauth_client_creds`| `oauth2` with `clientCredentials` flow + `tokenUrl`                |
| `kya`               | Generic `apiKey` in header + `x-sbproxy-auth-type: kya`            |
| `cap`               | Generic `apiKey` in header + `x-sbproxy-auth-type: cap`            |
| `forward_auth`      | Generic `apiKey` placeholder + `x-sbproxy-auth-type: forward_auth` |
| anything else       | Generic `apiKey` placeholder + `x-sbproxy-auth-type` extension     |

Custom auth types can register their own mappers via the `AuthSchemeMapper` registry exposed from the OpenAPI emission engine.

## Limitations

- Path templates and regex matchers describe routing surface, not upstream contract. Request and response body schemas are not emitted unless an upstream OpenAPI spec was fed in via the existing consumption path (`sbproxy-extension/openapi_convert.rs`); merging that spec into emitted operations is on the roadmap.
- CORS is surfaced as an `x-sbproxy-cors` extension because OpenAPI 3.0 has no native CORS vocabulary.
- The `info.version` field defaults to `1.0.0`; callers who want the live config revision should override it after `build()` returns.

## Programmatic access

The emission engine is a library:

```rust
use sbproxy_openapi::{build, render_json, render_yaml};

let spec = build(&snapshot, None);                          // all hosts
let spec_one = build(&snapshot, Some("api.example.com"));   // single host
let json = render_json(&spec)?;
let yaml = render_yaml(&spec)?;
```

If you have a custom auth provider plugged in via the public plugin API, register a mapper for it the same way: implement `AuthSchemeMapper` and add it to the registry.

## Why emission, not just proxying

Most gateways ship an OpenAPI editor (you write the spec) or an OpenAPI importer (you feed in an upstream spec). SBproxy goes the other way: you configure routes, auth, caching, and rate limits on the gateway, and the gateway publishes a faithful OpenAPI document that always matches the running config. Reloads invalidate the cache; the next consumer fetch sees the new shape.

That makes the gateway, not the upstream service, the source of truth for what your API looks like to the outside world. Buyers point their SDK generators, contract tests, and developer portals at SBproxy. When you change a route, the document changes. When you tighten an auth scheme, the document tightens.

You ship the gateway and you ship the spec, in one motion.

## Example

A runnable example is at [`examples/96-openapi-emission/`](../examples/96-openapi-emission/sb.yml).

## See also

- [config-reference.md](config-reference.md) for the `expose_openapi` and `forward_rules.parameters` field semantics.
- [features.md](features.md) for the broader tour of gateway features.
- [scripting.md](scripting.md) for the CEL, Lua, JavaScript, and WASM hook surfaces that can read captured `path_params`.
