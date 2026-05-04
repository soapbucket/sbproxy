# Configuration Reference
*Last modified: 2026-05-03*

The exhaustive field-by-field reference for an SBproxy `sb.yml` file. Every section listed here corresponds to a Rust struct in `crates/sbproxy-config/`, which is the canonical source of truth: if a field appears in the config schema there, it is supported here, and if a field is documented here, it is in the schema.

This page replaces the archived Go `proxy/docs/PROXY_CONFIG.md` reference. Buyer-facing prose lives here; the Rust types stay the source of truth, and the in-repo `configuration.md` keeps the long-form examples and migration notes.

For a tour of features with copy-paste configs, see [features.md](features.md). For a buyer-facing introduction to SBproxy, see [manual.md](manual.md).

## Table of contents

1. [File shape](#file-shape)
2. [`proxy:` server-level fields](#proxy-server-level-fields)
3. [`origins:` per-hostname fields](#origins-per-hostname-fields)
4. [Actions](#actions)
5. [Authentication](#authentication)
6. [Policies](#policies)
7. [Request and response modifiers](#request-and-response-modifiers)
8. [Transforms](#transforms)
9. [Forward rules](#forward-rules)
10. [Response cache](#response-cache)
11. [Cache Reserve and L2 cache](#cache-reserve-and-l2-cache)
12. [Middleware blocks (CORS, HSTS, compression, sessions)](#middleware-blocks-cors-hsts-compression-sessions)
13. [Connection pool](#connection-pool)
14. [Mirror and traffic capture](#mirror-and-traffic-capture)
15. [Rate limits](#rate-limits)
16. [Properties, sessions, users](#properties-sessions-users)
17. [Content shape and licensing fields](#content-shape-and-licensing-fields)
18. [Access log](#access-log)
19. [Agent classes](#agent-classes)
20. [Secrets and ACME](#secrets-and-acme)
21. [Extensions (opaque)](#extensions-opaque)

## File shape

A SBproxy config file has two required top-level keys (`proxy:` and `origins:`) and three optional ones.

```yaml
proxy:           # server-wide settings
  ...
origins:         # map of hostname to per-origin config
  "api.example.com":
    ...
access_log:      # optional structured-JSON access log
  ...
agent_classes:   # optional agent-class catalog selection
  ...
```

`origins:` is a map keyed by hostname. The hostname comes from the Host header (with optional SNI fallback when TLS terminates here). Wildcard prefixes are accepted (`*.api.example.com`).

## `proxy:` server-level fields

Source: `ProxyServerConfig` in `crates/sbproxy-config/src/types.rs`.

| Field                  | Type        | Default                  | Notes                                                                                      |
|------------------------|-------------|--------------------------|--------------------------------------------------------------------------------------------|
| `http_bind_port`       | `u16`       | `8080`                   | HTTP listener port.                                                                        |
| `http2_cleartext`      | `bool`      | `false`                  | Detect the HTTP/2 preface on the plain HTTP listener (h2c). Off keeps the listener HTTP/1.1 only. |
| `https_bind_port`      | `u16?`      | unset                    | When set, requires `tls_cert_file` + `tls_key_file` or `acme.enabled: true`.               |
| `tls_cert_file`        | `String?`   | unset                    | PEM cert path. Ignored when `acme` is set.                                                 |
| `tls_key_file`         | `String?`   | unset                    | PEM key path matching `tls_cert_file`.                                                     |
| `acme`                 | `AcmeConfig?` | unset                  | ACME-managed TLS. See [Secrets and ACME](#secrets-and-acme).                               |
| `http3`                | `Http3Config?` | unset                 | QUIC listener. `enabled`, `max_streams` (default 100), `idle_timeout_secs` (default 30).   |
| `metrics`              | `MetricsConfig?` | unset                | `max_cardinality_per_label` (default 1 000).                                               |
| `alerting`             | `AlertingConfig?` | unset               | `channels[]`. Each channel has `type: webhook` or `type: log`, plus `url:` and `headers:`. |
| `admin`                | `AdminConfig?` | unset                  | `enabled`, `port` (9090), `username` (`admin`), `password` (`changeme`), `max_log_entries` (1000). |
| `secrets`              | `SecretsConfig?` | unset                | `backend`, `hashicorp`, `map`, `rotation`, `fallback`. See [Secrets and ACME](#secrets-and-acme). |
| `l2_cache_settings`    | `L2CacheConfig?` | unset                | Shared-state backend. Today only `driver: redis` is supported. Alias: `l2_cache`.          |
| `cache_reserve`        | `CacheReserveConfig?` | unset           | Long-tail cold cache tier. See [Cache Reserve and L2 cache](#cache-reserve-and-l2-cache).  |
| `messenger_settings`   | `MessengerSettings?` | unset            | Inter-component event bus. Drivers: `memory`, `redis`, `sqs`, `gcp_pubsub`.                |
| `trusted_proxies`      | `[String]`  | `[]`                     | CIDRs whose `X-Forwarded-For` / `X-Real-IP` / `Forwarded` headers SBproxy will trust.       |
| `correlation_id`       | `CorrelationIdConfig` | defaults       | `enabled: true`, `header: X-Request-Id`, `echo_response: true`.                            |
| `mtls`                 | `MtlsListenerConfig?` | unset          | `client_ca_file`, `require: true`. Requires `https_bind_port`.                             |
| `ai_providers_file`    | `String?`   | unset                    | Override path for the AI provider catalogue.                                               |
| `device_parser_file`   | `String?`   | unset                    | Reserved override for the device-parser regex catalogue.                                   |
| `extensions`           | map         | `{}`                     | Opaque map. OSS never parses; enterprise crates read their own keys.                        |

### TLS, ACME, mTLS

ACME (`AcmeConfig`):

| Field                | Type      | Default                                                       |
|----------------------|-----------|---------------------------------------------------------------|
| `enabled`            | `bool`    | `false`                                                       |
| `email`              | `String`  | empty                                                         |
| `directory_url`      | `String`  | `https://acme-v02.api.letsencrypt.org/directory`              |
| `challenge_types`    | `[String]`| `["tls-alpn-01", "http-01"]`                                  |
| `storage_backend`    | `String`  | `redb`                                                        |
| `storage_path`       | `String`  | `/var/lib/sbproxy/certs`                                      |
| `renew_before_days`  | `u32`     | `30`                                                          |

mTLS listener (`MtlsListenerConfig`):

| Field             | Type     | Default | Notes                                                                                |
|-------------------|----------|---------|--------------------------------------------------------------------------------------|
| `client_ca_file`  | `String` | required| PEM CA bundle that signs valid client certs.                                         |
| `require`         | `bool`   | `true`  | When `true`, the TLS handshake fails if the client does not present a certificate.   |

The proxy stamps `X-Client-Cert-Verified`, `X-Client-Cert-Organization`, `X-Client-Cert-Serial`, `X-Client-Cert-Fingerprint` on the upstream request after a successful handshake.

### Correlation ID

| Field            | Type     | Default        | Notes                                                            |
|------------------|----------|----------------|------------------------------------------------------------------|
| `enabled`        | `bool`   | `true`         | Master switch.                                                   |
| `header`         | `String` | `X-Request-Id` | Read on ingress, set on the upstream, echoed on the response.    |
| `echo_response`  | `bool`   | `true`         | When `false`, the value is set on the upstream but not echoed.   |

## `origins:` per-hostname fields

Source: `RawOriginConfig` in `crates/sbproxy-config/src/types.rs`.

The origin block sits at `origins."<hostname>":`. The handler chain below `action:` is built inside-out at config-load time, so per-request execution does no allocation in the chain-construction path.

| Field                    | Type                      | Notes                                                                                          |
|--------------------------|---------------------------|------------------------------------------------------------------------------------------------|
| `action`                 | typed object              | Required. See [Actions](#actions). Plugin-extensible.                                          |
| `authentication` / `auth`| typed object              | Optional. See [Authentication](#authentication).                                               |
| `policies`               | `[typed object]`          | Optional. Evaluated in order. See [Policies](#policies).                                       |
| `transforms`             | `[typed object]`          | Optional. See [Transforms](#transforms).                                                       |
| `request_modifiers`      | `[RequestModifierConfig]` | See [Request and response modifiers](#request-and-response-modifiers).                         |
| `response_modifiers`     | `[ResponseModifierConfig]`| See [Request and response modifiers](#request-and-response-modifiers).                         |
| `cors`                   | `CorsConfig?`             | Per-origin CORS.                                                                               |
| `hsts`                   | `HstsConfig?`             | Per-origin HSTS header.                                                                        |
| `compression`            | `CompressionConfig?`      | Response compression.                                                                          |
| `session` / `session_config` | `SessionConfig?`      | Cookie-based session config.                                                                   |
| `properties`             | `PropertiesConfig?`       | Wave 8 P0 custom-properties capture.                                                           |
| `sessions`               | `SessionsConfig?`         | Wave 8 P0 session-id capture.                                                                  |
| `user`                   | `UserConfig?`             | Wave 8 P0 user-id capture.                                                                     |
| `force_ssl`              | `bool`                    | Redirect plain HTTP to HTTPS.                                                                  |
| `allowed_methods`        | `[String]`                | Whitelist. Empty allows all.                                                                   |
| `forward_rules`          | `[RawForwardRule]`        | See [Forward rules](#forward-rules).                                                           |
| `fallback_origin`        | typed object              | Origin used when the primary upstream fails.                                                   |
| `response_cache`         | typed object              | See [Response cache](#response-cache).                                                         |
| `variables`              | `{String: any}`           | Static variables for template interpolation.                                                   |
| `on_request`             | `[typed object]`          | Hooks invoked when a request enters the origin.                                                |
| `on_response`            | `[typed object]`          | Hooks invoked when a response is being returned.                                               |
| `bot_detection`          | typed object              | Bot detection rules.                                                                           |
| `threat_protection`      | typed object              | IP reputation, blocklist.                                                                      |
| `rate_limit_headers`     | typed object              | RFC 9239 header configuration.                                                                 |
| `error_pages`            | typed object              | Custom error pages keyed by status or status class.                                            |
| `traffic_capture`        | typed object              | Traffic capture / mirroring config.                                                            |
| `mirror`                 | `MirrorConfig?`           | Fire-and-forget shadow upstream.                                                               |
| `message_signatures`     | typed object              | RFC 9421 HTTP Message Signatures.                                                              |
| `connection_pool`        | `ConnectionPoolConfig?`   | See [Connection pool](#connection-pool).                                                       |
| `extensions`             | `{String: any}`           | Opaque. OSS never parses.                                                                       |
| `expose_openapi`         | `bool`                    | When `true`, publish `/.well-known/openapi.json` and `.yaml` for this origin.                  |
| `stream_safety`          | `[String]`                | Streaming-safety rule identifiers (forwarded to enterprise hook when present).                 |
| `rate_limits`            | `OriginRateLimitsConfig?` | See [Rate limits](#rate-limits).                                                               |
| `default_content_shape`  | `String?`                 | Wave 4 default shape when `Accept` is `*/*` or absent. One of `markdown`, `json`, `html`, `pdf`, `other`. |
| `content_signal`         | `String?`                 | Wave 4 Content-Signal response header. Closed enum: `ai-train`, `search`, `ai-input`.          |
| `token_bytes_ratio`      | `f32?`                    | Wave 4 per-origin Markdown projection tokens-per-byte ratio. Defaults to 0.25 when unset.       |

## Actions

Each origin must declare exactly one `action`. The `type:` field selects the action; remaining fields are action-specific.

| `type:`              | What it does                                                                                                                |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------|
| `proxy`              | Reverse-proxy to `url`. The most common action.                                                                             |
| `redirect`           | HTTP redirect (`status`, `url`).                                                                                            |
| `static`             | Serve static files from a root path.                                                                                        |
| `echo`               | Mirror the inbound request back as the response body. Useful for debugging.                                                  |
| `mock`               | Return a canned response (`status`, `headers`, `body`).                                                                     |
| `beacon`             | Accept-and-204. Useful for analytics endpoints.                                                                             |
| `ai_gateway`         | Route to the AI gateway path. Provider catalogue + routing strategy + guardrails. See [ai-gateway.md](ai-gateway.md).        |
| `mcp_federation`     | Aggregate tool catalogues across upstream MCP servers; route `tools/call` per tool.                                          |
| `content_negotiate`  | Two-pass `Accept` resolution. Auto-prepended when `ai_crawl_control` or shape transforms are present. See Wave 4 in [wave-history.md](wave-history.md). |

The proxy field is `url` (not `target`).

## Authentication

Set `authentication:` (or its alias `auth:`) on an origin. Exactly one auth provider per origin.

| `type:`               | What it does                                                                                              |
|-----------------------|-----------------------------------------------------------------------------------------------------------|
| `api_keys`            | Header-based API key check. The keys list is `api_keys:` (not `keys:`).                                   |
| `basic_auth`          | HTTP basic auth.                                                                                          |
| `bearer`              | Static bearer-token check.                                                                                |
| `jwt`                 | JWT verification with JWKS or static keys.                                                                |
| `digest`              | RFC 7616 HTTP Digest Auth.                                                                                |
| `forward_auth`        | Forward the request to an external auth service for an allow / deny decision.                             |
| `noop`                | Allow everything. Useful for debugging.                                                                   |
| `kya`                 | Skyfire Know-Your-Agent token verifier (Wave 5).                                                          |
| `cap`                 | Crawler Authorization Protocol JWT verifier (Wave 6). See [glossary.md](glossary.md).                     |

Auth type names follow snake_case in the schema. The legacy `basic` alias is not accepted; use `basic_auth`.

## Policies

`policies:` is a list of policy entries that evaluate in order.

| `type:`                   | What it does                                                                                              |
|---------------------------|-----------------------------------------------------------------------------------------------------------|
| `rate_limiting`           | Token-bucket rate limiter. Set `requests_per_second`, `burst`, `key:` (`ip`, `header:Authorization`, JWT claim path). |
| `ip_filter`               | IP allow / block. Use `whitelist:` and `blacklist:` (CIDR lists).                                         |
| `cel_expression`          | CEL boolean expression on the request context. See [scripting.md](scripting.md).                          |
| `assertion`               | Structural assertion. Used in tests.                                                                      |
| `waf`                     | OWASP-style WAF rules.                                                                                    |
| `ddos_protection`         | Connection-rate cap with adaptive backpressure.                                                           |
| `csrf`                    | CSRF token enforcement. Requires `secret_key`.                                                            |
| `security_headers`        | Stamps a configurable set of security headers on the response.                                            |
| `ai_crawl_control`        | Pay Per Crawl. 402 + Crawler-Payment token redemption. See [ai-crawl-control.md](ai-crawl-control.md).    |
| `exposed_credentials`     | Cloudflare-style leaked-password check (k-anonymity SHA-1 prefix).                                        |
| `page_shield`             | Page Shield equivalent.                                                                                    |
| `bulk_redirects`          | Bulk redirect map.                                                                                         |
| `dlp_catalog`             | Data-loss-prevention catalogue.                                                                            |
| `web_bot_auth`            | Web Bot Auth (RFC 9421-style signed bot traffic).                                                          |
| `http_framing`            | Smuggling defence. Drops H2-to-H1 downgrade attacks.                                                       |
| `a2a_envelope`            | Agent-to-Agent envelope policy with depth cap and cycle detection (Wave 7).                                |

Lua scripts use `function match_request(req, ctx)` (not bare code with a global `request`).

## Request and response modifiers

Two parallel lists, evaluated in declaration order. Each entry is a `RequestModifierConfig` or `ResponseModifierConfig`.

`RequestModifierConfig`:

| Field        | Type                | Notes                                                                                  |
|--------------|---------------------|----------------------------------------------------------------------------------------|
| `headers`    | `HeaderModifiers?`  | `set` (replace), `add` (append), `remove` / `delete`.                                  |
| `url`        | `UrlModifier?`      | `path.replace.old` and `.new` for substring path rewrites.                             |
| `query`      | `QueryModifier?`    | `set`, `add`, `remove` / `delete`.                                                     |
| `method`     | `String?`           | Override HTTP method.                                                                  |
| `body`       | `BodyModifier?`     | `replace_json` or `replace`.                                                           |
| `lua_script` | `String?`           | Inline Lua. Entry point: `function modify_request(req, ctx)`.                          |
| `js_script`  | `String?`           | Inline JavaScript. Entry point: `function modify_request(req, ctx)`.                   |

`ResponseModifierConfig`:

| Field        | Type                       | Notes                                                                                  |
|--------------|----------------------------|----------------------------------------------------------------------------------------|
| `headers`    | `HeaderModifiers?`         | Same shape as request modifiers.                                                       |
| `status`     | `StatusOverride?`          | `code` and optional `text`.                                                            |
| `body`       | `ResponseBodyModifier?`    | `replace` or `replace_json`.                                                           |
| `lua_script` | `String?`                  | Entry point: `function modify_response(res, ctx)`.                                     |
| `js_script`  | `String?`                  | Entry point: `function modify_response(res, ctx)`.                                     |

## Transforms

`transforms:` is a list of transform entries that run on the request body, response body, or both. There are 18 transform types: JSON, HTML, Markdown, CSS, Lua, JavaScript, encoding, projection, citation block, boilerplate strip, JSON envelope, and so on. Each entry's `type:` field selects the transform; remaining fields are transform-specific. See [features.md](features.md) for the full list with copy-paste configs.

Wave 4 added auto-wiring: when an origin uses `ai_crawl_control` or any of the shape transforms, the proxy auto-prepends a `content_negotiate` action and the matching transforms.

## Forward rules

`forward_rules:` lets one origin dispatch into one of several inline child origins based on path, header, or query. Source: `RawForwardRule`.

```yaml
forward_rules:
  - rules:
      - path: { exact: /health }
      - path: { prefix: /api/ }
      - path: { template: /users/{id:[0-9]+}/posts/{post_id} }
      - path: { regex: '^/v(?P<version>[0-9]+)/items' }
      - header: { name: X-Tenant, value: vip }
      - query: { name: debug, value: "1" }
    parameters:
      - name: id
        in: path
        required: true
        schema: { type: integer, format: int64 }
    origin:
      action: { type: proxy, url: http://upstream }
```

Path matchers (`PathMatcher`) accept `prefix`, `exact`, `template`, or `regex`. Precedence when more than one is set: `template` > `regex` > `exact` > `prefix`. Within an entry the present matchers are ANDed; across entries in the same rule they are ORed.

`parameters:` follow OpenAPI 3.0 Parameter Objects verbatim. `in:` accepts `path`, `query`, `header` (cookie not yet supported).

The inline child origin (`origin:`) carries the same shape as a top-level origin: `action`, optional `request_modifiers`, optional `id`, `hostname`, `workspace_id`, `version`. Forward rules can therefore embed full origin configs.

## Response cache

Source: `ResponseCacheConfig`.

| Field                       | Type                  | Default       | Notes                                                                                |
|-----------------------------|-----------------------|---------------|--------------------------------------------------------------------------------------|
| `enabled`                   | `bool`                | `false`       | Global on / off for this origin.                                                     |
| `ttl_secs` / `ttl`          | seconds or duration   | `300`         | Accepts `60`, `60s`, `5m`, `2h30m`. Alias `ttl` matches Go schema.                   |
| `cacheable_methods` / `methods` | `[String]`        | `["GET"]`     | Methods eligible for caching.                                                         |
| `cacheable_status` / `status_codes` | `[u16]`       | `[200]`       | Status codes eligible for caching.                                                   |
| `max_size`                  | `usize`               | `10_000`      | In-memory entry cap. Ignored for Redis (server-controlled eviction).                 |
| `vary` / `vary_by`          | `[String]`            | `[]`          | Headers folded into the cache key (case-insensitive match).                          |
| `query_normalize`           | `QueryNormalize`      | `sort`        | One of `ignore_all`, `sort`, `allowlist:[...]`.                                      |
| `stale_while_revalidate` / `swr_secs` | `u64?`      | unset         | Seconds beyond TTL to serve a stale entry while revalidating in the background.       |
| `invalidate_on_mutation`    | `bool`                | `true`        | Mutating method to a path evicts every cached `GET` for the same workspace + path.    |

Stale replays carry `x-sbproxy-cache: STALE`.

## Cache Reserve and L2 cache

Cache Reserve (`CacheReserveConfig`) sits under the per-origin response cache:

| Field            | Type                       | Default     |
|------------------|----------------------------|-------------|
| `enabled`        | `bool`                     | `false`     |
| `backend`        | `CacheReserveBackendConfig?` | unset      |
| `sample_rate`    | `f64`                      | `0.1`       |
| `min_ttl`        | `u64`                      | `3600`      |
| `max_size_bytes` | `u64`                      | `1048576`   |

OSS backends: `memory`, `filesystem` (with `path:`), `redis` (with `redis_url:`, optional `key_prefix:`).

L2 cache (`L2CacheConfig`) is the cluster-wide shared backend:

```yaml
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: redis://localhost:6379/0
```

## Middleware blocks (CORS, HSTS, compression, sessions)

CORS (`CorsConfig`):

| Field                | Aliases             | Default |
|----------------------|---------------------|---------|
| `allowed_origins`    | `allow_origins`     | `[]`    |
| `allowed_methods`    | `allow_methods`     | `[]`    |
| `allowed_headers`    | `allow_headers`     | `[]`    |
| `expose_headers`     |                     | `[]`    |
| `max_age`            |                     | unset   |
| `allow_credentials`  |                     | `false` |
| `enable` / `enabled` |                     | unset   |

HSTS (`HstsConfig`): `max_age` (default 31_536_000), `include_subdomains`, `preload`.

Compression (`CompressionConfig`): `enabled` (alias `enable`, default `true`), `algorithms`, `min_size`, `level`.

Session cookie (`SessionConfig`): `cookie_name`, `max_age` (alias `cookie_max_age`), `http_only`, `secure`, `same_site` (alias `cookie_same_site`), `allow_non_ssl`.

## Connection pool

Source: `ConnectionPoolConfig`. Per-origin upstream pool tuning.

| Field                | Default | Notes                                                                    |
|----------------------|---------|--------------------------------------------------------------------------|
| `max_connections`    | `128`   | Max concurrent connections to the upstream.                              |
| `idle_timeout_secs`  | `90`    | Drop connections unused for longer than this from the pool.              |
| `max_lifetime_secs`  | `300`   | Close connections older than this even if healthy.                       |

Falls back to proxy-wide defaults when unset.

## Mirror and traffic capture

Mirror (`MirrorConfig`): fire-and-forget shadow upstream. Field shape:

| Field             | Default     | Notes                                                                |
|-------------------|-------------|----------------------------------------------------------------------|
| `url`             | required    | `http://` or `https://` (IPv6 hosts must be bracketed per RFC 3986). |
| `sample_rate`     | `1.0`       | Per-request uniform PRNG sample.                                     |
| `timeout_ms`      | `5000`      | Independent from primary upstream timeout.                           |
| `mirror_body`     | `false`     | When `true`, tee the inbound body into the mirror request.           |
| `max_body_bytes`  | `1048576`   | Bodies larger than this skip mirroring.                              |

`traffic_capture:` is the broader recording surface (full request and response capture for debugging).

## Rate limits

Two surfaces:

1. **Per-policy** (`policies:` entry with `type: rate_limiting`). Token-bucket on a key.
2. **Per-origin** (`rate_limits:` block, `OriginRateLimitsConfig`). RFC 9239 middleware mounted ahead of policies in the handler chain.

Per-origin rate limits:

| Field                  | Default | Notes                                                                          |
|------------------------|---------|--------------------------------------------------------------------------------|
| `tenant_burst`         | `2000`  | Burst ceiling per tenant.                                                      |
| `tenant_sustained`     | `1000`  | Sustained rps per tenant.                                                      |
| `route_default`        | `100`   | Per-route default rps when no override matches.                                |
| `route_overrides`      | `{}`    | Map keyed by literal path or `/prefix/*`. First match wins, in iteration order.|
| `soft_threshold_rps`   | unset   | Above this but below `tenant_sustained`, requests are tagged but not throttled.|

Throttled responses carry `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, and `Retry-After`.

## Properties, sessions, users

Wave 8 P0 capture surfaces. Per-origin blocks mirror the `sbproxy_observe` types.

| Field          | Type                | Default behaviour                                            |
|----------------|---------------------|--------------------------------------------------------------|
| `properties`   | `PropertiesConfig?` | Capture on, no echo, no redaction.                           |
| `sessions`     | `SessionsConfig?`   | Capture on, `Anonymous` auto-generate.                       |
| `user`         | `UserConfig?`       | Capture on, 256-byte cap.                                    |

## Content shape and licensing fields

Wave 4 surfaces on the origin block:

| Field                    | Type     | Default | Notes                                                                                          |
|--------------------------|----------|---------|------------------------------------------------------------------------------------------------|
| `default_content_shape`  | `String?`| `html`  | `markdown`, `json`, `html`, `pdf`, `other`. Resolved when `Accept` is `*/*` or absent.         |
| `content_signal`         | `String?`| unset   | `ai-train`, `search`, `ai-input`. Stamps Content-Signal on 200 responses.                      |
| `token_bytes_ratio`      | `f32?`   | `0.25`  | Markdown projection tokens-per-byte. Drives `x-markdown-tokens` header and JSON envelope.       |
| `expose_openapi`         | `bool`   | `false` | When `true`, publish `/.well-known/openapi.json` and `.yaml`. See [openapi-emission.md](openapi-emission.md). |

When `content_signal` is unset, the proxy stamps `TDM-Reservation: 1` instead of asserting a positive Content-Signal.

## Access log

Top-level optional block. Source: `AccessLogConfig`.

| Field          | Default | Notes                                                                  |
|----------------|---------|------------------------------------------------------------------------|
| `enabled`      | `false` | When `false`, no access-log lines are emitted regardless of filters.   |
| `sample_rate`  | `1.0`   | Probability that a matching request is logged.                         |
| `status_codes` | `[]`    | Empty matches every status; non-empty restricts to listed codes.       |
| `methods`      | `[]`    | Empty matches every method; non-empty restricts (case-insensitive).    |

Each emitted line is one JSON record per the `AccessLogEntry` shape in `sbproxy-observe`.

## Agent classes

Top-level optional block. Source: `AgentClassesConfig`. Tunes the agent-class resolver the binary builds at startup.

| Field            | Default     | Notes                                                                                       |
|------------------|-------------|---------------------------------------------------------------------------------------------|
| `catalog`        | `builtin`   | `builtin`, `hosted-feed`, or `merged`.                                                      |
| `hosted_feed`    | unset       | Required when `catalog: hosted-feed` or `merged`. `url:` and `bootstrap_keys:`.             |
| `resolver`       | defaults    | `rdns_enabled: true`, `bot_auth_keyid_enabled: true`, `cache_size: 10_000`.                 |

Most operators leave this block untouched. The binary builds the resolver from `AgentClassCatalog::defaults()` plus default tuning when the block is absent.

## Secrets and ACME

Secrets (`SecretsConfig`):

| Field        | Default | Notes                                                                                            |
|--------------|---------|--------------------------------------------------------------------------------------------------|
| `backend`    | `env`   | `env`, `local`, `hashicorp`.                                                                     |
| `hashicorp`  | unset   | Required when `backend: hashicorp`. Fields: `addr`, `token`, `mount` (default `secret`).         |
| `map`        | `{}`    | Logical-name to vault-path mapping.                                                              |
| `rotation`   | unset   | `grace_period_secs` (default 300), `re_resolve_interval_secs` (default 60).                       |
| `fallback`   | `cache` | `cache`, `reject`, `env`.                                                                        |

Secret references in config values are written `secret:<name>`. The vault crate resolves them on config load and on rotation.

## Extensions (opaque)

Both `proxy.extensions` and per-origin `extensions` are opaque maps that OSS never inspects. Enterprise crates read their own keys by name. This pattern is the standard escape hatch for enterprise schemas; OSS configs can still validate-clean against the OSS schema without depending on enterprise types.

```yaml
proxy:
  extensions:
    classifier:
      endpoint: "http://127.0.0.1:9500"

origins:
  api.example.com:
    action: { type: proxy, url: http://localhost:3000 }
    extensions:
      semantic_cache:
        enabled: true
        ttl_secs: 1200
```

## See also

- [glossary.md](glossary.md) for the vocabulary used in this reference.
- [features.md](features.md) for tour-of-features prose with copy-paste configs.
- [scripting.md](scripting.md) for CEL, Lua, JavaScript, and WASM hook surfaces.
- [openapi-emission.md](openapi-emission.md) for how `expose_openapi` and the admin OpenAPI route work.
- [manual.md](manual.md) for install, CLI, runtime, and deployment patterns.
