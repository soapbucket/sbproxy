# Config stability tiers

*Last modified: 2026-07-23*

Stability guarantees for every field in `sb.yml`. Check a field's tier before relying on it in production.

---

## Stability tiers

### `stable`

A `stable` field is part of the committed public API of SBproxy.

- The field name, type, and default value will not change in a minor or patch release.
- Removing or renaming a `stable` field requires a major version bump (e.g. v1 -> v2) and a migration guide.
- Behavioral changes to a `stable` field require at least a minor version bump and a changelog entry.

### `beta`

A `beta` field is functional and tested but may still change.

- Available for production use. Monitor the changelog before upgrading.
- Renames or semantic changes may happen in a minor release with a deprecation notice.
- Beta fields are not silently removed. A one-release deprecation period applies.

### `alpha`

An `alpha` field is experimental.

- May be renamed, restructured, or removed in any release without prior notice.
- Do not depend on `alpha` fields in critical production paths.
- Feedback on alpha fields is welcome and influences their stabilization.

### `disabled`

A `disabled` field is retained in the schema but cannot activate runtime behavior today.

- An omitted block or its disabled value remains valid for config compatibility.
- Attempting to enable unavailable behavior fails config compilation instead of being ignored.
- Currently applies to the `http3` block. Native HTTP/3 support is tracked in WOR-1969.

### `config-only`

A `config-only` field remains parseable for compatibility but has no live
consumer in the open-source runtime.

- Do not use it to satisfy an operational requirement.
- An explicitly authored config-only key emits a boot/config-validation warning
  naming the complete schema path and the reason it has no effect.
- The build-time config-reader guard requires an explicit registry entry and
  an operator-facing reason for every such field.
- The field is removed from examples that purport to demonstrate working
  behavior. Its reference entry states the live alternative, when one exists.

---

## Stabilization rules

1. A field moves from `alpha` to `beta` once its interface is reviewed, it has integration tests, and it has been in at least one release.
2. A field moves from `beta` to `stable` once it has been in production use by at least one internal deployment for one full release cycle without interface changes.
3. Stable fields are never silently removed. The process is: deprecate (the config compiler logs a structured deprecation warning at load time naming the legacy and canonical field), then remove in the next major version. A schema-level `x-deprecated` annotation is planned but not shipped.

## Build-time reader coverage

CI walks the generated `ConfigFile` JSON Schema and requires every key to have
either a non-test Rust field read or a reviewed entry in
`CONFIG_KEY_OVERRIDES`. Indirect serde consumers name their concrete runtime
consumer. Deliberately inert fields are marked `config-only` with a reason.
Run the same lane locally with:

```bash
scripts/check-config-readers.sh
```

Adding a key to `types.rs` without wiring it now fails with the complete dotted
schema path. Adding a reviewed `ConfigOnly` entry makes the exception explicit
and stale entries fail when their schema path is removed or renamed.

### Current config-only compatibility fields

| Field or subtree | What happens today |
|---|---|
| `agent_classes.hosted_feed` | The OSS resolver uses builtin or inline catalogs; it does not fetch a hosted feed. |
| `origins.*.agent_skills[].max_clock_skew_secs` | Reserved for signed artifact freshness headers that are not emitted yet. |
| `origins.*.connection_pool` | Pingora's built-in upstream pool is used; these per-origin limits are not applied. |
| `origins.*.compression.level` | Compression libraries use their runtime defaults; this parsed level is not applied. |
| `origins.*.cors.enable` | The presence of `cors:` enables CORS; the legacy boolean value is ignored. |
| `origins.*.rate_limit_headers` | Use the live rate-limit policy's `headers` block instead. |
| `origins.*.sessions.ttl_seconds` | Reserved retention hint; the in-process request ring does not expire entries from it. |
| `origins.*.traffic_capture` | No OSS capture consumer; use `mirror` for live fire-and-forget request mirroring. |
| `proxy.device_parser_file` | The current pure-Rust device parser does not load this catalog override. |
| `proxy.key_management.governance.key_introspection` | The caller-only introspection route is not installed. |
| `proxy.key_management.store.redis_source_of_truth` | Redis is authoritative whenever `store.backend: redis`; this legacy boolean changes nothing. |
| `proxy.observability.log.level`, `.format`, `.sampling` | Process logging uses CLI/environment selection and fixed sampling defaults. Sink-local `format` remains live. |
| `proxy.scripting.javascript` | QuickJS engines use built-in sandbox defaults; this YAML subtree is not installed. |
| `proxy.secrets.backend`, `.hashicorp`, `.map`, `.rotation`, `.fallback` | Legacy single-backend surface. Use named `proxy.secrets.backends` and provider URI references. |

---

## Field stability reference

### Top-level fields

| Field | Type | Stability | Notes |
|---|---|---|---|
| `proxy` | object | **stable** | Server configuration block. |
| `origins` | object (map) | **stable** | Map of hostname to origin config. |

### `proxy` - ProxyServerConfig

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `http_bind_port` | integer | 8080 | **stable** | Plain HTTP listener port. |
| `https_bind_port` | integer | - | **stable** | TLS listener port. Optional. |
| `tls_cert_file` | string | - | **stable** | Path to PEM cert for manual TLS. |
| `tls_key_file` | string | - | **stable** | Path to PEM key for manual TLS. |
| `acme` | object | - | **beta** | Automatic TLS via ACME. |
| `http3` | object | - | **disabled** | Reserved HTTP/3 (QUIC) listener shape. `enabled: true` is rejected. |

### `proxy.acme` - AcmeConfig

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `enabled` | boolean | false | **beta** | Activates ACME. |
| `email` | string | "" | **beta** | Contact email for the ACME account. |
| `directory_url` | string | Let's Encrypt prod | **beta** | ACME directory endpoint URL. |
| `challenge_types` | array | `[http-01]` | **beta** | Challenge method preference list. `tls-alpn-01` is accepted in the list but not yet served. |
| `storage_backend` | string | `redb` | **beta** | Cert persistence backend. |
| `storage_path` | string | `/var/lib/sbproxy/certs` | **beta** | Filesystem path for cert storage. |
| `renew_before_days` | integer | 30 | **beta** | Days before expiry to renew. |

### `proxy.http3` - Http3Config

HTTP/3 is not served by this build. The block is retained for forward compatibility: omission or `enabled: false` compiles, while `enabled: true` fails config compilation with a reference to WOR-1969.

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `enabled` | boolean | false | **disabled** | Must remain false until HTTP/3 is served. |
| `max_streams` | integer | 100 | **disabled** | Reserved max concurrent QUIC streams per connection. |
| `idle_timeout_secs` | integer | 30 | **disabled** | Reserved QUIC idle timeout in seconds. |

### Origin Config (each entry under `origins:`)

| Field | Alias | Type | Default | Stability | Notes |
|---|---|---|---|---|---|
| `action` | - | object | required | **stable** | What the proxy does with requests. |
| `authentication` | `auth` | object | - | **stable** | Auth plugin config. |
| `policies` | - | array | `[]` | **stable** | Policy plugin list. |
| `transforms` | - | array | `[]` | **beta** | Body transform plugin list. |
| `request_modifiers` | - | array | `[]` | **stable** | Request modification steps. |
| `response_modifiers` | - | array | `[]` | **stable** | Response modification steps. |
| `cors` | - | object | - | **stable** | CORS policy. |
| `hsts` | - | object | - | **stable** | HSTS policy. |
| `compression` | - | object | - | **stable** | Response compression. |
| `session` | `session_config` | object | - | **beta** | Session cookie management. |
| `force_ssl` | - | boolean | false | **stable** | Redirect HTTP to HTTPS. |
| `allowed_methods` | - | array | `[]` (all) | **stable** | HTTP method allowlist. |
| `forward_rules` | - | array | `[]` | **beta** | Conditional routing rules. |
| `fallback_origin` | - | object | - | **beta** | Secondary origin on primary failure. |
| `response_cache` | - | object | - | **beta** | Response caching config. |
| `variables` | - | object | `{}` | **beta** | Named template variables. |
| `on_request` | - | array | `[]` | **alpha** | Request event hook plugins. |
| `on_response` | - | array | `[]` | **alpha** | Response event hook plugins. |
| `bot_detection` | - | object | - | **alpha** | Bot detection config. |
| `threat_protection` | - | object | - | **alpha** | Dynamic threat blocklist config. |
| `rate_limit_headers` | - | object | - | **config-only** | Use the live rate-limit policy's `headers` block. |
| `error_pages` | - | object | - | **beta** | Custom error page config. |
| `traffic_capture` | - | object | - | **config-only** | No OSS consumer; use `mirror` for request mirroring. |
| `connection_pool` | - | object | - | **config-only** | Retained for compatibility; Pingora's built-in pool settings apply. |
| `message_signatures` | - | object | - | **alpha** | HTTP message signing config. |

### CORS Config (`cors:`)

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `allowed_origins` | `allow_origins` | array | `[]` | **stable** |
| `allowed_methods` | `allow_methods` | array | `[]` | **stable** |
| `allowed_headers` | `allow_headers` | array | `[]` | **stable** |
| `expose_headers` | - | array | `[]` | **stable** |
| `max_age` | - | integer | - | **stable** |
| `allow_credentials` | - | boolean | false | **stable** |
| `enable` | `enabled` | boolean | - | **config-only** |

### HSTS Config (`hsts:`)

| Field | Type | Default | Stability |
|---|---|---|---|
| `max_age` | integer | 31536000 | **stable** |
| `include_subdomains` | boolean | false | **stable** |
| `preload` | boolean | false | **stable** |

### Compression Config (`compression:`)

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `enabled` | `enable` | boolean | true | **stable** |
| `algorithms` | - | array | `[]` | **stable** |
| `min_size` | - | integer | 0 | **stable** |
| `level` | - | integer | - | **beta** |

`level` is parsed but not applied: the encoders use their library
default levels (gzip and zstd defaults, brotli quality 4).

### Session Config (`session:`, alias `session_config:`)

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `cookie_name` | - | string | - | **beta** |
| `max_age` | `cookie_max_age` | integer | - | **beta** |
| `http_only` | - | boolean | false | **beta** |
| `secure` | - | boolean | false | **beta** |
| `same_site` | `cookie_same_site` | string | - | **beta** |
| `allow_non_ssl` | - | boolean | false | **beta** |

### Request Modifier (`request_modifiers[]`)

| Field | Type | Stability | Notes |
|---|---|---|---|
| `headers` | object | **stable** | Header set/add/remove. |
| `url` | object | **stable** | Path rewrite. |
| `query` | object | **stable** | Query param set/add/remove. |
| `method` | string | **stable** | Override HTTP method. |
| `body` | object | **stable** | Body replacement. |
| `lua_script` | string | **beta** | Dynamic modification via Lua. |

### Response Modifier (`response_modifiers[]`)

| Field | Type | Stability | Notes |
|---|---|---|---|
| `headers` | object | **stable** | Header set/add/remove. |
| `status` | object | **stable** | Status code override. |
| `body` | object | **stable** | Body replacement. |
| `lua_script` | string | **beta** | Dynamic modification via Lua. |

### Header Modifiers

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `set` | - | object | `{}` | **stable** |
| `add` | - | object | `{}` | **stable** |
| `remove` | `delete` | array | `[]` | **stable** |

### Path Replace (`url.path.replace`)

| Field | Type | Stability |
|---|---|---|
| `old` | string | **stable** |
| `new` | string | **stable** |

### Query Modifier

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `set` | - | object | `{}` | **stable** |
| `add` | - | object | `{}` | **stable** |
| `remove` | `delete` | array | `[]` | **stable** |

### Body Modifier (request)

| Field | Type | Stability |
|---|---|---|
| `replace` | string | **stable** |
| `replace_json` | any | **stable** |

### Response Body Modifier

| Field | Type | Stability |
|---|---|---|
| `replace` | string | **stable** |
| `replace_json` | any | **stable** |

### Status Override

| Field | Type | Stability |
|---|---|---|
| `code` | integer | **stable** |
| `text` | string | **stable** |
