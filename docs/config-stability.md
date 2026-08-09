# Config stability tiers

*Last modified: 2026-08-09*

This page defines the stability tiers and applies them to representative or
high-impact configuration leaves. It also lists the current reviewed
`config-only` registry. It is not an exhaustive field matrix:
[`configuration.md`](configuration.md) is the complete field inventory.

An unlisted field has no implicit stability promise. Before depending on one,
review its Rust source and the changelog for the release you plan to run.

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
- Currently applies to the `http3` block. Native HTTP/3 support is not implemented.

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

### Module and AI-gateway keys

The generated schema stops at `action:`, `authentication:`, `policies:` and
`transforms:`, because modules are pluggable and the configuration crate does
not name their types. Keys below those four are covered by a second input: a
registry of subtrees, each naming the Rust type the subtree deserializes into,
which the same scan walks directly.

Coverage is deliberately incremental. Every module an operator can name must
say whether its configuration is walked, and a module that reaches the config
compiler without saying so fails the build. Saying "not yet" is a valid answer
and requires a reason.

A module may also warn for its own config-only field rather than route it
through the registry, using the same message and the same `config_key` field
the registry uses, so an operator reads one boot log rather than two. No
module field does this today: `origins.*.action.sticky`, the one field that
did, was removed in favor of the `ring_hash` load-balancer algorithm and is
now refused at config compile with an error naming the replacement.

#### Module keys refused at config compile

A module key that names behavior the runtime does not have is refused rather
than warned about, because a key nobody can make work is not a compatibility
surface. The error names the key, says what it did not do, and points at the
surface that does the job. Boot and reload both refuse the document.

| Key | Why it is refused | What to use instead |
|---|---|---|
| `origins.*.action.context_overflow` (`ai_proxy`) | Never a field on the AI handler and never read by anything. The decision layer behind it (error, fall back to a larger model, truncate) had no caller in the life of the tree, and the AI gateway guide described the block as ignored, which left operators free to write it. | A `window_fit` lever under `compression.levers`, or the `resilience.llm_aware.context_compress` shorthand. No configuration reroutes an oversized prompt to a larger-window model; order the larger model first, or alias to it. |
| `origins.*.action.sticky` (`load_balancer`) | No affinity cookie was ever issued. | `algorithm: ring_hash` keyed on `cookie`, `header`, `ip`, or `uri`. |
| `transforms[].allowed_hosts` (`type: wasm`) | Never enforced, and unenforceable: WASM modules have no network surface at all here, so the allowlist described a boundary nothing checked. | Keep the reaching on the proxy side. Gate the origin with an `expression` policy, or route the callout through an origin the proxy controls. The key returns as an enforced one if a host callout ever lands. |
| `transforms[].on_request` (`type: cel`) | Compiled at config load and never evaluated. Transforms run on the response body, so there is no request phase for it to run in. | An `expression` policy to gate the request, a rate-limit or WAF `key:` expression to key on it, or a forward rule to route on it. |

#### Schema keys refused at config compile

These parsed, warned once at boot, and then governed nothing. A warning
is the proportionate response to a key whose behavior is narrower than
its name suggests, which is why `cors.enable` still gets one. It is the
wrong response to a key with no implementation at all: four of the five
below name a resource limit or a retention window, and a config that
sets one keeps claiming a property the proxy does not have.

| Key | Why it is refused | What to use instead |
|---|---|---|
| `origins.*.connection_pool.max_connections` | Pingora sizes the upstream keepalive pool once per connector, not per origin, so there was no per-origin limit for the value to become and upstream connections were never capped at it. | A `concurrent_limit` policy, which caps in-flight requests per origin and rejects over the cap rather than queueing. |
| `origins.*.connection_pool.max_lifetime_secs` | Pingora's connection pool has no age-based eviction, so no pooled connection was ever retired for being old. | `timeouts.idle_ms`, the deadline that does retire pooled connections once they go unused. |
| `origins.*.sessions.ttl_seconds` | There is no sessions index to retain. Sessions appear in the admin recent-request ring, which is bounded by entry count and evicts the oldest entry when full, so a session aged out on request volume and never on this deadline. | `sessions.budget.max_per_window` with `sessions.budget.window_seconds`, both enforced. |
| `origins.*.traffic_capture` | No capture consumer exists. The block was accepted as an untyped value, so nothing validated its contents either and a misspelled field inside it looked exactly like a working setting. | `mirror`, which forwards a fire-and-forget copy of each request to a second upstream without delaying or failing the real one. |
| `proxy.device_parser_file` | The device parser matches on compiled-in rules and has no code path that opens a catalog file, so a maintained catalog and a missing one behaved identically. | Nothing for device detection. `proxy.ai_providers_file` is the neighboring override that does work, and it applies to the AI provider catalog. |

`origins.*.connection_pool.idle_timeout_secs` is not refused. It is the
legacy spelling of `timeouts.idle_ms` and feeds the resolved upstream
idle deadline.

#### Top-level values refused at config compile

The same rule reaches a key the schema does describe when it is one
accepted *value* of that key that does nothing. No reader-based check can
see that case, because the key is read.

| Key | Why it is refused | What to use instead |
|---|---|---|
| `audit.sink: tracing` | It never selected anything. Emission to the `config_audit`, `security_audit`, and `key_audit` targets has always been unconditional, so `tracing` and `memory` described the same proxy. | `memory` for the same behavior under an honest name, or `chain` with a `path` and a `sign_with` for a hash-chained, signed trail that survives a restart. |
| `audit.path`, `audit.sign_with` under any sink but `chain` | Nothing would write to the file or sign anything. A path nothing writes to is the more dangerous of the two shapes, because it looks configured. | Set `sink: chain`, or remove the key. |

### Current config-only compatibility fields

| Field or subtree | What happens today |
|---|---|
| `agent_classes.hosted_feed.url`, `.bootstrap_keys` | The resolver uses builtin or inline catalogs; it does not fetch or verify a hosted feed. |
| `origins.*.action.resilience.circuit_breaker` | The AI router is built without per-provider breakers, so the breaker gate never fires. Setting `resilience` at all still widens cross-provider retries. |
| `origins.*.action.resilience.outlier_detection` | The AI router is built without an outlier detector, so no provider is ejected on failure rate. Use `resilience.health_check`, which is live. |
| `origins.*.action.targets[].zone` (load_balancer) | Target selection is not locality aware. The label is echoed in the admin targets view and nowhere else. |
| `origins.*.agent_skills[].max_clock_skew_secs` | Reserved for signed artifact freshness headers that are not emitted yet. |
| `origins.*.cors.enable` | The presence of `cors:` enables CORS; the legacy boolean value is ignored. |
| `origins.*.credentials[].attrs.budget.reset` | Reserved reset hint; no credential reset schedule is installed. The same leaf is config-only at proxy and tenant credential scopes. |
| `origins.*.forward_rules[].origin.hostname`, `.workspace_id`, `.version` | Inline forward-origin metadata is accepted but not copied into the compiled child origin. |
| `proxy.key_management.governance.key_introspection` | The caller-only introspection route is not installed. |
| `proxy.key_management.store.redis_source_of_truth` | Redis is authoritative whenever `store.backend: redis`; this legacy boolean changes nothing. |
| `proxy.observability.log.level`, `.format`, `.sampling` | Process logging uses CLI/environment selection and fixed sampling defaults. Sink-local `format` remains live. |
| `proxy.secrets.backend`, `.hashicorp`, `.map`, `.rotation`, `.fallback` | Legacy single-backend surface. Use named `proxy.secrets.backends` and provider URI references. |

---

## Selected field stability reference

The tables below cover representative and high-impact leaves. They do not
assign a tier to every property accepted by the configuration parser. Use the
tier definitions above only where a field is listed explicitly.

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

HTTP/3 is not served by this build. The block is retained for forward compatibility: omission or `enabled: false` compiles, while `enabled: true` fails config compilation and says so plainly.

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
| `error_pages` | - | array | - | **beta** | Custom error page entries, each matching one status or a list of statuses. |
| `traffic_capture` | - | object | - | **refused** | No consumer; setting it fails config load. Use `mirror`. |
| `connection_pool` | - | object | - | **stable** | Only `idle_timeout_secs` is read, as the legacy spelling of `timeouts.idle_ms`. `max_connections` and `max_lifetime_secs` fail config load. |
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

`level` is applied to whichever encoder the client negotiates, clamped
into that algorithm's native range (gzip 0-9, brotli 0-11, zstd 1-22).
Unset keeps each library's default (gzip and zstd defaults, brotli
quality 4).

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
| `text` | string | **beta** |

`text` is emitted as the reason phrase on the HTTP/1.x status line; absent
means the canonical phrase for `code`. HTTP/2 has no reason phrase on the
wire, so the value is ignored there.
