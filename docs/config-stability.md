# Config stability tiers

*Last modified: 2026-08-12*

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

`disabled` is a tier in this document, not a level in the build-time key
registry. That registry has four levels (`stable`, `preview`,
`config_only`, `unsupported`) and pins the three `proxy.http3` leaves
`config_only`, which is the accurate level for them: the keys parse and
nothing reads them. `unsupported` would be wrong, because that level
means the compiler rejects a document for containing the key at all, and
`http3:` with `enabled: false` compiles. `disabled` is those
`config_only` keys plus the one refused value, so `config_only` for
`proxy.http3.*` in registry-backed output is not a contradiction.

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
| `transforms[].on_response`, and its `expression` alias (`type: cel`) | Replaced the entire response body with whatever scalar the expression evaluated to. No partial edit, no structure-aware change, no streaming. CEL is for deciding; producing a payload is a different job, and no config in the tree ever authored the key. | A `javascript`, `lua_json`, or WASM transform, each of which parses the body, edits part of it, and re-emits. The same transform's `headers:` rules still set response headers from CEL. |

#### Schema keys refused at config compile

These parsed, warned once at boot, and then governed nothing. A warning
is the proportionate response to a key that does less than its name
promises while still doing something. `origins.*.action.targets[].zone`
is one: it renders a column in the admin target-health view and never
makes the proxy prefer a same-zone target, so refusing it would delete a
working label over a routing promise nobody made.

Refusal is for two other shapes. The first is a key with nothing behind
it at all, where a config that sets it keeps claiming a property the
proxy does not have: a connection cap nothing enforces, a retention
window nothing retires on, a catalog file nothing opens. The second is a
key that reads as the opposite of what it does. `cors.enable` was the
second one. The runtime turns CORS on when the `cors:` block is present
and never looks at the boolean inside it, so an operator who wrote
`enable: false` to switch CORS off switched it on. A boot warning next
to headers the proxy is already sending does not fix that.

Three of the rows below name a value rather than a key, because only one
of the accepted values misdescribed the build and the other agreed with
it. Those three keys stay writable at the value the proxy actually does.

Two further rows name a value for a different reason. The response
cache's `key_event` and `admit_event` take an inline script, and two of
the engine names an operator might reach for cannot answer the event at
all: one returns the wrong shape, the other is not inline source.
Neither is inert, so neither is a warning. They are refused where every
other engine mistake is caught, at config compile.

| Key | Why it is refused | What to use instead |
|---|---|---|
| `origins.*.connection_pool.max_connections` | Pingora sizes the upstream keepalive pool once per connector, not per origin, so there was no per-origin limit for the value to become and upstream connections were never capped at it. | A `concurrent_limit` policy, which caps in-flight requests per origin and rejects over the cap rather than queueing. |
| `origins.*.connection_pool.max_lifetime_secs` | Pingora's connection pool has no age-based eviction, so no pooled connection was ever retired for being old. | `timeouts.idle_ms`, the deadline that does retire pooled connections once they go unused. |
| `origins.*.cors.enable: false` (alias `enabled`) | Both entry points, the preflight responder and the response header pass, gate on the presence of the `cors:` block and neither reads the boolean. An operator who wrote `false` to switch CORS off ran with CORS fully on. `true` stays accepted, because it agrees with what the block already does. | Delete the whole `cors:` block to turn CORS off for that origin. To keep CORS on, delete just the `enable` line and narrow `allowed_origins` instead. |
| `origins.*.forward_rules[].origin.hostname` | The request has already been matched to the parent origin by the time a rule fires, so this tag selected no upstream and changed no header. The inline origin's `action`, `request_modifiers`, and `id` are the only three fields anything reads. | The rule's own `origin.action.url`, to send the matched request to a different host. To label the rule, use `origin.id`, which does reach metrics and the emitted OpenAPI document. |
| `origins.*.forward_rules[].origin.version` | The compiled child origin carries no version label, so the value reached neither routing, logs, metrics, nor the emitted OpenAPI document. | Match the version in the path instead (`rules: - path: { prefix: /v2/ }`). To version the rule for your own records, fold it into `origin.id`. |
| `origins.*.forward_rules[].origin.workspace_id` | The compiled child origin has no workspace field, so nothing scoped, attributed, or logged a request by it. | `origins.*.tenant_id`, naming an id declared under `proxy.tenants[]`. That one is checked at compile and labels the request everywhere downstream. |
| `origins.*.response_cache.key_event.engine: cel`, and the same value on `admit_event` | These events return a document, a list of key dimensions for `cache.key` and `store` plus `ttl_secs` for `cache.admit`, and CEL evaluates to a single scalar. Accepting it would mean a token grammar for packing a document into a string, which is what `route_to:gpt-4o-mini` already did once. | `lua` or `js`, which return documents natively. CEL keeps every surface where a scalar is the answer: `expression` and `assertion` policies, rate-limit and WAF keys, custom log fields, and the `cel` transform's header rules. |
| `origins.*.response_cache.key_event.engine: wasm`, and the same value on `admit_event` | The field takes an inline `source`, and a compiled module is not inline source, so there was nothing for the engine to evaluate. | `lua` or `js` for an inline script. For a compiled hook, attach it through an [extension bundle](extension-bundles.md), which is the surface that gives a module a path, a version, and a load step. |
| `origins.*.sessions.ttl_seconds` | There is no sessions index to retain. Sessions appear in the admin recent-request ring, which is bounded by entry count and evicts the oldest entry when full, so a session aged out on request volume and never on this deadline. | `sessions.budget.max_per_window` with `sessions.budget.window_seconds`, both enforced. |
| `origins.*.traffic_capture` | No capture consumer exists. The block was accepted as an untyped value, so nothing validated its contents either and a misspelled field inside it looked exactly like a working setting. | `mirror`, which forwards a fire-and-forget copy of each request to a second upstream without delaying or failing the real one. |
| `proxy.device_parser_file` | The device parser matches on compiled-in rules and has no code path that opens a catalog file, so a maintained catalog and a missing one behaved identically. | Nothing for device detection. `proxy.ai_providers_file` is the neighboring override that does work, and it applies to the AI provider catalog. |
| `proxy.key_management.governance.key_introspection: true` | No build installs a caller-facing introspection route, so the holder of a minted key had nothing to call and got the same 404 with the flag as without it. `false` is the default and is what the build does, so it stays accepted. | `GET /admin/keys/{id}` and `GET /admin/keys/{id}/usage` on the admin API, which read a key's policy and usage under an operator credential rather than the caller's own key. |
| `proxy.key_management.store.redis_source_of_truth: true` | The key plane picks its system of record from `store.backend` and from nothing else, so the flag offered a choice that does not exist: it could neither promote Redis under another backend nor demote it under its own. `false` stays accepted. | `proxy.key_management.store.backend`. Set `redis` with a `store.url` for a Redis-backed key store, or keep the default `embedded`, which is the local redb file. |
| `proxy.secrets.backend`, `proxy.secrets.fallback` | The resolver walks the named entries under `proxy.secrets.backends` and nothing else. The single-backend selector selected no backend, and the fallback selector was never reached, because an unresolved provider URI fails loudly instead of falling through to a second backend. | Declare each backend as a named entry under `proxy.secrets.backends` and reference it by name: `secret://<name>/<key>` for a local backend, `vault://<name>/<path>` for HashiCorp. The reference you write is what picks the backend. |
| `proxy.secrets.hashicorp.addr`, `.mount`, `.token` | The legacy inline HashiCorp block was parsed and never turned into a backend, so an address, a mount, and a token sat in the config while the resolver had no Vault registered to reach. | A `type: hashicorp` entry under `proxy.secrets.backends`. It takes the same `addr` and `mount` and reads its credential from the entry's `auth:` block, and references to it are `vault://<name>/<path>`. |

`origins.*.connection_pool.idle_timeout_secs` is not refused. It is the
legacy spelling of `timeouts.idle_ms` and feeds the resolved upstream
idle deadline.

`proxy.secrets.map` is not refused either, and it is no longer
config-only: the key registry pins it `stable`. Two things read it. A
non-empty map installs the process secret resolver on its own, with no
`backends` entry present. Its keys are also what `sbproxy plan` checks a
legacy `secret:<name>` reference against, so a config that declares the
block and leaves a referenced name out of it is a `missing-vault-key`
error and exits 3. What the map no longer does is resolve anything at
request time, because the `secret:<name>` reference form it served was
removed, and boot warns about that when the map is set. Write
`secret://<backend>/<name>` for live references.

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
| `agent_classes.hosted_feed.url`, `.bootstrap_keys` | The resolver uses builtin or inline catalogs; it does not fetch or verify a hosted feed. No fetcher is installed, and no signature check is installed for one either, so the bootstrap keys verify nothing. |
| `origins.*.action.targets[].zone` (load_balancer) | Target selection is not locality aware. The label has one reader, the admin target-health view behind `GET /api/health/targets`, so zoning your targets renders a column and does not make the proxy prefer a same-zone target. |
| `origins.*.agent_skills[].max_clock_skew_secs` | Reserved for signed artifact freshness headers that are not emitted yet. |
| `origins.*.credentials[].attrs.budget.reset` | Credential lowering copies `max_tokens` and `max_cost_usd` and nothing else, so the cap is cumulative and never resets. For a resetting cap today, use the AI action's `budget.limits[]`, which does take a `period`. The same leaf is config-only at proxy and tenant credential scopes. |
| `proxy.observability.log.sampling.info`, `.debug`, `.trace` | The process logger has no sampling call site, so no rate is applied at any level and every line is emitted. Throttle request logs with `access_log.sample_rate` instead. The sibling `log.level` and `log.format` are live; see [observability.md](observability.md) for where they sit against the CLI flags and `RUST_LOG`. |
| `proxy.secrets.rotation.grace_period_secs`, `.re_resolve_interval_secs` | The rotation runtime exists and implements exactly this grace window and interval, but nothing constructs it from this block and nothing drives the interval. Secrets are resolved once at boot and never again, so neither deadline is ever reached. Wiring it is tracked as future work. |

`origins.*.action.resilience.circuit_breaker` and
`.outlier_detection` used to be listed here and are not config-only any
more. The AI router installs both when the config asks for them, so they
are live and are pinned `stable` in the key registry.

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

The build-time key registry pins all three leaves `config_only` rather than `unsupported`, because the block itself stays legal and only the one value is refused. See the [`disabled`](#disabled) tier for why the two labels disagree on purpose.

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `enabled` | boolean | false | **disabled** | Must remain false until HTTP/3 is served. |
| `max_streams` | integer | 100 | **disabled** | Reserved max concurrent QUIC streams per connection. No QUIC listener starts, so nothing is capped. |
| `idle_timeout_secs` | integer | 30 | **disabled** | Reserved QUIC idle timeout in seconds. No QUIC listener starts, so nothing times out. |

The two tuning leaves have one live effect, and it is not on traffic:
`proxy.http3.**` carries a Restart blast radius, so editing either of
them turns an `sbproxy plan` reload into a restart.

### Origin Config (each entry under `origins:`)

| Field | Alias | Type | Default | Stability | Notes |
|---|---|---|---|---|---|
| `action` | - | object | required | **stable** | What the proxy does with requests. |
| `authentication` | `auth` | object | - | **stable** | Auth plugin config. |
| `policies` | - | array | `[]` | **stable** | Policy plugin list. |
| `transforms` | - | array | `[]` | **beta** | Body transform plugin list. |
| `request_modifiers` | - | array | `[]` | **stable** | Request modification steps. |
| `response_modifiers` | - | array | `[]` | **stable** | Response modification steps. |
| `cors` | - | object | - | **stable** | CORS policy. Presence of the block is what enables CORS. The legacy `enable: false` inside it fails config load, because it never turned CORS off. |
| `hsts` | - | object | - | **stable** | HSTS policy. |
| `compression` | - | object | - | **stable** | Response compression. |
| `session` | `session_config` | object | - | **beta** | Session cookie management. |
| `force_ssl` | - | boolean | false | **stable** | Redirect HTTP to HTTPS. |
| `allowed_methods` | - | array | `[]` (all) | **stable** | HTTP method allowlist. |
| `forward_rules` | - | array | `[]` | **beta** | Conditional routing rules. The inline origin's `hostname`, `version`, and `workspace_id` metadata fields fail config load. |
| `fallback_origin` | - | object | - | **beta** | Secondary origin on primary failure. |
| `response_cache` | - | object | - | **beta** | Response caching config. The `key_event` and `admit_event` decision events inside it are **alpha**, and an `engine` of `cel` or `wasm` on either fails config load. |
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
| `enable` | `enabled` | boolean | - | **refused** at `false` |

CORS is on for an origin exactly when that origin has a `cors:` block.
Nothing reads `enable`, so `false` never turned anything off and now
fails config load; `true` still compiles, because it agrees with what the
block does. Both spellings deserialize into the same field and are
checked together. Delete the block to turn CORS off.

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

### Response Cache (`response_cache:`)

The block is **beta** in the origin table above. The two decision events
are newer than the rest of it and their document shapes have not been
through a release yet, so they are tiered separately.

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `key_event` | object | - | **alpha** | Request-side `cache.key` script: `source` plus `engine`. Returns the dimensions folded into the cache key. |
| `admit_event` | object | - | **alpha** | Response-side `cache.admit` script, same shape. Returns whether the response is stored and for how long. |
| `key_event.engine`, `admit_event.engine` | string | required | **alpha** | `lua` or `js`. `cel` and `wasm` fail config load; see the refusal rows above. |
| `key_event.source`, `admit_event.source` | string | required | **alpha** | Inline script body. An empty one fails config load. |

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
