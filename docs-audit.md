# SBproxy Documentation Audit

Date: 2026-05-10
Scope: sbproxy/ (Rust). proxy/ (Go) is archived and excluded.

## Summary

- Total user-visible features identified: ~145 (CLI: 5 subcommands + 7 flags / env vars, modules: 14 action variants, 9 auth variants, 22 policy variants, 24 transform variants, 4 extension surfaces with their host bindings, 5 projection kinds, 4 storage backends, 4 cache backends, 4 messenger backends, plus the top-level config blocks, the well-known endpoints, and the metrics/health surface).
- Existing docs: 53 files (accurate: 35, stale: 13, aspirational or partially aspirational: 5).
- Features in code with no doc (missing): roughly 15 substantive gaps (see Feature Inventory and Existing Docs Review). Most are minor (one config field, one transform variant) but a handful are user-visible features without a home (semantic-constraint policy, A2A policy, idempotency middleware, problem-details middleware, message-signatures middleware, http-framing policy, request-validator policy as a doc page).
- Aspirational items to delete or rewrite:
  - `events` crate referenced in `sbproxy/CLAUDE.md` as one of the public crates. Does not exist. Recommendation: keep `CLAUDE.md` accurate (it already notes "planned but not yet implemented"), do not advertise in user docs.
  - `proxy` crate referenced in `sbproxy/CLAUDE.md` as one of the public crates. Does not exist. Same recommendation.
  - `comparison.md` claims response-cache backends include `sled`. The real backends are `memory`, `file`, `memcached`, `redis`. Recommendation: rewrite the row.
  - `codebase.md` calls the WASM module a passthrough stub. The runtime is actually a full `wasmtime` + WASI preview-1 integration with fuel metering, memory limits, and host import isolation. Recommendation: rewrite the WASM section.
  - `codebase.md` is missing the `redis` response-cache backend in its `sbproxy-cache` section (lists only memory, file, memcached). Recommendation: add a `redis.rs` entry.
- Scope recommendation: deferred to the final section, but in short the gap is small enough that a full doc refresh is feasible in one pass (no need to phase).

## Feature Inventory

### Workspace and crates

#### sbproxy (binary)
- Source: `crates/sbproxy/Cargo.toml`, `crates/sbproxy/src/main.rs`.
- Builds the `sbproxy` binary, installs `mimalloc` (`src/main.rs:16`), installs the `ring` rustls crypto provider (`src/main.rs:24`), wires the CLI, and delegates the proxy runtime to `sbproxy_core::run`. Doc status: covered by `manual.md` (accurate for the CLI flag surface; one stale "Planned, not yet wired" claim, see Existing Docs Review).
- Feature flags (default-on): `tiered-pricing`, `agent-class`, `http-ledger`, `content-negotiate`, `licensing-rsl`, `licensing-tdmrep`, `llms-txt`, `tls-fingerprint` (`crates/sbproxy/Cargo.toml:33-45`). Doc status: covered by `feature-flags.md` and `manual.md` §10.

#### sbproxy-core
Source: `crates/sbproxy-core/src/lib.rs`. Modules: `admin`, `agent_class` (feature-gated), `builtin_enforcers`, `context`, `dispatch`, `hook_registry`, `hooks`, `identity`, `pipeline`, `policy_bus`, `policy_dispatch`, `reload`, `router`, `sb_flags`, `server`, `synthetic`, `wave8`.
- Pingora `ProxyHttp` impl `SbProxy` (`crates/sbproxy-core/src/server.rs`). Doc status: described in `architecture.md` and `codebase.md` (accurate).
- Hot reload via `ArcSwap<CompiledPipeline>` (`src/reload.rs`, `src/server.rs`). Doc status: accurate in `manual.md` §9 and `architecture.md`.
- Admin endpoint handlers `handle_admin_request` (`src/admin.rs:864`). Doc status: covered by `manual.md` §5 and `events.md` indirectly. Routes listed under HTTP routes below.
- Per-request feature flags via `x-sb-flags` header and `?_sb.<k>` query params (`src/sb_flags.rs`). Doc status: covered by `feature-flags.md` and `headers-reference.md`.
- Synthetic-transaction probe driver (`src/synthetic.rs`). Doc status: in `observability.md` and `manual.md` §6; the config block is documented in `configuration.md`.
- Wave 8 edge capture (`src/wave8.rs`). Doc status: covered piecewise by `access-log.md` (properties / sessions / user fields).

#### sbproxy-config
Source: `crates/sbproxy-config/src/lib.rs`. Public re-exports: `compiler`, `duration`, `listing`, `plan`, `raw`, `snapshot`, `types`, `validate`.
- `compile_config(yaml: &str)` -> `CompiledConfig` (`src/compiler.rs`). Doc status: covered in `configuration.md`.
- `plan(baseline, proposed)`, `plan_with_options`, `compute_baseline_revision`, `PlanFile`, `render_text` (`src/plan.rs`). Doc status: documented in `adr-config-plan-apply.md`. Accurate.
- `Listing` primitive + loader: `load_listings_from_repo`, `validate_listings`, `ListingRegistry`, `NoopRevisionResolver`, `StaticRevisionResolver` (`src/listing.rs`). Doc status: covered by `listings.md`. Accurate.
- `validate` module: `KNOWN_ACTION_TYPES`, `KNOWN_AUTH_TYPES`, `KNOWN_POLICY_TYPES`, `KNOWN_TRANSFORM_TYPES` (`src/validate.rs`). Doc status: types not enumerated in any single reference, but each item is mentioned in `configuration.md`.

#### sbproxy-modules
Source: `crates/sbproxy-modules/src/lib.rs`. Modules under `action/`, `auth/`, `policy/`, `transform/`, `projections/`, plus `compile.rs`. See "Action handlers", "Auth providers", "Policies", "Transforms", and "Projections" below for the full enum-by-enum inventory.

#### sbproxy-plugin
Source: `crates/sbproxy-plugin/src/lib.rs`. Modules: `audit`, `context`, `identity`, `lifecycle`, `registry`, `traits`. Public traits: `ActionHandler`, `PolicyEnforcer`, `AuthProvider`, `TransformHandler`, `RequestEnricher`, plus the identity / anomaly / ML classifier hooks. Doc status: trait surface is referenced in `features.md` §"Plugin system". Accurate but explicitly internal-facing (per the "install + extension story is configuration, not traits" rule).

#### sbproxy-httpkit
Source: `crates/sbproxy-httpkit/src/lib.rs`. Modules: `bufferpool`. The only public type is `bufferpool::BufferPool`. Doc status: described in `codebase.md`. Accurate.

#### sbproxy-platform
Source: `crates/sbproxy-platform/src/lib.rs`. Modules: `adaptive_breaker`, `circuitbreaker`, `dns`, `health`, `messenger/{memory, redis, aws_sqs, gcp_pubsub}`, `outlier`, `proxy_protocol`, `storage/{memory, file, redis, postgres, sqlite, redb_store, async_kv, async_redis}`. Doc status: described in `codebase.md`. Accurate (`messenger/aws_sqs.rs` aligns with public `SqsMessenger`).

#### sbproxy-cache
Source: `crates/sbproxy-cache/src/lib.rs`. Modules: `reserve`, `response`, `store`, `two_tier`. Stores: `memory`, `file`, `memcached`, `redis` (`src/store/`). Reserve backends: `MemoryReserve`, `FsReserve`, `RedisReserve` (`src/reserve/`). Doc status: covered by `cache-reserve.md` (accurate) and `configuration.md` (accurate). `codebase.md` is stale: it lists memory/file/memcached and omits redis; cache reserve is not described.

#### sbproxy-ai
Source: `crates/sbproxy-ai/src/lib.rs`. Modules: `ai_metrics`, `alerting`, `api_routes`, `assistants`, `audio`, `batch`, `budget`, `client`, `concurrency`, `context_compress`, `context_overflow`, `context_relay`, `degradation`, `fill_first`, `finetune`, `guardrails`, `handler`, `hierarchical_budget`, `idempotency`, `identity`, `image`, `judge`, `key_scoping`, `model_alias`, `multimodal`, `prompt_cache`, `provider`, `provider_ratelimit`, `providers`, `ratelimit`, `realtime`, `response_dedup`, `routing`, `semantic_cache`, `session`, `streaming`, `streaming_analytics`, `structured_output`, `threads`, `tracing_spans`, `translators`, `types`, `usage_parser`. Public re-exports include `BudgetTracker`, `BudgetConfig`, `OnExceedAction`, `Router`, `RoutingStrategy`, `ConcurrencyLimiter`, `ModelAlias`, `ModelAliasRegistry`, `IdempotencyCache`, `KeyStore`, `VirtualKeyConfig`, `KeyPermissions`, `Modality`, `ProviderInfo`, `ProviderFormat`, `SemanticCache`, `SessionStore`, and the streaming helpers. Doc status: most surfaces are described in `ai-gateway.md` and `providers.md`; some details (`response_dedup`, `streaming_analytics`, `structured_output`, `tracing_spans`, `translators`, `realtime`, `usage_parser`, `assistants`, `threads`, `batch`, `image`, `audio`, `finetune`) are not enumerated in any doc.

#### sbproxy-extension
Source: `crates/sbproxy-extension/src/lib.rs`. Public modules: `cel`, `flags`, `js`, `lua`, `mcp`, `wasm`.
- CEL: `cel::{CelExpression, CelContext}` plus `context.rs` and `functions.rs` for HTTP-shaped accessors (`crates/sbproxy-extension/src/cel/`). Doc status: covered by `scripting.md` §3.
- Lua: `mlua` with Luau dialect, sandboxed (`crates/sbproxy-extension/src/lua/`). Doc status: covered by `scripting.md` §4.
- JavaScript: QuickJS via `rquickjs` (`crates/sbproxy-extension/src/js/mod.rs`). Doc status: covered by `scripting.md` §5.
- WASM: `wasmtime` 44 + WASI preview-1 (`crates/sbproxy-extension/src/wasm/mod.rs`). Doc status: covered by `wasm-development.md` and `scripting.md` §6 (accurate). `codebase.md` is stale on this (calls it a passthrough stub).
- MCP server / federation (`crates/sbproxy-extension/src/mcp/`). Doc status: covered by `mcp.md` (very short; many submodules unmentioned).
- `flags`: per-request feature-flag surface. Doc status: covered by `feature-flags.md`.

#### sbproxy-observe
Source: `crates/sbproxy-observe/src/lib.rs`. Public modules: `access_log`, `agent_labels`, `alerting`, `audit`, `capture`, `cardinality`, `clock_skew`, `events`, `exemplars`, `export`, `fake_sinks`, `golden_signals`, `health`, `logging`, `metrics`, `notify`, `redact`, `request_event`, `request_sink`, `synthetic`, `telemetry`, `topology`, `trace_ctx`. Doc status: metrics covered by `metrics-stability.md`; events covered by `events.md`; access log covered by `access-log.md`; audit covered by `audit-log.md`; telemetry/trace context covered by `observability.md`; webhook exporter and `Notifier` covered piecewise by `observability.md`. `agent_labels`, `cardinality`, `clock_skew`, `exemplars`, `golden_signals`, `topology`, `redact`, `request_sink`, `fake_sinks` are not described in any single doc.

#### sbproxy-security
Source: `crates/sbproxy-security/src/lib.rs`. Modules: `agent_verify` (feature-gated `agent-class`), `crypto`, `headless_detect` (feature-gated `tls-fingerprint`), `hostfilter`, `ip`, `pii`, `ssrf`. Doc status: covered piecewise by `threat-model.md` and `headers-reference.md`. The headless-detect surface is mentioned in `ai-crawl-control.md` and `features.md`.

#### sbproxy-tls
Source: `crates/sbproxy-tls/src/lib.rs`. Modules: `acme`, `alt_svc`, `cert_resolver`, `cert_store`, `challenges`, `fingerprint`, `h3_listener`, `mtls`, `ocsp`. Doc status: TLS + ACME + HTTP/3 surfaces are described in `manual.md` §7 and `configuration.md`. Fingerprint is mentioned in `web-bot-auth.md`. OCSP is mentioned in `manual.md` §7.

#### sbproxy-transport
Source: `crates/sbproxy-transport/src/lib.rs`. Modules: `auto_pool`, `coalescing`, `dedup`, `hedging`, `mirroring`, `ratelimit`, `retry`. Doc status: covered by `performance.md` (accurate for retry / coalescing / hedging), `features.md` for mirror.

#### sbproxy-vault
Source: `crates/sbproxy-vault/src/lib.rs`. Modules: `convergent`, `local`, `manager`, `metadata`, `resolver`, `rotation`, `scope`, `secret_string`. Doc status: covered by `configuration.md` (secret-resolution section) and `codebase.md` (accurate).

#### sbproxy-middleware
Source: `crates/sbproxy-middleware/src/lib.rs`. Modules: `callback`, `compression`, `cors`, `error_pages`, `hsts`, `idempotency`, `modifiers`, `problem_details`, `proxy_status`, `signatures`. Doc status: cors, hsts, compression covered by `configuration.md`. Idempotency, problem-details, proxy-status, signatures are not documented as a feature anywhere in `docs/`; idempotency-key is mentioned in passing in `features.md` §11.6.

#### sbproxy-openapi
Source: `crates/sbproxy-openapi/src/lib.rs`. Public API: `build`, `render_json`, `render_yaml`, `AuthSchemeMapper`. Doc status: covered by `openapi-emission.md`. Accurate.

#### sbproxy-k8s-operator
Source: `crates/sbproxy-k8s-operator/src/lib.rs`. CRDs: `SBProxy` (`sbproxy.dev/v1alpha1`), `SBProxyConfig` (`sbproxy.dev/v1alpha1`). Reconcile loop in `reconcile.rs`. Leader election in `leader.rs`. Doc status: covered by `kubernetes.md` and `quickstart-operator.md`. Accurate.

#### sbproxy-classifiers
Source: `crates/sbproxy-classifiers/src/lib.rs`. Modules: `agent_class`, `agent_classifier_types`, `known_models`. Public API: `OnnxClassifier` with `download_and_load`. Doc status: covered by `onnx-classifier.md` and `model-pinning.md`. Accurate. Used by the `prompt_injection_v2` policy.

### CLI (binary `sbproxy`)
Source: `crates/sbproxy/src/main.rs`. The argv parser is hand-rolled (no clap); subcommands are matched by string compare.

Subcommands:
- `sbproxy serve` (default when only `--config` is passed). Source: `main.rs:171-194`. Doc status: accurate in `manual.md` §2.
- `sbproxy validate <path>` (alias: `--check`). Source: `main.rs:101-120`, `handle_validate_subcommand` at line 413. Doc status: accurate in `manual.md` §2.
- `sbproxy plan -f <yaml> [--against <yaml>] [--format json|text] [--out <plan-file>]`. Source: `main.rs:151-158`, `handle_plan_subcommand` at line 760. Doc status: documented in `adr-config-plan-apply.md`. Not surfaced in `manual.md` CLI section (stale: `manual.md` does not list `plan` or `apply` as subcommands at all in §2).
- `sbproxy apply -f <yaml>` or `sbproxy apply -p <plan-file>`. Source: `main.rs:160-168`, `handle_apply_subcommand` at line 882. Doc status: documented in `adr-config-plan-apply.md`. Not surfaced in `manual.md` §2.
- `sbproxy projections render --kind {robots|llms|llms-full|licenses|tdmrep} --config <path> [--hostname <h>]`. Source: `main.rs:128-136`, `handle_projections_subcommand` at line 345. Doc status: covered in `manual.md` §2 (one-line mention), `agent-skills.md` (no), `content-for-agents.md`, `rsl.md` (the licenses + tdmrep projections), `ai-crawl-control.md` (no). The render command itself is not described as a CLI surface in any doc.
- `sbproxy --version` / `-V` / `version`. Source: `main.rs:69-80`. Doc status: noted in `manual.md` §1.
- `sbproxy --help` / `-h` / `help`. Source: `main.rs:85-91`. Doc status: noted in `manual.md` §1.

Flags + env vars (server-process surface, not config):
- `--config <path>` / `-f <path>` (positional `<path>` also accepted). Env: `SB_CONFIG_FILE`. Source: `main.rs:306` (`parse_config_path`).
- `--log-level <level>`. Env: `SB_LOG_LEVEL` (fallback to `RUST_LOG`, then `info`). Source: `main.rs:205` (`resolve_log_filter`).
- `--request-log-level <level>`. Env: `SB_REQUEST_LOG_LEVEL`. Adds `access_log=<level>` to the tracing filter. Source: `main.rs:237`.
- `--grace-time <secs>`. Env: `SB_GRACE_TIME`. Stashed into env at parse time so `sbproxy_core::run` picks it up. Source: `main.rs:251`.
- `--disable-sb-flags`. Env: `SB_DISABLE_SB_FLAGS` (accepts `1` / `true` / `yes` / `on`). Source: `main.rs:271`. Doc status: `manual.md` §2 incorrectly lists this under "Planned, not yet wired"; the flag is actually wired (sets `sbproxy_core::sb_flags::set_disabled(true)`). Stale.
- `--check`. Source: `main.rs:101`. Alias for `validate`.
- `SB_APPLY_CONFIG` (env-only). Source: `main.rs:943` in `handle_apply_from_plan_file`. Required when running `apply -p`. Doc status: documented in `adr-config-plan-apply.md`. Missing from `manual.md` §13.
- `SB_APPLY_BASELINE` (env-only). Source: `main.rs:964`. Override baseline for `apply -p`. Doc status: documented in `adr-config-plan-apply.md`. Missing from `manual.md` §13.

### Configuration surface

The top-level `ConfigFile` (`crates/sbproxy-config/src/types.rs:14`) has the following keys (serde-renamed). Each row gives: serde key, type, default, source citation, doc status.

| Key | Type | Default | Source | Doc status |
|---|---|---|---|---|
| `proxy` | `ProxyServerConfig` | default-constructed | `types.rs:14, 155` | accurate (`configuration.md`) |
| `origins` | `HashMap<String, RawOriginConfig>` | empty | `types.rs:20, 1375` | accurate |
| `access_log` | `Option<AccessLogConfig>` | None | `types.rs:26, 991` | accurate (`access-log.md`) |
| `agent_classes` | `Option<AgentClassesConfig>` | None | `types.rs:33, 47` | accurate (referenced in `web-bot-auth.md`) |

`ProxyServerConfig` (`types.rs:155`) fields:
- `http_bind_port: u16` (default 8080). Doc status: accurate.
- `http2_cleartext: bool` (default false). Doc status: accurate.
- `https_bind_port: Option<u16>`. Doc status: accurate.
- `tls_cert_file: Option<String>`, `tls_key_file: Option<String>`. Doc status: accurate.
- `acme: Option<AcmeConfig>` (`types.rs:896`). Doc status: accurate.
- `http3: Option<Http3Config>` (`types.rs:1297`). Doc status: accurate.
- `metrics: Option<MetricsConfig>` (`types.rs:944`) and `cardinality` (`types.rs:969`). Doc status: cardinality missing from any reference (covered in code only).
- `alerting: Option<AlertingConfig>` (`types.rs:1274`). Doc status: covered in `observability.md`.
- `admin: Option<AdminConfig>` (`types.rs:853`). Doc status: accurate.
- `secrets: Option<SecretsConfig>` (`types.rs:2086`). Doc status: accurate.
- `l2_cache: Option<L2CacheConfig>` (`types.rs:705`). Doc status: accurate.
- `cache_reserve: Option<CacheReserveConfig>` (`types.rs:739`). Doc status: accurate (`cache-reserve.md`).
- `messenger_settings: Option<MessengerSettings>` (`types.rs:841`). Doc status: accurate.
- `trusted_proxies: Vec<String>`. Doc status: accurate.
- `correlation_id: CorrelationIdConfig` (`types.rs:443`). Doc status: accurate.
- `mtls: Option<MtlsListenerConfig>` (`types.rs:411`). Doc status: accurate.
- `ai_providers_file: Option<String>`. Doc status: covered in `providers.md`.
- `device_parser_file: Option<String>`. Doc status: not surfaced (parser swap is reserved per code comment).
- `synthetic_probe: Option<SyntheticProbeConfig>` (`types.rs:323`). Doc status: accurate.
- `extensions: HashMap<String, serde_yaml::Value>` (opaque). Doc status: accurate.

`RawOriginConfig` (`types.rs:1375`) per-origin fields: `action`, `authentication` (alias `auth`), `policies`, `transforms`, `request_modifiers`, `response_modifiers`, `cors`, `hsts`, `compression`, `session` (alias `session_config`), `properties`, `sessions`, `user`, `force_ssl`, `allowed_methods`, `forward_rules`, `fallback_origin`, `response_cache`, `variables`, `on_request`, `on_response`, `bot_detection`, `threat_protection`, `rate_limit_headers`, `error_pages`, `traffic_capture`, `mirror`, `message_signatures`, `connection_pool`, `extensions`, `expose_openapi`, `stream_safety`, `rate_limits`, `default_content_shape`, `content_signal`, `token_bytes_ratio`, `agent_skills`. Doc status: all of the above are covered in `configuration.md` and the per-feature pages (cors, hsts, compression, error-pages, mirror, agent-skills, etc.). `stream_safety`, `connection_pool`, `default_content_shape`, `content_signal`, `token_bytes_ratio` are not given dedicated treatment in any single doc page.

### Action handlers
Enum: `Action` (`crates/sbproxy-modules/src/action/mod.rs:42`). Wire `type` strings come from `Action::action_type()` (`mod.rs:696`).

| `type` | Source | Doc status |
|---|---|---|
| `proxy` | `mod.rs:84` (`ProxyAction`) | accurate (`configuration.md`) |
| `redirect` | `mod.rs:494` (`RedirectAction`) | accurate; bulk-list source covered by `bulk-redirects.md` |
| `static` | `mod.rs:601` (`StaticAction`) | accurate |
| `echo` | `mod.rs:642` (`EchoAction`) | accurate |
| `mock` | `mod.rs:659` (`MockAction`) | accurate |
| `beacon` | `mod.rs:684` (`BeaconAction`) | accurate |
| `load_balancer` | `action/loadbalancer.rs` | accurate (`routing-strategies.md`) |
| `ai_proxy` | `action/aiproxy.rs` | covered by `ai-gateway.md` |
| `websocket` | `action/websocket.rs` | accurate |
| `grpc` | `action/grpc.rs` and `grpc_web.rs` | accurate |
| `graphql` | `action/graphql.rs` | accurate |
| `storage` | `action/storage.rs` (object_store: S3, GCS, Azure, fs) | accurate |
| `a2a` | `action/a2a.rs` | covered in `enterprise.md` and shipped-features memory |
| `mcp` | `action/mcp.rs` | accurate (`mcp.md`) |
| `noop` | `mod.rs:76` | accurate |
| `plugin` | `mod.rs:78` (Box<dyn ActionHandler>) | accurate |

### Auth providers
Enum: `Auth` (`crates/sbproxy-modules/src/auth/mod.rs:67`). Wire `type` strings come from `Auth::auth_type()` (`mod.rs:97`).

| `type` | Source | Doc status |
|---|---|---|
| `api_key` | `auth/mod.rs:135` (`ApiKeyAuth`) | accurate |
| `basic_auth` | `auth/mod.rs:186` (`BasicAuthProvider`) | accurate |
| `bearer` | `auth/mod.rs:248` (`BearerAuth`) | accurate |
| `jwt` | `auth/mod.rs:286` (`JwtAuth`) + `auth/jwks.rs` | accurate |
| `digest` | `auth/mod.rs:446` (`DigestAuth`) | accurate |
| `forward_auth` | `auth/mod.rs:705` (`ForwardAuthProvider`) | accurate |
| `bot_auth` | `auth/bot_auth.rs` + `bot_auth_directory.rs` | accurate (`web-bot-auth.md`) |
| `cap` | `auth/cap.rs` | accurate; described in shipped-features memory and `enterprise.md` |
| `noop` | enum literal | accurate |
| `plugin` | enum literal | accurate |

### Policies
Enum: `Policy` (`crates/sbproxy-modules/src/policy/mod.rs:118`). Wire `type` strings come from `Policy::policy_type()` (`mod.rs:203`).

| `type` | Source | Doc status |
|---|---|---|
| `rate_limiting` | `policy/rate_limit.rs` | accurate (`features.md` §11.x) |
| `ip_filter` | `policy/ip_filter.rs` | accurate |
| `security_headers` | `policy/sec_headers.rs` | accurate |
| `request_limit` | `policy/request_limit.rs` | accurate |
| `csrf` | `policy/csrf.rs` | accurate |
| `ddos` | `policy/ddos.rs` | accurate |
| `sri` | `policy/sri.rs` | accurate |
| `expression` | `policy/expression.rs` | accurate (CEL/Lua boolean condition) |
| `assertion` | `policy/assertion.rs` | covered in `scripting.md`; could use a dedicated mention in `policy.md` |
| `waf` | `policy/waf/mod.rs`, `feed.rs`, `policy.rs` | accurate |
| `request_validator` | `policy/request_validator.rs` (JSON Schema) | missing dedicated doc |
| `concurrent_limit` | `policy/concurrent_limit.rs` | missing dedicated doc |
| `ai_crawl_control` | `policy/ai_crawl.rs` | accurate (`ai-crawl-control.md`) |
| `exposed_credentials` | `policy/exposed_creds.rs` | accurate (`exposed-credentials.md`) |
| `page_shield` | `policy/page_shield.rs` | accurate |
| `dlp` | `policy/dlp.rs` | accurate |
| `openapi_validation` | `policy/openapi_validation.rs` | accurate (`openapi-validation.md`) |
| `prompt_injection_v2` | `policy/prompt_injection_v2/` | accurate (`prompt-injection-v2.md`) |
| `http_framing` | `policy/http_framing.rs` | missing dedicated doc |
| `agent_class` | `policy/agent_class.rs` (feature `agent-class`) | accurate in `agent-skills.md` only obliquely; could use a callout |
| `a2a` | `policy/a2a.rs` | missing dedicated doc page; mentioned in `enterprise.md` and shipped-features memory |
| `semantic_constraint` | `policy/semantic_constraint.rs` | accurate (`policy.md`) |
| `plugin` | enum literal | accurate |

### Transforms
Enum: `Transform` (`crates/sbproxy-modules/src/transform/mod.rs:89`). Wire `type` strings come from `Transform::transform_type()` (`mod.rs:168`).

| `type` | Source | Doc status |
|---|---|---|
| `json` | `transform/json.rs::JsonTransform` | accurate |
| `json_projection` | `transform/json.rs::JsonProjectionTransform` | accurate |
| `json_schema` | `transform/json.rs::JsonSchemaTransform` | accurate |
| `template` | `transform/text.rs::TemplateTransform` | accurate |
| `replace_strings` | `transform/text.rs::ReplaceStringsTransform` | accurate |
| `normalize` | `transform/text.rs::NormalizeTransform` | accurate |
| `encoding` | `transform/text.rs::EncodingTransform` | accurate |
| `format_convert` | `transform/text.rs::FormatConvertTransform` | accurate |
| `payload_limit` | `transform/control.rs::PayloadLimitTransform` | accurate |
| `discard` | `transform/control.rs::DiscardTransform` | accurate |
| `sse_chunking` | `transform/control.rs::SseChunkingTransform` | accurate |
| `html` | `transform/markup.rs::HtmlTransform` | accurate |
| `optimize_html` | `transform/markup.rs::OptimizeHtmlTransform` | accurate |
| `html_to_markdown` | `transform/markup.rs::HtmlToMarkdownTransform` | accurate |
| `markdown` | `transform/markup.rs::MarkdownTransform` | accurate |
| `css` | `transform/markup.rs::CssTransform` | accurate |
| `lua_json` | `transform/json.rs::LuaJsonTransform` (via `sbproxy-extension`) | accurate |
| `javascript` | `transform/text.rs::JavaScriptTransform` (via `sbproxy-extension`) | accurate |
| `js_json` | `transform/json.rs::JsJsonTransform` (via `sbproxy-extension`) | accurate |
| `wasm` | `transform/control.rs::WasmTransform` (via `sbproxy-extension`) | accurate (`wasm-development.md`) |
| `boilerplate` | `transform/boilerplate.rs::BoilerplateTransform` | accurate (`content-for-agents.md`) |
| `citation_block` | `transform/citation_block.rs::CitationBlockTransform` | accurate (`content-for-agents.md`) |
| `json_envelope` | `transform/json_envelope.rs::JsonEnvelopeTransform` | accurate |
| `cel` (CelScript) | `transform/cel_script.rs::CelScriptTransform` | accurate (`scripting.md`) |
| `noop` | enum literal | accurate |
| `plugin` | enum literal | accurate |

### Extension surfaces

- CEL. Wired into: `forward_rules[].match.cel`, `request_modifiers.cel`, `response_modifiers.cel`, `policies[].expression`, `routing.{model_selector, provider_selector, cache_bypass, dynamic_rpm}`, `cel_guardrails[].condition`, and the `cel` transform. Context namespaces: `request`, `response`, `vars`, `env`, `session`, `secret`, `now`, `time`, `regex` (plus AI-routing ones). Source: `crates/sbproxy-extension/src/cel/`. Doc status: accurate in `scripting.md` §3.
- Lua. Wired into: `forward_rules[].match.lua`, `request_modifiers.lua`, `response_modifiers.lua`, `lua_json` transform, and policy `expression` (Lua mode). Implementation: `mlua` + Luau dialect. Source: `crates/sbproxy-extension/src/lua/`. Doc status: accurate.
- JavaScript. Wired into: `request_modifiers.js`, `response_modifiers.js`, `javascript` and `js_json` transforms. Implementation: `rquickjs` (QuickJS). Source: `crates/sbproxy-extension/src/js/`. Doc status: accurate.
- WASM. Wired into: `wasm` transform (and the MCP code-mode runtime). Implementation: `wasmtime` 44 + WASI preview-1. Source: `crates/sbproxy-extension/src/wasm/`. Doc status: accurate in `wasm-development.md`; `codebase.md` is stale on this one.

### Projections (well-known well-named documents)
Enum-keyed registry: `ProjectionDocs` (`crates/sbproxy-modules/src/projections/mod.rs`).

| Kind | Path | Source | Doc status |
|---|---|---|---|
| `robots` | `/robots.txt` | `projections/robots.rs` | accurate (`content-for-agents.md`) |
| `llms` | `/llms.txt` | `projections/llms.rs` | accurate (`llms.txt`) |
| `llms-full` | `/llms-full.txt` | `projections/llms.rs` | accurate |
| `licenses` | `/licenses.xml` | `projections/licenses.rs` | accurate (`rsl.md`) |
| `tdmrep` | `/.well-known/tdmrep.json` | `projections/tdmrep.rs` | accurate |
| (agent skills) | `/.well-known/agent-skills/index.json` | `projections/agent_skills.rs` + `server.rs:6193` | accurate (`agent-skills.md`) |

### HTTP routes (data-plane endpoints terminated by the proxy itself)

| Method | Path | Handler / Source | Doc status |
|---|---|---|---|
| GET | `/healthz`, `/livez`, `/health`, `/readyz`, `/ready` | `sbproxy_observe::handle_healthz`/`handle_livez`/`handle_readyz`/`handle_health` (`crates/sbproxy-observe/src/health.rs:366-409`); dispatched from `crates/sbproxy-core/src/server.rs` and `admin.rs:883-892`. | accurate |
| GET | `/metrics` | Prometheus text from `metrics().render()` (`server.rs:7247`) | accurate |
| POST | `/admin/reload` | `handle_reload` (`admin.rs:620, 927`) | accurate |
| GET | `/admin/drift` | `handle_drift` (`admin.rs:793, 940`) | accurate |
| GET | `/api/requests` | `admin.rs:954` | partially documented (admin API in `manual.md` §5) |
| GET | `/api/health`, `/api/health/targets` | `admin.rs:967, 975` | partially documented |
| GET | `/api/openapi.json` / `.yaml` | `render_openapi` (`admin.rs:983, 995`) | accurate (`openapi-emission.md`) |
| GET | `/api/stats` | `admin.rs:1005` | partially documented |
| GET | `/.well-known/sbproxy/quote-keys.json` | `render_quote_keys_jwks` (`admin.rs:904`) | mentioned in `402-challenge.md` |
| GET | `/.well-known/openapi.json` / `.yaml` (per-origin) | `server.rs:7644-7645` (only when origin `expose_openapi: true`) | accurate |
| GET | `/.well-known/agent-skills/index.json` (per-origin) | `server.rs:7397, 7512` | accurate (`agent-skills.md`) |
| GET | `/.well-known/acme-challenge/<token>` | `crates/sbproxy-tls/src/challenges.rs:12` | accurate (`manual.md`) |
| GET | `/robots.txt`, `/llms.txt`, `/llms-full.txt`, `/licenses.xml`, `/.well-known/tdmrep.json` | Projection serving in `server.rs:437, 9637`, etc. | accurate |
| POST | Page Shield CSP report intake | `policy::page_shield::DEFAULT_REPORT_PATH`, `server.rs:7265` | accurate |

The admin endpoints `/api/requests`, `/api/health`, `/api/health/targets`, `/api/stats`, and the test-only `/api/_test/sinks/...` fan-out are described in `manual.md` §5 but the schema of `/api/stats` and `/api/health/targets` JSON is not documented anywhere.

### Metrics
Source: `crates/sbproxy-observe/src/metrics.rs`. All exported counters/histograms live in `metrics().render()` and are prefixed `sbproxy_*`. Doc status: stability contract covered by `metrics-stability.md`. Individual labels for the agent-class bundle covered by `agent_labels.rs` but no docs page describes the full label set.

## Existing Docs Review

One row per file in `sbproxy/docs/`. Stale and aspirational rows include a one-line "why" with code evidence.

| File | Status | Notes |
|---|---|---|
| `README.md` | accurate | Index hub; cross-references all the per-feature pages. |
| `manual.md` | stale (in 1 spot) | §2 still lists `--disable-sb-flags` and `SB_DISABLE_SB_FLAGS` under "Planned, not yet wired" but the flag is wired in `crates/sbproxy/src/main.rs:55-57, 271-282`. Also missing: `sbproxy plan` and `sbproxy apply` subcommands; `SB_APPLY_CONFIG` / `SB_APPLY_BASELINE` env vars; CRD types in §12 are not enumerated. |
| `configuration.md` | accurate | Long, dense, matches code field-by-field for the verified blocks (server, origin, agent_classes, listings, projections). |
| `features.md` | accurate (mostly) | `features.md` §"Plugin system" intentionally references the `sbproxy-plugin` trait surface. Per the project rule "install + extension is configuration, not traits", this is acceptable for a contributor-flavoured doc but should not be advertised as the user extension path. Recommend a callout at the top of the §"Plugin system" section. |
| `troubleshooting.md` | accurate | Sampled; reads like a runbook against the actual env vars and admin endpoints. |
| `ai-gateway.md` | accurate | Lines up with `sbproxy-ai` public re-exports (routing strategies, budgets, virtual keys, MCP). Some sub-features (`assistants`, `threads`, `batch`, `image`, `audio`, `finetune`, `realtime`, `structured_output`, `response_dedup`, `streaming_analytics`, `usage_parser`, `translators`) exist as modules but are not enumerated in the doc. |
| `providers.md` | accurate | Matches `crates/sbproxy-ai/src/providers/mod.rs::ProviderInfo`. |
| `scripting.md` | accurate | Matches `crates/sbproxy-extension/src/cel`, `lua`, `js`, `wasm`. |
| `mcp.md` | stale (lite) | Doc is only ~5 headings; the `crates/sbproxy-extension/src/mcp/` directory has 15 source files including `access_control`, `audit`, `code_mode`, `context_opt`, `federation`, `guardrails`, `openapi_convert`, `rest_to_mcp`, `sse_client`, `streamable`, `spans`. The `mcp` action variant is in `crates/sbproxy-modules/src/action/mcp.rs` and re-exports `McpAction`, `McpActionConfig`, `McpFederatedServerConfig`, `McpGuardrailEntry`, `McpServerInfoConfig`, `McpServerPrefix`. None of these are described in `mcp.md` today. |
| `agent-skills.md` | accurate | Schema + integrity contract matches `AgentSkillEntry` in `types.rs:1550` and projection in `projections/agent_skills.rs`. |
| `access-log.md` | accurate | Matches `AccessLogConfig` (`types.rs:991`) and `access_log.rs`. |
| `audit-log.md` | accurate | Matches `audit.rs` event types. |
| `observability.md` | accurate | Matches `observability.md` headings against `observe/lib.rs`. |
| `operator-runbook.md` | accurate | Matches admin endpoints and metrics names. |
| `threat-model.md` | accurate | Wave-aware. |
| `events.md` | accurate | Matches `events.rs::EventType` exactly (11 variants, snake_case JSON). |
| `openapi-emission.md` | accurate | Matches `crates/sbproxy-openapi/src/lib.rs::build`. |
| `policy.md` | accurate | Matches `semantic_constraint`, the NL linter, and the OSS / enterprise capability split. |
| `performance.md` | accurate | |
| `degradation.md` | accurate | |
| `upgrade.md` | accurate | The "Go references allowed" exception applies here. |
| `quickstart-operator.md` | accurate | Matches `crates/sbproxy-k8s-operator/`. |
| `kubernetes.md` | accurate | Matches `crd.rs` and `reconcile.rs`. |
| `402-challenge.md` | accurate | Matches quote-token issuance + verifier wiring. |
| `config-stability.md` | accurate | |
| `listings.md` | accurate | Matches `listing.rs` exactly: schema, three pinning modes, plan-validation rules. |
| `enterprise.md` | accurate | Buyer-facing landing page; OSS / enterprise split is accurate. |
| `glossary.md` | accurate | |
| `headers-reference.md` | accurate | Matches the header surface in `crates/sbproxy-core/src/server.rs`. |
| `metrics-stability.md` | accurate | Matches `metrics.rs`. |
| `model-pinning.md` | accurate | Matches `crates/sbproxy-classifiers/src/known_models.rs`. |
| `adr-classifier-supply-chain-oss.md` | accurate | ADR. |
| `adr-config-plan-apply.md` | accurate | ADR; matches `plan.rs` + `main.rs` plan/apply handlers exactly. |
| `adr-config-source-modes.md` | accurate | ADR; describes file + git + git+overlay + db source modes. The `git` source mode is not implemented in code yet (the `compile_config` path only reads YAML strings; `load_listings_from_repo` walks the filesystem). Recommendation: keep as ADR; do not surface as a user feature until shipped. |
| `adr-fast-track-amendment.md` | accurate | ADR template. |
| `comparison.md` | **stale** | Line 59: "Response caching | Built-in (memory, file, sled, redis)". The real backends are memory, file, memcached, redis (`crates/sbproxy-cache/src/store/`). `sled` is not used anywhere. |
| `architecture.md` | accurate | Pipeline shape matches `crates/sbproxy-core/src/pipeline.rs`. |
| `codebase.md` | **stale (multiple)** | (1) WASM section calls the runtime a "passthrough stub". Code: `crates/sbproxy-extension/src/wasm/mod.rs` is a full `wasmtime` 44 integration with fuel metering and limits. (2) `sbproxy-cache` section omits the `redis` backend (`crates/sbproxy-cache/src/store/redis.rs` exists). (3) `sbproxy-extension` MCP section omits 11 sub-files. (4) `sbproxy-observe` section omits exemplars, golden_signals, topology, request_event, request_sink, synthetic, redact, agent_labels, cardinality. (5) `sbproxy-ai` section understates the surface (the crate has 40+ modules; codebase.md lists ~10). |
| `build.md` | accurate | Matches `Cargo.toml` and `Makefile`. |
| `ai-crawl-control.md` | accurate | Matches `policy/ai_crawl.rs` and the OSS / enterprise ledger split. |
| `bulk-redirects.md` | accurate | Matches `action/mod.rs::BulkRedirectTable`. |
| `cache-reserve.md` | accurate | Matches `crates/sbproxy-cache/src/reserve/`. |
| `content-for-agents.md` | accurate | |
| `exposed-credentials.md` | accurate | Matches `policy/exposed_creds.rs`. |
| `feature-flags.md` | accurate | Matches `crates/sbproxy-core/src/sb_flags.rs`. |
| `headers-reference.md` | accurate | |
| `llms.txt` | accurate | Static index. |
| `onnx-classifier.md` | accurate | Matches `crates/sbproxy-classifiers/`. |
| `openapi-validation.md` | accurate | Matches `policy/openapi_validation.rs`. |
| `prompt-injection-v2.md` | accurate | Matches `policy/prompt_injection_v2/`. |
| `rsl.md` | accurate | Matches `projections/licenses.rs`. |
| `routing-strategies.md` | accurate | Matches `action/loadbalancer.rs` + `action/routing/`. |
| `wasm-development.md` | accurate | Matches `crates/sbproxy-extension/src/wasm/mod.rs`. |
| `web-bot-auth.md` | accurate | Matches `auth/bot_auth.rs` + `auth/bot_auth_directory.rs`. |

## Aspirational / Wrong-Audience Items (action required)

1. `sbproxy/CLAUDE.md` lists `sbproxy-events` and `sbproxy-proxy` as public crates. Neither exists in the workspace `Cargo.toml` (verified). The CLAUDE.md text already notes "planned but not yet implemented"; no user-facing doc surfaces them. **Action: leave `CLAUDE.md` as-is (the caveat is correct). Do not advertise either crate name in `docs/` until they ship.**
2. `docs/comparison.md` row "Response caching | Built-in (memory, file, sled, redis)" is wrong. **Action: rewrite to `Built-in (memory, file, memcached, redis)`.** Source: `crates/sbproxy-cache/src/store/mod.rs`.
3. `docs/codebase.md` §"sbproxy-extension" calls the WASM runtime a "passthrough stub". The actual code is a fully wired `wasmtime` 44 integration (fuel metering, store limits, WASI preview-1 sandbox). **Action: rewrite the WASM bullet to describe the real runtime.**
4. `docs/codebase.md` §"sbproxy-cache" omits the Redis backend. **Action: add `redis.rs - Redis-backed cache store for distributed deployments` next to memcached.**
5. `docs/codebase.md` §"sbproxy-extension MCP" lists 4 files but the directory has 15 (including `access_control`, `audit`, `code_mode`, `context_opt`, `federation`, `guardrails`, `openapi_convert`, `rest_to_mcp`, `sse_client`, `streamable`, `spans`). **Action: expand the MCP bullets to reflect federation, REST-to-MCP conversion, code-mode, access control, and audit.**
6. `docs/codebase.md` §"sbproxy-ai" understates the surface. **Action: list the missing modules (`assistants`, `audio`, `batch`, `finetune`, `image`, `realtime`, `response_dedup`, `streaming_analytics`, `structured_output`, `threads`, `translators`, `usage_parser`) or rewrite the section to describe sub-systems rather than file lists.**
7. `docs/manual.md` §2 lists `--disable-sb-flags` and `SB_DISABLE_SB_FLAGS` under "Planned, not yet wired". The flag is wired in `crates/sbproxy/src/main.rs:55-57, 271-282`. **Action: move the entry from "Planned" into the supported-flag table, document the env var values (`1`, `true`, `yes`, `on`), and link to `feature-flags.md`.**
8. `docs/manual.md` §2 does not mention `sbproxy plan` or `sbproxy apply`. Both subcommands exist in `crates/sbproxy/src/main.rs:151-168` and are described in `adr-config-plan-apply.md`. **Action: add a subsection per subcommand with usage + exit codes, mirroring `adr-config-plan-apply.md`.**
9. `docs/manual.md` §13 (env-var table) is missing `SB_APPLY_CONFIG` and `SB_APPLY_BASELINE`. **Action: add both rows.**
10. `docs/mcp.md` is very short relative to the actual surface in `crates/sbproxy-extension/src/mcp/`. The `mcp` action (`crates/sbproxy-modules/src/action/mcp.rs`) re-exports six config types that are not documented anywhere. **Action: extend `mcp.md` to cover server federation, guardrail entries, code-mode (WASM), and REST-to-MCP conversion.**
11. `docs/adr-config-source-modes.md` describes `git`, `git+overlay`, `db` source modes. Of these, only the filesystem-Repo Listing loader is implemented (`crates/sbproxy-config/src/listing.rs`). The `git`, `git+overlay`, and `db` modes are not present in the compiler. **Action: keep as ADR; do not advertise as a shipped feature until the corresponding source modes land in `compiler.rs`.**

Missing-docs gaps (features in code that have no doc page):

12. `request_validator` policy (`crates/sbproxy-modules/src/policy/request_validator.rs`). Validates request bodies against a JSON Schema. No dedicated doc. **Action: add a section to `policy.md` or a small `request-validation.md` page.**
13. `concurrent_limit` policy (`crates/sbproxy-modules/src/policy/concurrent_limit.rs`). Per-route, per-IP, or per-API-key in-flight cap. No dedicated doc. **Action: add a section to `policy.md`.**
14. `http_framing` policy (`crates/sbproxy-modules/src/policy/http_framing.rs`). Detects request smuggling (CL.TE, TE.CL, malformed CRLF). No dedicated doc. **Action: add to `policy.md` or `threat-model.md`.**
15. `a2a` policy (`crates/sbproxy-modules/src/policy/a2a.rs`). No dedicated doc. **Action: extend `policy.md` with a section, or surface as part of the A2A action page (which also needs writing).**
16. Idempotency-Key middleware (`crates/sbproxy-middleware/src/idempotency.rs`). Cached-retry vs conflict semantics (Wave 3 / R3.2, A3.4). Mentioned in `features.md` §11.6 only. **Action: short dedicated page or a `configuration.md` callout.**
17. Problem-Details middleware (`crates/sbproxy-middleware/src/problem_details.rs`). RFC 7807. Not documented. **Action: add to `headers-reference.md` or extend `error_pages` section in `configuration.md`.**
18. Message-Signatures middleware (`crates/sbproxy-middleware/src/signatures.rs`). RFC 9421 verification + signing for upstream. Not documented. **Action: small dedicated doc.**
19. Proxy-Status middleware (`crates/sbproxy-middleware/src/proxy_status.rs`). RFC 9209 header. Not documented. **Action: small section in `headers-reference.md`.**

## Open Questions

1. The `device_parser_file: Option<String>` field on `ProxyServerConfig` is reserved per the code comment but not wired. What is the rollout plan? If the field is going to be removed, `configuration.md` should drop the mention. If it is going to be wired, it should appear in the future-roadmap doc. Source: `crates/sbproxy-config/src/types.rs:256-262`. Assumption if forced to guess: keep as reserved, leave the field in the schema for forward compatibility, and do not advertise.
2. `sbproxy-ai` re-exports `assistants`, `threads`, `batch`, `image`, `audio`, `finetune`, `realtime`, `structured_output` as separate modules. Are these production-ready, alpha, or stubs? Their public APIs are visible to plugin authors. Source: `crates/sbproxy-ai/src/lib.rs`. Assumption: production-ready (they would not be public re-exports otherwise). They deserve an `ai-gateway.md` subsection per module.
3. The admin API exposes `/api/openapi.{json,yaml}` and `/api/stats` and `/api/health/targets`, but the JSON schema for these endpoints is undocumented. Source: `crates/sbproxy-core/src/admin.rs:983-1005`. Assumption if forced to guess: the schema is stable; an "Admin API reference" doc would be a natural follow-up.
4. `sbproxy plan -p <file>` requires `SB_APPLY_CONFIG`. Is the design intentional (env-var only) or temporary? Source: `crates/sbproxy/src/main.rs:943`. Assumption: intentional per the ADR (plan file does not embed the YAML path); document explicitly.
5. The `extensions:` opaque map exists on both `ProxyServerConfig` and `RawOriginConfig`. There is no doc listing the in-tree extensions actually consumed. Source: `types.rs:274, 1477`. Assumption: out-of-tree only; document the field as a no-op for the OSS build.

## Scope Recommendation

The gap is small enough for a single-pass refresh, no phasing needed. Concretely:

1. Fix the 4 stale claims in `codebase.md` and `comparison.md` (Items 2-6 above).
2. Bring `manual.md` in sync with the wired `--disable-sb-flags` flag and the `plan` / `apply` subcommands (Items 7-9).
3. Add short policy / middleware sections for the 8 undocumented features (Items 12-19); none warrants a full-page treatment, all can live as subsections in `policy.md`, `configuration.md`, or `headers-reference.md`.
4. Extend `mcp.md` to cover the real submodule surface (Item 10).
5. Leave the two ADRs (`adr-config-source-modes.md`, `adr-config-plan-apply.md`) untouched; they correctly describe forward-looking design and partly-implemented features.

Full scope feasible in one wave. No need to defer "feature manual" vs "configuration reference"; both are largely accurate.
