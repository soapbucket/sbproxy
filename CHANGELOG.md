# Changelog

All notable changes to SBproxy v1.x. Versions before v1.0 shipped as the
Go implementation and now live in the archived
[`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go)
repository.

## [Unreleased]

Work that has merged to `main` since the latest tag and is queued for
the next version cut. No promises about backward compatibility for any
of the new YAML fields below until the version that ships them.

### Added

- **The released binary is GPU-aware out of the box.** The `gpu-nvidia`
  (NVML GPU discovery with an `nvidia-smi` fallback) and `model-weights`
  (Hugging Face weight download) features moved into the `sbproxy`
  binary's default feature set, so one downloaded artifact adapts to its
  host: the NVIDIA driver library is loaded at runtime when present,
  never linked, and a GPU-free host still runs the same binary (a
  `serve:` provider rejects admission cleanly there). Building with
  `--features gpu-nvidia,model-weights` is no longer needed for local
  model serving. Library consumers of the workspace crates still opt in
  per crate.
- **`sbproxy doctor`.** New subcommand that reports what the binary can
  do on the current host: compiled capability features, the GPUs the
  `serve:` admission path sees (same probe, so they cannot disagree),
  which inference engines (`vllm`, `llama-server`) resolve on `PATH`,
  the model-weight cache directory, and a readiness verdict for local
  model serving with every blocker listed. `--format json` emits a
  stable machine-readable report; collection is read-only.

### Fixed

- **Revoking a key now blocks OIDC/JWT identities mapped to it.** With
  `key_management.oidc_claim_map` configured, a verified token whose mapped
  claim named a revoked, blocked, or expired record was silently downgraded to
  an ungoverned request (no per-key policy) instead of being denied. The
  mapped-claim path now mirrors the bearer path: an inactive record denies with
  403, a claim naming a missing record denies with 401, and a store outage
  fails closed unless `failure_mode_allow` is set. Tokens that carry no mapped
  claim are unaffected.

## [1.4.0] - 2026-06-27

Fourth minor release on the Rust v1.x line. Hardening and reach for the
AI gateway and the clustering mesh: mutually-authenticated TLS on the
peer transport, external HTTP guardrail providers on the request and the
response, native Langfuse and Datadog usage sinks, and per-server
namespace control for MCP federation. One correctness fix promotes
budget windows from parsed-but-ignored to enforced. No config-breaking
changes; existing `sb.yml` files compile unchanged, and every new field
is default-off.

### Added

- **Mesh peer mTLS.** The mesh peer transport can run over
  mutually-authenticated TLS: set `key_management.cache.mesh.peer_tls` with
  `cert_file`, `key_file`, and `ca_file` (plus an optional `server_name`,
  default `sbproxy-mesh`). Every inbound connection must present a CA-signed
  client certificate and every outbound connection presents this node's
  certificate, both verified against the CA, so an untrusted peer cannot join
  the cache fabric. Plaintext when unset.

- **Per-server namespace mode for MCP federation.** A federated upstream can
  set `namespace: always` to expose every tool as `<prefix>.<tool>` and every
  resource as `<prefix>/<uri>`, where the prefix is the server's `prefix` (or
  a name derived from its origin). The default, `on_collision`, keeps bare
  names and only qualifies one when it clashes with an earlier server.

- **External HTTP guardrail providers.** An AI origin's `guardrails.external`
  list runs external guardrail services alongside the built-in checks.
  Input-mode entries (`pre_call` / `during_call`) inspect the request before
  dispatch; output-mode entries (`post_call` / `during_call`) inspect the
  non-streaming response before it is cached or sent. Either blocks on a
  not-allowed verdict (`logging_only` records only), and a transport or parse
  error honors each entry's `fail_open` flag. Provider presets shape the
  request and response for Presidio (`/analyze` with a findings array) and a
  generic `{"input"}` shape that fits Lakera, Aporia, and custom endpoints,
  with an optional API key on a configurable auth header. Streaming-response
  and AWS Bedrock (SigV4) guardrails are not yet wired.

- **Native Langfuse and Datadog usage sinks.** Alongside the JSONL-file,
  webhook, and ledger sinks, `usage_sinks` now accepts `type: langfuse`
  (`host` plus public/secret key; posts a generation observation to
  `/api/public/ingestion`) and `type: datadog` (`api_key` plus optional
  `site` / `service`; posts to the logs-intake API). Both are
  fire-and-forget and never fail the request they record. Object-store
  (S3/GCS) and OTel usage sinks are not yet included.

### Fixed

- **Budget windows now reset per period.** A budget `limit` with a `period`
  (`daily`, `monthly`, or a duration like `30d`) was parsed but never enforced
  as a rolling window, so spend accumulated forever and a daily cap behaved
  like a lifetime cap. Each limit now accrues against its own per-period
  bucket, so a daily cap clears at the next day and a daily and a monthly cap
  on the same scope are tracked independently. Cumulative limits (no `period`,
  or `total` / `lifetime`) are unchanged.

- **MCP federation now advertises the disambiguated name on a collision.**
  When two upstreams exported the same tool name, the gateway kept the
  prefixed name only as an internal registry key while still advertising the
  bare name, so the second tool was unreachable and `tools/list` showed a
  duplicate. The disambiguated name (`<server>.<tool>`, or `<server>/<uri>`
  for resources) is now the advertised, routable name; resource reads still
  forward the original upstream URI.

## [1.3.1] - 2026-06-25

Patch release. Fixes TLS, which was broken on startup in v1.2.0 and v1.3.0.

### Fixed

- **TLS no longer panics on startup.** The OCSP-staple and ACME-renewal
  background tasks were spawned before the proxy runtime existed, so any HTTPS
  listener with a manual cert (`tls_cert_file` / `tls_key_file`) or enabled ACME
  crashed the process on boot ("there is no reactor running"). The tasks now
  spawn on a runtime that is always available.
- **HTTP/2 is now negotiated over TLS.** No TLS listener advertised `h2` in ALPN,
  so every HTTPS connection fell back to HTTP/1.1. The manual-cert, ACME, and
  mTLS listeners now enable h2; clients that do not offer it still get HTTP/1.1.

## [1.3.0] - 2026-06-25

Third minor release on the Rust v1.x line. Two headlines: dynamic key
management with an open-source mesh for clustering, and a wave of
state-of-the-art AI-gateway capabilities. No config-breaking changes;
existing `sb.yml` files compile unchanged, and every new field is
default-off.

### Added

- **Dynamic key management.** Inbound virtual keys are a live, governed
  resource: mint, list, rotate, and revoke them at runtime through an admin
  API under `/admin/keys`, with no reload. Keys are hashed at rest with
  HMAC-SHA256 and a server pepper, and a revoke takes effect on the next
  request. Upstream provider credentials are encrypted at rest with an
  AES-256-GCM envelope or held as a vault reference. Per-key policy travels
  with the key: model and provider allow/deny, rate and token limits, token
  and USD budgets, expiry, required PII redaction, principal selectors, a
  pinned model, injected tools, and an injection-scan bypass. Pluggable
  stores: embedded (redb), Redis, or a secrets manager. OIDC and JWT claims
  can map to a key. New `key_management:` config block. (#542, #543)
- **Open-source mesh clustering.** The mesh layer (SWIM gossip, CRDTs, a
  consistent-hash distributed cache) is now Apache-2.0 in this repository.
  Setting `cache.tier: mesh` keeps the key plane, budgets, and per-key spend
  and rate counters coherent across a replica fleet, so the cluster
  coordinates itself with no external Redis in the path. (#542)
- **State-of-the-art AI-gateway differentiation.** A verifiable, hash-chained
  and optionally Ed25519-signed usage ledger; a single sandboxed CEL policy
  plane over guardrails, budgets, routing, and principal; a guardrail mesh
  that fuses verdicts on a quorum with a verdict cache; outcome-aware routing
  by realized cost-per-success; predictive budgets that warn, then downgrade,
  then block; and LLM-aware resilience: per-error retry, context-window
  compression, hedged and raced dispatch, and content-policy fallback to a
  more permissive provider. (#538, #539, #540, #541)
- **LiteLLM drop-in.** A `config import-litellm` translator, model groups, and
  usage-sink plus budget foundations for moving a LiteLLM proxy over. (#537)
- **Model-based routing** with a failover metric and a refreshed model-id
  catalog. (#536)
- VHS cassettes for the AI gateway and the example configs. (#534)

### Changed

- The mesh wire encoding moved off the unmaintained `bincode` crate to
  `postcard`.
- The README and docs now lead with the two-way framing: SBproxy governs the
  AI you call and the AI that calls you.

## [1.2.0] - 2026-06-24

Second minor release on the Rust v1.x line. Headline: local ONNX
inference for the embedding semantic cache and the prompt-injection
classifier, a standalone OpenAI-compatible embedding source, a
best-of-class OpenTelemetry story for the AI gateway, and the move to
Apache 2.0. No config-breaking changes; existing `sb.yml` files compile
unchanged.

### Added

- **Local ONNX inference for the semantic cache.** The embedding
  semantic cache can vectorize prompts on-box, with no per-call API cost
  and no prompt egress. `source: sidecar` runs the embedder in the
  supervised classifier sidecar; `source: inprocess` loads an ONNX model
  (all-MiniLM-L6-v2 by default) into the proxy behind an explicit opt-in
  and a `max_model_bytes` guard. Prompt-injection v2 gains first-class
  ONNX detectors (`detector: sidecar`, `detector: inprocess`) next to the
  zero-dependency heuristic default. See
  [docs/local-inference.md](docs/local-inference.md).
- **OpenAI-compatible embedding source** (`source: openai`). Vectorize
  prompts through any standalone OpenAI-compatible `/v1/embeddings`
  endpoint, decoupled from the origin's chat providers: point it at
  another sbproxy that fronts an embedding model, at OpenRouter, or at a
  hosted provider. Auth defaults to `Authorization: Bearer`; set
  `auth_header` / `auth_prefix` for `api-key` / `x-api-key` endpoints, or
  carry the credential in arbitrary extra `headers`.
- **Best-of-class OpenTelemetry for the AI gateway.** AI spans now carry
  derived USD cost (and a first-class cost metric), map failures
  (guardrail, provider 429/5xx, content filter) to span status ERROR with
  an `error.type`, and emit capture-gated, redacted prompt and completion
  content as OpenInference / OTel gen_ai span events. A pinned GenAI
  semantic-convention conformance test guards against attribute drift.
  The reference stack adds Arize Phoenix and Langfuse with provisioned
  dashboards, plus cost-aware (ParentBased + TraceIdRatio) trace
  sampling. [docs/observability.md](docs/observability.md) gains a
  verified backend matrix.
- **Per-credential, multi-tenant, multi-model AI value tracking** in the
  reporting surface.
- **GCP Secret Manager vault backend** (`gcpsm://`), joining HashiCorp
  Vault (`vault://`) and AWS Secrets Manager (`awssm://`).
- Configurable retry on upstream response statuses.
- Web Bot Auth key IDs now feed the agent identity proof.

### Changed

- **SBproxy OSS is now licensed Apache 2.0.** The previous Business
  Source License field-of-use restriction is dropped; the project is free
  for any use, including production and commercial, with no field-of-use
  limit.
- **Vault references moved to per-provider schemes.** The scheme now
  selects the backend (`vault://` HashiCorp, `awssm://` AWS, `gcpsm://`
  GCP) rather than a `vault://<alias>` umbrella form. The legacy form
  still resolves during a deprecation window and logs a one-time warning.
- **HTTP/3 (QUIC) is temporarily disabled** until native support lands in
  the underlying proxy engine. Existing config still parses, but no
  HTTP/3 listener starts.
- The admin playground chat route is gated by default.

### Fixed

- Credential selectors are enforced consistently across request paths,
  and the AI preference script context is exposed to request scripts.

## [1.1.0] - 2026-06-06

First minor release on the Rust v1.x line. This release carries
breaking changes to the MCP tool-access policy (now closed-by-default
and principal-aware); read the Breaking section and
`docs/migration-mcp-rbac.md` before upgrading. It also ships 66 native
AI providers behind one OpenAI-compatible API.

### Breaking

- **MCP default-deny**: `ToolAccessPolicy` flipped from
  open-by-default to closed-by-default. An unknown caller (no
  matching ACL rule) is denied every tool. An empty `allowed: []`
  list under an ACL rule means "deny all", not "allow all".
  Operators who want the legacy behaviour add `default_allow: true`
  on the origin's MCP action. The legacy `key_permissions: { key: [tools] }`
  shape is gone; rewrite to the principal-aware `tool_access[]`
  selector list. See `docs/migration-mcp-rbac.md`.

- **MCP principal-aware ACL**: `ToolAccessPolicy` now
  carries `tool_access[]` rules with `principals[]` selectors
  (`virtual_key`, `sub`, `team`, `project`, `user`, `role`,
  `tenant_id`) plus an `allowed[]` tool list. The legacy
  `key_permissions: HashMap<String, Vec<String>>` map is removed
  along with `ToolAccessPolicy::is_tool_allowed(key, tool)`; the new
  surface is `policy.check(&principal, tool) -> ToolAccessDecision`
  and `policy.filter_tools(&principal, &tools)`. `tools/list` now
  filters by RBAC against the inbound principal (the legacy schema
  leaked tool names through `tools/list` even when the gate would
  deny the matching `tools/call`). A new `tool_quotas[]` table
  enforces per-tool sliding-window quotas keyed on
  `(tenant_id, principal_id, tool_name)`. See
  `docs/migration-mcp-rbac.md`.

### Added

- **66 native AI providers behind one OpenAI-compatible API.** The
  embedded `ai_providers.yml` registry ships 66 providers (up from 43),
  adding Hugging Face Inference, GitHub Models, Vercel AI Gateway,
  Nebius, Baseten, Lambda, FriendliAI, Scaleway, Nscale, DigitalOcean
  Gradient, OVHcloud, Inference.net, kluster.ai, OpenPipe, Writer,
  Upstage, Aleph Alpha, MiniMax, Volcengine Ark (Doubao), Tencent
  Hunyuan, Baidu Qianfan (ERNIE), StepFun, and Mixedbread. The catalog
  is plain YAML and operator-extensible at runtime via
  `proxy.ai_providers_file`; the `model` field passes through to the
  upstream, so any model a provider serves is reachable without
  per-model config. The "200+ models" reach is native (bring your own
  keys); OpenRouter is one provider among the 66, not a dependency. See
  `docs/providers.md#extending-the-provider-catalog`.

- **Session ledger from live MCP traffic.** A new top-level
  `session_ledger:` block makes SBproxy emit the canonical
  `session-ledger-v1` run record (shared with mcptest) from its
  `tools/call` path: one `header` per session, then one `tool_call`
  record per call carrying `session_id`, a zero-based `hop_index`, the
  bare tool name and server, redacted `params` / `result`, an error
  flag, and the round-trip `duration_ms`. `sink: logging` (default)
  emits each record as a `session_ledger` tracing line; `sink: file`
  with a `path:` appends NDJSON. Off unless `enabled: true`; when off
  the tool-call path pays only a single atomic load. Payloads are
  redacted with the same secret-stripping the access log uses. See
  `docs/mcp.md` and `examples/mcp-federation/sb.yml`.

- **Structured-log schema v2 (`SCHEMA_VERSION = "2"`).** Three changes
  land together so downstream tooling can read them in one swing:
  optional `session_id` and `user_id` top-level fields parallel the
  `RequestEvent` envelope (cross-surface JOIN no longer relies on
  `request_id` alone); the field-key redaction marker is normalised
  to `[REDACTED:<NAME>]` everywhere (was `<redacted:name>` in v1) so
  the schema-v1 layer matches the existing PII-rule replacement
  shape; the schema bump is additive on the field set (a v1 reader
  parsing a v2 line keeps working because every new field is
  `skip_serializing_if = Option::is_none`). Marker normalisation is
  a string change; downstream tooling that greps for the old
  `<redacted:...>` form must update.

- **Phase-timing breakdown on the access log + new
  `sbproxy_phase_duration_seconds` Prometheus histogram.** The
  access log carried `latency_ms` end to end and that was it; an
  operator looking at a slow request could not tell from the log
  whether the time went to the auth provider, the upstream, or a
  response transform. Three new optional fields land on every
  `AccessLogEntry`: `auth_ms` (request_start → auth provider
  returned), `upstream_ttfb_ms` (request_start → first upstream
  response byte), `response_filter_ms` (first upstream byte → end
  of `response_filter`). All three are `Option<f64>` and
  `serde-skip` when None, so origins that short-circuit (cache
  hit, auth deny) keep compact lines. The same observations also
  feed a new `sbproxy_phase_duration_seconds{phase, origin}`
  histogram with buckets identical to
  `sbproxy_request_duration_seconds` for cross-cut dashboards. See
  `docs/access-log.md` and `docs/metrics-stability.md`.

- **Nine standard HTTP fields on the access log: `host`, `query`,
  `protocol`, `scheme`, `user_agent`, `referer`, `upstream_status`,
  `response_content_type`, `response_content_encoding`.** The log
  was missing the canonical fields most HTTP access-log consumers
  expect (Apache, NGINX, Envoy, the cookie-cutter ELK pipeline).
  `host` is the client-supplied Host header (distinct from
  `origin`, the matched virtual-host pattern); `upstream_status`
  is the upstream's response code when the proxy rewrote the
  status the client sees. All nine are `Option`, `serde-skip` when
  not applicable. Promoted from the generic header allowlist
  because nearly every analytics consumer wants them. See
  `docs/access-log.md`.

- **Opt-in OpenTelemetry metrics mirror alongside the canonical
  Prometheus surface.** New `telemetry.export_metrics: true`
  (with `telemetry.metrics_interval_secs` cadence, default 30s)
  installs an OTel `MeterProvider` that ships observations to the
  same OTLP collector the trace pipeline targets. The first two
  mirrored instruments are `sbproxy.phase.duration` and
  `sbproxy.request.duration`; record-paths fall back to OTel's
  global no-op meter when the export is off, so operators pay
  nothing for the mirror unless they opt in. The Prometheus
  surface remains canonical; this is for operators who already
  aggregate via Mimir / Datadog / Honeycomb and want to skip the
  Prometheus scrape.

- **OIDC Relying-Party stack shipped end to end.**
  `/oidc/callback` (auth-code + PKCE + sealed session cookie)
  plus the helpers + config wiring for
  `/.well-known/openid-configuration` discovery, refresh-token
  rotation, RP-initiated logout at `/oidc/logout`, userinfo →
  `X-Auth-*` trust headers, an optional server-side session store
  (in-memory + KV-backed redb/file/Redis) for targeted revocation.
  See `docs/configuration.md` § OIDC auth.

- **OpenAI Apps SDK / MCP Apps (SEP-1865) compatibility.**
  Gateway-side `_meta.mcpApps` passthrough for tool definitions,
  `params.audit.cause` plumbing on `tools/call`, and a typed
  validator set (`apps.template_declared`, `apps.iframe_sandbox`,
  `apps.csp_present`, `apps.cache_metadata`) usable by sbproxy,
  the enterprise extension, and any CI gate over the
  `sbproxy-plugin` surface.

- **Web Bot Auth full conformance, publish + sign sides.**
  SBproxy now publishes its own JWKS-shaped
  directory at `/.well-known/http-message-signatures-directory`
  and a Signature Agent Card at
  `/.well-known/web-bot-auth/agent-card` (opt in via
  `web_bot_auth_publish` per origin). New
  `sbproxy-middleware::signatures::MessageSignatureSigner`
  primitive signs outbound requests per RFC 9421, round-trips
  through the existing verifier. See `docs/web-bot-auth.md` and
  `examples/web-bot-auth-publish/`.

- **Three previously-undocumented OSS policies now have docs +
  runnable examples:** `object_authz` (BOLA + BFLA with
  enumeration detection), `content_digest` (RFC 9530 request-body
  verification), `agent_budget` (per-agent semantic rate limit).
  See `docs/object-authz.md`, `docs/content-digest.md`,
  `docs/agent-budget.md`.

- **Discoverable FAQ.** `docs/faq.md` covers install, common
  401 causes, OIDC minimal config, log levels, OSS-vs-enterprise
  scope, and pointers into the rest of `docs/`. Wired into
  `docs/README.md` under "Getting started".

- **Explicit SIGINT/SIGTERM handling with a structured shutdown
  event and a 30s default drain budget.** Pingora's
  `Server::run_forever` already trapped SIGTERM and SIGINT, but
  the proxy emitted no operator-facing log line on receipt, so a
  pod eviction or `docker stop` looked the same as a crash in the
  log stream. This change subscribes to Pingora's execution-phase
  broadcast and emits `shutdown_signal_received`,
  `shutdown_grace_period`, and `shutdown_complete` tracing events
  with the resolved grace budget. The Kubernetes operator
  (`sbproxy-k8s-operator`) now installs the same SIGINT/SIGTERM
  handlers via `tokio::signal::ctrl_c` and
  `tokio::signal::unix::signal(SignalKind::terminate())`; before
  this change the operator relied on the orchestrator SIGKILL at
  `terminationGracePeriodSeconds`. The drain budget is the new
  `SBPROXY_SHUTDOWN_GRACE_MS` env var (or `--shutdown-grace-ms`
  CLI flag) which defaults to 30000ms, matching Kubernetes'
  default `terminationGracePeriodSeconds`. The legacy
  `SB_GRACE_TIME` / `--grace-time` (seconds) still works and
  takes precedence when explicitly set; an unset legacy var lets
  the new 30s default apply. Operator exits 0 on a clean drain,
  1 when the grace window is exceeded, so the orchestrator can
  alert. Documented in `docs/manual.md` §3 and
  `docs/kubernetes.md` §Graceful shutdown.

- **Idempotency middleware now engages on AI gateway origins
  (`action: ai_proxy`).** Before this change, the
  RFC 8594 middleware only ran on general HTTP origins
  (`action: proxy`). AI customers using `Idempotency-Key`
  headers for Stripe-style retries were double-billed by the
  upstream provider because the proxy did not replay from cache.
  The fix engages the same primitive in `handle_ai_proxy` after
  the request body is buffered (the AI gateway already buffers
  for the JSON parser, model router, and guardrails) and before
  the upstream call. On a cache hit the gateway writes the
  cached `(status, headers, body)` triple directly to the client
  with `x-sbproxy-idempotency: HIT` and never contacts the
  provider. On a body conflict the gateway returns 409
  `ledger.idempotency_conflict` per the RFC. On a miss the
  gateway forwards, then records the post-translation OpenAI-shape
  bytes the client actually saw so retries replay byte-identical.
  Reuses the same per-request and pool caps shipped on
  `CompiledIdempotency`: `max_request_body_bytes`,
  `max_response_body_bytes`, `max_concurrent_buffers`. The four
  skip markers (`SKIPPED-OVERSIZE-REQUEST`, `SKIPPED-POOL-FULL`,
  `SKIPPED-OVERSIZE-RESPONSE`, `SKIPPED-MULTIPART`) stamp on the
  outgoing response so operators see graceful degradation in
  dashboards. Multipart bodies (audio transcription, image edit /
  variation, file upload) skip caching with `SKIPPED-MULTIPART`
  because the cache primitive stores raw bytes and multipart
  boundaries may be regenerated by clients on retry. Streaming
  (SSE) chat completion responses abandon the cache record on
  oversize because framing-aware capture is out of scope for v1.

- **`proxy_status` and `problem_details` now cover upstream
  failures.** Before this change, `proxy_status.enabled: true`
  stamped the `Proxy-Status` header on proxy-generated errors
  (auth deny, policy deny, default 404) but **not** on upstream
  failures routed through Pingora's `fail_to_proxy` path (connect
  refused, connect timeout, TLS handshake error, mid-stream
  connection loss). The fix wires both blocks into the
  upstream-failure path so dashboards consuming `Proxy-Status` see
  consistent coverage across error sources. The status code +
  RFC 9209 `error` token derive from the Pingora `ErrorType` via
  a new `map_upstream_failure` translator: 504 +
  `connection_timeout` for `ConnectTimedout` /
  `ReadTimedout`; 502 + `connection_refused` for `ConnectRefused`;
  502 + `tls_protocol_error` for TLS errors; 502 +
  `connection_terminated` for mid-stream loss; 502 +
  `http_request_error` as the catch-all. When
  `problem_details.enabled: true` the body is now rendered as
  `application/problem+json` for upstream failures too, with the
  RFC 9209 error token in the `detail` field so both signals share
  the same vocabulary.

- **Idempotency cache check moved to `request_filter`.** Before this
  change, the cache lookup ran in `request_body_filter`, after
  Pingora had already opened the upstream TCP connection. On a cache
  hit the upstream observed one aborted partial request before the
  proxy served the cached response to the client. The check now runs
  before Pingora's upstream-peer phase: cache hits and body
  conflicts write the response from inside `request_filter` and
  return `Ok(true)`, so the upstream is never contacted at all. On
  cache miss the proxy buffers the body (bounded by
  `max_request_body_bytes` from PR #139), then re-injects it via
  `request_body_filter` at end-of-stream so Pingora's normal upstream
  forwarding picks it up. Existing e2e tests now assert the
  upstream-not-contacted invariant; the previous "may observe one
  aborted partial request" caveat has been removed from
  `docs/configuration.md` and the example README.

- **Idempotency middleware: per-request and pool caps.** Three new
  fields on the `idempotency:` block bound memory usage and let the
  middleware gracefully degrade under pressure rather than buffering
  unbounded bodies. `max_request_body_bytes` (default 1 MiB) caps
  the per-request buffer; bodies above the cap skip caching with
  `x-sbproxy-idempotency: SKIPPED-OVERSIZE-REQUEST` stamped on the
  response. `max_response_body_bytes` (default 1 MiB) caps the
  per-response cache buffer; responses above the cap stream through
  uncached. `max_concurrent_buffers` (default 256) is a per-origin
  pool over concurrent buffered requests; pool exhaustion skips the
  cache with `x-sbproxy-idempotency: SKIPPED-POOL-FULL`. Worst-case
  memory is bounded at `max_concurrent_buffers * max_request_body_bytes`
  per origin.

- **RFC 8594 idempotency middleware (`idempotency:`).** Per-origin
  block that engages on POST / PUT / PATCH (configurable via
  `methods:`) when an `Idempotency-Key` header is present. The
  middleware sits ahead of policies in the handler chain, hashes the
  request body, and short-circuits the three branches per the RFC:
  cache hits replay the cached `(status, headers, body)` verbatim
  with `x-sbproxy-idempotency: HIT`; conflicts (same key, different
  body) return 409 with the `ledger.idempotency_conflict` JSON body;
  misses forward to the upstream and capture the response for the
  next retry. Workspace-isolated keys prevent cross-tenant
  collisions. Memory backend (default) is per-origin and per-replica;
  `backend: redis` binds to `proxy.l2_store` at config-compile time
  for cluster-wide replay. Cached replays do not consume rate-limit
  slots. Documented in `docs/configuration.md` and demonstrated by
  `examples/idempotency/`. Known v1 limitation: the cache check
  fires in `request_body_filter`, after Pingora has already opened
  the upstream connection. On a cache hit the upstream observes one
  aborted partial handshake before the proxy serves the cached
  response to the client; future work moves the check earlier so the
  upstream never sees the replay.

- **RFC 9457 problem-details default renderer (`problem_details:`).**
  New per-origin block that opts in to `application/problem+json` for
  proxy-generated errors (authentication denials, policy denials,
  default 404) that are not matched by an authored `error_pages`
  entry. The two blocks compose: per-status custom pages still win
  when authored; `problem_details` catches everything else with a
  structured `type` / `title` / `status` / `detail` / `instance`
  body. `type_base_uri` produces stable per-status `type` URIs;
  `include_detail: false` suppresses the internal error string.
  Documented in `docs/configuration.md` and demonstrated by
  `examples/problem-details/`.

- **Typed `error_pages` config.** The opaque
  `error_pages: Option<serde_json::Value>` field is now typed as
  `Option<Vec<ErrorPageEntry>>`. Public types `ErrorPageEntry`,
  `StatusSpec`, and `ProblemDetailsConfig` live in `sbproxy-config`.
  The authored YAML shape is unchanged: every existing
  `error_pages:` list keeps parsing, including the `status:` single-
  int / `[status]` list shorthand and `template: true` substitution.
  The OpenAPI emitter now walks typed entries to populate
  per-status `responses` keys (the previous code inspected the
  field as an object and silently produced no entries; this is a
  bug fix on top of the migration).

- **AI gateway Realtime WebSocket dispatch (Phase 7, Option C).**
  `GET /v1/realtime` requests with `Upgrade: websocket` against an
  `ai_proxy` origin are now dispatched through the AI gateway
  pipeline:

  - Pre-upgrade gating runs the same surface classification, 501
    capability check (only providers in
    `provider_supports_realtime` are eligible; today: OpenAI),
    per-surface rate limit, and provider selection as the rest of
    the AI surface set.
  - After the gating passes, Pingora forwards bytes between
    client and provider transparently through the upgraded
    connection. The dispatcher does not terminate the WebSocket;
    per-frame guardrails and frame-exact audio metering are
    reserved for a future enterprise terminate-and-relay path so
    every AI gateway feature added to `handle_action` continues
    to apply to realtime through one shared code path.
  - `sbproxy_ai_realtime_sessions_active` (gauge),
    `sbproxy_ai_realtime_session_duration_seconds` (histogram),
    `sbproxy_ai_realtime_audio_seconds_total` (counter), and
    `sbproxy_ai_realtime_frames_forwarded_total` (counter) are
    registered. The OSS dispatch ticks the gauge on session open
    and observes the duration histogram on close. Documented in
    `docs/metrics-stability.md`.
  - At session close, `logging` emits a session-end
    `AiBillingEvent` with `AudioSeconds { seconds }` valued at
    the wall-clock session duration so realtime usage appears on
    the standard billing-event bus alongside chat/image/audio.
  - `RealtimeSessionTracker` (lock-free atomic counters) and
    `audio_seconds_from_frame(bytes, sample_rate, channels)` ship
    in `sbproxy-ai::realtime` for the eventual terminate-and-relay
    path to consume.
  - `docs/ai-gateway.md` documents the new dispatch path with a
    YAML example and the per-surface rate-limit knob.

- **AI gateway OpenAI surface dispatch (Option A).** The `ai_proxy`
  action now routes every OpenAI-compatible surface through a
  single classifier with per-surface observability and gating:

  - New `AiSurface` enum + `classify_surface(method, path)` cover
    chat completions, models, embeddings, assistants and threads
    (full v2 surface), batches, fine-tuning, files, realtime,
    image generation/edits/variations, audio transcription/speech,
    moderations, and reranking. Marked `#[non_exhaustive]` so
    future variants don't break downstream pattern matches.
  - Method coverage extended past GET/POST: DELETE, PUT, PATCH,
    HEAD, and OPTIONS dispatch through `AiClient::forward_with_method`
    without engaging the JSON body-parse pipeline.
  - Multipart bodies (image edits/variations, audio transcription,
    file uploads) byte-forward via `AiClient::forward_bytes` with
    the inbound `Content-Type` preserved. Previously these surfaces
    returned a 400 "invalid JSON body" from the chat-path body parse.
  - Provider capability matrix in `api_routes.rs` corrected:
    Anthropic no longer claims audio/reranking/moderations support,
    Gemini no longer claims moderations. A new
    `provider_supports_surface` matrix gates non-universal surfaces
    with **501 Not Implemented** when no configured provider
    supports the surface.
  - Per-surface observability: new
    `sbproxy_ai_surface_requests_total{surface, method}` counter and
    `sbproxy_ai_surface_request_duration_seconds{surface, method}`
    histogram. Sibling of the existing per-provider metrics so
    dashboards can pivot between surface and provider views.
    Documented in `docs/metrics-stability.md`.
  - Per-surface input guardrails: image generation, audio speech,
    reranking, and moderations bodies now have their input field
    (`prompt`, `input`, `query`, `input`) extracted and run through
    the same guardrail pipeline as chat-style `messages`.
  - Per-surface rate limits: new `per_surface_rate_limits` field
    on the AI handler config, keyed by surface label. 429 fires
    before any upstream call when the cap is hit.
  - Surface-aware billing event: new `AiBillingEvent` carrying
    `AiUsage` with `Tokens`, `Images { count, resolution }`,
    `AudioSeconds`, `Characters`, `RerankUnits`, and `PerCall`
    variants. Every dispatched request emits exactly one event.
    Image generation, audio speech, and reranking emit real cost
    via per-surface pricing tables (`lookup_image_price`,
    `lookup_audio_speech_price`, `lookup_rerank_price`,
    `lookup_audio_transcription_price`). `docs/ai-gateway.md`
    documents the new surface, methods, guardrails, and rate-limit
    knobs.

- **Policy verdict audit bus + Plugin dispatch.**
  Wires the previously-dead `Policy::Plugin` arm in `server.rs` to
  call the trait's `enforce()`, folds the returned `PolicyDecision`
  into the existing chain reducer, and emits a
  `PolicyVerdictEvent` for every decision on a bounded
  `tokio::sync::mpsc` audit bus per
  `docs/adr-policy-audit-binding.md`. The OSS substrate ships an
  in-memory drain stub; enterprise replaces the consumer with a
  NATS-backed audit-chain subscriber. Multi-policy resolution
  rules from `docs/adr-policy-verdict-shape.md` are implemented at
  the chain level: any Deny wins, the first Confirm wins over
  AllowWithHeaders, AllowWithHeaders accumulate, otherwise Allow.
  `Confirm` in OSS routes through the existing AllowWithHeaders
  mechanism with `X-Policy-Confirm: <reason>` stamped on the
  response; an `expires_at` already in the past synthesises a 410
  and an SSRF-blocked `webhook_url` synthesises a 502 at decision
  time. New metrics:
  `sbproxy_policy_audit_events_total{verdict, surface, policy_id}`,
  `sbproxy_policy_audit_events_dropped_total{tenant}`,
  `sbproxy_policy_decision_duration_seconds{surface}`. New Grafana
  dashboard `sbproxy-policy-verdicts` covers the surface.
  ([crates/sbproxy-observe/src/events.rs],
  [crates/sbproxy-observe/src/metrics.rs],
  [crates/sbproxy-core/src/policy_bus.rs],
  [crates/sbproxy-core/src/policy_dispatch.rs],
  [crates/sbproxy-core/src/server.rs],
  [crates/sbproxy-plugin/src/traits.rs],
  [dashboards/grafana/sbproxy-policy-verdicts.json])

- **Synthetic-transaction `/readyz` probe.** Optional
  background driver that fires an in-process request through the
  compiled handler chain on a fixed cadence and reports the verdict as
  a `synthetic_pipeline` component on `/readyz`. Disabled by default;
  opt in via `proxy.synthetic_probe.enabled: true` and define an origin
  for the configured sentinel hostname (default `__synthetic.local`)
  pointing at a non-network action (`static`, `mock`, `echo`, `noop`).
  Failures bump the new
  `sbproxy_synthetic_probe_failures_total{reason}` counter so they do
  not pollute real-traffic error metrics.
  ([crates/sbproxy-config/src/types.rs],
  [crates/sbproxy-core/src/synthetic.rs],
  [crates/sbproxy-observe/src/synthetic.rs],
  [crates/sbproxy-observe/src/metrics.rs],
  [e2e/tests/synthetic_probe.rs])

- **`GET /admin/drift` config drift endpoint.** Returns
  whether the on-disk config file has diverged from what the running
  proxy has loaded, without triggering a reload. Compares a
  content-hash baseline captured at startup (and refreshed on every
  `/admin/reload`) against a fresh hash of the current file. K8s
  operators and dashboards scrape this so they can flag an edited
  config that has not been hot-reloaded yet. Documented in
  `docs/configuration.md` § Admin fields.
  ([crates/sbproxy-core/src/admin.rs],
  [crates/sbproxy-core/src/server.rs],
  [docs/configuration.md])

- **Deterministic clock-skew testing hooks.** `ClockSkewMonitor` now
  accepts an injected clock source for tests while production continues
  to use the system clock.
  ([crates/sbproxy-observe/src/clock_skew.rs])

- **Operator runbook hooks and fast-track ADR template.** Added a
  dashboard-oriented operator runbook, linked all Grafana panels to the
  relevant triage sections, and added a fast-track ADR amendment
  template plus OSS threat-model refresh checklist.
  ([docs/operator-runbook.md], [docs/adr-fast-track-amendment.md],
  [docs/threat-model.md], [dashboards/grafana/])

- **Live reverse-DNS resolver for agent verification.** `SystemResolver`
  now uses `hickory-resolver` for PTR and forward-confirmation lookups,
  replacing the previous typed PTR stub.
  ([crates/sbproxy-security/src/agent_verify.rs])

- **Multi-window SLO burn-rate replay harness.** `sbproxy-observe`
  now includes a burn-rate evaluator and `AlertSnapshot` replay helper
  for substrate availability and latency alert taxonomy tests.
  ([crates/sbproxy-observe/src/alerting/burn_rate.rs],
  [e2e/tests/slo_burn_rate.rs])

- **Vault-style quote-token seed references.** `ai_crawl_control.quote_token.secret_ref`
  now accepts `secret:` references resolved through `sbproxy-vault`
  with the existing environment fallback, in addition to the older
  `secret_ref.env` and inline `seed_hex` paths.
  ([crates/sbproxy-modules/src/policy/ai_crawl.rs])

- **Operator first-24-hours quickstart.** Added a concise
  `docs/quickstart-operator.md` covering deploy, `/readyz`, metrics,
  Grafana, logs, and rollback, linked from the README and Kubernetes
  docs.
  ([docs/quickstart-operator.md])

- **Hostname cardinality override for metrics.** `proxy.metrics.cardinality.hostname_cap`
  can lower the `hostname` label budget independently from the default
  per-label cap, enabling deterministic overflow tests and tighter
  multi-tenant Prometheus budgets.
  ([crates/sbproxy-config/src/types.rs],
  [crates/sbproxy-observe/src/cardinality.rs])

- **`release-fast` build profile for CI images.** Docker-based CI and
  local kind smoke-test builds can now use `CARGO_PROFILE=release-fast`
  to skip fat LTO and use more codegen units, cutting link memory/time
  while leaving production release artifacts on the existing `release`
  profile.
  ([Cargo.toml], [Dockerfile.ci], [Dockerfile.cloudbuild])

- **Reproducible build probe workflow.** CI now has an informational
  double-build lane that builds the release binary twice on independent
  GitHub-hosted runners, uploads each binary and SHA-256, and publishes
  a comparison report without yet treating non-identical output as a
  failure.
  ([.github/workflows/reproducible-build.yml], [SUPPLY-CHAIN.md])

- **Phase 2: CEL `features[...]` namespace.** Per-request
  flags parsed from the `x-sb-flags` header and `?_sb.<key>` query
  prefix are now exposed to CEL expressions. Built-in flags surface
  as bools (`features.debug`, `features.trace`,
  `features["no-cache"]`, `features.any_set`); free-form `k=v` extras
  surface as strings (`features["env"]`). Wired into the rate-limit
  CEL evaluator and `ExpressionPolicy::evaluate_with_views`.
  ([crates/sbproxy-extension/src/cel/context.rs])

- **`SB_WORKER_THREADS` env var.** Positive integer overrides the
  auto-detected Pingora worker thread count
  (`std::thread::available_parallelism()`). Useful for benchmarking
  with a fixed worker count or capping the pool below a cgroup quota.
  ([crates/sbproxy-core/src/server.rs])

- **`/live`, `/livez`, `/ready`, `/healthz`, and rich `/health`
  admin endpoints.**
  `/livez` returns `{"alive":true}` on every call and never 503s, so
  K8s liveness probes don't trip on transient readiness failures.
  `/live` is a bare alias. `/ready` is an alias for `/readyz`.
  `/healthz` stays a fixed liveness body, while `/health` now returns
  version, build hash, timestamp, uptime, and readiness checks for
  dashboards / SIEM ingestion. Existing `/readyz` behavior unchanged.
  ([crates/sbproxy-observe/src/health.rs],
  [crates/sbproxy-core/src/admin.rs])

- **`--request-log-level` and `SB_REQUEST_LOG_LEVEL`.** Operators can
  now tune request/access logging independently from application logs.
  The setting appends an `access_log=<level>` target directive to the
  effective `tracing-subscriber` filter while preserving the existing
  per-target `RUST_LOG` escape hatch.
  ([crates/sbproxy/src/main.rs])

- **Access-log forced emission and file output.** `access_log` now
  supports `slow_request_threshold_ms` and `always_log_errors` so slow
  requests and 5xxs bypass sampling after status/method filters match.
  It also supports `output: { type: file, path, max_size_mb,
  max_backups, compress }` for direct JSON-line access-log files with
  size-based rotation and optional gzip compression of rotated files.
  ([crates/sbproxy-config/src/types.rs],
  [crates/sbproxy-core/src/server.rs],
  [crates/sbproxy-observe/src/access_log.rs])

- **OCSP stapling for the manual fallback cert.** `OcspStapler`
  (which previously existed but was unwired) now does an immediate
  fetch on startup, refreshes every 12 hours, and pushes the bytes
  into `CertResolver::update_fallback_ocsp` so subsequent rustls
  handshakes staple the response on the wire. No-op when no manual
  cert is configured or when the cert lacks an AIA extension.
  ([crates/sbproxy-tls/src/ocsp.rs],
  [crates/sbproxy-tls/src/cert_resolver.rs])

- **Readiness synthetic probe primitive.** `sbproxy-observe` now ships a
  `SyntheticProbe` type so startup or test wiring can register an
  in-process readiness probe that exercises a caller-provided path and
  reports through the same `/readyz` component model as built-in probes.
  ([crates/sbproxy-observe/src/health.rs])

### Removed

- **`sbproxy_ai::IdempotencyCache`.** The OSS AI gateway never wired
  this cache; it was publicly re-exported but had zero callers in the
  workspace. The new `idempotency:` block on general HTTP origins
  (above) supersedes it. AI gateway integration is a follow-up tracked
  in `docs/missing.md`. Plugin authors that imported the removed
  type can switch to
  `sbproxy_middleware::idempotency::{IdempotencyCache,
  InMemoryIdempotencyCache, KvIdempotencyCache}` which carries the
  richer surface (workspace isolation, body-hash conflict detection,
  conflict body builder).

### Changed

- **mTLS now wired on the ACME path.** Previously, an operator who
  configured `mtls:` alongside `acme:` got plain TLS until they
  noticed clients reaching the upstream without the expected cert
  headers. The ACME branch now mirrors the manual-cert branch:
  builds `TlsSettings` with the configured `ClientCertVerifier` and
  falls back to plain TLS only when mTLS setup itself fails.
  ([crates/sbproxy-core/src/server.rs])

- **Examples and Kubernetes smoke checks are local-only.** The
  Docker-backed examples smoke lane and kind-based Kubernetes operator
  smoke lane no longer run automatically on pull requests. They remain
  available as `make examples-smoke` and `make k8s-operator-smoke` for
  explicit local / release validation.
  ([Makefile], [docs/kubernetes.md])

- **Reload drain state is now one coherent atomic snapshot.** The
  drain flag and active request count are packed into one `AtomicU64`,
  so `is_draining()` no longer combines two independent relaxed loads.
  Added loom coverage for the last-request-finish interleaving.
  ([crates/sbproxy-core/src/reload.rs])

- **Optional readiness dependencies no longer fail `/readyz` by
  default.** The default admin health registry now registers absent
  ledger and bot-auth-directory probes as `not_configured`, matching the
  existing future-wave stubs and keeping `/readyz` green when those
  optional services are not wired in a deployment.
  ([crates/sbproxy-observe/src/health.rs],
  [crates/sbproxy-core/src/admin.rs])

- **`docs/manual.md` rewrites** matching what actually ships:
  - §6 Health checks: `/livez`, `/readyz`, `/healthz`, and rich
    `/health` semantics, replacing the old per-endpoint URL fork
    diagram and stale `/health` alias wording.
  - §10 Feature flags: CEL accessor table, kill-switch note, and
    a "planned, not yet wired" note for Lua / JS / WASM features
    namespaces and workspace-level pub/sub flags.
  - §3 CPU detection: documents the new `SB_WORKER_THREADS` knob.
  - §13 env-var table: adds `SB_WORKER_THREADS` and
    `SB_DISABLE_SB_FLAGS`; later updates add
    `SB_REQUEST_LOG_LEVEL` and access-log file/forced-emit examples.

### Fixed

- **CAP `sub` binding only fires for a genuinely resolved agent.** The
  CAP verifier binds a token's `sub` to the request's resolved agent id
  (rejecting a mismatch with `403`). Because the agent-class resolver is
  installed with the built-in catalog by default and always stamps
  *some* id (falling through to the `human` sentinel when no signal
  matches), the binding would have rejected every CAP token whose `sub`
  was not literally `"human"`, even on origins that never configured
  agent classes. The binding now skips the resolver's fallback / `human`
  verdict and engages only when the resolver actually identified an
  agent, so an unauthenticated caller falls through to the normal CAP
  validation path. Set `cap.require_agent_binding: true` to fail closed
  when no agent is resolved.

- **Virtual-key model allow/block lists are now enforced.** A virtual
  key (or `ai_provider` credential) with `models.allow` / `models.block`
  declared its scope but the AI dispatch path never checked it, so a key
  confined to a subset of the gateway's models could still call any
  model the gateway served. The matched key's allow/block lists are now
  enforced against the effective model (after any `route_to_model`
  rewrite): a request for a disallowed model is rejected with `403`
  before any upstream call, the block-list taking precedence over the
  allow-list. Keys with no `models.allow` are unaffected. See
  `examples/ai-virtual-keys/`.

- **Licensing-projection wire formats now match the canonical specs [BREAKING].** Two projection emitters were producing
  document shapes that didn't match their cited specifications.
  `/licenses.xml` previously declared the namespace
  `https://rsl.ai/spec/1.0` and emitted a flat
  `<rsl><license urn=...>...</license></rsl>` document. The canonical
  RSL Collective spec at <https://rslstandard.org/rsl> uses the
  namespace `https://rslstandard.org/rsl` and a nested
  `<rsl><content url="..."><license>...</license></content></rsl>`
  shape; the `<content>` `url` attribute is the canonical wildcard
  `https://<hostname>/*` for the origin-wide license. `/.well-known/tdmrep.json`
  previously wrapped its policies in a `{"version", "generated", "policies": [...]}`
  envelope; the W3C TDMRep CG-FINAL spec mandates a bare JSON array
  at the document root with `location`, `tdm-reservation`
  (integer 0 or 1), and `tdm-policy` (URL of the policy document)
  fields per entry. Both emitters now produce the canonical shapes.
  Operators consuming `/licenses.xml` or `/.well-known/tdmrep.json`
  programmatically must update their parsers to the new shapes; the
  in-process JSON envelope and the response middleware that stamps
  `TDM-Reservation: 1` and the URN-bearing `license` field are
  unaffected. Conformance is asserted by the active structure-shape
  tests; the earlier schema-validation tests were removed because
  neither standard publishes a machine-readable schema to validate
  against (RSL 1.0 is prose-only; W3C TDMRep ships no JSON Schema).
  ([crates/sbproxy-modules/src/projections/licenses.rs],
  [crates/sbproxy-modules/src/projections/tdmrep.rs],
  [e2e/tests/rsl_licenses_projection_e2e.rs],
  [e2e/tests/tdmrep_projection_e2e.rs])

- **Build under prometheus 0.14 type inference.** Sites in
  `sbproxy-observe::metrics` and `sbproxy-core::server` that passed
  heterogeneous `&[&String, &str]` arrays to
  `prometheus::with_label_values` no longer compile on prometheus
  0.14 because Rust unifies the array element type to `&String` and
  rejects bare `&str` literals. Coerced all such call sites to
  uniform `&[&str]` via `.as_str()` so the workspace builds clean
  again. No behavioural change.
  ([crates/sbproxy-observe/src/metrics.rs],
  [crates/sbproxy-core/src/server.rs])

- **WASM extension docs corrected.** `CLAUDE.md` previously labeled the
  WASM surface as "WASM stub" while marketing docs claimed
  production-grade support; the runtime is real
  (`wasmtime` + WASI preview-1 with sandboxed memory and CPU caps,
  stderr capture, no FS or network). `llms.txt` also incorrectly
  claimed "WASI networking with host allowlist" but `allowed_hosts` is
  parsed-but-inert until WASI sockets land. CLAUDE.md and llms.txt now
  match the shipped surface.
  ([CLAUDE.md], [llms.txt],
  [crates/sbproxy-extension/src/wasm/mod.rs])

- **E2E proxy startup flake under CPU contention.** The e2e
  `ProxyHarness` keeps its HTTP-level readiness probe, but now gives
  release/debug proxy boots a 10-second window instead of 5 seconds so
  tests like `action_graphql` do not fail spuriously while cargo is
  competing for CPU.
  ([e2e/src/lib.rs])

- **Docs CI Rust snippet failures.** Workspace-dependent documentation
  examples that cannot compile as standalone `rust-script` programs are
  now tagged `rust,no_run`, keeping docs-ci focused on executable
  snippets instead of illustrative API fragments.
  ([docs/architecture.md], [docs/audit-log.md], [docs/cache-reserve.md])

- **Unsafe-code drift guardrails.** Crates that do not need unsafe now
  forbid it at the crate root, while `sbproxy-vault` explicitly allows
  its narrowly-scoped volatile zeroization unsafe with an inline
  justification.
  ([crates/sbproxy-*/src/lib.rs])

- **Outbound webhook delivery identity headers.** Signed customer
  webhooks now include `Sbproxy-Subscription-Id`,
  `Sbproxy-Delivery-Id`, and 1-based `Sbproxy-Attempt` headers, with a
  fresh delivery ULID on every retry attempt.
  ([crates/sbproxy-observe/src/notify.rs])

- **AI client retry resilience.** `MemoryBatchStore` now uses
  `parking_lot::Mutex` so a panic in one worker cannot poison the
  in-memory batch map for every later operation. Provider retries now
  honor `provider.max_retries` as same-provider retry attempts with
  bounded jittered exponential backoff before recording provider
  failure and moving to the next eligible provider.
  ([crates/sbproxy-ai/src/batch.rs],
  [crates/sbproxy-ai/src/client.rs])

- **Dynamic Web Bot Auth directory dispatch.** The main request auth
  path now invokes `BotAuthProvider::verify_async` when a configured
  hosted directory and `Signature-Agent` header are present, so dynamic
  directory failures surface distinctly instead of falling through the
  static inline-agent verifier.
  ([crates/sbproxy-core/src/server.rs])

- **ACME/Pebble order polling.** Certificate issuance now polls the
  authorization to `valid` after responding to the HTTP-01 challenge
  before polling the order to `ready`, matching Pebble's stricter state
  progression. Finalization also parses the order returned by the
  finalize response and falls back to polling the original order URL,
  avoiding accidental POST-as-GET polling of the finalize URL when
  `Location` is absent.
  ([crates/sbproxy-tls/src/acme.rs])

- **JWKS unknown-`kid` key rotation.** JWTs that reference an unseen
  `kid` now trigger one rate-limited JWKS refetch before failing
  closed, with a Prometheus counter for success / failure /
  rate-limited outcomes. This avoids requiring operator intervention
  for routine IdP key rotation.
  ([crates/sbproxy-modules/src/auth/jwks.rs],
  [crates/sbproxy-modules/src/auth/mod.rs],
  [crates/sbproxy-observe/src/metrics.rs])

- **Rate-limit LRU pollution bypass.** Per-key local token buckets now
  preserve deny state in a bounded cold tier after hot LRU eviction, so
  a spray of attacker keys cannot reset an already-throttled
  legitimate client.
  ([crates/sbproxy-modules/src/policy/mod.rs])

### Open follow-ups

Tracked in Linear, not in this changeset:

- the upstream issue full configurable
  synthetic transaction through the live request pipeline. The
  `SyntheticProbe` readiness primitive has landed; config and pipeline
  execution remain.
- Phase 2.5: Lua / JS / WASM `features` namespace, plus
  workspace-level flags via messenger pub/sub
- the upstream issue remaining
  rate-limiter proptest coverage. The reload-drain loom portion has
  landed.

## [1.0.1] - 2026-05-04

Patch release. No runtime behavior changes.

### Fixed

- **Container image publish**: the `release.yml` workflow's docker
  prepare step extracted the flat-layout tarballs into `/tmp/`
  directly, which tripped a sticky-bit `Cannot utime` error on the
  archive's `./` entry and caused `ghcr.io/soapbucket/sbproxy:1.0.0`
  to never publish. Each platform tarball now extracts to a per-arch
  staging dir before the binary moves into the docker context.

## [1.0.0] - 2026-05-03

First Rust release of SBproxy on this repository.

### What changed

- **Implementation**: SBproxy is now written in Rust on Cloudflare's
  Pingora. The Go implementation that previously occupied this repo
  (`v0.1.0` through `v0.1.2`) has moved to
  [`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go),
  preserved as the `v0.1.2-go-final` branch and tag, and is now in
  maintenance-only mode.
- **Data plane**: routing, AI gateway, MCP gateway, guardrails, security
  policies, and scripting (CEL, Lua, JavaScript, WebAssembly) all ship
  open source in this release. See [`docs/architecture.md`](docs/architecture.md)
  for the request pipeline shape.
- **Enterprise tier**: see [`docs/enterprise.md`](docs/enterprise.md) for
  what enterprise adds on top of the OSS data plane and how to request
  access.

### Upgrading from v0.1.x (Go)

The internal config schema (`schema-v1`) is supported by both the Go
`v0.1.x` line and this Rust `v1.x` line, so existing `sb.yml` files
should compile unchanged. See [`MIGRATION.md`](MIGRATION.md) for the
full upgrade path.
