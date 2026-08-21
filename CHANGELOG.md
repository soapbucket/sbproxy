# Changelog

All notable changes to SBproxy v1.x. Versions before v1.0 shipped as the
Go implementation and now live in the archived
[`soapbucket/sbproxy-go`](https://github.com/soapbucket/sbproxy-go)
repository.

## [Unreleased]

Work that has merged to `main` since the latest tag and is queued for
the next version cut.

### Added

- **Routing decision traces: `GET /api/routing-decisions` and the
  admin console's Routing decisions view.** Every routed request
  (AI dispatch or a load-balanced origin) now records a per-request
  decision trace: the strategy or operator plan that decided, the
  ordered candidates it weighed, the winner, the reason, the fallback
  chain actually traversed, and timing. The record's open `detail`
  map is additive by design so later explanatory columns land as
  keys, not schema changes. Bounded in-memory ring sharing
  `proxy.admin.max_log_entries` with the request log; server-side
  filters by origin, strategy, model (either side of a substitution),
  provider, and time range. See the routing-decisions sections of
  [docs/admin-api-reference.md](docs/admin-api-reference.md) and
  [docs/admin-ui.md](docs/admin-ui.md).

- **Reporting: multi-dimension spend aggregation and raw export on
  the request log, with shareable filtered views.**
  `GET /api/requests/report` aggregates the same filtered ring that
  `GET /api/requests` serves into one row per composite group:
  `group_by` takes any mix of `model`, `api_key_id`, `tenant`, and
  `user` simultaneously, and each row carries request count, tokens
  in/out, and estimated cost. `GET /api/requests/export` downloads
  the filtered rows as CSV or JSONL, bounded by the ring cap and
  hardened against spreadsheet formula injection. Every export is an
  audited admin action (`export_request_log`, naming the format, the
  row count, and which filter dimensions were set) and increments the
  new `sbproxy_admin_request_exports_total{format}` and
  `sbproxy_admin_request_export_rows_total{format}` counters, so every
  export is recorded and alertable. That record covers the export
  route, not every bulk read: `GET /api/requests?limit=<max>` returns
  the same rows under the same cap with no record and no counter, so a
  detection built on `export_request_log` alone covers the download
  button rather than the whole read surface. The response is bounded
  by the ring cap but materialized rather than streamed, because the
  admin dispatcher answers with a whole body; what the row-at-a-time
  encoding avoids is a second copy, not the response itself.
  All three routes share one filter surface, which gains exact
  `model`, `tenant`, and `user` filters, refuses a malformed `status`,
  `offset`, or `limit` with a `400` instead of ignoring it, and treats
  an empty filter value as "rows with nothing there", so the report's
  unattributed group drills through to its own rows like any other. The admin console's new
  Reports view drives them and serializes filter and grouping state
  into URL query params, so a filtered report is a shareable link.
  See the reporting sections of
  [docs/admin-api-reference.md](docs/admin-api-reference.md) and
  [docs/admin-ui.md](docs/admin-ui.md), and the worked example in
  [examples/admin-reporting/](examples/admin-reporting/).

- **Audit chain viewer: `GET /api/audit/chain` and the console's
  Audit view.** The four tamper-evident audit chains
  (`audit.path`, `audit.config_path`, `audit.key_path`,
  `audit.admin_path`) were CLI-only reads until now. The new route
  reads the chained files themselves with channel, actor, and
  time-range filters plus cursor paging, re-verifying every hash link
  and Ed25519 signature as it reads; reads are windowed (streamed one
  record at a time, never a whole-file load) and a verification
  failure is served in the response with the first broken sequence
  and reason, alongside the records that verified. A truncated or
  deleted chain file is reported as a failure too: what is left of a
  truncated file links and signs perfectly, so the read compares the
  walk against the number of records **this process** wrote to that
  chain, which means it catches a truncation the running proxy
  outlived and not one that survived a restart. The console's
  Audit view renders the four channel cards, the merged entry table,
  and a failure banner. GET-only, readable by the `read_only` role;
  a login narrowed with `proxy.admin.operators[].tenant` is refused,
  because the chains are deployment-wide and a per-tenant slice of an
  audit trail reads as "nothing else happened". Read access is wider
  than the bounded ring at `GET /api/audit/events` on two axes, both
  stated in [docs/audit-log.md](docs/audit-log.md): history is the
  whole chain rather than the last `max_audit_events` records, and
  each entry carries the chained payload verbatim rather than the
  ring's `detail` projection. No secrets cross either way; a
  deployment that wants the trail narrower turns the channel's chain
  path off or fronts the admin port. Every call is itself
  recorded on the admin channel (`read_audit_chain`, or
  `read_audit_chain_denied` on the refusal). See the audit-chain
  sections of [docs/audit-log.md](docs/audit-log.md),
  [docs/admin-api-reference.md](docs/admin-api-reference.md), and
  [docs/admin-ui.md](docs/admin-ui.md).

- **New metric `sbproxy_audit_chain_read_total{channel, outcome}`.**
  One increment per chain walked per viewer read, with an `outcome`
  of `verified`, `broken`, or `unreadable`; a refusal increments all
  four channels with `denied`, because it refuses all four. A broken
  chain that only a person looking at the console can see is a finding
  nobody is on call for, and a tenant-scoped operator probing a
  deployment-wide security surface is one whose only other record sits
  inside the chain that operator was refused. Both leave the page:
  alert on
  `increase(sbproxy_audit_chain_read_total{outcome!="verified"}[15m]) > 0`.
  That rule does not cover a chain file truncated at the tail and read
  after a restart: the boot re-baselines on what is left, every link
  and signature holds, and the read is `verified`. Pre-restart records
  are covered by `sbproxy audit verify` against an offsite copy.

- **Temporary, auto-expiring budget overrides on dynamic keys.** `POST
  /admin/keys/{id}/budget-override` raises a governed key's effective
  budget on top of its base caps (`max_tokens_increase`,
  `max_cost_usd_increase`) until a `ttl_secs` or `expires_at` expiry,
  after which the base caps resume with no operator action: expiry is
  persisted on the key record and evaluated lazily at every budget
  read, so it survives restarts and needs no sweeper. Read responses
  and the console's Keys page show the base budget, the override with
  its countdown and grantor, and the enforced `effective_budget`;
  `DELETE` on the same path ends a raise early. Three points in the
  raise's life land in the `key_audit` trail: `budget_override_grant`
  and `budget_override_clear` name the operator who granted or ended
  one, and `budget_override_expire` is the unattributed, time-driven
  end. All three routes are counted on
  `sbproxy_key_operations_total{operation, outcome}` alongside the
  other key mutations. See the temp-override section
  of [docs/ai-gateway.md](docs/ai-gateway.md) and
  [examples/temp-budget-override/](examples/temp-budget-override/).

- **First-class API deprecation: RFC 9745 `Deprecation`, RFC 8594
  `Sunset`, and the successor and documentation `Link` relations.** A
  `deprecation:` block on an origin or on a single forward rule stamps
  the standard announcement headers onto the responses that rule
  matches. Per-path deprecation, the normal case where `/v1/*` is going
  away and `/v2/*` is not, was not expressible before: response
  modifiers hang only off the origin, so it was the whole origin or
  nothing. `deprecated:` takes a date or an RFC 3339 timestamp and
  emits `Deprecation: @<unix>`, the structured-field Date the RFC
  requires; a bare `true` marks the route for spec emission and metrics
  but emits no header, because the draft-era literal `true` did not
  survive into the final RFC. `sunset:` emits the HTTP-date form, and a
  sunset earlier than the deprecation instant is refused at config
  compile rather than shipped as a contradiction. `successor:` and
  `link:` emit the `successor-version` and `deprecation` relations,
  appended so an upstream's own `Link` headers survive.
  `after_sunset: gone` retires the route with `410 Gone` and a JSON
  body naming the successor once the instant passes; the default
  `serve` keeps proxying, so a forgotten config never takes an API down
  by surprise. That refusal is enforcement, so it also emits a
  `policy_violation` audit record with `event_type: api_deprecation`
  carrying the tenant and the accountable key id.
  `openapi_validation.deprecation_headers:` (off by default) drives the
  same emission from operations a loaded spec marks `deprecated: true`,
  and `/.well-known/openapi.json` marks config-deprecated operations
  `deprecated: true` with `x-sbproxy-sunset` and `x-sbproxy-successor`
  extensions, so the published spec and the wire headers cannot
  disagree. `sbproxy_deprecated_requests_total{origin, route,
  past_sunset, outcome}` is the migration tracker: who is still
  calling, against which announcement, and whether they are being
  served or refused. See
  [docs/api-gateway.md](docs/api-gateway.md#deprecating-endpoints) and
  [examples/api-deprecation/](examples/api-deprecation/).

- **`body_threat_protection`: structural JSON and XML request-body
  limits.** A new `policies:` entry that refuses bodies by shape rather
  than by content: a thousand levels of nesting to blow a recursive
  parser's stack, a million-key object to soak CPU in hash insertion,
  an XML DTD whose entities expand into gigabytes. JSON limits are
  `max_depth` (64), `max_object_entries` (10 000), `max_array_items`
  (10 000), `max_key_length` (1 024 bytes), `max_string_length` (128
  KiB), and `max_containers` (50 000, objects plus arrays); XML limits
  are `max_depth` (64), `max_elements` (10 000), and `max_attributes`
  (256). Any single limit set to `0` disables that one check. A
  `<!DOCTYPE` declaration is refused unconditionally and is not
  configurable, which closes the entity-expansion class by construction
  rather than by pattern. The JSON scanner is iterative with an
  explicit stack and a hard 10 000-depth ceiling that holds even when
  the operator disables the depth check, so the attack the policy
  exists to stop cannot overflow the scanner itself. A violation
  answers `400` naming the limit and the observed and allowed numbers,
  and never echoes body content into the response, the log, or the
  audit record. `mode: tap` logs and counts without blocking, for
  sizing limits against real traffic before enforcing; the policy
  counter's `action` label keeps the two apart. One thing to know if
  you are migrating from the origin-level `threat_protection:` block:
  this policy has no body-size knob. The successor to
  `json.max_total_size` is `request_limit.max_body_size`, not a key
  here, and all three of the policy's structs refuse unknown fields, so
  an invented one fails config load instead of being silently ignored.
  See
  [docs/api-security.md](docs/api-security.md#structural-body-threat-limits)
  and
  [examples/body-threat-protection/](examples/body-threat-protection/).

- **`sbproxy_target_health_state`: per-target load-balancer health as a
  Prometheus gauge.** Whether a target is actually taking traffic used
  to mean polling `GET /api/health/targets`. It is a gauge now, on
  LiteLLM's 0/1/2 deployment-state scale (0 healthy, 1 degraded with
  the circuit breaker half-open, 2 excluded from selection), so Grafana
  panels built against that convention port over unchanged. The value
  folds all three exclusion mechanisms, active probe, passive outlier
  ejection, and circuit breaker, and is sampled at scrape time from the
  same pipeline walk that renders the admin endpoint, so the two
  surfaces cannot tell different stories about one target. A target
  dropped by a config reload leaves the scrape on the next render
  instead of freezing at its last value. The `target` label is the
  configured URL, or the load balancer's own `url#index` identifier
  when one origin configures that URL more than once. A Target Health
  State panel ships on the origins dashboard, and a Budget Utilization
  by Scope panel on the AI gateway dashboard for the already-exported
  `sbproxy_ai_budget_utilization_ratio`; headroom is
  `1 - sbproxy_ai_budget_utilization_ratio` in PromQL, and there is
  deliberately no separate remaining family, because a family and its
  complement double the series without adding information. See
  [docs/observability.md](docs/observability.md#budget-headroom-and-target-health)
  and
  [examples/health-and-budget-gauges/](examples/health-and-budget-gauges/).

- **`hmac_auth`: signed-request authentication.** A new auth provider
  for machine callers that prove possession of a shared secret by
  signing each request (RFC 9421 HTTP Message Signatures,
  `hmac-sha256`) instead of sending a static credential. Config is a
  `keys` list of `key_id` + `secret` pairs (secrets resolve through
  the secret resolver) with optional per-credential metadata, a
  `required_components` list defaulting to `["@method",
  "@target-uri"]`, and a `clock_skew_seconds` window (default 300)
  enforced against the mandatory `created` parameter as the replay
  defense. Failures answer `401` with a `WWW-Authenticate: Signature`
  challenge that never carries key material. See the `hmac_auth`
  section of [docs/configuration.md](docs/configuration.md) and
  [examples/auth-hmac/](examples/auth-hmac/).

- **`POST /v1/responses` resolves an object-valued `prompt` against the
  gateway prompt store.** A request carrying
  `{"prompt": {"id": "...", "version": "...", "variables": {...}}}`
  previously had the whole object dropped in translation. The `id` now
  maps onto a stored prompt name and `version` onto a stored version
  label, an absent version takes the pinned default, and caller
  `variables` render into the template before guardrails scan the
  result. One stored prompt serves every configured provider, which is
  the part a dashboard-hosted template cannot do. An unknown reference
  answers `404`, a malformed object or a failed render answers `400`,
  and nothing falls through to the raw input. Caller-supplied
  `variables` override an operator's static `variables:` on a version,
  so a constraint that must hold regardless of the caller belongs in
  the template text; see the prompt-object section of
  [docs/ai-gateway.md](docs/ai-gateway.md).

- **`sbproxy_ai_translation_dropped_total{surface, field}` counts every
  request field lost in translation.** `/v1/messages` and
  `/v1/responses` now push a note for each unrepresented top-level
  field, each dropped content block, and each extension attribute on a
  block they keep, then emit one aggregated warn per request naming at
  most eight distinct fields. `surface` uses the same `messages` and
  `responses` values as `sbproxy_ai_surface_requests_total`, so a
  drop-rate query joins the two. The log line to grep is
  `AI proxy: request fields dropped in translation`, and it carries the
  origin and tenant.
- **Key-lifecycle events reach the SIEM feed.** The `events:` type
  list grows to eighteen declared types with five key-lifecycle kinds.
  `key_minted`, `key_revoked`, `key_rotated`, and `key_blocked` bridge
  from the `key_audit` channel, so every admin mint, revoke, rotate,
  or block of a key or upstream credential publishes one typed event
  beside its audit-chain entry instead of a SIEM having to poll the
  admin API. `credential_resolved` fires once per actual resolution of
  an upstream credential's material (never per request), with
  `outcome: stale_served` marking the start of a rotation grace window
  serving through a secret-backend outage. That one is per outage, not
  per request in the window; the per-serve count is the `cache="stale"`
  series on the resolution histogram. Payloads are an explicit
  allowlist (`op`, `resource`, the public id, actor, tenant, outcome, and closed
  status labels), never the `key_audit` diff, a token, or a hash;
  `events.types:` filters the new kinds like any other, and
  `sbproxy_events_dropped_total` covers them. See
  [docs/events.md](docs/events.md#key-lifecycle-events-the-dual-record).

- **Key management gets its four operational metrics.**
  `sbproxy_key_operations_total{operation, outcome}` counts every admin
  key-lifecycle call at the dispatch seam, keeping `refused` (a 4xx the
  caller can fix) apart from `error` (the store or governance backend
  failed) so a busy console never reads as an outage.
  `sbproxy_credential_resolution_duration_seconds{cache, outcome}`
  times each bound-credential resolution and names the layer that
  answered, with `stale` marking a grace-window serve rather than
  folding it into `hit`. `sbproxy_key_lookup_cache_total{kind,
  outcome}` reports the keystore TTL cache, including `negative_hit` as
  its own value so a stampede of unknown keys stays visible. And
  `sbproxy_audit_write_failures_total{channel}` counts audit emissions
  that did not reach a sink they were promised, touching the series at
  0 on every emission so an `increase()` alert has a baseline from the
  first scrape; its two channels are the key-mutation trail
  (`key_path`) and the admin-console action trail (`admin_path`), which
  is why it is named for the audit signal rather than for the key
  plane. Every label value is a compile-time constant,
  so none passes through the cardinality limiter. The `sbproxy-security`
  Grafana dashboard gains the matching panels. See the operational
  metrics section of
  [docs/key-management.md](docs/key-management.md#operational-metrics).

- **A signed extension bundle can ship a `runtime: rego` transform, not
  just a policy.** A `kind: transform` hook on a Rego bundle attaches
  under `transforms[]` by its `type` name and evaluates once per
  buffered response body. Its input is `input.body.body_base64` (the
  complete body, base64), `input.body.content_type`,
  `input.body.origin`, and `input.config`; the pinned rule must return
  a base64 string, which becomes the replacement body, bounded by
  `sandbox.max_output_bytes`. An undefined rule is the transform
  declining and the body passes through untouched. The module compiles
  once per hook at candidate load and its query is proved evaluable
  there, so a bad rule reference refuses the bundle instead of failing
  every request. Bounded by `sandbox.budget_ms` plus the buffer and
  output caps; `memory_mb` and `stack_kb` do not apply to Rego and are
  now refused on a Rego manifest rather than accepted and ignored. See
  the Rego transform section of
  [docs/extension-bundles.md](docs/extension-bundles.md).

### Changed, and worth checking before you upgrade

- **`POST /admin/keys/{id}/rotate` returns the current `sbp_` token
  shape, and refuses a key id it cannot mint one for.** Every shipped
  release before this returned the legacy `sk-<id>-<secret>` shape from
  this endpoint while `POST /admin/keys` had already moved to
  `sbp_<id>_<secret>`. Any operator script matching `^sk-`, or splitting
  a rotated token on `-` to recover the key id, needs updating.

  The refusal is the part to check before you upgrade. A minted key id
  is sixteen lowercase hex characters, and the strict parser on the
  inbound path asserts exactly that. A key seeded from config under
  `key_management.seed.keys[]` can carry any id its author wrote, and
  rotating one produced a token nothing could parse: the endpoint
  answered `200` with a credential that authenticated on no code path,
  and when the grace window closed the working token died with it.
  Rotating a non-conforming id now answers
  `409 {"error": "key id is not in the minted format ..."}` and changes
  nothing. If you rotated a seeded key on a build carrying the earlier
  behavior, the token you were handed is not usable; create a
  replacement key with `POST /admin/keys`, move callers over, and revoke
  the seeded id.

- **Every upgraded WebSocket tunnel is now scanned, and every one that
  is not a `websocket` action's is held to a 10 MB message ceiling.**
  The frame scanner was armed inside a match on `Action::WebSocket`, so
  `/v1/realtime` (which runs under an `ai_proxy` origin and hands off to
  transparent forwarding) and any `type: proxy` or `type: load_balancer`
  origin fronting a WebSocket backend opened a completely unscanned
  tunnel. Those now get the scanner, with the same documented 10 MB
  default a `websocket` action gets when it configures nothing. A `101`
  for a non-WebSocket upgrade is still left alone.

  Check this one before you upgrade if you front a WebSocket backend
  through any action other than `websocket` and your peers send messages
  larger than 10 MB. Those tunnels were unbounded on every prior release
  and are not any more: the first oversized message drops both TCP
  connections mid-message, with no close frame and no HTTP status,
  because nothing HTTP may be written into a stream the client is
  already reading as frames. `sbproxy_websocket_teardowns_total{reason="message_too_large"}`
  and a `websocket_message_too_large` audit record are how it shows up.
  There is no config key to raise the ceiling for those origins yet;
  `max_message_size` is a `websocket`-action field, so today the escape
  hatch is to front the backend with a `websocket` action, which also
  gets you the subprotocol allowlist. Widening the key to the other
  action types is tracked separately.

- **`transport: stdio` MCP servers now run as one supervised
  persistent child per configured server, not one process per
  JSON-RPC exchange.** Server-side session state survives between
  calls, and process startup is paid once per child rather than once
  per call. The supervisor health-probes an idle child with an MCP
  `ping`, restarts a crashed child under bounded exponential backoff,
  replays the `initialize` handshake on the replacement child, fails
  in-flight calls closed with a typed error on a crash or timeout
  instead of hanging, and kills the child when its server leaves the
  configuration. Legacy one-shot commands that answer a single
  request and exit keep working: a child that dies after serving is
  respawned on the next call. See the stdio section of
  [docs/mcp-gateway-guardrails.md](docs/mcp-gateway-guardrails.md).

- **`tool_choice` is honored end to end, and `top_k` is now stripped
  for OpenAI-format upstreams.** `/v1/messages` used to parse neither
  field, so both were dropped silently and a forced-tool request came
  back as an ordinary completion. Both are honored now, and each
  provider translator rewrites `tool_choice` into that provider's own
  spelling: `{"type": "any" | "none" | "tool"}` for Anthropic,
  `toolConfig.functionCallingConfig` for Gemini, and Bedrock already
  mapped it. `top_k` has no OpenAI Chat Completions equivalent, so the
  OpenAI arm drops it rather than forwarding an argument
  `api.openai.com` answers with a `400`. Check this one before you
  upgrade if you point an origin with `format: openai` at an
  OpenAI-compatible upstream that does honor `top_k`, such as Together
  or a self-hosted vLLM: that value used to be forwarded and is now
  removed, and sampling will change. `format: custom` byte-forwards the
  body and is the escape hatch. See the translation section of
  [docs/ai-gateway.md](docs/ai-gateway.md).

### Fixed

- **A `failure_posture: closed` transform now fails a `static` or
  `mock` response closed instead of serving it untransformed.** The
  transform chain has reached generated bodies since the response-phase
  work landed, but a fault there logged a warning and continued with
  the untransformed buffer, whatever the transform's declared posture.
  A redaction transform on a `type: static` origin therefore shipped
  the exact string it existed to strip whenever it faulted (a budget
  overrun, a non-string result, a body over the buffer cap). A `closed`
  transform's fault now answers `500` with
  `x-sbproxy-transform-error: <transform>` and never writes the
  generated body, matching the proxied and plugin-action paths.
  `failure_posture: open`, which is what a `transforms:` entry defaults
  to, keeps warning and continuing.

- **A WebSocket control frame can no longer disable
  `max_message_size`.** Control frames do not count toward a message
  total, so their declared payload length was skipped rather than
  checked. A fourteen-byte masked pong header declaring `u64::MAX` was
  enough: the scanner spent the declared count skipping payload bytes,
  never parsed another frame header, and the cap stopped applying in
  that direction for the life of the connection, with nothing logged
  and no teardown. RFC 6455 section 5.5 is now enforced on the frames
  it governs: a control frame over 125 payload bytes, or one arriving
  without `FIN`, closes the tunnel.

- **`print()` inside a Rego bundle hook is bounded and redacted.** A
  transform hook's input is the complete buffered response body, so
  `print(input.body.body_base64)` copied every response into the log at
  `info`, uncapped and unredacted. Messages now pass through the secret
  redactor, are truncated at 512 bytes, and at most eight events are
  emitted per evaluation with one summary line for the remainder.

- **A large request body no longer costs the client the response
  sbproxy already wrote.** Any response the proxy generates itself goes
  out before the client's body has been read: `type: mock`,
  `type: static`, `type: echo`, `type: beacon`, every policy denial,
  and the 502 for an upstream that could not be reached. The socket
  therefore still held unread bytes when the session ended, and closing
  a socket in that state makes the kernel send a TCP RST rather than a
  FIN, which discards whatever the peer had buffered but not yet read,
  the response included. Clients saw a reset connection instead of
  their 200, 403, or 502. The proxy now reads and discards the rest of
  the body before closing, bounded at five seconds the way nginx bounds
  `lingering_close`; the response still goes out immediately and only
  the teardown waits. Hitting the bound increments the new
  `sbproxy_request_body_drain_timeout_total`. One consequence worth
  knowing: a client that sends `Expect: 100-continue`, receives the
  final response instead of a 100, and then correctly sends no body now
  holds its connection for that bound rather than being closed at once.

- **`type: mock` and `type: beacon` responses declare
  `Content-Length`.** Without it the body was close-delimited, so the
  only end-of-body signal was the connection closing: a client could
  not tell a complete body from a killed one, and every mock or beacon
  response burned a connection even when it advertised `keep-alive`.
  That missing header is why the reset above surfaced on the mock path
  from roughly 70 KB while `type: static`, which has always declared
  its length, survived to a megabyte. Neither arm declares a length on
  204 or 304, where RFC 9110 section 8.6 forbids it; `type: static` no
  longer does either.

- **`content_digest`'s `on_missing: require` refuses before the
  upstream is dialed.** The missing-header check ran in
  `request_body_filter`, which Pingora reaches only after
  `upstream_peer` has selected a peer and the connection is up. The
  verdict was never wrong, only late, and late is an availability
  problem: every refusal paid for a full upstream dial and held the
  connection slot for it, and pointed at an upstream that was slow or
  unreachable the client got the upstream's failure instead of the
  policy's. Against an unreachable upstream the proxy answered `502`
  rather than the configured `400`. Nothing about that verdict depends
  on the body, so it now runs in the header phase: the upstream is
  never dialed, `missing_status`, `error_body`, and
  `error_content_type` are honored exactly as before, and
  `on_missing: skip` still falls through to the body filter unchanged.
  Digest refusals from either phase now increment
  `sbproxy_policy_triggers_total{policy_type="content_digest",action="deny"}`,
  which none of the body-phase refusals did, and log on the
  `sbproxy::content_digest` target with a `reason` naming the outcome.
  See [docs/content-digest.md](docs/content-digest.md).
- **`prompt_injection_v2`: the URI and header scan now honors
  `block_body` and `block_content_type`.** The policy can block from
  four places. Three of them (the buffered request body, the `ai_proxy`
  prompt segments, and A2A message parts) wrote the operator's
  configured rejection body and media type to the wire. The fourth, the
  synchronous scan of the request line and non-auth headers, denied
  through the generic policy renderer instead: it wrapped the body in a
  fixed `{"error": "<block_body>"}` envelope and always answered
  `Content-Type: application/json`. `block_content_type` was ignored
  outright on that path, and a `block_body` that was already JSON came
  back double-encoded as a string inside an `error` field, so
  enforcement depended on which internal path happened to run. All four
  paths now serve `block_body` verbatim with `block_content_type`. If
  you pre-wrapped `block_body` to work around this, unwrap it. Each
  block increments the new
  `sbproxy_prompt_injection_blocks_total{scan_path,tenant}` counter, so
  the four paths can be compared rather than merged.

- **`security_headers`: a configured `content_security_policy` is no
  longer silently dropped.** Setting both a `headers:` array and a
  `content_security_policy` block emitted the array and no CSP at all
  whenever `enable_nonce` was false and no `dynamic_routes` were set:
  no error, no warning, just responses with no CSP. The two now merge,
  with the `content_security_policy` block as the single source of
  truth for that header and `headers:` supplying everything else. Two
  siblings of the same bug went with it: `report_only` and `report_uri`
  were consulted only on the nonce path, so a policy asking for
  report-only monitoring was emitted as an enforcing one, and a CSP
  block whose `policy` string was empty emitted nothing. Authoring a
  CSP in both places at once is now refused at config compile rather
  than resolved quietly, and a `headers:` array that supersedes legacy
  flat fields logs which ones it is dropping. Emitted policies are
  counted by
  `sbproxy_security_headers_csp_emitted_total{mode,tenant}`.

- **Prompts admin page "Add version" now sends the field the backend
  expects.** The form built a `content` key while
  `POST /admin/prompts/<host>/<name>/versions` deserializes into a
  required `template` field with no alias, so every submission 400ed.
  The form now sends `template`; the same operation already worked via
  the raw admin API.

- **The `websocket` action's `max_message_size` and `subprotocols` are
  enforced.** Both fields parsed and did nothing. `max_message_size`
  (default 10 MB, now enforced including the default) closes the
  upgraded tunnel as soon as a message in either direction declares
  more payload than the cap; frame headers are scanned, payloads are
  never read or buffered. A non-empty `subprotocols` list now
  allowlists `Sec-WebSocket-Protocol` negotiation: the client's offer
  is filtered to it before going upstream, an offer with no allowed
  entry is refused with a `400` before any upstream connection, and an
  upstream selection outside the negotiated set fails the upgrade with
  a `502`.

- **Mid-tunnel failures on an upgraded websocket tear the connection
  down instead of writing an HTTP error body into the frame stream.**
  Once the `101` reaches the downstream wire the client is speaking
  WebSocket frames, but a post-upgrade failure fell through to the
  generic upstream-error tail and wrote a synthesized `502 Bad Gateway`
  response, which arrives as garbage bytes spliced into the frame
  sequence. Every post-upgrade failure (upstream reset, timeout, read
  error) now closes both connections and writes nothing, on both
  surfaces that upgrade: the `websocket` action, and the AI gateway's
  realtime tunnel (`type: ai_proxy` reaching `/v1/realtime`), where a
  provider reset used to splice a `502` into a client's audio frames.
  What decides it is the `101` reaching the wire rather than which
  action opened the tunnel, so pre-upgrade failures still render an
  ordinary HTTP error a client can read: a connect error, a refused
  subprotocol negotiation, or a realtime handshake the provider
  answered `401`. The real failure mode still lands in the log,
  classified the way the `Proxy-Status` machinery classifies upstream
  errors, and on
  `sbproxy_websocket_teardowns_total{reason="upstream_error"}`. See
  [docs/websocket.md](docs/websocket.md#mid-tunnel-errors-never-write-http-bytes).
- **GraphQL validation refuses before connecting upstream.** On a
  validated `graphql` origin without `request_modifiers`, an invalid
  document now gets its `400` in the request phase, before any upstream
  connection is attempted; previously validation ran only after the
  connect, so an invalid query against a down upstream surfaced as a
  `502`. Routes with `request_modifiers` still validate at the
  post-modifier seam, since the modified request is the one the
  contract holds.

### Security

- **`hmac_auth` now binds a signature to the body it covers.** A
  signature covering `content-digest` was checked against the empty body
  the authentication phase can offer, not against the bytes the client
  sent. The check was inverted rather than weak: a client sending the
  true digest of its body was refused, while one declaring the empty-body
  digest `sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:` was
  admitted and could then send any body at all. Because covering
  `content-digest` could not work, deployments signed `("@method"
  "@target-uri")` and nothing else, so a request captured off the wire
  replayed with an attacker-chosen body until its `created` timestamp
  left the `clock_skew_seconds` window. An attacker could not forge a
  signature, change the method or the route, or extend the window; they
  substituted the body of a request someone else signed.

  Verification now defers the digest half to the request body filter and
  completes it against the complete pre-transform body, the same
  two-step contract `bot_auth` uses, answering `401` on a mismatch.
  Covering `content-digest` works, so `required_components` can require
  it and mean it. Two consequences worth knowing before you upgrade: a
  body-covering signature now caps the request at the 8 MiB request-body
  buffer and a larger body answers `413`, and the `401` body for a
  mismatch changed from `bot_auth: content-digest body mismatch` to
  `signature: content-digest body mismatch`, since either provider can
  raise it. See the `hmac_auth` section of
  [docs/configuration.md](docs/configuration.md).

- **`ldap_auth` bounds what it dials.** Authentication runs before an
  origin's `policies:`, so no `rate_limit` or `ddos` policy could cap the
  directory bind: anyone able to send an `Authorization: Basic` header
  drove one bind per request, which made the gateway a 1:1 amplifier
  pointed at the directory and offered account lockout for any guessable
  username. Three bounds now run before the dial, none of which caches a
  success: a 30 second refused-credential cache keyed on a salted
  SHA-256 of the exact username and password, a per-username failed-bind
  budget of 5 per 60 seconds that then throttles to one bind per 12
  seconds, and a cap of 32 binds in flight. The budget throttles rather
  than blocks on purpose, so nobody can spend a username's budget with
  wrong guesses and lock its owner out; a throttled request answers
  `503`, not `401`, because the directory was never consulted. An
  attacker cycling *distinct* usernames is still bounded only by what
  runs in front of the origin.

- **Refused LDAP binds and refused JWE algorithms are visible in release
  builds.** Both logged at `debug`, which the release profile's
  `release_max_level_info` compiles out, so the shipped binary recorded
  nothing for a refused credential while the documentation promised the
  log named the offending algorithm. Raised to `info`. A failed
  `content-digest` body binding now logs at `warn` at all three refusal
  sites; it previously logged at `debug` in one and nowhere in the other
  two. No credential is logged at any of them.

### Fixed, plan-time validation

- **`ldap_auth` and its `ldap` alias validate clean.** Both were missing
  from the OSS auth catalogue, so `sbproxy validate` reported that the
  type "is not in the OSS catalog (will fail at runtime)" on every LDAP
  config, including this repository's own `examples/auth-ldap/sb.yml`,
  which was false. The same omission stopped both names being reserved
  against a bundle hook claiming them.

### Documentation

- **gRPC streaming support is described accurately.**
  `examples/grpc-h2c/README.md` reported that server reflection
  (`list`) came back as a garbled framing error through the proxy and
  steered readers away from it. Rechecked against a grpc-go server
  with reflection registered: `list` works, `grpcurl describe` returns
  byte-identical output through the proxy and straight at the
  upstream, and bidirectional streaming round-trips every message.
  New end-to-end coverage pins all of it; there was none before. A new
  [gRPC limits](docs/routing.md#grpc-limits) section records what is
  genuinely narrower, including one composition worth avoiding: a
  body-reading policy on a `grpc` origin needs the complete request
  body, so it stalls every streaming RPC on that origin while leaving
  unary calls working.

## [1.13.0] - 2026-08-18

### Security

- **h2 updated to 0.4.16.** RUSTSEC-2026-0258 (low severity): h2 0.4.15
  could queue empty DATA frames without bound on streams the peer never
  drains. The 0.4.16 patch bounds the queue. Lockfile-only change; no
  SBproxy behavior differs beyond the fix itself.

### Added

- **A `federated_servers[]` entry can be `type: local`: tools the
  gateway serves itself, declared entirely in config.** A local tool is
  one of three handlers: a fixed value, one HTTP call, or a
  dependency-ordered DAG of HTTP calls under `steps:`, connected by a
  `${args}` / `${steps}` interpolation language and shaped into one
  response with a `template`, JavaScript, or Lua script. DAG steps run
  in deterministic topological order with per-step CEL `condition`
  gating, per-step retry, `continue_on_error`, and a whole-tool-call
  budget (`steps.timeout`, default 30 seconds, capped at 5 minutes).
  Every outbound step dial goes through the server's own
  deny-by-default egress gate, and a failed step, a throwing script, or
  a template referencing a missing path fails the tool call closed
  through the normal JSON-RPC error path, never a partial result.
  Because local tools publish into the same registry federation does,
  the whole existing governance surface applies with no new wiring:
  RBAC, approval status (a `draft` local server is hidden and refused
  like any other), versioning, argument and result policies, content
  filters, session-flow enforcement, and evidence records.
  [mcp-compose.md](docs/mcp-compose.md) is the field reference;
  [`examples/mcp-local-tools`](examples/mcp-local-tools/),
  [`examples/mcp-compose`](examples/mcp-compose/), and
  [`examples/mcp-compose-js`](examples/mcp-compose-js/) are the
  runnable shapes.

- **`proxy.config_history` keeps a durable ring of every applied
  config, surfaced end to end.** Off by default. When enabled, every
  config this proxy applies (from disk, git, or the config authority)
  is recorded as a content-addressed, zstd-compressed entry holding the
  pre-resolution bytes: a `${VAR}` or `vault://` / `secret://`
  reference never resolves into a stored entry. `keep` bounds the ring,
  and eviction persists the shrunk index before unlinking any blob, so
  a crash mid-eviction can never leave an index naming a blob that is
  gone; a host crash that truncates `index.json`, all the way to zero
  bytes, is repaired on the next open rather than bricking the ring.
  Read it back with `GET /admin/config/history` and
  `GET /admin/config/history/{digest}`, with `sbproxy config history`
  and `sbproxy config show`, or in the admin console's config panel;
  `sbproxy_config_history_entries` and `sbproxy_config_revision_info`
  report the ring on the metrics surface. The admin route and CLI mask
  a literal secret an operator typed into the YAML as `[REDACTED]`, the
  same pass `GET /admin/config` applies; the ring file underneath keeps
  the original bytes, because a rollback needs them, and the
  owner-only directory permissions (`0700`/`0600`) are the real
  boundary on that file. Two honest limits: changing this block takes a
  restart, not a hot reload, and `keep_rejected` is accepted for
  forward compatibility but nothing writes rejected candidates yet in
  this release. See
  [configuration.md](docs/configuration.md#config_history) and the
  [config-history example](examples/config-history/).

- **Raw-body Lua transforms, and per-request context for WASM
  transforms.** A `type: lua` transform mirrors the JavaScript raw
  transform's contract: the body is a string in and a string out, never
  parsed as JSON, so a script can rewrite plain text, XML, CSV, or any
  non-JSON payload, the thing `lua_json` cannot do. It uses the same
  two-tier invocation as `lua_json`: a `transform(body, ctx)` function
  when defined, otherwise legacy top-level code with `body` bound as a
  global. Separately, a `type: wasm` transform can set
  `request_context: true` to receive the same `ctx` document Lua and
  JavaScript transforms get (principal, aipref, TLS fingerprint) as a
  JSON-encoded `SBPROXY_REQUEST_CONTEXT` WASI environment variable,
  scoped to that invocation; stdin is untouched either way. Both new
  shapes are request-dependent (WASM only when the flag is set), so the
  config compiler's existing refusal of a request-dependent transform
  on a response-cached origin covers them too, and a ctx-off WASM
  transform keeps its cacheability exactly as before. See
  [scripting.md](docs/scripting.md) and
  [wasm-development.md](docs/wasm-development.md).

- **PII and secret detections carry bounded position spans.** A
  detection record previously said only "email detected," with no way
  to say where or whether it was one match or a thousand. The PII
  guardrail's decision-audit records, the `dlp` policy's deny reason,
  and MCP `content_filters` logging now carry a bounded list of match
  spans plus a dropped count, using one shared capped span type across
  all three surfaces. Wiring the MCP spans also fixed a real ordering
  bug: `secrets` and `pii` were scanned in sequence against the same
  live document, so a `secrets: redact` hit shifted offsets before
  `pii` scanned; both categories now scan one snapshot taken before
  either mutates anything.

- **`policies: [{type: owasp_api_top10}]` expands into the OWASP API
  Security Top 10 controls the proxy can honestly cover.** A
  compile-time expander synthesizes concrete policy entries per item,
  backing off per piece when the origin already authors an overlapping
  policy, and surfaces a five-state manifest (`enforced`,
  `report_only`, `already_enforced`, `needs_operator_input`,
  `not_covered`) three ways: `GET /admin/owasp-api-pack`,
  `sbproxy plan`, and validation errors naming the knob that completes
  a parked item. The posture is safe by default: `report_only` unless
  `posture: enforce`, and api4's rate pieces synthesize only when the
  operator declares `per_item.api4.rps`, because blind IP-keyed budgets
  behind an undeclared load balancer collapse every client onto one
  budget. api2, api6, and api10 are named `not_covered` with reasons
  rather than pretended at. See
  [owasp-api-top10.md](docs/owasp-api-top10.md) and the
  `owasp-api-top10` and `owasp-api-selective` examples.

### Changed, and worth checking before you upgrade

- **The `dlp` policy now scans request bodies.** It documented body
  scanning and only ever saw the URI and headers; the enforcer received
  the buffered body and never read it. It now scans request bodies by
  default, capped at the first 16 KiB, the same bound the injection
  policy uses. An origin carrying a `dlp` policy starts matching on
  body content the moment you upgrade, so traffic that only ever
  tripped on a header can now trip on a payload: check what your
  patterns match before deploying. Response-side scanning is
  structurally out of the policy phase's reach and stays with
  transforms; [api-security.md](docs/api-security.md) now states
  exactly what each direction covers.

- **The AI PII guardrail's knobs all do something, or refuse.**
  `action: log` was a silent no-op; it now logs the detection (pattern
  type only, never the matched text) and allows the request.
  `action: mask` and `redact_response: true` cannot work under the
  current guardrail signature, so both are now refused at config load
  with an error naming the limitation, instead of being accepted and
  ignored. A config carrying either stops loading on upgrade; the
  refusal is the honest state until per-entity actions land.

- **Enumeration detection fires without `object_rules`.** The
  `object_authz` policy's `enumeration.enabled: true` never counted
  anything unless a declared ownership rule captured an object id,
  which contradicted its documentation as a standalone anomaly
  detector. With no `object_rules` configured it now falls back to a
  path heuristic: a request whose trailing path segment is id-shaped (a
  numeric run or a canonical UUID) counts the whole normalized path as
  the object, so a sweep across `/orders/1` through `/orders/500` trips
  while `/reports/2026/08/` browsing does not. The heuristic counts
  identified callers only (an anonymous flood is never attributed to a
  shared bucket), does constant bounded work per request under a capped
  tumbling window, and its hits are always detect-only: audited to the
  security log and `sbproxy_object_authz_violations_total`, never
  blocking, because both the id shape and the path-to-object mapping
  are guesses. Rule-scoped enumeration, BOLA, and BFLA are unchanged
  and stay fully enforceable, and any configured `object_rules` scope
  detection exactly as before. If you run with `enumeration.enabled`
  and no rules, expect violation records to start appearing on traffic
  that previously counted nothing. See
  [object-authz.md](docs/object-authz.md).

- **`$${...}` is now an escape everywhere the config's `${VAR}`
  environment interpolation runs.** The MCP composition docs define
  `$${VAR}` as rendering a literal `${VAR}`, but the pre-parse layer
  spliced the live environment value first, which could bake a secret
  into the compiled config. The escape is honored end to end now: an
  even run of dollars never substitutes. A config that relied on
  `$${VAR}` splicing a value (none of the shipped examples did) reads
  differently after upgrading.

- **Displayed credential masking covers more key names.** The pass that
  masks secrets in `GET /admin/config`, config-history views, and log
  output now recognizes session tokens, signing and client secrets, and
  the product's own key-name families (`master_key`, `signing_key`,
  `virtual_key`, and relatives), and masks only the value while
  preserving the surrounding structure, so JSON log lines survive
  redaction intact. Operators diffing displayed config against disk
  will see more `[REDACTED]` than 1.12 showed.

### Fixed

- **`codemode.ts` no longer advertises `draft` servers.** The
  TypeScript module served at `GET /.well-known/mcp/codemode.ts`
  rendered the full federation catalog with no approval-status
  filtering, so a `draft` server's tool names and descriptions leaked
  even though `tools/list` and `tools/call` already hid and refused it.
  It now uses the same visibility predicate as `tools/list`;
  `deprecated` servers are unaffected. One caveat is still true and now
  documented rather than conflated with this gap: the module is served
  ahead of per-caller authentication and cached per catalog, not per
  principal, so `rbac_policies` scoping does not reach it. See
  [cloudflare-code-mode.md](docs/cloudflare-code-mode.md).

- **The shipped examples demonstrate what they claim, on camera.** A
  live replay of the example cassettes against the release binary found
  recordings whose payoff commands printed nothing, and two examples
  that could never fire at all. The `sri` example hooked a policy that
  runs in the upstream response phase to a `type: static` origin that
  phase never reaches; it now proxies to a local fixture and the
  violation metric demonstrably increments. The `websocket-proxy`
  example's client could not read a frame over 125 bytes (no RFC 6455
  extended-length decoding); it now speaks full frame lengths and
  demonstrates the oversized-frame cap the README promised.
  `pii-redaction` recorded against a fixture that never echoed bodies,
  so there was nothing to redact; it records against a local echoing
  fixture now. The recording harness probes the admin port (admin bind
  failure is non-fatal, so a stale occupant silently blanked every
  admin payoff), starts each example's fixture itself, and parses the
  `admin:` block by its own indentation instead of grabbing the first
  `port:` anywhere in the file. All affected cassettes are re-recorded
  and frame-verified showing real output.

- **Trace and metric exporters answer to a reload, not just to boot.**
  The egress inventory's boot-time authorization never re-checked the
  boot-built OTLP exporters after a hot reload, so a config that newly
  denies the running telemetry endpoint silently kept exporting; and a
  denied telemetry endpoint stamped the sightings inventory but never
  reached the `egress_refused` counter or the event feed, unlike every
  other purpose. A reload whose config denies a running exporter's
  endpoint is now refused naming the conflict, and telemetry denials
  publish through the same refused-event bridge as everything else.

## [1.12.0] - 2026-08-17

### Added

- **The full MCP surface is governed: content filters, tenant-bound
  sessions, and registry approval status.** `content_filters` runs the
  shared secret and PII detector catalog over tool-call arguments and
  results, and over `resources/read` and `prompts/get` results, with
  `off | warn | redact | block` per category; MCP responses are written
  outside the HTTP `response_filter` phase, so this is the first time
  those detectors see MCP traffic at all. Sessions are tenant-bound: a
  session id presented by a different tenant is refused with the same
  generic error a stranger gets, and session establishment is capped
  (256 per tenant, 4096 globally, sixteen tenants at full sub-cap) with
  a fail-closed refusal of `initialize` at saturation rather than an
  untracked session. `federated_servers[].status` gates the registry:
  `draft` servers are invisible on every listing surface and refused at
  dispatch, `deprecated` serves but warns on every call. The peer
  registry behind downgrade detection carries the same caps; under
  `downgrade: block`, a peer it cannot track is refused rather than
  enforced against no baseline. `result_policies[]` runs the same
  CEL/Rego engine over the tool-call result document after dispatch.
  [mcp-security.md](docs/mcp-security.md) is the narrative;
  [mcp-security-coverage.md](docs/mcp-security-coverage.md) maps
  MCP01:2025 through MCP10:2025 row by row, each claim naming the test
  or example that proves it.

- **Every security decision reaches the SIEM.** A twelfth typed event,
  `egress_refused`, carries every purpose-scoped outbound-dial refusal
  (AI providers, MCP upstreams, token exchange, webhooks, artifact
  fetches) with the same bounded labels its Prometheus series already
  had. All six config-reload paths emit `config_audit` records for
  accepts and rejections, with rejection reasons bounded and scrubbed
  of the config path. mTLS handshake rejections write a
  `security_audit` record with the certificate CN control-stripped and
  bounded on every surface it reaches. Circuit-breaker state
  transitions emit one structured record alongside the existing
  counter. `budget_exceeded`, `guardrail_triggered`,
  `provider_selected`, `ai.failure`, and `ai.close` are wired at their
  decision points, and boot warns when `events.types:` names a type
  nothing publishes. [events.md](docs/events.md) is rewritten as the
  SIEM integration map: which channel carries what, the gapless
  sequence contract, and what deliberately stays off the lossy feed.

- **MCP tool calls emit a governance evidence event, with an optional
  fail-closed guarantee.** The `events:` type list grows to thirteen
  declared types, eleven of which publish today (see
  [events.md](docs/events.md)). The new one,
  `mcp_governance_decision`, carries OTel GenAI/MCP semantic-convention
  attribute names plus sbproxy's own `sbproxy.*` fields (verdict,
  redacted reason, a salted argument hash, and a per-tenant gapless
  sequence number a SIEM can use to detect a dropped record) for every
  dispatched `tools/call`. `events.fail_closed` names event types that
  must never be silently dropped; when `mcp_governance_decision` is
  listed there and the record cannot be queued, the tool call is
  refused with a JSON-RPC internal error rather than served
  un-evidenced, and `sbproxy_mcp_evidence_fail_closed_total{tenant}`
  counts every refusal. Everything else keeps the existing best-effort,
  drop-and-count contract.

- **`mcp_governance_decision` covers tool-definition and registry
  changes, plus an opt-in verbatim-arguments capture.** The
  version-lockfile gate now emits a `tool_definition_changed` record
  (verdict matching the gate's own `mode: block`/`warn` posture, old
  and new contract-digest prefixes, never the contract text) whenever
  a live tool contract moves without a matching declared version bump.
  A federated server's registry approval status transitioning across a
  config reload (`draft`, `approved`, `deprecated`) emits one
  `server_status_changed` record per transition, not one per call.
  New `mcp_audit.capture_arguments` (default `false`) opts a dispatched
  call's record into `gen_ai.tool.call.arguments`: the call's
  arguments, redacted and size-bounded the same way `mcp_audit`'s own
  content fields already are, alongside the salted digest every call
  already carries.

- **Federated MCP servers resist a silent protocol or auth downgrade.**
  `federated_servers[].protocol` pins one upstream to `2025-06-18`
  (the only era outbound federation speaks today; pinning `2026-07-28`
  is a config-compile error until outbound federation speaks it too);
  the default, `auto`, negotiates and remembers, per tenant, the best
  era and strictest auth posture that upstream has ever demonstrated.
  A later contact that looks weaker, a legacy-only answer after
  showing a stronger era, or a successful call needing no credentials
  after having required them (classified from the upstream's real HTTP
  response, a 401/407 for "required" and a clean unauthenticated
  success for "not required"), is a downgrade:
  `federated_servers[].downgrade: warn` (default) logs, counts, and
  emits an `mcp_governance_decision` evidence event with verdict
  `warn`; `block` refuses the call until the operator pins `protocol`
  explicitly or edits that server entry. A refusal emits the same
  event with verdict `deny`, and a `SecurityAuditEntry` policy
  violation; `rule_id` is `peer_downgrade` for an actual downgrade and
  `protocol_pin_mismatch` for a pinned peer answering the wrong era.
  `resources/read` and `prompts/get` reach the same downgrade check for
  the federated peer they contact, alongside `tools/call`.

- **The base MCP connect is gated and inventoried, and federated
  servers get a registry approval status.** `federated_servers[].egress`
  now applies to a plain `type: mcp` server's base connect
  (`streamable_http` or `sse`), not just a `type: openapi` server's REST
  calls; an unconfigured policy is stamped `ungated` rather than
  silently allowed, and every dial's outcome shows up at
  `GET /api/egress` under purpose `mcp_upstream`. A `type: openapi`
  server's egress denial, previously silent, is now recorded there too.
  `federated_servers[].status: draft | approved | deprecated` (absent
  means `approved`, so existing configs are unaffected) stages a
  Draft-to-Approved-to-Deprecated review lifecycle: `draft` hides a
  server's tools from `tools/list` and refuses every call against them,
  naming the status; `deprecated` keeps the server fully callable but
  emits a warn-level `mcp_governance_decision` event on every call.
  Optional `approved_by` / `approved_at` metadata is operator-attested
  and stored, not verified.

- **MCP tool calls can be authorized on their arguments, not just their
  name.** An `mcp` action's `argument_policies[]` evaluates a CEL or
  OPA-compatible Rego expression against the tool-call context
  (`mcp.tool.name`, `mcp.server`, `mcp.session.id`, `mcp.arguments`,
  `mcp.tenant`, `mcp.principal.{sub,team,project,user}`) after RBAC and
  JSON-Schema validation pass and before the call quotas and
  dispatches: a rule can only narrow an already-passed RBAC allow,
  never widen it. `mode: warn` (default) logs and emits a
  `mcp_governance_decision` event with verdict `warn`; `mode: block`
  refuses the call with a JSON-RPC error and verdict `deny`, naming the
  rule as `sbproxy.decision.rule_id`. A rule that cannot be evaluated,
  or whose engine panics, fails closed regardless of `mode`. Optional
  `principals[]` selectors scope a rule to a tenant, team, or project,
  the same shape as the RBAC `tool_access[].principals` rows. Legacy-era
  `tools/call` requests with a compiled contract now also get the
  JSON-Schema check modern-era calls already had.

- **Deterministic session-flow enforcement gates a session that read
  something untrusted and sensitive, then tries to leave (Meta's Rule of
  Two).** An `mcp` action's `flow` block tracks two session-scoped,
  most-restrictive-wins labels that never lower within a session:
  `integrity` (`trusted` -> `tainted`, leg 1) and `sensitive_touched`
  (`false` -> sticky `true`, leg 2). Leg 3 (an externally visible or
  state-changing action) is evaluated fresh at each `tools/call` against
  `flow.outbound_tools`, not stored. A `tools/call` result (or
  `resources/read`) from a server outside `flow.trusted_servers` taints
  the session (unlabeled upstream is untrusted, fail closed); one from a
  server in `flow.sensitive_servers`, or a `tools/call` for a tool
  matching `flow.sensitive_tools`, sets `sensitive_touched` (absent
  sensitivity config reads default-open, unlike `integrity`). The
  default rule, `flow.rule: two_of_three`, is Rule of Two itself: the
  violation is a session with both legs tripped attempting an outbound
  call; the explicit `flow.rule: taint_and_outbound` reproduces a
  strictly stricter pair rule (tainted + outbound, sensitivity not
  considered) for an operator who wants that instead.
  `flow.mode: warn` logs and emits a `mcp_governance_decision` event
  with verdict `warn`; `mode: block` refuses the call before dispatch
  with verdict `deny`; `mode: off` (the default) tracks nothing. Every
  transition and violation carries its own `sbproxy.decision.rule_id`:
  `flow_taint`, `flow_sensitive_touched`, `flow_exfil_block` (the
  default rule), or `flow_pair_block` (the explicit rule). Runs after
  RBAC, per-tool quota, and `argument_policies[]` have already allowed
  the call, and composes with (rather than replaces) `lethal_trifecta`
  and `dual_llm_quarantine`. Without `sessions.enabled: true`, this
  degrades to single-call scope, the same fallback `lethal_trifecta`
  uses. The labels are also exposed on the `mcp` CEL/Rego namespace as
  `mcp.session.integrity` and `mcp.session.sensitive_touched`, so a
  custom `argument_policies[]` rule can compose a policy the two
  built-in rules do not express.

- **A gate refuses Apache-2.0-only crates that NOTICE does not name.**
  `scripts/check-notice.sh` (local `scripts/check.sh` and the CI lint
  job) fails when an Apache-2.0-only dependency is missing a stanza,
  so the next swc-class crate cannot land unattributed.

- **Self-host certification writes a complete `record.json`.** Live Apple
  Metal and GitHub release macos-14 runs emit macOS version, chip, memory,
  engine version, artifact digest, time to ready, and first-token result in
  one file. The Metal probe is compiled by the named `apple_metal_probe`
  lane, and a live launch fails if engine RSS overshoots the planned
  memory envelope by more than 25%.

- **Bundles can make granted outbound HTTP calls.** A JavaScript hook
  may declare `net:outbound=<scheme>://<host>[:port]` destinations in
  its manifest `permissions`, the operator grants them per bundle under
  `extensions.grants`, and a declared destination without a grant
  refuses the candidate at load naming both sets. Granted hooks call
  the synchronous `sbproxy_fetch` host function; every call is
  authorized against the grant, resolution-pinned, redirect-free,
  bounded by the hook's remaining budget, and capped at the sandbox
  buffer limit. The wasm runtimes have no host-call surface and refuse
  declarations at parse.

- **`ai_tool_call` hooks can rewrite tool calls.** A bundle hook
  declaring `execution.mutates: true` on `ai_tool_call` may return a
  `mutate` decision whose rewritten call replaces the held argument
  fragments on the wire as one canonical frame. Rewrites that change
  the call's index, produce non-JSON arguments, or edit a call whose
  arguments were truncated at the stream buffer cap refuse instead of
  shipping approximately. `mutates` combined with
  `enforcement_mode: observe` now refuses at config load, since an
  observe hook's decisions are discarded.

- **`policy: rego` and the AI gateway's Rego routing engine can load a
  module from a file, and accept pre-OPA-1.0 syntax.** `module_path`
  reads a `.rego` file at config-compile time, the same convention
  `transforms[] type: wasm` already uses, and `rego_v0: true` runs
  Regorus's own compatibility switch so a module written before OPA
  1.0's `if`/`contains` requirement parses unchanged. A policy's
  `print()` calls are gathered per evaluation and logged through
  `tracing` at INFO under the `rego_print` target instead of reaching
  the process's stderr.

- **`sbproxy rego test` runs Rego fixtures offline, with line
  coverage.** Point the new subcommand at a fixture YAML file or a
  directory of `*_test.yaml` files and it compiles each module through
  the same engine construction a live policy uses, runs every named
  case, and reports per-module line coverage. `--min-coverage` gates
  the exit code on it, and `--format json` emits a structured result
  for a CI step to parse.

- **Request and response modifiers gained a Rego form.**
  `request_modifiers[]` and `response_modifiers[]` now accept
  `rego_module` / `rego_module_path` beside the existing `lua_script`
  and `js_script`, evaluating `data.sbproxy.modify_request` /
  `modify_response` against the same context document those two
  engines already receive and returning the same `set_headers` shape.
  `rego_budget_ms` bounds the evaluation, matching the `budget_ms`
  knob on `policy: rego`.

- **Signed extension bundles can ship a `.rego` policy module.**
  `runtime: rego` bundle hooks compile at candidate load on the same
  Regorus interpreter `policy: rego` uses, register into the same
  policy registry a config-inline module would, and evaluate the same
  wire-level envelope a JavaScript or WASM policy hook reads. A
  tampered or malformed `.rego` module fails verification like any
  other bundle asset, and the previous bundle keeps serving.

### Changed, and worth checking before you upgrade

- **`proxy.messenger_settings` refuse names the deleted bus defects.** The
  block was already refused. The error now says GCP Pub/Sub and SQS
  acknowledged before yield, treated errors as end-of-stream, and could
  not stop on drop, and that a replacement needs an async Stream with
  cancellation (WOR-2192). Remove the block; config distribution is
  `proxy.config_authority` and cache invalidation is
  `POST /admin/cache/purge`.

- **A broken `ai_policy.expression` now refuses the config instead of
  disabling itself.** A syntax error, or a reference to a binding
  outside the `ai` namespace, previously logged one error and booted
  the proxy with the policy silently absent; it now fails boot and
  reload with a message naming the expression, like every other CEL
  surface. If your config stops loading on upgrade, the expression was
  never running; fix the typo and the policy starts enforcing.
- **The response cache now stores the transform chain's output.** On an
  origin combining `response_cache` with `transforms`, entries hold the
  transformed body, hits serve what misses ship, a closed transform
  refusal blocks admission, and a request-dependent transform on a
  cached origin refuses at config load. All existing response-cache
  entries are retired on upgrade (one cold start per key), so an
  upgraded node can never replay a pre-transform body as a hit.
- **A configured origin now owns `/health` on the data plane.** Until
  now the proxy answered `GET /health` itself with a fixed
  `{"status":"ok"}` before any origin routing ran. It now proxies the
  path like any other when an origin or forward rule matches it. If a
  load balancer probes `/health` **with a configured origin's Host
  header**, that probe now reaches your upstream, and an upstream with
  no `/health` route answers 404, which a health checker reads as
  unhealthy. Point such probes at the admin listener's health route, or
  make sure the upstream serves the path. Probes against the pod IP or
  an unconfigured Host still get the built-in response.
- **`timeout_ms` on an AI provider is now enforced.** The key
  previously validated and did nothing. It bounds one dispatch attempt
  wall-clock from connect through the end of the response body, so a
  streaming completion that runs past it is severed mid-stream; each
  retry attempt gets a fresh window, so worst case is
  `(timeout_ms + backoff) x (max_retries + 1)` per provider. A config
  carrying a forgotten low value starts cutting requests off on
  upgrade: check yours before deploying.
- **The `outcome` label value `auth_denied` split in two.** Gateway-side
  refusals and upstream auth failures were one value and are now
  distinguishable; dashboards keyed on `outcome="auth_denied"` need
  updating. Usage rollups keep the legacy mapping.
- **Single-tenant traffic now reports workspace `__default__`, not
  `default`.** The rate-limit budget enforcer's workspace label on
  `sbproxy_rate_limit_total` and `sbproxy_rate_limit_decisions_total`,
  and the `target_id` on the matching rate-limit audit records, moved
  to the synthetic `__default__` tenant name used elsewhere in the
  multi-tenant work. Budget behavior is unchanged; only the label
  value moved. Dashboards or alerts matching `workspace="default"`
  need updating to `workspace="__default__"`.
- **Meter receipts now fold extra attempts under `billable.retry: collapse`.**
  Provider fallback and HTTP origin retries previously billed only the
  final attempt as `delivered`, so the `retry` outcome never ran. Extra
  attempts are recorded as `retry` and collapse; the receipt that bills
  remains `delivered`. Exhausted retries that still end in 4xx/5xx keep
  those outcomes.
- **The Kubernetes operator image builds inside Docker.**
  `crates/sbproxy-k8s-operator/Dockerfile.ci` compiled on the host and
  copied a `target/` binary that `.dockerignore` excluded (and that was
  the wrong platform on macOS/Windows). The documented
  `docker build -f crates/sbproxy-k8s-operator/Dockerfile.ci .` path now
  compiles in a Linux builder stage.

### Fixed

- **A prefix-namespaced MCP tool call now reaches its upstream.**
  Since the dual-revision release, the federation advertised namespaced
  tool names (`reports.hello`) but also forwarded that advertised name
  on `tools/call`, so an upstream serving the bare name refused every
  dispatch with "Unknown tool". Tools now keep the name the upstream
  advertised, the way prompts and resources always did, and dispatch
  forwards it; the governance-pack e2e's mock upstream now refuses
  prefixed names the way real upstreams do, so this cannot regress
  silently.

- **NOTICE names the 27 Apache-2.0-only crates it previously omitted.**
  Most of them are the swc TypeScript and JavaScript toolchain reached
  through `sbproxy-extension`, plus `unicode-general-category`. Apache
  2.0 section 4(d) requires those stanzas on every redistributed binary.

- **Anthropic multi-tool-call streams now close every content block.**
  The Messages SSE emitter opened a `content_block_start` per tool call
  but always emitted `content_block_stop` at `index: 0`, so a native
  Anthropic client watching a stream with two or more tool calls saw a
  mismatched block lifecycle.
- **Gemini empty generateContent bodies no longer look like successes.**
  A 2xx response with no `candidates` (typically a prompt-level safety
  block carried in `promptFeedback`) was translated into an OpenAI
  completion with empty content and `finish_reason: stop`. Those bodies
  now surface as an error envelope, keep the billed `usage` counts, and
  use the `content_filter` taxonomy when Gemini named a safety block.
  HTTP 4xx/5xx Gemini envelopes were already relayed unchanged.
- **llama.cpp and mistral.rs Model Host provisioning on the official
  Docker image.** Engine release extract shelled out to `tar`, which the
  distroless gateway image does not contain. Archives unpack in-process.
- **Jobs admin table overflow.** A long artifact digest pushed the
  Updated column past the content panel. Shared `.sb-table` styles now
  wrap long cells and the Jobs table scrolls inside the panel.

## [1.11.0] - 2026-08-10

### Added

- **A tamper-evident security audit trail, behind `audit.sink: chain`.**
  The security audit log was a tracing stream and an in-memory ring, which
  means it recorded what the proxy said rather than what happened: whoever
  could write the log file could edit a line, delete one out of the
  middle, and leave nothing behind that said so. Setting `audit.sink:
  chain` with a `path` and a `sign_with` now additionally appends every
  `security_audit` event to a SHA-256 hash-chained, Ed25519-signed file.
  Editing a record breaks its own digest and every link after it; deleting
  one leaves a gap in a contiguous sequence; rewriting the file wholesale
  produces a chain that no longer verifies against the published key.
  `sbproxy audit verify <path> [--signing-seed-hex ...]` re-derives the
  chain from genesis and exits 1 with the first broken record, reading the
  file and nothing else, so an auditor can check a trail the proxy that
  wrote it no longer has.

  None of this is new cryptography. It is the hash chain that already
  carried metering receipts and LLM spend, bound to a third payload; the
  signing identity is the proxy's existing `proxy.web_bot_auth` keypair,
  the same one `proxy.attestation.sign_with` names, so a deployment that
  already publishes that key does not acquire a second key-distribution
  problem by turning this on. The chained record is byte-for-byte the
  record the `security_audit` tracing target already ships, so a SIEM's
  copy and the chain's copy cannot disagree.

  A chain that will not open fails the boot rather than degrading, which
  is the opposite of what the metering chain does with an unopenable
  ledger and deliberately so: billing can be reconciled after the fact and
  an audit hole cannot. `config_audit`, `key_audit`, and the admin-action
  ring are not chained yet.

- **Trace spans on the ordinary proxied request, not only on the AI
  gateway.** A plain proxied HTTP request produced no span at all: it went
  through origin resolution, an auth provider, an enforcer chain, an
  upstream call, and a transform chain, and the only ways to see where the
  time went were a metric with no per-request identity and an access-log
  line with no phase breakdown. Meanwhile three of the
  `sbproxy.<pillar>.<verb>` names had been published as the span-naming
  convention for long enough that operators had built trace queries on
  them, and nothing emitted any of them. Four spans now cover the request:
  `sbproxy.intake.accept` over the whole inbound phase and parent of the
  rest, `sbproxy.intake.authenticate` per authentication check,
  `sbproxy.policy.enforce` per enforcer, and `sbproxy.transform.shape` per
  response-body transform. Their attributes are the HTTP method, the auth
  provider type, the policy type, and the transform type, all of which are
  already bounded metric labels; nothing caller-supplied and no part of the
  request target rides along. The upstream connect and send, and the
  response header filter, still have no span, because the pillar
  vocabulary names neither phase.

- **A top-level `request_events:` block, so the request events the proxy
  already builds can leave the process.** Every terminating request was
  populating a full event envelope (tenant, session, credential id,
  provider, model, token counts, cost, guardrail verdict, status, geo)
  and then handing it to an implicit no-op, because nothing in the boot
  path ever registered a sink. Three kinds ship: `none` (the default,
  and the behavior every earlier build had), `logging` (one JSON line
  per event on the `request_event` tracing target), and `file` (NDJSON
  appended to `path`). The file sink writes on its own thread behind a
  bounded queue, so a slow disk cannot add latency to the request that
  produced the event; a full queue discards the incoming event and
  increments
  `sbproxy_telemetry_dropped_total{kind="request_event",reason="queue_full"}`
  rather than losing it quietly. A `file` sink with a missing or
  unopenable `path` warns at startup and falls back to `logging`.

- **A ratchet on `.unwrap()`, `.expect(..)`, and `panic!` in production
  code.** Each ends the process on a path a caller cannot catch, which in a
  proxy means a dropped request rather than an error a client can act on. The
  count is allowed to fall and never to rise, so existing sites can be cleaned
  up opportunistically while no new ones land. `panic!` is tracked separately
  with a baseline of zero, since production code has none today and that is
  worth locking rather than trading against an unwrap someone removed.

- **Extension bundle manifests can declare `secret_vars` and
  `masked_vars` on a hook.** A `secret_vars` property is resolved
  through the same secret reference forms (`${VAR}`, `env:NAME`,
  `file:`, or a provider URI) any other secret-bearing field accepts,
  once, when the bundle candidate loads; a `masked_vars` property is
  never resolved but is still kept out of logs, errors, and
  diagnostics. Neither list can name a property `config_schema` does
  not declare, and a property cannot appear in both. Masked values
  render with their length and an HKDF-derived fingerprint rather than
  a bare placeholder, so an operator can tell two values apart without
  the value ever being logged.

- **`env:NAME` now resolves through the same secret resolver as every
  other secret-bearing field.** Three call sites (JWKS auth, a vault
  backend, and one CEL helper) hand-rolled their own `env:NAME` parsing
  outside `SecretResolver::resolve()`, so a field that accepted
  `${VAR}`, `file:`, and seven provider URIs still refused the bare
  `env:NAME` spelling everywhere else. It now resolves identically
  wherever any other secret reference does, with the same
  missing-variable error.

- **`localsecret://` replaces the overloaded `secret://` scheme name.**
  `secret://` reads as "any secret" but has only ever named one
  specific backend, the local-secret provider, which is exactly the
  kind of mismatch that led one deployment to misread
  `secret://env/NAME` as an env-variable alias. `secret://` keeps
  working, with a once-per-process deprecation warning identical to the
  existing `vault://<alias>` mechanism. The scheme-validation table in
  `sbproxy-config` also gains an entry for it; previously it wasn't
  recognized there at all and silently skipped validation against
  `proxy.secrets.backends`.

- **Forward rules can match on a field inside the JSON request body.**
  A rule now accepts an RFC 6901 JSON Pointer matcher, ANDed with the
  existing path, header, and query matchers. The motivating case is AI
  traffic, where the model name lives in the body on OpenAI, Anthropic,
  and Bedrock shapes: routing different models to different origins
  used to mean cramming everything into one `ai_proxy` action sharing
  one auth config, one policy chain, and one transform set. The cost is
  opt-in: an origin with no body matcher never buffers a body for this
  purpose, and a body that's too large or not JSON just falls through
  to header-only matching instead of failing the request.

- **`origins.*.timeouts` makes the five upstream deadlines configurable
  per origin.** Connect (5s), total-connect (10s), read/write (30s),
  and idle (90s) were hardcoded with no config path at all. They're now
  set via `connect_ms`, `total_connect_ms`, `read_ms`, `write_ms`, and
  `idle_ms`, resolved at config compile; a zero value is refused. The
  legacy, previously inert `connection_pool.idle_timeout_secs` now
  feeds the same resolved idle timeout and is promoted from
  config-only to stable, and authoring both spellings on one origin is
  a compile error. A forward rule's inline origin inherits its
  parent's timeouts.

- **The configured A2A agent card is now served at its well-known
  path.** `agent_card` has been storable on the `a2a` action, but
  nothing served it: a request to `/.well-known/agent-card.json` just
  proxied through like any other path. It's now served pre-auth
  (matching sbproxy's other discovery surfaces), GET-only, at the
  ratified A2A 1.0 path plus two legacy aliases. The card is validated
  as a typed `AgentCard` at config compile, so a malformed card is a
  boot error rather than a runtime surprise, and its URLs are rewritten
  to advertise the proxy host through the same mechanism the
  `a2a_agent_card_rewrite` transform uses.

- **Forward rules can match on HTTP method.** A rule that should route
  `POST /webhook` differently from `GET /webhook` had no way to say so.
  A `method:` field, single value or list, is normalized to uppercase
  and validated against `http::Method`, and it's evaluated first in the
  rule's match chain since it's the cheapest, non-capturing test to run
  before path, header, and body predicates.

- **Origin hostnames can start with `*.` for wildcard routing.**
  Hostnames could previously only match exactly, so a per-subdomain
  product (`*.tenant.example.com`) needed one origin block per literal
  hostname actually in use. A wildcard origin key now matches on the
  longest matching suffix after an exact match fails, Envoy-style,
  across both the request-path router and the admin snapshot lookup.
  Configs with no wildcards keep the existing bloom-filter fast-reject
  path unchanged, so this costs nothing for anyone not using it. Docs
  that already (incorrectly) claimed one-level wildcard support now
  match the code.

- **`sbproxy ai ledger report` reads the AI value ledger offline.** The
  local-versus-cloud spend and savings ledger was only queryable
  through the admin HTTP endpoint, and the docs had long promised a CLI
  subcommand that was never built (and has since been retracted from
  the docs it was promised in). The new subcommand reads the redb
  ledger file directly, the same pattern `ai ledger verify` already
  uses, and prints the identical report as text or JSON, with the JSON
  matching the admin endpoint's schema byte for byte. Useful for
  scripting, air-gapped nodes, or CI cost reporting where hitting the
  admin API isn't an option.

- **`algorithm: ring_hash` adds consistent hashing to the load
  balancer.** The existing hash-based algorithms used a plain modulus
  over the target list, so any pool resize, a scale-up, a scale-down,
  an unhealthy target dropping out, reshuffled most keys' target
  assignment and defeated session or cache affinity at exactly the
  moment it mattered. `ring_hash` implements ketama-style consistent
  hashing (160 virtual nodes per target by weight, FNV-1a plus a
  splitmix64 finisher), so only the keys owned by a target that joins
  or leaves the pool actually move. Health is applied at lookup time by
  walking the ring, so an unhealthy target doesn't require rebuilding
  it. The `sticky:` block, which parsed and produced a boot warning but
  never issued an affinity cookie, is now a hard config-compile refusal
  that points at `ring_hash` instead, and a dead `ConsistentHash`
  scaffold built on a non-deterministic per-process hasher, which would
  have disagreed across replicas had it ever been wired up, is deleted.

- **An `examples/admin-mcp` reference config lets an agent client
  manage a running proxy over MCP.** No MCP server exposed SBproxy's
  own admin API before this, so Claude Code, Cursor, or any other MCP
  client couldn't manage a proxy the way it could manage other
  infrastructure. It reuses the existing OpenAPI-to-MCP-tools converter
  against a curated, hand-written admin API spec (the live
  `/api/openapi.json` only describes the data plane, so no generated
  admin spec exists to point at). `openapi` federated MCP servers also
  gain a static `headers:` map for service credentials like HTTP Basic,
  since outbound MCP auth previously only supported per-caller
  run-as-user Bearer tokens and failed closed for anonymous callers; a
  minted per-call header always wins over the static one, so
  run-as-user auth can't be shadowed by it. `headers:` on a
  non-openapi server, or combined with `run_as_user_auth`, is a config
  error. The shipped example's tool surface is read-only by default,
  held there by three independent gates (the curated spec, RBAC, and
  `tool_allowlist`), so exposing any mutating admin action takes
  deliberately editing at least two of them.

- **The MCP gateway federates `prompts/list` and `prompts/get`.** Both
  previously returned JSON-RPC `-32601`, method not found, for every
  caller, so an agent client built around MCP prompts rather than tools
  got nothing through the gateway even when the upstream server it
  wanted supported them. They now federate the same way `tools/list`
  and `tools/call` already do: aggregated across upstream servers under
  the existing name-prefixing scheme, and routed back to the owning
  server by namespaced name. The `prompts` capability is only
  advertised in `initialize` when at least one upstream actually
  declares it, and access follows the server's existing
  `rbac_policies` entry rather than a new config key. Five other
  unimplemented MCP methods are unchanged and still return `-32601`.

- **`model_aliases` now actually does something.** The config key
  parsed and was silently ignored, since `ConfigFile` has no
  `deny_unknown_fields` to catch it, and the documented workaround,
  per-provider `model_map`, doesn't cover the same case: `map_model`
  only runs after a provider is already chosen, so it can rename a
  model on the way out but has no say in which provider gets picked,
  which is non-deterministic under round-robin routing. Aliases now
  resolve before provider selection on all three AI dispatch paths,
  with an optional provider pin that narrows candidates rather than
  falling through to a provider that can't serve the aliased model.
  Config load rejects an alias that shadows a served model, a
  `model_map` key, or the default model, plus duplicate aliases,
  self-reference, alias chains, and a pin at a provider that can't
  serve the target. A second bug closed in the same change: on the
  non-POST dispatch path, credential-level model gates were checked
  against the pre-alias name, so an alias could previously be used to
  reach a model a credential's block list was supposed to forbid.
  That's now closed and pinned by a regression test.

- **`digest_scope: bundle_v1` covers a whole extension bundle, not just
  its entry file.** An extension bundle's `sha256` previously covered
  only the JS or WASM entry artifact; `bundle.yaml`, which declares
  hook kinds, sandbox limits, `failure_posture`, and `permissions`, sat
  outside the digest and could be widened (`permissions: []` and
  beyond) without breaking verification. Under `bundle_v1`, the digest
  is computed over a sorted, path-plus-content-hash index of every
  regular file in the bundle directory, including `bundle.yaml` itself
  with its own `sha256:` line stripped first. Symlinks, non-UTF-8 or
  control-character filenames, and oversized bundles are refused
  outright. `digest_scope: entry`, the old whole-entry-file behavior,
  stays the default, so existing bundles load unchanged.
  `scripts/bundle-digest.sh` computes a `bundle_v1` digest for bundle
  authors.

- **The Kubernetes Gateway API controller ships in OSS for the first
  time.** It watches `Gateway`, `HTTPRoute`, and `GRPCRoute` resources
  and renders an `sb.yml` from them, in a new `sbproxy-k8s-controller`
  crate (`deploy/k8s/gateway-controller/`, `docs/gateway-api.md`). It
  also fixes a real bug carried over from the closed-source tree it's
  ported from: the generator emitted forward rules using a `path`
  field the config schema doesn't accept, so any `HTTPRoute` with a
  non-root `PathPrefix` produced a document sbproxy couldn't parse, and
  the data plane kept serving stale config while the controller logged
  success. Enterprise-only pieces, a non-Gateway-API custom CRD and a
  `bincode` dependency banned under RUSTSEC-2025-0141, were dropped
  rather than ported. Generated output is now deterministic, sorted,
  where it previously churned on hash-iteration order.

- **Seven more outbound helper call sites inject W3C trace context.**
  Only one of 49 production files making outbound HTTP calls injected
  `traceparent`, and the docs' own list of exceptions was wrong in both
  directions and missed the request mirror, webhooks, JWKS, and forward
  auth entirely. Ledger redeem, the Web Bot Auth directory fetch,
  webhooks, OAuth and OIDC token exchange, and forward auth now inject
  it too, with the trace context threaded explicitly through the
  `tokio::spawn` boundaries that would otherwise drop the ambient span.
  Two duplicate-header bugs came out of the same pass: the request
  mirror and forward auth were both copying the inbound `traceparent`
  verbatim, which would have put two headers on the wire the moment
  injection was added on top. Coverage across all outbound call sites
  is now enforced by a build-time guard.

- **RFC 9421 message-signature verification adds ECDSA-P256 and can now
  actually check a covered body.** Inbound signature verification only
  recognized `hmac-sha256` and `ed25519`; `ecdsa-p256-sha256` (RFC 9421
  section 3.3.5) is now supported too, through `ring`, so a caller or
  partner signing with ECDSA-P256 is no longer refused outright.
  Separately, and more seriously: a signature claiming to cover
  `content-digest` could never actually be checked against the body,
  because the verifier was always invoked with an empty body regardless
  of what the signature claimed to cover. It's now an explicit, typed
  decision through a new `BodyBinding` enum: `Enforce` checks a covered
  `content-digest` against the real bytes and fails the signature on a
  mismatch, `Defer` is for the one call site that verifies headers
  during auth and completes the body check later in the body filter,
  and a caller that claims body coverage with no body available is
  refused rather than marked verified. Before this fix, a forged or
  tampered body could pass signature verification whenever the
  signature covered the digest, because the digest itself was never
  checked.

### Changed

- **A payment stuck in reconciliation now withholds fresh 402 challenges
  from the payer it belongs to instead of from every payer of the route.**
  The guard that stops a second bill for content whose first payment may
  already have moved money was keyed on `(tenant, origin, route)` alone,
  because no column in the settlement store said anything about who was
  paying. One stranded payer therefore took a route's revenue to zero for
  everybody, and on x402 there is no status query to end it, so a
  facilitator outage could hold a hot route at 503 for its whole duration.
  Settlement intents now carry a payer scope key, and the guard matches on
  it. The key is a salted HKDF derivation, under its own purpose, of the
  caller identity the request already proved: an authenticated inbound key,
  or an agent identity from a verified Web Bot Auth `keyid` or a
  forward-confirmed reverse DNS match. A `User-Agent` match and the client
  IP are both excluded, the first because any client can assert one and the
  second because egress pools and NAT make it neither stable nor unique.
  The key never leaves the settlement database: it is not a metric label,
  not a log or tracing field, and not part of any response. Intents written
  by earlier builds carry no scope key and keep withholding route-wide, as
  does any intent minted for a caller this proxy could not identify, so an
  upgrade in flight cannot turn one of them into a double charge.

- **Boot and every SIGHUP reload now warn when `key_management.inbound.provider_hints`
  recognizes a native provider credential that no `inbound.native_key_policy`
  admits.** `provider_hints` ships non-empty by default and
  `native_key_policy` defaults to absent, so simply enabling
  `key_management` was enough to silently refuse every native provider key
  with a 403, with nothing at boot or in `sbproxy validate` to say so. The
  new WARN names the recognized providers so the gap is visible before a
  caller hits it.

- **`compression.level` is applied to the response encoders instead of being
  parsed and dropped.** The configured value is clamped into whichever
  algorithm the client negotiates (gzip 0-9, brotli 0-11, zstd 1-22), so one
  number stays meaningful across the three codecs. Leaving it unset keeps the
  previous behavior exactly: gzip and zstd library defaults, brotli
  quality 4.

- **`response_modifiers[].status.text` is emitted as the reason phrase on the
  HTTP/1.x status line instead of being parsed and dropped.** A modifier
  that sets `status: { code: 418, text: "I am a teapot" }` now puts that
  phrase on the wire for proxied, static, and plugin-action responses.
  HTTP/2 has no reason phrase on the wire, so the value is ignored there,
  and a `status` block without a `text` keeps the canonical phrase for its
  code.

- **Config compile now warns when `invalidate_on_mutation` is combined with
  the `file` or `memcached` response-cache store.** Both backends hash their
  cache keys, so the prefix scan behind mutation-driven invalidation has
  nothing to walk: a POST or DELETE evicted nothing and entries only fell
  out by TTL, silently. The warning names each affected origin and points at
  the `memory` and `redis` backends, which can purge by prefix, and at
  `invalidate_on_mutation: false` for deployments that accept TTL-based
  expiry.

- **`proxy.scripting.javascript.sandbox` now tunes the live QuickJS
  engines.** The block parsed and nothing read it, so every JavaScript
  surface ran the built-in 100 ms budget, 16 MiB heap cap, and 1 MiB stack
  cap however the operator authored it. It installs into a process-wide
  handle at boot now, the same mechanism the Lua half has used since the
  block was introduced, and refreshes on SIGHUP, admin reload, and the
  filesystem watcher. Every JavaScript engine is built per invocation, so a
  reload reaches the next script with no restart. The limits apply to
  response modifiers, `javascript` and `js_json` transforms, WAF custom
  rules, MCP adapters, and `engine: js` custom log fields alike.

- **`key_management.crypto.pepper`/`master_key` and
  `cluster.security.shared_key` can now resolve through any configured
  secrets backend.** These fields previously accepted `env:NAME`,
  `file:PATH`, or an inline literal, but refused a provider-URI
  reference like `vault://` or `awssm://` even when a secrets backend
  was already configured for everything else. They now delegate to the
  installed process resolver when one exists, so the crypto pepper,
  master key, and cluster shared key can come from any backend the rest
  of the config uses, not just env or file. MCP run-as-user credential
  lookups gain the same resolver support, keeping the existing
  bare-variable-name shorthand. `validate_shared_key_reference` also
  stops silently under-validating: it previously only recognized
  `vault://` by name and let the other six provider schemes fall
  through to a length check as if they were inline entropy. The runtime
  path already caught a bad value here, so this closes a validate-time
  message gap rather than a live bypass.

- **cert-manager is now the recommended path for TLS on Kubernetes, and
  the operator refuses the configurations that can't work.** Reconcile
  previously rolled out a multi-replica deployment with
  `proxy.acme.enabled: true` on a pod-local cert store without
  complaint, which doesn't work: every replica opens its own ACME order
  for the same hostname, risking Let's Encrypt's five-per-week
  duplicate-certificate limit, and a load-balanced HTTP-01 challenge
  fetch often lands on a replica that never opened the order. Reconcile
  now refuses that combination outright when `spec.replicas > 1` and
  ACME is enabled on a pod-local backend (`file`-backed and remote
  backends are unaffected), recording the error on `status.lastError`
  and requeuing rather than rolling out. The docs now lead with
  cert-manager plus Ingress-terminated TLS as the recommended
  Kubernetes path, with worked examples.

### Removed

- **Five config keys that parsed, warned, and governed nothing.**
  `origins.*.connection_pool.max_connections`,
  `origins.*.connection_pool.max_lifetime_secs`,
  `origins.*.traffic_capture`, `origins.*.sessions.ttl_seconds`, and
  `proxy.device_parser_file` were all accepted with a boot warning and
  then ignored for the life of the process. Each now fails config compile
  with a message naming the surface that does the job.

  The warning was the wrong response for these. It fits a key whose
  behavior is narrower than its name suggests, which is why
  `cors.enable` still gets one. Four of these five name a resource limit
  or a retention window, so a config that set one kept claiming a
  property the proxy did not have, and nobody rereads a boot log from
  three months ago.

  None of them was waiting on plumbing. The two pool limits have no
  primitive behind them: the upstream keepalive pool is sized once per
  connector rather than per origin, so `max_connections` had nowhere to
  go, and the pool has no age-based eviction at all, so
  `max_lifetime_secs` never retired anything. `traffic_capture` was
  accepted as a free-form value, so nothing read it and nothing
  validated it either. `sessions.ttl_seconds` described the retention of
  an index that does not exist; sessions age out of the admin
  recent-request ring on entry count. `proxy.device_parser_file` named a
  file no code path opens.

  Migration, in order: a `concurrent_limit` policy for
  `max_connections`, `timeouts.idle_ms` for `max_lifetime_secs`,
  `mirror` for `traffic_capture`, `sessions.budget` for
  `sessions.ttl_seconds`, and nothing for `device_parser_file`. Each key
  still parses, so the failure is an explanatory diagnostic rather than
  an unknown-key error.

  `origins.*.connection_pool.idle_timeout_secs` is unaffected. It is the
  legacy spelling of `timeouts.idle_ms` and is live.

- **`audit.sink: tracing`.** It never selected anything. Emission to the
  `config_audit`, `security_audit`, and `key_audit` targets has always been
  unconditional, so `tracing` and `memory` described the same proxy, and
  the key was documented as compatibility-only for exactly that reason.
  Now that `audit.sink` does select something, a value that selects nothing
  is the failure the rest of this entry is about. A config that still names
  it fails config compile with a message pointing at `memory` for the same
  behavior under an honest name, or `chain` for a trail that survives a
  restart. `audit.path` or `audit.sign_with` under any sink other than
  `chain` is refused on the same grounds: a path nothing writes to looks
  configured and is not.

- **The origin-level `rate_limit_headers:` block.** It parsed but was never
  consumed: `X-RateLimit-*` and `Retry-After` are emitted by the
  rate-limiting policy's own `headers` block, and were even while the
  origin-level key was accepted. A config that still carries the block now
  fails config compile with a pointer at the policy-level configuration
  instead of silently doing nothing.

- **`allowed_hosts:` on the `wasm` transform.** It parsed and was never
  enforced, and it could not have been: a module gets no sockets here at
  all, neither WASI networking nor a host callout function, so the
  allowlist named a boundary nothing checked. That is the worst shape a
  security key can have, because an operator who writes one believes the
  boundary exists. An authored key now fails config compile with an error
  saying so and pointing at the proxy-side alternatives. If host callouts
  ever land, the key returns as an enforced one that fails closed from its
  first day rather than an inert one already in circulation.

- **`on_request:` on the `cel` transform.** It was compiled at config load
  and then never evaluated, because there is nowhere for it to run:
  transforms in SBproxy are response-side, driven off the response body
  buffer. Accepting it read as a broken request-phase feature rather than
  an absent one. An authored key now fails config compile and names the CEL
  surfaces that do run at request time: an `expression` policy to gate the
  request, a rate-limit or WAF `key:` expression to key on it, or a forward
  rule to route on it.

- **The AI gateway's context-overflow decision layer, and the
  `context_overflow:` block the docs said it read.** The block was never a
  field on the AI handler, and the code behind it, a pair of functions
  returning an action of error, fall back to a larger model, or truncate,
  was never called from anywhere. The AI gateway guide described the key as
  parsed and ignored, which is an invitation to write it and wait. None of
  the three actions was worth wiring as written. Truncating an oversized
  prompt is the `window_fit` compression lever, which ships; the deleted
  code only named truncation as a recommendation and never trimmed a
  message. Erroring took an estimated token count as its input, so a prompt
  the provider would have accepted could be refused before it was ever sent.
  Rerouting to a model with a larger window needs a config surface nobody
  designed, since no key names the model to reroute to. An authored
  `context_overflow:` now fails config compile with an error naming the
  compression settings that do fit a prompt to the window. The window
  registry the module also held is untouched and still live: compression
  reads it to size a model's budget, and it now sits in `context_window`, a
  file named for the one thing left in it.

### Fixed

- **`proxy.observability.log.level` and `.format` now reach the process
  logger.** Both parsed, both validated, and neither was ever installed: the
  binary resolved the startup filter from `--log-level`, `SB_LOG_LEVEL`, and
  `RUST_LOG` and never opened the config file for it, so an operator who
  wrote `level: debug` in `sb.yml` got `info` with nothing anywhere saying
  why. They are now the rank below `RUST_LOG` in one documented order: the
  flag wins, then the environment variable, then YAML, then the built-in
  `info` and `compact`. A deployment that exports `RUST_LOG` today resolves
  to exactly what it resolved to before, and that override is pinned for the
  life of the process so a later config reload cannot demote it.

  `level` also picks up a config reload, through the same handle
  `PUT /admin/log-level` uses, so SIGHUP applies an edited filter without a
  restart. `format` does not and cannot: the output layer is built once at
  startup and only the filter sits behind a reload handle. Changing it still
  needs a restart, and an unrecognized value is now named on stderr and
  falls back to `compact` rather than being silently accepted. The
  precedence table, the reload split, and the admin-API interaction are in
  `docs/observability.md`.

  `proxy.observability.log.sampling` is not fixed and is now described
  accurately. Its note used to say the process logger runs fixed sampling
  defaults, which reads as though some rate applies. None does: the emitter
  has no sampling call site at all, so every level ships at 100% whatever
  the three rates are set to. Throttling request logs is
  `access_log.sample_rate`, which is a different key with a live consumer.
- **OCSP stapling asks the responder a real question, so it can work at all.**
  Refusing to staple a `malformedRequest` stopped the proxy sending bytes no
  client could verify, and it left stapling inactive rather than active and
  wrong: the fetch still built no OCSP request, so there was nothing a
  responder could usefully answer. It now sends the request RFC 6960 defines,
  a POST of `application/ocsp-request` carrying a `CertID` that names the
  certificate by its serial number and by hashes of its issuer's name and
  public key. The issuer is read out of `tls_cert_file`, matched by
  comparing the leaf's issuer name against each certificate's subject name
  rather than by position, so a chain written in an unusual order still
  produces the right question and a file holding only the leaf is refused
  with a message that says to configure the full chain.

  Two checks came with it, both of which a fetch can pass without and both
  of which decide whether the answer means anything. The HTTP status is
  checked before the body is read, because `reqwest` reports a 4xx as a
  completed transfer and an error page otherwise arrives as bytes like any
  other. And the `CertID` on the response is matched against the one that
  was sent, so a responder, or anything on the plaintext hop to it, cannot
  answer `good` about a different certificate and have that stapled to
  every handshake. Both refusals count as
  `sbproxy_ocsp_fetch_total{result="unknown_status"}`.

  The responder's own signature is still not verified. A client that reads
  the staple verifies it against the issuer itself, so a forged response
  cannot make a revoked certificate look good; what it can do is cost
  connections to clients that check. Stapling still covers the manual
  fallback certificate only.

- **A stapled OCSP response that no client could verify is no longer sent.**
  The fetch never built an OCSP request. It issued a plain GET against the
  responder URL in the certificate's Authority Information Access
  extension, and a responder told nothing about a certificate cannot answer
  for one, so it replied with `malformedRequest` or an HTTP error page.
  `reqwest` reports a 4xx as a completed transfer, so those bytes were
  cached and attached to the fallback certificate, and every handshake
  carried them. A client that checks the staple rejects a perfectly valid
  certificate on that basis, on every connection rather than
  intermittently, which is a worse outcome than sending no staple. A fetch
  now counts as successful only when what came back parses as a successful
  basic OCSP response per RFC 6960; anything else is refused and counted as
  `sbproxy_ocsp_fetch_total{result="unknown_status"}`, a label
  `docs/observability.md` already documented and nothing emitted.

- **The startup log now says which certificates OCSP stapling reaches.**
  Stapling covers the manual fallback certificate loaded from
  `tls_cert_file` and nothing else: the refresh task does not start without
  that file pair, and its update path writes the fallback slot rather than
  the SNI map every ACME-issued certificate lives in. Neither condition
  produced an error or a warning, so an operator who enabled HTTPS and read
  a clean log had no way to distinguish a stapled deployment from an
  unstapled one before a TLS scanner said so. Both paths through the boot
  hook now log `served`, `stapled`, and `covered`, and name the boundary.
  `docs/manual.md` section 7 documents it.

- **The in-process burn-rate rule now reads the hour it is named for, and
  reads only that hour.** The evaluator published three availability
  objectives, `-1H`, `-6H`, and `-24H`, and not one of them computed the
  window its name claimed. `-1H` had no window at all: it summed every
  sample in the ring, so it widened with process uptime until, against a
  full 1,440-minute ring, it returned the identical number as `-24H`. `-6H`
  was gated on 60 samples and read a 30-minute tail, so its name, its gate,
  and its window were three different durations. Only `-24H` was honest.

  In practice that meant a proxy that had been up for a day would page on an
  outage that ended hours ago while the hour actually in front of it was
  clean, and would stay quiet through a 20x burn in the last hour because
  the clean day behind it averaged the number down to under 1x.

  All three collapsed into one alert with one severity and one deduplication
  key, so they were never three paging decisions. There is one objective
  now: `SBPROXY-SUBSTRATE-AVAIL-INBOUND-1H`, the last 60 minutes at 14.4x,
  which is the window the rule's existing 60-sample floor fills exactly. The
  6x-over-6h and 3x-over-24h tiers are Prometheus rules in
  `deploy/alerts/alerting-rules.yml` and are not evaluated in process at
  all; both need history that outlives the process, and a 24-hour window
  read from a ring that empties on restart reports healthy for a full day
  every time the proxy comes back.

  What changes for an operator: a slow burn under 14.4x over the last hour
  no longer opens an in-process incident, and if you were paging off this
  rule rather than off Prometheus, that coverage has to come from
  `alerting-rules.yml`. A fast burn confined to the last hour now opens one
  that did not open before. Recovery takes a full window, because the
  failing minutes have to leave the hour rather than merely stop arriving.
  The alert's labels are now `scope`, `objective`, and `window` in place of
  `scope` and a joined `objectives` list, which changes the PagerDuty
  deduplication key: an incident open across the upgrade will not be closed
  by the new build's resolve event. The new key is at least stable, which
  the old one was not, since its value moved with the set of tiers firing.

- **A secret reference in `message_signatures.key` is now resolved instead
  of being used as the key itself.** Writing `key: vault://prod/signing-key`
  or `key: env:SIGNING_KEY` on an origin left the reference text standing in
  for the RFC 9421 signing key. The HMAC shared secret became the reference
  string itself, identical on every deployment that pasted the same line, so
  anyone who read the config could forge a signature the proxy accepted. The
  field now resolves through the same secret resolver every other
  secret-bearing field uses, and it resolves before the value is decoded, so
  a stored secret yields the same key bytes as that value written inline. A
  reference no declared backend can resolve fails the verifier build, and the
  origin then rejects every request with a 401. Inline keys behave exactly as
  before, and the `${VAR}` form was never affected, because config
  interpolation replaced it before this code ran.

- **A plain "not paid yet" read from a Lightning invoice no longer
  poisons the settlement intent.** The CLN/LND invoice-status check ran
  inside the same write gate as a real provider write, and since only
  `ProviderRejected` is on the authoritative-negative allowlist, an
  unpaid-but-not-rejected read resolved to `Ambiguous` and stamped the
  intent `NeedsReconciliation`, unreachable by the request path until a
  background worker swept it later. The status read now runs in the
  read-only query gate; only paid, expired, or unparseable outcomes
  touch the write gate. A client retrying against a still-unpaid
  invoice now gets a normal `RetryWait` and settles on the next request
  once it's actually paid, instead of waiting on the reconciliation
  worker.

- **An `ai_proxy` origin's `credentials:` block now does something even
  without `action.require_governed_key: true` set alongside it.**
  Before this fix, `credentials:` on its own enforced nothing:
  `/v1/chat/completions` accepted any Bearer token, or none, and
  dispatched to the real upstream regardless. Eight of the nine shipped
  examples, including the flagship `ai-virtual-keys` example, shipped
  this exact vulnerable shape. Config compile now fails loud when
  `credentials:` is present without `require_governed_key: true`,
  naming the origin and pointing at
  `docs/migration-credentials.md`, rather than silently turning the
  flag on and flipping an already-compiling, already-vulnerable config
  into one that starts rejecting traffic with no compile-time signal
  that anything changed. All eight examples and six e2e fixtures
  carrying the vulnerable shape were fixed in the same change.

- **The `a2a_agent_card_rewrite` transform now actually runs.** It was
  fully implemented, but `apply()` was a deliberate no-op with no call
  site, so a configured rewrite silently passed agent-card response
  bodies through unchanged. A client reading an unrewritten card
  learned the real upstream URL and could call it directly on later
  requests, going around the proxy entirely. It's now wired into
  `apply_transform_with_ctx`, covering both upstream-proxied and
  static-action agent cards, with a new `RequestContext::request_path`
  field feeding it: a configured `proxy_host` wins, and the inbound
  `Host` header is the fallback.

- **`require_mtls_bound: true` no longer rejects every request in
  production.** The RFC 8705 verifier itself was correct, but the
  production auth path hardcoded `None` for the client certificate's
  thumbprint; only test code ever passed a real one. Any origin
  actually enabling `require_mtls_bound` was rejecting all of its
  traffic. `request_filter` now derives the real `x5t#S256` thumbprint
  from the session's TLS digest and passes it through. A plaintext
  connection or a handshake with no client certificate still correctly
  yields `None`, so a bound token still fails closed there, and origins
  that don't use `require_mtls_bound` are unaffected.

- **`GET /admin/config` and `GET /admin/config/effective` no longer
  return inlined secrets in plaintext.** Both endpoints returned the
  raw or merged config verbatim, so a read-only admin credential could
  read back any secret written inline into the config. Both now pass
  through the same `redact_secrets` the log pipeline already uses. One
  side effect worth knowing about: a config with an inlined secret can
  no longer be round-tripped through a GET, edit, PUT cycle, since PUT
  now rejects the redacted placeholder with a 400. Moving those values
  to an `env:` or secrets-backend reference restores the round trip,
  which was already the documented way to hold a secret in config.

- **Four fixes from a security inventory of the auth path.** The JWKS
  unknown-`kid` refresh built a blocking `reqwest` client inside an
  async call chain, which could stall a Tokio worker for up to ten
  seconds against a slow identity provider; it's now async end to end,
  with the blocking variant kept only for the one caller that genuinely
  needs `spawn_blocking`. Seven hand-rolled constant-time comparators,
  not the two originally scoped, now delegate to
  `subtle::ConstantTimeEq`, closing a timing side-channel; two vault
  comparators are deliberately left as they were, since they need
  length-padding that `subtle`'s slice implementation short-circuits. A
  malformed CIDR in `parse_cidrs` now fails config compile instead of
  warning and dropping the entry, so a typo can no longer silently
  narrow a deny list. Two misleading code comments were also corrected.

- **A federated MCP server with no `rbac:` label of its own no longer
  defaults to allowing every tool on it.** A server declared under
  `federated_servers` with `rbac_policies` configured elsewhere in the
  config, but no `rbac:` label pointing at one of them, was treated as
  allow-all at all four dispatch sites, which quietly undoes
  default-deny for exactly the upstream an operator forgot to label.
  Config compile now rejects that combination outright, naming the
  offending server. An operator who genuinely wants allow-all for a
  server sets `rbac:` pointing at a policy with `default_allow: true`,
  an explicit choice instead of a silent default. Servers with no
  `rbac_policies` configured anywhere are unaffected. The dead
  `rest_to_mcp.rs` stub, a REST-execution path with zero call sites, is
  deleted in the same change.

- **`agent_budget`'s `tokens_per_hour` limit is now actually
  enforced.** The policy's request-rate half worked; the token half
  didn't, because `consume_tokens` had zero call sites.
  `tokens_per_hour` was checked for pre-flight headroom, so a 429 could
  still fire against a budget that had never once been decremented, but
  nothing ever charged usage after a response completed. Completion now
  charges the per-agent token sink at two points, the logging phase for
  buffered responses and end-of-stream aggregation for streamed ones,
  draining exactly once so neither seam double-counts. The streaming
  path previously never stamped `ctx.ai_tokens_*` at all, despite a
  comment claiming it did, so fixing only the logging phase would have
  silently missed every streamed AI response. Non-AI traffic and
  upstream errors consume nothing.

- **The Helm chart, the operator's own version, and the workspace
  version now agree.** `Chart.appVersion` claimed `2.0.0`, the operator
  crate was still versioned `0.1.0` and had never been bumped, and the
  workspace was at `1.10.0`; none of the three numbers matched anything
  real. The operator crate now inherits `version.workspace = true`, and
  the chart's deployment template defaults `image.tag` to
  `.Chart.AppVersion`, so the chart carries one true version instead of
  three that drift independently. Separately, the chart's operator
  image tag pointed at an image no CI workflow actually builds, so a
  stock `helm install` landed the operator pod in `ImagePullBackOff`;
  this is now called out explicitly in the docs and `values.yaml`, with
  a documented local-build workaround. Three docs and the sample
  manifest had also disagreed with each other on the proxy image tag;
  all now match what the release workflow actually publishes.

- **ACME HTTP-01 challenge validation now works behind a load
  balancer.** The per-hostname issuance lease was already shared across
  replicas, but the challenge token itself lived only in a
  process-local map on whichever replica won the lease. The CA's
  validation callback is load-balanced like any other request, so it
  frequently landed on a different replica with no record of the token
  and answered 404, meaning HTTP-01 validation couldn't complete at all
  in a multi-replica deployment. This failed silently: issuance errors
  are logged and swallowed, the proxy falls back to a self-signed
  certificate so the handshake still completes and the pod stays
  Ready, and nothing paged anyone for the roughly twelve-hour retry
  window in between. The token now lives in the same shared `KVStore`
  backing the cert store, keyed `acme:challenge:<token>`, so any
  replica can answer the CA. Its TTL is now derived from the CA's
  actual authorization-expiry field per RFC 8555 section 7.1.4, instead
  of a hardcoded, invented 600 seconds. In the same change,
  `storage_backend: sqlite` stopped silently downgrading to in-memory
  storage; an unrecognized backend value is now a hard error instead.

- **The served-quote nonce ledger for x402 payments is now durable.**
  Double-charge protection was already durable, backed by SQLite, but
  double-serve protection, stopping an already-settled quote token from
  being redeemed twice, used an in-memory set on the production path. A
  client re-presenting a settled quote token got served the paid
  content again, once per proxy restart. The ledger is now
  SQLite-backed over the settlement store's own connection, and a spend
  is a single atomic `BEGIN IMMEDIATE` plus
  `INSERT ... ON CONFLICT DO NOTHING`, so there's no read-then-write
  race across processes. Nonces prune themselves on the quote token's
  own expiry claim, and there's no longer a production code path that
  can construct the old in-memory version.

- **A stranded payment intent with no identifiable payer now stops
  withholding challenges after a bounded window.** When a payment
  intent lands in `NeedsReconciliation` and its payer can't be
  identified, the normal case for anonymous or crawler traffic, the
  route withheld fresh 402 challenges entirely and indefinitely; x402
  has no status-query endpoint, so a facilitator outage could zero a
  route's revenue for as long as the outage lasted. A separate fix
  already scoped withholding to a single payer when one could be
  identified; this covers the case where it can't. A new `Stranded`
  state now lifts the gate at the quote token's own challenge expiry
  plus a fixed fifteen-minute reconciliation grace window, past which
  point the stranded payer couldn't redeem the token anyway. The route
  resumes issuing challenges while the underlying provider attempt
  stays queued, so a late answer can still commit a real receipt.
  Operators get a documented query to pull stranded intent IDs for
  manual reconciliation, and a
  `sbproxy_payment_recovery_total{operation="strand_intent"}` metric to
  alert on.

- **A credential's `attrs.team` now reaches the request principal.**
  `project`, `user`, `tags`, `metadata`, and `cost_center` all flowed
  from a virtual key's attrs into the principal; `team` didn't, because
  `VirtualKeyConfig` had no field for it and
  `principal_for_resolved_virtual_key` hardcoded `team: None`. Any
  deployment attributing spend or metrics by team, across five metric
  families, the access log, spend rollups, the usage sink, CEL/Lua/JS
  contexts, and MCP RBAC, got every request bucketed under an empty
  team. `team` now follows the same origin, proxy, and tenant
  config-scope lowering path the other attribution fields already use.

- **The metering divergence sweep no longer alerts on every tenant with
  billable traffic.** `chain_contribution` only had a trait default
  returning `None`, so `note_chained` never ran, the chained-receipts
  map stayed permanently empty, and the sweep flagged a divergence for
  every tenant, every window, unconditionally. Once wired, a second
  problem surfaced: comparing raw per-window totals flagged any request
  whose count and its chain entry landed on opposite sides of a window
  boundary, and the false-positive rate rose with traffic. State is now
  a signed per-tenant balance carried across sweeps, along with its
  nearest-to-zero floor since the last sweep; a request straddling a
  window boundary nets to zero and stays quiet, while a genuinely lost
  receipt holds the balance up and reports once, at the cost of
  surfacing sixty to a hundred twenty seconds later than before. The
  `ledger` health component is also renamed `usage_ledger`, and
  `with_recency` is removed, since it would have marked a healthy but
  idle deployment, one with no paying traffic, Unhealthy and pulled it
  out of rotation.

- **A matched virtual key no longer erases the inbound principal's
  roles and claims.** `apply_resolved_virtual_key_context`
  wholesale-replaced `ctx.principal` on a match, so a JWT-authenticated
  request lost its `roles` and `claims` the moment a virtual key also
  matched. Under default-deny, that meant role-scoped MCP ACL rules and
  claim-based CEL policies could silently stop matching. The merge is
  now per field: attribution fields let the credential win, identity
  fields like `sub`, `source`, and `virtual_key` still replace
  outright, but `roles` and `claims` now carry forward from the inbound
  principal. Separately, five header-settable attribution tags reached
  Prometheus straight from caller headers with no cardinality limit; a
  documented constant, `MAX_DISTINCT_VALUES_PER_TAG`, existed but no
  call site read it, so an untrusted caller could mint unbounded label
  values across five metric families. Both are now routed through the
  existing cardinality limiter.

- **Every `config_only` key now has a real disposition instead of a
  boot warning pointing at a closed ticket.** The most visible fix
  among 32: `cors.enable: false` was silently ignored, since the
  runtime enabled CORS on the block's presence, never on the boolean's
  value, so an operator writing `false` to disable CORS actually left
  it enabled. Config compile now refuses that combination, naming the
  fix. Eleven other config-only keys are now refused outright instead
  of silently accepted: five legacy `proxy.secrets` keys superseded by
  `backends`, three dead `forward_rules[].origin` metadata fields, and
  `key_introspection` and `redis_source_of_truth` on the one value that
  never worked. Two keys, `proxy.secrets.map` and
  `proxy.http3.idle_timeout_secs`/`.max_streams`, turn out to have been
  live all along and are reclassified from config-only to stable.

- **`request_modifiers[].js_script` now runs.** It parsed, compiled,
  and was pinned `stable` in the key registry, so it never triggered a
  boot warning, but no code path ever executed it: only its Lua twin,
  `lua_request_modifier`, actually ran at the request phase, despite
  docs and the glossary describing both as supported symmetrically. A
  second, independently found instance of the same class of bug: a
  forward rule's modifier loop only read `headers`, so a `lua_script`
  or `js_script` attached to a forward rule was compiled and silently
  never run, for either engine. Both are now wired to execute; on the
  origin path, JS runs after Lua, and both now run on forward rules
  too.

- **ACME issuance now retries a `badNonce` rejection with the nonce the
  server actually offered.** On a `badNonce` response, the retry
  previously discarded the fresh nonce the server returned in
  `Replay-Nonce`, because the body was read before the headers, making
  the header unreachable, and instead re-fetched a nonce with a second
  `HEAD newNonce` call that could itself be rejected with no further
  retry. A failed second attempt then surfaced only as a bare "returned
  400," with the real cause lost. `post_jws` is now a bounded loop,
  three attempts, that reads `Replay-Nonce` off the 400 before
  consuming the body and signs the retry with it, falling back to
  `newNonce` only when the header is absent. Non-badNonce errors are
  unaffected. This makes certificate issuance resilient to a
  nonce-rejection race against a real CA, per RFC 8555 section 6.5,
  instead of failing outright.

- **A `sbproxy_ai_multipart_inspection_skipped_total` counter makes the
  multipart guardrail gap visible.** The AI gateway's dispatch gate
  branches on the inbound `Content-Type`, and every exit of the
  multipart branch returns early, so input guardrails, `pii:` request
  redaction, and `prompt_injection_v2` never run against a multipart
  request. A caller can still send `multipart/form-data` to
  `/v1/chat/completions` and route around every configured guardrail
  with no metric or log to show it happened, until now: a nonzero rate
  on a surface where multipart isn't legitimate, like
  `chat_completions`, is now a dashboard signal. Enforcement itself is
  unchanged here, only the visibility; the docs are also corrected,
  since they previously understated how narrow the bypass was and
  overstated what the `dlp` policy covers (it reads URIs and headers,
  not body content).

- **A multipart AI request's `prompt` field now goes through input
  guardrails.** A multipart request, an image edit or a transcription,
  short-circuited before the JSON parse, so the guardrail pipeline,
  including prompt-injection scanning, never ran on its `prompt` text
  field at all. That was a documented way to bypass scanning entirely:
  send the same text as a multipart part instead of JSON. The `prompt`
  part is now extracted and run through the same
  `evaluate_ai_input_guardrails` evaluator the JSON path uses, covering
  both built-in and external guardrails. Image and audio bytes still
  aren't scanned, since no classifier reads them, and PII redaction
  still deliberately skips multipart, since rewriting it would break
  the multipart framing, but a credential that requires redaction now
  gets a 403 instead of an unredacted forward.

## [1.10.0] - 2026-08-04

### Added

- **Extension bundles: install TypeScript, JavaScript, or WebAssembly
  behavior from a directory and attach it in `sb.yml`.** The plugin trait
  surface and its registry already existed, but only `AuthProvider` was
  reachable from configuration: `compile_policy`, `compile_transform`,
  and `compile_action` never fell back to the registry for an unknown
  `type:`, so `Transform::Plugin` had full timeout- and panic-guarded
  dispatch machinery that no config could reach. A bundle is a directory
  holding a `bundle.yaml` manifest and one entry artifact. TypeScript is
  stripped to ES2020 once while the candidate loads; JavaScript loads
  directly; dependencies must arrive as one prebuilt flat `.js` file,
  because nothing here installs packages or resolves modules at runtime.
  Four runtimes are available: `javascript`, `wasm` on sbproxy's own
  envelope ABI, and `proxy_wasm` against the real Proxy-Wasm 0.2.1 host
  ABI, which is the one Envoy, Kong, and APISIX SDKs already target.
  Hooks cover `policy`, `transform`, and `action` on the HTTP path, the
  AI seams (`ai_tool_call`, input and output guardrails, stream events,
  and close), and a rail-neutral payment lifecycle whose first complete
  adapter is x402. The manifest bounds wall time, memory, stack,
  buffered input, output, and WASM fuel, and `permissions` must stay
  empty: bundle code gets no filesystem or network capability. `sha256`
  pins the exact bytes of the entry artifact, and a mismatch refuses
  startup, validation, doctor, or reload before the candidate can become
  active. Reload swaps bundles as one pipeline generation, so a rejected
  candidate never leaves half its hooks attached. `GET
  /api/extensions` and `sbproxy doctor` both report what is installed,
  what is attached, and where each hook sits in its chain. Worked
  examples are in [examples/extension-bundles](examples/extension-bundles/),
  and the reference is section 12 of [docs/scripting.md](docs/scripting.md).

- **A configured usage reporter now receives live proxy traffic.**
  `proxy.payments.usage_reporters.stripe_meter` shipped with a reporter,
  a durable queue, and a worker that drains it, and with nothing that
  produced an event. An operator could configure the block, pass
  validation, pass startup, serve traffic, and bill nothing. The request
  path now enqueues each billable unit immediately after the meter
  settles the request receipt, billing from that settlement rather than
  re-deriving it, so a cache hit or a policy block is charged or not
  charged according to the same outcome table the signed receipt used.
  The HTTP call to the provider stays in the background worker: a served
  request writes one durable row and stops, so no request ever waits on
  Stripe. Two counters describe it, `sbproxy_usage_bridge_enqueued_total`
  and `sbproxy_usage_bridge_gap_total`, both labeled by tenant. See
  [`docs/payment-settlement.md`](docs/payment-settlement.md).

  **`usage_reporters.stripe_meter` gains two required fields, `source`
  and `unit` [BREAKING].** A config with a `stripe_meter` block and no
  `source` no longer parses. There is deliberately no default: one
  request can produce a request receipt, an AI usage record, and a
  record per MCP tool call, and two of those can describe the same sale,
  so billing both against one meter charges the customer twice. An
  unstated answer there *is* the double charge, and a default would be
  this proxy picking a side of a commercial argument on the operator's
  behalf. Set `source` to `http`, `ai`, or `mcp`, and `unit` to the unit
  that meter bills. An operator who wants both dimensions configures two
  meter events. The block shipped one day before this change, so the
  affected population should be close to nobody.

- **mistral.rs is a subprocess engine kind.** `engine: mistralrs` drives the
  upstream v0.9 `mistralrs` CLI as a supervised subprocess over its
  OpenAI-compatible surface, acquired exactly like llama.cpp: PATH-first,
  then the pinned upstream prebuilt release (Metal on Apple Silicon; CPU
  and per-compute-capability CUDA builds on Linux x86-64), sha256-verified
  against checked-in digests. The lane serves safetensors weights with
  native tool calls, appears in `sbproxy doctor` and `models list`, and is
  an explicit opt-in: `auto` never resolves to it and placement ranks it
  behind the certified lanes. See
  [`docs/model-host.md`](docs/model-host.md).
- **A managed worker refuses to boot into a configuration it cannot
  serve.** `sbproxy doctor --strict <config>` runs six named startup checks
  (NVIDIA driver, visible accelerators, per-entry engine compatibility,
  `/dev/shm` against the size an engine asked for, the weight-cache mount
  against `cache_budget_gib`, and `proxy.cluster` identity material) and
  exits 3 when any of them blocks. Each check compares the config's own
  demands against the host, reads both the provider-level `serve:` form and
  the canonical `proxy.model_host` form, and reports `skip` rather than a
  hollow pass when it does not apply. The worker image and the generic VM
  bootstrap now boot behind it, so a box handed no GPU devices, a too-small
  `/dev/shm`, an undersized cache mount, or unreadable model-plane identity
  fails at boot with a named blocker instead of joining the cluster,
  advertising itself as eligible, and failing every dispatch. See
  [`docs/manual.md`](docs/manual.md).
- **The self-host matrix has a runner and an evidence ledger.**
  `scripts/certify-selfhost.sh` gives every lane in the certification table
  one reproducible command, a recorded expected result, captured host and
  version metadata, and a retained log. A lane passes only when its command
  ran on this host and succeeded; a host that cannot provide what a lane
  needs is recorded `unsupported` with the reason, never as a pass. Apple
  Silicon and NVIDIA single-GPU CUDA now have live evidence dated
  2026-07-30, including a real vLLM container completion on an L4. See
  [`docs/model-host-certification.md`](docs/model-host-certification.md).
- **The macOS launchd agent has an environment file.**
  `sbproxy service install` creates
  `~/Library/Application Support/sbproxy/service/env` (mode 0600) once and
  never overwrites it, so an `HF_TOKEN` a gated model needs survives
  reinstalling to change the model or the port. A launchd agent inherits
  almost nothing from the shell that installed it, so a token exported in a
  terminal was previously invisible to the agent. `service status` now also
  reports the config, log, and environment-file paths.
- **Rate limits converge across a gossip mesh with no Redis.** A clustered
  deployment previously enforced `requests_per_minute` once per node, so 600 rpm
  on three nodes admitted roughly 1800. Each node now admits against its own
  count plus a view of its peers refreshed every 3 seconds, which bounds the
  overshoot at `(nodes - 1) x rate_per_second x 3`: about 660 for that same
  configuration. An L2 Redis store still enforces exactly and takes precedence
  when configured. `requests_per_second` is unchanged and still per-node, since a
  one second window closes before a peer count can arrive, and it now warns at
  boot on a mesh cluster instead of silently enforcing N times the limit.
  `sbproxy_rate_limit_cluster_peer_denials_total` makes the approximation
  observable. See [`docs/configuration.md`](docs/configuration.md).

- **External AI guardrails now use hardened vendor contracts.** Generic
  webhooks and Presidio remain compatible, while Lakera, Aporia, Azure AI
  Content Safety, Amazon Bedrock Guardrails, CrowdStrike AIDR, Mistral
  moderation, Pangea AI Guard, and Patronus have typed adapters. Credentials
  resolve through the existing secret providers; outbound URLs are validated
  and DNS-pinned; redirects are disabled; and responses have a timeout and a
  64 KiB limit. Fail policy now covers malformed responses, replayed output,
  streaming, and uninspectable multipart content before bytes can leave the
  gateway. See [`docs/guardrails.md`](docs/guardrails.md).
- **AI routing learns live locality and shares caller quota across the
  fleet.** Prefix affinity records bounded, expiring provider holders and
  falls back by recent token load; outcome-aware routing blends learned
  feedback during warm-up and keeps that feedback across config reloads;
  and weighted request pools support local, approximate mesh, and strict
  Redis accounting keyed by immutable credential ids. Each external
  provider attempt reserves independently and settles only at its outbound
  send boundary, with explicit closed or `allow_unreserved` backend failure
  behavior.

### Changed

- **`sbproxy-plugin` is 0.3.0, and `ActionOutcome` is the reason.** The
  enum gained a data-bearing `Response { status, headers, body }` variant
  so a handler can hand the host a complete response as data rather than
  writing one through host state, which is what lets ordinary response
  middleware and the bundle action contract see it. That drops the enum's
  `Copy` impl and makes any exhaustive match on the 0.2 variants
  non-exhaustive. The crate stayed at 0.2.0 through that change, so an
  out-of-tree plugin hit a breaking change with no version to notice it
  by; 0.x breaking changes bump the minor, and this one now does. Both
  0.2 variants still exist and still mean what they meant, so migrating
  is adding a `Response { .. }` arm and replacing any implicit copy with
  a clone or a move. The migration note is on `ActionOutcome`'s rustdoc,
  and a test now pins which traits the enum carries so a later change
  cannot move the contract silently again.

### Removed

- **The in-process embedded engine (`engine: embedded`).**
  Never on by default (it required a build with `--features embedded`) and
  never certified: no dedicated tests, no CI lane, and no capability-ledger
  entry. llama.cpp already covers the CPU/Metal, zero-external-binary case
  it existed for, and the new `mistralrs` subprocess engine (see above)
  covers safetensors mistral.rs serving without the large in-process
  dependency tree. A config that still sets `engine: embedded` now fails
  to parse.

### Fixed

- **A bundle hook can no longer end a request with a status that is not
  final, or attach a body to one that forbids it.** Extension-produced
  responses accepted anything from 100 through 599. A 1xx is
  informational, so it asks the host to keep going, but both surfaces
  that can return one (a dynamic action's result and Proxy-Wasm's
  `proxy_send_local_response`) have already stopped dispatch by the time
  they see it, which left the caller waiting on a final status that could
  never arrive. A 204 or 304 could also carry a guest body, which
  desynchronizes an HTTP/1 connection and is a protocol error on HTTP/2.
  Both surfaces now share one rule applied before any byte reaches the
  wire, and a rejected body is refused rather than silently dropped, so a
  bundle that believes it is returning content cannot look like it works.
  Every rejection message is a fixed string plus the status, so no
  guest-supplied bytes reach host logs.

- **A bundle's declared `failure_posture` is now the posture the pipeline
  applies.** The manifest accepted the key for policy, transform, and
  action hooks, and compilation dropped it. A buffered dynamic policy
  that failed was denied regardless of what its manifest said, and a
  transform never received the value at all, because `Transform::Plugin`
  carried no bundle metadata the way the action and policy wrappers
  already did. Resolution now follows one precedence: an explicit
  `failure_posture` or `fail_on_error` on the attachment, then the
  manifest, then the attachment default. Silence on the attachment is
  distinguished from an explicit `open`, which is the whole fix, because
  `TransformConfig::failure_posture()` returns `Open` for both. A genuine
  host invariant violation is still a 500 whatever the posture says.
  Action hooks are unchanged and still fail closed: the manifest already
  refuses any other posture for them, since they are terminal.

- **Extension inventory reports the chain order the proxy runs, not an
  alphabetical one.** Positions were derived by sorting hook identities
  and counting, so two Proxy-Wasm filters listed `zeta` then `alpha` came
  back as `alpha` at position 0 and `zeta` at 1, the reverse of their
  execution order, and ordered AI and payment chains could all report as
  position 0. Positions now come from the same enumeration the compiler
  walks and from each chain's real dispatch order. A hook attached at
  more than one site deterministically reports the earliest one in
  document order. Attachment and position are also separate facts now: a
  hook the chain cannot name stays attached and reports no position,
  rather than being given one that is wrong.

- **The AI gateway's circuit breaker and outlier detection now run.**
  `resilience.circuit_breaker` and `resilience.outlier_detection` parsed,
  validated, and were documented and exampled, and nothing ever attached
  them to a router. The constructor that would have done it had no
  callers anywhere in the tree, so the breaker list was empty and the detector
  absent on every router the proxy has ever built, both arms of the
  eligibility check passed unconditionally, and the ejection sweep the
  request path ran on every provider failure evaluated state nothing
  populated.
  A deployment that configured circuit breaking against a flaky provider
  had none. Both blocks are now attached where the router is built, each
  by its own config block, so configuring one does not arm the other on
  thresholds nobody chose.

  **If you have either block configured, providers will now start
  leaving the routing pool.** On the shipped defaults a provider leaves
  after five consecutive request failures, or after a 50% failure rate
  over at least five requests in a 60-second window, and only a 5xx or a
  transport error counts; a 4xx, including a 429, does not. Each signal
  clears on its own terms without help from the others: a breaker admits
  a probe after `open_duration_secs` and closes on `success_threshold`
  successes, an ejection lapses after `ejection_duration_secs`, and a
  probe verdict flips back after `healthy_threshold` consecutive passes.
  A provider that failed on two signals returns when both have cleared.
  Breaker transitions and outlier ejections are logged.

  With every provider ejected, dispatch routes to the full permitted set
  rather than refusing the request, which is what `resilience` has always
  documented and what the load balancer's identical filter does. Three
  advisory signals should not combine into an outage none of them can
  cause alone. Credential policy, model eligibility, and `enabled` stay
  hard filters and are never revived. An `outlier_detection.threshold` of
  zero or a `min_requests` of zero, which together would eject a provider
  that had never failed, are refused with a warning and the default is
  used instead.
- **`routing.strategy: token_rate` is refused at config load instead of
  silently behaving as a different strategy.** It ranks providers by
  remaining tokens-per-minute headroom against a declared per-provider
  limit, and no configuration field declares one, so every limit was zero
  and the score reduced to observed usage alone: `least_token_usage`
  under another name, with no error and no warning. **If you have
  `token_rate` set, the proxy will now refuse the config.** Change it to
  `least_token_usage`, which is what you have been running, or to
  `headroom` or `reset_aware`, which score the rate-limit headers
  providers actually return. See
  [`docs/ai-gateway.md`](docs/ai-gateway.md#token_rate-refused).
- **`sbproxy run` and `sbproxy service install` no longer publish the
  local model gateway to the network.** Both generate a config the code
  calls secure defaults, and the admin half was: loopback bind, random
  port, a 32-byte `OsRng` password written at mode 0600. The public
  listener was hardcoded to `0.0.0.0` in the server, with no schema
  field able to express anything else and no authentication in front of
  it, while the ready banner printed `http://127.0.0.1:<port>` and
  handed you an `OPENAI_BASE_URL` built from it. On a laptop on a shared
  network that was an open inference endpoint, described as local. The
  generated `origins:` map restricting to `127.0.0.1` and `localhost`
  was not a defense, because that matches on the `Host` header, which
  the caller sets.

  Both commands now generate `bind_address: 127.0.0.1`, so the banner's
  URL is true. **If you relied on `sbproxy run` being reachable from
  another machine, it no longer is.** Write a config and set
  `proxy.bind_address` to `0.0.0.0` or a specific interface, and put
  authentication in front of it.
- **`proxy.bind_address` makes the public listener's interface
  configurable at all.** It applies to `http_bind_port` and
  `https_bind_port` together, because two fields would let an operator
  lock down HTTP, leave HTTPS open, and believe the box was closed. It
  defaults to `0.0.0.0`, so every existing config keeps the reach it
  has. The value must be an IP literal: hostnames are refused because a
  name can resolve to more than one address, and a malformed address is
  refused at config load rather than falling back to a default, since
  falling back is precisely the failure the field exists to prevent. See
  [`docs/configuration.md`](docs/configuration.md#choosing-a-bind-address).
- **The `a2a` policy no longer decides on inputs the caller controls.**
  Chain depth, chain membership, and caller and callee identity were read
  from `X-A2A-*` request headers with no verification and no ingress
  stripping, so a caller could send `X-A2A-Chain-Depth: 1` with no chain
  and clear `max_chain_depth` and cycle detection together, or rename
  itself off `caller_denylist`. The envelope now comes from the RFC 8693
  `act` claim chain on the verified principal, which a caller cannot
  flatten, and the `X-A2A-*` headers are honored only from a peer in
  `proxy.trusted_proxies` and stripped from everyone else. Operators
  relying on the header transport must now list the peer that stamps it;
  `examples/a2a-protocol/` shows the shape. The policy's `route_glob` is
  also consulted for the first time: it was parsed, validated, and never
  read, so the one detection signal a caller could not opt out of did
  nothing. See [A2A gateway](docs/a2a-gateway.md).

- **`sbproxy_a2a_hops_total` distinguishes verified allows from
  unverified ones.** The `decision` label emitted a bare `allow` whether
  the policy had checked a verified delegation chain or waved through an
  envelope it could not trust, so a fully bypassed policy produced the
  same green dashboard as a working one. Allows are now
  `allow:verified` or `allow:unverified`, and a request the policy never
  engaged on records `skip:undetected` rather than nothing at all.
  Denials are unchanged. This relabels a `beta`-compatibility metric; no
  dashboard or alert in this repository reads it.

- **Ollama streaming keeps its stream and its usage accounting.** The
  buffered-relay fallback for streaming requests keyed on `text/event-stream`
  alone, so Ollama's NDJSON (`application/x-ndjson`) success responses were
  buffered whole and their token counts never reached budget recording: a
  workspace past its cap kept getting 200s. NDJSON responses now stay on the
  streaming relay, where the Ollama usage parser reads them line by line.
- **A bulk credential purge now reaches every node.** `invalidate_all` cleared
  only the local shard, so peers kept serving stale resolved credentials until
  TTL. It now fans out to every peer. The same change fixes the opposite problem
  on the node running it: because a clustered node's key-plane cache is the
  node-wide distributed cache, the old blanket purge also discarded unrelated
  entries such as compression sessions. The purge is now scoped to the key-plane
  prefixes.
- **A clustered node now says what its node-local keystore does and does not
  guarantee.** The `embedded` redb store is per-node, so a key minted on one node
  is not durably resolvable by its peers and a revocation may not deny on all of
  them. A node declaring `proxy.cluster.seeds` with `key_management.enabled: true`
  and `store.backend: embedded` now warns at boot when a `mesh` or `redis`
  `cache.tier` propagates records (resolution works while cached, but does not
  survive expiry or a restart), and fails to start when `cache.tier: none` leaves
  nothing to propagate through. A single node with no seeds keeps the embedded
  default. See [`docs/key-management.md`](docs/key-management.md).
- **The legacy `serve:` fit path books the KV cost the engine will run.** The
  1.9.0 fix that made the fit planner and the engine drivers share one KV
  table missed the single-node runtime behind a legacy `serve:` block, which
  still sized its KV term from the requested `kv_quant`: `int4` on vLLM
  booked 0.5 bytes per element while the engine allocated fp8 at 1.0,
  halving the planned cache. That path now sizes from the shared table and
  logs the same substitution warning, the single-replica managed activation
  path warns too instead of substituting silently, and the llama.cpp
  driver's own dtype mapping now derives from the table instead of
  restating it. See [`docs/gpu-fit-planning.md`](docs/gpu-fit-planning.md).

## [1.9.0] - 2026-07-28

### Added

- **AI routing and state now carry production authority end to end.** Peak
  EWMA routing tracks complete provider attempts with configurable decay;
  Realtime WebSocket upgrades replace caller credentials with one trusted
  provider credential and apply governed-key budget admission; stateful
  context compression defaults to a private, restart-durable Local redb store
  while retaining explicit Redis and mesh choices; and verified crawler CAPs
  enforce bounded per-subject request rates before policy evaluation while
  exempting approved traffic from ledger pricing.
- **Classifier safety guardrails now ship calibrated default centroids.**
  `toxicity`, `jailbreak`, and `content_safety` classifier mode no longer
  requires operator examples. Optional examples extend the versioned
  defaults. The artifact pins the exact `all-MiniLM-L6-v2` revision, model,
  tokenizer, and artifact digests, and incompatible bytes fail closed.
  Repo-authored held-out fixtures, measured class precision and recall, and
  deterministic regeneration live in
  [`docs/ai-default-centroids-evaluation.md`](docs/ai-default-centroids-evaluation.md).
- **Outbound credentials can use DPoP-bound tokens.** `client_credentials`,
  token exchange, and vault-backed credentials can load an existing private
  key from the secret-provider surface and mint fresh RFC 9449 proofs for
  token and resource requests. Method and URI binding, access-token hashes,
  nonce challenges, retry bounds, and proof-header redaction are enforced.
  See [`docs/outbound-dpop.md`](docs/outbound-dpop.md).
- **The admin API exposes model-host lifecycle jobs.** `GET
  /admin/model-host/jobs` and `GET /admin/model-host/jobs/{id}` list and read
  durable load/evict operations. `GET /admin/model-host/jobs/{id}/stream`
  tails one job's progress as `text/event-stream`, with `Last-Event-ID`
  reconnect replay. `POST /admin/model-host/load` and `/evict` now answer
  `202` with a `job_id` and `poll_url` when a durable job store is
  configured, instead of blocking the request until the engine finishes;
  with no job store configured they keep the previous synchronous `200`
  contract. See [`docs/admin-api-guide.md`](docs/admin-api-guide.md).
- **The admin console playground dispatches through the real request
  pipeline.** `POST /admin/api/playground/dispatch` impersonates a chosen
  virtual key with a short-lived, single-use ticket and makes a genuine
  loopback call into the server's own data-plane listener, so key policy,
  governance, routing, and guardrails run exactly as they would for that
  key's real traffic. Plain-HTTP AI origins only; an origin with
  `force_ssl` set answers `501`. The existing `POST
  /admin/api/playground/chat` (calls the AI client directly, bypassing the
  data plane) is unchanged.
- **A data-plane route reports a caller's own usage.** `GET /v1/key/usage`
  returns the resolved caller's governance snapshot (requests, tokens,
  spend, remaining budget), scoped strictly to its own key id. There is no
  key-id parameter, so a key can never read another key's usage.
- **Fleet VRAM aggregation and new admin console views.** `GET
  /admin/cluster/vram` sums VRAM totals across every currently eligible
  cluster node. The admin console adds a Get Started onboarding view, a
  Jobs view backed by the new job API, four axes per deployment on the
  Model host view instead of two (desired / runtime / assignment /
  live-replica state), and a per-replica disclosure in the cluster node
  roster.
- **`sbproxy service install|uninstall|status` runs a model as a background
  launchd agent on macOS.** `install` generates the same secure loopback
  config `sbproxy run` would, persists it under `~/Library/Application
  Support/sbproxy/service/`, and registers a per-user `launchd` agent that
  restarts on failure; `uninstall` unloads and removes it; `status` reports
  whether it is registered and running. See
  [`docs/manual.md`](docs/manual.md).
- **Recommended-model catalog entries are pinned.** Six of the seven
  built-in `models.yaml` recommended entries now carry exact `variants:`
  blocks (sha256, size, revision) instead of resolving loosely at pull
  time.
- **Worker and gateway container images are split, with a generic cloud
  bootstrap script.** `Dockerfile.worker` (CUDA + vLLM) and
  `Dockerfile.gateway` (lightweight, no GPU stack) replace one combined
  image. `deploy/terraform/l4-demo/bootstrap-generic.sh` is a
  cloud-agnostic install/validate/start script driven entirely by
  environment variables, used by both the GCP Terraform path and
  `cloud-init.yaml`. See [`docs/build.md`](docs/build.md).
- **vLLM prefix caching is a config flag.** `enable_prefix_caching` on a
  managed vLLM deployment emits `--enable-prefix-caching`. See
  [`docs/model-host.md`](docs/model-host.md).
- **An opt-in Xet-aware weight transport is available behind a feature
  flag.** The new `hf-xet-transport` Cargo feature (off by default) adds a
  second artifact transport built on `hf-hub` 1.0's managed, Xet-aware
  client. It is not wired into the default build or either production
  transport call site yet; this ships the transport for a follow-up to
  adopt.
- **Six new AI providers.** AI21 Labs (Jamba), Clarifai, Inception Labs
  (Mercury), Azure AI Foundry Models, Snowflake Cortex, and Sarvam AI,
  bringing the native provider catalog to 72. See
  [`docs/providers.md`](docs/providers.md).
- **OTLP metrics export actually exports.** `telemetry.export_metrics:
  true` previously did nothing; boot now wires the metrics pipeline, and
  fails loud if `export_metrics: true` is set without `enabled: true`.
- **Six new self-host observability metrics, with alerts and dashboard
  panels.** The previously dead `sbproxy_model_host_load_queue_depth` gauge
  is now wired to a real signal, and five new counters cover artifact
  acquisition failures (`sbproxy_model_host_artifact_errors_total`),
  model-directory exclusions
  (`sbproxy_ai_model_directory_exclusions_total`), replica-selection
  exclusions (`sbproxy_ai_replica_selection_excluded_total`), placement
  rejections (`sbproxy_model_host_placement_rejections_total`), and the
  key-policy budget fail-closed path
  (`sbproxy_key_policy_stored_rejections_total`). See
  [`docs/metrics-stability.md`](docs/metrics-stability.md).
- **CI gates on the admin UI's typecheck and tests.** Previously nothing in
  CI ran `npm run typecheck` or `npm run test` for the admin console.

### Removed

- **Superseded `sbproxy-ai` library modules.** Removed unreachable local
  emulation, prompt-cache, response-deduplication, context-relay,
  structured-output, and streaming-tracker code. Provider passthrough
  surfaces, semantic caching, idempotency, live streaming metrics, and the
  shipped context-compression pipeline are unchanged.
- **Unreachable policy prototypes no longer look supported.** The
  `peer_pricing_preflight` policy and the inactive NL-to-Cedar compiler,
  linter, and compiled-policy store had no production request-path caller
  and have been removed. Delete `peer_pricing_preflight` entries from
  configuration; there is no outbound peer-pricing replacement today.
  Existing `semantic_constraint` policies remain supported, but must drop
  the inert `policy_id` field and continue to configure their judge
  directly. AI crawl payment negotiation keeps its live
  `Accept-Payment` parser.
- **Dead model-host residency prototypes.** Removed the unwired vLLM sleep/wake
  client and policy-only KV tiering abstraction. Neither was a supported
  capability, and vLLM development endpoints are no longer enabled by default.
  The engine-native `swap_space_gib` and `cpu_offload_gib` settings remain.
  Safe future sleep/wake wiring needs bounded asynchronous transition polling,
  retained process ownership and accounting after cleanup failures, a bounded
  host-RAM policy, isolated container development endpoints, and end-to-end
  fake-engine coverage.

### Changed

- **A CEL syntax error is now a config error, everywhere CEL comes from
  config.** `assertion` policies, `cel` transform bodies and header
  rules, rate-limit `key:` expressions, WAF `persistent_block.key`, and
  `engine: cel` custom log fields all compile while the config compiles,
  the same way `expression` policies already did. A malformed expression
  refuses the config at boot, and a reload carrying one is rejected with
  the previously active config still serving. Before, each of these
  parsed again on every request or response and swallowed the parse
  error at that point, so a typo booted fine and then silently disabled
  the thing the operator wrote: an assertion that never ran, a header
  rule that never fired, a log field that never appeared. **A config
  with a CEL typo that used to start will now refuse to start.** That is
  the point, but it is a startup-behavior change, so run `sbproxy
  validate` against your config before upgrading; it reports the same
  errors with the owning origin, policy, and field named.

  Turning the check on immediately found two expressions that had never
  worked, both of them ours. `docs/access-log.md` and
  `examples/custom-log-fields/sb.yml` both used
  `has(request.headers["x-tier"])` to test for a header. CEL's `has()`
  macro takes a field selection, not an index, so that expression has
  never parsed, and the log field it guarded has never once appeared in
  an access line. The working form for a hyphenated header name is
  `"x-tier" in request.headers`, and both pages now use it. Separately,
  `examples/rate-limiting/sb.yml` wrote `key: ip` as though `key` took a
  keyword; it is a CEL expression, so `ip` was an undefined identifier
  that failed every request and dropped the policy into the default
  bucket, which happens to be keyed by client IP. It looked like it
  worked because the fallback did. It is now
  `key: 'connection.remote_ip'`, which is the same partitioning, said in
  the language the field actually speaks.
- **A rate-limit `key:` expression that fails to evaluate no longer
  drops the request into the default bucket.** It buckets under a
  `__cel_key_error__:` prefix on the default client key instead. The old
  fallback was a rate-limit bypass: the default key is the client IP, or
  the hostname when no client IP is known, so a caller that could force
  the expression to fail left its own identity bucket, and its
  accumulated count, behind. Rate limiting stays on either way, and
  error traffic no longer shares a bucket with correctly keyed traffic.
  An expression that evaluates cleanly to null or an empty string still
  means "no key for this request" and still falls back to the default
  client key, because that is the operator's own logic talking.
- **Outbound HTTP no longer follows a redirect without re-authorizing it,
  and the AI provider client no longer follows one at all.** The AI
  client, the webhook, Langfuse, and Datadog usage sinks, the MCP token
  exchange, and engine artifact downloads all followed redirects inside
  `reqwest` with no second look, so a host allowlist only ever covered
  hop one. Each of them now runs an explicit hop loop: every hop is
  authorized from scratch, an off-allowlist target is reported
  separately from a hop-one refusal, and the chain is capped at ten.
  Credentials are stripped when a hop leaves its origin, keyed on
  whether the header is marked sensitive, which matters because
  `reqwest` strips `Authorization` and nothing else: `x-api-key`,
  `api-key`, and `DD-API-KEY` were riding along. **A provider base URL
  that depended on a 301 to add a trailing slash will now fail instead
  of silently working.** Point the config at the URL the provider
  actually serves.
- **Egress authorization resolves DNS for real.** These same consumers
  ran their egress gate against a fixed synthetic resolver that always
  answered `93.184.216.34`. Because that address is public and always
  resolves, the private-address rule and the resolution-failure rule
  were unreachable: an allowlisted hostname pointing at
  `169.254.169.254` passed the gate. Resolution now goes through a
  cached system resolver with a 30 second TTL, shared between the
  authorize step and the verify step so a mismatch means the answer
  genuinely changed. Refusals are counted by
  `sbproxy_egress_refused_total{purpose, reason, tenant, origin}`.
  Dial-time pinning on the shared long-lived clients is deliberately
  still open; `docs/threat-model.md` records that exemption, its
  residual risk, and the two ways to close it.
- **Admin operator passwords are now hashed at rest [BREAKING].**
  `proxy.admin.operators[].password` is replaced by `password_hash`, an
  HMAC-SHA256 hash (hex-encoded) using the same pepper the inbound key
  plane hashes virtual keys with. A plaintext `password` field under
  `operators:` no longer parses. Compute the hash with the new `sbproxy
  admin hash-password` CLI helper (`--password` or `--password-stdin`),
  which resolves `key_management.crypto.pepper` from config when set and
  falls back to a fixed default otherwise, so hashing works with no
  `key_management:` block configured. That default is a fixed public
  constant, the same in every install, so a leaked `password_hash` is
  offline-crackable unless `key_management.crypto.pepper` is pinned; pin
  it in production. The admin console gains a read-only Operators page
  (`GET /api/operators`) listing configured operator usernames and roles;
  operators stay config-only, with no admin API to add, remove, or
  re-role one.
- **Unsupported `telemetry.propagation` values now fail boot.** Previously
  any value other than `w3c` parsed successfully and was silently ignored,
  since the installed propagator was always W3C regardless of what
  `proxy.observability.telemetry.propagation` said. Boot now rejects it,
  naming the unsupported value and the one supported value.
- **Speculative decoding config is validated instead of silently dropped.**
  A `speculative` block on a deployment pinned to a non-vLLM engine now
  fails validation; previously it parsed and did nothing, since only vLLM
  emits the corresponding engine flags. n-gram speculation on vLLM is
  newly accepted. Draft-model speculation stays rejected, pending a
  VRAM-headroom check at a real prepare-time call site.
- **The HTTP OTLP transport's default endpoint is corrected.** With
  `transport: http` and no explicit `endpoint`, sbproxy now defaults to
  `http://localhost:4318/v1/traces` instead of the gRPC-oriented default
  with no path suffix appended.

### Fixed

- **`kv_quant: int4` no longer under-sizes the KV cache on vLLM and SGLang.**
  The fit planner sized the requested mode (int4 at 0.5 bytes per element)
  while both CUDA engine drivers substituted fp8 at 1.0, because neither
  exposes an integer KV kernel. The plan booked half the cache the engine
  would allocate, and the plan is what derives `--gpu-memory-utilization`,
  so a tight long-context config could fail at first-token graph capture.
  The dtype passed to the engine and the bytes the planner books now come
  from one table, so they cannot drift apart, and a substitution is logged
  rather than silent. llama.cpp is unaffected: its `q8_0` and `q4_0` caches
  are real. The legacy SGLang launch template also dropped the KV flag
  entirely and now emits it. See
  [`docs/gpu-fit-planning.md`](docs/gpu-fit-planning.md).
- **The worker image pins vLLM.** `Dockerfile.worker` installed vLLM with a
  bare `pip3 install vllm`, so every rebuild resolved to whatever version was
  newest and drifted the image off `DEFAULT_VLLM_VERSION`, which the fit
  planner, the argv builder, and the recorded NVIDIA certification all target.
  It is now pinned through a `VLLM_VERSION` build arg. See
  [`docs/build.md`](docs/build.md).
- **The launchd agent gives a shutdown drain room to finish.** launchd's
  default `ExitTimeOut` is 20 seconds, shorter than the proxy's 30-second
  default shutdown grace, so an agent still draining in-flight requests was
  SIGKILLed part-way through. The plist now sets it above the grace period.

- **OTLP spans are flushed on graceful shutdown.** A
  `shutdown_otlp_pipeline` call existed but nothing in the binary invoked
  it; spans still in flight at shutdown could be dropped.
- **Exported spans join the caller's trace.** An inbound `traceparent`
  header is now honored when seeding an exported span's parent context.
  Previously every exported span got a fresh random root trace ID
  regardless of the caller's own trace.
- **A latent boot panic in the gRPC OTLP exporter is fixed.** Building the
  gRPC trace or metrics exporter synchronously spawned a background task
  with no ambient Tokio runtime present at that point in boot, which
  panicked with `telemetry.enabled: true` and the (default) gRPC
  transport. Masked previously because the only test coverage of this path
  ran inside `#[tokio::test]`, which supplies a runtime.
- **Killed engines auto-recover on the next request.** A managed
  deployment whose engine process died after reaching `ready` (for
  example, `kill -9`, not a crash loop) previously stayed failed until an
  operator called `POST /admin/model-host/reset`. It now retries the same
  relaunch a fresh deployment uses; a deployment that is genuinely
  crash-looping still fails closed.
- **Stale cluster nodes no longer inflate fleet VRAM totals.** The cluster
  VRAM aggregator counted a node's last-known VRAM forever, even after it
  dropped out of eligibility. It now excludes any node that is not
  currently model-eligible.

## [1.8.0] - 2026-07-27

Trust tier becomes live policy input, config authority grows a command
line, and the admin console gains the pages it was missing. This release
also moves the vendored Pingora fork onto upstream 0.8.1, which carries
security fixes; see Security below.

### Security

- **Pingora updated to upstream 0.8.1.** The vendored fork was based on
  0.8.0 and has been rebased onto 0.8.1, picking up an HTTP/2 server
  limit bound that mitigates a memory-exhaustion vector, plus the fixes
  for `RUSTSEC-2026-0098` and `RUSTSEC-2026-0099`. Every deployment
  terminating HTTP/2 should take this release. SBproxy's three local
  patches (dynamic rustls cert resolver, the
  `upstream_response_decision` retry hook, and the refusal to retry once
  response bytes have reached the client) are unchanged.

### Added

- **The admin console reports context compression.** A Compression page
  lists the sessions whose history has been externalized to a summary,
  with tokens covered, summary size, and the resulting ratio. Summary
  text is never listed, only its size and provenance.
- **The admin console reports who can sign in.** A Users page lists each
  account and its role over a new read-only `GET /api/admin/users`.
  Accounts remain config (`admin.username`, `admin.operators`), so the
  route reports and does not mutate, and passwords are never included in
  the response.
- **Spend links through to the requests behind it.** Origin rows in the
  spend breakdown open the request log filtered to that origin.
- **Trust tier is now live policy input.** The request path combines
  authentication and agent-detection evidence into `suspicious`, `strong`,
  `named`, or `anonymous`; CEL expression and assertion policies can read
  `request.trust_tier`, and `sbproxy_trust_tier_requests_total` reports the
  closed-set distribution. Verified Web Bot Auth resolves to `strong`.
- **Operate a config authority from the command line.** Running one used
  to mean hand-rolled `curl`. `sbproxy config authority init` generates
  the Ed25519 signing key owner-only, writes the verifying-key file
  subscribers install, and prints what to copy where; it refuses to
  overwrite an existing key, and `--force` rotates by adding the new
  verifying key beside the old one so subscribers keep verifying while
  they are updated. `publish` runs the same three validation steps the
  authority runs, through the same code, so a payload that would be
  refused is refused locally before a revision number is spent on it.
  `status` shows the current revision, the key id, and every subscriber's
  last-seen revision, which is fleet drift visible from a terminal.
  `rollback` republishes the previous revision's payload under a new
  revision number, because a subscriber's anti-replay cursor refuses
  anything that does not move forward. `subscriber add | list | revoke`
  manages credentials, and `add` prints the credential exactly once and
  says so. Every command that changes what the fleet sees goes over the
  admin API and reports what the server returned, and an unreachable
  authority is a distinct non-zero exit rather than something local that
  looks like success. New admin route:
  `POST /admin/config-authority/rollback`.
- **Preview the configuration an authority would push, before it lands.**
  `sbproxy config pull --dry-run` runs a real subscriber cycle up to the
  point of applying: conditional fetch, signature and digest and replay
  verification, the merge over the local document, and the
  unresolved-`${VAR}` screen. Then it prints the plan diff and stops. The
  bundle cache is not written, the replay cursor is not advanced, and
  nothing reloads.
- **Subscribe to signed configuration from an upstream authority.** A new
  `proxy.config_authority.upstream` block points a node at an authority
  that publishes signed configuration bundles. The node polls, verifies
  the signature against the keys it trusts, merges the payload over its
  own file, and applies the result through the same reload transaction a
  SIGHUP takes, so a bad bundle is rejected before anything is published
  and the previously applied configuration keeps serving. Paths that
  describe the box rather than the fleet are refused outright: listeners,
  TLS material, the admin surface, secret backends, cluster identity, and
  the authority block itself. A monotonic cursor refuses a replayed or
  rolled-back revision, including across a restart, and the verified
  bundle is cached so an unreachable authority costs nothing but a
  climbing staleness gauge. `mode: overlay` merges over the local file;
  `mode: replace` treats the bundle as the configuration and will not
  start without one. Bundles that still reference an environment
  variable the node does not set are refused rather than applied as
  literal text, because nobody is reading the log on a hundred machines
  at once. New metrics: `sbproxy_config_bundle_revision`,
  `sbproxy_config_bundle_age_seconds`,
  `sbproxy_config_bundle_fetch_total`,
  `sbproxy_config_bundle_applied_total`, and
  `sbproxy_config_bundle_applied_degraded_total`.
- **A response-cache store you can pick.** The response cache has had
  four storage backends for a while, but only one of them was reachable:
  nothing in the pipeline built the others, so no config could ask for
  them. The new top-level `proxy.response_cache_store` block selects
  `memory`, `file`, `memcached`, or `redis` and the pipeline builds what
  it names. `file` gives you a cache that survives a restart and can be
  shared by replicas pointed at one directory; `memcached` gives you a
  shared cache without standing up Redis. The block sits under `proxy`
  rather than on an origin because one store serves the whole process,
  and every origin with `response_cache.enabled` shares it. Leave it out
  and nothing moves: the store is still Redis when `l2_cache_settings`
  is configured and an in-process map otherwise. See
  [`docs/configuration.md`](docs/configuration.md#choosing-the-backing-store).
- **Encryption at rest for cached responses.** An `encryption` block
  under `proxy.response_cache_store` seals cached headers and bodies
  with AES-256-GCM on the way to whichever backend you chose, so a
  cache directory or a shared memcached is no longer a plaintext copy
  of everything your upstreams returned. The key is a secret reference
  like any other in the config, so it stays out of the config file, and
  it should be 32 random bytes rather than a passphrase. `previous_keys`
  covers rotation: new writes seal under the active key while retired
  keys keep opening older entries. There is no plaintext fallback. A key
  that cannot be resolved stops startup instead of quietly caching in
  the clear, and an entry that fails its integrity check is evicted
  rather than served. Runnable example in
  [`examples/response-cache-encrypted/`](examples/response-cache-encrypted/).
- **Local classifier-based routing.** A `type: classifier` input guardrail
  embeds a prompt with a verified local ONNX model, chooses the nearest
  configured class centroid, and publishes the label to
  `ai.guardrails.labels`. CEL can turn that label into
  `route_to:<model>`, so the gateway routes on request intent without
  sending the prompt to a classifier service. Invalid or unresolved
  classifier artifacts remain inert, and score and margin thresholds prevent
  ambiguous labels. See
  [`docs/ai-gateway.md`](docs/ai-gateway.md#embedding-classifier) and the
  runnable
  [`examples/ai-classifier-routing/`](examples/ai-classifier-routing/).

### Changed

- **A reload that fails now really does change nothing.** Reloading a
  config installed a dozen pieces of process state (log redaction,
  cardinality caps, log sinks, the AI provider catalog, the key plane,
  detection singletons, Lua sandbox limits) *before* it got to the two
  steps most likely to reject the config. So a config that parsed but
  failed to build left the box running the new redaction rules and the
  new AI catalog against the old pipeline, while the log line said the
  previous config was still serving. Everything that can refuse a config
  now runs first, and nothing installs until every one of those checks
  has passed. `POST /admin/reload` also reports what happened rather
  than only whether it worked: the response carries `fully_applied` and,
  when a subsystem loaded with stale state, a `degraded` list naming it.
  A handful of subsystems are still allowed to fail without refusing the
  reload, because a stale AI catalog beats a proxy pinned on an old
  config, but they can no longer fail silently.
- **Changing `proxy.secrets` is refused instead of ignored.** The secret
  resolver owns live connections to Vault, AWS, GCP, or Kubernetes and
  is built once at startup, so a reload never actually rebuilt it. The
  change was dropped on the floor and the first reference to a
  newly-declared backend then failed at handler construction with an
  error naming the reference rather than the cause, long after the
  reload had reported success. Such a reload is now rejected outright
  with a message saying a restart is required, the way a cluster
  identity change already was. Rotating a secret inside your vault still
  needs no restart; only changing where SBproxy looks does. See
  [`docs/secrets.md`](docs/secrets.md).
- **The admin server no longer boots wide open on default credentials.**
  `admin` / `changeme` exists so a first run works, but nothing stopped
  it from being the credential on an admin API bound to `0.0.0.0` with a
  private-range allowlist and no TLS, which is a published password in
  front of key minting and config writes. Validation now refuses the
  default password when the surface is reachable from another host,
  meaning `bind` is not a loopback address or `allow_ips` contains an
  entry outside loopback, and the error names which of the two tripped.
  Loopback with the defaults is untouched, since that is the local
  development path. Three related soft spots went with it: an empty
  `allow_ips` denied nothing at the type level (the safe loopback-only
  default lived in an `if` at the one call site, so the filter itself
  was fail-open), loopback was matched by comparing text so an
  IPv4-mapped peer such as `::ffff:127.0.0.1` was turned away from a
  loopback-only server, and an unparseable `bind` silently fell back to
  `127.0.0.1` rather than failing, which made a typo in a wide bind look
  like it had worked. `sbproxy plan` also stops describing
  `proxy.admin.**` as a reload: `AdminConfig` is read once at startup, so
  a rotated admin password or a swapped certificate needs a restart, and
  the plan now says so. See [`docs/admin.md`](docs/admin.md).
- **Accepted configuration now has an accountable runtime owner.** GraphQL
  depth, introspection, and syntax controls are enforced before upstream
  dispatch; configured CEL feature flags publish atomically across reloads;
  concurrent limits can be keyed by client, API key, header, or route; and AI
  shadow requests run through a bounded, drop-on-saturation lane that cannot
  delay the primary response. Enabling the reserved HTTP/3 listener now fails
  configuration compilation instead of logging and continuing without QUIC.
  A build-time schema audit rejects future keys that have neither a production
  reader nor an exact reviewed `ConfigOnly` justification.
- **Workspace rate-budget behavior now has one owner.** The
  `rate_limit_budget` policy module owns the soft, throttle, and auto-suspend
  state machine and its tests. The previously ignored `per_route_rps` field is
  now a config error; use `rate_limiting` for a per-route ceiling. The
  `headers.include_ratelimit_policy` switch now controls the corresponding
  response header.

### Fixed

- **`GET /admin/drift` no longer invents drift after a hot reload.** The
  baseline it compares against was recorded at startup and by
  `POST /admin/reload`, but not by the file watcher or by `SIGHUP`. So
  editing the config file and letting the watcher pick it up left the
  running config correct and the baseline stale, and drift reported a
  difference that did not exist until the next admin reload or restart.
  Every path that loads a config now records the baseline.
- **Saving config from the admin console no longer leaks health probes.**
  Validating a config meant building the whole pipeline to see whether
  every module would construct, and that construction spawned the active
  health-check probes for any load-balancer target configured with
  `health_check`. The pipeline was then thrown away, but the probes were
  not: each one held the discarded pipeline alive and kept issuing real
  requests at the upstream on its own timer, forever. Every save in the
  admin console's config editor started another full set. An operator
  iterating on a config could leave a target being probed by a dozen
  generations of dead pipelines at once. Validation now constructs
  without starting anything that outlives the check, and the admin write
  path asks for a validation pipeline rather than a live one. The
  `validate` and `plan` subcommands were never affected, because they
  run outside an async runtime where the spawn was already a no-op.
- **Memcached cache keys are hashed.** Memcached rejects a key longer
  than 250 bytes outright, and a response-cache key carries the
  hostname, path, query, and Vary fingerprint, so any reasonably long
  URL produced a key the server refused. Those requests missed on every
  single read. Keys are now hashed before they go on the wire.
- **Memcached TTLs are clamped at 30 days.** The protocol reads any
  expiry above 30 days as an absolute Unix timestamp rather than an
  offset, so a longer configured TTL was stored as a moment in 1970 and
  the entry was dead the instant it was written. Relative TTLs are now
  capped at the protocol ceiling.
- **The file cache no longer discards entries it was asked to keep.** A
  stale-while-revalidate read deleted the entry it had just fetched, so
  the grace window it existed to serve was gone after one request.
- **Concurrent file-cache writes no longer tear.** Two threads writing
  the same key shared one staging file and could interleave their bytes
  into it, and the atomic rename then published the mixture. Each write
  now stages in its own file.

## [1.7.0] - 2026-07-22

The admin release. The console is rebuilt around the editorial brand
system, gains live sampled charts, and, most importantly, stops hiding
data the proxy was already collecting: request sessions, custom
properties, and the gateway's own decisions now reach the operator,
and the alerting engine finally has a face. Per-origin scoping runs
across the estate so a multi-tenant gateway reports per tenant.

### Added

- **Sessions.** Requests carrying `X-Sb-Session-Id` (and optionally
  `X-Sb-Parent-Session-Id`) are reconstructed into logical
  interactions. A session index ranks recent work by requests, tokens,
  cost, wall-clock duration, and worst status, indenting child
  sessions under their parent; a detail page reads one session's call
  chain oldest first with each call's gateway decisions, identifiers,
  AI route, tokens, cost, and properties. This is a view over the
  in-memory request ring, not durable trace storage.
- **Custom properties as first-class dimensions.** Bounded
  `X-Sb-Property-*` headers are captured, redacted per configuration,
  and carried on the request log, where they become filter and column
  choices. Properties named in an origin's `properties.rollup_keys`
  are promoted to durable spend dimensions, so the Spend page can
  group a window by a business dimension the caller supplied.
- **Gateway decisions on every request row.** The log now records what
  the gateway actually did: cache result, retry count, whether
  failover engaged and between which providers, the load-balancer
  strategy and target, and the guardrail outcome. The console reads
  them as one causal rail per row, answering whether the resilience
  configuration fired without opening a body.
- **Alerts page.** The alerting runtime is visible for the first time:
  rule thresholds, current reading, sample floor, and evaluation
  state; sanitized channel targets with delivery health and bounded
  errors; and recent fired, resolved, and test events. A targeted
  channel test exercises delivery without changing configuration.
  `sb.yml` remains authoritative and the page is read-only.
- **Live metrics.** The Metrics page samples the Prometheus endpoint
  and charts what happened between samples: request rate, error rate,
  latency percentiles from histogram bucket deltas, and AI token
  throughput, with numeric tiles and trend sparklines.
- **Per-origin scoping.** The attributed AI counters and the durable
  usage rollups carry the origin the request arrived on, and Metrics,
  Spend, Cache, and Logs can scope to one origin. Panels whose series
  have no origin dimension say so rather than showing unscoped numbers
  under a filter.
- **Context-compression reporting.** The compression policies report
  compressed requests, tokens and cost saved, per-lever savings,
  outcomes, and average ratio per lever.

### Changed

- **`sbproxy apply` now actually applies to the running proxy.** It used
  to compile the config into its own short-lived process, swap that
  process's pipeline, print `apply: reloaded config from ...`, and exit
  without ever contacting the proxy. A running server picked the change
  up only if its file watcher happened to notice the file, so exit 0 was
  not evidence that the config had been accepted, or even seen. A config
  the server would have rejected still exited 0. Apply now pushes the
  config over the admin API and reports what the server did with it, so
  the exit code means something: 4 if the proxy refused the config, 7 if
  no proxy answered, 8 if it loaded but a subsystem kept stale state.
  The admin endpoint defaults to `http://127.0.0.1:9090` and is
  overridable with `--admin-url` or `SB_ADMIN_URL`.

  **This changes the contract.** Apply previously needed no running proxy
  and always exited 0; it now needs to reach one. If you call `apply` in
  CI as a validation step, switch it to the new `--validate-only`, which
  runs every check and stops without contacting anything. That flag is
  the honest name for what the old behavior was actually doing.


- **The admin console follows the sbproxy.dev editorial system.**
  Paper and ink surfaces, a persistent top bar carrying the admin
  host, a live health dot, and the cluster node count, mono
  microcopy, and square corners. Every mutation confirms or fails
  through a toast; validation detail and revision conflicts stay
  inline next to the form that caused them.
- **The admin rate-limit default is 240 requests per minute per
  client IP**, up from 60, with the global cap still ten times that.
  A busy console no longer trips its own limiter.

### Fixed

- **Cache hit and miss counts are no longer always zero.** The Cache
  page read a metric name the server never emitted.
- **The playground reaches locally served models.** A chat against a
  served or managed deployment returned 404 because the request
  skipped the runtime's endpoint resolution and fell back to a
  localhost URL pointing at the proxy itself.
- **Spend groups by a promoted property.** The group-by parameter was
  read without percent-decoding, so the console's own
  `property:<key>` selection failed as an unknown dimension.
- **Spend history reports a disabled rollup store as a hint**, not as
  a failed view.
- **The overview lists managed models by name** with their reserved
  memory, instead of "unknown".
- **An engine that dies after reaching readiness reports why.** The
  health path now carries the bounded, redacted stderr tail into the
  retained error rather than logging only that the process exited.

## [1.6.2] - 2026-07-21

### Added

- **The local llama.cpp engine pin follows your macOS version.** Pinned
  builds now carry their measured minimum macOS, and the host selects the
  newest compatible one: macOS 26 gets the current build, macOS 14 and 15
  get the newest build published against the older toolchain. Previously
  the single pin targeted macOS 26 and died at dynamic-link time on
  anything older. A host older than every pin fails before download with
  the versions named; an explicit `version:` still wins.

### Fixed

- **Loading the admin UI no longer spends the admin rate budget.** Static
  UI bundle assets are exempt from the per-IP admin rate limiter, so
  opening the dashboard cannot starve API polling behind 429s.
- **`sbproxy --version` reports the real product version** instead of a
  stale crate stub.
- **The installer reports the binary it just installed**, not whatever an
  earlier install left on PATH.

## [1.6.1] - 2026-07-21

A point release fixing operational defects found immediately after the
1.6.0 cut.

### Added

- **Configurable admin rate limit.** `proxy.admin.rate_limit_per_minute`
  (default 60, the previous hardcoded value; valid 1 to 100000). Automation
  and dashboards that poll admin endpoints faster than once per second per
  node can now raise the cap instead of silently reading 429s.

### Fixed

- **Docker images start again.** The published linux binaries are built
  against glibc 2.36 so the container runtime image can execute them.
- **Gateway-only clusters no longer report a standing pseudo-outage.**
  Nodes without the worker role are not graded on the model plane, so a
  cluster of pure gateways shows healthy nodes in `/admin/cluster/status`
  and dashboards instead of a permanent degraded state. Worker health
  semantics are unchanged.
- **Model engine launch failures are diagnosable.** A failed engine start
  logs its bounded, credential-redacted stderr tail instead of holding it
  only in memory, and the release certification artifact carries the boot
  log and durable job records.

## [1.6.0] - 2026-07-20

The cluster release. The mesh gains durable replicated state, governed
budgets that mean the same thing on every node, full
self-instrumentation, and a Kubernetes operator that forms it. Local
model serving grows a real deployment control plane and serves across
nodes, tensor-parallel GPU groups, replicas, LoRA adapters, and a
second Python engine. Two load-time behavior changes to note under
Changed: invalid `retry_on` entries and `max_attempts` above 16 now
fail the load, and `sbproxy validate` now fails a config that would
refuse to boot. The serve-related YAML fields remain unpinned, as in
v1.5.0.

### Added

- **Managed model deployments.** Local serving gains a real control
  plane: a canonical `model_host.deployments` desired state (existing
  `serve:` entries lower onto it), content-addressed weight artifacts
  with resumable sha256-verified pulls and protected LRU garbage
  collection, durable deployment revisions and operation jobs, and one
  process-wide runtime manager for atomic reload, warm rolling or
  recreate rollouts with capacity preflight and rollback, admission,
  keep-alive, idle eviction, drain, health, and crash-loop retention.
  Operated through authenticated lifecycle APIs and `sbproxy models
  pull / list / show / ps / stop / remove`.
- **Governed multi-node model serving.** A fleet of gateways serves one
  model estate: constrained node enrollment with strict manual-PKI
  identity verification, a model directory carrying the full node
  roster with stable exclusion reasons and explicit unhealthy-node
  callouts, deterministic capability-aware placement with rolling
  handoffs, durable generation fencing, and signed deployment-authority
  state. A dedicated private HTTP/2 model plane (production mTLS,
  signed one-hop dispatch envelopes, bounded replay protection) routes
  governed requests across current-generation local and peer replicas
  with coordinated cold starts, streaming backpressure, client
  cancellation, and failover only before any client output. Model
  discovery stays OpenAI-shaped and topology-free.
- **Tensor-parallel groups and N replicas per node.** The fit planner
  searches tensor-parallel degrees 1, 2, 4, and 8 over homogeneous GPU
  groups and picks the smallest degree at which a candidate quant fits,
  so a model larger than the largest single card (a 70B at fp16 needs
  about 140 GB) shards across a group instead of being unservable. A
  deployment can also run several replicas of one model on disjoint
  device sets of the same node, so a dense GPU box no longer idles its
  other cards; asking for more replicas than the node can hold fails
  with a reason naming the shortfall.
- **The fit planner understands model shape.** Catalog entries carry a
  `modality` (`chat`, `embedding`, `rerank`, `speech_to_text`,
  `text_to_speech`, `image`): a non-decode model stops being charged
  autoregressive KV-cache VRAM, vLLM launches an embedder in embed
  mode, and a locally served embedder answers `/v1/embeddings` instead
  of a blanket 501. A mixture-of-experts model that does not fit VRAM
  whole keeps attention, shared, and dense tensors on the GPU and
  spills the fewest whole expert layers to CPU RAM (llama.cpp's
  `--n-cpu-moe`), which is how a 30B-A3B-class model runs on a 12 GiB
  card. The planner also predicts decode throughput per placement,
  calibrated against live A100 measurements.
- **SGLang engine driver.** `engine: sglang` serves safetensors models
  on CUDA through SGLang, acquired via `uvx` or a digest-pinned
  container and dispatched over the same OpenAI shape as vLLM. vLLM
  stays the default; SGLang is a one-line opt-in for prefix-heavy agent
  traffic, where the measured head-to-head favors it. The benchmark
  behind that guidance is published in
  `docs/serving-engine-benchmark.md`.
- **Container engine provisioning is the default when a runtime is
  present.** Standing up vLLM from a bare host environment needs its
  whole build toolchain and fails in a cascade on a stock GPU box, so
  when docker or podman is on PATH and the operator has not configured
  provisioning, the Python engines (vLLM, SGLang) now provision from
  curated digest-pinned container images, the exact digests validated
  on real GPU hardware. The host `uvx` path remains available by
  configuration.
- **The embedded in-process engine moves to mistral.rs 0.9**
  (PagedAttention default-on for CUDA, CUDA graphs, FlashInfer). The
  dependency stays opt-in and off by default.
- **Accurate prompt token counting with a pre-flight context-fit
  gate.** Locally served models count prompt tokens against the
  model's own tokenizer (prefetched alongside the weights, parsed once,
  cached) instead of a chars/4 heuristic, and an over-context prompt is
  rejected before dispatch with a clear error instead of failing
  opaquely inside the engine.
- **LoRA adapters over one resident base model.** A vLLM serve entry
  with `lora_adapters` launches the base model with each adapter
  registered by name, so a client requests a fine-tune by name over one
  resident base instead of paying for a separate engine per fine-tune.
  vLLM-only for now; other engines reject the fields with a clear
  reason.
- **Per-deployment engine tuning and version pins.** Canonical managed
  deployments carry the engine tuning knobs (`chunked_prefill`,
  including a TTFT-target mode that derives the batch size,
  `tool_call_parser`, `swap_space_gib`, `cpu_offload_gib`,
  `extra_args`), and the vLLM passthroughs now actually reach the
  engine instead of being rejected at prepare. A deployment can pin its
  own `engine_version` / `engine_image` / `engine_sha256` over the
  node-wide engine policy, so two models on one node can run different
  vLLM versions (canary an upgrade on one model, hold another to its
  certified version); `latest` versions and unpinned images are
  rejected at config validation, and the served engine version surfaces
  in deployment status.
- **Per-completion local-vs-cloud savings.** A serve entry can declare
  the hosted model it displaces and that model's per-million-token
  price in a `reference:` block; every completion the local model
  serves is priced at the reference into a durable ledger, and
  `GET /admin/model-host/value` reports completions and dollars saved
  per model. Explicit config only: no reference means no savings claim,
  never a guessed cloud price.
- **`sbproxy update` acts on stale artifacts.** A plain run now
  fetches, verifies, and atomically swaps a stale engine prebuilt, and
  `--self` replaces the sbproxy binary from its release channel;
  `--check` keeps the report-only behavior. A pinned artifact, or one
  managed elsewhere (a `path`, brew, or apt engine), is reported and
  never mutated; the new `update.{channel, auto, check_interval}`
  block configures it, and `auto` only ever reports in the background.
- **Weight-cache and artifact management.** The admin plane gains a
  verified-artifact inventory (`GET /admin/model-host/files`),
  fail-closed artifact deletion, on-demand garbage collection, per-node
  cluster artifact totals, and a Storage view in the admin UI. A cache
  miss can reuse a discovered Ollama, LM Studio, or Hugging Face cache
  read-only instead of re-downloading weights. `sbproxy models lock`
  pins resolved artifacts to a lockfile, `models verify-lock` reports
  drift, and `--locked` refuses to serve anything off-lock. `sbproxy
  models prune` reclaims content-addressed weight blobs no cached
  artifact references.
- **Served-model priority lanes.** `serve.max_concurrent_requests` caps
  in-flight requests into a local engine behind a queue ordered by the
  calling key's `priority` lane (`interactive`, `standard`, `batch`),
  FIFO within a lane, so a batch flood cannot starve interactive keys;
  an interactive request that would queue spills immediately to the
  next non-served provider when one exists. The lane binds to the key
  record, never a client header.
- **Governed key policy enforces end to end.** One canonical
  effective-policy contract covers configured and dynamically stored
  keys, and lifecycle, tenant, model, provider, route, principal, PII,
  tool, prompt-injection, rate, budget, and admission policy all act on
  the live request path; admin mint, preview, and revisioned PATCH are
  fail-closed and the Keys UI is driven by the server's schema. Keys
  gain a working per-key tokens-per-minute cap, a priority lane,
  `inject_mcp` on dynamically stored keys, and PATCHable metadata, and
  immutable key and attribution dimensions propagate through usage,
  access logs, metrics, traces, and bounded audit events.
- **Cluster-coherent governed-key budgets.** A governed key's request,
  token, and cost limits enforce through a reserve-then-settle flow on
  the live AI path and mean the same thing on every gateway node, in
  two tiers: approximate (the default; each node disseminates settled
  usage over the mesh and admission weighs the whole fleet's spend
  within a bounded staleness window, no external database) and strict
  (atomic reserve and settle against a shared Redis backend, so two
  nodes cannot both admit a request only one has budget for). Strict
  without a Redis backend fails config validation.
- **MCP guardrails.** Deterministic OpenAPI-derived egress policies
  with redirect-target validation, lethal-trifecta session risk
  tracking and enforcement, opt-in dual-LLM quarantine, run-as-user
  credential minting that carries the caller's own Authorization on the
  federation wire, token compaction, and a supervised local stdio MCP
  transport.
- **Traffic governance fills out, and LiteLLM import stops dropping
  keys silently.** OTel, S3, and GCS usage sinks join the existing sink
  set; purpose-scoped egress, quota headroom- and reset-aware routing,
  and local fair-share pools land alongside them. `config
  import-litellm` now classifies every unknown key as mapped, warned,
  or unsupported instead of silently dropping it, and known sink
  callbacks and `max_budget` emit real config.
- **Durable replicated cluster state.** `proxy.cluster.replication`
  turns the mesh's single-owner in-memory state into a replicated,
  durable substrate: each key maps to a preference list of nodes on the
  existing hash ring, writes and reads choose `one`, `quorum`, or `all`
  consistency with read repair, every replica persists write-through to
  redb so an owner restart loses nothing, deletes replicate as
  tombstones collected only after every replica confirms them and a
  grace period passes, and fleet admin runs over topology-safe bounded
  pagination.
- **The mesh reports on itself.** Gossip probe round-trip time and
  indirect-probe retries, enrollment outcomes, transport RPC errors by
  phase and durations by operation, owner-routing outcomes, and a live
  peer-count gauge; every mesh metric now sits in the executable
  stability catalog under the sanctioned `mesh_` prefix.
- **The Kubernetes operator forms the mesh.** With
  `spec.clustering.enabled`, the operator reconciles a StatefulSet
  (stable per-pod identity, one-peer-at-a-time rolling restarts), a
  headless Service publishing the gossip and transport ports, a
  shared-key Secret, and a rendered `proxy.cluster` block with
  full-ordinal seed lists and per-pod node identity, built through the
  typed config so invented fields are impossible. Includes the two
  fixes live validation on kind surfaced: the operator now installs its
  TLS crypto provider (it previously panicked on its first handshake
  and reconciled nothing), and DNS-name gossip seeds resolve before the
  probe path (they were silently skipped, leaving every pod a one-node
  mesh).
- **Compression session state can live on the mesh.** Stateful
  compression's `state.backend: mesh` now runs on the durable
  replicated substrate: conditional versioned session commits with
  deterministic cross-node conflict resolution, tombstoned deletes that
  survive partition and heal, and the same admin list, inspect, and
  purge over fleet pagination. Redis remains the default and
  recommended backend.
- **Measured 3-node cluster benchmark.** `docs/performance.md` gains a
  clustered section from a real 3-node GCP mesh run: forming the mesh
  costs within noise on a single node (43,129 vs 43,958 requests per
  second), three nodes sustain 119,178 requests per second aggregate
  with zero errors, governed spend becomes visible on a peer in 15 to
  20 seconds, and survivors run at 100% success through a mid-run node
  kill, with rejoin about 10 seconds after restart.
- **Request-selectable AI context compression.** Declare named route-local
  profiles and explicit input budgets, then select them through
  `X-Compression`, governed virtual keys, or CEL with deterministic precedence
  and safe invalid-selector behavior. Phase 1 adds `rag_select`,
  `compact_serialization`, and `position_reorder` for explicit line-delimited
  retrieval blocks. The levers use deterministic ranking, reversible
  `sbproxy_table_v1` encoding, closed fail-open outcomes, and semantic-cache
  bypass before the final `window_fit` bound. Stateful summaries use Redis as
  the canonical session store while request workers remain stateless;
  authenticated Admin APIs list, inspect metadata for, and purge that state.
  Per-lever results now appear in bounded metrics and one content-free summary
  event per executed pipeline; reducing levers also feed bounded value metrics,
  dashboards, and the model-host value report. Live request-path acceptance and
  five independently authored structural smoke reports cover the production
  stateless pipeline.
- **MCP tool rollout plane.** Publish several versions of one tool at once
  and roll out breaking changes without breaking callers: a `rollout:` block
  under the `mcp` action's `tool_versioning` declares versions, where each
  routes, and who gets which. Resolution walks a ladder (per-call `_meta`
  requirement, per-session requirements declared at `initialize`, operator
  pins on the authenticated principal, `search_v1`-style catalog aliases,
  then the default), all as semver ranges. Old versions can route to the
  upstream that still serves them or run JavaScript request/response
  adapters against the new one, carry a sunset date that warns or blocks
  past it, and every versioned call lands on
  `sbproxy_mcp_tool_version_calls_total{tool, version, via, deprecated}` so
  migration is observable. `tools/list` advertises the consumer's resolved
  version per tool with the available versions and sunset in `_meta`;
  results carry the version that served them. The `tool_versioning.lockfile`
  is now optional so the rollout plane works without the version-bump gate.
  See `docs/tool-versioning.md` and `examples/mcp-tool-rollout/`.
- **Model deployment management in the built-in admin UI.** Operators can
  browse catalog evidence, add or edit the complete desired deployment map,
  resolve revision conflicts explicitly, and run Load, Stop, or Reset. The
  same UI respects file-managed, admin-managed, and signed cluster-authority
  ownership; file-managed and verifier nodes stay read-only.
- **Cluster operations and unhealthy-node alerts in the admin UI.** The
  Cluster page now shows every node, placement and rollout state, deployment
  authority, and prominent links to unhealthy roster entries. Health remains
  visible when metrics fail, and the last cluster snapshot stays on screen
  with a stale warning after a refresh error.
- Streaming responses now run every built-in output guardrail, with
  verdicts matching the buffered path. A per-stream session matches the
  substring guardrails (injection, toxicity, jailbreak, content safety)
  over a cumulative window of decoded deltas, so a pattern split across
  chunk boundaries still blocks, and word-boundary rules never
  false-block on split words.
- Streamed tool calls are assembled per call and judged by the
  agent-alignment guardrail as each call completes. Block mode holds
  tool-call frames until their call is judged while text keeps flowing;
  flag mode logs and counts without touching the stream.
- Per-entry `stream_policy` (`chunk`, `close`, `off`) on output
  guardrails, plus new metrics:
  `sbproxy_ai_stream_guardrail_violations_total`,
  `sbproxy_ai_stream_guardrail_skipped_total`, and
  `sbproxy_ai_stream_guardrail_decode_fallback_total`.
- A TPOT histogram (`sbproxy_ai_inter_token_latency_seconds`)
  completing the TTFT / TPOT / throughput serving triple, OpenMetrics
  exemplars on the AI latency histograms so a spike links to its
  trace, and the OTel GenAI metric instruments
  (`gen_ai.client.operation.duration`, `gen_ai.client.token.usage`)
  mirrored over OTLP so GenAI-aware backends chart without relabeling.
- `headers:` on the telemetry block for authenticated OTLP export to
  hosted backends. Values accept secret references that resolve at
  boot and fail loud, apply to traces, mirrored metrics, and the
  OTLP log sink, and are masked in config printouts. Every signal now
  carries detected resource attributes (host, process, Kubernetes
  downward API, `OTEL_RESOURCE_ATTRIBUTES`), with explicit
  `resource_attrs` winning conflicts.
- Durable windowed spend rollups: hour and day usage buckets that
  survive restarts, a windowed `/api/usage/spend`
  (`window`/`group_by`/`from`/`to`), and a spend-history section on
  the admin Spend page. On by default with bounded retention; rows
  carry no prompt content and no raw key material.
- Access log AI columns: `cost_usd_micros` (integer micro-USD) and
  `guardrail_category` / `guardrail_action` on every guardrail
  intervention, mirrored onto the request envelope and the admin
  request ring; `/api/requests` accepts `guardrail_action` and
  `guardrail_category` filters.
- Slack and PagerDuty alert delivery channels as formatters over the
  existing webhook transport (PagerDuty trigger/resolve keyed on a
  stable per-rule deduplication key), plus Prometheus alert examples
  for AI budget utilization, provider error burn, and spend velocity.
- MCP `execute_tool` spans following the OTel GenAI agent
  conventions, parented into the caller's trace so agent request,
  tool dispatch, and LLM calls render as one tree; the AI request
  span emits tool-call span events (ids and names always, arguments
  only under `trace_content`).
- Admin views: AI performance (TTFT / TPOT / throughput and provider
  health with failovers, cascade tiers, and router decisions), Spend
  (live attributed cost, token, and request breakdowns by model,
  provider, key, team, and project),
  Guardrails (blocks by category and wasted tokens / spend by kind),
  live tail on the Logs view with full-record row expansion and
  operator-configurable trace deep links
  (`admin.trace_url_template`).
- **Executable capability registry.** SBproxy's claims about itself are
  now checkable code: every capability claim carries a support level,
  nothing may be called stable unless a test proves a production caller
  consumes it, and config-only is the honest, permitted name for a
  surface that parses and does nothing. Build guards fail on a
  published metric no code writes and on a tenant-relevant metric
  family missing its tenant labels, and the shipped Prometheus alert
  rules are validated with promtool in CI. This machinery surfaced the
  availability SLO that read 100 percent forever and the
  never-incremented metric families fixed in this release.
- **Getting started and framework integrations.** A dedicated
  `docs/getting-started.md`, install and quick start grouped together
  in the README, and five framework one-pagers (LangChain, Vercel AI
  SDK, Pydantic AI, Mastra, n8n) whose snippets were all executed
  against a running gateway before landing. The README lede now leads
  with what the gateway does today.

### Changed

- **`sbproxy validate` runs the boot path.** `validate`, `plan`, and
  `apply` now construct the same compiled pipeline the server and
  reload paths construct, so a config that would refuse to boot fails
  validation instead of validating clean (measured before the change:
  five published examples validated but refused to boot). Custom YAML
  tags are rejected at compile: serde_yaml strips unknown tags, so a
  `password: !env ADMIN_PASSWORD` silently became the literal string
  `ADMIN_PASSWORD`; the error now points at `${VAR}` interpolation,
  and `${VAR:-default}` fallbacks work.
- **Status-code upstream retries moved onto a dedicated decision
  hook.** The retry decision fires on the pinned Pingora fork's new
  upstream-response hook, once per upstream response and before any
  bytes reach the client, replacing the response-filter workaround;
  connect-time and status retries now share one attempt counter and
  cap. Load-time validation is a behavior change: a `retry_on` entry
  must be `connect_error`, `timeout`, or a status in 100..=599 (junk
  entries used to deserialize and silently never match; they now fail
  the load naming the entry), and `max_attempts` above 16 is rejected.
  Retries land on
  `sbproxy_upstream_status_retries_total{origin, status}`.

### Fixed

- **`retry_on: timeout` is honored, in both upstream phases.** The
  token was accepted and documented but nothing consulted it. A
  connect-phase timeout now retries under either `timeout` or
  `connect_error`, and an established-connection upstream read or write
  timeout retries when the policy allows it, sharing the same attempt
  cap, and only when the request is replayable and no response bytes
  have reached the client. The fork's retry loop also gains a backstop
  refusing any retry after response bytes were sent, regardless of what
  marked the error retryable.
- **Redis L2 connections keep their TLS, AUTH, and database
  semantics.** `redis://` and `rediss://` URLs preserve ACL and
  percent-encoded credentials, IPv6 hosts, the selected database,
  private CAs, and mutual TLS uniformly across the general L2 store,
  compression state, and admin paths, compiled once per config
  generation into an immutable connection snapshot. The blocking
  plaintext RESP path is replaced with a real client, and connection,
  TLS, authentication, and command failures classify without leaking
  endpoints or credentials.
- **Cross-node mesh RPCs no longer stall about 40 ms on Linux.** The
  transport wrote a frame's length prefix and body as two separate
  writes and never set TCP_NODELAY on accepted sockets, so Nagle plus
  the delayed-ACK timer held every response leg. Frames now leave as
  one write and the server sets nodelay on accept; a small-frame
  replica fetch drops from about 41 ms back to sub-millisecond.
- **The MCP gateway speaks the spec's camelCase on the wire.**
  `initialize` results, tool results, and tool annotations serialized
  as snake_case (`protocol_version`, `is_error`, `read_only_hint`),
  which the official TypeScript SDK's schema rejects outright, so a
  strict client could not connect at all and tolerant clients silently
  dropped tool error flags. Serialization is now camelCase; snake_case
  still parses so results from older nodes survive mixed-version
  rollouts.
- **Raw `hf:` references serve through the live path.** The production
  runtime manager only resolved fully pinned catalog artifacts, so a
  raw `hf:Org/Repo` reference in a `serve:` block failed reconciliation
  and, in practice, no open-weight model could be served on a GPU from
  the gateway. Raw references now resolve, pull, and serve end to end,
  validated on real multi-GPU NVIDIA hardware across vLLM, SGLang,
  embeddings, and tensor-parallel launches.
- **SGLang serving hardening.** The launcher passes a runtime-owned
  memory fraction so SGLang no longer OOMs at launch; liveness probes
  hit a non-generating endpoint instead of one that generated tokens
  (and returned 503 under load); one transient health-probe miss no
  longer kills a ready engine; and the probed SGLang version is
  recorded on the provisioned engine.
- **Self-host admin edges.** Attributed AI token and cost metrics now
  populate `/api/usage/spend` for locally served providers; direct AI
  responses no longer log status 0 when a real response was written; an
  upstream-TLS native-certificate failure on macOS is an actionable
  startup error instead of a panic; and the admin Keys UI submits the
  backend's full key-policy shape.
- **The `alerting:` block alerts, and declared metrics record.** The
  alerting config parsed and silently discarded its settings; it now
  drives a live dispatcher (delivering through the Slack and PagerDuty
  channels above). The response-cache hit/miss, circuit-breaker
  transition, and guardrail-block families were declared and scraped
  but always zero; they are now written by the live request path, and
  the metric drift guard follows aliased writers it was blind to.
- **The release provenance push no longer clobbers the SBOM
  attestation.** The provenance step replaced the image's attestation
  tag wholesale after the CycloneDX attest step, so
  `cosign verify-attestation --type cyclonedx` failed on every
  published image; the jobs are reordered so the SBOM attestation
  appends last, and the offline verification recipe in
  `SUPPLY-CHAIN.md` now works with current cosign.

### Removed

- The unattributed AI metric families `sbproxy_ai_requests_total`,
  `sbproxy_ai_tokens_total`, `sbproxy_ai_cost_dollars_total`, and the
  per-virtual-key trio. They were registered but never written on the
  live path, and counter series register lazily, so no released
  binary ever exposed a sample under these names. Consumers read the
  attributed families; details in docs/metrics-stability.md.
- **The Go-era `secret:<name>` colon form.** It resolved through a
  logical-name map with an environment fallback and was superseded by
  the provider-URI `secret://<backend>/<name>` schemes; a stale
  reference now fails config load with a migration pointer instead of
  resolving through a side channel. `proxy.secrets.map` still parses
  for schema-v1 compatibility and warns at boot that it has no effect.
- **Dead mesh scaffolding and write-only key counters.** The
  unreferenced leader-election, health-monitor, consistency, and
  membership-protocol modules are gone (live membership is the gossip
  loop), along with a legacy wire variant only tests constructed and
  the per-request mesh key counters that were incremented on every AI
  request but never read anywhere. Governed-key budget enforcement is
  unaffected, and the AI hot path now does no counter work at all.
- **Two dead metric families**: `sbproxy_dedup_cache_size` (registered,
  never written, no readers) and the hostname-keyed
  `sbproxy_cache_hits_total` duplicate; the overview dashboard reads
  the now-live `sbproxy_cache_results_total` instead.

## [1.5.0] - 2026-07-08

Model serving lands: run open models on your own GPU behind the same
gateway that fronts the 66 hosted providers, plus the engine-acquisition
and self-host work queued since v1.4.0. No promises about backward
compatibility for any of the new YAML fields below until a later version
pins them.

### Changed

- **Duration strings parse consistently everywhere.** The `ms`/`s`/`m`/`h`/`d`
  units, compound forms like `1h30m`, decimals like `1.5h`, and a bare
  number (seconds) are now accepted by every duration field, instead of
  each config block supporting a different subset (so a value like `1h`
  that parsed in one block and errored in another now works in both). This
  only widens what is accepted; no previously valid value changes meaning.
- **Unresolvable upstream hosts always fail closed.** The upstream SSRF
  guard no longer blocks the request worker on a per-request DNS resolve
  (it resolves asynchronously now), and as part of that an upstream host
  that fails to resolve is uniformly rejected, closing an edge where an
  origin with a private-CIDR allowlist could previously fail open.

### Removed

- **Two rate-limit config options that parsed but never enforced anything
  are gone.** A virtual key's `max_tokens_per_minute` (and the credential
  policy's `tpm`) and an origin's per-origin `rate_limits:` block both
  compiled and round-tripped but were never read at request time, so an
  operator who set them believed they were capped when they were not.
  They are removed rather than wired. Existing configs that still set
  these keys keep loading (the keys are ignored). The live limits are
  unaffected: the top-level workspace `rate_limits:` budget, and the AI
  gateway's `model_rate_limits` / per-surface limits, all still enforce.
- **Two build-only feature flags that nothing enabled were removed**
  (`sbproxy-platform/postgres-store` and an unused `sbproxy-modules`
  rate-limit feature), along with roughly 4,300 lines of verified
  zero-caller internal code. No shipped configuration or public API
  changes; the redb/SQLite storage stack is unaffected.

### Added

- **vLLM, provisioned with `uvx`.** vLLM is a Python package, not a
  single-binary release, so sbproxy now acquires it by fetching `uv`
  (Astral's single-binary package manager) and running the engine through
  `uv tool run` (`uvx`): a cached, ephemeral environment that uv sets up
  on first use, bringing its own Python if the host lacks one. The default
  wheel is CUDA-enabled, so a safetensors model offloads to an NVIDIA GPU
  on a box that carries only the driver. Opt in with
  `engines.vllm.acquire.source: uvx`; `sbproxy run <model>` sets it for
  you. `sbproxy doctor` reports it as the recommended vLLM path.
- **`sbproxy update`: is any of it out of date.** A dry-run freshness
  report: `sbproxy update` checks the inference engine release feed (the
  pinned llama.cpp prebuilt vs the latest) and the cached models (flagging
  any that track a moving ref like `main` and could be behind upstream);
  `--self` also checks the sbproxy binary against its release channel.
  `--json` for tooling. Reports only, nothing is mutated; a pinned artifact
  is never swapped without an explicit run.
- **`sbproxy config print`: see the effective config, with secrets
  masked.** Prints the config after built-in defaults + the file +
  `${ENV}` interpolation, so it is obvious what a box will actually do.
  Inline secret values (an `api_key`, `client_secret`, `token`, ...) are
  masked; secret *references* (`vault://`, `${ENV}`, `file:`, ...) are
  shown, since they are pointers, not the secret. `--json` for tooling,
  YAML by default.
- **`sbproxy models list` / `show`: discover what this host can run.**
  `sbproxy models` (or `models list`) prints one row per catalog model
  with a real per-GPU fit verdict (reusing the same probe `doctor` uses),
  the resolved engine, params, and cache status (cached / not-pulled).
  `sbproxy models show <id>` prints the full entry: HF repo, source,
  revision, sha256 digests, engine, pull policy, and quants. `--json` on
  both for scripts and the admin UI; `--catalog-file` points at an
  operator manifest. Resident / serving state needs a running gateway and
  is not shown by this offline view.
- **`sbproxy run <model>`: serve a model in one command, no YAML.**
  `sbproxy run qwen3-14b` (or `sbproxy run hf:Org/Repo:Q4_K_M --name
  coder`) synthesizes a minimal serving config, checks the model can run
  on this host (the same detection `sbproxy doctor` uses, so a model with
  no viable engine fails now with a remediation instead of a later 502),
  and boots the gateway with an OpenAI-compatible endpoint on loopback at
  `http://127.0.0.1:<port>` (both the IP and `localhost` route). The
  engine and weights are acquired on the first request. Flags override
  the port, engine, acceleration, and cache directory; `--dry-run` prints
  the resolution and the synthesized config without serving.
- **Model pull honors manifest pins and works for safetensors/vLLM on a
  fresh box.** A model's weight pull now uses the manifest `revision`
  (was hard-coded `main`) and verifies the per-file `sha256` when one is
  pinned, so a digest mismatch fails the pull loudly instead of serving
  bad weights. And a safetensors model served via vLLM now pre-fetches
  its `config.json` on first use, so it admits on a box that has never
  pulled it (previously it failed with "no model metadata").
- **sbproxy acquires the inference engine, not just finds it on PATH.**
  A `serve:` block can now carry a per-engine `engines.<engine>.acquire:`
  block: for llama.cpp, `source: release` (the default) fetches a pinned
  ggml-org prebuilt for the host platform and acceleration
  (`accel: auto|cuda|vulkan|metal|cpu`; on Linux a GPU build means the
  Vulkan asset, since there is no upstream CUDA Linux prebuilt),
  sha256-verified when a digest is pinned, while `source: path` points at
  an operator-installed binary for an air-gapped box. A host with no
  engine now serves a GGUF model instead of failing at the first request,
  and a bad acquisition (a `path` source with no path, a `latest`
  version) is rejected at config load, not at runtime. Engine identity
  stays the allowlisted set (`vllm`, `llama_cpp`, `embedded`); only how
  the binary is obtained is configurable. The gateway also detects a
  container runtime now, so `engine: auto` can resolve to vLLM's
  container path for safetensors weights.
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
- **`sbproxy doctor` is the self-host front door.** The subcommand now
  reports the full picture of what the binary can do on this host and
  how to make it serve: OS and arch, CPU and RAM, free disk in the cache
  directory, the GPU (or CPU / unified-memory budget) the `serve:`
  admission path sees, NVIDIA driver and CUDA / Metal / ROCm, container
  runtimes and daemon liveness, package managers, Python and uv, and
  Hugging Face reach plus whether `HF_TOKEN` is set. For each engine
  (llama.cpp, vLLM, embedded) it lists what is installed (with version)
  and which acquisition sources are viable here, each with a reason.
  Pass a config file (`sbproxy doctor sb.yml`) and it adds, per `serve:`
  model, what `engine: auto` resolves to and a coarse fit preview, and
  exits non-zero when a configured model has no viable engine.
  `--format json` emits a stable machine-readable report; collection is
  read-only.
- **Local model serving runs on Macs and CPU boxes, not just NVIDIA.**
  The fit planner used to see zero devices on anything but an NVIDIA GPU,
  so a `serve:` block on a Mac or a GPU-less server rejected every model.
  The GPU probe is now layered: NVIDIA discrete GPUs first, then Apple
  Silicon unified memory (reported as the working-set budget), then a CPU
  budget sized to a fraction of system RAM. A small GGUF is admitted
  against unified memory or RAM and served by llama.cpp or the embedded
  engine; FP8 and other datacenter quants are still refused on hardware
  that lacks the kernels. Set `SBPROXY_CPU_MEMORY_FRACTION=0` to opt back
  into rejecting admission on a GPU-less host. The weight cache defaults to
  `~/.cache/sbproxy/models` for a non-root run (and the service path
  `/var/lib/sbproxy/models` when running as root), so serving works out of
  the box without configuring `cache_dir`.
- **Serve-preflight warnings at config load.** A config that declares
  `serve:` on a host with no visible GPU, or with a serve entry whose
  engine has no binary and no container runtime, now logs a warning at
  startup and on every hot reload naming the model, the resolved
  engine, and the blocker, instead of degrading silently until the
  first request fails over.

### Changed

- **A forward rule whose header matcher names an invalid HTTP header now
  fails at config load.** The `header:` matcher on a `forward_rules:`
  entry precompiles its name at load time; a name that is not a valid
  header (for example one containing spaces) previously loaded and then
  silently never matched, and now reports a clear error at load and on
  reload. Valid configurations are unaffected.

### Fixed

- **Revoking a key now blocks OIDC/JWT identities mapped to it.** With
  `key_management.oidc_claim_map` configured, a verified token whose mapped
  claim named a revoked, blocked, or expired record was silently downgraded to
  an ungoverned request (no per-key policy) instead of being denied. The
  mapped-claim path now mirrors the bearer path: an inactive record denies with
  403, a claim naming a missing record denies with 401, and a store outage
  fails closed unless `failure_mode_allow` is set. Tokens that carry no mapped
  claim are unaffected.

- **Error responses now emit valid JSON when the message contains a quote or
  backslash.** The shared `send_error` helper and the ledger, policy, and
  storage error paths built the `{"error": "..."}` body by string
  interpolation, so a message carrying a client-supplied value (for example a
  rejected AI `model` name) could break the JSON envelope or inject a sibling
  field. Every error body is now serialized, so the message is always escaped.

- **JSON threat protection now scans the whole request body.** The depth, key,
  and size checks read only the first body chunk, so a JSON payload whose
  oversized structure began past the first chunk could slip past the scan while
  the full body still reached the upstream. The scan now accumulates the
  complete body, bounded by `max_total_size` (or a hard ceiling when unset),
  before validating it.

- **The in-memory idempotency cache and the native SSE reassembly buffer are
  now bounded.** The single-instance idempotency store grew without limit under
  unique keys and is now a capacity-bounded LRU. The native streaming framer
  buffered upstream bytes until a frame boundary and now caps the reassembly
  buffer, so an upstream that never closes a frame cannot grow it without limit.

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
- **Open-source mesh clustering.** The mesh layer (SWIM gossip, a
  consistent-hash distributed cache) is now Apache-2.0 in this repository.
  Setting `cache.tier: mesh` keeps the key plane coherent across a replica
  fleet: a key minted on one replica is usable on any, and a revocation on
  one denies on the rest, with no external control plane in the path. Per-key
  spend and rate counters remain node-local; cluster-wide budget enforcement
  uses a shared backend. (#542)
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
  Operators who want the legacy behavior add `default_allow: true`
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
  `request_id` alone); the field-key redaction marker is normalized
  to `[REDACTED:<NAME>]` everywhere (was `<redacted:name>` in v1) so
  the schema-v1 layer matches the existing PII-rule replacement
  shape; the schema bump is additive on the field set (a v1 reader
  parsing a v2 line keeps working because every new field is
  `skip_serializing_if = Option::is_none`). Marker normalization is
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
  gateway forwards, then records the final client-wire bytes.
  Retries receive the same bytes.
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
  again. No behavioral change.
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

- **AI client retry resilience.** Provider retries now honor
  `provider.max_retries` as same-provider retry attempts with
  bounded jittered exponential backoff before recording provider
  failure and moving to the next eligible provider.
  ([crates/sbproxy-ai/src/client.rs])

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
  which is archived and read-only; its `v0.1.2` release tag preserves
  the final historical release.
- **Data plane**: routing, AI gateway, MCP gateway, guardrails, security
  policies, and scripting (CEL, Lua, JavaScript, WebAssembly) all ship
  open source in this release. See [`docs/architecture.md`](docs/architecture.md)
  for the request pipeline shape.
- **Editions**: this release originally described a separate paid tier
  layered on the open-source data plane. That split no longer exists.
  Every feature ships in one Apache-2.0 binary; the `1.2.0` entry
  records the relicensing that got there.

### Upgrading from v0.1.x (Go)

The internal config schema (`schema-v1`) is supported by both the Go
`v0.1.x` line and this Rust `v1.x` line, so existing `sb.yml` files
should compile unchanged. See [`MIGRATION.md`](MIGRATION.md) for the
full upgrade path.
