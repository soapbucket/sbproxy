//! Per-request context threaded through all Pingora phases as CTX.
//!
//! `RequestContext` is the per-request state that flows through every Pingora
//! callback (request_filter, upstream_peer, response_filter, etc.). It carries
//! identity, routing results, auth decisions, and short-circuit flags.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Instant;

use bytes::BytesMut;
use compact_str::CompactString;
use sbproxy_modules::policy::{AgentBudgetGuard, ConcurrentLimitGuard};
use sbproxy_modules::transform::{CelHeaderMutation, MarkdownProjection};
use sbproxy_modules::{ContentShape, RateLimitInfo};
use sbproxy_observe::UserIdSource;
use sbproxy_plugin::AuthDecision;
use ulid::Ulid;

use crate::hooks::{ClassifyVerdict, IntentCategory};

/// Realtime WebSocket dispatch state carried on the request context.
///
/// Populated by `handle_action` when an `Action::AiProxy` request is
/// classified as the Realtime surface and arrives with an
/// `Upgrade: websocket` header. The AI gateway runs its gating logic
/// (`provider_supports_realtime`, per-surface rate limit, surface
/// metrics) before the dispatcher selects a provider and stashes the
/// connection target here. The `upstream_peer` callback reads this
/// to build the dynamic `HttpPeer`; Pingora then forwards bytes
/// transparently between client and provider after the
/// `101 Switching Protocols` handshake. The `logging` callback reads
/// it again at session close to observe duration, decrement the
/// active-sessions gauge, and emit a session-end `AiBillingEvent`.
#[derive(Debug, Clone)]
pub struct RealtimeDispatchCtx {
    /// Provider that received this realtime session (e.g. `openai`).
    pub provider_name: String,
    /// Upstream host the WebSocket connects to.
    pub upstream_host: String,
    /// Upstream port (443 for wss, 80 for ws by default).
    pub upstream_port: u16,
    /// Whether the upstream uses TLS.
    pub upstream_tls: bool,
    /// Wall-clock instant when the session started. Diffed against
    /// the `logging` callback time to produce the session-duration
    /// histogram observation and the AudioSeconds billing approximation.
    pub started_at: Instant,
    /// Stable surface label (`"realtime"`) for downstream metric and
    /// log attribution.
    pub surface_label: &'static str,
}

/// Parameters captured at `request_filter` time and consumed by
/// `request_body_filter` to fire a request mirror with the optional
/// teed body.
pub struct MirrorParams {
    /// Mirror upstream URL.
    pub url: String,
    /// Per-request timeout for the mirror call.
    pub timeout: std::time::Duration,
    /// Original request method.
    pub method: String,
    /// Original `path?query` for the upstream request.
    pub path_and_query: String,
    /// Snapshot of inbound headers (hop-by-hop filtered when sent).
    pub headers: http::HeaderMap,
    /// Correlation ID; surfaced as `X-Sbproxy-Request-Id` on the mirror.
    pub request_id: String,
    /// Whether to tee the inbound body into the mirror request.
    pub mirror_body: bool,
    /// Body size cap. Bodies larger than this skip body teeing (the
    /// mirror still fires, just without a body) so a single large
    /// upload can't blow up memory.
    pub max_body_bytes: usize,
}

/// Per-request metrics counters populated by transforms and policies.
///
/// A small bag of counters that the audit regression and operator
/// dashboards consume. New fields land here
/// rather than widening [`RequestContext`] every time a transform
/// wants to surface a number.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestMetrics {
    /// Bytes removed from the upstream response body by the
    /// boilerplate-stripping transform. `0` when the
    /// transform did not run or removed nothing.
    pub stripped_bytes: u64,
}

/// Per-request state threaded through all Pingora phases as CTX.
pub struct RequestContext {
    // --- Identity ---
    /// Unique request identifier (set during request_filter).
    pub request_id: CompactString,
    /// Client IP address extracted from the downstream connection.
    pub client_ip: Option<IpAddr>,
    /// Hostname extracted from the Host header (without port).
    pub hostname: CompactString,
    /// WOR-1053: tenant the matched origin resolves to. Stamped on
    /// route match from `CompiledOrigin.tenant_id`; defaults to
    /// `__default__` for un-routed requests and single-tenant
    /// deployments. Downstream auth / policy / vault resolution
    /// picks the tenant-scoped config block off this field.
    pub tenant_id: CompactString,

    // --- Origin routing ---
    /// Index into `CompiledConfig.origins`, set after host routing.
    pub origin_idx: Option<usize>,

    // --- Pipeline snapshot ---
    /// The compiled pipeline snapshot this request runs against, pinned
    /// once at request start (WOR-1690). Every Pingora phase after
    /// `request_filter` reads config, actions, origins, policies, and
    /// fallbacks through this field instead of re-loading the global
    /// pipeline, so `origin_idx` and the collections it indexes always
    /// come from the same snapshot. A hot reload mid-request no longer
    /// risks a panic or a cross-origin config read; the request simply
    /// completes on the config it started with.
    pub pipeline: std::sync::Arc<crate::pipeline::CompiledPipeline>,

    // --- Auth state ---
    /// Authentication result, populated by the auth phase.
    pub auth_result: Option<AuthDecision>,

    // --- Flags ---
    /// Whether the force-SSL redirect check has already been performed.
    pub force_ssl_checked: bool,
    /// If set, the proxy should short-circuit with this HTTP status code
    /// instead of proxying upstream.
    pub short_circuit_status: Option<u16>,
    /// Optional body to send with a short-circuit response.
    pub short_circuit_body: Option<bytes::Bytes>,
    /// Optional `Content-Type` for the short-circuit body. Defaults to
    /// `text/plain` when unset (e.g. the AI-crawler tarpit sets
    /// `text/html` so a crawler parses the maze links).
    pub short_circuit_content_type: Option<String>,

    // --- Load balancer state ---
    /// Index of the selected load balancer target (for connection tracking).
    pub lb_target_idx: Option<usize>,

    // --- Upstream retry state ---
    /// Number of retry attempts already made for this request.
    /// `0` means we are on the original attempt; `1` means one retry
    /// has occurred. Compared against the action's `RetryConfig.max_attempts`
    /// in `fail_to_connect` to decide whether to retry again.
    pub retry_count: u32,
    /// Backoff delay scheduled by the last retry decision. Consumed by
    /// `upstream_peer` before it selects the next upstream attempt.
    pub retry_backoff_ms: Option<u64>,
    /// Reason a configured status-code retry was skipped. Stamped on
    /// the final upstream response so operators can see why the proxy
    /// did not replay a matching failure status.
    pub status_retry_skip_reason: Option<&'static str>,

    // --- Concurrent limit guards ---
    /// Permits issued by `ConcurrentLimitPolicy` for this request. The
    /// guards release their slots when dropped, which happens when the
    /// context is dropped at the end of the request lifecycle.
    pub concurrent_limit_guards: Vec<ConcurrentLimitGuard>,
    /// Permits issued by `AgentBudgetPolicy`. Same lifecycle
    /// as `concurrent_limit_guards`: each guard tracks an in-flight
    /// agent-keyed slot and releases it when the request finishes.
    pub agent_budget_guards: Vec<AgentBudgetGuard>,

    // --- Request validator state ---
    /// Set by `check_policies` when a `RequestValidator` policy is
    /// configured on this origin. When true, `request_body_filter`
    /// accumulates the body into `request_body_buf` and runs every
    /// matching validator once the stream ends.
    pub validate_request_body: bool,
    /// Buffered request body, populated only when `validate_request_body`
    /// is true.
    pub request_body_buf: Option<BytesMut>,
    /// WOR-819: set in `upstream_request_filter` when the request matched
    /// a `transcode` route on a `grpc` action. While true, the body
    /// filters re-fetch the transcoder from the pipeline and rewrite the
    /// request body (JSON -> framed gRPC) and the response body (gRPC
    /// frame -> JSON). The original request (method + path) is read back
    /// from `session.req_header()`, so only this signal is carried.
    pub transcode_active: bool,
    /// Fully-qualified gRPC method the matched transcode route targets,
    /// needed to decode the response message type.
    pub transcode_grpc_method: Option<String>,
    /// Accumulator for the upstream gRPC response frame, drained and
    /// transcoded to JSON at `end_of_stream` in `response_body_filter`.
    pub transcode_response_buf: Option<BytesMut>,
    /// gRPC status captured from a trailers-only error response header
    /// (`grpc-status`). `None` defaults to OK (0) for the success path,
    /// where the status arrives in trailers after the body.
    pub transcode_grpc_status: Option<i32>,
    /// `grpc-message` captured alongside `transcode_grpc_status`.
    pub transcode_grpc_message: Option<String>,
    /// True once the transcoded JSON response body has been emitted, so
    /// later `response_body_filter` calls (a final `end_of_stream`, or
    /// post-trailer call) do not emit it twice. gRPC-over-h2 sends the
    /// message in a DATA frame without `END_STREAM` (trailers follow),
    /// so the frame is emitted as soon as it is complete rather than
    /// waiting for an `end_of_stream` that may never carry it.
    pub transcode_response_emitted: bool,
    /// WOR-819: set in `upstream_request_filter` when a gRPC-Web request
    /// (`content-type: application/grpc-web*`) hits a `grpc` action with
    /// `grpc_web: true`. The body filters then bridge gRPC-Web <-> native
    /// gRPC: decode the request frames upstream and re-encode the
    /// response frames + a trailer frame back to the browser.
    pub grpc_web_active: bool,
    /// True when the gRPC-Web request used the base64 `-text` variant, so
    /// the request body is base64-decoded and the response re-encoded.
    pub grpc_web_text: bool,
    /// Accumulator for the upstream gRPC response message frame(s).
    pub grpc_web_buf: Option<BytesMut>,
    /// True once the gRPC-Web response body (message frames + trailer
    /// frame) has been emitted, so later filter calls do not double-emit.
    pub grpc_web_emitted: bool,
    /// Set by `request_body_filter` when a request body fails schema
    /// validation. The triple is `(status, body, content_type)` and is
    /// surfaced by `fail_to_proxy` (the body filter aborts the
    /// upstream by returning Ok with no body, then we synthesise the
    /// rejection in `fail_to_proxy`).
    pub validator_failed: Option<(u16, String, String)>,

    // --- Idempotency middleware state ---
    /// Set in `request_filter` when the origin has `idempotency:`
    /// configured and the request method matches the configured set.
    /// `request_body_filter` reads this flag and buffers the request
    /// body into [`Self::request_body_buf`] so the body hash can be
    /// computed against the cache.
    pub idempotency_buffering: bool,
    /// Workspace identifier (resolved by auth or defaulted to the
    /// origin's workspace id) used as the cache key prefix to prevent
    /// cross-tenant collisions on the same `Idempotency-Key`.
    pub idempotency_workspace: Option<String>,
    /// Idempotency key + body hash captured on a cache miss. Carried
    /// into `response_body_filter` so the captured upstream response
    /// can be stored under the same `(workspace, key)` pair.
    pub idempotency_miss: Option<(String, [u8; 32])>,
    /// Buffer the upstream response body accumulates into while the
    /// proxy captures a cache-miss response for later replay.
    pub idempotency_response_body_buf: Option<BytesMut>,
    /// Upstream response status captured at `response_filter` time so
    /// the cache entry written at end-of-body carries the correct
    /// status. Parallel to [`Self::cache_status`] but kept separate
    /// because the response cache and idempotency cache can both run.
    pub idempotency_response_status: Option<u16>,
    /// Response headers captured at `response_filter` time, paired
    /// with [`Self::idempotency_response_status`] and written when the
    /// body filter sees `end_of_stream`.
    pub idempotency_response_headers: Option<Vec<(String, String)>>,
    /// Permit held while the request is participating in the
    /// per-origin idempotency buffer pool. Dropped at end of the
    /// request to release the slot.
    pub idempotency_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    /// Reason the middleware *skipped* engagement for this request,
    /// stamped as `x-sbproxy-idempotency: <reason>` on the response
    /// so operators can spot pool pressure or oversize bodies. None
    /// when the middleware engaged normally (hit / miss / conflict).
    pub idempotency_skip_reason: Option<&'static str>,

    // --- Request body size limit (streaming) ---
    /// Streaming-time max body size cap from `RequestLimitPolicy`.
    /// Populated by `check_policies` when a `request_limit` policy with
    /// `max_body_size` is attached. `request_body_filter` accumulates
    /// `body_bytes_seen` and synthesises a 413 once the cap is crossed.
    pub body_size_limit: Option<usize>,
    /// Running total of inbound body bytes observed by the body filter.
    pub body_bytes_seen: usize,
    /// Total request body bytes seen this request, summed across all
    /// `request_body_filter` chunks. Always tracked (even when no
    /// `RequestLimitPolicy` is attached) so the access log can stamp
    /// `bytes_in` for ML / billing / abuse analytics.
    pub request_body_bytes: u64,
    /// Total response body bytes sent to the client, summed across
    /// all `response_body_filter` chunks. Counts what the client
    /// actually saw, not what the upstream sent: transforms,
    /// fallback bodies, and cached responses are included.
    pub response_body_bytes: u64,

    // --- Request mirror state ---
    /// Captured-at-`request_filter` parameters for a request whose
    /// mirror should fire from `request_body_filter` (so the body
    /// can be teed in). When `None`, no mirror is configured or the
    /// sample missed.
    pub mirror_pending: Option<MirrorParams>,

    // --- Timing ---
    /// Request start time for latency measurement.
    pub request_start: Option<Instant>,
    /// Instant the auth check finished (success or denial), set just
    /// after `auth_check` returns in `request_filter`. Difference
    /// from `request_start` is `auth_ms` on the access log + the
    /// `auth` slice of `sbproxy_phase_duration_seconds`. `None` for
    /// origins with no auth provider.
    pub auth_finished_at: Option<Instant>,
    /// Instant the proxy received the first response header byte
    /// from the upstream. Set at the top of `response_filter`.
    /// Difference from `request_start` is `upstream_ttfb_ms` on the
    /// access log + the `upstream_ttfb` slice of
    /// `sbproxy_phase_duration_seconds`.
    pub upstream_first_byte_at: Option<Instant>,
    /// Instant the `response_filter` hook returned for the final
    /// transform. Difference from `upstream_first_byte_at` is
    /// `response_filter_ms` on the access log + the
    /// `response_filter` slice of `sbproxy_phase_duration_seconds`.
    /// `None` when no response_filter ran (e.g. early auth rejection).
    pub response_filter_finished_at: Option<Instant>,
    /// HTTP status code from the upstream response (set in response_filter).
    pub response_status: Option<u16>,

    // --- Rate limit info ---
    /// Rate limit info from the policy check, used to add response headers.
    pub rate_limit_info: Option<RateLimitInfo>,

    // --- Transform body buffering ---
    /// Buffer for accumulating upstream response body chunks when transforms are configured.
    pub response_body_buf: Option<BytesMut>,
    /// Whether we are currently buffering the response body for transform processing.
    pub buffering_body: bool,
    /// Cached upstream content-type header for transform content-type matching.
    pub upstream_content_type: Option<String>,

    // --- SRI scan ---
    /// Set in the response phase when an enforcing `sri` policy is
    /// attached to this origin and the upstream response is `text/html`.
    /// Tells the body filter to buffer the response so the SRI scanner
    /// can inspect the document. Logging-only; the response body is not
    /// modified.
    pub sri_scan_enabled: bool,

    /// WOR-805 PR2: set to true in `request_body_filter` after the
    /// `content_digest` policy returns `Verified` (or `Skipped` with
    /// `on_missing: skip`). Downstream consumers can attest the body
    /// matched a signed `content-digest` component without re-hashing:
    /// the HTTP Message Signatures composition check reads this flag
    /// so an origin that requires both a signature AND a digest gets
    /// a single audit signal saying "body integrity verified".
    /// Distinct from `validator_failed`: a `Verified` outcome flips
    /// the flag, while a `Mismatch` / `Malformed` outcome fills
    /// `validator_failed` and short-circuits the request before this
    /// flag is read.
    pub content_digest_verified: bool,

    /// WOR-805 F1.6.1: a successful `bot_auth` verdict carried a
    /// `Signature-Input` that covered `content-digest`. The auth
    /// phase verified the signature header but the body was not
    /// available yet, so the body-vs-`Content-Digest`-header check
    /// is deferred to `request_body_filter`. The body filter sets
    /// `validate_request_body` alongside this flag so the buffer
    /// path runs; on `end_of_stream` it runs
    /// `verify_content_digest(header_value, body)` and rejects with
    /// 401 if the body does not match the signed digest.
    pub bot_auth_digest_check_required: bool,

    // --- WOR-808 PR5 / PR6: RSL <link rel="license"> body injection ---
    /// Set in `response_filter` when the origin advertises an RSL
    /// `licenses.xml` projection (i.e. `rsl_urns` has an entry for
    /// the hostname) AND the upstream response is HTML, RSS, or Atom.
    /// Tells the body filter to accumulate the response and inject a
    /// `<link rel="license" href="/licenses.xml">` (HTML) or self-
    /// closing `<link rel="license" href="/licenses.xml"/>` (RSS or
    /// Atom) into the document's container element so consumers
    /// reading the rendered body discover the license document the
    /// same way clients reading the `Link` header do. Injection is a
    /// no-op when the body already carries a license-rel link or has
    /// no parseable container.
    pub rsl_inject_link_pending: bool,
    /// WOR-808 PR6: when `rsl_inject_link_pending` is set, which
    /// document family the body filter should run the injection
    /// against. `None` means HTML (the PR5 default); `Some(FeedFormat)`
    /// switches to the XML self-closing form, keyed to either RSS
    /// (`<channel>`) or Atom (`<feed>`).
    pub rsl_inject_link_feed: Option<sbproxy_modules::projections::FeedFormat>,
    /// Buffer for the body when `rsl_inject_link_pending` is set.
    /// Drained at `end_of_stream` to perform the one-shot injection.
    pub rsl_inject_link_buf: Option<BytesMut>,
    /// Once-only guard so the body filter does not double-emit the
    /// injected body if `end_of_stream` arrives in a second filter
    /// call after the buffer has already been flushed.
    pub rsl_inject_link_emitted: bool,

    // --- Forward rule state ---
    /// If a forward rule matched, this holds the index into the origin's forward_rules vec.
    pub forward_rule_idx: Option<usize>,
    /// Path parameters captured by the matched forward rule's `template` or
    /// `regex` matcher. `None` when no forward rule matched, or the rule
    /// matched via `prefix`/`exact` (which capture nothing). Available to
    /// request modifiers, CEL/Lua scripts, and metrics labels.
    pub path_params: Option<HashMap<String, String>>,

    // --- Fallback state ---
    /// Set to true when the primary upstream failed and a fallback response was served.
    pub fallback_triggered: bool,
    /// When on_status fallback triggers in response_filter, the replacement body is stored
    /// here so response_body_filter can swap it in.
    pub fallback_body: Option<bytes::Bytes>,

    // --- CSRF state ---
    /// CSRF token to set as a cookie on the response (for safe methods).
    pub csrf_cookie: Option<String>,

    // --- Request body replacement ---
    /// If a request modifier specifies a body replacement, it is stored here
    /// so that the body filter phase can swap it in before sending upstream.
    pub replacement_request_body: Option<bytes::Bytes>,

    // --- Response modifier state ---
    /// If a response modifier specifies a status code override, it is stored here
    /// so that response_filter can apply it.
    pub response_status_override: Option<u16>,
    /// If a response modifier specifies a body replacement, it is stored here
    /// so that response_body_filter can swap it in.
    pub response_body_replacement: Option<bytes::Bytes>,

    // --- Forward auth trust headers ---
    /// Headers from a successful forward auth response (e.g., X-User-ID)
    /// to inject into the upstream request.
    pub trust_headers: Option<Vec<(String, String)>>,

    // --- on_request enrichment headers ---
    /// Headers harvested from an `on_request` enrichment callback
    /// response (any `X-Inject-*` header on the callback's reply
    /// becomes an unprefixed header on the upstream request). Drained
    /// in `upstream_request_filter`.
    pub callback_inject_headers: Option<Vec<(String, String)>>,

    // --- Wave 5 day-6 Item 1: CEL header transform mutations ---
    /// Header mutations produced by the `headers:` array on a `type:
    /// cel` transform. The static action and `response_filter` drain
    /// this and stamp the operations onto the outgoing response so
    /// operators can set / append / remove response headers from a
    /// CEL expression. Empty by default; populated by the transform
    /// pipeline at `apply_transform_with_ctx` time.
    pub cel_response_header_mutations: Vec<CelHeaderMutation>,

    // --- WOR-168 transform-error attribution ---
    /// Set by the body-buffer transform pipeline when a transform
    /// returns a `TransformError` shape that must surface as a 500
    /// with attribution. The value is the human-readable transform
    /// name (e.g. `"cel"` or `"my-plugin"`) and is stamped onto the
    /// outgoing response as `x-sbproxy-transform-error`. Distinct
    /// from `validator_failed` (which carries the request-validator
    /// rejection body) so the two failure surfaces stay independently
    /// observable.
    pub transform_error_attribution: Option<String>,

    // --- AI Crawl Control challenge ---
    /// Set by an `ai_crawl_control` policy when a request must be
    /// charged. Tuple is `(header_name, challenge_value, json_body)`.
    /// The 402 response handler reads this to stamp the configured
    /// header and write the JSON body.
    pub crawl_challenge: Option<(String, String, String)>,
    /// Set by an `ai_crawl_control` policy in Cloudflare Pay Per Crawl
    /// interop mode when a request settled through the ledger. Carries
    /// the `crawler-charged` header value (`<currency> <amount>`, e.g.
    /// `USD 0.01`). The served-response path stamps this onto the 2xx
    /// response so the crawler learns exactly what it paid. `None` when
    /// the request was not a paid Cloudflare-compat crawl.
    pub crawl_charged: Option<String>,

    // --- Distributed tracing ---
    /// W3C Trace Context for this request (parsed from `traceparent` or generated fresh).
    pub trace_ctx: Option<sbproxy_observe::TraceContext>,

    // --- Response cache state ---
    /// Computed cache key for this request. Populated in `request_filter` when
    /// the origin has response-caching enabled and the request is cacheable.
    /// `response_filter` / body filters use this to decide whether to write
    /// the upstream response into the cache.
    pub cache_key: Option<String>,
    /// Buffer holding the upstream response body while we accumulate it for
    /// caching. Kept separate from `response_body_buf` (which the transform
    /// pipeline owns) so the two features can coexist.
    pub cache_body_buf: Option<bytes::BytesMut>,
    /// Upstream response status captured at `response_filter` time, used when
    /// the last body chunk arrives to construct the `CachedResponse`.
    pub cache_status: Option<u16>,
    /// Response headers captured at `response_filter` time, stored alongside
    /// the body when the entry is finally written.
    pub cache_headers: Option<Vec<(String, String)>>,
    /// True when the current response was served from cache; the upstream
    /// dispatch is skipped entirely.
    pub served_from_cache: bool,

    // --- Response compression ---
    /// Negotiated response encoding for this request. Set in
    /// `response_filter` when the origin has compression enabled, the
    /// upstream content-type is compressible, and the client advertises a
    /// supported algorithm. `response_body_filter` buffers the body and
    /// emits it compressed once the stream ends.
    pub compression_encoding: Option<sbproxy_middleware::compression::Encoding>,
    /// Buffer holding the upstream response body while compression is
    /// pending. Kept separate from `response_body_buf` (transforms) and
    /// `cache_body_buf` (response cache) so the three features can stack
    /// without tripping each other.
    pub compression_buf: Option<BytesMut>,
    /// Minimum payload size, in bytes, before compression is applied. Set
    /// from the origin's `compression.min_size`. The body filter consults
    /// this on end-of-stream and falls back to identity when the buffered
    /// body comes in below the floor.
    pub compression_min_size: usize,

    // --- Classifier verdicts (F5) ---
    /// Verdict produced by the prompt-classifier hook
    /// (`PromptClassifierHook::classify_prompt`). Populated in the AI proxy
    /// handler after the hook returns `Some(verdict)`. Downstream modifiers,
    /// transforms, routing, and metrics can branch on it without re-running
    /// the classifier.
    pub classifier_prompt: Option<ClassifyVerdict>,
    /// Intent category produced by the intent-detection hook
    /// (`IntentDetectionHook::detect`). Populated alongside `classifier_prompt`
    /// in the AI proxy handler so downstream code can coarsely route by
    /// task (coding, vision, analysis, ...).
    pub classifier_intent: Option<IntentCategory>,
    /// Extension map for future verdict-style producers (PII scanners,
    /// language detection, semantic-cache scores, ...). Keys are free-form
    /// namespaces (e.g. "enterprise.pii", "enterprise.language"). Values
    /// are arbitrary JSON so new producers can ship without widening this
    /// struct.
    pub classifier_extensions: HashMap<String, serde_json::Value>,

    // --- P0 envelope dimensions ---
    //
    // Filled at request entry by `capture_envelope::capture_dimensions`.
    /// Caller-supplied custom properties from `X-Sb-Property-*`
    /// headers. Cardinality-capped, allowlist-checked, redaction-applied.
    pub properties: BTreeMap<String, String>,
    /// Session identifier (caller-supplied or auto-generated for
    /// anonymous traffic per `SessionsConfig::auto_generate`).
    pub session_id: Option<Ulid>,
    /// Parent session linkage. Caller-supplied only; never
    /// auto-generated.
    pub parent_session_id: Option<Ulid>,
    /// Resolved end-user identifier. Set when a
    /// trusted source (header today; JWT and forward-auth in the
    /// follow-up slice) yields a non-empty value.
    pub user_id: Option<String>,
    /// Diagnostic stamp recording which source filled `user_id`.
    pub user_id_source: Option<UserIdSource>,
    /// ISO-3166-1 alpha-2 country derived from `client_ip` by the
    /// optional geo-enrichment policy (PORTAL.md gap 3.1 P2). Stays
    /// `None` when the policy is not configured.
    pub request_geo: Option<String>,
    /// ULID for the capture envelope.
    /// Minted alongside the existing UUID-based [`Self::request_id`]
    /// at request entry; the UUID stays for backward-compatible
    /// correlation headers, the ULID feeds the typed envelope which
    /// the enterprise ingest pipeline consumes verbatim.
    pub envelope_request_id: Option<Ulid>,
    /// T1.3 properties echo. When `true`, `response_filter` stamps
    /// every captured property back as `X-Sb-Property-<key>` response
    /// headers so SDKs can correlate replies. Mirrors the
    /// `properties.echo` field on `PropertiesConfig`; set during
    /// capture so the response phase needs no further config lookup.
    pub properties_echo: bool,

    // --- Agent-class resolution (G1.4, feature-gated) ---
    //
    // Populated by the request pipeline early in `request_filter`,
    // after the trust-boundary header strip and the bot-auth
    // verifier (when configured). The triple `agent_id` /
    // `agent_vendor` / `agent_id_source` is exposed to the scripting
    // layers (CEL, Lua, JS, WASM) so policy expressions can branch on
    // the resolved identity.
    /// Resolved agent identifier. One of the three reserved sentinels
    /// (`human`, `anonymous`, `unknown`) or a catalog `id`.
    #[cfg(feature = "agent-class")]
    pub agent_id: Option<sbproxy_classifiers::AgentId>,
    /// Operator display name for the resolved agent (`OpenAI`,
    /// `Google`, ...). `Some("unknown")` for sentinels.
    #[cfg(feature = "agent-class")]
    pub agent_vendor: Option<String>,
    /// Operator-stated purpose for the resolved agent.
    #[cfg(feature = "agent-class")]
    pub agent_purpose: Option<sbproxy_classifiers::AgentPurpose>,
    /// Diagnostic stamp for which signal in the resolver chain matched.
    #[cfg(feature = "agent-class")]
    pub agent_id_source: Option<sbproxy_classifiers::AgentIdSource>,
    /// Forward-confirmed reverse-DNS hostname when the rDNS path
    /// matched. Surfaced as `request.agent_rdns_hostname` to scripts.
    #[cfg(feature = "agent-class")]
    pub agent_rdns_hostname: Option<String>,

    // --- Wave 5 / G5.1 KYA verifier side-channel ---
    //
    // Populated by an `IdentityResolverHook` (typically the enterprise
    // KYA verifier) every time it runs, regardless of whether the
    // verifier produced an `agent_id`. A token presented but rejected
    // (`expired`, `revoked`, ...) leaves `agent_id = None` here but
    // populates `kya_verdict` so policy expressions can author
    // `request.kya.verdict != "missing"` style gates without owning
    // the verifier.
    //
    // `None` means the KYA hook never ran (no enterprise binary, or
    // the operator has not configured KYA in `sb.yml`).
    /// KYA verdict label as exposed to CEL / Lua / JS / WASM under
    /// `request.kya.verdict`. One of:
    /// `"verified"`, `"missing"`, `"expired"`, `"revoked"`,
    /// `"invalid"`, `"directory_unavailable"`. `None` when no KYA
    /// hook ran.
    #[cfg(feature = "agent-class")]
    pub kya_verdict: Option<&'static str>,
    /// KYA agent vendor (e.g. `"skyfire"`) exposed under
    /// `request.kya.vendor`. `None` when the KYA hook did not produce
    /// a verified token.
    #[cfg(feature = "agent-class")]
    pub kya_vendor: Option<String>,
    /// KYA spec version (e.g. `"v1"`) exposed under
    /// `request.kya.kya_version`. `None` when the KYA hook did not
    /// produce a verified token.
    #[cfg(feature = "agent-class")]
    pub kya_version: Option<String>,
    /// KYAB advisory balance amount (smallest unit) exposed under
    /// `request.kya.kyab_balance.amount`. `None` when the verified
    /// token did not carry a balance, or when no KYA hook ran.
    #[cfg(feature = "agent-class")]
    pub kya_kyab_balance: Option<u64>,

    // --- aipref signal (Wave 4 / G4.9) ---
    //
    // Parsed from the request-side `aipref` header by a request
    // enricher early in the pipeline. `None` when no header was
    // present or the header was malformed (the enricher logs a warn
    // and falls through to default-permissive for downstream
    // policy use). Exposed to CEL / Lua / JS / WASM under
    // `request.aipref.{train,search,ai_input}`.
    /// Parsed aipref preference signal from the inbound `aipref`
    /// header. `None` means "no signal asserted"; populated value
    /// reflects the publisher's stated AI-use preferences. See
    /// [`sbproxy_modules::AiprefSignal`].
    pub aipref: Option<sbproxy_modules::AiprefSignal>,

    // --- Wave 4 content-shaping fields (G4.x coordination) ---
    //
    // These three fields are co-owned with rust-A (G4.1-G4.4) and
    // rust-B (RSL projection). rust-C adds the field declarations
    // here so the citation_block transform and aipref enricher can
    // reference them; the upstream branches will fill them in. If
    // names collide on merge, rust-A's branch wins (rename here).
    /// Canonical URL for the resource being served, used by content
    /// projections (citation block, JSON envelope `url` field). `None`
    /// until the request handler stamps it.
    pub canonical_url: Option<String>,
    /// RSL license URN for the resource. Set by rust-B's RSL
    /// projection. Used by the citation_block transform to render
    /// the License: clause. `None` falls back to "all-rights-
    /// reserved".
    pub rsl_urn: Option<String>,
    /// Approximate token count for the Markdown projection. Set by
    /// the projection once it runs. Read by the
    /// `x-markdown-tokens` header emitter.
    pub markdown_token_estimate: Option<u32>,

    // --- Wave 4 metrics (G4.10) ---
    /// Per-request metrics counters surfaced for the audit.
    /// Adds up bytes stripped by the boilerplate transform, etc.
    pub metrics: RequestMetrics,

    // --- AI gateway access-log fields ---
    /// Resolved AI provider (`openai`, `anthropic`, `bedrock`, ...)
    /// when the AI handler dispatched the request. `None` for
    /// non-AI traffic.
    pub ai_provider: Option<String>,
    /// WOR-800: name of the stored prompt this request resolved (when it
    /// referenced one via `"prompt": "name@version"`). Recorded on the
    /// run metadata / billing event so a run can be traced to the prompt
    /// version that produced it. `None` when no stored prompt was used.
    pub ai_prompt_name: Option<String>,
    /// WOR-800: resolved version label of [`Self::ai_prompt_name`].
    pub ai_prompt_version: Option<String>,
    /// Unified inbound identity carrier. Populated by the auth
    /// pipeline (today: AI virtual-key match writes the
    /// `virtual_key` field + `attrs` from the matched key). Reads
    /// across the codebase walk `principal.attrs.project`,
    /// `principal.attrs.user`, `principal.attrs.metadata`,
    /// `principal.attrs.tags` rather than maintaining a parallel
    /// `ai_*` shape.
    ///
    /// Defaults to [`sbproxy_plugin::Principal::anonymous`] for
    /// un-matched requests; access-log + metric paths short-circuit
    /// on `is_anonymous` to skip attribution work.
    pub principal: sbproxy_plugin::Principal,
    /// Resolved business attribution tags for this request (project,
    /// feature, team, customer, environment, agent_type, risk_tier,
    /// trace_id, ...). Built once at the entry of `handle_ai_proxy`
    /// from the credential's `attrs:` defaults merged with the inbound
    /// `SB-Attr-*` headers, then fanned out to the per-attribution
    /// spend metric and the access log so spend can be sliced by any
    /// of these business dimensions. Empty for non-AI requests.
    pub attribution_tags: sbproxy_ai::attribution::AttributionTags,
    /// AI model identifier the request routed to (e.g. `gpt-4o`,
    /// `claude-sonnet-4-6`). Captured before the upstream call so
    /// the access log records the resolved model even when the
    /// upstream errors before returning a body.
    pub ai_model: Option<String>,
    /// Set when the dispatched provider hosts its model on this box
    /// (a `serve:` provider): the serve-entry name the client asked
    /// for. The response handler rewrites the upstream body's `model`
    /// field to this name, because a local engine reports its weights
    /// file path there, which is not the id any plane routed on.
    pub ai_serve_model: Option<String>,
    /// Prompt / input tokens reported by the provider response.
    pub ai_tokens_in: Option<u64>,
    /// WOR-1499: estimated prompt tokens computed on the request path
    /// from the inbound body (before any upstream usage is known). Used
    /// for request-path prompt accounting and as the fallback token
    /// volume attributed to blocked / failed requests that never receive
    /// an upstream `usage` block (WOR-1497). `None` for non-chat
    /// surfaces.
    pub ai_prompt_tokens_est: Option<u64>,
    /// WOR-1499: salted, non-reversible fingerprint of the prompt, for
    /// correlating identical prompts across requests (cache / value
    /// analysis) without persisting prompt text. `None` for non-chat
    /// surfaces.
    pub ai_prompt_fingerprint: Option<String>,
    /// Completion / output tokens reported by the provider response.
    pub ai_tokens_out: Option<u64>,
    /// Rate-limiter bucket for the authenticated virtual key, set only
    /// when the key carries a tokens-per-minute cap (WOR-1833). The
    /// request-completion path uses it to charge the response's token
    /// usage into the key's one-minute window; the identifier is the
    /// limiter's bucket key (the stable key id, never the display name).
    pub ai_key_tpm_bucket: Option<String>,
    /// Scheduling lane of the authenticated virtual key (WOR-1679),
    /// stamped at auth when the key declares a `priority`. The served-
    /// model admission gate reads it to decide queue ordering and
    /// spill behavior; `None` means the standard lane.
    pub ai_lane_priority: Option<sbproxy_ai::identity::KeyPriority>,
    /// Deployment-specific admission held across the complete managed-model
    /// response stream. Dropping the context releases capacity to the next
    /// priority-ordered request.
    pub managed_model_permit: Option<crate::server::model_host::ManagedModelPermit>,
    /// Bounded non-sensitive replica decision for a distributed managed request.
    pub managed_route_trace: Option<crate::model_plane::ManagedRouteTrace>,
    /// Direct local or authenticated peer route selected for a managed request.
    pub managed_route_class: Option<sbproxy_ai::managed_replica::ManagedRouteClass>,
    /// Derived AI request cost in micro-USD (`1e-6` USD), computed
    /// from the same pricing catalog used by AI billing metrics.
    pub ai_cost_usd_micros: Option<u64>,
    /// Classified AI surface label from `classify_surface`. Stamped at
    /// the entry of `handle_ai_proxy` so every access log line for an
    /// AI request carries the surface (chat_completions, assistants,
    /// image_generation, etc.) without re-parsing the path.
    pub ai_surface: Option<String>,
    /// WOR-1496: AI-specific request outcome override for the
    /// per-attribution outcome metric. Set at block sites whose HTTP
    /// status alone is ambiguous (a guardrail block and a generic bad
    /// request both surface as 400). When `None` the access-log
    /// finalizer derives the outcome from the final HTTP status. Stable
    /// closed-set strings only (`guardrail_block`, `content_filter`,
    /// ...).
    pub ai_outcome: Option<String>,
    /// WOR-1874: category (configured guardrail / rule name) of the
    /// guardrail that intervened on this request. Stamped at every
    /// unary block site and by the streaming relay when an output
    /// guardrail terminates a stream, so the access log line and the
    /// admin request ring can filter on guardrail interventions.
    pub ai_guardrail_category: Option<String>,
    /// WOR-1874: what the intervening guardrail did. `block` is the
    /// only live action today; `redact`, `rewrite`, and `hold` are
    /// reserved for actions that gain live paths later.
    pub ai_guardrail_action: Option<String>,
    /// WOR-1528 / WOR-1540: usage sinks for this origin, stashed by
    /// `handle_ai_proxy` when the AI handler configures any. The
    /// end-of-request `logging` hook reads them once the final status,
    /// token counts, cost, and latency are known, builds one
    /// `LlmUsageEvent`, and hands it to each sink (the verifiable ledger
    /// among them). `None` (the default) means no sinks are configured,
    /// so the request path does no extra work.
    pub ai_usage_sinks: Option<Vec<std::sync::Arc<dyn sbproxy_ai::usage_sink::UsageSink>>>,
    /// WOR-1542: usage-record tag set by a `set_sink_tag:<tag>` action
    /// from the AI policy plane. Stamped onto the `LlmUsageEvent` handed
    /// to the usage sinks (including the verifiable ledger) so policy
    /// decisions are queryable in the spend record. `None` by default.
    pub ai_policy_sink_tag: Option<String>,
    /// WOR-1543: labels of the guardrails that flagged the request, set by
    /// the guardrail mesh when configured. Fed into the AI policy plane's
    /// `ai.guardrails.*` namespace so a policy rule can fuse the verdict
    /// set. Empty when the mesh is off or nothing flagged.
    pub ai_guardrail_labels: Vec<String>,
    /// WOR-1541: when true, the end-of-request hook folds this request's
    /// realized outcome (success / refusal / cost / latency) into the
    /// global routing feedback store. Set by `handle_ai_proxy` only when
    /// the origin uses the `outcome_aware` routing strategy.
    pub ai_record_routing_feedback: bool,
    /// WOR-1544: tightest active budget-window fraction consumed (0.0 to
    /// just under 1.0), computed by the predictive soft-landing check.
    /// Surfaced to the AI policy plane's `ai.budget.*` namespace. `0.0`
    /// when no budget is configured.
    pub ai_budget_fraction: f64,
    /// Inbound `ChatFormat` id when the request entered on a native
    /// shim path (`anthropic` for `/v1/messages`, `responses` for
    /// `/v1/responses`). `None` (or `"openai"`) for the canonical
    /// `/v1/chat/completions` path. Set by `handle_ai_proxy` after the
    /// inbound parse and read by the relay path so the response body
    /// is rewrapped into the format the client expects.
    pub ai_inbound_format: Option<String>,
    /// True when the inbound client format matched the
    /// upstream provider's native format, so the request bypassed the
    /// hub round-trip and the response body is already in the inbound
    /// shape. Read by the response handler to skip the rewrap step
    /// that would otherwise convert an OpenAI Chat body into the
    /// inbound wire shape.
    pub ai_native_bypass: bool,
    /// Pre-flight rate-limit reservation. Stamped by
    /// `handle_ai_proxy` after the prompt has been parsed and the
    /// tiktoken estimator has run; reconciled on the response side
    /// with the upstream's `usage.prompt_tokens` so TPM / TPD math
    /// settles against the real token count. Dropping the field
    /// without calling `reconcile` refunds the full reservation,
    /// which is the right behaviour on upstream-error paths.
    pub ai_admission: Option<sbproxy_ai::Admission>,
    /// OpenAI Realtime API session identifier for sessions dispatched
    /// through the realtime WebSocket path. `None` for non-realtime
    /// AI requests. Set by the realtime dispatcher when the upstream
    /// session is established; carried through the request context so
    /// the access log line emitted on session close carries the
    /// session id.
    pub ai_realtime_session: Option<String>,
    /// Realtime WebSocket dispatch state. Populated in `handle_action`
    /// when the AI gateway recognizes a `GET /v1/realtime` WebSocket
    /// upgrade for an `Action::AiProxy` origin. Carries the selected
    /// provider's connection target so `upstream_peer` can build the
    /// peer without re-running the AI gateway's gating logic, and the
    /// `logging` hook can observe session duration + emit the
    /// session-end `AiBillingEvent`.
    pub ai_realtime_dispatch: Option<RealtimeDispatchCtx>,

    /// WOR-1044: reversible PII redaction map for this request.
    /// Each entry is `(rule_name, placeholder, original)` recorded by
    /// the request-side `redact_json_with_capture` pass. The response
    /// handler walks this once to restore originals before the body
    /// is written back to the client. The vector lives only for the
    /// request lifetime so the original values never reach the access
    /// log, audit log, trace span, or any persisted artefact.
    pub ai_reversible_redactions: Vec<(String, String, String)>,

    // --- Wave 4 content negotiation (G4.2 / G4.3 / G4.4) ---
    //
    // The two-pass `Accept` resolver in `sbproxy-modules::action::content_negotiate`
    // stores both shapes here: `content_shape_pricing` is the first-match-wins
    // shape used for tier / quote-token selection (price-resolution semantics
    // from G3.5, unchanged), while `content_shape_transform` is the q-value
    // winner used to pick the response body transformer (G4.3 Markdown
    // projection vs G4.4 JSON envelope vs HTML pass-through). Both are filled
    // before the response phase runs; the JSON-envelope transform reads
    // `content_shape_transform` to know whether to wrap the body, and the
    // header-stamp middleware reads it to gate `x-markdown-tokens`.
    /// Pass 1 (pricing) shape resolved from the request `Accept` header.
    /// Set by the `content_negotiate` action; read by the quote-token
    /// verifier and the 402 challenge body. The pricing shape follows the
    /// existing first-match-wins contract from `ContentShape::from_accept`.
    pub content_shape_pricing: Option<ContentShape>,
    /// Pass 2 (transformation) shape resolved by the q-value-aware Accept
    /// scanner in `content_negotiate`. Drives which response transformer
    /// runs (`Markdown` -> Markdown projection, `Json` -> JSON envelope,
    /// `Html` / `Pdf` / `Other` -> pass-through). May differ from
    /// `content_shape_pricing` when the agent's q-values disagree with
    /// declaration order; the divergence is logged at debug.
    pub content_shape_transform: Option<ContentShape>,
    /// Cached Markdown projection (body + title + token estimate) emitted
    /// by `HtmlToMarkdownTransform` when wired into a content-negotiated
    /// origin. Held so the JSON envelope builder and the Markdown
    /// response path can both reach the same projection without re-running
    /// the regex pipeline. The token-estimate sibling field is
    /// `markdown_token_estimate` declared earlier; re-read both surfaces
    /// from the same source.
    pub markdown_projection: Option<MarkdownProjection>,

    // --- Wave 4 citation requirement (G4.4 + G4.10 closeout) ---
    /// Per-request citation flag, resolved from the matched
    /// [`sbproxy_modules::Tier::citation_required`] when an
    /// `ai_crawl_control` policy fires the tier resolver. The
    /// [`sbproxy_modules::JsonEnvelopeTransform`] and
    /// [`sbproxy_modules::CitationBlockTransform`] both read from this
    /// field so the YAML config has a single source of truth for the
    /// flag. `None` means "no tier matched", and the transforms fall
    /// back to their optional `force_citation` config (defaulting to
    /// `false`). See `docs/AIGOVERNANCE.md` § 9 for the centralisation
    /// rationale.
    pub citation_required: Option<bool>,

    // --- Wave 5 / G5.3 TLS fingerprint ---
    //
    // Current OSS runtime capture comes from trusted sidecar headers
    // because Pingora 0.8 + rustls does not expose raw ClientHello
    // bytes to the request/session API. A future native listener hook
    // should populate this from [`sbproxy_tls::parse_client_hello`].
    // `ja4h` is filled mid-pipeline by [`sbproxy_tls::compute_ja4h`]
    // in `request_filter`, after headers are read. `None` for
    // plaintext HTTP requests, when the feature is disabled, or when
    // no trusted capture source supplied JA3 / JA4 values.
    /// JA3 / JA4 / JA4H / JA4S fingerprint bundle for this request.
    /// See [`sbproxy_tls::TlsFingerprint`].
    pub tls_fingerprint: Option<sbproxy_tls::TlsFingerprint>,

    /// Agent-detection verdict for this request. `None` unless
    /// `proxy.extensions.agent_detect.enabled` is set, in which case the
    /// pipeline runs the configured scorer in `request_filter` and stores
    /// the result here for the scripting bridges (`request.agent.*`) and the
    /// `trust_tier` combiner to read. See
    /// [`sbproxy_agent_detect::AgentDetection`].
    pub agent_detection: Option<sbproxy_agent_detect::AgentDetection>,

    // --- Wave 5 / G5.4 headless detection ---
    //
    // Populated by `sbproxy_security::headless_detect` after the
    // request pipeline reads `tls_fingerprint`. The G1.4 resolver
    // chain reads this as an advisory signal when no higher-confidence
    // step matched.
    /// Headless-browser detection verdict, if the security pipeline
    /// ran the JA4-based detector. `None` when the detector did not
    /// run; otherwise [`HeadlessSignal::NotDetected`] or
    /// [`HeadlessSignal::Detected`] with a library hint and a
    /// confidence in `[0.0, 1.0]`.
    pub headless_signal: Option<HeadlessSignal>,

    // --- Wave 7 / A7.2 A2A protocol envelope ---
    //
    // Populated once in `request_filter` by [`sbproxy_modules::detect_a2a`]
    // and the optional spec parsers. `None` for plain HTTP requests;
    // present for any request that detection matched (regardless of
    // whether the parsers are compiled in). The policy module reads
    // this field and never recomputes it.
    /// Per-request A2A envelope. `None` for non-A2A traffic.
    pub a2a: Option<sbproxy_modules::A2AContext>,
    /// JSON denial body produced by the A2A policy module.
    /// Populated by the policy enforcer when a denial fires
    /// so the response handler can stamp the spec-pinned body
    /// verbatim instead of falling through to the generic
    /// `send_error` template.
    pub a2a_denial_body: Option<String>,

    // --- WOR-114: per-request feature flags ---
    /// Parsed `x-sb-flags` header + `?_sb.<key>` query params.
    /// Populated in `request_filter` from
    /// [`crate::sb_flags::parse_request`]; honoured by the response
    /// cache (no-cache bypass) and the response phase (debug header
    /// stamp + tracing emission). The kill switch
    /// `--disable-sb-flags` / `SB_DISABLE_SB_FLAGS=1` causes parsing
    /// to short-circuit so this is always the empty default.
    pub flags: crate::sb_flags::RequestFlags,

    // --- WOR-201 PR 1b: plugin-policy response header injection ---
    /// Response headers contributed by `Policy::Plugin` enforcers
    /// returning [`sbproxy_plugin::PolicyDecision::AllowWithHeaders`]
    /// (or the OSS Confirm bridge that translates `Confirm` into
    /// `AllowWithHeaders` with `X-Policy-Confirm` stamped per
    /// `docs/adr-policy-verdict-shape.md`). Drained in
    /// `response_filter`. Empty by default; appended onto the
    /// outgoing response after every other header source so the
    /// plugin policy contract reads "stamp these on the way out."
    pub policy_response_headers: Vec<(String, String)>,

    // --- WOR-201 PR 1c.0: response-handler keying for ported policies ---
    /// Per-request label that the response handler keys on to choose the
    /// 429 / 403 / 451 / 502 response shape. Set by the policy that
    /// returns Deny; carries the same string the existing `audit_deny!`
    /// macro receives in its `policy_type` argument. Examples:
    /// `"rate_limit"`, `"ai_crawl_payment"`, `"a2a_chain_depth_exceeded"`.
    /// Required to preserve byte-identical Deny responses across the
    /// `PolicyResult` -> `PolicyDecision` migration (WOR-201 PR 1c).
    /// `None` until the dispatcher in `check_policies` (or a ported
    /// enforcer wrapper) sets it; the response handler then prefers
    /// this slot over the macro fallback.
    pub deny_policy_type: Option<&'static str>,

    /// True when the inbound request was terminated over TLS at the
    /// edge. The CSRF policy needs this to enforce HTTPS-only cookies;
    /// it is precomputed here because [`sbproxy_plugin::PolicyEnforcer::enforce`]
    /// takes the request snapshot and cannot reach back to the live
    /// Pingora session. The signal mirrors the existing CSRF
    /// `is_secure` derivation in `server.rs`: either a Pingora
    /// `ssl_digest` is present (the listener itself was TLS) or the
    /// trusted-proxy chain stamped `X-Forwarded-Proto: https`.
    pub tls_terminated: bool,
}

/// Verdict produced by the headless-browser detector
/// (`sbproxy_security::headless_detect`).
///
/// The detector compares the request's JA4 fingerprint
/// against the vendored TLS-fingerprint catalogue
/// (`crates/sbproxy-classifiers/data/tls-fingerprints.json`); a
/// match yields [`Self::Detected`] with the library name (e.g.
/// `"puppeteer"`) and a confidence score that is halved to a 0.5 cap
/// when the fingerprint is not trustworthy (e.g. behind a CDN that
/// terminated TLS).
#[derive(Debug, Clone, PartialEq)]
pub enum HeadlessSignal {
    /// Detector ran and matched a known headless library.
    Detected {
        /// Library name (`puppeteer`, `playwright`, ...). Stable
        /// across releases; safe for metric labels.
        library: String,
        /// Confidence in `[0.0, 1.0]`. Halved (capped at 0.5) when
        /// `tls_fingerprint.trustworthy = false`.
        confidence: f32,
    },
    /// Detector ran and did NOT match any known headless library.
    NotDetected,
}

impl RequestContext {
    /// Create a new, empty request context.
    pub fn new() -> Self {
        Self {
            request_id: CompactString::default(),
            client_ip: None,
            hostname: CompactString::default(),
            tenant_id: CompactString::const_new("__default__"),
            origin_idx: None,
            pipeline: crate::reload::current_pipeline_full(),
            lb_target_idx: None,
            retry_count: 0,
            retry_backoff_ms: None,
            status_retry_skip_reason: None,
            concurrent_limit_guards: Vec::new(),
            agent_budget_guards: Vec::new(),
            validate_request_body: false,
            request_body_buf: None,
            transcode_active: false,
            transcode_grpc_method: None,
            transcode_response_buf: None,
            transcode_grpc_status: None,
            transcode_grpc_message: None,
            transcode_response_emitted: false,
            grpc_web_active: false,
            grpc_web_text: false,
            grpc_web_buf: None,
            grpc_web_emitted: false,
            validator_failed: None,
            idempotency_buffering: false,
            idempotency_workspace: None,
            idempotency_miss: None,
            idempotency_response_body_buf: None,
            idempotency_response_status: None,
            idempotency_response_headers: None,
            idempotency_permit: None,
            idempotency_skip_reason: None,
            body_size_limit: None,
            body_bytes_seen: 0,
            request_body_bytes: 0,
            response_body_bytes: 0,
            mirror_pending: None,
            auth_result: None,
            force_ssl_checked: false,
            short_circuit_status: None,
            short_circuit_body: None,
            short_circuit_content_type: None,
            request_start: None,
            auth_finished_at: None,
            upstream_first_byte_at: None,
            response_filter_finished_at: None,
            response_status: None,
            rate_limit_info: None,
            response_body_buf: None,
            buffering_body: false,
            upstream_content_type: None,
            sri_scan_enabled: false,
            content_digest_verified: false,
            bot_auth_digest_check_required: false,
            rsl_inject_link_pending: false,
            rsl_inject_link_feed: None,
            rsl_inject_link_buf: None,
            rsl_inject_link_emitted: false,
            forward_rule_idx: None,
            path_params: None,
            fallback_triggered: false,
            fallback_body: None,
            csrf_cookie: None,
            replacement_request_body: None,
            response_status_override: None,
            response_body_replacement: None,
            trust_headers: None,
            callback_inject_headers: None,
            cel_response_header_mutations: Vec::new(),
            transform_error_attribution: None,
            crawl_challenge: None,
            crawl_charged: None,
            trace_ctx: None,
            cache_key: None,
            cache_body_buf: None,
            cache_status: None,
            cache_headers: None,
            served_from_cache: false,
            compression_encoding: None,
            compression_buf: None,
            compression_min_size: 0,
            classifier_prompt: None,
            classifier_intent: None,
            classifier_extensions: HashMap::new(),
            properties: BTreeMap::new(),
            session_id: None,
            parent_session_id: None,
            user_id: None,
            user_id_source: None,
            request_geo: None,
            envelope_request_id: None,
            properties_echo: false,
            #[cfg(feature = "agent-class")]
            agent_id: None,
            #[cfg(feature = "agent-class")]
            agent_vendor: None,
            #[cfg(feature = "agent-class")]
            agent_purpose: None,
            #[cfg(feature = "agent-class")]
            agent_id_source: None,
            #[cfg(feature = "agent-class")]
            agent_rdns_hostname: None,
            #[cfg(feature = "agent-class")]
            kya_verdict: None,
            #[cfg(feature = "agent-class")]
            kya_vendor: None,
            #[cfg(feature = "agent-class")]
            kya_version: None,
            #[cfg(feature = "agent-class")]
            kya_kyab_balance: None,
            aipref: None,
            canonical_url: None,
            metrics: RequestMetrics::default(),
            ai_provider: None,
            ai_prompt_name: None,
            ai_prompt_version: None,
            principal: sbproxy_plugin::Principal::anonymous(),
            attribution_tags: sbproxy_ai::attribution::AttributionTags::default(),
            ai_model: None,
            ai_serve_model: None,
            ai_tokens_in: None,
            ai_prompt_tokens_est: None,
            ai_prompt_fingerprint: None,
            ai_tokens_out: None,
            ai_key_tpm_bucket: None,
            ai_lane_priority: None,
            managed_model_permit: None,
            managed_route_trace: None,
            managed_route_class: None,
            ai_cost_usd_micros: None,
            ai_surface: None,
            ai_outcome: None,
            ai_guardrail_category: None,
            ai_guardrail_action: None,
            ai_usage_sinks: None,
            ai_policy_sink_tag: None,
            ai_guardrail_labels: Vec::new(),
            ai_record_routing_feedback: false,
            ai_budget_fraction: 0.0,
            ai_inbound_format: None,
            ai_native_bypass: false,
            ai_admission: None,
            ai_realtime_session: None,
            ai_realtime_dispatch: None,
            ai_reversible_redactions: Vec::new(),
            content_shape_pricing: None,
            content_shape_transform: None,
            markdown_token_estimate: None,
            markdown_projection: None,
            rsl_urn: None,
            citation_required: None,
            tls_fingerprint: None,
            agent_detection: None,
            headless_signal: None,
            a2a: None,
            a2a_denial_body: None,
            flags: crate::sb_flags::RequestFlags::default(),
            policy_response_headers: Vec::new(),
            deny_policy_type: None,
            tls_terminated: false,
        }
    }

    // --- Classifier verdict accessors (F5) ---

    /// Read-only view of the prompt classifier verdict, if the hook
    /// produced one for this request.
    pub fn classifier_prompt(&self) -> Option<&ClassifyVerdict> {
        self.classifier_prompt.as_ref()
    }

    /// Copy of the detected intent category, if the intent-detection
    /// hook fired and returned a category.
    pub fn classifier_intent(&self) -> Option<IntentCategory> {
        self.classifier_intent
    }

    /// Look up a free-form classifier extension value by key.
    ///
    /// Callers should namespace keys (e.g. `"enterprise.pii"`) so the
    /// map stays collision-free as more producers land.
    pub fn classifier_extension(&self, key: &str) -> Option<&serde_json::Value> {
        self.classifier_extensions.get(key)
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_context_has_sensible_defaults() {
        let ctx = RequestContext::new();
        assert!(ctx.request_id.is_empty());
        assert!(ctx.client_ip.is_none());
        assert!(ctx.hostname.is_empty());
        assert!(ctx.origin_idx.is_none());
        assert!(ctx.auth_result.is_none());
        assert!(!ctx.force_ssl_checked);
        assert!(ctx.short_circuit_status.is_none());
        assert!(ctx.short_circuit_body.is_none());
        assert!(ctx.request_start.is_none());
        assert!(ctx.response_status.is_none());
        assert!(ctx.rate_limit_info.is_none());
        assert!(ctx.response_body_buf.is_none());
        assert!(!ctx.buffering_body);
        assert!(ctx.upstream_content_type.is_none());
        assert!(ctx.forward_rule_idx.is_none());
        assert!(!ctx.fallback_triggered);
    }

    #[test]
    fn default_equals_new() {
        let a = RequestContext::new();
        let b = RequestContext::default();
        assert_eq!(a.request_id, b.request_id);
        assert_eq!(a.client_ip, b.client_ip);
        assert_eq!(a.hostname, b.hostname);
        assert_eq!(a.origin_idx, b.origin_idx);
    }

    #[test]
    fn context_fields_are_mutable() {
        let mut ctx = RequestContext::new();
        ctx.request_id = CompactString::new("req-abc123");
        ctx.client_ip = Some("192.168.1.1".parse().unwrap());
        ctx.hostname = CompactString::new("api.example.com");
        ctx.origin_idx = Some(0);
        ctx.auth_result = Some(AuthDecision::allow_anonymous());
        ctx.force_ssl_checked = true;
        ctx.short_circuit_status = Some(429);

        assert_eq!(ctx.request_id, "req-abc123");
        assert_eq!(ctx.client_ip.unwrap().to_string(), "192.168.1.1");
        assert_eq!(ctx.hostname, "api.example.com");
        assert_eq!(ctx.origin_idx, Some(0));
        assert_eq!(ctx.auth_result, Some(AuthDecision::allow_anonymous()));
        assert!(ctx.force_ssl_checked);
        assert_eq!(ctx.short_circuit_status, Some(429));
    }

    #[test]
    fn context_supports_ipv6() {
        let mut ctx = RequestContext::new();
        ctx.client_ip = Some("::1".parse().unwrap());
        assert_eq!(ctx.client_ip.unwrap().to_string(), "::1");
    }

    // --- Trace context integration ---

    #[test]
    fn trace_ctx_defaults_to_none() {
        let ctx = RequestContext::new();
        assert!(ctx.trace_ctx.is_none());
    }

    #[test]
    fn trace_ctx_survives_pipeline_assignment() {
        let mut ctx = RequestContext::new();

        // Simulate request_filter: parse incoming traceparent.
        let incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let trace = sbproxy_observe::trace_ctx::w3c::TraceContext::parse(incoming).unwrap();
        ctx.trace_ctx = Some(trace);

        assert!(ctx.trace_ctx.is_some());
        let tc = ctx.trace_ctx.as_ref().unwrap();
        assert_eq!(tc.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(tc.is_sampled());

        // Simulate upstream_request_filter: create child span.
        let child = tc.child();
        assert_eq!(child.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_ne!(child.parent_id, "00f067aa0ba902b7");
        ctx.trace_ctx = Some(child);

        // Simulate response_filter: serialize for downstream.
        let traceparent = ctx.trace_ctx.as_ref().unwrap().to_traceparent();
        assert!(traceparent.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
        assert!(traceparent.ends_with("-01"));
    }

    #[test]
    fn trace_ctx_new_random_when_no_incoming_header() {
        let mut ctx = RequestContext::new();
        // Simulate: no traceparent header -> generate fresh context.
        ctx.trace_ctx = Some(sbproxy_observe::TraceContext::new_random());
        let tc = ctx.trace_ctx.as_ref().unwrap();
        assert_eq!(tc.trace_id.len(), 32);
        assert_eq!(tc.parent_id.len(), 16);
        assert!(tc.is_sampled());
    }

    // --- Classifier verdict state (F5) ---

    #[test]
    fn classifier_fields_default_to_none_and_empty() {
        let ctx = RequestContext::new();
        assert!(ctx.classifier_prompt.is_none());
        assert!(ctx.classifier_intent.is_none());
        assert!(ctx.classifier_extensions.is_empty());

        // Accessors mirror the field state.
        assert!(ctx.classifier_prompt().is_none());
        assert!(ctx.classifier_intent().is_none());
        assert!(ctx.classifier_extension("enterprise.pii").is_none());
    }

    #[test]
    fn classifier_fields_are_mutable_and_read_back() {
        use crate::hooks::{ClassifyVerdict, IntentCategory};
        use std::collections::HashMap;

        let mut ctx = RequestContext::new();

        // Populate prompt verdict.
        let mut scores = HashMap::new();
        scores.insert("toxic".to_string(), 0.12_f32);
        scores.insert("safe".to_string(), 0.88_f32);
        let verdict = ClassifyVerdict {
            labels: vec!["safe".to_string()],
            scores,
            confidence: 0.88,
        };
        ctx.classifier_prompt = Some(verdict.clone());
        ctx.classifier_intent = Some(IntentCategory::Coding);
        ctx.classifier_extensions
            .insert("enterprise.pii".to_string(), serde_json::json!({"hits": 0}));

        // Accessors surface the populated values.
        let got = ctx.classifier_prompt().expect("prompt verdict set");
        assert_eq!(got.labels, vec!["safe".to_string()]);
        assert!((got.confidence - 0.88).abs() < f32::EPSILON);

        assert_eq!(ctx.classifier_intent(), Some(IntentCategory::Coding));

        let ext = ctx
            .classifier_extension("enterprise.pii")
            .expect("extension set");
        assert_eq!(ext["hits"], 0);
        assert!(ctx.classifier_extension("enterprise.language").is_none());
    }
}
