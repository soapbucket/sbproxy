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
use sbproxy_modules::policy::ConcurrentLimitGuard;
use sbproxy_modules::transform::{CelHeaderMutation, MarkdownProjection};
use sbproxy_modules::{ContentShape, RateLimitInfo};
use sbproxy_observe::UserIdSource;
use sbproxy_plugin::AuthDecision;
use ulid::Ulid;

use crate::hooks::{ClassifyVerdict, IntentCategory};

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
/// Wave 4 introduces a small bag of counters that the Q4.14 audit
/// regression and operator dashboards consume. New fields land here
/// rather than widening [`RequestContext`] every time a transform
/// wants to surface a number.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestMetrics {
    /// Bytes removed from the upstream response body by the
    /// boilerplate-stripping transform (G4.10). `0` when the
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

    // --- Origin routing ---
    /// Index into `CompiledConfig.origins`, set after host routing.
    pub origin_idx: Option<usize>,

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

    // --- Load balancer state ---
    /// Index of the selected load balancer target (for connection tracking).
    pub lb_target_idx: Option<usize>,

    // --- Upstream retry state ---
    /// Number of retry attempts already made for this request.
    /// `0` means we are on the original attempt; `1` means one retry
    /// has occurred. Compared against the action's `RetryConfig.max_attempts`
    /// in `fail_to_connect` to decide whether to retry again.
    pub retry_count: u32,

    // --- Concurrent limit guards ---
    /// Permits issued by `ConcurrentLimitPolicy` for this request. The
    /// guards release their slots when dropped, which happens when the
    /// context is dropped at the end of the request lifecycle.
    pub concurrent_limit_guards: Vec<ConcurrentLimitGuard>,

    // --- Request validator state ---
    /// Set by `check_policies` when a `RequestValidator` policy is
    /// configured on this origin. When true, `request_body_filter`
    /// accumulates the body into `request_body_buf` and runs every
    /// matching validator once the stream ends.
    pub validate_request_body: bool,
    /// Buffered request body, populated only when `validate_request_body`
    /// is true.
    pub request_body_buf: Option<BytesMut>,
    /// Set by `request_body_filter` when a request body fails schema
    /// validation. The triple is `(status, body, content_type)` and is
    /// surfaced by `fail_to_proxy` (the body filter aborts the
    /// upstream by returning Ok with no body, then we synthesise the
    /// rejection in `fail_to_proxy`).
    pub validator_failed: Option<(u16, String, String)>,

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

    // --- AI Crawl Control challenge ---
    /// Set by an `ai_crawl_control` policy when a request must be
    /// charged. Tuple is `(header_name, challenge_value, json_body)`.
    /// The 402 response handler reads this to stamp the configured
    /// header and write the JSON body.
    pub crawl_challenge: Option<(String, String, String)>,

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

    // --- Wave 8 P0 envelope dimensions ---
    //
    // Filled at request entry by `pipeline::capture_wave8_dimensions`.
    // The envelope shape is locked by `docs/adr-event-envelope.md`;
    // per-stream semantics live in the companion ADRs
    // (`adr-custom-properties.md`, `adr-session-id.md`,
    // `adr-user-id.md`).
    /// Caller-supplied custom properties from `X-Sb-Property-*`
    /// headers. Cardinality-capped, allowlist-checked, redaction-applied.
    pub properties: BTreeMap<String, String>,
    /// Session identifier (caller-supplied or auto-generated for
    /// anonymous traffic per `SessionsConfig::auto_generate`).
    pub session_id: Option<Ulid>,
    /// Parent session linkage. Caller-supplied only; never
    /// auto-generated.
    pub parent_session_id: Option<Ulid>,
    /// Resolved end-user identifier per `adr-user-id.md`. Set when a
    /// trusted source (header today; JWT and forward-auth in the
    /// follow-up slice) yields a non-empty value.
    pub user_id: Option<String>,
    /// Diagnostic stamp recording which source filled `user_id`.
    pub user_id_source: Option<UserIdSource>,
    /// ISO-3166-1 alpha-2 country derived from `client_ip` by the
    /// optional geo-enrichment policy (PORTAL.md gap 3.1 P2). Stays
    /// `None` when the policy is not configured.
    pub request_geo: Option<String>,
    /// ULID for the Wave 8 envelope (`docs/adr-event-envelope.md`).
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
    // the resolved identity. See `docs/adr-agent-class-taxonomy.md`
    // for the schema.
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

    // --- ML agent classifier verdict (A5.2 / G5.5) ---
    //
    // Populated by the enterprise classifier sidecar's feature builder
    // + ONNX inference path. In async mode (the default), the verdict
    // lands here after the request phase and is read by response-phase
    // policies. In sync mode, it lands before policy evaluation.
    //
    // `None` when:
    //   - the `agent-classifier` feature is disabled,
    //   - no enterprise classifier is configured for this hostname,
    //   - or inference timed out and the timeout path filled `Some` with
    //     `MlClass::Unknown`. (Timeout still produces `Some` so the
    //     access log can distinguish "did not run" from "ran and gave up".)
    /// Verdict from the ML agent classifier (A5.2). See
    /// `docs/adr-ml-agent-classifier.md` for the contract.
    #[cfg(feature = "agent-classifier")]
    pub ml_classification: Option<sbproxy_classifiers::MlClassification>,

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
    /// G4.3 / G4.4 once the projection runs. Read by G4.5's
    /// `x-markdown-tokens` header emitter. Owned by rust-A.
    pub markdown_token_estimate: Option<u32>,

    // --- Wave 4 metrics (G4.10) ---
    /// Per-request metrics counters surfaced for the Q4.14 audit.
    /// Adds up bytes stripped by the boilerplate transform, etc.
    pub metrics: RequestMetrics,

    // --- AI gateway access-log fields ---
    /// Resolved AI provider (`openai`, `anthropic`, `bedrock`, ...)
    /// when the AI handler dispatched the request. `None` for
    /// non-AI traffic.
    pub ai_provider: Option<String>,
    /// AI model identifier the request routed to (e.g. `gpt-4o`,
    /// `claude-sonnet-4-6`). Captured before the upstream call so
    /// the access log records the resolved model even when the
    /// upstream errors before returning a body.
    pub ai_model: Option<String>,
    /// Prompt / input tokens reported by the provider response.
    pub ai_tokens_in: Option<u64>,
    /// Completion / output tokens reported by the provider response.
    pub ai_tokens_out: Option<u64>,

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
    /// origin. Held so the JSON envelope builder (G4.4) and the Markdown
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
    // Captured at the Pingora TLS session lifecycle hook by
    // [`sbproxy_tls::parse_client_hello`] when the `tls-fingerprint`
    // cargo feature is on. `ja4h` is filled mid-pipeline by
    // [`sbproxy_tls::compute_ja4h`] in `request_filter`, after
    // headers are read. `None` for plaintext HTTP requests or when
    // the feature is disabled.
    /// JA3 / JA4 / JA4H / JA4S fingerprint bundle for this request.
    /// See [`sbproxy_tls::TlsFingerprint`].
    pub tls_fingerprint: Option<sbproxy_tls::TlsFingerprint>,

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
    // this field and never recomputes it. See
    // `docs/adr-a2a-protocol-envelope.md`.
    /// Per-request A2A envelope. `None` for non-A2A traffic.
    pub a2a: Option<sbproxy_modules::A2AContext>,
    /// JSON denial body produced by the A2A policy module (Wave 7 /
    /// A7.2). Populated by the policy enforcer when a denial fires
    /// so the response handler can stamp the spec-pinned body
    /// verbatim instead of falling through to the generic
    /// `send_error` template.
    pub a2a_denial_body: Option<String>,
}

/// Verdict produced by the headless-browser detector
/// (`sbproxy_security::headless_detect`).
///
/// Wave 5 / G5.4. The detector compares the request's JA4 fingerprint
/// against the vendored TLS-fingerprint catalogue
/// (`crates/sbproxy-classifiers/data/tls-fingerprints.json`); a
/// match yields [`Self::Detected`] with the library name (e.g.
/// `"puppeteer"`) and a confidence score that is halved to a 0.5 cap
/// when the fingerprint is not trustworthy (e.g. behind a CDN that
/// terminated TLS). See `docs/adr-tls-fingerprint-pipeline.md`.
#[derive(Debug, Clone, PartialEq)]
pub enum HeadlessSignal {
    /// Detector ran and matched a known headless library.
    Detected {
        /// Library name (`puppeteer`, `playwright`, ...). Stable
        /// across releases; safe for metric labels.
        library: String,
        /// Confidence in `[0.0, 1.0]`. Halved (capped at 0.5) when
        /// `tls_fingerprint.trustworthy = false` per A5.1.
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
            origin_idx: None,
            lb_target_idx: None,
            retry_count: 0,
            concurrent_limit_guards: Vec::new(),
            validate_request_body: false,
            request_body_buf: None,
            validator_failed: None,
            body_size_limit: None,
            body_bytes_seen: 0,
            request_body_bytes: 0,
            response_body_bytes: 0,
            mirror_pending: None,
            auth_result: None,
            force_ssl_checked: false,
            short_circuit_status: None,
            short_circuit_body: None,
            request_start: None,
            response_status: None,
            rate_limit_info: None,
            response_body_buf: None,
            buffering_body: false,
            upstream_content_type: None,
            sri_scan_enabled: false,
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
            crawl_challenge: None,
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
            #[cfg(feature = "agent-classifier")]
            ml_classification: None,
            aipref: None,
            canonical_url: None,
            metrics: RequestMetrics::default(),
            ai_provider: None,
            ai_model: None,
            ai_tokens_in: None,
            ai_tokens_out: None,
            content_shape_pricing: None,
            content_shape_transform: None,
            markdown_token_estimate: None,
            markdown_projection: None,
            rsl_urn: None,
            citation_required: None,
            tls_fingerprint: None,
            headless_signal: None,
            a2a: None,
            a2a_denial_body: None,
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
