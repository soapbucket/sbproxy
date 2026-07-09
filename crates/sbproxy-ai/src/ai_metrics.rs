//! Per-provider, per-model AI gateway metrics.
//!
//! Tracks requests, tokens, cost, failovers, guardrail blocks,
//! cache hits, and budget utilization for every AI provider and model.

use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_gauge_vec,
    register_histogram_vec, Counter, CounterVec, Gauge, GaugeVec, HistogramOpts, HistogramVec,
    Opts,
};
use std::sync::LazyLock;

// --- Provider metrics ---

static AI_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new("sbproxy_ai_requests_total", "AI gateway requests"),
        &["provider", "model", "status"]
    )
    .unwrap()
});

/// Per-surface request counter, partitioned by AI surface (chat
/// completions, assistants, embeddings, image generation, etc.) and
/// HTTP method.
///
/// Additive with `sbproxy_ai_requests_total`; dashboards that
/// aggregate by provider/model continue to use the original counter,
/// while surface-aware views use this one. Cardinality is bounded by
/// the closed `AiSurface::label()` set times the standard HTTP method
/// set (~17 surfaces times ~7 methods). A `status` partition will be
/// added in a later phase when per-surface billing events carry the
/// final response status.
static AI_SURFACE_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_surface_requests_total",
            "AI gateway requests partitioned by classified surface"
        ),
        &["surface", "method"]
    )
    .unwrap()
});

/// Per-surface request latency in seconds.
///
/// Sibling of `AI_LATENCY` (which is per-provider). The two histograms
/// share their bucket schedule so cross-cut dashboards can plot
/// "surface vs provider" side by side without quantile mismatch.
static AI_SURFACE_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_surface_request_duration_seconds",
            "AI request latency partitioned by classified surface"
        )
        .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]),
        &["surface", "method"]
    )
    .unwrap()
});

static AI_TOKENS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new("sbproxy_ai_tokens_total", "Tokens consumed"),
        &["provider", "model", "direction"] // direction: "input" | "output"
    )
    .unwrap()
});

static AI_COST: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new("sbproxy_ai_cost_dollars_total", "Estimated cost in USD"),
        &["provider", "model"]
    )
    .unwrap()
});

static AI_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new("sbproxy_ai_request_duration_seconds", "AI request latency")
            .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]),
        &["provider", "model"]
    )
    .unwrap()
});

/// Per-attribution model latency histogram (WOR-1501). Mirrors
/// `AI_LATENCY`'s bucket schedule but adds the surface and the
/// authoritative identity dimensions (tenant + credential) so p50 / p95
/// upstream latency can be sliced per tenant, per credential, and per
/// model, not just globally per provider/model. Same bounded-cardinality
/// contract as the attributed spend metrics.
static AI_LATENCY_ATTRIBUTED: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_request_duration_attributed_seconds",
            "AI upstream request latency, partitioned by surface + tenant + credential (WOR-1501)"
        )
        .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]),
        &["provider", "model", "surface", "tenant_id", "api_key_id"]
    )
    .unwrap()
});

/// Record upstream model latency on the live request path.
///
/// Observes BOTH the long-standing global histogram
/// (`sbproxy_ai_request_duration_seconds{provider, model}`) and the
/// attributed histogram (`sbproxy_ai_request_duration_attributed_seconds`,
/// which adds surface + tenant + credential), so existing dashboards and
/// the new per-credential / per-tenant latency view both work off a
/// single call site. `secs` is the upstream round-trip latency to the
/// accepted response. A non-finite or negative value is dropped.
#[allow(clippy::too_many_arguments)]
pub fn record_model_latency(
    provider: &str,
    model: &str,
    surface: &str,
    tenant_id: &str,
    api_key_id: &str,
    secs: f64,
) {
    if !secs.is_finite() || secs < 0.0 {
        return;
    }
    AI_LATENCY
        .with_label_values(&[provider, model])
        .observe(secs);
    AI_LATENCY_ATTRIBUTED
        .with_label_values(&[provider, model, surface, tenant_id, api_key_id])
        .observe(secs);
}

// Time to first token, in seconds. Recorded once per streaming
// response when the first token arrives. The Prometheus client
// auto-derives the `_bucket`, `_sum`, and `_count` series referenced
// by the AI gateway dashboard.
static AI_TTFT: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_ttft_seconds",
            "AI streaming time to first token"
        )
        .buckets(vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]),
        &["provider", "model"]
    )
    .unwrap()
});

// WOR-895: streaming output throughput in tokens per second. Recorded
// once per streaming response, after the upstream usage parser reports
// final completion tokens, against the generation window
// (first-token -> stream-end), so TTFT does not depress it. Bucket
// boundaries span typical model speeds (tiny / chat / fast streaming /
// frontier accelerators).
static AI_OUTPUT_THROUGHPUT: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_output_throughput_tokens_per_second",
            "AI streaming output throughput (completion tokens / generation duration)"
        )
        .buckets(vec![
            1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0
        ]),
        &["provider", "model"]
    )
    .unwrap()
});

// Per-provider error counter. Incremented at every site that maps a
// non-success outcome back to a named provider (transport error,
// timeout, upstream 4xx/5xx, parse failure). The dashboard groups by
// `provider`; `error_kind` is intended for ad-hoc drill-downs and
// should stay low cardinality (handful of stable strings). The AI
// gateway dispatch path uses the same stable categories it records on
// span `error.type`, such as `rate_limited`, `content_filter`,
// `upstream_5xx`, and `timeout`.
static AI_PROVIDER_ERRORS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_provider_errors_total",
            "Per-provider AI error events"
        ),
        &["provider", "error_kind"]
    )
    .unwrap()
});

static AI_FAILOVERS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new("sbproxy_ai_failovers_total", "Provider failover events"),
        &["from_provider", "to_provider", "reason"]
    )
    .unwrap()
});

/// WOR-798: every provider selection by the AI router. `strategy`
/// is the active `RoutingStrategy` variant name (snake_case); the
/// `provider` label is the picked provider's configured name.
/// Cardinality is bounded by the number of strategies (small, fixed)
/// times the per-origin provider count, both of which are operator-
/// declared in config.
static AI_LB_DECISIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_lb_decisions_total",
            "AI router provider selections by strategy"
        ),
        &["strategy", "provider"]
    )
    .unwrap()
});

static AI_GUARDRAIL_BLOCKS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_guardrail_blocks_total",
            "Guardrail block events"
        ),
        &["category"] // "pii", "injection", "toxicity", "jailbreak", etc.
    )
    .unwrap()
});

static AI_CACHE_RESULTS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_cache_results_total",
            "AI response cache results"
        ),
        &["provider", "cache_type", "result"] // cache_type: "exact"|"semantic", result: "hit"|"miss"
    )
    .unwrap()
});

// Cosine similarity score of a semantic-cache hit, per provider
// (WOR-796). Recorded only on a hit so the dashboard can show the
// distribution of how close served prompts were to their cached match.
static AI_SEMANTIC_SIMILARITY: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_semantic_cache_similarity",
            "Cosine similarity of semantic-cache hits"
        )
        .buckets(vec![0.5, 0.7, 0.8, 0.85, 0.9, 0.95, 0.98, 0.99, 1.0]),
        &["provider"]
    )
    .unwrap()
});

static AI_BUDGET_UTILIZATION: LazyLock<GaugeVec> = LazyLock::new(|| {
    register_gauge_vec!(
        Opts::new(
            "sbproxy_ai_budget_utilization_ratio",
            "Budget utilization as ratio 0-1"
        ),
        &["scope"] // "org", "team", "project", "user"
    )
    .unwrap()
});

// --- Realtime session metrics (Phase 7) ---

static AI_REALTIME_SESSIONS_ACTIVE: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "sbproxy_ai_realtime_sessions_active",
        "Currently open OpenAI Realtime API WebSocket sessions"
    )
    .unwrap()
});

static AI_REALTIME_SESSION_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_realtime_session_duration_seconds",
            "Wall-clock duration of a Realtime WebSocket session, recorded on close"
        )
        .buckets(vec![
            1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0
        ]),
        &["provider", "close_reason"]
    )
    .unwrap()
});

static AI_REALTIME_AUDIO_SECONDS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_realtime_audio_seconds_total",
            "Cumulative audio seconds forwarded over Realtime sessions"
        ),
        &["provider", "direction"]
    )
    .unwrap()
});

static AI_REALTIME_FRAMES_FORWARDED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_realtime_frames_forwarded_total",
            "Cumulative frames forwarded over Realtime sessions"
        ),
        &["provider", "direction", "kind"]
    )
    .unwrap()
});

/// Bump the active-sessions gauge on Realtime session open.
pub fn inc_realtime_sessions_active() {
    AI_REALTIME_SESSIONS_ACTIVE.inc();
}

/// Bump the active-sessions gauge on Realtime session close.
pub fn dec_realtime_sessions_active() {
    AI_REALTIME_SESSIONS_ACTIVE.dec();
}

/// Read the current active-sessions gauge value.
pub fn realtime_sessions_active_value() -> f64 {
    AI_REALTIME_SESSIONS_ACTIVE.get()
}

/// Record a Realtime session duration in seconds. `close_reason` is
/// a low-cardinality label (`client_closed`, `upstream_closed`,
/// `policy_violation`, `error`).
pub fn record_realtime_session_duration(provider: &str, close_reason: &str, duration_secs: f64) {
    AI_REALTIME_SESSION_DURATION
        .with_label_values(&[provider, close_reason])
        .observe(duration_secs);
}

/// Record audio seconds forwarded over a Realtime session.
/// `direction` is `inbound` (client to provider) or `outbound`
/// (provider to client).
pub fn record_realtime_audio_seconds(provider: &str, direction: &str, seconds: f64) {
    if seconds <= 0.0 {
        return;
    }
    AI_REALTIME_AUDIO_SECONDS
        .with_label_values(&[provider, direction])
        .inc_by(seconds);
}

/// Record one frame forwarded. `kind` is `text` or `audio`.
pub fn record_realtime_frame(provider: &str, direction: &str, kind: &str) {
    AI_REALTIME_FRAMES_FORWARDED
        .with_label_values(&[provider, direction, kind])
        .inc();
}

static AI_PRICE_SOURCE: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_price_source_total",
            "Cost estimates by the price-table layer that produced the price (WOR-1710)"
        ),
        &["source"]
    )
    .unwrap()
});

/// Record which price-table layer produced a request's cost (WOR-1710).
/// `source` is `config`, `rate_card`, `catalog`, or `fallback`. A high
/// `fallback` share signals a stale catalog or a missing rate card, so
/// reported cost is the pessimistic $5/$5 default rather than real.
pub fn record_price_source(source: &str) {
    AI_PRICE_SOURCE.with_label_values(&[source]).inc();
}

// --- Shadow supervisor metrics ---

static AI_SHADOW_INFLIGHT: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "sbproxy_ai_shadow_inflight",
        "Currently in-flight shadow request tasks supervised by the AI client"
    )
    .unwrap()
});

static AI_SHADOW_DROPPED: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "sbproxy_ai_shadow_dropped_total",
        "Shadow requests dropped because the supervisor queue was full"
    )
    .unwrap()
});

static AI_SHADOW_TIMEOUT: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "sbproxy_ai_shadow_timeout_total",
        "Shadow requests dropped because the supervisor task timeout elapsed"
    )
    .unwrap()
});

/// Increment the in-flight shadow gauge by one. Pair every call with
/// a matching `dec_shadow_inflight()` (Drop guard recommended) so the
/// gauge always reflects the supervisor's current depth.
pub fn inc_shadow_inflight() {
    AI_SHADOW_INFLIGHT.inc();
}

/// Decrement the in-flight shadow gauge by one.
pub fn dec_shadow_inflight() {
    AI_SHADOW_INFLIGHT.dec();
}

/// Record one shadow request that the supervisor refused to spawn
/// because the in-flight queue was at capacity.
pub fn record_shadow_dropped() {
    AI_SHADOW_DROPPED.inc();
}

/// Record one shadow task that exceeded its wall-clock supervisor
/// timeout and was cancelled.
pub fn record_shadow_timeout() {
    AI_SHADOW_TIMEOUT.inc();
}

// --- Cascade routing metrics ---

/// Per-tier outcome counter for the [`RoutingStrategy::Cascade`]
/// dispatch path. `tier` is the 0-based tier index as a decimal
/// string; `outcome` is one of `accepted`, `retry`, or `cost_cap`.
/// Cardinality is bounded by the number of configured tiers (in
/// practice 2 to 5) times the three outcome labels.
///
/// [`RoutingStrategy::Cascade`]: crate::routing::RoutingStrategy::Cascade
static AI_CASCADE_TIER_OUTCOMES: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_cascade_tier_outcomes_total",
            "Cascade routing tier outcomes (accepted | retry | cost_cap)"
        ),
        &["tier", "outcome"]
    )
    .unwrap()
});

/// Record one cascade tier outcome. `tier_index` is converted to a
/// decimal label; `outcome` should be a low-cardinality stable
/// string from the closed set `{accepted, retry, cost_cap}`.
pub fn record_cascade_tier_outcome(tier_index: usize, outcome: &str) {
    AI_CASCADE_TIER_OUTCOMES
        .with_label_values(&[tier_index.to_string().as_str(), outcome])
        .inc();
}

/// Read the cumulative cascade tier outcome counter value. Tests
/// use this to assert that the expected tiers ticked. Returns 0
/// when no observations have landed yet.
pub fn cascade_tier_outcome_value(tier_index: usize, outcome: &str) -> f64 {
    AI_CASCADE_TIER_OUTCOMES
        .with_label_values(&[tier_index.to_string().as_str(), outcome])
        .get()
}

/// Read the current value of the in-flight shadow gauge. Used in
/// tests and admin diagnostics to assert supervisor depth.
pub fn shadow_inflight_value() -> f64 {
    AI_SHADOW_INFLIGHT.get()
}

/// Read the cumulative shadow-dropped counter value. Tests use this
/// to assert that an overflow tick happened.
pub fn shadow_dropped_value() -> f64 {
    AI_SHADOW_DROPPED.get()
}

/// Read the cumulative shadow-timeout counter value. Tests use this
/// to assert that a hung shadow was actually cancelled.
pub fn shadow_timeout_value() -> f64 {
    AI_SHADOW_TIMEOUT.get()
}

// --- Per-key metrics ---

static AI_KEY_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new("sbproxy_ai_key_requests_total", "Requests per virtual key"),
        &["virtual_key", "provider", "model"]
    )
    .unwrap()
});

static AI_KEY_TOKENS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new("sbproxy_ai_key_tokens_total", "Tokens per virtual key"),
        &["virtual_key", "direction"]
    )
    .unwrap()
});

static AI_KEY_COST: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new("sbproxy_ai_key_cost_dollars_total", "Cost per virtual key"),
        &["virtual_key"]
    )
    .unwrap()
});

// --- AI gateway rate-limit rejection counter ---
//
// Operators alert on any non-zero rate of this counter to detect a
// rejected client. `axis` is the bucket that tripped (`rpm`, `tpm`,
// `rpd`, `tpd`, `concurrent`). `key_hash` is the hashed virtual key
// the rejection was charged to; the limiter never receives the raw
// key. `model` is the upstream model name.
static AI_RATELIMIT_REJECTED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_ratelimit_rejected_total",
            "AI gateway rate-limit rejections, partitioned by axis",
        ),
        &["axis", "key_hash", "tenant", "model"]
    )
    .unwrap()
});

// --- Pre-request token estimate error ratio ---
//
// Sampled at reconcile time as `(actual - estimated) / actual` so the
// histogram captures both over-estimation (negative values) and
// under-estimation (positive values). The buckets straddle zero so a
// well-tuned estimator concentrates around 0 and operators alert when
// the p95 drifts outside +/- 0.10. The `model` label keeps drift
// observable per model so an upstream tokenizer change shows up as a
// step function on one series rather than blurring into the aggregate.
static AI_TOKEN_ESTIMATE_ERROR_RATIO: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_token_estimate_error_ratio",
            "Relative error of pre-request token estimate vs upstream usage.prompt_tokens",
        )
        .buckets(vec![
            -1.0, -0.5, -0.25, -0.10, -0.05, 0.0, 0.05, 0.10, 0.25, 0.5, 1.0
        ]),
        &["model"]
    )
    .unwrap()
});

/// Record a completed AI request.
pub fn record_ai_request(
    provider: &str,
    model: &str,
    status: u16,
    duration_secs: f64,
    input_tokens: u64,
    output_tokens: u64,
    cost: f64,
) {
    let status_str = status.to_string();
    AI_REQUESTS
        .with_label_values(&[provider, model, &status_str])
        .inc();
    AI_LATENCY
        .with_label_values(&[provider, model])
        .observe(duration_secs);
    AI_TOKENS
        .with_label_values(&[provider, model, "input"])
        .inc_by(input_tokens as f64);
    AI_TOKENS
        .with_label_values(&[provider, model, "output"])
        .inc_by(output_tokens as f64);
    if cost > 0.0 {
        AI_COST.with_label_values(&[provider, model]).inc_by(cost);
    }
}

/// Record a request against the per-surface counter.
///
/// Called once per AI request from `handle_ai_proxy` (in `sbproxy-core`)
/// with the surface label from `classify_surface`. Separate from
/// `record_ai_request` so adding the surface partition does not change
/// the cardinality of the original counter that existing dashboards
/// and alerts depend on.
pub fn record_surface_request(surface: &str, method: &str) {
    AI_SURFACE_REQUESTS
        .with_label_values(&[surface, method])
        .inc();
}

/// Record per-surface request latency in seconds.
pub fn record_surface_latency(surface: &str, method: &str, duration_secs: f64) {
    AI_SURFACE_LATENCY
        .with_label_values(&[surface, method])
        .observe(duration_secs);
}

/// Counter for requests that bypassed the hub round-trip because the
/// client and upstream provider speak the same wire format. The
/// `inbound_format` label matches the values stamped on
/// `ctx.ai_inbound_format` (`anthropic`, `openai`, `responses`); the
/// `provider_format` label matches `ProviderFormat` snake-case names.
/// Cardinality is bounded by the small closed sets on both sides.
static AI_NATIVE_BYPASS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_native_bypass_total",
            "AI requests that bypassed the hub format round-trip when client format matched provider format"
        ),
        &["inbound_format", "provider_format"]
    )
    .unwrap()
});

/// Record one native-format-bypass event. Called from the AI dispatch
/// path in `sbproxy-core` once an inbound request has been matched to
/// an upstream provider whose wire format already equals the inbound
/// format, so no hub round-trip is needed.
pub fn record_native_bypass(inbound_format: &str, provider_format: &str) {
    AI_NATIVE_BYPASS
        .with_label_values(&[inbound_format, provider_format])
        .inc();
}

/// RAII guard that records per-surface latency when it is dropped.
///
/// Created at the start of `handle_ai_proxy` (in `sbproxy-core`); its
/// `Drop` impl observes the elapsed wall-clock time against
/// `sbproxy_ai_surface_request_duration_seconds`. This guarantees a
/// latency observation on every exit path, including early returns
/// for validation failures and panic unwinding.
pub struct AiSurfaceLatencyGuard {
    surface: &'static str,
    method: String,
    started: std::time::Instant,
}

impl AiSurfaceLatencyGuard {
    /// Open a latency guard. `surface` is the static label returned by
    /// `AiSurface::label()`. `method` is the inbound HTTP method.
    pub fn new(surface: &'static str, method: String) -> Self {
        Self {
            surface,
            method,
            started: std::time::Instant::now(),
        }
    }
}

impl Drop for AiSurfaceLatencyGuard {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed().as_secs_f64();
        record_surface_latency(self.surface, &self.method, elapsed);
    }
}

/// Record a failover event.
pub fn record_failover(from: &str, to: &str, reason: &str) {
    AI_FAILOVERS.with_label_values(&[from, to, reason]).inc();
}

/// WOR-798: record one AI router selection. `strategy` is the
/// active `RoutingStrategy` variant rendered as a snake_case name
/// (`round_robin`, `peak_ewma`, `least_token_usage`, ...). `provider`
/// is the picked provider's configured name.
pub fn record_lb_decision(strategy: &str, provider: &str) {
    AI_LB_DECISIONS
        .with_label_values(&[strategy, provider])
        .inc();
}

/// Record a streaming time-to-first-token observation, in seconds.
///
/// Call sites: the streaming relay's first-token hook, after the
/// per-request `StreamTracker::record_first_token` has captured the
/// instant. Convert with `tracker.ttft_ms().map(|ms| ms / 1000.0)`.
pub fn record_ttft(provider: &str, model: &str, ttft_seconds: f64) {
    AI_TTFT
        .with_label_values(&[provider, model])
        .observe(ttft_seconds);
}

/// Record one streaming response's output throughput in tokens per
/// second, measured against the generation window (first-token ->
/// stream-end) so TTFT does not depress it. Caller filters out zero /
/// non-positive values so the histogram only sees meaningful samples.
pub fn record_output_throughput(provider: &str, model: &str, tokens_per_second: f64) {
    if tokens_per_second.is_finite() && tokens_per_second > 0.0 {
        AI_OUTPUT_THROUGHPUT
            .with_label_values(&[provider, model])
            .observe(tokens_per_second);
    }
}

/// Record a per-provider error.
///
/// `error_kind` is a short, low-cardinality label (e.g. `transport`,
/// `timeout`, `rate_limited`, `content_filter`, `upstream_5xx`,
/// `http_4xx`, `http_5xx`, `parse`). Free-form upstream strings should
/// be mapped to one of these stable buckets before being passed in.
pub fn record_provider_error(provider: &str, error_kind: &str) {
    AI_PROVIDER_ERRORS
        .with_label_values(&[provider, error_kind])
        .inc();
}

/// Record a guardrail block.
pub fn record_guardrail_block(category: &str) {
    AI_GUARDRAIL_BLOCKS.with_label_values(&[category]).inc();
}

// --- Context-poisoning guardrail metrics ---

/// Per-rule, per-action counter of context-poisoning findings. Fires
/// once for every rule hit regardless of whether the configured
/// `action` blocks the request, so dashboards can compare log/score
/// volume against deny volume.
static AI_CONTEXT_POISONING_FINDINGS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_context_poisoning_findings_total",
            "Context-poisoning guardrail findings",
        ),
        &["rule_id", "action"]
    )
    .unwrap()
});

/// Counter of context-poisoning hits that resulted in a blocked
/// request (configured action `deny`).
static AI_CONTEXT_POISONING_BLOCKED: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "sbproxy_ai_context_poisoning_blocked_total",
        "Context-poisoning guardrail blocked-request count",
    )
    .unwrap()
});

/// Record a single context-poisoning finding. `rule_id` is the stable
/// ID from the rule catalogue; `action` is one of `log`, `score`,
/// `deny`.
pub fn record_context_poisoning_finding(rule_id: &str, action: &str) {
    AI_CONTEXT_POISONING_FINDINGS
        .with_label_values(&[rule_id, action])
        .inc();
}

/// Record one context-poisoning hit that resulted in a blocked
/// request. Called only when `action` is `deny`.
pub fn record_context_poisoning_blocked() {
    AI_CONTEXT_POISONING_BLOCKED.inc();
}

/// Read the cumulative blocked-request counter. Used in tests.
pub fn context_poisoning_blocked_value() -> f64 {
    AI_CONTEXT_POISONING_BLOCKED.get()
}

/// Record a cache result.
pub fn record_cache_result(provider: &str, cache_type: &str, hit: bool) {
    let result = if hit { "hit" } else { "miss" };
    AI_CACHE_RESULTS
        .with_label_values(&[provider, cache_type, result])
        .inc();
}

/// Record the cosine similarity of a semantic-cache hit (WOR-796).
pub fn record_semantic_similarity(provider: &str, score: f32) {
    AI_SEMANTIC_SIMILARITY
        .with_label_values(&[provider])
        .observe(score as f64);
}

/// Update budget utilization gauge.
pub fn set_budget_utilization(scope: &str, ratio: f64) {
    AI_BUDGET_UTILIZATION.with_label_values(&[scope]).set(ratio);
}

/// Record an AI gateway rate-limit rejection.
///
/// `axis` is the stable label returned by
/// [`crate::ratelimit::RejectReason::axis_label`]; `key_hash` is the
/// hashed virtual-key identifier (never the raw key); `tenant` is the
/// originating tenant (empty for the tenant-blind entry point); `model`
/// is the upstream model name. Surface this via the
/// `sbproxy_ai_ratelimit_rejected_total` counter; operators alert when
/// any axis fires.
pub fn record_ratelimit_rejected(axis: &str, key_hash: &str, tenant: &str, model: &str) {
    AI_RATELIMIT_REJECTED
        .with_label_values(&[axis, key_hash, tenant, model])
        .inc();
}

/// Read the cumulative value of the rate-limit rejection counter for
/// one `(axis, key_hash, tenant, model)` tuple. Used by tests.
pub fn ratelimit_rejected_value(axis: &str, key_hash: &str, tenant: &str, model: &str) -> f64 {
    AI_RATELIMIT_REJECTED
        .with_label_values(&[axis, key_hash, tenant, model])
        .get()
}

/// Record one observation against the pre-request token-estimate error
/// histogram. `estimated` is the pre-flight reservation;
/// `actual` is the reconciled `usage.prompt_tokens` from the upstream
/// response. A zero-token actual is dropped to keep the ratio
/// well-defined.
pub fn record_token_estimate_error(model: &str, estimated: u64, actual: u64) {
    if actual == 0 {
        return;
    }
    let ratio = (actual as f64 - estimated as f64) / actual as f64;
    AI_TOKEN_ESTIMATE_ERROR_RATIO
        .with_label_values(&[model])
        .observe(ratio);
}

/// Record per-key usage.
pub fn record_key_usage(
    key: &str,
    provider: &str,
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
    cost: f64,
) {
    AI_KEY_REQUESTS
        .with_label_values(&[key, provider, model])
        .inc();
    AI_KEY_TOKENS
        .with_label_values(&[key, "input"])
        .inc_by(input_tokens as f64);
    AI_KEY_TOKENS
        .with_label_values(&[key, "output"])
        .inc_by(output_tokens as f64);
    if cost > 0.0 {
        AI_KEY_COST.with_label_values(&[key]).inc_by(cost);
    }
}

// --- Waste-signal metrics (WOR-1085) ---
//
// The Token-to-Value Ledger lists "tokens spent with no outcome"
// detectors that the gateway can flag deterministically without
// any guess about what the caller intended:
//
// * `duplicate_request`: response_dedup.rs already detects an
//   exact-context resend; tag the spend wasted.
// * `abandoned_stream`: the client cancelled or the upstream
//   stream closed with zero output tokens after the prompt was
//   already sent.
// * `validation_failed`: a guardrail or structured-output
//   validator rejected AFTER the upstream call completed; the
//   spend already happened.
// * `context_bloat`: input tokens significantly above the
//   route's rolling median (the gateway emits the counter; the
//   classifier-cum-roller lives outside this module and reports
//   in).
//
// These are observational counters + an estimated-wasted-USD
// gauge. Enforcement (budget caps, denial gates) lives in
// `budget.rs` / `hierarchical_budget.rs`, not here.

/// Wasted-token counter, partitioned by waste class + bounded
/// attribution labels. The same cardinality contract as
/// [`AI_TOKENS_ATTRIBUTED`] applies: only bounded dimensions land
/// on metric labels; `customer` / `trace_id` / `okr` stay on the
/// span + access log.
static AI_WASTED_TOKENS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_wasted_tokens_total",
            "AI tokens classified as wasted, by waste class (WOR-1085)"
        ),
        &[
            "kind", // "duplicate_request" | "abandoned_stream" | "validation_failed" | "context_bloat" | "failover_loser"
            "provider",
            "model",
            "surface", // classified AI surface, e.g. "chat_completions" | "embeddings" | "realtime"
            "project",
            "feature",
            "team",
            "agent_type",
            "environment",
        ]
    )
    .unwrap()
});

/// Wasted-USD counter, same labels as [`AI_WASTED_TOKENS`] minus
/// the token-direction split.
static AI_WASTED_COST: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_wasted_cost_dollars_total",
            "Estimated USD cost of AI spend classified as wasted (WOR-1085)"
        ),
        &[
            "kind",
            "provider",
            "model",
            "surface",
            "project",
            "feature",
            "team",
            "agent_type",
            "environment",
        ]
    )
    .unwrap()
});

/// Resolve an optional tag value to the label string Prometheus
/// gets: empty stays empty (so `sum without (project)` works
/// naturally), the string passes through otherwise.
fn label_or_empty(value: Option<&str>) -> &str {
    value.unwrap_or("")
}

/// Stable waste-class identifiers. The string slug lands on the
/// `kind` label; using a closed enum keeps the label vocabulary
/// auditable instead of letting a typo create a new time series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasteKind {
    /// The request's full context matched a recent prior request
    /// per `response_dedup.rs`; the gateway served the cached
    /// reply but the upstream call still happened (or would have).
    DuplicateRequest,
    /// The client cancelled or the upstream stream closed with
    /// zero output tokens after the prompt was sent.
    AbandonedStream,
    /// A guardrail / structured-output validator rejected after
    /// the upstream call completed; the spend already happened.
    ValidationFailed,
    /// Input tokens significantly above the route's rolling
    /// median. The threshold is policy; this module just records
    /// when the rolling-window observer flags an event.
    ContextBloat,
    /// A cascade / failover tier consumed tokens but its response
    /// was rejected (5xx, refusal, or below the quality threshold)
    /// in favour of a later tier; the losing tier's spend produced
    /// no served outcome.
    FailoverLoser,
}

impl WasteKind {
    /// Stable lower-snake string slug used as the `kind` label.
    pub fn as_str(&self) -> &'static str {
        match self {
            WasteKind::DuplicateRequest => "duplicate_request",
            WasteKind::AbandonedStream => "abandoned_stream",
            WasteKind::ValidationFailed => "validation_failed",
            WasteKind::ContextBloat => "context_bloat",
            WasteKind::FailoverLoser => "failover_loser",
        }
    }
}

/// Record an observed waste event: `tokens` is the upstream-side
/// token count the gateway accounted for (input + output for a
/// completed call, input + reasoning for an abandoned stream).
/// `cost_usd` is the matching USD cost from the pricing catalog.
#[allow(clippy::too_many_arguments)]
pub fn record_waste(
    kind: WasteKind,
    provider: &str,
    model: &str,
    surface: &str,
    tags: &crate::attribution::AttributionTags,
    tokens: u64,
    cost_usd: f64,
) {
    let project = label_or_empty(tags.project.as_deref());
    let feature = label_or_empty(tags.feature.as_deref());
    let team = label_or_empty(tags.team.as_deref());
    let agent_type = label_or_empty(tags.agent_type.as_deref());
    let environment = label_or_empty(tags.environment.as_deref());
    if tokens > 0 {
        AI_WASTED_TOKENS
            .with_label_values(&[
                kind.as_str(),
                provider,
                model,
                surface,
                project,
                feature,
                team,
                agent_type,
                environment,
            ])
            .inc_by(tokens as f64);
    }
    if cost_usd > 0.0 {
        AI_WASTED_COST
            .with_label_values(&[
                kind.as_str(),
                provider,
                model,
                surface,
                project,
                feature,
                team,
                agent_type,
                environment,
            ])
            .inc_by(cost_usd);
    }
}

// --- Per-attribution spend metrics (WOR-1086) ---
//
// Per-request attribution tags ride on every AI spend record (see
// `crate::attribution`). The dashboard wants spend broken down by
// the business dimensions those tags carry; this section exposes
// the same totals as `AI_TOKENS` + `AI_COST` plus a bounded set of
// attribution labels.
//
// ## Cardinality
//
// Only the dimensions with bounded vocabulary land on metric
// labels: `project`, `feature`, `team`, `agent_type`,
// `environment`. The high-cardinality dimensions (`customer`,
// `trace_id`, `okr`) intentionally do NOT appear as metric labels;
// they ride on the OTel span and the access log instead, where the
// ledger consumes them via trace_id join.
//
// ## Token-kind split (overlap with WOR-1084)
//
// The `direction` label takes one of: `input`, `output`,
// `cache_read`, `cache_write`, `reasoning`. The non-input/output
// variants are no-ops on providers that don't report them; the
// caller passes 0 and this module skips the increment.

/// Per-attribution token counter. Labels are kept to the bounded
/// set documented above so the cardinality stays predictable.
static AI_TOKENS_ATTRIBUTED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_tokens_attributed_total",
            "AI tokens consumed, partitioned by attribution tag (WOR-1086)"
        ),
        &[
            "provider",
            "model",
            "surface", // classified AI surface (WOR-1095): chat_completions, embeddings, image_generation, audio_speech, realtime, ...
            "direction",
            "project",
            "feature",
            "team",
            "agent_type",
            "environment",
            // Authoritative identity dimensions (WOR-1493/WOR-1494):
            // the tenant the request resolved to and the credential
            // (API key) that injected the policy. Both are sourced from
            // the resolved Principal, never from a spoofable header, so
            // multi-tenant + multi-model + per-credential spend is one
            // PromQL: `sum by (tenant_id, model) (...)`.
            "tenant_id",
            "api_key_id",
        ]
    )
    .unwrap()
});

/// Per-attribution USD cost counter. Same label set as
/// `AI_TOKENS_ATTRIBUTED` so a single PromQL `sum by (project)`
/// answers "what did project X spend this week".
static AI_COST_ATTRIBUTED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_cost_dollars_attributed_total",
            "AI cost in USD, partitioned by attribution tag (WOR-1086)"
        ),
        &[
            "provider",
            "model",
            "surface", // classified AI surface (WOR-1095)
            "project",
            "feature",
            "team",
            "agent_type",
            "environment",
            // See AI_TOKENS_ATTRIBUTED (WOR-1493/WOR-1494).
            "tenant_id",
            "api_key_id",
        ]
    )
    .unwrap()
});

/// Per-attribution request-outcome counter (WOR-1496). One row per AI
/// request, partitioned by the authoritative identity dimensions plus a
/// closed `outcome` label so token / cost spend can be reconciled
/// against value-vs-waste: `sum by (tenant_id, outcome)` answers "how
/// much traffic for tenant X ended in a refusal / guardrail block /
/// budget block / upstream error". The `outcome` label is a small
/// closed set (`ok`, `guardrail_block`, `content_filter`,
/// `budget_exceeded`, `rate_limited`, `timeout`, `upstream_5xx`,
/// `auth_denied`, `client_error`, `other`) so cardinality stays bounded.
static AI_OUTCOMES_ATTRIBUTED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_requests_attributed_total",
            "AI requests partitioned by attribution + outcome (WOR-1496)"
        ),
        &[
            "provider",
            "model",
            "surface",
            "tenant_id",
            "api_key_id",
            "outcome",
        ]
    )
    .unwrap()
});

/// Record one AI request against the per-attribution outcome counter.
/// `outcome` must be one of the closed-set labels documented on the
/// `AI_OUTCOMES_ATTRIBUTED` counter; callers map their status / error
/// into that set before calling so the label cardinality stays bounded.
#[allow(clippy::too_many_arguments)]
pub fn record_ai_outcome_attributed(
    provider: &str,
    model: &str,
    surface: &str,
    tenant_id: &str,
    api_key_id: &str,
    outcome: &str,
) {
    AI_OUTCOMES_ATTRIBUTED
        .with_label_values(&[provider, model, surface, tenant_id, api_key_id, outcome])
        .inc();
}

/// Record a per-attribution AI spend record.
///
/// Token-kind split: pass `input_tokens`, `output_tokens`, and the
/// optional `cache_read` / `cache_write` / `reasoning` token
/// counts. Any zero count is skipped so the empty cell does not
/// land in the metric.
///
/// The OSS access log + OTel span pick up the high-cardinality
/// dimensions (customer, trace_id, okr) elsewhere; the ledger's
/// Allocate-layer join works off the span's trace_id.
#[allow(clippy::too_many_arguments)]
pub fn record_ai_request_attributed(
    provider: &str,
    model: &str,
    surface: &str,
    tenant_id: &str,
    api_key_id: &str,
    tags: &crate::attribution::AttributionTags,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    reasoning_tokens: u64,
    cost: f64,
) {
    let project = label_or_empty(tags.project.as_deref());
    let feature = label_or_empty(tags.feature.as_deref());
    let team = label_or_empty(tags.team.as_deref());
    let agent_type = label_or_empty(tags.agent_type.as_deref());
    let environment = label_or_empty(tags.environment.as_deref());

    let record_token_kind = |direction: &'static str, n: u64| {
        if n == 0 {
            return;
        }
        AI_TOKENS_ATTRIBUTED
            .with_label_values(&[
                provider,
                model,
                surface,
                direction,
                project,
                feature,
                team,
                agent_type,
                environment,
                tenant_id,
                api_key_id,
            ])
            .inc_by(n as f64);
    };
    record_token_kind("input", input_tokens);
    record_token_kind("output", output_tokens);
    record_token_kind("cache_read", cache_read_tokens);
    record_token_kind("cache_write", cache_write_tokens);
    record_token_kind("reasoning", reasoning_tokens);

    if cost > 0.0 {
        AI_COST_ATTRIBUTED
            .with_label_values(&[
                provider,
                model,
                surface,
                project,
                feature,
                team,
                agent_type,
                environment,
                tenant_id,
                api_key_id,
            ])
            .inc_by(cost);
    }
}

/// Per-attribution audio-seconds counter (WOR-1095).
///
/// Realtime sessions and audio surfaces consume seconds, not tokens,
/// and realtime has no catalogue price yet, so neither the token nor
/// the cost attributed counter captures them. This sibling counter
/// gives those surfaces an attributed-spend presence keyed on the
/// same bounded label set, so a project / team dashboard can answer
/// "how much realtime / audio did X consume" even at zero priced
/// cost. Same cardinality contract as [`AI_TOKENS_ATTRIBUTED`].
static AI_AUDIO_SECONDS_ATTRIBUTED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_audio_seconds_attributed_total",
            "AI audio seconds consumed (realtime + audio surfaces), partitioned by attribution tag (WOR-1095)"
        ),
        &[
            "provider",
            "model",
            "surface",
            "project",
            "feature",
            "team",
            "agent_type",
            "environment",
            // See AI_TOKENS_ATTRIBUTED (WOR-1493/WOR-1494).
            "tenant_id",
            "api_key_id",
        ]
    )
    .unwrap()
});

/// Record per-attribution audio seconds for a realtime or audio
/// surface. A zero/negative duration is skipped so an empty cell does
/// not land in the metric.
#[allow(clippy::too_many_arguments)]
pub fn record_audio_seconds_attributed(
    provider: &str,
    model: &str,
    surface: &str,
    tenant_id: &str,
    api_key_id: &str,
    tags: &crate::attribution::AttributionTags,
    seconds: f64,
) {
    if seconds <= 0.0 {
        return;
    }
    AI_AUDIO_SECONDS_ATTRIBUTED
        .with_label_values(&[
            provider,
            model,
            surface,
            label_or_empty(tags.project.as_deref()),
            label_or_empty(tags.feature.as_deref()),
            label_or_empty(tags.team.as_deref()),
            label_or_empty(tags.agent_type.as_deref()),
            label_or_empty(tags.environment.as_deref()),
            tenant_id,
            api_key_id,
        ])
        .inc_by(seconds);
}

// --- WOR-1810: streaming guardrail observability ---

/// Streamed responses terminated (or flagged) by an output guardrail,
/// by guardrail type name. The WOR-490 metric that never landed.
static STREAM_GUARDRAIL_VIOLATIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_stream_guardrail_violations_total",
            "Streaming output guardrail violations, by guardrail type (WOR-1810)"
        ),
        &["guardrail"] // bounded: the built-in guardrail type names
    )
    .unwrap()
});

/// Output guardrails excluded from a streaming response by
/// `stream_policy: off`, counted per stream so a policy that silently
/// disables coverage stays visible on dashboards.
static STREAM_GUARDRAIL_SKIPPED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_stream_guardrail_skipped_total",
            "Output guardrails skipped on streaming responses via stream_policy: off (WOR-1810)"
        ),
        &["guardrail"]
    )
    .unwrap()
});

/// Chunks where decoded-delta extraction failed and guardrails fell
/// back to matching the raw frame text. A rising rate means a provider
/// is emitting frames the OpenAI delta parser cannot read.
static STREAM_GUARDRAIL_DECODE_FALLBACK: LazyLock<prometheus::Counter> = LazyLock::new(|| {
    prometheus::register_counter!(
        "sbproxy_ai_stream_guardrail_decode_fallback_total",
        "Streaming chunks where guardrails fell back to raw-frame matching (WOR-1810)"
    )
    .unwrap()
});

/// Record a streaming guardrail violation (block or flag).
pub fn record_stream_guardrail_violation(guardrail: &str) {
    STREAM_GUARDRAIL_VIOLATIONS
        .with_label_values(&[guardrail])
        .inc();
}

/// Record guardrails excluded from a stream by `stream_policy: off`.
pub fn record_stream_guardrail_skipped(guardrail: &str, n: u64) {
    if n == 0 {
        return;
    }
    STREAM_GUARDRAIL_SKIPPED
        .with_label_values(&[guardrail])
        .inc_by(n as f64);
}

/// Record a raw-frame guardrail fallback on an undecodable chunk.
pub fn record_stream_guardrail_decode_fallback() {
    STREAM_GUARDRAIL_DECODE_FALLBACK.inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_guardrail_counters_register_and_increment() {
        record_stream_guardrail_violation("toxicity");
        record_stream_guardrail_skipped("injection", 2);
        record_stream_guardrail_skipped("injection", 0); // no-op
        record_stream_guardrail_decode_fallback();
        let families = prometheus::gather();
        let violations = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_stream_guardrail_violations_total")
            .expect("violations counter registered");
        assert!(violations.get_metric().iter().any(|m| {
            m.get_label()
                .iter()
                .any(|l| l.name() == "guardrail" && l.value() == "toxicity")
        }));
        let skipped = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_stream_guardrail_skipped_total")
            .expect("skipped counter registered");
        let inj = skipped
            .get_metric()
            .iter()
            .find(|m| {
                m.get_label()
                    .iter()
                    .any(|l| l.name() == "guardrail" && l.value() == "injection")
            })
            .expect("injection row");
        assert_eq!(inj.get_counter().value(), 2.0);
        assert!(families
            .iter()
            .any(|f| f.name() == "sbproxy_ai_stream_guardrail_decode_fallback_total"));
    }

    #[test]
    fn test_record_ai_request() {
        record_ai_request("openai", "gpt-4o", 200, 1.5, 100, 50, 0.003);
        // Verify counter incremented (use prometheus gather())
        let families = prometheus::gather();
        let ai_req = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_requests_total");
        assert!(ai_req.is_some());
    }

    #[test]
    fn test_record_surface_request() {
        record_surface_request("assistants", "DELETE");
        record_surface_request("image_generation", "POST");
        record_surface_request("chat_completions", "POST");

        let families = prometheus::gather();
        let surface_req = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_surface_requests_total")
            .expect("sbproxy_ai_surface_requests_total should be registered");

        // Confirm the new label set is present.
        let metrics = surface_req.get_metric();
        let labels: Vec<&str> = metrics
            .iter()
            .flat_map(|m| m.get_label().iter().map(|l| l.name()))
            .collect();
        for required in &["surface", "method"] {
            assert!(
                labels.contains(required),
                "expected label '{required}' on sbproxy_ai_surface_requests_total"
            );
        }
    }

    /// WOR-1501: model latency lands on BOTH the global histogram and
    /// the attributed histogram, and the attributed series carries the
    /// tenant + credential identity so latency is sliceable per
    /// credential. A non-finite value is a no-op.
    #[test]
    fn test_record_model_latency() {
        record_model_latency(
            "openai",
            "gpt-4o",
            "chat_completions",
            "acme-tenant",
            "sk_latency0001",
            0.875,
        );
        // Non-finite / negative durations are dropped.
        record_model_latency(
            "openai",
            "gpt-4o",
            "chat_completions",
            "acme-tenant",
            "x",
            -1.0,
        );
        record_model_latency(
            "openai",
            "gpt-4o",
            "chat_completions",
            "acme-tenant",
            "x",
            f64::NAN,
        );
        let families = prometheus::gather();
        assert!(families
            .iter()
            .any(|f| f.name() == "sbproxy_ai_request_duration_seconds"));
        let attributed = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_request_duration_attributed_seconds")
            .expect("attributed latency histogram registered");
        let has_identity = attributed.get_metric().iter().any(|m| {
            let labels = m.get_label();
            labels
                .iter()
                .any(|l| l.name() == "tenant_id" && l.value() == "acme-tenant")
                && labels
                    .iter()
                    .any(|l| l.name() == "api_key_id" && l.value() == "sk_latency0001")
        });
        assert!(
            has_identity,
            "attributed latency must carry tenant_id + api_key_id"
        );
    }

    /// WOR-1496: the outcome counter records one row per request with
    /// the closed outcome label plus the authoritative identity.
    #[test]
    fn test_record_ai_outcome_attributed() {
        record_ai_outcome_attributed(
            "openai",
            "gpt-4o",
            "chat_completions",
            "acme-tenant",
            "sk_outcome0001",
            "guardrail_block",
        );
        let families = prometheus::gather();
        let f = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_requests_attributed_total")
            .expect("outcome counter registered");
        let has_row = f.get_metric().iter().any(|m| {
            let labels = m.get_label();
            labels
                .iter()
                .any(|l| l.name() == "outcome" && l.value() == "guardrail_block")
                && labels
                    .iter()
                    .any(|l| l.name() == "api_key_id" && l.value() == "sk_outcome0001")
        });
        assert!(has_row, "outcome row with identity must be recorded");
    }

    #[test]
    fn test_record_surface_latency() {
        record_surface_latency("chat_completions", "POST", 1.25);
        record_surface_latency("realtime", "GET", 0.42);

        let families = prometheus::gather();
        let surface_lat = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_surface_request_duration_seconds")
            .expect("sbproxy_ai_surface_request_duration_seconds should be registered");

        // Sanity: at least one observation registered with non-zero count.
        let total_count: u64 = surface_lat
            .get_metric()
            .iter()
            .map(|m| m.get_histogram().get_sample_count())
            .sum();
        assert!(total_count >= 2, "expected at least 2 observations");
    }

    #[test]
    fn realtime_metrics_increment_and_decrement() {
        let before = realtime_sessions_active_value();
        inc_realtime_sessions_active();
        inc_realtime_sessions_active();
        assert!((realtime_sessions_active_value() - before - 2.0).abs() < 1e-9);
        dec_realtime_sessions_active();
        dec_realtime_sessions_active();
        assert!((realtime_sessions_active_value() - before).abs() < 1e-9);
    }

    #[test]
    fn realtime_session_duration_records_observation() {
        record_realtime_session_duration("openai", "client_closed", 42.5);
        let families = prometheus::gather();
        let fam = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_realtime_session_duration_seconds")
            .expect("metric should be registered");
        let total: u64 = fam
            .get_metric()
            .iter()
            .map(|m| m.get_histogram().get_sample_count())
            .sum();
        assert!(total >= 1, "expected at least one observation");
    }

    #[test]
    fn realtime_audio_seconds_registers_metric_family() {
        // Negative or zero seconds should not record (a frame with
        // zero bytes or a misconfigured sample rate should not
        // contribute). Positive values should land in the family.
        record_realtime_audio_seconds("openai", "inbound", 0.0);
        record_realtime_audio_seconds("openai", "inbound", -1.5);
        record_realtime_audio_seconds("openai", "inbound", 0.1);
        let families = prometheus::gather();
        let fam = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_realtime_audio_seconds_total")
            .expect("metric should be registered");
        let labels: Vec<&str> = fam
            .get_metric()
            .iter()
            .flat_map(|m| m.get_label().iter().map(|l| l.name()))
            .collect();
        for required in &["provider", "direction"] {
            assert!(
                labels.contains(required),
                "expected label '{required}' on sbproxy_ai_realtime_audio_seconds_total"
            );
        }
    }

    #[test]
    fn realtime_frames_forwarded_counter_increments_per_kind() {
        record_realtime_frame("openai", "inbound", "audio");
        record_realtime_frame("openai", "outbound", "text");
        let families = prometheus::gather();
        let fam = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_realtime_frames_forwarded_total")
            .expect("metric should be registered");
        let labels: Vec<&str> = fam
            .get_metric()
            .iter()
            .flat_map(|m| m.get_label().iter().map(|l| l.name()))
            .collect();
        for required in &["provider", "direction", "kind"] {
            assert!(
                labels.contains(required),
                "expected label '{required}' on sbproxy_ai_realtime_frames_forwarded_total"
            );
        }
    }

    #[test]
    fn ai_surface_latency_guard_records_on_drop() {
        let before = surface_latency_sample_count("audio_speech", "POST");
        {
            let _guard = AiSurfaceLatencyGuard::new("audio_speech", "POST".to_string());
            // Sleep briefly so the elapsed observation is non-zero.
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let after = surface_latency_sample_count("audio_speech", "POST");
        assert_eq!(
            after,
            before + 1,
            "dropping the guard should observe exactly one latency sample"
        );
    }

    fn surface_latency_sample_count(surface: &str, method: &str) -> u64 {
        let families = prometheus::gather();
        let fam = match families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_surface_request_duration_seconds")
        {
            Some(f) => f,
            None => return 0,
        };
        fam.get_metric()
            .iter()
            .find(|m| {
                let labels = m.get_label();
                labels
                    .iter()
                    .any(|l| l.name() == "surface" && l.value() == surface)
                    && labels
                        .iter()
                        .any(|l| l.name() == "method" && l.value() == method)
            })
            .map(|m| m.get_histogram().get_sample_count())
            .unwrap_or(0)
    }

    #[test]
    fn test_record_failover() {
        record_failover("openai", "anthropic", "rate_limited");
        let families = prometheus::gather();
        let failovers = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_failovers_total");
        assert!(failovers.is_some());
    }

    #[test]
    fn test_record_guardrail_block() {
        record_guardrail_block("pii");
        record_guardrail_block("injection");
        let families = prometheus::gather();
        let blocks = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_guardrail_blocks_total");
        assert!(blocks.is_some());
    }

    #[test]
    fn test_cache_result() {
        record_cache_result("openai", "exact", true);
        record_cache_result("openai", "exact", false);
    }

    #[test]
    fn test_budget_utilization() {
        set_budget_utilization("org", 0.75);
        set_budget_utilization("team", 0.45);
    }

    #[test]
    fn test_key_usage() {
        record_key_usage("vk-test-123", "openai", "gpt-4o", 100, 50, 0.003);
    }

    #[test]
    fn test_record_ttft() {
        record_ttft("openai", "gpt-4o", 0.42);
        let families = prometheus::gather();
        let ttft = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_ttft_seconds");
        assert!(ttft.is_some(), "ttft histogram must be registered");
    }

    #[test]
    fn test_record_output_throughput() {
        record_output_throughput("openai", "gpt-4o", 87.5);
        // Non-positive / non-finite samples are dropped by the helper.
        record_output_throughput("openai", "gpt-4o", 0.0);
        record_output_throughput("openai", "gpt-4o", f64::NAN);
        record_output_throughput("openai", "gpt-4o", -1.0);
        let families = prometheus::gather();
        let tput = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_output_throughput_tokens_per_second");
        assert!(tput.is_some(), "throughput histogram must be registered");
    }

    #[test]
    fn test_record_provider_error() {
        record_provider_error("openai", "timeout");
        record_provider_error("anthropic", "http_5xx");
        let families = prometheus::gather();
        let errs = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_provider_errors_total");
        assert!(errs.is_some(), "provider errors counter must be registered");
    }

    /// WOR-1085: `record_waste` registers + increments both
    /// counters, and the `kind` label carries the slug from the
    /// closed enum.
    #[test]
    fn test_record_waste() {
        use crate::attribution::AttributionTags;
        let tags = AttributionTags {
            project: Some("growth".to_string()),
            team: Some("platform".to_string()),
            ..Default::default()
        };
        record_waste(
            WasteKind::DuplicateRequest,
            "openai",
            "gpt-4o",
            "chat_completions",
            &tags,
            120,
            0.0024,
        );
        record_waste(
            WasteKind::AbandonedStream,
            "anthropic",
            "claude-sonnet",
            "chat_completions",
            &tags,
            500,
            0.003,
        );
        let families = prometheus::gather();
        let tokens = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_wasted_tokens_total")
            .expect("wasted_tokens counter registered");
        let kinds: Vec<String> = tokens
            .get_metric()
            .iter()
            .flat_map(|m| {
                m.get_label()
                    .iter()
                    .filter(|l| l.name() == "kind")
                    .map(|l| l.value().to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(kinds.contains(&"duplicate_request".to_string()));
        assert!(kinds.contains(&"abandoned_stream".to_string()));
    }

    /// `record_waste` with zero tokens skips the token counter
    /// increment (matches the WOR-1086 behaviour and keeps empty
    /// cells out of the metric).
    #[test]
    fn test_record_waste_zero_tokens_skipped() {
        use crate::attribution::AttributionTags;
        let tags = AttributionTags::default();
        // Cost-only event (e.g. context_bloat detected against
        // the rolling-median observer but no upstream token).
        record_waste(
            WasteKind::ContextBloat,
            "openai",
            "gpt-4o",
            "chat_completions",
            &tags,
            0,
            0.01,
        );
        let families = prometheus::gather();
        let cost = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_wasted_cost_dollars_total");
        assert!(cost.is_some(), "wasted_cost counter must be registered");
    }

    /// `WasteKind::as_str` is a closed-set vocabulary; the test
    /// pins the exact wire form for each variant so a future
    /// renaming surfaces here.
    #[test]
    fn waste_kind_slugs_pinned() {
        assert_eq!(WasteKind::DuplicateRequest.as_str(), "duplicate_request");
        assert_eq!(WasteKind::AbandonedStream.as_str(), "abandoned_stream");
        assert_eq!(WasteKind::ValidationFailed.as_str(), "validation_failed");
        assert_eq!(WasteKind::ContextBloat.as_str(), "context_bloat");
        assert_eq!(WasteKind::FailoverLoser.as_str(), "failover_loser");
    }

    /// WOR-1086: per-attribution spend record registers both
    /// counters and increments each populated token-kind cell.
    #[test]
    fn test_record_ai_request_attributed() {
        use crate::attribution::AttributionTags;
        let tags = AttributionTags {
            project: Some("growth-q3".to_string()),
            feature: Some("onboarding-summary".to_string()),
            team: Some("platform".to_string()),
            agent_type: Some("runtime".to_string()),
            environment: Some("prod".to_string()),
            ..Default::default()
        };
        record_ai_request_attributed(
            "openai",
            "gpt-4o",
            "chat_completions",
            "acme-tenant",
            "sk_deadbeef0001",
            &tags,
            100,
            50,
            20,
            5,
            30,
            0.01,
        );
        let families = prometheus::gather();
        let tokens = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_tokens_attributed_total")
            .expect("tokens counter registered");
        // WOR-1494: the authoritative identity dimensions must land on
        // the spend record so per-tenant / per-credential rollups work.
        let has_identity = tokens.get_metric().iter().any(|m| {
            let labels = m.get_label();
            labels
                .iter()
                .any(|l| l.name() == "tenant_id" && l.value() == "acme-tenant")
                && labels
                    .iter()
                    .any(|l| l.name() == "api_key_id" && l.value() == "sk_deadbeef0001")
        });
        assert!(
            has_identity,
            "tenant_id + api_key_id must be present on the attributed token metric"
        );
        assert!(families
            .iter()
            .any(|f| f.name() == "sbproxy_ai_cost_dollars_attributed_total"));
    }

    /// WOR-1095: realtime / audio surfaces land in the attributed
    /// audio-seconds counter (priced cost is absent for realtime, so
    /// this is the only attributed-spend presence those surfaces get).
    /// A zero duration is skipped.
    #[test]
    fn test_record_audio_seconds_attributed() {
        use crate::attribution::AttributionTags;
        let tags = AttributionTags {
            project: Some("voice-q3".to_string()),
            team: Some("realtime".to_string()),
            ..Default::default()
        };
        record_audio_seconds_attributed(
            "openai",
            "gpt-4o-realtime-preview",
            "realtime",
            "acme-tenant",
            "sk_deadbeef0002",
            &tags,
            12.5,
        );
        // Zero duration is a no-op.
        record_audio_seconds_attributed(
            "openai",
            "whisper-1",
            "audio_transcription",
            "acme-tenant",
            "sk_deadbeef0002",
            &tags,
            0.0,
        );
        let families = prometheus::gather();
        let f = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_audio_seconds_attributed_total")
            .expect("audio-seconds attributed counter registered");
        let has_realtime = f.get_metric().iter().any(|m| {
            m.get_label()
                .iter()
                .any(|l| l.name() == "surface" && l.value() == "realtime")
        });
        assert!(
            has_realtime,
            "realtime session must land with surface label"
        );
    }

    /// Zero-token kinds are skipped: the empty cell does not land
    /// in the metric for the recorded (provider, model) cell, so a
    /// deployment whose provider does not report cache / reasoning
    /// tokens does not pay cardinality for unused directions.
    ///
    /// Pinned to a UNIQUE (provider, model) combo so the cross-test
    /// shared Prometheus registry does not produce false positives
    /// from a sibling test that legitimately wrote a `cache_read`
    /// cell against a different label set.
    #[test]
    fn test_attributed_zero_kinds_skipped() {
        use crate::attribution::AttributionTags;
        let tags = AttributionTags::default();
        // Unique provider+model labels not used by any other test
        // in this module so the per-cell assertion is isolated from
        // the global Prometheus registry's state.
        let provider = "zero-kinds-test-provider";
        let model = "zero-kinds-test-model";
        record_ai_request_attributed(
            provider,
            model,
            "chat_completions",
            "",
            "",
            &tags,
            1000,
            200,
            0,
            0,
            0,
            0.0,
        );
        let families = prometheus::gather();
        let tokens = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_tokens_attributed_total")
            .expect("tokens counter registered");
        let has_cache_for_our_labels = tokens.get_metric().iter().any(|m| {
            let labels = m.get_label();
            let has_provider = labels
                .iter()
                .any(|l| l.name() == "provider" && l.value() == provider);
            let has_model = labels
                .iter()
                .any(|l| l.name() == "model" && l.value() == model);
            let has_cache_dir = labels
                .iter()
                .any(|l| l.name() == "direction" && l.value() == "cache_read");
            has_provider && has_model && has_cache_dir
        });
        assert!(
            !has_cache_for_our_labels,
            "zero cache_read tokens should not land in the metric for this test's labels"
        );
    }
}
