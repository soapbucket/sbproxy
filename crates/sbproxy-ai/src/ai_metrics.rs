//! Per-provider, per-model AI gateway metrics.
//!
//! Tracks requests, tokens, cost, failovers, guardrail blocks,
//! cache hits, and budget utilization for every AI provider and model.

use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_gauge_vec, register_histogram,
    register_histogram_vec, Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts,
    HistogramVec, Opts,
};
use std::sync::LazyLock;

// --- Provider metrics ---
//
// WOR-1873: the original unattributed `sbproxy_ai_requests_total`,
// `sbproxy_ai_tokens_total`, and `sbproxy_ai_cost_dollars_total`
// families (plus the per-virtual-key trio) were registered here but
// had no live writer; the dispatch path records the attributed
// families below instead. They were removed rather than re-wired
// because a same-named `sbproxy_ai_tokens_total` also existed in the
// custom registry and the merged /metrics render would have emitted
// two families with different label sets. See
// docs/metrics-stability.md for the deprecation note.

/// Per-surface request counter, partitioned by AI surface (chat
/// completions, assistants, embeddings, image generation, etc.) and
/// HTTP method.
///
/// Additive with `sbproxy_ai_requests_attributed_total`; dashboards
/// that aggregate by provider/model use the attributed counter, while
/// surface-aware views use this one. Cardinality is bounded by
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

// WOR-1873: average inter-token latency (TPOT) per streaming
// response, in seconds. Recorded once per stream alongside TTFT and
// output throughput, from the same generation window (first token ->
// stream end) divided by the gap count, so the three serving signals
// stay mutually consistent. Buckets span sub-10ms accelerator gaps
// through multi-second degraded streams.
static AI_INTER_TOKEN_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_inter_token_latency_seconds",
            "AI streaming average inter-token latency (TPOT)"
        )
        .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]),
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

/// Route reasoning-policy outcomes for each provider attempt.
///
/// `provider` is bounded by configured provider names and `outcome` comes
/// from [`crate::reasoning::ReasoningOutcome`]'s closed label set.
static AI_REASONING_POLICY_ATTEMPTS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_reasoning_policy_attempts_total",
            "AI provider attempts by concise-reasoning policy outcome"
        ),
        &["provider", "outcome"]
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

/// AI routing decisions that intentionally use a fallback path.
///
/// `strategy` comes from the closed routing enum. `reason` is normalized by
/// [`record_routing_fallback`] so request data cannot create new series.
static AI_ROUTING_FALLBACKS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_routing_fallbacks_total",
            "AI routing selections that used an explicit fallback path"
        ),
        &["strategy", "reason"]
    )
    .unwrap()
});

/// Operator routing-policy (WOR-2366) decisions by outcome and the
/// normalized reason code. `outcome` is a closed set (`plan`,
/// `plan_degraded` for a plan the host had to drop a tier from,
/// `overridden` when a security `route_to` cleared it, `decline`,
/// `error`); `reason_code` is bounded by the policy's `reason_codes`
/// allowlist (`policy` / `other` / an allowlisted code, or `none` for a
/// decline or error), so neither label can grow unbounded from a request.
static AI_ROUTING_POLICY_DECISIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_routing_policy_decisions_total",
            "Operator AI routing-policy decisions by outcome and reason code"
        ),
        &["outcome", "reason_code"]
    )
    .unwrap()
});

/// Prefix-affinity selections by observed-cache outcome.
static AI_PREFIX_AFFINITY_DECISIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_prefix_affinity_decisions_total",
            "Prefix-affinity selections by cache-location outcome"
        ),
        &["outcome"]
    )
    .unwrap()
});

/// Bounded prefix-table evictions by cause.
static AI_PREFIX_AFFINITY_EVICTIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_prefix_affinity_evictions_total",
            "Entries evicted from the bounded prefix-affinity table"
        ),
        &["reason"]
    )
    .unwrap()
});

/// Semantic-route selections by closed decision outcome (WOR-2564).
/// `matched` pinned a deployment; every other outcome is a fallback
/// disposition, mirrored on `sbproxy_ai_routing_fallbacks_total`.
///
/// Held as an `Option` rather than unwrapped like the older families
/// above: a registration error is a duplicate name or a malformed label
/// set, and losing one metric family is not worth ending the process a
/// request is running through. The recorder below no-ops when the family
/// is absent. The unwrap ratchet
/// (`scripts/check-unwrap-ratchet.sh`) counts the older form; this is the
/// shape new families take.
static AI_SEMANTIC_ROUTE_DECISIONS: LazyLock<Option<CounterVec>> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_semantic_route_decisions_total",
            "Semantic-route selections by decision outcome"
        ),
        &["outcome"]
    )
    .ok()
});

/// Best exemplar cosine similarity per scored semantic-route request
/// (WOR-2564). Recorded on matched and below-floor outcomes both, so an
/// operator tuning `min_similarity` can see the near-miss distribution
/// and not just the winners. Labeled by the best-scoring deployment; the
/// score itself is the observation, never a label.
static AI_SEMANTIC_ROUTE_SIMILARITY: LazyLock<Option<HistogramVec>> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_semantic_route_similarity",
            "Best exemplar cosine similarity of scored semantic-route requests"
        )
        .buckets(vec![0.3, 0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0]),
        &["provider"]
    )
    .ok()
});

/// Distributed quota-pool admissions allowed during backend unavailability.
///
/// Pool names are operator-declared config values. Virtual-key identities are
/// deliberately excluded from this family.
static AI_QUOTA_POOL_FAIL_OPEN: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_quota_pool_fail_open_total",
            "Quota-pool admissions allowed while the shared backend was unavailable"
        ),
        &["pool"]
    )
    .unwrap()
});

/// Soft-policy quota-pool admissions beyond a member's entitlement.
///
/// Pool names are operator-declared config values. Caller identities are
/// deliberately excluded from this family.
static AI_QUOTA_POOL_OVERSHARE: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_quota_pool_overshare_total",
            "Soft quota-pool admissions beyond a member entitlement"
        ),
        &["pool"]
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

static AI_SAFETY_GUARDRAIL_VERDICTS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_safety_guardrail_verdicts_total",
            "Built-in safety guardrail evaluations by class, backend, and verdict"
        ),
        &["guardrail", "class", "backend", "verdict"]
    )
    .unwrap()
});

static AI_EXTERNAL_GUARDRAIL_VERDICTS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_external_guardrail_verdicts_total",
            "External guardrail evaluations by provider, phase, and outcome"
        ),
        &["provider", "phase", "outcome"]
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
            "Budget utilization as a fraction of the limit; above 1 is over budget"
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

// --- Inbound-translation lossiness (WOR-2535) ---

static AI_TRANSLATION_DROPPED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_translation_dropped_total",
            "Request fields dropped while translating an inbound AI body to the canonical chat shape"
        ),
        &["surface", "field"]
    )
    .unwrap()
});

/// Record `count` dropped request fields of one class at an
/// inbound-translation seam (WOR-2535). `surface` is the inbound
/// surface label from `AiSurface::label` (`messages`, `responses`), so
/// the series joins `sbproxy_ai_surface_requests_total` on the same
/// label values; `field` is the note's bounded `metric_label` class
/// (`anthropic.messages.content`, `responses.tools`, ...), never the
/// client-derived detail (see `LossinessNote::metric_label`). Both
/// still pass the workspace cardinality limiter as a backstop, so a
/// future call site that leaks an open value demotes to `__other__`
/// instead of minting unbounded series.
///
/// Callers fold their notes per class and pass a count rather than
/// calling once per note: the note count is bounded only by request
/// body size, and the limiter round trips plus label allocations of a
/// per-note loop are a client-reachable cost on the request path
/// (WOR-2535 review).
pub fn record_translation_dropped(surface: &str, field: &str, count: u64) {
    if count == 0 {
        return;
    }
    let metric = "sbproxy_ai_translation_dropped_total";
    let surface = sbproxy_observe::metrics::sanitize_label_budget(metric, "surface", surface);
    let field = sbproxy_observe::metrics::sanitize_label_budget(metric, "field", field);
    AI_TRANSLATION_DROPPED
        .with_label_values(&[&surface, &field])
        .inc_by(count as f64);
}

/// Current value of the translation-drop counter for one label pair,
/// for asserting deltas in unit tests.
#[cfg(test)]
pub(crate) fn translation_dropped_value(surface: &str, field: &str) -> u64 {
    AI_TRANSLATION_DROPPED
        .with_label_values(&[surface, field])
        .get() as u64
}

// --- Pre-provider admission refusals (WOR-2595) ---

/// Registered without `.unwrap()` for the same reason as
/// `AI_PRICE_CEILING` below: the production unwrap/expect ratchet in
/// `scripts/check-unwrap-ratchet.sh` is at its baseline and one metric
/// family is not worth a panic path.
static AI_ADMISSION_DECISIONS: LazyLock<Option<CounterVec>> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_admission_decisions_total",
            "Pre-provider AI gateway admission decisions by inbound surface and reason (WOR-2595)"
        ),
        &["surface", "reason", "outcome"]
    )
    .ok()
});

/// Record a pre-provider AI admission decision (WOR-2595).
///
/// `surface` is the inbound surface label from `AiSurface::label`, so
/// the series joins `sbproxy_ai_surface_requests_total` on the same
/// values: `messages` or `responses` for a refusal at the native-format
/// shim, and any JSON surface, `chat_completions` included, for one at
/// the shared stored-prompt resolver. `reason` is
/// the refusal's bounded code from `ChatError::reason`
/// (`tools_mcp_unsupported`, `store_unsupported`, `malformed_json`, ...),
/// the prompt-bridge codes the dispatcher names
/// (`prompt_reference_not_found`, `prompt_object_unrenderable`), or
/// `malformed_request` where a refusal site has not been coded.
/// `outcome` is `deny` today and is carried anyway so an admit-side
/// counterpart can share the family rather than mint a second one.
///
/// Every label value is a `&'static str` at the call site; the
/// cardinality limiter is a backstop, not the contract. Never pass a
/// `ChatError::message`: several of the coded refusals interpolate
/// caller bytes into it.
pub fn record_admission_decision(surface: &str, reason: &str, outcome: &str) {
    let Some(counter) = &*AI_ADMISSION_DECISIONS else {
        return;
    };
    let metric = "sbproxy_ai_admission_decisions_total";
    let surface = sbproxy_observe::metrics::sanitize_label_budget(metric, "surface", surface);
    let reason = sbproxy_observe::metrics::sanitize_label_budget(metric, "reason", reason);
    // `outcome` is a literal at the only call site, but it goes through
    // the limiter like its two neighbors: an exemption held by "the
    // caller passes a constant" is exactly the invariant a second caller
    // breaks silently.
    let outcome = sbproxy_observe::metrics::sanitize_label_budget(metric, "outcome", outcome);
    counter
        .with_label_values(&[surface.as_str(), reason.as_str(), outcome.as_str()])
        .inc();
}

// --- Per-request price ceiling (WOR-2559) ---

/// Registered without `.unwrap()` (mirroring
/// `MULTIPART_INSPECTION_SKIPPED`) because the production unwrap/expect
/// ratchet in `scripts/check-unwrap-ratchet.sh` is at its baseline and
/// a metric family is not worth a panic path.
static AI_PRICE_CEILING: LazyLock<Option<CounterVec>> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_price_ceiling_total",
            "Per-request price ceiling routing-guard outcomes (WOR-2559)"
        ),
        &["outcome"]
    )
    .ok()
});

/// Record a per-request price-ceiling outcome (WOR-2559). `outcome` is a
/// closed set of four:
///
/// - `candidate_excluded`: one routing candidate's estimate exceeded the
///   ceiling and it was dropped from the eligible set.
/// - `refused`: every candidate was over the ceiling, so the request
///   failed closed with 402.
/// - `invalid_header`: the caller's `x-sbproxy-max-price` was not a
///   positive USD amount, answered 400.
/// - `unsupported_surface`: the caller set that header on a surface the
///   per-token estimate cannot price, answered 400.
///
/// A rising `candidate_excluded` rate with a flat `refused` rate means
/// the ceiling is trimming the expensive tier; a rising `refused` rate
/// means it is blocking traffic outright. The two 400 outcomes are
/// caller mistakes rather than gateway decisions, so alert on them
/// separately or not at all.
///
/// A request has two candidate sets the ceiling can filter, the provider
/// order and a confidence cascade's tier list, and both count here. On a
/// cascade origin one request can therefore report an exclusion from
/// each, which is the honest reading: two separate routes were priced
/// and both were over.
pub fn record_price_ceiling(outcome: &str) {
    let Some(counter) = &*AI_PRICE_CEILING else {
        return;
    };
    counter.with_label_values(&[outcome]).inc();
}

// --- Per-error-class provider cooldowns (WOR-2556) ---

/// Registered without `.unwrap()` for the same reason as
/// `AI_PRICE_CEILING` above: the production unwrap/expect ratchet is at
/// its baseline and one metric family is not worth a panic path on a
/// request the process is already serving.
static AI_PROVIDER_COOLDOWNS: LazyLock<Option<CounterVec>> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_provider_cooldowns_total",
            "AI providers parked out of rotation by a classified-failure cooldown (WOR-2556)"
        ),
        &["provider", "cause"]
    )
    .ok()
});

/// Record one provider parked out of rotation by a
/// `resilience.cooldown_policy` match (WOR-2556).
///
/// `cause` is the closed `FailureCause` label set and nothing else:
/// `timeout`, `rate_limit`, `context_window_exceeded`, `content_policy`,
/// `auth`, `server_error`, `bad_request`, `unknown`. `provider` is an
/// operator-declared `providers[].name`, so it is bounded by the config
/// rather than by traffic.
///
/// Both labels still pass the workspace cardinality limiter as a
/// backstop, so a future call site that hands this an open value demotes
/// to `__other__` instead of minting unbounded series, the same contract
/// [`record_translation_dropped`] holds.
///
/// The counter exists because the cooldown axis is otherwise invisible:
/// parking a provider is the moment traffic stops reaching it, and
/// before this the only record was a rotating `warn!` line, which is
/// neither alertable nor graphable. The comparable axis, the circuit
/// breaker, has published `sbproxy_circuit_breaker_transitions_total`
/// all along. `rate(sbproxy_ai_provider_cooldowns_total[5m]) > 0` is the
/// expression an operator wants when a rotated credential parks the
/// whole pool on `cause="auth"`.
pub fn record_provider_cooldown(provider: &str, cause: &str) {
    let Some(counter) = &*AI_PROVIDER_COOLDOWNS else {
        return;
    };
    let metric = "sbproxy_ai_provider_cooldowns_total";
    let provider = sbproxy_observe::metrics::sanitize_label_budget(metric, "provider", provider);
    let cause = sbproxy_observe::metrics::sanitize_label_budget(metric, "cause", cause);
    counter.with_label_values(&[&provider, &cause]).inc();
}

// --- Shadow supervisor metrics ---

static AI_SHADOW_INFLIGHT: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "sbproxy_ai_shadow_inflight",
        "Currently in-flight shadow request tasks supervised by the AI client"
    )
    .unwrap()
});

static AI_SHADOW_DROPPED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_shadow_dropped_total",
            "Shadow requests skipped or dropped before dispatch"
        ),
        &["reason"]
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

/// Closed, low-cardinality reasons why a configured shadow request
/// did not reach the shadow provider. Deliberate sampling is excluded:
/// sampling out is expected behavior, not a failed dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowDropReason {
    /// Streaming requests are intentionally unsupported by shadow dispatch.
    Streaming,
    /// The configured shadow provider was absent from the handler provider list.
    ProviderNotFound,
    /// Credential-scoped provider policy disallowed the shadow provider.
    ProviderNotAllowed,
    /// The request opted out of prompt training and the shadow provider did not.
    PromptTrainingDisallowed,
    /// Purpose-scoped egress is active and shadow transport cannot honor it.
    EgressDenied,
    /// The bounded shadow supervisor had no free admission slots.
    Saturated,
}

/// Every [`ShadowDropReason`], in label order.
///
/// A variant added to the enum and not added here fails to compile,
/// enforced by [`ShadowDropReason::next_in_label_order`] and the const
/// walk below rather than by the written-out array length, which on
/// its own would happily stay at six. Before this, the exhaustiveness
/// test held a hand-written copy of this list: a seventh variant would
/// have compiled, shipped, and never been asserted on, and
/// `docs/observability.md` states this family's cardinality as a
/// number that would then have been wrong.
///
/// What it still cannot see: the two prose enumerations of the same
/// vocabulary, `docs/observability.md` and `docs/ai-gateway.md`. A new
/// variant has to be written into both by hand.
pub const ALL_SHADOW_DROP_REASONS: [ShadowDropReason; 6] = [
    ShadowDropReason::Streaming,
    ShadowDropReason::ProviderNotFound,
    ShadowDropReason::ProviderNotAllowed,
    ShadowDropReason::PromptTrainingDisallowed,
    ShadowDropReason::EgressDenied,
    ShadowDropReason::Saturated,
];

// Walks the variant chain against the array at compile time. A seventh
// variant makes `next_in_label_order` non-exhaustive, and the arm its
// author has to add puts a seventh link in the chain, which indexes one
// slot past a six-element array and fails const evaluation. Written as
// a walk rather than as a length assertion because a length written out
// beside the array is a copy of the array, not a check on it.
const _: () = {
    let mut index = 0usize;
    let mut current = Some(ShadowDropReason::Streaming);
    while let Some(reason) = current {
        assert!(
            ALL_SHADOW_DROP_REASONS[index] as u8 == reason as u8,
            "ALL_SHADOW_DROP_REASONS is out of order with the variant chain"
        );
        index += 1;
        current = reason.next_in_label_order();
    }
    assert!(
        index == ALL_SHADOW_DROP_REASONS.len(),
        "ALL_SHADOW_DROP_REASONS has an entry no variant claims"
    );
};

impl ShadowDropReason {
    /// Stable Prometheus label value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Streaming => "streaming",
            Self::ProviderNotFound => "provider_not_found",
            Self::ProviderNotAllowed => "provider_not_allowed",
            Self::PromptTrainingDisallowed => "prompt_training_disallowed",
            Self::EgressDenied => "egress_denied",
            Self::Saturated => "saturated",
        }
    }

    /// The variant that follows this one in [`ALL_SHADOW_DROP_REASONS`],
    /// or `None` for the last.
    ///
    /// This exists only so the array's contents are enforced rather
    /// than asserted in prose. The match is exhaustive, so a new
    /// variant cannot compile without joining the chain.
    const fn next_in_label_order(self) -> Option<Self> {
        match self {
            Self::Streaming => Some(Self::ProviderNotFound),
            Self::ProviderNotFound => Some(Self::ProviderNotAllowed),
            Self::ProviderNotAllowed => Some(Self::PromptTrainingDisallowed),
            Self::PromptTrainingDisallowed => Some(Self::EgressDenied),
            Self::EgressDenied => Some(Self::Saturated),
            Self::Saturated => None,
        }
    }
}

/// Record one configured shadow request that could not be dispatched.
pub fn record_shadow_dropped(reason: ShadowDropReason) {
    AI_SHADOW_DROPPED
        .with_label_values(&[reason.as_str()])
        .inc();
}

/// Record one shadow task that exceeded its wall-clock supervisor
/// timeout and was cancelled.
pub fn record_shadow_timeout() {
    AI_SHADOW_TIMEOUT.inc();
}

/// Per-target outcome counter for completed shadow calls.
///
/// `target` is the shadow target's provider name, bounded by the
/// route's `shadow.targets` list, which refuses a duplicate provider
/// so the label identifies exactly one target. `status_class` and
/// `finish_reason` are normalized to closed sets below.
///
/// This is the per-target comparison surface. Cost per target is
/// answerable from the usage ledger instead (`tag == "shadow"`, grouped
/// by `provider`, joined to the primary through `shadow_of`), which is
/// why there is no cost metric here: the ledger is non-lossy and this
/// counter is not.
static AI_SHADOW_CALLS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_shadow_calls_total",
            "Completed shadow evaluation calls by target, status class, and finish reason"
        ),
        &["target", "status_class", "finish_reason"]
    )
    .unwrap()
});

/// Per-target latency of a completed shadow call, in seconds.
///
/// Same bucket layout as `sbproxy_ai_request_duration_seconds`, so a
/// target's latency distribution can be read against the primary's
/// without rescaling.
static AI_SHADOW_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_shadow_latency_seconds",
            "Shadow evaluation call latency by target"
        )
        .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]),
        &["target"]
    )
    .unwrap()
});

/// Record one completed shadow call against one target.
///
/// `status` is the HTTP status the target answered, 504 when the
/// wall-clock supervisor timeout fired (the same status the ledger row
/// records for that case, so the two surfaces agree), and 0 when the
/// transport never produced a response at all, which lands in the
/// `error` class. `sbproxy_ai_shadow_timeout_total` is what separates
/// a supervisor timeout from an upstream 504. `finish_reason` is
/// whatever the target reported, normalized here.
pub fn record_shadow_call(target: &str, status: u16, finish_reason: Option<&str>, secs: f64) {
    let status_class = match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        // 0 is what the transport paths report when no response
        // arrived at all; anything else is not a status we produce.
        _ => "error",
    };
    let finish_reason = normalize_shadow_finish_reason(finish_reason);
    AI_SHADOW_CALLS
        .with_label_values(&[target, status_class, finish_reason])
        .inc();
    if secs.is_finite() && secs >= 0.0 {
        AI_SHADOW_LATENCY.with_label_values(&[target]).observe(secs);
    }
}

/// Close the `finish_reason` label to the OpenAI chat vocabulary the
/// hub normalizes every provider into, plus `none` for a call that
/// reported none and `other` for anything else.
///
/// Closed because the value reaches a Prometheus label and comes off a
/// provider response body. A provider that invents a finish reason, or
/// a translated native shape that passes an unmapped `stopReason`
/// through, would otherwise mint a new series per distinct string.
fn normalize_shadow_finish_reason(finish_reason: Option<&str>) -> &'static str {
    match finish_reason {
        None => "none",
        Some("stop") => "stop",
        Some("length") => "length",
        Some("tool_calls") => "tool_calls",
        Some("content_filter") => "content_filter",
        Some("function_call") => "function_call",
        Some("") => "none",
        Some(_) => "other",
    }
}

/// Read one `sbproxy_ai_shadow_calls_total` sample (test accessor).
#[cfg(test)]
pub(crate) fn shadow_calls_value(target: &str, status_class: &str, finish_reason: &str) -> f64 {
    AI_SHADOW_CALLS
        .with_label_values(&[target, status_class, finish_reason])
        .get()
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

/// Read the cumulative shadow-dropped counter value for one closed
/// reason. Tests use this to assert that the expected path ticked.
#[cfg(test)]
pub(crate) fn shadow_dropped_value(reason: ShadowDropReason) -> f64 {
    AI_SHADOW_DROPPED
        .with_label_values(&[reason.as_str()])
        .get()
}

/// Read the cumulative shadow-timeout counter value. Tests use this
/// to assert that a hung shadow was actually cancelled.
#[cfg(test)]
pub(crate) fn shadow_timeout_value() -> f64 {
    AI_SHADOW_TIMEOUT.get()
}

// --- AI gateway rate-limit rejection counter ---
//
// Operators alert on any non-zero rate of this counter to detect a
// rejected client. `axis` is the bucket that tripped (`rpm`, `tpm`,
// `rpd`, `tpd`, `concurrent`). The legacy `key_hash` label contains the
// immutable, secret-free resolved policy/key id; the limiter never receives
// raw credential text. `model` is the upstream model name.
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

/// Record a request against the per-surface counter.
///
/// Called once per AI request from `handle_ai_proxy` (in `sbproxy-core`)
/// with the surface label from `classify_surface`. Kept separate from
/// the attributed request counter so the surface partition does not
/// change the cardinality of the families that existing dashboards
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

/// Requests whose provider candidate set the data-handling posture
/// constraint narrowed or refused (WOR-2557).
///
/// `constraint` is the closed [`crate::data_posture::DataPostureConstraint::label`]
/// set (three values); `outcome` is `filtered` (the set narrowed and the
/// request proceeded on the eligible remainder) or `refused` (the
/// exclusion left no eligible provider and the request failed closed).
/// A refused request increments both outcomes: the narrowing happened,
/// and then nothing remained.
///
/// All three labels are closed sets. `tenant` is the origin's resolved
/// tenant, which is drawn from the declared `proxy.tenants[]` list and
/// is `__default__` in a single-tenant deployment; no client-derived
/// value reaches a label here.
static AI_DATA_POSTURE_FILTER: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_data_posture_filter_total",
            "AI requests whose provider candidate set the data-posture constraint narrowed or refused"
        ),
        &["constraint", "outcome", "tenant"]
    )
    .unwrap()
});

/// Record a data-posture candidate-set narrowing or refusal.
///
/// An empty `tenant` is recorded as `__default__` rather than as an
/// empty label value, so a single-tenant deployment still produces one
/// readable series instead of a blank one.
pub fn record_data_posture_filter(constraint: &str, outcome: &str, tenant: &str) {
    let tenant = if tenant.is_empty() {
        "__default__"
    } else {
        tenant
    };
    AI_DATA_POSTURE_FILTER
        .with_label_values(&[constraint, outcome, tenant])
        .inc();
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
///
/// The provider-advance seam (WOR-2486): every call site is a fallback
/// or an advance to the next configured provider, never a per-request
/// selection, so this is also where `EventType::ProviderSelected`
/// publishes. `tenant` is the requesting tenant, or `""` in a
/// single-tenant deployment; [`sbproxy_observe::ProxyEvent::new`]
/// carries an empty string the same way every other bridge in this
/// codebase does.
pub fn record_failover(from: &str, to: &str, reason: &str, tenant: &str) {
    AI_FAILOVERS.with_label_values(&[from, to, reason]).inc();
    sbproxy_observe::publish_proxy_event(sbproxy_observe::EventType::ProviderSelected, || {
        provider_selected_event(from, to, reason, tenant)
    });
}

/// Build the `provider_selected` [`sbproxy_observe::ProxyEvent`] for one
/// failover.
///
/// Split out for the same reason `sbproxy_observe::egress_bridge`'s
/// builder is: testable without a running event egress.
fn provider_selected_event(
    from: &str,
    to: &str,
    reason: &str,
    tenant: &str,
) -> sbproxy_observe::ProxyEvent {
    sbproxy_observe::ProxyEvent::new(
        sbproxy_observe::EventType::ProviderSelected,
        to.to_owned(),
        tenant.to_owned(),
        serde_json::json!({
            "from_provider": from,
            "to_provider": to,
            "reason": reason,
        }),
    )
}

/// Record one closed reasoning-policy outcome for a provider attempt.
pub fn record_reasoning_policy_attempt(provider: &str, outcome: &'static str) {
    AI_REASONING_POLICY_ATTEMPTS
        .with_label_values(&[provider, outcome])
        .inc();
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

/// Record an intentional routing fallback.
///
/// Reasons are a closed vocabulary shared by the outcome-aware,
/// prefix-affinity, and semantic-route strategies. `below_floor`,
/// `embed_error`, and `target_ineligible` are the semantic-route
/// dispositions (WOR-2564); an unavailable embedder is deliberately a
/// counted fallback here, never a failed request.
pub fn record_routing_fallback(strategy: &str, reason: &str) {
    let reason = match reason {
        "warmup" | "missing_signal" | "no_holder" | "no_feedback" | "below_floor"
        | "embed_error" | "target_ineligible" => reason,
        _ => "unknown",
    };
    AI_ROUTING_FALLBACKS
        .with_label_values(&[strategy, reason])
        .inc();
}

/// Record an operator routing-policy decision (WOR-2366).
///
/// `outcome` is one of `plan` (a plan that ran), `overridden` (a plan a
/// later `ai_policy route_to` cleared), `decline`, or `error`. `reason_code`
/// is the already-normalized code (`policy` / `other` / an allowlisted
/// value, or `none` for anything but a plan); the caller owns normalization
/// so this function never sees a request-controlled string.
pub fn record_routing_policy_decision(outcome: &str, reason_code: &str) {
    AI_ROUTING_POLICY_DECISIONS
        .with_label_values(&[outcome, reason_code])
        .inc();
}

/// Record whether prefix affinity found a live holder or used a fallback.
pub fn record_prefix_affinity_decision(outcome: &str) {
    let outcome = match outcome {
        "hit" | "miss" | "missing_signal" => outcome,
        _ => "unknown",
    };
    AI_PREFIX_AFFINITY_DECISIONS
        .with_label_values(&[outcome])
        .inc();
}

/// Record removal from the bounded prefix table.
pub fn record_prefix_affinity_eviction(reason: &str) {
    let reason = match reason {
        "ttl" | "capacity" => reason,
        _ => "unknown",
    };
    AI_PREFIX_AFFINITY_EVICTIONS
        .with_label_values(&[reason])
        .inc();
}

/// Record one semantic-route decision by closed outcome (WOR-2564):
/// `matched`, `below_floor`, `no_prompt`, `embed_error`, or
/// `target_ineligible`.
pub fn record_semantic_route_decision(outcome: &str) {
    let outcome = match outcome {
        "matched" | "below_floor" | "no_prompt" | "embed_error" | "target_ineligible" => outcome,
        _ => "unknown",
    };
    if let Some(decisions) = AI_SEMANTIC_ROUTE_DECISIONS.as_ref() {
        decisions.with_label_values(&[outcome]).inc();
    }
}

/// Record the best exemplar cosine similarity of one scored
/// semantic-route request, labeled by the best-scoring deployment
/// (WOR-2564).
pub fn record_semantic_route_similarity(provider: &str, score: f32) {
    if let Some(similarity) = AI_SEMANTIC_ROUTE_SIMILARITY.as_ref() {
        similarity
            .with_label_values(&[provider])
            .observe(f64::from(score));
    }
}

/// Record an admission that bypassed a failed shared quota backend.
pub fn record_quota_pool_fail_open(pool: &str) {
    AI_QUOTA_POOL_FAIL_OPEN.with_label_values(&[pool]).inc();
}

/// Record a soft-policy admission beyond a member's weighted entitlement.
pub fn record_quota_pool_overshare(pool: &str) {
    AI_QUOTA_POOL_OVERSHARE.with_label_values(&[pool]).inc();
}

/// Record a streaming time-to-first-token observation, in seconds.
///
/// The streaming relay calls this from its first-token hook using the
/// elapsed time captured directly for that request.
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

/// Record one streaming response's average inter-token latency
/// (TPOT), in seconds. Callers derive it from the same generation
/// window `record_output_throughput` uses: window / (tokens - 1),
/// so it needs at least two tokens to be defined. Non-finite and
/// non-positive values are dropped so the histogram only sees
/// meaningful gaps.
pub fn record_inter_token_latency(provider: &str, model: &str, seconds: f64) {
    if seconds.is_finite() && seconds > 0.0 {
        AI_INTER_TOKEN_LATENCY
            .with_label_values(&[provider, model])
            .observe(seconds);
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

/// Record one built-in safety guardrail evaluation.
///
/// Every label is normalized to a closed vocabulary before it reaches
/// Prometheus. Classifier implementations and configuration can therefore
/// never turn model-produced labels into unbounded metric cardinality.
pub fn record_safety_guardrail_verdict(guardrail: &str, class: &str, backend: &str, verdict: &str) {
    let guardrail = match guardrail {
        "toxicity" | "jailbreak" | "content_safety" => guardrail,
        _ => "unknown",
    };
    let class = match class {
        "toxic" | "jailbreak" | "violence" | "self_harm" | "sexual" | "hate_speech" | "illegal"
        | "safe" | "none" | "error" | "unknown" => class,
        _ => "unknown",
    };
    let backend = match backend {
        "keyword" | "classifier" => backend,
        _ => "unknown",
    };
    let verdict = match verdict {
        "allow" | "block" => verdict,
        _ => "unknown",
    };
    AI_SAFETY_GUARDRAIL_VERDICTS
        .with_label_values(&[guardrail, class, backend, verdict])
        .inc();
}

/// Record an external guardrail result with a bounded label vocabulary.
pub fn record_external_guardrail_verdict(provider: &str, phase: &str, outcome: &str) {
    let (provider, phase, outcome) = normalize_external_guardrail_labels(provider, phase, outcome);
    AI_EXTERNAL_GUARDRAIL_VERDICTS
        .with_label_values(&[provider, phase, outcome])
        .inc();
}

fn normalize_external_guardrail_labels<'a>(
    provider: &'a str,
    phase: &'a str,
    outcome: &'a str,
) -> (&'a str, &'a str, &'a str) {
    let provider = match provider {
        "generic"
        | "presidio"
        | "lakera"
        | "aporia"
        | "azure_content_safety"
        | "bedrock"
        // Not a `GuardrailProvider` variant. `bedrock` is an
        // out-of-band `ApplyGuardrail` side call; `bedrock_inline` is
        // the same AWS guardrail evaluated inside the Converse
        // generation via a provider entry's `bedrock_guardrail`.
        // Sharing one label would make the two layers
        // indistinguishable on the dashboard that exists to say which
        // one stopped a request.
        | "bedrock_inline"
        | "crowdstrike"
        | "mistral"
        | "pangea"
        | "patronus" => provider,
        _ => "unknown",
    };
    let phase = match phase {
        "input" | "output" => phase,
        _ => "unknown",
    };
    let outcome = match outcome {
        "allow" | "block" | "fail_open" | "fail_closed" => outcome,
        _ => "unknown",
    };
    (provider, phase, outcome)
}

#[cfg(test)]
pub(crate) fn external_guardrail_verdict_value(provider: &str, phase: &str, outcome: &str) -> f64 {
    let (provider, phase, outcome) = normalize_external_guardrail_labels(provider, phase, outcome);
    AI_EXTERNAL_GUARDRAIL_VERDICTS
        .with_label_values(&[provider, phase, outcome])
        .get()
}

#[cfg(test)]
pub(crate) fn safety_guardrail_verdict_value(
    guardrail: &str,
    class: &str,
    backend: &str,
    verdict: &str,
) -> f64 {
    AI_SAFETY_GUARDRAIL_VERDICTS
        .with_label_values(&[guardrail, class, backend, verdict])
        .get()
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
/// [`crate::ratelimit::RejectReason::axis_label`]; `key_id` is the immutable,
/// secret-free resolved policy/key identifier; `tenant` is the
/// originating tenant (empty for the tenant-blind entry point); `model`
/// is the upstream model name. Surface this via the
/// `sbproxy_ai_ratelimit_rejected_total` counter; operators alert when
/// any axis fires.
pub fn record_ratelimit_rejected(axis: &str, key_id: &str, tenant: &str, model: &str) {
    AI_RATELIMIT_REJECTED
        .with_label_values(&[axis, key_id, tenant, model])
        .inc();
}

/// Read the cumulative value of the rate-limit rejection counter for
/// one `(axis, key_id, tenant, model)` tuple. Used by tests.
#[cfg(test)]
pub(crate) fn ratelimit_rejected_value(axis: &str, key_id: &str, tenant: &str, model: &str) -> f64 {
    AI_RATELIMIT_REJECTED
        .with_label_values(&[axis, key_id, tenant, model])
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

// --- Waste-signal metrics (WOR-1085) ---
//
// The Token-to-Value Ledger lists "tokens spent with no outcome"
// detectors that the gateway can flag deterministically without
// any guess about what the caller intended:
//
// * `duplicate_request`: an exact-context resend reported by the serving
//   path; tag the spend wasted.
// * `abandoned_stream`: the client cancelled or the upstream
//   stream closed with zero output tokens after the prompt was
//   already sent.
// * `validation_failed`: a guardrail rejected AFTER the upstream call
//   completed; the spend already happened.
// * `context_bloat`: input tokens significantly above the
//   route's rolling median (the gateway emits the counter; the
//   classifier-cum-roller lives outside this module and reports
//   in).
//
// These are observational counters + an estimated-wasted-USD
// gauge. Enforcement (budget caps, denial gates) lives in
// `budget.rs`, not here. There is no separate hierarchical
// budget tracker; scopes are flat `BudgetScope` limits.

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

/// The five attribution tags that reach a Prometheus label, bounded.
///
/// [`crate::attribution::AttributionTags`] is a closed schema and each
/// value is length-capped at
/// [`MAX_TAG_VALUE_LEN`](crate::attribution::MAX_TAG_VALUE_LEN), which
/// is what the parser enforces and is not a cardinality bound: it caps
/// how long one value is, not how many distinct ones there can be.
/// Every one of these five is settable per request by an `SB-Attr-*`
/// header, so a caller varying a single header mints a time series per
/// value on each of the five families that carry them. Rejecting
/// unknown tag KEYS does nothing about that, because the keys were
/// never the unbounded part.
///
/// They therefore go through the same cardinality limiter as the rest
/// of this proxy's label values, against the per-label budgets in
/// [`sbproxy_observe::cardinality::budget_for_label`]. Past a label's
/// budget the value becomes the `__other__` sentinel and
/// `sbproxy_label_cardinality_overflow_total{metric, label}`
/// increments, so an operator sees the collapse instead of inferring it
/// from a panel that stopped splitting.
///
/// `trace_id`, `customer`, and `okr` are not here because they are not
/// labels at all; they ride the span and the access log. `agent_id` is
/// not here either, and that one is a real exclusion rather than an
/// absence: it is the only attribution field no header can set, and
/// what bounds it is the rule that the gateway writes it only from an
/// identity it verified.
struct AttributionLabels {
    project: String,
    feature: String,
    team: String,
    agent_type: String,
    environment: String,
}

impl AttributionLabels {
    /// Sanitize the label-bearing tags for a write to `metric`.
    ///
    /// Sanitizing once per record call rather than once per family is
    /// deliberate. The limiter keys its accepted-value set on the label
    /// name alone, not on the metric, so the answer is identical for
    /// every family carrying the same label; asking a second time would
    /// only double-count the overflow counter for one request. `metric`
    /// therefore names the family whose write observed the demotion,
    /// which is the family an operator reading the counter should go
    /// look at first.
    ///
    /// The proxy-wide limiter is used rather than its tenant-scoped
    /// sibling so that all five families agree. Two of the three
    /// callers know the tenant and one does not, and a value accepted
    /// under a tenant set on one family while being demoted under the
    /// proxy-wide set on another would make the token counter and the
    /// waste counter disagree about the same request.
    fn sanitized(metric: &str, tags: &crate::attribution::AttributionTags) -> Self {
        let bounded = |label: &str, value: Option<&str>| {
            sbproxy_observe::metrics::sanitize_label_budget(metric, label, label_or_empty(value))
        };
        Self {
            project: bounded("project", tags.project.as_deref()),
            feature: bounded("feature", tags.feature.as_deref()),
            team: bounded("team", tags.team.as_deref()),
            agent_type: bounded("agent_type", tags.agent_type.as_deref()),
            environment: bounded("environment", tags.environment.as_deref()),
        }
    }
}

/// Stable waste-class identifiers. The string slug lands on the
/// `kind` label; using a closed enum keeps the label vocabulary
/// auditable instead of letting a typo create a new time series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasteKind {
    /// The request's full context matched a recent prior request; the
    /// upstream call still happened (or would have).
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
    let labels = AttributionLabels::sanitized("sbproxy_ai_wasted_tokens_total", tags);
    if tokens > 0 {
        AI_WASTED_TOKENS
            .with_label_values(&[
                kind.as_str(),
                provider,
                model,
                surface,
                labels.project.as_str(),
                labels.feature.as_str(),
                labels.team.as_str(),
                labels.agent_type.as_str(),
                labels.environment.as_str(),
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
                labels.project.as_str(),
                labels.feature.as_str(),
                labels.team.as_str(),
                labels.agent_type.as_str(),
                labels.environment.as_str(),
            ])
            .inc_by(cost_usd);
    }
}

// --- Per-attribution spend metrics (WOR-1086) ---
//
// Per-request attribution tags ride on every AI spend record (see
// `crate::attribution`). The dashboard wants spend broken down by
// the business dimensions those tags carry; this section exposes
// the request / token / cost totals plus a bounded set of
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
            // Origin (config hostname) the request arrived on; bounded
            // by the config, so it is cardinality-safe. Enables the
            // admin UI's per-origin spend and token views.
            "origin",
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
            // WOR-2140: which agent spent it. Appended last because the
            // metric registry treats a family's label list as positional
            // and append-only. Empty unless the gateway resolved a
            // VERIFIED agent identity, so the distinct values are the
            // operator's agent roster rather than whatever a caller
            // decided to call itself. See `record_ai_request_attributed`.
            "agent_id",
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
            // See AI_TOKENS_ATTRIBUTED: config-bounded origin hostname.
            "origin",
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
            // See AI_TOKENS_ATTRIBUTED (WOR-2140). Appended last, and
            // in the same position relative to the shared labels, so
            // `sum by (agent_id)` reads the same on tokens and cost.
            "agent_id",
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
/// `gateway_auth_denied`, `upstream_auth_denied`, `policy_block`,
/// `data_posture_block`, `price_ceiling_block`, `refusal`,
/// `client_error`, `other`) so cardinality stays bounded.
static AI_OUTCOMES_ATTRIBUTED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_requests_attributed_total",
            "AI requests partitioned by attribution + outcome (WOR-1496)"
        ),
        &[
            // See AI_TOKENS_ATTRIBUTED: config-bounded origin hostname.
            "origin",
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

/// One terminal decision for every AI request, including requests rejected
/// before provider dispatch. `decision` is `admitted` or `rejected`; `reason`
/// is `none` for admitted traffic and otherwise reuses the bounded outcome
/// vocabulary.
static AI_GATEWAY_DECISIONS: LazyLock<Result<CounterVec, prometheus::Error>> =
    LazyLock::new(|| {
        register_counter_vec!(
            Opts::new(
                "sbproxy_ai_gateway_decisions_total",
                "AI gateway admission decisions, including pre-provider rejections"
            ),
            &["decision", "reason"]
        )
    });

/// Record one terminal AI gateway admission decision.
pub fn record_ai_gateway_decision(decision: &'static str, reason: &'static str) {
    if let Ok(counter) = AI_GATEWAY_DECISIONS.as_ref() {
        counter.with_label_values(&[decision, reason]).inc();
    }
}

/// Record one AI request against the per-attribution outcome counter.
/// `outcome` must be one of the closed-set labels documented on the
/// `AI_OUTCOMES_ATTRIBUTED` counter; callers map their status / error
/// into that set before calling so the label cardinality stays bounded.
#[allow(clippy::too_many_arguments)]
pub fn record_ai_outcome_attributed(
    origin: &str,
    provider: &str,
    model: &str,
    surface: &str,
    tenant_id: &str,
    api_key_id: &str,
    outcome: &str,
) {
    AI_OUTCOMES_ATTRIBUTED
        .with_label_values(&[
            origin, provider, model, surface, tenant_id, api_key_id, outcome,
        ])
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
/// Allocate-layer join works off the span's trace_id, which is also the
/// workflow key (see [`crate::attribution::AttributionTags::trace_id`]).
///
/// # Agent attribution (WOR-2140)
///
/// `agent_id` comes off `tags` and rides as the last label on both
/// counters, so `sum by (agent_id) (rate(sbproxy_ai_cost_dollars_attributed_total[5m]))`
/// answers "what is each agent costing me per minute" with no join.
///
/// Two things are load bearing about which agent ids get here.
///
/// The caller cannot pick one. `agent_id` is not settable from an
/// `SB-Attr-*` header, and the dispatch path fills it only from an
/// identity the proxy verified. An agent that merely asserts its own
/// name lands in the empty bucket, which reads as "spend we could not
/// attribute to a verified agent" rather than as somebody else's bill.
/// That is also what keeps the label's distinct values bounded by the
/// operator's agent roster instead of by traffic.
///
/// The run and workflow ids never get here at all. A `contextId`, a task
/// id, and a `trace_id` each take one value per occurrence, so as labels
/// they mint a time series per run and the series count grows with
/// traffic. The run and task ids belong on the span and in the usage
/// ledger, the workflow id on the access log, and that is where they
/// are. `sbproxy-observe`'s metric-registry guard fails the build if one
/// of them reaches a label list here.
#[allow(clippy::too_many_arguments)]
pub fn record_ai_request_attributed(
    origin: &str,
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
    let labels = AttributionLabels::sanitized("sbproxy_ai_tokens_attributed_total", tags);
    // WOR-2140. Empty when no verified agent identity resolved, which is
    // the same convention every other optional dimension here uses: the
    // spend is still counted, in a bucket that says it is not attributed
    // to an agent rather than one that names the wrong one.
    //
    // This one does not go through the limiter beside the five above it,
    // and the reason is that it is not the same kind of value. No header
    // sets it, so its distinct values are the operator's agent roster
    // rather than whatever a caller sends.
    let agent_id = label_or_empty(tags.agent_id.as_deref());

    let record_token_kind = |direction: &'static str, n: u64| {
        if n == 0 {
            return;
        }
        AI_TOKENS_ATTRIBUTED
            .with_label_values(&[
                origin,
                provider,
                model,
                surface,
                direction,
                labels.project.as_str(),
                labels.feature.as_str(),
                labels.team.as_str(),
                labels.agent_type.as_str(),
                labels.environment.as_str(),
                tenant_id,
                api_key_id,
                agent_id,
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
                origin,
                provider,
                model,
                surface,
                labels.project.as_str(),
                labels.feature.as_str(),
                labels.team.as_str(),
                labels.agent_type.as_str(),
                labels.environment.as_str(),
                tenant_id,
                api_key_id,
                agent_id,
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
    let labels = AttributionLabels::sanitized("sbproxy_ai_audio_seconds_attributed_total", tags);
    AI_AUDIO_SECONDS_ATTRIBUTED
        .with_label_values(&[
            provider,
            model,
            surface,
            labels.project.as_str(),
            labels.feature.as_str(),
            labels.team.as_str(),
            labels.agent_type.as_str(),
            labels.environment.as_str(),
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

/// Request-body inspection the AI gateway skipped because the inbound
/// body was multipart, by inspection kind and classified surface
/// (WOR-2309).
///
/// The multipart short-circuit forwards the body byte-transparently, so
/// every check that needs a parsed JSON body is bypassed. That bypass
/// was previously silent: the only evidence a configured guardrail did
/// not run was the absence of a block, which is indistinguishable from
/// a clean request. This is the built-in analogue of
/// `sbproxy_ai_stream_guardrail_skipped_total`, and it exists for the
/// same reason: a coverage gap has to be visible on a dashboard.
///
/// The `surface` label carries the security signal. Multipart on
/// `audio_transcription` or `image_edits` is the expected shape, but the
/// short-circuit keys on the inbound `Content-Type` rather than on the
/// surface, so a caller can relabel any surface as multipart and take
/// the same path. A nonzero rate on `chat_completions` is a bypass
/// attempt, not routine traffic.
///
/// Cardinality is bounded: `check` is a closed set fixed at the call
/// site and `surface` is the closed `AiSurface::label()` vocabulary.
///
/// Registered without `.unwrap()` (unlike its neighbors) because the
/// production unwrap/expect ratchet in `scripts/check-unwrap-ratchet.sh`
/// is at its baseline and a metric family is not worth a panic path.
static MULTIPART_INSPECTION_SKIPPED: LazyLock<Option<CounterVec>> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_multipart_inspection_skipped_total",
            "Request-body inspection skipped because the AI request body was multipart (WOR-2309)"
        ),
        &["check", "surface"]
    )
    .ok()
});

/// Record a request-body inspection skipped by the multipart short-circuit.
///
/// `check` names the bypassed inspection (`input_guardrails`,
/// `pii_redaction`); `surface` is [`AiSurface::label`] for the
/// classified request.
///
/// [`AiSurface::label`]: crate::handler::AiSurface::label
pub fn record_multipart_inspection_skipped(check: &str, surface: &str) {
    let Some(counter) = &*MULTIPART_INSPECTION_SKIPPED else {
        return;
    };
    counter.with_label_values(&[check, surface]).inc();
}

// --- RAG retrieval metrics (WOR-2098) ---

/// AI requests that consulted a RAG retrieval runtime, by embedding
/// provider, vector store, and closed outcome.
///
/// `embedding` and `vector_store` are the runtime's configured provider
/// kind labels (bounded by the closed provider sets the `rag` config
/// accepts); `outcome` is one of `retrieved`, `no_match`, `stale`,
/// `continued`, or `error`, normalized by [`record_rag_request`] so
/// request data cannot create new series.
static AI_RAG_REQUESTS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_rag_requests_total",
            "AI requests that ran RAG retrieval, by embedding provider, vector store, and outcome"
        ),
        &["embedding", "vector_store", "outcome"]
    )
    .unwrap()
});

/// RAG retrieval latency in seconds, by stage and provider.
///
/// `stage` is one of `embedding`, `search`, or `total`; an unknown stage
/// is dropped rather than remapped so a typo cannot misattribute time.
/// `provider` is the provider kind label that served the stage (the
/// embedding provider for `embedding` and `total`, the vector store for
/// `search`). Buckets span local sub-10ms lookups through slow remote
/// stores.
static AI_RAG_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_ai_rag_latency_seconds",
            "RAG retrieval latency in seconds, by stage and provider"
        )
        .buckets(vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0
        ]),
        &["stage", "provider"]
    )
    .unwrap()
});

/// Bytes of rendered retrieval context injected into the request body.
///
/// Observed once per retrieval that produced a context (zero-byte
/// observations are recorded too, so a run of empty renders is visible).
/// Buckets span a one-sentence snippet through the configured context
/// ceiling.
static AI_RAG_CONTEXT_BYTES: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(HistogramOpts::new(
        "sbproxy_ai_rag_context_bytes",
        "Bytes of rendered RAG context injected into the request body"
    )
    .buckets(vec![
        256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0
    ]))
    .unwrap()
});

/// Record one RAG retrieval attempt against the request counter.
///
/// `outcome` must come from the closed set `retrieved | no_match |
/// stale | continued | error`; any other value is folded into `error`
/// so a future outcome variant cannot mint an unbounded label.
pub fn record_rag_request(embedding: &str, vector_store: &str, outcome: &str) {
    let outcome = match outcome {
        "retrieved" | "no_match" | "stale" | "continued" | "error" => outcome,
        _ => "error",
    };
    AI_RAG_REQUESTS
        .with_label_values(&[embedding, vector_store, outcome])
        .inc();
}

/// Record one RAG retrieval latency observation, in seconds.
///
/// `stage` must be `embedding`, `search`, or `total`; unknown stages
/// and non-finite or negative durations are dropped so the histogram
/// only sees meaningful, correctly attributed samples.
pub fn record_rag_latency(stage: &str, provider: &str, seconds: f64) {
    if !seconds.is_finite() || seconds < 0.0 {
        return;
    }
    let stage = match stage {
        "embedding" | "search" | "total" => stage,
        _ => return,
    };
    AI_RAG_LATENCY
        .with_label_values(&[stage, provider])
        .observe(seconds);
}

/// Record the rendered RAG context size, in bytes, for one retrieval.
pub fn record_rag_context_bytes(bytes: usize) {
    AI_RAG_CONTEXT_BYTES.observe(bytes as f64);
}

// --- Model directory metrics ---

/// Directory nodes excluded from model routing, by
/// [`crate::model_directory::ModelDirectoryExclusionReason`]. Counted once
/// per excluded node per `ModelDirectory::refresh`, so a steady
/// exclusion shows up as a steady rate rather than a one-shot event.
static AI_MODEL_DIRECTORY_EXCLUSIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_model_directory_exclusions_total",
            "Directory nodes excluded from model routing, by exclusion reason"
        ),
        &["exclusion_reason"]
    )
    .unwrap()
});

/// Record one directory node classified out of eligible routing on a
/// `refresh`, by its bounded exclusion reason.
pub fn record_model_directory_exclusion(reason: &'static str) {
    AI_MODEL_DIRECTORY_EXCLUSIONS
        .with_label_values(&[reason])
        .inc();
}

#[cfg(test)]
pub(crate) fn model_directory_exclusion_value(reason: &str) -> f64 {
    AI_MODEL_DIRECTORY_EXCLUSIONS
        .with_label_values(&[reason])
        .get()
}

// --- Managed-replica routing metrics ---

/// Managed-replica candidates excluded before rendezvous ranking, by the
/// [`crate::managed_replica::ReplicaSelectionTrace`] stage that dropped
/// them (`generation`, `health`, `endpoint`, `state`, `adapter`).
static AI_REPLICA_SELECTION_EXCLUDED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_ai_replica_selection_excluded_total",
            "Managed-replica candidates excluded before rendezvous ranking, by stage"
        ),
        &["stage"]
    )
    .unwrap()
});

/// Record `count` candidates excluded at one `ReplicaSelectionTrace`
/// stage for a single routing decision. A no-op for `count == 0` so a
/// clean routing decision does not touch every stage's series.
pub fn record_replica_selection_excluded(stage: &'static str, count: usize) {
    if count == 0 {
        return;
    }
    AI_REPLICA_SELECTION_EXCLUDED
        .with_label_values(&[stage])
        .inc_by(count as f64);
}

#[cfg(test)]
pub(crate) fn replica_selection_excluded_value(stage: &str) -> f64 {
    AI_REPLICA_SELECTION_EXCLUDED
        .with_label_values(&[stage])
        .get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bedrock_inline_verdict_is_labeled_separately_from_apply_guardrail() {
        // An operator's whole reason for reading this metric is to see
        // which layer stopped a request. Folding the inline Converse
        // guardrail into the `bedrock` label (or into `unknown`) makes
        // that unanswerable.
        assert_eq!(
            normalize_external_guardrail_labels("bedrock_inline", "output", "block"),
            ("bedrock_inline", "output", "block")
        );
        assert_eq!(
            normalize_external_guardrail_labels("bedrock", "input", "block"),
            ("bedrock", "input", "block")
        );
        assert_eq!(
            normalize_external_guardrail_labels("bedrock-inline", "output", "block").0,
            "unknown",
            "the set stays closed; only the exact spelling is admitted"
        );
    }

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

    /// WOR-2309: the multipart coverage-gap family registers and carries
    /// both label names. Pinned because the `surface` label is what makes
    /// a content-type bypass distinguishable from routine audio traffic;
    /// dropping it would leave the family readable but useless.
    #[test]
    fn multipart_inspection_skipped_counter_registers_with_check_and_surface_labels() {
        record_multipart_inspection_skipped("input_guardrails", "chat_completions");
        record_multipart_inspection_skipped("pii_redaction", "audio_transcription");
        let families = prometheus::gather();
        let skipped = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_multipart_inspection_skipped_total")
            .expect("multipart inspection skipped counter registered");
        let bypass = skipped
            .get_metric()
            .iter()
            .find(|m| {
                m.get_label()
                    .iter()
                    .any(|l| l.name() == "check" && l.value() == "input_guardrails")
                    && m.get_label()
                        .iter()
                        .any(|l| l.name() == "surface" && l.value() == "chat_completions")
            })
            .expect("input_guardrails row on chat_completions");
        assert_eq!(bypass.get_counter().value(), 1.0);
        assert!(skipped.get_metric().iter().any(|m| {
            m.get_label()
                .iter()
                .any(|l| l.name() == "check" && l.value() == "pii_redaction")
        }));
    }

    /// WOR-2098: the three RAG families register and carry the expected
    /// label names.
    #[test]
    fn rag_metrics_families_register_with_expected_labels() {
        record_rag_request("openai_compatible", "qdrant", "retrieved");
        record_rag_latency("embedding", "openai_compatible", 0.012);
        record_rag_latency("search", "qdrant", 0.004);
        record_rag_latency("total", "openai_compatible", 0.02);
        record_rag_context_bytes(1536);

        let families = prometheus::gather();
        let requests = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_rag_requests_total")
            .expect("rag request counter registered");
        let request_labels: Vec<&str> = requests
            .get_metric()
            .iter()
            .flat_map(|m| m.get_label().iter().map(|l| l.name()))
            .collect();
        for required in &["embedding", "vector_store", "outcome"] {
            assert!(
                request_labels.contains(required),
                "expected label '{required}' on sbproxy_ai_rag_requests_total"
            );
        }

        let latency = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_rag_latency_seconds")
            .expect("rag latency histogram registered");
        let latency_labels: Vec<&str> = latency
            .get_metric()
            .iter()
            .flat_map(|m| m.get_label().iter().map(|l| l.name()))
            .collect();
        for required in &["stage", "provider"] {
            assert!(
                latency_labels.contains(required),
                "expected label '{required}' on sbproxy_ai_rag_latency_seconds"
            );
        }
        for stage in ["embedding", "search", "total"] {
            assert!(
                latency.get_metric().iter().any(|m| {
                    m.get_label()
                        .iter()
                        .any(|l| l.name() == "stage" && l.value() == stage)
                }),
                "expected a '{stage}' stage row on sbproxy_ai_rag_latency_seconds"
            );
        }

        let context = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_rag_context_bytes")
            .expect("rag context-bytes histogram registered");
        let samples: u64 = context
            .get_metric()
            .iter()
            .map(|m| m.get_histogram().get_sample_count())
            .sum();
        assert!(samples >= 1, "expected at least one context observation");
    }

    /// WOR-2098: an outcome outside the closed vocabulary is folded into
    /// `error` instead of minting a new series.
    #[test]
    fn rag_metrics_outcome_labels_are_closed() {
        let outcome_value = |outcome: &str| {
            AI_RAG_REQUESTS
                .with_label_values(&["closed-set-embed", "closed-set-store", outcome])
                .get()
        };
        let before = outcome_value("error");
        record_rag_request(
            "closed-set-embed",
            "closed-set-store",
            "operator-controlled",
        );
        assert_eq!(outcome_value("error"), before + 1.0);

        let families = prometheus::gather();
        let requests = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_rag_requests_total")
            .expect("rag request counter registered");
        assert!(
            !requests.get_metric().iter().any(|m| {
                m.get_label()
                    .iter()
                    .any(|l| l.name() == "outcome" && l.value() == "operator-controlled")
            }),
            "an out-of-set outcome must never appear as its own series"
        );
    }

    /// WOR-2098: unknown stages plus non-finite and negative durations
    /// are dropped, keeping the stage vocabulary closed.
    #[test]
    fn rag_metrics_latency_drops_unknown_stage_and_bad_values() {
        let sample_count = || -> u64 {
            let families = prometheus::gather();
            families
                .iter()
                .find(|f| f.name() == "sbproxy_ai_rag_latency_seconds")
                .map(|f| {
                    f.get_metric()
                        .iter()
                        .filter(|m| {
                            m.get_label().iter().any(|l| {
                                l.name() == "provider" && l.value() == "stage-guard-provider"
                            })
                        })
                        .map(|m| m.get_histogram().get_sample_count())
                        .sum()
                })
                .unwrap_or(0)
        };
        let before = sample_count();
        record_rag_latency("prefetch", "stage-guard-provider", 0.1);
        record_rag_latency("total", "stage-guard-provider", f64::NAN);
        record_rag_latency("total", "stage-guard-provider", -0.5);
        assert_eq!(
            sample_count(),
            before,
            "unknown stages and invalid durations must not be observed"
        );
        record_rag_latency("total", "stage-guard-provider", 0.1);
        assert_eq!(sample_count(), before + 1);
    }

    #[test]
    fn test_record_data_posture_filter() {
        record_data_posture_filter("require_zdr", "filtered", "acme");
        record_data_posture_filter("require_zdr", "refused", "acme");
        record_data_posture_filter("deny_data_collection", "filtered", "");

        let families = prometheus::gather();
        let family = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_data_posture_filter_total")
            .expect("sbproxy_ai_data_posture_filter_total should be registered");
        let outcomes: Vec<&str> = family
            .get_metric()
            .iter()
            .flat_map(|m| m.get_label())
            .filter(|l| l.name() == "outcome")
            .map(|l| l.value())
            .collect();
        assert!(outcomes.contains(&"filtered"));
        assert!(outcomes.contains(&"refused"));
        let tenants: Vec<&str> = family
            .get_metric()
            .iter()
            .flat_map(|m| m.get_label())
            .filter(|l| l.name() == "tenant")
            .map(|l| l.value())
            .collect();
        assert!(
            tenants.contains(&"__default__"),
            "an empty tenant becomes the single-tenant default, never a blank label"
        );
        assert!(tenants.contains(&"acme"));
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
            "test.origin",
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
    fn test_record_ai_gateway_decision() {
        record_ai_gateway_decision("rejected", "gateway_auth_denied");
        let families = prometheus::gather();
        let family = families
            .iter()
            .find(|family| family.name() == "sbproxy_ai_gateway_decisions_total")
            .expect("gateway decisions counter registered");
        assert!(family.get_metric().iter().any(|metric| {
            let labels = metric.get_label();
            labels
                .iter()
                .any(|label| label.name() == "decision" && label.value() == "rejected")
                && labels
                    .iter()
                    .any(|label| label.name() == "reason" && label.value() == "gateway_auth_denied")
        }));
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
        // WOR-1535: the dispatch path emits three reason kinds
        // (retriable upstream status, transport failure, content-policy
        // fallback). Pin the label names and that vocabulary so a
        // rename breaks this test instead of silently orphaning
        // dashboards and the provider-health admin view.
        record_failover("primary", "backup", "http_503", "acme");
        record_failover("primary", "backup", "transport", "acme");
        record_failover("primary", "backup", "content_policy", "acme");
        let families = prometheus::gather();
        let failovers = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_failovers_total")
            .expect("failover counter must be registered");
        let mut reasons = std::collections::HashSet::new();
        for m in failovers.get_metric() {
            let labels: std::collections::HashMap<&str, &str> = m
                .get_label()
                .iter()
                .map(|l| (l.name(), l.value()))
                .collect();
            assert!(labels.contains_key("from_provider"));
            assert!(labels.contains_key("to_provider"));
            if labels.get("from_provider").copied() == Some("primary") {
                assert_eq!(labels.get("to_provider").copied(), Some("backup"));
                reasons.insert(labels["reason"].to_string());
                assert_eq!(m.get_counter().value(), 1.0);
            }
        }
        for expected in ["http_503", "transport", "content_policy"] {
            assert!(
                reasons.contains(expected),
                "missing failover reason {expected}"
            );
        }
    }

    /// WOR-2486: `provider_selected` fires only on the fallback/advance
    /// transition this function already is, never per request. Red
    /// first: before this wiring `EventType::ProviderSelected` had no
    /// production call site anywhere in the workspace.
    #[test]
    fn provider_selected_event_carries_the_transition() {
        let event = super::provider_selected_event("primary", "backup", "http_503", "acme");
        assert_eq!(
            event.event_type,
            sbproxy_observe::EventType::ProviderSelected
        );
        assert_eq!(event.hostname, "backup");
        assert_eq!(event.tenant_id, "acme");
        assert_eq!(event.data["from_provider"], "primary");
        assert_eq!(event.data["to_provider"], "backup");
        assert_eq!(event.data["reason"], "http_503");
    }

    #[test]
    fn routing_depth_counters_register_bounded_labels_and_increment() {
        record_routing_fallback("outcome_aware", "warmup");
        record_routing_fallback("outcome_aware", "operator-controlled");
        record_prefix_affinity_decision("hit");
        record_prefix_affinity_decision("operator-controlled");
        record_prefix_affinity_eviction("ttl");
        record_prefix_affinity_eviction("operator-controlled");
        record_routing_fallback("semantic_route", "embed_error");
        record_semantic_route_decision("matched");
        record_semantic_route_decision("operator-controlled");
        record_semantic_route_similarity("code-pool", 0.91);
        record_quota_pool_fail_open("shared-upstream");
        record_quota_pool_overshare("shared-upstream");

        let families = prometheus::gather();
        let expected = [
            (
                "sbproxy_ai_routing_fallbacks_total",
                vec![("strategy", "outcome_aware"), ("reason", "warmup")],
            ),
            (
                "sbproxy_ai_prefix_affinity_decisions_total",
                vec![("outcome", "hit")],
            ),
            (
                "sbproxy_ai_prefix_affinity_evictions_total",
                vec![("reason", "ttl")],
            ),
            (
                "sbproxy_ai_routing_fallbacks_total",
                vec![("strategy", "semantic_route"), ("reason", "embed_error")],
            ),
            (
                "sbproxy_ai_semantic_route_decisions_total",
                vec![("outcome", "matched")],
            ),
            (
                "sbproxy_ai_quota_pool_fail_open_total",
                vec![("pool", "shared-upstream")],
            ),
            (
                "sbproxy_ai_quota_pool_overshare_total",
                vec![("pool", "shared-upstream")],
            ),
        ];

        for (name, labels) in expected {
            let family = families
                .iter()
                .find(|family| family.name() == name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            assert!(
                family.get_metric().iter().any(|metric| {
                    labels.iter().all(|(label_name, label_value)| {
                        metric.get_label().iter().any(|label| {
                            label.name() == *label_name && label.value() == *label_value
                        })
                    }) && metric.get_counter().value() >= 1.0
                }),
                "{name} must contain the expected incremented label set"
            );
        }

        for (name, label_name) in [
            ("sbproxy_ai_routing_fallbacks_total", "reason"),
            ("sbproxy_ai_prefix_affinity_decisions_total", "outcome"),
            ("sbproxy_ai_prefix_affinity_evictions_total", "reason"),
            ("sbproxy_ai_semantic_route_decisions_total", "outcome"),
        ] {
            let family = families
                .iter()
                .find(|family| family.name() == name)
                .expect("metric family registered above");
            assert!(
                family.get_metric().iter().any(|metric| {
                    metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == label_name && label.value() == "unknown")
                }),
                "{name} must normalize unexpected label values"
            );
        }
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
    fn safety_guardrail_verdict_labels_are_closed() {
        let before = safety_guardrail_verdict_value("jailbreak", "unknown", "unknown", "unknown");
        record_safety_guardrail_verdict("jailbreak", "operator-value", "remote", "deny");
        let after = safety_guardrail_verdict_value("jailbreak", "unknown", "unknown", "unknown");
        assert_eq!(after, before + 1.0);
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
    fn test_record_inter_token_latency() {
        record_inter_token_latency("openai", "gpt-4o", 0.032);
        // Non-positive / non-finite samples are dropped by the helper.
        record_inter_token_latency("openai", "gpt-4o", 0.0);
        record_inter_token_latency("openai", "gpt-4o", f64::NAN);
        record_inter_token_latency("openai", "gpt-4o", -0.5);
        let families = prometheus::gather();
        let itl = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_inter_token_latency_seconds")
            .expect("inter-token latency histogram must be registered");
        let sample = &itl.get_metric()[0];
        assert_eq!(sample.get_histogram().get_sample_count(), 1);
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
            "test.origin",
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

    /// WOR-2140: the agent that spent it reaches both attributed
    /// counters as `agent_id`, and nothing run-scoped reaches either.
    ///
    /// The second half is the part worth a test rather than a comment.
    /// `agent_id` is safe as a label because it names a member of the
    /// operator's agent roster; a run, task, context, or workflow id is
    /// not, because it takes a fresh value per occurrence and would mint
    /// one dead time series per run forever. Those ids are on the span
    /// and in the usage ledger instead. `sbproxy-observe` fails the build
    /// if one appears in the registry's declared label list, but the
    /// registry is a hand-maintained table; this asserts against the
    /// labels the process actually emitted.
    #[test]
    fn attributed_spend_carries_the_agent_and_no_run_scoped_id() {
        use crate::attribution::AttributionTags;
        // Unique provider + model so the assertions are isolated from
        // the shared process-wide Prometheus registry.
        let provider = "agent-attr-test-provider";
        let model = "agent-attr-test-model";
        let tags = AttributionTags {
            project: Some("growth-q3".to_string()),
            team: Some("platform".to_string()),
            // The workflow key. It must reach the span and the access
            // log, and it must NOT reach a label here.
            trace_id: Some("wf-01J6FQ7X0000000000000000".to_string()),
            agent_id: Some("billing-orchestrator".to_string()),
            ..Default::default()
        };
        record_ai_request_attributed(
            "test.origin",
            provider,
            model,
            "chat_completions",
            "acme-tenant",
            "sk_deadbeef0003",
            &tags,
            100,
            50,
            0,
            0,
            0,
            0.25,
        );

        let families = prometheus::gather();
        for family in [
            "sbproxy_ai_tokens_attributed_total",
            "sbproxy_ai_cost_dollars_attributed_total",
        ] {
            let f = families
                .iter()
                .find(|f| f.name() == family)
                .unwrap_or_else(|| panic!("{family} must be registered"));
            let ours: Vec<_> = f
                .get_metric()
                .iter()
                .filter(|m| {
                    m.get_label()
                        .iter()
                        .any(|l| l.name() == "provider" && l.value() == provider)
                })
                .collect();
            assert!(!ours.is_empty(), "{family} recorded no cell for {provider}");
            for m in &ours {
                let labels = m.get_label();
                assert!(
                    labels
                        .iter()
                        .any(|l| l.name() == "agent_id" && l.value() == "billing-orchestrator"),
                    "{family} must carry the spending agent, got {labels:?}"
                );
                for forbidden in [
                    "trace_id",
                    "run_id",
                    "task_id",
                    "session_id",
                    "context_id",
                    "request_id",
                    "a2a_context_id",
                ] {
                    assert!(
                        !labels.iter().any(|l| l.name() == forbidden),
                        "{family} must not carry the run-scoped label {forbidden:?}"
                    );
                }
            }
        }
    }

    /// Spend the gateway could not tie to a verified agent still counts,
    /// under an empty `agent_id`. Dropping the row would hide the spend;
    /// inventing a value for it would attribute somebody's bill to an
    /// agent that did not make the call.
    #[test]
    fn unattributed_spend_lands_under_an_empty_agent_id() {
        use crate::attribution::AttributionTags;
        let provider = "no-agent-test-provider";
        let model = "no-agent-test-model";
        record_ai_request_attributed(
            "test.origin",
            provider,
            model,
            "chat_completions",
            "acme-tenant",
            "sk_deadbeef0004",
            &AttributionTags::default(),
            10,
            5,
            0,
            0,
            0,
            0.5,
        );
        let families = prometheus::gather();
        let f = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_cost_dollars_attributed_total")
            .expect("cost counter registered");
        let ours = f
            .get_metric()
            .iter()
            .find(|m| {
                m.get_label()
                    .iter()
                    .any(|l| l.name() == "provider" && l.value() == provider)
            })
            .expect("the unattributed cell was recorded");
        assert!(
            ours.get_label()
                .iter()
                .any(|l| l.name() == "agent_id" && l.value().is_empty()),
            "an unresolved agent must record as empty, not be dropped"
        );
        assert!(ours.get_counter().value() >= 0.5);
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
            "test.origin",
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

    #[test]
    fn model_directory_exclusion_counts_by_reason() {
        let before = model_directory_exclusion_value("membership_dead");
        record_model_directory_exclusion("membership_dead");
        record_model_directory_exclusion("membership_dead");
        assert!((model_directory_exclusion_value("membership_dead") - before - 2.0).abs() < 1e-9);
    }

    #[test]
    fn replica_selection_excluded_counts_by_stage_and_skips_zero() {
        let before = replica_selection_excluded_value("health");
        // A clean routing decision (0 excluded) must not touch the series.
        record_replica_selection_excluded("health", 0);
        assert!((replica_selection_excluded_value("health") - before).abs() < 1e-9);

        record_replica_selection_excluded("health", 3);
        assert!((replica_selection_excluded_value("health") - before - 3.0).abs() < 1e-9);
    }
}
