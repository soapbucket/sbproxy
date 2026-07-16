use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use prometheus::{
    CounterVec, Encoder, GaugeVec, Histogram, HistogramVec, IntCounterVec, IntGauge, Opts,
    Registry, TextEncoder,
};

use crate::agent_labels::AgentLabels;
use crate::cardinality::{CardinalityConfig, CardinalityLimiter};

/// Global metrics registry.
static METRICS: OnceLock<ProxyMetrics> = OnceLock::new();

/// Global cardinality limiter shared by all metrics recording helpers.
static CARDINALITY_LIMITER: OnceLock<CardinalityLimiter> = OnceLock::new();

/// Return a reference to the global [`CardinalityLimiter`].
///
/// Initialised with the default configuration (1 000 unique values per label)
/// on first call. To apply a custom limit, call [`init_cardinality_limiter`]
/// before recording any metrics.
pub fn global_limiter() -> &'static CardinalityLimiter {
    CARDINALITY_LIMITER.get_or_init(|| CardinalityLimiter::new(CardinalityConfig::default()))
}

/// Initialise the global cardinality limiter with a custom configuration.
///
/// Must be called before the first metric is recorded. If the limiter has
/// already been initialised, this is a no-op and returns `false`.
pub fn init_cardinality_limiter(config: CardinalityConfig) -> bool {
    CARDINALITY_LIMITER
        .set(CardinalityLimiter::new(config))
        .is_ok()
}

/// Sanitize a label value through the global cardinality limiter.
///
/// Returns the value unchanged if it has been seen before or the label still
/// has capacity. Returns `"__other__"` once the cap is reached.
pub fn sanitize_label(label_name: &str, value: &str) -> String {
    global_limiter().sanitize(label_name, value)
}

/// Sanitize a label value against the per-label budget. Empty strings
/// pass through unchanged because they are the explicit "no agent context attached"
/// sentinel and do not consume budget. Overflow demotions emit a
/// `sbproxy_label_cardinality_overflow_total{metric, label}` counter
/// and a rate-limited tracing warning (one per minute per (metric,
/// label)).
pub fn sanitize_label_budget(metric: &str, label_name: &str, value: &str) -> String {
    if value.is_empty() {
        // Empty == "unset" sentinel. We deliberately let it through
        // without touching the limiter so an empty string never
        // counts against the budget. Otherwise every legacy call
        // site would burn one slot just by passing AgentLabels::unset().
        return value.to_string();
    }
    let sanitised = global_limiter().sanitize_budget(label_name, value);
    if sanitised == crate::cardinality::OTHER_LABEL && value != crate::cardinality::OTHER_LABEL {
        // Real overflow: increment the counter and rate-limit the
        // warning so a steady stream of overflows does not flood
        // the log.
        record_label_overflow(metric, label_name);
    }
    sanitised
}

/// WOR-1067 PR2: tenant-scoped equivalent of [`sanitize_label_budget`].
/// Routes to the per-tenant accepted-value set so a noisy tenant cannot
/// demote labels for every other tenant. Tenant-scoped overflows
/// increment the separate
/// `sbproxy_label_cardinality_overflow_per_tenant_total{metric, label, tenant_id}`
/// counter so PromQL queries against the existing 2-label counter stay
/// unchanged.
///
/// The synthetic `__default__` tenant falls through to the proxy-wide
/// path (and the existing 2-label counter) so single-tenant deployments
/// stay bit-for-bit identical to pre-WOR-1067 behaviour.
pub fn sanitize_label_budget_tenant(
    metric: &str,
    label_name: &str,
    value: &str,
    tenant_id: &str,
) -> String {
    if value.is_empty() {
        return value.to_string();
    }
    if tenant_id.is_empty() || tenant_id == "__default__" {
        return sanitize_label_budget(metric, label_name, value);
    }
    let sanitised = global_limiter().sanitize_tenant(tenant_id, label_name, value);
    if sanitised == crate::cardinality::OTHER_LABEL && value != crate::cardinality::OTHER_LABEL {
        record_label_overflow_per_tenant(metric, label_name, tenant_id);
    }
    sanitised
}

// --- Cardinality overflow counter and rate-limiter ---

/// Counter `sbproxy_label_cardinality_overflow_total{metric, label}`.
/// Created lazily on the first overflow so the metric only appears
/// when there is something to report.
static OVERFLOW_COUNTER: OnceLock<prometheus::IntCounterVec> = OnceLock::new();

/// Tracks the last warning instant per (metric, label) tuple so the
/// per-minute rate limit on `tracing::warn!` is enforced without
/// rebuilding a tracing layer.
static OVERFLOW_LAST_WARN: OnceLock<Mutex<HashMap<(String, String), Instant>>> = OnceLock::new();

/// Minimum spacing between overflow warnings for the same (metric,
/// label) tuple.
const OVERFLOW_WARN_INTERVAL_SECS: u64 = 60;

fn overflow_counter() -> &'static prometheus::IntCounterVec {
    OVERFLOW_COUNTER.get_or_init(|| {
        let counter = prometheus::IntCounterVec::new(
            Opts::new(
                "sbproxy_label_cardinality_overflow_total",
                "Number of label values demoted to __other__ because the per-label budget was exhausted",
            ),
            &["metric", "label"],
        )
        .expect("overflow counter constructs");
        // Best-effort registration on the global ProxyMetrics
        // registry. If this fires in a unit test that already
        // registered the same counter (e.g. across `ProxyMetrics::new()`
        // calls) we ignore the AlreadyReg error and use the local
        // copy; the metric still increments and is visible via
        // `prometheus::gather()`.
        let _ = metrics().registry.register(Box::new(counter.clone()));
        counter
    })
}

/// Increment the overflow counter and, when more than a minute has
/// passed since the last warning for this (metric, label), emit a
/// single tracing warning.
fn record_label_overflow(metric: &str, label: &str) {
    overflow_counter().with_label_values(&[metric, label]).inc();

    let map = OVERFLOW_LAST_WARN.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().expect("overflow warn map poisoned");
    let key = (metric.to_string(), label.to_string());
    let now = Instant::now();
    let should_warn = match guard.get(&key) {
        Some(prev) => now.duration_since(*prev).as_secs() >= OVERFLOW_WARN_INTERVAL_SECS,
        None => true,
    };
    if should_warn {
        guard.insert(key, now);
        drop(guard);
        tracing::warn!(
            metric = metric,
            label = label,
            "metric label budget exceeded; demoting new values to __other__ (rate-limited 1/min)"
        );
    }
}

/// WOR-1067 PR2: per-tenant overflow counter.
/// `sbproxy_label_cardinality_overflow_per_tenant_total{metric, label, tenant_id}`.
/// Kept separate from the proxy-wide [`overflow_counter`] so existing
/// PromQL queries against the 2-label counter are unchanged when an
/// operator opts in to per-tenant budgets.
static OVERFLOW_COUNTER_PER_TENANT: OnceLock<prometheus::IntCounterVec> = OnceLock::new();

fn overflow_counter_per_tenant() -> &'static prometheus::IntCounterVec {
    OVERFLOW_COUNTER_PER_TENANT.get_or_init(|| {
        let counter = prometheus::IntCounterVec::new(
            Opts::new(
                "sbproxy_label_cardinality_overflow_per_tenant_total",
                "Per-tenant overflow demotions (`sbproxy_label_cardinality_overflow_total` with the tenant_id label)",
            ),
            &["metric", "label", "tenant_id"],
        )
        .expect("per-tenant overflow counter constructs");
        let _ = metrics().registry.register(Box::new(counter.clone()));
        counter
    })
}

/// Increment the per-tenant overflow counter. Rate-limited tracing
/// shares the same map as the proxy-wide counter so a single noisy
/// `(metric, label)` pair does not spam regardless of which tenant
/// scope it appears under; the warning includes the tenant id so an
/// operator can identify the source.
fn record_label_overflow_per_tenant(metric: &str, label: &str, tenant_id: &str) {
    overflow_counter_per_tenant()
        .with_label_values(&[metric, label, tenant_id])
        .inc();

    let map = OVERFLOW_LAST_WARN.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().expect("overflow warn map poisoned");
    let key = (format!("{metric}@{tenant_id}"), label.to_string());
    let now = Instant::now();
    let should_warn = match guard.get(&key) {
        Some(prev) => now.duration_since(*prev).as_secs() >= OVERFLOW_WARN_INTERVAL_SECS,
        None => true,
    };
    if should_warn {
        guard.insert(key, now);
        drop(guard);
        tracing::warn!(
            metric = metric,
            label = label,
            tenant_id = tenant_id,
            "per-tenant metric label budget exceeded; demoting new values to __other__ (rate-limited 1/min)"
        );
    }
}

/// Return a reference to the global [`ProxyMetrics`] registry, initialising it on first use.
pub fn metrics() -> &'static ProxyMetrics {
    METRICS.get_or_init(ProxyMetrics::new)
}

/// All proxy metrics collected in one place.
pub struct ProxyMetrics {
    /// Underlying Prometheus registry that owns all collectors.
    pub registry: Registry,

    // --- Legacy / basic metrics (retained for backwards compat) ---
    /// Counter `sbproxy_requests_total` with hostname, method, and status labels.
    pub requests_total: IntCounterVec,
    /// Histogram `sbproxy_request_duration_seconds` of request latency labelled by hostname.
    pub request_duration: HistogramVec,
    /// Counter `sbproxy_errors_total` of total errors labelled by hostname and error_type.
    pub errors_total: IntCounterVec,
    /// Gauge `sbproxy_active_connections` of currently active connections.
    pub active_connections: IntGauge,
    /// Counter `sbproxy_ai_cost_usd_micros_total` of AI request cost in
    /// micro-USD, labelled by provider, model, and tenant.
    pub ai_cost_usd_micros_total: IntCounterVec,

    // --- Local inference + semantic cache (WOR-1225) ---
    /// Counter `sbproxy_semantic_cache_results_total` of semantic-cache
    /// outcomes labelled by tenant, origin, embedding source, and result.
    pub semantic_cache_results: IntCounterVec,
    /// Counter `sbproxy_inference_requests_total` of local inference calls
    /// labelled by kind (embed|classify), backend (sidecar|inprocess),
    /// model, and result (ok|error).
    pub inference_requests: IntCounterVec,
    /// Histogram `sbproxy_inference_duration_seconds` of local inference
    /// latency labelled by kind, backend, and model.
    pub inference_duration: HistogramVec,
    /// Counter `sbproxy_ai_tokens_saved_total` of tokens a semantic-cache
    /// hit avoided, labelled by tenant, origin, model, and kind
    /// (prompt|completion).
    pub ai_tokens_saved: IntCounterVec,
    /// Counter `sbproxy_ai_cost_saved_micros_total` of micro-USD a
    /// semantic-cache hit avoided, labelled by tenant, origin, and model.
    pub ai_cost_saved_micros: IntCounterVec,

    // --- Agent detection (WOR-592) ---
    /// Counter `sbproxy_agent_detect_total` of agent-detect scorer
    /// verdicts labelled by agent id and provenance.
    pub agent_detect_total: IntCounterVec,
    /// Histogram `sbproxy_agent_detect_score` of produced 0-100 scores.
    pub agent_detect_score: Histogram,
    /// Histogram `sbproxy_agent_detect_inference_seconds` of scorer
    /// latency in seconds.
    pub agent_detect_inference_seconds: Histogram,

    // --- Per-origin metrics (Sprint 1A) ---
    /// Total HTTP requests with origin, method, and status labels.
    pub per_origin_requests_total: CounterVec,
    /// Request latency histogram with origin, method, and status labels.
    pub per_origin_request_duration: HistogramVec,
    /// In-flight requests gauge with origin label.
    pub per_origin_active_connections: GaugeVec,
    /// Bytes transferred with origin and direction (in/out) labels.
    pub bytes_total: CounterVec,
    /// Auth check results with origin, auth_type, and result labels.
    pub auth_results: CounterVec,
    /// Policy enforcement results with origin, policy_type, and action labels.
    pub policy_triggers: CounterVec,
    /// Cache hit/miss with origin and result labels.
    pub cache_results: CounterVec,
    /// Circuit breaker state transitions with origin, from_state, and to_state labels.
    pub circuit_breaker_transitions: CounterVec,

    // --- Cache Reserve metrics ---
    /// Counter `sbproxy_cache_reserve_hits_total` of reserve hits served
    /// after a hot-cache miss, labelled by origin.
    pub cache_reserve_hits: IntCounterVec,
    /// Counter `sbproxy_cache_reserve_misses_total` of reserve misses
    /// (hot cache and reserve both empty), labelled by origin.
    pub cache_reserve_misses: IntCounterVec,
    /// Counter `sbproxy_cache_reserve_writes_total` of entries written
    /// into the reserve, labelled by origin.
    pub cache_reserve_writes: IntCounterVec,
    /// Counter `sbproxy_cache_reserve_evictions_total` of explicit
    /// reserve deletions (invalidate-on-mutation, expired sweeps),
    /// labelled by origin.
    pub cache_reserve_evictions: IntCounterVec,

    // --- Synthetic probe metrics ---
    /// Counter `sbproxy_synthetic_probe_failures_total` of synthetic
    /// readiness probe failures, labelled by failure `reason`. Distinct
    /// from `sbproxy_errors_total` so dashboards can keep synthetic
    /// noise out of real-traffic SLO numerators.
    pub synthetic_probe_failures: IntCounterVec,

    // --- Reliability metrics ---
    /// Counter `sbproxy_mirror_state_drift_total` incremented when the
    /// request pipeline observes a `mirror_pending` slot that was
    /// expected to be `Some(...)` but turns out to be `None`. The fix
    /// for WOR-168 changed the unwrap into a graceful no-op; this
    /// counter surfaces how often the previously-panicking path is
    /// taken so the drift can be diagnosed in production.
    pub mirror_state_drift: prometheus::IntCounter,

    // --- Agent Skills ---
    /// Counter `sbproxy_agent_skill_digest_mismatch_total` of artifact
    /// `GET`s where the served body re-hash did not match the manifest
    /// digest. Labelled by `skill` so operators can dedupe alerts and
    /// pinpoint which entry diverged. The data-plane handler returns
    /// HTTP 503 to the client and emits a structured audit event on
    /// every increment.
    pub agent_skill_digest_mismatch: IntCounterVec,
    /// Histogram `sbproxy_phase_duration_seconds` of intra-request
    /// phase durations. Labelled by `phase` (currently `auth`,
    /// `upstream_ttfb`, `response_filter`) and `origin`. Lets
    /// dashboards split where end-to-end latency comes from
    /// (slow auth provider vs slow upstream vs heavy transform).
    /// Same observation appears as fields on the access-log entry
    /// (`auth_ms`, `upstream_ttfb_ms`, `response_filter_ms`); the
    /// histogram is the aggregate view.
    pub phase_duration: HistogramVec,

    // --- Content transform metrics ---
    /// Counter `sbproxy_boilerplate_stripped_bytes_total{hostname}` of
    /// bytes removed by the `boilerplate` transform. Summed across
    /// requests this matches the per-request `stripped_bytes` access-log
    /// field; dashboards use it to size how much chrome the strip pass
    /// removes per origin.
    pub boilerplate_stripped_bytes: IntCounterVec,
}

impl ProxyMetrics {
    fn new() -> Self {
        let registry = Registry::new();

        // --- Legacy metrics ---

        let requests_total = IntCounterVec::new(
            Opts::new("sbproxy_requests_total", "Total HTTP requests"),
            // Wave 1 / G1.6: per-agent labels added per ADR A1.1.
            // Order matters: the metric handle indexes labels positionally,
            // so any change here is a wire break for dashboards. Append
            // new labels at the end; never reorder.
            &[
                "hostname",
                "method",
                "status",
                "agent_id",
                "agent_class",
                "agent_vendor",
                "payment_rail",
                "content_shape",
            ],
        )
        .unwrap();

        let request_duration = HistogramVec::new(
            prometheus::HistogramOpts::new("sbproxy_request_duration_seconds", "Request latency")
                .buckets(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ]),
            &["hostname"],
        )
        .unwrap();

        let errors_total = IntCounterVec::new(
            Opts::new("sbproxy_errors_total", "Total errors"),
            &["hostname", "error_type"],
        )
        .unwrap();

        let active_connections =
            IntGauge::new("sbproxy_active_connections", "Current active connections").unwrap();

        let ai_cost_usd_micros_total = IntCounterVec::new(
            Opts::new(
                "sbproxy_ai_cost_usd_micros_total",
                "Derived AI request cost in micro-USD",
            ),
            &["provider", "model", "tenant_id"],
        )
        .unwrap();

        // --- Local inference + semantic cache (WOR-1225) ---

        let semantic_cache_results = IntCounterVec::new(
            Opts::new(
                "sbproxy_semantic_cache_results_total",
                "Semantic-cache hit/miss/error counts",
            ),
            // tenant: multi-tenant attribution; source: provider|sidecar|inprocess; result: hit|miss|error
            &["tenant", "origin", "source", "result"],
        )
        .unwrap();

        let inference_requests = IntCounterVec::new(
            Opts::new(
                "sbproxy_inference_requests_total",
                "Local inference call counts",
            ),
            &["kind", "backend", "model", "result"], // kind: embed|classify; result: ok|error
        )
        .unwrap();

        let inference_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "sbproxy_inference_duration_seconds",
                "Local inference latency in seconds",
            )
            .buckets(vec![
                0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
            ]),
            &["kind", "backend", "model"],
        )
        .unwrap();

        let ai_tokens_saved = IntCounterVec::new(
            Opts::new(
                "sbproxy_ai_tokens_saved_total",
                "Tokens avoided by a semantic-cache hit",
            ),
            &["tenant", "origin", "model", "kind"], // kind: prompt|completion
        )
        .unwrap();

        let ai_cost_saved_micros = IntCounterVec::new(
            Opts::new(
                "sbproxy_ai_cost_saved_micros_total",
                "Micro-USD avoided by a semantic-cache hit",
            ),
            &["tenant", "origin", "model"],
        )
        .unwrap();

        // --- Agent detection (WOR-592) ---

        let agent_detect_total = IntCounterVec::new(
            Opts::new(
                "sbproxy_agent_detect_total",
                "Agent-detect scorer verdicts by agent id and provenance",
            ),
            &["agent_id", "provenance"],
        )
        .unwrap();

        let agent_detect_score = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "sbproxy_agent_detect_score",
                "Agent-detect scorer output score, scaled 0-100",
            )
            .buckets(vec![
                0.0, 5.0, 10.0, 20.0, 40.0, 60.0, 80.0, 90.0, 95.0, 100.0,
            ]),
        )
        .unwrap();

        let agent_detect_inference_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "sbproxy_agent_detect_inference_seconds",
                "Agent-detect scorer inference latency in seconds",
            )
            .buckets(vec![
                0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.002, 0.005, 0.01,
            ]),
        )
        .unwrap();

        // --- Per-origin metrics (Sprint 1A) ---

        let per_origin_requests_total = CounterVec::new(
            Opts::new(
                "sbproxy_origin_requests_total",
                "Total HTTP requests per origin",
            ),
            &["origin", "method", "status"],
        )
        .unwrap();

        let per_origin_request_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "sbproxy_origin_request_duration_seconds",
                "Request latency per origin",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["origin", "method", "status"],
        )
        .unwrap();

        let per_origin_active_connections = GaugeVec::new(
            Opts::new(
                "sbproxy_origin_active_connections",
                "In-flight requests per origin",
            ),
            &["origin"],
        )
        .unwrap();

        let bytes_total = CounterVec::new(
            Opts::new("sbproxy_bytes_total", "Bytes transferred"),
            &["origin", "direction"],
        )
        .unwrap();

        let auth_results = CounterVec::new(
            Opts::new("sbproxy_auth_results_total", "Auth check results"),
            &["origin", "auth_type", "result"],
        )
        .unwrap();

        let policy_triggers = CounterVec::new(
            Opts::new(
                "sbproxy_policy_triggers_total",
                "Policy enforcement results",
            ),
            // Wave 1 / G1.6: agent_id and agent_class added per ADR
            // A1.1. The other Wave 1 labels (vendor, rail, shape) are
            // intentionally not on this metric: the budget table caps
            // policy_triggers at 5 labels because cardinality on the
            // deny path is dominated by hostname and policy_type.
            &["origin", "policy_type", "action", "agent_id", "agent_class"],
        )
        .unwrap();

        let cache_results = CounterVec::new(
            Opts::new("sbproxy_cache_results_total", "Cache hit/miss"),
            &["origin", "result"],
        )
        .unwrap();

        let circuit_breaker_transitions = CounterVec::new(
            Opts::new(
                "sbproxy_circuit_breaker_transitions_total",
                "Circuit breaker state transitions",
            ),
            &["origin", "from_state", "to_state"],
        )
        .unwrap();

        // --- Cache Reserve counters (W5-A) ---

        let cache_reserve_hits = IntCounterVec::new(
            Opts::new(
                "sbproxy_cache_reserve_hits_total",
                "Cache Reserve hits served after a hot-cache miss",
            ),
            &["origin"],
        )
        .unwrap();

        let cache_reserve_misses = IntCounterVec::new(
            Opts::new(
                "sbproxy_cache_reserve_misses_total",
                "Cache Reserve misses (hot + reserve both empty)",
            ),
            &["origin"],
        )
        .unwrap();

        let cache_reserve_writes = IntCounterVec::new(
            Opts::new(
                "sbproxy_cache_reserve_writes_total",
                "Cache Reserve writes (admitted entries)",
            ),
            &["origin"],
        )
        .unwrap();

        let cache_reserve_evictions = IntCounterVec::new(
            Opts::new(
                "sbproxy_cache_reserve_evictions_total",
                "Cache Reserve explicit deletions",
            ),
            &["origin"],
        )
        .unwrap();

        // --- Synthetic probe counters ---

        let synthetic_probe_failures = IntCounterVec::new(
            Opts::new(
                "sbproxy_synthetic_probe_failures_total",
                "Synthetic readiness probe failures by reason",
            ),
            &["reason"],
        )
        .unwrap();

        // --- Reliability counters ---

        let mirror_state_drift = prometheus::IntCounter::new(
            "sbproxy_mirror_state_drift_total",
            "Times the mirror_pending slot was unexpectedly empty when the pipeline tried to fire a shadow request",
        )
        .unwrap();

        // --- Content transform counters ---

        let boilerplate_stripped_bytes = IntCounterVec::new(
            Opts::new(
                "sbproxy_boilerplate_stripped_bytes_total",
                "Bytes removed by the boilerplate transform, by hostname",
            ),
            &["hostname"],
        )
        .unwrap();

        // --- Agent Skills counters ---

        let agent_skill_digest_mismatch = IntCounterVec::new(
            Opts::new(
                "sbproxy_agent_skill_digest_mismatch_total",
                "Agent Skills artifact digest mismatches detected at serve time",
            ),
            &["skill"],
        )
        .unwrap();

        // Phase-duration histogram. Buckets match `request_duration`
        // so cross-cut dashboards (phase vs end-to-end) align by le
        // label without bucket interpolation. `phase` label values
        // today: `auth`, `upstream_ttfb`, `response_filter`. New
        // phases append to the closed enum; never reorder.
        let phase_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "sbproxy_phase_duration_seconds",
                "Intra-request phase duration, partitioned by phase + origin",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["phase", "origin"],
        )
        .unwrap();

        // --- Register all metrics ---

        registry.register(Box::new(requests_total.clone())).unwrap();
        registry
            .register(Box::new(request_duration.clone()))
            .unwrap();
        registry.register(Box::new(errors_total.clone())).unwrap();
        registry
            .register(Box::new(active_connections.clone()))
            .unwrap();
        registry
            .register(Box::new(ai_cost_usd_micros_total.clone()))
            .unwrap();
        registry
            .register(Box::new(semantic_cache_results.clone()))
            .unwrap();
        registry
            .register(Box::new(inference_requests.clone()))
            .unwrap();
        registry
            .register(Box::new(inference_duration.clone()))
            .unwrap();
        registry
            .register(Box::new(ai_tokens_saved.clone()))
            .unwrap();
        registry
            .register(Box::new(ai_cost_saved_micros.clone()))
            .unwrap();
        registry
            .register(Box::new(agent_detect_total.clone()))
            .unwrap();
        registry
            .register(Box::new(agent_detect_score.clone()))
            .unwrap();
        registry
            .register(Box::new(agent_detect_inference_seconds.clone()))
            .unwrap();
        registry
            .register(Box::new(per_origin_requests_total.clone()))
            .unwrap();
        registry
            .register(Box::new(per_origin_request_duration.clone()))
            .unwrap();
        registry
            .register(Box::new(per_origin_active_connections.clone()))
            .unwrap();
        registry.register(Box::new(bytes_total.clone())).unwrap();
        registry.register(Box::new(auth_results.clone())).unwrap();
        registry
            .register(Box::new(policy_triggers.clone()))
            .unwrap();
        registry.register(Box::new(cache_results.clone())).unwrap();
        registry
            .register(Box::new(circuit_breaker_transitions.clone()))
            .unwrap();
        registry
            .register(Box::new(cache_reserve_hits.clone()))
            .unwrap();
        registry
            .register(Box::new(cache_reserve_misses.clone()))
            .unwrap();
        registry
            .register(Box::new(cache_reserve_writes.clone()))
            .unwrap();
        registry
            .register(Box::new(cache_reserve_evictions.clone()))
            .unwrap();
        registry
            .register(Box::new(synthetic_probe_failures.clone()))
            .unwrap();
        registry
            .register(Box::new(mirror_state_drift.clone()))
            .unwrap();
        registry
            .register(Box::new(agent_skill_digest_mismatch.clone()))
            .unwrap();
        registry.register(Box::new(phase_duration.clone())).unwrap();
        registry
            .register(Box::new(boilerplate_stripped_bytes.clone()))
            .unwrap();

        Self {
            registry,
            requests_total,
            request_duration,
            errors_total,
            active_connections,
            ai_cost_usd_micros_total,
            semantic_cache_results,
            inference_requests,
            inference_duration,
            ai_tokens_saved,
            ai_cost_saved_micros,
            agent_detect_total,
            agent_detect_score,
            agent_detect_inference_seconds,
            per_origin_requests_total,
            per_origin_request_duration,
            per_origin_active_connections,
            bytes_total,
            auth_results,
            policy_triggers,
            cache_results,
            circuit_breaker_transitions,
            cache_reserve_hits,
            cache_reserve_misses,
            cache_reserve_writes,
            cache_reserve_evictions,
            synthetic_probe_failures,
            mirror_state_drift,
            agent_skill_digest_mismatch,
            phase_duration,
            boilerplate_stripped_bytes,
        }
    }

    /// Render all metrics in Prometheus text format.
    ///
    /// On the rare errors this call can produce (encoder failure, non-UTF-8
    /// metric label from some exotic collector) we return an empty string
    /// rather than panic. Metrics are an operational surface, not a
    /// correctness surface; a missed scrape is always preferable to
    /// crashing the proxy.
    ///
    /// Output includes both this struct's `self.registry` (the canonical
    /// `sbproxy_*` series) AND the global `prometheus::default_registry()`
    /// (where downstream crates register their families via the
    /// `register_*_vec!` macros). Without the second `gather()` those
    /// series exist in-process but never reach a `/metrics` scrape.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let mut metric_families = self.registry.gather();
        metric_families.extend(prometheus::gather());
        let mut buffer = Vec::new();
        if let Err(error) = encoder.encode(&metric_families, &mut buffer) {
            // Returning an empty body here used to be silent, which made an
            // encode failure indistinguishable from a healthy process that
            // happens to emit nothing. The scrape succeeded, the dashboards
            // went flat, and no signal anywhere said why. Say why.
            tracing::error!(
                %error,
                families = metric_families.len(),
                "failed to encode the Prometheus scrape; /metrics is serving an empty body"
            );
            record_render_failure("encode");
            return String::new();
        }
        let raw = String::from_utf8(buffer).unwrap_or_default();
        // Splice exemplars onto histogram bucket lines per A1.4. The
        // splicer pass-throughs lines without recorded exemplars, so
        // a `text/plain` scraper sees identical bytes; an
        // `application/openmetrics-text` scraper picks up the
        // `# {trace_id="..."} ...` suffix.
        crate::exemplars::splice_into_text(&raw)
    }

    /// Sum the current values of the named metric families across all
    /// their label sets, for cluster-metric publication (WOR-1721). Each
    /// requested name maps to the total of its counter / gauge samples
    /// (histograms contribute their sample sum); a name not present in
    /// either registry maps to `0.0`. The mesh producer ships this compact
    /// per-node snapshot so one node can report fleet totals without an
    /// external Prometheus.
    ///
    /// Gathers **both** registries, mirroring [`Self::render`]. Gathering only
    /// `self.registry` is what made fleet AI tokens read zero on every node
    /// forever: `sbproxy_ai_tokens_attributed_total` is registered by a
    /// `register_counter_vec!` macro, so it lives on the process-global
    /// default registry and this method could not see it. The pre-seeded
    /// `0.0` below then supplied a plausible answer instead of an error, and
    /// the guard test asserted only that the key was present, which the
    /// pre-seed guarantees. Three layers, each individually reasonable,
    /// producing a number that was always wrong.
    pub fn snapshot_named(&self, names: &[&str]) -> std::collections::HashMap<String, f64> {
        let mut out: std::collections::HashMap<String, f64> =
            names.iter().map(|n| ((*n).to_string(), 0.0)).collect();

        let mut families = self.registry.gather();
        families.extend(prometheus::gather());

        for fam in families {
            let fname = fam.name();
            if !names.contains(&fname) {
                continue;
            }
            let mut total = 0.0;
            for m in &fam.metric {
                if let Some(c) = m.counter.as_ref() {
                    total += c.value();
                } else if let Some(g) = m.gauge.as_ref() {
                    total += g.value();
                } else if let Some(h) = m.histogram.as_ref() {
                    total += h.sample_sum();
                }
            }
            // A family cannot appear on both registries (the metric registry
            // declares exactly one per metric, and `metric_drift.rs` enforces
            // it), so accumulate rather than overwrite and a future double
            // registration shows up as a doubled value rather than a silent
            // half.
            *out.entry(fname.to_string()).or_insert(0.0) += total;
        }
        out
    }
}

/// Count a failure to serve `/metrics`.
///
/// Self-observability: if the scrape endpoint breaks, the only thing that can
/// report it is the scrape endpoint, so this counter is the one series that
/// has to survive its own failure mode. It lives on the proxy registry alone.
fn record_render_failure(reason: &'static str) {
    use prometheus::IntCounterVec;
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        let counter = IntCounterVec::new(
            Opts::new(
                "sbproxy_metrics_render_failures_total",
                "Failures to encode the Prometheus scrape body",
            ),
            &["reason"],
        )
        .expect("render failure counter constructs");
        let _ = metrics().registry.register(Box::new(counter.clone()));
        counter
    });
    counter.with_label_values(&[reason]).inc();
}

// --- Trace-id helper for exemplars ---

/// Return `(trace_id, span_id)` of the currently active OTel context,
/// or empty strings when no context is active. Used by metric
/// recording helpers to stamp exemplars without each call site
/// pulling in OTel directly.
pub fn current_trace_ids() -> (String, String) {
    use opentelemetry::trace::TraceContextExt;

    // Prefer the per-`tracing::Span` context when the
    // `tracing-opentelemetry` layer is wired; fall back to the
    // task-local context populated by `extract_from_headers`.
    let cx_span = tracing_opentelemetry::OpenTelemetrySpanExt::context(&tracing::Span::current());
    let cx = if cx_span.has_active_span() {
        cx_span
    } else {
        opentelemetry::Context::current()
    };
    let span = cx.span();
    let sc = span.span_context();
    if sc.is_valid() {
        (sc.trace_id().to_string(), sc.span_id().to_string())
    } else {
        (String::new(), String::new())
    }
}

// --- Per-origin helper functions ---

/// Record a completed request with all per-origin metrics.
///
/// Updates the requests counter, latency histogram, and bytes transferred
/// counters for the given origin. The `origin` label is sanitized through
/// the global cardinality limiter.
///
/// Legacy entry point: stamps the per-agent labels with the empty-string
/// sentinel. Call sites with a resolved [`AgentLabels`] should prefer
/// [`record_request_with_labels`] so the per-agent dimensions land on
/// `sbproxy_requests_total`.
pub fn record_request(
    origin: &str,
    method: &str,
    status: u16,
    duration_secs: f64,
    bytes_in: u64,
    bytes_out: u64,
) {
    record_request_with_labels(
        origin,
        method,
        status,
        duration_secs,
        bytes_in,
        bytes_out,
        AgentLabels::unset(),
    );
}

/// Record a completed request and stamp the per-agent labels onto
/// `sbproxy_requests_total`.
///
/// All labels run through [`sanitize_label_budget`] so the per-label
/// cardinality budget is enforced before the value reaches Prometheus.
/// Overflow values are demoted to
/// `__other__` and emit a `sbproxy_label_cardinality_overflow_total`
/// counter (rate-limited to once per minute per (metric, label)).
pub fn record_request_with_labels(
    origin: &str,
    method: &str,
    status: u16,
    duration_secs: f64,
    bytes_in: u64,
    bytes_out: u64,
    agent: AgentLabels<'_>,
) {
    let hostname_san = sanitize_label_budget("sbproxy_requests_total", "hostname", origin);
    let origin_san = sanitize_label_budget("sbproxy_origin_requests_total", "origin", origin);
    let status_str = status.to_string();

    // --- Wave 1 / G1.6: per-agent labels on sbproxy_requests_total ---
    //
    // Hot-path: five additional sanitisations. Each is a single
    // HashSet contains() on the cardinality limiter when the value
    // is already accepted, so the steady-state cost is one mutex
    // acquire per label. A future optimisation can batch the
    // sanitisations under one lock if profiling flags it.
    let agent_id = sanitize_label_budget("sbproxy_requests_total", "agent_id", agent.agent_id);
    let agent_class =
        sanitize_label_budget("sbproxy_requests_total", "agent_class", agent.agent_class);
    let agent_vendor =
        sanitize_label_budget("sbproxy_requests_total", "agent_vendor", agent.agent_vendor);
    let payment_rail =
        sanitize_label_budget("sbproxy_requests_total", "payment_rail", agent.payment_rail);
    let content_shape = sanitize_label_budget(
        "sbproxy_requests_total",
        "content_shape",
        agent.content_shape,
    );

    let m = metrics();
    // sbproxy_requests_total now carries the full Wave 1 label set.
    // Sanitise with the metric's public label name (`hostname`) so
    // `metrics.cardinality.hostname_cap` can lower this budget without
    // affecting the per-origin views below.
    m.requests_total
        .with_label_values(&[
            hostname_san.as_str(),
            method,
            status_str.as_str(),
            agent_id.as_str(),
            agent_class.as_str(),
            agent_vendor.as_str(),
            payment_rail.as_str(),
            content_shape.as_str(),
        ])
        .inc();

    // --- Per-origin views (unchanged label set; pre-existing) ---
    m.per_origin_requests_total
        .with_label_values(&[origin_san.as_str(), method, status_str.as_str()])
        .inc();
    m.per_origin_request_duration
        .with_label_values(&[origin_san.as_str(), method, status_str.as_str()])
        .observe(duration_secs);
    // Wave 1 exemplar: stamp the active trace_id onto the latency
    // histogram so Grafana's "click an outlier" path reaches the
    // right span. `current_trace_ids` returns empty strings when no
    // trace context is active and the splicer omits the labels in
    // that case, so this call is safe to issue unconditionally.
    let (trace_id, span_id) = current_trace_ids();
    crate::exemplars::record(
        "sbproxy_origin_request_duration_seconds",
        &[
            ("origin", origin),
            ("method", method),
            ("status", &status_str),
        ],
        duration_secs,
        crate::exemplars::STANDARD_LATENCY_BUCKETS,
        &trace_id,
        &span_id,
    );
    crate::exemplars::record(
        "sbproxy_request_duration_seconds",
        &[("hostname", origin)],
        duration_secs,
        crate::exemplars::STANDARD_LATENCY_BUCKETS,
        &trace_id,
        &span_id,
    );
    if bytes_in > 0 {
        m.bytes_total
            .with_label_values(&[origin_san.as_str(), "in"])
            .inc_by(bytes_in as f64);
    }
    if bytes_out > 0 {
        m.bytes_total
            .with_label_values(&[origin_san.as_str(), "out"])
            .inc_by(bytes_out as f64);
    }
}

/// Record an auth check result for an origin.
///
/// `allowed` maps to the label value `"allow"` or `"deny"`.
pub fn record_auth(origin: &str, auth_type: &str, allowed: bool) {
    let origin = sanitize_label("origin", origin);
    let result = if allowed { "allow" } else { "deny" };
    metrics()
        .auth_results
        .with_label_values(&[origin.as_str(), auth_type, result])
        .inc();
}

/// Observe one phase-duration sample on `sbproxy_phase_duration_seconds`.
/// `phase` is the closed-enum slice (`auth`, `upstream_ttfb`,
/// `response_filter`); `origin` is the matched origin hostname.
/// `duration_secs` is wall-clock seconds; pass derived deltas from
/// `Instant::saturating_duration_since` to avoid negative values on
/// clock skew. Helper is a no-op when `duration_secs <= 0.0`.
///
/// Observed on both the canonical Prometheus surface AND, when the
/// operator opted into `telemetry.export_metrics`, the parallel
/// OTel histogram. The two surfaces share the same `phase` /
/// `origin` label vocabulary so dashboards bridge cleanly.
pub fn record_phase_duration(phase: &str, origin: &str, duration_secs: f64) {
    if duration_secs <= 0.0 {
        return;
    }
    let origin = sanitize_label("origin", origin);
    metrics()
        .phase_duration
        .with_label_values(&[phase, origin.as_str()])
        .observe(duration_secs);
    crate::otel::phase_duration_histogram().record(
        duration_secs,
        &[
            opentelemetry::KeyValue::new("phase", phase.to_string()),
            opentelemetry::KeyValue::new("origin", origin),
        ],
    );
}

/// Record a semantic-cache outcome (WOR-1225), attributed per tenant.
/// `source` is provider|sidecar|inprocess; `result` is hit|miss|error.
pub fn record_semantic_cache(tenant: &str, origin: &str, source: &str, result: &str) {
    let tenant = sanitize_label("tenant", tenant);
    let origin = sanitize_label("origin", origin);
    metrics()
        .semantic_cache_results
        .with_label_values(&[tenant.as_str(), origin.as_str(), source, result])
        .inc();
}

/// Record a local inference call and its latency (WOR-1225). `kind` is
/// embed|classify; `backend` is sidecar|inprocess; `result` is ok|error.
pub fn record_inference(kind: &str, backend: &str, model: &str, result: &str, duration_secs: f64) {
    let model = sanitize_label("model", model);
    metrics()
        .inference_requests
        .with_label_values(&[kind, backend, model.as_str(), result])
        .inc();
    if duration_secs > 0.0 {
        metrics()
            .inference_duration
            .with_label_values(&[kind, backend, model.as_str()])
            .observe(duration_secs);
    }
}

/// Record one agent-detect scorer verdict (WOR-592).
///
/// `agent_id == None` is encoded as the empty-string sentinel, matching
/// the existing per-agent request metrics. `provenance` is a closed enum
/// label (`signed`, `unsigned-named`, `unsigned-anonymous`) and unknown
/// values are collapsed to `unknown`.
pub fn record_agent_detect(
    agent_id: Option<&str>,
    provenance: &str,
    score: u8,
    duration_secs: f64,
) {
    let agent_id = sanitize_label_budget(
        "sbproxy_agent_detect_total",
        "agent_id",
        agent_id.unwrap_or_default(),
    );
    let provenance = match provenance {
        "signed" | "unsigned-named" | "unsigned-anonymous" => provenance,
        _ => "unknown",
    };
    let m = metrics();
    m.agent_detect_total
        .with_label_values(&[agent_id.as_str(), provenance])
        .inc();
    m.agent_detect_score.observe(score as f64);
    if duration_secs > 0.0 {
        m.agent_detect_inference_seconds.observe(duration_secs);
    }
}

/// Attribute the tokens and cost a semantic-cache hit avoided (WOR-1225):
/// the upstream call that did not happen. This is the value-delivered side
/// of usage tracking, so saved cost uses the same cost table as spent cost.
pub fn record_cache_savings(
    tenant: &str,
    origin: &str,
    model: &str,
    prompt_tokens: u64,
    completion_tokens: u64,
    cost_micros: u64,
) {
    let tenant = sanitize_label("tenant", tenant);
    let origin = sanitize_label("origin", origin);
    let model = sanitize_label("model", model);
    if prompt_tokens > 0 {
        metrics()
            .ai_tokens_saved
            .with_label_values(&[tenant.as_str(), origin.as_str(), model.as_str(), "prompt"])
            .inc_by(prompt_tokens);
    }
    if completion_tokens > 0 {
        metrics()
            .ai_tokens_saved
            .with_label_values(&[
                tenant.as_str(),
                origin.as_str(),
                model.as_str(),
                "completion",
            ])
            .inc_by(completion_tokens);
    }
    if cost_micros > 0 {
        metrics()
            .ai_cost_saved_micros
            .with_label_values(&[tenant.as_str(), origin.as_str(), model.as_str()])
            .inc_by(cost_micros);
    }
}

/// Record a policy trigger (allow or deny) for an origin.
///
/// Legacy entry point: stamps the per-agent labels with the empty
/// sentinel. Use [`record_policy_with_labels`] when the resolved
/// agent identity is available so the deny path attributes the
/// trigger to its agent.
pub fn record_policy(origin: &str, policy_type: &str, action: &str) {
    record_policy_with_labels(origin, policy_type, action, AgentLabels::unset());
}

/// Record a policy trigger and stamp the per-agent labels onto
/// `sbproxy_policy_triggers_total`.
pub fn record_policy_with_labels(
    origin: &str,
    policy_type: &str,
    action: &str,
    agent: AgentLabels<'_>,
) {
    let origin_san = sanitize_label("origin", origin);
    let agent_id =
        sanitize_label_budget("sbproxy_policy_triggers_total", "agent_id", agent.agent_id);
    let agent_class = sanitize_label_budget(
        "sbproxy_policy_triggers_total",
        "agent_class",
        agent.agent_class,
    );
    metrics()
        .policy_triggers
        .with_label_values(&[
            origin_san.as_str(),
            policy_type,
            action,
            agent_id.as_str(),
            agent_class.as_str(),
        ])
        .inc();
}

/// Record a capture-budget drop. `dimension` is
/// `"session"` or `"user"`; the workspace label is sanitized through
/// the cardinality limiter so an attacker cannot blow up label space
/// by spraying tenant ids.
pub fn record_capture_budget_drop(workspace_id: &str, dimension: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_capture_budget_dropped_total",
            "Capture envelope dimensions dropped because the per-workspace budget was exhausted",
            &["workspace", "dimension"],
        )
        .expect("capture budget counter registers")
    });
    let workspace = sanitize_label("workspace", workspace_id);
    counter
        .with_label_values(&[workspace.as_str(), dimension])
        .inc();
}

/// Record a served-lane admission decision on
/// `sbproxy_serve_lane_admissions_total{priority, decision}` (WOR-1679).
///
/// `priority` is the request's lane (`interactive` / `standard` /
/// `batch`) and `decision` one of the closed set `admitted` (free
/// slot), `queued_admitted` (waited, then got a slot), `spilled`
/// (interactive overflowed to the next provider instead of queuing),
/// or `timed_out` (queue wait exhausted). Both label sets are closed,
/// so no sanitization is needed.
pub fn record_serve_lane_decision(priority: &'static str, decision: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_serve_lane_admissions_total",
            "Served-lane admission gate decisions by priority lane",
            &["priority", "decision"],
        )
        .expect("serve lane counter registers")
    });
    counter.with_label_values(&[priority, decision]).inc();
}

/// Record a bot-auth hosted-directory fetch failure on
/// `sbproxy_bot_auth_directory_fetch_failures_total{url}`.
///
/// The rustdoc on `bot_auth` has pointed operators at this counter
/// since the directory shipped, but nothing registered it, so a
/// broken key-directory endpoint was observable only in logs
/// (WOR-1828). The URL label is an operator-configured value (never
/// client-controlled), sanitized through the cardinality limiter
/// anyway for uniformity.
pub fn record_bot_auth_directory_fetch_failure(url: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_bot_auth_directory_fetch_failures_total",
            "Bot-auth hosted key-directory fetches that failed (the verifier serves stale or fails per nonce_policy)",
            &["url"],
        )
        .expect("bot-auth directory counter registers")
    });
    let url = sanitize_label("url", url);
    counter.with_label_values(&[url.as_str()]).inc();
}

/// Record a WAF persistent-block lifecycle event on
/// `sbproxy_waf_persistent_blocks_total{origin, event, key_kind}`.
///
/// `event` is one of the closed strings `escalated` (a client crossed
/// the strike threshold and was placed in a time-boxed block),
/// `blocked` (a request was rejected because the client is inside an
/// active block window), or `strike` (a WAF/challenge deny was counted
/// toward the threshold without yet escalating). `key_kind` is the
/// dimension the block is tracked by: `ip`, `api_key`, or `cel`.
///
/// The origin label is run through the cardinality limiter; `event`
/// and `key_kind` are closed sets and pass through unsanitised.
pub fn record_waf_persistent_block(
    origin: &str,
    tenant: &str,
    event: &'static str,
    key_kind: &'static str,
) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_waf_persistent_blocks_total",
            "WAF persistent (time-boxed) block actions, by lifecycle event and key kind",
            &["origin", "tenant", "event", "key_kind"],
        )
        .expect("waf persistent block counter registers")
    });
    // Both origin and tenant are operator-supplied and so pass through
    // the cardinality limiter; event and key_kind are closed sets.
    let origin_san = sanitize_label("origin", origin);
    let tenant_san = sanitize_label("tenant", tenant);
    counter
        .with_label_values(&[origin_san.as_str(), tenant_san.as_str(), event, key_kind])
        .inc();
}

/// Count an `object_authz` (BOLA/BFLA) authorization violation. `kind`
/// is one of the closed strings `bola`, `bfla`, or `enumeration`; the
/// origin label is run through the cardinality limiter.
pub fn record_object_authz_violation(origin: &str, kind: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_object_authz_violations_total",
            "Object/function-level authorization violations, by kind (bola, bfla, enumeration)",
            &["origin", "kind"],
        )
        .expect("object_authz violation counter registers")
    });
    let origin_san = sanitize_label("origin", origin);
    counter
        .with_label_values(&[origin_san.as_str(), kind])
        .inc();
}

/// Count a governed key admission that bypassed reservation because the
/// governance backend was unavailable and
/// `key_management.governance.failure_mode` is `allow_unreserved` (WOR-1835).
///
/// Exposed on `sbproxy_governance_fail_open_total{key_id}` so an operator
/// watching a degraded governance backend can see how many requests it let
/// through unreserved. Every increment here is paired with a
/// `security_audit` event on the same request (see
/// `sbproxy_core::server::ai_dispatch`), since a governed limit silently
/// stopped being enforced. `key_id` is the immutable, non-secret governed
/// key identifier and is run through the cardinality limiter.
pub fn record_governance_fail_open(key_id: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_governance_fail_open_total",
            "Governed key admissions that bypassed reservation because the governance backend was unavailable and failure_mode is allow_unreserved",
            &["key_id"],
        )
        .expect("governance fail-open counter registers")
    });
    let key_id_san = sanitize_label("key_id", key_id);
    counter.with_label_values(&[key_id_san.as_str()]).inc();
}

/// Record drop counters returned by the capture helpers.
/// `dimension` is `"property"`, `"session"`, or `"user"`; `reason`
/// is one of the closed strings each helper exposes (e.g. `count`,
/// `key_len`, `value_len`, `payload_size`, `regex` for properties;
/// `invalid_format`, `too_long`, `empty` for sessions;
/// `length`, `empty` for users). `workspace_id` is sanitised so the
/// cardinality limiter caps the label space. `n == 0` is a no-op.
pub fn record_capture_drop(
    workspace_id: &str,
    dimension: &'static str,
    reason: &'static str,
    n: u64,
) {
    if n == 0 {
        return;
    }
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_capture_dropped_total",
            "Capture envelope dimensions dropped during capture, by reason",
            &["workspace", "dimension", "reason"],
        )
        .expect("capture drop counter registers")
    });
    let workspace = sanitize_label("workspace", workspace_id);
    counter
        .with_label_values(&[workspace.as_str(), dimension, reason])
        .inc_by(n);
}

/// Record one A2A hop. `decision` is `"allow"` or
/// `"deny:<reason>"`; `spec` is one of the closed strings from
/// `A2ASpec::as_label`. Cardinality is bounded by route + spec +
/// decision and is safe for dashboards.
pub fn record_a2a_hop(route: &str, spec: &str, decision: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_a2a_hops_total",
            "A2A hops observed by the proxy, labelled by route, spec, and policy decision",
            &["route", "spec", "decision"],
        )
        .expect("a2a hops counter registers")
    });
    let route = sanitize_label("route", route);
    counter
        .with_label_values(&[route.as_str(), spec, decision])
        .inc();
}

/// Record an A2A chain depth observation. Surfaces
/// the depth distribution per route + spec so dashboards can spot
/// runaway recursion before the depth-cap policy denies.
pub fn record_a2a_chain_depth(route: &str, spec: &str, depth: u32) {
    use prometheus::{register_histogram_vec, HistogramVec};
    use std::sync::OnceLock;
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_a2a_chain_depth",
            "Distribution of A2A chain depth observed at the proxy",
            &["route", "spec"],
            vec![1.0, 2.0, 3.0, 5.0, 8.0, 13.0, 21.0, 32.0],
        )
        .expect("a2a chain depth histogram registers")
    });
    let route = sanitize_label("route", route);
    hist.with_label_values(&[route.as_str(), spec])
        .observe(depth as f64);
}

/// Record an A2A denial. `reason` is one of
/// `depth`, `cycle`, `callee_not_allowed`, `caller_denied` per the
/// ADR's Failure Modes section.
pub fn record_a2a_denied(route: &str, reason: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_a2a_denied_total",
            "A2A hops denied by the a2a policy, labelled by route and reason",
            &["route", "reason"],
        )
        .expect("a2a denied counter registers")
    });
    let route = sanitize_label("route", route);
    counter.with_label_values(&[route.as_str(), reason]).inc();
}

/// Record a bounded channel drop on a hot-path lane.
///
/// `lane` is a fixed identifier for the channel's purpose
/// (`"hooks"`, `"streaming"`, `"mirror"`, ...). `reason` is one of the
/// closed strings `"channel_full"` (the receiver was alive but the
/// buffer was at capacity) or `"receiver_closed"` (the consumer hung
/// up). Both label values are compile-time constants so this counter
/// has zero label cardinality risk.
///
/// Emitted as `sbproxy_<lane>_channel_dropped_total{reason}`; the
/// counter is created lazily on the first drop so the metric only
/// appears in the scrape output when there is something to report.
/// Subsequent drops on the same `lane` reuse the cached counter, so
/// the increment path is one `HashMap::get` and one atomic add.
///
/// The counter is registered on both `metrics().registry` (the
/// canonical `sbproxy_*` registry that the scrape endpoint serves)
/// and `prometheus::default_registry()` (where ad-hoc tests and
/// `prometheus::gather()` look). Either side may have already
/// registered an identical counter (e.g. test re-runs); the
/// `AlreadyReg` error is non-fatal, the metric still increments.
pub fn record_channel_drop(lane: &'static str, reason: &'static str) {
    use prometheus::IntCounterVec;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    // One counter per `lane`. The lane is part of the metric name so
    // we cannot share a single CounterVec across lanes; instead we
    // memoise a per-lane CounterVec keyed by the lane string.
    static REGISTRY: OnceLock<Mutex<HashMap<&'static str, IntCounterVec>>> = OnceLock::new();
    let map = REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().expect("channel-drop registry mutex poisoned");
    let counter = guard.entry(lane).or_insert_with(|| {
        let name = format!("sbproxy_{lane}_channel_dropped_total");
        let cv = IntCounterVec::new(
            Opts::new(
                name,
                "Bounded channel sends dropped on the hot path, labelled by drop reason",
            ),
            &["reason"],
        )
        .expect("channel drop counter constructs");
        // Register on the canonical scrape registry, and *only* there.
        //
        // This used to register on the process-global default registry as
        // well, so that an ad-hoc `prometheus::gather()` would also see the
        // counter. But `ProxyMetrics::render()` gathers both registries and
        // concatenates them, so the family came out twice: two `# HELP` and
        // two `# TYPE` lines for one name. The Prometheus text format forbids
        // that and the parser rejects the whole scrape.
        //
        // The trigger makes it worse than it sounds. This counter does not
        // exist until something drops a message on a full channel, which
        // happens when the proxy is saturated. So `/metrics` broke at exactly
        // the moment an operator needed it, and was fine every time anyone
        // checked.
        let _ = metrics().registry.register(Box::new(cv.clone()));
        cv
    });
    counter.with_label_values(&[reason]).inc();
}

/// Record one MCP pre-tool-call policy hook invocation (WOR-152 PR β).
///
/// `verdict` is one of the closed labels `allow`, `deny`, or `confirm`
/// (the OSS bridge treats `confirm` as a deny until the
/// `PendingConfirmStore` lands in PR ζ; the verdict label still reads
/// `confirm` so dashboards can distinguish the two). `mcp_server` is
/// the logical upstream MCP server name; `tool_name` is the tool the
/// caller requested. Both label values are sanitised through the
/// cardinality limiter so a hostile caller cannot blow up label space
/// by spraying tool names.
pub fn record_mcp_policy_hook_invocation(verdict: &str, mcp_server: &str, tool_name: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_policy_hook_invocations_total",
            "MCP pre-tool-call policy hook invocations by verdict, upstream MCP server, and tool",
            &["verdict", "mcp_server", "tool_name"],
        )
        .expect("mcp policy hook invocation counter registers")
    });
    let mcp_server = sanitize_label("mcp_server", mcp_server);
    let tool_name = sanitize_label("tool_name", tool_name);
    counter
        .with_label_values(&[verdict, mcp_server.as_str(), tool_name.as_str()])
        .inc();
}

/// Record a request blocked by the `http_framing` policy. The
/// `reason` label is one of the stable strings from
/// `FramingViolation::metric_reason` (`dual_cl_te`, `duplicate_cl`,
/// `malformed_te`, `duplicate_te`, `control_chars`). Cardinality is
/// bounded at five and locked by the policy.
pub fn record_http_framing_block(reason: &str, tenant: &str) {
    use prometheus::{register_counter_vec, CounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<CounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_counter_vec!(
            "sbproxy_http_framing_blocks_total",
            "Requests rejected by the http_framing policy (request smuggling defense)",
            &["reason", "tenant"],
        )
        .expect("counter vec registers")
    });
    // `reason` is a closed five-value set; `tenant` is operator-supplied
    // and so passes through the cardinality limiter.
    let tenant_san = sanitize_label("tenant", tenant);
    counter
        .with_label_values(&[reason, tenant_san.as_str()])
        .inc();
}

/// Count a request that was rejected before origin resolution because
/// no configured origin matched the inbound Host. `reason` is a closed
/// string (`unknown_host`). These requests never reach the access log
/// or the per-origin counters, so without this counter misrouted /
/// probing traffic is invisible (WOR-1097).
pub fn record_unrouted_request(reason: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_unrouted_requests_total",
            "Requests rejected before origin resolution, by reason",
            &["reason"],
        )
        .expect("unrouted requests counter registers")
    });
    counter.with_label_values(&[reason]).inc();
}

/// Count a failed install of the process-wide sink dispatcher. A
/// non-zero value means the telemetry pipeline did not swap in and the
/// proxy may be serving traffic with no log/event export (WOR-1099).
pub fn record_sink_install_failure() {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_sink_install_failures_total",
            "Failed installs of the process-wide telemetry sink dispatcher",
        )
        .expect("sink install failure counter registers")
    });
    counter.inc();
}

/// Count telemetry that was dropped or failed to set up, by sink kind
/// and reason. Makes otherwise-silent telemetry loss (a webhook task
/// that never spawned, a file sink whose directory could not be
/// created, an OTLP sink skipped at boot) observable (WOR-1100).
/// `kind` and `reason` are closed operator-facing strings.
pub fn record_telemetry_dropped(kind: &'static str, reason: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_telemetry_dropped_total",
            "Telemetry records dropped or sinks that failed to set up, by kind and reason",
            &["kind", "reason"],
        )
        .expect("telemetry dropped counter registers")
    });
    counter.with_label_values(&[kind, reason]).inc();
}

/// Count a config (hot) reload outcome on
/// `sbproxy_config_reload_total{result}`. `result` is a closed string
/// (`success` / `failure`). Operators alert on a non-zero `failure`
/// rate or on a stalled `success` cadence (WOR-1101).
pub fn record_config_reload(result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_config_reload_total",
            "Config reload attempts, by result",
            &["result"],
        )
        .expect("config reload counter registers")
    });
    counter.with_label_values(&[result]).inc();
}

/// Count a well-known projection render failure on
/// `sbproxy_projection_render_failures_total{projection}`. A non-zero
/// value means a robots.txt / llms.txt / similar projection could not
/// be rendered on reload and may be served stale or empty (WOR-1101).
pub fn record_projection_render_failure(projection: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_projection_render_failures_total",
            "Well-known projection render failures, by projection",
            &["projection"],
        )
        .expect("projection render failure counter registers")
    });
    let projection_san = sanitize_label("projection", projection);
    counter.with_label_values(&[projection_san.as_str()]).inc();
}

/// Count an AI provider attempt during failover/selection on
/// `sbproxy_ai_provider_attempts_total{provider, outcome}`. `outcome`
/// is a closed string (`success` / `error`). Gives operators the
/// per-provider load distribution and failure rate that a bare
/// "failover happened" signal cannot (WOR-1103).
pub fn record_provider_attempt(provider: &str, outcome: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_ai_provider_attempts_total",
            "AI provider attempts during failover/selection, by provider and outcome",
            &["provider", "outcome"],
        )
        .expect("provider attempts counter registers")
    });
    let provider_san = sanitize_label("provider", provider);
    counter
        .with_label_values(&[provider_san.as_str(), outcome])
        .inc();
}

/// Count one managed-replica attempt without exposing worker topology.
pub fn record_managed_replica_attempt(
    provider: &str,
    deployment: &str,
    route_class: &'static str,
    outcome: &str,
) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_managed_replica_attempts_total",
            "Managed model replica attempts by provider, deployment, route class, and bounded outcome",
            &["provider", "deployment", "route_class", "outcome"],
        )
        .expect("managed replica attempt counter registers")
    });
    let provider = sanitize_label("provider", provider);
    let deployment = sanitize_label("deployment", deployment);
    let outcome = sanitize_label("managed_replica_outcome", outcome);
    counter
        .with_label_values(&[
            provider.as_str(),
            deployment.as_str(),
            route_class,
            outcome.as_str(),
        ])
        .inc();
}

/// Count a safe managed-replica handover made before client output.
pub fn record_managed_replica_failover(provider: &str, deployment: &str, reason: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_managed_replica_failovers_total",
            "Safe pre-output managed replica handovers by provider, deployment, and bounded reason",
            &["provider", "deployment", "reason"],
        )
        .expect("managed replica failover counter registers")
    });
    let provider = sanitize_label("provider", provider);
    let deployment = sanitize_label("deployment", deployment);
    let reason = sanitize_label("managed_replica_failover_reason", reason);
    counter
        .with_label_values(&[provider.as_str(), deployment.as_str(), reason.as_str()])
        .inc();
}

/// Record private peer dispatch time to response headers.
pub fn record_model_plane_peer_dispatch(outcome: &'static str, duration_seconds: f64) {
    use prometheus::{register_histogram_vec, HistogramVec};
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let histogram = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_model_plane_peer_dispatch_seconds",
            "Private model-plane peer dispatch duration to response headers by outcome",
            &["outcome"],
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
        )
        .expect("model-plane peer dispatch histogram registers")
    });
    histogram
        .with_label_values(&[outcome])
        .observe(duration_seconds);
}

/// Count a private response body dropped before its terminal frame.
pub fn record_model_plane_stream_cancellation(route_class: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_model_plane_stream_cancellations_total",
            "Managed response streams dropped before completion by route class",
            &["route_class"],
        )
        .expect("model-plane cancellation counter registers")
    });
    counter.with_label_values(&[route_class]).inc();
}

/// Count authenticated model-plane refusals using stable internal codes only.
pub fn record_model_plane_rejection(code: &str, retry_class: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_model_plane_rejections_total",
            "Private model-plane request refusals by bounded code and retry class",
            &["code", "retry_class"],
        )
        .expect("model-plane rejection counter registers")
    });
    let code = sanitize_label("model_plane_rejection_code", code);
    counter
        .with_label_values(&[code.as_str(), retry_class])
        .inc();
}

/// Count a silently-degraded best-effort operation on
/// `sbproxy_silent_degradations_total{op}`. Surfaces error paths that
/// were previously dropped with `let _ = ...` (cache promotion, cache
/// cleanup, ...) so operators can see them accumulate (WOR-1104).
pub fn record_silent_degradation(op: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_silent_degradations_total",
            "Best-effort operations that failed and were previously dropped silently, by op",
            &["op"],
        )
        .expect("silent degradation counter registers")
    });
    counter.with_label_values(&[op]).inc();
}

/// Record a replayed nonce observed by the Web Bot Auth verifier
///. `policy` is one of the closed labels `strict` (the
/// verifier rejected the request) or `permissive` (the verifier
/// logged the replay and still returned Verified, the operator
/// opted in to monitoring without blocking).
///
/// Cardinality is bounded at two label values; both are compile-time
/// constants on the call path so there is no cardinality risk.
pub fn record_bot_auth_nonce_replay(policy: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_bot_auth_nonce_replay_total",
            "Web Bot Auth signatures rejected (or logged) because the nonce was already observed",
            &["policy"],
        )
        .expect("bot auth nonce replay counter registers")
    });
    counter.with_label_values(&[policy]).inc();
}

/// Count JWKS refreshes triggered synchronously by an unknown JWT `kid`.
///
/// `result` is intentionally closed by convention: `success`, `failure`,
/// or `rate_limited`.
pub fn record_jwks_unknown_kid_refetch(result: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_jwks_unknown_kid_refetch_total",
            "JWKS refreshes triggered by tokens whose kid was absent from the local cache",
            &["result"]
        )
        .expect("register sbproxy_jwks_unknown_kid_refetch_total")
    });
    counter.with_label_values(&[result]).inc();
}

/// Record a cache result (hit or miss) for an origin.
pub fn record_cache(origin: &str, result: &str) {
    let origin = sanitize_label("origin", origin);
    metrics()
        .cache_results
        .with_label_values(&[origin.as_str(), result])
        .inc();
}

/// Record a circuit breaker state transition for an origin.
pub fn record_circuit_breaker(origin: &str, from_state: &str, to_state: &str) {
    let origin = sanitize_label("origin", origin);
    metrics()
        .circuit_breaker_transitions
        .with_label_values(&[origin.as_str(), from_state, to_state])
        .inc();
}

/// Increment the active (in-flight) connections gauge for an origin.
pub fn inc_active(origin: &str) {
    let origin = sanitize_label("origin", origin);
    metrics()
        .per_origin_active_connections
        .with_label_values(&[&origin])
        .inc();
}

/// Decrement the active (in-flight) connections gauge for an origin.
pub fn dec_active(origin: &str) {
    let origin = sanitize_label("origin", origin);
    metrics()
        .per_origin_active_connections
        .with_label_values(&[&origin])
        .dec();
}

/// Increment `sbproxy_mirror_state_drift_total`.
///
/// Called when the request pipeline expects `mirror_pending` to be
/// `Some(...)` but finds `None`. Before WOR-168 this path was an
/// `unwrap()` that would have panicked the worker; now it is a
/// best-effort no-op with a counter so operators can spot drift.
pub fn record_mirror_state_drift() {
    metrics().mirror_state_drift.inc();
}

/// Add `bytes` to `sbproxy_boilerplate_stripped_bytes_total{hostname}`.
///
/// Called once per request that ran a `boilerplate` transform, with the
/// total bytes the strip pass removed. A no-op for `bytes == 0` so the
/// series stays absent for origins that never strip anything.
pub fn record_boilerplate_stripped_bytes(hostname: &str, bytes: u64) {
    if bytes == 0 {
        return;
    }
    let hostname = sanitize_label("hostname", hostname);
    metrics()
        .boilerplate_stripped_bytes
        .with_label_values(&[&hostname])
        .inc_by(bytes);
}

/// Increment `sbproxy_policy_audit_events_total{verdict, surface, policy_id}`.
///
/// Called once for every policy decision the dispatcher renders.
/// Mirrors the [`PolicyVerdictEvent`](crate::events::PolicyVerdictEvent)
/// payload that lands on the audit bus, but stays local to the
/// metric registry so dashboards see decisions even when the bus
/// consumer is offline.
///
/// The `policy_id` label is sanitised through the cardinality
/// limiter so a misbehaving plugin cannot blow up label space by
/// reporting a fresh policy_type per call.
pub fn record_policy_audit_emitted(verdict: &str, surface: &str, policy_id: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_policy_audit_events_total",
            "Policy decisions emitted on the audit event bus, labelled by verdict, surface, and policy_id",
            &["verdict", "surface", "policy_id"],
        )
        .expect("policy audit emitted counter registers")
    });
    let policy_id =
        sanitize_label_budget("sbproxy_policy_audit_events_total", "policy_id", policy_id);
    counter
        .with_label_values(&[verdict, surface, policy_id.as_str()])
        .inc();
}

/// WOR-1130: increment `sbproxy_rate_limit_total{workspace, result}`.
/// `result` is `soft` (above the soft threshold, not throttled) or
/// `throttle` (burst ceiling hit).
pub fn record_rate_limit(workspace: &str, result: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_rate_limit_total",
            "Workspace rate-limit budget outcomes by workspace and result (soft/throttle)",
            &["workspace", "result"],
        )
        .expect("rate_limit_total counter registers")
    });
    let workspace = sanitize_label("workspace", workspace);
    counter
        .with_label_values(&[workspace.as_str(), result])
        .inc();
}

/// WOR-1130: increment `sbproxy_rate_limit_suspend_total{workspace}` on
/// each workspace auto-suspend transition.
pub fn record_rate_limit_suspend(workspace: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_rate_limit_suspend_total",
            "Workspace auto-suspend transitions",
            &["workspace"],
        )
        .expect("rate_limit_suspend_total counter registers")
    });
    let workspace = sanitize_label("workspace", workspace);
    counter.with_label_values(&[workspace.as_str()]).inc();
}

/// Increment `sbproxy_policy_audit_events_dropped_total{tenant}`.
///
/// Called when the bounded mpsc audit bus is full and the
/// dispatcher must drop a [`PolicyVerdictEvent`](crate::events::PolicyVerdictEvent)
/// to avoid blocking the hot path. Per
/// `docs/adr-policy-audit-binding.md`, this is a paging signal:
/// operators should alert on a non-zero rate so they get warning
/// before audit coverage degrades.
pub fn record_policy_audit_event_dropped(tenant: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_policy_audit_events_dropped_total",
            "Policy verdict audit events dropped because the bus queue was full",
            &["tenant"],
        )
        .expect("policy audit dropped counter registers")
    });
    let tenant = sanitize_label_budget(
        "sbproxy_policy_audit_events_dropped_total",
        "tenant",
        tenant,
    );
    counter.with_label_values(&[tenant.as_str()]).inc();
}

/// Observe the wall-clock latency of a policy decision in seconds.
///
/// Records the time from entering the dispatcher to the verdict
/// being produced, labelled by `surface` (`built_in` / `plugin`).
/// Bucket boundaries are tuned for the OSS in-process path: most
/// decisions land under 1 ms, plugin decisions can spread to tens
/// of milliseconds when an enforcer makes a network call.
pub fn record_policy_decision_latency(surface: &str, duration_secs: f64) {
    use prometheus::{register_histogram_vec, HistogramVec};
    use std::sync::OnceLock;
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_policy_decision_duration_seconds",
            "Wall-clock latency of policy decisions",
            &["surface"],
            vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
        )
        .expect("policy decision latency histogram registers")
    });
    hist.with_label_values(&[surface]).observe(duration_secs);
}

// --- WOR-75: four exemplar-emitting histograms ---
//
// Each helper below registers its own `HistogramVec` lazily, calls
// `.observe(duration_secs)`, and stamps the active trace + span IDs
// onto the matching bucket via `exemplars::record(...)`. The metric
// names line up with the WOR-75 allow-list in
// [`crate::exemplars::is_exemplar_metric`].
//
// All four share [`exemplars::STANDARD_LATENCY_BUCKETS`] so dashboards
// can use one bucket template across the request, ledger, policy,
// outbound, and audit pipelines. Bucket boundaries match
// `request_duration` (12 buckets from 1ms to 10s) so an outlier in
// the gateway always lands in the same `le=...` slot as the outlier
// in the corresponding downstream call.

/// Observe the wall-clock latency of one payment-token redemption in
/// seconds (WOR-75 / `sbproxy_ledger_redeem_duration_seconds`).
///
/// Called by the `ai_crawl` policy after every
/// [`crate::events::PolicyVerdictEvent`]-eligible ledger call. The
/// `outcome` label is one of `success`, `hard_failure`, or
/// `transient_failure` so the dashboard can distinguish "ledger is
/// up but the token is bad" from "ledger is unreachable" without
/// blowing up cardinality. `host` carries the request hostname so
/// per-origin dashboards can split slow ledgers from fast ones.
///
/// An exemplar with the active OpenTelemetry trace + span IDs is
/// stamped onto the matching bucket; scrapers negotiating
/// `application/openmetrics-text` will see the `# {trace_id="..."}`
/// suffix.
pub fn record_ledger_redeem_duration(host: &str, outcome: &str, duration_secs: f64) {
    use prometheus::{register_histogram_vec, HistogramVec};
    use std::sync::OnceLock;
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_ledger_redeem_duration_seconds",
            "Wall-clock latency of a single ledger token redemption",
            &["host", "outcome"],
            crate::exemplars::STANDARD_LATENCY_BUCKETS.to_vec(),
        )
        .expect("ledger redeem histogram registers")
    });
    let host_san = sanitize_label("host", host);
    hist.with_label_values(&[host_san.as_str(), outcome])
        .observe(duration_secs);
    let (trace_id, span_id) = current_trace_ids();
    crate::exemplars::record(
        "sbproxy_ledger_redeem_duration_seconds",
        &[("host", host_san.as_str()), ("outcome", outcome)],
        duration_secs,
        crate::exemplars::STANDARD_LATENCY_BUCKETS,
        &trace_id,
        &span_id,
    );
}

/// Observe the wall-clock latency of one policy-chain evaluation in
/// seconds (WOR-75 / `sbproxy_policy_evaluation_duration_seconds`).
///
/// This is the cousin of [`record_policy_decision_latency`]: that one
/// is the per-policy decision timer, while this one covers the full
/// chain evaluation (every policy in the chain for one request) so
/// dashboards can see end-to-end policy overhead per origin without
/// stitching per-policy buckets together. `origin` is the request
/// hostname; `verdict` is one of `allow`, `deny`, `confirm` to match
/// the verdict bus vocabulary.
///
/// An exemplar with the active trace + span IDs lands on the matching
/// bucket so a Grafana "click an outlier" path reaches the right
/// span.
pub fn record_policy_evaluation_duration(origin: &str, verdict: &str, duration_secs: f64) {
    use prometheus::{register_histogram_vec, HistogramVec};
    use std::sync::OnceLock;
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_policy_evaluation_duration_seconds",
            "Wall-clock latency of one full policy-chain evaluation",
            &["origin", "verdict"],
            crate::exemplars::STANDARD_LATENCY_BUCKETS.to_vec(),
        )
        .expect("policy evaluation histogram registers")
    });
    let origin_san = sanitize_label("origin", origin);
    hist.with_label_values(&[origin_san.as_str(), verdict])
        .observe(duration_secs);
    let (trace_id, span_id) = current_trace_ids();
    crate::exemplars::record(
        "sbproxy_policy_evaluation_duration_seconds",
        &[("origin", origin_san.as_str()), ("verdict", verdict)],
        duration_secs,
        crate::exemplars::STANDARD_LATENCY_BUCKETS,
        &trace_id,
        &span_id,
    );
}

/// Observe the wall-clock latency of one outbound upstream request in
/// seconds (WOR-75 / `sbproxy_outbound_request_duration_seconds`).
///
/// Called from the proxy dispatch path after the upstream response
/// has been read (or the call has failed). `host` is the upstream
/// hostname (sanitised through the cardinality limiter); `method` is
/// the request method; `status` is the upstream response status or
/// `"error"` when the upstream call failed before a status was seen.
///
/// An exemplar with the active trace + span IDs is stamped onto the
/// matching bucket. The metric is a peer to
/// `sbproxy_origin_request_duration_seconds`: that one is the
/// inbound view (proxy boundary), this one is the outbound view
/// (upstream boundary). Both share the standard 12-bucket layout so
/// dashboards can subtract one from the other to surface
/// proxy-internal overhead.
pub fn record_outbound_request_duration(
    host: &str,
    method: &str,
    status: &str,
    duration_secs: f64,
) {
    use prometheus::{register_histogram_vec, HistogramVec};
    use std::sync::OnceLock;
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_outbound_request_duration_seconds",
            "Wall-clock latency of one outbound upstream request",
            &["host", "method", "status"],
            crate::exemplars::STANDARD_LATENCY_BUCKETS.to_vec(),
        )
        .expect("outbound request histogram registers")
    });
    let host_san = sanitize_label("host", host);
    hist.with_label_values(&[host_san.as_str(), method, status])
        .observe(duration_secs);
    let (trace_id, span_id) = current_trace_ids();
    crate::exemplars::record(
        "sbproxy_outbound_request_duration_seconds",
        &[
            ("host", host_san.as_str()),
            ("method", method),
            ("status", status),
        ],
        duration_secs,
        crate::exemplars::STANDARD_LATENCY_BUCKETS,
        &trace_id,
        &span_id,
    );
}

/// Observe the wall-clock latency of one audit-channel emission in
/// seconds (WOR-75 / `sbproxy_audit_emit_duration_seconds`).
///
/// Called by [`crate::audit::ConfigAuditEntry::emit`] and
/// [`crate::audit::SecurityAuditEntry::emit`] after the JSON has been
/// pushed to the `config_audit` / `security_audit` tracing target.
/// `channel` is one of `config`, `security`; `outcome` is `ok` when
/// serialization succeeded and `serialize_error` when the JSON encode
/// returned an error (in which case the audit was dropped, which is
/// itself worth alerting on).
///
/// An exemplar with the active trace + span IDs lands on the matching
/// bucket; this is the primary way operators correlate a slow audit
/// emit with the request that triggered it.
pub fn record_audit_emit_duration(channel: &str, outcome: &str, duration_secs: f64) {
    use prometheus::{register_histogram_vec, HistogramVec};
    use std::sync::OnceLock;
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_audit_emit_duration_seconds",
            "Wall-clock latency of one audit-channel emission",
            &["channel", "outcome"],
            crate::exemplars::STANDARD_LATENCY_BUCKETS.to_vec(),
        )
        .expect("audit emit histogram registers")
    });
    hist.with_label_values(&[channel, outcome])
        .observe(duration_secs);
    let (trace_id, span_id) = current_trace_ids();
    crate::exemplars::record(
        "sbproxy_audit_emit_duration_seconds",
        &[("channel", channel), ("outcome", outcome)],
        duration_secs,
        crate::exemplars::STANDARD_LATENCY_BUCKETS,
        &trace_id,
        &span_id,
    );
}

// --- script-engine metrics (CEL / Lua / JS / WASM) -----------------------
//
// Four counters / histograms cover the script-engine lifecycle so an
// operator can alert on sandbox kills, runaway execution time, and
// compile churn from a hot-reload watcher.
//
// `engine` is the closed enum `cel|lua|js|wasm`. The `result` and
// `outcome` labels are also closed enums; everything passes through
// unsanitised because the label space is bounded by the schema.

/// Count a script compile attempt on
/// `sbproxy_script_compile_total{engine, result}`. `engine` is one of
/// `cel`, `lua`, `js`, `wasm`. `result` is one of `ok`, `parse_error`,
/// `sandbox_reject`.
pub fn record_script_compile(engine: &'static str, result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_script_compile_total",
            "Script-engine compile attempts, by engine and outcome",
            &["engine", "result"],
        )
        .expect("script compile counter registers")
    });
    counter.with_label_values(&[engine, result]).inc();
}

/// Count a script invocation on
/// `sbproxy_script_invocations_total{engine, result}`. `result` is one
/// of `ok`, `runtime_error`, `timeout`, `memory_cap`,
/// `instruction_cap`. The matching duration histogram is emitted by
/// [`record_script_duration`].
pub fn record_script_invocation(engine: &'static str, result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_script_invocations_total",
            "Script-engine invocations, by engine and outcome",
            &["engine", "result"],
        )
        .expect("script invocations counter registers")
    });
    counter.with_label_values(&[engine, result]).inc();
}

/// Record a script-engine invocation duration on
/// `sbproxy_script_duration_seconds{engine}`. Buckets cover the typical
/// per-request budget envelope: 100 microseconds through 10 seconds.
pub fn record_script_duration(engine: &'static str, duration_secs: f64) {
    use prometheus::{register_histogram_vec, HistogramVec};
    use std::sync::OnceLock;
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_script_duration_seconds",
            "Script-engine invocation duration, by engine",
            &["engine"],
            vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,],
        )
        .expect("script duration histogram registers")
    });
    hist.with_label_values(&[engine]).observe(duration_secs);
}

/// Count a hot-reload event on
/// `sbproxy_script_reloads_total{engine, result}`. `result` is one of
/// `ok`, `parse_error`, `sandbox_reject`. The reload counter is
/// distinct from the compile counter so operators can spot reload
/// churn separately from cold-start compile failures.
pub fn record_script_reload(engine: &'static str, result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_script_reloads_total",
            "Script-engine hot-reload events, by engine and outcome",
            &["engine", "result"],
        )
        .expect("script reloads counter registers")
    });
    counter.with_label_values(&[engine, result]).inc();
}

// --- rate-limit + idempotency metrics ------------------------------------
//
// The two request-shaping middlewares (rate_limit, idempotency) expose
// counters and a histogram so operators can see throttle decisions
// distinct from rejections and idempotency cache health independently
// of overall response cache hits.
//
// `policy` is sanitised so a misconfigured route does not explode the
// label space; `result` is a closed enum from the middleware itself
// and passes through unsanitised. The same holds for `backend` and
// `result` on the idempotency family.

/// Record a rate-limit decision on
/// `sbproxy_rate_limit_decisions_total{policy, result}`. `policy` is
/// the route-pattern the decision was scoped to (sanitised). `result`
/// is one of the closed strings `allow`, `throttle_route`,
/// `throttle_tenant`, or `disabled`.
pub fn record_rate_limit_decision(policy: &str, result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_rate_limit_decisions_total",
            "Rate-limit middleware decisions, by policy and outcome",
            &["policy", "result"],
        )
        .expect("rate-limit decision counter registers")
    });
    let policy = sanitize_label("policy", policy);
    counter.with_label_values(&[policy.as_str(), result]).inc();
}

/// Record an idempotency-cache outcome on
/// `sbproxy_idempotency_cache_results_total{backend, result}`. `result`
/// is one of `hit`, `miss`, `conflict`, `not_applicable`.
pub fn record_idempotency_cache_result(backend: &'static str, result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_idempotency_cache_results_total",
            "Idempotency cache outcomes, by backend and result",
            &["backend", "result"],
        )
        .expect("idempotency cache result counter registers")
    });
    counter.with_label_values(&[backend, result]).inc();
}

/// Record an idempotency-cache lookup duration on
/// `sbproxy_idempotency_cache_duration_seconds{backend}`. Buckets
/// cover the typical local-memory and remote-redis envelopes:
/// 50 microseconds through 1 second.
pub fn record_idempotency_cache_duration(backend: &'static str, duration_secs: f64) {
    use prometheus::{register_histogram_vec, HistogramVec};
    use std::sync::OnceLock;
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_idempotency_cache_duration_seconds",
            "Idempotency cache lookup duration, by backend",
            &["backend"],
            vec![0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0,],
        )
        .expect("idempotency cache duration histogram registers")
    });
    hist.with_label_values(&[backend]).observe(duration_secs);
}

// --- body size + compression metrics --------------------------------------
//
// Three families let an operator see how load-shaped traffic is:
// response body sizes before and after compression, the per-codec
// distribution of compression decisions, and the achieved compression
// ratio when compression was applied.
//
// `codec` is the closed enum `gzip | br | zstd | identity`; `result`
// is a closed enum off the compression decision site; `direction` is
// closed too. No sanitisation is required.

const BODY_BYTES_BUCKETS: &[f64] = &[
    256.0,
    1024.0,
    4096.0,
    16_384.0,
    65_536.0,
    262_144.0,
    1_048_576.0,
    4_194_304.0,
    16_777_216.0,
];

/// Record a response body size on
/// `sbproxy_response_body_bytes{direction}`. `direction` is
/// `pre_compress` or `post_compress`. Buckets span 256 bytes through
/// 16 MiB so dashboards can spot tiny payloads (where compression
/// wastes CPU) and the long tail (where it shrinks bytes the most).
pub fn record_response_body_bytes(direction: &'static str, bytes: u64) {
    use prometheus::{register_histogram_vec, HistogramVec};
    use std::sync::OnceLock;
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_response_body_bytes",
            "Response body size, by compression direction",
            &["direction"],
            BODY_BYTES_BUCKETS.to_vec(),
        )
        .expect("response body bytes histogram registers")
    });
    hist.with_label_values(&[direction]).observe(bytes as f64);
}

/// Record a compression decision on
/// `sbproxy_compression_decisions_total{codec, result}`. `codec` is
/// one of `gzip`, `br`, `zstd`, `identity`. `result` is one of
/// `applied`, `skipped_size`, `skipped_accept`, `disabled`.
pub fn record_compression_decision(codec: &'static str, result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_compression_decisions_total",
            "Compression middleware decisions, by codec and outcome",
            &["codec", "result"],
        )
        .expect("compression decision counter registers")
    });
    counter.with_label_values(&[codec, result]).inc();
}

/// Record an observed compression ratio on
/// `sbproxy_compression_ratio{codec}`. Buckets cover the expected
/// envelope from no shrinkage (1.0) down to 25x shrinkage (0.04).
/// Lower is better. Only emitted when compression was applied.
pub fn record_compression_ratio(codec: &'static str, ratio: f64) {
    use prometheus::{register_histogram_vec, HistogramVec};
    use std::sync::OnceLock;
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_compression_ratio",
            "Achieved compression ratio (post_size / pre_size) when compression was applied",
            &["codec"],
            vec![0.04, 0.08, 0.16, 0.25, 0.33, 0.5, 0.66, 0.8, 0.9, 1.0],
        )
        .expect("compression ratio histogram registers")
    });
    hist.with_label_values(&[codec]).observe(ratio);
}

// --- plugin registry metrics --------------------------------------------
//
// Two families cover the plugin-registry surface today:
//
// * `sbproxy_plugin_registered_total{kind, plugin}`: a counter
//   incremented once per known registration. Callers walk the
//   `inventory::iter` set at startup and call this helper for each
//   row.
// * `sbproxy_plugin_init_duration_seconds{kind, plugin, result}` plus
//   its `sbproxy_plugin_init_total{kind, plugin, result}` sibling:
//   timed and counted at every factory call, so an operator can
//   alert on config-invalid factories or panicking plugin init.
//
// `kind` is the closed enum
// `policy | action | auth | transform | enricher`. `plugin` is
// sanitised through the cardinality limiter so a hostile or
// misconfigured deployment cannot blow up the label space by
// registering thousands of distinct plugin names. `result` is a
// closed enum from the factory side.
//
// Per-invocation counters (calls into the plugin at request time)
// are deferred: instrumenting every plugin trait call site is a
// follow-up because it touches every transform / policy / auth /
// action call path.

/// Record a known plugin registration on
/// `sbproxy_plugin_registered_total{kind, plugin}`. Callers walk the
/// `inventory::iter` set once at startup and call this helper for
/// each row.
pub fn record_plugin_registered(kind: &'static str, plugin: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_plugin_registered_total",
            "Known plugin registrations, by kind and plugin name",
            &["kind", "plugin"],
        )
        .expect("plugin registered counter registers")
    });
    let plugin = sanitize_label("plugin", plugin);
    counter.with_label_values(&[kind, plugin.as_str()]).inc();
}

/// Record a plugin factory invocation outcome on
/// `sbproxy_plugin_init_total{kind, plugin, result}` and its matching
/// `sbproxy_plugin_init_duration_seconds{kind, plugin, result}`
/// histogram. `result` is one of `ok`, `config_invalid`, `panic`.
/// Buckets cover the typical config-time envelope: 100us through 10s.
pub fn record_plugin_init(
    kind: &'static str,
    plugin: &str,
    result: &'static str,
    duration_secs: f64,
) {
    use prometheus::{
        register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec,
    };
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_plugin_init_total",
            "Plugin factory init attempts, by kind, plugin name, and outcome",
            &["kind", "plugin", "result"],
        )
        .expect("plugin init counter registers")
    });
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_plugin_init_duration_seconds",
            "Plugin factory init duration, by kind, plugin name, and outcome",
            &["kind", "plugin", "result"],
            vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 10.0],
        )
        .expect("plugin init duration histogram registers")
    });
    let plugin = sanitize_label("plugin", plugin);
    counter
        .with_label_values(&[kind, plugin.as_str(), result])
        .inc();
    hist.with_label_values(&[kind, plugin.as_str(), result])
        .observe(duration_secs);
}

// --- TLS / ACME / OCSP metrics ------------------------------------------
//
// The TLS subsystem ran without any sbproxy_* metric until this PR.
// An expired ACME account or a stale OCSP staple was invisible until
// handshake failures started surfacing. These families let an
// operator alert before the first user-visible 5xx.
//
// `result` labels are all closed enums.

/// Record an ACME certificate renewal outcome on
/// `sbproxy_acme_renewals_total{result}` and its matching duration
/// histogram. `result` is one of `ok`, `http_error`, `order_invalid`,
/// `account_invalid`, `rate_limited`, `other`. Buckets cover 100ms
/// through 5 minutes, matching the ACME poll-and-finalise envelope.
pub fn record_acme_renewal(result: &'static str, duration_secs: f64) {
    use prometheus::{
        register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec,
    };
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_acme_renewals_total",
            "ACME certificate renewal attempts, by outcome",
            &["result"],
        )
        .expect("acme renewal counter registers")
    });
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_acme_renewal_duration_seconds",
            "ACME renewal full-flow duration, by outcome",
            &["result"],
            vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
        )
        .expect("acme renewal duration histogram registers")
    });
    counter.with_label_values(&[result]).inc();
    hist.with_label_values(&[result]).observe(duration_secs);
}

/// Record an OCSP fetch outcome on
/// `sbproxy_ocsp_fetch_total{result}`. `result` is one of `ok`,
/// `http_error`, `parse_error`, `unknown_status`, `no_responder`.
pub fn record_ocsp_fetch(result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_ocsp_fetch_total",
            "OCSP fetch attempts, by outcome",
            &["result"],
        )
        .expect("ocsp fetch counter registers")
    });
    counter.with_label_values(&[result]).inc();
}

/// Record the seconds-until-expiry for the active certificate of
/// `host` on `sbproxy_cert_expiry_seconds{host}`. Negative values
/// indicate the cert has already expired. `host` is sanitised so the
/// label space stays bounded.
pub fn record_cert_expiry(host: &str, seconds_until_expiry: f64) {
    use prometheus::{register_gauge_vec, GaugeVec};
    use std::sync::OnceLock;
    static G: OnceLock<GaugeVec> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_gauge_vec!(
            "sbproxy_cert_expiry_seconds",
            "Seconds until the active certificate for the host expires; negative when expired",
            &["host"],
        )
        .expect("cert expiry gauge registers")
    });
    let host = sanitize_label("host", host);
    gauge
        .with_label_values(&[host.as_str()])
        .set(seconds_until_expiry);
}

/// WOR-1024: record the age of the cached OCSP staple for `host` on
/// `sbproxy_ocsp_staple_age_seconds{host}`. A stale staple (over
/// 24 hours) signals an OCSP refresh failure that has not yet
/// produced a hard handshake error.
pub fn record_ocsp_staple_age(host: &str, age_seconds: f64) {
    use prometheus::{register_gauge_vec, GaugeVec};
    use std::sync::OnceLock;
    static G: OnceLock<GaugeVec> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_gauge_vec!(
            "sbproxy_ocsp_staple_age_seconds",
            "Age of the cached OCSP staple for the host, in seconds",
            &["host"],
        )
        .expect("ocsp staple age gauge registers")
    });
    let host = sanitize_label("host", host);
    gauge.with_label_values(&[host.as_str()]).set(age_seconds);
}

/// WOR-1024: record an mTLS client-certificate verification outcome
/// on `sbproxy_mtls_handshake_total{result}`. `result` is one of
/// `ok`, `untrusted_issuer`, `expired`, `revoked`, `other`. An
/// operator alerting on a non-trivial `untrusted_issuer` rate
/// catches a CA misconfiguration before users see handshake errors.
pub fn record_mtls_handshake(result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mtls_handshake_total",
            "mTLS client-certificate verification outcomes",
            &["result"],
        )
        .expect("mtls handshake counter registers")
    });
    counter.with_label_values(&[result]).inc();
}

// --- vault / secret-resolver metrics ------------------------------------
//
// The vault subsystem ran without any sbproxy_* metric until this PR.
// Backend errors and slow resolutions were invisible until requests
// started failing. The two families below let an operator alert on
// slow secret reads and on backend availability.
//
// `backend` is the user-controlled registered name (HashiCorp vault
// instance, AWS Secrets Manager, GCP Secret Manager, local file, env)
// so it is sanitised through the cardinality limiter. `result` is a
// closed enum derived from the resolver's own outcome.

/// Record a vault resolution outcome on
/// `sbproxy_vault_resolution_total{backend, result}` and its matching
/// `sbproxy_vault_resolution_duration_seconds{backend, result}`
/// histogram. `result` is one of `ok`, `not_found`, `backend_error`,
/// `denied`. Buckets cover 100 microseconds through 5 seconds (the
/// typical local + remote resolution envelope).
pub fn record_vault_resolution(backend: &str, result: &'static str, duration_secs: f64) {
    use prometheus::{
        register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec,
    };
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_vault_resolution_total",
            "Vault resolution attempts, by backend and outcome",
            &["backend", "result"],
        )
        .expect("vault resolution counter registers")
    });
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_vault_resolution_duration_seconds",
            "Vault resolution duration, by backend and outcome",
            &["backend", "result"],
            vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
        )
        .expect("vault resolution duration histogram registers")
    });
    let backend = sanitize_label("backend", backend);
    counter.with_label_values(&[backend.as_str(), result]).inc();
    hist.with_label_values(&[backend.as_str(), result])
        .observe(duration_secs);
}

// --- transport metrics -------------------------------------------------
//
// Three families cover the non-HTTP/1.1 transport surface. `protocol`
// is the closed enum `h1 | h2 | h3 | grpc | grpc_web | graphql |
// websocket`. The H1 / H2 paths already have rich coverage from the
// generic request metrics; the families below let an operator alert
// on protocol-specific failure modes (gRPC status drift, websocket
// frame errors, H3 session churn) without double-counting requests
// from the generic path.
//
// gRPC status codes are emitted under
// `sbproxy_grpc_status_total{code}` where `code` is the canonical
// tonic::Code lowercase name (`ok`, `cancelled`, `unknown`,
// `invalid_argument`, ...). The label space is bounded by tonic's
// closed enum, so no sanitisation is required.

/// Record a transport-layer request outcome on
/// `sbproxy_transport_requests_total{protocol, result}` and its
/// matching duration histogram. `result` is one of `ok`,
/// `client_error`, `upstream_error`, `timeout`.
pub fn record_transport_request(protocol: &'static str, result: &'static str, duration_secs: f64) {
    use prometheus::{
        register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec,
    };
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_transport_requests_total",
            "Transport-layer requests, by protocol and outcome",
            &["protocol", "result"],
        )
        .expect("transport requests counter registers")
    });
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_transport_duration_seconds",
            "Transport-layer request duration, by protocol and outcome",
            &["protocol", "result"],
            vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,],
        )
        .expect("transport duration histogram registers")
    });
    counter.with_label_values(&[protocol, result]).inc();
    hist.with_label_values(&[protocol, result])
        .observe(duration_secs);
}

/// Record a gRPC status code on `sbproxy_grpc_status_total{code}`.
/// `code` is the canonical tonic-style lowercase name (`ok`,
/// `not_found`, `unauthenticated`, ...). Useful for spotting a
/// `failed_precondition` burst after a deploy or an `unavailable`
/// spike from an upstream pool.
pub fn record_grpc_status(code: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_grpc_status_total",
            "Observed gRPC status codes, by canonical name",
            &["code"],
        )
        .expect("grpc status counter registers")
    });
    counter.with_label_values(&[code]).inc();
}

/// Map a gRPC numeric status code (RFC-style, 0..16) to the closed
/// `code` label set. Out-of-range codes report as `unknown`.
pub fn grpc_status_label(code: u32) -> &'static str {
    match code {
        0 => "ok",
        1 => "cancelled",
        2 => "unknown",
        3 => "invalid_argument",
        4 => "deadline_exceeded",
        5 => "not_found",
        6 => "already_exists",
        7 => "permission_denied",
        8 => "resource_exhausted",
        9 => "failed_precondition",
        10 => "aborted",
        11 => "out_of_range",
        12 => "unimplemented",
        13 => "internal",
        14 => "unavailable",
        15 => "data_loss",
        16 => "unauthenticated",
        _ => "unknown",
    }
}

// --- MCP server metrics -------------------------------------------------
//
// Today `sbproxy_mcp_policy_hook_invocations_total` is the only MCP
// counter (`metrics.rs:1074`). These three families let operators see
// tool-dispatch volume, resource-fetch volume, and federation health
// without scraping the audit log.

/// Record an MCP tool dispatch on
/// `sbproxy_mcp_tool_dispatch_total{tool, result}` and its matching
/// duration histogram. `tool` is sanitised so a misconfigured tool
/// registry cannot blow the label space. `result` is one of `ok`,
/// `tool_error`, `tool_not_found`, `policy_denied`.
pub fn record_mcp_tool_dispatch(tool: &str, result: &'static str, duration_secs: f64) {
    use prometheus::{
        register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec,
    };
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_tool_dispatch_total",
            "MCP tool dispatch attempts, by tool name and outcome",
            &["tool", "result"],
        )
        .expect("mcp tool dispatch counter registers")
    });
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_mcp_tool_dispatch_duration_seconds",
            "MCP tool dispatch duration, by tool name",
            &["tool"],
            vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 10.0],
        )
        .expect("mcp tool dispatch duration histogram registers")
    });
    let tool = sanitize_label("tool", tool);
    counter.with_label_values(&[tool.as_str(), result]).inc();
    hist.with_label_values(&[tool.as_str()])
        .observe(duration_secs);
}

/// Record MCP tool-call spend on
/// `sbproxy_mcp_tool_cost_usd_total{tool, server}` (WOR-1644). Only
/// emitted when a price map resolves a cost for the tool; the
/// dispatch-count and duration already ride on
/// `sbproxy_mcp_tool_dispatch_*`.
pub fn record_mcp_tool_cost(tool: &str, server: &str, cost_usd: f64) {
    use prometheus::{register_counter_vec, CounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<CounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_counter_vec!(
            "sbproxy_mcp_tool_cost_usd_total",
            "MCP tool-call cost in USD, by tool and owning server",
            &["tool", "server"],
        )
        .expect("mcp tool cost counter registers")
    });
    let tool = sanitize_label("tool", tool);
    let server = sanitize_label("server", server);
    counter
        .with_label_values(&[tool.as_str(), server.as_str()])
        .inc_by(cost_usd);
}

/// Record a tool-versioning oracle verdict on
/// `sbproxy_mcp_tool_compat_verdicts_total{grade, outcome}`
/// (WOR-1635). `grade` is the computed semver grade (`none`, `patch`,
/// `minor`, `major`); `outcome` is `ok`, `violation`, `removed_tool`,
/// or `lockfile_error`.
pub fn record_mcp_tool_compat_verdict(grade: &str, outcome: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_tool_compat_verdicts_total",
            "Tool-versioning oracle verdicts, by computed grade and outcome",
            &["grade", "outcome"],
        )
        .expect("mcp tool compat verdict counter registers")
    });
    let grade = sanitize_label("grade", grade);
    counter.with_label_values(&[grade.as_str(), outcome]).inc();
}

/// Record a rollout-plane tool call on
/// `sbproxy_mcp_tool_version_calls_total{tool, version, via,
/// deprecated}`. `via` is the resolution rung that chose the version
/// (`meta`, `session`, `pin`, `alias`, `default`); `deprecated` is
/// `yes` once the served version is past its sunset date. The
/// per-version traffic split is the operator's migration dashboard:
/// a version whose calls hit zero is safe to retire.
pub fn record_mcp_tool_version_call(
    tool: &str,
    version: &str,
    via: &'static str,
    past_sunset: bool,
) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_tool_version_calls_total",
            "Rollout-plane tool calls, by tool, served version, resolution rung, and deprecation",
            &["tool", "version", "via", "deprecated"],
        )
        .expect("mcp tool version call counter registers")
    });
    let tool = sanitize_label("tool", tool);
    let version = sanitize_label("version", version);
    counter
        .with_label_values(&[
            tool.as_str(),
            version.as_str(),
            via,
            if past_sunset { "yes" } else { "no" },
        ])
        .inc();
}

/// Record an MCP upstream IO failure on
/// `sbproxy_mcp_upstream_io_failures_total{kind}`. `kind` is one of
/// `timeout`, `connect`, `response_cap`, `other`. Lets an operator
/// see hung or oversized upstreams that the per-request deadlines
/// and byte caps are absorbing.
pub fn record_mcp_upstream_io_failure(kind: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_upstream_io_failures_total",
            "MCP upstream IO failures absorbed by deadlines and byte caps, by kind",
            &["kind"],
        )
        .expect("mcp upstream io failure counter registers")
    });
    counter.with_label_values(&[kind]).inc();
}

/// Record an MCP resource-fetch attempt on
/// `sbproxy_mcp_resource_fetch_total{result}`. `result` is one of
/// `ok`, `not_found`, `upstream_error`, `policy_denied`.
pub fn record_mcp_resource_fetch(result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_resource_fetch_total",
            "MCP resource-fetch attempts, by outcome",
            &["result"],
        )
        .expect("mcp resource fetch counter registers")
    });
    counter.with_label_values(&[result]).inc();
}

/// Set the live federation-peer count on
/// `sbproxy_mcp_federation_peers_up`. A periodic refresh task in the
/// federation aggregator publishes this so an operator can alert on
/// `< 1` for a federation that needs >0 live upstreams.
pub fn set_mcp_federation_peers_up(count: i64) {
    use prometheus::{register_int_gauge, IntGauge};
    use std::sync::OnceLock;
    static G: OnceLock<IntGauge> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge!(
            "sbproxy_mcp_federation_peers_up",
            "Live MCP federation peers as of the last refresh",
        )
        .expect("mcp federation peers gauge registers")
    });
    gauge.set(count);
}

// --- model host metrics (WOR-1652, WOR-1659) ---------------------------
//
// The local model host spawns/supervises inference engines and fits
// them to the GPU. These families let an operator see cold-start cost,
// residency, evictions, and per-device VRAM/utilization, and they
// publish the `gpu_utilization` signal the gpu-aware routing strategy
// already consumes. `engine` is the engine kind (`vllm`, `llama_cpp`);
// `model` is the catalog id / advertised model name (sanitized).

/// Record an engine reaching Ready on
/// `sbproxy_model_host_time_to_ready_seconds{engine, model, outcome}`
/// (a histogram) plus a launch counter. `outcome` is `ready` or
/// `failed`. Buckets span 1s..600s (a cold weight load + warm-up).
pub fn record_model_host_time_to_ready(
    engine: &str,
    model: &str,
    outcome: &'static str,
    duration_secs: f64,
) {
    use prometheus::{
        register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec,
    };
    use std::sync::OnceLock;
    static H: OnceLock<HistogramVec> = OnceLock::new();
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_model_host_time_to_ready_seconds",
            "Time from engine launch to Ready, by engine and model",
            &["engine", "model"],
            vec![1.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 300.0, 600.0],
        )
        .expect("model host time-to-ready histogram registers")
    });
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_model_host_launches_total",
            "Engine launch attempts by engine, model, and outcome",
            &["engine", "model", "outcome"],
        )
        .expect("model host launches counter registers")
    });
    let engine = sanitize_label("engine", engine);
    let model = sanitize_label("model", model);
    if outcome == "ready" {
        hist.with_label_values(&[engine.as_str(), model.as_str()])
            .observe(duration_secs);
    }
    counter
        .with_label_values(&[engine.as_str(), model.as_str(), outcome])
        .inc();
}

/// Record a model eviction on
/// `sbproxy_model_host_evictions_total{reason}`. `reason` is one of
/// `lru`, `keep_alive`, `manual`.
pub fn record_model_host_eviction(reason: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_model_host_evictions_total",
            "Model evictions by reason",
            &["reason"],
        )
        .expect("model host evictions counter registers")
    });
    counter.with_label_values(&[reason]).inc();
}

/// Set the count of currently-resident (Ready) local models on
/// `sbproxy_model_host_resident_models`.
pub fn set_model_host_resident_models(count: i64) {
    use prometheus::{register_int_gauge, IntGauge};
    use std::sync::OnceLock;
    static G: OnceLock<IntGauge> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge!(
            "sbproxy_model_host_resident_models",
            "Local models currently loaded and Ready",
        )
        .expect("model host resident-models gauge registers")
    });
    gauge.set(count);
}

/// A LoRA adapter was loaded onto a base engine (WOR-1709):
/// `sbproxy_model_host_lora_loads_total`.
pub fn record_model_host_lora_load() {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_model_host_lora_loads_total",
            "LoRA adapters loaded onto a base engine (dynamic-paging cache misses)",
        )
        .expect("model host lora-loads counter registers")
    });
    counter.inc();
}

/// A LoRA adapter was paged out of a base engine's adapter cache
/// (WOR-1709): `sbproxy_model_host_lora_evictions_total`.
pub fn record_model_host_lora_eviction() {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_model_host_lora_evictions_total",
            "LoRA adapters evicted from a base engine's cache to make room",
        )
        .expect("model host lora-evictions counter registers")
    });
    counter.inc();
}

/// Total resident (loaded) LoRA adapters across all base engines
/// (WOR-1709): `sbproxy_model_host_resident_adapters`.
pub fn set_model_host_resident_adapters(count: i64) {
    use prometheus::{register_int_gauge, IntGauge};
    use std::sync::OnceLock;
    static G: OnceLock<IntGauge> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge!(
            "sbproxy_model_host_resident_adapters",
            "LoRA adapters currently loaded across all base engines",
        )
        .expect("model host resident-adapters gauge registers")
    });
    gauge.set(count);
}

/// Bringing a model to ready failed (WOR-1711):
/// `sbproxy_model_host_ensure_failures_total{reason}`. `reason` is one of
/// `unknown_model`, `resolve`, `no_metadata`, `fit`, `residency`, `port`,
/// `launch`, distinguishing a model that cannot fit the GPU from an
/// engine that crash-loops.
pub fn record_model_host_ensure_failure(reason: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_model_host_ensure_failures_total",
            "Model ensure-ready failures by reason",
            &["reason"],
        )
        .expect("model host ensure-failures counter registers")
    });
    counter.with_label_values(&[reason]).inc();
}

/// A model-host weight pre-fetch completed (WOR-1712): `bytes` pulled in
/// `secs`, `ok` false on failure. Records
/// `sbproxy_model_host_weight_download_bytes_total`,
/// `sbproxy_model_host_weight_download_seconds`, and, on failure,
/// `sbproxy_model_host_weight_download_failures_total`.
pub fn record_model_host_weight_download(bytes: u64, secs: f64, ok: bool) {
    use prometheus::{register_histogram, register_int_counter, Histogram, IntCounter};
    use std::sync::OnceLock;
    static BYTES: OnceLock<IntCounter> = OnceLock::new();
    static FAILS: OnceLock<IntCounter> = OnceLock::new();
    static SECS: OnceLock<Histogram> = OnceLock::new();
    if ok {
        let bytes_c = BYTES.get_or_init(|| {
            register_int_counter!(
                "sbproxy_model_host_weight_download_bytes_total",
                "Bytes downloaded by model-host weight pre-fetches",
            )
            .expect("model host weight-download bytes counter registers")
        });
        bytes_c.inc_by(bytes);
    } else {
        let fails = FAILS.get_or_init(|| {
            register_int_counter!(
                "sbproxy_model_host_weight_download_failures_total",
                "Model-host weight pre-fetches that failed",
            )
            .expect("model host weight-download failures counter registers")
        });
        fails.inc();
    }
    let secs_h = SECS.get_or_init(|| {
        register_histogram!(
            "sbproxy_model_host_weight_download_seconds",
            "Model-host weight pre-fetch duration in seconds",
        )
        .expect("model host weight-download duration histogram registers")
    });
    secs_h.observe(secs);
}

/// Set the request queue depth while an engine loads on
/// `sbproxy_model_host_load_queue_depth{model}` (requests parked
/// waiting for a cold model to become Ready).
pub fn set_model_host_load_queue_depth(model: &str, depth: i64) {
    use prometheus::{register_int_gauge_vec, IntGaugeVec};
    use std::sync::OnceLock;
    static G: OnceLock<IntGaugeVec> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_model_host_load_queue_depth",
            "Requests queued while a model loads, by model",
            &["model"],
        )
        .expect("model host load-queue gauge registers")
    });
    let model = sanitize_label("model", model);
    gauge.with_label_values(&[model.as_str()]).set(depth);
}

/// Publish per-device GPU VRAM, compute utilization, and memory occupancy on
/// `sbproxy_model_host_gpu_vram_bytes{device, kind}` (kind = `total` |
/// `free`), `sbproxy_model_host_gpu_utilization{device}`, and
/// `sbproxy_model_host_gpu_memory_occupancy{device}`. Unknown compute
/// utilization is not published and is never synthesized from memory.
pub fn set_model_host_gpu_stats(
    device: &str,
    total_bytes: i64,
    free_bytes: i64,
    compute_utilization: Option<f64>,
    memory_occupancy: Option<f64>,
) {
    use prometheus::{register_gauge_vec, register_int_gauge_vec, GaugeVec, IntGaugeVec};
    use std::sync::OnceLock;
    static VRAM: OnceLock<IntGaugeVec> = OnceLock::new();
    static COMPUTE: OnceLock<GaugeVec> = OnceLock::new();
    static MEMORY: OnceLock<GaugeVec> = OnceLock::new();
    let vram = VRAM.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_model_host_gpu_vram_bytes",
            "GPU memory in bytes, by device and kind (total/free)",
            &["device", "kind"],
        )
        .expect("model host gpu vram gauge registers")
    });
    let compute = COMPUTE.get_or_init(|| {
        register_gauge_vec!(
            "sbproxy_model_host_gpu_utilization",
            "GPU compute utilization fraction (0.0-1.0), by device",
            &["device"],
        )
        .expect("model host gpu utilization gauge registers")
    });
    let memory = MEMORY.get_or_init(|| {
        register_gauge_vec!(
            "sbproxy_model_host_gpu_memory_occupancy",
            "GPU occupied-memory fraction (0.0-1.0), by device",
            &["device"],
        )
        .expect("model host gpu memory-occupancy gauge registers")
    });
    let device = sanitize_label("device", device);
    vram.with_label_values(&[device.as_str(), "total"])
        .set(total_bytes);
    vram.with_label_values(&[device.as_str(), "free"])
        .set(free_bytes);
    if let Some(utilization) = bounded_fraction(compute_utilization) {
        compute
            .with_label_values(&[device.as_str()])
            .set(utilization);
    }
    if let Some(occupancy) = bounded_fraction(memory_occupancy) {
        memory.with_label_values(&[device.as_str()]).set(occupancy);
    }
}

/// Set exact active and queued requests for one managed deployment.
pub fn set_model_host_deployment_requests(deployment: &str, active: i64, queued: i64) {
    use prometheus::{register_int_gauge_vec, IntGaugeVec};
    use std::sync::OnceLock;
    static ACTIVE: OnceLock<IntGaugeVec> = OnceLock::new();
    static QUEUED: OnceLock<IntGaugeVec> = OnceLock::new();
    let active_gauge = ACTIVE.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_model_host_active_requests",
            "Requests holding an active managed-model permit",
            &["deployment"],
        )
        .expect("model host active-requests gauge registers")
    });
    let queued_gauge = QUEUED.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_model_host_queued_requests",
            "Requests waiting in a managed-model admission queue",
            &["deployment"],
        )
        .expect("model host queued-requests gauge registers")
    });
    let deployment = sanitize_label("deployment", deployment);
    active_gauge
        .with_label_values(&[deployment.as_str()])
        .set(active.max(0));
    queued_gauge
        .with_label_values(&[deployment.as_str()])
        .set(queued.max(0));
}

/// Publish the current one-hot lifecycle state for a managed deployment.
pub fn set_model_host_deployment_state(deployment: &str, engine: &str, state: &str) {
    use prometheus::{register_int_gauge_vec, IntGaugeVec};
    use std::collections::BTreeMap;
    use std::sync::{Mutex, OnceLock};
    const STATES: &[&str] = &[
        "configured",
        "assigned",
        "cached",
        "preparing",
        "ready",
        "draining",
        "stopped",
        "failed",
        "unknown",
    ];
    static GAUGE: OnceLock<IntGaugeVec> = OnceLock::new();
    static PREVIOUS: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();
    let gauge = GAUGE.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_model_host_deployment_state",
            "One-hot managed-model deployment lifecycle state",
            &["deployment", "engine", "state"],
        )
        .expect("model host deployment-state gauge registers")
    });
    let deployment = sanitize_label("deployment", deployment);
    let engine = closed_label(
        engine,
        &["vllm", "sglang", "llama_cpp", "embedded"],
        "unknown",
    );
    let state = closed_label(state, STATES, "unknown");
    let previous = PREVIOUS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut previous = previous
        .lock()
        .expect("model host deployment-state mutex poisoned");
    let old_engine = previous.insert(deployment.clone(), engine.to_string());
    if let Some(old_engine) = old_engine.filter(|old| old != engine) {
        for candidate in STATES {
            let _ =
                gauge.remove_label_values(&[deployment.as_str(), old_engine.as_str(), candidate]);
        }
    }
    for candidate in STATES {
        gauge
            .with_label_values(&[deployment.as_str(), engine, candidate])
            .set(i64::from(*candidate == state));
    }
    drop(previous);
}

/// Count a bounded managed-model admission rejection.
pub fn record_model_host_admission_rejection(deployment: &str, priority: &str, reason: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_model_host_admission_rejections_total",
            "Managed-model admission rejections by deployment, priority, and reason",
            &["deployment", "priority", "reason"],
        )
        .expect("model host admission-rejections counter registers")
    });
    let deployment = sanitize_label("deployment", deployment);
    let priority = closed_label(priority, &["interactive", "standard", "batch"], "unknown");
    let reason = closed_label(
        reason,
        &[
            "insufficient_capacity",
            "queue_full",
            "queue_timeout",
            "engine_unhealthy",
            "crash_loop",
            "draining",
        ],
        "unknown",
    );
    counter
        .with_label_values(&[deployment.as_str(), priority, reason])
        .inc();
}

fn bounded_fraction(value: Option<f64>) -> Option<f64> {
    value
        .filter(|value| value.is_finite())
        .map(|value| value.clamp(0.0, 1.0))
}

fn closed_label(value: &str, allowed: &[&'static str], fallback: &'static str) -> &'static str {
    allowed
        .iter()
        .copied()
        .find(|candidate| *candidate == value)
        .unwrap_or(fallback)
}

// --- k8s operator metrics ----------------------------------------------
//
// The operator runs a reconcile loop + a leader-election session. These
// three families let an operator alert on a stuck reconcile, a noisy
// retry pattern, and a leader transition that signals a pod restart.
//
// `kind` is the CRD short name (`sbproxy` or `sbproxyconfig`). `result`
// is a closed enum on both families.

/// Record a reconcile outcome on
/// `sbproxy_operator_reconcile_total{kind, result}` and the matching
/// duration histogram. `result` is one of `ok`, `conflict`,
/// `backend_error`, `crd_invalid`. Buckets cover 1ms..60s (the
/// reconcile envelope including server-side apply round-trips).
pub fn record_operator_reconcile(kind: &'static str, result: &'static str, duration_secs: f64) {
    use prometheus::{
        register_histogram_vec, register_int_counter_vec, HistogramVec, IntCounterVec,
    };
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    static H: OnceLock<HistogramVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_operator_reconcile_total",
            "Operator reconcile attempts, by CRD kind and outcome",
            &["kind", "result"],
        )
        .expect("operator reconcile counter registers")
    });
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_operator_reconcile_duration_seconds",
            "Operator reconcile duration, by CRD kind",
            &["kind"],
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0],
        )
        .expect("operator reconcile duration histogram registers")
    });
    counter.with_label_values(&[kind, result]).inc();
    hist.with_label_values(&[kind]).observe(duration_secs);
}

/// Record a leader-election transition on
/// `sbproxy_operator_leader_transitions_total{result}`. `result` is
/// one of `elected` (acquired the lease for the first time on this
/// replica), `lost` (held the lease then exited the renew loop), or
/// `renewed` (refreshed an existing lease).
pub fn record_operator_leader_transition(result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_operator_leader_transitions_total",
            "Leader-election lifecycle events on this replica",
            &["result"],
        )
        .expect("operator leader transitions counter registers")
    });
    counter.with_label_values(&[result]).inc();
}

/// Set the leader gauge on `sbproxy_operator_leader_is_leader`. `1`
/// when this replica currently holds the lease, `0` otherwise.
pub fn set_operator_leader_is_leader(is_leader: bool) {
    use prometheus::{register_int_gauge, IntGauge};
    use std::sync::OnceLock;
    static G: OnceLock<IntGauge> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge!(
            "sbproxy_operator_leader_is_leader",
            "1 when this operator replica currently holds the leader lease",
        )
        .expect("operator leader gauge registers")
    });
    gauge.set(if is_leader { 1 } else { 0 });
}

// --- per-credential token attribution metric ---------------------------
//
// `sbproxy_ai_tokens_attributed_total` (in `sbproxy-ai`) already
// rolls up token usage by upstream provider and model; that surface
// is what spend dashboards consume. This second metric
// indexes the same observation by who-paid attribution
// (`project`, `user`, `tag`) so a per-tenant operator can write a
// Prometheus alert against budget burn without scraping the access
// log into ClickHouse first.
//
// All four labels go through the cardinality limiter; the metric
// still emits when the budget overflows (the limiter demotes the
// excess values into `__other__`), and `sbproxy_label_cardinality_overflow_total`
// fires so operators can spot the demotion.
//
// `tenant_id` is intentionally not on the label set today; it lands
// once the multi-tenant scaffolding from the credentials epic merges
// (origin -> tenant resolution is the prerequisite).

/// Increment `sbproxy_tokens_attributed_total{project, user, tag,
/// direction}` by `count`. Call once per direction per request.
///
/// Each label is sanitised through the cardinality limiter:
/// `project` and `user` come from the matched virtual-key config;
/// `tag` is the first element of the credential's `tags:` list
/// (callers wanting per-tag fan-out emit one call per tag). The
/// `direction` enum takes `input` for the prompt side and `output`
/// for the completion side, matching the attributed token counter
/// in `sbproxy-ai`.
///
/// Empty `project` / `user` / `tag` strings serialise as empty
/// labels; downstream queries should `OR project=""` etc. to roll up
/// the unattributed segment.
pub fn record_tokens_attributed(
    project: &str,
    user: &str,
    tag: &str,
    direction: &'static str,
    count: u64,
) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    if count == 0 {
        return;
    }
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_tokens_attributed_total",
            "AI token usage attributed to a credential's project / user / tag",
            &["project", "user", "tag", "direction"],
        )
        .expect("tokens attributed counter registers")
    });
    let project = sanitize_label("project", project);
    let user = sanitize_label("user", user);
    let tag = sanitize_label("tag", tag);
    counter
        .with_label_values(&[project.as_str(), user.as_str(), tag.as_str(), direction])
        .inc_by(count);
}

/// Increment `sbproxy_ai_cost_usd_micros_total{provider, model,
/// tenant_id}` by `cost_usd_micros`.
///
/// The unit is micro-USD (`1e-6` USD), matching
/// [`crate::request_event::RequestEvent::cost_usd_micros`]. The
/// helper also mirrors the observation to the optional OTLP metrics
/// pipeline as `sbproxy.ai.cost_usd_micros` with the same labels.
pub fn record_ai_cost_usd_micros(
    provider: &str,
    model: &str,
    tenant_id: &str,
    cost_usd_micros: u64,
) {
    const METRIC: &str = "sbproxy_ai_cost_usd_micros_total";
    if cost_usd_micros == 0 {
        return;
    }
    let provider = sanitize_label_budget_tenant(METRIC, "provider", provider, tenant_id);
    let model = sanitize_label_budget_tenant(METRIC, "model", model, tenant_id);
    let tenant_id = sanitize_label_budget(METRIC, "tenant_id", tenant_id);
    let m = metrics();
    m.ai_cost_usd_micros_total
        .with_label_values(&[provider.as_str(), model.as_str(), tenant_id.as_str()])
        .inc_by(cost_usd_micros);
    crate::otel::ai_cost_usd_micros_counter().add(
        cost_usd_micros,
        &[
            opentelemetry::KeyValue::new("provider", provider),
            opentelemetry::KeyValue::new("model", model),
            opentelemetry::KeyValue::new("tenant_id", tenant_id),
        ],
    );
}

/// Increment `sbproxy_ai_usage_parse_miss_total{provider, surface}` by
/// one (WOR-1146).
///
/// Called when a 2xx AI response on a token-bearing surface carried no
/// parseable `usage` block, so the gateway fell back to an estimated
/// token debit against the budget. A sustained miss rate per provider
/// is an operability signal (an upstream wrapper stripping usage, or a
/// surface the estimator does not yet cover) and can be alerted on.
pub fn record_ai_usage_parse_miss(provider: &str, surface: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_ai_usage_parse_miss_total",
            "2xx AI responses on a token surface that carried no parseable usage block (budget debited from an estimate)",
            &["provider", "surface"],
        )
        .expect("ai usage parse miss counter registers")
    });
    let provider = sanitize_label("provider", provider);
    let surface = sanitize_label("surface", surface);
    counter
        .with_label_values(&[provider.as_str(), surface.as_str()])
        .inc();
}

// --- WOR-1044: reversible PII redaction miss ---
//
// Incremented when a `<placeholder:...>` shape appears in the upstream
// response body but is NOT present in the request-scoped capture map
// (i.e. the LLM hallucinated a placeholder string the gateway never
// inserted). The placeholder is left in the response so the caller
// can see the synthetic value rather than have the gateway silently
// drop it.
//
// Label `rule` is the slug parsed out of the `<placeholder:<rule>:N>`
// shape (or `unknown` when the slug does not match a known shape).
// Both labels go through the cardinality limiter.

/// Increment `sbproxy_ai_reversible_redaction_miss_total{rule}` by one.
///
/// Called by the response handler whenever it spots a placeholder in
/// the inbound LLM response that the request-side capture did not
/// produce. The metric exists so operators can spot prompt-injection
/// attempts or model hallucinations that probe the placeholder
/// vocabulary; the unmatched placeholder is left in the response
/// rather than substituted out, so the caller sees the synthetic
/// value verbatim.
pub fn record_reversible_redaction_miss(rule: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_ai_reversible_redaction_miss_total",
            "Reversible PII placeholders that appeared in the upstream response but did not match a request-side capture entry",
            &["rule"],
        )
        .expect("reversible redaction miss counter registers")
    });
    let rule = sanitize_label("rule", rule);
    counter.with_label_values(&[rule.as_str()]).inc();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardinality::CardinalityConfig;

    /// `/metrics` must stay parseable once a channel drop has been recorded.
    ///
    /// `record_channel_drop` used to register its counter on the private
    /// registry *and* the process-global default, while `render()` gathers and
    /// concatenates both. The family therefore came out twice, with two
    /// `# HELP` and two `# TYPE` lines for one name, which the Prometheus text
    /// format forbids and the parser rejects outright. Not a degraded scrape:
    /// no scrape.
    ///
    /// The trigger is what makes it vicious. The counter does not exist until
    /// something drops a message on a full channel, which happens when the
    /// proxy is saturated. So `/metrics` was intact every time anyone looked at
    /// it and broke at precisely the moment an operator needed it to work.
    #[test]
    fn a_channel_drop_does_not_break_the_scrape() {
        record_channel_drop("hooks", "channel_full");

        let rendered = metrics().render();

        assert!(
            rendered.contains("sbproxy_hooks_channel_dropped_total"),
            "the drop counter must reach the scrape at all"
        );

        let mut types: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        let mut helps: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for line in rendered.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                if let Some(name) = rest.split_whitespace().next() {
                    *types.entry(name).or_default() += 1;
                }
            } else if let Some(rest) = line.strip_prefix("# HELP ") {
                if let Some(name) = rest.split_whitespace().next() {
                    *helps.entry(name).or_default() += 1;
                }
            }
        }

        let dupe_types: Vec<_> = types.iter().filter(|(_, n)| **n > 1).collect();
        assert!(
            dupe_types.is_empty(),
            "the Prometheus text format allows one # TYPE per family; duplicates: {dupe_types:?}"
        );
        let dupe_helps: Vec<_> = helps.iter().filter(|(_, n)| **n > 1).collect();
        assert!(
            dupe_helps.is_empty(),
            "the Prometheus text format allows one # HELP per family; duplicates: {dupe_helps:?}"
        );
    }

    // Each test creates its own ProxyMetrics to avoid global state conflicts.
    // Helper functions that call metrics() use the global instance, so those
    // tests verify the global registry path.

    #[test]
    fn local_inference_and_savings_metrics_registered() {
        let m = ProxyMetrics::new();
        m.semantic_cache_results
            .with_label_values(&["acme", "o", "sidecar", "hit"])
            .inc();
        m.inference_requests
            .with_label_values(&["embed", "sidecar", "all-MiniLM-L6-v2", "ok"])
            .inc();
        m.inference_duration
            .with_label_values(&["embed", "sidecar", "all-MiniLM-L6-v2"])
            .observe(0.001);
        m.ai_tokens_saved
            .with_label_values(&["acme", "o", "gpt-4o", "prompt"])
            .inc_by(120);
        m.ai_cost_saved_micros
            .with_label_values(&["acme", "o", "gpt-4o"])
            .inc_by(900);
        m.agent_detect_total
            .with_label_values(&["claude-code-cli", "unsigned-named"])
            .inc();
        m.agent_detect_score.observe(91.0);
        m.agent_detect_inference_seconds.observe(0.0002);
        let names: Vec<String> = m
            .registry
            .gather()
            .iter()
            .map(|f| f.name().to_string())
            .collect();
        for expected in [
            "sbproxy_semantic_cache_results_total",
            "sbproxy_inference_requests_total",
            "sbproxy_inference_duration_seconds",
            "sbproxy_ai_tokens_saved_total",
            "sbproxy_ai_cost_saved_micros_total",
            "sbproxy_agent_detect_total",
            "sbproxy_agent_detect_score",
            "sbproxy_agent_detect_inference_seconds",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing metric {expected}"
            );
        }
    }

    #[test]
    fn test_increment_requests() {
        let m = ProxyMetrics::new();
        // Wave 1 / G1.6: requests_total now carries the 8-label set.
        // Pass empty agent labels so the test exercises the unset path.
        m.requests_total
            .with_label_values(&["example.com", "GET", "200", "", "", "", "", ""])
            .inc();
        m.requests_total
            .with_label_values(&["example.com", "GET", "200", "", "", "", "", ""])
            .inc();

        let output = m.render();
        assert!(output.contains("sbproxy_requests_total"));
        assert!(output.contains("example.com"));
    }

    #[test]
    fn test_active_connections_gauge() {
        let m = ProxyMetrics::new();
        m.active_connections.set(42);
        let output = m.render();
        assert!(output.contains("sbproxy_active_connections 42"));
    }

    #[test]
    fn test_request_duration_histogram() {
        let m = ProxyMetrics::new();
        m.request_duration
            .with_label_values(&["example.com"])
            .observe(0.05);
        let output = m.render();
        assert!(output.contains("sbproxy_request_duration_seconds"));
    }

    #[test]
    fn test_errors_total() {
        let m = ProxyMetrics::new();
        m.errors_total
            .with_label_values(&["example.com", "timeout"])
            .inc();
        let output = m.render();
        assert!(output.contains("sbproxy_errors_total"));
        assert!(output.contains("timeout"));
    }

    #[test]
    fn test_render_contains_all_metric_names() {
        let m = ProxyMetrics::new();
        // Touch each legacy metric so they appear in output.
        // requests_total carries the Wave 1 8-label set; pad agent
        // dimensions with the empty sentinel.
        m.requests_total
            .with_label_values(&["h", "GET", "200", "", "", "", "", ""])
            .inc();
        m.request_duration.with_label_values(&["h"]).observe(0.1);
        m.errors_total.with_label_values(&["h", "e"]).inc();
        m.active_connections.set(1);
        m.ai_cost_usd_micros_total
            .with_label_values(&["p", "m", "tenant-a"])
            .inc_by(42);

        // Touch each per-origin metric.
        m.per_origin_requests_total
            .with_label_values(&["h", "GET", "200"])
            .inc();
        m.per_origin_request_duration
            .with_label_values(&["h", "GET", "200"])
            .observe(0.05);
        m.per_origin_active_connections
            .with_label_values(&["h"])
            .inc();
        m.bytes_total.with_label_values(&["h", "in"]).inc_by(100.0);
        m.auth_results
            .with_label_values(&["h", "api_key", "allow"])
            .inc();
        // policy_triggers gains agent_id + agent_class (5-label set).
        m.policy_triggers
            .with_label_values(&["h", "rate_limit", "deny", "", ""])
            .inc();
        m.cache_results.with_label_values(&["h", "hit"]).inc();
        m.circuit_breaker_transitions
            .with_label_values(&["h", "closed", "open"])
            .inc();

        let output = m.render();
        assert!(output.contains("sbproxy_requests_total"));
        assert!(output.contains("sbproxy_request_duration_seconds"));
        assert!(output.contains("sbproxy_errors_total"));
        assert!(output.contains("sbproxy_active_connections"));
        assert!(output.contains("sbproxy_ai_cost_usd_micros_total"));
        assert!(output.contains("sbproxy_origin_requests_total"));
        assert!(output.contains("sbproxy_origin_request_duration_seconds"));
        assert!(output.contains("sbproxy_origin_active_connections"));
        assert!(output.contains("sbproxy_bytes_total"));
        assert!(output.contains("sbproxy_auth_results_total"));
        assert!(output.contains("sbproxy_policy_triggers_total"));
        assert!(output.contains("sbproxy_cache_results_total"));
        assert!(output.contains("sbproxy_circuit_breaker_transitions_total"));
    }

    // --- Per-origin helper function tests ---
    // These tests use the global metrics() instance. We verify the counters/gauges
    // change by checking the global ProxyMetrics directly after calling helpers.

    /// The new mirror_state_drift counter must be present in the rendered
    /// Prometheus output and increment when the helper is called.
    #[test]
    fn test_record_mirror_state_drift_increments_counter() {
        let m = metrics();
        let before = m.mirror_state_drift.get();
        record_mirror_state_drift();
        record_mirror_state_drift();
        let after = m.mirror_state_drift.get();
        assert!(
            after >= before + 2,
            "expected mirror_state_drift to gain >=2, before={before} after={after}",
        );
        let output = m.render();
        assert!(
            output.contains("sbproxy_mirror_state_drift_total"),
            "rendered output must include the new counter family",
        );
    }

    /// WOR-1131: the boilerplate strip counter must register, render in
    /// the Prometheus output, accumulate by the supplied byte count, and
    /// no-op on zero.
    #[test]
    fn test_record_boilerplate_stripped_bytes() {
        let m = metrics();
        let hostname = "test-boilerplate.example.com";
        let sanitized = sanitize_label("hostname", hostname);
        let before = m
            .boilerplate_stripped_bytes
            .with_label_values(&[&sanitized])
            .get();

        record_boilerplate_stripped_bytes(hostname, 0); // no-op
        record_boilerplate_stripped_bytes(hostname, 128);
        record_boilerplate_stripped_bytes(hostname, 64);

        let after = m
            .boilerplate_stripped_bytes
            .with_label_values(&[&sanitized])
            .get();
        assert_eq!(after, before + 192, "zero is a no-op; 128 + 64 accrue");

        let output = m.render();
        assert!(
            output.contains("sbproxy_boilerplate_stripped_bytes_total"),
            "rendered output must include the boilerplate counter family",
        );
    }

    #[test]
    fn test_record_request_increments_counters() {
        let m = metrics();

        // Prime the origin label.
        let origin = "test-record-request.example.com";
        let sanitized = sanitize_label("origin", origin);

        // Record two requests.
        record_request(origin, "GET", 200, 0.05, 1024, 512);
        record_request(origin, "GET", 200, 0.10, 2048, 256);

        let count = m
            .per_origin_requests_total
            .with_label_values(&[sanitized.as_str(), "GET", "200"])
            .get();
        assert_eq!(count, 2.0, "expected 2 requests recorded");

        let bytes_in = m
            .bytes_total
            .with_label_values(&[sanitized.as_str(), "in"])
            .get();
        assert_eq!(bytes_in, 3072.0, "bytes_in should be 1024 + 2048");

        let bytes_out = m
            .bytes_total
            .with_label_values(&[sanitized.as_str(), "out"])
            .get();
        assert_eq!(bytes_out, 768.0, "bytes_out should be 512 + 256");
    }

    #[test]
    fn test_record_auth_allow_and_deny() {
        let m = metrics();
        let origin = "test-record-auth.example.com";
        let sanitized = sanitize_label("origin", origin);

        record_auth(origin, "api_key", true);
        record_auth(origin, "api_key", false);
        record_auth(origin, "api_key", false);

        let allow_count = m
            .auth_results
            .with_label_values(&[sanitized.as_str(), "api_key", "allow"])
            .get();
        assert_eq!(allow_count, 1.0);

        let deny_count = m
            .auth_results
            .with_label_values(&[sanitized.as_str(), "api_key", "deny"])
            .get();
        assert_eq!(deny_count, 2.0);
    }

    #[test]
    fn test_record_policy_different_types() {
        let m = metrics();
        let origin = "test-record-policy.example.com";
        let sanitized = sanitize_label("origin", origin);

        record_policy(origin, "rate_limit", "deny");
        record_policy(origin, "ip_filter", "deny");
        record_policy(origin, "waf", "allow");

        // After Wave 1 G1.6 the metric carries five labels; legacy
        // record_policy stamps the agent dimensions with the empty
        // sentinel. Read back with the same label tuple.
        let rl = m
            .policy_triggers
            .with_label_values(&[sanitized.as_str(), "rate_limit", "deny", "", ""])
            .get();
        assert_eq!(rl, 1.0);

        let ip = m
            .policy_triggers
            .with_label_values(&[sanitized.as_str(), "ip_filter", "deny", "", ""])
            .get();
        assert_eq!(ip, 1.0);

        let waf = m
            .policy_triggers
            .with_label_values(&[sanitized.as_str(), "waf", "allow", "", ""])
            .get();
        assert_eq!(waf, 1.0);
    }

    #[test]
    fn test_inc_dec_active_gauge() {
        let m = metrics();
        let origin = "test-active-gauge.example.com";
        let sanitized = sanitize_label("origin", origin);

        // Gauge starts at 0 for a fresh origin label.
        let gauge = m
            .per_origin_active_connections
            .with_label_values(&[&sanitized]);
        let before = gauge.get();

        inc_active(origin);
        inc_active(origin);
        assert_eq!(gauge.get(), before + 2.0);

        dec_active(origin);
        assert_eq!(gauge.get(), before + 1.0);

        dec_active(origin);
        assert_eq!(gauge.get(), before);
    }

    #[test]
    fn test_render_includes_new_metric_families() {
        // Touch each new metric via helpers so they appear in output.
        let origin = "render-check.example.com";
        record_request(origin, "POST", 201, 0.02, 100, 50);
        record_auth(origin, "bearer", true);
        record_policy(origin, "waf", "allow");
        record_cache(origin, "miss");
        record_circuit_breaker(origin, "closed", "open");
        inc_active(origin);
        dec_active(origin);

        let output = metrics().render();
        assert!(output.contains("sbproxy_origin_requests_total"));
        assert!(output.contains("sbproxy_origin_request_duration_seconds"));
        assert!(output.contains("sbproxy_origin_active_connections"));
        assert!(output.contains("sbproxy_bytes_total"));
        assert!(output.contains("sbproxy_auth_results_total"));
        assert!(output.contains("sbproxy_policy_triggers_total"));
        assert!(output.contains("sbproxy_cache_results_total"));
        assert!(output.contains("sbproxy_circuit_breaker_transitions_total"));
    }

    #[test]
    fn test_cardinality_limiter_overflow_to_other() {
        // Use a fresh limiter with a tiny cap to test overflow.
        let lim = CardinalityLimiter::new(CardinalityConfig {
            max_per_label: 3,
            hostname_cap: None,
        });

        let a = lim.sanitize("origin", "a.com");
        let b = lim.sanitize("origin", "b.com");
        let c = lim.sanitize("origin", "c.com");
        assert_eq!(a, "a.com");
        assert_eq!(b, "b.com");
        assert_eq!(c, "c.com");

        // 4th unique origin overflows.
        let d = lim.sanitize("origin", "d.com");
        assert_eq!(d, crate::cardinality::OTHER_LABEL);

        // Previously accepted values still pass through.
        assert_eq!(lim.sanitize("origin", "a.com"), "a.com");

        // Verify unique_count did not grow beyond 3.
        assert_eq!(lim.unique_count("origin"), 3);
    }

    #[test]
    fn test_global_cardinality_limiter_origin_overflow() {
        // Fill the global limiter's "origin_overflow_test" label to its cap
        // via a dedicated limiter (we can't reset the global one safely in tests).
        let lim = CardinalityLimiter::new(CardinalityConfig {
            max_per_label: 1000,
            hostname_cap: None,
        });
        for i in 0..1000 {
            lim.sanitize("origin", &format!("overflow-origin-{i}.example.com"));
        }
        // The 1001st origin must be remapped to __other__.
        let result = lim.sanitize("origin", "overflow-origin-1001.example.com");
        assert_eq!(result, crate::cardinality::OTHER_LABEL);
    }

    // --- Wave 1 / G1.6 per-agent label tests ---

    #[test]
    fn record_request_with_labels_stamps_agent_dimensions() {
        let m = metrics();
        let origin = "test-with-labels.example.com";
        let agent = AgentLabels {
            agent_id: "openai-gptbot",
            agent_class: "training",
            agent_vendor: "openai",
            payment_rail: "x402",
            content_shape: "html",
        };
        record_request_with_labels(origin, "GET", 200, 0.01, 0, 0, agent);

        // Look up using whatever the limiter actually stored. Other
        // tests run in the same process and may have filled the
        // global limiter for one of these labels, in which case the
        // recorded value is `__other__`. Read via the same sanitiser
        // so the test works either way.
        let origin_san = sanitize_label("origin", origin);
        let agent_id_san =
            sanitize_label_budget("sbproxy_requests_total", "agent_id", agent.agent_id);
        let agent_class_san =
            sanitize_label_budget("sbproxy_requests_total", "agent_class", agent.agent_class);
        let agent_vendor_san =
            sanitize_label_budget("sbproxy_requests_total", "agent_vendor", agent.agent_vendor);
        let payment_rail_san =
            sanitize_label_budget("sbproxy_requests_total", "payment_rail", agent.payment_rail);
        let content_shape_san = sanitize_label_budget(
            "sbproxy_requests_total",
            "content_shape",
            agent.content_shape,
        );
        let count = m
            .requests_total
            .with_label_values(&[
                origin_san.as_str(),
                "GET",
                "200",
                agent_id_san.as_str(),
                agent_class_san.as_str(),
                agent_vendor_san.as_str(),
                payment_rail_san.as_str(),
                content_shape_san.as_str(),
            ])
            .get();
        assert!(count >= 1, "agent-labelled request must increment");
    }

    #[test]
    fn record_request_legacy_uses_empty_sentinel() {
        let m = metrics();
        let origin = "test-legacy-empty.example.com";
        record_request(origin, "POST", 201, 0.0, 0, 0);

        let origin_san = sanitize_label("origin", origin);
        // Legacy path attributes the increment to the empty-sentinel
        // tuple, which is the "no agent context attached" series.
        let count = m
            .requests_total
            .with_label_values(&[origin_san.as_str(), "POST", "201", "", "", "", "", ""])
            .get();
        assert_eq!(count, 1, "legacy record_request must use empty sentinel");
    }

    #[test]
    fn record_agent_detect_stamps_labels_and_histograms() {
        let m = metrics();
        record_agent_detect(Some("claude-code-cli"), "unsigned-named", 88, 0.0003);

        let agent_id =
            sanitize_label_budget("sbproxy_agent_detect_total", "agent_id", "claude-code-cli");
        let count = m
            .agent_detect_total
            .with_label_values(&[agent_id.as_str(), "unsigned-named"])
            .get();
        assert!(count >= 1, "agent-detect counter must increment");

        let out = metrics().render();
        assert!(out.contains("sbproxy_agent_detect_score_bucket"));
        assert!(out.contains("sbproxy_agent_detect_inference_seconds_bucket"));
    }

    #[test]
    fn record_policy_with_labels_stamps_agent_id() {
        let m = metrics();
        let origin = "test-policy-labels.example.com";
        let agent = AgentLabels {
            agent_id: "anthropic-claudebot",
            agent_class: "training",
            agent_vendor: "anthropic",
            payment_rail: "",
            content_shape: "",
        };
        record_policy_with_labels(origin, "rate_limit", "deny", agent);

        let origin_san = sanitize_label("origin", origin);
        let agent_id_san =
            sanitize_label_budget("sbproxy_policy_triggers_total", "agent_id", agent.agent_id);
        let agent_class_san = sanitize_label_budget(
            "sbproxy_policy_triggers_total",
            "agent_class",
            agent.agent_class,
        );
        let count = m
            .policy_triggers
            .with_label_values(&[
                origin_san.as_str(),
                "rate_limit",
                "deny",
                agent_id_san.as_str(),
                agent_class_san.as_str(),
            ])
            .get();
        assert!(count >= 1.0, "policy trigger must stamp agent_id");
    }

    #[test]
    fn sanitize_label_budget_passes_through_empty_sentinel() {
        // Empty string never consumes the budget; this is what makes
        // the legacy fast-path safe.
        for _ in 0..1_000 {
            assert_eq!(
                sanitize_label_budget("sbproxy_requests_total", "agent_id", ""),
                ""
            );
        }
    }

    #[test]
    fn sanitize_label_budget_overflow_emits_other_and_increments_counter() {
        // Pin a unique label name so this test does not collide with
        // the global limiter's other tests. The agent_class budget
        // (8) is the lowest one in the table; we exercise the
        // overflow path through that.
        //
        // We can't reset the global limiter mid-process, so use a
        // label name that's effectively private to this test.
        // The overflow counter is keyed on (metric, label) so we can
        // isolate it by metric name.
        let metric_name = "sbproxy_test_g16_overflow_metric";
        // Use a label that has a per-label budget pulled from the
        // ADR table.
        let label = "agent_class";

        // Fill the global limiter for `agent_class` up to its ADR
        // budget (8). Each test process shares the limiter, so this
        // may collide with other tests filling agent_class. Use
        // lots of distinct values so the cap is definitely reached.
        for i in 0..16 {
            let _ = sanitize_label_budget(metric_name, label, &format!("test-overflow-cls-{i}"));
        }

        // After 8+ unique values, fresh ones must demote to __other__.
        let demoted =
            sanitize_label_budget(metric_name, label, "test-overflow-cls-definitely-fresh");
        assert_eq!(demoted, crate::cardinality::OTHER_LABEL);

        // The overflow counter must have been touched.
        let counter = overflow_counter();
        let observed = counter.with_label_values(&[metric_name, label]).get();
        assert!(
            observed >= 1,
            "overflow counter for ({metric_name},{label}) must be >= 1, was {observed}"
        );
    }

    // --- WOR-75: exemplar wiring on the four new histograms ---
    //
    // Each test exercises the helper end-to-end (histogram observe +
    // exemplar record). The render fragment proves the bucket
    // landed; the `last_recorded_for_test` probe proves the exemplar
    // landed. Labels include a per-test unique value so parallel
    // runners do not stomp the global exemplar store.

    #[test]
    fn record_ledger_redeem_duration_emits_bucket_and_exemplar() {
        let host = "ledger-host-uniq.example.com";
        record_ledger_redeem_duration(host, "success", 0.004);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_ledger_redeem_duration_seconds"),
            "histogram family missing from render:\n{out}"
        );
        // Hostname is sanitised through the cardinality limiter so we
        // look up the exemplar by the sanitised form to match what
        // the helper recorded.
        let host_san = sanitize_label("host", host);
        let ex = crate::exemplars::last_recorded_for_test(
            "sbproxy_ledger_redeem_duration_seconds",
            &[("host", host_san.as_str()), ("outcome", "success")],
        );
        assert!(
            ex.is_some(),
            "expected an exemplar for ledger_redeem; store entry missing"
        );
        let ex = ex.expect("exemplar present");
        assert!((ex.value - 0.004).abs() < f64::EPSILON);
    }

    #[test]
    fn record_policy_evaluation_duration_emits_bucket_and_exemplar() {
        let origin = "policy-origin-uniq.example.com";
        record_policy_evaluation_duration(origin, "allow", 0.012);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_policy_evaluation_duration_seconds"),
            "histogram family missing from render:\n{out}"
        );
        let origin_san = sanitize_label("origin", origin);
        let ex = crate::exemplars::last_recorded_for_test(
            "sbproxy_policy_evaluation_duration_seconds",
            &[("origin", origin_san.as_str()), ("verdict", "allow")],
        );
        assert!(
            ex.is_some(),
            "expected an exemplar for policy_evaluation; store entry missing"
        );
    }

    #[test]
    fn record_outbound_request_duration_emits_bucket_and_exemplar() {
        let host = "outbound-host-uniq.example.com";
        record_outbound_request_duration(host, "GET", "200", 0.030);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_outbound_request_duration_seconds"),
            "histogram family missing from render:\n{out}"
        );
        let host_san = sanitize_label("host", host);
        let ex = crate::exemplars::last_recorded_for_test(
            "sbproxy_outbound_request_duration_seconds",
            &[
                ("host", host_san.as_str()),
                ("method", "GET"),
                ("status", "200"),
            ],
        );
        assert!(
            ex.is_some(),
            "expected an exemplar for outbound_request; store entry missing"
        );
    }

    #[test]
    fn record_audit_emit_duration_emits_bucket_and_exemplar() {
        record_audit_emit_duration("config", "ok", 0.0015);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_audit_emit_duration_seconds"),
            "histogram family missing from render:\n{out}"
        );
        let ex = crate::exemplars::last_recorded_for_test(
            "sbproxy_audit_emit_duration_seconds",
            &[("channel", "config"), ("outcome", "ok")],
        );
        assert!(
            ex.is_some(),
            "expected an exemplar for audit_emit; store entry missing"
        );
    }

    // --- script-engine metrics (CEL / Lua / JS / WASM) ---

    #[test]
    fn record_script_compile_emits_counter() {
        record_script_compile("cel", "ok");
        record_script_compile("cel", "parse_error");
        record_script_compile("lua", "ok");
        record_script_compile("js", "sandbox_reject");
        record_script_compile("wasm", "ok");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_script_compile_total"),
            "compile counter missing from render"
        );
        for engine in ["cel", "lua", "js", "wasm"] {
            assert!(
                out.contains(&format!("engine=\"{engine}\"")),
                "engine={engine} label missing from render"
            );
        }
    }

    #[test]
    fn record_script_invocation_emits_counter() {
        record_script_invocation("cel", "ok");
        record_script_invocation("lua", "runtime_error");
        record_script_invocation("js", "timeout");
        record_script_invocation("wasm", "memory_cap");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_script_invocations_total"),
            "invocations counter missing from render"
        );
        for result in ["ok", "runtime_error", "timeout", "memory_cap"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
    }

    #[test]
    fn record_script_duration_emits_histogram_buckets() {
        record_script_duration("cel", 0.002);
        record_script_duration("cel", 0.150);
        record_script_duration("wasm", 1.5);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_script_duration_seconds_bucket"),
            "duration buckets missing from render"
        );
        assert!(
            out.contains("sbproxy_script_duration_seconds_count"),
            "duration count missing from render"
        );
    }

    #[test]
    fn record_script_reload_emits_counter() {
        record_script_reload("lua", "ok");
        record_script_reload("js", "parse_error");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_script_reloads_total"),
            "reload counter missing from render"
        );
    }

    // --- rate-limit + idempotency ---

    #[test]
    fn record_rate_limit_decision_emits_counter() {
        record_rate_limit_decision("/api/*", "allow");
        record_rate_limit_decision("/api/*", "throttle_route");
        record_rate_limit_decision("/billing", "throttle_tenant");
        record_rate_limit_decision("__default__", "disabled");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_rate_limit_decisions_total"),
            "rate-limit counter missing from render"
        );
        for result in ["allow", "throttle_route", "throttle_tenant", "disabled"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
    }

    #[test]
    fn record_idempotency_cache_result_emits_counter() {
        record_idempotency_cache_result("default", "hit");
        record_idempotency_cache_result("default", "miss");
        record_idempotency_cache_result("default", "conflict");
        record_idempotency_cache_result("default", "not_applicable");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_idempotency_cache_results_total"),
            "idempotency results counter missing from render"
        );
        for result in ["hit", "miss", "conflict", "not_applicable"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
    }

    #[test]
    fn record_idempotency_cache_duration_emits_histogram() {
        record_idempotency_cache_duration("default", 0.0005);
        record_idempotency_cache_duration("default", 0.02);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_idempotency_cache_duration_seconds_bucket"),
            "idempotency duration buckets missing"
        );
    }

    // --- body + compression ---

    #[test]
    fn record_response_body_bytes_emits_histogram() {
        record_response_body_bytes("pre_compress", 4096);
        record_response_body_bytes("post_compress", 1200);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_response_body_bytes_bucket"),
            "response body bytes buckets missing"
        );
        for direction in ["pre_compress", "post_compress"] {
            assert!(
                out.contains(&format!("direction=\"{direction}\"")),
                "direction={direction} label missing"
            );
        }
    }

    #[test]
    fn record_compression_decision_emits_counter() {
        record_compression_decision("gzip", "applied");
        record_compression_decision("br", "skipped_size");
        record_compression_decision("zstd", "skipped_accept");
        record_compression_decision("identity", "disabled");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_compression_decisions_total"),
            "compression decision counter missing"
        );
        for codec in ["gzip", "br", "zstd", "identity"] {
            assert!(
                out.contains(&format!("codec=\"{codec}\"")),
                "codec={codec} label missing"
            );
        }
        for result in ["applied", "skipped_size", "skipped_accept", "disabled"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
    }

    #[test]
    fn record_compression_ratio_emits_histogram() {
        record_compression_ratio("gzip", 0.3);
        record_compression_ratio("zstd", 0.15);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_compression_ratio_bucket"),
            "compression ratio buckets missing"
        );
    }

    // --- plugin registry ---

    #[test]
    fn record_plugin_registered_emits_counter() {
        record_plugin_registered("auth", "saml");
        record_plugin_registered("action", "my-action");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_plugin_registered_total"),
            "plugin registered counter missing"
        );
        assert!(out.contains("kind=\"auth\""), "kind=auth label missing");
        assert!(out.contains("kind=\"action\""), "kind=action label missing");
    }

    #[test]
    fn record_plugin_init_emits_counter_and_histogram() {
        record_plugin_init("auth", "saml", "ok", 0.012);
        record_plugin_init("auth", "saml", "config_invalid", 0.001);
        record_plugin_init("action", "my-action", "panic", 0.5);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_plugin_init_total"),
            "plugin init counter missing"
        );
        assert!(
            out.contains("sbproxy_plugin_init_duration_seconds_bucket"),
            "plugin init duration buckets missing"
        );
        for result in ["ok", "config_invalid", "panic"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
    }

    // --- TLS / ACME / OCSP ---

    #[test]
    fn record_acme_renewal_emits_counter_and_histogram() {
        record_acme_renewal("ok", 12.4);
        record_acme_renewal("http_error", 2.0);
        record_acme_renewal("rate_limited", 0.5);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_acme_renewals_total"),
            "acme renewal counter missing"
        );
        assert!(
            out.contains("sbproxy_acme_renewal_duration_seconds_bucket"),
            "acme renewal duration buckets missing"
        );
        for result in ["ok", "http_error", "rate_limited"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
    }

    #[test]
    fn record_ocsp_fetch_emits_counter() {
        record_ocsp_fetch("ok");
        record_ocsp_fetch("parse_error");
        record_ocsp_fetch("no_responder");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_ocsp_fetch_total"),
            "ocsp fetch counter missing"
        );
        for result in ["ok", "parse_error", "no_responder"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
    }

    #[test]
    fn record_cert_expiry_emits_gauge() {
        record_cert_expiry("api.example.com", 7.0 * 86_400.0);
        record_cert_expiry("static.example.com", -100.0);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_cert_expiry_seconds"),
            "cert expiry gauge missing"
        );
        for host in ["api.example.com", "static.example.com"] {
            assert!(
                out.contains(&format!("host=\"{host}\"")),
                "host={host} label missing"
            );
        }
    }

    // --- vault ---

    #[test]
    fn record_vault_resolution_emits_counter_and_histogram() {
        record_vault_resolution("hashicorp", "ok", 0.012);
        record_vault_resolution("hashicorp", "backend_error", 1.5);
        record_vault_resolution("aws_secrets_manager", "not_found", 0.05);
        record_vault_resolution("file", "denied", 0.0001);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_vault_resolution_total"),
            "vault resolution counter missing"
        );
        assert!(
            out.contains("sbproxy_vault_resolution_duration_seconds_bucket"),
            "vault resolution duration buckets missing"
        );
        for result in ["ok", "backend_error", "not_found", "denied"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
    }

    // --- transport ---

    #[test]
    fn record_transport_request_emits_counter_and_histogram() {
        record_transport_request("grpc", "ok", 0.005);
        record_transport_request("grpc", "upstream_error", 0.1);
        record_transport_request("websocket", "timeout", 2.0);
        record_transport_request("h3", "client_error", 0.001);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_transport_requests_total"),
            "transport requests counter missing"
        );
        assert!(
            out.contains("sbproxy_transport_duration_seconds_bucket"),
            "transport duration buckets missing"
        );
        for protocol in ["grpc", "websocket", "h3"] {
            assert!(
                out.contains(&format!("protocol=\"{protocol}\"")),
                "protocol={protocol} label missing"
            );
        }
    }

    #[test]
    fn record_grpc_status_emits_counter() {
        record_grpc_status("ok");
        record_grpc_status("not_found");
        record_grpc_status("unavailable");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_grpc_status_total"),
            "grpc status counter missing"
        );
        for code in ["ok", "not_found", "unavailable"] {
            assert!(
                out.contains(&format!("code=\"{code}\"")),
                "code={code} label missing"
            );
        }
    }

    #[test]
    fn grpc_status_label_covers_canonical_codes() {
        assert_eq!(grpc_status_label(0), "ok");
        assert_eq!(grpc_status_label(5), "not_found");
        assert_eq!(grpc_status_label(14), "unavailable");
        assert_eq!(grpc_status_label(16), "unauthenticated");
        assert_eq!(grpc_status_label(99), "unknown");
    }

    // --- MCP server metrics ---

    #[test]
    fn record_mcp_tool_dispatch_emits_counter_and_histogram() {
        record_mcp_tool_dispatch("get_user", "ok", 0.012);
        record_mcp_tool_dispatch("get_user", "tool_error", 0.5);
        record_mcp_tool_dispatch("delete_user", "policy_denied", 0.0001);
        record_mcp_tool_dispatch("unknown_tool", "tool_not_found", 0.0001);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_mcp_tool_dispatch_total"),
            "mcp tool dispatch counter missing"
        );
        assert!(
            out.contains("sbproxy_mcp_tool_dispatch_duration_seconds_bucket"),
            "mcp tool dispatch duration buckets missing"
        );
        for result in ["ok", "tool_error", "policy_denied", "tool_not_found"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
    }

    #[test]
    fn record_mcp_resource_fetch_emits_counter() {
        record_mcp_resource_fetch("ok");
        record_mcp_resource_fetch("not_found");
        record_mcp_resource_fetch("upstream_error");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_mcp_resource_fetch_total"),
            "mcp resource fetch counter missing"
        );
    }

    #[test]
    fn set_mcp_federation_peers_up_emits_gauge() {
        set_mcp_federation_peers_up(3);
        set_mcp_federation_peers_up(0);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_mcp_federation_peers_up"),
            "mcp federation peers gauge missing"
        );
    }

    // --- model host metrics (WOR-1659) ---

    #[test]
    fn model_host_metrics_emit() {
        record_model_host_time_to_ready("vllm", "qwen3-32b", "ready", 12.5);
        record_model_host_time_to_ready("vllm", "qwen3-32b", "failed", 0.0);
        record_model_host_eviction("lru");
        set_model_host_resident_models(2);
        set_model_host_load_queue_depth("qwen3-32b", 4);
        set_model_host_gpu_stats(
            "0",
            24 * 1024 * 1024 * 1024,
            8 * 1024 * 1024 * 1024,
            Some(0.42),
            Some(2.0 / 3.0),
        );
        set_model_host_gpu_stats("unknown", 1024, 512, None, Some(0.5));
        set_model_host_deployment_requests("qwen3-32b", 2, 4);
        set_model_host_deployment_state("qwen3-32b", "vllm", "ready");
        record_model_host_admission_rejection("qwen3-32b", "interactive", "queue_full");
        // WOR-1709 / WOR-1711 / WOR-1712 additions.
        record_model_host_lora_load();
        record_model_host_lora_eviction();
        set_model_host_resident_adapters(3);
        record_model_host_ensure_failure("fit");
        record_model_host_weight_download(1_000_000, 4.2, true);
        record_model_host_weight_download(0, 0.5, false);
        let out = metrics().render();
        for name in [
            "sbproxy_model_host_time_to_ready_seconds",
            "sbproxy_model_host_launches_total",
            "sbproxy_model_host_evictions_total",
            "sbproxy_model_host_resident_models",
            "sbproxy_model_host_load_queue_depth",
            "sbproxy_model_host_gpu_vram_bytes",
            "sbproxy_model_host_gpu_utilization",
            "sbproxy_model_host_gpu_memory_occupancy",
            "sbproxy_model_host_active_requests",
            "sbproxy_model_host_queued_requests",
            "sbproxy_model_host_deployment_state",
            "sbproxy_model_host_admission_rejections_total",
            "sbproxy_model_host_lora_loads_total",
            "sbproxy_model_host_lora_evictions_total",
            "sbproxy_model_host_resident_adapters",
            "sbproxy_model_host_ensure_failures_total",
            "sbproxy_model_host_weight_download_bytes_total",
            "sbproxy_model_host_weight_download_failures_total",
            "sbproxy_model_host_weight_download_seconds",
        ] {
            assert!(out.contains(name), "missing model-host metric {name}");
        }
        assert!(out.contains("sbproxy_model_host_gpu_utilization{device=\"0\"} 0.42"));
        assert!(!out.contains("sbproxy_model_host_gpu_utilization{device=\"unknown\"}"));
        assert!(out.contains("sbproxy_model_host_gpu_memory_occupancy{device=\"unknown\"} 0.5"));
        assert!(out.contains("sbproxy_model_host_active_requests{deployment=\"qwen3-32b\"} 2"));
        assert!(out.contains("sbproxy_model_host_queued_requests{deployment=\"qwen3-32b\"} 4"));
        assert!(out.contains(
            "sbproxy_model_host_deployment_state{deployment=\"qwen3-32b\",engine=\"vllm\",state=\"ready\"} 1"
        ));
        assert!(out.contains(
            "sbproxy_model_host_admission_rejections_total{deployment=\"qwen3-32b\",priority=\"interactive\",reason=\"queue_full\"} 1"
        ));
    }

    // --- k8s operator metrics ---

    #[test]
    fn record_operator_reconcile_emits_counter_and_histogram() {
        record_operator_reconcile("sbproxy", "ok", 0.12);
        record_operator_reconcile("sbproxy", "conflict", 0.001);
        record_operator_reconcile("sbproxyconfig", "backend_error", 2.5);
        record_operator_reconcile("sbproxy", "crd_invalid", 0.005);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_operator_reconcile_total"),
            "operator reconcile counter missing"
        );
        assert!(
            out.contains("sbproxy_operator_reconcile_duration_seconds_bucket"),
            "operator reconcile duration buckets missing"
        );
        for result in ["ok", "conflict", "backend_error", "crd_invalid"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
    }

    #[test]
    fn record_operator_leader_transition_emits_counter() {
        record_operator_leader_transition("elected");
        record_operator_leader_transition("renewed");
        record_operator_leader_transition("lost");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_operator_leader_transitions_total"),
            "operator leader transitions counter missing"
        );
        for result in ["elected", "renewed", "lost"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
    }

    #[test]
    fn set_operator_leader_is_leader_emits_gauge() {
        set_operator_leader_is_leader(true);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_operator_leader_is_leader"),
            "operator leader gauge missing"
        );
        set_operator_leader_is_leader(false);
    }

    // --- per-credential token attribution ---

    #[test]
    fn record_tokens_attributed_emits_counter_with_four_labels() {
        record_tokens_attributed("frontend", "alice", "team:frontend", "input", 1234);
        record_tokens_attributed("frontend", "alice", "team:frontend", "output", 567);
        record_tokens_attributed("billing", "bob", "env:prod", "input", 42);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_tokens_attributed_total"),
            "tokens attributed counter missing"
        );
        for label_check in [
            "project=\"frontend\"",
            "project=\"billing\"",
            "user=\"alice\"",
            "user=\"bob\"",
            "tag=\"team:frontend\"",
            "tag=\"env:prod\"",
            "direction=\"input\"",
            "direction=\"output\"",
        ] {
            assert!(
                out.contains(label_check),
                "expected {label_check} in render"
            );
        }
    }

    #[test]
    fn record_tokens_attributed_skips_zero_count() {
        record_tokens_attributed("a", "b", "", "input", 0);
        // No row added; the assertion is that the call does not
        // panic and does not create a noise row for zero-count
        // observations.
    }

    #[test]
    fn record_ai_cost_usd_micros_emits_counter_with_provider_model_tenant() {
        record_ai_cost_usd_micros("openai", "gpt-4o", "acme", 1_234);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_ai_cost_usd_micros_total"),
            "AI cost micros counter missing"
        );
        for label_check in [
            "provider=\"openai\"",
            "model=\"gpt-4o\"",
            "tenant_id=\"acme\"",
        ] {
            assert!(
                out.contains(label_check),
                "expected {label_check} in render"
            );
        }
    }

    #[test]
    fn record_ai_cost_usd_micros_skips_zero_cost() {
        record_ai_cost_usd_micros("openai", "gpt-4o", "acme", 0);
    }
}
