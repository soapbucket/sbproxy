use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use prometheus::{
    CounterVec, Encoder, GaugeVec, HistogramVec, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};

use crate::agent_labels::AgentLabels;
use crate::cardinality::{CardinalityConfig, CardinalityLimiter};

// --- Scrape rate limiter ---

static LAST_SCRAPE: AtomicU64 = AtomicU64::new(0);

/// Minimum milliseconds required between two consecutive metrics scrapes.
const MIN_SCRAPE_INTERVAL_MS: u64 = 1_000;

/// Check if a metrics scrape is allowed based on a 1-second minimum interval.
///
/// Uses a compare-and-swap on an atomic timestamp so this function is
/// lock-free and safe to call from multiple threads simultaneously.
/// Returns `true` when the scrape is permitted and the timestamp is updated.
/// Returns `false` when the last scrape was too recent.
pub fn allow_scrape() -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let last = LAST_SCRAPE.load(Ordering::Relaxed);
    if now.saturating_sub(last) < MIN_SCRAPE_INTERVAL_MS {
        return false;
    }
    // Best-effort CAS: if another thread wins, we still return false for this
    // call, which is safe (the caller can retry on the next request).
    LAST_SCRAPE
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

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

/// Sanitize a label value against the per-label budget defined in
/// `docs/adr-metric-cardinality.md`. Empty strings pass through
/// unchanged because they are the explicit "no agent context attached"
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
    /// Counter `sbproxy_cache_hits_total` of cache hits and misses labelled by hostname.
    pub cache_hits: IntCounterVec,
    /// Counter `sbproxy_ai_tokens_total` of AI token usage labelled by hostname, provider, and direction.
    pub ai_tokens_total: IntCounterVec,

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

        let cache_hits = IntCounterVec::new(
            Opts::new("sbproxy_cache_hits_total", "Cache hit/miss counts"),
            &["hostname", "result"], // "hit" or "miss"
        )
        .unwrap();

        let ai_tokens_total = IntCounterVec::new(
            Opts::new("sbproxy_ai_tokens_total", "AI token usage"),
            &["hostname", "provider", "direction"], // "input" or "output"
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

        // --- Register all metrics ---

        registry.register(Box::new(requests_total.clone())).unwrap();
        registry
            .register(Box::new(request_duration.clone()))
            .unwrap();
        registry.register(Box::new(errors_total.clone())).unwrap();
        registry
            .register(Box::new(active_connections.clone()))
            .unwrap();
        registry.register(Box::new(cache_hits.clone())).unwrap();
        registry
            .register(Box::new(ai_tokens_total.clone()))
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

        Self {
            registry,
            requests_total,
            request_duration,
            errors_total,
            active_connections,
            cache_hits,
            ai_tokens_total,
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
        if encoder.encode(&metric_families, &mut buffer).is_err() {
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
/// cardinality budget from `docs/adr-metric-cardinality.md` is enforced
/// before the value reaches Prometheus. Overflow values are demoted to
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
    let origin_san = sanitize_label("origin", origin);
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
    // Sanitised hostname is reused via origin_san (cardinality cap
    // 200 per ADR; same numeric cap, different label name).
    m.requests_total
        .with_label_values(&[
            &origin_san,
            method,
            &status_str,
            &agent_id,
            &agent_class,
            &agent_vendor,
            &payment_rail,
            &content_shape,
        ])
        .inc();

    // --- Per-origin views (unchanged label set; pre-existing) ---
    m.per_origin_requests_total
        .with_label_values(&[&origin_san, method, &status_str])
        .inc();
    m.per_origin_request_duration
        .with_label_values(&[&origin_san, method, &status_str])
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
            .with_label_values(&[&origin_san, "in"])
            .inc_by(bytes_in as f64);
    }
    if bytes_out > 0 {
        m.bytes_total
            .with_label_values(&[&origin_san, "out"])
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
        .with_label_values(&[&origin, auth_type, result])
        .inc();
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
        .with_label_values(&[&origin_san, policy_type, action, &agent_id, &agent_class])
        .inc();
}

/// Record a Wave 8 capture-budget drop (T2.3 / T3.3). `dimension` is
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
            "Wave 8 envelope dimensions dropped because the per-workspace budget was exhausted",
            &["workspace", "dimension"],
        )
        .expect("capture budget counter registers")
    });
    let workspace = sanitize_label("workspace", workspace_id);
    counter.with_label_values(&[&workspace, dimension]).inc();
}

/// Record drop counters returned by the Wave 8 capture helpers.
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
            "Wave 8 envelope dimensions dropped during capture, by reason",
            &["workspace", "dimension", "reason"],
        )
        .expect("capture drop counter registers")
    });
    let workspace = sanitize_label("workspace", workspace_id);
    counter
        .with_label_values(&[&workspace, dimension, reason])
        .inc_by(n);
}

/// Record one A2A hop (Wave 7 / A7.2). `decision` is `"allow"` or
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
    counter.with_label_values(&[&route, spec, decision]).inc();
}

/// Record an A2A chain depth observation (Wave 7 / A7.2). Surfaces
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
    hist.with_label_values(&[&route, spec])
        .observe(depth as f64);
}

/// Record an A2A denial (Wave 7 / A7.2). `reason` is one of
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
    counter.with_label_values(&[&route, reason]).inc();
}

/// Record a request blocked by the `http_framing` policy. The
/// `reason` label is one of the stable strings from
/// `FramingViolation::metric_reason` (`dual_cl_te`, `duplicate_cl`,
/// `malformed_te`, `duplicate_te`, `control_chars`). Cardinality is
/// bounded at five and locked by the policy.
pub fn record_http_framing_block(reason: &str) {
    use prometheus::{register_counter_vec, CounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<CounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_counter_vec!(
            "sbproxy_http_framing_blocks_total",
            "Requests rejected by the http_framing policy (request smuggling defense)",
            &["reason"],
        )
        .expect("counter vec registers")
    });
    counter.with_label_values(&[reason]).inc();
}

/// Record a cache result (hit or miss) for an origin.
pub fn record_cache(origin: &str, result: &str) {
    let origin = sanitize_label("origin", origin);
    metrics()
        .cache_results
        .with_label_values(&[&origin, result])
        .inc();
}

/// Record a circuit breaker state transition for an origin.
pub fn record_circuit_breaker(origin: &str, from_state: &str, to_state: &str) {
    let origin = sanitize_label("origin", origin);
    metrics()
        .circuit_breaker_transitions
        .with_label_values(&[&origin, from_state, to_state])
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardinality::CardinalityConfig;

    // Each test creates its own ProxyMetrics to avoid global state conflicts.
    // Helper functions that call metrics() use the global instance, so those
    // tests verify the global registry path.

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
    fn test_cache_hits() {
        let m = ProxyMetrics::new();
        m.cache_hits
            .with_label_values(&["example.com", "hit"])
            .inc();
        m.cache_hits
            .with_label_values(&["example.com", "miss"])
            .inc_by(3);
        let output = m.render();
        assert!(output.contains("sbproxy_cache_hits_total"));
    }

    #[test]
    fn test_ai_tokens() {
        let m = ProxyMetrics::new();
        m.ai_tokens_total
            .with_label_values(&["example.com", "openai", "input"])
            .inc_by(500);
        let output = m.render();
        assert!(output.contains("sbproxy_ai_tokens_total"));
        assert!(output.contains("openai"));
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
        m.cache_hits.with_label_values(&["h", "hit"]).inc();
        m.ai_tokens_total
            .with_label_values(&["h", "p", "input"])
            .inc();

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
        assert!(output.contains("sbproxy_cache_hits_total"));
        assert!(output.contains("sbproxy_ai_tokens_total"));
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
            .with_label_values(&[&sanitized, "GET", "200"])
            .get();
        assert_eq!(count, 2.0, "expected 2 requests recorded");

        let bytes_in = m.bytes_total.with_label_values(&[&sanitized, "in"]).get();
        assert_eq!(bytes_in, 3072.0, "bytes_in should be 1024 + 2048");

        let bytes_out = m.bytes_total.with_label_values(&[&sanitized, "out"]).get();
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
            .with_label_values(&[&sanitized, "api_key", "allow"])
            .get();
        assert_eq!(allow_count, 1.0);

        let deny_count = m
            .auth_results
            .with_label_values(&[&sanitized, "api_key", "deny"])
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
            .with_label_values(&[&sanitized, "rate_limit", "deny", "", ""])
            .get();
        assert_eq!(rl, 1.0);

        let ip = m
            .policy_triggers
            .with_label_values(&[&sanitized, "ip_filter", "deny", "", ""])
            .get();
        assert_eq!(ip, 1.0);

        let waf = m
            .policy_triggers
            .with_label_values(&[&sanitized, "waf", "allow", "", ""])
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
        let lim = CardinalityLimiter::new(CardinalityConfig { max_per_label: 3 });

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
                &origin_san,
                "GET",
                "200",
                &agent_id_san,
                &agent_class_san,
                &agent_vendor_san,
                &payment_rail_san,
                &content_shape_san,
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
            .with_label_values(&[&origin_san, "POST", "201", "", "", "", "", ""])
            .get();
        assert_eq!(count, 1, "legacy record_request must use empty sentinel");
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
                &origin_san,
                "rate_limit",
                "deny",
                &agent_id_san,
                &agent_class_san,
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

    // --- allow_scrape rate limiter ---
    //
    // The three `allow_scrape_*` tests share the process-global
    // `LAST_SCRAPE` atomic. Without serialisation, parallel `cargo test`
    // workers race: one test stores its desired state, the scheduler
    // preempts, another test stores a different value, then the first
    // test's assertion runs against the second test's state and fails
    // intermittently. Hold this mutex for the duration of each test to
    // make them run serially with respect to one another while still
    // running in parallel with the rest of the suite.
    static SCRAPE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn allow_scrape_first_call_is_permitted() {
        let _guard = SCRAPE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Reset the global atomic so this test is not order-dependent.
        LAST_SCRAPE.store(0, Ordering::Relaxed);
        assert!(allow_scrape(), "first scrape after reset must be allowed");
    }

    #[test]
    fn allow_scrape_immediate_second_call_is_denied() {
        let _guard = SCRAPE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Prime the atomic to "just now" so any immediate follow-up is blocked.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        LAST_SCRAPE.store(now, Ordering::Relaxed);
        assert!(!allow_scrape(), "second scrape within 1 s must be denied");
    }

    #[test]
    fn allow_scrape_after_interval_is_permitted() {
        let _guard = SCRAPE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Simulate that the last scrape happened more than 1 second ago.
        let past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - 2_000; // 2 seconds in the past
        LAST_SCRAPE.store(past, Ordering::Relaxed);
        assert!(allow_scrape(), "scrape after interval must be allowed");
    }
}
