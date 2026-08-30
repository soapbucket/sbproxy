use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::Instant;

use prometheus::{
    CounterVec, Encoder, GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};

use crate::agent_labels::AgentLabels;
use crate::cardinality::{CardinalityConfig, CardinalityLimiter};
use crate::decision::{DecisionEvent, DecisionOutcome};

/// Keep a metric that built and registered, or drop it and say which
/// one went.
///
/// Construction fails only on an illegal metric or label name and
/// registration only on a duplicate family, so both are build-time
/// mistakes: every name in this file is a literal and the constructor
/// below runs once per registry. The `debug_assert`
/// makes either one a test failure. In a release build the family is
/// dropped and the writes through it become no-ops, because a proxy
/// that cannot chart a number must still answer the request that
/// would have produced it.
///
/// What this cannot do: bring the family back, or tell an operator
/// anything beyond the one warning. A process that lost a family stays
/// without it until it restarts.
fn kept<M>(result: prometheus::Result<M>, family: &'static str) -> Option<M> {
    match result {
        Ok(metric) => Some(metric),
        Err(error) => {
            debug_assert!(
                false,
                "metric family {family} must build and register exactly once: {error}"
            );
            tracing::warn!(
                metric = family,
                %error,
                "metric family did not register; every panel reading it stays flat for this process"
            );
            None
        }
    }
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

// --- Cardinality headroom gauges ---

/// Gauges `sbproxy_label_cardinality_unique_values{label}` and
/// `sbproxy_label_cardinality_budget{label}`.
///
/// The overflow counter above only moves once a label has *already*
/// collapsed. That is the wrong moment to find out in a multi-tenant
/// deployment: the collapse merges tenants into one `__other__` series,
/// so a per-tenant panel keeps drawing and quietly starts answering a
/// different question, and the only tell is noticing `__other__` in a
/// query result. These two gauges are the before-picture, so
/// `unique_values / budget > 0.9` is an alert an operator can act on
/// while the label still has room.
///
/// Labelled by label name only, which is what the limiter's
/// accepted-value map is keyed by. Two labels are deliberately absent.
/// A `metric` label would be a lie, because one budget is shared by
/// every metric using that label name. A `tenant_id` label would
/// multiply the series count by the tenant budget, which is the failure
/// these gauges exist to warn about.
///
/// Kept as one static so the pair registers together or not at all: a
/// numerator without its denominator is not readable.
static CARDINALITY_USAGE: OnceLock<(prometheus::IntGaugeVec, prometheus::IntGaugeVec)> =
    OnceLock::new();

fn cardinality_usage_gauges() -> &'static (prometheus::IntGaugeVec, prometheus::IntGaugeVec) {
    CARDINALITY_USAGE.get_or_init(|| {
        let unique = prometheus::IntGaugeVec::new(
            Opts::new(
                "sbproxy_label_cardinality_unique_values",
                "Unique values a label name has accepted so far, before new ones are demoted to __other__",
            ),
            &["label"],
        )
        .expect("cardinality unique-value gauge constructs");
        let budget = prometheus::IntGaugeVec::new(
            Opts::new(
                "sbproxy_label_cardinality_budget",
                "Cap the accepted unique values for a label name are counted against",
            ),
            &["label"],
        )
        .expect("cardinality budget gauge constructs");
        // Best-effort registration on the ProxyMetrics registry, same as
        // the overflow counters above: a duplicate registration across
        // `ProxyMetrics::new()` calls in tests is ignored and the local
        // copy is used.
        let _ = metrics().registry.register(Box::new(unique.clone()));
        let _ = metrics().registry.register(Box::new(budget.clone()));
        (unique, budget)
    })
}

/// Refresh the cardinality headroom gauges from the global limiter.
///
/// Driven from [`ProxyMetrics::render`] rather than from the sanitize
/// path. The counts only move when a previously unseen value is
/// accepted, but testing for that on every request would put a gauge
/// write in the hot path to maintain a number nobody reads between
/// scrapes. Recomputing at scrape is one pass over the tracked label
/// names, of which there are a few dozen.
fn refresh_cardinality_gauges() {
    let (unique, budget) = cardinality_usage_gauges();
    let limiter = global_limiter();
    for label in limiter.tracked_labels() {
        unique
            .with_label_values(&[label.as_str()])
            .set(limiter.unique_count(&label) as i64);
        budget
            .with_label_values(&[label.as_str()])
            .set(limiter.cap_for_label(&label) as i64);
    }
}

// --- Target health tri-state gauge (WOR-2560) ---

/// `sbproxy_target_health_state` value for a target that is fully
/// healthy: probe passing, not outlier-ejected, circuit breaker closed.
pub const TARGET_HEALTH_HEALTHY: i64 = 0;

/// `sbproxy_target_health_state` value for a target that is degraded
/// but still selectable: the circuit breaker is half-open, so it is
/// carrying trial traffic while recovery is confirmed.
pub const TARGET_HEALTH_DEGRADED: i64 = 1;

/// `sbproxy_target_health_state` value for a target excluded from
/// selection: probe-unhealthy, outlier-ejected, or breaker open.
pub const TARGET_HEALTH_EXCLUDED: i64 = 2;

/// One load-balancer target's health, as reported by the callback
/// installed with [`set_target_health_source`].
///
/// `state` uses the 0/1/2 scale LiteLLM's deployment-state gauge
/// established, so Grafana panels built against that convention port
/// over unchanged: [`TARGET_HEALTH_HEALTHY`] (0),
/// [`TARGET_HEALTH_DEGRADED`] (1), [`TARGET_HEALTH_EXCLUDED`] (2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetHealthSample {
    /// Configured origin id the target belongs to. Never the request
    /// `Host`, so the label stays bounded by the operator's config.
    pub origin: String,
    /// Target URL exactly as configured under the origin's load
    /// balancer, or the load balancer's own `url#index` identifier when
    /// one origin configures that URL more than once. Config-bounded
    /// for the same reason, and unique per target within an origin, so
    /// two same-URL targets cannot collapse onto one series while
    /// `GET /api/health/targets` still shows them apart.
    pub target: String,
    /// Tri-state health; one of the three `TARGET_HEALTH_*` constants.
    pub state: i64,
}

/// The callback that samples per-target health for the gauge.
type TargetHealthSource = Box<dyn Fn() -> Vec<TargetHealthSample> + Send + Sync>;

/// Installed target-health source. An `RwLock<Option<..>>` rather than
/// a `OnceLock` so every pipeline publication (and every test) can
/// install afresh; [`refresh_target_health_gauge`] takes the read side
/// once per scrape.
static TARGET_HEALTH_SOURCE: RwLock<Option<TargetHealthSource>> = RwLock::new(None);

/// Install (or replace) the callback that samples per-target health
/// for the `sbproxy_target_health_state` gauge.
///
/// The proxy installs one at every pipeline publication
/// (`reload::load_pipeline` in `sbproxy-core`) that walks the live
/// pipeline exactly as `GET /api/health/targets` does, so the
/// Prometheus view and the admin view cannot disagree. Until a source
/// is installed the family is absent from the scrape, which is the
/// honest shape for "nothing is load-balancing yet": absent, not zero.
pub fn set_target_health_source(
    source: impl Fn() -> Vec<TargetHealthSample> + Send + Sync + 'static,
) {
    *TARGET_HEALTH_SOURCE
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(source));
}

/// The `sbproxy_target_health_state` gauge, registered on the
/// `ProxyMetrics` registry on first use. Best-effort registration for
/// the same reason as the cardinality gauges above: a duplicate
/// registration across `ProxyMetrics::new()` calls in tests is ignored
/// and the local copy is used.
static TARGET_HEALTH_GAUGE: OnceLock<prometheus::IntGaugeVec> = OnceLock::new();

fn target_health_gauge() -> &'static prometheus::IntGaugeVec {
    TARGET_HEALTH_GAUGE.get_or_init(|| {
        let gauge = prometheus::IntGaugeVec::new(
            Opts::new(
                "sbproxy_target_health_state",
                "Per-target tri-state health: 0 healthy, 1 degraded (circuit breaker half-open), 2 excluded from selection (probe-unhealthy, outlier-ejected, or breaker open). `origin` is the configured origin id; `target` is the configured URL, or url#index when an origin configures one URL twice",
            ),
            &["origin", "target"],
        )
        .expect("target health gauge constructs");
        let _ = metrics().registry.register(Box::new(gauge.clone()));
        gauge
    })
}

/// Label pairs the target-health gauge is currently publishing.
///
/// Held across the whole refresh, which is what makes two concurrent
/// `/metrics` renders safe (see [`refresh_target_health_gauge`]). Kept
/// in the order the source reported so removals are deterministic.
static TARGET_HEALTH_PUBLISHED: Mutex<Vec<[String; 2]>> = Mutex::new(Vec::new());

/// Refresh the target-health gauge from the installed source.
///
/// Driven from [`ProxyMetrics::render`] beside
/// [`refresh_cardinality_gauges`], and for the same reason: the truth
/// lives elsewhere (the load balancer's probe, ejection, and breaker
/// state), it only needs to be a gauge when someone scrapes, and
/// sampling it at scrape time keeps the per-request path free of gauge
/// writes it would otherwise have to maintain between scrapes.
///
/// A target removed by a config reload has to leave the scrape rather
/// than serve its last pre-reload value forever, and the obvious way to
/// do that, `gauge.reset()` followed by a repopulate, is wrong here.
/// `/metrics` is served from two independent listeners (the data plane
/// and the admin plane) with nothing serializing them, so a second
/// render could wipe the first one's writes and let its `gather()` land
/// in the gap, returning the family empty. On a family where a MISSING
/// series is the alertable condition (`absent(...)`, or
/// `min by (origin) (...) == 2` on an origin whose targets all
/// vanished) that turns a healthy proxy into a page.
///
/// So the refresh is differential instead: take the mutex, drop only
/// the label pairs the source stopped reporting, set the ones it did,
/// and record what is now published. There is no instant at which a
/// live series is absent, and two concurrent renders serialize on the
/// mutex rather than racing through a wiped vec.
fn refresh_target_health_gauge() {
    let source = TARGET_HEALTH_SOURCE
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(source) = source.as_ref() else {
        return;
    };
    let gauge = target_health_gauge();
    // The mutex is taken before the source is sampled, not after, so a
    // render cannot publish a snapshot an already-completed render has
    // superseded. Two scrapes racing across the two listeners then
    // apply in a real order rather than an interleaved one, and the
    // pipeline walk they serialize on is a walk over the configured
    // origins, not per-request work.
    let mut published = TARGET_HEALTH_PUBLISHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let samples = source();

    // Both labels go through the per-label budget rather than the
    // workspace default, so the caps the budget table publishes on
    // `sbproxy_label_cardinality_budget` are the caps actually
    // enforced, and an overflow demotion increments
    // `sbproxy_label_cardinality_overflow_total` instead of demoting
    // silently.
    let fresh: Vec<[String; 2]> = samples
        .iter()
        .map(|sample| {
            [
                sanitize_label_budget("sbproxy_target_health_state", "origin", &sample.origin),
                sanitize_label_budget("sbproxy_target_health_state", "target", &sample.target),
            ]
        })
        .collect();
    for stale in published.iter() {
        if !fresh.contains(stale) {
            let _ = gauge.remove_label_values(&[stale[0].as_str(), stale[1].as_str()]);
        }
    }
    for (labels, sample) in fresh.iter().zip(samples.iter()) {
        gauge
            .with_label_values(&[labels[0].as_str(), labels[1].as_str()])
            .set(sample.state);
    }
    *published = fresh;
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
    /// Counter `sbproxy_ai_compression_value_tokens_saved_total` of
    /// estimated target-model input tokens avoided by successful compression,
    /// labelled by tenant, origin, model, closed lever, and count precision.
    pub ai_compression_value_tokens_saved: IntCounterVec,
    /// Counter `sbproxy_ai_compression_value_cost_saved_micros_total` of gross
    /// known-price target-model input cost avoided by successful compression,
    /// labelled by tenant, origin, model, closed lever, and count precision.
    pub ai_compression_value_cost_saved_micros: IntCounterVec,

    // --- Agent detection (WOR-592) ---
    /// Counter `sbproxy_agent_detect_total` of agent-detect scorer
    /// verdicts labelled by agent id and provenance.
    pub agent_detect_total: IntCounterVec,
    /// Histogram `sbproxy_agent_detect_score` of produced 0-100 scores.
    pub agent_detect_score: Histogram,
    /// Histogram `sbproxy_agent_detect_inference_seconds` of scorer
    /// latency in seconds.
    pub agent_detect_inference_seconds: Histogram,
    /// Counter `sbproxy_trust_tier_requests_total` of requests partitioned
    /// by the closed trust-tier decision.
    pub trust_tier_requests: IntCounterVec,
    /// Counter `sbproxy_inbound_key_requests_total` of requests partitioned
    /// by caller credential mode and its recognized provider.
    pub inbound_key_requests: IntCounterVec,

    /// Counter `sbproxy_deprecated_requests_total` of requests that
    /// resolved to a route carrying a `deprecation:` block or a
    /// spec-deprecated OpenAPI operation, partitioned by origin, rule,
    /// and whether the sunset instant had already passed (WOR-2565).
    pub deprecated_requests_total: IntCounterVec,

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
    /// WOR-2667: `ext_authz` callout outcomes, by outcome
    /// (`allow`, `deny`, `unavailable`, `fail_open`).
    ///
    /// Separate from `auth_results` because that family answers "was
    /// the request admitted"; this one answers "did the authorization
    /// service decide". A `fail_open` is an admitted request whose
    /// decision was never made, and folding the two together hides
    /// exactly the event an operator alerts on. Break down per origin
    /// by joining against `sbproxy_auth_results_total{auth_type="ext_authz"}`.
    pub ext_authz_decisions: Option<IntCounterVec>,
    /// WOR-2667: RFC 7662 token-introspection results, by result
    /// (`active`, `inactive`, `insufficient_scope`, `cached`,
    /// `no_token`, `unavailable`).
    ///
    /// Two of those are not verdicts. `cached` counts the requests a
    /// verdict cache answered without reaching the authorization
    /// server, which is what tells an operator whether `cache_ttl` is
    /// doing anything; `no_token` counts requests that presented no
    /// bearer token, so nothing was asked.
    pub oauth_introspection_results: Option<IntCounterVec>,
    /// WOR-2667: Know Your Agent token verdicts, by verdict
    /// (`verified`, `missing`, `expired`, `revoked`, `invalid`,
    /// `insufficient_balance`, `directory_unavailable`).
    ///
    /// The issuer URL is deliberately not a label: an operator's
    /// issuer allowlist is small but the value is operator-supplied
    /// config, and the verdict is what an alert fires on.
    pub kya_verdicts: Option<IntCounterVec>,
    /// Policy enforcement results with origin, policy_type, and action labels.
    pub policy_triggers: CounterVec,
    /// Cache hit/miss with origin and result labels.
    pub cache_results: CounterVec,
    /// Counter `sbproxy_decision_event_total`: one family for every
    /// decision event, dimensioned by `event`, `engine`, `outcome`,
    /// `origin`, and `tenant` rather than duplicated per feature.
    /// Written through `sbproxy_observe::decision::record_decision`.
    pub decision_event_total: IntCounterVec,
    /// Histogram `sbproxy_decision_event_duration_seconds`. No
    /// `tenant` label on purpose: a histogram multiplies its label set
    /// by its bucket count, and latency per origin and per engine is
    /// the actionable cut.
    pub decision_event_duration: HistogramVec,
    /// Counter `sbproxy_decision_event_fail_open_total`. Its own
    /// family rather than an `outcome` label, because a fail-open is a
    /// request that proceeded without the decision being made, which is
    /// a different thing to alert on than an engine fault.
    pub decision_event_fail_open: IntCounterVec,
    /// Circuit breaker state transitions with origin, from_state, and to_state labels.
    pub circuit_breaker_transitions: CounterVec,
    /// Counter `sbproxy_upstream_status_retries_total` of upstream
    /// retries triggered by a configured response status
    /// (`retry.retry_on`), labelled by origin and the matched status.
    /// Incremented once per scheduled retry, at decision time; matched
    /// statuses that are skipped (method not idempotent, body not
    /// replayable, cap reached) do not count.
    pub upstream_status_retries: IntCounterVec,
    /// Counter `sbproxy_upstream_timeout_retries_total` of upstream
    /// retries whose triggering error was a timeout, labelled by
    /// origin and the phase the deadline was hit in: `connect` (TCP
    /// connect or TLS handshake) or `upstream` (read or write on the
    /// established connection). Keyed on the error class, not on
    /// which `retry_on` token enabled the retry. Incremented once per
    /// scheduled retry, at decision time; timeouts that are not
    /// retried do not count.
    pub upstream_timeout_retries: IntCounterVec,

    // --- Cache Reserve metrics ---
    /// Counter `sbproxy_cache_reserve_hits_total` of reserve hits served
    /// after a hot-cache miss, labelled by origin.
    pub cache_reserve_hits: IntCounterVec,
    /// Counter `sbproxy_cache_reserve_misses_total` of reserve misses
    /// (hot cache and reserve both empty), labelled by origin.
    pub cache_reserve_misses: IntCounterVec,
    /// WOR-2666: counter `sbproxy_anomaly_detected_total` of behavioral
    /// anomalies flagged, by kind and severity.
    ///
    /// `AnomalyDetectorHook`'s own documentation has promised this
    /// family since the trait shipped; nothing emitted it until an
    /// implementation existed to emit it for.
    pub anomaly_detected: Option<IntCounterVec>,
    /// WOR-2666: gauge `sbproxy_agent_reputation_score` in `[0.0, 1.0]`
    /// per tenant and agent class, where 1.0 is a class that has
    /// produced no anomalies inside the rolling window.
    pub agent_reputation_score: Option<GaugeVec>,
    /// WOR-2666: gauge `sbproxy_anomaly_tracked_keys` of
    /// `(tenant, agent class)` pairs the detector currently holds a
    /// window for.
    ///
    /// The detector's resident set is this number times the per-key
    /// window, so it is the one figure that turns "the caps are
    /// bounded" into a size an operator can plan against. It is also
    /// how the budget below becomes visible before it starts evicting.
    pub anomaly_tracked_keys: Option<IntGauge>,
    /// WOR-2666: counter `sbproxy_anomaly_key_budget_spent_total` of
    /// requests that arrived for a key the detector had no slot for.
    ///
    /// Every increment is a key that displaced another key's window, or
    /// a request the detector declined to judge. Either way the
    /// baseline an operator's `deny_below` reads is being churned, and
    /// silence here used to be the only signal: the budget was spent
    /// with no counter and no log line, and `admission_for` reads a
    /// missing score as "admit".
    pub anomaly_key_budget_spent: Option<IntCounter>,
    /// WOR-2673: counter `sbproxy_olp_decisions_total` of RSL Open
    /// Licensing Protocol endpoint outcomes, by endpoint and outcome.
    ///
    /// The OLP endpoints mint bearer license tokens on the request
    /// path. Before this family the entire record of a failed issuance
    /// was one `warn!` and the record of a successful one was nothing,
    /// while the CoMP bridge on the same proxy emitted a counter and a
    /// decision event for every mint of the identical token shape.
    pub olp_decisions: Option<IntCounterVec>,
    /// WOR-2673: counter `sbproxy_cache_reserve_errors_total` of reserve
    /// operations the backend refused, by operation.
    ///
    /// The reserve is best-effort, so every call site swallows its
    /// error and serves the request anyway. That is the right behavior
    /// and it is also why this family exists: without it, a reserve
    /// whose bucket credentials expired reads as a cache with a poor
    /// hit rate rather than as a tier that is failing every write.
    pub cache_reserve_errors: Option<IntCounterVec>,
    /// Counter `sbproxy_cache_reserve_writes_total` of entries written
    /// into the reserve, labelled by origin.
    pub cache_reserve_writes: IntCounterVec,
    /// Counter `sbproxy_cache_reserve_evictions_total` of explicit
    /// reserve deletions (invalidate-on-mutation, expired sweeps),
    /// labelled by origin.
    pub cache_reserve_evictions: IntCounterVec,
    /// Gauge `sbproxy_cache_reserve_degraded` set to one while the
    /// configured reserve backend is degraded, labelled by backend.
    ///
    /// `None` only when the family failed to build, which needs an
    /// illegal metric or label name and is therefore a build-time
    /// mistake rather than a runtime one. A reserve that cannot chart
    /// its health must not take the proxy down with it, so the family
    /// is dropped and every write through it becomes a no-op.
    pub cache_reserve_degraded: Option<IntGaugeVec>,
    /// Counter `sbproxy_cache_reserve_health_transitions_total` of
    /// bounded reserve health transitions by backend, state, and reason.
    ///
    /// `None` under the same conditions as
    /// [`Self::cache_reserve_degraded`].
    pub cache_reserve_health_transitions: Option<IntCounterVec>,

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

    /// Counter `sbproxy_request_body_drain_timeout_total` incremented when
    /// the post-response drain of a client's request body hits its bound
    /// and the connection is closed with bytes still unread.
    ///
    /// A response sbproxy writes itself goes out before the client's body
    /// has been read, and closing a socket with unread bytes queued makes
    /// the kernel send an RST that destroys the response (WOR-2599). The
    /// drain exists to avoid that, and this counter is how an operator
    /// sees it give up: every increment is a client that may have lost a
    /// response it was already sent. A steady rate means either very slow
    /// uploads or something holding connections open deliberately.
    pub request_body_drain_timeout: prometheus::IntCounter,

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

/// Build a labeled counter and register it, without a panic on either
/// step.
///
/// `IntCounterVec::new` rejects an invalid metric name or label set, and
/// `Registry::register` rejects a duplicate. Both inputs here are
/// compile-time constants, so neither can happen in a build that ran its
/// tests once. The helper exists because the alternative is an
/// `.unwrap()` on a startup path, and a proxy that refuses to boot over
/// a metric it could have skipped is a worse failure than a metric that
/// is missing. A refusal logs the family name and yields `None`; the
/// recorders below are no-ops against `None`, so the only consequence is
/// a series that does not appear.
/// [`registered_counter_vec`] for a gauge. Same contract, same reason.
fn registered_gauge_vec(
    registry: &Registry,
    name: &'static str,
    help: &'static str,
    labels: &[&str],
) -> Option<GaugeVec> {
    let gauge = match GaugeVec::new(Opts::new(name, help), labels) {
        Ok(gauge) => gauge,
        Err(error) => {
            tracing::error!(metric = name, %error, "metric family could not be built");
            return None;
        }
    };
    if let Err(error) = registry.register(Box::new(gauge.clone())) {
        tracing::error!(metric = name, %error, "metric family could not be registered");
        return None;
    }
    Some(gauge)
}

/// [`registered_counter_vec`] for an unlabeled gauge.
fn registered_int_gauge(
    registry: &Registry,
    name: &'static str,
    help: &'static str,
) -> Option<IntGauge> {
    let gauge = match IntGauge::new(name, help) {
        Ok(gauge) => gauge,
        Err(error) => {
            tracing::error!(metric = name, %error, "metric family could not be built");
            return None;
        }
    };
    if let Err(error) = registry.register(Box::new(gauge.clone())) {
        tracing::error!(metric = name, %error, "metric family could not be registered");
        return None;
    }
    Some(gauge)
}

/// [`registered_counter_vec`] for an unlabeled counter.
fn registered_int_counter(
    registry: &Registry,
    name: &'static str,
    help: &'static str,
) -> Option<IntCounter> {
    let counter = match IntCounter::new(name, help) {
        Ok(counter) => counter,
        Err(error) => {
            tracing::error!(metric = name, %error, "metric family could not be built");
            return None;
        }
    };
    if let Err(error) = registry.register(Box::new(counter.clone())) {
        tracing::error!(metric = name, %error, "metric family could not be registered");
        return None;
    }
    Some(counter)
}

fn registered_counter_vec(
    registry: &Registry,
    name: &'static str,
    help: &'static str,
    labels: &[&str],
) -> Option<IntCounterVec> {
    let counter = match IntCounterVec::new(Opts::new(name, help), labels) {
        Ok(counter) => counter,
        Err(error) => {
            tracing::error!(metric = name, %error, "metric family could not be built");
            return None;
        }
    };
    if let Err(error) = registry.register(Box::new(counter.clone())) {
        tracing::error!(metric = name, %error, "metric family could not be registered");
        return None;
    }
    Some(counter)
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

        let ai_compression_value_tokens_saved = IntCounterVec::new(
            Opts::new(
                "sbproxy_ai_compression_value_tokens_saved_total",
                "Estimated target-model input tokens avoided by successful context compression",
            ),
            &[
                "tenant_id",
                "origin",
                "model",
                "lever",
                "token_count_precision",
            ],
        )
        .unwrap();

        let ai_compression_value_cost_saved_micros = IntCounterVec::new(
            Opts::new(
                "sbproxy_ai_compression_value_cost_saved_micros_total",
                "Gross known-price target-model input cost avoided by successful context compression, in micro-USD",
            ),
            &[
                "tenant_id",
                "origin",
                "model",
                "lever",
                "token_count_precision",
            ],
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

        let trust_tier_requests = IntCounterVec::new(
            Opts::new(
                "sbproxy_trust_tier_requests_total",
                "Requests partitioned by the derived trust tier",
            ),
            &["tier"],
        )
        .unwrap();
        let inbound_key_requests = IntCounterVec::new(
            Opts::new(
                "sbproxy_inbound_key_requests_total",
                "Requests partitioned by inbound credential mode and provider",
            ),
            &["provider", "key_mode", "tenant_id", "api_key_id"],
        )
        .unwrap();

        // WOR-2565: deprecated-route usage. The whole point of
        // announcing a deprecation is finding the remaining callers,
        // so the counter carries which route is deprecated (`route` is
        // the forward rule's id or index, the OpenAPI path template
        // for spec-driven matches, or empty for a whole-origin block),
        // whether the hit landed after the announced sunset, and
        // whether this request was served anyway or refused with 410.
        let deprecated_requests_total = IntCounterVec::new(
            Opts::new(
                "sbproxy_deprecated_requests_total",
                "Requests that resolved to a deprecated route",
            ),
            &["origin", "route", "past_sunset", "outcome"],
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

        // WOR-2667: built and registered through the panic-free helper
        // rather than the `.unwrap()` every family above uses. The
        // construction cannot fail for a name and label set that are
        // compile-time constants, but "cannot fail" is exactly the
        // claim a `.unwrap()` in a proxy makes right up until it is
        // wrong, and this workspace's unwrap ratchet is the record of
        // that judgment. A refusal here loses one metric family and
        // says so; it does not take the process with it.
        let ext_authz_decisions = registered_counter_vec(
            &registry,
            "sbproxy_ext_authz_decisions_total",
            "External-authorization callout outcomes, by outcome",
            &["outcome"],
        );
        let oauth_introspection_results = registered_counter_vec(
            &registry,
            "sbproxy_oauth_introspection_results_total",
            "RFC 7662 token-introspection results, by result",
            &["result"],
        );
        let kya_verdicts = registered_counter_vec(
            &registry,
            "sbproxy_kya_verdicts_total",
            "Know Your Agent token verification verdicts, by verdict",
            &["verdict"],
        );

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

        // --- One decision-event family (WOR-2370) ---

        let decision_event_total = IntCounterVec::new(
            Opts::new(
                "sbproxy_decision_event_total",
                "Decision events by pipeline point, engine, and outcome",
            ),
            &["event", "engine", "outcome", "origin", "tenant"],
        )
        .expect("metric name and label set are compile-time constants and are valid");

        let decision_event_duration = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "sbproxy_decision_event_duration_seconds",
                "Decision event evaluation latency",
            )
            .buckets(vec![
                0.000_05, 0.000_1, 0.000_5, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0,
            ]),
            &["event", "engine", "origin"],
        )
        .expect("metric name and label set are compile-time constants and are valid");

        let decision_event_fail_open = IntCounterVec::new(
            Opts::new(
                "sbproxy_decision_event_fail_open_total",
                "Decision events that proceeded without the decision being made",
            ),
            &["event", "engine", "origin", "tenant"],
        )
        .expect("metric name and label set are compile-time constants and are valid");

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

        let upstream_status_retries = IntCounterVec::new(
            Opts::new(
                "sbproxy_upstream_status_retries_total",
                "Upstream retries triggered by a configured response status",
            ),
            // status stays low-cardinality: only statuses an operator
            // listed in `retry.retry_on` (validated 100..=599) appear.
            &["origin", "status"],
        )
        .unwrap();

        let upstream_timeout_retries = IntCounterVec::new(
            Opts::new(
                "sbproxy_upstream_timeout_retries_total",
                "Upstream retries triggered by a timeout-classed failure",
            ),
            // phase is a closed two-value set: `connect` (TCP/TLS
            // establishment deadline) or `upstream` (read/write
            // deadline on the established connection).
            &["origin", "phase"],
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

        let anomaly_detected = registered_counter_vec(
            &registry,
            "sbproxy_anomaly_detected_total",
            "Behavioral anomalies flagged, by kind and severity",
            &["kind", "severity"],
        );

        let agent_reputation_score = registered_gauge_vec(
            &registry,
            "sbproxy_agent_reputation_score",
            "Agent-class reputation in [0.0, 1.0]; 1.0 is a class with no anomalies in the window",
            &["tenant_id", "agent_class"],
        );

        let anomaly_tracked_keys = registered_int_gauge(
            &registry,
            "sbproxy_anomaly_tracked_keys",
            "(tenant, agent class) pairs the anomaly detector currently holds a window for",
        );

        let anomaly_key_budget_spent = registered_int_counter(
            &registry,
            "sbproxy_anomaly_key_budget_spent_total",
            "Requests that arrived for an agent class the detector had no tracking slot for",
        );

        let olp_decisions = registered_counter_vec(
            &registry,
            "sbproxy_olp_decisions_total",
            "RSL OLP endpoint outcomes, by endpoint and outcome",
            &["endpoint", "outcome"],
        );

        let cache_reserve_errors = registered_counter_vec(
            &registry,
            "sbproxy_cache_reserve_errors_total",
            "Cache Reserve operations the backend refused, by operation",
            &["origin", "operation"],
        );

        let cache_reserve_evictions = IntCounterVec::new(
            Opts::new(
                "sbproxy_cache_reserve_evictions_total",
                "Cache Reserve explicit deletions",
            ),
            &["origin"],
        )
        .unwrap();

        // The two Cache Reserve health families are the one pair here
        // that answers a construction or registration failure by
        // dropping the family rather than by ending the process. A
        // reserve exists so a proxy keeps serving when its cache is
        // sick; dying because the gauge that reports that could not be
        // built would invert the whole point. `kept` debug_asserts, so
        // a mistake in either name is a test failure rather than
        // something an operator discovers from a flat panel.
        let cache_reserve_degraded = kept(
            IntGaugeVec::new(
                Opts::new(
                    "sbproxy_cache_reserve_degraded",
                    "Whether the configured Cache Reserve backend is degraded",
                ),
                &["backend"],
            ),
            "sbproxy_cache_reserve_degraded",
        );

        let cache_reserve_health_transitions = kept(
            IntCounterVec::new(
                Opts::new(
                    "sbproxy_cache_reserve_health_transitions_total",
                    "Cache Reserve backend health transitions by bounded reason",
                ),
                &["backend", "state", "reason"],
            ),
            "sbproxy_cache_reserve_health_transitions_total",
        );

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

        let request_body_drain_timeout = prometheus::IntCounter::new(
            "sbproxy_request_body_drain_timeout_total",
            "Times the post-response drain of a client's request body hit its bound and the connection was closed with bytes unread",
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
            .register(Box::new(decision_event_total.clone()))
            .expect("the decision-event families are registered exactly once, at startup");
        registry
            .register(Box::new(decision_event_duration.clone()))
            .expect("the decision-event families are registered exactly once, at startup");
        registry
            .register(Box::new(decision_event_fail_open.clone()))
            .expect("the decision-event families are registered exactly once, at startup");
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
            .register(Box::new(ai_compression_value_tokens_saved.clone()))
            .unwrap();
        registry
            .register(Box::new(ai_compression_value_cost_saved_micros.clone()))
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
            .register(Box::new(trust_tier_requests.clone()))
            .unwrap();
        registry
            .register(Box::new(inbound_key_requests.clone()))
            .unwrap();
        registry
            .register(Box::new(deprecated_requests_total.clone()))
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
            .register(Box::new(upstream_status_retries.clone()))
            .unwrap();
        registry
            .register(Box::new(upstream_timeout_retries.clone()))
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
        // Rebind from the register result. Discarding it left the field
        // `Some` while the family was never in the registry, so writes
        // through it went to a gauge nothing scrapes, which is exactly
        // the state `kept`'s doc says cannot happen.
        let cache_reserve_degraded = cache_reserve_degraded.and_then(|family| {
            kept(
                registry.register(Box::new(family.clone())),
                "sbproxy_cache_reserve_degraded",
            )
            .map(|()| family)
        });
        let cache_reserve_health_transitions =
            cache_reserve_health_transitions.and_then(|family| {
                kept(
                    registry.register(Box::new(family.clone())),
                    "sbproxy_cache_reserve_health_transitions_total",
                )
                .map(|()| family)
            });
        registry
            .register(Box::new(synthetic_probe_failures.clone()))
            .unwrap();
        registry
            .register(Box::new(mirror_state_drift.clone()))
            .unwrap();
        registry
            .register(Box::new(request_body_drain_timeout.clone()))
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
            ai_compression_value_tokens_saved,
            ai_compression_value_cost_saved_micros,
            agent_detect_total,
            agent_detect_score,
            agent_detect_inference_seconds,
            trust_tier_requests,
            inbound_key_requests,
            deprecated_requests_total,
            per_origin_requests_total,
            per_origin_request_duration,
            per_origin_active_connections,
            bytes_total,
            auth_results,
            ext_authz_decisions,
            oauth_introspection_results,
            kya_verdicts,
            policy_triggers,
            cache_results,
            decision_event_total,
            decision_event_duration,
            decision_event_fail_open,
            circuit_breaker_transitions,
            upstream_status_retries,
            upstream_timeout_retries,
            cache_reserve_hits,
            cache_reserve_misses,
            cache_reserve_writes,
            olp_decisions,
            cache_reserve_errors,
            anomaly_detected,
            agent_reputation_score,
            anomaly_tracked_keys,
            anomaly_key_budget_spent,
            cache_reserve_evictions,
            cache_reserve_degraded,
            cache_reserve_health_transitions,
            synthetic_probe_failures,
            mirror_state_drift,
            request_body_drain_timeout,
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
        // The cardinality gauges are derived from the limiter's
        // accepted-value sets rather than written as they change, so
        // snapshot them before gathering. A scrape is exactly when
        // someone wants them current.
        refresh_cardinality_gauges();
        // Same shape for target health: the truth is the load
        // balancer's probe/ejection/breaker state, sampled through the
        // installed source when a scrape wants it as a gauge.
        refresh_target_health_gauge();
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
    // `tracing-opentelemetry` layer is wired (seeded explicitly by
    // `sbproxy_observe::telemetry::parent_span_on_remote_trace_context`
    // at each span's creation site, not any ambient state); fall back
    // to the task-local context as a last resort, though nothing in
    // this crate populates it today.
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

/// Record a completed request and stamp the per-agent labels onto
/// `sbproxy_requests_total`.
///
/// Updates the requests counter, latency histogram, and bytes-transferred
/// counters for the given origin. All labels run through
/// [`sanitize_label_budget`] so the per-label cardinality budget is
/// enforced before the value reaches Prometheus. Overflow values are
/// demoted to `__other__` and emit a
/// `sbproxy_label_cardinality_overflow_total` counter (rate-limited to
/// once per minute per (metric, label)).
///
/// A caller with no agent context passes [`AgentLabels::unset`], which
/// stamps the empty-string sentinel across all five agent dimensions.
/// That is a distinct series from any positive `human` / `unknown` /
/// `anonymous` decision, so a dashboard can tell "never classified"
/// apart from "classified as not-an-agent".
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

/// Record one request that resolved to a deprecated route (WOR-2565).
///
/// `route` names which deprecation announcement matched: the forward
/// rule's `origin.id` (or its index when no id is configured), the
/// OpenAPI path template for a spec-driven match, or the empty-string
/// sentinel for a whole-origin `deprecation:` block. It is deliberately
/// not called `rule`: the accepted-value set behind the cardinality
/// budget is keyed on the label NAME, and `rule` is already the
/// operator-named rule ids of four MCP and redaction families, whose
/// budget a 1200-operation deprecated spec would exhaust on its own.
/// `route` is the value space this label actually belongs to, shared
/// with the `sbproxy_openapi_*` families that carry the same path
/// templates.
///
/// `past_sunset` says whether the request landed after the announced
/// sunset instant; it is always `false` when no sunset is configured.
/// `refused` says whether this particular request was turned away with
/// `410 Gone`, which `past_sunset` alone cannot answer: an origin on
/// `after_sunset: serve` keeps serving past its sunset, so without the
/// split an operator running both postures cannot count who is actually
/// being cut off. Both booleans come from real comparisons, so all four
/// combinations are reachable from real input.
///
/// Both free-form labels run through [`sanitize_label_budget`], though
/// in practice their cardinality is bounded by the authored config and
/// spec.
pub fn record_deprecated_request(origin: &str, route: &str, past_sunset: bool, refused: bool) {
    let origin_san = sanitize_label_budget("sbproxy_deprecated_requests_total", "origin", origin);
    let route_san = sanitize_label_budget("sbproxy_deprecated_requests_total", "route", route);
    metrics()
        .deprecated_requests_total
        .with_label_values(&[
            origin_san.as_str(),
            route_san.as_str(),
            if past_sunset { "true" } else { "false" },
            if refused { "gone" } else { "served" },
        ])
        .inc();
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

/// Record one flagged behavioral anomaly (WOR-2666).
///
/// `kind` and `severity` are the closed label sets
/// [`sbproxy_plugin::AnomalyVerdict`] documents. Both come from the
/// hook rather than from a request, so neither is attacker-controlled.
pub fn record_anomaly_detected(kind: &str, severity: &str) {
    if let Some(counter) = metrics().anomaly_detected.as_ref() {
        counter.with_label_values(&[kind, severity]).inc();
    }
}

/// Publish how many `(tenant, agent class)` windows the detector holds
/// (WOR-2666).
///
/// The detector's resident set is this number times the per-key window,
/// so this is the figure that turns "the per-request cost is bounded"
/// into a memory size an operator can plan against. Without it, the cap
/// was reachable and invisible.
pub fn set_anomaly_tracked_keys(count: usize) {
    if let Some(gauge) = metrics().anomaly_tracked_keys.as_ref() {
        gauge.set(count as i64);
    }
}

/// Count one request that arrived for an agent class the detector had
/// no tracking slot for (WOR-2666).
///
/// Non-zero means the key budget is spent and windows are being
/// displaced, which churns the baseline an operator's `deny_below`
/// reads. The failure it makes visible is a quiet one: a key with no
/// slot has no score, and no score reads as "admit".
pub fn record_anomaly_key_budget_spent() {
    if let Some(counter) = metrics().anomaly_key_budget_spent.as_ref() {
        counter.inc();
    }
}

/// Publish one tenant's agent-class reputation score (WOR-2666).
///
/// `agent_class` goes through the cardinality limiter's **budget**
/// door, the one that knows `agent_class` is capped at 8 and counts an
/// overflow on `sbproxy_label_cardinality_overflow_total`.
///
/// The plain `sanitize_label` door this used is a 1,000-value cap, and
/// it writes into a set keyed by label name alone. So a gauge admitting
/// 40 classes through the wide door did not only widen itself: it
/// raised the effective `agent_class` cardinality of
/// `sbproxy_requests_total` from 8 to whatever it had admitted, with no
/// overflow counter to show it had happened. Every other `agent_class`
/// writer uses the budget form, and now so does this one.
///
/// `tenant_id` is a label because reputation is an input a policy can
/// act on: without it, one tenant's noisy crawler decides what another
/// tenant's admission threshold sees.
pub fn set_agent_reputation_score(tenant_id: &str, agent_class: &str, score: f64) {
    const METRIC: &str = "sbproxy_agent_reputation_score";
    let tenant_id = sanitize_label_budget(METRIC, "tenant_id", tenant_id);
    let agent_class = sanitize_label_budget_tenant(METRIC, "agent_class", agent_class, &tenant_id);
    if let Some(gauge) = metrics().agent_reputation_score.as_ref() {
        gauge
            .with_label_values(&[tenant_id.as_str(), agent_class.as_str()])
            .set(score);
    }
}

/// Record one RSL OLP endpoint outcome (WOR-2673).
///
/// `endpoint` is the closed set `token` / `key` / `introspect` /
/// `revoke`, naming the well-known route. `outcome` is the closed set
/// `ok` / `rejected` / `error`: `rejected` is a caller mistake the
/// endpoint answered 4xx for, `error` is a failure on this side.
///
/// Both labels are `&'static str` so no caller-supplied value can reach
/// a label, matching the `sbproxy_comp_marketplace_*` families the CoMP
/// bridge writes for the same token shape.
pub fn record_olp_decision(endpoint: &'static str, outcome: &'static str) {
    if let Some(counter) = metrics().olp_decisions.as_ref() {
        counter.with_label_values(&[endpoint, outcome]).inc();
    }
}

/// Record one cache-reserve operation the backend refused (WOR-2673).
///
/// `operation` is the closed set `put` / `get` / `delete` / `sweep` /
/// `init`, naming the trait method that failed. `origin` is the
/// config-bounded origin id, matching the other
/// `sbproxy_cache_reserve_*` families, or one of two proxy-wide
/// sentinels: `__init__` for a reserve that never got built and
/// `__sweep__` for the expiry sweep, neither of which belongs to an
/// origin.
///
/// `init` is the one an operator most needs. A reserve whose backend
/// failed to construct is *absent*, so no call site runs and every
/// other family reads flat zero, which is byte-for-byte identical to
/// "no reserve configured". Without this series the most likely
/// real-world failure of the feature, a wrong region or an expired
/// instance profile, is invisible on every dashboard.
pub fn record_cache_reserve_error(origin: &str, operation: &'static str) {
    if let Some(counter) = metrics().cache_reserve_errors.as_ref() {
        let origin = sanitize_label("origin", origin);
        counter
            .with_label_values(&[origin.as_str(), operation])
            .inc();
    }
}

/// Record one `ext_authz` callout outcome (WOR-2667).
///
/// `outcome` is the closed set `allow` / `deny` / `unavailable` /
/// `fail_open`, produced by
/// `sbproxy_modules::auth::ext_authz::ExtAuthzOutcome::metric_label`, so
/// the label vocabulary cannot drift from the outcomes the provider can
/// actually reach.
pub fn record_ext_authz_decision(outcome: &'static str) {
    if let Some(counter) = metrics().ext_authz_decisions.as_ref() {
        counter.with_label_values(&[outcome]).inc();
    }
}

/// Record one RFC 7662 introspection result (WOR-2667).
///
/// `result` is the closed set `active` / `inactive` /
/// `insufficient_scope` / `cached` / `no_token` / `unavailable`.
pub fn record_oauth_introspection_result(result: &'static str) {
    if let Some(counter) = metrics().oauth_introspection_results.as_ref() {
        counter.with_label_values(&[result]).inc();
    }
}

/// Record one Know Your Agent verification verdict (WOR-2667).
///
/// `verdict` is the closed set produced by
/// `sbproxy_modules::auth::kya::KyaVerdict::metric_label`.
pub fn record_kya_verdict(verdict: &'static str) {
    if let Some(counter) = metrics().kya_verdicts.as_ref() {
        counter.with_label_values(&[verdict]).inc();
    }
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

/// Record one derived request trust tier.
///
/// The label is closed to the four trust-tier values. Unknown input is
/// conservatively attributed to
/// `anonymous` instead of creating attacker-controlled cardinality.
pub fn record_trust_tier(tier: &str) {
    let tier = match tier {
        "suspicious" | "strong" | "named" | "anonymous" => tier,
        _ => "anonymous",
    };
    metrics()
        .trust_tier_requests
        .with_label_values(&[tier])
        .inc();
}

/// Record the request's inbound credential mode without exposing credential
/// material. `key_mode` is a closed set; provider, tenant, and public key-id
/// labels pass through bounded cardinality budgets. `None` is represented by
/// the empty sentinel, never a made-up provider name.
pub fn record_inbound_key_request(
    provider: Option<&str>,
    key_mode: &str,
    tenant_id: &str,
    api_key_id: Option<&str>,
) {
    const METRIC: &str = "sbproxy_inbound_key_requests_total";
    let key_mode = match key_mode {
        "none" | "minted" | "native" => key_mode,
        _ => "none",
    };
    let tenant_id = sanitize_label_budget(METRIC, "tenant_id", tenant_id);
    let provider =
        sanitize_label_budget_tenant(METRIC, "provider", provider.unwrap_or_default(), &tenant_id);
    let api_key_id = sanitize_label_budget_tenant(
        METRIC,
        "api_key_id",
        api_key_id.unwrap_or_default(),
        &tenant_id,
    );
    metrics()
        .inbound_key_requests
        .with_label_values(&[
            provider.as_str(),
            key_mode,
            tenant_id.as_str(),
            api_key_id.as_str(),
        ])
        .inc();
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

/// Record per-lever value delivered by successful AI context compression.
///
/// `lever` and `token_count_precision` are accepted only from their closed
/// production sets. Unknown values and records without positive token savings
/// are not emitted. A positive token result may have zero cost when the model
/// is unpriced or after micro-USD rounding. Tenant, origin, and
/// model labels pass through the bounded cardinality limiter; prompt and
/// summary content never enter this interface.
pub fn record_compression_value(
    tenant_id: &str,
    origin: &str,
    model: &str,
    lever: &str,
    token_count_precision: &str,
    tokens_saved: u64,
    gross_cost_saved_micros: u64,
) {
    record_compression_value_to(
        metrics(),
        CompressionValueObservation {
            tenant_id,
            origin,
            model,
            lever,
            token_count_precision,
            tokens_saved,
            gross_cost_saved_micros,
        },
    );
}

struct CompressionValueObservation<'a> {
    tenant_id: &'a str,
    origin: &'a str,
    model: &'a str,
    lever: &'a str,
    token_count_precision: &'a str,
    tokens_saved: u64,
    gross_cost_saved_micros: u64,
}

fn record_compression_value_to(
    target: &ProxyMetrics,
    observation: CompressionValueObservation<'_>,
) {
    const METRIC: &str = "sbproxy_ai_compression_value_tokens_saved_total";

    let CompressionValueObservation {
        tenant_id,
        origin,
        model,
        lever,
        token_count_precision,
        tokens_saved,
        gross_cost_saved_micros,
    } = observation;
    if tokens_saved == 0 {
        return;
    }
    let lever = match lever {
        "summary_buffer" => "summary_buffer",
        "window_fit" => "window_fit",
        "rag_select" => "rag_select",
        "compact_serialization" => "compact_serialization",
        _ => return,
    };
    let token_count_precision = match token_count_precision {
        "model_tokenizer" => "model_tokenizer",
        "heuristic" => "heuristic",
        _ => return,
    };
    let tenant_id = sanitize_label_budget(METRIC, "tenant_id", tenant_id);
    let origin = sanitize_label_budget_tenant(METRIC, "origin", origin, &tenant_id);
    let model = sanitize_label_budget_tenant(METRIC, "model", model, &tenant_id);
    let labels = [
        tenant_id.as_str(),
        origin.as_str(),
        model.as_str(),
        lever,
        token_count_precision,
    ];
    target
        .ai_compression_value_tokens_saved
        .with_label_values(&labels)
        .inc_by(tokens_saved);
    if gross_cost_saved_micros > 0 {
        target
            .ai_compression_value_cost_saved_micros
            .with_label_values(&labels)
            .inc_by(gross_cost_saved_micros);
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
/// origin label is run through the cardinality limiter. `enforced` is
/// `true` only when the proxy actually refused the request; a
/// violation that was reported but allowed through (`test_mode`, or a
/// `detect_only` hit from the ruleless enumeration heuristic) lands on
/// the `enforced="false"` series, so an operator alerting on refusals
/// is never paged by audit-only traffic and audit-only traffic is
/// still visible on its own series.
pub fn record_object_authz_violation(origin: &str, kind: &'static str, enforced: bool) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_object_authz_violations_total",
            "Object/function-level authorization violations, by kind (bola, bfla, enumeration) and enforcement disposition (enforced=true refused the request; enforced=false was audited only)",
            &["origin", "kind", "enforced"],
        )
        .expect("object_authz violation counter registers")
    });
    let origin_san = sanitize_label("origin", origin);
    counter
        .with_label_values(&[
            origin_san.as_str(),
            kind,
            if enforced { "true" } else { "false" },
        ])
        .inc();
}

/// Record one enumeration observation the `object_authz` policy could
/// not track because its per-principal tracker was at capacity with
/// only live windows, even after sweeping expired ones
/// (`sbproxy_object_authz_enumeration_tracker_saturated_total`). No
/// labels, mirroring `record_mcp_peer_registry_saturated`'s reasoning:
/// the principal that caused the refusal is exactly the
/// caller-controlled string the cap exists to bound. Ticks on every
/// refused observation, not once per episode, so the series size shows
/// how much traffic went unobserved; the once-per-window
/// `tracing::warn!` beside it is a separate, deliberately quieter
/// signal.
pub fn record_object_authz_tracker_saturated() {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_object_authz_enumeration_tracker_saturated_total",
            "Enumeration observations the object_authz policy could not track because the per-principal tracker was at capacity with live windows",
        )
        .expect("object_authz tracker saturated counter registers")
    });
    counter.inc();
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

// --- virtual key store degradation ------------------------------------
//
// The widest blast radius of any dependency this proxy has. An
// unreachable `key_management.store` does not degrade one feature; it
// changes the authentication posture of the whole listener, because
// `key_management.failure_posture` decides whether the request is
// refused with a 503 or handed to the origin's own auth carrying no
// per-key policy, budget, or attribution. Every other posture in
// `docs/degradation.md` costs an enforcement guarantee. This one can
// cost the identity the enforcement was keyed on.
//
// Until now the only trace of it was a WARN line, which is a signal
// nobody is watching at three in the morning. Two families replace it,
// and they answer different questions on purpose. The counter answers
// "how often, and at which gate". The gauge answers "right now", which
// is the question a counter structurally cannot: an operator paged at
// 03:00 needs to know whether the store is failing *at this moment* and
// what that currently costs, and `increase(...[5m]) > 0` is a claim
// about the past five minutes, not about now.

/// Move `sbproxy_key_store_unavailable{posture}`, keeping exactly one
/// series alive for it.
///
/// `posture` changes only on a config reload, so the previous label value
/// is removed before the new one is set. Without that a proxy reloaded
/// from `closed` to `degraded` would keep exporting a `closed` series at
/// whatever value it last held, and a stale series reads exactly like a
/// live answer.
///
/// Registration failure is swallowed with `.ok()` rather than unwrapped,
/// for the reason [`record_events_dropped`] gives: this runs from the
/// request path, and a proxy that aborts because a gauge would not
/// register is a worse outcome than one whose gauge is missing.
///
/// The mutex is taken on every inbound-key resolution, including the L1
/// cache hits that are the hot auth path, and that is deliberate rather
/// than unexamined. An uncontended lock plus a short string compare is
/// the same order as the `with_label_values` hash lookup underneath it,
/// and both are well inside what the surrounding path already pays for
/// the keystore cache's own mutex and for `record_inbound_key_request`,
/// which sanitises four labels through the cardinality budget on the same
/// request. An atomic fast path was considered and dropped: it can skip
/// the publish only by not noticing a posture change that leaves the
/// value alone, which is exactly the reload that would strand the label
/// this gauge exists to carry.
fn set_key_store_unavailable(posture: &str, value: i64) {
    use prometheus::{register_int_gauge_vec, IntGaugeVec};
    use std::sync::{Mutex, OnceLock};
    static G: OnceLock<Option<IntGaugeVec>> = OnceLock::new();
    static CURRENT: Mutex<Option<String>> = Mutex::new(None);
    let gauge = G.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_key_store_unavailable",
            "1 while the last inbound-key resolution could not reach the virtual key store; the posture label is what that costs",
            &["posture"],
        )
        .ok()
    });
    let Some(gauge) = gauge else {
        return;
    };
    let mut current = CURRENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if current.as_deref() != Some(posture) {
        if let Some(previous) = current.as_deref() {
            let _ = gauge.remove_label_values(&[previous]);
        }
        *current = Some(posture.to_string());
    }
    gauge.with_label_values(&[posture]).set(value);
}

/// Count one virtual-key-store outage decision on
/// `sbproxy_key_store_outage_total{entrypoint,posture,outcome}` and raise
/// `sbproxy_key_store_unavailable{posture}` to 1.
///
/// Every label value is a compile-time constant drawn from a closed set,
/// so neither family can grow with traffic, with the config, or with the
/// number of keys. Nothing derived from a credential, a key id, or a
/// resolved config value is ever a label here: the id that failed to
/// resolve belongs in the log line and the audit record, not in a series
/// name.
///
/// | Label | Values |
/// |---|---|
/// | `entrypoint` | `header_sweep`, `impersonation_ticket`, `bearer`, `oidc_claim`, `native_key` |
/// | `posture` | `closed`, `degraded`, `open`, `observe` |
/// | `outcome` | `denied`, `admitted` |
///
/// `posture` carries all four spellings of `FailureMode` (the config
/// enum, which this crate deliberately does not depend on) even though
/// `observe` is refused at config-compile time for this key, because the
/// bound the cardinality budget promises should hold against the enum
/// rather than against today's validation rules.
///
/// One observation per gate, not per request. A caller that presents a
/// bearer token and then reaches the native-provider-key carve-out is
/// counted under both entrypoints, because those are two separate
/// decisions and an operator debugging one does not want it hidden inside
/// the other.
pub fn record_key_store_outage(
    entrypoint: &'static str,
    posture: &'static str,
    outcome: &'static str,
) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_key_store_outage_total",
            "Inbound-key resolutions that could not reach the virtual key store, by entrypoint, configured failure posture, and what the posture decided",
            &["entrypoint", "posture", "outcome"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        counter
            .with_label_values(&[entrypoint, posture, outcome])
            .inc();
    }
    set_key_store_unavailable(posture, 1);
}

/// Drop `sbproxy_key_store_unavailable{posture}` back to 0 after an
/// inbound-key resolution reached a verdict without needing the posture.
///
/// Deliberately says "reached a verdict" and not "reached the store". A
/// resolution served from the TTL cache during an outage did keep its
/// per-key policy, budget, and attribution, so nothing was waived for
/// that request and the gauge is right to read 0 for it. What the gauge
/// tracks is whether the posture is in force, which is the operator's
/// actual question; the counter beside it is what survives the flap.
pub fn record_key_store_reachable(posture: &'static str) {
    set_key_store_unavailable(posture, 0);
}

/// Count one admin key-lifecycle operation on
/// `sbproxy_key_operations_total{operation, outcome}` (WOR-2572).
///
/// `operation` is the closed admin-route set: `mint`, `update`, `delete`,
/// `revoke`, `block`, `unblock`, `rotate`, `budget_override_grant`,
/// `budget_override_clear`. Every one of them loads and CAS-writes the
/// same `KeyRecord`, which is the membership test; `/admin/credentials`
/// writes a different record and gets its own family rather than
/// doubling this one's. `outcome` is `ok`, `refused`,
/// or `error`, derived at the dispatch seam from the status class the
/// handler actually returned (2xx, 4xx, 5xx), never from a default. The
/// three values are deliberately separate: a revision conflict the
/// operator can retry and a store that is down are different facts, and
/// folding them into one value produces a rate panel that cannot tell an
/// outage from a busy console.
pub fn record_key_operation(operation: &'static str, outcome: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_key_operations_total",
            "Admin key-lifecycle operations, by operation and by what the handler actually returned (ok, refused, error)",
            &["operation", "outcome"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        counter.with_label_values(&[operation, outcome]).inc();
    }
}

/// Count one shared-cache-tier invalidation that did not propagate, on
/// `sbproxy_key_cache_invalidation_failures_total{scope}`.
///
/// `scope` is `key` (one id) or `all` (the whole tier). Both mean the
/// same thing to an operator: the store write landed and the shared L2
/// did not hear about it, so every other replica keeps answering with the
/// record that was just changed until its TTL lapses. On a revoke that is
/// a credential that stays accepted fleet-wide, which is why this is a
/// counter of its own rather than a label on the lookup family: a
/// failed lookup is a cache miss the store covers for, and this is not.
///
/// There is deliberately no `ok` counterpart. The question an alert asks
/// here is "did any invalidation fail", not "what fraction", and a
/// success series on a path that runs once per admin mutation buys
/// nothing a `sbproxy_key_operations_total` rate does not already give.
pub fn record_key_cache_invalidation_failure(scope: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_key_cache_invalidation_failures_total",
            "Keystore cache-tier invalidations that did not reach the shared tier or its peers, by scope (key or all)",
            &["scope"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        counter.with_label_values(&[scope]).inc();
    }
}

/// Observe one bound-credential resolution on
/// `sbproxy_credential_resolution_duration_seconds{cache, outcome}`
/// (WOR-2572).
///
/// `cache` says which layer answered: `hit` (the per-generation
/// resolved-secret cache, fresh), `stale` (a known-good value served
/// inside the `proxy.secrets.rotation` grace window after re-resolution
/// failed), or `miss` (the full keystore/vault path ran). `outcome` is
/// `ok`, `refused` (absent, revoked/blocked, or cross-tenant), or
/// `error` (the secret backend could not answer), taken from the one
/// `Result` every caller sees. The cache-hit ratio derives from the
/// `_count` series; `stale` is deliberately not folded into `hit`
/// because a stale serve is a backend failure wearing a grace period.
pub fn record_credential_resolution(
    cache: &'static str,
    outcome: &'static str,
    duration_secs: f64,
) {
    use prometheus::{register_histogram_vec, HistogramVec};
    use std::sync::OnceLock;
    static H: OnceLock<Option<HistogramVec>> = OnceLock::new();
    let hist = H.get_or_init(|| {
        register_histogram_vec!(
            "sbproxy_credential_resolution_duration_seconds",
            "Wall-clock latency of one bound-credential resolution, by which cache layer answered and the real outcome",
            &["cache", "outcome"],
            crate::exemplars::STANDARD_LATENCY_BUCKETS.to_vec(),
        )
        .ok()
    });
    if let Some(hist) = hist {
        hist.with_label_values(&[cache, outcome])
            .observe(duration_secs);
    }
}

/// Count one keystore TTL-cache lookup on
/// `sbproxy_key_lookup_cache_total{kind, outcome}` (WOR-2572).
///
/// Driven through the cache's lookup observer
/// (`sbproxy_keystore::cache::TtlCache::with_lookup_observer`), installed
/// where the production cache is built (`key_plane::build_cache`), because
/// the keystore crate deliberately does not depend on this one. `kind` is
/// `key` or `credential`; `outcome` is `hit` (fresh L1 record),
/// `negative_hit` (fresh L1 known-absent), `tier_hit` (the L2 tier
/// answered), `miss` (the store was consulted and answered), or `error`
/// (the store was consulted and could not answer). Hit ratio:
/// `(hit + negative_hit + tier_hit) / total`.
pub fn record_key_lookup_cache(kind: &'static str, outcome: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_key_lookup_cache_total",
            "Keystore TTL-cache lookups, by record kind and which layer answered (hit, negative_hit, tier_hit, miss, error)",
            &["kind", "outcome"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        counter.with_label_values(&[kind, outcome]).inc();
    }
}

/// Fold one audit emission's real write result into
/// `sbproxy_audit_write_failures_total{channel}` (WOR-2572).
///
/// Modeled on Vault's audit-log failure counter, whose docs say a healthy
/// system reads exactly zero, so the counter touches the channel's series
/// on every emission (exporting an explicit 0 an `increase()` alert can
/// baseline against) and increments only when `ok` is false. `ok` comes
/// from the emit path's actual result - the chain append's returned
/// `bool` or the serialize failure - never from a default, which is the
/// difference between this counter and the `RB-AUDIT-WRITE-FAILURE`
/// landmine WOR-2572 exists to avoid: an outcome label nothing can set to
/// a failure value is an alert that structurally cannot fire. `channel`
/// names the config key that turned the trail on: `key_path` (the key and
/// credential mutation trail) or `admin_path` (the admin-console action
/// trail) today, `key_access_path` reserved for the read-audit channel
/// (WOR-2570). The family is named for the signal rather than for the key
/// plane because `admin_path` is a console channel, not a key-management
/// one.
///
/// Two things can set `ok` to false, and they have different
/// reachability. A deployment with no chain configured cannot reach the
/// chain half at all: [`crate::audit::KeyAuditEntry::emit`] substitutes `true`
/// for the append result when no chain is installed. The serialize half
/// is independent of that and does reach this call site on its own, so it
/// is unreachable today only because every field of a `KeyAuditEntry` is
/// a `String`, an `Option<String>`, or a `serde_json::Value`, none of
/// which can fail to encode. A field with a hand-written `Serialize`
/// would change that, which is why the reason is written down rather than
/// left as "no chain, no failures".
pub fn record_audit_write_outcome(channel: &'static str, ok: bool) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_audit_write_failures_total",
            "Audit emissions that did not reach a sink they were promised, by audit channel; healthy systems read 0",
            &["channel"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        let series = counter.with_label_values(&[channel]);
        if !ok {
            series.inc();
        }
    }
}

/// Shared-budget reads/writes that could not reach the Redis/KV store and
/// fell open to the per-instance tracker. Fired at the exact branch where
/// the store error is still distinguishable from "no shared store
/// configured" (budget_share.rs). WOR-2474.
pub fn record_budget_share_fail_open(op: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_budget_share_fail_open_total",
            "Shared budget store operations that failed and fell open to per-instance enforcement, by operation (`read`, `write`, `mirror_dropped`)",
            &["op"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        counter.with_label_values(&[op]).inc();
    }
    set_budget_share_unavailable(1);
}

/// 1 while the last shared-budget store operation failed, 0 once one
/// succeeds. Clears on any successful read or write, so it reports the
/// store's reachability, not the staleness of the TTL cache. WOR-2474.
pub fn set_budget_share_unavailable(state: i64) {
    use prometheus::{register_int_gauge, IntGauge};
    use std::sync::OnceLock;
    static G: OnceLock<Option<IntGauge>> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge!(
            "sbproxy_budget_share_unavailable",
            "1 while shared budget enforcement is degraded to per-instance tracking, 0 when the shared store answered",
        )
        .ok()
    });
    if let Some(gauge) = gauge {
        gauge.set(state);
    }
}

/// A policy enforcer panicked and the panic was contained to a 500 deny
/// instead of crashing the proxy. Label is the enforcer's policy type,
/// a closed set. WOR-2477.
pub fn record_policy_panic(policy: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_policy_panic_total",
            "Policy enforcer panics contained on the serving path, by policy type",
            &["policy"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        let policy = sanitize_label("policy", policy);
        counter.with_label_values(&[policy.as_str()]).inc();
    }
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

/// Record one A2A 1.0 JSON-RPC method invocation.
///
/// Separate from `sbproxy_a2a_hops_total` rather than another label on
/// it: method only exists for the ratified 1.0 spec, so folding it in
/// would leave an empty dimension on every v0 hop and multiply the
/// existing series by a value most of them cannot carry.
///
/// `method` must come from the closed method enum, never from the raw
/// wire string. The enum has eleven variants; the wire field is
/// caller-controlled and unbounded, and would blow up cardinality.
pub fn record_a2a_method(route: &str, method: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_a2a_methods_total",
            "A2A 1.0 JSON-RPC methods observed by the proxy, labelled by route and method.",
            &["route", "method"],
        )
        .expect("a2a methods counter registers")
    });
    let route = sanitize_label("route", route);
    counter.with_label_values(&[route.as_ref(), method]).inc();
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

/// Record one `prompt_injection_v2` block, labeled by the scan path that
/// produced it (WOR-2530).
///
/// `scan_path` is a closed four-value set, one per place the policy can
/// deny: `header_scan` (the synchronous request-line and header scan in
/// the `request_filter` enforcer), `body_scan` (the buffered request body
/// on the generic proxy path), `ai_body` (the AI dispatch prompt
/// segments), and `a2a` (agent-to-agent message parts).
///
/// The label is the point. Those four paths drifted: three wrote the
/// operator's configured `block_body` and `block_content_type` verbatim
/// and one wrapped the body in `{"error": ...}` with a hardcoded
/// `application/json`. Nothing in `/metrics` told them apart, so which
/// path had blocked a given request was not an answerable question, and
/// the asymmetry survived until someone compared two responses by hand.
///
/// `tenant` is operator-supplied and passes through the cardinality
/// limiter. A block is a security verdict about one tenant's traffic, so
/// this family is listed in `TENANT_SCOPED_METRICS`.
pub fn record_prompt_injection_block(scan_path: &str, tenant: &str) {
    use prometheus::{register_counter_vec, CounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<CounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_counter_vec!(
            "sbproxy_prompt_injection_blocks_total",
            "Requests blocked by the prompt_injection_v2 policy, by scan path",
            &["scan_path", "tenant"],
        )
        .expect("counter vec registers")
    });
    let tenant_san = sanitize_label("tenant", tenant);
    counter
        .with_label_values(&[scan_path, tenant_san.as_str()])
        .inc();
}

/// Record one closed stage of a `prompt_injection_v2` classifier failure.
///
/// Every free-form input is collapsed onto a fixed fallback before it reaches
/// Prometheus. The caller records both stages when a primary sidecar and its
/// mandatory local fallback fail, so the outage is attributable without
/// exposing an endpoint, model path, prompt, or dependency error.
pub fn record_prompt_injection_classifier_failure(
    scan_path: &str,
    action: &str,
    stage: &str,
    reason: &str,
    outcome: &str,
    tenant: &str,
) {
    use prometheus::{register_counter_vec, CounterVec};
    use std::sync::OnceLock;

    let scan_path = match scan_path {
        "header_scan" => "header_scan",
        "body_scan" => "body_scan",
        "ai_body" => "ai_body",
        "a2a" => "a2a",
        _ => "unknown",
    };
    let action = match action {
        "block" => "block",
        "tag" => "tag",
        "log" => "log",
        _ => "unknown",
    };
    let stage = match stage {
        "detector" => "detector",
        "primary_sidecar" => "primary_sidecar",
        "local_fallback" => "local_fallback",
        _ => "unknown",
    };
    let reason = match reason {
        "queue_full" => "queue_full",
        "deadline" => "deadline",
        "worker" => "worker",
        "runtime" => "runtime",
        "inference" => "inference",
        "sidecar" => "sidecar",
        _ => "unknown",
    };
    let outcome = match outcome {
        "blocked" => "blocked",
        "degraded" => "degraded",
        _ => "unknown",
    };

    static C: OnceLock<CounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_counter_vec!(
            "sbproxy_prompt_injection_classifier_failures_total",
            "Unavailable prompt-injection classifier stages by action and request outcome",
            &[
                "scan_path",
                "action",
                "stage",
                "reason",
                "outcome",
                "tenant"
            ],
        )
        .expect("counter vec registers")
    });
    let tenant_san = sanitize_label("tenant", tenant);
    counter
        .with_label_values(&[
            scan_path,
            action,
            stage,
            reason,
            outcome,
            tenant_san.as_str(),
        ])
        .inc();
}

/// Record one Content-Security-Policy header emitted by the
/// `security_headers` policy, by `mode` (`enforce` or `report_only`).
///
/// A CSP that is configured and silently never shipped is
/// indistinguishable from a working one by reading the config file, which
/// is how a dropped `content_security_policy` survived in an example
/// config and in the docs (WOR-2526). This counter is the difference: an
/// operator who configured a CSP and watches this series sit at zero
/// knows the header is not reaching browsers. The `mode` label carries
/// the second half of that bug, where a `report_only` policy was emitted
/// as an enforcing one.
///
/// `tenant` is operator-supplied and passes through the cardinality
/// limiter.
pub fn record_security_headers_csp_emitted(mode: &str, tenant: &str) {
    use prometheus::{register_counter_vec, CounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<CounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_counter_vec!(
            "sbproxy_security_headers_csp_emitted_total",
            "Content-Security-Policy headers emitted by the security_headers policy, by mode",
            &["mode", "tenant"],
        )
        .expect("counter vec registers")
    });
    let tenant_san = sanitize_label("tenant", tenant);
    counter
        .with_label_values(&[mode, tenant_san.as_str()])
        .inc();
}

/// Record one `fallback_origin` response served, by which trigger fired.
///
/// `trigger` is a closed two-value set: `status` when the primary
/// upstream answered with a status the operator listed under
/// `on_status`, and `error` when it failed outright and `on_error`
/// caught it in `fail_to_proxy`. Both are proxy-authored constants;
/// `origin` and `tenant` are operator-scoped and pass through the
/// cardinality limiter.
///
/// Registration failure yields no counter rather than a panic, the same
/// shape [`record_websocket_teardown`] uses. Both call sites are on a
/// request that is already degraded and already answered, and killing
/// the worker over a metric family that would not register is a worse
/// outcome than the missing series. It also keeps this off the
/// production `expect` budget `scripts/check-unwrap-ratchet.sh` holds,
/// which the first shape of this recorder pushed up by one.
///
/// Until WOR-2686 a fallback taken left no scrapeable trace at all. The
/// only evidence was `fallback_triggered` on an access-log row, so
/// "fallbacks are firing on checkout.local" was a log-scraping question
/// rather than an alert, and `on_status` in particular was not reliably
/// serving what it claimed to serve. A fallback is a degraded response
/// by construction, so the rate of this counter is the first number an
/// operator wants when a primary starts failing.
pub fn record_fallback_served(trigger: &str, origin: &str, tenant: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_fallback_total",
            "fallback_origin responses served, by trigger",
            &["trigger", "origin", "tenant"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        let origin_san = sanitize_label("origin", origin);
        let tenant_san = sanitize_label("tenant", tenant);
        counter
            .with_label_values(&[trigger, origin_san.as_str(), tenant_san.as_str()])
            .inc();
    }
}

/// Record one WebSocket upgrade refusal or tunnel teardown initiated
/// by the gateway (WOR-2552).
///
/// `reason` is a closed four-value set: `message_too_large` (a frame
/// scan crossed the tunnel's `max_message_size` cap),
/// `control_frame_violation` (a control frame declared more than RFC
/// 6455's 125 payload bytes, or arrived fragmented),
/// `subprotocol_violation` (the upstream's 101 selected a subprotocol
/// outside the negotiated set, refused before the tunnel opened), and
/// `upstream_error` (a post-upgrade failure tore the tunnel down:
/// an upstream reset, timeout, or read error; WOR-2551's no-write
/// teardown). `direction` is
/// `client_to_upstream` or `upstream_to_client` for the two frame-scan
/// reasons, and `none` for the two that have no per-direction scan.
/// Both are proxy-authored constants; `tenant` and `origin` are
/// operator-scoped and pass through the cardinality limiter.
///
/// Registration failure yields no counter rather than a panic, the same
/// shape [`record_policy_panic`] uses. This runs while a connection is
/// already being torn down, and killing the process over a metric that
/// would not register is a worse outcome than the missing series.
pub fn record_websocket_teardown(reason: &str, direction: &str, tenant: &str, origin: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_websocket_teardowns_total",
            "WebSocket upgrades refused or tunnels torn down by the gateway, by closed reason, direction, tenant, and origin",
            &["reason", "direction", "tenant", "origin"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        let tenant_san = sanitize_label("tenant", tenant);
        let origin_san = sanitize_label("origin", origin);
        counter
            .with_label_values(&[reason, direction, tenant_san.as_str(), origin_san.as_str()])
            .inc();
    }
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

/// Feedback and eval scores accepted by the ingestion sink (WOR-2581),
/// labeled by the evaluator `label` the caller supplied and by a coarse
/// `bucket` (`negative`, `neutral`, `positive`).
///
/// Two labels and no more. The score itself is deliberately not a label:
/// it is a value with 21 possible readings, and one series per reading
/// per evaluator is how a cardinality problem starts. The bucket answers
/// the question a dashboard actually asks ("is quality falling"), and
/// the exact distribution lives in `GET /api/scores`, which the console
/// charts.
///
/// The `label` is caller-supplied, so it is sanitized and length-capped
/// before it reaches here (`admin_scores::sanitize_label`). An evaluator
/// name is low-cardinality operator vocabulary in every real
/// deployment; a caller that invents one per request is the reason the
/// cap exists.
static FEEDBACK_SCORES_TOTAL: std::sync::LazyLock<Option<IntCounterVec>> = std::sync::LazyLock::new(
    || {
        match prometheus::register_int_counter_vec!(
            "sbproxy_feedback_scores_total",
            "Feedback and eval scores accepted by the ingestion sink, by evaluator label and sign bucket.",
            &["label", "bucket"]
        ) {
            Ok(metric) => Some(metric),
            Err(error) => {
                tracing::warn!(
                    metric = "sbproxy_feedback_scores_total",
                    %error,
                    "metric family did not register; every panel reading it stays flat for this process"
                );
                None
            }
        }
    },
);

/// Record one accepted score (WOR-2581).
///
/// Called only after the score has been range-checked, so a value
/// outside the accepted bounds never reaches a series. An absent label
/// counts as `unlabeled`, matching what `GET /api/scores` aggregates it
/// under, so the metric and the JSON do not disagree about what an
/// unlabeled score is called.
pub fn record_feedback_score(label: Option<&str>, score: i64) {
    let bucket = if score < 0 {
        "negative"
    } else if score == 0 {
        "neutral"
    } else {
        "positive"
    };
    if let Some(metric) = FEEDBACK_SCORES_TOTAL.as_ref() {
        metric
            .with_label_values(&[label.unwrap_or("unlabeled"), bucket])
            .inc();
    }
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

/// Count a [`crate::events::ProxyEvent`] the `events:` egress did not
/// deliver, by sink and closed reason.
///
/// Separate from `sbproxy_telemetry_dropped_total` on purpose, and the
/// reason is the label set rather than the subject. That family is keyed
/// `{kind, reason}`, where `kind` is a compile-time constant naming a
/// subsystem. The question an operator has about an event sink is
/// per-sink ("is my SIEM webhook keeping up"), and answering it there
/// would mean folding the sink into `kind` and teaching every existing
/// `kind` consumer that some of its values are now sinks.
///
/// `sink` is the backend kind (`file` or `webhook`), not the operator's
/// name for it: one `events:` block selects one sink, so the label is
/// closed at two values and cannot grow with the config.
///
/// The closed reasons are `queue_full` (the bounded hand-off queue was
/// at capacity when a request tried to publish), `worker_stopped` (the
/// delivery thread is gone), `serialize_error`, `write_error`,
/// `http_error` (the endpoint answered non-2xx), `delivery_failed` (the
/// request never got an answer), `ssrf_rejected` (the configured URL
/// resolved onto an address the SSRF guard refuses), and
/// `egress_denied` (the collector, or a host it redirected to, is not
/// one egress authorization allows this proxy to reach).
///
/// This enumeration is the closest thing the label has to a schema, so
/// an alert whose `reason=~` union is written from it has to stay
/// complete: a new drop path that lands here and not in this list is
/// invisible to every dashboard built on it. The other copies are the
/// `event_sink` module docs and the reason table in `docs/events.md`.
///
/// A drop that is not counted is indistinguishable from a proxy that saw
/// no traffic, which is the failure this exists to make impossible.
/// Registration itself is the one failure this cannot report, so it is
/// swallowed with `.ok()` rather than unwrapped: the recorder runs from a
/// request-path publish, and a proxy that aborts because a counter would
/// not register is a worse outcome than one whose drop counter is
/// missing. The only ways `register_int_counter_vec!` fails are a
/// duplicate name and a malformed one, both of which
/// `events_dropped_counter_registers_and_increments` catches before a
/// release.
pub fn record_events_dropped(sink: &'static str, reason: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_events_dropped_total",
            "Proxy events the events: egress did not deliver, by sink and reason",
            &["sink", "reason"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        counter.with_label_values(&[sink, reason]).inc();
    }
}

/// Count a config (hot) reload outcome on
/// `sbproxy_config_reload_total{result}`. `result` is a closed string:
///
/// | Result | Meaning |
/// |---|---|
/// | `success` | The reload published |
/// | `failure` | The candidate was refused and the previous config keeps serving |
/// | `suspended` | The node is pinned to a configuration its boot fallback restored, so local reloads are deliberately inert (WOR-2459) |
///
/// Operators alert on a non-zero `failure` rate or on a stalled
/// `success` cadence (WOR-1101). `suspended` is deliberately its own
/// value rather than folded into `failure`: a pinned node is the state
/// the fallback is supposed to leave it in, and counting it as a failure
/// made that indistinguishable from a broken config on the dashboard
/// operators alert from.
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

// --- config authority (subscriber) metrics ---------------------------
//
// A subscriber pulls signed config bundles from an upstream authority,
// verifies them, merges them over its local document, and applies the
// result through the ordinary reload transaction. These five families are
// how an operator sees that the fleet's configuration plane is alive:
// which revision each node holds, how long since it last heard from the
// authority, and why a node stopped taking updates.

/// Publish the authority revision this node currently serves on
/// `sbproxy_config_bundle_revision`.
///
/// Set once per successful apply, and again at boot when a node applies a
/// cached bundle, so a fleet-wide `min()` shows the laggard.
pub fn set_config_bundle_revision(revision: i64) {
    use prometheus::{register_int_gauge, IntGauge};
    use std::sync::OnceLock;
    static G: OnceLock<IntGauge> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge!(
            "sbproxy_config_bundle_revision",
            "Authority revision of the config bundle this node currently serves",
        )
        .expect("config bundle revision gauge registers")
    });
    gauge.set(revision);
}

/// Publish the age of the config bundle this node serves on
/// `sbproxy_config_bundle_age_seconds`.
///
/// Age is measured from the moment this node received and applied the
/// bundle, not from the authority's `issued_at`. The authority's clock is
/// not this node's clock, and a skewed pair produces a negative or absurd
/// age exactly when an operator is trying to decide whether config
/// distribution is stuck. Receipt time is recorded alongside the cached
/// bundle, so the value survives a restart. `issued_at` is still enforced
/// through the bundle's own expiry check.
pub fn set_config_bundle_age_seconds(age_seconds: f64) {
    use prometheus::{register_gauge, Gauge};
    use std::sync::OnceLock;
    static G: OnceLock<Gauge> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_gauge!(
            "sbproxy_config_bundle_age_seconds",
            "Seconds since this node received the config bundle it currently serves",
        )
        .expect("config bundle age gauge registers")
    });
    gauge.set(age_seconds);
}

/// Count one config-bundle fetch cycle on
/// `sbproxy_config_bundle_fetch_total{result}`.
///
/// `result` is a closed string:
///
/// | Result | Meaning |
/// |---|---|
/// | `ok` | Fetched, verified, merged, and applied. |
/// | `not_modified` | The authority answered 304, or re-served the revision this node already holds. No compile and no reload. |
/// | `unreachable` | Connect or read failure, timeout, or a status other than 200 and 304. The cached bundle keeps serving. |
/// | `verify_failed` | Signature, schema, digest, expiry, declared-mode, or anti-replay refusal. |
/// | `compile_failed` | The merged document did not compile, could not be constructed, or still carried an unresolved `${VAR}` reference. |
/// | `denied_path` | The bundle named a path the subscriber owns outright. |
/// | `reload_busy` | Another reload held the reload lock; the cycle was skipped and the next interval retries. |
pub fn record_config_bundle_fetch(result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_config_bundle_fetch_total",
            "Config bundle fetch cycles, by result",
            &["result"],
        )
        .expect("config bundle fetch counter registers")
    });
    counter.with_label_values(&[result]).inc();
}

/// Count one config bundle that applied cleanly on
/// `sbproxy_config_bundle_applied_total`.
///
/// Disjoint from [`record_config_bundle_applied_degraded`] on purpose: a
/// reload that published the pipeline while a subsystem stayed on prior
/// state is not a clean apply, and folding the two together would make
/// the healthy counter unusable as an alert baseline.
pub fn record_config_bundle_applied() {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_config_bundle_applied_total",
            "Config bundles applied with every subsystem reloaded cleanly",
        )
        .expect("config bundle applied counter registers")
    });
    counter.inc();
}

/// Count one config bundle whose apply left a subsystem behind on
/// `sbproxy_config_bundle_applied_degraded_total`.
///
/// The pipeline is live on the new configuration, but at least one
/// subsystem carries prior state. Alert on any non-zero rate here.
pub fn record_config_bundle_applied_degraded() {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_config_bundle_applied_degraded_total",
            "Config bundles applied while at least one subsystem stayed on prior state",
        )
        .expect("config bundle degraded counter registers")
    });
    counter.inc();
}

// --- config source (git) metrics --------------------------------------
//
// A `source:` block resolves the config document from somewhere other
// than the local file, today a git repository. These two families make a
// stuck source as visible as a stale bundle: the counter says whether
// the last resolution worked and why not, and the info gauge says which
// commit the node is actually running.

/// Count one config-source resolution on
/// `sbproxy_config_source_fetch_total{kind,result}`.
///
/// `kind` is the `source.kind` that was resolved (`git` or
/// `git_overlay`). `result` is a closed string:
///
/// | Result | Meaning |
/// |---|---|
/// | `ok` | Resolved, and the resolved commit differs from the one already serving, so it was compiled and applied. |
/// | `not_modified` | Resolved to the commit already serving. No compile and no reload. |
/// | `unreachable` | The remote could not be reached, or `git` is not installed. The cached document keeps serving. |
/// | `timeout` | The fetch did not finish inside `timeout_secs` and the child process was killed. |
/// | `revision_mismatch` | `revision` pins a commit sha and the resolved `HEAD` is a different commit. |
/// | `verify_failed` | `verify_signature` is set and the tag or commit carries no signature this host can verify. |
/// | `invalid` | The source block, the resolved path, or the resolved document itself is unusable. |
/// | `compile_failed` | The resolved document did not compile, could not be constructed, or left a node-local `${VAR}` unresolved. |
/// | `reload_busy` | Another reload held the reload lock; the cycle was skipped and the next interval retries. |
/// | `suspended` | This node is pinned to a configuration its boot fallback restored, so the poller is deliberately inert (WOR-2459). Its own value rather than `not_modified`: the commit did move, and the operator's fix is being held back rather than absent. |
pub fn record_config_source_fetch(kind: &'static str, result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_config_source_fetch_total",
            "Config source resolutions, by source kind and result",
            &["kind", "result"],
        )
        .expect("config source fetch counter registers")
    });
    counter.with_label_values(&[kind, result]).inc();
}

/// Publish the commit the config source resolved to on
/// `sbproxy_config_source_revision_info{sha}`.
///
/// An info-style gauge: the value is always `1` and the commit travels
/// as a label, which is how an operator joins "which config" onto every
/// other series from this node. The previous label set is removed before
/// the new one is set, so a node that has followed a branch for a year
/// exports one series rather than a year of them.
pub fn set_config_source_revision_info(sha: &str) {
    use prometheus::{register_int_gauge_vec, IntGaugeVec};
    use std::sync::{Mutex, OnceLock};
    static G: OnceLock<IntGaugeVec> = OnceLock::new();
    static CURRENT: Mutex<Option<String>> = Mutex::new(None);
    let gauge = G.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_config_source_revision_info",
            "Commit the config source resolved to; always 1, the commit is the label",
            &["sha"],
        )
        .expect("config source revision gauge registers")
    });
    let mut current = CURRENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if current.as_deref() == Some(sha) {
        return;
    }
    if let Some(previous) = current.as_deref() {
        let _ = gauge.remove_label_values(&[previous]);
    }
    gauge.with_label_values(&[sha]).set(1);
    *current = Some(sha.to_string());
}

// --- config history (revision ring) metrics ---------------------------
//
// `sbproxy-core`'s `ConfigHistoryRecorder` wraps the durable,
// content-addressed ring of every config this process has applied. These
// two families make the ring's own state visible without reading its
// admin routes: which revision is current, and how many entries the ring
// is carrying.

/// Publish the ring's current entry on
/// `sbproxy_config_revision_info{revision,digest,provenance}`.
///
/// An info-style gauge, the same idiom as
/// [`set_config_source_revision_info`]: the value is always `1` and the
/// revision, digest, and provenance travel as labels. `revision` only
/// grows and `digest` changes on every distinct document the ring
/// records, so left unmanaged this would mint one series per revision a
/// process has ever applied over its lifetime. The previous label set is
/// removed before the new one is set, so a long-lived node exports one
/// series, not a history of them; the ring itself is where the history
/// lives.
///
/// `provenance` is a closed string naming where the revision's document
/// came from (`local` or `git`, matching `sbproxy_config::BaseOrigin`'s
/// variants); `digest` is the ring's bounded lowercase-hex SHA-256, and
/// `revision` is the ring's monotonic counter rendered as a string.
/// Callers are expected to pass values already shaped this way rather
/// than raw, unbounded strings.
pub fn set_config_revision_info(revision: u64, digest: &str, provenance: &str) {
    use prometheus::{register_int_gauge_vec, IntGaugeVec};
    use std::sync::{Mutex, OnceLock};
    static G: OnceLock<IntGaugeVec> = OnceLock::new();
    static CURRENT: Mutex<Option<(String, String, String)>> = Mutex::new(None);
    let gauge = G.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_config_revision_info",
            "Current entry in the config revision ring; always 1, the revision/digest/provenance are the labels",
            &["revision", "digest", "provenance"],
        )
        .expect("config revision info gauge registers")
    });
    let revision = revision.to_string();
    let mut current = CURRENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let unchanged = current
        .as_ref()
        .is_some_and(|(r, d, p)| r == &revision && d == digest && p == provenance);
    if unchanged {
        return;
    }
    if let Some((prev_revision, prev_digest, prev_provenance)) = current.as_ref() {
        let _ = gauge.remove_label_values(&[prev_revision, prev_digest, prev_provenance]);
    }
    gauge
        .with_label_values(&[revision.as_str(), digest, provenance])
        .set(1);
    *current = Some((revision, digest.to_string(), provenance.to_string()));
}

/// Project repositories declared under `origin_sources`, by runtime
/// tier and whether the entry is pinned to an immutable revision
/// (WOR-2436).
///
/// Set at config load, so it describes the document this process is
/// running rather than an aggregation cycle. Two questions it answers
/// that nothing else does: whether a fleet that should be pulling N
/// project repositories has quietly dropped to zero, and whether any
/// entry is following a movable ref. The second series is always zero in
/// a `production` tier, because the load-time check refuses the config
/// outright, so a non-zero reading there means a node is running a
/// document that predates the rule.
///
/// Registration failure is swallowed rather than panicked on. The
/// neighbours in this file predate the rule that production code ends no
/// process it cannot recover from; a config load that died because a
/// gauge would not register would take the proxy down over a number.
pub fn set_origin_source_entries(tier: &str, pinned: bool, count: i64) {
    use prometheus::{register_int_gauge_vec, IntGaugeVec};
    use std::sync::OnceLock;
    static G: OnceLock<Option<IntGaugeVec>> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_origin_source_entries",
            "Project repositories declared under origin_sources, by runtime tier and pin state",
            &["tier", "pinned"]
        )
        .ok()
    });
    if let Some(gauge) = gauge.as_ref() {
        gauge
            .with_label_values(&[tier, if pinned { "true" } else { "false" }])
            .set(count);
    }
}

/// Publish one aggregation round's per-outcome entry counts on
/// `sbproxy_aggregate_entries`.
///
/// A gauge rather than a counter because the question an operator has is
/// "how many of my fifty project repositories are unreachable right
/// now", not "how many fetches have ever failed". Every outcome is
/// written on every round, including the zeroes, so a failure that
/// clears shows as the drop rather than as a series that stops moving.
///
/// The label is the outcome and never the entry name: fifty entries
/// would be fifty series that churn as the block is edited, and the
/// entry that failed is named in the structured log and in the CLI
/// output where a name belongs.
///
/// Registration failure is swallowed rather than panicked on, matching
/// the neighbours in this file: an aggregation that died because a gauge
/// would not register would stop a fleet's config over a number.
pub fn set_aggregate_entries(outcome: &str, count: i64) {
    use prometheus::{register_int_gauge_vec, IntGaugeVec};
    use std::sync::OnceLock;
    static G: OnceLock<Option<IntGaugeVec>> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_aggregate_entries",
            "origin_sources entries by the outcome of the last aggregation round",
            &["outcome"]
        )
        .ok()
    });
    if let Some(gauge) = gauge.as_ref() {
        gauge.with_label_values(&[outcome]).set(count);
    }
}

/// Record how long one composition took, fetches included, on
/// `sbproxy_aggregate_compose_duration_seconds`.
///
/// The buckets run from a fifth of a second to five minutes because the
/// whole spread is interesting: a round that resolves nothing new
/// finishes in milliseconds, and a cold round against fifty
/// repositories is bounded by `deadline_secs`, whose default is 300.
pub fn record_aggregate_compose_duration(seconds: f64) {
    use prometheus::{register_histogram, Histogram};
    use std::sync::OnceLock;
    static H: OnceLock<Option<Histogram>> = OnceLock::new();
    let histogram = H.get_or_init(|| {
        register_histogram!(
            "sbproxy_aggregate_compose_duration_seconds",
            "Wall-clock time for one aggregation round, fetches included",
            vec![0.2, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]
        )
        .ok()
    });
    if let Some(histogram) = histogram.as_ref() {
        histogram.observe(seconds);
    }
}

/// Publish the revision the aggregator last published on
/// `sbproxy_aggregate_published_revision`.
///
/// Zero means this aggregator has published nothing yet. A revision that
/// stops advancing while `sbproxy_aggregate_entries{outcome="resolved"}`
/// keeps moving is the steady state the change detector exists to
/// produce, not a fault, which is why the two are read together.
pub fn set_aggregate_published_revision(revision: i64) {
    use prometheus::{register_int_gauge, IntGauge};
    use std::sync::OnceLock;
    static G: OnceLock<Option<IntGauge>> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge!(
            "sbproxy_aggregate_published_revision",
            "Config-authority revision the aggregator last published"
        )
        .ok()
    });
    if let Some(gauge) = gauge.as_ref() {
        gauge.set(revision);
    }
}

/// Count one aggregation round's publish decision on
/// `sbproxy_aggregate_rounds_total`.
///
/// The outcomes are `published`, `unchanged`, and `refused`. The middle
/// one is the point: a round that composes a byte-identical document
/// publishes nothing, and without a counter for it an operator cannot
/// tell a working change detector from a stalled aggregator.
pub fn record_aggregate_round(outcome: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_aggregate_rounds_total",
            "Aggregation rounds by what the round decided to do",
            &["outcome"]
        )
        .ok()
    });
    if let Some(counter) = counter.as_ref() {
        counter.with_label_values(&[outcome]).inc();
    }
}

/// Publish the config revision ring's current entry count on
/// `sbproxy_config_history_entries`.
///
/// Set at recorder construction from the ring's existing on-disk state
/// (so a restart reports the truth before the first reload), and again
/// after every successful append, so this always mirrors what the ring
/// itself holds rather than a count of events this process has seen.
pub fn set_config_history_entries(count: i64) {
    use prometheus::{register_int_gauge, IntGauge};
    use std::sync::OnceLock;
    static G: OnceLock<IntGauge> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge!(
            "sbproxy_config_history_entries",
            "Entries currently held in the config revision ring",
        )
        .expect("config history entries gauge registers")
    });
    gauge.set(count);
}

/// Set `sbproxy_config_lkg_revision` to the revision the config ring's
/// last-known-good pointer names, or `-1` when it names none (WOR-2458).
///
/// `-1` rather than an absent series: "this node has no rollback target"
/// is the answer an operator most needs during an incident, and an
/// absent series answers it with silence. Every real revision is
/// positive, so the sentinel cannot collide with one.
pub fn set_config_lkg_revision(revision: i64) {
    use prometheus::{register_int_gauge, IntGauge};
    use std::sync::OnceLock;
    static G: OnceLock<Option<IntGauge>> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge!(
            "sbproxy_config_lkg_revision",
            "Config ring revision the last-known-good pointer names, or -1 when it names none",
        )
        .ok()
    });
    let Some(gauge) = gauge else {
        return;
    };
    gauge.set(revision);
}

/// Count one soak signal's contribution to a verdict on
/// `sbproxy_config_soak_verdict_total{verdict,signal}` (WOR-2458).
///
/// `verdict` is a closed string:
///
/// | Verdict | Meaning |
/// |---|---|
/// | `passed` | The signal reported a pass, or the window closed passing |
/// | `failed` | The signal reported a failure, or the window closed failing |
/// | `abstain` | The signal had too little information to report anything |
/// | `inconclusive` | Every signal abstained, so the window reached no verdict |
/// | `superseded` | A newer revision applied mid-soak, so this window was dropped without ever reaching a verdict |
///
/// `abstain` and `inconclusive` are both first class on purpose. A soak
/// that never measures anything is a configuration problem worth
/// surfacing, not something to hide behind a green promotion.
///
/// `signal` is `degraded_subsystems`, `upstream_health`,
/// `request_outcome`, `operator_probe`, or `window` for the aggregate
/// verdict the window itself reached.
pub fn record_config_soak_verdict(verdict: &str, signal: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_config_soak_verdict_total",
            "Config soak outcomes, by verdict and reporting signal",
            &["verdict", "signal"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        counter.with_label_values(&[verdict, signal]).inc();
    }
}

/// Count one rollback attempt on `sbproxy_config_apply_total{outcome}`
/// (WOR-2460, WOR-2461).
///
/// Narrower than its name reads, and deliberately so: this family counts
/// what the **rollback** paths did, not every config apply. Ordinary
/// applies are already counted by `sbproxy_config_reload_total{result}`
/// and by `sbproxy_config_bundle_fetch_total{result}`, and a second
/// family covering the same events would give two different answers to
/// "how many applies happened" depending on which one an operator
/// happened to graph.
///
/// `outcome` is a closed string:
///
/// | Outcome | Meaning |
/// |---|---|
/// | `applied` | A rollback candidate compiled and published; the node is now serving the restored revision |
/// | `rejected` | A rollback was refused before anything was applied: an unknown target, a stale `expected_current`, a lineage break, an unconfirmed restart-class radius, or a document that no longer compiles on this binary |
/// | `reverted` | An **automatic** revert fired: a soak failed with `auto_revert` armed and the node re-applied its last known good |
/// | `declined` | A soak failed with `auto_revert` armed and the node decided **not** to revert: the change was not one an arc-swap can undo, its radius could not be measured, reverting would loop, or there was nowhere to go |
///
/// `reverted` and `applied` are disjoint by construction: an auto-revert
/// counts `reverted` and a manual rollback counts `applied`, so
/// "did anything roll this fleet back without an operator" is one query
/// rather than a subtraction.
///
/// `declined` exists because its absence made a whole fleet's inaction
/// unreadable. Every declining arm returns before the apply, so without
/// it a change that failed its soak on thirty nodes and reverted on none
/// left `reverted` flat, which is the same reading as "no soak failed".
/// The reason for each decline is on the `config_rollback` event rather
/// than on a label here, because the reason set is open enough that
/// putting it in a label would be a cardinality decision rather than a
/// naming one.
///
/// A node running the default `auto_revert: false` does **not** count
/// `declined`. It is the default, so counting it would fire on every
/// failed soak on almost every node and bury the four answers that need
/// acting on. That an unarmed node did nothing is already readable from
/// `sbproxy_config_soak_verdict_total{verdict="failed"}`.
pub fn record_config_apply(outcome: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_config_apply_total",
            "Config rollback attempts, by outcome",
            &["outcome"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        counter.with_label_values(&[outcome]).inc();
    }
}

/// Count one refused config candidate on
/// `sbproxy_config_rejected_total{reason}` (WOR-2462).
///
/// `reason` is a closed string: the four `sbproxy_config::RejectionReason`
/// values (`verify_failed`, `compile_failed`, `denied_path`,
/// `confinement_refused`), plus `ring_write_failed` for a candidate that
/// applied fine but could not be recorded, which skips its soak and so
/// holds the last-known-good pointer back exactly like a refusal does.
/// A skipped cycle (`reload_busy`) is a deferral rather than a refusal
/// and is deliberately not counted here.
pub fn record_config_rejection(reason: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_config_rejected_total",
            "Config candidates refused before applying, by reason",
            &["reason"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        counter.with_label_values(&[reason]).inc();
    }
}

/// Set `sbproxy_config_fallback_active` to 1 while this node is serving
/// a config its boot fallback rescued from the ring, 0 otherwise
/// (WOR-2459).
///
/// A node quietly serving a config nobody wrote is worse than one that
/// is down, because nobody goes looking for it. This gauge, a WARN at
/// startup, and the admin surface's degraded report are the three places
/// that say so.
pub fn set_config_fallback_active(active: bool) {
    use prometheus::{register_int_gauge, IntGauge};
    use std::sync::OnceLock;
    static G: OnceLock<Option<IntGauge>> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge!(
            "sbproxy_config_fallback_active",
            "1 while this node serves a config its boot fallback restored from the revision ring",
        )
        .ok()
    });
    let Some(gauge) = gauge else {
        return;
    };
    gauge.set(i64::from(active));
}

/// Count one config-revision announcement on
/// `sbproxy_config_authority_announce_total{result}`.
///
/// An authority publishes its current revision into typed cluster state
/// after every successful publication, so a mesh-member subscriber can pull
/// on the hint rather than waiting out its poll interval. The announcement
/// is an accelerator: `failed` costs propagation speed and nothing else,
/// because polling converges on its own.
///
/// `result` is a closed string:
///
/// | Result | Meaning |
/// |---|---|
/// | `published` | Written into typed cluster state. |
/// | `not_clustered` | This node has no mesh node, so there is nobody to tell. The ordinary case for a single-node authority serving subscribers over the internet. |
/// | `failed` | The cluster write was refused or its owner was unreachable. Subscribers still converge on their poll interval. |
pub fn record_config_authority_announce(result: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_config_authority_announce_total",
            "Config revision announcements published to the cluster, by result",
            &["result"],
        )
        .expect("config authority announce counter registers")
    });
    counter.with_label_values(&[result]).inc();
}

/// Count one read of the cluster's config-revision announcement on
/// `sbproxy_config_bundle_gossip_total{outcome}`.
///
/// Recorded once per probe by a mesh-member subscriber while it waits out
/// its poll interval. `hint` is the interesting series: it counts the pulls
/// gossip brought forward, so `rate(hint)` is what the accelerator is
/// actually buying. Every other outcome leaves the subscriber on its
/// interval.
///
/// `outcome` is a closed string:
///
/// | Outcome | Meaning |
/// |---|---|
/// | `hint` | An announced revision above this node's cursor. The poll interval was cut short and a full verify-and-apply pull ran. |
/// | `stale` | An announced revision at or below this node's cursor. No fetch. |
/// | `absent` | Nothing announced, or the announcement passed its TTL. |
/// | `unreadable` | The announcement could not be read or did not validate. |
pub fn record_config_bundle_gossip(outcome: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_config_bundle_gossip_total",
            "Cluster config-revision announcement probes, by outcome",
            &["outcome"],
        )
        .expect("config bundle gossip counter registers")
    });
    counter.with_label_values(&[outcome]).inc();
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
/// `sbproxy_ai_provider_attempts_total{provider, outcome}`. Gives
/// operators the per-provider load distribution and failure rate that a
/// bare "failover happened" signal cannot (WOR-1103).
///
/// `outcome` is a closed string: `success`, `error`, `client_disconnected`
/// for a call the gateway abandoned because the caller's connection was
/// gone (WOR-2690), and `moderation_cancelled` for a call dropped because
/// a parallel inspect-only input hook blocked first (WOR-2421). Keep it
/// closed and keep this list current: the registry row declares label
/// *names* only, so this comment is the only place the value set is written
/// down, and a dashboard that selects one value silently loses traffic to
/// a new one nobody recorded here.
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

/// Record an RFC 9421 signature that verified only against the
/// pre-conformance derivation of a request-target component, on
/// `sbproxy_signature_legacy_derivation_total{component}`.
///
/// `component` is `@target-uri` or `@request-target`, both compile-time
/// constants on the call path, so the series set is closed at two.
///
/// This is the one number that says whether the deprecation window can
/// close. The acceptance is otherwise a single `warn` line logged once
/// per process, which tells an operator that some signer somewhere has
/// not moved and nothing about whether that is still true today.
pub fn record_signature_legacy_derivation(component: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_signature_legacy_derivation_total",
            "RFC 9421 signatures accepted only against the pre-conformance derivation of a request-target component",
            &["component"],
        )
        .expect("signature legacy derivation counter registers")
    });
    counter.with_label_values(&[component]).inc();
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

/// Record a circuit breaker state transition on both the metric and a
/// structured, SIEM-observable log line (WOR-2486).
///
/// Call only on an actual transition, never per request: the three
/// production call sites (the load-balancer target breaker, the AI
/// provider breaker, the crawl-ledger HTTP breaker) all guard this
/// behind `if let Some((from, to)) = breaker.record_success()/
/// record_failure()`, which is `None` on the overwhelming majority of
/// calls. `record_circuit_breaker` alone (the metric-only sibling this
/// wraps) predates this function and stays as a direct call where a
/// caller has already decided a metric is enough.
///
/// `tenant` is `""` when the breaker has no tenant scope, which is the
/// common case: a circuit breaker in this codebase is keyed by origin
/// or provider, not by caller, so most transitions have nothing to
/// attribute to a tenant. Pass one when the call site actually knows
/// it.
pub fn record_circuit_breaker_transition(
    origin: &str,
    from_state: &str,
    to_state: &str,
    reason: &str,
    tenant: &str,
) {
    record_circuit_breaker(origin, from_state, to_state);
    let sanitized_origin = sanitize_label("origin", origin);
    tracing::warn!(
        target: "sbproxy::circuit_breaker",
        event = "circuit_breaker_transition",
        origin = %sanitized_origin,
        from = from_state,
        to = to_state,
        reason = reason,
        tenant = tenant,
        "circuit breaker state transition"
    );
}

/// Increment `sbproxy_upstream_status_retries_total{origin, status}`.
///
/// Called once per status-triggered upstream retry, at the moment the
/// retry is scheduled. Matched statuses that are skipped (method not
/// idempotent, body not replayable, `max_attempts` reached) are not
/// counted; they surface via `x-sbproxy-retry-skip-reason` instead.
pub fn record_upstream_status_retry(origin: &str, status: u16) {
    let origin = sanitize_label("origin", origin);
    let status = status.to_string();
    metrics()
        .upstream_status_retries
        .with_label_values(&[origin.as_str(), status.as_str()])
        .inc();
}

/// Increment `sbproxy_upstream_timeout_retries_total{origin, phase}`.
///
/// Called once per timeout-triggered upstream retry, at the moment
/// the retry is scheduled. `phase` is `connect` for TCP connect and
/// TLS handshake deadlines, `upstream` for read and write deadlines
/// on the established connection; no other value may be passed.
/// Timeouts that are not retried (policy does not allow them, cap
/// reached, response already started, body not replayable) are not
/// counted.
pub fn record_upstream_timeout_retry(origin: &str, phase: &str) {
    let origin = sanitize_label("origin", origin);
    metrics()
        .upstream_timeout_retries
        .with_label_values(&[origin.as_str(), phase])
        .inc();
}

/// Increment `sbproxy_lb_zone_locality_total{origin, verdict}`
/// (WOR-2328).
///
/// Called once per load-balancer selection the zone-locality stage
/// actually shaped. `verdict` is `local` (selection narrowed to the
/// proxy's own zone) or `spilled` (no same-zone target was healthy, so
/// selection widened across every eligible target). A selection the
/// stage stood down on records nothing, so the two series together
/// count exactly the selections locality decided.
///
/// The spill series is the one to alert on:
/// `rate(sbproxy_lb_zone_locality_total{verdict="spilled"}[5m]) > 0`
/// says traffic is crossing zones right now, paying the cross-AZ RTT
/// and the egress bill. Before this counter that event reached only a
/// `debug!` line, which `release_max_level_info` compiles out of a
/// release build, and the in-memory admin request ring, which is off
/// unless the admin server is enabled. On a release binary with admin
/// off, a total local-zone outage was invisible until the invoice
/// arrived.
///
/// The origin label is operator-supplied and passes through the
/// cardinality limiter; `verdict` is a closed two-value set.
pub fn record_zone_locality(origin: &str, verdict: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    // Registered through `.ok()` rather than an expect, the same shape
    // `record_policy_panic` uses: the unwrap/expect ratchet is at its
    // baseline and one metric family does not justify a panic path on
    // the serving side of a request already in flight.
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_lb_zone_locality_total",
            "Load-balancer selections shaped by the zone-locality stage, by verdict (local: narrowed to the proxy's own zone; spilled: no same-zone target was healthy)",
            &["origin", "verdict"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        let origin = sanitize_label("origin", origin);
        counter.with_label_values(&[origin.as_str(), verdict]).inc();
    }
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

/// Increment `sbproxy_request_body_drain_timeout_total`.
///
/// Called when the drain of a client's remaining request body, run after
/// sbproxy has already answered the request, hits its time bound. The
/// connection is then closed with bytes still unread, which is the
/// pre-WOR-2599 behavior and can cost the client the response it was
/// sent.
pub fn record_request_body_drain_timeout() {
    metrics().request_body_drain_timeout.inc();
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

/// Count one rate-limit denial that required peer counts to reach the limit.
///
/// This is the observable form of mesh rate limiting's approximation. On a
/// mesh-only cluster a node admits against its own count plus a merged view of
/// its peers, so this counter rises exactly when the merged view changed the
/// outcome: the local count alone would have admitted the request.
///
/// Read it two ways. Rising means convergence is doing work, which is the
/// healthy state on a busy multi-node cluster. Flat at zero while several
/// nodes serve the same limited key means dissemination is not reaching this
/// node, and it is enforcing a per-node limit while believing otherwise.
///
/// A counter rather than a gauge of the divergence magnitude on purpose. Every
/// request for every bucket would overwrite such a gauge, so it would sample
/// whichever bucket happened to be last rather than describing the cluster.
pub fn record_rate_limit_cluster_peer_denial() {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_rate_limit_cluster_peer_denials_total",
            "Rate-limit denials that needed peer counts: the local count alone would have admitted",
        )
        .expect("rate_limit_cluster_peer_denials counter registers")
    })
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
/// `docs/events.md`, this is a paging signal:
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

// --- WOR-2405: decision audit publication accounting ---
//
// Two new families rather than two more labels on
// `sbproxy_policy_audit_events_dropped_total`. That counter is
// `SupportLevel::Stable`, and a label added to a live counter changes
// every series an operator already selects on, so the dashboards and
// alert rules built against it stop matching. A new name costs a doc row;
// a widened label set costs somebody's paging rule.
//
// The two carry deliberately different label sets, and the asymmetry is
// the point rather than an oversight.
//
// The drop counter carries `tenant` because the question a drop raises is
// whose audit trail just went lossy, and `event` alone cannot answer it.
// It is the same reasoning `record_policy_audit_event_dropped` is built
// on: one noisy tenant must not silently degrade another tenant's
// evidence, and an operator cannot act on a drop they cannot attribute.
//
// The emit counter carries `outcome` instead, because what it answers is
// the shape of the feed: an audit stream that is all `allow` and an audit
// stream that is all `deny` are different systems, and only the second is
// worth waking somebody for. It does not carry `tenant`, because the
// product of the two would multiply the label budget for a counter that
// should be dense, and the per-tenant cut is already available from two
// families that do carry it: this pair's own drop counter, and
// `sbproxy_decision_event_total{event, engine, outcome, origin, tenant}`,
// which counts the decisions these records are made from.
//
// `event` and `outcome` are closed by construction, the same way the
// `sbproxy_decision_event_*` families close theirs. Both recorders take
// `DecisionEvent` / `DecisionOutcome` and read `as_label()`, so no caller
// can widen either dimension and neither has to spend a cardinality
// budget slot to be safe. `tenant` is the only open dimension here, and
// it goes through `sanitize_label_budget` exactly as its policy sibling
// does.

/// Increment `sbproxy_decision_audit_events_dropped_total{event, tenant}`.
///
/// Called when a [`DecisionAudit`](crate::decision::DecisionAudit) could
/// not be handed to the audit bus: the bounded queue was full, the
/// receiver was gone, or no bus was installed. The publisher never blocks
/// the request path to make room, so the record is lost, and a lossy
/// audit feed is worse than an absent one because the gap reads as
/// evidence that nothing was decided. Treat a non-zero rate as a paging
/// signal, the same way [`record_policy_audit_event_dropped`] is treated.
///
/// `event` names which feed lost coverage, which is the first thing an
/// operator needs and the only thing that distinguishes one flooding
/// event from a bus that is failing for everybody. `tenant` names whose
/// trail it was.
///
/// Registration failure is swallowed with `.ok()` rather than unwrapped,
/// following [`record_events_dropped`], and for the same reason: this
/// runs from a request-path publish, and a proxy that aborts because a
/// counter would not register is a worse outcome than one whose drop
/// counter is missing. The only ways `register_int_counter_vec!` fails
/// are a duplicate name and a malformed one, and the registry drift
/// guard catches both before a release.
pub fn record_decision_audit_dropped(event: DecisionEvent, tenant: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_decision_audit_events_dropped_total",
            "Decision audit records dropped before publication, by decision event and tenant",
            &["event", "tenant"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        let tenant = sanitize_label_budget(
            "sbproxy_decision_audit_events_dropped_total",
            "tenant",
            tenant,
        );
        counter
            .with_label_values(&[event.as_label(), tenant.as_str()])
            .inc();
    }
}

/// Increment `sbproxy_decision_audit_events_total{event, outcome}`.
///
/// One increment per [`DecisionAudit`](crate::decision::DecisionAudit)
/// accepted by the audit bus. This is the affirmative half of the pair:
/// a drop counter on its own cannot tell a healthy quiet feed from a
/// broken one, because both read zero. Pairing an emit counter with a
/// drop counter is what makes "my `cache.admit` audit trail stopped" a
/// question the metrics can answer, and it follows the policy family,
/// where `record_policy_audit_emitted` sits beside
/// [`record_policy_audit_event_dropped`] for the same reason.
///
/// `outcome` rather than `tenant`: see the note above this pair. The
/// counter describes the shape of the feed, and its per-tenant cut is
/// already carried by the drop counter and by
/// `sbproxy_decision_event_total`.
///
/// Registration failure is swallowed with `.ok()` for the reason given on
/// [`record_decision_audit_dropped`].
pub fn record_decision_audit_emitted(event: DecisionEvent, outcome: DecisionOutcome) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_decision_audit_events_total",
            "Decision audit records published on the audit bus, by decision event and outcome",
            &["event", "outcome"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        counter
            .with_label_values(&[event.as_label(), outcome.as_label()])
            .inc();
    }
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

// --- WOR-2100: payment settlement observability ---
//
// Four label names, and every one of them is closed by construction rather
// than by sanitization. `rail` is the settlement rail's stable spelling,
// its four values plus `none` for a rail negotiation that failed before a
// rail was chosen. `operation` names the settlement or recovery step from a
// fixed list. `outcome` is what that step concluded, drawn from the closed
// vocabulary the step decides in. `provider_class` names the kind of
// provider rather than the provider itself: `facilitator`,
// `card_processor`, `lightning_node`, or `meter`.
//
// None of these recorders takes a payer identifier, a tenant, a quote id, a
// challenge id, an intent id, a provider reference, a PaymentIntent id, an
// invoice, a credential, a client secret, a macaroon, a rune, or provider
// error text. Those values are not sanitized down to a bounded set here;
// they are not parameters at all, which is the only form of that promise a
// reader can check by looking at the signature.
//
// That is also why nothing below calls `sanitize_label`. A closed enum
// cannot overflow a cardinality budget, and routing it through the limiter
// would consume budget slots that an unbounded label actually needs.

/// Add to `sbproxy_payment_settlement_total{rail, operation, outcome}`.
///
/// One observation per settlement transition, from either half of the
/// settlement path. `operation` says which half decided, and it is the
/// label to read first, because each half concludes in its own closed
/// vocabulary:
///
/// - `challenge` and `redeem` are the request-path gate. `challenge`
///   concludes `prepared` or `no_acceptable_rail`. `redeem` concludes
///   `succeeded`, `unavailable`, or the payment problem code that refused
///   it (`proof_replayed`, `challenge_expired`, `rejected`, and the rest
///   of that closed set).
/// - Every other `operation` value names an attempt operation the recovery
///   sweep reconciled, and concludes in the reconciliation vocabulary:
///   `succeeded`, `terminal`, `retry_wait`, or `needs_reconciliation`.
///   There, `outcome` is the state the store committed and never the
///   adapter's return value, so a provider that answered "paid" while the
///   durable record moved to `needs_reconciliation` is counted as
///   `needs_reconciliation`. That is the point: the metric has to agree
///   with the thing that decides access.
///
/// Splitting the two halves this way, rather than by adding a fourth
/// label, is what keeps every query written against the recovery sweep
/// selecting exactly the rows it selected before: the request path only
/// ever adds `operation` values the sweep cannot produce.
///
/// `count` may be zero. `inc_by(0)` creates the series without asserting a
/// transition, which is what lets startup seed the series for each
/// configured rail. An absent series then means the rail is not
/// configured, rather than that nothing has settled yet.
pub fn record_payment_settlement(rail: &str, operation: &str, outcome: &str, count: u64) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_payment_settlement_total",
            "Payment settlement transitions, by rail, deciding step, and outcome",
            &["rail", "operation", "outcome"],
        )
        .expect("payment settlement counter registers")
    });
    counter
        .with_label_values(&[rail, operation, outcome])
        .inc_by(count);
}

/// Increment
/// `sbproxy_payment_provider_calls_total{rail, operation, provider_class}`.
///
/// One observation per call that actually left the process. It exists so an
/// operator can see that reconciliation is doing provider reads and not
/// provider writes: `operation` is `query` for every reconciliation, and a
/// `settle` on this family from a background sweep would be a bug with a
/// visible signature.
pub fn record_payment_provider_call(rail: &str, operation: &str, provider_class: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_payment_provider_calls_total",
            "Payment provider calls that left the process, by rail, operation, and provider class",
            &["rail", "operation", "provider_class"],
        )
        .expect("payment provider call counter registers")
    });
    counter
        .with_label_values(&[rail, operation, provider_class])
        .inc();
}

/// Add to `sbproxy_payment_recovery_total{operation, outcome}`.
///
/// The recovery worker reports its work as durable-row counts rather than
/// as events, so this takes a delta. `count` may be zero: incrementing by
/// zero creates the series, which makes an idle recovery queue draw a flat
/// line instead of disappearing from the scrape.
///
/// There is no `rail` label here on purpose. A sweep claims rows across
/// every rail in one batch and reports one total, so splitting it by rail
/// would mean inventing an attribution the worker never computed.
///
/// `outcome = "failed"` is the one value that is not a durable row. It
/// counts sweeps of that operation that returned a store error and moved
/// nothing, which is what makes a flat row series next to it readable as an
/// outage rather than as an empty queue. The other stages of the same tick
/// still ran.
pub fn record_payment_recovery(operation: &str, outcome: &str, count: u64) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_payment_recovery_total",
            "Durable rows the settlement recovery worker moved, by recovery operation and committed outcome",
            &["operation", "outcome"],
        )
        .expect("payment recovery counter registers")
    });
    counter
        .with_label_values(&[operation, outcome])
        .inc_by(count);
}

/// Add to `sbproxy_payment_worker_ticks_total`.
///
/// A tick is one completed pass over every recovery queue. The worker
/// counts its own ticks, so the observer hands over a delta rather than
/// calling once per tick and hoping it never misses one.
///
/// A flat tick rate beside a growing `sbproxy_payment_recovery_total` is a
/// backlog. A tick rate that stops entirely is a worker that died, which is
/// otherwise invisible from outside because the request path keeps serving
/// and only the recovery of stuck payments quietly stops.
pub fn record_payment_worker_ticks(completed: u64) {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_payment_worker_ticks_total",
            "Completed settlement recovery worker ticks"
        )
        .expect("payment worker tick counter registers")
    });
    counter.inc_by(completed);
}

/// Set `sbproxy_payment_worker_drain_clean` to 1 or 0.
///
/// Reports the truth about shutdown rather than the intent. `0` means the
/// configured shutdown deadline elapsed and the loop was abandoned partway
/// through a tick. Nothing is corrupted by that, because every transition
/// the worker performs is its own committed transaction, but the operator
/// should be able to tell the difference between a drain and a stop.
pub fn record_payment_worker_drain(clean: bool) {
    use prometheus::{register_int_gauge, IntGauge};
    use std::sync::OnceLock;
    static G: OnceLock<IntGauge> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge!(
            "sbproxy_payment_worker_drain_clean",
            "1 when the settlement worker drained inside its shutdown deadline, 0 when it was abandoned mid tick"
        )
        .expect("payment worker drain gauge registers")
    });
    gauge.set(i64::from(clean));
}

/// Set `sbproxy_payment_rail_enabled{rail}` to 1 or 0.
///
/// Stamped once per rail at runtime assembly, after the compiled feature
/// check and after the adapter registered. It answers the question an
/// operator asks first when a payer reports a rail they cannot use: is this
/// build even carrying that adapter, and did this configuration turn it on.
pub fn record_payment_rail_enabled(rail: &str, enabled: bool) {
    use prometheus::{register_int_gauge_vec, IntGaugeVec};
    use std::sync::OnceLock;
    static G: OnceLock<IntGaugeVec> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_payment_rail_enabled",
            "1 for each settlement rail this build compiled and this configuration registered, 0 otherwise",
            &["rail"],
        )
        .expect("payment rail gauge registers")
    });
    gauge.with_label_values(&[rail]).set(i64::from(enabled));
}

// --- WOR-2169: the usage bridge ---
//
// Unlike the settlement families above, both of these carry `tenant_id`,
// and the difference is not an inconsistency. A settlement metric describes
// one payment and a payer identifier on it would be a way to read who paid
// for what. A usage metric describes metered consumption, this deployment
// is multi-tenant, and a billing counter that merged every tenant into one
// series answers no question an operator has: "are we billing anyone" and
// "are we billing *this customer*" are different questions and only the
// second one gets anybody out of bed. The neighbouring `sbproxy_meter_*`
// families label themselves the same way and for the same reason.
//
// Every other label is closed by construction. `reporter` is a registered
// reporter name, `resource_type` is one of three values held in code, and
// `failure_mode` is the four-posture vocabulary. No route, no model, no
// tool, no customer identifier, and no usage identifier is a parameter
// here: the durable row carries all of those, and it is the thing an
// operator reconciles against anyway.

/// Keep a usage-bridge tenant label bounded, and never empty.
///
/// An empty label value is legal Prometheus and useless to read: it renders
/// as an absent dimension and silently joins with every other series that
/// omits the label, which for a billing counter means one tenant's spend
/// quietly aggregating into another's panel. `sbproxy_meter_*` substitutes
/// the same placeholder for the same reason.
fn usage_bridge_tenant(tenant_id: &str) -> String {
    if tenant_id.is_empty() {
        return "unknown".to_string();
    }
    sanitize_label("tenant_id", tenant_id)
}

/// Increment
/// `sbproxy_usage_bridge_enqueued_total{tenant_id, reporter, resource_type, result}`.
///
/// One observation per billable unit the request path offered to the
/// durable queue. `result` separates `queued` from `duplicate`, because the
/// store deduplicates on the provider identifier and a duplicate is the
/// idempotency contract working rather than a failure. A deployment where
/// that series is entirely `duplicate` has an identifier that is not varying
/// when it should, which is the shape of a silently dropped charge.
pub fn record_usage_bridge_enqueued(
    tenant_id: &str,
    reporter: &str,
    resource_type: &str,
    inserted: bool,
) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_usage_bridge_enqueued_total",
            "Billable units the request path queued for a usage reporter, by tenant, reporter, resource type, and whether the row was new",
            &["tenant_id", "reporter", "resource_type", "result"],
        )
        .expect("usage bridge enqueue counter registers")
    });
    let tenant = usage_bridge_tenant(tenant_id);
    let result = if inserted { "queued" } else { "duplicate" };
    counter
        .with_label_values(&[tenant.as_str(), reporter, resource_type, result])
        .inc();
}

/// Increment `sbproxy_usage_bridge_gap_total{tenant_id, failure_mode}`.
///
/// Nonzero means a served request produced a billable unit that never
/// reached the durable queue, so the customer will be under-billed and
/// nothing downstream will notice on its own. This is the family to alert
/// on. Under `degraded` and `closed` there is also a signed `usage_gap`
/// marker on the receipt chain naming the exact claim; under `open` this
/// counter is the whole record.
pub fn record_usage_bridge_gap(tenant_id: &str, failure_mode: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_usage_bridge_gap_total",
            "Billable units that could not be queued for a usage reporter, by tenant and the posture in force",
            &["tenant_id", "failure_mode"],
        )
        .expect("usage bridge gap counter registers")
    });
    let tenant = usage_bridge_tenant(tenant_id);
    counter
        .with_label_values(&[tenant.as_str(), failure_mode])
        .inc();
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
/// Called by [`crate::audit::ConfigAuditEntry::emit`],
/// [`crate::audit::SecurityAuditEntry::emit`],
/// [`crate::audit::KeyAuditEntry::emit`], and
/// [`crate::audit::AdminActionAuditEntry::emit`] after each channel's own
/// tracing/ring step. `channel` is one of `config`, `security`, `key`,
/// `admin`; `outcome` is `ok` on success, `serialize_error` when a
/// channel's own JSON encode failed (the `config` and `security`
/// channels only), and `chain_error` when a configured chain rejected
/// the append (in each case the audit was dropped from that path, which
/// is itself worth alerting on).
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

/// Count one completed admin request-log export on
/// `sbproxy_admin_request_exports_total{format}` and the rows it wrote
/// on `sbproxy_admin_request_export_rows_total{format}` (WOR-2578).
///
/// `format` is the closed enum `csv|jsonl`, selected from a static
/// match in the admin route; no caller string becomes a label.
///
/// Why an export needs a counter from day one: `GET
/// /api/requests/export` is the one admin route that hands back the
/// operational log in bulk, which makes it the exfiltration shape of
/// the admin surface. The audit chain records that an export happened;
/// this pair is what an operator alerts on, because "exports per hour
/// tripled" and "one export wrote the whole ring" are rate questions
/// an audit ring cannot answer. Two families rather than one so a
/// dashboard can read rows-per-export without inventing a histogram
/// over a low-frequency event.
/// A registration failure warns once and leaves the family unscraped
/// rather than ending the admin request: an operator who cannot see the
/// export counter still gets the export, and still gets the audit
/// record, which is the load-bearing half.
pub fn record_admin_request_export(format: &'static str, rows: u64) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static EXPORTS: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    static ROWS: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let warn_failed = |name: &'static str, error: &prometheus::Error| {
        tracing::warn!(
            metric = name,
            %error,
            "admin export counter failed to register; export volume is not scrapeable"
        );
    };
    let exports = EXPORTS.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_admin_request_exports_total",
            "Admin request-log exports served, by format",
            &["format"],
        )
        .inspect_err(|error| warn_failed("sbproxy_admin_request_exports_total", error))
        .ok()
    });
    if let Some(counter) = exports {
        counter.with_label_values(&[format]).inc();
    }
    let row_counter = ROWS.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_admin_request_export_rows_total",
            "Rows written by admin request-log exports, by format",
            &["format"],
        )
        .inspect_err(|error| warn_failed("sbproxy_admin_request_export_rows_total", error))
        .ok()
    });
    if let Some(counter) = row_counter {
        counter.with_label_values(&[format]).inc_by(rows);
    }
}

/// Closed export formats for the live admin chargeback route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminChargebackExportFormat {
    /// The JSON admin route (`GET /admin/ai-chargeback`).
    Json,
    /// The CSV admin route (`GET /admin/ai-chargeback.csv`).
    Csv,
}

impl AdminChargebackExportFormat {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
        }
    }
}

/// Closed refusal reasons for admin chargeback exports and pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminChargebackExportRefusalReason {
    /// The supplied `cursor` did not decode to a valid page offset.
    InvalidCursor,
    /// The supplied `limit` was absent, non-numeric, or not positive.
    InvalidLimit,
    /// The caller requested an unsupported `schema_version`.
    UnsupportedSchemaVersion,
    /// The response would exceed the bounded admin byte budget.
    ResponseTooLarge,
}

impl AdminChargebackExportRefusalReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCursor => "invalid_cursor",
            Self::InvalidLimit => "invalid_limit",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::ResponseTooLarge => "response_too_large",
        }
    }
}

/// Count one live admin chargeback-export refusal on
/// `sbproxy_admin_chargeback_export_refusals_total{format, reason}`.
///
/// This covers request-shape and page/response-admission refusals on the
/// authenticated chargeback export boundary. Both labels are closed
/// vocabularies selected in Rust, never caller input.
pub fn record_admin_chargeback_export_refusal(
    format: AdminChargebackExportFormat,
    reason: AdminChargebackExportRefusalReason,
) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static REFUSALS: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let warn_failed = |name: &'static str, error: &prometheus::Error| {
        tracing::warn!(
            metric = name,
            %error,
            "admin chargeback export refusal counter failed to register; refusal volume is not scrapeable"
        );
    };
    let refusals = REFUSALS.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_admin_chargeback_export_refusals_total",
            "Admin chargeback export refusals, by format and closed reason",
            &["format", "reason"],
        )
        .inspect_err(|error| warn_failed("sbproxy_admin_chargeback_export_refusals_total", error))
        .ok()
    });
    if let Some(counter) = refusals {
        counter
            .with_label_values(&[format.as_str(), reason.as_str()])
            .inc();
    }
}

/// Count one audit-chain read attempt on
/// `sbproxy_audit_chain_read_total{channel, outcome}` (WOR-2579).
///
/// `channel` is one of `security`, `config`, `key`, `admin`. `outcome` is
/// `verified` when every link and signature held, `broken` when the walk
/// stopped at a bad record, `unreadable` when the file could not be
/// walked at all, and `denied` when the viewer refused the read before
/// walking anything. A refusal increments all four channels, because it
/// refuses all four.
///
/// The reason this exists rather than leaving the verdict on the page: a
/// broken chain that only a person looking at the console can see is a
/// finding nobody is on call for. `broken`, `unreadable` and `denied`
/// are all alertable from the moment this ships, and
/// `increase(...{outcome!="verified"}[15m]) > 0` is the rule an operator
/// wants. Both label values are closed vocabularies from this crate,
/// never caller input, and both parameters are `&'static str` so that
/// stays true by construction: a caller-supplied `String` cannot be
/// passed here at all, which is what keeps this family off the
/// cardinality limiter honestly rather than by assertion.
///
/// What that rule does **not** cover, so nobody sizes their response
/// wrong: the shortfall comparison behind `broken` counts what *this
/// process* wrote. A chain file truncated at the tail and then read
/// after a restart re-baselines on boot, links and signs perfectly, and
/// reports `verified`. Records written before the last restart are
/// covered by `sbproxy audit verify` against an offsite copy, not by
/// this counter.
pub fn record_audit_chain_read(channel: &'static str, outcome: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    // `.ok()` rather than `.expect(...)`, the same shape
    // [`record_key_store_outage`] uses: registration can only fail on a
    // duplicate name, which the metric-registry guard catches at build
    // time, and a counter is not worth ending the process over on a path
    // whose whole job is to report on somebody else's failure.
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_audit_chain_read_total",
            "Audit-chain reads served by the console viewer, by verification outcome",
            &["channel", "outcome"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        counter.with_label_values(&[channel, outcome]).inc();
    }
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
/// of `ok`, `runtime_error`, `timeout`, `admission_timeout`,
/// `queue_timeout`, `cancelled`, `input_limit`, `output_limit`,
/// `memory_cap`, `table_cap`, `stack_cap`, `instruction_cap`,
/// `guest_exception`, or `runtime_unavailable`. Every value is selected from
/// a static match; guest and configuration strings never become labels. The
/// matching duration histogram is emitted by [`record_script_duration`].
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
/// `sbproxy_idempotency_cache_results_total{backend, result}`.
///
/// `backend` is the cache implementation that answered (`memory` or
/// `kv`), so a broken shared store is visible next to a cold local one.
///
/// `result` is a closed set in two halves. The first half is the
/// request's outcome, and exactly one of these is recorded per request
/// the middleware *resolves*, so they sum to the middleware's own
/// throughput rather than to the origin's request count. A request the
/// middleware skips records nothing: an oversize request or response
/// body, a multipart body, and a full buffering pool each go upstream
/// uncached and are visible only as an `x-sbproxy-idempotency:
/// SKIPPED-*` response header. `docs/configuration.md` says the same
/// thing in the operator's terms.
///
/// * `not_applicable` - no idempotency key on the request. Recorded on
///   the AI proxy path, which has the whole body before it decides;
///   the streaming proxy path never engages the middleware for a
///   keyless request and records nothing.
/// * `miss` - this request took the key and goes upstream.
/// * `takeover` - the same, on a key whose previous holder never came
///   back. A nonzero rate means requests are dying mid-flight.
/// * `hit` - a stored response was replayed.
/// * `coalesced` - a stored response was replayed after waiting for
///   the request that was producing it. The upstream was called once
///   for both.
/// * `conflict` - the key carried a different request body; answered
///   409 `ledger.idempotency_conflict`.
/// * `wait_timeout` - the wait budget ran out while the holder was
///   still working; answered 409 `ledger.idempotency_in_flight`. A
///   nonzero rate means overlapping retries are outliving the budget.
/// * `abandoned` - the holder ended without storing a response, so
///   there was nothing to wait for. Same 409, opposite thing to look
///   at: requests are failing rather than running long.
/// * `in_flight` - a live claim was found by a request that cannot wait
///   for it, so no wait was attempted; answered 409
///   `ledger.idempotency_in_flight` immediately. Two populations: the
///   GraphQL late path, which has already committed the body and has
///   nowhere to re-send it, and a request that could not take a waiter
///   slot because the waiter pool was full.
///
/// The second half is diagnostic and additive rather than terminal. A
/// request can record one of these as well as its outcome:
///
/// * `error` - a store-side read or write failure. Counted in addition
///   to the outcome the failure degrades into, so `miss` stays the
///   denominator for lookups and `error` is the numerator for "the
///   cache is not working".
/// * `fenced` - a publish was refused because another request owns the
///   key or has already answered it.
/// * `single_flight_unsupported` - the configured store has no atomic
///   create, so overlapping first requests are not serialized. Replay
///   and conflict detection still work.
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

/// Record a CORS response the middleware refused to decorate on
/// `sbproxy_cors_refusals_total{reason}`.
///
/// The refusal used to be visible only as a `tracing::warn!` per request,
/// which is a log flood on a busy origin and nothing at all on a
/// dashboard. `reason` is a closed string from the middleware.
pub fn record_cors_refusal(reason: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_cors_refusals_total",
            "Responses the CORS middleware refused to add headers to, by reason",
            &["reason"],
        )
        .expect("cors refusal counter registers")
    });
    counter.with_label_values(&[reason]).inc();
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
// `policy | action | auth | transform`. `plugin` is
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

/// Publish whether the certificate store this process is running on is the
/// one the config asked for, on `sbproxy_cert_store_degraded{backend}`.
///
/// `1` means the configured backend could not be opened and the process fell
/// back to an in-memory store; `0` means it opened. `backend` is the
/// configured `acme.storage_backend`, a closed set.
///
/// The series is published on the successful path too, deliberately. A gauge
/// that only appears when something is wrong cannot be told apart from a
/// scrape that never happened, and this one is the only signal for a failure
/// mode with no other symptom until the CA rate-limits the domain: an
/// in-memory store inherits the `KVStore` single-node lock defaults, so every
/// replica wins its own ACME issuance lease and opens its own order.
///
/// Set once, at startup, from the certificate-store open path. Shared
/// backends refuse to start rather than degrade, so a `1` here is a pod-local
/// backend that could not open its file.
pub fn set_cert_store_degraded(backend: &str, degraded: bool) {
    use prometheus::{register_int_gauge_vec, IntGaugeVec};
    use std::sync::OnceLock;
    static G: OnceLock<IntGaugeVec> = OnceLock::new();
    let gauge = G.get_or_init(|| {
        register_int_gauge_vec!(
            "sbproxy_cert_store_degraded",
            "1 when the configured certificate store could not be opened and an in-memory fallback is in use, 0 when the configured backend opened",
            &["backend"],
        )
        .expect("cert store degraded gauge registers")
    });
    let backend = sanitize_label("backend", backend);
    gauge
        .with_label_values(&[backend.as_str()])
        .set(i64::from(degraded));
}

/// WOR-1024: record the age of the cached OCSP staple for `host` on
/// `sbproxy_ocsp_staple_age_seconds{host}`. A stale staple (over
/// 24 hours) signals an OCSP refresh failure that has not yet
/// produced a hard handshake error.
///
/// WOR-2086: driven once a minute by the stapler's age tick
/// (`OcspStapler::publish_staple_age`), not only at fetch time. The
/// series is absent until the first successful fetch, which is
/// deliberate: for a deployment that expects stapling, never-fetched
/// is worse than old, and an absent series is what lets an alert
/// distinguish the two. `SBProxyOcspStapleStale` in
/// `dashboards/prometheus/alerts.yml` fires past 26 hours.
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

/// Record one MCP tool call refused because `events.fail_closed` names
/// `mcp_governance_decision` and the evidence record could not be
/// queued (`sbproxy_mcp_evidence_fail_closed_total{tenant}`, WOR-2384).
///
/// A tick here means the caller received a JSON-RPC internal error
/// naming `evidence_unavailable` rather than the tool's actual result,
/// even when the tool call itself succeeded: the gateway refused to
/// serve a response it could not also evidence.
pub fn record_mcp_evidence_fail_closed(tenant: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_evidence_fail_closed_total",
            "MCP tool calls refused because fail-closed evidence delivery failed, by tenant",
            &["tenant"],
        )
        .expect("mcp evidence fail-closed counter registers")
    });
    let tenant = sanitize_label("tenant", tenant);
    counter.with_label_values(&[tenant.as_str()]).inc();
}

/// Record one tenant that overflowed the evidence-sequence registry's
/// [`crate::evidence_seq`] cap and fell back to the shared overflow
/// counter (`sbproxy_evidence_seq_tenant_cap_total`, WOR-2384). No
/// labels: the cap is process-wide, and the tenant that caused it is
/// exactly the caller-controlled string the cap exists to bound, so it
/// cannot appear as a label value without recreating the unbounded
/// cardinality the cap is closing off.
pub fn record_evidence_seq_tenant_cap() {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_evidence_seq_tenant_cap_total",
            "Evidence sequence lookups for a tenant past the tracked-tenant cap, sharing the overflow counter",
        )
        .expect("evidence seq tenant cap counter registers")
    });
    counter.inc();
}

/// Record one `argument_policies[]` rule outcome that was not a plain
/// allow, on `sbproxy_mcp_argument_policy_total{tenant, rule, verdict}`
/// (WOR-2384, MCP05). `verdict` is `"warn"` or `"deny"`; a compliant
/// evaluation is not recorded here, matching the sibling `mcp_rbac` /
/// `mcp_quota` / `mcp_peer_downgrade` policy triggers, which also only
/// ever record a triggered outcome.
///
/// `rule` is the operator-configured rule name. Cardinality is bounded
/// by config, the same reasoning `sbproxy_mcp_evidence_fail_closed_total`
/// documents for `tenant`: both label values come from what an operator
/// wrote, not from caller-controlled request data.
pub fn record_mcp_argument_policy(tenant: &str, rule: &str, verdict: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_argument_policy_total",
            "MCP argument-policy rule triggers, by tenant, rule name, and verdict",
            &["tenant", "rule", "verdict"],
        )
        .expect("mcp argument policy counter registers")
    });
    let tenant = sanitize_label("tenant", tenant);
    let rule = sanitize_label("rule", rule);
    counter
        .with_label_values(&[tenant.as_str(), rule.as_str(), verdict])
        .inc();
}

/// Record one `initialize` refused because the session registry was
/// full, either globally (`MAX_TRACKED_SESSIONS`) or for the caller's
/// tenant (`MAX_TRACKED_SESSIONS_PER_TENANT`)
/// (`sbproxy_mcp_session_registry_saturated_total`, WOR-2384; meaning
/// changed by the F1/F2 fix round from "shared the fallback overflow
/// session" to this fail-closed refusal once that fallback session
/// was removed). No labels: the tenant that caused it is exactly the
/// caller-controlled string the cap exists to bound, so it cannot
/// appear as a label value without recreating the unbounded
/// cardinality the cap is closing off -- same reasoning
/// `record_evidence_seq_tenant_cap` documents for its own cap. Which
/// of the two caps tripped is on the `sbproxy::mcp::sessions`
/// `tracing::warn!` line only; the caller-visible refusal, the
/// `security_audit` entry, and this counter all stay one closed
/// reason (`mcp_session_registry_saturated`) regardless, since the
/// caller-visible behavior is identical either way.
pub fn record_mcp_session_registry_saturated() {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_mcp_session_registry_saturated_total",
            "MCP session mints refused because the session registry was at capacity, globally or for the caller's tenant",
        )
        .expect("mcp session registry saturated counter registers")
    });
    counter.inc();
}

/// Record one peer-profile observation that could not be tracked
/// because the peer registry was full, either globally
/// (`sbproxy_extension::mcp::peer_profile::MAX_TRACKED_PEERS`) or for
/// the caller's tenant
/// (`MAX_TRACKED_PEERS_PER_TENANT`)
/// (`sbproxy_mcp_peer_registry_saturated_total`, WOR-2384 whole-branch
/// review, item 1: fail-closed per-pair, no shared fallback profile,
/// mirroring `record_mcp_session_registry_saturated`'s own redesign).
/// No labels, same reasoning as that counter's: the tenant that caused
/// it is exactly the caller-controlled string the cap exists to bound.
/// Ticks on every refused-tracking call regardless of `downgrade:`
/// policy -- registry capacity is a fact independent of whether the
/// caller then refuses (`block`) or allows (`warn`) the call; the
/// once-per-tenant `tracing::warn!` line that accompanies it is a
/// separate, deliberately noisier-than-this-counter dedup (see
/// `peer_profile::warned_tenants`'s doc comment).
pub fn record_mcp_peer_registry_saturated() {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_mcp_peer_registry_saturated_total",
            "MCP peer-profile observations that could not be tracked because the peer registry was at capacity, globally or for the caller's tenant",
        )
        .expect("mcp peer registry saturated counter registers")
    });
    counter.inc();
}

/// Record one MCP `tools/call` refused because the per-tool quota
/// store could not track the caller's principal, either for the
/// caller's tenant
/// (`sbproxy_extension::mcp::MAX_TRACKED_QUOTA_KEYS_PER_TENANT`) or
/// globally (`MAX_TRACKED_QUOTA_KEYS`), on
/// `sbproxy_mcp_tool_quota_registry_saturated_total`.
///
/// The refusal is fail-closed, on the grounds that a limiter which
/// cannot count is not a limiter, so without this counter it is
/// indistinguishable on a dashboard from a caller genuinely over
/// quota. Alert on it: a non-zero rate means some share of traffic is
/// being refused for a capacity reason rather than a policy one.
///
/// No labels, the same reasoning as
/// [`record_mcp_peer_registry_saturated`]: the tenant and principal
/// that caused it are exactly the caller-controlled strings the caps
/// exist to bound. Ticks on every refused call, while the
/// `tracing::warn!` beside it fires once per scope per process.
pub fn record_mcp_tool_quota_registry_saturated() {
    use prometheus::{register_int_counter, IntCounter};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounter> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter!(
            "sbproxy_mcp_tool_quota_registry_saturated_total",
            "MCP tools/call refused because the per-tool quota store was at capacity, globally or for the caller's tenant",
        )
        .expect("mcp tool quota registry saturated counter registers")
    });
    counter.inc();
}

/// Record one `content_filters` category outcome that was not a plain
/// miss, on `sbproxy_mcp_content_filter_total{tenant, category,
/// verdict}` (WOR-2384, MCP01/MCP10). `category` is `"secrets"` or
/// `"pii"`; `verdict` is `"warn"`, `"redact"`, or `"deny"`. A category
/// that matched nothing (or is `off`) is not recorded here, matching
/// the sibling `mcp_argument_policy` / `mcp_flow` triggers, which also
/// only ever record a triggered outcome.
///
/// `category` is a fixed, closed-vocabulary string (not operator-
/// supplied), so cardinality here is bounded by this crate rather than
/// by config.
pub fn record_mcp_content_filter(tenant: &str, category: &'static str, verdict: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_content_filter_total",
            "MCP content-filter (secrets/pii) triggers, by tenant, category, and verdict",
            &["tenant", "category", "verdict"],
        )
        .expect("mcp content filter counter registers")
    });
    let tenant = sanitize_label("tenant", tenant);
    counter
        .with_label_values(&[tenant.as_str(), category, verdict])
        .inc();
}

/// Record one `result_policies[]` rule outcome that was not a plain
/// allow, on `sbproxy_mcp_result_policy_total{tenant, rule, verdict}`
/// (WOR-2384, MCP01/MCP10). `verdict` is `"warn"` or `"deny"`. Mirrors
/// [`record_mcp_argument_policy`] exactly, for the result-side surface.
///
/// `rule` is the operator-configured rule name, so cardinality here is
/// bounded by config, the same reasoning `record_mcp_argument_policy`
/// documents.
pub fn record_mcp_result_policy(tenant: &str, rule: &str, verdict: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_result_policy_total",
            "MCP result-policy rule triggers, by tenant, rule name, and verdict",
            &["tenant", "rule", "verdict"],
        )
        .expect("mcp result policy counter registers")
    });
    let tenant = sanitize_label("tenant", tenant);
    let rule = sanitize_label("rule", rule);
    counter
        .with_label_values(&[tenant.as_str(), rule.as_str(), verdict])
        .inc();
}

/// Record one time-boxed MCP RBAC grant that elapsed
/// (`sbproxy_mcp_grant_expired_total{tenant, policy}`, WOR-2386).
/// `policy` is the `rbac_policies` label, so cardinality is bounded by
/// config. Registration failure yields no counter rather than a
/// panic, matching [`record_fallback_served`].
pub fn record_mcp_grant_expired(tenant: &str, policy: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_grant_expired_total",
            "MCP tools/call refused because a time-boxed RBAC grant elapsed, by tenant and policy",
            &["tenant", "policy"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        let tenant = sanitize_label("tenant", tenant);
        let policy = sanitize_label("policy", policy);
        counter
            .with_label_values(&[tenant.as_str(), policy.as_str()])
            .inc();
    }
}

/// Record one gateway-originated MCP approval hold
/// (`sbproxy_mcp_approval_hold_total{tenant, outcome}`, WOR-2454).
/// `outcome` is a closed set: `held` when a call is parked for an
/// operator, `saturated` when the hold table refused a new row.
/// Registration failure yields no counter rather than a
/// panic, matching [`record_fallback_served`].
pub fn record_mcp_approval_hold(tenant: &str, outcome: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<Option<IntCounterVec>> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_approval_hold_total",
            "MCP tools/call parked for operator approval, by tenant and outcome",
            &["tenant", "outcome"],
        )
        .ok()
    });
    if let Some(counter) = counter {
        let tenant = sanitize_label("tenant", tenant);
        counter.with_label_values(&[tenant.as_str(), outcome]).inc();
    }
}

/// Record one session-flow enforcement outcome that was not a plain
/// allow, on `sbproxy_mcp_flow_total{tenant, rule, verdict}` (WOR-2384,
/// MCP06; fix round 1 added the confidentiality-axis and pair-rule
/// values). `rule` is one of the closed set: `"flow_taint"` (a session
/// newly tainted -- leg 1) or `"flow_sensitive_touched"` (a session
/// newly touched sensitive-labeled data -- leg 2), both always recorded
/// with `verdict = "warn"` since the read that caused either transition
/// was itself permitted; `"flow_exfil_block"` (an outbound-tool call
/// while the default `rule: two_of_three` is satisfied -- both legs 1
/// and 2) or `"flow_pair_block"` (an outbound-tool call while the
/// explicit `rule: taint_and_outbound` is satisfied -- leg 1 alone),
/// either recorded with `verdict = "warn"` or `"deny"` depending on
/// `flow.mode`. A compliant call is not recorded here,
/// matching the sibling `mcp_rbac` / `mcp_quota` / `mcp_peer_downgrade`
/// / `mcp_argument_policy` triggers, which also only ever record a
/// triggered outcome.
///
/// `rule` is a fixed, closed-vocabulary string (not operator-supplied,
/// unlike `sbproxy_mcp_argument_policy_total`'s `rule` label), so
/// cardinality here is bounded by this crate rather than by config.
pub fn record_mcp_flow(tenant: &str, rule: &'static str, verdict: &'static str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_flow_total",
            "MCP session-flow enforcement triggers, by tenant, rule id, and verdict",
            &["tenant", "rule", "verdict"],
        )
        .expect("mcp flow counter registers")
    });
    let tenant = sanitize_label("tenant", tenant);
    counter
        .with_label_values(&[tenant.as_str(), rule, verdict])
        .inc();
}

/// Record a static tool-poisoning indicator found in advertised tool text on
/// `sbproxy_mcp_poison_indicators_total{field, indicator, kind}`.
///
/// Reporting only. Nothing gates on this: published evaluations put
/// injection classifiers at single-digit catch rates on realistic channels,
/// so an indicator is a signal for a reviewer, never a boundary. The
/// boundaries this gateway enforces are deterministic and live elsewhere.
///
/// Labels are closed sets and exclude the tool and server names, which a
/// federated peer controls.
pub fn record_mcp_poison_indicator(
    field: &'static str,
    indicator: &'static str,
    kind: &'static str,
) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_poison_indicators_total",
            "Static tool-poisoning indicators in advertised MCP tool text, by field and indicator",
            &["field", "indicator", "kind"],
        )
        .expect("mcp poison indicator counter registers")
    });
    counter.with_label_values(&[field, indicator, kind]).inc();
}

/// Record advertised tool text that hides content from a reader on
/// `sbproxy_mcp_concealed_text_findings_total{field, class, kind}`.
///
/// `field` is the advertised field (`name`, `title`, `description`), `class`
/// the concealment class (`tag_block`, `bidi_control`, `zero_width`,
/// `variation_selector`, `other_control`), and `kind` whether the finding
/// appeared or cleared.
///
/// Every label is a closed set chosen by this gateway. Deliberately none of
/// them is the tool or server name: those are upstream-controlled strings and
/// would make this series unbounded, which is the standing rule for anything
/// a federated peer can name.
pub fn record_mcp_concealed_text_finding(
    field: &'static str,
    class: &'static str,
    kind: &'static str,
) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_mcp_concealed_text_findings_total",
            "Advertised MCP tool text carrying characters hidden from a reader, by field and class",
            &["field", "class", "kind"],
        )
        .expect("mcp concealed text finding counter registers")
    });
    counter.with_label_values(&[field, class, kind]).inc();
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
/// `timeout`, `connect`, `response_cap`, `other` for the HTTP
/// transports, plus `stdio_spawn`, `stdio_backoff`, and
/// `stdio_session_closed` from the supervised stdio session
/// (`timeout` is shared; a hung stdio child records it too). Lets an
/// operator see hung or oversized upstreams that the per-request
/// deadlines and byte caps are absorbing, and stdio children that
/// are crash-looping or probe-deaf.
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
        &["vllm", "sglang", "llama_cpp", "mistralrs"],
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

/// Count a bounded artifact acquisition failure by `ArtifactError` kind
/// (e.g. `digest_mismatch`, `transport`, `cache_corrupt`; see
/// `sbproxy-model-host`'s `ArtifactError::kind`).
pub fn record_model_host_artifact_error(kind: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_model_host_artifact_errors_total",
            "Model artifact acquisition failures by ArtifactError kind",
            &["artifact_error_kind"],
        )
        .expect("model host artifact-errors counter registers")
    });
    // Scoped label name, not the bare "kind" other metrics in this file
    // use: `budget_for_label` keys on label name globally, and "kind" is
    // shared by ~20 other metrics with their own, unrelated closed
    // enums, so a cap sized for ArtifactError's 18 variants must not
    // apply to any of those.
    let kind = closed_label(
        kind,
        &[
            "invalid_artifact",
            "io",
            "transport",
            "http_status",
            "unexpected_response",
            "size_mismatch",
            "digest_mismatch",
            "cache_corrupt",
            "manual_artifact_missing",
            "offline_artifact_missing",
            "startup_artifact_not_selected",
            "pickle_refused",
            "pickle_unsafe",
            "job",
            "serialization",
            "clock",
            "join",
            "removal_blocked",
        ],
        "unknown",
    );
    counter.with_label_values(&[kind]).inc();
}

/// Count a placement plan's per-node rejection by deployment and
/// `PlacementRejectionReason`.
pub fn record_model_host_placement_rejection(deployment: &str, reason: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_model_host_placement_rejections_total",
            "Placement plan node rejections by deployment and reason",
            &["deployment", "placement_reason"],
        )
        .expect("model host placement-rejections counter registers")
    });
    let deployment = sanitize_label("deployment", deployment);
    let reason = closed_label(
        reason,
        &[
            "not_worker",
            "node_unhealthy",
            "required_labels",
            "missing_endpoint",
            "no_capacity",
            "variant_incompatible",
            "accelerator_incompatible",
            "insufficient_memory",
            "engine_unavailable",
            "artifact_not_ready",
        ],
        "unknown",
    );
    counter
        .with_label_values(&[deployment.as_str(), reason])
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

// --- key policy metrics --------------------------------------------------
//
// `key_record_to_effective_policy` fails closed on a malformed stored key
// record rather than lowering it into a partial or best-guess policy. This
// counts every such rejection by its bounded reason, `invalid_budget` among
// them, so a stored-policy corruption (or a budget value outside what the
// gateway can represent) shows up as a rate instead of a silent 401/403.

/// Count a stored key record that failed closed while lowering to an
/// effective policy, by `StoredPolicyErrorKind` reason
/// (`sbproxy-core`'s `key_policy` module).
pub fn record_key_policy_stored_rejection(reason: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_key_policy_stored_rejections_total",
            "Stored key records rejected while lowering to an effective policy, by reason",
            &["reason"],
        )
        .expect("key policy stored-rejections counter registers")
    });
    let reason = closed_label(
        reason,
        &[
            "empty_key_id",
            "invalid_policy_revision",
            "tenant_mismatch",
            "invalid_principal_selector",
            "invalid_mcp_reference",
            "invalid_priority",
            "invalid_budget",
        ],
        "unknown",
    );
    counter.with_label_values(&[reason]).inc();
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
/// `backend_error`, `crd_invalid`, or `fenced` (the replica could no
/// longer prove it holds the leader lease and abandoned the pass
/// without writing). Buckets cover 1ms..60s (the reconcile envelope
/// including server-side apply round-trips).
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
pub fn record_ai_usage_parse_miss(provider: &str, surface: &str, usage_source: &str) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_ai_usage_parse_miss_total",
            "2xx AI responses on a token surface that carried no parseable usage block, by what was billed instead: `estimated` (this gateway's own tokenizer count) or `absent` (nothing could be counted, so nothing was billed)",
            &["provider", "surface", "usage_source"],
        )
        .expect("ai usage parse miss counter registers")
    });
    let provider = sanitize_label("provider", provider);
    let surface = sanitize_label("surface", surface);
    let usage_source = sanitize_label("usage_source", usage_source);
    counter
        .with_label_values(&[provider.as_str(), surface.as_str(), usage_source.as_str()])
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
        m.ai_compression_value_tokens_saved
            .with_label_values(&["acme", "o", "gpt-4o", "window_fit", "model_tokenizer"])
            .inc_by(120);
        m.ai_compression_value_cost_saved_micros
            .with_label_values(&["acme", "o", "gpt-4o", "window_fit", "model_tokenizer"])
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
            "sbproxy_ai_compression_value_tokens_saved_total",
            "sbproxy_ai_compression_value_cost_saved_micros_total",
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
    fn compression_value_records_positive_closed_levers_only() {
        let m = ProxyMetrics::new();
        record_compression_value_to(
            &m,
            CompressionValueObservation {
                tenant_id: "tenant-a",
                origin: "origin-a",
                model: "gpt-4o",
                lever: "rag_select",
                token_count_precision: "model_tokenizer",
                tokens_saved: 30,
                gross_cost_saved_micros: 300,
            },
        );
        record_compression_value_to(
            &m,
            CompressionValueObservation {
                tenant_id: "tenant-a",
                origin: "origin-a",
                model: "gpt-4o",
                lever: "compact_serialization",
                token_count_precision: "model_tokenizer",
                tokens_saved: 40,
                gross_cost_saved_micros: 400,
            },
        );
        record_compression_value_to(
            &m,
            CompressionValueObservation {
                tenant_id: "tenant-a",
                origin: "origin-a",
                model: "gpt-4o",
                lever: "position_reorder",
                token_count_precision: "model_tokenizer",
                tokens_saved: 50,
                gross_cost_saved_micros: 500,
            },
        );
        record_compression_value_to(
            &m,
            CompressionValueObservation {
                tenant_id: "tenant-a",
                origin: "origin-a",
                model: "gpt-4o",
                lever: "window_fit",
                token_count_precision: "model_tokenizer",
                tokens_saved: 120,
                gross_cost_saved_micros: 900,
            },
        );
        record_compression_value_to(
            &m,
            CompressionValueObservation {
                tenant_id: "tenant-a",
                origin: "origin-a",
                model: "gpt-4o",
                lever: "not-a-lever",
                token_count_precision: "model_tokenizer",
                tokens_saved: 50,
                gross_cost_saved_micros: 50,
            },
        );
        record_compression_value_to(
            &m,
            CompressionValueObservation {
                tenant_id: "tenant-a",
                origin: "origin-a",
                model: "gpt-4o",
                lever: "window_fit",
                token_count_precision: "exact",
                tokens_saved: 50,
                gross_cost_saved_micros: 50,
            },
        );
        record_compression_value_to(
            &m,
            CompressionValueObservation {
                tenant_id: "tenant-a",
                origin: "origin-a",
                model: "gpt-4o",
                lever: "window_fit",
                token_count_precision: "model_tokenizer",
                tokens_saved: 0,
                gross_cost_saved_micros: 0,
            },
        );
        record_compression_value_to(
            &m,
            CompressionValueObservation {
                tenant_id: "tenant-a",
                origin: "origin-a",
                model: "gpt-4o",
                lever: "window_fit",
                token_count_precision: "model_tokenizer",
                tokens_saved: 0,
                gross_cost_saved_micros: 50,
            },
        );

        assert_eq!(
            m.ai_compression_value_tokens_saved
                .with_label_values(&[
                    "tenant-a",
                    "origin-a",
                    "gpt-4o",
                    "window_fit",
                    "model_tokenizer",
                ])
                .get(),
            120
        );
        assert_eq!(
            m.ai_compression_value_cost_saved_micros
                .with_label_values(&[
                    "tenant-a",
                    "origin-a",
                    "gpt-4o",
                    "window_fit",
                    "model_tokenizer",
                ])
                .get(),
            900
        );
        let scrape = m.render();
        assert!(scrape.contains(
            "sbproxy_ai_compression_value_tokens_saved_total{lever=\"window_fit\",model=\"gpt-4o\",origin=\"origin-a\",tenant_id=\"tenant-a\",token_count_precision=\"model_tokenizer\"} 120"
        ));
        assert!(scrape.contains(
            "sbproxy_ai_compression_value_cost_saved_micros_total{lever=\"window_fit\",model=\"gpt-4o\",origin=\"origin-a\",tenant_id=\"tenant-a\",token_count_precision=\"model_tokenizer\"} 900"
        ));
        assert!(scrape.contains(
            "sbproxy_ai_compression_value_tokens_saved_total{lever=\"rag_select\",model=\"gpt-4o\",origin=\"origin-a\",tenant_id=\"tenant-a\",token_count_precision=\"model_tokenizer\"} 30"
        ));
        assert!(scrape.contains(
            "sbproxy_ai_compression_value_cost_saved_micros_total{lever=\"rag_select\",model=\"gpt-4o\",origin=\"origin-a\",tenant_id=\"tenant-a\",token_count_precision=\"model_tokenizer\"} 300"
        ));
        assert!(scrape.contains(
            "sbproxy_ai_compression_value_tokens_saved_total{lever=\"compact_serialization\",model=\"gpt-4o\",origin=\"origin-a\",tenant_id=\"tenant-a\",token_count_precision=\"model_tokenizer\"} 40"
        ));
        assert!(scrape.contains(
            "sbproxy_ai_compression_value_cost_saved_micros_total{lever=\"compact_serialization\",model=\"gpt-4o\",origin=\"origin-a\",tenant_id=\"tenant-a\",token_count_precision=\"model_tokenizer\"} 400"
        ));
        assert!(!scrape.contains("lever=\"position_reorder\""));
        assert!(!scrape.contains("not-a-lever"));
        assert!(!scrape.contains("token_count_precision=\"exact\""));
    }

    #[test]
    fn heuristic_compression_value_exposes_tokens_without_fabricating_cost() {
        let m = ProxyMetrics::new();
        record_compression_value_to(
            &m,
            CompressionValueObservation {
                tenant_id: "tenant-heuristic",
                origin: "origin-heuristic",
                model: "self-hosted-model",
                lever: "window_fit",
                token_count_precision: "heuristic",
                tokens_saved: 80,
                gross_cost_saved_micros: 0,
            },
        );

        let scrape = m.render();
        assert!(scrape.contains("token_count_precision=\"heuristic\""));
        assert!(scrape.contains("sbproxy_ai_compression_value_tokens_saved_total"));
        assert!(!scrape.contains(
            "sbproxy_ai_compression_value_cost_saved_micros_total{lever=\"window_fit\",model=\"self-hosted-model\""
        ));
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
        record_request_with_labels(origin, "GET", 200, 0.05, 1024, 512, AgentLabels::unset());
        record_request_with_labels(origin, "GET", 200, 0.10, 2048, 256, AgentLabels::unset());

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
        record_request_with_labels(origin, "POST", 201, 0.02, 100, 50, AgentLabels::unset());
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

    /// WOR-2486: red first. Before `record_circuit_breaker_transition`
    /// existed, a circuit-breaker state change bumped a Prometheus
    /// counter (or nothing, on the AI-provider call site, which logged
    /// with `tracing::info!/warn!` under its own field names) and
    /// nothing else; there was no single structured record a SIEM
    /// query could select `event = "circuit_breaker_transition"` on.
    #[test]
    fn record_circuit_breaker_transition_logs_a_structured_line() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);
        struct SharedLogGuard(Arc<Mutex<Vec<u8>>>);
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLogWriter {
            type Writer = SharedLogGuard;
            fn make_writer(&'a self) -> Self::Writer {
                SharedLogGuard(Arc::clone(&self.0))
            }
        }
        impl std::io::Write for SharedLogGuard {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("log capture").extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::WARN)
            .with_writer(SharedLogWriter(Arc::clone(&captured)))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            // Load bearing (WOR-2486 fix round 2). `record_circuit_breaker_transition`'s
            // `tracing::warn!` callsite registers its `Interest` against
            // whatever subscriber is active the first time this process
            // ever evaluates it, and that decision is cached process-wide,
            // not per test. If no subscriber (or one this event is not
            // enabled under) was active earlier in this same test binary,
            // the callsite caches `Interest::never()` and the freshly
            // installed subscriber above never sees the event at all, even
            // though `with_default` genuinely made it the active one. This
            // is the same landmine `request_path_spans_carry_their_name_and_no_credential_shaped_field`
            // documents in `telemetry.rs`: rebuilding the cache here forces
            // every known callsite to re-check `enabled()`/`register_callsite`
            // against the subscriber this closure just installed.
            tracing::callsite::rebuild_interest_cache();
            record_circuit_breaker_transition(
                "breaker-transition.example.com",
                "closed",
                "open",
                "failure_threshold_exceeded",
                "acme",
            );
        });

        let output =
            String::from_utf8(captured.lock().expect("log capture").clone()).expect("utf8 log");
        assert!(output.contains("\"event\":\"circuit_breaker_transition\""));
        assert!(output.contains("\"from\":\"closed\""));
        assert!(output.contains("\"to\":\"open\""));
        assert!(output.contains("\"reason\":\"failure_threshold_exceeded\""));
        assert!(output.contains("\"tenant\":\"acme\""));
        // And the metric still fires: this wraps `record_circuit_breaker`
        // rather than replacing it.
        assert!(output_or_metric_has_transition(
            "breaker-transition.example.com"
        ));
    }

    fn output_or_metric_has_transition(origin: &str) -> bool {
        // `metrics().registry` is the canonical scrape registry that owns
        // `sbproxy_circuit_breaker_transitions_total`; the process-global
        // `prometheus::gather()` never sees it (see `ProxyMetrics::new`).
        for family in metrics().registry.gather() {
            if family.name() != "sbproxy_circuit_breaker_transitions_total" {
                continue;
            }
            for metric in family.get_metric() {
                let labels: std::collections::HashMap<&str, &str> = metric
                    .get_label()
                    .iter()
                    .map(|l| (l.name(), l.value()))
                    .collect();
                if labels.get("origin").copied() == Some(origin)
                    && labels.get("from_state").copied() == Some("closed")
                    && labels.get("to_state").copied() == Some("open")
                {
                    return true;
                }
            }
        }
        false
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

    #[test]
    fn cardinality_headroom_is_readable_before_the_collapse() {
        // `sbproxy_label_cardinality_overflow_total` only moves after a
        // label has already started merging values into __other__, and
        // in a multi-tenant deployment that merge turns a per-tenant
        // panel into a wrong number with no warning. Assert the two
        // gauges that make the approach visible while the label still
        // has room, since a scrape is the only place an operator can
        // see it.
        //
        // The label name is unique to this test: the global limiter is
        // shared by every test in this binary, so a name any other test
        // could touch would make the counts racy.
        let label = "cardinality_headroom_probe";
        for value in ["one", "two", "three"] {
            sanitize_label_budget("sbproxy_headroom_probe_total", label, value);
        }

        let out = metrics().render();
        assert!(
            out.contains(&format!(
                "sbproxy_label_cardinality_unique_values{{label=\"{label}\"}} 3"
            )),
            "the accepted-value count must be scrapeable per label:\n{out}"
        );
        // Not in the per-label budget table, so it falls through to the
        // workspace default. The cap has to be published too: without a
        // denominator, 3 says nothing about how much room is left.
        assert!(
            out.contains(&format!(
                "sbproxy_label_cardinality_budget{{label=\"{label}\"}} 1000"
            )),
            "the cap must be scrapeable per label:\n{out}"
        );
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
    fn unset_agent_labels_land_on_the_empty_sentinel_series() {
        let m = metrics();
        let origin = "test-legacy-empty.example.com";
        record_request_with_labels(origin, "POST", 201, 0.0, 0, 0, AgentLabels::unset());

        let origin_san = sanitize_label("origin", origin);
        // An unresolved request attributes the increment to the
        // empty-sentinel tuple, which is the "no agent context attached"
        // series and is deliberately distinct from a positive `human` or
        // `unknown` verdict. `sanitize_label_budget` short-circuits the
        // empty string before the limiter sees it, so these five stay
        // empty rather than being demoted to `__other__` under load.
        let count = m
            .requests_total
            .with_label_values(&[origin_san.as_str(), "POST", "201", "", "", "", "", ""])
            .get();
        assert_eq!(count, 1, "unset agent labels must use the empty sentinel");
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
    fn record_trust_tier_stamps_the_closed_tier_label() {
        let before = metrics()
            .trust_tier_requests
            .with_label_values(&["strong"])
            .get();
        record_trust_tier("strong");
        let after = metrics()
            .trust_tier_requests
            .with_label_values(&["strong"])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn record_inbound_key_request_emits_safe_tenant_and_key_dimensions() {
        let before = metrics()
            .inbound_key_requests
            .with_label_values(&["openai", "native", "tenant-a", "native:tenant-a:api:openai"])
            .get();
        record_inbound_key_request(
            Some("openai"),
            "native",
            "tenant-a",
            Some("native:tenant-a:api:openai"),
        );
        let after = metrics()
            .inbound_key_requests
            .with_label_values(&["openai", "native", "tenant-a", "native:tenant-a:api:openai"])
            .get();

        assert_eq!(after, before + 1);
        record_inbound_key_request(None, "none", "tenant-a", None);
        let rendered = metrics().render();
        assert!(rendered.contains(
            "sbproxy_inbound_key_requests_total{api_key_id=\"native:tenant-a:api:openai\",key_mode=\"native\",provider=\"openai\",tenant_id=\"tenant-a\"}"
        ));
        assert!(rendered.contains(
            "sbproxy_inbound_key_requests_total{api_key_id=\"\",key_mode=\"none\",provider=\"\",tenant_id=\"tenant-a\"}"
        ));
        assert!(!rendered.contains("sk-caller-owned-canary"));
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
        record_idempotency_cache_result("memory", "hit");
        record_idempotency_cache_result("memory", "miss");
        record_idempotency_cache_result("memory", "conflict");
        record_idempotency_cache_result("memory", "not_applicable");
        record_idempotency_cache_result("kv", "error");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_idempotency_cache_results_total"),
            "idempotency results counter missing from render"
        );
        for result in ["hit", "miss", "conflict", "not_applicable", "error"] {
            assert!(
                out.contains(&format!("result=\"{result}\"")),
                "result={result} label missing"
            );
        }
        // The backend dimension used to be the constant "default", so a
        // dashboard could not tell a broken redis from a cold memory
        // cache. Both real backends have to appear.
        for backend in ["memory", "kv"] {
            assert!(
                out.contains(&format!("backend=\"{backend}\"")),
                "backend={backend} label missing"
            );
        }
    }

    #[test]
    fn record_idempotency_cache_duration_emits_histogram() {
        record_idempotency_cache_duration("kv", 0.0005);
        record_idempotency_cache_duration("kv", 0.02);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_idempotency_cache_duration_seconds_bucket"),
            "idempotency duration buckets missing"
        );
        assert!(
            out.contains("backend=\"kv\""),
            "backend label must carry the real backend"
        );
    }

    #[test]
    fn record_cors_refusal_emits_counter() {
        record_cors_refusal("wildcard_with_credentials");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_cors_refusals_total"),
            "cors refusal counter missing from render"
        );
        assert!(
            out.contains("reason=\"wildcard_with_credentials\""),
            "reason label missing"
        );
    }

    #[test]
    fn record_signature_legacy_derivation_emits_counter() {
        record_signature_legacy_derivation("@target-uri");
        record_signature_legacy_derivation("@request-target");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_signature_legacy_derivation_total"),
            "legacy derivation counter missing from render"
        );
        for component in ["@target-uri", "@request-target"] {
            assert!(
                out.contains(&format!("component=\"{component}\"")),
                "component={component} label missing"
            );
        }
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

    #[test]
    fn set_model_host_load_queue_depth_reflects_queue_transitions() {
        // The gauge has to track a request joining the queue and then
        // leaving it, not just accept a single set() call. Pinned to a
        // model name unused by any other test in this module so the
        // render-string assertions below are unambiguous.
        let model = "load-queue-depth-transition-test-model";
        set_model_host_load_queue_depth(model, 0);
        let out = metrics().render();
        assert!(out.contains(&format!(
            "sbproxy_model_host_load_queue_depth{{model=\"{model}\"}} 0"
        )));

        // A second request queues behind the first cold load.
        set_model_host_load_queue_depth(model, 1);
        let out = metrics().render();
        assert!(out.contains(&format!(
            "sbproxy_model_host_load_queue_depth{{model=\"{model}\"}} 1"
        )));

        // Both requests dequeue once the load completes.
        set_model_host_load_queue_depth(model, 0);
        let out = metrics().render();
        assert!(out.contains(&format!(
            "sbproxy_model_host_load_queue_depth{{model=\"{model}\"}} 0"
        )));
    }

    #[test]
    fn model_host_artifact_error_and_placement_rejection_metrics_emit() {
        record_model_host_artifact_error("digest_mismatch");
        record_model_host_artifact_error("not_a_real_kind");
        record_model_host_placement_rejection("qwen3-32b", "insufficient_memory");
        let out = metrics().render();
        assert!(out.contains(
            "sbproxy_model_host_artifact_errors_total{artifact_error_kind=\"digest_mismatch\"} 1"
        ));
        assert!(out.contains(
            "sbproxy_model_host_artifact_errors_total{artifact_error_kind=\"unknown\"} 1"
        ));
        assert!(out.contains(
            "sbproxy_model_host_placement_rejections_total{deployment=\"qwen3-32b\",placement_reason=\"insufficient_memory\"} 1"
        ));
    }

    // --- key policy metrics ---

    #[test]
    fn key_policy_stored_rejection_counts_by_reason() {
        record_key_policy_stored_rejection("invalid_budget");
        record_key_policy_stored_rejection("invalid_budget");
        record_key_policy_stored_rejection("tenant_mismatch");
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_key_policy_stored_rejections_total{reason=\"invalid_budget\"} 2")
        );
        assert!(out
            .contains("sbproxy_key_policy_stored_rejections_total{reason=\"tenant_mismatch\"} 1"));
    }

    // --- k8s operator metrics ---

    #[test]
    fn record_operator_reconcile_emits_counter_and_histogram() {
        record_operator_reconcile("sbproxy", "ok", 0.12);
        record_operator_reconcile("sbproxy", "conflict", 0.001);
        record_operator_reconcile("sbproxyconfig", "backend_error", 2.5);
        record_operator_reconcile("sbproxy", "crd_invalid", 0.005);
        record_operator_reconcile("sbproxy", "fenced", 0.0);
        let out = metrics().render();
        assert!(
            out.contains("sbproxy_operator_reconcile_total"),
            "operator reconcile counter missing"
        );
        assert!(
            out.contains("sbproxy_operator_reconcile_duration_seconds_bucket"),
            "operator reconcile duration buckets missing"
        );
        for result in ["ok", "conflict", "backend_error", "crd_invalid", "fenced"] {
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

    /// `record_events_dropped` swallows a registration failure so a
    /// request-path publish cannot abort the process. That makes the
    /// registration itself the untested branch unless something proves
    /// it takes the `Some` arm, which is what this does: a counter that
    /// silently failed to register would leave the family absent from
    /// the render.
    #[test]
    fn events_dropped_counter_registers_and_increments() {
        record_events_dropped("webhook", "queue_full");

        let mut rendered = String::new();
        for family in prometheus::gather() {
            if family.name() == "sbproxy_events_dropped_total" {
                for metric in family.get_metric() {
                    let labels: Vec<String> = metric
                        .get_label()
                        .iter()
                        .map(|pair| format!("{}={}", pair.name(), pair.value()))
                        .collect();
                    rendered.push_str(&format!(
                        "{} {}\n",
                        labels.join(","),
                        metric.get_counter().value()
                    ));
                }
            }
        }

        // Each label separately, not one joined string. `prometheus` returns
        // a metric's labels sorted by name, so the pair renders as
        // `reason=...,sink=...` regardless of the order they were declared
        // in, and asserting on the declared order tests the crate's sort
        // rather than our registration.
        assert!(
            rendered.contains("sink=webhook") && rendered.contains("reason=queue_full"),
            "sbproxy_events_dropped_total did not register or did not carry \
             the sink/reason labels: {rendered:?}"
        );
    }

    /// Every label of a gathered family, as `name=value` pairs joined by
    /// commas, one entry per series, with the series value appended.
    fn gathered_series(family_name: &str) -> Vec<(String, f64)> {
        let mut out = Vec::new();
        for family in prometheus::gather() {
            if family.name() != family_name {
                continue;
            }
            for metric in family.get_metric() {
                let labels: Vec<String> = metric
                    .get_label()
                    .iter()
                    .map(|pair| format!("{}={}", pair.name(), pair.value()))
                    .collect();
                let value = match family.get_field_type() {
                    prometheus::proto::MetricType::COUNTER => metric.get_counter().value(),
                    prometheus::proto::MetricType::GAUGE => metric.get_gauge().value(),
                    // Nothing calls this for a histogram or a summary, and
                    // silently returning 0 for one would make a wrong
                    // assertion pass rather than fail.
                    other => {
                        unreachable!("{family_name} is a {other:?}, not a counter or a gauge")
                    }
                };
                out.push((labels.join(","), value));
            }
        }
        out
    }

    /// The reset half of the info-gauge idiom: `set_config_revision_info`
    /// must leave exactly one series behind, not one per revision it has
    /// ever been called with.
    ///
    /// A red version of this test (no `remove_label_values` call before
    /// the second `with_label_values`) would show two series after the
    /// second update, one per revision; that failure mode is exactly what
    /// happened to the eight `stable` metrics this registry's module doc
    /// describes, except here it would be silent cardinality growth
    /// instead of a flat zero.
    #[test]
    fn config_revision_info_gauge_carries_exactly_one_series_after_two_records() {
        set_config_revision_info(1, "aaaa1111aaaa1111", "local");
        let first = gathered_series("sbproxy_config_revision_info");
        assert_eq!(
            first.len(),
            1,
            "the first record must publish exactly one series: {first:?}"
        );
        assert!(
            first[0].0.contains("revision=1")
                && first[0].0.contains("provenance=local")
                && first[0].0.contains("digest=aaaa1111aaaa1111"),
            "the first series did not carry the expected labels: {first:?}"
        );
        assert_eq!(first[0].1, 1.0);

        set_config_revision_info(2, "bbbb2222bbbb2222", "git");
        let second = gathered_series("sbproxy_config_revision_info");
        assert_eq!(
            second.len(),
            1,
            "a second record must remove the first revision's series rather than \
             adding a second one: {second:?}"
        );
        assert!(
            second[0].0.contains("revision=2")
                && second[0].0.contains("provenance=git")
                && second[0].0.contains("digest=bbbb2222bbbb2222"),
            "the second series did not carry the new labels: {second:?}"
        );

        // A repeat of the same revision/digest/provenance is a no-op, not
        // a third series and not a needless remove-then-set cycle.
        set_config_revision_info(2, "bbbb2222bbbb2222", "git");
        assert_eq!(gathered_series("sbproxy_config_revision_info").len(), 1);
    }

    /// `sbproxy_config_history_entries` is a plain gauge: it just tracks
    /// whatever count it was last told, growing and shrinking with it.
    #[test]
    fn config_history_entries_gauge_tracks_the_count() {
        set_config_history_entries(0);
        assert_eq!(
            gathered_series("sbproxy_config_history_entries")
                .last()
                .map(|(_, value)| *value),
            Some(0.0)
        );

        set_config_history_entries(5);
        assert_eq!(
            gathered_series("sbproxy_config_history_entries")
                .last()
                .map(|(_, value)| *value),
            Some(5.0)
        );

        set_config_history_entries(2);
        assert_eq!(
            gathered_series("sbproxy_config_history_entries")
                .last()
                .map(|(_, value)| *value),
            Some(2.0),
            "the gauge must track a count that shrinks, not just one that grows"
        );
    }

    /// Both halves of the key-store degradation pair, in one test on
    /// purpose.
    ///
    /// They share one process-global gauge whose whole job is to hold a
    /// single series, so splitting the claims into separate `#[test]`
    /// functions would let a threaded runner interleave two posture
    /// changes and fail on the interleaving rather than on the code.
    /// Nextest's process-per-test would hide that; a plain
    /// `cargo test -p sbproxy-observe --lib` would not.
    ///
    /// Three claims, in the order an outage produces them:
    ///
    /// 1. The counter registers (both families swallow a registration
    ///    failure with `.ok()`, so nothing else proves the `Some` arm is
    ///    taken) and carries all three labels.
    /// 2. The gauge goes to 1 while the store is unreachable and back to 0
    ///    once a resolution succeeds. This is the question a counter
    ///    structurally cannot answer: "is it failing right now".
    /// 3. A posture change removes the previous series. A stale
    ///    `posture="closed"` stuck at 1 reads exactly like a live one, and
    ///    it is the more alarming of the two on a panel.
    #[test]
    fn key_store_outage_is_counted_and_its_posture_gauge_tracks_the_current_state() {
        record_key_store_outage("oidc_claim", "degraded", "admitted");

        let counted = gathered_series("sbproxy_key_store_outage_total");
        assert!(
            counted
                .iter()
                .any(|(labels, value)| labels.contains("entrypoint=oidc_claim")
                    && labels.contains("posture=degraded")
                    && labels.contains("outcome=admitted")
                    && *value >= 1.0),
            "sbproxy_key_store_outage_total did not register or did not carry \
             the entrypoint/posture/outcome labels: {counted:?}"
        );

        let during = gathered_series("sbproxy_key_store_unavailable");
        assert_eq!(
            during
                .iter()
                .find(|(labels, _)| labels.contains("posture=degraded"))
                .map(|(_, value)| *value),
            Some(1.0),
            "the gauge did not go to 1 while the store was unreachable: {during:?}"
        );

        record_key_store_reachable("degraded");
        let after = gathered_series("sbproxy_key_store_unavailable");
        assert_eq!(
            after
                .iter()
                .find(|(labels, _)| labels.contains("posture=degraded"))
                .map(|(_, value)| *value),
            Some(0.0),
            "the gauge did not fall back to 0 once a resolution succeeded: {after:?}"
        );

        record_key_store_outage("header_sweep", "closed", "denied");
        let reloaded = gathered_series("sbproxy_key_store_unavailable");
        assert!(
            !reloaded
                .iter()
                .any(|(labels, _)| labels.contains("posture=degraded")),
            "the previous posture's series survived a posture change: {reloaded:?}"
        );
    }

    /// Both halves of the budget-share degradation pair, in one test on
    /// purpose, the same reason `key_store_outage_is_counted...` covers its
    /// pair together: they share one process-global gauge.
    ///
    /// Three claims:
    ///
    /// 1. `record_budget_share_fail_open` counts on
    ///    `sbproxy_budget_share_fail_open_total{op}` and carries the `op`
    ///    label.
    /// 2. It also raises `sbproxy_budget_share_unavailable` to 1.
    /// 3. `set_budget_share_unavailable(0)` drops the gauge back to 0 once a
    ///    shared-store operation succeeds again.
    #[test]
    fn budget_share_fail_open_is_counted_and_its_unavailable_gauge_tracks_the_current_state() {
        record_budget_share_fail_open("read");

        let counted = gathered_series("sbproxy_budget_share_fail_open_total");
        assert!(
            counted
                .iter()
                .any(|(labels, value)| labels.contains("op=read") && *value >= 1.0),
            "sbproxy_budget_share_fail_open_total did not register or did not carry \
             the op label: {counted:?}"
        );

        let during = gathered_series("sbproxy_budget_share_unavailable");
        assert_eq!(
            during.first().map(|(_, value)| *value),
            Some(1.0),
            "the gauge did not go to 1 while the shared store was unreachable: {during:?}"
        );

        set_budget_share_unavailable(0);
        let after = gathered_series("sbproxy_budget_share_unavailable");
        assert_eq!(
            after.first().map(|(_, value)| *value),
            Some(0.0),
            "the gauge did not fall back to 0 once a resolution succeeded: {after:?}"
        );
    }

    /// A contained policy-enforcer panic is counted on
    /// `sbproxy_policy_panic_total{policy}` and carries the policy label.
    #[test]
    fn policy_panic_is_counted_with_its_policy_label() {
        record_policy_panic("budget_share");

        let counted = gathered_series("sbproxy_policy_panic_total");
        assert!(
            counted
                .iter()
                .any(|(labels, value)| labels.contains("policy=budget_share") && *value >= 1.0),
            "sbproxy_policy_panic_total did not register or did not carry \
             the policy label: {counted:?}"
        );
    }

    /// An MCP argument-policy trigger is counted on
    /// `sbproxy_mcp_argument_policy_total{tenant, rule, verdict}` and
    /// carries all three labels (WOR-2384, MCP05).
    #[test]
    fn mcp_argument_policy_trigger_is_counted_with_its_tenant_rule_and_verdict_labels() {
        record_mcp_argument_policy("acme", "no-path-traversal", "deny");

        let counted = gathered_series("sbproxy_mcp_argument_policy_total");
        assert!(
            counted.iter().any(|(labels, value)| {
                labels.contains("tenant=acme")
                    && labels.contains("rule=no-path-traversal")
                    && labels.contains("verdict=deny")
                    && *value >= 1.0
            }),
            "sbproxy_mcp_argument_policy_total did not register or did not carry \
             the tenant/rule/verdict labels: {counted:?}"
        );
    }

    #[test]
    fn mcp_grant_expired_is_counted_with_tenant_and_policy_labels() {
        record_mcp_grant_expired("acme", "analyst");

        let counted = gathered_series("sbproxy_mcp_grant_expired_total");
        assert!(
            counted.iter().any(|(labels, value)| {
                labels.contains("tenant=acme") && labels.contains("policy=analyst") && *value >= 1.0
            }),
            "sbproxy_mcp_grant_expired_total did not register or did not carry \
             the tenant/policy labels: {counted:?}"
        );
    }

    #[test]
    fn mcp_approval_hold_is_counted_with_tenant_and_outcome_labels() {
        record_mcp_approval_hold("acme", "held");

        let counted = gathered_series("sbproxy_mcp_approval_hold_total");
        assert!(
            counted.iter().any(|(labels, value)| {
                labels.contains("tenant=acme") && labels.contains("outcome=held") && *value >= 1.0
            }),
            "sbproxy_mcp_approval_hold_total did not register or did not carry \
             the tenant/outcome labels: {counted:?}"
        );
    }

    /// A session-flow enforcement trigger is counted on
    /// `sbproxy_mcp_flow_total{tenant, rule, verdict}` and carries all
    /// three labels (WOR-2384, MCP06).
    #[test]
    fn mcp_flow_trigger_is_counted_with_its_tenant_rule_and_verdict_labels() {
        record_mcp_flow("acme", "flow_exfil_block", "deny");

        let counted = gathered_series("sbproxy_mcp_flow_total");
        assert!(
            counted.iter().any(|(labels, value)| {
                labels.contains("tenant=acme")
                    && labels.contains("rule=flow_exfil_block")
                    && labels.contains("verdict=deny")
                    && *value >= 1.0
            }),
            "sbproxy_mcp_flow_total did not register or did not carry \
             the tenant/rule/verdict labels: {counted:?}"
        );
    }

    /// The full rule vocabulary WOR-2384 fix round 1 added
    /// (`flow_sensitive_touched`, `flow_pair_block`) is recorded the
    /// same way the pre-existing `flow_exfil_block` rule already was.
    #[test]
    fn mcp_flow_records_the_confidentiality_axis_and_pair_rule_labels() {
        record_mcp_flow("acme", "flow_sensitive_touched", "warn");
        record_mcp_flow("acme", "flow_pair_block", "deny");

        let counted = gathered_series("sbproxy_mcp_flow_total");
        assert!(
            counted.iter().any(|(labels, value)| {
                labels.contains("tenant=acme")
                    && labels.contains("rule=flow_sensitive_touched")
                    && labels.contains("verdict=warn")
                    && *value >= 1.0
            }),
            "sbproxy_mcp_flow_total did not carry flow_sensitive_touched: {counted:?}"
        );
        assert!(
            counted.iter().any(|(labels, value)| {
                labels.contains("tenant=acme")
                    && labels.contains("rule=flow_pair_block")
                    && labels.contains("verdict=deny")
                    && *value >= 1.0
            }),
            "sbproxy_mcp_flow_total did not carry flow_pair_block: {counted:?}"
        );
    }

    #[test]
    fn prompt_injection_classifier_failures_use_closed_attributable_labels() {
        record_prompt_injection_classifier_failure(
            "ai_body",
            "block",
            "primary_sidecar",
            "sidecar",
            "blocked",
            "prompt-health-tenant",
        );
        record_prompt_injection_classifier_failure(
            "https://secret.example/internal",
            "bearer-secret",
            "127.0.0.1:50051",
            "prompt bytes",
            "clean",
            "prompt-health-tenant",
        );

        let counted = gathered_series("sbproxy_prompt_injection_classifier_failures_total");
        assert!(counted.iter().any(|(labels, value)| {
            labels.contains("scan_path=ai_body")
                && labels.contains("action=block")
                && labels.contains("stage=primary_sidecar")
                && labels.contains("reason=sidecar")
                && labels.contains("outcome=blocked")
                && *value >= 1.0
        }));
        assert!(counted.iter().any(|(labels, value)| {
            labels.contains("scan_path=unknown")
                && labels.contains("action=unknown")
                && labels.contains("stage=unknown")
                && labels.contains("reason=unknown")
                && labels.contains("outcome=unknown")
                && *value >= 1.0
        }));
        let rendered = format!("{counted:?}");
        for secret in [
            "secret.example",
            "bearer-secret",
            "127.0.0.1:50051",
            "prompt bytes",
        ] {
            assert!(
                !rendered.contains(secret),
                "closed labels leaked {secret:?}"
            );
        }
    }

    /// WOR-2560: the target-health gauge is a scrape-time sample of the
    /// installed source, on the LiteLLM 0/1/2 scale.
    ///
    /// Three assertions, each a distinct failure mode:
    /// 1. installing a source and scraping surfaces the series (red
    ///    until `render()` calls `refresh_target_health_gauge`);
    /// 2. a health change in the source moves the value on the next
    ///    scrape, with no recorder call in between;
    /// 3. a target the source stops reporting (config reload shrank the
    ///    pool) leaves the scrape instead of freezing at its last value.
    #[test]
    fn target_health_gauge_follows_the_installed_source() {
        set_target_health_source(|| {
            vec![
                TargetHealthSample {
                    origin: "wor2560-origin".to_string(),
                    target: "http://127.0.0.1:19601".to_string(),
                    state: TARGET_HEALTH_HEALTHY,
                },
                TargetHealthSample {
                    origin: "wor2560-origin".to_string(),
                    target: "http://127.0.0.1:19602".to_string(),
                    state: TARGET_HEALTH_EXCLUDED,
                },
            ]
        });
        let output = metrics().render();
        assert!(
            output.contains(
                "sbproxy_target_health_state{origin=\"wor2560-origin\",target=\"http://127.0.0.1:19601\"} 0"
            ),
            "healthy target missing from the scrape:\n{output}"
        );
        assert!(
            output.contains(
                "sbproxy_target_health_state{origin=\"wor2560-origin\",target=\"http://127.0.0.1:19602\"} 2"
            ),
            "excluded target missing from the scrape:\n{output}"
        );

        // The pool shrinks to one target and that target recovers into
        // half-open trial traffic. The next scrape must say exactly that.
        set_target_health_source(|| {
            vec![TargetHealthSample {
                origin: "wor2560-origin".to_string(),
                target: "http://127.0.0.1:19602".to_string(),
                state: TARGET_HEALTH_DEGRADED,
            }]
        });
        let output = metrics().render();
        assert!(
            output.contains(
                "sbproxy_target_health_state{origin=\"wor2560-origin\",target=\"http://127.0.0.1:19602\"} 1"
            ),
            "state change did not move the gauge:\n{output}"
        );
        assert!(
            !output.contains("http://127.0.0.1:19601"),
            "a target removed from the source is still being scraped:\n{output}"
        );
    }

    /// Fix round on the #1177 review, red-first: `/metrics` is served
    /// from two independent listeners (the data plane's and the admin
    /// plane's), nothing serializes them, and the first shipped refresh
    /// did `gauge.reset()` before repopulating. Two renders in flight
    /// meant one could wipe the other's writes and let its `gather()`
    /// land in the gap, returning the family empty or partial.
    ///
    /// That matters here more than on the neighbouring cardinality
    /// gauges, which never reset: on this family a MISSING series is
    /// the alertable condition, so a scrape that drops it turns a
    /// healthy proxy into `absent(sbproxy_target_health_state)` firing
    /// and `min by (origin) (...) == 2` flapping.
    ///
    /// Before the differential refresh this failed within the first
    /// handful of iterations. Every render must carry every series.
    #[test]
    fn concurrent_renders_never_scrape_a_half_reset_target_health_gauge() {
        const TARGETS: [&str; 3] = [
            "http://127.0.0.1:19701",
            "http://127.0.0.1:19702",
            "http://127.0.0.1:19703",
        ];
        set_target_health_source(|| {
            TARGETS
                .iter()
                .map(|target| TargetHealthSample {
                    origin: "wor2560-race".to_string(),
                    target: (*target).to_string(),
                    state: TARGET_HEALTH_HEALTHY,
                })
                .collect()
        });
        // Prime it once so a missing series can only come from a wipe.
        let _ = metrics().render();

        let missing = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let missing = std::sync::Arc::clone(&missing);
            handles.push(std::thread::spawn(move || {
                for _ in 0..40 {
                    let output = metrics().render();
                    for target in TARGETS {
                        let series = format!(
                            "sbproxy_target_health_state{{origin=\"wor2560-race\",target=\"{target}\"}} 0"
                        );
                        if !output.contains(&series) {
                            missing
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(series);
                        }
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("render thread panicked");
        }
        let missing = missing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            missing.is_empty(),
            "{} concurrent scrapes observed a target-health series that a parallel refresh had \
             wiped; first: {:?}",
            missing.len(),
            missing.first()
        );
    }
}

/// WOR-2673 re-review N4: the OLP family has a writer that reaches it.
///
/// The CoMP families are pinned by
/// `serving_moves_the_metric_family_the_dashboard_reads` in
/// `sbproxy-licensing`; this one had nothing, so a `record_olp_decision`
/// wired to a field that never registered would have shown up as a flat
/// Grafana panel weeks later rather than as a red test.
#[cfg(test)]
mod olp_decision_metric_tests {
    use super::{metrics, record_olp_decision};

    /// Current value for one `(endpoint, outcome)` pair, or `None` when
    /// the family did not register at all.
    fn value(endpoint: &str, outcome: &str) -> Option<f64> {
        for family in metrics().registry.gather() {
            if family.name() != "sbproxy_olp_decisions_total" {
                continue;
            }
            for metric in family.get_metric() {
                let labels: std::collections::HashMap<&str, &str> = metric
                    .get_label()
                    .iter()
                    .map(|label| (label.name(), label.value()))
                    .collect();
                if labels.get("endpoint").copied() == Some(endpoint)
                    && labels.get("outcome").copied() == Some(outcome)
                {
                    return Some(metric.get_counter().value());
                }
            }
            // The family is registered but carries no series for this
            // pair yet, which reads as zero rather than as absent.
            return Some(0.0);
        }
        // `gather()` omits a `CounterVec` that has no children at all,
        // so an absent family before the first write is indistinguishable
        // from an unregistered one. That is why the assertions below
        // require the family to be *present* after the write: a recorder
        // wired to a field that never registered leaves it absent
        // forever.
        None
    }

    #[test]
    fn recording_an_olp_decision_moves_the_family_the_dashboard_reads() {
        // Every endpoint the registry declares, so a recorder wired to
        // the wrong field for one of them cannot hide behind the others.
        for endpoint in ["token", "key", "introspect", "revoke"] {
            let before = value(endpoint, "ok").unwrap_or(0.0);
            record_olp_decision(endpoint, "ok");
            let after = value(endpoint, "ok").unwrap_or_else(|| {
                panic!(
                    "sbproxy_olp_decisions_total is absent after recording {endpoint}/ok, so \
                     the recorder is wired to a family nothing scrapes"
                )
            });
            assert!(
                after > before,
                "recording {endpoint}/ok must move the family: {before} -> {after}"
            );
        }
    }

    /// The two refusal values the request path writes, so a label that
    /// stopped being reachable fails here rather than on a dashboard.
    #[test]
    fn the_refusal_outcomes_are_writable() {
        for outcome in ["rejected", "rate_limited", "error"] {
            let before = value("token", outcome).unwrap_or(0.0);
            record_olp_decision("token", outcome);
            assert!(
                value("token", outcome).expect("registered after the write") > before,
                "token/{outcome} must be writable"
            );
        }
    }
}
