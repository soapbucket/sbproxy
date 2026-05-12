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

// Per-provider error counter. Incremented at every site that maps a
// non-success outcome back to a named provider (transport error,
// timeout, upstream 4xx/5xx, parse failure). The dashboard groups by
// `provider`; `error_kind` is intended for ad-hoc drill-downs and
// should stay low cardinality (handful of stable strings).
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

/// Record a per-provider error.
///
/// `error_kind` is a short, low-cardinality label (e.g. `transport`,
/// `timeout`, `http_4xx`, `http_5xx`, `parse`). Free-form upstream
/// strings should be mapped to one of these stable buckets before
/// being passed in.
pub fn record_provider_error(provider: &str, error_kind: &str) {
    AI_PROVIDER_ERRORS
        .with_label_values(&[provider, error_kind])
        .inc();
}

/// Record a guardrail block.
pub fn record_guardrail_block(category: &str) {
    AI_GUARDRAIL_BLOCKS.with_label_values(&[category]).inc();
}

// --- Context-poisoning guardrail metrics (WOR-159) ---

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

/// Update budget utilization gauge.
pub fn set_budget_utilization(scope: &str, ratio: f64) {
    AI_BUDGET_UTILIZATION.with_label_values(&[scope]).set(ratio);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_record_provider_error() {
        record_provider_error("openai", "timeout");
        record_provider_error("anthropic", "http_5xx");
        let families = prometheus::gather();
        let errs = families
            .iter()
            .find(|f| f.name() == "sbproxy_ai_provider_errors_total");
        assert!(errs.is_some(), "provider errors counter must be registered");
    }
}
