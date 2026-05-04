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

/// Record a failover event.
pub fn record_failover(from: &str, to: &str, reason: &str) {
    AI_FAILOVERS.with_label_values(&[from, to, reason]).inc();
}

/// Record a guardrail block.
pub fn record_guardrail_block(category: &str) {
    AI_GUARDRAIL_BLOCKS.with_label_values(&[category]).inc();
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
            .find(|f| f.get_name() == "sbproxy_ai_requests_total");
        assert!(ai_req.is_some());
    }

    #[test]
    fn test_record_failover() {
        record_failover("openai", "anthropic", "rate_limited");
        let families = prometheus::gather();
        let failovers = families
            .iter()
            .find(|f| f.get_name() == "sbproxy_ai_failovers_total");
        assert!(failovers.is_some());
    }

    #[test]
    fn test_record_guardrail_block() {
        record_guardrail_block("pii");
        record_guardrail_block("injection");
        let families = prometheus::gather();
        let blocks = families
            .iter()
            .find(|f| f.get_name() == "sbproxy_ai_guardrail_blocks_total");
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
}
