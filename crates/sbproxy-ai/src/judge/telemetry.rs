//! Prometheus metrics for the judge backend.
//!
//! Four metrics are registered, matching the OSS-scoped subset of the
//! telemetry surface from `adr-judge-trait.md`:
//!
//! | Metric | Type | Labels |
//! |---|---|---|
//! | `sbproxy_judge_calls_total` | counter | `provider`, `verdict`, `cached` |
//! | `sbproxy_judge_latency_seconds` | histogram | `provider`, `cached` |
//! | `sbproxy_judge_cost_usd` | counter | `provider` |
//! | `sbproxy_judge_budget_exhausted_total` | counter | `tenant` |
//!
//! The `template` label (per-policy template id) and the
//! `calibration_delta` metric are intentionally absent; both belong
//! to the enterprise router, not the OSS judge.
//!
//! Metrics are registered once on first access via [`std::sync::LazyLock`]
//! against the default Prometheus registry. The same pattern is used
//! by `crate::ai_metrics`, so all sbproxy-ai metrics live in the same
//! registry and the existing `/metrics` scrape endpoint surfaces them
//! without further wiring.

use std::sync::LazyLock;

use prometheus::{
    register_counter_vec, register_histogram_vec, CounterVec, HistogramOpts, HistogramVec, Opts,
};

/// Counter `sbproxy_judge_calls_total{provider, verdict, cached}`.
/// `verdict` is the high-level outcome (`allow`, `deny`,
/// `allow_with_headers`, or `error`); `cached` is `"true"` or
/// `"false"`. Cardinality is bounded because all three labels come
/// from a fixed-size enum domain.
static JUDGE_CALLS: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new("sbproxy_judge_calls_total", "Judge backend invocations"),
        &["provider", "verdict", "cached"]
    )
    .expect("sbproxy_judge_calls_total registers")
});

/// Histogram `sbproxy_judge_latency_seconds{provider, cached}`.
/// Bucket boundaries cover the ADR-published SLO range:
/// in-VPC judge p95 ~300ms, hosted frontier judge p95 ~2s.
static JUDGE_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "sbproxy_judge_latency_seconds",
            "Judge backend round-trip latency"
        )
        .buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0,]),
        &["provider", "cached"]
    )
    .expect("sbproxy_judge_latency_seconds registers")
});

/// Counter `sbproxy_judge_cost_usd{provider}` of provider-reported
/// cost per decision in USD. Cache hits charge zero and so do not
/// move the needle on this counter.
static JUDGE_COST: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_judge_cost_usd",
            "Judge backend cost per decision in USD"
        ),
        &["provider"]
    )
    .expect("sbproxy_judge_cost_usd registers")
});

/// Counter `sbproxy_judge_budget_exhausted_total{tenant}` ticked
/// every time [`super::BudgetTracker::charge`] returns
/// [`super::BudgetExhausted`]. Operators alert on a non-zero rate
/// of this metric; once it fires, the tenant's judge-gated requests
/// will start failing closed.
static JUDGE_BUDGET_EXHAUSTED: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        Opts::new(
            "sbproxy_judge_budget_exhausted_total",
            "Judge calls denied because the per-tenant budget was empty"
        ),
        &["tenant"]
    )
    .expect("sbproxy_judge_budget_exhausted_total registers")
});

/// Verdict bucket label used on `sbproxy_judge_calls_total`.
/// Centralising the strings here keeps the call sites uniform and
/// the dashboard queries stable.
pub const VERDICT_ALLOW: &str = "allow";
/// Verdict bucket label for `PolicyDecision::Deny`.
pub const VERDICT_DENY: &str = "deny";
/// Verdict bucket label for `PolicyDecision::AllowWithHeaders`.
pub const VERDICT_ALLOW_WITH_HEADERS: &str = "allow_with_headers";
/// Verdict bucket label for non-success outcomes (timeout,
/// provider error, malformed response, budget exhausted).
pub const VERDICT_ERROR: &str = "error";

/// `cached` label value returned by a cache hit.
pub const CACHED_TRUE: &str = "true";
/// `cached` label value returned by a cache miss / live provider call.
pub const CACHED_FALSE: &str = "false";

/// Record one judge call. `latency_seconds` is the wall-clock from
/// the point of dispatch to the point of result, including cache
/// lookup; `cost_usd` is the provider-reported per-call cost (zero
/// on cache hits or when the provider does not report cost).
pub fn record_judge_call(
    provider: &str,
    verdict: &str,
    cached: bool,
    latency_seconds: f64,
    cost_usd: f64,
) {
    let cached_label = if cached { CACHED_TRUE } else { CACHED_FALSE };
    JUDGE_CALLS
        .with_label_values(&[provider, verdict, cached_label])
        .inc();
    JUDGE_LATENCY
        .with_label_values(&[provider, cached_label])
        .observe(latency_seconds);
    if cost_usd > 0.0 {
        JUDGE_COST.with_label_values(&[provider]).inc_by(cost_usd);
    }
}

/// Tick the budget-exhausted counter for `tenant`. Tenants without
/// a meaningful identifier should pass the empty string; the label
/// is preserved verbatim because tenant strings come from operator
/// config and cardinality is the operator's responsibility.
pub fn record_budget_exhausted(tenant: &str) {
    JUDGE_BUDGET_EXHAUSTED.with_label_values(&[tenant]).inc();
}

/// Test accessor: cumulative count of `sbproxy_judge_calls_total`
/// for the given label triple.
#[cfg(test)]
pub fn judge_calls_value(provider: &str, verdict: &str, cached: bool) -> f64 {
    let cached_label = if cached { CACHED_TRUE } else { CACHED_FALSE };
    JUDGE_CALLS
        .with_label_values(&[provider, verdict, cached_label])
        .get()
}

/// Test accessor: cumulative count of
/// `sbproxy_judge_budget_exhausted_total` for `tenant`.
#[cfg(test)]
pub fn budget_exhausted_value(tenant: &str) -> f64 {
    JUDGE_BUDGET_EXHAUSTED.with_label_values(&[tenant]).get()
}

/// Test accessor: cumulative count of `sbproxy_judge_cost_usd`
/// for `provider`.
#[cfg(test)]
pub fn judge_cost_value(provider: &str) -> f64 {
    JUDGE_COST.with_label_values(&[provider]).get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_judge_call_increments_counters() {
        // Use a unique provider tag so this test does not race with
        // any other test that touches the same global counter.
        let provider = "telemetry_test_provider_a";
        let before = judge_calls_value(provider, VERDICT_ALLOW, false);
        let cost_before = judge_cost_value(provider);

        record_judge_call(provider, VERDICT_ALLOW, false, 0.123, 0.0042);

        // The acceptance gate from the implementation plan: after
        // one judge call the calls counter is non-zero for that
        // label triple.
        let after = judge_calls_value(provider, VERDICT_ALLOW, false);
        assert!(
            after - before >= 1.0,
            "calls_total must tick after a recorded call (before={before}, after={after})"
        );
        let cost_after = judge_cost_value(provider);
        assert!(
            (cost_after - cost_before - 0.0042).abs() < 1e-9,
            "cost_usd must add the recorded cost"
        );
    }

    #[test]
    fn record_judge_call_treats_zero_cost_as_no_op() {
        let provider = "telemetry_test_provider_b";
        let before = judge_cost_value(provider);
        record_judge_call(provider, VERDICT_ALLOW, true, 0.001, 0.0);
        let after = judge_cost_value(provider);
        assert!(
            (after - before).abs() < 1e-12,
            "zero-cost calls must not move the cost counter"
        );
    }

    #[test]
    fn record_budget_exhausted_ticks_counter() {
        let tenant = "telemetry_test_tenant_c";
        let before = budget_exhausted_value(tenant);
        record_budget_exhausted(tenant);
        record_budget_exhausted(tenant);
        let after = budget_exhausted_value(tenant);
        assert!(
            after - before >= 2.0,
            "budget_exhausted_total must tick once per call"
        );
    }
}
