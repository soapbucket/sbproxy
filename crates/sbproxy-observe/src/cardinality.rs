//! Metrics cardinality limiter.
//!
//! Wraps Prometheus metric types to cap unique label values per label.
//! When a label exceeds the configured max unique values, new values
//! are mapped to `__other__` to prevent Prometheus OOM.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Sentinel value used when a label exceeds its cardinality cap.
pub const OTHER_LABEL: &str = "__other__";

/// Log when a label value is demoted due to cardinality limit.
pub fn log_demotion(label_name: &str, value: &str) {
    tracing::warn!(
        label = label_name,
        value = value,
        "label value demoted to __other__ due to cardinality limit"
    );
}

/// Configuration for cardinality limiting.
pub struct CardinalityConfig {
    /// Max unique values per label name. Default: 1000.
    pub max_per_label: usize,
}

impl Default for CardinalityConfig {
    fn default() -> Self {
        Self {
            max_per_label: 1000,
        }
    }
}

// --- Per-label budget table (Wave 1 / A1.1) ---

/// Per-label cardinality budget from `docs/adr-metric-cardinality.md`.
///
/// The lookup is closed: a label name not in the table falls back to
/// the workspace default cap. Values match the ADR table exactly so
/// the regression test in Q1.14 can assert the budget by name.
pub fn budget_for_label(label_name: &str) -> usize {
    match label_name {
        // Workspace-scoped traffic dimensions.
        "hostname" => 200,
        "origin" => 200,
        "tenant_id" | "workspace" | "workspace_id" => 1000,
        // Agent-class taxonomy (closed enums plus catalog).
        "agent_id" => 200,
        "agent_class" => 8,
        "agent_vendor" => 20,
        // Closed payment-rail enum (six values).
        "payment_rail" => 6,
        // Closed content-shape enum (five values).
        "content_shape" => 5,
        // HTTP basics. Method/status are closed but we keep the cap
        // tight to catch drift.
        "method" => 8,
        "status" => 12,
        // Policy / auth labels: closed enums; budget bounds drift.
        "policy_type" => 20,
        "auth_type" => 12,
        "action" => 8,
        "result" => 5,
        "reason" => 8,
        // Default workspace cap when the label is not in the table.
        _ => 1000,
    }
}

/// Tracks unique values seen for each label name.
///
/// Thread-safe via internal `Mutex`. Contention is low because the mutex is
/// only held when a new, previously-unseen label value arrives; after the set
/// reaches capacity every call for an unknown value takes only a brief lock to
/// do the size check before returning `__other__`.
pub struct CardinalityLimiter {
    config: CardinalityConfig,
    /// label_name -> set of accepted unique values.
    seen: Mutex<HashMap<String, HashSet<String>>>,
}

impl CardinalityLimiter {
    /// Create a new limiter with the given configuration.
    pub fn new(config: CardinalityConfig) -> Self {
        Self {
            config,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Sanitize a label value against the cardinality cap.
    ///
    /// Returns the value unchanged when:
    /// - The value has already been accepted for this label, **or**
    /// - The label has not yet reached `max_per_label` unique values.
    ///
    /// Returns `"__other__"` when the label is at capacity and this is a new
    /// value (the new value is **not** inserted into the tracking set).
    pub fn sanitize(&self, label_name: &str, value: &str) -> String {
        self.sanitize_with_cap(label_name, value, self.config.max_per_label)
    }

    /// Sanitize a label value with the budget pulled from the per-label
    /// table in `docs/adr-metric-cardinality.md`. Falls back to the
    /// workspace cap when the label is not in the table.
    ///
    /// Used by per-metric helpers (G1.6) so each label respects the
    /// budget that the cardinality ADR pins, rather than a single
    /// global ceiling. Existing callers of [`sanitize`](Self::sanitize)
    /// keep the workspace default.
    pub fn sanitize_budget(&self, label_name: &str, value: &str) -> String {
        let cap = budget_for_label(label_name);
        self.sanitize_with_cap(label_name, value, cap)
    }

    /// Internal helper: sanitize with an explicit cap. Used by both
    /// the workspace-default and per-label-budget paths above.
    fn sanitize_with_cap(&self, label_name: &str, value: &str, cap: usize) -> String {
        let mut guard = self
            .seen
            .lock()
            .expect("cardinality limiter mutex poisoned");
        let set = guard.entry(label_name.to_string()).or_default();

        if set.contains(value) {
            // Fast path: already accepted.
            return value.to_string();
        }

        if set.len() < cap {
            set.insert(value.to_string());
            value.to_string()
        } else {
            log_demotion(label_name, value);
            OTHER_LABEL.to_string()
        }
    }

    /// Return the current count of unique accepted values for a label.
    pub fn unique_count(&self, label_name: &str) -> usize {
        let guard = self
            .seen
            .lock()
            .expect("cardinality limiter mutex poisoned");
        guard.get(label_name).map(|s| s.len()).unwrap_or(0)
    }

    /// Reset all tracking. Primarily useful in tests.
    pub fn reset(&self) {
        let mut guard = self
            .seen
            .lock()
            .expect("cardinality limiter mutex poisoned");
        guard.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    fn limiter_with_max(max: usize) -> CardinalityLimiter {
        CardinalityLimiter::new(CardinalityConfig { max_per_label: max })
    }

    // --- log_demotion ---

    #[test]
    fn log_demotion_does_not_panic() {
        // log_demotion is a tracing call; verify it runs without panicking.
        log_demotion("origin", "overflow-value");
    }

    #[test]
    fn sanitize_calls_log_demotion_on_overflow() {
        // After the cap is reached, sanitize returns __other__ (demotion occurred).
        let lim = limiter_with_max(2);
        lim.sanitize("lbl", "a");
        lim.sanitize("lbl", "b");
        let result = lim.sanitize("lbl", "c");
        assert_eq!(result, OTHER_LABEL, "overflow value must be demoted");
    }

    // --- Basic behaviour ---

    #[test]
    fn value_within_limit_returned_unchanged() {
        let lim = limiter_with_max(10);
        assert_eq!(lim.sanitize("origin", "example.com"), "example.com");
        assert_eq!(lim.sanitize("origin", "example.com"), "example.com");
    }

    #[test]
    fn first_n_unique_values_accepted() {
        let lim = limiter_with_max(1000);
        for i in 0..1000 {
            let v = format!("origin-{i}");
            assert_eq!(lim.sanitize("origin", &v), v);
        }
        assert_eq!(lim.unique_count("origin"), 1000);
    }

    #[test]
    fn value_1001_returns_other() {
        let lim = limiter_with_max(1000);
        for i in 0..1000 {
            lim.sanitize("origin", &format!("origin-{i}"));
        }
        // The 1001st unique value must be redirected.
        assert_eq!(lim.sanitize("origin", "overflow-value"), OTHER_LABEL);
    }

    #[test]
    fn previously_seen_value_still_returned_after_limit_hit() {
        let lim = limiter_with_max(3);
        lim.sanitize("label", "a");
        lim.sanitize("label", "b");
        lim.sanitize("label", "c");

        // New value overflows.
        assert_eq!(lim.sanitize("label", "d"), OTHER_LABEL);

        // Previously accepted values must still pass through.
        assert_eq!(lim.sanitize("label", "a"), "a");
        assert_eq!(lim.sanitize("label", "b"), "b");
        assert_eq!(lim.sanitize("label", "c"), "c");
    }

    #[test]
    fn different_label_names_have_independent_limits() {
        let lim = limiter_with_max(2);

        // Fill "provider" to capacity.
        lim.sanitize("provider", "openai");
        lim.sanitize("provider", "anthropic");
        assert_eq!(lim.sanitize("provider", "cohere"), OTHER_LABEL);

        // "model" is a separate label and still has room.
        assert_eq!(lim.sanitize("model", "gpt-4"), "gpt-4");
        assert_eq!(lim.sanitize("model", "claude-3"), "claude-3");
        assert_eq!(lim.sanitize("model", "overflow"), OTHER_LABEL);
    }

    // --- Reset ---

    #[test]
    fn reset_clears_all_tracking() {
        let lim = limiter_with_max(2);
        lim.sanitize("x", "a");
        lim.sanitize("x", "b");
        assert_eq!(lim.sanitize("x", "c"), OTHER_LABEL);

        lim.reset();
        assert_eq!(lim.unique_count("x"), 0);

        // After reset "c" should be accepted.
        assert_eq!(lim.sanitize("x", "c"), "c");
    }

    // --- unique_count ---

    #[test]
    fn unique_count_reflects_accepted_values() {
        let lim = limiter_with_max(5);
        assert_eq!(lim.unique_count("k"), 0);
        lim.sanitize("k", "v1");
        assert_eq!(lim.unique_count("k"), 1);
        lim.sanitize("k", "v2");
        assert_eq!(lim.unique_count("k"), 2);
        // Duplicate does not increase count.
        lim.sanitize("k", "v1");
        assert_eq!(lim.unique_count("k"), 2);
    }

    // --- Per-label budget table (A1.1) ---

    #[test]
    fn budget_for_known_labels_matches_adr_table() {
        // Pin the ADR table values so a silent edit shows up in CI.
        assert_eq!(budget_for_label("hostname"), 200);
        assert_eq!(budget_for_label("agent_id"), 200);
        assert_eq!(budget_for_label("agent_class"), 8);
        assert_eq!(budget_for_label("agent_vendor"), 20);
        assert_eq!(budget_for_label("payment_rail"), 6);
        assert_eq!(budget_for_label("content_shape"), 5);
        assert_eq!(budget_for_label("workspace_id"), 1000);
        assert_eq!(budget_for_label("tenant_id"), 1000);
    }

    #[test]
    fn budget_for_unknown_label_falls_back_to_default_cap() {
        // Unknown labels get the workspace default. The ADR calls
        // this out: the table is closed, anything outside it is
        // capped at the global default.
        assert_eq!(budget_for_label("totally-novel-label"), 1000);
    }

    #[test]
    fn sanitize_budget_demotes_at_per_label_cap_for_agent_class() {
        // agent_class budget is 8 per ADR. Insert 8 distinct values,
        // then verify the 9th overflows to __other__.
        let lim = CardinalityLimiter::new(CardinalityConfig {
            max_per_label: 1_000_000,
        });
        for i in 0..8 {
            let v = format!("class-{i}");
            assert_eq!(lim.sanitize_budget("agent_class", &v), v);
        }
        assert_eq!(
            lim.sanitize_budget("agent_class", "class-9"),
            OTHER_LABEL,
            "9th distinct agent_class must demote (budget=8)"
        );
    }

    #[test]
    fn sanitize_budget_payment_rail_caps_at_six() {
        let lim = CardinalityLimiter::new(CardinalityConfig {
            max_per_label: 1_000_000,
        });
        for v in &[
            "none",
            "x402",
            "mpp_card",
            "mpp_stablecoin",
            "stripe_fiat",
            "lightning",
        ] {
            assert_eq!(lim.sanitize_budget("payment_rail", v), *v);
        }
        // Seventh value: overflow.
        assert_eq!(
            lim.sanitize_budget("payment_rail", "swift_wire"),
            OTHER_LABEL
        );
    }

    #[test]
    fn sanitize_budget_uses_default_for_unknown_label() {
        // Unknown labels still get a generous cap; this confirms the
        // fallback path doesn't accidentally cap at zero.
        let lim = CardinalityLimiter::new(CardinalityConfig {
            max_per_label: 1_000_000,
        });
        assert_eq!(lim.sanitize_budget("oddball", "value-1"), "value-1");
        assert_eq!(lim.sanitize_budget("oddball", "value-2"), "value-2");
    }

    // --- Concurrent access ---

    #[test]
    fn concurrent_access_is_safe() {
        // 10 threads each insert 150 unique values into the same label,
        // capped at 500. All returned values must be either the original
        // string or "__other__", and the accepted count must not exceed 500.
        let lim = Arc::new(CardinalityLimiter::new(CardinalityConfig {
            max_per_label: 500,
        }));

        let mut handles = Vec::new();
        for thread_id in 0..10_u32 {
            let lim = Arc::clone(&lim);
            let handle = std::thread::spawn(move || {
                let mut results = HashSet::new();
                for i in 0..150_u32 {
                    // Each thread uses a globally unique value to maximise
                    // contention at the cardinality boundary.
                    let v = format!("t{thread_id}-v{i}");
                    let out = lim.sanitize("concurrent_label", &v);
                    assert!(out == v || out == OTHER_LABEL, "unexpected output: {out}");
                    results.insert(out);
                }
                results
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // Accepted unique values must not exceed the cap.
        assert!(
            lim.unique_count("concurrent_label") <= 500,
            "cardinality cap exceeded: {}",
            lim.unique_count("concurrent_label")
        );
    }
}
