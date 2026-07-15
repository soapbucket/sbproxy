// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The alert evaluation engine.
//!
//! [`channels`](super::channels) can deliver an alert and the rule modules can
//! decide whether a single reading breaches a threshold, but until now nothing
//! connected the two: the evaluators had no caller and no memory, so a
//! configured PagerDuty routing key opened no incident and a cleared condition
//! never resolved one. This module is the missing middle.
//!
//! [`AlertEngine::evaluate`] runs the built-in rules against a [`MetricReadings`]
//! snapshot and returns the alerts to dispatch this tick. It fires a rule the
//! first time it breaches, stays silent while it keeps breaching (so one
//! incident is opened, not one per tick), and emits exactly one `resolved`
//! alert when the condition clears. The engine is a pure state machine: the
//! caller does the sampling and the dispatching, which keeps the fire/recover
//! logic testable without a runtime or a live registry.
//!
//! [`sample_registry`] and [`error_burn`] read the two live inputs the built-in
//! rules need out of the default Prometheus registry, so the loop that drives
//! the engine has no dependency on the request path.

use std::collections::HashMap;

use super::channels::Alert;
use super::error_rate::{check_error_rate_spike, ErrorRateRule};
use super::rules::check_budget_exhaustion;

/// Origin label for the aggregate provider-error-burn rule. The rule spans
/// every provider rather than one upstream origin, so it carries a fixed scope
/// name instead of a hostname.
pub const PROVIDER_ERROR_SCOPE: &str = "ai_providers";

/// Live metric values the built-in rules evaluate against.
///
/// A field left `None` disables its rule for that tick, which is how a
/// deployment with channels configured but nothing breaching stays silent.
#[derive(Debug, Clone, Default)]
pub struct MetricReadings {
    /// Highest budget utilization across every budget scope, in `[0, 1]`.
    pub budget_utilization: Option<f64>,
    /// Fraction of AI provider attempts in the last interval that errored, in
    /// `[0, 1]`. `None` when no attempts were made in the window, so a quiet
    /// gateway does not read as 0% and does not recover a real alert.
    pub provider_error_rate: Option<f64>,
}

/// Thresholds for the built-in rules.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Budget utilization thresholds, ascending; the last is critical.
    pub budget_thresholds: Vec<f64>,
    /// Provider error-burn threshold in `[0, 1]`. A window whose error
    /// fraction exceeds this fires; twice this is critical.
    pub provider_error_threshold: f64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            budget_thresholds: vec![0.80, 0.95],
            provider_error_threshold: 0.10,
        }
    }
}

/// Evaluates the built-in rules and tracks per-rule firing state so each
/// condition fires once and recovers once.
#[derive(Debug)]
pub struct AlertEngine {
    config: EngineConfig,
    /// Rule instances currently firing, keyed by a stable identity, holding the
    /// alert exactly as first fired so the recovery notification carries the
    /// same labels (and therefore the same PagerDuty deduplication key).
    firing: HashMap<String, Alert>,
}

impl AlertEngine {
    /// Build an engine with the given thresholds.
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            firing: HashMap::new(),
        }
    }

    /// Evaluate every built-in rule against `readings` and return the alerts to
    /// dispatch this tick: one per rule that has just started breaching, plus a
    /// `resolved` alert for each rule that was firing and has now cleared.
    ///
    /// The caller passes the returned alerts to an
    /// [`AlertDispatcher`](super::channels::AlertDispatcher). Calling this again
    /// with the same breaching reading returns nothing, which is what holds a
    /// single incident open instead of reopening one every interval.
    pub fn evaluate(&mut self, readings: &MetricReadings) -> Vec<Alert> {
        let mut active: HashMap<String, Alert> = HashMap::new();

        if let Some(util) = readings.budget_utilization {
            if let Some(alert) = check_budget_exhaustion(util, &self.config.budget_thresholds) {
                active.insert(firing_key(&alert), alert);
            }
        }
        if let Some(rate) = readings.provider_error_rate {
            let rule = ErrorRateRule {
                origin: PROVIDER_ERROR_SCOPE.to_string(),
                threshold: self.config.provider_error_threshold,
            };
            if let Some(alert) = check_error_rate_spike(&rule, rate) {
                active.insert(firing_key(&alert), alert);
            }
        }

        let mut to_fire = Vec::new();

        // Fire only on the not-firing to firing edge.
        for (key, alert) in &active {
            if !self.firing.contains_key(key) {
                to_fire.push(alert.clone());
            }
        }

        // Resolve rules that were firing last tick and no longer breach. Re-emit
        // the alert as first fired, flipped to resolved, so the dispatcher's
        // dedup key matches the trigger it is closing.
        let cleared: Vec<String> = self
            .firing
            .keys()
            .filter(|key| !active.contains_key(*key))
            .cloned()
            .collect();
        for key in cleared {
            if let Some(mut alert) = self.firing.remove(&key) {
                alert.resolved = true;
                alert.timestamp = chrono::Utc::now().to_rfc3339();
                to_fire.push(alert);
            }
        }

        self.firing = active;
        to_fire
    }

    /// Number of rule instances currently held open. For tests and diagnostics.
    pub fn firing_count(&self) -> usize {
        self.firing.len()
    }
}

/// Stable identity for a firing rule instance.
///
/// The rule name plus its entity labels, deliberately excluding the fluctuating
/// value labels (`utilization`, `observed_rate`, `threshold`). Those change on
/// every sample; keying on them would treat each tick as a fresh instance and
/// reopen an incident every interval instead of holding one open to recovery.
fn firing_key(alert: &Alert) -> String {
    let mut key = alert.rule.clone();
    for label in ["origin", "provider", "tenant", "workspace", "scope"] {
        if let Some(value) = alert.labels.get(label) {
            key.push(':');
            key.push_str(label);
            key.push('=');
            key.push_str(value);
        }
    }
    key
}

/// The two monotonic provider counters, snapshotted so a burn rate can be taken
/// as a delta between ticks.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ProviderCounters {
    /// Cumulative `sbproxy_ai_provider_errors_total` across every label set.
    pub errors: f64,
    /// Cumulative `sbproxy_ai_provider_attempts_total` across every label set.
    pub attempts: f64,
}

/// Read the current provider attempt / error totals and the budget-utilization
/// high-water mark from the default Prometheus registry.
///
/// All three families register on the default (process-global) registry, so a
/// single `gather()` sees them; the private `ProxyMetrics` registry is not
/// consulted and does not need to be.
pub fn sample_registry() -> (ProviderCounters, Option<f64>) {
    let mut counters = ProviderCounters::default();
    let mut budget: Option<f64> = None;

    for family in prometheus::gather() {
        match family.name() {
            "sbproxy_ai_provider_errors_total" => counters.errors = sum_counter(&family),
            "sbproxy_ai_provider_attempts_total" => counters.attempts = sum_counter(&family),
            "sbproxy_ai_budget_utilization_ratio" => budget = Some(max_gauge(&family)),
            _ => {}
        }
    }

    (counters, budget)
}

fn sum_counter(family: &prometheus::proto::MetricFamily) -> f64 {
    family
        .get_metric()
        .iter()
        .map(|m| m.get_counter().value())
        .sum()
}

fn max_gauge(family: &prometheus::proto::MetricFamily) -> f64 {
    family
        .get_metric()
        .iter()
        .map(|m| m.get_gauge().value())
        .fold(0.0_f64, f64::max)
}

/// Turn two counter snapshots into the error-burn fraction for the interval
/// between them.
///
/// Returns `None` when no attempts were made in the window: a gateway that
/// served nothing has no error rate, and reporting 0% there would resolve a
/// real alert the moment traffic paused.
pub fn error_burn(prev: ProviderCounters, now: ProviderCounters) -> Option<f64> {
    let attempts = now.attempts - prev.attempts;
    if attempts <= 0.0 {
        return None;
    }
    let errors = (now.errors - prev.errors).max(0.0);
    Some((errors / attempts).clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readings(budget: Option<f64>, errors: Option<f64>) -> MetricReadings {
        MetricReadings {
            budget_utilization: budget,
            provider_error_rate: errors,
        }
    }

    #[test]
    fn a_breaching_rule_fires_once_then_stays_quiet() {
        let mut engine = AlertEngine::new(EngineConfig::default());

        // First breach fires.
        let fired = engine.evaluate(&readings(Some(0.97), None));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "budget_exhaustion");
        assert_eq!(fired[0].severity, "critical");
        assert!(!fired[0].resolved);

        // Still breaching: no new alert.
        assert!(engine.evaluate(&readings(Some(0.98), None)).is_empty());
        assert_eq!(engine.firing_count(), 1);
    }

    #[test]
    fn a_cleared_rule_emits_exactly_one_resolved_alert() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        engine.evaluate(&readings(Some(0.97), None));

        let recovered = engine.evaluate(&readings(Some(0.10), None));
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].resolved);
        assert_eq!(recovered[0].rule, "budget_exhaustion");
        assert_eq!(engine.firing_count(), 0);

        // Recovery is emitted once, not on every subsequent quiet tick.
        assert!(engine.evaluate(&readings(Some(0.10), None)).is_empty());
    }

    #[test]
    fn config_with_no_breaching_reading_does_nothing() {
        let mut engine = AlertEngine::new(EngineConfig::default());
        assert!(engine.evaluate(&readings(Some(0.10), Some(0.0))).is_empty());
        assert!(engine.evaluate(&readings(None, None)).is_empty());
        assert_eq!(engine.firing_count(), 0);
    }

    #[test]
    fn a_provider_error_burn_fires_and_recovers_independently() {
        let mut engine = AlertEngine::new(EngineConfig::default());

        // 50% error rate against a 10% threshold: critical, and independent of
        // the budget rule, which is not breaching.
        let fired = engine.evaluate(&readings(Some(0.10), Some(0.50)));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, "error_rate_spike");
        assert_eq!(fired[0].labels["origin"], PROVIDER_ERROR_SCOPE);

        // Error rate falls back under threshold: one recovery.
        let recovered = engine.evaluate(&readings(Some(0.10), Some(0.01)));
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].resolved);
    }

    #[test]
    fn two_rules_breach_and_recover_on_their_own_schedules() {
        let mut engine = AlertEngine::new(EngineConfig::default());

        // Both breach on the same tick: two distinct alerts.
        let fired = engine.evaluate(&readings(Some(0.99), Some(0.90)));
        assert_eq!(fired.len(), 2);
        assert_eq!(engine.firing_count(), 2);

        // Budget clears, provider error still burning: one recovery, and the
        // provider rule is not re-fired.
        let next = engine.evaluate(&readings(Some(0.10), Some(0.90)));
        assert_eq!(next.len(), 1);
        assert!(next[0].resolved);
        assert_eq!(next[0].rule, "budget_exhaustion");
        assert_eq!(engine.firing_count(), 1);
    }

    #[test]
    fn error_burn_is_a_delta_and_ignores_idle_windows() {
        let prev = ProviderCounters {
            errors: 10.0,
            attempts: 100.0,
        };
        // 5 more errors over 20 more attempts = 25% this window, not the
        // lifetime average.
        let now = ProviderCounters {
            errors: 15.0,
            attempts: 120.0,
        };
        assert_eq!(error_burn(prev, now), Some(0.25));

        // No attempts in the window: no reading, so no alert and no recovery.
        assert_eq!(error_burn(now, now), None);
    }
}
