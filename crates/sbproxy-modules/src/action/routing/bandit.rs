// SPDX-License-Identifier: Apache-2.0
//! Epsilon-greedy multi-armed bandit routing strategy.
//!
//! Treats each target as an arm of a bandit and learns which one delivers
//! the best success rate over time. The hot-path selection is cheap: a
//! single hash-map lookup per target plus one float comparison per
//! candidate. Statistics are kept in a process-local
//! [`std::sync::Mutex`]-guarded map keyed by target URL, so the state
//! survives reload of the load-balancer action as long as the URL is
//! stable.
//!
//! # Selection rule
//!
//! For every healthy target the strategy computes a score:
//!
//! - **Unseen arm**: `1.0 + bonus`, where `bonus` is a small constant
//!   (`0.05` by default). This is a UCB-style optimism bump that keeps
//!   unseen arms ahead of any arm with observed losses, so every target
//!   gets at least one trial before exploitation kicks in.
//! - **Seen arm**: empirical success rate `successes / total`.
//!
//! With probability `epsilon` (default `0.1`) the strategy picks a
//! healthy target uniformly at random instead, which is the exploration
//! half of epsilon-greedy. Setting `epsilon = 0.0` produces pure
//! exploitation; setting `epsilon = 1.0` produces pure exploration.
//!
//! # Recording outcomes
//!
//! The proxy's request-finalize path calls
//! [`BanditStrategy::record_outcome`] after the response is settled.
//! "Success" is whatever the operator wants (typically 2xx without
//! upstream timeout). Outcomes update a `(successes, total)` pair in the
//! interior map; the counters never decay, which is intentional. If
//! operators want a sliding window they can wrap the strategy or reset
//! by reloading the config.
//!
//! # Fall-back semantics
//!
//! Returns `None` when no healthy target exists, so the caller falls
//! through to the configured `lb_method`. Otherwise always returns
//! `Some`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use rand::Rng;
use serde::Deserialize;

use super::{RoutingRequest, RoutingStrategy, RoutingStrategyRegistration, TargetState};

/// Default value for the `epsilon` config field (`0.1`).
fn default_epsilon() -> f64 {
    0.1
}

/// Default value for the `unseen_bonus` config field (`0.05`).
fn default_unseen_bonus() -> f64 {
    0.05
}

/// Wire shape for the strategy's JSON config blob.
///
/// All fields are optional; an empty object (`{}`) builds a strategy
/// with default settings.
#[derive(Debug, Deserialize, Default)]
struct BanditConfig {
    /// Optional override for the strategy's `name` (used in logs and
    /// metrics labels). Defaults to `"bandit"`.
    #[serde(default)]
    name: Option<String>,
    /// Exploration rate in `[0.0, 1.0]`. With this probability the
    /// strategy picks a healthy target uniformly at random instead of
    /// the empirical best. Defaults to `0.1`.
    #[serde(default = "default_epsilon")]
    epsilon: f64,
    /// Optimism bonus added to unseen arms so they win at least one
    /// trial before exploitation. Defaults to `0.05`.
    #[serde(default = "default_unseen_bonus")]
    unseen_bonus: f64,
}

/// Per-target observation counters.
///
/// `total` is `successes + failures`, kept as one number so the
/// success-rate computation is a single division.
#[derive(Debug, Default, Clone, Copy)]
struct ArmStats {
    /// Count of recorded successful outcomes.
    successes: u64,
    /// Count of all recorded outcomes (successes plus failures).
    total: u64,
}

/// Epsilon-greedy multi-armed bandit routing strategy.
///
/// See the module-level documentation for the selection rule, the
/// outcome-recording contract, and fall-back semantics.
pub struct BanditStrategy {
    /// Stable identifier returned from [`RoutingStrategy::name`].
    name: String,
    /// Exploration probability in `[0.0, 1.0]`.
    epsilon: f64,
    /// Optimism bonus added to the score of any unseen arm.
    unseen_bonus: f64,
    /// Per-target observation counters keyed by upstream URL. The mutex
    /// is held only for the duration of a single hash-map operation so
    /// contention on the hot path is dominated by the read in `select`.
    stats: Mutex<HashMap<String, ArmStats>>,
}

impl BanditStrategy {
    /// Build a strategy from a JSON config blob.
    ///
    /// Accepts an empty object (`{}`) or `null` and uses defaults
    /// (`name = "bandit"`, `epsilon = 0.1`, `unseen_bonus = 0.05`).
    /// Out-of-range values for `epsilon` are clamped to `[0.0, 1.0]`.
    pub fn from_config(value: &serde_json::Value) -> Result<Arc<dyn RoutingStrategy>> {
        let config: BanditConfig = if value.is_null() {
            BanditConfig::default()
        } else {
            serde_json::from_value(value.clone())?
        };
        Ok(Arc::new(Self {
            name: config.name.unwrap_or_else(|| "bandit".to_string()),
            epsilon: config.epsilon.clamp(0.0, 1.0),
            unseen_bonus: config.unseen_bonus.max(0.0),
            stats: Mutex::new(HashMap::new()),
        }))
    }

    /// Compute the score for a target given its current counters and
    /// the configured `unseen_bonus`. An unseen arm (zero total) gets
    /// `1.0 + unseen_bonus` so it edges out any arm with observed
    /// success less than `1.0 + unseen_bonus`.
    fn score(&self, stats: Option<&ArmStats>) -> f64 {
        match stats {
            None => 1.0 + self.unseen_bonus,
            Some(s) if s.total == 0 => 1.0 + self.unseen_bonus,
            Some(s) => s.successes as f64 / s.total as f64,
        }
    }

    /// Record the outcome of a request that the strategy routed to
    /// `target_url`. Callers invoke this after the response resolves;
    /// `success` is operator-defined (typically a 2xx response without
    /// upstream timeout).
    ///
    /// Unknown URLs are added to the map on first record, which is the
    /// expected path on the very first request to a new arm.
    pub fn record_outcome(&self, target_url: &str, success: bool) {
        let mut guard = match self.stats.lock() {
            Ok(g) => g,
            // A poisoned mutex means a previous holder panicked while
            // holding the lock. Recovering the inner data is safe here
            // because the only state inside is plain counters; no
            // invariant can have been left half-updated.
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = guard.entry(target_url.to_string()).or_default();
        if success {
            entry.successes += 1;
        }
        entry.total += 1;
    }
}

impl RoutingStrategy for BanditStrategy {
    fn select(&self, _request: &RoutingRequest, targets: &[TargetState]) -> Option<usize> {
        // Build the healthy candidate list. No healthy target means we
        // fall through to the configured lb_method.
        let healthy: Vec<usize> = targets
            .iter()
            .enumerate()
            .filter(|(_, t)| t.healthy)
            .map(|(i, _)| i)
            .collect();
        if healthy.is_empty() {
            return None;
        }

        // Exploration: uniform-random among healthy targets.
        let mut rng = rand::thread_rng();
        let roll: f64 = rng.gen();
        if roll < self.epsilon {
            let pick = rng.gen_range(0..healthy.len());
            return Some(healthy[pick]);
        }

        // Exploitation: highest-scoring healthy target. Tie-break by
        // lower index so selection is deterministic when scores match
        // (notably on the all-unseen first call).
        let guard = match self.stats.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut best_idx = healthy[0];
        let mut best_score = self.score(guard.get(&targets[best_idx].url));
        for &i in &healthy[1..] {
            let s = self.score(guard.get(&targets[i].url));
            if s > best_score {
                best_score = s;
                best_idx = i;
            }
        }
        Some(best_idx)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

inventory::submit! {
    RoutingStrategyRegistration {
        name: "bandit",
        build: BanditStrategy::from_config,
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::routing::build_routing_strategy;
    use std::collections::HashMap;

    /// Build a minimal `TargetState` slot.
    fn target(index: usize, healthy: bool) -> TargetState {
        TargetState {
            index,
            url: format!("http://upstream-{}", index),
            healthy,
            active_connections: 0,
            weight: 1,
            metadata: HashMap::new(),
        }
    }

    fn req() -> RoutingRequest {
        RoutingRequest::new("POST", "/v1/chat", "ai.example.com")
    }

    /// Build a strategy with a deterministic epsilon for tests.
    fn build_with_epsilon(epsilon: f64) -> BanditStrategy {
        BanditStrategy {
            name: "bandit".to_string(),
            epsilon,
            unseen_bonus: 0.05,
            stats: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn from_config_accepts_empty_and_uses_defaults() {
        let strat =
            BanditStrategy::from_config(&serde_json::json!({})).expect("empty config should build");
        assert_eq!(strat.name(), "bandit");
        let from_registry =
            build_routing_strategy("bandit", &serde_json::Value::Null).expect("registered");
        assert_eq!(from_registry.name(), "bandit");
    }

    #[test]
    fn no_healthy_targets_returns_none() {
        let strat = build_with_epsilon(0.0);
        let targets = vec![target(0, false), target(1, false)];
        assert!(strat.select(&req(), &targets).is_none());
    }

    #[test]
    fn unseen_arms_win_over_failing_arms() {
        // With epsilon = 0 the strategy is pure exploitation. Arm 0 has
        // 0/10 success; arm 1 is unseen and must be tried first.
        let strat = build_with_epsilon(0.0);
        for _ in 0..10 {
            strat.record_outcome("http://upstream-0", false);
        }
        let targets = vec![target(0, true), target(1, true)];
        assert_eq!(strat.select(&req(), &targets), Some(1));
    }

    #[test]
    fn pure_exploitation_picks_best_success_rate() {
        let strat = build_with_epsilon(0.0);
        // Arm 0: 9/10 success rate.
        for _ in 0..9 {
            strat.record_outcome("http://upstream-0", true);
        }
        strat.record_outcome("http://upstream-0", false);
        // Arm 1: 1/10 success rate.
        strat.record_outcome("http://upstream-1", true);
        for _ in 0..9 {
            strat.record_outcome("http://upstream-1", false);
        }
        let targets = vec![target(0, true), target(1, true)];
        for _ in 0..20 {
            assert_eq!(strat.select(&req(), &targets), Some(0));
        }
    }

    #[test]
    fn pure_exploration_distributes_across_targets() {
        // epsilon = 1.0 means every call rolls into the explore branch.
        // With three healthy targets and 200 trials we should see all
        // three picked at least once; the probability of missing any
        // particular arm is (2/3)^200, which is negligible.
        let strat = build_with_epsilon(1.0);
        let targets = vec![target(0, true), target(1, true), target(2, true)];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            if let Some(idx) = strat.select(&req(), &targets) {
                seen.insert(idx);
            }
        }
        assert_eq!(
            seen.len(),
            3,
            "pure exploration must touch every healthy target"
        );
    }

    #[test]
    fn record_outcome_shifts_selection() {
        // Both arms start unseen, so under pure exploitation index 0
        // wins by tie-break. After feeding arm 0 a string of failures
        // its score drops and the unseen arm 1 takes the lead.
        let strat = build_with_epsilon(0.0);
        let targets = vec![target(0, true), target(1, true)];
        assert_eq!(strat.select(&req(), &targets), Some(0));
        for _ in 0..5 {
            strat.record_outcome("http://upstream-0", false);
        }
        assert_eq!(strat.select(&req(), &targets), Some(1));
    }

    #[test]
    fn unhealthy_targets_are_skipped_even_with_perfect_history() {
        let strat = build_with_epsilon(0.0);
        // Arm 0 has perfect history but is unhealthy: must be skipped.
        for _ in 0..10 {
            strat.record_outcome("http://upstream-0", true);
        }
        let targets = vec![target(0, false), target(1, true)];
        assert_eq!(strat.select(&req(), &targets), Some(1));
    }

    #[test]
    fn registered_under_bandit_name() {
        let names = crate::action::routing::list_routing_strategies();
        assert!(
            names.contains(&"bandit"),
            "bandit should be registered, got: {:?}",
            names
        );
    }

    #[test]
    fn epsilon_out_of_range_is_clamped() {
        // epsilon = -1.0 clamps to 0.0 (no exploration); the strategy
        // therefore behaves as pure exploitation.
        let strat = BanditStrategy::from_config(&serde_json::json!({ "epsilon": -1.0 }))
            .expect("config should build");
        assert_eq!(strat.name(), "bandit");
        // epsilon = 2.0 clamps to 1.0; building succeeds.
        let _ = BanditStrategy::from_config(&serde_json::json!({ "epsilon": 2.0 }))
            .expect("config should build");
    }
}
