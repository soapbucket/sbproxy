// SPDX-License-Identifier: Apache-2.0
//! GPU-utilisation-aware routing strategy.
//!
//! Picks the healthy upstream with the lowest reported GPU utilisation,
//! falling back to a deterministic round robin across healthy targets
//! when no target advertises a utilisation signal. The strategy is
//! a pure consumer of telemetry: it does not poll any device.
//!
//! # Telemetry contract
//!
//! Each [`TargetState`] may carry a `gpu_utilization` entry in its
//! `metadata` map. The value is a JSON number in `[0.0, 1.0]` (the
//! fraction of compute the GPU is currently doing). Anything else
//! (missing key, non-number, out-of-range) is treated as "no signal"
//! for that target.
//!
//! ```json
//! { "gpu_utilization": 0.42 }
//! ```
//!
//! The signal is externally updated. Operators wire a metrics scrape,
//! a sidecar agent, or a control-plane hook that writes the current
//! reading into each target's metadata before the wrapper builds the
//! per-request `TargetState` slice. The strategy never blocks on I/O
//! to fetch the number; that would violate the hot-path "no async"
//! contract documented on [`RoutingStrategy`].
//!
//! # Fall-back semantics
//!
//! - At least one healthy target has a valid signal: the lowest-util
//!   target wins. Ties break by lower index for deterministic replay.
//! - No healthy target has a valid signal: round robin across the
//!   healthy targets. Round-robin state is process-local and stored
//!   in an [`AtomicU64`] so the counter never serialises with the
//!   selection path.
//! - No healthy targets at all: returns `None` and the caller falls
//!   through to the configured `lb_method`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;

use super::{RoutingRequest, RoutingStrategy, RoutingStrategyRegistration, TargetState};

/// Metadata key the strategy reads from each target's `metadata` map.
const GPU_UTILIZATION_KEY: &str = "gpu_utilization";

/// Wire shape for the strategy's JSON config blob.
///
/// All fields are optional; an empty object (`{}`) builds a strategy
/// with default settings.
#[derive(Debug, Deserialize, Default)]
struct GpuAwareConfig {
    /// Optional override for the strategy's `name` (used in logs and
    /// metrics labels). Defaults to `"gpu-aware"`.
    #[serde(default)]
    name: Option<String>,
}

/// Routing strategy that prefers the healthy target with the lowest
/// reported GPU utilisation.
///
/// See the module-level documentation for the telemetry contract and
/// fall-back behaviour.
pub struct GpuAwareStrategy {
    /// Stable identifier returned from [`RoutingStrategy::name`].
    name: String,
    /// Round-robin counter used when no target carries a usable
    /// utilisation reading. Wraps on overflow, which is fine because
    /// it is always reduced modulo the healthy-target count.
    counter: AtomicU64,
}

impl GpuAwareStrategy {
    /// Build a strategy from a JSON config blob.
    ///
    /// Accepts an empty object (`{}`) or `null` and uses defaults
    /// (`name = "gpu-aware"`).
    pub fn from_config(value: &serde_json::Value) -> Result<Arc<dyn RoutingStrategy>> {
        let config: GpuAwareConfig = if value.is_null() {
            GpuAwareConfig::default()
        } else {
            serde_json::from_value(value.clone())?
        };
        Ok(Arc::new(Self {
            name: config.name.unwrap_or_else(|| "gpu-aware".to_string()),
            counter: AtomicU64::new(0),
        }))
    }

    /// Read the GPU utilisation from a target's metadata, returning
    /// `None` for missing, non-numeric, or out-of-range values. The
    /// `[0.0, 1.0]` clamp protects against operator typos (e.g. a
    /// percent value of `42` slipping through instead of `0.42`).
    fn target_gpu_utilization(target: &TargetState) -> Option<f64> {
        let value = target.metadata.get(GPU_UTILIZATION_KEY)?;
        let n = value.as_f64()?;
        if n.is_finite() && (0.0..=1.0).contains(&n) {
            Some(n)
        } else {
            None
        }
    }
}

impl RoutingStrategy for GpuAwareStrategy {
    fn select(&self, _request: &RoutingRequest, targets: &[TargetState]) -> Option<usize> {
        // Collect healthy targets once so the score loop and the
        // fall-back round robin both work off the same slice.
        let healthy: Vec<usize> = targets
            .iter()
            .enumerate()
            .filter(|(_, t)| t.healthy)
            .map(|(i, _)| i)
            .collect();
        if healthy.is_empty() {
            return None;
        }

        // Walk healthy targets and track the lowest valid reading.
        // Tie-break by lower index for deterministic replay.
        let mut best: Option<(usize, f64)> = None;
        for &idx in &healthy {
            let Some(util) = Self::target_gpu_utilization(&targets[idx]) else {
                continue;
            };
            match best {
                None => best = Some((idx, util)),
                Some((_, current)) if util < current => best = Some((idx, util)),
                _ => {}
            }
        }
        if let Some((idx, _)) = best {
            return Some(idx);
        }

        // No usable telemetry: round robin across the healthy slice.
        let counter = self.counter.fetch_add(1, Ordering::Relaxed) as usize;
        Some(healthy[counter % healthy.len()])
    }

    fn name(&self) -> &str {
        &self.name
    }
}

inventory::submit! {
    RoutingStrategyRegistration {
        name: "gpu-aware",
        build: GpuAwareStrategy::from_config,
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::routing::build_routing_strategy;
    use std::collections::HashMap;

    /// Build a healthy `TargetState` with an optional GPU utilisation
    /// reading. `None` leaves the metadata key absent (the "no signal"
    /// case).
    fn target(index: usize, healthy: bool, gpu_util: Option<f64>) -> TargetState {
        let mut metadata = HashMap::new();
        if let Some(u) = gpu_util {
            metadata.insert(GPU_UTILIZATION_KEY.to_string(), serde_json::json!(u));
        }
        TargetState {
            index,
            url: format!("http://upstream-{}", index),
            healthy,
            active_connections: 0,
            weight: 1,
            metadata,
        }
    }

    /// Build a healthy target with arbitrary metadata (used for the
    /// "garbage value" coverage cases).
    fn target_with_metadata(
        index: usize,
        healthy: bool,
        metadata: HashMap<String, serde_json::Value>,
    ) -> TargetState {
        TargetState {
            index,
            url: format!("http://upstream-{}", index),
            healthy,
            active_connections: 0,
            weight: 1,
            metadata,
        }
    }

    fn req() -> RoutingRequest {
        RoutingRequest::new("POST", "/v1/chat", "ai.example.com")
    }

    fn build_default() -> GpuAwareStrategy {
        GpuAwareStrategy {
            name: "gpu-aware".to_string(),
            counter: AtomicU64::new(0),
        }
    }

    #[test]
    fn from_config_accepts_empty_and_uses_defaults() {
        let strat = GpuAwareStrategy::from_config(&serde_json::json!({}))
            .expect("empty config should build");
        assert_eq!(strat.name(), "gpu-aware");
        let from_registry =
            build_routing_strategy("gpu-aware", &serde_json::Value::Null).expect("registered");
        assert_eq!(from_registry.name(), "gpu-aware");
    }

    #[test]
    fn lowest_utilisation_wins() {
        let strat = build_default();
        let targets = vec![
            target(0, true, Some(0.9)),
            target(1, true, Some(0.2)),
            target(2, true, Some(0.5)),
        ];
        for _ in 0..10 {
            assert_eq!(strat.select(&req(), &targets), Some(1));
        }
    }

    #[test]
    fn unhealthy_target_is_skipped_even_if_idle() {
        let strat = build_default();
        let targets = vec![
            target(0, false, Some(0.01)),
            target(1, true, Some(0.5)),
            target(2, true, Some(0.4)),
        ];
        assert_eq!(strat.select(&req(), &targets), Some(2));
    }

    #[test]
    fn ties_break_on_lower_index() {
        let strat = build_default();
        let targets = vec![
            target(0, true, Some(0.3)),
            target(1, true, Some(0.3)),
            target(2, true, Some(0.3)),
        ];
        assert_eq!(strat.select(&req(), &targets), Some(0));
    }

    #[test]
    fn missing_signal_falls_back_to_round_robin() {
        let strat = build_default();
        let targets = vec![target(0, true, None), target(1, true, None)];
        // Without any utilisation signal the strategy must still pick
        // a healthy target. Three calls cycle 0, 1, 0 (round robin).
        assert_eq!(strat.select(&req(), &targets), Some(0));
        assert_eq!(strat.select(&req(), &targets), Some(1));
        assert_eq!(strat.select(&req(), &targets), Some(0));
    }

    #[test]
    fn mixed_signal_uses_only_targets_with_readings() {
        // Target 0 has no reading; targets 1 and 2 do. The strategy
        // must ignore the unreadable target and pick the lowest of
        // the two readings.
        let strat = build_default();
        let targets = vec![
            target(0, true, None),
            target(1, true, Some(0.7)),
            target(2, true, Some(0.3)),
        ];
        assert_eq!(strat.select(&req(), &targets), Some(2));
    }

    #[test]
    fn out_of_range_values_are_treated_as_missing() {
        let strat = build_default();
        // Negative, NaN, and >1.0 are all treated as missing. The
        // remaining target with a valid reading wins.
        let mut bad_neg = HashMap::new();
        bad_neg.insert(GPU_UTILIZATION_KEY.to_string(), serde_json::json!(-0.1));
        let mut bad_high = HashMap::new();
        bad_high.insert(GPU_UTILIZATION_KEY.to_string(), serde_json::json!(2.5));
        let targets = vec![
            target_with_metadata(0, true, bad_neg),
            target_with_metadata(1, true, bad_high),
            target(2, true, Some(0.6)),
        ];
        assert_eq!(strat.select(&req(), &targets), Some(2));
    }

    #[test]
    fn non_number_values_are_treated_as_missing() {
        let strat = build_default();
        let mut bad = HashMap::new();
        bad.insert(GPU_UTILIZATION_KEY.to_string(), serde_json::json!("high"));
        // Only one target, no usable reading: round robin still picks
        // the single healthy target.
        let targets = vec![target_with_metadata(0, true, bad)];
        assert_eq!(strat.select(&req(), &targets), Some(0));
    }

    #[test]
    fn no_healthy_targets_returns_none() {
        let strat = build_default();
        let targets = vec![target(0, false, Some(0.1)), target(1, false, None)];
        assert!(strat.select(&req(), &targets).is_none());
    }

    #[test]
    fn registered_under_gpu_aware_name() {
        let names = crate::action::routing::list_routing_strategies();
        assert!(
            names.contains(&"gpu-aware"),
            "gpu-aware should be registered, got: {:?}",
            names
        );
    }
}
