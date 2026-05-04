//! LoRA-aware routing strategy.
//!
//! Picks an upstream that already has the requested LoRA / fine-tune
//! adapter loaded in memory, avoiding the cold-load penalty paid when a
//! new adapter has to be paged onto a fresh GPU. Falls back to `None`
//! when no upstream advertises the adapter so the configured
//! `lb_method` still gets to pick.
//!
//! # Metadata contract
//!
//! Each [`TargetState`] passed to the strategy may carry a
//! `loaded_adapters` entry in its `metadata` map. The shape is a JSON
//! array of adapter identifiers (strings):
//!
//! ```json
//! { "loaded_adapters": ["alice-tone", "bob-style"] }
//! ```
//!
//! Anything else (missing key, non-array value, non-string elements)
//! is treated as an empty list. The strategy is intentionally lenient
//! so a misconfigured upstream cannot poison routing for the rest of
//! the pool.
//!
//! Populating this metadata is operator work and is intentionally
//! out of scope for this PR. The Fail-6 GPU-aware sibling card will
//! productionise the live telemetry feed; until then, configs can hard
//! code the inventory under each target's `metadata:` block.
//!
//! # Fall-back semantics
//!
//! The `fallback_below` config field is the cliff at which the strategy
//! hands control back to the caller. If fewer than that many healthy
//! targets advertise the adapter,
//! [`select`](RoutingStrategy::select) returns `None` and the load
//! balancer's configured `lb_method` runs. The default is `1`: route to
//! a warm target whenever one exists, fall through otherwise. Operators
//! that want a stronger signal (e.g. only engage when at least two warm
//! replicas are available, so a single slow target cannot be
//! hot-spotted) can raise the threshold.

use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;

use super::{RoutingRequest, RoutingStrategy, RoutingStrategyRegistration, TargetState};

/// Metadata key the strategy reads from each target's `metadata` map.
const LOADED_ADAPTERS_KEY: &str = "loaded_adapters";

/// Default value for the `fallback_below` config field.
fn default_fallback_below() -> usize {
    1
}

/// Wire shape for the strategy's JSON config blob.
///
/// All fields are optional; an empty object (`{}`) builds a strategy
/// with default settings.
#[derive(Debug, Deserialize, Default)]
struct LoraAwareConfig {
    /// Optional override for the strategy's `name` (used in logs and
    /// metrics labels). Defaults to `"lora-aware"`.
    #[serde(default)]
    name: Option<String>,
    /// Minimum healthy-and-warm targets required before the strategy
    /// commits to a selection. See the module-level "Fall-back
    /// semantics" section for the full description. Defaults to `1`.
    #[serde(default = "default_fallback_below")]
    fallback_below: usize,
}

/// Routing strategy that prefers upstreams which already have the
/// requested LoRA adapter loaded.
///
/// See the module-level documentation for the metadata contract and
/// fall-back semantics.
pub struct LoraAwareStrategy {
    /// Stable identifier returned from [`RoutingStrategy::name`].
    name: String,
    /// Minimum number of healthy targets that must advertise the
    /// adapter before the strategy will commit to one. Anything below
    /// this returns `None` and falls through to the configured
    /// `lb_method`.
    fallback_below: usize,
}

impl LoraAwareStrategy {
    /// Build a strategy from a JSON config blob.
    ///
    /// Accepts an empty object (`{}`) or `null` and uses defaults
    /// (`name = "lora-aware"`, `fallback_below = 1`).
    pub fn from_config(value: &serde_json::Value) -> Result<Arc<dyn RoutingStrategy>> {
        let config: LoraAwareConfig = if value.is_null() {
            LoraAwareConfig::default()
        } else {
            serde_json::from_value(value.clone())?
        };
        let fallback_below = if config.fallback_below == 0 {
            // Treat 0 as "always fall through" by clamping to 1; the
            // user almost certainly meant the default rather than a
            // strategy that never fires.
            1
        } else {
            config.fallback_below
        };
        Ok(Arc::new(Self {
            name: config.name.unwrap_or_else(|| "lora-aware".to_string()),
            fallback_below,
        }))
    }

    /// Returns `true` when `target.metadata.loaded_adapters` contains
    /// `adapter`. A missing key, a non-array value, or non-string
    /// elements all produce `false` rather than an error: a single
    /// misconfigured target should not break selection for the pool.
    fn target_has_adapter(target: &TargetState, adapter: &str) -> bool {
        let Some(value) = target.metadata.get(LOADED_ADAPTERS_KEY) else {
            return false;
        };
        let Some(array) = value.as_array() else {
            return false;
        };
        array.iter().any(|v| v.as_str() == Some(adapter))
    }
}

impl RoutingStrategy for LoraAwareStrategy {
    fn select(&self, request: &RoutingRequest, targets: &[TargetState]) -> Option<usize> {
        // No adapter on the request means there is no LoRA signal to
        // route on; defer to the configured lb_method.
        let adapter = request.adapter.as_deref()?;

        // Walk the targets once, collecting (slice index, active conns)
        // for every healthy target that advertises the adapter. Single
        // pass keeps the hot path allocation-bounded by the pool size.
        let mut warm: Vec<(usize, u64)> = Vec::with_capacity(targets.len());
        for (idx, target) in targets.iter().enumerate() {
            if !target.healthy {
                continue;
            }
            if Self::target_has_adapter(target, adapter) {
                warm.push((idx, target.active_connections));
            }
        }

        if warm.len() < self.fallback_below {
            return None;
        }

        // Pick the warm target with the lowest active_connections.
        // Tiebreak by slice index so the choice is deterministic across
        // runs (important for replayability of latency benchmarks).
        warm.into_iter()
            .min_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)))
            .map(|(idx, _)| idx)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

inventory::submit! {
    RoutingStrategyRegistration {
        name: "lora-aware",
        build: LoraAwareStrategy::from_config,
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::routing::build_routing_strategy;
    use std::collections::HashMap;

    /// Build a TargetState with a `loaded_adapters` metadata array.
    fn target_with_adapters(
        index: usize,
        healthy: bool,
        active_connections: u64,
        adapters: &[&str],
    ) -> TargetState {
        let mut metadata = HashMap::new();
        let arr: Vec<serde_json::Value> = adapters
            .iter()
            .map(|s| serde_json::Value::String((*s).to_string()))
            .collect();
        metadata.insert(
            LOADED_ADAPTERS_KEY.to_string(),
            serde_json::Value::Array(arr),
        );
        TargetState {
            index,
            url: format!("http://upstream-{}", index),
            healthy,
            active_connections,
            weight: 1,
            metadata,
        }
    }

    /// Build a TargetState with arbitrary metadata.
    fn target_with_metadata(
        index: usize,
        healthy: bool,
        active_connections: u64,
        metadata: HashMap<String, serde_json::Value>,
    ) -> TargetState {
        TargetState {
            index,
            url: format!("http://upstream-{}", index),
            healthy,
            active_connections,
            weight: 1,
            metadata,
        }
    }

    fn ai_request(adapter: Option<&str>) -> RoutingRequest {
        let mut req = RoutingRequest::new("POST", "/v1/chat", "ai.example.com");
        req.adapter = adapter.map(|s| s.to_string());
        req
    }

    fn build_default() -> LoraAwareStrategy {
        LoraAwareStrategy {
            name: "lora-aware".to_string(),
            fallback_below: 1,
        }
    }

    #[test]
    fn no_adapter_on_request_returns_none() {
        let strat = build_default();
        let req = ai_request(None);
        let targets = vec![target_with_adapters(0, true, 0, &["alice-tone"])];
        assert!(strat.select(&req, &targets).is_none());
    }

    #[test]
    fn single_warm_healthy_target_is_selected() {
        let strat = build_default();
        let req = ai_request(Some("alice-tone"));
        let targets = vec![target_with_adapters(0, true, 5, &["alice-tone"])];
        assert_eq!(strat.select(&req, &targets), Some(0));
    }

    #[test]
    fn warm_target_wins_over_cold_target() {
        let strat = build_default();
        let req = ai_request(Some("alice-tone"));
        let targets = vec![
            target_with_adapters(0, true, 1, &["bob-style"]),
            target_with_adapters(1, true, 99, &["alice-tone"]),
        ];
        // Index 1 is warm (loaded), index 0 is cold for this adapter.
        // Active connections do not matter when only one is warm.
        assert_eq!(strat.select(&req, &targets), Some(1));
    }

    #[test]
    fn lowest_active_connections_wins_among_warm_targets() {
        let strat = build_default();
        let req = ai_request(Some("alice-tone"));
        let targets = vec![
            target_with_adapters(0, true, 50, &["alice-tone"]),
            target_with_adapters(1, true, 10, &["alice-tone"]),
            target_with_adapters(2, true, 30, &["alice-tone"]),
        ];
        assert_eq!(strat.select(&req, &targets), Some(1));
    }

    #[test]
    fn ties_break_on_lower_index() {
        let strat = build_default();
        let req = ai_request(Some("alice-tone"));
        let targets = vec![
            target_with_adapters(0, true, 7, &["alice-tone"]),
            target_with_adapters(1, true, 7, &["alice-tone"]),
            target_with_adapters(2, true, 7, &["alice-tone"]),
        ];
        assert_eq!(strat.select(&req, &targets), Some(0));
    }

    #[test]
    fn unhealthy_warm_target_is_skipped() {
        let strat = build_default();
        let req = ai_request(Some("alice-tone"));
        let targets = vec![
            // Has the adapter but is unhealthy: must be ignored.
            target_with_adapters(0, false, 0, &["alice-tone"]),
            // Healthy but cold: not selected because the strategy has
            // no warm target to defer to. With fallback_below = 1 and
            // zero warm targets, the strategy returns None.
            target_with_adapters(1, true, 0, &["bob-style"]),
            // Healthy and warm: this is the one.
            target_with_adapters(2, true, 100, &["alice-tone"]),
        ];
        assert_eq!(strat.select(&req, &targets), Some(2));
    }

    #[test]
    fn no_target_has_adapter_returns_none() {
        let strat = build_default();
        let req = ai_request(Some("alice-tone"));
        let targets = vec![
            target_with_adapters(0, true, 0, &["bob-style"]),
            target_with_adapters(1, true, 0, &["carol-voice"]),
        ];
        assert!(strat.select(&req, &targets).is_none());
    }

    #[test]
    fn missing_loaded_adapters_key_treated_as_empty() {
        let strat = build_default();
        let req = ai_request(Some("alice-tone"));
        // Metadata exists but lacks the loaded_adapters key entirely.
        let mut metadata = HashMap::new();
        metadata.insert("region".to_string(), serde_json::json!("us-east-1"));
        let targets = vec![target_with_metadata(0, true, 0, metadata)];
        assert!(strat.select(&req, &targets).is_none());
    }

    #[test]
    fn non_array_loaded_adapters_treated_as_empty() {
        let strat = build_default();
        let req = ai_request(Some("alice-tone"));
        // Operator misconfiguration: loaded_adapters is a string, not
        // an array. The strategy must not panic; it must simply skip
        // this target.
        let mut metadata = HashMap::new();
        metadata.insert(
            LOADED_ADAPTERS_KEY.to_string(),
            serde_json::json!("alice-tone"),
        );
        let targets = vec![target_with_metadata(0, true, 0, metadata)];
        assert!(strat.select(&req, &targets).is_none());

        // Object instead of array: same behaviour.
        let mut metadata = HashMap::new();
        metadata.insert(
            LOADED_ADAPTERS_KEY.to_string(),
            serde_json::json!({"alice-tone": true}),
        );
        let targets = vec![target_with_metadata(0, true, 0, metadata)];
        assert!(strat.select(&req, &targets).is_none());
    }

    #[test]
    fn non_string_array_elements_are_ignored() {
        let strat = build_default();
        let req = ai_request(Some("alice-tone"));
        // The array contains a number and an object; neither matches
        // the requested adapter string. Mixed-type arrays should not
        // panic.
        let mut metadata = HashMap::new();
        metadata.insert(
            LOADED_ADAPTERS_KEY.to_string(),
            serde_json::json!([42, {"name": "alice-tone"}]),
        );
        let targets = vec![target_with_metadata(0, true, 0, metadata)];
        assert!(strat.select(&req, &targets).is_none());
    }

    #[test]
    fn from_config_accepts_empty_and_uses_defaults() {
        let strat = LoraAwareStrategy::from_config(&serde_json::json!({}))
            .expect("empty config should build");
        assert_eq!(strat.name(), "lora-aware");
        // Verify the registry round-trips the same name with a null
        // config, which is the path config validation actually walks.
        let from_registry =
            build_routing_strategy("lora-aware", &serde_json::Value::Null).expect("registered");
        assert_eq!(from_registry.name(), "lora-aware");
    }

    #[test]
    fn from_config_honours_fallback_below() {
        // fallback_below = 2 means: only fire when at least two warm
        // targets are available. A single warm target falls through
        // to the lb_method.
        let strat_arc = LoraAwareStrategy::from_config(&serde_json::json!({
            "fallback_below": 2,
        }))
        .expect("config should build");
        let req = ai_request(Some("alice-tone"));
        let targets = vec![
            target_with_adapters(0, true, 0, &["alice-tone"]),
            target_with_adapters(1, true, 0, &["bob-style"]),
        ];
        // Only one warm target, so we fall through.
        assert!(strat_arc.select(&req, &targets).is_none());

        // Add a second warm target: now the strategy commits.
        let targets = vec![
            target_with_adapters(0, true, 5, &["alice-tone"]),
            target_with_adapters(1, true, 1, &["alice-tone"]),
            target_with_adapters(2, true, 0, &["bob-style"]),
        ];
        assert_eq!(strat_arc.select(&req, &targets), Some(1));
    }

    #[test]
    fn registered_under_lora_aware_name() {
        // Confirms the `inventory::submit!` block at the bottom of
        // the module wires the factory in. Without this, no config
        // referencing `strategy: lora-aware` would resolve.
        let names = crate::action::routing::list_routing_strategies();
        assert!(
            names.contains(&"lora-aware"),
            "lora-aware should be registered, got: {:?}",
            names
        );
    }
}
