// SPDX-License-Identifier: Apache-2.0
//! LoRA-identifier routing strategy.
//!
//! Picks the healthy upstream that advertises the LoRA adapter named on
//! the request. This is the "strict match" sibling of
//! [`super::lora_aware::LoraAwareStrategy`]: where `lora-aware` smooths
//! over the no-match case with a fall-back threshold and weights warm
//! targets by load, this strategy is intentionally crisp.
//!
//! # Selection rule
//!
//! - The request carries **no** LoRA identifier: pick the first healthy
//!   target.
//! - The request **has** a LoRA identifier and at least one healthy
//!   target advertises it: pick the lowest-index such target.
//! - The request has a LoRA identifier but **no** healthy target
//!   advertises it: return `None` so the caller falls back to the
//!   configured `lb_method`. The strategy does not silently route to a
//!   cold target; that decision belongs to the operator's fall-back
//!   policy.
//!
//! # Metadata contract
//!
//! Each [`TargetState`] may carry a `loaded_adapters` entry in its
//! `metadata` map, shaped as a JSON array of adapter identifier strings:
//!
//! ```json
//! { "loaded_adapters": ["alice-tone", "bob-style"] }
//! ```
//!
//! Anything else (missing key, non-array value, non-string elements) is
//! treated as "this target has no adapters loaded". A single
//! misconfigured target therefore cannot poison routing for the pool.
//!
//! # Request shape
//!
//! The LoRA identifier comes from [`RoutingRequest::adapter`]. The
//! wrapper that builds the request is responsible for parsing the
//! incoming `?adapter=...` query parameter or `X-LoRA-Adapter` header.

use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;

use super::{RoutingRequest, RoutingStrategy, RoutingStrategyRegistration, TargetState};

/// Metadata key the strategy reads from each target's `metadata` map.
const LOADED_ADAPTERS_KEY: &str = "loaded_adapters";

/// Wire shape for the strategy's JSON config blob.
///
/// All fields are optional; an empty object (`{}`) builds a strategy
/// with default settings.
#[derive(Debug, Deserialize, Default)]
struct LoraConfig {
    /// Optional override for the strategy's `name` (used in logs and
    /// metrics labels). Defaults to `"lora"`.
    #[serde(default)]
    name: Option<String>,
}

/// Routing strategy that picks the target advertising the requested
/// LoRA adapter, with strict no-match semantics.
///
/// See the module-level documentation for the selection rule and the
/// metadata contract.
pub struct LoraStrategy {
    /// Stable identifier returned from [`RoutingStrategy::name`].
    name: String,
}

impl LoraStrategy {
    /// Build a strategy from a JSON config blob.
    ///
    /// Accepts an empty object (`{}`) or `null` and uses defaults
    /// (`name = "lora"`).
    pub fn from_config(value: &serde_json::Value) -> Result<Arc<dyn RoutingStrategy>> {
        let config: LoraConfig = if value.is_null() {
            LoraConfig::default()
        } else {
            serde_json::from_value(value.clone())?
        };
        Ok(Arc::new(Self {
            name: config.name.unwrap_or_else(|| "lora".to_string()),
        }))
    }

    /// Returns `true` when `target.metadata.loaded_adapters` contains
    /// `adapter`. Tolerant of misconfiguration: a missing key, a
    /// non-array value, or non-string elements all yield `false` rather
    /// than panicking, so a single bad target cannot poison routing.
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

impl RoutingStrategy for LoraStrategy {
    fn select(&self, request: &RoutingRequest, targets: &[TargetState]) -> Option<usize> {
        // No LoRA identifier on the request: first healthy target.
        let Some(adapter) = request.adapter.as_deref() else {
            return targets.iter().position(|t| t.healthy);
        };

        // Identifier present: find a healthy target that advertises it.
        // Walk in index order so the tie-break is deterministic.
        for (idx, target) in targets.iter().enumerate() {
            if target.healthy && Self::target_has_adapter(target, adapter) {
                return Some(idx);
            }
        }
        // Strict no-match: defer to the configured lb_method.
        None
    }

    fn name(&self) -> &str {
        &self.name
    }
}

inventory::submit! {
    RoutingStrategyRegistration {
        name: "lora",
        build: LoraStrategy::from_config,
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::routing::build_routing_strategy;
    use std::collections::HashMap;

    /// Build a TargetState with a `loaded_adapters` metadata array.
    fn target_with_adapters(index: usize, healthy: bool, adapters: &[&str]) -> TargetState {
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
            active_connections: 0,
            weight: 1,
            metadata,
        }
    }

    /// Build a TargetState with no adapter metadata at all.
    fn bare_target(index: usize, healthy: bool) -> TargetState {
        TargetState {
            index,
            url: format!("http://upstream-{}", index),
            healthy,
            active_connections: 0,
            weight: 1,
            metadata: HashMap::new(),
        }
    }

    fn req(adapter: Option<&str>) -> RoutingRequest {
        let mut r = RoutingRequest::new("POST", "/v1/chat", "ai.example.com");
        r.adapter = adapter.map(|s| s.to_string());
        r
    }

    fn build_default() -> LoraStrategy {
        LoraStrategy {
            name: "lora".to_string(),
        }
    }

    #[test]
    fn from_config_accepts_empty_and_uses_defaults() {
        let strat =
            LoraStrategy::from_config(&serde_json::json!({})).expect("empty config should build");
        assert_eq!(strat.name(), "lora");
        let from_registry =
            build_routing_strategy("lora", &serde_json::Value::Null).expect("registered");
        assert_eq!(from_registry.name(), "lora");
    }

    #[test]
    fn no_adapter_id_picks_first_healthy_target() {
        let strat = build_default();
        let targets = vec![
            bare_target(0, false),
            bare_target(1, true),
            bare_target(2, true),
        ];
        // No adapter on the request: the first healthy target wins.
        assert_eq!(strat.select(&req(None), &targets), Some(1));
    }

    #[test]
    fn matching_adapter_is_selected() {
        let strat = build_default();
        let targets = vec![
            target_with_adapters(0, true, &["bob-style"]),
            target_with_adapters(1, true, &["alice-tone"]),
            target_with_adapters(2, true, &["alice-tone"]),
        ];
        // Index 1 is the lowest-index match. Stable tie-break.
        assert_eq!(strat.select(&req(Some("alice-tone")), &targets), Some(1));
    }

    #[test]
    fn no_matching_adapter_returns_none() {
        let strat = build_default();
        let targets = vec![
            target_with_adapters(0, true, &["bob-style"]),
            target_with_adapters(1, true, &["carol-voice"]),
        ];
        // Strict: no fall-back to a cold target. Caller decides.
        assert!(strat.select(&req(Some("alice-tone")), &targets).is_none());
    }

    #[test]
    fn unhealthy_match_is_ignored() {
        let strat = build_default();
        let targets = vec![
            target_with_adapters(0, false, &["alice-tone"]),
            target_with_adapters(1, true, &["alice-tone"]),
        ];
        assert_eq!(strat.select(&req(Some("alice-tone")), &targets), Some(1));
    }

    #[test]
    fn unhealthy_only_match_returns_none() {
        let strat = build_default();
        let targets = vec![
            // Only target that advertises the adapter is unhealthy.
            target_with_adapters(0, false, &["alice-tone"]),
            target_with_adapters(1, true, &["bob-style"]),
        ];
        assert!(strat.select(&req(Some("alice-tone")), &targets).is_none());
    }

    #[test]
    fn missing_metadata_key_treated_as_no_adapters() {
        let strat = build_default();
        let mut weird = HashMap::new();
        weird.insert("region".to_string(), serde_json::json!("us-east-1"));
        let targets = vec![TargetState {
            index: 0,
            url: "http://t0".to_string(),
            healthy: true,
            active_connections: 0,
            weight: 1,
            metadata: weird,
        }];
        assert!(strat.select(&req(Some("alice-tone")), &targets).is_none());
    }

    #[test]
    fn non_array_metadata_treated_as_no_adapters() {
        let strat = build_default();
        let mut wrong = HashMap::new();
        wrong.insert(
            LOADED_ADAPTERS_KEY.to_string(),
            serde_json::json!("alice-tone"),
        );
        let targets = vec![TargetState {
            index: 0,
            url: "http://t0".to_string(),
            healthy: true,
            active_connections: 0,
            weight: 1,
            metadata: wrong,
        }];
        assert!(strat.select(&req(Some("alice-tone")), &targets).is_none());
    }

    #[test]
    fn no_healthy_targets_and_no_adapter_returns_none() {
        let strat = build_default();
        let targets = vec![bare_target(0, false), bare_target(1, false)];
        assert!(strat.select(&req(None), &targets).is_none());
    }

    #[test]
    fn empty_targets_returns_none() {
        let strat = build_default();
        assert!(strat.select(&req(Some("alice-tone")), &[]).is_none());
        assert!(strat.select(&req(None), &[]).is_none());
    }

    #[test]
    fn registered_under_lora_name() {
        let names = crate::action::routing::list_routing_strategies();
        assert!(
            names.contains(&"lora"),
            "lora should be registered, got: {:?}",
            names
        );
    }
}
