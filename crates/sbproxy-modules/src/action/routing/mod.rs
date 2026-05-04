//! Pluggable routing strategy trait + plugin registry.
//!
//! This is the OSS scaffold for [Fail-6](../../../../docs/roadmap.md):
//! third-party crates (think the enterprise team's LoRA-aware,
//! GPU-aware, and contextual-bandit routers) implement
//! [`RoutingStrategy`] and register a factory via
//! [`inventory::submit!`]. The proxy discovers them at link time,
//! exactly like the auth-plugin registry in `sbproxy-plugin::registry`.
//!
//! The trait runs *alongside* the existing built-in load-balancer
//! algorithms (`round_robin`, `weighted`, `least_connections`,
//! `consistent_hash`, ...). Those algorithms are not behind this trait
//! and are not changed by the introduction of this module. A future
//! follow-up will route through the trait first, fall back to the
//! configured `lb_method` when [`RoutingStrategy::select`] returns
//! `None`, and migrate the built-ins to live behind the trait.
//!
//! # Why a hot-path trait
//!
//! Selection is on the request hot path, so the trait is intentionally
//! synchronous and takes already-projected `&[TargetState]` rather than
//! the live load-balancer state. The wrapper that builds the
//! `TargetState` slice does the translation from circuit breakers,
//! active health checks, and outlier ejection into a single boolean
//! `healthy` flag per target.
//!
//! # Registering a strategy
//!
//! ```ignore
//! use std::sync::Arc;
//! use sbproxy_modules::action::routing::{
//!     RoutingStrategy, RoutingStrategyRegistration, RoutingRequest,
//!     TargetState,
//! };
//!
//! struct MyStrategy;
//!
//! impl RoutingStrategy for MyStrategy {
//!     fn name(&self) -> &str { "my-strategy" }
//!     fn select(
//!         &self,
//!         _request: &RoutingRequest,
//!         targets: &[TargetState],
//!     ) -> Option<usize> {
//!         targets.iter().position(|t| t.healthy)
//!     }
//! }
//!
//! inventory::submit! {
//!     RoutingStrategyRegistration {
//!         name: "my-strategy",
//!         build: |_config| Ok(Arc::new(MyStrategy)),
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use http::HeaderMap;

pub mod lora_aware;

pub use lora_aware::LoraAwareStrategy;

// --- RoutingRequest ---

/// Request projection passed to a [`RoutingStrategy`].
///
/// Owns the data the strategy needs so the trait stays object-safe
/// without taking a generic lifetime. Construction is the hot path's
/// responsibility; strategies should treat this as read-only.
#[derive(Debug, Clone)]
pub struct RoutingRequest {
    /// HTTP method, e.g. `"GET"`, `"POST"`.
    pub method: String,
    /// Request path including any query string. Strategies that key on
    /// the path-only component should split on `?` themselves.
    pub path: String,
    /// Full client request headers. Cloned so the strategy can scan
    /// them without holding a borrow on the inbound request.
    pub headers: HeaderMap,
    /// Resolved client IP, when the proxy could determine it. `None`
    /// means trust-proxy parsing failed or the request came in over a
    /// transport that does not expose a peer address.
    pub client_ip: Option<String>,
    /// The hostname the request matched, before any forwarding rule
    /// rewrote it. Useful for tenant-aware strategies.
    pub hostname: String,
    /// AI model identifier when the request is an AI proxy request.
    /// Only set on the AI-proxy code path; plain HTTP routing leaves
    /// this `None`.
    pub model: Option<String>,
    /// LoRA / fine-tune adapter identifier when present in the request
    /// (e.g. `?adapter=...` or `X-LoRA-Adapter`). Only set on the
    /// AI-proxy code path.
    pub adapter: Option<String>,
    /// Free-form metadata bag for additional signals the strategy
    /// might want (sticky session keys, geo zone, A/B bucket, ...).
    /// The wrapper that builds the request decides what goes here.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl RoutingRequest {
    /// Build a minimal `RoutingRequest`. Optional fields default to
    /// empty / `None`. Mostly useful for tests; the production hot
    /// path constructs the struct field-by-field.
    pub fn new(
        method: impl Into<String>,
        path: impl Into<String>,
        hostname: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: HeaderMap::new(),
            client_ip: None,
            hostname: hostname.into(),
            model: None,
            adapter: None,
            metadata: HashMap::new(),
        }
    }
}

// --- TargetState ---

/// One upstream target as visible to a [`RoutingStrategy`].
///
/// The wrapper that calls into the strategy collapses live load-balancer
/// signals (active health check, circuit breaker, outlier detector) into
/// the single [`healthy`](Self::healthy) boolean. Strategies that pick
/// an unhealthy target produce undefined behaviour from the proxy's
/// point of view, so well-behaved strategies skip them and return
/// `None` if no healthy target is available.
#[derive(Debug, Clone)]
pub struct TargetState {
    /// Position of this target in the original `LoadBalancerAction.targets`
    /// slice. The strategy returns this index (or rather the index into
    /// the `&[TargetState]` it received, which the caller maps back).
    pub index: usize,
    /// Upstream URL for this target. Read-only; the strategy must not
    /// rewrite it.
    pub url: String,
    /// `true` when the target is currently eligible to receive traffic.
    /// Collapses health-check, circuit-breaker, and outlier-detector
    /// state into one flag so strategies do not have to know about each
    /// signal individually.
    pub healthy: bool,
    /// Number of in-flight requests against this target right now,
    /// as observed by the load balancer's active-connections counter.
    pub active_connections: u64,
    /// Static weight from the target config (typically 1-100). Strategies
    /// that do not honour weights can ignore this.
    pub weight: u32,
    /// Free-form metadata copied from the target config. Lets a strategy
    /// key on labels (e.g. `gpu_model`, `region`, loaded LoRA adapters)
    /// without the trait needing a strategy-specific extension point.
    pub metadata: HashMap<String, serde_json::Value>,
}

// --- RoutingStrategy trait ---

/// Pluggable routing strategy.
///
/// Implementors pick one of the supplied `targets` for a given
/// `request`. The trait is `Send + Sync` because the strategy is
/// stored behind an `Arc` and called from any worker thread.
///
/// # Hot path constraints
///
/// - **No async.** Selection runs once per request before any
///   upstream connection is established. Async work (e.g. polling
///   GPU telemetry) belongs in a background task that updates state
///   the strategy reads through interior mutability.
/// - **No allocation in the common path.** `&self` and a borrowed
///   slice mean the strategy can be a pure function over its own
///   accumulated state.
/// - **Returning `None`** signals "fall through to the configured
///   `lb_method`". Strategies that always have an opinion can return
///   `Some(0)` as a degenerate fall-back rather than `None`.
pub trait RoutingStrategy: Send + Sync {
    /// Pick a target for this request.
    ///
    /// Returns the index *into the supplied `targets` slice* of the
    /// chosen target, or `None` to defer to the built-in algorithm.
    /// Indices outside `0..targets.len()` are treated as `None` by
    /// the caller.
    fn select(&self, request: &RoutingRequest, targets: &[TargetState]) -> Option<usize>;

    /// Stable identifier for this strategy, matching the `name` used
    /// at registration time. Used for logging and metrics labels.
    fn name(&self) -> &str;
}

// --- Plugin registry ---

/// Registration entry for a [`RoutingStrategy`] plugin.
///
/// Third-party crates submit one of these via [`inventory::submit!`]
/// per strategy they expose. The proxy discovers them at link time,
/// builds a strategy from JSON config via [`build_routing_strategy`],
/// and stores the resulting `Arc<dyn RoutingStrategy>` on the
/// load-balancer action.
pub struct RoutingStrategyRegistration {
    /// Unique name for this strategy. Must match
    /// [`RoutingStrategy::name`] on the strategy the factory builds.
    pub name: &'static str,
    /// Factory that builds a configured strategy from JSON. The
    /// shape of the JSON value is strategy-defined.
    pub build: fn(&serde_json::Value) -> Result<Arc<dyn RoutingStrategy>>,
}

inventory::collect!(RoutingStrategyRegistration);

/// Build a [`RoutingStrategy`] from its registered name and a JSON
/// config blob.
///
/// Returns an error when no strategy is registered under `name`. The
/// error message names the unknown strategy so config-validation can
/// surface it to the user.
pub fn build_routing_strategy(
    name: &str,
    config: &serde_json::Value,
) -> Result<Arc<dyn RoutingStrategy>> {
    let reg = inventory::iter::<RoutingStrategyRegistration>()
        .find(|r| r.name == name)
        .ok_or_else(|| anyhow!("unknown routing strategy: {}", name))?;
    (reg.build)(config)
}

/// List the names of every registered routing strategy. Useful for
/// diagnostics and the `clictl` config validator.
pub fn list_routing_strategies() -> Vec<&'static str> {
    inventory::iter::<RoutingStrategyRegistration>()
        .map(|r| r.name)
        .collect()
}

// --- Built-in: AlwaysFirstHealthyStrategy ---

/// Reference [`RoutingStrategy`] implementation that picks the
/// lowest-index healthy target.
///
/// This is **for documentation and tests only**. Production
/// strategies (LoRA-aware, GPU-aware, contextual bandit) live in
/// downstream crates. Use the existing `lb_method: round_robin` or
/// `least_connections` for production deployments.
pub struct AlwaysFirstHealthyStrategy;

impl RoutingStrategy for AlwaysFirstHealthyStrategy {
    fn select(&self, _request: &RoutingRequest, targets: &[TargetState]) -> Option<usize> {
        targets.iter().position(|t| t.healthy)
    }

    fn name(&self) -> &str {
        "first-healthy"
    }
}

inventory::submit! {
    RoutingStrategyRegistration {
        name: "first-healthy",
        build: |_config| Ok(Arc::new(AlwaysFirstHealthyStrategy)),
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    /// A no-op strategy used to exercise the registry without coupling
    /// the test to `AlwaysFirstHealthyStrategy`'s behaviour.
    struct NoopStrategy;

    impl RoutingStrategy for NoopStrategy {
        fn select(&self, _request: &RoutingRequest, _targets: &[TargetState]) -> Option<usize> {
            None
        }
        fn name(&self) -> &str {
            "test-noop"
        }
    }

    inventory::submit! {
        RoutingStrategyRegistration {
            name: "test-noop",
            build: |_config| Ok(Arc::new(NoopStrategy)),
        }
    }

    #[test]
    fn trait_is_object_safe() {
        // Compile-time check: if `RoutingStrategy` ever loses object
        // safety, this stops compiling. The `Box::new` keeps it from
        // being optimized away in release builds.
        let _: Box<dyn RoutingStrategy> = Box::new(NoopStrategy);
    }

    #[test]
    fn build_unknown_strategy_returns_err_with_name() {
        // Avoid `unwrap_err` here because `Arc<dyn RoutingStrategy>`
        // is intentionally not `Debug` (would force every plugin to
        // implement it). Match the result instead.
        let result = build_routing_strategy("does-not-exist", &serde_json::Value::Null);
        let err = match result {
            Ok(_) => panic!("expected error for unknown strategy"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("does-not-exist"),
            "error message should name the unknown strategy, got: {}",
            msg
        );
    }

    #[test]
    fn registered_strategy_round_trips_via_builder() {
        // `Result::expect` requires `E: Debug`, which `anyhow::Error`
        // already provides; the `Ok` arm uses `Arc<dyn RoutingStrategy>`
        // which is *not* Debug, so we match instead of unwrap.
        let strat = match build_routing_strategy("test-noop", &serde_json::Value::Null) {
            Ok(s) => s,
            Err(e) => panic!("test-noop should be registered: {}", e),
        };
        assert_eq!(strat.name(), "test-noop");
        // Confirm the built strategy actually behaves like the
        // registered one (returns None on every selection).
        let req = RoutingRequest::new("GET", "/", "example.com");
        assert!(strat.select(&req, &[]).is_none());
    }

    #[test]
    fn list_routing_strategies_includes_registered() {
        let names = list_routing_strategies();
        assert!(
            names.contains(&"first-healthy"),
            "first-healthy should be registered, got: {:?}",
            names
        );
        assert!(
            names.contains(&"test-noop"),
            "test-noop should be registered, got: {:?}",
            names
        );
    }

    #[test]
    fn routing_request_debug_and_clone_preserve_metadata() {
        let mut req = RoutingRequest::new("POST", "/v1/chat", "ai.example.com");
        req.client_ip = Some("203.0.113.7".to_string());
        req.model = Some("llama-3-70b".to_string());
        req.adapter = Some("legal-en".to_string());
        req.metadata
            .insert("ab_bucket".to_string(), serde_json::json!("treatment"));

        let cloned = req.clone();
        assert_eq!(cloned.method, "POST");
        assert_eq!(cloned.path, "/v1/chat");
        assert_eq!(cloned.hostname, "ai.example.com");
        assert_eq!(cloned.client_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(cloned.model.as_deref(), Some("llama-3-70b"));
        assert_eq!(cloned.adapter.as_deref(), Some("legal-en"));
        assert_eq!(
            cloned.metadata.get("ab_bucket"),
            Some(&serde_json::json!("treatment"))
        );

        // Debug prints something non-empty and includes the path so
        // logs that drop a request-debug line stay useful.
        let debug = format!("{:?}", cloned);
        assert!(debug.contains("/v1/chat"));
    }

    #[test]
    fn target_state_debug_and_clone_preserve_metadata() {
        let mut t = TargetState {
            index: 3,
            url: "http://upstream-3.internal:8080".to_string(),
            healthy: true,
            active_connections: 17,
            weight: 50,
            metadata: HashMap::new(),
        };
        t.metadata
            .insert("gpu_model".to_string(), serde_json::json!("a100"));

        let cloned = t.clone();
        assert_eq!(cloned.index, 3);
        assert_eq!(cloned.url, "http://upstream-3.internal:8080");
        assert!(cloned.healthy);
        assert_eq!(cloned.active_connections, 17);
        assert_eq!(cloned.weight, 50);
        assert_eq!(
            cloned.metadata.get("gpu_model"),
            Some(&serde_json::json!("a100"))
        );

        let debug = format!("{:?}", cloned);
        assert!(debug.contains("upstream-3"));
    }

    #[test]
    fn always_first_healthy_skips_unhealthy() {
        let strat = AlwaysFirstHealthyStrategy;
        let req = RoutingRequest::new("GET", "/", "example.com");
        let targets = vec![
            TargetState {
                index: 0,
                url: "http://t0".to_string(),
                healthy: false,
                active_connections: 0,
                weight: 1,
                metadata: HashMap::new(),
            },
            TargetState {
                index: 1,
                url: "http://t1".to_string(),
                healthy: false,
                active_connections: 0,
                weight: 1,
                metadata: HashMap::new(),
            },
            TargetState {
                index: 2,
                url: "http://t2".to_string(),
                healthy: true,
                active_connections: 99,
                weight: 1,
                metadata: HashMap::new(),
            },
        ];
        assert_eq!(strat.select(&req, &targets), Some(2));
    }

    #[test]
    fn always_first_healthy_returns_none_when_all_unhealthy() {
        let strat = AlwaysFirstHealthyStrategy;
        let req = RoutingRequest::new("GET", "/", "example.com");
        let targets = vec![TargetState {
            index: 0,
            url: "http://t0".to_string(),
            healthy: false,
            active_connections: 0,
            weight: 1,
            metadata: HashMap::new(),
        }];
        assert!(strat.select(&req, &targets).is_none());
    }
}
