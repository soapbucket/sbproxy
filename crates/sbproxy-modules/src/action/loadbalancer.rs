//! Load balancer action - distributes requests across multiple upstream targets.
//!
//! Supports multiple routing algorithms: round-robin, weighted random,
//! least connections, IP hash, URI hash, header hash, cookie hash, and
//! ketama-style ring hash (consistent hashing).
//! Backup targets are excluded from normal selection and reserved for fallback.
//!
//! Also supports blue-green and canary deployment modes, priority-based
//! routing via the `X-Priority` request header, and zone-aware locality
//! (WOR-2328): when the proxy knows its own zone, selection prefers
//! same-zone targets and spills across zones only when no same-zone
//! target is healthy.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use sbproxy_platform::circuitbreaker::CircuitBreaker;
use sbproxy_platform::outlier::{OutlierDetector, OutlierDetectorConfig};
use serde::Deserialize;

use super::routing::build_routing_strategy_with_name;
use super::ForwardingHeaderControls;
use super::{RoutingOutcome, RoutingRequest, RoutingStrategy, TargetState};

const MAX_TARGET_METADATA_ENTRIES: usize = 64;
const MAX_TARGET_METADATA_KEY_BYTES: usize = 64;
const MAX_TARGET_METADATA_SERIALIZED_BYTES: usize = 16 * 1024;
const MAX_TARGET_METADATA_NESTING_DEPTH: usize = 8;

// --- Configuration types ---

/// Deployment mode for the load balancer.
///
/// Controls how traffic is split across target groups during deployments.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DeploymentMode {
    /// Normal load balancing (default). All active targets participate.
    #[default]
    #[serde(rename = "normal")]
    Normal,
    /// Blue-green deployment. Routes 100% of traffic to the named active group.
    /// Targets must have a `group` field set to "blue" or "green".
    #[serde(rename = "blue_green")]
    BlueGreen {
        /// The currently-active group: "blue" or "green".
        active: String,
    },
    /// Canary deployment. Routes `weight`% of requests to canary targets
    /// (targets with `group = "canary"`); remaining traffic uses primary targets.
    #[serde(rename = "canary")]
    Canary {
        /// Percentage of requests routed to canary targets (0 to 100).
        weight: u8,
    },
}

/// Load balancer action - distributes requests across multiple upstream targets.
pub struct LoadBalancerAction {
    /// Pool of upstream targets that may receive requests.
    pub targets: Vec<Target>,
    /// Routing algorithm used to pick a target per request.
    pub algorithm: Algorithm,
    /// Deployment mode (normal, blue-green, or canary).
    pub deployment_mode: DeploymentMode,
    /// Optional outlier detector that ejects targets which exceed the
    /// configured error rate over a sliding window. When `None`, every
    /// active target is always eligible for selection.
    pub outlier_detector: Option<Arc<OutlierDetector>>,
    /// Per-target circuit breakers, parallel to `targets`. `None`
    /// when the action does not configure `circuit_breaker`. When
    /// set, every target gets its own breaker and a target with
    /// state == `Open` is excluded from `select_target`.
    pub circuit_breakers: Option<Vec<Arc<CircuitBreaker>>>,
    /// Optional upstream retry policy. On a connect-time failure,
    /// the proxy increments the retry counter and re-runs
    /// `upstream_peer`, which routes traffic to a different healthy
    /// target via outlier / breaker / health filtering.
    pub retry: Option<crate::action::RetryConfig>,
    strategy_name: Option<&'static str>,
    strategy: Option<Arc<dyn RoutingStrategy>>,
    /// Consistent-hash ring, built once at config compile time.
    /// `Some` exactly when `algorithm` is [`Algorithm::RingHash`].
    ring: Option<HashRing>,
    /// The zone this proxy considers itself in, bound once by the
    /// pipeline after compilation (`proxy.zone`, falling back to the
    /// `SB_ZONE` environment variable). Unset means the zone-locality
    /// stage never engages, so a proxy with no zone identity selects
    /// exactly as it did before WOR-2328.
    local_zone: std::sync::OnceLock<String>,
    /// `true` when at least one configured target carries a `zone`
    /// label. Precomputed so the per-request locality stage does not
    /// rescan an unlabeled pool.
    zoned_targets: bool,
    /// Minimum eligible-target count for the locality stage; see
    /// [`LocalityConfig::min_pool_size`].
    locality_min_pool_size: usize,
    state: LoadBalancerState,
}

/// One load-balancer target choice and the method that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSelection {
    /// Parsed upstream hostname.
    pub host: String,
    /// Parsed upstream port.
    pub port: u16,
    /// Whether the upstream URL uses TLS.
    pub tls: bool,
    /// Position in [`LoadBalancerAction::targets`].
    pub target_index: usize,
    /// Registered strategy name or built-in algorithm name.
    pub selection_method: String,
    /// How the zone-locality stage shaped this selection. `None` when
    /// the stage did not engage (no proxy zone, no zoned targets, pool
    /// below `locality.min_pool_size`, or every target already
    /// filtered out by health signals).
    pub zone_locality: Option<ZoneLocality>,
}

/// Per-selection verdict of the zone-locality stage (WOR-2328).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneLocality {
    /// Selection was narrowed to targets in the proxy's own zone.
    Local,
    /// No same-zone target was healthy, so selection spilled across
    /// every eligible target regardless of zone.
    Spilled,
}

impl ZoneLocality {
    /// Stable lowercase label for logs, the admin request ring, the
    /// access log's `zone_locality` field, and the `verdict` label on
    /// `sbproxy_lb_zone_locality_total`. All four carry the same two
    /// strings, so an operator can join a spilled log line to the
    /// series that alerted.
    pub fn as_str(self) -> &'static str {
        match self {
            ZoneLocality::Local => "local",
            ZoneLocality::Spilled => "spilled",
        }
    }
}

impl std::fmt::Debug for LoadBalancerAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalancerAction")
            .field("targets", &self.targets)
            .field("algorithm", &self.algorithm)
            .field("deployment_mode", &self.deployment_mode)
            .field("outlier_detector", &self.outlier_detector.is_some())
            .field(
                "circuit_breakers",
                &self.circuit_breakers.as_ref().map(|v| v.len()),
            )
            .field("retry", &self.retry.is_some())
            .field("strategy", &self.strategy_name)
            .field("local_zone", &self.local_zone.get())
            .field("zoned_targets", &self.zoned_targets)
            .field("locality_min_pool_size", &self.locality_min_pool_size)
            .field("state", &self.state)
            .finish()
    }
}

/// Active health-check configuration accepted under the
/// `health_check:` key on a load_balancer target.
///
/// When set, the proxy issues a periodic GET to `<target_url><path>` and
/// marks the target unhealthy after `unhealthy_threshold` consecutive
/// non-2xx/timeout responses; it returns to healthy after
/// `healthy_threshold` consecutive 2xx responses. Unhealthy targets are
/// excluded from `select_target` until they recover.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheckConfig {
    /// Path to probe (e.g. `"/healthz"`). Must start with `/`.
    #[serde(default = "default_health_path")]
    pub path: String,
    /// Probe period (interval between probes) in seconds. Default 10.
    /// Each target runs its own probe loop on this cadence.
    #[serde(default = "default_health_interval", alias = "period_secs")]
    pub interval_secs: u64,
    /// Per-probe timeout in milliseconds. Default 2000.
    #[serde(default = "default_health_timeout_ms")]
    pub timeout_ms: u64,
    /// Consecutive failures required to mark a target unhealthy.
    /// Default 3.
    #[serde(default = "default_health_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    /// Consecutive successes required to mark a recovered target
    /// healthy again. Default 2.
    #[serde(default = "default_health_healthy_threshold")]
    pub healthy_threshold: u32,
}

fn default_health_path() -> String {
    "/healthz".to_string()
}

fn default_health_interval() -> u64 {
    10
}

fn default_health_timeout_ms() -> u64 {
    2000
}

fn default_health_unhealthy_threshold() -> u32 {
    3
}

fn default_health_healthy_threshold() -> u32 {
    2
}

/// Circuit-breaker configuration for a `load_balancer` action.
///
/// Distinct from outlier detection (which ejects on a sliding-window
/// error rate): the circuit breaker is a formal state machine that
/// opens after `failure_threshold` consecutive failures, rejects all
/// traffic for `open_duration_secs`, then admits a small number of
/// probe requests in `HalfOpen`; on `success_threshold` consecutive
/// successes it closes, otherwise it re-opens. One breaker is held
/// per target, so a flaky target is isolated without taking down
/// the rest of the pool.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures (5xx, connect/timeout) before tripping.
    /// Default `5`.
    #[serde(default = "default_cb_failure_threshold")]
    pub failure_threshold: u32,
    /// Consecutive successes in `HalfOpen` to close the breaker.
    /// Default `2`.
    #[serde(default = "default_cb_success_threshold")]
    pub success_threshold: u32,
    /// How long the breaker stays Open before admitting probe
    /// requests in HalfOpen. Default `30` seconds.
    #[serde(default = "default_cb_open_duration_secs")]
    pub open_duration_secs: u64,
}

fn default_cb_failure_threshold() -> u32 {
    5
}

fn default_cb_success_threshold() -> u32 {
    2
}

fn default_cb_open_duration_secs() -> u64 {
    30
}

/// Outlier-detection configuration block accepted under the
/// `outlier_detection:` key on a load_balancer action. All fields are
/// optional and fall back to `OutlierDetectorConfig::default()`.
#[derive(Debug, Deserialize, Default)]
pub struct OutlierDetectionConfig {
    /// Failure-rate threshold in `[0.0, 1.0]` above which a target is
    /// ejected. Default `0.5`.
    #[serde(default)]
    pub threshold: Option<f64>,
    /// Sliding-window length in seconds. Default `60`.
    #[serde(default)]
    pub window_secs: Option<u64>,
    /// Minimum requests in the window before a target can be ejected.
    /// Default `5`.
    #[serde(default)]
    pub min_requests: Option<u32>,
    /// How long to keep an ejected target out of the pool, in seconds.
    /// Default `30`.
    #[serde(default)]
    pub ejection_duration_secs: Option<u64>,
}

/// Zone-locality tuning accepted under the `locality:` key on a
/// load_balancer action (WOR-2328).
///
/// The zone-locality stage itself needs no block to run: it engages
/// whenever the proxy knows its own zone (`proxy.zone`, or `SB_ZONE`
/// when that is unset) and at least one target carries a `zone` label.
/// This block only tunes it.
#[derive(Debug, Deserialize)]
pub struct LocalityConfig {
    /// Minimum pool size required before the zone-locality stage
    /// narrows selection, counted over the deployment-filtered pool
    /// before health filtering (as Envoy counts cluster hosts) so a
    /// health flap cannot toggle the stage. Below it, selection
    /// spreads across every eligible target as if no zone were set.
    ///
    /// Envoy's zone-aware routing carries the same deactivation guard
    /// as `min_cluster_size` (default 6 there) so a small local zone
    /// cannot absorb a large fleet's traffic. The default here is 2,
    /// not 6, because this stage is a hard per-proxy preference rather
    /// than Envoy's fleet-wide percentage balancing, and a deactivating
    /// default would make the common two-target, two-zone config
    /// silently non-local, which is the exact trap WOR-2328 exists to
    /// remove. Values below 2 disable the guard entirely.
    #[serde(default = "default_locality_min_pool_size")]
    pub min_pool_size: usize,
}

fn default_locality_min_pool_size() -> usize {
    2
}

/// A single upstream target.
#[derive(Debug, Clone, Deserialize)]
pub struct Target {
    /// Full URL of the upstream (scheme://host:port).
    pub url: String,
    /// Weight used by weighted-random and similar algorithms.
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// When true, this target is reserved for fallback only.
    #[serde(default)]
    pub backup: bool,
    /// Deployment group tag used by blue-green and canary modes ("blue", "green", "canary").
    #[serde(default)]
    pub group: Option<String>,
    /// Routing priority (1 = highest, 10 = lowest). Lower numbers are preferred.
    /// Read from `X-Priority` header when not set here; defaults to 5.
    #[serde(default = "default_priority")]
    pub priority: u8,
    /// Availability zone or region label, e.g. `"us-east-1a"`.
    ///
    /// A routing input since WOR-2328: when the proxy knows its own
    /// zone (`proxy.zone`, or the `SB_ZONE` environment variable as a
    /// fallback), selection prefers targets whose `zone` matches it and
    /// widens to every eligible target only when no same-zone target is
    /// healthy. A proxy with no zone identity ignores the label, so a
    /// config that sets it without `proxy.zone` behaves exactly as an
    /// unzoned one (and says so in a boot warning).
    ///
    /// History: WOR-2246 pinned `zone` as a display label, WOR-2498
    /// removed it and refused an authored `zone:` at config compile
    /// because a label whose name promises routing must route, and
    /// WOR-2328 re-introduced it with the enforcement attached.
    #[serde(default)]
    pub zone: Option<String>,
    /// Active health-check configuration for this target. When set,
    /// the proxy probes the target on a background timer and ejects it
    /// from selection on consecutive probe failures. See
    /// [`HealthCheckConfig`].
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    /// Override the `Host` header sent to this target. Defaults to the
    /// target URL's hostname (so vhost-routed upstreams resolve correctly).
    /// Set this when the target expects a different `Host`.
    #[serde(default)]
    pub host_override: Option<String>,
    /// Strategy-specific static routing signals.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
    /// Per-target opt-out flags for the standard proxy forwarding headers.
    #[serde(flatten, default)]
    pub forwarding: ForwardingHeaderControls,
}

fn default_priority() -> u8 {
    5
}

fn default_weight() -> u32 {
    1
}

fn validate_target_metadata(metadata: &HashMap<String, serde_json::Value>) -> Result<()> {
    anyhow::ensure!(
        metadata.len() <= MAX_TARGET_METADATA_ENTRIES,
        "target metadata cannot contain more than {MAX_TARGET_METADATA_ENTRIES} entries"
    );
    anyhow::ensure!(
        metadata
            .keys()
            .all(|key| key.len() <= MAX_TARGET_METADATA_KEY_BYTES),
        "target metadata keys cannot exceed {MAX_TARGET_METADATA_KEY_BYTES} bytes"
    );
    let serialized_size = serde_json::to_vec(metadata)?.len();
    anyhow::ensure!(
        serialized_size <= MAX_TARGET_METADATA_SERIALIZED_BYTES,
        "target metadata serialized size cannot exceed {MAX_TARGET_METADATA_SERIALIZED_BYTES} bytes"
    );

    let mut pending: Vec<(&serde_json::Value, usize)> =
        metadata.values().map(|value| (value, 1)).collect();
    while let Some((value, depth)) = pending.pop() {
        anyhow::ensure!(
            depth <= MAX_TARGET_METADATA_NESTING_DEPTH,
            "target metadata nesting depth cannot exceed {MAX_TARGET_METADATA_NESTING_DEPTH}"
        );
        match value {
            serde_json::Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            serde_json::Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }

    Ok(())
}

/// Load balancing algorithm.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    /// Cycle through active targets in order.
    RoundRobin,
    /// Pick a target with probability proportional to its weight.
    WeightedRandom,
    /// Pick the target with the fewest in-flight connections.
    LeastConnections,
    /// Hash the client IP to a target (sticky by client).
    IpHash,
    /// Hash the request URI to a target (sticky by path).
    UriHash,
    /// Hash a named request header to a target.
    HeaderHash {
        /// Name of the header used as the hash key.
        header: String,
    },
    /// Hash a named cookie value to a target.
    CookieHash {
        /// Name of the cookie used as the hash key.
        cookie: String,
    },
    /// Ketama-style consistent hashing over the configured targets.
    ///
    /// The modulus algorithms above hash over the eligible slice, so a
    /// pool resize or health flap reshuffles most keys. The ring is
    /// built once over the configured targets instead, and an
    /// ineligible target is handled by walking to the next eligible
    /// point on the ring: removing one of N targets remaps roughly 1/N
    /// of keys, and a health flap moves only the keys the flapping
    /// target owned.
    RingHash {
        /// Where the hash key comes from. Defaults to the client IP.
        #[serde(default)]
        key: RingHashKey,
    },
}

/// Key source for [`Algorithm::RingHash`].
///
/// Each variant reuses the exact key material of the matching modulus
/// algorithm, so switching an existing `ip_hash`, `uri_hash`,
/// `header_hash`, or `cookie_hash` config to the ring changes only the
/// key-to-target mapping function, never what is hashed.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RingHashKey {
    /// Hash the client IP (the key `ip_hash` uses).
    #[default]
    Ip,
    /// Hash the path-only request URI (the key `uri_hash` uses).
    Uri,
    /// Hash a named request header (the key `header_hash` uses).
    /// Configured as `key: { header: X-User }`.
    Header(String),
    /// Hash a named cookie value (the key `cookie_hash` uses).
    /// Configured as `key: { cookie: session_id }`.
    Cookie(String),
}

// WOR-2311: `StickyConfig` lived here, parsed for compatibility, and
// never did anything: no affinity cookie was ever issued and nothing on
// the response path writes `Set-Cookie` (WOR-2246 pinned the gap).
// Deleted along with its boot warning when `ring_hash` landed as the
// real session-affinity answer. Unknown keys under `action:` are not
// rejected, so `from_config_for_origin` refuses an authored `sticky:`
// explicitly rather than letting the old warning decay into silence.

/// The exact YAML shape a `load_balancer` action accepts.
///
/// This lives at module scope rather than inside `from_config_for_origin`
/// because the build-time config-reader guard walks named types. A shape
/// declared inside a function body is invisible to `syn` module indexing,
/// so every key underneath it is unguarded: nothing can prove the key is
/// read and nothing complains when it stops being read. Keeping the shape
/// nameable is what lets `MODULE_CONFIG_ROOTS` in `sbproxy-config` point
/// at it. See `crates/sbproxy-capability/src/config_scan.rs`.
#[derive(Deserialize)]
struct LoadBalancerConfig {
    /// Upstream pool. At least one entry is required.
    targets: Vec<Target>,
    /// Built-in selection algorithm. Ignored when `strategy` names a
    /// registered routing strategy.
    #[serde(default = "default_algo")]
    algorithm: Algorithm,
    /// Sliding-window failure-rate ejection.
    #[serde(default)]
    outlier_detection: Option<OutlierDetectionConfig>,
    /// Zone-locality tuning. The stage runs without the block; see
    /// [`LocalityConfig`].
    #[serde(default)]
    locality: Option<LocalityConfig>,
    /// Per-target circuit breakers.
    #[serde(default)]
    circuit_breaker: Option<CircuitBreakerConfig>,
    /// Upstream retry policy applied on connect-time failure.
    #[serde(default)]
    retry: Option<crate::action::RetryConfig>,
    /// Name of a registered routing strategy, which takes precedence
    /// over `algorithm`.
    #[serde(default)]
    strategy: Option<String>,
    /// Opaque per-strategy configuration handed to the named strategy.
    #[serde(default)]
    strategy_config: Option<serde_json::Value>,
    /// Legacy selector kept for compatibility with the Go line.
    #[serde(default)]
    lb_method: Option<String>,
}

fn default_algo() -> Algorithm {
    Algorithm::RoundRobin
}

// --- Internal state ---

/// Internal state for the load balancer (not serialized).
struct LoadBalancerState {
    round_robin_counter: AtomicU64,
    connections: Vec<AtomicU32>,
    /// Per-target health: `0` = unknown (treated as healthy), `1` =
    /// healthy, `2` = unhealthy. Vec indexed by target index.
    health: Vec<AtomicU8>,
    /// Immutable metadata snapshots swapped atomically by target index.
    metadata: Vec<ArcSwap<HashMap<String, serde_json::Value>>>,
}

impl std::fmt::Debug for LoadBalancerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalancerState")
            .field(
                "round_robin_counter",
                &self.round_robin_counter.load(Ordering::Relaxed),
            )
            .field("connections_len", &self.connections.len())
            .field("metadata_len", &self.metadata.len())
            .finish()
    }
}

// --- Implementation ---

impl LoadBalancerAction {
    /// Build a LoadBalancerAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> Result<Self> {
        Self::from_config_for_origin(value, "")
    }

    /// Build a load balancer with a stable identity for strategy state.
    pub fn from_config_for_origin(value: serde_json::Value, origin_id: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct DeploymentConfig {
            #[serde(default)]
            mode: Option<String>,
            #[serde(default)]
            active: Option<String>,
            #[serde(default)]
            weight: Option<u8>,
        }

        let deployment_mode = if let Some(dm) = value.get("deployment_mode") {
            let dc: DeploymentConfig = serde_json::from_value(dm.clone())?;
            match dc.mode.as_deref() {
                Some("blue_green") => DeploymentMode::BlueGreen {
                    active: dc.active.unwrap_or_else(|| "blue".to_string()),
                },
                Some("canary") => DeploymentMode::Canary {
                    weight: dc.weight.unwrap_or(10),
                },
                _ => DeploymentMode::Normal,
            }
        } else {
            DeploymentMode::Normal
        };

        // WOR-2311: `sticky:` parsed for years and did nothing: no
        // affinity cookie was ever issued and nothing on the response
        // path writes `Set-Cookie`. Unknown keys under `action:` are
        // not rejected, so dropping the field alone would demote the
        // old boot warning to silence; refusing keeps the removal
        // loud, the way the AI handler refuses `token_rate`.
        anyhow::ensure!(
            value.get("sticky").is_none(),
            "load_balancer `sticky:` was removed: it never issued an affinity cookie. For \
             session affinity that survives pool resizes, use `algorithm: ring_hash` keyed \
             on `cookie`, `header`, `ip`, or `uri` (a ketama ring; removing one of N \
             targets remaps ~1/N of keys). The `cookie_hash`, `header_hash`, and `ip_hash` \
             modulus algorithms also remain available."
        );

        // `targets[].zone` was refused here between WOR-2498 and
        // WOR-2328: it parsed as a display label and steered nothing,
        // and a key whose name promises locality routing must not sit
        // inert. The refusal is gone because the promise is now kept:
        // `select_target_for_request` runs a zone-locality stage that
        // prefers same-zone targets and spills across zones when the
        // local zone has no healthy target.
        let config: LoadBalancerConfig = serde_json::from_value(value)?;
        anyhow::ensure!(
            !config.targets.is_empty(),
            "load balancer requires at least one target"
        );
        for target in &config.targets {
            validate_target_metadata(&target.metadata)?;
        }
        anyhow::ensure!(
            config.lb_method.as_deref() != Some("plugin") || config.strategy.is_some(),
            "lb_method: plugin requires strategy"
        );
        anyhow::ensure!(
            config
                .strategy_config
                .as_ref()
                .is_none_or(serde_json::Value::is_object),
            "strategy_config must be an object"
        );
        if config.strategy.as_deref() == Some("bandit") {
            anyhow::ensure!(
                config.targets.len() <= super::routing::bandit::MAX_TARGETS_PER_NAMESPACE,
                "bandit strategy supports at most {} targets",
                super::routing::bandit::MAX_TARGETS_PER_NAMESPACE
            );
        }
        let num_targets = config.targets.len();
        let metadata = config
            .targets
            .iter()
            .map(|target| ArcSwap::from_pointee(target.metadata.clone()))
            .collect();
        let (strategy_name, strategy) = match config.strategy.as_deref() {
            Some(name) => {
                let mut strategy_config = config
                    .strategy_config
                    .unwrap_or_else(|| serde_json::json!({}));
                if name == "bandit" {
                    let object = strategy_config
                        .as_object_mut()
                        .expect("strategy config was normalized to an object");
                    let target_urls: Vec<&str> = config
                        .targets
                        .iter()
                        .map(|target| target.url.as_str())
                        .collect();
                    let namespace = format!(
                        "{origin_id}:{name}:{}",
                        serde_json::to_string(&target_urls)?
                    );
                    object.insert(
                        "state_namespace".to_string(),
                        serde_json::Value::String(namespace),
                    );
                }
                let (registered_name, strategy) =
                    build_routing_strategy_with_name(name, &strategy_config)?;
                (Some(registered_name), Some(strategy))
            }
            None => (None, None),
        };

        // Build the outlier detector when the user has configured it.
        // The detector is shared across requests via Arc so the
        // ejection state survives between target selections.
        let outlier_detector = config.outlier_detection.map(|cfg| {
            let defaults = OutlierDetectorConfig::default();
            Arc::new(OutlierDetector::new(OutlierDetectorConfig {
                threshold: cfg.threshold.unwrap_or(defaults.threshold),
                window_secs: cfg.window_secs.unwrap_or(defaults.window_secs),
                min_requests: cfg.min_requests.unwrap_or(defaults.min_requests),
                ejection_duration_secs: cfg
                    .ejection_duration_secs
                    .unwrap_or(defaults.ejection_duration_secs),
            }))
        });

        // Build per-target circuit breakers when configured. One
        // breaker per target so a flaky upstream is isolated without
        // taking down the rest of the pool.
        let circuit_breakers = config.circuit_breaker.as_ref().map(|cfg| {
            (0..num_targets)
                .map(|_| {
                    Arc::new(CircuitBreaker::new(
                        cfg.failure_threshold,
                        cfg.success_threshold,
                        std::time::Duration::from_secs(cfg.open_duration_secs),
                    ))
                })
                .collect::<Vec<_>>()
        });

        // Build the ring up front so per-request selection only binary
        // searches. The ring covers every configured target; eligibility
        // is applied at lookup time by walking, never by rebuilding.
        let ring = matches!(config.algorithm, Algorithm::RingHash { .. })
            .then(|| HashRing::build(&config.targets));

        let zoned_targets = config.targets.iter().any(|target| target.zone.is_some());
        let locality_min_pool_size = config
            .locality
            .map(|locality| locality.min_pool_size)
            .unwrap_or_else(default_locality_min_pool_size);

        Ok(Self {
            targets: config.targets,
            algorithm: config.algorithm,
            deployment_mode,
            outlier_detector,
            circuit_breakers,
            retry: config.retry,
            strategy_name,
            strategy,
            ring,
            local_zone: std::sync::OnceLock::new(),
            zoned_targets,
            locality_min_pool_size,
            state: LoadBalancerState {
                round_robin_counter: AtomicU64::new(0),
                connections: (0..num_targets).map(|_| AtomicU32::new(0)).collect(),
                health: (0..num_targets).map(|_| AtomicU8::new(0)).collect(),
                metadata,
            },
        })
    }

    /// Atomically replace one target's bounded strategy metadata snapshot.
    pub fn update_target_metadata(
        &self,
        target_index: usize,
        metadata: HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        validate_target_metadata(&metadata)?;
        let slot = self.state.metadata.get(target_index).ok_or_else(|| {
            anyhow::anyhow!("target metadata index {target_index} is out of range")
        })?;
        slot.store(Arc::new(metadata));
        Ok(())
    }

    /// Return the current immutable strategy metadata snapshot for a target.
    pub fn target_metadata_snapshot(
        &self,
        target_index: usize,
    ) -> Option<Arc<HashMap<String, serde_json::Value>>> {
        self.state
            .metadata
            .get(target_index)
            .map(ArcSwap::load_full)
    }

    /// Bind the zone this proxy considers itself in (WOR-2328).
    ///
    /// Called once per compiled pipeline, after action compilation,
    /// with the value `proxy.zone` resolves to (config first, then the
    /// `SB_ZONE` environment variable). Empty and whitespace-only
    /// values are ignored, and only the first non-empty bind sticks;
    /// a config reload builds a new action and binds it fresh.
    pub fn bind_local_zone(&self, zone: &str) {
        let zone = zone.trim();
        if zone.is_empty() {
            return;
        }
        let _ = self.local_zone.set(zone.to_string());
    }

    /// The zone this proxy considers itself in, when one is bound.
    pub fn local_zone(&self) -> Option<&str> {
        self.local_zone.get().map(String::as_str)
    }

    /// `true` when at least one configured target carries a `zone` label.
    pub fn has_zoned_targets(&self) -> bool {
        self.zoned_targets
    }

    // There was a `pub fn locality_min_pool_size()` accessor here.
    // Nothing outside this file's tests ever called it: production
    // reads `self.locality_min_pool_size` directly at the one call
    // site in `select_target_for_request`. The pub-item ratchet is
    // blind to a same-file test consumer, so it shipped as public API
    // surface promising a capability no caller had. The two tests read
    // the field, which they can do from a child module.
    //
    // `has_zoned_targets()` and `local_zone()` above stay: both have
    // production callers in `sbproxy-core`'s boot path.

    /// Returns `true` when the breaker for the target at `idx` would
    /// allow a new request right now (Closed or HalfOpen). Returns
    /// `true` when no breaker is configured for this LB.
    pub fn target_breaker_allows(&self, idx: usize) -> bool {
        match &self.circuit_breakers {
            None => true,
            Some(brs) => brs.get(idx).map(|b| b.allow_request()).unwrap_or(true),
        }
    }

    /// Tell the breaker (if configured) that the target at `idx`
    /// just succeeded. Counter-pressure: in `HalfOpen`, this moves
    /// the breaker toward Closed; in Closed, this resets the failure
    /// counter.
    pub fn record_breaker_success(&self, idx: usize) {
        if let Some(brs) = &self.circuit_breakers {
            if let Some(b) = brs.get(idx) {
                if let Some((from, to)) = b.record_success() {
                    if let Some(target) = self.targets.get(idx) {
                        sbproxy_observe::metrics::record_circuit_breaker_transition(
                            &target.url,
                            from.as_str(),
                            to.as_str(),
                            "success_threshold_met",
                            "",
                        );
                    }
                }
            }
        }
    }

    /// Tell the breaker (if configured) that the target at `idx`
    /// just failed (5xx, connect error, timeout). Counter-pressure:
    /// in Closed, this counts toward the failure threshold; in
    /// HalfOpen, this re-opens the breaker immediately.
    pub fn record_breaker_failure(&self, idx: usize) {
        if let Some(brs) = &self.circuit_breakers {
            if let Some(b) = brs.get(idx) {
                if let Some((from, to)) = b.record_failure() {
                    if let Some(target) = self.targets.get(idx) {
                        let reason = match from {
                            sbproxy_platform::CircuitState::HalfOpen => "probe_failed",
                            _ => "failure_threshold_exceeded",
                        };
                        sbproxy_observe::metrics::record_circuit_breaker_transition(
                            &target.url,
                            from.as_str(),
                            to.as_str(),
                            reason,
                            "",
                        );
                    }
                }
            }
        }
    }

    /// Spawn the background health-check probe tasks for each target
    /// that has a `health_check` block configured. Must be called from
    /// inside a Tokio runtime. The proxy invokes this once per
    /// LoadBalancer action after the pipeline finishes compiling.
    ///
    /// Each target gets its own loop that fires every
    /// `interval_secs`, updates the consecutive-success / consecutive-
    /// failure counter, flips the per-target health AtomicU8 once a
    /// threshold is met, and feeds the same signal into the shared
    /// outlier detector when one is configured.
    pub fn spawn_health_probes(self: &std::sync::Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        self.spawn_health_probes_on(&handle);
    }

    /// Spawn health probes on a caller-owned runtime.
    ///
    /// Each loop holds only a weak reference while it sleeps. Replacing a
    /// pipeline generation therefore lets its probes stop as soon as no
    /// request still pins that generation.
    pub fn spawn_health_probes_on(self: &std::sync::Arc<Self>, handle: &tokio::runtime::Handle) {
        for (idx, target) in self.targets.iter().enumerate() {
            let cfg = match &target.health_check {
                Some(c) => c.clone(),
                None => continue,
            };
            let probe_url = match build_health_probe_url(&target.url, &cfg.path) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(
                        target_url = %target.url,
                        error = %e,
                        "health-check disabled for target: invalid url"
                    );
                    continue;
                }
            };
            let lb = std::sync::Arc::downgrade(self);
            handle.spawn(async move {
                run_health_probe_loop(lb, idx, probe_url, cfg).await;
            });
        }
    }

    /// Read the per-target health flag.
    pub fn target_is_healthy(&self, idx: usize) -> bool {
        self.state
            .health
            .get(idx)
            .map(|h| h.load(Ordering::Relaxed) != 2) // 2 = unhealthy
            .unwrap_or(true)
    }

    /// Set a target's health flag (used by the probe loop).
    pub(crate) fn set_target_health(&self, idx: usize, healthy: bool) {
        if let Some(slot) = self.state.health.get(idx) {
            slot.store(if healthy { 1 } else { 2 }, Ordering::Relaxed);
        }
    }

    /// Stable identifier for a target used by the outlier detector.
    /// We derive it from the URL plus index so two targets with the
    /// same URL stay distinguishable.
    pub fn target_id(&self, idx: usize) -> String {
        match self.targets.get(idx) {
            Some(t) => format!("{}#{idx}", t.url),
            None => format!("idx#{idx}"),
        }
    }

    /// Record a successful response from the target at `idx` so the
    /// outlier detector can keep its sliding-window stats up to date.
    /// No-op when no detector is configured.
    pub fn record_target_success(&self, idx: usize) {
        if let Some(det) = &self.outlier_detector {
            det.record_success(&self.target_id(idx));
        }
    }

    /// Record a failed response from the target at `idx` (5xx, network
    /// error, or timeout). No-op when no detector is configured.
    pub fn record_target_failure(&self, idx: usize) {
        if let Some(det) = &self.outlier_detector {
            det.record_failure(&self.target_id(idx));
            // Cheap to call repeatedly. It just walks the stats map
            // to apply pending ejections so the next select_target
            // sees them immediately.
            let _ = det.check_ejections();
        }
    }

    /// Select a target through the compatibility request projection.
    pub fn select_target(
        &self,
        client_ip: Option<&str>,
        uri: &str,
        headers: &http::HeaderMap,
    ) -> Result<(String, u16, bool, usize)> {
        let hostname = headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let mut request = RoutingRequest::new("GET", uri, hostname);
        request.headers = headers.clone();
        request.client_ip = client_ip.map(str::to_string);
        let selection = self.select_target_for_request(request)?;
        Ok((
            selection.host,
            selection.port,
            selection.tls,
            selection.target_index,
        ))
    }

    /// Select a target through the configured strategy, then the algorithm.
    ///
    /// Deployment, backup, health, breaker, outlier, zone-locality, and
    /// priority filters run before the strategy projection, in that
    /// order. A strategy can therefore choose only from the same final
    /// eligible slice used by the fallback algorithm.
    pub fn select_target_for_request(
        &self,
        mut request: RoutingRequest,
    ) -> Result<TargetSelection> {
        enrich_routing_request(&mut request);
        let client_ip = request.client_ip.as_deref();
        // Registry strategies receive the full path plus query above. Legacy
        // URI hashing used Pingora's path-only projection, so keep a separate
        // fallback key when no strategy selects a target.
        let fallback_uri = request
            .path
            .split_once('?')
            .map_or(request.path.as_str(), |(path, _)| path);
        let headers = &request.headers;

        // --- Outlier / active-health / circuit-breaker filter ---
        // Skip a target if any of:
        //   * the outlier detector has currently ejected it,
        //   * the active health check has marked it unhealthy, or
        //   * its circuit breaker is in the Open state.
        // Each check falls through (target is eligible) when the
        // corresponding feature is not configured.
        let is_ejected = |idx: usize| -> bool {
            let outlier = self
                .outlier_detector
                .as_ref()
                .map(|d| d.is_ejected(&self.target_id(idx)))
                .unwrap_or(false);
            let unhealthy = !self.target_is_healthy(idx);
            let breaker_open = !self.target_breaker_allows(idx);
            outlier || unhealthy || breaker_open
        };

        // --- Deployment mode filtering ---
        let active_targets: Vec<(usize, &Target)> = match &self.deployment_mode {
            DeploymentMode::Normal => self
                .targets
                .iter()
                .enumerate()
                .filter(|(_, t)| !t.backup)
                .collect(),
            DeploymentMode::BlueGreen { active } => {
                // Route 100% to the active group (targets whose group matches).
                let group_targets: Vec<(usize, &Target)> = self
                    .targets
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| !t.backup && t.group.as_deref() == Some(active.as_str()))
                    .collect();
                if group_targets.is_empty() {
                    // Fallback: any non-backup target if the group is empty.
                    self.targets
                        .iter()
                        .enumerate()
                        .filter(|(_, t)| !t.backup)
                        .collect()
                } else {
                    group_targets
                }
            }
            DeploymentMode::Canary { weight } => {
                // Use counter to determine canary vs primary split.
                let counter = self
                    .state
                    .round_robin_counter
                    .fetch_add(1, Ordering::Relaxed);
                // Every `weight`% of requests go to canary targets.
                let pct = counter % 100;
                let use_canary = pct < *weight as u64;
                let candidate_group = if use_canary { "canary" } else { "" };
                if use_canary {
                    let canary: Vec<(usize, &Target)> = self
                        .targets
                        .iter()
                        .enumerate()
                        .filter(|(_, t)| !t.backup && t.group.as_deref() == Some("canary"))
                        .collect();
                    if canary.is_empty() {
                        // No canary targets; fall back to non-backup.
                        self.targets
                            .iter()
                            .enumerate()
                            .filter(|(_, t)| !t.backup)
                            .collect()
                    } else {
                        canary
                    }
                } else {
                    let _ = candidate_group;
                    let primary: Vec<(usize, &Target)> = self
                        .targets
                        .iter()
                        .enumerate()
                        .filter(|(_, t)| !t.backup && t.group.as_deref() != Some("canary"))
                        .collect();
                    if primary.is_empty() {
                        self.targets
                            .iter()
                            .enumerate()
                            .filter(|(_, t)| !t.backup)
                            .collect()
                    } else {
                        primary
                    }
                }
            }
        };

        // The zone-locality guard below counts the deployment-filtered
        // pool before health filtering, matching Envoy's
        // `min_cluster_size` (cluster hosts, not the healthy subset).
        // Counting after would deactivate locality exactly when a
        // health flap shrinks the pool, which is when the spill
        // verdict matters most.
        let deployment_pool_size = active_targets.len();

        // Filter out targets the outlier detector has ejected. Fall
        // back to the unfiltered list when every active target is
        // ejected (better to send traffic to a flaky upstream than to
        // 502 the client).
        let (active_targets, has_strictly_eligible_targets): (Vec<(usize, &Target)>, bool) = {
            let kept: Vec<(usize, &Target)> = active_targets
                .iter()
                .filter(|(idx, _)| !is_ejected(*idx))
                .cloned()
                .collect();
            if kept.is_empty() {
                (active_targets, false)
            } else {
                (kept, true)
            }
        };

        anyhow::ensure!(!active_targets.is_empty(), "no active targets available");

        // --- Zone-locality filter (WOR-2328) ---
        // Fourth narrowing stage: prefer targets in the proxy's own
        // zone, spill across zones when none is left. Running after
        // the health filters makes "healthy same-zone" literal and
        // cross-zone failover per-request rather than a mode switch,
        // and it stands down entirely in the all-ejected last-resort
        // case above, the same reason Envoy disables zone-aware
        // routing in panic mode.
        let (active_targets, zone_locality) = locality_filter(
            self.local_zone(),
            self.zoned_targets,
            self.locality_min_pool_size,
            deployment_pool_size,
            has_strictly_eligible_targets,
            active_targets,
        );

        // --- Priority-based pre-filtering ---
        // If an X-Priority header is present, sort targets by their priority field
        // and pick only those whose priority <= the requested priority.
        let request_priority: Option<u8> = headers
            .get("x-priority")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        // Sort by target priority (lower = higher priority).
        let mut sorted_targets = active_targets.clone();
        sorted_targets.sort_by_key(|(_, t)| t.priority);

        // When X-Priority header is provided, prefer targets with priority <= header value.
        let priority_filtered: Vec<(usize, &Target)> = if let Some(req_prio) = request_priority {
            let filtered: Vec<(usize, &Target)> = sorted_targets
                .iter()
                .filter(|(_, t)| t.priority <= req_prio)
                .cloned()
                .collect();
            if filtered.is_empty() {
                sorted_targets.clone()
            } else {
                filtered
            }
        } else {
            sorted_targets
        };

        let active_targets = priority_filtered;

        let strategy_selection = self
            .strategy
            .as_ref()
            .filter(|_| has_strictly_eligible_targets)
            .and_then(|strategy| {
                let projection: Vec<TargetState> = active_targets
                    .iter()
                    .map(|(index, target)| TargetState {
                        index: *index,
                        url: target.url.clone(),
                        healthy: true,
                        active_connections: self
                            .state
                            .connections
                            .get(*index)
                            .map(|count| u64::from(count.load(Ordering::Relaxed)))
                            .unwrap_or_default(),
                        weight: target.weight,
                        metadata: self
                            .target_metadata_snapshot(*index)
                            .expect("metadata state is parallel to configured targets"),
                    })
                    .collect();
                strategy
                    .select(&request, &projection)
                    .and_then(|slice_index| active_targets.get(slice_index))
                    .map(|(index, _)| {
                        (
                            *index,
                            self.strategy_name
                                .expect("compiled strategy must retain its registry name")
                                .to_string(),
                        )
                    })
            });

        let (idx, selection_method) = match strategy_selection {
            Some(selection) => selection,
            None => (
                self.select_with_algorithm(&active_targets, client_ip, fallback_uri, headers),
                algorithm_name(&self.algorithm).to_string(),
            ),
        };

        let target = &self.targets[idx];
        let parsed = url::Url::parse(&target.url)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("missing host in target URL"))?
            .to_string();
        let tls = parsed.scheme() == "https";
        let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
        Ok(TargetSelection {
            host,
            port,
            tls,
            target_index: idx,
            selection_method,
            zone_locality,
        })
    }

    /// Report one completed target attempt to the configured strategy.
    pub fn record_strategy_outcome(&self, target_index: usize, outcome: RoutingOutcome) {
        if let (Some(strategy), Some(target)) =
            (self.strategy.as_ref(), self.targets.get(target_index))
        {
            strategy.record_outcome(&target.url, outcome);
        }
    }

    /// Record that a connection to a target was established.
    pub fn record_connect(&self, target_idx: usize) {
        if target_idx < self.state.connections.len() {
            self.state.connections[target_idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record that a connection to a target was closed.
    pub fn record_disconnect(&self, target_idx: usize) {
        if target_idx < self.state.connections.len() {
            self.state.connections[target_idx].fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get the current connection count for a target.
    pub fn connection_count(&self, target_idx: usize) -> u32 {
        if target_idx < self.state.connections.len() {
            self.state.connections[target_idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    // --- Private helpers ---

    fn select_with_algorithm(
        &self,
        active_targets: &[(usize, &Target)],
        client_ip: Option<&str>,
        uri: &str,
        headers: &http::HeaderMap,
    ) -> usize {
        match &self.algorithm {
            Algorithm::RoundRobin => {
                let counter = self
                    .state
                    .round_robin_counter
                    .fetch_add(1, Ordering::Relaxed);
                active_targets[counter as usize % active_targets.len()].0
            }
            Algorithm::WeightedRandom => self.select_weighted_random(active_targets),
            Algorithm::LeastConnections => self.select_least_connections(active_targets),
            Algorithm::IpHash => {
                let ip = client_ip.unwrap_or("0.0.0.0");
                let hash = fnv1a_hash(ip.as_bytes());
                active_targets[hash % active_targets.len()].0
            }
            Algorithm::UriHash => {
                let hash = fnv1a_hash(uri.as_bytes());
                active_targets[hash % active_targets.len()].0
            }
            Algorithm::HeaderHash { header } => {
                let val = headers
                    .get(header.as_str())
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let hash = fnv1a_hash(val.as_bytes());
                active_targets[hash % active_targets.len()].0
            }
            Algorithm::CookieHash { cookie } => {
                let cookie_val = extract_cookie(headers, cookie);
                let hash = fnv1a_hash(cookie_val.as_bytes());
                active_targets[hash % active_targets.len()].0
            }
            Algorithm::RingHash { key } => {
                let cookie_val;
                let key_material: &[u8] = match key {
                    RingHashKey::Ip => client_ip.unwrap_or("0.0.0.0").as_bytes(),
                    RingHashKey::Uri => uri.as_bytes(),
                    RingHashKey::Header(header) => headers
                        .get(header.as_str())
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .as_bytes(),
                    RingHashKey::Cookie(cookie) => {
                        cookie_val = extract_cookie(headers, cookie);
                        cookie_val.as_bytes()
                    }
                };
                let mut eligible = vec![false; self.targets.len()];
                for (index, _) in active_targets {
                    eligible[*index] = true;
                }
                self.ring
                    .as_ref()
                    .and_then(|ring| ring.select(key_material, &eligible))
                    // Unreachable in practice: the ring exists whenever the
                    // algorithm is ring_hash, every configured target keeps
                    // at least one point on it, and `active_targets` is
                    // never empty here. Modulus hashing keeps a violated
                    // assumption from becoming a panic.
                    .unwrap_or_else(|| {
                        active_targets[fnv1a_hash(key_material) % active_targets.len()].0
                    })
            }
        }
    }

    fn select_weighted_random(&self, active_targets: &[(usize, &Target)]) -> usize {
        let total_weight: u32 = active_targets.iter().map(|(_, t)| t.weight).sum();
        // LCG-based pseudo-random from the counter (deterministic, no external rng needed).
        let counter = self
            .state
            .round_robin_counter
            .fetch_add(1, Ordering::Relaxed);
        let mut remaining = (counter
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407))
            % total_weight as u64;
        let mut selected = active_targets[0].0;
        for &(idx, target) in active_targets {
            if remaining < target.weight as u64 {
                selected = idx;
                break;
            }
            remaining -= target.weight as u64;
        }
        selected
    }

    fn select_least_connections(&self, active_targets: &[(usize, &Target)]) -> usize {
        active_targets
            .iter()
            .min_by_key(|&&(idx, _)| self.state.connections[idx].load(Ordering::Relaxed))
            .map(|&(idx, _)| idx)
            .unwrap_or(0)
    }
}

// --- Active health check probe loop ---

/// Compose a probe URL by joining a target URL and a probe path.
///
/// Handles IPv6 hosts correctly: the target URL must already wrap
/// IPv6 hosts in `[…]` per RFC 3986. We pass the URL through
/// `url::Url::parse` and rewrite only the path/query, so bracketing
/// is preserved.
fn build_health_probe_url(target_url: &str, probe_path: &str) -> anyhow::Result<String> {
    let mut parsed = url::Url::parse(target_url)?;
    if !probe_path.starts_with('/') {
        anyhow::bail!("health probe path must start with /");
    }
    parsed.set_path(probe_path);
    // Drop any query that might be in the target URL. We want
    // exactly `<scheme>://<host>[:port]<probe_path>`.
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

/// Per-target probe loop: GETs the probe URL on a fixed interval and
/// flips the target's health flag once the consecutive-success or
/// consecutive-failure threshold is met. Also feeds the signal into
/// the LB's outlier detector when one is configured (so a single
/// shared store records both passive and active failures).
async fn run_health_probe_loop(
    lb: std::sync::Weak<LoadBalancerAction>,
    target_idx: usize,
    probe_url: String,
    cfg: HealthCheckConfig,
) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
        .user_agent(format!("sbproxy-healthcheck/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build health-check client; probes disabled");
            return;
        }
    };
    let mut consecutive_ok: u32 = 0;
    let mut consecutive_fail: u32 = 0;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(cfg.interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let Some(lb) = lb.upgrade() else {
            return;
        };
        let ok = match client.get(&probe_url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        };
        if ok {
            consecutive_fail = 0;
            consecutive_ok = consecutive_ok.saturating_add(1);
            if consecutive_ok >= cfg.healthy_threshold {
                lb.set_target_health(target_idx, true);
                if let Some(d) = &lb.outlier_detector {
                    d.record_success(&lb.target_id(target_idx));
                }
            }
        } else {
            consecutive_ok = 0;
            consecutive_fail = consecutive_fail.saturating_add(1);
            if consecutive_fail >= cfg.unhealthy_threshold {
                lb.set_target_health(target_idx, false);
                if let Some(d) = &lb.outlier_detector {
                    d.record_failure(&lb.target_id(target_idx));
                    let _ = d.check_ejections();
                }
            }
        }
    }
}

// History of the locality names in this module: WOR-2246 deleted an
// earlier `LocalityConfig` + `locality_filter` pair that was reached
// only by its own tests and made `targets[].zone` look like a routing
// input, and WOR-2498 then refused the label itself at config compile
// rather than letting it sit inert. WOR-2328 brought both names back
// wired for real: `LocalityConfig` deserializes from the `locality:`
// key and `locality_filter` (below) runs on every
// `select_target_for_request` call between the health filters and the
// priority filter.

/// Narrow `candidates` to the proxy's own zone (WOR-2328).
///
/// Returns the (possibly narrowed) candidate set plus the verdict the
/// selection reports outward. The stage stands down, returning the
/// set untouched and no verdict, when any precondition is missing:
/// no bound proxy zone, an unlabeled pool, a deployment-filtered pool
/// smaller than `locality.min_pool_size` (Envoy's `min_cluster_size`
/// guard; `pool_size` is counted before health filtering, as Envoy
/// counts cluster hosts, so a health flap cannot toggle the stage), or
/// the all-ejected last-resort case where the health stage already
/// fell back to the full pool (`strictly_eligible == false`, Envoy's
/// panic mode). With the preconditions met it keeps the same-zone
/// candidates when at least one exists ([`ZoneLocality::Local`]) and
/// otherwise spills across every candidate ([`ZoneLocality::Spilled`]),
/// which is what makes cross-zone failover per-request instead of a
/// special case. An unlabeled target in a labeled pool is a different
/// locality, matching Envoy's endpoint-locality model: only an exact
/// zone match is local.
///
/// A free function rather than a method so the build-time
/// config-reader guard sees the `Target::zone` read (the guard proves
/// a key through field access and cannot see into inherent impls; see
/// `sbproxy-capability`'s `config_scan`). It does not cover
/// `locality.min_pool_size`: that arrives here as a plain `usize`
/// parameter, so `pool_size < min_pool_size` is an identifier
/// comparison the scanner never sees as a field read. The key is
/// covered by the `stable("origins.*.action.locality.min_pool_size",
/// ...)` override in `sbproxy-config`'s `key_registry`, which is
/// load-bearing and must not be deleted on the strength of this
/// signature.
fn locality_filter<'t>(
    local_zone: Option<&str>,
    pool_is_zoned: bool,
    min_pool_size: usize,
    pool_size: usize,
    strictly_eligible: bool,
    candidates: Vec<(usize, &'t Target)>,
) -> (Vec<(usize, &'t Target)>, Option<ZoneLocality>) {
    let Some(local_zone) = local_zone else {
        return (candidates, None);
    };
    if !pool_is_zoned || !strictly_eligible || pool_size < min_pool_size {
        return (candidates, None);
    }
    let same_zone: Vec<(usize, &'t Target)> = candidates
        .iter()
        .filter(|(_, target)| target.zone.as_deref() == Some(local_zone))
        .cloned()
        .collect();
    if same_zone.is_empty() {
        (candidates, Some(ZoneLocality::Spilled))
    } else {
        (same_zone, Some(ZoneLocality::Local))
    }
}

// --- Consistent-hash ring (ring_hash) ---

// WOR-2311: a `ConsistentHash` scaffold stood here for the same idea,
// reached only by its own tests and positioned over `DefaultHasher`,
// which is randomized per process and would have made replicas disagree
// on the ring. Replaced wholesale by `HashRing`, which the `ring_hash`
// algorithm actually selects through.

/// Ring positions apportioned across the configured targets.
///
/// The ring holds `targets.len() * RING_VNODES_PER_TARGET` virtual
/// nodes in total, split across targets in proportion to their weights
/// (the classic ketama sizing; Envoy's default minimum ring of 1024 is
/// comparable for small pools). More vnodes flatten each target's share
/// of the keyspace; fewer keep the sorted ring small and the binary
/// search cheap. At 160 the per-target imbalance stays within a few
/// percent while a 10-target pool still fits in a 1,600-entry ring.
const RING_VNODES_PER_TARGET: usize = 160;

/// A ketama-style consistent-hash ring over the configured targets.
///
/// Built once at config compile time and never rebuilt afterwards:
/// eligibility (health, breakers, outliers, deployment filters) is
/// applied at lookup time by walking clockwise past ineligible targets,
/// so a target dropping out and returning moves only the keys that
/// target owned. Every hash input runs through [`ring_point`], which
/// has a fixed offset basis and no per-process seed, so every replica
/// that shares a config file agrees on the ring.
struct HashRing {
    /// Sorted (ring position, target index) pairs.
    entries: Vec<(u64, usize)>,
}

impl HashRing {
    /// Build the ring over every configured target, weighted.
    fn build(targets: &[Target]) -> Self {
        let total_weight: u64 = targets.iter().map(|t| u64::from(t.weight.max(1))).sum();
        let ring_size = (targets.len() * RING_VNODES_PER_TARGET) as u64;
        let mut entries = Vec::with_capacity(ring_size as usize);
        for (index, target) in targets.iter().enumerate() {
            let weight = u64::from(target.weight.max(1));
            // Weight share of the fixed ring size, never rounded to
            // zero: a configured target must keep at least one point on
            // the ring or it could never be selected.
            let vnodes = (ring_size * weight / total_weight).max(1);
            for vnode in 0..vnodes {
                // Position vnodes by URL rather than by index, so
                // reordering the target list does not move the ring.
                // Targets sharing one URL also share positions; the
                // tie-break below hands those points to the lower index.
                let point = ring_point(format!("{}#{vnode}", target.url).as_bytes());
                entries.push((point, index));
            }
        }
        // Position ties sort by target index, keeping the ring a
        // deterministic function of the config alone.
        entries.sort_unstable();
        Self { entries }
    }

    /// Map `key` to the first eligible target at or after its ring
    /// position, wrapping around. Returns `None` only when no entry on
    /// the ring belongs to an eligible target.
    fn select(&self, key: &[u8], eligible: &[bool]) -> Option<usize> {
        if self.entries.is_empty() {
            return None;
        }
        let position = ring_point(key);
        let start = self.entries.partition_point(|&(point, _)| point < position);
        (0..self.entries.len()).find_map(|offset| {
            let (_, index) = self.entries[(start + offset) % self.entries.len()];
            eligible
                .get(index)
                .copied()
                .unwrap_or(false)
                .then_some(index)
        })
    }
}

// --- Utility functions ---

/// FNV-1a hash for consistent hashing of strings.
fn fnv1a_hash(data: &[u8]) -> usize {
    fnv1a_hash_u64(data) as usize
}

/// 64-bit FNV-1a with the standard offset basis and prime.
///
/// Deterministic across processes and platforms by construction, which
/// [`HashRing`] depends on: the ring must be the same in every replica
/// so all of them send a given key to the same target. That rules out
/// `DefaultHasher`, whose keys are explicitly randomized per process.
fn fnv1a_hash_u64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Ring position hash: FNV-1a finished with the splitmix64 mixer.
///
/// FNV-1a alone is not fit for ring positions: its avalanche is weak,
/// so the structured, near-identical inputs the ring hashes (vnode
/// labels like `url#0`, `url#1`, and sequential client IPs) cluster
/// into arcs, and one target can end up owning several times its fair
/// share of the keyspace (classic ketama uses MD5 for exactly this
/// reason). The splitmix64 finalizer disperses those clusters while
/// staying seedless, so replicas sharing a config still agree on the
/// ring. The modulus algorithms keep raw [`fnv1a_hash`]: their mapping
/// is deployed behavior and `hash % len` is far less sensitive to
/// high-bit clustering.
fn ring_point(data: &[u8]) -> u64 {
    let mut x = fnv1a_hash_u64(data);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

fn algorithm_name(algorithm: &Algorithm) -> &'static str {
    match algorithm {
        Algorithm::RoundRobin => "round_robin",
        Algorithm::WeightedRandom => "weighted_random",
        Algorithm::LeastConnections => "least_connections",
        Algorithm::IpHash => "ip_hash",
        Algorithm::UriHash => "uri_hash",
        Algorithm::HeaderHash { .. } => "header_hash",
        Algorithm::CookieHash { .. } => "cookie_hash",
        Algorithm::RingHash { .. } => "ring_hash",
    }
}

const MAX_ROUTING_HINT_BYTES: usize = 256;

fn enrich_routing_request(request: &mut RoutingRequest) {
    if request.model.is_none() {
        request.model = bounded_header(&request.headers, "x-model")
            .or_else(|| bounded_query_value(&request.path, "model"));
    }
    if request.adapter.is_none() {
        request.adapter = bounded_header(&request.headers, "x-lora-adapter")
            .or_else(|| bounded_query_value(&request.path, "adapter"));
    }
}

fn bounded_header(headers: &http::HeaderMap, name: &str) -> Option<String> {
    bounded_routing_hint(headers.get(name)?.to_str().ok()?)
}

fn bounded_query_value(path: &str, name: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == name)
        .and_then(|(_, value)| bounded_routing_hint(&value))
}

fn bounded_routing_hint(value: &str) -> Option<String> {
    (!value.is_empty() && value.len() <= MAX_ROUTING_HINT_BYTES).then(|| value.to_string())
}

/// Extract a named cookie value from the Cookie header.
fn extract_cookie(headers: &http::HeaderMap, cookie_name: &str) -> String {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let (name, val) = c.trim().split_once('=')?;

                if name == cookie_name {
                    Some(val.to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_default()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::routing::RoutingStrategyRegistration;

    struct StrictConfigStrategy;

    impl RoutingStrategy for StrictConfigStrategy {
        fn select(&self, _request: &RoutingRequest, targets: &[TargetState]) -> Option<usize> {
            (!targets.is_empty()).then_some(0)
        }

        fn name(&self) -> &str {
            "strict-config-test"
        }
    }

    fn build_strict_config_strategy(
        value: &serde_json::Value,
    ) -> anyhow::Result<Arc<dyn RoutingStrategy>> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StrictConfig {
            enabled: bool,
        }

        let config: StrictConfig = serde_json::from_value(value.clone())?;
        anyhow::ensure!(config.enabled, "strict test strategy must be enabled");
        Ok(Arc::new(StrictConfigStrategy))
    }

    inventory::submit! {
        RoutingStrategyRegistration {
            name: "strict-config-test",
            build: build_strict_config_strategy,
        }
    }

    struct DeferringStrategy;

    impl RoutingStrategy for DeferringStrategy {
        fn select(&self, _request: &RoutingRequest, _targets: &[TargetState]) -> Option<usize> {
            None
        }

        fn name(&self) -> &str {
            "deferring-test"
        }
    }

    struct PathCapturingDeferringStrategy {
        paths: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl RoutingStrategy for PathCapturingDeferringStrategy {
        fn select(&self, request: &RoutingRequest, _targets: &[TargetState]) -> Option<usize> {
            self.paths
                .lock()
                .expect("path capture lock")
                .push(request.path.clone());
            None
        }

        fn name(&self) -> &str {
            "path-capturing-deferring-test"
        }
    }

    struct OutOfRangeStrategy;

    impl RoutingStrategy for OutOfRangeStrategy {
        fn select(&self, _request: &RoutingRequest, targets: &[TargetState]) -> Option<usize> {
            Some(targets.len())
        }

        fn name(&self) -> &str {
            "out-of-range-test"
        }
    }

    struct ProjectionGuardStrategy {
        forbidden_url: &'static str,
        saw_forbidden: Arc<std::sync::atomic::AtomicBool>,
    }

    impl RoutingStrategy for ProjectionGuardStrategy {
        fn select(&self, _request: &RoutingRequest, targets: &[TargetState]) -> Option<usize> {
            if targets
                .iter()
                .any(|target| target.url == self.forbidden_url)
            {
                self.saw_forbidden.store(true, Ordering::Relaxed);
            }
            Some(0)
        }

        fn name(&self) -> &str {
            "projection-guard-test"
        }
    }

    struct InvocationTrackingStrategy {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl RoutingStrategy for InvocationTrackingStrategy {
        fn select(&self, _request: &RoutingRequest, _targets: &[TargetState]) -> Option<usize> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Some(0)
        }

        fn name(&self) -> &str {
            "invocation-tracking-test"
        }
    }

    fn make_lb(json: serde_json::Value) -> LoadBalancerAction {
        LoadBalancerAction::from_config(json).unwrap()
    }

    fn empty_headers() -> http::HeaderMap {
        http::HeaderMap::new()
    }

    // --- Circuit breaker integration ---

    #[test]
    fn breaker_open_target_excluded_from_selection() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"}
            ],
            "circuit_breaker": {
                "failure_threshold": 2,
                "success_threshold": 1,
                "open_duration_secs": 60
            }
        }));
        // Open the breaker on target 0 by recording 2 consecutive failures.
        lb.record_breaker_failure(0);
        lb.record_breaker_failure(0);

        let headers = empty_headers();
        for _ in 0..50 {
            let (_, _, _, idx) = lb.select_target(None, "/", &headers).unwrap();
            assert_eq!(
                idx, 1,
                "target 0's breaker is Open; selection must avoid it"
            );
        }
    }

    #[test]
    fn breaker_falls_back_when_all_targets_open() {
        // When every target's breaker is Open, the LB falls back to
        // the unfiltered list rather than 502'ing the client (better
        // to send to a flaky peer than to fail closed).
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"}
            ],
            "circuit_breaker": {
                "failure_threshold": 1,
                "success_threshold": 1,
                "open_duration_secs": 60
            }
        }));
        lb.record_breaker_failure(0);
        lb.record_breaker_failure(1);

        let headers = empty_headers();
        let result = lb.select_target(None, "/", &headers);
        assert!(result.is_ok(), "all-Open should fall back, not error");
    }

    #[test]
    fn no_breaker_means_target_is_always_eligible() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}]
        }));
        // record_breaker_failure with no breaker configured is a no-op.
        lb.record_breaker_failure(0);
        assert!(lb.target_breaker_allows(0));
    }

    // --- IPv6 health-probe URL building ---

    #[test]
    fn health_probe_url_ipv4() {
        let url = build_health_probe_url("http://10.0.0.1:8080", "/healthz").unwrap();
        assert_eq!(url, "http://10.0.0.1:8080/healthz");
    }

    #[test]
    fn health_probe_url_ipv6_preserves_brackets() {
        let url = build_health_probe_url("http://[2001:db8::1]:8080", "/healthz").unwrap();
        // The url crate normalizes the host but must keep brackets so
        // reqwest can parse it.
        assert!(
            url.starts_with("http://[2001:db8::1]:8080"),
            "ipv6 host must remain bracketed: got {url}"
        );
        assert!(url.ends_with("/healthz"));
    }

    #[test]
    fn health_probe_url_ipv6_loopback() {
        let url = build_health_probe_url("https://[::1]:9443", "/probe").unwrap();
        assert!(url.contains("[::1]"));
        assert!(url.ends_with("/probe"));
    }

    #[test]
    fn health_probe_url_overwrites_existing_path_and_query() {
        let url =
            build_health_probe_url("http://api.example.com/api/v1?token=x", "/healthz").unwrap();
        assert_eq!(url, "http://api.example.com/healthz");
    }

    #[test]
    fn health_probe_url_rejects_relative_path() {
        assert!(build_health_probe_url("http://localhost", "healthz").is_err());
    }

    // --- from_config tests ---

    #[test]
    fn from_config_round_robin_default() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"}
            ]
        }));
        assert_eq!(lb.algorithm, Algorithm::RoundRobin);
        assert_eq!(lb.targets.len(), 2);
    }

    #[test]
    fn from_config_weighted_random() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080", "weight": 3},
                {"url": "http://b:8080", "weight": 1}
            ],
            "algorithm": "weighted_random"
        }));
        assert_eq!(lb.algorithm, Algorithm::WeightedRandom);
        assert_eq!(lb.targets[0].weight, 3);
        assert_eq!(lb.targets[1].weight, 1);
    }

    #[test]
    fn from_config_least_connections() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}],
            "algorithm": "least_connections"
        }));
        assert_eq!(lb.algorithm, Algorithm::LeastConnections);
    }

    #[test]
    fn from_config_ip_hash() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}],
            "algorithm": "ip_hash"
        }));
        assert_eq!(lb.algorithm, Algorithm::IpHash);
    }

    #[test]
    fn from_config_uri_hash() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}],
            "algorithm": "uri_hash"
        }));
        assert_eq!(lb.algorithm, Algorithm::UriHash);
    }

    #[test]
    fn from_config_header_hash() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}],
            "algorithm": {"header_hash": {"header": "X-Tenant"}}
        }));
        assert_eq!(
            lb.algorithm,
            Algorithm::HeaderHash {
                header: "X-Tenant".to_string()
            }
        );
    }

    #[test]
    fn from_config_cookie_hash() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}],
            "algorithm": {"cookie_hash": {"cookie": "session_id"}}
        }));
        assert_eq!(
            lb.algorithm,
            Algorithm::CookieHash {
                cookie: "session_id".to_string()
            }
        );
    }

    #[test]
    fn from_config_ring_hash_defaults_to_ip_key() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}],
            "algorithm": {"ring_hash": {}}
        }));
        assert_eq!(
            lb.algorithm,
            Algorithm::RingHash {
                key: RingHashKey::Ip
            }
        );
    }

    #[test]
    fn from_config_ring_hash_cookie_key() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}],
            "algorithm": {"ring_hash": {"key": {"cookie": "session_id"}}}
        }));
        assert_eq!(
            lb.algorithm,
            Algorithm::RingHash {
                key: RingHashKey::Cookie("session_id".to_string())
            }
        );
    }

    // --- sticky: is removed and refused (WOR-2311) ---
    //
    // WOR-2246 pinned `sticky:` as parsed-and-inert with a boot warning.
    // The block is gone now, and because unknown keys under `action:`
    // are not rejected, silence is the failure mode a plain field
    // deletion would produce. This pins the refusal instead.

    #[test]
    fn sticky_block_is_refused_at_config_compile_with_a_migration_path() {
        let error = LoadBalancerAction::from_config(serde_json::json!({
            "targets": [{"url": "http://a:8080"}],
            "sticky": {"cookie_name": "_sb_backend", "ttl": 3600}
        }))
        .expect_err("an authored sticky block must fail config compilation, not sit inert");

        let message = error.to_string();
        assert!(
            message.contains("sticky"),
            "the error must name the removed key: '{message}'"
        );
        assert!(
            message.contains("ring_hash"),
            "the error must name the replacement algorithm: '{message}'"
        );
        assert!(
            message.contains("cookie"),
            "the error must point cookie-affinity users at a keyed ring: '{message}'"
        );
    }

    #[test]
    fn omitting_sticky_compiles_cleanly() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}]
        }));
        assert_eq!(lb.targets.len(), 1);
    }

    // --- Zone-locality stage (WOR-2328) ---
    //
    // WOR-2246 pinned `zone` as a display label, and WOR-2498 refused
    // an authored `zone:` at config compile because the label steered
    // nothing. WOR-2328 re-introduced the field together with the
    // enforcement: selection prefers same-zone targets and spills
    // across zones when no same-zone target is healthy. These tests
    // pin the enforcement; `zone_on_a_target_compiles_and_routes`
    // replaces the old refusal test
    // (`zone_on_a_target_is_refused_at_config_compile`) with the
    // positive claim.

    /// Select through the request projection so the assertion can see
    /// the per-selection `zone_locality` verdict.
    fn select_from(lb: &LoadBalancerAction, client_ip: &str) -> TargetSelection {
        let mut request = RoutingRequest::new("GET", "/", "lb.test");
        request.client_ip = Some(client_ip.to_string());
        lb.select_target_for_request(request)
            .expect("an eligible pool always selects")
    }

    fn zoned_two_target_lb() -> LoadBalancerAction {
        make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080", "zone": "zone-a"},
                {"url": "http://b:8080", "zone": "zone-b"}
            ],
            "algorithm": "round_robin"
        }))
    }

    #[test]
    fn zone_on_a_target_compiles_and_routes() {
        // The exact shape WOR-2498 refused at config compile. The
        // refusal is gone because the label routes now.
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080", "zone": "us-east-1a"},
                {"url": "http://b:8080"}
            ]
        }));
        assert_eq!(lb.targets[0].zone.as_deref(), Some("us-east-1a"));
        assert!(lb.has_zoned_targets());

        lb.bind_local_zone("us-east-1a");
        for _ in 0..4 {
            let selection = select_from(&lb, "203.0.113.7");
            assert_eq!(
                selection.target_index, 0,
                "a zoned pool with a bound proxy zone must keep traffic local"
            );
            assert_eq!(selection.zone_locality, Some(ZoneLocality::Local));
        }
    }

    #[test]
    fn target_zone_field_defaults_to_none() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}]
        }));
        assert!(lb.targets[0].zone.is_none());
        assert!(!lb.has_zoned_targets());
    }

    #[test]
    fn zone_prefers_local_targets_over_round_robin() {
        let lb = zoned_two_target_lb();
        lb.bind_local_zone("zone-a");

        let visited: std::collections::BTreeSet<usize> = (0..6)
            .map(|_| select_from(&lb, "203.0.113.7").target_index)
            .collect();
        assert_eq!(
            visited,
            std::collections::BTreeSet::from([0]),
            "same-zone preference must keep round-robin inside zone-a"
        );
    }

    #[test]
    fn zone_spills_when_no_local_target_is_healthy_and_returns_with_health() {
        let lb = zoned_two_target_lb();
        lb.bind_local_zone("zone-a");

        // Local zone down: the request spills across zones instead of
        // blackholing, and says so.
        lb.set_target_health(0, false);
        for _ in 0..4 {
            let selection = select_from(&lb, "203.0.113.7");
            assert_eq!(
                selection.target_index, 1,
                "with zone-a unhealthy every request must spill to zone-b"
            );
            assert_eq!(selection.zone_locality, Some(ZoneLocality::Spilled));
        }

        // Failover is per-request, not per-config: health returning
        // moves the very next selection back inside the local zone.
        lb.set_target_health(0, true);
        let selection = select_from(&lb, "203.0.113.7");
        assert_eq!(selection.target_index, 0);
        assert_eq!(selection.zone_locality, Some(ZoneLocality::Local));
    }

    #[test]
    fn zone_spills_when_the_local_zone_has_no_targets() {
        let lb = zoned_two_target_lb();
        lb.bind_local_zone("zone-c");

        let mut visited = std::collections::BTreeSet::new();
        for _ in 0..6 {
            let selection = select_from(&lb, "203.0.113.7");
            assert_eq!(selection.zone_locality, Some(ZoneLocality::Spilled));
            visited.insert(selection.target_index);
        }
        assert_eq!(
            visited,
            std::collections::BTreeSet::from([0, 1]),
            "a proxy zoned away from every target must still spread traffic"
        );
    }

    #[test]
    fn unbound_proxy_zone_leaves_selection_unchanged() {
        // Zone labels with no proxy zone identity: exactly the
        // pre-WOR-2328 shape. Both targets take traffic and no
        // locality verdict is reported.
        let lb = zoned_two_target_lb();

        let mut visited = std::collections::BTreeSet::new();
        for _ in 0..6 {
            let selection = select_from(&lb, "203.0.113.7");
            assert_eq!(selection.zone_locality, None);
            visited.insert(selection.target_index);
        }
        assert_eq!(visited, std::collections::BTreeSet::from([0, 1]));
    }

    #[test]
    fn unlabeled_pool_ignores_the_proxy_zone() {
        // A single-zone config (no target labels) behaves exactly as
        // today even when the proxy itself is zoned.
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"}
            ],
            "algorithm": "round_robin"
        }));
        lb.bind_local_zone("zone-a");

        let mut visited = std::collections::BTreeSet::new();
        for _ in 0..6 {
            let selection = select_from(&lb, "203.0.113.7");
            assert_eq!(selection.zone_locality, None);
            visited.insert(selection.target_index);
        }
        assert_eq!(visited, std::collections::BTreeSet::from([0, 1]));
    }

    #[test]
    fn unlabeled_target_is_not_local() {
        // An unlabeled target in a labeled pool is a different
        // locality, matching Envoy's endpoint-locality model: only an
        // exact zone match is local.
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080", "zone": "zone-a"},
                {"url": "http://b:8080"}
            ],
            "algorithm": "round_robin"
        }));
        lb.bind_local_zone("zone-a");

        for _ in 0..4 {
            let selection = select_from(&lb, "203.0.113.7");
            assert_eq!(selection.target_index, 0);
            assert_eq!(selection.zone_locality, Some(ZoneLocality::Local));
        }
    }

    #[test]
    fn locality_deactivates_below_min_pool_size() {
        // Envoy's `min_cluster_size` shape: below the configured pool
        // size the stage stands down entirely and traffic spreads.
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080", "zone": "zone-a"},
                {"url": "http://b:8080", "zone": "zone-b"}
            ],
            "algorithm": "round_robin",
            "locality": {"min_pool_size": 3}
        }));
        assert_eq!(lb.locality_min_pool_size, 3);
        lb.bind_local_zone("zone-a");

        let mut visited = std::collections::BTreeSet::new();
        for _ in 0..6 {
            let selection = select_from(&lb, "203.0.113.7");
            assert_eq!(selection.zone_locality, None);
            visited.insert(selection.target_index);
        }
        assert_eq!(visited, std::collections::BTreeSet::from([0, 1]));
    }

    #[test]
    fn min_pool_size_defaults_to_two() {
        let lb = zoned_two_target_lb();
        assert_eq!(lb.locality_min_pool_size, 2);
    }

    #[test]
    fn locality_stands_down_when_every_target_is_filtered() {
        // Panic-mode composition: when health filtering removes every
        // target, the ejection stage already falls back to the whole
        // pool rather than 502ing, and the locality stage must not
        // re-narrow that last-resort set (Envoy disables zone-aware
        // routing in panic mode for the same reason).
        let lb = zoned_two_target_lb();
        lb.bind_local_zone("zone-a");
        lb.set_target_health(0, false);
        lb.set_target_health(1, false);

        let mut visited = std::collections::BTreeSet::new();
        for _ in 0..6 {
            let selection = select_from(&lb, "203.0.113.7");
            assert_eq!(selection.zone_locality, None);
            visited.insert(selection.target_index);
        }
        assert_eq!(
            visited,
            std::collections::BTreeSet::from([0, 1]),
            "an all-unhealthy pool must still spread rather than pin to the local zone"
        );
    }

    #[test]
    fn locality_narrows_before_the_priority_filter() {
        // Stage order is ejection, locality, priority: a cross-zone
        // target with a better priority must not beat a healthy local
        // one.
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080", "zone": "zone-a", "priority": 5},
                {"url": "http://b:8080", "zone": "zone-b", "priority": 1}
            ],
            "algorithm": "round_robin"
        }));
        lb.bind_local_zone("zone-a");

        for _ in 0..4 {
            let selection = select_from(&lb, "203.0.113.7");
            assert_eq!(selection.target_index, 0);
            assert_eq!(selection.zone_locality, Some(ZoneLocality::Local));
        }
    }

    #[test]
    fn locality_composes_with_ring_hash() {
        // The ring is built over every configured target; locality
        // narrows the eligibility bitmap, so the walk skips cross-zone
        // targets without rebuilding the ring.
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080", "zone": "zone-a"},
                {"url": "http://b:8080", "zone": "zone-a"},
                {"url": "http://c:8080", "zone": "zone-b"}
            ],
            "algorithm": {"ring_hash": {"key": "ip"}},
            "locality": {"min_pool_size": 2}
        }));
        lb.bind_local_zone("zone-a");

        let mut visited = std::collections::BTreeSet::new();
        for octet in 1..=32u8 {
            let selection = select_from(&lb, &format!("203.0.113.{octet}"));
            assert_eq!(selection.zone_locality, Some(ZoneLocality::Local));
            visited.insert(selection.target_index);
        }
        assert_eq!(
            visited,
            std::collections::BTreeSet::from([0, 1]),
            "ring keys must stay inside zone-a while both local targets are healthy"
        );
    }

    #[test]
    fn binding_an_empty_zone_is_ignored() {
        let lb = zoned_two_target_lb();
        lb.bind_local_zone("   ");
        assert_eq!(lb.local_zone(), None);
        lb.bind_local_zone(" zone-a ");
        assert_eq!(lb.local_zone(), Some("zone-a"));
    }

    #[test]
    fn from_config_empty_targets_fails() {
        let result = LoadBalancerAction::from_config(serde_json::json!({
            "targets": []
        }));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one target"));
    }

    #[test]
    fn target_metadata_rejects_oversized_and_deep_values() {
        let oversized = LoadBalancerAction::from_config(serde_json::json!({
            "targets": [{
                "url": "http://a:8080",
                "metadata": {"payload": "x".repeat(17 * 1024)}
            }]
        }))
        .expect_err("oversized metadata must be rejected");
        assert!(
            oversized.to_string().contains("serialized size"),
            "unexpected error: {oversized}"
        );

        let mut nested = serde_json::json!("leaf");
        for _ in 0..9 {
            nested = serde_json::json!([nested]);
        }
        let too_deep = LoadBalancerAction::from_config(serde_json::json!({
            "targets": [{
                "url": "http://a:8080",
                "metadata": {"nested": nested}
            }]
        }))
        .expect_err("deeply nested metadata must be rejected");
        assert!(
            too_deep.to_string().contains("nesting depth"),
            "unexpected error: {too_deep}"
        );
    }

    #[test]
    fn third_party_strategy_receives_exact_user_config() {
        let lb = LoadBalancerAction::from_config_for_origin(
            serde_json::json!({
                "targets": [{"url": "http://a:8080"}],
                "strategy": "strict-config-test",
                "strategy_config": {"enabled": true}
            }),
            "workspace-a/origin-a",
        )
        .expect("internal routing context must not enter a third-party config");

        let selection = lb
            .select_target_for_request(RoutingRequest::new("GET", "/", "example.com"))
            .expect("strict strategy selection");
        assert_eq!(selection.selection_method, "strict-config-test");
    }

    #[test]
    fn bandit_rejects_a_257_target_pool_at_compile_time() {
        let targets: Vec<serde_json::Value> = (0..257)
            .map(|index| serde_json::json!({"url": format!("http://target-{index}:8080")}))
            .collect();
        let error = LoadBalancerAction::from_config(serde_json::json!({
            "targets": targets,
            "strategy": "bandit"
        }))
        .expect_err("a bandit pool above the retained arm bound must be rejected");

        assert!(
            error.to_string().contains("at most 256 targets"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn from_config_missing_targets_fails() {
        let result = LoadBalancerAction::from_config(serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn from_config_default_weight() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}]
        }));
        assert_eq!(lb.targets[0].weight, 1);
        assert!(!lb.targets[0].backup);
    }

    #[test]
    fn from_config_backup_target() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080", "backup": true}
            ]
        }));
        assert!(!lb.targets[0].backup);
        assert!(lb.targets[1].backup);
    }

    // --- round_robin tests ---

    #[test]
    fn round_robin_distributes_evenly() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"},
                {"url": "http://c:8080"}
            ]
        }));
        let headers = empty_headers();
        let mut counts = [0u32; 3];
        for _ in 0..300 {
            let (_, _, _, idx) = lb.select_target(None, "/", &headers).unwrap();
            counts[idx] += 1;
        }
        assert_eq!(counts[0], 100);
        assert_eq!(counts[1], 100);
        assert_eq!(counts[2], 100);
    }

    // --- ip_hash tests ---

    #[test]
    fn ip_hash_consistent_for_same_ip() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"},
                {"url": "http://c:8080"}
            ],
            "algorithm": "ip_hash"
        }));
        let headers = empty_headers();
        let (_, _, _, first) = lb.select_target(Some("10.0.0.1"), "/", &headers).unwrap();
        for _ in 0..50 {
            let (_, _, _, idx) = lb.select_target(Some("10.0.0.1"), "/", &headers).unwrap();
            assert_eq!(idx, first, "ip_hash must be consistent for the same IP");
        }
    }

    #[test]
    fn ip_hash_different_ips_can_differ() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"},
                {"url": "http://c:8080"},
                {"url": "http://d:8080"},
                {"url": "http://e:8080"}
            ],
            "algorithm": "ip_hash"
        }));
        let headers = empty_headers();
        let mut seen = std::collections::HashSet::new();
        for i in 0..20 {
            let ip = format!("10.0.0.{}", i);
            let (_, _, _, idx) = lb.select_target(Some(&ip), "/", &headers).unwrap();
            seen.insert(idx);
        }
        // With 20 different IPs and 5 targets, we should hit more than 1.
        assert!(
            seen.len() > 1,
            "different IPs should map to different targets"
        );
    }

    // --- uri_hash tests ---

    #[test]
    fn uri_hash_consistent_for_same_uri() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"},
                {"url": "http://c:8080"}
            ],
            "algorithm": "uri_hash"
        }));
        let headers = empty_headers();
        let (_, _, _, first) = lb.select_target(None, "/api/users", &headers).unwrap();
        for _ in 0..50 {
            let (_, _, _, idx) = lb.select_target(None, "/api/users", &headers).unwrap();
            assert_eq!(idx, first, "uri_hash must be consistent for the same URI");
        }
    }

    #[test]
    fn uri_hash_fallback_ignores_query_without_strategy() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"},
                {"url": "http://c:8080"},
                {"url": "http://d:8080"},
                {"url": "http://e:8080"}
            ],
            "algorithm": "uri_hash"
        }));

        let first = lb
            .select_target_for_request(RoutingRequest::new("GET", "/resource?a=1", "example.com"))
            .expect("first URI hash selection");
        let second = lb
            .select_target_for_request(RoutingRequest::new("GET", "/resource?a=2", "example.com"))
            .expect("second URI hash selection");

        assert_eq!(first.target_index, second.target_index);
        assert_eq!(first.selection_method, "uri_hash");
        assert_eq!(second.selection_method, "uri_hash");
    }

    #[test]
    fn uri_hash_fallback_ignores_query_after_strategy_deferral() {
        let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"},
                {"url": "http://c:8080"},
                {"url": "http://d:8080"},
                {"url": "http://e:8080"}
            ],
            "algorithm": "uri_hash"
        }));
        lb.strategy_name = Some("path-capturing-deferring-test");
        lb.strategy = Some(Arc::new(PathCapturingDeferringStrategy {
            paths: Arc::clone(&paths),
        }));

        let first = lb
            .select_target_for_request(RoutingRequest::new("GET", "/resource?a=1", "example.com"))
            .expect("first deferred URI hash selection");
        let second = lb
            .select_target_for_request(RoutingRequest::new("GET", "/resource?a=2", "example.com"))
            .expect("second deferred URI hash selection");

        assert_eq!(first.target_index, second.target_index);
        assert_eq!(first.selection_method, "uri_hash");
        assert_eq!(second.selection_method, "uri_hash");
        assert_eq!(
            *paths.lock().expect("path capture lock"),
            vec!["/resource?a=1", "/resource?a=2"]
        );
    }

    // --- least_connections tests ---

    #[test]
    fn least_connections_picks_lowest() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"},
                {"url": "http://c:8080"}
            ],
            "algorithm": "least_connections"
        }));
        let headers = empty_headers();

        // Add connections to targets 0 and 1.
        lb.record_connect(0);
        lb.record_connect(0);
        lb.record_connect(1);

        let (_, _, _, idx) = lb.select_target(None, "/", &headers).unwrap();
        assert_eq!(idx, 2, "should pick target with 0 connections");

        // Disconnect from target 0, now target 2 still has 0 but target 0 has 1.
        lb.record_disconnect(0);
        let (_, _, _, idx) = lb.select_target(None, "/", &headers).unwrap();
        assert_eq!(idx, 2, "target 2 still has fewest connections");
    }

    #[test]
    fn least_connections_tracks_correctly() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"}
            ],
            "algorithm": "least_connections"
        }));

        lb.record_connect(0);
        lb.record_connect(0);
        lb.record_connect(1);
        assert_eq!(lb.connection_count(0), 2);
        assert_eq!(lb.connection_count(1), 1);

        lb.record_disconnect(0);
        assert_eq!(lb.connection_count(0), 1);
    }

    #[test]
    fn first_healthy_strategy_selects_first_eligible_target() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://first:8080"},
                {"url": "http://second:8080"}
            ],
            "algorithm": "least_connections",
            "strategy": "first-healthy"
        }));
        lb.record_connect(0);

        let selection = lb
            .select_target_for_request(RoutingRequest::new("GET", "/", "example.com"))
            .expect("strategy selection should succeed");

        assert_eq!(selection.target_index, 0);
        assert_eq!(selection.selection_method, "first-healthy");
    }

    #[test]
    fn omitted_strategy_preserves_round_robin_default() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://first:8080"},
                {"url": "http://second:8080"}
            ]
        }));

        let first = lb
            .select_target_for_request(RoutingRequest::new("GET", "/", "example.com"))
            .expect("first selection should succeed");
        let second = lb
            .select_target_for_request(RoutingRequest::new("GET", "/", "example.com"))
            .expect("second selection should succeed");

        assert_eq!(first.target_index, 0);
        assert_eq!(second.target_index, 1);
        assert_eq!(first.selection_method, "round_robin");
        assert_eq!(second.selection_method, "round_robin");
    }

    #[test]
    fn gpu_aware_strategy_uses_eligible_target_metadata() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {
                    "url": "http://busy:8080",
                    "metadata": {"gpu_utilization": 0.8}
                },
                {
                    "url": "http://idle:8080",
                    "metadata": {"gpu_utilization": 0.2}
                }
            ],
            "strategy": "gpu-aware"
        }));

        let selection = lb
            .select_target_for_request(RoutingRequest::new("POST", "/v1/chat", "ai.example.com"))
            .expect("GPU-aware selection should succeed");

        assert_eq!(selection.target_index, 1);
        assert_eq!(selection.selection_method, "gpu-aware");
    }

    #[test]
    fn target_metadata_can_be_updated_without_rebuilding_the_action() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {
                    "url": "http://busy:8080",
                    "metadata": {"gpu_utilization": 0.8}
                },
                {
                    "url": "http://idle:8080",
                    "metadata": {"gpu_utilization": 0.2}
                }
            ],
            "strategy": "gpu-aware"
        }));
        let before = lb
            .target_metadata_snapshot(0)
            .expect("configured target metadata snapshot");
        assert_eq!(
            lb.select_target_for_request(RoutingRequest::new("POST", "/v1/chat", "ai.example.com"))
                .expect("initial GPU-aware selection")
                .target_index,
            1
        );

        lb.update_target_metadata(
            0,
            HashMap::from([("gpu_utilization".to_string(), serde_json::json!(0.05))]),
        )
        .expect("bounded metadata update");

        let after = lb
            .target_metadata_snapshot(0)
            .expect("updated target metadata snapshot");
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(after.get("gpu_utilization"), Some(&serde_json::json!(0.05)));
        assert_eq!(
            lb.select_target_for_request(RoutingRequest::new("POST", "/v1/chat", "ai.example.com"))
                .expect("selection with updated metadata")
                .target_index,
            0
        );

        let invalid = HashMap::from([(
            "payload".to_string(),
            serde_json::json!("x".repeat(17 * 1024)),
        )]);
        assert!(lb.update_target_metadata(0, invalid).is_err());
        assert!(Arc::ptr_eq(
            &after,
            &lb.target_metadata_snapshot(0)
                .expect("rejected updates must preserve the current snapshot")
        ));
    }

    #[test]
    fn selection_method_uses_closed_registry_name() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://first:8080"}],
            "strategy": "bandit",
            "strategy_config": {
                "name": "tenant-controlled-label",
                "epsilon": 0.0
            }
        }));

        let selection = lb
            .select_target_for_request(RoutingRequest::new("GET", "/", "example.com"))
            .expect("bandit selection should succeed");

        assert_eq!(selection.selection_method, "bandit");
    }

    #[test]
    fn lora_aware_strategy_reads_adapter_header_and_selects_warm_target() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {
                    "url": "http://cold:8080",
                    "metadata": {"loaded_adapters": []}
                },
                {
                    "url": "http://warm:8080",
                    "metadata": {"loaded_adapters": ["support"]}
                }
            ],
            "strategy": "lora-aware"
        }));
        let mut request = RoutingRequest::new("POST", "/v1/chat", "ai.example.com");
        request
            .headers
            .insert("x-lora-adapter", "support".parse().unwrap());

        let selection = lb
            .select_target_for_request(request)
            .expect("LoRA-aware selection should succeed");

        assert_eq!(selection.target_index, 1);
        assert_eq!(selection.selection_method, "lora-aware");
    }

    #[test]
    fn deferring_strategy_falls_back_to_configured_algorithm() {
        let mut lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://busy:8080"},
                {"url": "http://idle:8080"}
            ],
            "algorithm": "least_connections"
        }));
        lb.strategy_name = Some("deferring-test");
        lb.strategy = Some(Arc::new(DeferringStrategy));
        lb.record_connect(0);

        let selection = lb
            .select_target_for_request(RoutingRequest::new("GET", "/", "example.com"))
            .expect("algorithm fallback should succeed");

        assert_eq!(selection.target_index, 1);
        assert_eq!(selection.selection_method, "least_connections");
    }

    #[test]
    fn out_of_range_strategy_result_falls_back_without_panicking() {
        let mut lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://busy:8080"},
                {"url": "http://idle:8080"}
            ],
            "algorithm": "least_connections"
        }));
        lb.strategy_name = Some("out-of-range-test");
        lb.strategy = Some(Arc::new(OutOfRangeStrategy));
        lb.record_connect(0);

        let selection = lb
            .select_target_for_request(RoutingRequest::new("GET", "/", "example.com"))
            .expect("invalid strategy result should use algorithm fallback");

        assert_eq!(selection.target_index, 1);
        assert_eq!(selection.selection_method, "least_connections");
    }

    #[test]
    fn filtered_targets_never_appear_in_strategy_projection() {
        let saw_filtered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://backup:8080", "backup": true},
                {"url": "http://eligible:8080"}
            ]
        }));
        lb.strategy_name = Some("projection-guard-test");
        lb.strategy = Some(Arc::new(ProjectionGuardStrategy {
            forbidden_url: "http://backup:8080",
            saw_forbidden: Arc::clone(&saw_filtered),
        }));

        let selection = lb
            .select_target_for_request(RoutingRequest::new("GET", "/", "example.com"))
            .expect("eligible target selection should succeed");

        assert_eq!(selection.target_index, 1);
        assert!(
            !saw_filtered.load(Ordering::Relaxed),
            "backup target must be removed before strategy projection"
        );
    }

    #[test]
    fn strategy_is_skipped_when_strict_eligibility_filter_rejects_every_target() {
        #[derive(Debug, Clone, Copy)]
        enum Rejection {
            Health,
            Breaker,
            Outlier,
        }

        for rejection in [Rejection::Health, Rejection::Breaker, Rejection::Outlier] {
            let mut config = serde_json::json!({
                "targets": [
                    {"url": "http://first:8080"},
                    {"url": "http://second:8080"}
                ]
            });
            match rejection {
                Rejection::Health => {}
                Rejection::Breaker => {
                    config["circuit_breaker"] = serde_json::json!({
                        "failure_threshold": 1,
                        "success_threshold": 1,
                        "open_duration_secs": 60
                    });
                }
                Rejection::Outlier => {
                    config["outlier_detection"] = serde_json::json!({
                        "threshold": 0.0,
                        "window_secs": 60,
                        "min_requests": 1,
                        "ejection_duration_secs": 60
                    });
                }
            }

            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut lb = make_lb(config);
            lb.strategy_name = Some("invocation-tracking-test");
            lb.strategy = Some(Arc::new(InvocationTrackingStrategy {
                calls: Arc::clone(&calls),
            }));
            match rejection {
                Rejection::Health => {
                    lb.set_target_health(0, false);
                    lb.set_target_health(1, false);
                }
                Rejection::Breaker => {
                    lb.record_breaker_failure(0);
                    lb.record_breaker_failure(1);
                }
                Rejection::Outlier => {
                    lb.record_target_failure(0);
                    lb.record_target_failure(1);
                }
            }

            let selection = lb
                .select_target_for_request(RoutingRequest::new("GET", "/", "example.com"))
                .expect("legacy algorithm fallback should select a target");

            assert_eq!(
                selection.selection_method, "round_robin",
                "{rejection:?} must preserve legacy algorithm fallback"
            );
            assert_eq!(
                calls.load(Ordering::Relaxed),
                0,
                "strategy must not see a pool rejected by {rejection:?}"
            );
        }
    }

    #[test]
    fn stable_origin_namespace_reuses_bandit_outcomes_after_recompile() {
        let config = serde_json::json!({
            "targets": [
                {"url": "http://first:8080"},
                {"url": "http://second:8080"}
            ],
            "strategy": "bandit",
            "strategy_config": {"epsilon": 0.0}
        });
        let first =
            LoadBalancerAction::from_config_for_origin(config.clone(), "task2-reload-persistence")
                .expect("first action should compile");
        let request = || RoutingRequest::new("GET", "/", "example.com");
        let initial = first
            .select_target_for_request(request())
            .expect("initial selection should succeed");
        assert_eq!(initial.target_index, 0);
        first.record_strategy_outcome(
            initial.target_index,
            RoutingOutcome {
                success: false,
                latency: std::time::Duration::from_millis(10),
            },
        );

        let recompiled =
            LoadBalancerAction::from_config_for_origin(config.clone(), "task2-reload-persistence")
                .expect("recompiled action should compile");
        let next = recompiled
            .select_target_for_request(request())
            .expect("selection after reload should succeed");

        assert_eq!(
            next.target_index, 1,
            "recompiled action should reuse feedback for the stable namespace"
        );

        let other_origin = LoadBalancerAction::from_config_for_origin(config, "task2-other-origin")
            .expect("distinct origin should compile");
        assert_eq!(
            other_origin
                .select_target_for_request(request())
                .expect("distinct-origin selection should succeed")
                .target_index,
            0,
            "a distinct origin must not inherit another origin's feedback"
        );

        let changed_pool = LoadBalancerAction::from_config_for_origin(
            serde_json::json!({
                "targets": [
                    {"url": "http://first:8080"},
                    {"url": "http://replacement:8080"}
                ],
                "strategy": "bandit",
                "strategy_config": {"epsilon": 0.0}
            }),
            "task2-reload-persistence",
        )
        .expect("changed target pool should compile");
        assert_eq!(
            changed_pool
                .select_target_for_request(request())
                .expect("changed-pool selection should succeed")
                .target_index,
            0,
            "a changed target pool must start with a fresh namespace"
        );
    }

    // --- weighted distribution tests ---

    #[test]
    fn weighted_random_favors_higher_weight() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080", "weight": 9},
                {"url": "http://b:8080", "weight": 1}
            ],
            "algorithm": "weighted_random"
        }));
        let headers = empty_headers();
        let mut counts = [0u32; 2];
        for _ in 0..1000 {
            let (_, _, _, idx) = lb.select_target(None, "/", &headers).unwrap();
            counts[idx] += 1;
        }
        // Target 0 (weight 9) should get significantly more than target 1 (weight 1).
        assert!(
            counts[0] > counts[1],
            "higher weight target should receive more requests: a={}, b={}",
            counts[0],
            counts[1]
        );
    }

    // --- backup target tests ---

    #[test]
    fn backup_targets_excluded_from_selection() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://primary:8080"},
                {"url": "http://backup:8080", "backup": true}
            ]
        }));
        let headers = empty_headers();
        for _ in 0..100 {
            let (host, _, _, idx) = lb.select_target(None, "/", &headers).unwrap();
            assert_eq!(idx, 0);
            assert_eq!(host, "primary");
        }
    }

    #[test]
    fn all_backup_targets_returns_error() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080", "backup": true},
                {"url": "http://b:8080", "backup": true}
            ]
        }));
        let headers = empty_headers();
        let result = lb.select_target(None, "/", &headers);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no active targets"));
    }

    // --- select_target URL parsing tests ---

    #[test]
    fn select_target_https_default_port() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "https://secure.example.com"}]
        }));
        let headers = empty_headers();
        let (host, port, tls, _) = lb.select_target(None, "/", &headers).unwrap();
        assert_eq!(host, "secure.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn select_target_http_custom_port() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://backend:9090"}]
        }));
        let headers = empty_headers();
        let (host, port, tls, _) = lb.select_target(None, "/", &headers).unwrap();
        assert_eq!(host, "backend");
        assert_eq!(port, 9090);
        assert!(!tls);
    }

    #[test]
    fn select_target_http_default_port() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://plain.example.com"}]
        }));
        let headers = empty_headers();
        let (host, port, tls, _) = lb.select_target(None, "/", &headers).unwrap();
        assert_eq!(host, "plain.example.com");
        assert_eq!(port, 80);
        assert!(!tls);
    }

    // --- header_hash tests ---

    #[test]
    fn header_hash_consistent() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"},
                {"url": "http://c:8080"}
            ],
            "algorithm": {"header_hash": {"header": "X-Tenant"}}
        }));
        let mut headers = http::HeaderMap::new();
        headers.insert("x-tenant", http::HeaderValue::from_static("tenant-42"));
        let (_, _, _, first) = lb.select_target(None, "/", &headers).unwrap();
        for _ in 0..50 {
            let (_, _, _, idx) = lb.select_target(None, "/", &headers).unwrap();
            assert_eq!(idx, first);
        }
    }

    // --- cookie_hash tests ---

    #[test]
    fn cookie_hash_consistent() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"},
                {"url": "http://c:8080"}
            ],
            "algorithm": {"cookie_hash": {"cookie": "session_id"}}
        }));
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "cookie",
            http::HeaderValue::from_static("foo=bar; session_id=abc123; other=val"),
        );
        let (_, _, _, first) = lb.select_target(None, "/", &headers).unwrap();
        for _ in 0..50 {
            let (_, _, _, idx) = lb.select_target(None, "/", &headers).unwrap();
            assert_eq!(idx, first);
        }
    }

    // --- fnv1a_hash tests ---

    #[test]
    fn fnv1a_hash_deterministic() {
        let h1 = fnv1a_hash(b"hello");
        let h2 = fnv1a_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn fnv1a_hash_different_inputs() {
        let h1 = fnv1a_hash(b"hello");
        let h2 = fnv1a_hash(b"world");
        assert_ne!(h1, h2);
    }

    // --- record_connect/disconnect boundary tests ---

    #[test]
    fn record_connect_out_of_bounds_is_safe() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}]
        }));
        // Should not panic.
        lb.record_connect(999);
        lb.record_disconnect(999);
    }

    // --- blue-green deployment tests ---

    #[test]
    fn blue_green_routes_all_to_active_blue() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://blue:8080", "group": "blue"},
                {"url": "http://green:8080", "group": "green"}
            ],
            "deployment_mode": {"mode": "blue_green", "active": "blue"}
        }));
        let headers = empty_headers();
        for _ in 0..50 {
            let (host, _, _, _) = lb.select_target(None, "/", &headers).unwrap();
            assert_eq!(
                host, "blue",
                "blue-green active=blue should always route to blue"
            );
        }
    }

    #[test]
    fn blue_green_routes_all_to_active_green() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://blue:8080", "group": "blue"},
                {"url": "http://green:8080", "group": "green"}
            ],
            "deployment_mode": {"mode": "blue_green", "active": "green"}
        }));
        let headers = empty_headers();
        for _ in 0..50 {
            let (host, _, _, _) = lb.select_target(None, "/", &headers).unwrap();
            assert_eq!(
                host, "green",
                "blue-green active=green should always route to green"
            );
        }
    }

    #[test]
    fn blue_green_fallback_when_group_empty() {
        // If neither target has the active group, fall back to all non-backup targets.
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"}
            ],
            "deployment_mode": {"mode": "blue_green", "active": "blue"}
        }));
        let headers = empty_headers();
        // Should not panic or error - falls back gracefully.
        let result = lb.select_target(None, "/", &headers);
        assert!(result.is_ok());
    }

    #[test]
    fn deployment_mode_defaults_to_normal() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}]
        }));
        assert_eq!(lb.deployment_mode, DeploymentMode::Normal);
    }

    // --- canary deployment tests ---

    #[test]
    fn canary_splits_traffic_by_weight() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://primary:8080"},
                {"url": "http://canary:8080", "group": "canary"}
            ],
            "deployment_mode": {"mode": "canary", "weight": 20}
        }));
        let headers = empty_headers();
        let mut canary_count = 0;
        let total = 100;
        for _ in 0..total {
            let (host, _, _, _) = lb.select_target(None, "/", &headers).unwrap();
            if host == "canary" {
                canary_count += 1;
            }
        }
        // With weight=20, approximately 20% should go to canary.
        // Allow some tolerance: 15 to 25%.
        assert!(
            (15..=25).contains(&canary_count),
            "canary should receive ~20% of traffic, got {}%",
            canary_count
        );
    }

    #[test]
    fn canary_fallback_when_no_canary_targets() {
        // If no targets have group=canary, falls back to all active targets.
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080"},
                {"url": "http://b:8080"}
            ],
            "deployment_mode": {"mode": "canary", "weight": 50}
        }));
        let headers = empty_headers();
        let result = lb.select_target(None, "/", &headers);
        assert!(result.is_ok());
    }

    // --- priority-based routing tests ---

    #[test]
    fn priority_routing_prefers_lower_priority_number() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://low-priority:8080", "priority": 8},
                {"url": "http://high-priority:8080", "priority": 1}
            ]
        }));
        let mut headers = http::HeaderMap::new();
        // Request priority 3: should prefer target with priority <= 3 (high-priority at 1).
        headers.insert("x-priority", http::HeaderValue::from_static("3"));

        for _ in 0..30 {
            let (host, _, _, _) = lb.select_target(None, "/", &headers).unwrap();
            assert_eq!(
                host, "high-priority",
                "x-priority=3 should route to target with priority=1"
            );
        }
    }

    #[test]
    fn priority_routing_falls_back_when_no_match() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080", "priority": 5},
                {"url": "http://b:8080", "priority": 7}
            ]
        }));
        let mut headers = http::HeaderMap::new();
        // Request priority 1: no target has priority <= 1, so fallback to all.
        headers.insert("x-priority", http::HeaderValue::from_static("1"));
        let result = lb.select_target(None, "/", &headers);
        assert!(
            result.is_ok(),
            "should not error when no priority match, falling back"
        );
    }

    #[test]
    fn target_default_priority_is_five() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}]
        }));
        assert_eq!(lb.targets[0].priority, 5);
    }

    #[test]
    fn priority_routing_no_header_uses_all_targets() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://a:8080", "priority": 1},
                {"url": "http://b:8080", "priority": 9}
            ]
        }));
        // Without X-Priority header, all targets are available.
        let headers = empty_headers();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let (host, _, _, _) = lb.select_target(None, "/", &headers).unwrap();
            seen.insert(host);
        }
        assert_eq!(
            seen.len(),
            2,
            "without X-Priority, both targets should be reachable"
        );
    }

    // WOR-2246: four tests of an unwired `locality_filter` helper
    // stood here, the only callers it ever had, which is how a routing
    // input nothing routed on kept looking covered. WOR-2498 then
    // removed and refused the `zone` field, and WOR-2328 rebuilt the
    // filter as a live selection stage. Its tests live in the
    // zone-locality block above and drive it through
    // `select_target_for_request`, never by calling the helper
    // directly, so coverage tracks the wiring rather than the helper.

    // --- ring_hash tests ---

    fn ring_lb(target_count: usize) -> LoadBalancerAction {
        let targets: Vec<serde_json::Value> = (0..target_count)
            .map(|index| serde_json::json!({"url": format!("http://backend-{index}:8080")}))
            .collect();
        make_lb(serde_json::json!({
            "targets": targets,
            "algorithm": {"ring_hash": {}}
        }))
    }

    /// 1000 syntactically distinct client IPs for key sampling.
    fn sample_ips() -> Vec<String> {
        (0..1000u32)
            .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
            .collect()
    }

    #[test]
    fn ring_hash_same_key_selects_the_same_target() {
        let lb = ring_lb(5);
        let headers = empty_headers();
        let (_, _, _, first) = lb.select_target(Some("10.0.0.1"), "/", &headers).unwrap();
        for _ in 0..50 {
            let (_, _, _, idx) = lb.select_target(Some("10.0.0.1"), "/", &headers).unwrap();
            assert_eq!(idx, first, "ring_hash must be consistent for the same key");
        }
    }

    #[test]
    fn ring_hash_single_target_always_selected() {
        let lb = ring_lb(1);
        let headers = empty_headers();
        for ip in sample_ips().iter().take(50) {
            let (_, _, _, idx) = lb.select_target(Some(ip), "/", &headers).unwrap();
            assert_eq!(idx, 0, "a one-target ring has one owner for every key");
        }
    }

    #[test]
    fn ring_hash_ring_is_identical_across_two_builds() {
        // Two compilations of the same config must produce the same
        // key-to-target mapping: reloads must not reshuffle sessions,
        // and replicas sharing a config file must agree on owners.
        let config = || {
            serde_json::json!({
                "targets": [
                    {"url": "http://backend-0:8080"},
                    {"url": "http://backend-1:8080"},
                    {"url": "http://backend-2:8080"},
                    {"url": "http://backend-3:8080"},
                    {"url": "http://backend-4:8080"}
                ],
                "algorithm": {"ring_hash": {}}
            })
        };
        let first = make_lb(config());
        let second = make_lb(config());
        let headers = empty_headers();
        for ip in sample_ips().iter().take(200) {
            assert_eq!(
                first.select_target(Some(ip), "/", &headers).unwrap().3,
                second.select_target(Some(ip), "/", &headers).unwrap().3,
                "two builds of one config must map {ip} identically"
            );
        }
    }

    #[test]
    fn ring_hash_positions_use_the_seedless_fnv1a_hash() {
        // `DefaultHasher` is explicitly randomized per process; a ring
        // built over it would send the same key to different targets on
        // different replicas. Pinning one reference value through the
        // full position hash (FNV-1a plus the splitmix64 finalizer)
        // means neither half can be swapped silently.
        assert_eq!(fnv1a_hash_u64(b"ring-position-pin"), 0x07f8_8f52_a522_f2ef);
        assert_eq!(ring_point(b"ring-position-pin"), 0x2cc5_6769_3f3d_8522);
    }

    #[test]
    fn ring_hash_remaps_only_the_removed_targets_share_of_keys() {
        // The property that justifies the ring: dropping one of ten
        // targets from the config moves only the keys that target
        // owned, roughly 1/10 of them. The modulus algorithms reshuffle
        // most keys on the same edit.
        let ten = ring_lb(10);
        let nine = ring_lb(9); // same urls minus http://backend-9:8080
        let headers = empty_headers();

        let mut owned_by_removed = 0usize;
        for ip in sample_ips() {
            let before = ten.select_target(Some(&ip), "/", &headers).unwrap().3;
            let after = nine.select_target(Some(&ip), "/", &headers).unwrap().3;
            if before == 9 {
                owned_by_removed += 1;
            } else {
                assert_eq!(
                    after, before,
                    "a key on a surviving target must not move when another target is removed"
                );
            }
        }

        // Fair share of 1000 keys across 10 targets is ~100. The bound
        // is generous because vnode shares are lumpy, but a modulus
        // reshuffle (which moves ~90% of keys) stays far outside it.
        assert!(
            owned_by_removed > 0,
            "the removed target must have owned some keys"
        );
        assert!(
            owned_by_removed < 250,
            "removing 1 of 10 targets should remap ~1/10 of keys, moved {owned_by_removed} of 1000"
        );
    }

    #[test]
    fn ring_hash_gives_a_heavier_target_a_larger_key_share() {
        let lb = make_lb(serde_json::json!({
            "targets": [
                {"url": "http://heavy:8080", "weight": 3},
                {"url": "http://light:8080", "weight": 1}
            ],
            "algorithm": {"ring_hash": {}}
        }));
        let headers = empty_headers();
        let mut counts = [0u32; 2];
        for ip in sample_ips() {
            let (_, _, _, idx) = lb.select_target(Some(&ip), "/", &headers).unwrap();
            counts[idx] += 1;
        }
        // Weight 3 vs 1 apportions ring points 3:1. Demand a clear
        // majority rather than the exact ratio; vnode shares are lumpy.
        assert!(
            counts[0] > counts[1] * 2,
            "weight-3 target should own roughly 3x the keys: heavy={}, light={}",
            counts[0],
            counts[1]
        );
    }

    #[test]
    fn ring_hash_walks_past_an_unhealthy_target_and_returns_after_recovery() {
        let lb = ring_lb(3);
        let headers = empty_headers();

        // Find a probe key owned by target 0 and a control key owned by
        // another target.
        let mut probe = None;
        let mut control = None;
        for ip in sample_ips() {
            let (_, _, _, idx) = lb.select_target(Some(&ip), "/", &headers).unwrap();
            if idx == 0 && probe.is_none() {
                probe = Some(ip);
            } else if idx != 0 && control.is_none() {
                control = Some((ip, idx));
            }
            if probe.is_some() && control.is_some() {
                break;
            }
        }
        let probe = probe.expect("1000 keys must reach a 3-target ring's first target");
        let (control_ip, control_idx) =
            control.expect("1000 keys must reach the other two targets");

        // The owner goes unhealthy: its keys walk to the next node on
        // the ring, deterministically, and nobody else's keys move.
        lb.set_target_health(0, false);
        let (_, _, _, walked) = lb.select_target(Some(&probe), "/", &headers).unwrap();
        assert_ne!(walked, 0, "an unhealthy owner must be walked past");
        assert_eq!(
            lb.select_target(Some(&probe), "/", &headers).unwrap().3,
            walked,
            "the walked-to target must be stable while the owner is down"
        );
        assert_eq!(
            lb.select_target(Some(&control_ip), "/", &headers)
                .unwrap()
                .3,
            control_idx,
            "keys owned by healthy targets must not move during the flap"
        );

        // Health returns: the key goes home. This is what ring-walking
        // buys over rebuilding: the flap never re-apportioned the ring.
        lb.set_target_health(0, true);
        assert_eq!(
            lb.select_target(Some(&probe), "/", &headers).unwrap().3,
            0,
            "the key must return to its owner when health returns"
        );
    }
}
