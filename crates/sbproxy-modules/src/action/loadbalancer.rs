//! Load balancer action - distributes requests across multiple upstream targets.
//!
//! Supports multiple routing algorithms: round-robin, weighted random,
//! least connections, IP hash, URI hash, header hash, and cookie hash.
//! Backup targets are excluded from normal selection and reserved for fallback.
//!
//! Also supports blue-green and canary deployment modes, and priority-based
//! routing via the `X-Priority` request header.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use anyhow::Result;
use sbproxy_platform::circuitbreaker::CircuitBreaker;
use sbproxy_platform::outlier::{OutlierDetector, OutlierDetectorConfig};
use serde::Deserialize;

use super::ForwardingHeaderControls;

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
        /// Percentage of requests routed to canary targets (0–100).
        weight: u8,
    },
}

/// Load balancer action - distributes requests across multiple upstream targets.
pub struct LoadBalancerAction {
    /// Pool of upstream targets that may receive requests.
    pub targets: Vec<Target>,
    /// Routing algorithm used to pick a target per request.
    pub algorithm: Algorithm,
    /// Optional sticky-session configuration.
    pub sticky: Option<StickyConfig>,
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
    state: LoadBalancerState,
}

impl std::fmt::Debug for LoadBalancerAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalancerAction")
            .field("targets", &self.targets)
            .field("algorithm", &self.algorithm)
            .field("sticky", &self.sticky)
            .field("deployment_mode", &self.deployment_mode)
            .field("outlier_detector", &self.outlier_detector.is_some())
            .field(
                "circuit_breakers",
                &self.circuit_breakers.as_ref().map(|v| v.len()),
            )
            .field("retry", &self.retry.is_some())
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
    /// Availability zone or region label for locality-aware routing (e.g. "us-east-1a").
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
}

/// Sticky session configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct StickyConfig {
    /// Name of the cookie used to pin a client to a target.
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    /// Optional cookie TTL in seconds.
    #[serde(default)]
    pub ttl: Option<u64>,
}

fn default_cookie_name() -> String {
    "sb_sticky".to_string()
}

// --- Internal state ---

/// Internal state for the load balancer (not serialized).
struct LoadBalancerState {
    round_robin_counter: AtomicU64,
    connections: Vec<AtomicU32>,
    /// Per-target health: `0` = unknown (treated as healthy), `1` =
    /// healthy, `2` = unhealthy. Vec indexed by target index.
    health: Vec<AtomicU8>,
}

impl std::fmt::Debug for LoadBalancerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadBalancerState")
            .field(
                "round_robin_counter",
                &self.round_robin_counter.load(Ordering::Relaxed),
            )
            .field("connections_len", &self.connections.len())
            .finish()
    }
}

// --- Implementation ---

impl LoadBalancerAction {
    /// Build a LoadBalancerAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            targets: Vec<Target>,
            #[serde(default = "default_algo")]
            algorithm: Algorithm,
            #[serde(default)]
            sticky: Option<StickyConfig>,
            #[serde(default)]
            outlier_detection: Option<OutlierDetectionConfig>,
            #[serde(default)]
            circuit_breaker: Option<CircuitBreakerConfig>,
            #[serde(default)]
            retry: Option<crate::action::RetryConfig>,
        }
        fn default_algo() -> Algorithm {
            Algorithm::RoundRobin
        }

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

        let config: Config = serde_json::from_value(value)?;
        anyhow::ensure!(
            !config.targets.is_empty(),
            "load balancer requires at least one target"
        );
        let num_targets = config.targets.len();

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

        Ok(Self {
            targets: config.targets,
            algorithm: config.algorithm,
            sticky: config.sticky,
            deployment_mode,
            outlier_detector,
            circuit_breakers,
            retry: config.retry,
            state: LoadBalancerState {
                round_robin_counter: AtomicU64::new(0),
                connections: (0..num_targets).map(|_| AtomicU32::new(0)).collect(),
                health: (0..num_targets).map(|_| AtomicU8::new(0)).collect(),
            },
        })
    }

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
                b.record_success();
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
                b.record_failure();
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
            let lb = std::sync::Arc::clone(self);
            tokio::spawn(async move {
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

    /// Select a target based on the configured algorithm.
    /// Returns (host, port, tls, target_index).
    ///
    /// When `deployment_mode` is `BlueGreen`, only targets in the active group are used.
    /// When `deployment_mode` is `Canary`, `weight`% of requests go to canary targets.
    /// Priority-based routing pre-sorts active targets by `priority` ascending (1 = highest),
    /// then by any `X-Priority` header value.
    pub fn select_target(
        &self,
        client_ip: Option<&str>,
        uri: &str,
        headers: &http::HeaderMap,
    ) -> Result<(String, u16, bool, usize)> {
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

        // Filter out targets the outlier detector has ejected. Fall
        // back to the unfiltered list when every active target is
        // ejected (better to send traffic to a flaky upstream than to
        // 502 the client).
        let active_targets: Vec<(usize, &Target)> = {
            let kept: Vec<(usize, &Target)> = active_targets
                .iter()
                .filter(|(idx, _)| !is_ejected(*idx))
                .cloned()
                .collect();
            if kept.is_empty() {
                active_targets
            } else {
                kept
            }
        };

        anyhow::ensure!(!active_targets.is_empty(), "no active targets available");

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

        let idx = match &self.algorithm {
            Algorithm::RoundRobin => {
                let counter = self
                    .state
                    .round_robin_counter
                    .fetch_add(1, Ordering::Relaxed);
                active_targets[counter as usize % active_targets.len()].0
            }
            Algorithm::WeightedRandom => self.select_weighted_random(&active_targets),
            Algorithm::LeastConnections => self.select_least_connections(&active_targets),
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
        };

        let target = &self.targets[idx];
        let parsed = url::Url::parse(&target.url)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("missing host in target URL"))?
            .to_string();
        let tls = parsed.scheme() == "https";
        let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
        Ok((host, port, tls, idx))
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
    #[cfg(test)]
    pub fn connection_count(&self, target_idx: usize) -> u32 {
        if target_idx < self.state.connections.len() {
            self.state.connections[target_idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    // --- Private helpers ---

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
    lb: std::sync::Arc<LoadBalancerAction>,
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

// --- Locality-aware routing ---

/// Configuration for zone/region-aware target selection.
#[derive(Debug, Clone, Deserialize)]
pub struct LocalityConfig {
    /// The availability zone or region label of this proxy instance, e.g. `"us-east-1a"`.
    pub local_zone: String,
    /// When `true`, prefer targets in the same zone before falling back to all targets.
    #[serde(default = "default_prefer_local")]
    pub prefer_local: bool,
}

fn default_prefer_local() -> bool {
    true
}

/// Return the indices of targets in `local_zone`.
/// If no targets match, returns all target indices as a fallback.
pub fn locality_filter(targets: &[Target], local_zone: &str) -> Vec<usize> {
    let local: Vec<usize> = targets
        .iter()
        .enumerate()
        .filter(|(_, t)| t.zone.as_deref() == Some(local_zone))
        .map(|(i, _)| i)
        .collect();
    if local.is_empty() {
        (0..targets.len()).collect()
    } else {
        local
    }
}

// --- Session affinity via consistent hashing ---

/// A consistent-hash ring for session-affinity load balancing.
///
/// Each target is replicated `vnodes` times on the ring to improve
/// distribution uniformity.
pub struct ConsistentHash {
    /// Sorted (hash, target_index) pairs.
    ring: Vec<(u64, usize)>,
}

impl ConsistentHash {
    /// Build a consistent-hash ring for `target_count` targets, each
    /// represented by `vnodes` virtual nodes.
    pub fn new(target_count: usize, vnodes: usize) -> Self {
        let vnodes = vnodes.max(1);
        let mut ring: Vec<(u64, usize)> = Vec::with_capacity(target_count * vnodes);
        for target_idx in 0..target_count {
            for vnode in 0..vnodes {
                let key = format!("target-{}-vnode-{}", target_idx, vnode);
                let hash = session_affinity_hash(&key);
                ring.push((hash, target_idx));
            }
        }
        ring.sort_by_key(|&(h, _)| h);
        Self { ring }
    }

    /// Map `key` to a target index using consistent hashing.
    ///
    /// Uses binary search on the sorted ring and wraps around for keys
    /// that exceed the largest hash.
    pub fn get(&self, key: &str) -> usize {
        if self.ring.is_empty() {
            return 0;
        }
        let h = session_affinity_hash(key);
        // Find the first ring entry whose hash >= h.
        match self.ring.binary_search_by_key(&h, |&(hash, _)| hash) {
            Ok(idx) => self.ring[idx].1,
            Err(idx) => {
                if idx < self.ring.len() {
                    self.ring[idx].1
                } else {
                    // Wrap around to the first entry on the ring.
                    self.ring[0].1
                }
            }
        }
    }
}

/// Hash a session key (e.g. a header value, cookie, or IP address) to a
/// `u64` suitable for consistent-hash ring placement.
///
/// Uses `DefaultHasher` which is deterministic within a single process
/// run.  For cross-process stability, callers should switch to a
/// fixed-seed hasher such as FNV or xxHash.
pub fn session_affinity_hash(key: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

// --- Utility functions ---

/// FNV-1a hash for consistent hashing of strings.
fn fnv1a_hash(data: &[u8]) -> usize {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash as usize
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
        assert!(lb.sticky.is_none());
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
    fn from_config_with_sticky() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}],
            "sticky": {"cookie_name": "my_sticky", "ttl": 3600}
        }));
        let sticky = lb.sticky.as_ref().unwrap();
        assert_eq!(sticky.cookie_name, "my_sticky");
        assert_eq!(sticky.ttl, Some(3600));
    }

    #[test]
    fn from_config_sticky_defaults() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}],
            "sticky": {}
        }));
        let sticky = lb.sticky.as_ref().unwrap();
        assert_eq!(sticky.cookie_name, "sb_sticky");
        assert!(sticky.ttl.is_none());
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
        // Allow some tolerance: 15–25%.
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

    // --- locality_filter tests ---

    #[test]
    fn locality_filter_returns_same_zone_indices() {
        let targets = vec![
            Target {
                url: "http://a:80".into(),
                weight: 1,
                backup: false,
                group: None,
                priority: 5,
                zone: Some("us-east-1a".into()),
                health_check: None,
                host_override: None,
                forwarding: Default::default(),
            },
            Target {
                url: "http://b:80".into(),
                weight: 1,
                backup: false,
                group: None,
                priority: 5,
                zone: Some("us-west-2a".into()),
                health_check: None,
                host_override: None,
                forwarding: Default::default(),
            },
            Target {
                url: "http://c:80".into(),
                weight: 1,
                backup: false,
                group: None,
                priority: 5,
                zone: Some("us-east-1a".into()),
                health_check: None,
                host_override: None,
                forwarding: Default::default(),
            },
        ];
        let indices = locality_filter(&targets, "us-east-1a");
        assert_eq!(indices, vec![0, 2], "should return only same-zone targets");
    }

    #[test]
    fn locality_filter_fallback_when_no_match() {
        let targets = vec![
            Target {
                url: "http://a:80".into(),
                weight: 1,
                backup: false,
                group: None,
                priority: 5,
                zone: Some("eu-west-1a".into()),
                health_check: None,
                host_override: None,
                forwarding: Default::default(),
            },
            Target {
                url: "http://b:80".into(),
                weight: 1,
                backup: false,
                group: None,
                priority: 5,
                zone: Some("eu-central-1a".into()),
                health_check: None,
                host_override: None,
                forwarding: Default::default(),
            },
        ];
        let indices = locality_filter(&targets, "us-east-1a");
        // No same-zone targets, should return all.
        assert_eq!(
            indices,
            vec![0, 1],
            "should fall back to all targets when no zone match"
        );
    }

    #[test]
    fn locality_filter_targets_without_zone_not_matched() {
        let targets = vec![
            Target {
                url: "http://a:80".into(),
                weight: 1,
                backup: false,
                group: None,
                priority: 5,
                zone: None,
                health_check: None,
                host_override: None,
                forwarding: Default::default(),
            },
            Target {
                url: "http://b:80".into(),
                weight: 1,
                backup: false,
                group: None,
                priority: 5,
                zone: Some("us-east-1a".into()),
                health_check: None,
                host_override: None,
                forwarding: Default::default(),
            },
        ];
        let indices = locality_filter(&targets, "us-east-1a");
        assert_eq!(indices, vec![1], "target without zone should not match");
    }

    #[test]
    fn locality_filter_empty_targets_returns_empty() {
        let targets: Vec<Target> = vec![];
        let indices = locality_filter(&targets, "us-east-1a");
        assert!(indices.is_empty());
    }

    // --- ConsistentHash tests ---

    #[test]
    fn consistent_hash_same_key_same_target() {
        let ch = ConsistentHash::new(5, 100);
        let first = ch.get("user-session-abc123");
        for _ in 0..100 {
            assert_eq!(
                ch.get("user-session-abc123"),
                first,
                "same key must always return same target"
            );
        }
    }

    #[test]
    fn consistent_hash_different_keys_distribute() {
        let ch = ConsistentHash::new(4, 100);
        let mut seen = std::collections::HashSet::new();
        for i in 0..200 {
            let key = format!("session-{}", i);
            seen.insert(ch.get(&key));
        }
        // With 200 keys and 4 targets we expect all targets to be used.
        assert!(
            seen.len() > 1,
            "different keys should map to multiple targets"
        );
    }

    #[test]
    fn consistent_hash_single_target_always_zero() {
        let ch = ConsistentHash::new(1, 10);
        for i in 0..50 {
            let key = format!("key-{}", i);
            assert_eq!(ch.get(&key), 0, "single target must always return index 0");
        }
    }

    // --- session_affinity_hash tests ---

    #[test]
    fn session_affinity_hash_deterministic() {
        let h1 = session_affinity_hash("192.168.1.1");
        let h2 = session_affinity_hash("192.168.1.1");
        assert_eq!(h1, h2);
    }

    #[test]
    fn session_affinity_hash_different_keys_differ() {
        let h1 = session_affinity_hash("session-abc");
        let h2 = session_affinity_hash("session-xyz");
        assert_ne!(h1, h2);
    }

    #[test]
    fn target_zone_field_defaults_to_none() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080"}]
        }));
        assert!(lb.targets[0].zone.is_none());
    }

    #[test]
    fn target_zone_field_deserializes() {
        let lb = make_lb(serde_json::json!({
            "targets": [{"url": "http://a:8080", "zone": "us-east-1a"}]
        }));
        assert_eq!(lb.targets[0].zone.as_deref(), Some("us-east-1a"));
    }
}
