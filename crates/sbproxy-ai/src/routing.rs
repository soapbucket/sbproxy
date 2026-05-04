//! Routing strategies for selecting AI providers.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use sbproxy_platform::circuitbreaker::CircuitBreaker;
use sbproxy_platform::outlier::{OutlierDetector, OutlierDetectorConfig};
use serde::Deserialize;

use crate::provider::ProviderConfig;

/// Strategy for selecting a provider.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingStrategy {
    /// Rotate through providers in order, one request at a time.
    RoundRobin,
    /// Distribute requests proportional to each provider's weight.
    Weighted,
    /// Try providers in priority order, falling back on failure.
    FallbackChain,
    /// Pick a provider uniformly at random.
    Random,
    /// Choose the provider with the lowest observed latency.
    LowestLatency,
    /// Choose the provider with the fewest in-flight requests.
    LeastConnections,
    /// Pick the cheapest provider that can serve the requested model.
    CostOptimized,
    /// Choose providers by remaining tokens-per-minute headroom.
    TokenRate,
    /// Pin a session key to the same provider across requests.
    Sticky,
    /// Send the request concurrently to every eligible provider and
    /// return the first acceptable response. Cancels the losers.
    /// Trades doubled spend for halved latency on the chat-first-token
    /// path; useful when every millisecond of TTFT matters.
    Race,
}

/// Router that selects a provider for each request.
pub struct Router {
    strategy: RoutingStrategy,
    counter: AtomicU64,
    // --- Per-provider state (sized at creation time) ---
    /// Observed p50 latency in microseconds per provider.
    latencies: Vec<AtomicU64>,
    /// In-flight request count per provider.
    connections: Vec<AtomicU32>,
    /// Tokens used in the current minute per provider.
    tokens_used: Vec<AtomicU64>,
    /// Token-per-minute limits per provider.
    token_limits: Vec<u64>,
    /// Session affinity map (session key -> provider index).
    sticky_map: DashMap<String, usize>,
    /// Per-provider circuit breakers. Empty when no resilience policy
    /// is configured; populated when the AI handler config carries a
    /// `resilience.circuit_breaker` block.
    breakers: Vec<Arc<CircuitBreaker>>,
    /// Optional shared outlier detector. Keys requests by provider
    /// name (matches the AI provider's stable id rather than its
    /// index so reload-time provider list changes don't reset state).
    outlier: Option<Arc<OutlierDetector>>,
    /// Per-provider active-probe health. `0` = unknown, `1` =
    /// healthy, `2` = unhealthy. Updated by background probe tasks
    /// when an `health_check` config is present.
    health: Vec<AtomicU8>,
}

impl Router {
    /// Create a router pre-allocated for `num_providers` providers using `strategy`.
    pub fn new(strategy: RoutingStrategy, num_providers: usize) -> Self {
        let latencies = (0..num_providers).map(|_| AtomicU64::new(0)).collect();
        let connections = (0..num_providers).map(|_| AtomicU32::new(0)).collect();
        let tokens_used = (0..num_providers).map(|_| AtomicU64::new(0)).collect();
        let token_limits = vec![0; num_providers];
        let health = (0..num_providers).map(|_| AtomicU8::new(0)).collect();

        Self {
            strategy,
            counter: AtomicU64::new(0),
            latencies,
            connections,
            tokens_used,
            token_limits,
            sticky_map: DashMap::new(),
            breakers: Vec::new(),
            outlier: None,
            health,
        }
    }

    /// Attach circuit breakers and an outlier detector built from the
    /// handler's `resilience` config. Idempotent: calling twice
    /// replaces the previous bundle, which is what the pipeline does
    /// on hot reload.
    pub fn with_resilience(
        mut self,
        num_providers: usize,
        cb_failure_threshold: u32,
        cb_success_threshold: u32,
        cb_open_duration_secs: u64,
        outlier: Option<OutlierDetectorConfig>,
    ) -> Self {
        self.breakers = (0..num_providers)
            .map(|_| {
                Arc::new(CircuitBreaker::new(
                    cb_failure_threshold,
                    cb_success_threshold,
                    std::time::Duration::from_secs(cb_open_duration_secs),
                ))
            })
            .collect();
        self.outlier = outlier.map(|cfg| Arc::new(OutlierDetector::new(cfg)));
        self
    }

    /// Read access to the per-provider circuit breakers (mostly for
    /// admin diagnostics and tests).
    pub fn breakers(&self) -> &[Arc<CircuitBreaker>] {
        &self.breakers
    }

    /// Mark a provider's last response as a success (for outlier
    /// detection + circuit breaker recovery). Called by the AI client
    /// after a 2xx response.
    pub fn record_provider_success(&self, provider_idx: usize, provider_name: &str) {
        if let Some(b) = self.breakers.get(provider_idx) {
            b.record_success();
        }
        if let Some(d) = &self.outlier {
            d.record_success(provider_name);
        }
    }

    /// Mark a provider's last response as a failure (5xx, timeout,
    /// transport error). Trips the breaker after enough consecutive
    /// failures, and feeds the sliding-window outlier detector.
    pub fn record_provider_failure(&self, provider_idx: usize, provider_name: &str) {
        if let Some(b) = self.breakers.get(provider_idx) {
            b.record_failure();
        }
        if let Some(d) = &self.outlier {
            d.record_failure(provider_name);
            let _ = d.check_ejections();
        }
    }

    /// Set a provider's active-probe health flag (used by the
    /// background health-check task).
    pub fn set_provider_health(&self, provider_idx: usize, healthy: bool) {
        if let Some(slot) = self.health.get(provider_idx) {
            slot.store(if healthy { 1 } else { 2 }, Ordering::Relaxed);
        }
    }

    fn provider_eligible(&self, idx: usize, name: &str) -> bool {
        // Active health probe verdict (default unknown is treated as healthy).
        let health_ok = self
            .health
            .get(idx)
            .map(|h| h.load(Ordering::Relaxed) != 2)
            .unwrap_or(true);
        if !health_ok {
            return false;
        }
        // Circuit-breaker gate.
        let breaker_ok = self
            .breakers
            .get(idx)
            .map(|b| b.allow_request())
            .unwrap_or(true);
        if !breaker_ok {
            return false;
        }
        // Outlier ejection.
        if let Some(d) = &self.outlier {
            if d.is_ejected(name) {
                return false;
            }
        }
        true
    }

    /// Set the token-per-minute limit for a specific provider.
    pub fn set_token_limit(&mut self, provider_idx: usize, limit: u64) {
        if provider_idx < self.token_limits.len() {
            self.token_limits[provider_idx] = limit;
        }
    }

    /// Record observed latency (in microseconds) for a provider.
    pub fn record_latency(&self, provider_idx: usize, latency_us: u64) {
        if let Some(slot) = self.latencies.get(provider_idx) {
            slot.store(latency_us, Ordering::Relaxed);
        }
    }

    /// Increment the in-flight connection count for a provider.
    pub fn record_connect(&self, provider_idx: usize) {
        if let Some(slot) = self.connections.get(provider_idx) {
            slot.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrement the in-flight connection count for a provider.
    pub fn record_disconnect(&self, provider_idx: usize) {
        if let Some(slot) = self.connections.get(provider_idx) {
            slot.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Record tokens consumed by a provider in the current minute window.
    pub fn record_tokens(&self, provider_idx: usize, tokens: u64) {
        if let Some(slot) = self.tokens_used.get(provider_idx) {
            slot.fetch_add(tokens, Ordering::Relaxed);
        }
    }

    /// Reset token counters (call at the start of each minute window).
    pub fn reset_tokens(&self) {
        for slot in &self.tokens_used {
            slot.store(0, Ordering::Relaxed);
        }
    }

    /// Select a provider using sticky (session affinity) routing.
    /// If the session key already has a cached provider, returns it.
    /// Otherwise, selects via round robin and caches the result.
    pub fn select_sticky(&self, providers: &[ProviderConfig], session_key: &str) -> Option<usize> {
        let enabled: Vec<(usize, &ProviderConfig)> = providers
            .iter()
            .enumerate()
            .filter(|(_, p)| p.enabled)
            .collect();

        if enabled.is_empty() {
            return None;
        }

        // Check cache first
        if let Some(cached) = self.sticky_map.get(session_key) {
            let idx = *cached;
            // Verify the cached provider is still enabled
            if providers.get(idx).is_some_and(|p| p.enabled) {
                return Some(idx);
            }
            // Cached provider is gone or disabled, remove stale entry
            drop(cached);
            self.sticky_map.remove(session_key);
        }

        // Fall back to round robin for new sessions
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let selected = enabled[counter as usize % enabled.len()].0;
        self.sticky_map.insert(session_key.to_string(), selected);
        Some(selected)
    }

    /// Select a provider index from the list of enabled providers.
    /// Returns `None` if no providers are enabled.
    ///
    /// When a `resilience` config is attached (circuit breakers,
    /// outlier detection, or active health probes), the eligible set
    /// is filtered to providers whose state machines pass. If every
    /// provider is currently ejected, the router falls back to the
    /// unfiltered enabled set rather than returning `None`, on the
    /// theory that sending traffic to a flaky provider beats failing
    /// the request entirely.
    pub fn select(&self, providers: &[ProviderConfig]) -> Option<usize> {
        let enabled: Vec<(usize, &ProviderConfig)> = providers
            .iter()
            .enumerate()
            .filter(|(_, p)| p.enabled)
            .collect();

        if enabled.is_empty() {
            return None;
        }

        // Apply resilience filtering when configured. Fall through to
        // the full enabled list on the all-ejected edge case.
        let eligible: Vec<(usize, &ProviderConfig)> = enabled
            .iter()
            .filter(|(idx, p)| self.provider_eligible(*idx, p.name.as_str()))
            .cloned()
            .collect();
        let enabled = if eligible.is_empty() {
            enabled
        } else {
            eligible
        };

        match self.strategy {
            RoutingStrategy::RoundRobin => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed);
                Some(enabled[idx as usize % enabled.len()].0)
            }
            RoutingStrategy::Weighted => {
                let total: u32 = enabled.iter().map(|(_, p)| p.weight).sum();
                if total == 0 {
                    return Some(enabled[0].0);
                }
                let counter = self.counter.fetch_add(1, Ordering::Relaxed);
                // LCG-derived pseudo-random selection for weighted distribution
                let mut target =
                    (counter.wrapping_mul(6364136223846793005).wrapping_add(1)) % total as u64;
                for &(idx, provider) in &enabled {
                    if target < provider.weight as u64 {
                        return Some(idx);
                    }
                    target -= provider.weight as u64;
                }
                Some(enabled[0].0)
            }
            RoutingStrategy::FallbackChain => {
                // Priority order: lowest priority number is first choice
                let mut sorted = enabled.clone();
                sorted.sort_by_key(|(_, p)| p.priority.unwrap_or(u32::MAX));
                Some(sorted[0].0)
            }
            RoutingStrategy::Random => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed);
                let hash = idx
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                Some(enabled[hash as usize % enabled.len()].0)
            }
            RoutingStrategy::LowestLatency => {
                // Select provider with lowest observed latency.
                // If no latency data recorded yet, fall back to round robin.
                let mut best_idx = None;
                let mut best_latency = u64::MAX;
                let mut has_data = false;

                for &(idx, _) in &enabled {
                    let latency = self
                        .latencies
                        .get(idx)
                        .map_or(0, |l| l.load(Ordering::Relaxed));
                    if latency > 0 {
                        has_data = true;
                        if latency < best_latency {
                            best_latency = latency;
                            best_idx = Some(idx);
                        }
                    }
                }

                if has_data {
                    best_idx.or(Some(enabled[0].0))
                } else {
                    // No latency data yet, use round robin
                    let counter = self.counter.fetch_add(1, Ordering::Relaxed);
                    Some(enabled[counter as usize % enabled.len()].0)
                }
            }
            RoutingStrategy::LeastConnections => {
                // Select provider with fewest in-flight requests
                let mut best_idx = enabled[0].0;
                let mut best_conns = u32::MAX;

                for &(idx, _) in &enabled {
                    let conns = self
                        .connections
                        .get(idx)
                        .map_or(0, |c| c.load(Ordering::Relaxed));
                    if conns < best_conns {
                        best_conns = conns;
                        best_idx = idx;
                    }
                }

                Some(best_idx)
            }
            RoutingStrategy::CostOptimized => {
                // Favor providers with lower weight (cheaper) when utilization is similar.
                // Score = connections * 1000 + weight, pick the lowest score.
                let mut best_idx = enabled[0].0;
                let mut best_score = u64::MAX;

                for &(idx, provider) in &enabled {
                    let conns = self
                        .connections
                        .get(idx)
                        .map_or(0, |c| c.load(Ordering::Relaxed))
                        as u64;
                    // Scale connections heavily so utilization dominates,
                    // but weight breaks ties in favor of cheaper providers.
                    let score = conns * 1000 + provider.weight as u64;
                    if score < best_score {
                        best_score = score;
                        best_idx = idx;
                    }
                }

                Some(best_idx)
            }
            RoutingStrategy::TokenRate => {
                // Select provider with the most remaining token-per-minute capacity
                let mut best_idx = enabled[0].0;
                let mut best_remaining: i64 = i64::MIN;

                for &(idx, _) in &enabled {
                    let limit = self.token_limits.get(idx).copied().unwrap_or(0);
                    let used = self
                        .tokens_used
                        .get(idx)
                        .map_or(0, |t| t.load(Ordering::Relaxed));
                    let remaining = limit as i64 - used as i64;
                    if remaining > best_remaining {
                        best_remaining = remaining;
                        best_idx = idx;
                    }
                }

                Some(best_idx)
            }
            RoutingStrategy::Sticky => {
                // Sticky without a session key falls back to round robin.
                // Callers should use select_sticky() instead for session affinity.
                let counter = self.counter.fetch_add(1, Ordering::Relaxed);
                Some(enabled[counter as usize % enabled.len()].0)
            }
            RoutingStrategy::Race => {
                // Pick the first eligible provider for the basic
                // `select` API. The fan-out is performed by the AI
                // client when it sees `RoutingStrategy::Race`; this
                // path is the fallback when only one provider is
                // eligible.
                Some(enabled[0].0)
            }
        }
    }

    /// Returns true when the configured strategy is `Race`. The AI
    /// client uses this to decide whether to fan out the request.
    pub fn is_race(&self) -> bool {
        matches!(self.strategy, RoutingStrategy::Race)
    }

    /// Return every eligible provider index. Used by the race
    /// strategy and the shadow request orchestration.
    pub fn eligible_indices(&self, providers: &[ProviderConfig]) -> Vec<usize> {
        providers
            .iter()
            .enumerate()
            .filter(|(idx, p)| p.enabled && self.provider_eligible(*idx, p.name.as_str()))
            .map(|(idx, _)| idx)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_provider(
        name: &str,
        weight: u32,
        priority: Option<u32>,
        enabled: bool,
    ) -> ProviderConfig {
        ProviderConfig {
            name: name.to_string(),
            provider_type: None,
            api_key: None,
            base_url: None,
            models: Vec::new(),
            default_model: None,
            model_map: HashMap::new(),
            weight,
            priority,
            enabled,
            max_retries: None,
            timeout_ms: None,
            organization: None,
            api_version: None,
            host_override: None,
            disable_forwarded_host_header: false,
        }
    }

    // --- RoundRobin Tests ---

    #[test]
    fn round_robin_distribution() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len());
        let mut counts = [0u32; 3];
        for _ in 0..30 {
            let idx = router.select(&providers).unwrap();
            counts[idx] += 1;
        }
        assert_eq!(counts[0], 10);
        assert_eq!(counts[1], 10);
        assert_eq!(counts[2], 10);
    }

    #[test]
    fn round_robin_skips_disabled() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, false),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len());
        for _ in 0..10 {
            let idx = router.select(&providers).unwrap();
            assert_ne!(idx, 1, "disabled provider should never be selected");
        }
    }

    #[test]
    fn no_enabled_providers_returns_none() {
        let providers = vec![
            make_provider("a", 1, None, false),
            make_provider("b", 1, None, false),
        ];
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len());
        assert!(router.select(&providers).is_none());
    }

    #[test]
    fn empty_providers_returns_none() {
        let providers: Vec<ProviderConfig> = Vec::new();
        let router = Router::new(RoutingStrategy::RoundRobin, 0);
        assert!(router.select(&providers).is_none());
    }

    // --- Weighted Tests ---

    #[test]
    fn weighted_selection() {
        let providers = vec![
            make_provider("heavy", 9, None, true),
            make_provider("light", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::Weighted, providers.len());
        let mut counts = [0u32; 2];
        for _ in 0..100 {
            let idx = router.select(&providers).unwrap();
            counts[idx] += 1;
        }
        assert!(
            counts[0] > counts[1],
            "heavy provider ({}) should get more than light ({})",
            counts[0],
            counts[1]
        );
    }

    // --- FallbackChain Tests ---

    #[test]
    fn fallback_chain_priority() {
        let providers = vec![
            make_provider("low-priority", 1, Some(10), true),
            make_provider("high-priority", 1, Some(1), true),
            make_provider("medium-priority", 1, Some(5), true),
        ];
        let router = Router::new(RoutingStrategy::FallbackChain, providers.len());
        for _ in 0..10 {
            let idx = router.select(&providers).unwrap();
            assert_eq!(idx, 1, "should always pick high-priority provider");
        }
    }

    #[test]
    fn fallback_chain_skips_disabled() {
        let providers = vec![
            make_provider("best", 1, Some(1), false),
            make_provider("second", 1, Some(2), true),
            make_provider("third", 1, Some(3), true),
        ];
        let router = Router::new(RoutingStrategy::FallbackChain, providers.len());
        let idx = router.select(&providers).unwrap();
        assert_eq!(idx, 1, "should pick second-best since best is disabled");
    }

    // --- Random Tests ---

    #[test]
    fn random_selects_from_enabled() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, false),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::Random, providers.len());
        for _ in 0..20 {
            let idx = router.select(&providers).unwrap();
            assert_ne!(idx, 1, "disabled provider should never be selected");
        }
    }

    // --- Deserialization Tests ---

    #[test]
    fn routing_strategy_deserialize() {
        let json = serde_json::json!("round_robin");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        assert!(matches!(strategy, RoutingStrategy::RoundRobin));

        let json = serde_json::json!("fallback_chain");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        assert!(matches!(strategy, RoutingStrategy::FallbackChain));

        let json = serde_json::json!("lowest_latency");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        assert!(matches!(strategy, RoutingStrategy::LowestLatency));

        let json = serde_json::json!("least_connections");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        assert!(matches!(strategy, RoutingStrategy::LeastConnections));

        let json = serde_json::json!("cost_optimized");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        assert!(matches!(strategy, RoutingStrategy::CostOptimized));

        let json = serde_json::json!("token_rate");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        assert!(matches!(strategy, RoutingStrategy::TokenRate));

        let json = serde_json::json!("sticky");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        assert!(matches!(strategy, RoutingStrategy::Sticky));
    }

    // --- LowestLatency Tests ---

    #[test]
    fn lowest_latency_picks_fastest() {
        let providers = vec![
            make_provider("slow", 1, None, true),
            make_provider("fast", 1, None, true),
            make_provider("medium", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::LowestLatency, providers.len());

        router.record_latency(0, 5000); // 5ms
        router.record_latency(1, 1000); // 1ms
        router.record_latency(2, 3000); // 3ms

        for _ in 0..10 {
            let idx = router.select(&providers).unwrap();
            assert_eq!(idx, 1, "should always pick the fastest provider");
        }
    }

    #[test]
    fn lowest_latency_falls_back_to_round_robin_without_data() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::LowestLatency, providers.len());

        // No latency data recorded, should round robin
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            let idx = router.select(&providers).unwrap();
            seen.insert(idx);
        }
        assert!(
            seen.len() > 1,
            "should distribute across providers without latency data"
        );
    }

    #[test]
    fn lowest_latency_skips_disabled() {
        let providers = vec![
            make_provider("fast-disabled", 1, None, false),
            make_provider("slow-enabled", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::LowestLatency, providers.len());
        router.record_latency(0, 100);
        router.record_latency(1, 5000);

        let idx = router.select(&providers).unwrap();
        assert_eq!(idx, 1, "should skip disabled provider even if faster");
    }

    // --- LeastConnections Tests ---

    #[test]
    fn least_connections_picks_least_loaded() {
        let providers = vec![
            make_provider("busy", 1, None, true),
            make_provider("idle", 1, None, true),
            make_provider("moderate", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::LeastConnections, providers.len());

        // Simulate connections
        for _ in 0..5 {
            router.record_connect(0);
        }
        for _ in 0..3 {
            router.record_connect(2);
        }
        // Provider 1 has 0 connections

        let idx = router.select(&providers).unwrap();
        assert_eq!(idx, 1, "should pick provider with fewest connections");
    }

    #[test]
    fn record_connect_disconnect_updates_state() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::LeastConnections, providers.len());

        // Both start at 0, a gets loaded
        router.record_connect(0);
        router.record_connect(0);
        router.record_connect(0);

        let idx = router.select(&providers).unwrap();
        assert_eq!(idx, 1, "b should be picked (0 connections)");

        // Disconnect all from a, connect to b
        router.record_disconnect(0);
        router.record_disconnect(0);
        router.record_disconnect(0);
        router.record_connect(1);

        let idx = router.select(&providers).unwrap();
        assert_eq!(
            idx, 0,
            "a should be picked (0 connections after disconnect)"
        );
    }

    // --- CostOptimized Tests ---

    #[test]
    fn cost_optimized_picks_cheaper_when_utilization_similar() {
        let providers = vec![
            make_provider("expensive", 10, None, true),
            make_provider("cheap", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::CostOptimized, providers.len());

        // Both have 0 connections, should prefer cheaper (lower weight)
        let idx = router.select(&providers).unwrap();
        assert_eq!(
            idx, 1,
            "should pick cheaper provider when utilization is equal"
        );
    }

    #[test]
    fn cost_optimized_avoids_overloaded_cheap() {
        let providers = vec![
            make_provider("expensive-idle", 10, None, true),
            make_provider("cheap-busy", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::CostOptimized, providers.len());

        // Make the cheap provider very busy
        for _ in 0..20 {
            router.record_connect(1);
        }

        let idx = router.select(&providers).unwrap();
        assert_eq!(
            idx, 0,
            "should pick idle expensive provider over overloaded cheap one"
        );
    }

    // --- TokenRate Tests ---

    #[test]
    fn token_rate_picks_most_remaining_capacity() {
        let providers = vec![
            make_provider("nearly-full", 1, None, true),
            make_provider("mostly-empty", 1, None, true),
            make_provider("half-full", 1, None, true),
        ];
        let mut router = Router::new(RoutingStrategy::TokenRate, providers.len());
        router.set_token_limit(0, 10000);
        router.set_token_limit(1, 10000);
        router.set_token_limit(2, 10000);

        router.record_tokens(0, 9000); // 1000 remaining
        router.record_tokens(1, 1000); // 9000 remaining
        router.record_tokens(2, 5000); // 5000 remaining

        let idx = router.select(&providers).unwrap();
        assert_eq!(idx, 1, "should pick provider with most remaining capacity");
    }

    #[test]
    fn token_rate_respects_different_limits() {
        let providers = vec![
            make_provider("small-limit", 1, None, true),
            make_provider("large-limit", 1, None, true),
        ];
        let mut router = Router::new(RoutingStrategy::TokenRate, providers.len());
        router.set_token_limit(0, 1000);
        router.set_token_limit(1, 100000);

        router.record_tokens(0, 500); // 500 remaining
        router.record_tokens(1, 50000); // 50000 remaining

        let idx = router.select(&providers).unwrap();
        assert_eq!(
            idx, 1,
            "should pick provider with more absolute remaining capacity"
        );
    }

    #[test]
    fn token_rate_reset_clears_counters() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
        ];
        let mut router = Router::new(RoutingStrategy::TokenRate, providers.len());
        router.set_token_limit(0, 10000);
        router.set_token_limit(1, 10000);

        router.record_tokens(0, 9000);
        router.record_tokens(1, 1000);

        // Before reset, b has more capacity
        let idx = router.select(&providers).unwrap();
        assert_eq!(idx, 1);

        // After reset, both have full capacity, picks first
        router.reset_tokens();
        let idx = router.select(&providers).unwrap();
        assert_eq!(
            idx, 0,
            "after reset both have equal capacity, should pick first"
        );
    }

    // --- Sticky Tests ---

    #[test]
    fn sticky_same_key_same_provider() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::Sticky, providers.len());

        let first = router.select_sticky(&providers, "user-123").unwrap();

        // Same key should always return the same provider
        for _ in 0..20 {
            let idx = router.select_sticky(&providers, "user-123").unwrap();
            assert_eq!(
                idx, first,
                "same session key should always route to same provider"
            );
        }
    }

    #[test]
    fn sticky_different_keys_may_differ() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::Sticky, providers.len());

        let mut assigned = std::collections::HashSet::new();
        for i in 0..30 {
            let key = format!("user-{}", i);
            let idx = router.select_sticky(&providers, &key).unwrap();
            assigned.insert(idx);
        }
        // With 30 different keys and 3 providers, we should hit multiple providers
        assert!(
            assigned.len() > 1,
            "different keys should distribute across providers"
        );
    }

    #[test]
    fn sticky_handles_disabled_cached_provider() {
        let mut providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::Sticky, providers.len());

        let first = router.select_sticky(&providers, "user-x").unwrap();

        // Disable the cached provider
        providers[first].enabled = false;

        // Should pick the other provider now
        let second = router.select_sticky(&providers, "user-x").unwrap();
        assert_ne!(
            second, first,
            "should re-route when cached provider is disabled"
        );
        assert!(providers[second].enabled, "should pick an enabled provider");
    }

    #[test]
    fn sticky_no_enabled_returns_none() {
        let providers = vec![
            make_provider("a", 1, None, false),
            make_provider("b", 1, None, false),
        ];
        let router = Router::new(RoutingStrategy::Sticky, providers.len());
        assert!(router.select_sticky(&providers, "user-1").is_none());
    }

    // --- record_latency Tests ---

    #[test]
    fn record_latency_updates_state() {
        let router = Router::new(RoutingStrategy::LowestLatency, 3);

        router.record_latency(0, 1000);
        router.record_latency(1, 2000);
        router.record_latency(2, 500);

        assert_eq!(router.latencies[0].load(Ordering::Relaxed), 1000);
        assert_eq!(router.latencies[1].load(Ordering::Relaxed), 2000);
        assert_eq!(router.latencies[2].load(Ordering::Relaxed), 500);
    }

    #[test]
    fn record_latency_out_of_bounds_is_noop() {
        let router = Router::new(RoutingStrategy::LowestLatency, 2);
        // Should not panic
        router.record_latency(99, 1000);
    }

    #[test]
    fn record_connect_disconnect_out_of_bounds_is_noop() {
        let router = Router::new(RoutingStrategy::LeastConnections, 2);
        // Should not panic
        router.record_connect(99);
        router.record_disconnect(99);
    }
}
