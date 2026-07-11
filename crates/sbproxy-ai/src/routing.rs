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
    /// WOR-798: choose the provider with the lowest recent token
    /// throughput in the current minute window, regardless of any
    /// configured TPM limit. Unlike `TokenRate` (which picks by
    /// remaining headroom against a per-provider limit), this picks
    /// by absolute observed throughput, so it does the right thing
    /// for self-hosted vLLM / SGLang pools where the operator does
    /// not pre-declare a token cap. Untried providers (zero
    /// observed tokens) sort lowest and are explored first.
    LeastTokenUsage,
    /// WOR-798: prefix-affinity routing for self-hosted LLM pools
    /// (vLLM, SGLang) that keep a per-worker KV cache of recently-
    /// processed prompt prefixes. Hash a stable prefix of the
    /// request body (the first N bytes of the JSON-serialised
    /// payload, captured at dispatch time) to an enabled-provider
    /// index, so two requests sharing the same prefix land on the
    /// same upstream and reuse its KV cache rather than warming a
    /// cold one. The hash is deterministic, modular over the
    /// eligible-providers count, and stable across reloads as long
    /// as the provider list does not reorder.
    ///
    /// Falls back to round-robin when the dispatcher cannot extract
    /// a prefix (e.g. the surface has no body, or it is an opaque
    /// upgrade request).
    PrefixAffinity,
    /// Pin a session key to the same provider across requests.
    Sticky,
    /// Send the request concurrently to every eligible provider and
    /// return the first acceptable response. Cancels the losers.
    /// Trades doubled spend for halved latency on the chat-first-token
    /// path; useful when every millisecond of TTFT matters.
    Race,
    /// Power-of-Two-Choices over observed latency (Helicone-style):
    /// sample two eligible providers and route to the one with the
    /// lower recently-observed latency. Cuts tail latency under skewed
    /// load versus always picking the single lowest-latency provider
    /// (which herds). An untried provider is explored first; with a
    /// single eligible provider it is returned directly. The signal is
    /// the most recent observed latency; an EWMA-decay refinement is a
    /// follow-up.
    PeakEwma,
    /// Try a sequence of (provider, model) tiers from cheapest to
    /// most expensive. Each tier's response is graded against a
    /// quality threshold; if the response falls below threshold,
    /// is empty, or is refused, the request retries on the next
    /// tier. Theoretically Pareto-optimal under standard assumptions
    /// (see arxiv 2410.10347, "A Unified Approach to Routing and
    /// Cascading for LLMs"). Streaming requests dispatch only to
    /// the first tier; mid-stream retry is out of scope for v1.
    Cascade(CascadeConfig),
    /// Cost/quality routing (WOR-797): score the prompt's difficulty and
    /// route simple prompts to a cheap model and hard prompts to a
    /// frontier model, on a `cost_threshold` dial. The dispatcher reads
    /// the prompt and applies [`crate::cost_quality`]; `select` returns
    /// the cheap provider as a deterministic fallback.
    CostQuality(crate::cost_quality::CostQualityConfig),
    /// Closed-loop outcome-aware routing (WOR-1541): score candidates by
    /// the realized cost-per-success fed back from completed requests
    /// ([`crate::routing_feedback`]), demoting providers whose refusal or
    /// error rate is climbing. Falls back to round-robin while providers
    /// are still warming up.
    OutcomeAware,
}

/// Configuration for the [`RoutingStrategy::Cascade`] variant.
///
/// `tiers` is ordered: the first entry is tried first, the last
/// entry is the final fallback. `max_total_cost`, when set, is a
/// best-effort budget cap (in micro-USD) that aborts the cascade
/// once the cumulative estimated cost of attempted tiers would
/// exceed it. The cap is checked before dispatching each tier so
/// a single in-flight tier can still finish.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CascadeConfig {
    /// Ordered list of tiers to try. Must contain at least one
    /// entry; the config compiler rejects empty lists.
    pub tiers: Vec<CascadeTier>,
    /// Optional cumulative cost cap across the cascade. The unit
    /// is the same micro-USD scale used by the cost catalog
    /// (`crate::budget::estimate_cost`). `None` disables the cap.
    #[serde(default)]
    pub max_total_cost: Option<u64>,
}

/// One step of a [`CascadeConfig`].
///
/// `quality_threshold` is interpreted against the response's
/// `confidence_score` field (a JSON number in `[0.0, 1.0]`). When
/// the field is absent the response is treated as quality `1.0`
/// and accepted; cascade therefore does not retry providers that
/// do not emit a score. Richer scoring (classifier-driven, CEL
/// expressions) is a follow-up.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CascadeTier {
    /// Name of the provider in [`crate::handler::AiHandlerConfig::providers`].
    pub provider_id: String,
    /// Model id to send to that provider for this tier.
    pub model: String,
    /// Minimum acceptable `confidence_score` for this tier's
    /// response. Responses scoring below this value trigger a
    /// retry on the next tier.
    pub quality_threshold: f32,
    /// Optional per-tier cost cap in micro-USD. When set, the
    /// cascade will not dispatch this tier if doing so would push
    /// the cumulative cost above the cap.
    #[serde(default)]
    pub cost_cap: Option<u64>,
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

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("strategy", &self.strategy)
            .field("num_providers", &self.latencies.len())
            .finish_non_exhaustive()
    }
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

    /// WOR-798: record tokens consumed against a provider looked up by
    /// name. Used by the dispatch path, which knows the provider's
    /// configured name from `ProviderConfig.name` but not its index.
    /// Silently no-ops on an unknown name so a config rename or hot
    /// reload cannot panic an in-flight request.
    pub fn record_tokens_for_provider(
        &self,
        providers: &[ProviderConfig],
        provider_name: &str,
        tokens: u64,
    ) {
        if tokens == 0 {
            return;
        }
        if let Some((idx, _)) = providers
            .iter()
            .enumerate()
            .find(|(_, p)| p.name == provider_name)
        {
            self.record_tokens(idx, tokens);
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
        let picked = self.select_inner(providers);
        // WOR-798: emit the LB-decision metric on every successful
        // pick. The strategy label is the active variant's
        // snake_case name; the provider label is the chosen
        // provider's configured name. A `None` return (no enabled
        // providers) is intentionally not recorded; that surfaces
        // through error metrics elsewhere.
        if let Some(idx) = picked {
            if let Some(p) = providers.get(idx) {
                crate::ai_metrics::record_lb_decision(self.strategy_name(), &p.name);
            }
        }
        picked
    }

    /// Pick an enabled provider whose name is on `allowed`. Empty
    /// `allowed` means "no restriction" and behaves identically to
    /// [`Self::select`]. Used by the AI dispatch hot path to enforce
    /// per-virtual-key `allowed_providers` without the call site
    /// having to clone the provider vec.
    pub fn select_with_allowed(
        &self,
        providers: &[ProviderConfig],
        allowed: &[String],
    ) -> Option<usize> {
        if allowed.is_empty() {
            return self.select(providers);
        }
        let picked = self.select_inner_filtered(providers, &|p| {
            allowed.iter().any(|a| a.as_str() == p.name.as_str())
        });
        if let Some(idx) = picked {
            if let Some(p) = providers.get(idx) {
                crate::ai_metrics::record_lb_decision(self.strategy_name(), &p.name);
            }
        }
        picked
    }

    /// `select_inner` with an additional predicate. Mirrors the
    /// resilience-filter fallback: when the additional filter rejects
    /// every otherwise-enabled provider, the router returns `None`
    /// instead of falling back, because the operator's
    /// `allowed_providers` block is a hard policy gate, not a hint.
    fn select_inner_filtered(
        &self,
        providers: &[ProviderConfig],
        extra: &dyn Fn(&ProviderConfig) -> bool,
    ) -> Option<usize> {
        let enabled: Vec<(usize, &ProviderConfig)> = providers
            .iter()
            .enumerate()
            .filter(|(_, p)| p.enabled && extra(p))
            .collect();
        if enabled.is_empty() {
            return None;
        }
        // From here, reuse the same strategy dispatch as
        // `select_inner`. We do not reapply the resilience filter on
        // top of `extra` because the explicit allowlist already
        // narrows the set; resilience ejection on a narrowed set
        // produces too many false-deny outcomes in practice.
        match self.strategy {
            RoutingStrategy::RoundRobin => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed);
                Some(enabled[idx as usize % enabled.len()].0)
            }
            RoutingStrategy::FallbackChain => {
                let mut sorted = enabled.clone();
                sorted.sort_by_key(|(_, p)| p.priority.unwrap_or(u32::MAX));
                Some(sorted[0].0)
            }
            // Outcome-aware routing works on the narrowed set directly:
            // realized cost-per-success is provider-keyed, so the allowlist
            // simply restricts the candidate pool.
            RoutingStrategy::OutcomeAware => self.select_outcome_aware(&enabled),
            // For other non-trivial strategies fall back to the unfiltered
            // dispatch on the narrowed set. The shape of the strategy
            // body matches `select_inner` so behaviour stays consistent.
            _ => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed);
                Some(enabled[idx as usize % enabled.len()].0)
            }
        }
    }

    fn select_inner(&self, providers: &[ProviderConfig]) -> Option<usize> {
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
            RoutingStrategy::PeakEwma => {
                // Power-of-Two-Choices over observed latency: sample two
                // distinct eligible providers and route to the lower
                // latency. An untried provider (latency 0) sorts lowest,
                // so the pair naturally explores it once. With a single
                // eligible provider, return it.
                if enabled.len() == 1 {
                    return Some(enabled[0].0);
                }
                let c = self.counter.fetch_add(1, Ordering::Relaxed);
                let a =
                    (c.wrapping_mul(6364136223846793005).wrapping_add(1)) as usize % enabled.len();
                let mut b = (c.wrapping_mul(2862933555777941757).wrapping_add(3037000493)) as usize
                    % enabled.len();
                if b == a {
                    b = (a + 1) % enabled.len();
                }
                let lat = |i: usize| {
                    self.latencies
                        .get(enabled[i].0)
                        .map_or(0, |l| l.load(Ordering::Relaxed))
                };
                Some(enabled[if lat(a) <= lat(b) { a } else { b }].0)
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
            RoutingStrategy::PrefixAffinity => {
                // Basic `select` API has no prefix in hand (the
                // dispatcher routes through `select_with_prefix` when
                // it has the request body). Fall back to round-robin
                // so a callsite that has not been threaded with the
                // prefix-aware API still gets a deterministic answer.
                let counter = self.counter.fetch_add(1, Ordering::Relaxed);
                Some(enabled[counter as usize % enabled.len()].0)
            }
            RoutingStrategy::LeastTokenUsage => {
                // WOR-798: select the eligible provider with the
                // smallest tokens_used in the current minute window.
                // An untried provider has tokens_used = 0 and sorts
                // first, so an empty pool naturally explores every
                // upstream before settling. Ties are broken by the
                // first match in enabled order, which gives stable
                // routing under no load.
                let mut best_idx = enabled[0].0;
                let mut best_used = u64::MAX;
                for &(idx, _) in &enabled {
                    let used = self
                        .tokens_used
                        .get(idx)
                        .map_or(0, |t| t.load(Ordering::Relaxed));
                    if used < best_used {
                        best_used = used;
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
            RoutingStrategy::Cascade(ref cfg) => {
                // The cascade dispatcher walks `cfg.tiers` itself
                // (via `cascade_config()`); the basic `select` API
                // just hands back the first tier's provider so
                // callers that do not engage the cascade path still
                // get a deterministic provider. If the first tier's
                // provider name doesn't match any configured
                // provider, fall through to the first enabled one
                // so we never return None for misconfigured cascades.
                if let Some(first) = cfg.tiers.first() {
                    for &(idx, p) in &enabled {
                        if p.name == first.provider_id {
                            return Some(idx);
                        }
                    }
                }
                Some(enabled[0].0)
            }
            RoutingStrategy::CostQuality(ref cfg) => {
                // The cost/quality dispatcher scores the prompt and picks
                // the cheap or frontier provider itself (via
                // `cost_quality_config()`); `select` hands back the cheap
                // provider as a deterministic fallback for callers that do
                // not engage that path.
                for &(idx, p) in &enabled {
                    if p.name == cfg.cheap_provider {
                        return Some(idx);
                    }
                }
                Some(enabled[0].0)
            }
            RoutingStrategy::OutcomeAware => self.select_outcome_aware(&enabled),
        }
    }

    /// Pick the enabled provider with the best realized cost-per-success
    /// from the global feedback store. Falls back to round-robin while
    /// providers warm up (the store explores under-sampled candidates
    /// first), so a fresh deployment behaves exactly like round-robin
    /// until it has data.
    fn select_outcome_aware(&self, enabled: &[(usize, &ProviderConfig)]) -> Option<usize> {
        if enabled.is_empty() {
            return None;
        }
        let names: Vec<&str> = enabled.iter().map(|(_, p)| p.name.as_str()).collect();
        let store = crate::routing_feedback::FeedbackStore::global();
        // While any candidate is still warming up, round-robin so every
        // provider earns an estimate (and a fresh deployment behaves like
        // round-robin until it has data).
        if store.needs_exploration(&names) {
            let idx = self.counter.fetch_add(1, Ordering::Relaxed);
            return Some(enabled[idx as usize % enabled.len()].0);
        }
        match store.best_among(&names) {
            Some(pos) => Some(enabled[pos].0),
            None => Some(enabled[0].0),
        }
    }

    /// Returns true when the configured strategy is `Race`. The AI
    /// client uses this to decide whether to fan out the request.
    pub fn is_race(&self) -> bool {
        matches!(self.strategy, RoutingStrategy::Race)
    }

    /// WOR-798: returns true when the configured strategy wants the
    /// dispatcher to route through [`Self::select_with_prefix`]
    /// (i.e. it benefits from a stable prompt prefix). The
    /// dispatcher checks this before doing the prefix-extraction
    /// work; non-prefix strategies skip the extraction entirely.
    pub fn is_prefix_affinity(&self) -> bool {
        matches!(self.strategy, RoutingStrategy::PrefixAffinity)
    }

    /// WOR-798: prefix-aware provider selection. `prefix_key` is a
    /// stable, request-derived byte slice (e.g. the first N bytes of
    /// the request body) that hashes deterministically to one
    /// enabled provider so two requests sharing the prefix land on
    /// the same upstream and reuse its KV cache.
    ///
    /// Uses FxHash for speed (the rule is "same prefix -> same
    /// provider", not "cryptographic identity"); ineligible
    /// providers are filtered out the same way [`Self::select`] does
    /// so the affinity respects circuit-breaker / outlier ejection.
    /// With a single eligible provider, returns it directly. With an
    /// empty `prefix_key`, falls back to the same round-robin that
    /// the basic [`Self::select`] uses for this strategy, so callers
    /// that get a None-prefix request still progress.
    pub fn select_with_prefix(
        &self,
        providers: &[ProviderConfig],
        prefix_key: &[u8],
    ) -> Option<usize> {
        let enabled: Vec<(usize, &ProviderConfig)> = providers
            .iter()
            .enumerate()
            .filter(|(_, p)| p.enabled)
            .collect();
        if enabled.is_empty() {
            return None;
        }
        let eligible: Vec<(usize, &ProviderConfig)> = enabled
            .iter()
            .filter(|(idx, p)| self.provider_eligible(*idx, p.name.as_str()))
            .cloned()
            .collect();
        let pool = if eligible.is_empty() {
            enabled
        } else {
            eligible
        };
        if pool.len() == 1 || prefix_key.is_empty() {
            // Sole-provider case OR no prefix in hand: fall through
            // to a deterministic pick. Sole-provider always returns
            // that provider; empty prefix uses round-robin so two
            // body-less requests do not herd onto one upstream.
            let pool_idx = if prefix_key.is_empty() {
                let counter = self.counter.fetch_add(1, Ordering::Relaxed);
                counter as usize % pool.len()
            } else {
                0
            };
            crate::ai_metrics::record_lb_decision(self.strategy_name(), &pool[pool_idx].1.name);
            return Some(pool[pool_idx].0);
        }
        // Deterministic hash of the prefix mod the eligible-pool
        // size. FNV-1a 64-bit; small, no_std, and stable across
        // releases. The pool's order matches `providers` (filtered),
        // so the result is stable as long as the provider list
        // does not reorder.
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in prefix_key {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        let picked_pool_idx = (hash % pool.len() as u64) as usize;
        let picked = pool[picked_pool_idx].0;
        crate::ai_metrics::record_lb_decision(self.strategy_name(), &pool[picked_pool_idx].1.name);
        Some(picked)
    }

    /// WOR-798: snake_case name of the active strategy, used as the
    /// `strategy` label on `sbproxy_ai_lb_decisions_total` and any
    /// other strategy-tagged telemetry.
    pub fn strategy_name(&self) -> &'static str {
        match self.strategy {
            RoutingStrategy::RoundRobin => "round_robin",
            RoutingStrategy::Weighted => "weighted",
            RoutingStrategy::FallbackChain => "fallback_chain",
            RoutingStrategy::Random => "random",
            RoutingStrategy::LowestLatency => "lowest_latency",
            RoutingStrategy::LeastConnections => "least_connections",
            RoutingStrategy::CostOptimized => "cost_optimized",
            RoutingStrategy::TokenRate => "token_rate",
            RoutingStrategy::LeastTokenUsage => "least_token_usage",
            RoutingStrategy::PrefixAffinity => "prefix_affinity",
            RoutingStrategy::Sticky => "sticky",
            RoutingStrategy::Race => "race",
            RoutingStrategy::PeakEwma => "peak_ewma",
            RoutingStrategy::Cascade(_) => "cascade",
            RoutingStrategy::CostQuality(_) => "cost_quality",
            RoutingStrategy::OutcomeAware => "outcome_aware",
        }
    }

    /// Returns true when the configured strategy is `Cascade`. The
    /// AI client uses this to decide whether to engage the
    /// tier-by-tier cascade dispatch path.
    pub fn is_cascade(&self) -> bool {
        matches!(self.strategy, RoutingStrategy::Cascade(_))
    }

    /// Borrow the cascade config when the configured strategy is
    /// [`RoutingStrategy::Cascade`].
    pub fn cascade_config(&self) -> Option<&CascadeConfig> {
        match &self.strategy {
            RoutingStrategy::Cascade(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Returns true when the configured strategy is `CostQuality`.
    pub fn is_cost_quality(&self) -> bool {
        matches!(self.strategy, RoutingStrategy::CostQuality(_))
    }

    /// Borrow the cost/quality config when the configured strategy is
    /// [`RoutingStrategy::CostQuality`].
    pub fn cost_quality_config(&self) -> Option<&crate::cost_quality::CostQualityConfig> {
        match &self.strategy {
            RoutingStrategy::CostQuality(cfg) => Some(cfg),
            _ => None,
        }
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
            name: name.into(),
            provider_type: None,
            deployment: None,
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
            allow_private_base_url: false,
            no_prompt_training: false,
            serve: None,
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

        let json = serde_json::json!("least_token_usage");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        assert!(matches!(strategy, RoutingStrategy::LeastTokenUsage));

        let json = serde_json::json!("prefix_affinity");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        assert!(matches!(strategy, RoutingStrategy::PrefixAffinity));

        let json = serde_json::json!("sticky");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        assert!(matches!(strategy, RoutingStrategy::Sticky));
    }

    // --- WOR-798: LeastTokenUsage + record_tokens_for_provider ---

    #[test]
    fn least_token_usage_explores_untried_provider_first() {
        // With no observations recorded yet, every provider has
        // tokens_used = 0 and ties on the first key (enabled order).
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::LeastTokenUsage, providers.len());
        // First pick lands on the first enabled provider on the tie.
        assert_eq!(router.select(&providers), Some(0));
    }

    #[test]
    fn least_token_usage_picks_provider_with_smallest_observed_throughput() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::LeastTokenUsage, providers.len());
        // Provider 0 has absorbed a big load; 1 has absorbed a little;
        // 2 is fresh. Selection must favor 2 (zero), then 1 if 2 is
        // hot.
        router.record_tokens(0, 10_000);
        router.record_tokens(1, 200);
        assert_eq!(router.select(&providers), Some(2));
        // After charging 2 past 1, the next pick swings to 1.
        router.record_tokens(2, 500);
        assert_eq!(router.select(&providers), Some(1));
    }

    #[test]
    fn least_token_usage_falls_back_to_first_when_single_provider() {
        let providers = vec![make_provider("only", 1, None, true)];
        let router = Router::new(RoutingStrategy::LeastTokenUsage, providers.len());
        router.record_tokens(0, 50_000);
        // Sole eligible provider is always returned, regardless of
        // load.
        assert_eq!(router.select(&providers), Some(0));
    }

    #[test]
    fn record_tokens_for_provider_routes_by_name() {
        let providers = vec![
            make_provider("openai", 1, None, true),
            make_provider("anthropic", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::LeastTokenUsage, providers.len());
        router.record_tokens_for_provider(&providers, "anthropic", 1234);
        // Anthropic carries the load now, so a fresh pick goes to
        // the cheap-by-comparison openai.
        assert_eq!(router.select(&providers), Some(0));
    }

    #[test]
    fn record_tokens_for_provider_silently_skips_unknown_name() {
        let providers = vec![make_provider("openai", 1, None, true)];
        let router = Router::new(RoutingStrategy::LeastTokenUsage, providers.len());
        // A renamed-away or never-existed provider must not panic;
        // a hot reload could leave a stale provider_name in flight.
        router.record_tokens_for_provider(&providers, "ghost", 999);
        // The openai counter stayed at zero, so select returns it.
        assert_eq!(router.select(&providers), Some(0));
    }

    #[test]
    fn record_tokens_for_provider_zero_is_a_no_op() {
        let providers = vec![make_provider("openai", 1, None, true)];
        let router = Router::new(RoutingStrategy::LeastTokenUsage, providers.len());
        router.record_tokens_for_provider(&providers, "openai", 0);
        // No charge, so a subsequent zero-charge select sees no
        // accumulated load and still returns the provider.
        assert_eq!(router.select(&providers), Some(0));
    }

    // --- WOR-798 PrefixAffinity ---

    #[test]
    fn prefix_affinity_same_prefix_same_provider() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
            make_provider("d", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::PrefixAffinity, providers.len());
        // Same prefix repeats to the same provider; routing is
        // deterministic across calls so vLLM/SGLang upstream keeps
        // its KV cache warm for that prefix.
        let prefix = b"You are a helpful assistant. The user asks: ";
        let first = router.select_with_prefix(&providers, prefix);
        for _ in 0..50 {
            assert_eq!(router.select_with_prefix(&providers, prefix), first);
        }
    }

    #[test]
    fn prefix_affinity_different_prefixes_distribute() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
            make_provider("d", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::PrefixAffinity, providers.len());
        // 100 prefix variations should hit more than one provider
        // (with a 4-way pool and FNV-1a we expect ~uniform).
        let mut counts = [0u32; 4];
        for i in 0..100u32 {
            let key = format!("prompt-variant-{i:03}");
            let idx = router
                .select_with_prefix(&providers, key.as_bytes())
                .expect("select");
            counts[idx] += 1;
        }
        // At least 3 of the 4 providers must have been hit; with FNV-1a
        // we'd be very unlucky to get a perfect 0 for any single bucket.
        let nonzero = counts.iter().filter(|c| **c > 0).count();
        assert!(
            nonzero >= 3,
            "expected prefix-affinity to spread across at least 3 providers; counts={counts:?}"
        );
    }

    #[test]
    fn prefix_affinity_empty_prefix_uses_round_robin() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::PrefixAffinity, providers.len());
        // Empty prefix means "no prefix in hand" — fall back to a
        // round-robin so body-less requests do not herd onto provider 0.
        let mut counts = [0u32; 3];
        for _ in 0..30 {
            let idx = router.select_with_prefix(&providers, b"").expect("select");
            counts[idx] += 1;
        }
        assert_eq!(counts, [10, 10, 10]);
    }

    #[test]
    fn prefix_affinity_single_provider_always_returns_it() {
        let providers = vec![make_provider("only", 1, None, true)];
        let router = Router::new(RoutingStrategy::PrefixAffinity, providers.len());
        assert_eq!(
            router.select_with_prefix(&providers, b"any-prefix"),
            Some(0)
        );
        assert_eq!(router.select_with_prefix(&providers, b""), Some(0));
    }

    #[test]
    fn prefix_affinity_skips_disabled_providers() {
        let providers = vec![
            make_provider("a", 1, None, false),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::PrefixAffinity, providers.len());
        // Any prefix that hashes into the pool must land on b or c,
        // never a (which is disabled).
        for i in 0..20u32 {
            let key = format!("variant-{i}");
            let idx = router
                .select_with_prefix(&providers, key.as_bytes())
                .expect("select");
            assert_ne!(idx, 0, "disabled provider a must not be picked");
        }
    }

    #[test]
    fn prefix_affinity_basic_select_falls_back_to_round_robin() {
        // The basic `select` API has no prefix in hand. For
        // PrefixAffinity we round-robin so callers that have not been
        // threaded with the prefix-aware API still get a balanced
        // distribution rather than always returning provider 0.
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::PrefixAffinity, providers.len());
        let mut counts = [0u32; 3];
        for _ in 0..30 {
            counts[router.select(&providers).unwrap()] += 1;
        }
        assert_eq!(counts, [10, 10, 10]);
    }

    #[test]
    fn is_prefix_affinity_only_true_for_that_variant() {
        assert!(Router::new(RoutingStrategy::PrefixAffinity, 1).is_prefix_affinity());
        assert!(!Router::new(RoutingStrategy::RoundRobin, 1).is_prefix_affinity());
        assert!(!Router::new(RoutingStrategy::LeastTokenUsage, 1).is_prefix_affinity());
    }

    #[test]
    fn strategy_name_covers_every_variant() {
        // The label appears on `sbproxy_ai_lb_decisions_total` so a
        // missing arm would silently produce an empty string in the
        // metric. Spot-check the snake_case mapping for every
        // variant.
        assert_eq!(
            Router::new(RoutingStrategy::RoundRobin, 1).strategy_name(),
            "round_robin"
        );
        assert_eq!(
            Router::new(RoutingStrategy::PeakEwma, 1).strategy_name(),
            "peak_ewma"
        );
        assert_eq!(
            Router::new(RoutingStrategy::LeastTokenUsage, 1).strategy_name(),
            "least_token_usage"
        );
        assert_eq!(
            Router::new(RoutingStrategy::PrefixAffinity, 1).strategy_name(),
            "prefix_affinity"
        );
        assert_eq!(
            Router::new(RoutingStrategy::TokenRate, 1).strategy_name(),
            "token_rate"
        );
        assert_eq!(
            Router::new(cascade_strategy(), 1).strategy_name(),
            "cascade"
        );
    }

    // --- Cascade Tests ---

    fn cascade_strategy() -> RoutingStrategy {
        RoutingStrategy::Cascade(CascadeConfig {
            tiers: vec![
                CascadeTier {
                    provider_id: "smart".to_string(),
                    model: "gpt-4o".to_string(),
                    quality_threshold: 0.9,
                    cost_cap: None,
                },
                CascadeTier {
                    provider_id: "cheap".to_string(),
                    model: "gpt-4o-mini".to_string(),
                    quality_threshold: 0.7,
                    cost_cap: None,
                },
            ],
            max_total_cost: Some(10_000),
        })
    }

    #[test]
    fn router_is_cascade_reports_strategy() {
        let router = Router::new(cascade_strategy(), 2);
        assert!(router.is_cascade());
        assert!(!router.is_race());
        assert!(router.cascade_config().is_some());
    }

    #[test]
    fn router_select_picks_first_tier_provider() {
        // The basic `select` API hands back the provider whose
        // name matches the cascade's first tier so callers that
        // do not engage the cascade-aware dispatcher still get a
        // deterministic provider.
        let providers = vec![
            make_provider("cheap", 1, None, true),
            make_provider("smart", 1, None, true),
        ];
        let router = Router::new(cascade_strategy(), providers.len());
        let idx = router.select(&providers).expect("select");
        assert_eq!(idx, 1, "first tier targets `smart`, which is index 1");
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

    // --- OutcomeAware (WOR-1541) Tests ---

    #[test]
    fn outcome_aware_routes_to_healthy_provider() {
        use crate::routing_feedback::{FeedbackStore, Outcome};
        // Unique provider names so this test does not collide with the
        // process-wide feedback store used by other tests.
        let providers = vec![
            make_provider("oa_flaky", 1, None, true),
            make_provider("oa_good", 1, None, true),
        ];
        let store = FeedbackStore::global();
        // Warm both well past the explore threshold; the flaky one refuses
        // half its requests, the good one always succeeds.
        for i in 0..20 {
            let refused = i % 2 == 0;
            store.record(&Outcome {
                provider: "oa_flaky",
                success: !refused,
                refused,
                cost_usd: 0.001,
                latency_ms: 100,
            });
            store.record(&Outcome {
                provider: "oa_good",
                success: true,
                refused: false,
                cost_usd: 0.001,
                latency_ms: 100,
            });
        }
        let router = Router::new(RoutingStrategy::OutcomeAware, providers.len());
        // Every selection routes to the healthy provider once both are
        // warmed up.
        for _ in 0..10 {
            assert_eq!(router.select(&providers).unwrap(), 1);
        }
    }

    #[test]
    fn outcome_aware_round_robins_while_warming_up() {
        let providers = vec![
            make_provider("oa_cold_a", 1, None, true),
            make_provider("oa_cold_b", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::OutcomeAware, providers.len());
        // No feedback recorded for these names: the store explores, so
        // selection distributes rather than pinning one provider.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            seen.insert(router.select(&providers).unwrap());
        }
        assert!(seen.len() > 1, "explores both while warming up");
    }

    #[test]
    fn outcome_aware_deserializes_from_snake_case() {
        let s: RoutingStrategy =
            serde_json::from_value(serde_json::json!("outcome_aware")).unwrap();
        assert!(matches!(s, RoutingStrategy::OutcomeAware));
        assert_eq!(
            Router::new(RoutingStrategy::OutcomeAware, 1).strategy_name(),
            "outcome_aware"
        );
    }

    // --- PeakEwma (P2C latency) Tests ---

    #[test]
    fn peak_ewma_two_providers_picks_lower_latency() {
        let providers = vec![
            make_provider("slow", 1, None, true),
            make_provider("fast", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::PeakEwma, providers.len());
        router.record_latency(0, 5000);
        router.record_latency(1, 1000);
        // With two eligible providers, P2C samples both, so it always
        // routes to the lower-latency one.
        for _ in 0..10 {
            assert_eq!(router.select(&providers).unwrap(), 1);
        }
    }

    #[test]
    fn peak_ewma_single_provider_returns_it() {
        let providers = vec![make_provider("only", 1, None, true)];
        let router = Router::new(RoutingStrategy::PeakEwma, providers.len());
        assert_eq!(router.select(&providers).unwrap(), 0);
    }

    #[test]
    fn peak_ewma_deserializes_from_snake_case() {
        let s: RoutingStrategy = serde_json::from_value(serde_json::json!("peak_ewma")).unwrap();
        assert!(matches!(s, RoutingStrategy::PeakEwma));
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

    /// `select_with_allowed` with an empty list behaves identically
    /// to `select`. The principal's virtual_key.allowed_providers is
    /// empty by default; this exercise confirms the hot path is a
    /// no-op for non-restricted requests.
    #[test]
    fn select_with_allowed_empty_acts_as_select() {
        let router = Router::new(RoutingStrategy::RoundRobin, 2);
        let providers = vec![
            make_provider("openai", 1, None, true),
            make_provider("anthropic", 1, None, true),
        ];
        let allowed: Vec<String> = Vec::new();
        let pick = router
            .select_with_allowed(&providers, &allowed)
            .expect("a provider should be picked");
        assert!(providers.get(pick).is_some());
    }

    /// A non-empty `allowed` list narrows the eligible set to
    /// providers whose names are on it. Picking anything outside the
    /// list is a hard reject.
    #[test]
    fn select_with_allowed_filters_to_named_providers() {
        let router = Router::new(RoutingStrategy::RoundRobin, 3);
        let providers = vec![
            make_provider("openai", 1, None, true),
            make_provider("anthropic", 1, None, true),
            make_provider("cohere", 1, None, true),
        ];
        // Restrict to anthropic only.
        let allowed = vec!["anthropic".to_string()];
        for _ in 0..6 {
            let pick = router
                .select_with_allowed(&providers, &allowed)
                .expect("anthropic is on the list and enabled");
            assert_eq!(providers[pick].name, "anthropic");
        }
    }

    /// When the allowed list does not match any enabled provider,
    /// `select_with_allowed` returns `None`. The block is a hard
    /// policy gate, not a hint.
    #[test]
    fn select_with_allowed_returns_none_when_nothing_matches() {
        let router = Router::new(RoutingStrategy::RoundRobin, 2);
        let providers = vec![
            make_provider("openai", 1, None, true),
            make_provider("anthropic", 1, None, true),
        ];
        let allowed = vec!["nonexistent".to_string()];
        assert!(router.select_with_allowed(&providers, &allowed).is_none());
    }
}
