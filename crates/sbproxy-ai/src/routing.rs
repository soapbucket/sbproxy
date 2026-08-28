//! Routing strategies for selecting AI providers.

mod peak_ewma;
pub mod semantic_route;

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use sbproxy_platform::circuitbreaker::{CircuitBreaker, CircuitState};
use sbproxy_platform::outlier::{OutlierDetector, OutlierDetectorConfig};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

use crate::provider::ProviderConfig;
use crate::provider_ratelimit::{ProviderQuotaSnapshot, ProviderRateLimitTracker};
use crate::routing_state::{
    CacheAffinityConfig, CacheAffinityKey, CacheAffinityLookup, PrefixAffinityConfig, PrefixDigest,
    ReplicaRoutingState,
};

/// Explicit reason a policy-filtered selection fell back to round-robin.
///
/// Silent strategy degradation is forbidden: every round-robin fallback
/// under an allow/block filter must record one of these reasons and be
/// covered by a regression test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilteredSelectionFallback {
    /// Strategy needs a request signal (prefix, session, ...) that the
    /// basic filtered `select` path does not have, so round-robin on the
    /// narrowed candidate set is intentional.
    RoundRobinMissingSignal,
}

/// Return whether a provider name satisfies a credential's provider policy.
/// A block entry always wins, including when the same name is allowed.
pub fn provider_allowed_by_policy(
    provider_name: &str,
    allowed: &[String],
    blocked: &[String],
) -> bool {
    !blocked.iter().any(|name| name == provider_name)
        && (allowed.is_empty() || allowed.iter().any(|name| name == provider_name))
}

/// The snake_case wire name of a routing strategy.
///
/// A free function rather than a `Router` method because a named model
/// group carries its own strategy without a router of its own, and the
/// two must render the same name: the group listing and the load
/// balancer's `strategy` label are read side by side.
#[must_use]
pub fn strategy_name(strategy: &RoutingStrategy) -> &'static str {
    match strategy {
        RoutingStrategy::RoundRobin => "round_robin",
        RoutingStrategy::Weighted => "weighted",
        RoutingStrategy::FallbackChain => "fallback_chain",
        RoutingStrategy::Random => "random",
        RoutingStrategy::LowestLatency => "lowest_latency",
        RoutingStrategy::LeastConnections => "least_connections",
        RoutingStrategy::CostOptimized => "cost_optimized",
        RoutingStrategy::TokenRate => "token_rate",
        RoutingStrategy::LeastTokenUsage => "least_token_usage",
        RoutingStrategy::PrefixAffinity(_) => "prefix_affinity",
        RoutingStrategy::Sticky => "sticky",
        RoutingStrategy::Race => "race",
        RoutingStrategy::PeakEwma(_) => "peak_ewma",
        RoutingStrategy::Cascade(_) => "cascade",
        RoutingStrategy::CostQuality(_) => "cost_quality",
        RoutingStrategy::OutcomeAware => "outcome_aware",
        RoutingStrategy::Headroom => "headroom",
        RoutingStrategy::ResetAware => "reset_aware",
        RoutingStrategy::SemanticRoute(_) => "semantic_route",
    }
}

/// Strategy for selecting a provider.
#[derive(Debug, Clone)]
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
    ///
    /// WOR-2233: refused at config load. The headroom it scores is
    /// measured against a per-provider limit that no configuration
    /// field supplies, so every limit is zero and the score reduces to
    /// observed usage alone, which is `LeastTokenUsage`. The variant
    /// stays so the wire form still parses and the refusal can name it;
    /// nothing reaches the arm below it while the config gate stands.
    TokenRate,
    /// WOR-798: choose the provider with the lowest recent token
    /// throughput in the current minute window, regardless of any
    /// configured TPM limit. It picks by absolute observed throughput
    /// rather than by headroom against a per-provider limit, so it does
    /// the right thing for self-hosted vLLM / SGLang pools where the
    /// operator does not pre-declare a token cap. Untried providers
    /// (zero observed tokens) sort lowest and are explored first.
    LeastTokenUsage,
    /// Prefix-affinity routing for self-hosted LLM pools (vLLM, SGLang)
    /// whose workers retain prompt KV caches.
    ///
    /// The dispatcher normalizes the model namespace, leading
    /// system/developer instructions, and first user message into a bounded
    /// digest. An accepted response records its provider as an observed holder
    /// for that digest. Later requests prefer a live observed holder;
    /// deterministic holder ties preserve replica-state order. A miss or
    /// missing prefix chooses the provider with the lowest recent token load,
    /// rotating exact load ties.
    ///
    /// Holder and load state are bounded and process-local. They are learned
    /// from accepted traffic and are not shared across gateway processes.
    PrefixAffinity(PrefixAffinityConfig),
    /// Pin a session key to the same provider across requests.
    Sticky,
    /// Send the request concurrently to every eligible provider and
    /// return the first acceptable response. Cancels the losers.
    /// Trades doubled spend for halved latency on the chat-first-token
    /// path; useful when every millisecond of TTFT matters.
    Race,
    /// Power-of-Two-Choices over time-decayed latency and in-flight load.
    PeakEwma(PeakEwmaConfig),
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
    /// error rate is climbing. During warm-up it deterministically blends
    /// learned picks with an independent round-robin fallback cursor according
    /// to the least-observed candidate's confidence. A fresh process starts
    /// with pure round-robin and reaches fully learned selection at five
    /// samples per candidate.
    OutcomeAware,
    /// Prefer the provider with the lowest request-quota pressure
    /// (`1 - remaining/limit`) from fresh header-derived snapshots.
    /// Unknown or stale signals are advisory only and sort after known
    /// fresh observations; ties keep enabled-list order.
    Headroom,
    /// Prefer the provider whose quota window resets soonest among
    /// candidates waiting for positive capacity. Providers that already
    /// report remaining capacity sort first. Unknown/stale signals sort
    /// last and never invent a reset time.
    ResetAware,
    /// Semantic (embedding-similarity) routing (WOR-2564): the operator
    /// declares exemplar prompts or embedding centroids per deployment,
    /// the dispatcher embeds the request's final user message through the
    /// configured embedding source, and the best cosine match above
    /// `min_similarity` pins that deployment. Below-floor scores, absent
    /// prompts, and embedder failures all fall to the declared `fallback`
    /// deployment (or round-robin), never to an error. Routes on meaning,
    /// where `prefix_affinity` routes on byte-stable prefixes for
    /// KV-cache reuse.
    ///
    /// Boxed: the config carries the declared routes and their exemplar
    /// texts, and inlining it would grow every `RoutingStrategy` value in
    /// the process from 56 bytes to 328, including the eighteen
    /// strategies that declare nothing.
    SemanticRoute(Box<semantic_route::SemanticRouteConfig>),
}

/// Default half-life for Peak EWMA latency decay.
pub const DEFAULT_PEAK_EWMA_HALF_LIFE_SECS: u64 = 10;

/// Configuration for [`RoutingStrategy::PeakEwma`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeakEwmaConfig {
    /// Seconds of decay before an idle provider re-enters at neutral cost.
    pub half_life_secs: u64,
}

impl Default for PeakEwmaConfig {
    fn default() -> Self {
        Self {
            half_life_secs: DEFAULT_PEAK_EWMA_HALF_LIFE_SECS,
        }
    }
}

impl PeakEwmaConfig {
    /// Configured half-life as a duration.
    pub fn half_life(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.half_life_secs)
    }
}

impl<'de> Deserialize<'de> for PeakEwmaConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(
                default = "default_peak_ewma_half_life_secs",
                rename = "half_life",
                deserialize_with = "sbproxy_config::duration::deserialize_secs"
            )]
            half_life_secs: u64,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.half_life_secs == 0 {
            return Err(D::Error::custom(
                "peak_ewma routing half_life must be greater than zero",
            ));
        }
        Ok(Self {
            half_life_secs: wire.half_life_secs,
        })
    }
}

fn default_peak_ewma_half_life_secs() -> u64 {
    DEFAULT_PEAK_EWMA_HALF_LIFE_SECS
}

impl<'de> Deserialize<'de> for RoutingStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if value.as_str() == Some("peak_ewma") {
            return Ok(Self::PeakEwma(PeakEwmaConfig::default()));
        }
        if value.as_str() == Some("prefix_affinity") {
            return Ok(Self::PrefixAffinity(PrefixAffinityConfig::default()));
        }
        if value.as_str() == Some("semantic_route") {
            return Err(D::Error::custom(
                "routing strategy `semantic_route` requires a routing object carrying `routes` \
                 and an embedding source; the flat string form declares no specialties to \
                 route on. Write `routing: {strategy: semantic_route, routes: [...], \
                 embedding: {provider: ..., model: ...}}`",
            ));
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Wire {
            RoundRobin,
            Weighted,
            FallbackChain,
            Random,
            LowestLatency,
            LeastConnections,
            CostOptimized,
            TokenRate,
            LeastTokenUsage,
            PrefixAffinity(PrefixAffinityConfig),
            Sticky,
            Race,
            PeakEwma(PeakEwmaConfig),
            Cascade(CascadeConfig),
            CostQuality(crate::cost_quality::CostQualityConfig),
            OutcomeAware,
            Headroom,
            ResetAware,
            SemanticRoute(Box<semantic_route::SemanticRouteConfig>),
        }

        let wire = serde_json::from_value::<Wire>(value).map_err(D::Error::custom)?;
        Ok(match wire {
            Wire::RoundRobin => Self::RoundRobin,
            Wire::Weighted => Self::Weighted,
            Wire::FallbackChain => Self::FallbackChain,
            Wire::Random => Self::Random,
            Wire::LowestLatency => Self::LowestLatency,
            Wire::LeastConnections => Self::LeastConnections,
            Wire::CostOptimized => Self::CostOptimized,
            Wire::TokenRate => Self::TokenRate,
            Wire::LeastTokenUsage => Self::LeastTokenUsage,
            Wire::PrefixAffinity(config) => Self::PrefixAffinity(config),
            Wire::Sticky => Self::Sticky,
            Wire::Race => Self::Race,
            Wire::PeakEwma(config) => Self::PeakEwma(config),
            Wire::Cascade(config) => Self::Cascade(config),
            Wire::CostQuality(config) => Self::CostQuality(config),
            Wire::OutcomeAware => Self::OutcomeAware,
            Wire::Headroom => Self::Headroom,
            Wire::ResetAware => Self::ResetAware,
            Wire::SemanticRoute(config) => Self::SemanticRoute(config),
        })
    }
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

/// Cap on the sticky session-affinity map (WOR-1693). Session keys are
/// client-chosen, so without a bound the map gains one entry per unique
/// key for the life of the process. 100,000 matches the cap
/// [`crate::ratelimit::ModelRateLimiter`] uses for its entity buckets.
/// Overflow evicts the least-recently-used session, whose only effect is
/// that the evicted session re-pins on its next request, the same as
/// after a restart.
const MAX_STICKY_SESSIONS: usize = 100_000;

/// A point-in-time snapshot of one provider's live runtime state, as read
/// from the [`Router`]'s per-provider atomics and circuit breaker.
///
/// Returned index-aligned by [`Router::provider_runtime_states`] and surfaced
/// to a routing policy as `ai.providers[i]`. Every field is a plain scalar so
/// the AI decision view can bind it without depending on router internals.
#[derive(Debug, Clone)]
pub struct ProviderRuntimeState {
    /// Observed p50 latency in microseconds; `0` before the first observation.
    pub latency_us: u64,
    /// In-flight request count.
    pub in_flight: u32,
    /// Tokens charged to the current minute.
    pub tokens_used: u64,
    /// `false` only when an active probe marked the provider unhealthy;
    /// `unknown` (no probe) reads as healthy, matching selection.
    pub healthy: bool,
    /// Health as a stable label: `healthy`, `unhealthy`, or `unknown`.
    pub health: &'static str,
    /// `true` when the circuit breaker is open (requests are being rejected).
    pub circuit_open: bool,
    /// Circuit state as a stable label: `closed`, `open`, or `half_open`.
    pub circuit: &'static str,
}

/// Router that selects a provider for each request.
pub struct Router {
    strategy: RoutingStrategy,
    counter: AtomicU64,
    /// One rotation cursor per named model group (WOR-2657), sized at
    /// creation from the config's group list. Sharing `counter` would
    /// make two `round_robin` groups interleave each other's rotation,
    /// so a two-member group would alternate only when the other group
    /// happened not to be taking traffic.
    group_counters: std::collections::HashMap<String, AtomicU64>,
    /// Round-robin cursor for outcome-aware warm-up traffic. Kept separate
    /// from the confidence schedule so learned slots cannot starve whichever
    /// providers occupy the same schedule positions.
    outcome_fallback_counter: AtomicU64,
    // --- Per-provider state (sized at creation time) ---
    /// Observed p50 latency in microseconds per provider.
    latencies: Vec<AtomicU64>,
    /// Time-decayed, peak-sensitive latency state for Peak EWMA routing.
    peak_ewma: Option<peak_ewma::PeakEwmaEstimator>,
    /// In-flight request count per provider.
    connections: Vec<AtomicU32>,
    /// Tokens used in the current minute per provider.
    tokens_used: Vec<AtomicU64>,
    /// Bounded prefix locations and lazy recent-token load shared by
    /// prefix-affinity and least-token-usage routing.
    replica_state: ReplicaRoutingState,
    /// Token-per-minute limits per provider.
    token_limits: Vec<u64>,
    /// Session affinity map (session key -> provider index), bounded to
    /// [`MAX_STICKY_SESSIONS`] entries so client-chosen keys cannot grow
    /// it without limit (WOR-1693).
    sticky_map: parking_lot::Mutex<lru::LruCache<String, usize>>,
    /// Per-provider circuit breakers. Empty when no resilience policy
    /// is configured; populated by `AiHandlerConfig::router` when the
    /// handler config carries a `resilience.circuit_breaker` block, and
    /// by nothing else.
    breakers: Vec<Arc<CircuitBreaker>>,
    /// Optional shared outlier detector, populated by
    /// `AiHandlerConfig::router` from a `resilience.outlier_detection`
    /// block. Keys requests by provider name (matches the AI provider's
    /// stable id rather than its index so reload-time provider list
    /// changes don't reset state).
    outlier: Option<Arc<OutlierDetector>>,
    /// Per-provider active-probe health. `0` = unknown, `1` =
    /// healthy, `2` = unhealthy. Written by the probe tasks
    /// [`crate::health_probe`] spawns when the handler config carries a
    /// `resilience.health_check` block, and by nothing else. A pool
    /// with no probe configured stays at `unknown`, which reads as
    /// healthy so this axis simply abstains.
    health: Vec<AtomicU8>,
    /// Header-derived quota snapshots for headroom / reset-aware scoring.
    quota: ProviderRateLimitTracker,
    /// Last explicit round-robin fallback under policy-filtered selection.
    last_filtered_fallback: parking_lot::Mutex<Option<FilteredSelectionFallback>>,
    /// Per-error-class cooldown policy (WOR-2556). `None` (the default)
    /// disables the axis entirely; populated by
    /// `AiHandlerConfig::router` from a `resilience.cooldown_policy`
    /// block, and by nothing else. Unlike the breaker and the outlier
    /// detector, this axis is fed directly by the dispatch loop's
    /// failure classification ([`Self::note_classified_failure`]), so a
    /// configured block acts on real traffic.
    cooldown_policy: Option<crate::failure_cause::CooldownPolicy>,
    /// Per-provider cooldown deadline, in milliseconds since
    /// `cooldown_epoch`. `0` = no cooldown. Sized to the pool when a
    /// `cooldown_policy` is attached, empty otherwise.
    cooldown_until_ms: Vec<AtomicU64>,
    /// The instant `cooldown_until_ms` deadlines are measured from.
    cooldown_epoch: std::time::Instant,
}

/// Cancellation-safe accounting for one provider attempt.
#[must_use = "dropping the guard releases the provider's in-flight slot"]
pub struct ProviderInFlightGuard<'a> {
    router: &'a Router,
    provider_idx: Option<usize>,
}

impl Drop for ProviderInFlightGuard<'_> {
    fn drop(&mut self) {
        if let Some(provider_idx) = self.provider_idx {
            self.router.record_disconnect(provider_idx);
        }
    }
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
        let prefix_config = match &strategy {
            RoutingStrategy::PrefixAffinity(config) => *config,
            _ => PrefixAffinityConfig::default(),
        };
        let replica_state = ReplicaRoutingState::new(num_providers, prefix_config)
            .expect("routing strategy configuration must be validated before Router construction");
        let peak_ewma = match &strategy {
            RoutingStrategy::PeakEwma(config) => Some(peak_ewma::PeakEwmaEstimator::new(
                num_providers,
                config.half_life(),
            )),
            _ => None,
        };

        Self {
            strategy,
            counter: AtomicU64::new(0),
            group_counters: std::collections::HashMap::new(),
            outcome_fallback_counter: AtomicU64::new(0),
            latencies,
            peak_ewma,
            connections,
            tokens_used,
            replica_state,
            token_limits,
            sticky_map: parking_lot::Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(MAX_STICKY_SESSIONS).expect("cap is nonzero"),
            )),
            breakers: Vec::new(),
            outlier: None,
            health,
            quota: ProviderRateLimitTracker::new(0.1),
            last_filtered_fallback: parking_lot::Mutex::new(None),
            cooldown_policy: None,
            cooldown_until_ms: Vec::new(),
            cooldown_epoch: std::time::Instant::now(),
        }
    }

    /// Update quota snapshots from an upstream provider response.
    /// Call before retry/reselect so headroom and reset-aware strategies
    /// see the latest headers (including 429 paths).
    pub fn update_quota_from_headers(
        &self,
        provider: &str,
        headers: &[(String, String)],
        status: u16,
    ) {
        self.quota
            .update_from_headers_with_status(provider, headers, status);
    }

    /// Advisory quota snapshot for a provider. Unknown when never observed.
    pub fn quota_snapshot(&self, provider: &str) -> ProviderQuotaSnapshot {
        self.quota.snapshot(provider)
    }

    /// Last explicit round-robin fallback recorded by policy-filtered
    /// selection, if any. Cleared on the next filtered pick that does
    /// not fall back.
    pub fn last_filtered_fallback(&self) -> Option<FilteredSelectionFallback> {
        *self.last_filtered_fallback.lock()
    }

    fn record_filtered_fallback(&self, reason: Option<FilteredSelectionFallback>) {
        *self.last_filtered_fallback.lock() = reason;
    }

    /// Attach one circuit breaker per provider, sized to the pool this
    /// router was built for.
    ///
    /// Deliberately separate from [`Self::with_outlier_detection`].
    /// `resilience.circuit_breaker` and `resilience.outlier_detection`
    /// are independent blocks, and the single constructor this replaces
    /// took both, so wiring it would have armed breakers on default
    /// thresholds for an operator who had configured only outlier
    /// detection. Each axis is attached by the block that asks for it
    /// and by nothing else, which is how the probe axis is wired too
    /// (WOR-2224).
    pub fn with_circuit_breakers(
        mut self,
        failure_threshold: u32,
        success_threshold: u32,
        open_duration_secs: u64,
    ) -> Self {
        // Sized from an existing per-provider vec rather than from a
        // caller-supplied count, so `breakers[idx]` cannot drift out of
        // step with the index every other axis is keyed by.
        self.breakers = (0..self.latencies.len())
            .map(|_| {
                Arc::new(CircuitBreaker::new(
                    failure_threshold,
                    success_threshold,
                    std::time::Duration::from_secs(open_duration_secs),
                ))
            })
            .collect();
        self
    }

    /// Attach the shared sliding-window outlier detector.
    ///
    /// One detector serves the whole pool because it keys by provider
    /// name rather than index, so a hot reload that adds or reorders
    /// providers does not silently hand one provider another's history.
    pub fn with_outlier_detection(mut self, config: OutlierDetectorConfig) -> Self {
        self.outlier = Some(Arc::new(OutlierDetector::new(config)));
        self
    }

    /// Give each named model group its own rotation cursor (WOR-2657).
    ///
    /// Sized from the config's group list at construction, for the same
    /// reason the per-provider vectors are: a cursor allocated lazily on
    /// the request path would need a lock, and a cursor shared between
    /// groups makes each group's rotation depend on the other group's
    /// traffic.
    ///
    /// A group absent from this list falls back to the action's own
    /// cursor in [`Self::select_group`]. That can only happen when a
    /// router was built without its config's groups, which
    /// `AiHandlerConfig::router` does not do.
    #[must_use]
    pub fn with_model_groups<'a>(mut self, names: impl IntoIterator<Item = &'a str>) -> Self {
        self.group_counters = names
            .into_iter()
            .map(|name| (name.to_string(), AtomicU64::new(0)))
            .collect();
        self
    }

    /// Pick one member of a named model group.
    ///
    /// `candidates` is the caller's already-permitted provider index
    /// set, narrowed to the group's members: credential provider
    /// policy, the enabled switch, and the resilience axes have run
    /// before this. Selection uses the **group's** strategy and, under
    /// `weighted`, the **member's** weight rather than the provider's,
    /// on the group's own rotation cursor.
    ///
    /// Members are keyed by provider index, which the config validator
    /// makes unambiguous by refusing two members on one provider.
    pub fn select_group(
        &self,
        providers: &[ProviderConfig],
        candidate_indices: &[usize],
        group: &crate::model_group::ModelGroup,
    ) -> Option<usize> {
        // Only the `Weighted` arm reads the map, so the other twelve
        // strategies do not pay a per-request allocation on the AI
        // request path for a field they ignore.
        let member_weights: Option<std::collections::HashMap<usize, u32>> =
            matches!(group.routing, RoutingStrategy::Weighted).then(|| {
                group
                    .members
                    .iter()
                    .filter_map(|member| {
                        providers
                            .iter()
                            .position(|provider| provider.name.as_str() == member.provider.as_str())
                            .map(|index| (index, member.weight))
                    })
                    .collect()
            });
        let enabled = candidate_indices
            .iter()
            .filter_map(|&index| providers.get(index).map(|provider| (index, provider)))
            .collect::<Vec<_>>();
        let counter = self
            .group_counters
            .get(group.name.as_str())
            .unwrap_or(&self.counter);
        let picked = self.select_from_candidates_with(
            &enabled,
            false,
            &group.routing,
            counter,
            member_weights.as_ref(),
        );
        if let Some(index) = picked {
            if let Some(provider) = providers.get(index) {
                crate::ai_metrics::record_model_group_selection(
                    group.name.as_str(),
                    provider.name.as_str(),
                );
            }
        }
        picked
    }

    /// Attach the per-error-class cooldown policy (WOR-2556).
    ///
    /// Same attachment discipline as the breaker and outlier axes: only
    /// a `resilience.cooldown_policy` block arms it, so the default
    /// configuration changes nothing. Unlike those two, the write side
    /// is [`Self::note_classified_failure`], called by the dispatch
    /// loop at its failure-classification points, so this axis is fed
    /// by production traffic from the day it is configured.
    pub fn with_classified_cooldowns(
        mut self,
        policy: crate::failure_cause::CooldownPolicy,
    ) -> Self {
        self.cooldown_until_ms = (0..self.latencies.len())
            .map(|_| AtomicU64::new(0))
            .collect();
        self.cooldown_policy = Some(policy);
        self
    }

    /// Record a classified upstream failure against a provider (WOR-2556).
    ///
    /// When a `cooldown_policy` is attached and maps `cause` to a
    /// duration, the provider is removed from candidate rotation for
    /// that long. A no-op without a policy, so callers do not need to
    /// gate on configuration.
    pub fn note_classified_failure(
        &self,
        provider_idx: usize,
        provider_name: &str,
        cause: crate::failure_cause::FailureCause,
    ) {
        let Some(secs) = self
            .cooldown_policy
            .as_ref()
            .and_then(|policy| policy.cooldown_secs_for(cause))
        else {
            return;
        };
        let Some(slot) = self.cooldown_until_ms.get(provider_idx) else {
            return;
        };
        let now_ms = self.cooldown_epoch.elapsed().as_millis() as u64;
        let until_ms = now_ms.saturating_add(secs.saturating_mul(1_000));
        // `max` so racing failures never shorten a longer cooldown
        // another class just set.
        slot.fetch_max(until_ms, Ordering::Relaxed);
        // Like an outlier ejection, the moment traffic stops reaching a
        // provider must be visible somewhere an operator looks. A log
        // line alone is not that: it rotates, it cannot be graphed, and
        // nothing can alert on it. The counter is the durable half, and
        // the breaker axis has published one all along.
        crate::ai_metrics::record_provider_cooldown(provider_name, cause.as_str());
        tracing::warn!(
            provider = %provider_name,
            cause = cause.as_str(),
            cooldown_secs = secs,
            "ai provider placed on per-error-class cooldown"
        );
    }

    /// Whether a provider is currently held out by a classified-failure
    /// cooldown. Lapses by itself once the deadline passes; nothing
    /// sweeps it.
    fn cooldown_active(&self, provider_idx: usize) -> bool {
        let Some(slot) = self.cooldown_until_ms.get(provider_idx) else {
            return false;
        };
        let until_ms = slot.load(Ordering::Relaxed);
        until_ms != 0 && self.cooldown_epoch.elapsed().as_millis() as u64 <= until_ms
    }

    /// Read access to the per-provider circuit breakers (mostly for
    /// admin diagnostics and tests).
    pub fn breakers(&self) -> &[Arc<CircuitBreaker>] {
        &self.breakers
    }

    /// A cheap, lock-free snapshot of every provider's live runtime state,
    /// index-aligned with the providers passed to [`Router::new`].
    ///
    /// Reads each per-provider atomic with `Relaxed` ordering and each
    /// breaker's decoded state; it holds no lock and does no I/O, so it is
    /// safe to call on the request path before an `ai_routing_policy` runs.
    /// It exposes the same signals the built-in latency/load/health-aware
    /// strategies select on, so a routing policy can read them as
    /// `ai.providers` and author that decision itself.
    ///
    /// `health` follows the router's own selection semantics: a provider
    /// with no probe configured (or no result yet) is `unknown`, which reads
    /// as healthy because that axis simply abstains. `circuit` is `closed`
    /// when no breaker is configured.
    ///
    /// Reading `circuit` is not perfectly side-effect-free: like every other
    /// caller of [`CircuitBreaker::state`], it lazily transitions a breaker
    /// whose open duration has elapsed from open to half-open. That only
    /// advances a cooled-down breaker toward recovery (the same transition
    /// selection would make), so it is safe to call here, but it is why this
    /// is "no lock, no I/O" rather than "pure read".
    pub fn provider_runtime_states(&self) -> Vec<ProviderRuntimeState> {
        (0..self.latencies.len())
            .map(|i| {
                let (healthy, health) = match self.health[i].load(Ordering::Relaxed) {
                    1 => (true, "healthy"),
                    2 => (false, "unhealthy"),
                    _ => (true, "unknown"),
                };
                let circuit = self
                    .breakers
                    .get(i)
                    .map_or(CircuitState::Closed, |b| b.state());
                ProviderRuntimeState {
                    latency_us: self.latencies[i].load(Ordering::Relaxed),
                    in_flight: self.connections[i].load(Ordering::Relaxed),
                    tokens_used: self.tokens_used[i].load(Ordering::Relaxed),
                    healthy,
                    health,
                    circuit_open: matches!(circuit, CircuitState::Open),
                    circuit: circuit.as_str(),
                }
            })
            .collect()
    }

    /// Mark a provider's last response as a success (for outlier
    /// detection + circuit breaker recovery). Called by the AI client
    /// after a 2xx response.
    pub fn record_provider_success(&self, provider_idx: usize, provider_name: &str) {
        if let Some(b) = self.breakers.get(provider_idx) {
            // Only a half-open probe that met `success_threshold`
            // returns a transition. Logging it is the only signal an
            // operator gets that a provider came back, and a recovery
            // that never appears is the failure mode this whole ticket
            // is about.
            if let Some((from, to)) = b.record_success() {
                tracing::info!(
                    provider = %provider_name,
                    from = from.as_str(),
                    to = to.as_str(),
                    "ai provider circuit breaker closed"
                );
                sbproxy_observe::metrics::record_circuit_breaker_transition(
                    provider_name,
                    from.as_str(),
                    to.as_str(),
                    "success_threshold_met",
                    "",
                );
            }
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
            if let Some((from, to)) = b.record_failure() {
                tracing::warn!(
                    provider = %provider_name,
                    from = from.as_str(),
                    to = to.as_str(),
                    "ai provider circuit breaker opened"
                );
                let reason = match from {
                    CircuitState::HalfOpen => "probe_failed",
                    _ => "failure_threshold_exceeded",
                };
                sbproxy_observe::metrics::record_circuit_breaker_transition(
                    provider_name,
                    from.as_str(),
                    to.as_str(),
                    reason,
                    "",
                );
            }
        }
        if let Some(d) = &self.outlier {
            d.record_failure(provider_name);
            // The detector evaluates every provider it has seen, not
            // just this one, so a name here can differ from the caller's.
            // Ejection is the moment traffic stops reaching a provider;
            // it has to be visible somewhere an operator looks.
            for ejected in d.check_ejections() {
                tracing::warn!(
                    provider = %ejected,
                    "ai provider ejected by outlier detection"
                );
            }
        }
    }

    /// Set a provider's active-probe health flag.
    ///
    /// The probe loop in [`crate::health_probe`] is the only production
    /// caller. This axis is that module's to own: the breaker and the
    /// outlier detector keep their own state and are intersected with
    /// this one at selection time, rather than all three writing a
    /// single flag with three different recovery rules.
    pub fn set_provider_health(&self, provider_idx: usize, healthy: bool) {
        if let Some(slot) = self.health.get(provider_idx) {
            slot.store(if healthy { 1 } else { 2 }, Ordering::Relaxed);
        }
    }

    /// Intersect the three resilience axes for one provider.
    ///
    /// Each axis abstains when its config block is absent, so a pool
    /// with no `resilience` block answers `true` here for everything
    /// and the three checks cost three loads.
    ///
    /// The axes never write to each other, and each one has a path back
    /// to eligible that does not depend on the other two. That is the
    /// property that makes the intersection safe: an `AND` of three
    /// gates only lets a provider return if every gate that closed can
    /// reopen on its own evidence.
    fn provider_eligible(&self, idx: usize, name: &str) -> bool {
        // Active health probe verdict (default unknown is treated as
        // healthy). Clears when `healthy_threshold` probes pass in a
        // row, which the probe task keeps taking whether or not this
        // provider is receiving traffic.
        let health_ok = self
            .health
            .get(idx)
            .map(|h| h.load(Ordering::Relaxed) != 2)
            .unwrap_or(true);
        if !health_ok {
            return false;
        }
        // Circuit-breaker gate. `allow_request` is not a pure read: it
        // performs the Open -> HalfOpen transition once
        // `open_duration_secs` has elapsed, so asking the question is
        // also what lets a cooled-down breaker admit its probe. A
        // breaker that no caller consulted would stay Open forever.
        let breaker_ok = self
            .breakers
            .get(idx)
            .map(|b| b.allow_request())
            .unwrap_or(true);
        if !breaker_ok {
            return false;
        }
        // Outlier ejection. Also not a pure read: `is_ejected` drops an
        // expired entry as it passes over it, so the ejection lapses
        // after `ejection_duration_secs` without anyone sweeping it.
        if let Some(d) = &self.outlier {
            if d.is_ejected(name) {
                return false;
            }
        }
        // Per-error-class cooldown (WOR-2556). Advisory like the axes
        // above: `routable_candidate_indices` revives an all-ineligible
        // pool, so a cooldown can never manufacture an outage.
        if self.cooldown_active(idx) {
            return false;
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
            if let Some(estimator) = &self.peak_ewma {
                estimator.observe(provider_idx, latency_us);
            }
        }
    }

    /// Increment the in-flight connection count for a provider.
    pub fn record_connect(&self, provider_idx: usize) {
        if let Some(slot) = self.connections.get(provider_idx) {
            slot.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Track one provider attempt until the returned guard is dropped.
    ///
    /// The guard balances success, failure, early-return, and future
    /// cancellation paths. An unknown provider index produces an inert guard.
    pub fn track_in_flight(&self, provider_idx: usize) -> ProviderInFlightGuard<'_> {
        let provider_idx = self.connections.get(provider_idx).map(|slot| {
            slot.fetch_add(1, Ordering::Relaxed);
            provider_idx
        });
        ProviderInFlightGuard {
            router: self,
            provider_idx,
        }
    }

    /// Decrement the in-flight connection count for a provider.
    pub fn record_disconnect(&self, provider_idx: usize) {
        if let Some(slot) = self.connections.get(provider_idx) {
            let _ = slot.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            });
        }
    }

    /// Record tokens consumed by a provider in the current minute window.
    pub fn record_tokens(&self, provider_idx: usize, tokens: u64) {
        if let Some(slot) = self.tokens_used.get(provider_idx) {
            slot.fetch_add(tokens, Ordering::Relaxed);
        }
        self.replica_state.record_tokens(provider_idx, tokens);
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
        self.replica_state.reset_tokens();
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

        // Check cache first. `get` also marks the entry
        // most-recently-used, so active sessions survive LRU eviction
        // while idle ones age out (WOR-1693).
        let mut sticky = self.sticky_map.lock();
        if let Some(&idx) = sticky.get(session_key) {
            // Verify the cached provider is still enabled
            if providers.get(idx).is_some_and(|p| p.enabled) {
                return Some(idx);
            }
            // Cached provider is gone or disabled, remove stale entry
            sticky.pop(session_key);
        }

        // Fall back to round robin for new sessions. At capacity, `put`
        // evicts the least-recently-used session; that session re-pins
        // on its next request, the same as after a restart.
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let selected = enabled[counter as usize % enabled.len()].0;
        sticky.put(session_key.to_string(), selected);
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
        self.select_with_policy(providers, allowed, &[])
    }

    /// Pick an enabled provider permitted by the credential policy.
    ///
    /// The credential policy is a hard filter: a provider this key may
    /// not use is never selected, and `None` is the honest answer when
    /// the key is permitted nothing. Resilience is a soft filter on top
    /// of that set, on the same terms as [`Self::select`] and
    /// [`Self::routable_candidate_indices`], so an all-ejected pool
    /// still returns a provider the key is allowed to reach rather than
    /// failing the request.
    pub fn select_with_policy(
        &self,
        providers: &[ProviderConfig],
        allowed: &[String],
        blocked: &[String],
    ) -> Option<usize> {
        let picked = self.select_inner_filtered(providers, &|p| {
            provider_allowed_by_policy(p.name.as_str(), allowed, blocked)
        });
        if let Some(idx) = picked {
            if let Some(p) = providers.get(idx) {
                crate::ai_metrics::record_lb_decision(self.strategy_name(), &p.name);
            }
        }
        picked
    }

    /// `select_inner` with an additional predicate. The predicate is a
    /// hard gate and an empty predicate result returns `None`;
    /// resilience narrows what is left and gives the set back when it
    /// would narrow it to nothing.
    ///
    /// Candidate ranking reuses the same strategy dispatch as
    /// [`Self::select_inner`] on the narrowed set. Round-robin fallback
    /// is recorded explicitly via [`FilteredSelectionFallback`] when a
    /// strategy lacks a required request signal (e.g. PrefixAffinity
    /// without a prefix).
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
            self.record_filtered_fallback(None);
            return None;
        }
        let candidates = enabled.iter().map(|(idx, _)| *idx).collect::<Vec<_>>();
        let eligible = self.routable_candidate_indices(providers, &candidates);
        let eligible = eligible
            .into_iter()
            .filter_map(|idx| providers.get(idx).map(|provider| (idx, provider)))
            .collect::<Vec<_>>();
        self.select_from_candidates(&eligible, true)
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

        self.select_from_candidates(&enabled, false)
    }

    /// Shared strategy dispatch over an already-narrowed candidate list,
    /// using this router's own strategy and rotation cursor.
    ///
    /// When `record_fallback` is true, intentional round-robin fallbacks
    /// (missing prefix/session signal) are recorded for tests and ops.
    fn select_from_candidates(
        &self,
        enabled: &[(usize, &ProviderConfig)],
        record_fallback: bool,
    ) -> Option<usize> {
        self.select_from_candidates_with(
            enabled,
            record_fallback,
            &self.strategy,
            &self.counter,
            None,
        )
    }

    /// The same dispatch, parameterized on the strategy, the rotation
    /// cursor, and an optional per-candidate weight override.
    ///
    /// A named model group ([`Self::select_group`]) supplies all three:
    /// its own strategy, its own cursor so two groups do not interleave
    /// each other's rotation, and its members' weights, which live on
    /// the group entry rather than on `ProviderConfig`. Only the
    /// `Weighted` arm reads `member_weights`; every other axis
    /// (breakers, latency, sticky, replica state, quota) is per-provider
    /// runtime state and stays on `&self`, shared with the action's own
    /// selections, which is what makes a group's picks respond to the
    /// same live signals.
    fn select_from_candidates_with(
        &self,
        enabled: &[(usize, &ProviderConfig)],
        record_fallback: bool,
        strategy: &RoutingStrategy,
        counter: &AtomicU64,
        member_weights: Option<&std::collections::HashMap<usize, u32>>,
    ) -> Option<usize> {
        if enabled.is_empty() {
            if record_fallback {
                self.record_filtered_fallback(None);
            }
            return None;
        }

        let clear_fallback = || {
            if record_fallback {
                self.record_filtered_fallback(None);
            }
        };
        let mark_missing_signal = || {
            if record_fallback {
                self.record_filtered_fallback(Some(
                    FilteredSelectionFallback::RoundRobinMissingSignal,
                ));
            }
        };

        match strategy {
            RoutingStrategy::RoundRobin => {
                clear_fallback();
                let idx = counter.fetch_add(1, Ordering::Relaxed);
                Some(enabled[idx as usize % enabled.len()].0)
            }
            RoutingStrategy::Weighted => {
                clear_fallback();
                // A group's weights live on its members, not on the
                // providers, so a provider carrying `weight: 1` for the
                // action's own balancing does not also decide a group's
                // split. Absent an override this reads `p.weight`
                // exactly as before.
                let weight_of = |idx: usize, provider: &ProviderConfig| -> u32 {
                    member_weights
                        .and_then(|weights| weights.get(&idx).copied())
                        .unwrap_or(provider.weight)
                };
                let total: u64 = enabled
                    .iter()
                    .map(|&(idx, p)| u64::from(weight_of(idx, p)))
                    .sum();
                if total == 0 {
                    return Some(enabled[0].0);
                }
                let cursor = counter.fetch_add(1, Ordering::Relaxed);
                let mut target = (cursor.wrapping_mul(6364136223846793005).wrapping_add(1)) % total;
                for &(idx, provider) in enabled {
                    let weight = u64::from(weight_of(idx, provider));
                    if target < weight {
                        return Some(idx);
                    }
                    target -= weight;
                }
                Some(enabled[0].0)
            }
            RoutingStrategy::FallbackChain => {
                clear_fallback();
                let mut sorted = enabled.to_vec();
                sorted.sort_by_key(|(_, p)| p.priority.unwrap_or(u32::MAX));
                Some(sorted[0].0)
            }
            RoutingStrategy::Random => {
                clear_fallback();
                let idx = counter.fetch_add(1, Ordering::Relaxed);
                let hash = idx
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                Some(enabled[hash as usize % enabled.len()].0)
            }
            RoutingStrategy::LowestLatency => {
                clear_fallback();
                let mut best_idx = None;
                let mut best_latency = u64::MAX;
                let mut has_data = false;

                for &(idx, _) in enabled {
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
                    mark_missing_signal();
                    let cursor = counter.fetch_add(1, Ordering::Relaxed);
                    Some(enabled[cursor as usize % enabled.len()].0)
                }
            }
            RoutingStrategy::PeakEwma(_) => {
                clear_fallback();
                if enabled.len() == 1 {
                    return Some(enabled[0].0);
                }
                let c = counter.fetch_add(1, Ordering::Relaxed);
                let a =
                    (c.wrapping_mul(6364136223846793005).wrapping_add(1)) as usize % enabled.len();
                let mut b = (c.wrapping_mul(2862933555777941757).wrapping_add(3037000493)) as usize
                    % enabled.len();
                if b == a {
                    b = (a + 1) % enabled.len();
                }
                let cost = |pool_idx: usize| {
                    let provider_idx = enabled[pool_idx].0;
                    let in_flight = self
                        .connections
                        .get(provider_idx)
                        .map_or(0, |value| value.load(Ordering::Relaxed));
                    self.peak_ewma
                        .as_ref()
                        .and_then(|estimator| estimator.score(provider_idx, in_flight))
                        .unwrap_or(f64::INFINITY)
                };
                Some(enabled[if cost(a) <= cost(b) { a } else { b }].0)
            }
            RoutingStrategy::LeastConnections => {
                clear_fallback();
                let mut best_idx = enabled[0].0;
                let mut best_conns = u32::MAX;

                for &(idx, _) in enabled {
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
                clear_fallback();
                let mut best_idx = enabled[0].0;
                let mut best_score = u64::MAX;

                for &(idx, provider) in enabled {
                    let conns = self
                        .connections
                        .get(idx)
                        .map_or(0, |c| c.load(Ordering::Relaxed))
                        as u64;
                    let score = conns * 1000 + provider.weight as u64;
                    if score < best_score {
                        best_score = score;
                        best_idx = idx;
                    }
                }

                Some(best_idx)
            }
            RoutingStrategy::TokenRate => {
                clear_fallback();
                let mut best_idx = enabled[0].0;
                let mut best_remaining: i64 = i64::MIN;

                for &(idx, _) in enabled {
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
            RoutingStrategy::PrefixAffinity(_) => {
                // Basic select API has no prefix; intentional RR fallback.
                mark_missing_signal();
                let cursor = counter.fetch_add(1, Ordering::Relaxed);
                Some(enabled[cursor as usize % enabled.len()].0)
            }
            RoutingStrategy::LeastTokenUsage => {
                clear_fallback();
                let candidates = enabled.iter().map(|(idx, _)| *idx).collect::<Vec<_>>();
                let tie_cursor = counter.fetch_add(1, Ordering::Relaxed);
                self.replica_state.least_loaded(&candidates, tie_cursor)
            }
            RoutingStrategy::Sticky => {
                // Sticky without a session key: intentional RR fallback.
                mark_missing_signal();
                let cursor = counter.fetch_add(1, Ordering::Relaxed);
                Some(enabled[cursor as usize % enabled.len()].0)
            }
            RoutingStrategy::Race => {
                clear_fallback();
                Some(enabled[0].0)
            }
            RoutingStrategy::Cascade(ref cfg) => {
                clear_fallback();
                if let Some(first) = cfg.tiers.first() {
                    for &(idx, p) in enabled {
                        if p.name == first.provider_id {
                            return Some(idx);
                        }
                    }
                }
                Some(enabled[0].0)
            }
            RoutingStrategy::CostQuality(ref cfg) => {
                clear_fallback();
                for &(idx, p) in enabled {
                    if p.name == cfg.cheap_provider {
                        return Some(idx);
                    }
                }
                Some(enabled[0].0)
            }
            RoutingStrategy::OutcomeAware => {
                clear_fallback();
                self.select_outcome_aware(enabled, counter)
            }
            RoutingStrategy::Headroom => {
                clear_fallback();
                self.select_headroom(enabled)
            }
            RoutingStrategy::ResetAware => {
                clear_fallback();
                self.select_reset_aware(enabled)
            }
            RoutingStrategy::SemanticRoute(_) => {
                // The synchronous select path has no prompt to embed, so
                // this arm is the strategy's declared secondary: an
                // intentional round-robin over the eligible set, marked
                // as a missing-signal fallback the way PrefixAffinity and
                // Sticky mark theirs. The dispatcher's async path is
                // where the embedding, the floor, and the declared
                // `fallback` deployment apply.
                mark_missing_signal();
                let cursor = counter.fetch_add(1, Ordering::Relaxed);
                Some(enabled[cursor as usize % enabled.len()].0)
            }
        }
    }

    /// Prefer lowest known-fresh request pressure; ties keep enabled order.
    /// Unknown/stale candidates sort after known observations.
    fn select_headroom(&self, enabled: &[(usize, &ProviderConfig)]) -> Option<usize> {
        if enabled.is_empty() {
            return None;
        }
        let mut best_idx = enabled[0].0;
        // (tier, pressure_millis, stable_pos): lower is better.
        // tier 0 = known pressure, 1 = unknown/stale
        let mut best_key = (2u8, u64::MAX, 0usize);
        for (pos, &(idx, p)) in enabled.iter().enumerate() {
            let snap = self.quota.snapshot(&p.name);
            let key = match snap.request_pressure() {
                Some(pressure) => {
                    let millis = (pressure.clamp(0.0, 1.0) * 1_000_000.0) as u64;
                    (0u8, millis, pos)
                }
                None => (1u8, 0u64, pos),
            };
            if pos == 0 || key < best_key {
                best_key = key;
                best_idx = idx;
            }
        }
        Some(best_idx)
    }

    /// Prefer providers with positive capacity now; otherwise the earliest
    /// reset among exhausted candidates. Unknown/stale sort last.
    fn select_reset_aware(&self, enabled: &[(usize, &ProviderConfig)]) -> Option<usize> {
        if enabled.is_empty() {
            return None;
        }
        let now = std::time::Instant::now();
        let mut best_idx = enabled[0].0;
        let mut best_key: (u8, u128, usize) = (2, u128::MAX, 0);
        // tier 0 = has positive capacity now
        // tier 1 = exhausted with known reset (rank by earliest reset)
        // tier 2 = unknown/stale / no reset
        for (pos, &(idx, p)) in enabled.iter().enumerate() {
            let snap = self.quota.snapshot(&p.name);
            let key = if snap.has_positive_capacity() {
                (0u8, 0u128, pos)
            } else if snap.quality == crate::provider_ratelimit::QuotaSignalQuality::KnownFresh {
                match snap.reset_at {
                    Some(reset) => {
                        let nanos = reset.saturating_duration_since(now).as_nanos();
                        (1u8, nanos, pos)
                    }
                    None => (2u8, u128::MAX, pos),
                }
            } else {
                (2u8, u128::MAX, pos)
            };
            if pos == 0 || key < best_key {
                best_key = key;
                best_idx = idx;
            }
        }
        Some(best_idx)
    }

    /// Pick the enabled provider with the best realized cost-per-success
    /// from the global feedback store.
    ///
    /// During warm-up, learned selections are blended with round-robin in
    /// exact proportion to the least-observed candidate's confidence. The
    /// fallback has its own cursor, so learned schedule positions cannot
    /// starve providers of exploration. A fresh process still begins with
    /// pure round-robin.
    fn select_outcome_aware(
        &self,
        enabled: &[(usize, &ProviderConfig)],
        counter: &AtomicU64,
    ) -> Option<usize> {
        if enabled.is_empty() {
            return None;
        }
        let names: Vec<&str> = enabled.iter().map(|(_, p)| p.name.as_str()).collect();
        let store = crate::routing_feedback::FeedbackStore::global();
        let cursor = counter.fetch_add(1, Ordering::Relaxed);
        let (learned_slots, total_slots) = store.confidence(&names);
        if learned_slots > 0 && cursor % total_slots < learned_slots {
            if let Some(pos) = store.best_among(&names) {
                return Some(enabled[pos].0);
            }
        }
        crate::ai_metrics::record_routing_fallback("outcome_aware", "warmup");
        let fallback_cursor = self
            .outcome_fallback_counter
            .fetch_add(1, Ordering::Relaxed);
        Some(enabled[fallback_cursor as usize % enabled.len()].0)
    }

    /// Returns true when the configured strategy is `Race`. The AI
    /// client uses this to decide whether to fan out the request.
    pub fn is_race(&self) -> bool {
        matches!(self.strategy, RoutingStrategy::Race)
    }

    /// Return whether the dispatcher should normalize the request and use a
    /// prefix-aware selection method. Non-prefix strategies can skip that
    /// request-body work.
    pub fn is_prefix_affinity(&self) -> bool {
        matches!(self.strategy, RoutingStrategy::PrefixAffinity(_))
    }

    /// Select a live holder for a normalized prefix, falling back to the
    /// lowest recent-token load when no holder is known.
    pub fn select_with_prefix(
        &self,
        providers: &[ProviderConfig],
        prefix: Option<PrefixDigest>,
    ) -> Option<usize> {
        self.select_with_prefix_policy(providers, prefix, &[], &[])
    }

    /// Prefix-aware selection constrained by a credential provider policy.
    /// Policy filtering is applied before state lookup, and an empty
    /// policy-filtered set fails closed instead of falling back.
    pub fn select_with_prefix_policy(
        &self,
        providers: &[ProviderConfig],
        prefix: Option<PrefixDigest>,
        allowed: &[String],
        blocked: &[String],
    ) -> Option<usize> {
        let candidates = providers
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                p.enabled && provider_allowed_by_policy(p.name.as_str(), allowed, blocked)
            })
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();
        self.select_with_prefix_candidates(providers, prefix, &candidates)
    }

    /// Prefix-aware selection constrained to the dispatcher's exact final
    /// candidate indices.
    ///
    /// Disabled, unhealthy, breaker-blocked, and ejected candidates are
    /// removed without all-ineligible revival. A known prefix holder wins when
    /// it remains live; holder ties keep the deterministic ordering maintained
    /// by the bounded replica state. Otherwise the least recent-token load
    /// among the remaining candidates wins.
    pub fn select_with_prefix_candidates(
        &self,
        providers: &[ProviderConfig],
        prefix: Option<PrefixDigest>,
        candidate_indices: &[usize],
    ) -> Option<usize> {
        let eligible = self.eligible_candidate_indices(providers, candidate_indices);
        if eligible.is_empty() {
            return None;
        }
        let picked = match prefix {
            Some(prefix) => {
                if let Some(holder) = self.replica_state.select_holder(&prefix, &eligible) {
                    crate::ai_metrics::record_prefix_affinity_decision("hit");
                    holder
                } else {
                    crate::ai_metrics::record_prefix_affinity_decision("miss");
                    crate::ai_metrics::record_routing_fallback("prefix_affinity", "no_holder");
                    let tie_cursor = self.counter.fetch_add(1, Ordering::Relaxed);
                    self.replica_state.least_loaded(&eligible, tie_cursor)?
                }
            }
            None => {
                crate::ai_metrics::record_prefix_affinity_decision("missing_signal");
                crate::ai_metrics::record_routing_fallback("prefix_affinity", "missing_signal");
                let tie_cursor = self.counter.fetch_add(1, Ordering::Relaxed);
                self.replica_state.least_loaded(&eligible, tie_cursor)?
            }
        };
        let provider = providers.get(picked)?;
        crate::ai_metrics::record_lb_decision(self.strategy_name(), &provider.name);
        Some(picked)
    }

    /// Arm caller-keyed prompt-cache affinity for this router.
    ///
    /// Builder-shaped like [`Self::with_circuit_breakers`] and attached by
    /// the origin's `cache_affinity` block and by nothing else, so a router
    /// whose operator did not ask for affinity allocates no lease tables.
    /// Bounds are validated at config load, so a rejection here means the
    /// load-time check was bypassed. The router stays usable with affinity
    /// off and logs the reason rather than panicking a live proxy.
    #[must_use]
    pub fn with_cache_affinity(mut self, config: CacheAffinityConfig) -> Self {
        let provider_count = self.latencies.len();
        if let Err(error) = self
            .replica_state
            .enable_cache_affinity(provider_count, config)
        {
            tracing::error!(
                %error,
                "ai prompt-cache affinity bounds rejected; affinity stays disabled"
            );
        }
        self
    }

    /// Whether caller-keyed prompt-cache affinity is armed on this router.
    #[must_use]
    pub fn cache_affinity_enabled(&self) -> bool {
        self.replica_state.cache_affinity_enabled()
    }

    /// Prefer the provider already holding this caller's warm prompt cache.
    ///
    /// Returns an index from `candidate_indices` only. The list is first
    /// narrowed by [`Self::eligible_candidate_indices`], so health, circuit
    /// breakers, outlier ejection, and everything the dispatcher already
    /// filtered on keep winning: this is a preference over the strategy's
    /// pick, never a pin. `None` leaves the strategy's ordering untouched.
    ///
    /// Every call records exactly one
    /// `sbproxy_ai_cache_affinity_decisions_total` outcome. The dispatcher
    /// records `missing_signal` on the requests that never reach here for
    /// want of a cache key, so the five outcomes together total the requests
    /// an affinity-enabled origin evaluated.
    pub fn select_cache_affinity(
        &self,
        providers: &[ProviderConfig],
        key: &CacheAffinityKey,
        resolved_model: &str,
        candidate_indices: &[usize],
    ) -> Option<usize> {
        if !self.replica_state.cache_affinity_enabled() {
            return None;
        }
        let eligible = self.eligible_candidate_indices(providers, candidate_indices);
        match self
            .replica_state
            .select_cache_holder(key, resolved_model, &eligible)
        {
            CacheAffinityLookup::Hit(provider_idx) => {
                crate::ai_metrics::record_cache_affinity_decision("hit");
                Some(provider_idx)
            }
            CacheAffinityLookup::Miss => {
                crate::ai_metrics::record_cache_affinity_decision("miss");
                None
            }
            CacheAffinityLookup::Ineligible => {
                crate::ai_metrics::record_cache_affinity_decision("ineligible");
                None
            }
            CacheAffinityLookup::ModelChanged => {
                crate::ai_metrics::record_cache_affinity_decision("model_changed");
                None
            }
        }
    }

    /// Record that an accepted response left one provider holding this
    /// caller's warm prompt cache for `resolved_model`.
    pub fn record_cache_affinity(
        &self,
        provider_idx: usize,
        key: CacheAffinityKey,
        resolved_model: &str,
    ) {
        self.replica_state
            .record_cache_holder(provider_idx, key, resolved_model);
    }

    /// Record that an accepted response populated one provider's prefix cache.
    pub fn record_prefix(&self, provider_idx: usize, prefix: PrefixDigest) {
        self.replica_state.record_prefix(provider_idx, prefix);
    }

    /// Record prefix ownership after looking up a provider by stable name.
    pub fn record_prefix_for_provider(
        &self,
        providers: &[ProviderConfig],
        provider_name: &str,
        prefix: PrefixDigest,
    ) {
        if let Some((provider_idx, _)) = providers
            .iter()
            .enumerate()
            .find(|(_, provider)| provider.name == provider_name)
        {
            self.record_prefix(provider_idx, prefix);
        }
    }

    /// WOR-798: snake_case name of the active strategy, used as the
    /// `strategy` label on `sbproxy_ai_lb_decisions_total` and any
    /// other strategy-tagged telemetry.
    pub fn strategy_name(&self) -> &'static str {
        strategy_name(&self.strategy)
    }

    /// WOR-2651: whether this strategy produces a candidate order the
    /// operator authored, which a prompt-cache lease must not jump.
    ///
    /// `fallback_chain` sorts by declared priority, `cascade` walks
    /// tiers in cost order, and `cost_quality` splits cheap against
    /// frontier per request. Each is an order somebody wrote down on
    /// purpose, so moving a lease holder to the front of it would
    /// defeat the strategy rather than compose with it. (A
    /// `routing_policy` plan is the fourth of that set, but it is not a
    /// `RoutingStrategy` variant: the dispatcher checks for it
    /// separately.)
    ///
    /// The `fallback_chain` arm is the one that was missing. The
    /// dispatch site named all four in a comment and checked three, so
    /// a priority-sorted chain silently had its first candidate
    /// replaced by whichever provider held the caller's lease, and
    /// recorded a lease of its own on every success.
    pub fn owns_candidate_order(&self) -> bool {
        matches!(
            self.strategy,
            RoutingStrategy::FallbackChain
                | RoutingStrategy::Cascade(_)
                | RoutingStrategy::CostQuality(_)
        )
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

    /// Borrow the semantic-route config when the configured strategy is
    /// [`RoutingStrategy::SemanticRoute`] (WOR-2564). The dispatcher uses
    /// this to run the embed-and-match step before provider ordering.
    pub fn semantic_route_config(&self) -> Option<&semantic_route::SemanticRouteConfig> {
        match &self.strategy {
            RoutingStrategy::SemanticRoute(cfg) => Some(cfg.as_ref()),
            _ => None,
        }
    }

    /// Return the resilience-eligible subset of an exact candidate list.
    ///
    /// Input order is preserved. Disabled, unknown, unhealthy,
    /// breaker-blocked, and ejected entries are omitted. If every supplied
    /// candidate is omitted, the result stays empty; this strict API never
    /// revives the all-ineligible set.
    pub fn eligible_candidate_indices(
        &self,
        providers: &[ProviderConfig],
        candidate_indices: &[usize],
    ) -> Vec<usize> {
        candidate_indices
            .iter()
            .copied()
            .filter(|idx| {
                providers.get(*idx).is_some_and(|provider| {
                    provider.enabled && self.provider_eligible(*idx, provider.name.as_str())
                })
            })
            .collect()
    }

    /// The candidate list narrowed to resilience-eligible providers, or
    /// the list's still-enabled members when that narrowing empties it.
    ///
    /// Callers hand this the set a request is already permitted to use:
    /// credential policy, model eligibility, and the training opt-out
    /// have run, and those stay hard here. `enabled` stays hard too;
    /// it is an operator switch, not a health signal. The three
    /// resilience axes are the soft part, because what they express is
    /// which provider is the better bet among several. With nothing
    /// left to prefer they have nothing to say, and refusing the
    /// request would let three advisory signals combine into an outage
    /// none of them can cause alone.
    ///
    /// This is what `resilience` has promised since it shipped, in
    /// `docs/configuration.md` and in `examples/ai-resilience`, what
    /// [`Self::select`] already does, and what the load balancer's own
    /// three-axis filter does with the same reasoning. Reach for
    /// [`Self::eligible_candidate_indices`] instead where reviving is
    /// wrong: the cascade asks per tier, and skipping to the next tier
    /// is already its fallback.
    pub fn routable_candidate_indices(
        &self,
        providers: &[ProviderConfig],
        candidate_indices: &[usize],
    ) -> Vec<usize> {
        let eligible = self.eligible_candidate_indices(providers, candidate_indices);
        if !eligible.is_empty() {
            return eligible;
        }
        let enabled = candidate_indices
            .iter()
            .copied()
            .filter(|idx| providers.get(*idx).is_some_and(|provider| provider.enabled))
            .collect::<Vec<_>>();
        if !enabled.is_empty() {
            // Debug rather than warn because this sits on the request
            // path and would repeat per request for as long as the pool
            // stays down. The ejections that produced this state each
            // logged a warning once, at the transition, which is the
            // signal an operator should be alerting on.
            tracing::debug!(
                candidates = enabled.len(),
                "every eligible ai provider is ejected; routing to the full permitted set"
            );
        }
        enabled
    }

    /// Select with the configured strategy from an exact candidate list.
    ///
    /// The supplied order is retained for strategy tie-breaking. Resilience
    /// filtering is strict, so an all-ineligible set returns `None` without
    /// reviving candidates. Successful selections record the same normal
    /// load-balancer decision metric as [`Self::select`].
    pub fn select_with_candidates(
        &self,
        providers: &[ProviderConfig],
        candidate_indices: &[usize],
    ) -> Option<usize> {
        let eligible = self.eligible_candidate_indices(providers, candidate_indices);
        let eligible = eligible
            .into_iter()
            .filter_map(|idx| providers.get(idx).map(|provider| (idx, provider)))
            .collect::<Vec<_>>();
        let picked = self.select_from_candidates(&eligible, true);
        if let Some(idx) = picked {
            if let Some(provider) = providers.get(idx) {
                crate::ai_metrics::record_lb_decision(self.strategy_name(), &provider.name);
            }
        }
        picked
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

    #[test]
    fn provider_blocklist_overrides_allowlist() {
        // A block entry always wins, including over an explicit allow
        // of the same name. Every caller of this predicate (the
        // selection paths, the shadow gate, the cascade's per-tier
        // eligibility) inherits that precedence from here, which is
        // why it is pinned beside the function rather than in one
        // caller's test module.
        let allowed = vec!["openai".to_string()];
        let blocked = vec!["openai".to_string()];

        assert!(!provider_allowed_by_policy("openai", &allowed, &blocked));
        assert!(provider_allowed_by_policy("openai", &allowed, &[]));
    }

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
            accept_native_credentials_for: None,
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
            data_posture: None,
            service_tier: None,
            on_key_failure: crate::provider::KeyFailurePosture::Fallback,
            fallback_credential_id: None,
            serve: None,
            aws_sigv4: None,
            bedrock_guardrail: None,
        }
    }

    fn normalized_prefix(label: &str) -> PrefixDigest {
        crate::routing_state::normalize_prefix(
            &serde_json::json!({
                "messages": [
                    {"role": "system", "content": "Be concise."},
                    {"role": "user", "content": label}
                ]
            }),
            "model:test",
        )
        .expect("test request has a prefix")
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
    fn provider_runtime_states_reflects_recorded_signals() {
        let router = Router::new(RoutingStrategy::RoundRobin, 2);
        router.record_latency(0, 5_000); // 5ms, stored directly (no EWMA)
        router.record_tokens(0, 42);
        router.set_provider_health(1, false); // provider 1 unhealthy
        let guard = router.track_in_flight(0); // one in-flight on provider 0

        let states = router.provider_runtime_states();
        assert_eq!(states.len(), 2);

        // Provider 0: recorded latency + tokens + one in-flight; no probe so
        // health is unknown (reads healthy); no breaker so circuit is closed.
        assert_eq!(states[0].latency_us, 5_000);
        assert_eq!(states[0].tokens_used, 42);
        assert_eq!(states[0].in_flight, 1);
        assert!(states[0].healthy);
        assert_eq!(states[0].health, "unknown");
        assert!(!states[0].circuit_open);
        assert_eq!(states[0].circuit, "closed");

        // Provider 1: probe marked it unhealthy.
        assert!(!states[1].healthy);
        assert_eq!(states[1].health, "unhealthy");

        // Dropping the guard releases the in-flight slot.
        drop(guard);
        assert_eq!(router.provider_runtime_states()[0].in_flight, 0);
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

    /// WOR-2651: every strategy whose order a cache-affinity lease must
    /// not jump, and a sample of the ones it may.
    ///
    /// All three arms of the predicate are exercised, because a
    /// predicate wider than its test is how the `fallback_chain` gap
    /// this test was written to close survived in the first place:
    /// deleting an untested arm leaves the suite green.
    ///
    /// Red before the fix on the `fallback_chain` arm: the dispatch
    /// site excluded `cascade` and `cost_quality` and never excluded
    /// the chain, while both the doc and the comment above the check
    /// said all of them were excluded.
    #[test]
    fn the_authored_orderings_own_their_candidate_order() {
        let cascade: CascadeConfig = serde_json::from_value(serde_json::json!({
            "tiers": [
                {"provider_id": "cheap", "model": "cheap-model", "quality_threshold": 0.5},
                {"provider_id": "frontier", "model": "frontier-model", "quality_threshold": 0.9}
            ]
        }))
        .expect("cascade fixture");
        let cost_quality: crate::cost_quality::CostQualityConfig =
            serde_json::from_value(serde_json::json!({
                "cheap_provider": "cheap",
                "frontier_provider": "frontier"
            }))
            .expect("cost_quality fixture");
        for strategy in [
            RoutingStrategy::FallbackChain,
            RoutingStrategy::Cascade(cascade),
            RoutingStrategy::CostQuality(cost_quality),
        ] {
            let name = strategy_name(&strategy);
            assert!(
                Router::new(strategy, 2).owns_candidate_order(),
                "{name} orders its own candidates and a lease must not jump it"
            );
        }
        for strategy in [
            RoutingStrategy::RoundRobin,
            RoutingStrategy::Random,
            RoutingStrategy::LowestLatency,
        ] {
            let name = strategy_name(&strategy);
            assert!(
                !Router::new(strategy, 2).owns_candidate_order(),
                "{name} produces an order a lease is allowed to re-front"
            );
        }
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
        assert!(matches!(strategy, RoutingStrategy::PrefixAffinity(_)));

        let json = serde_json::json!("sticky");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        assert!(matches!(strategy, RoutingStrategy::Sticky));

        let json = serde_json::json!("peak_ewma");
        let strategy: RoutingStrategy = serde_json::from_value(json).unwrap();
        let RoutingStrategy::PeakEwma(config) = strategy else {
            panic!("expected peak_ewma");
        };
        assert_eq!(config.half_life_secs, 10);
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
    fn prefix_affinity_routes_a_continuation_to_its_observed_holder() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
        ];
        let router = Router::new(
            RoutingStrategy::PrefixAffinity(PrefixAffinityConfig::default()),
            providers.len(),
        );
        let first_turn = serde_json::json!({
            "messages": [
                {"role": "system", "content": "Be concise."},
                {"role": "user", "content": "Summarize this."}
            ]
        });
        let continuation = serde_json::json!({
            "messages": [
                {"role": "system", "content": "Be concise."},
                {"role": "user", "content": "Summarize this."},
                {"role": "assistant", "content": "Summary."},
                {"role": "user", "content": "Shorter."}
            ]
        });
        let first_prefix =
            crate::routing_state::normalize_prefix(&first_turn, "model:test").expect("prefix");
        let continued_prefix =
            crate::routing_state::normalize_prefix(&continuation, "model:test").expect("prefix");
        assert_eq!(continued_prefix, first_prefix);

        let first = router
            .select_with_prefix(&providers, Some(first_prefix))
            .expect("least-load fallback");
        router.record_prefix(first, first_prefix);
        router.record_tokens(first, 1_000);

        assert_eq!(
            router.select_with_prefix(&providers, Some(continued_prefix)),
            Some(first),
            "the live holder must win even when the other replica is less loaded"
        );
    }

    #[test]
    fn prefix_affinity_miss_uses_recent_token_load() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
        ];
        let router = Router::new(
            RoutingStrategy::PrefixAffinity(PrefixAffinityConfig::default()),
            providers.len(),
        );
        router.record_tokens(0, 500);

        assert_eq!(
            router.select_with_prefix(&providers, Some(normalized_prefix("new conversation"))),
            Some(1)
        );
    }

    #[test]
    fn prefix_affinity_missing_signal_rotates_exact_load_ties() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(
            RoutingStrategy::PrefixAffinity(PrefixAffinityConfig::default()),
            providers.len(),
        );
        let mut counts = [0u32; 3];
        for _ in 0..30 {
            let idx = router
                .select_with_prefix(&providers, None)
                .expect("least-load fallback");
            counts[idx] += 1;
        }
        assert_eq!(counts, [10, 10, 10]);
    }

    #[test]
    fn prefix_affinity_single_provider_always_returns_it() {
        let providers = vec![make_provider("only", 1, None, true)];
        let router = Router::new(
            RoutingStrategy::PrefixAffinity(PrefixAffinityConfig::default()),
            providers.len(),
        );
        assert_eq!(
            router.select_with_prefix(&providers, Some(normalized_prefix("any prefix"))),
            Some(0)
        );
        assert_eq!(router.select_with_prefix(&providers, None), Some(0));
    }

    #[test]
    fn prefix_affinity_skips_disabled_providers() {
        let providers = vec![
            make_provider("a", 1, None, false),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(
            RoutingStrategy::PrefixAffinity(PrefixAffinityConfig::default()),
            providers.len(),
        );
        let prefix = normalized_prefix("holder becomes disabled");
        router.record_prefix(0, prefix);

        let idx = router
            .select_with_prefix(&providers, Some(prefix))
            .expect("eligible fallback");
        assert_ne!(idx, 0, "disabled holder must not be picked");
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
        let router = Router::new(
            RoutingStrategy::PrefixAffinity(PrefixAffinityConfig::default()),
            providers.len(),
        );
        let mut counts = [0u32; 3];
        for _ in 0..30 {
            counts[router.select(&providers).unwrap()] += 1;
        }
        assert_eq!(counts, [10, 10, 10]);
    }

    #[test]
    fn is_prefix_affinity_only_true_for_that_variant() {
        assert!(Router::new(
            RoutingStrategy::PrefixAffinity(PrefixAffinityConfig::default()),
            1
        )
        .is_prefix_affinity());
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
            Router::new(RoutingStrategy::PeakEwma(PeakEwmaConfig::default()), 1).strategy_name(),
            "peak_ewma"
        );
        assert_eq!(
            Router::new(RoutingStrategy::LeastTokenUsage, 1).strategy_name(),
            "least_token_usage"
        );
        assert_eq!(
            Router::new(
                RoutingStrategy::PrefixAffinity(PrefixAffinityConfig::default()),
                1
            )
            .strategy_name(),
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
    fn outcome_aware_fallback_visits_every_provider_across_complete_schedules() {
        use crate::routing_feedback::{FeedbackStore, Outcome};

        for confidence in 1..=4u64 {
            let providers = (0..5)
                .map(|index| {
                    make_provider(&format!("oa_blend_{confidence}_{index}"), 1, None, true)
                })
                .collect::<Vec<_>>();
            let store = FeedbackStore::global();
            for provider in &providers {
                for _ in 0..confidence {
                    store.record(&Outcome {
                        provider: &provider.name,
                        success: true,
                        refused: false,
                        cost_usd: if provider.name.ends_with("_4") {
                            0.001
                        } else {
                            0.100
                        },
                        latency_ms: 100,
                    });
                }
            }

            let router = Router::new(RoutingStrategy::OutcomeAware, providers.len());
            let mut counts = [0u64; 5];
            // Five complete five-slot confidence schedules provide a whole
            // number of fallback turns for every provider at every partial
            // confidence. Each provider must receive an equal share of those
            // fallback turns, independent of where the learned winner sits.
            for _ in 0..25 {
                counts[router.select(&providers).expect("provider")] += 1;
            }

            let fallback_per_provider = 5 - confidence;
            assert_eq!(
                counts[..4],
                [fallback_per_provider; 4],
                "{confidence}/5 confidence must still give every non-winner an equal fallback share"
            );
            assert_eq!(
                counts[4],
                fallback_per_provider + 5 * confidence,
                "{confidence}/5 confidence must add learned picks without consuming the winner's \
                 fallback share"
            );
        }
    }

    #[test]
    fn outcome_feedback_survives_router_rebuild_for_hot_reload() {
        use crate::routing_feedback::{FeedbackStore, Outcome};

        let providers = vec![
            make_provider("oa_reload_expensive", 1, None, true),
            make_provider("oa_reload_efficient", 1, None, true),
        ];
        let store = FeedbackStore::global();
        for _ in 0..5 {
            store.record(&Outcome {
                provider: "oa_reload_expensive",
                success: true,
                refused: false,
                cost_usd: 0.100,
                latency_ms: 100,
            });
            store.record(&Outcome {
                provider: "oa_reload_efficient",
                success: true,
                refused: false,
                cost_usd: 0.001,
                latency_ms: 100,
            });
        }

        let before_reload = Router::new(RoutingStrategy::OutcomeAware, providers.len());
        assert_eq!(before_reload.select(&providers), Some(1));
        drop(before_reload);

        let after_reload = Router::new(RoutingStrategy::OutcomeAware, providers.len());
        assert_eq!(
            after_reload.select(&providers),
            Some(1),
            "replacing a handler/router must not replace process-wide feedback"
        );
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
        let router = Router::new(
            RoutingStrategy::PeakEwma(PeakEwmaConfig::default()),
            providers.len(),
        );
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
        let router = Router::new(
            RoutingStrategy::PeakEwma(PeakEwmaConfig::default()),
            providers.len(),
        );
        assert_eq!(router.select(&providers).unwrap(), 0);
    }

    #[test]
    fn peak_ewma_in_flight_load_breaks_equal_latency_tie() {
        let providers = vec![
            make_provider("queued", 1, None, true),
            make_provider("idle", 1, None, true),
        ];
        let router = Router::new(
            RoutingStrategy::PeakEwma(PeakEwmaConfig::default()),
            providers.len(),
        );
        router.record_latency(0, 1_000);
        router.record_latency(1, 1_000);
        router.record_connect(0);

        for _ in 0..10 {
            assert_eq!(router.select(&providers), Some(1));
        }

        router.record_disconnect(0);
        let selections = (0..10)
            .map(|_| router.select(&providers).expect("provider"))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(selections, std::collections::HashSet::from([0, 1]));
    }

    #[test]
    fn in_flight_guard_balances_on_drop_and_ignores_unknown_provider() {
        let router = Router::new(RoutingStrategy::LeastConnections, 2);
        assert_eq!(router.connections[0].load(Ordering::Relaxed), 0);

        {
            let _guard = router.track_in_flight(0);
            assert_eq!(router.connections[0].load(Ordering::Relaxed), 1);
        }
        assert_eq!(router.connections[0].load(Ordering::Relaxed), 0);

        {
            let _guard = router.track_in_flight(99);
        }
        assert_eq!(router.connections[0].load(Ordering::Relaxed), 0);
        assert_eq!(router.connections[1].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn peak_ewma_deserializes_from_snake_case() {
        let s: RoutingStrategy = serde_json::from_value(serde_json::json!("peak_ewma")).unwrap();
        assert!(matches!(s, RoutingStrategy::PeakEwma(_)));
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

    #[test]
    fn sticky_map_is_bounded_under_unique_session_keys() {
        // WOR-1693: session keys are client-chosen and unique in the
        // worst case, so pinning far more sessions than the cap must not
        // grow the map without bound.
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::Sticky, providers.len());
        let total = MAX_STICKY_SESSIONS + 100;
        for i in 0..total {
            router.select_sticky(&providers, &format!("session-{i}"));
        }
        assert_eq!(router.sticky_map.lock().len(), MAX_STICKY_SESSIONS);
        // The most recent session kept its pin; the oldest aged out and
        // re-pins on its next request instead of failing.
        let newest = format!("session-{}", total - 1);
        assert!(router.sticky_map.lock().contains(&newest));
        assert!(!router.sticky_map.lock().contains("session-0"));
        assert!(router.select_sticky(&providers, "session-0").is_some());
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

    #[test]
    fn select_with_policy_blocked_provider_overrides_allowlist() {
        let router = Router::new(RoutingStrategy::RoundRobin, 2);
        let providers = vec![
            make_provider("openai", 1, None, true),
            make_provider("anthropic", 1, None, true),
        ];
        let allowed = vec!["openai".to_string(), "anthropic".to_string()];
        let blocked = vec!["openai".to_string()];

        for _ in 0..4 {
            let pick = router
                .select_with_policy(&providers, &allowed, &blocked)
                .expect("anthropic remains eligible");
            assert_eq!(providers[pick].name, "anthropic");
        }
    }

    #[test]
    fn select_with_policy_blocklist_applies_without_allowlist() {
        let router = Router::new(RoutingStrategy::RoundRobin, 2);
        let providers = vec![
            make_provider("openai", 1, None, true),
            make_provider("anthropic", 1, None, true),
        ];
        let blocked = vec!["openai".to_string()];

        let pick = router
            .select_with_policy(&providers, &[], &blocked)
            .expect("anthropic remains eligible");
        assert_eq!(providers[pick].name, "anthropic");
    }

    // --- Resilience axes (WOR-2233) ---
    //
    // Every test below fails against the router as it shipped, because
    // `breakers` was empty and `outlier` was `None` on every router the
    // proxy ever built, so both arms of `provider_eligible` passed
    // unconditionally and `check_ejections` never ran.

    #[test]
    fn a_breaker_that_reached_its_threshold_takes_its_provider_out_of_rotation() {
        let providers = vec![
            make_provider("failing", 1, None, true),
            make_provider("healthy", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len())
            .with_circuit_breakers(2, 1, 30);

        router.record_provider_failure(0, "failing");
        assert_eq!(
            router.eligible_indices(&providers),
            vec![0, 1],
            "one failure is under the threshold"
        );

        router.record_provider_failure(0, "failing");
        assert_eq!(
            router.eligible_indices(&providers),
            vec![1],
            "the second failure opens the breaker and the provider leaves"
        );
        for _ in 0..4 {
            assert_eq!(router.select(&providers), Some(1));
        }
    }

    #[test]
    fn an_open_breaker_admits_a_probe_once_its_cooldown_elapses_and_closes_on_success() {
        let providers = vec![
            make_provider("recovering", 1, None, true),
            make_provider("healthy", 1, None, true),
        ];
        // A zero cooldown makes the Open -> HalfOpen transition
        // observable without sleeping; the transition is driven by
        // elapsed time either way.
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len())
            .with_circuit_breakers(1, 1, 0);

        router.record_provider_failure(0, "recovering");
        // `allow_request` performs the transition, so the provider is
        // back as a half-open probe on the very next eligibility check.
        assert_eq!(router.eligible_indices(&providers), vec![0, 1]);

        router.record_provider_success(0, "recovering");
        assert_eq!(
            router.breakers()[0].state(),
            sbproxy_platform::circuitbreaker::CircuitState::Closed,
            "one half-open success meets success_threshold 1 and closes it"
        );

        // WOR-2486: both transitions above must land on
        // `sbproxy_circuit_breaker_transitions_total`. Before this
        // wiring the AI-provider breaker only logged; the metric never
        // fired for this call site, which made the provider-health
        // dashboard blind to exactly the axis this test exists for.
        // The counter lives on `ProxyMetrics`'s own registry rather than
        // `prometheus::default_registry()`, so `render()` (which gathers
        // both) is the only way to see it from this crate. Scanned by
        // line, checking every label is present rather than a fixed
        // substring, so the assertion does not depend on the encoder's
        // label ordering.
        let rendered = sbproxy_observe::metrics::metrics().render();
        let transition_lines: Vec<&str> = rendered
            .lines()
            .filter(|line| {
                line.starts_with("sbproxy_circuit_breaker_transitions_total{")
                    && line.contains("origin=\"recovering\"")
            })
            .collect();
        assert!(
            transition_lines
                .iter()
                .any(|l| l.contains("from_state=\"closed\"") && l.contains("to_state=\"open\"")),
            "the failure must record closed->open: {transition_lines:?}"
        );
        assert!(
            transition_lines.iter().any(
                |l| l.contains("from_state=\"half_open\"") && l.contains("to_state=\"closed\"")
            ),
            "the recovery must record half_open->closed: {transition_lines:?}"
        );
    }

    /// The outlier axis clears on its own clock, and clears without any
    /// caller sweeping it: `is_ejected` drops an entry whose deadline
    /// has passed as it reads over it. A zero-second ejection makes
    /// that observable without a sleep, since the deadline is already
    /// in the past by the first read.
    #[test]
    fn an_outlier_ejection_lapses_without_anyone_sweeping_it() {
        let providers = vec![
            make_provider("flaky", 1, None, true),
            make_provider("healthy", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len())
            .with_outlier_detection(OutlierDetectorConfig {
                threshold: 0.5,
                window_secs: 60,
                min_requests: 2,
                ejection_duration_secs: 0,
            });

        router.record_provider_failure(0, "flaky");
        router.record_provider_failure(0, "flaky");
        assert!(
            router
                .outlier
                .as_ref()
                .expect("detector")
                .check_ejections()
                .is_empty(),
            "the second failure already ejected it, so there is nothing new to report"
        );
        assert_eq!(
            router.eligible_indices(&providers),
            vec![0, 1],
            "a lapsed ejection re-admits on the next eligibility read"
        );
    }

    #[test]
    fn an_outlier_ejection_holds_a_provider_out_while_it_is_live() {
        let providers = vec![
            make_provider("flaky", 1, None, true),
            make_provider("healthy", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len())
            .with_outlier_detection(OutlierDetectorConfig {
                threshold: 0.5,
                window_secs: 60,
                min_requests: 2,
                ejection_duration_secs: 300,
            });

        router.record_provider_failure(0, "flaky");
        router.record_provider_failure(0, "flaky");
        assert_eq!(router.eligible_indices(&providers), vec![1]);
        for _ in 0..4 {
            assert_eq!(router.select(&providers), Some(1));
        }
    }

    #[test]
    fn each_axis_is_armed_only_by_its_own_config_block() {
        let router = Router::new(RoutingStrategy::RoundRobin, 2)
            .with_outlier_detection(OutlierDetectorConfig::default());
        assert!(
            router.breakers().is_empty(),
            "outlier_detection alone must not arm circuit breakers on defaults nobody asked for"
        );

        let router = Router::new(RoutingStrategy::RoundRobin, 2).with_circuit_breakers(5, 2, 30);
        assert_eq!(router.breakers().len(), 2, "one breaker per provider slot");
        assert!(
            router.outlier.is_none(),
            "circuit_breaker alone must not arm outlier detection"
        );
    }

    /// A provider that failed on more than one axis has to clear every
    /// axis it failed before it returns, and no axis speaks for another.
    /// The breaker here clears itself on elapsed time while the probe
    /// verdict stands until a probe changes it, which is exactly the
    /// mismatch that makes cross-feeding the axes a trap: one signal
    /// written into both would leave a provider ejected until an
    /// unrelated clock agreed.
    #[test]
    fn a_provider_returns_only_once_every_axis_it_failed_has_cleared() {
        let providers = vec![
            make_provider("both", 1, None, true),
            make_provider("healthy", 1, None, true),
        ];
        // A zero cooldown means the breaker is willing again the moment
        // it is asked, so what is left holding the provider out is only
        // the probe verdict.
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len())
            .with_circuit_breakers(1, 1, 0);

        router.record_provider_failure(0, "both");
        router.set_provider_health(0, false);
        assert_eq!(
            router.eligible_indices(&providers),
            vec![1],
            "a breaker that has already cooled down does not revive the health axis"
        );

        router.set_provider_health(0, true);
        assert_eq!(
            router.eligible_indices(&providers),
            vec![0, 1],
            "both axes have cleared on their own terms, so the provider is back"
        );
    }

    #[test]
    fn an_all_ejected_pool_routes_to_the_permitted_set_rather_than_refusing() {
        let providers = vec![
            make_provider("first", 1, None, true),
            make_provider("second", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len())
            .with_circuit_breakers(1, 1, 300);

        router.record_provider_failure(0, "first");
        router.record_provider_failure(1, "second");
        assert!(router.eligible_indices(&providers).is_empty());

        assert_eq!(
            router.routable_candidate_indices(&providers, &[0, 1]),
            vec![0, 1],
            "with nothing left to prefer, the axes have nothing to say"
        );
        assert!(router.select(&providers).is_some());
        assert!(router.select_with_policy(&providers, &[], &[]).is_some());
    }

    #[test]
    fn reviving_an_all_ejected_pool_still_skips_a_disabled_provider() {
        let mut providers = vec![
            make_provider("ejected", 1, None, true),
            make_provider("switched-off", 1, None, true),
        ];
        providers[1].enabled = false;
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len())
            .with_circuit_breakers(1, 1, 300);

        router.record_provider_failure(0, "ejected");
        assert_eq!(
            router.routable_candidate_indices(&providers, &[0, 1]),
            vec![0],
            "enabled is an operator switch, not a health signal, and stays hard"
        );
    }

    /// The all-ejected case under a credential policy. Resilience is
    /// advisory and gives the permitted set back rather than failing
    /// the request, but it must not reach past the policy to do it:
    /// the healthy provider here is one this key may not use.
    #[test]
    fn select_with_policy_revives_the_permitted_set_but_never_crosses_the_policy() {
        let router = Router::new(RoutingStrategy::RoundRobin, 2);
        let providers = vec![
            make_provider("permitted-but-unhealthy", 1, None, true),
            make_provider("healthy-but-not-permitted", 1, None, true),
        ];
        router.set_provider_health(0, false);
        let allowed = vec!["permitted-but-unhealthy".to_string()];

        assert_eq!(
            router.select_with_policy(&providers, &allowed, &[]),
            Some(0)
        );
    }

    /// A key permitted nothing still gets `None`. Reviving is about
    /// resilience state, and there is no permitted set to revive here.
    #[test]
    fn select_with_policy_returns_none_when_the_policy_permits_no_provider() {
        let router = Router::new(RoutingStrategy::RoundRobin, 2);
        let providers = vec![
            make_provider("openai", 1, None, true),
            make_provider("anthropic", 1, None, true),
        ];
        let allowed = vec!["not-a-configured-provider".to_string()];

        assert_eq!(router.select_with_policy(&providers, &allowed, &[]), None);
    }

    #[test]
    fn eligible_candidate_indices_preserve_exact_order_without_reviving() {
        let router = Router::new(RoutingStrategy::RoundRobin, 3);
        let mut providers = vec![
            make_provider("healthy", 1, None, true),
            make_provider("disabled", 1, None, true),
            make_provider("unhealthy", 1, None, true),
        ];
        providers[1].enabled = false;
        router.set_provider_health(2, false);

        assert_eq!(
            router.eligible_candidate_indices(&providers, &[2, 0, 1]),
            vec![0]
        );

        router.set_provider_health(0, false);
        assert!(
            router
                .eligible_candidate_indices(&providers, &[2, 0, 1])
                .is_empty(),
            "an all-ineligible exact set must stay empty"
        );
    }

    #[test]
    fn select_with_candidates_uses_strategy_strictly_and_records_decision() {
        let router = Router::new(RoutingStrategy::LeastConnections, 3);
        let providers = vec![
            make_provider("healthy-outside-exact-set", 1, None, true),
            make_provider("strict-candidate-idle", 1, None, true),
            make_provider("strict-candidate-busy", 1, None, true),
        ];
        router.record_connect(2);

        let picked = router
            .select_with_candidates(&providers, &[2, 1])
            .expect("one exact candidate is healthy");
        assert_eq!(picked, 1, "least_connections must rank the exact set");

        let recorded = prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "sbproxy_ai_lb_decisions_total")
            .and_then(|family| {
                family.get_metric().iter().find_map(|metric| {
                    let labels = metric
                        .get_label()
                        .iter()
                        .map(|label| (label.name(), label.value()))
                        .collect::<std::collections::HashMap<_, _>>();
                    (labels.get("strategy") == Some(&"least_connections")
                        && labels.get("provider") == Some(&"strict-candidate-idle"))
                    .then(|| metric.get_counter().value())
                })
            })
            .unwrap_or(0.0);
        assert_eq!(recorded, 1.0);

        router.set_provider_health(1, false);
        router.set_provider_health(2, false);
        assert_eq!(
            router.select_with_candidates(&providers, &[2, 1]),
            None,
            "the healthy provider outside the exact set must not be revived"
        );
    }

    #[test]
    fn prefix_affinity_policy_never_selects_a_blocked_provider() {
        let router = Router::new(
            RoutingStrategy::PrefixAffinity(PrefixAffinityConfig::default()),
            3,
        );
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let allowed = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let blocked = vec!["b".to_string(), "c".to_string()];

        for label in ["one", "two", "three", "four"] {
            let pick = router
                .select_with_prefix_policy(
                    &providers,
                    Some(normalized_prefix(label)),
                    &allowed,
                    &blocked,
                )
                .expect("a remains eligible");
            assert_eq!(providers[pick].name, "a");
        }
    }

    #[test]
    fn prefix_candidates_do_not_revive_an_all_unhealthy_candidate_set() {
        let router = Router::new(
            RoutingStrategy::PrefixAffinity(PrefixAffinityConfig::default()),
            2,
        );
        let providers = vec![
            make_provider("outside-final-candidates", 1, None, true),
            make_provider("candidate-but-unhealthy", 1, None, true),
        ];
        router.set_provider_health(1, false);

        assert_eq!(
            router.select_with_prefix_candidates(
                &providers,
                Some(normalized_prefix("strict candidate")),
                &[1],
            ),
            None
        );
    }

    // --- WOR-2651: caller-keyed prompt-cache affinity ---

    fn affinity_key(caller_key: &str) -> crate::routing_state::CacheAffinityKey {
        crate::routing_state::CacheAffinityKey::derive(
            crate::routing_state::CacheAffinityKeyInput {
                tenant_id: "tenant-a",
                credential_identity: "key-1",
                origin: "ai.test",
                api_surface: "chat_completions",
                caller_key,
            },
        )
    }

    /// Affinity is a preference, never a pin. The lease holder still has to
    /// clear the resilience filter the dispatcher already applied, or a
    /// single ejected provider would keep serving every request its lease
    /// names.
    #[test]
    fn an_unhealthy_lease_holder_is_skipped() {
        let providers = vec![
            make_provider("healthy", 1, None, true),
            make_provider("lease-holder", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len())
            .with_cache_affinity(crate::routing_state::CacheAffinityConfig::default());
        let key = affinity_key("session-7");
        router.record_cache_affinity(1, key, "gpt-4o");

        assert_eq!(
            router.select_cache_affinity(&providers, &key, "gpt-4o", &[0, 1]),
            Some(1)
        );

        router.set_provider_health(1, false);
        assert_eq!(
            router.select_cache_affinity(&providers, &key, "gpt-4o", &[0, 1]),
            None,
            "an ejected lease holder must leave the strategy's own pick in place"
        );
    }

    /// The lease composes with the strategy rather than replacing it: the
    /// router is a plain round robin and still answers the lookup.
    #[test]
    fn cache_affinity_answers_under_a_non_affinity_strategy() {
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len())
            .with_cache_affinity(crate::routing_state::CacheAffinityConfig::default());
        assert!(router.cache_affinity_enabled());
        let key = affinity_key("session-7");
        assert_eq!(
            router.select_cache_affinity(&providers, &key, "gpt-4o", &[0, 1]),
            None
        );
        router.record_cache_affinity(0, key, "gpt-4o");
        assert_eq!(
            router.select_cache_affinity(&providers, &key, "gpt-4o", &[0, 1]),
            Some(0)
        );
    }

    /// An origin without the config key gets no lease table, so the lookup
    /// short-circuits before it can allocate or record anything.
    #[test]
    fn an_unconfigured_router_never_leases() {
        let providers = vec![make_provider("a", 1, None, true)];
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len());
        assert!(!router.cache_affinity_enabled());
        let key = affinity_key("session-7");
        router.record_cache_affinity(0, key, "gpt-4o");
        assert_eq!(
            router.select_cache_affinity(&providers, &key, "gpt-4o", &[0]),
            None
        );
    }

    // --- WOR-1881: headroom / reset-aware / explicit filtered fallback ---

    #[test]
    fn headroom_prefers_lower_pressure_then_stable_order() {
        let providers = vec![
            make_provider("high-pressure", 1, None, true),
            make_provider("low-pressure", 1, None, true),
            make_provider("also-low", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::Headroom, providers.len());
        router.update_quota_from_headers(
            "high-pressure",
            &[
                ("x-ratelimit-limit-requests".into(), "100".into()),
                ("x-ratelimit-remaining-requests".into(), "10".into()),
            ],
            200,
        );
        router.update_quota_from_headers(
            "low-pressure",
            &[
                ("x-ratelimit-limit-requests".into(), "100".into()),
                ("x-ratelimit-remaining-requests".into(), "80".into()),
            ],
            200,
        );
        router.update_quota_from_headers(
            "also-low",
            &[
                ("x-ratelimit-limit-requests".into(), "100".into()),
                ("x-ratelimit-remaining-requests".into(), "80".into()),
            ],
            200,
        );
        // Same pressure on low-pressure and also-low: stable enabled order wins.
        assert_eq!(router.select(&providers), Some(1));
    }

    #[test]
    fn reset_aware_prefers_earliest_positive_capacity_reset() {
        let providers = vec![
            make_provider("later", 1, None, true),
            make_provider("sooner", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::ResetAware, providers.len());
        router.update_quota_from_headers(
            "later",
            &[
                ("x-ratelimit-remaining-requests".into(), "0".into()),
                ("retry-after".into(), "60".into()),
            ],
            429,
        );
        router.update_quota_from_headers(
            "sooner",
            &[
                ("x-ratelimit-remaining-requests".into(), "0".into()),
                ("retry-after".into(), "5".into()),
            ],
            429,
        );
        assert_eq!(router.select(&providers), Some(1));
    }

    #[test]
    fn policy_filtered_least_connections_does_not_silently_round_robin() {
        // Unification lock: a non-trivial strategy under an allowlist must
        // keep its ranking on the narrowed set, not silently become RR.
        let providers = vec![
            make_provider("busy", 1, None, true),
            make_provider("idle", 1, None, true),
            make_provider("other", 1, None, true),
        ];
        let router = Router::new(RoutingStrategy::LeastConnections, providers.len());
        for _ in 0..5 {
            router.record_connect(0);
        }
        let allowed = vec!["busy".to_string(), "idle".to_string()];
        for _ in 0..6 {
            let pick = router
                .select_with_allowed(&providers, &allowed)
                .expect("eligible");
            assert_eq!(
                providers[pick].name, "idle",
                "policy-filtered least_connections must prefer idle, not round-robin"
            );
        }
    }

    #[test]
    fn policy_filtered_prefix_affinity_explicitly_falls_back_to_round_robin() {
        // Explicit fallback lock: PrefixAffinity via select_with_policy has
        // no prefix in hand, so round-robin is intentional and documented.
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
            make_provider("c", 1, None, true),
        ];
        let router = Router::new(
            RoutingStrategy::PrefixAffinity(PrefixAffinityConfig::default()),
            providers.len(),
        );
        let allowed = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let mut counts = [0u32; 3];
        for _ in 0..30 {
            let pick = router
                .select_with_allowed(&providers, &allowed)
                .expect("eligible");
            counts[pick] += 1;
        }
        assert_eq!(
            counts,
            [10, 10, 10],
            "PrefixAffinity without a prefix must explicitly round-robin on the filtered set"
        );
        assert_eq!(
            router.last_filtered_fallback(),
            Some(FilteredSelectionFallback::RoundRobinMissingSignal)
        );
    }

    #[test]
    fn semantic_route_without_a_prompt_signal_round_robins_and_records_it() {
        // The synchronous select path has no prompt to embed, so the
        // SemanticRoute arm is a declared missing-signal round-robin,
        // recorded per the FilteredSelectionFallback contract.
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
        ];
        let config: semantic_route::SemanticRouteConfig =
            serde_json::from_value(serde_json::json!({
                "routes": [{"deployment": "a", "exemplars": ["code review"]}],
                "embedding": {"provider": "a", "model": "text-embedding-3-small"}
            }))
            .expect("semantic_route fixture parses");
        let router = Router::new(
            RoutingStrategy::SemanticRoute(Box::new(config)),
            providers.len(),
        );
        let allowed = vec!["a".to_string(), "b".to_string()];
        let mut counts = [0u32; 2];
        for _ in 0..10 {
            let pick = router
                .select_with_allowed(&providers, &allowed)
                .expect("eligible");
            counts[pick] += 1;
        }
        assert_eq!(
            counts,
            [5, 5],
            "SemanticRoute on the sync path must explicitly round-robin the filtered set"
        );
        assert_eq!(
            router.last_filtered_fallback(),
            Some(FilteredSelectionFallback::RoundRobinMissingSignal)
        );
    }

    // --- Named model groups (WOR-2657) ---

    fn group_fixture(
        name: &str,
        routing: &str,
        members: &[(&str, &str, u32)],
    ) -> crate::model_group::ModelGroup {
        let members: Vec<serde_json::Value> = members
            .iter()
            .map(|(provider, model, weight)| {
                serde_json::json!({"provider": provider, "model": model, "weight": weight})
            })
            .collect();
        serde_json::from_value(serde_json::json!({
            "name": name,
            "routing": routing,
            "members": members,
        }))
        .expect("group fixture parses")
    }

    #[test]
    fn a_weighted_group_splits_by_member_weight_not_provider_weight() {
        // Both providers carry `weight: 1`, which is what the action's
        // own weighted balancing would use. The group's 9/1 split has to
        // come from the members instead, or the pick is the action's
        // balance wearing the group's name.
        let providers = vec![
            make_provider("openai-a", 1, None, true),
            make_provider("azure-b", 1, None, true),
        ];
        let group = group_fixture(
            "pool",
            "weighted",
            &[("openai-a", "gpt-4o-mini", 9), ("azure-b", "deployment", 1)],
        );
        let router =
            Router::new(RoutingStrategy::RoundRobin, providers.len()).with_model_groups(["pool"]);

        let mut counts = [0u32; 2];
        for _ in 0..100 {
            let picked = router
                .select_group(&providers, &[0, 1], &group)
                .expect("a two-member group always picks");
            counts[picked] += 1;
        }
        // The weighted arm hashes a monotonic cursor, so the split is
        // deterministic rather than sampled: assert the exact counts.
        assert_eq!(
            counts,
            [90, 10],
            "the group must split 9:1 by member weight; equal provider weights would give 100:0"
        );
    }

    #[test]
    fn the_group_strategy_overrides_the_action_strategy() {
        // The action is `fallback_chain`, which always returns the
        // lowest-priority provider. A group asking for round_robin must
        // rotate anyway.
        let providers = vec![
            make_provider("a", 1, Some(0), true),
            make_provider("b", 1, Some(1), true),
        ];
        let group = group_fixture("pool", "round_robin", &[("a", "m1", 1), ("b", "m2", 1)]);
        let router = Router::new(RoutingStrategy::FallbackChain, providers.len())
            .with_model_groups(["pool"]);

        let picks: Vec<usize> = (0..4)
            .map(|_| {
                router
                    .select_group(&providers, &[0, 1], &group)
                    .expect("group picks")
            })
            .collect();
        assert_eq!(picks, vec![0, 1, 0, 1], "the group's own strategy decides");
    }

    #[test]
    fn two_groups_do_not_share_a_rotation_cursor() {
        // Interleaved selections. On a shared cursor each group would
        // see every other tick and would pin to one member forever; on
        // its own cursor each rotates.
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
        ];
        let left = group_fixture("left", "round_robin", &[("a", "m1", 1), ("b", "m2", 1)]);
        let right = group_fixture("right", "round_robin", &[("a", "m1", 1), ("b", "m2", 1)]);
        let router = Router::new(RoutingStrategy::RoundRobin, providers.len())
            .with_model_groups(["left", "right"]);

        let mut left_picks = Vec::new();
        let mut right_picks = Vec::new();
        for _ in 0..4 {
            left_picks.push(
                router
                    .select_group(&providers, &[0, 1], &left)
                    .expect("left"),
            );
            right_picks.push(
                router
                    .select_group(&providers, &[0, 1], &right)
                    .expect("right"),
            );
        }
        assert_eq!(left_picks, vec![0, 1, 0, 1]);
        assert_eq!(right_picks, vec![0, 1, 0, 1]);
    }

    #[test]
    fn a_group_pick_never_reads_the_action_cursor() {
        // The action's own rotation and a group's must not advance each
        // other: a request routed by the action between two group
        // requests would otherwise skip the group's next member.
        let providers = vec![
            make_provider("a", 1, None, true),
            make_provider("b", 1, None, true),
        ];
        let group = group_fixture("pool", "round_robin", &[("a", "m1", 1), ("b", "m2", 1)]);
        let router =
            Router::new(RoutingStrategy::RoundRobin, providers.len()).with_model_groups(["pool"]);

        assert_eq!(router.select_group(&providers, &[0, 1], &group), Some(0));
        // One action-level selection in between.
        assert_eq!(router.select(&providers), Some(0));
        assert_eq!(
            router.select_group(&providers, &[0, 1], &group),
            Some(1),
            "the action's rotation must not consume the group's cursor"
        );
    }
}
