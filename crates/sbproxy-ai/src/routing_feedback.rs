//! Closed-loop, outcome-aware routing feedback.
//!
//! The latency- and cost-aware strategies decide from live signals
//! ([`crate::routing`]) or static catalog price, but none consume the
//! *realized* outcome of a request: did it succeed, get refused, or get
//! filtered, and what did it actually cost. This module closes that loop.
//! Each completed call feeds a per-provider rolling estimate of realized
//! cost-per-success, success rate, refusal rate, and latency, and the
//! [`RoutingStrategy::OutcomeAware`](crate::routing::RoutingStrategy)
//! strategy scores candidates by that realized signal rather than list
//! price, demoting providers whose refusal or error rate is climbing.
//!
//! The store is process-wide and keyed by provider name (stable across a
//! hot reload), mirroring the outlier detector. It turns the gateway's own
//! observations into a control signal without any external service.

use dashmap::DashMap;
use std::sync::OnceLock;

/// EWMA smoothing factor. A higher value reacts faster to a change in a
/// provider's behavior; a lower value is steadier.
const ALPHA: f64 = 0.2;

/// Below this many samples a provider is still "warming up" and the
/// outcome-aware strategy prefers to explore it rather than trust its
/// estimate.
const MIN_SAMPLES: u64 = 5;

/// Rolling per-provider realized-outcome statistics.
#[derive(Debug, Clone)]
struct ProviderStats {
    samples: u64,
    /// EWMA of realized cost in USD per request.
    ewma_cost: f64,
    /// EWMA of the success indicator (1.0 success, 0.0 otherwise).
    success_rate: f64,
    /// EWMA of the refusal / content-filter indicator.
    refusal_rate: f64,
    /// EWMA of end-to-end latency in milliseconds.
    ewma_latency_ms: f64,
}

impl ProviderStats {
    fn new() -> Self {
        Self {
            samples: 0,
            ewma_cost: 0.0,
            success_rate: 1.0,
            refusal_rate: 0.0,
            ewma_latency_ms: 0.0,
        }
    }

    fn update(&mut self, success: bool, refused: bool, cost_usd: f64, latency_ms: u64) {
        let s = if success { 1.0 } else { 0.0 };
        let r = if refused { 1.0 } else { 0.0 };
        if self.samples == 0 {
            self.ewma_cost = cost_usd.max(0.0);
            self.success_rate = s;
            self.refusal_rate = r;
            self.ewma_latency_ms = latency_ms as f64;
        } else {
            self.ewma_cost = ALPHA * cost_usd.max(0.0) + (1.0 - ALPHA) * self.ewma_cost;
            self.success_rate = ALPHA * s + (1.0 - ALPHA) * self.success_rate;
            self.refusal_rate = ALPHA * r + (1.0 - ALPHA) * self.refusal_rate;
            self.ewma_latency_ms = ALPHA * latency_ms as f64 + (1.0 - ALPHA) * self.ewma_latency_ms;
        }
        self.samples = self.samples.saturating_add(1);
    }

    /// Realized cost per successful request, penalized by the refusal
    /// rate. Lower is better. A provider that never succeeds scores
    /// [`f64::INFINITY`].
    fn score(&self) -> f64 {
        if self.success_rate <= f64::EPSILON {
            return f64::INFINITY;
        }
        // A floor on cost keeps a free-but-flaky provider from always
        // winning on price alone; the refusal penalty and success
        // division still demote it.
        let cost = self.ewma_cost.max(1e-9);
        (cost / self.success_rate) * (1.0 + self.refusal_rate)
    }
}

/// A process-wide store of realized routing outcomes.
#[derive(Debug, Default)]
pub struct FeedbackStore {
    by_provider: DashMap<String, ProviderStats>,
}

/// One realized request outcome to fold into the store.
#[derive(Debug, Clone)]
pub struct Outcome<'a> {
    /// Provider that served the request.
    pub provider: &'a str,
    /// Whether the request succeeded end to end.
    pub success: bool,
    /// Whether it was a refusal or content-filter outcome.
    pub refused: bool,
    /// Realized cost in USD.
    pub cost_usd: f64,
    /// End-to-end latency in milliseconds.
    pub latency_ms: u64,
}

impl FeedbackStore {
    /// The shared process-wide store.
    pub fn global() -> &'static FeedbackStore {
        static STORE: OnceLock<FeedbackStore> = OnceLock::new();
        STORE.get_or_init(FeedbackStore::default)
    }

    /// Fold one realized outcome into the provider's rolling estimate.
    pub fn record(&self, o: &Outcome<'_>) {
        self.by_provider
            .entry(o.provider.to_string())
            .or_insert_with(ProviderStats::new)
            .update(o.success, o.refused, o.cost_usd, o.latency_ms);
    }

    /// Realized cost-per-success score for a provider, lower is better.
    /// `None` when the provider has no samples yet.
    pub fn score(&self, provider: &str) -> Option<f64> {
        self.by_provider.get(provider).map(|s| s.score())
    }

    /// Number of samples recorded for a provider.
    pub fn samples(&self, provider: &str) -> u64 {
        self.by_provider
            .get(provider)
            .map(|s| s.samples)
            .unwrap_or(0)
    }

    /// True when any candidate still has fewer than [`MIN_SAMPLES`]
    /// samples. The outcome-aware strategy keeps round-robining while this
    /// holds, so every provider earns an estimate before the store commits
    /// to the cheapest-per-success one.
    pub fn needs_exploration(&self, candidates: &[&str]) -> bool {
        candidates.iter().any(|c| self.samples(c) < MIN_SAMPLES)
    }

    /// Pick the best candidate by realized cost-per-success.
    ///
    /// Returns the index into `candidates`. A candidate that is still
    /// warming up (fewer than [`MIN_SAMPLES`] samples) is explored first so
    /// every provider earns an estimate before the store commits to the
    /// cheapest-per-success one. With all candidates warmed up, the lowest
    /// score wins. Returns `None` for an empty slice.
    pub fn best_among(&self, candidates: &[&str]) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        // Explore any under-sampled candidate first.
        if let Some(idx) = candidates
            .iter()
            .position(|c| self.samples(c) < MIN_SAMPLES)
        {
            return Some(idx);
        }
        let mut best_idx = 0usize;
        let mut best_score = f64::INFINITY;
        for (i, c) in candidates.iter().enumerate() {
            let score = self.score(c).unwrap_or(f64::INFINITY);
            if score < best_score {
                best_score = score;
                best_idx = i;
            }
        }
        Some(best_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warm(store: &FeedbackStore, provider: &str, success: bool, refused: bool, cost: f64) {
        for _ in 0..MIN_SAMPLES + 2 {
            store.record(&Outcome {
                provider,
                success,
                refused,
                cost_usd: cost,
                latency_ms: 100,
            });
        }
    }

    #[test]
    fn healthy_provider_outscores_refuser() {
        let store = FeedbackStore::default();
        // `good` always succeeds; `flaky` refuses half the time.
        warm(&store, "good", true, false, 0.001);
        for i in 0..(MIN_SAMPLES + 2) {
            let refused = i % 2 == 0;
            store.record(&Outcome {
                provider: "flaky",
                success: !refused,
                refused,
                cost_usd: 0.001,
                latency_ms: 100,
            });
        }
        let good = store.score("good").unwrap();
        let flaky = store.score("flaky").unwrap();
        assert!(
            flaky > good,
            "flaky ({flaky}) should score worse than good ({good})"
        );
        // With both warmed up, the store routes to the healthy provider.
        assert_eq!(store.best_among(&["flaky", "good"]), Some(1));
    }

    #[test]
    fn explores_undersampled_candidate_first() {
        let store = FeedbackStore::default();
        warm(&store, "known", true, false, 0.001);
        // `fresh` has no samples; it is explored before the known one.
        assert_eq!(store.best_among(&["known", "fresh"]), Some(1));
    }

    #[test]
    fn never_succeeds_scores_infinite() {
        let store = FeedbackStore::default();
        warm(&store, "dead", false, false, 0.001);
        assert!(store.score("dead").unwrap().is_infinite());
    }

    #[test]
    fn cheaper_per_success_wins_when_both_healthy() {
        let store = FeedbackStore::default();
        warm(&store, "cheap", true, false, 0.001);
        warm(&store, "pricey", true, false, 0.010);
        assert_eq!(store.best_among(&["pricey", "cheap"]), Some(1));
    }

    #[test]
    fn unknown_provider_has_no_score() {
        let store = FeedbackStore::default();
        assert!(store.score("nope").is_none());
        assert_eq!(store.samples("nope"), 0);
    }
}
