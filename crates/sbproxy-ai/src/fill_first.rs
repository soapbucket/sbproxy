//! Fill-first routing strategy: fully utilize one provider before moving to next.
//!
//! Unlike round-robin, fill-first exhausts a provider's request budget before
//! promoting to the next. This is useful for maximizing throughput within tier
//! limits, or for preferring a primary provider while keeping a fallback warm.

use std::sync::Mutex;

/// Routes requests to the first provider that has not yet hit its per-window cap.
///
/// Providers are tried in order. Once `max_per_provider` requests have been
/// dispatched to `provider\[i\]`, all subsequent requests go to `provider\[i+1\]`,
/// and so on. Call [`reset`](FillFirstRouter::reset) at each window boundary to
/// restart from provider 0.
pub struct FillFirstRouter {
    providers: Vec<String>,
    /// Requests served by each provider in current window.
    counts: Mutex<Vec<u64>>,
    /// Max requests per provider before moving to next.
    max_per_provider: u64,
}

impl FillFirstRouter {
    /// Create a new router.
    ///
    /// # Panics
    ///
    /// Panics if `providers` is empty.
    pub fn new(providers: Vec<String>, max_per_provider: u64) -> Self {
        assert!(!providers.is_empty(), "providers list must not be empty");
        let len = providers.len();
        Self {
            providers,
            counts: Mutex::new(vec![0u64; len]),
            max_per_provider,
        }
    }

    /// Select the next provider name.
    ///
    /// Returns the first provider whose count is below `max_per_provider`.
    /// Falls back to the last provider if all are exhausted (avoids hard failure
    /// at the cost of overflow on the last provider).
    pub fn select(&self) -> &str {
        let counts = self.counts.lock().expect("mutex poisoned");
        for (idx, count) in counts.iter().enumerate() {
            if *count < self.max_per_provider {
                return &self.providers[idx];
            }
        }
        // All providers exhausted - overflow to the last one.
        &self.providers[self.providers.len() - 1]
    }

    /// Record that a request was served by `provider_idx`.
    pub fn record(&self, provider_idx: usize) {
        let mut counts = self.counts.lock().expect("mutex poisoned");
        if let Some(c) = counts.get_mut(provider_idx) {
            *c += 1;
        }
    }

    /// Reset all per-provider counts to zero (call at each window boundary).
    pub fn reset(&self) {
        let mut counts = self.counts.lock().expect("mutex poisoned");
        for c in counts.iter_mut() {
            *c = 0;
        }
    }

    /// Return the number of providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Return all provider names in order.
    pub fn providers(&self) -> &[String] {
        &self.providers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_router(providers: &[&str], max: u64) -> FillFirstRouter {
        FillFirstRouter::new(providers.iter().map(|s| s.to_string()).collect(), max)
    }

    #[test]
    fn starts_with_first_provider() {
        let router = make_router(&["openai", "anthropic"], 10);
        assert_eq!(router.select(), "openai");
    }

    #[test]
    fn fills_first_before_moving_to_next() {
        let router = make_router(&["openai", "anthropic"], 3);

        // Record 3 requests for openai (provider 0).
        router.record(0);
        router.record(0);
        router.record(0);

        // Next selection should be anthropic.
        assert_eq!(router.select(), "anthropic");
    }

    #[test]
    fn stays_on_first_while_under_cap() {
        let router = make_router(&["openai", "anthropic"], 5);

        router.record(0);
        router.record(0);
        assert_eq!(router.select(), "openai");
    }

    #[test]
    fn reset_restarts_from_first() {
        let router = make_router(&["openai", "anthropic"], 2);

        router.record(0);
        router.record(0);
        assert_eq!(router.select(), "anthropic");

        router.reset();
        assert_eq!(router.select(), "openai");
    }

    #[test]
    fn overflow_to_last_when_all_exhausted() {
        let router = make_router(&["openai", "anthropic"], 1);

        router.record(0);
        router.record(1);

        // Both exhausted - should fall back to last provider (anthropic).
        assert_eq!(router.select(), "anthropic");
    }

    #[test]
    fn single_provider_always_selected() {
        let router = make_router(&["openai"], 5);

        for _ in 0..10 {
            assert_eq!(router.select(), "openai");
            router.record(0);
        }
    }

    #[test]
    fn three_provider_fill_progression() {
        let router = make_router(&["a", "b", "c"], 2);

        assert_eq!(router.select(), "a");
        router.record(0);
        assert_eq!(router.select(), "a");
        router.record(0);

        assert_eq!(router.select(), "b");
        router.record(1);
        assert_eq!(router.select(), "b");
        router.record(1);

        assert_eq!(router.select(), "c");
    }

    #[test]
    fn record_out_of_bounds_is_safe() {
        let router = make_router(&["openai"], 10);
        // Should not panic.
        router.record(999);
        assert_eq!(router.select(), "openai");
    }

    #[test]
    fn provider_metadata_accessible() {
        let router = make_router(&["openai", "anthropic", "cohere"], 10);
        assert_eq!(router.provider_count(), 3);
        assert_eq!(router.providers(), &["openai", "anthropic", "cohere"]);
    }

    #[test]
    fn reset_after_partial_fill() {
        let router = make_router(&["a", "b"], 5);
        router.record(0);
        router.record(0);
        router.record(0);
        assert_eq!(router.select(), "a"); // still on a (3/5)

        router.reset();
        assert_eq!(router.select(), "a"); // back to a after reset
    }
}
