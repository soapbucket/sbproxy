//! Concurrency limiter for controlling parallel requests per provider.

use dashmap::DashMap;
use std::collections::HashMap;

/// Limits concurrent requests per provider.
pub struct ConcurrencyLimiter {
    limits: HashMap<String, u32>,
    current: DashMap<String, u32>,
}

impl ConcurrencyLimiter {
    /// Create a limiter from a map of provider name to maximum concurrent requests.
    pub fn new(limits: HashMap<String, u32>) -> Self {
        Self {
            limits,
            current: DashMap::new(),
        }
    }

    /// Try to acquire a concurrency slot for a provider.
    /// Returns true if a slot was acquired, false if at capacity.
    pub fn try_acquire(&self, provider: &str) -> bool {
        let max = self.limits.get(provider).copied().unwrap_or(u32::MAX);
        let mut acquired = false;
        self.current
            .entry(provider.to_string())
            .and_modify(|count| {
                if *count < max {
                    *count += 1;
                    acquired = true;
                }
            })
            .or_insert_with(|| {
                acquired = true;
                1
            });
        acquired
    }

    /// Release a concurrency slot for a provider.
    pub fn release(&self, provider: &str) {
        if let Some(mut entry) = self.current.get_mut(provider) {
            if *entry > 0 {
                *entry -= 1;
            }
        }
    }

    /// Get the current number of active requests for a provider.
    pub fn current_count(&self, provider: &str) -> u32 {
        self.current.get(provider).map(|e| *e).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_and_release() {
        let mut limits = HashMap::new();
        limits.insert("openai".to_string(), 5);
        let limiter = ConcurrencyLimiter::new(limits);

        assert!(limiter.try_acquire("openai"));
        assert_eq!(limiter.current_count("openai"), 1);

        limiter.release("openai");
        assert_eq!(limiter.current_count("openai"), 0);
    }

    #[test]
    fn at_capacity_returns_false() {
        let mut limits = HashMap::new();
        limits.insert("openai".to_string(), 2);
        let limiter = ConcurrencyLimiter::new(limits);

        assert!(limiter.try_acquire("openai"));
        assert!(limiter.try_acquire("openai"));
        // At capacity
        assert!(!limiter.try_acquire("openai"));
        assert_eq!(limiter.current_count("openai"), 2);
    }

    #[test]
    fn release_allows_new_acquire() {
        let mut limits = HashMap::new();
        limits.insert("openai".to_string(), 1);
        let limiter = ConcurrencyLimiter::new(limits);

        assert!(limiter.try_acquire("openai"));
        assert!(!limiter.try_acquire("openai"));

        limiter.release("openai");
        assert!(limiter.try_acquire("openai"));
    }

    #[test]
    fn unknown_provider_unlimited() {
        let limiter = ConcurrencyLimiter::new(HashMap::new());
        // No limit configured, should always succeed
        assert!(limiter.try_acquire("unknown-provider"));
        assert!(limiter.try_acquire("unknown-provider"));
    }

    #[test]
    fn current_count_tracks_correctly() {
        let mut limits = HashMap::new();
        limits.insert("anthropic".to_string(), 10);
        let limiter = ConcurrencyLimiter::new(limits);

        assert_eq!(limiter.current_count("anthropic"), 0);
        limiter.try_acquire("anthropic");
        limiter.try_acquire("anthropic");
        limiter.try_acquire("anthropic");
        assert_eq!(limiter.current_count("anthropic"), 3);

        limiter.release("anthropic");
        assert_eq!(limiter.current_count("anthropic"), 2);
    }

    #[test]
    fn separate_providers() {
        let mut limits = HashMap::new();
        limits.insert("openai".to_string(), 1);
        limits.insert("anthropic".to_string(), 1);
        let limiter = ConcurrencyLimiter::new(limits);

        assert!(limiter.try_acquire("openai"));
        assert!(limiter.try_acquire("anthropic"));
        // Both at capacity independently
        assert!(!limiter.try_acquire("openai"));
        assert!(!limiter.try_acquire("anthropic"));
    }
}
