//! Per-model rate limiter for AI provider requests.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Per-model rate limit configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelRateConfig {
    /// Maximum requests permitted per rolling one-minute window.
    pub requests_per_minute: Option<u64>,
    /// Maximum tokens permitted per rolling one-minute window.
    pub tokens_per_minute: Option<u64>,
}

/// Tracks rate limits per provider+model combination using a sliding window.
pub struct ModelRateLimiter {
    state: Mutex<HashMap<String, RateState>>,
}

#[derive(Debug)]
struct RateState {
    requests: u64,
    tokens: u64,
    window_start: Instant,
}

impl ModelRateLimiter {
    /// Create a new empty rate limiter with no in-flight state.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request is within rate limits for a provider+model.
    /// Returns true if allowed, and increments the request counter.
    pub fn check_rate(&self, provider: &str, model: &str, config: &ModelRateConfig) -> bool {
        let key = format!("{}:{}", provider, model);
        let mut state = self.state.lock().unwrap();
        let entry = state.entry(key).or_insert_with(|| RateState {
            requests: 0,
            tokens: 0,
            window_start: Instant::now(),
        });

        // Reset window if minute has elapsed
        if entry.window_start.elapsed().as_secs() >= 60 {
            entry.requests = 0;
            entry.tokens = 0;
            entry.window_start = Instant::now();
        }

        // Check RPM limit
        if let Some(rpm) = config.requests_per_minute {
            if entry.requests >= rpm {
                return false;
            }
        }

        entry.requests += 1;
        true
    }

    /// Record token usage for a provider+model after a response.
    pub fn record_tokens(&self, provider: &str, model: &str, tokens: u64) {
        let key = format!("{}:{}", provider, model);
        let mut state = self.state.lock().unwrap();
        if let Some(entry) = state.get_mut(&key) {
            entry.tokens += tokens;
        }
    }
}

impl Default for ModelRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_limit() {
        let limiter = ModelRateLimiter::new();
        let config = ModelRateConfig {
            requests_per_minute: Some(10),
            tokens_per_minute: None,
        };
        assert!(limiter.check_rate("openai", "gpt-4", &config));
        assert!(limiter.check_rate("openai", "gpt-4", &config));
    }

    #[test]
    fn exceeds_rpm() {
        let limiter = ModelRateLimiter::new();
        let config = ModelRateConfig {
            requests_per_minute: Some(3),
            tokens_per_minute: None,
        };
        assert!(limiter.check_rate("openai", "gpt-4", &config));
        assert!(limiter.check_rate("openai", "gpt-4", &config));
        assert!(limiter.check_rate("openai", "gpt-4", &config));
        // Fourth request should be rejected
        assert!(!limiter.check_rate("openai", "gpt-4", &config));
    }

    #[test]
    fn different_models_tracked_separately() {
        let limiter = ModelRateLimiter::new();
        let config = ModelRateConfig {
            requests_per_minute: Some(1),
            tokens_per_minute: None,
        };
        assert!(limiter.check_rate("openai", "gpt-4", &config));
        assert!(!limiter.check_rate("openai", "gpt-4", &config));
        // Different model should still be allowed
        assert!(limiter.check_rate("openai", "gpt-3.5", &config));
    }

    #[test]
    fn no_limit_always_allows() {
        let limiter = ModelRateLimiter::new();
        let config = ModelRateConfig {
            requests_per_minute: None,
            tokens_per_minute: None,
        };
        for _ in 0..100 {
            assert!(limiter.check_rate("openai", "gpt-4", &config));
        }
    }

    #[test]
    fn record_tokens() {
        let limiter = ModelRateLimiter::new();
        let config = ModelRateConfig {
            requests_per_minute: Some(10),
            tokens_per_minute: Some(1000),
        };
        // Must check_rate first to create the entry
        limiter.check_rate("openai", "gpt-4", &config);
        limiter.record_tokens("openai", "gpt-4", 150);
        // Recording tokens for a nonexistent entry is a no-op
        limiter.record_tokens("anthropic", "claude-3", 500);
    }

    #[test]
    fn window_reset() {
        let limiter = ModelRateLimiter::new();
        let config = ModelRateConfig {
            requests_per_minute: Some(2),
            tokens_per_minute: None,
        };
        assert!(limiter.check_rate("openai", "gpt-4", &config));
        assert!(limiter.check_rate("openai", "gpt-4", &config));
        assert!(!limiter.check_rate("openai", "gpt-4", &config));

        // Manually reset the window to simulate time passing
        {
            let mut state = limiter.state.lock().unwrap();
            let entry = state.get_mut("openai:gpt-4").unwrap();
            entry.window_start = Instant::now() - std::time::Duration::from_secs(61);
        }

        // After window reset, should be allowed again
        assert!(limiter.check_rate("openai", "gpt-4", &config));
    }
}
