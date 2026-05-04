//! Provider rate limit tracking.
//!
//! Parses rate limit headers from provider responses and tracks
//! remaining capacity. Pre-emptively throttles when close to limits.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Current rate limit state observed from a provider's response headers.
#[derive(Debug, Clone)]
pub struct ProviderRateState {
    /// Remaining requests allowed in the current window (if reported).
    pub remaining_requests: Option<u64>,
    /// Remaining tokens allowed in the current window (if reported).
    pub remaining_tokens: Option<u64>,
    /// When the rate limit window resets.
    pub reset_at: Option<Instant>,
    /// When this state was last updated.
    pub last_updated: Instant,
}

/// Tracks rate limit state across providers and pre-emptively throttles
/// when remaining capacity falls below the configured threshold.
pub struct ProviderRateLimitTracker {
    /// provider_name -> rate state
    state: Mutex<HashMap<String, ProviderRateState>>,
    /// Pre-emptive throttle threshold (0.0 - 1.0).
    /// Throttling is triggered when remaining / limit <= threshold.
    /// Default: 0.1 (throttle at 10% remaining or below).
    throttle_threshold: f64,
}

impl ProviderRateLimitTracker {
    /// Create a new tracker with the given throttle threshold (0.0 - 1.0).
    pub fn new(throttle_threshold: f64) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            throttle_threshold: throttle_threshold.clamp(0.0, 1.0),
        }
    }

    /// Update the rate state for a provider from response headers.
    ///
    /// Recognized headers (case-insensitive):
    /// - `x-ratelimit-remaining-requests` / `x-ratelimit-remaining-tokens`
    /// - `x-ratelimit-limit-requests` / `x-ratelimit-limit-tokens`
    /// - `x-ratelimit-reset-requests` (seconds until reset, e.g. `"1s"` or `"500ms"`)
    /// - `retry-after` (seconds to wait)
    /// - Anthropic variants: `anthropic-ratelimit-requests-remaining`,
    ///   `anthropic-ratelimit-tokens-remaining`,
    ///   `anthropic-ratelimit-requests-reset`
    pub fn update_from_headers(&self, provider: &str, headers: &[(String, String)]) {
        let mut remaining_requests: Option<u64> = None;
        let mut remaining_tokens: Option<u64> = None;
        let mut reset_secs: Option<f64> = None;

        for (name, value) in headers {
            let name_lower = name.to_lowercase();
            match name_lower.as_str() {
                // OpenAI-style
                "x-ratelimit-remaining-requests" | "anthropic-ratelimit-requests-remaining" => {
                    remaining_requests = value.parse().ok();
                }
                "x-ratelimit-remaining-tokens" | "anthropic-ratelimit-tokens-remaining" => {
                    remaining_tokens = value.parse().ok();
                }
                // Reset time - may be expressed as "1s", "500ms", or plain seconds
                "x-ratelimit-reset-requests"
                | "x-ratelimit-reset-tokens"
                | "anthropic-ratelimit-requests-reset" => {
                    if let Some(secs) = parse_duration_header(value) {
                        // Use the largest reset value so we wait long enough
                        reset_secs = Some(reset_secs.map_or(secs, |prev: f64| prev.max(secs)));
                    }
                }
                // Standard retry-after header (seconds)
                "retry-after" => {
                    if let Ok(secs) = value.parse::<f64>() {
                        reset_secs = Some(reset_secs.map_or(secs, |prev: f64| prev.max(secs)));
                    }
                }
                _ => {}
            }
        }

        // Only update if we got at least something useful
        if remaining_requests.is_none() && remaining_tokens.is_none() && reset_secs.is_none() {
            return;
        }

        let reset_at = reset_secs.map(|s| Instant::now() + Duration::from_secs_f64(s));

        let mut state = self.state.lock().unwrap();
        let entry = state
            .entry(provider.to_string())
            .or_insert_with(|| ProviderRateState {
                remaining_requests: None,
                remaining_tokens: None,
                reset_at: None,
                last_updated: Instant::now(),
            });

        if remaining_requests.is_some() {
            entry.remaining_requests = remaining_requests;
        }
        if remaining_tokens.is_some() {
            entry.remaining_tokens = remaining_tokens;
        }
        if reset_at.is_some() {
            entry.reset_at = reset_at;
        }
        entry.last_updated = Instant::now();
    }

    /// Return true if the provider should be pre-emptively throttled.
    ///
    /// Throttles when:
    /// - remaining_requests is Some and <= throttle_threshold * 100 (treated as % of a 1000-req limit), OR
    /// - remaining_requests == 0, OR
    /// - remaining_tokens == 0
    ///
    /// Does NOT throttle if no state is recorded for the provider (unknown -> allow).
    /// Clears stale throttle state after the reset window has passed.
    pub fn should_throttle(&self, provider: &str) -> bool {
        let mut state = self.state.lock().unwrap();
        let Some(entry) = state.get_mut(provider) else {
            return false;
        };

        // If reset window has passed, clear throttle state
        if let Some(reset_at) = entry.reset_at {
            if Instant::now() >= reset_at {
                entry.remaining_requests = None;
                entry.remaining_tokens = None;
                entry.reset_at = None;
                return false;
            }
        }

        // Hard block: no requests left
        if entry.remaining_requests == Some(0) {
            return true;
        }
        if entry.remaining_tokens == Some(0) {
            return true;
        }

        // Pre-emptive throttle: requests remaining below threshold
        // We use a reference limit of 1000 req/min as baseline for threshold calculation.
        // This avoids needing to track the original limit header separately.
        // In practice: throttle_threshold=0.1 means throttle when remaining <= 100 (10% of 1000).
        if let Some(remaining) = entry.remaining_requests {
            // Use small absolute thresholds: throttle when <= floor(1000 * threshold)
            let threshold_abs = (1000.0 * self.throttle_threshold) as u64;
            if remaining <= threshold_abs {
                return true;
            }
        }

        false
    }

    /// Get the current rate state for a provider, if any has been recorded.
    pub fn get_state(&self, provider: &str) -> Option<ProviderRateState> {
        self.state.lock().unwrap().get(provider).cloned()
    }
}

/// Parse a duration header value like `"1s"`, `"500ms"`, `"2.5s"`, or plain `"60"` (seconds).
fn parse_duration_header(value: &str) -> Option<f64> {
    let v = value.trim();
    if let Some(ms_str) = v.strip_suffix("ms") {
        return ms_str.trim().parse::<f64>().ok().map(|ms| ms / 1000.0);
    }
    if let Some(s_str) = v.strip_suffix('s') {
        return s_str.trim().parse::<f64>().ok();
    }
    // Plain numeric value - treat as seconds
    v.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // --- update_from_headers tests ---

    #[test]
    fn update_from_openai_style_headers() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-remaining-requests", "500"),
                ("x-ratelimit-remaining-tokens", "50000"),
                ("x-ratelimit-reset-requests", "30s"),
            ]),
        );

        let state = tracker.get_state("openai").unwrap();
        assert_eq!(state.remaining_requests, Some(500));
        assert_eq!(state.remaining_tokens, Some(50000));
        assert!(state.reset_at.is_some());
    }

    #[test]
    fn update_from_anthropic_style_headers() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "anthropic",
            &headers(&[
                ("anthropic-ratelimit-requests-remaining", "200"),
                ("anthropic-ratelimit-tokens-remaining", "100000"),
                ("anthropic-ratelimit-requests-reset", "60s"),
            ]),
        );

        let state = tracker.get_state("anthropic").unwrap();
        assert_eq!(state.remaining_requests, Some(200));
        assert_eq!(state.remaining_tokens, Some(100000));
        assert!(state.reset_at.is_some());
    }

    #[test]
    fn update_from_retry_after_header() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-remaining-requests", "0"),
                ("retry-after", "5"),
            ]),
        );

        let state = tracker.get_state("openai").unwrap();
        assert_eq!(state.remaining_requests, Some(0));
        assert!(state.reset_at.is_some());
    }

    #[test]
    fn empty_headers_do_not_create_state() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers("openai", &headers(&[]));
        assert!(tracker.get_state("openai").is_none());
    }

    #[test]
    fn parse_millisecond_duration_header() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[
                ("x-ratelimit-remaining-requests", "10"),
                ("x-ratelimit-reset-requests", "500ms"),
            ]),
        );
        let state = tracker.get_state("openai").unwrap();
        assert!(state.reset_at.is_some());
    }

    // --- should_throttle tests ---

    #[test]
    fn throttle_when_remaining_requests_is_zero() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-requests", "0")]),
        );
        assert!(tracker.should_throttle("openai"));
    }

    #[test]
    fn throttle_when_remaining_tokens_is_zero() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers("openai", &headers(&[("x-ratelimit-remaining-tokens", "0")]));
        assert!(tracker.should_throttle("openai"));
    }

    #[test]
    fn throttle_when_remaining_below_threshold() {
        // Threshold 0.1 -> throttle at <= 100 remaining (10% of 1000 baseline)
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-requests", "50")]),
        );
        assert!(tracker.should_throttle("openai"));
    }

    #[test]
    fn no_throttle_when_plenty_remaining() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-requests", "800")]),
        );
        assert!(!tracker.should_throttle("openai"));
    }

    #[test]
    fn no_throttle_for_unknown_provider() {
        let tracker = ProviderRateLimitTracker::new(0.1);
        assert!(!tracker.should_throttle("unknown-provider"));
    }

    #[test]
    fn no_throttle_after_reset_window_expires() {
        let tracker = ProviderRateLimitTracker::new(0.1);

        // Set remaining=0 with an already-expired reset (0 seconds in the future)
        {
            let mut state = tracker.state.lock().unwrap();
            state.insert(
                "openai".to_string(),
                ProviderRateState {
                    remaining_requests: Some(0),
                    remaining_tokens: None,
                    // Already expired: reset_at is in the past
                    reset_at: Some(Instant::now() - Duration::from_secs(1)),
                    last_updated: Instant::now(),
                },
            );
        }

        // After the reset window, should no longer throttle
        assert!(!tracker.should_throttle("openai"));
    }

    #[test]
    fn different_providers_tracked_independently() {
        let tracker = ProviderRateLimitTracker::new(0.1);

        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-requests", "0")]),
        );
        tracker.update_from_headers(
            "anthropic",
            &headers(&[("anthropic-ratelimit-requests-remaining", "500")]),
        );

        assert!(tracker.should_throttle("openai"));
        assert!(!tracker.should_throttle("anthropic"));
    }

    #[test]
    fn state_is_updated_incrementally() {
        let tracker = ProviderRateLimitTracker::new(0.1);

        // First update: requests only
        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-requests", "100")]),
        );

        // Second update: tokens only (requests should be preserved)
        tracker.update_from_headers(
            "openai",
            &headers(&[("x-ratelimit-remaining-tokens", "5000")]),
        );

        let state = tracker.get_state("openai").unwrap();
        assert_eq!(state.remaining_requests, Some(100));
        assert_eq!(state.remaining_tokens, Some(5000));
    }
}
