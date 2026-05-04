//! Token bucket rate limiter for upstream requests.
//!
//! Prevents overwhelming upstream services by limiting the rate of outgoing
//! requests using a token bucket algorithm with configurable burst capacity.

use std::sync::Mutex;
use std::time::Instant;

/// Token bucket rate limiter for upstream requests.
pub struct UpstreamRateLimiter {
    bucket: Mutex<TokenBucket>,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl UpstreamRateLimiter {
    /// Create a new rate limiter.
    ///
    /// - `requests_per_second`: the sustained request rate.
    /// - `burst`: maximum number of tokens (allows short bursts above the rate).
    pub fn new(requests_per_second: f64, burst: u32) -> Self {
        Self {
            bucket: Mutex::new(TokenBucket {
                tokens: burst as f64,
                max_tokens: burst as f64,
                refill_rate: requests_per_second,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Try to acquire a token. Returns `true` if the request is allowed.
    pub fn try_acquire(&self) -> bool {
        let mut bucket = self.bucket.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_rate).min(bucket.max_tokens);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn allows_burst() {
        let limiter = UpstreamRateLimiter::new(10.0, 5);
        // Should allow up to burst size immediately
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
    }

    #[test]
    fn rejects_when_exhausted() {
        let limiter = UpstreamRateLimiter::new(10.0, 3);
        // Exhaust the burst
        for _ in 0..3 {
            assert!(limiter.try_acquire());
        }
        // Next request should be rejected
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn refills_over_time() {
        let limiter = UpstreamRateLimiter::new(100.0, 1);
        // Use the single token
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());

        // Wait for refill (100 req/s = 1 token per 10ms)
        thread::sleep(Duration::from_millis(15));

        // Should have refilled at least one token
        assert!(limiter.try_acquire());
    }

    #[test]
    fn does_not_exceed_max_tokens() {
        let limiter = UpstreamRateLimiter::new(1000.0, 3);
        // Wait a while so many tokens would theoretically accumulate
        thread::sleep(Duration::from_millis(50));

        // Should still only allow burst amount
        let mut count = 0;
        for _ in 0..10 {
            if limiter.try_acquire() {
                count += 1;
            }
        }
        assert_eq!(count, 3, "Should not exceed max_tokens (burst)");
    }

    #[test]
    fn zero_burst_rejects_all() {
        let limiter = UpstreamRateLimiter::new(100.0, 0);
        assert!(!limiter.try_acquire());
    }
}
