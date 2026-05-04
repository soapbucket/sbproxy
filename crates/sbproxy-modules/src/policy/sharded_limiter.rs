//! Sharded token bucket rate limiter.
//!
//! Distributes load across 64 shards to minimize lock contention under
//! high concurrency. Each shard maintains its own token count using
//! atomic integers (fixed-point, scaled by 1000) so no mutex is needed
//! on the hot path.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

const NUM_SHARDS: usize = 64;

/// Fixed-point scaling factor. Token counts are stored as
/// `actual_tokens * SCALE` so we get sub-token precision with integers.
const SCALE: i64 = 1000;

/// Sharded token bucket rate limiter.
/// Distributes load across 64 shards to minimize lock contention.
pub struct ShardedRateLimiter {
    shards: Vec<Shard>,
    rate: f64,       // tokens per second (global)
    max_tokens: f64, // burst capacity (global)
}

struct Shard {
    /// Token count in fixed-point (actual * SCALE).
    tokens: AtomicI64,
    /// Last refill timestamp in epoch milliseconds.
    last_refill: AtomicU64,
}

impl ShardedRateLimiter {
    /// Create a new sharded rate limiter.
    ///
    /// `rate` is the token refill rate in tokens per second (global).
    /// `burst` is the maximum burst capacity (global). Each shard gets
    /// an equal fraction of the burst budget.
    pub fn new(rate: f64, burst: u32) -> Self {
        let per_shard_tokens = (burst as f64 / NUM_SHARDS as f64 * SCALE as f64) as i64;
        let shards: Vec<Shard> = (0..NUM_SHARDS)
            .map(|_| Shard {
                tokens: AtomicI64::new(per_shard_tokens),
                last_refill: AtomicU64::new(Self::now_millis()),
            })
            .collect();
        Self {
            shards,
            rate,
            max_tokens: burst as f64,
        }
    }

    /// Try to consume a token. Returns true if allowed.
    ///
    /// Uses `key` (typically a hash of the client IP) to select a shard
    /// for even distribution across the shards.
    pub fn allow(&self, key: u64) -> bool {
        let shard_idx = (key as usize) % NUM_SHARDS;
        let shard = &self.shards[shard_idx];

        // Refill tokens based on elapsed time.
        let now = Self::now_millis();
        let last = shard.last_refill.load(Ordering::Relaxed);
        let elapsed_ms = now.saturating_sub(last);
        if elapsed_ms > 0 {
            let refill = (self.rate * elapsed_ms as f64 / 1000.0 * SCALE as f64) as i64;
            let max_per_shard = (self.max_tokens / NUM_SHARDS as f64 * SCALE as f64) as i64;
            // Cap at per-shard maximum.
            let added = refill.min(max_per_shard);
            if added > 0 {
                shard.tokens.fetch_add(added, Ordering::Relaxed);
                shard.last_refill.store(now, Ordering::Relaxed);
            }
            // Clamp so we never exceed the per-shard cap even after
            // multiple concurrent refills.
            let current = shard.tokens.load(Ordering::Relaxed);
            if current > max_per_shard {
                // Best-effort clamp; concurrent threads may also clamp,
                // which is harmless.
                let _ = shard.tokens.compare_exchange(
                    current,
                    max_per_shard,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
        }

        // Try to consume one token (SCALE units in fixed-point).
        let prev = shard.tokens.fetch_sub(SCALE, Ordering::Relaxed);
        if prev >= SCALE {
            true
        } else {
            // Not enough tokens - undo the subtraction.
            shard.tokens.fetch_add(SCALE, Ordering::Relaxed);
            false
        }
    }

    /// Current epoch time in milliseconds.
    fn now_millis() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Number of shards (exposed for testing).
    pub fn num_shards() -> usize {
        NUM_SHARDS
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_within_burst_returns_true() {
        let limiter = ShardedRateLimiter::new(100.0, 64);
        // Each shard gets 1 token (64 / 64). Key 0 always hits shard 0.
        assert!(limiter.allow(0));
    }

    #[test]
    fn exhausting_burst_returns_false() {
        let limiter = ShardedRateLimiter::new(0.0, 64);
        // With rate=0 there is no refill.
        // Shard 0 starts with floor(64/64) = 1 token.
        assert!(limiter.allow(0), "first request should succeed");
        assert!(!limiter.allow(0), "second request should be rejected");
    }

    #[test]
    fn different_keys_use_different_shards() {
        // rate=0 so no refill. burst=64 gives 1 token per shard.
        let limiter = ShardedRateLimiter::new(0.0, 64);
        // Keys 0 and 1 hit different shards.
        assert!(limiter.allow(0));
        assert!(limiter.allow(1));
        // Both shards are now empty.
        assert!(!limiter.allow(0));
        assert!(!limiter.allow(1));
    }

    #[test]
    fn refill_over_time_allows_more_requests() {
        // High rate so tokens refill very quickly.
        let limiter = ShardedRateLimiter::new(100_000.0, 64);
        // Drain shard 0.
        assert!(limiter.allow(0));
        // Sleep briefly so the clock advances enough for a refill.
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(
            limiter.allow(0),
            "refill should allow another request after a brief sleep"
        );
    }

    #[test]
    fn concurrent_access_does_not_panic() {
        use std::sync::Arc;
        let limiter = Arc::new(ShardedRateLimiter::new(1000.0, 256));
        let mut handles = Vec::new();
        for i in 0..8 {
            let lim = Arc::clone(&limiter);
            handles.push(std::thread::spawn(move || {
                for j in 0..1000 {
                    let _ = lim.allow((i * 1000 + j) as u64);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread should not panic");
        }
    }
}
