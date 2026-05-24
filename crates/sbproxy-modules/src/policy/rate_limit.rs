//! Rate limit policy.
//!
//! Token bucket algorithm with optional per-key buckets and an
//! optional shared L2 (Redis) fixed-window counter for cluster-wide
//! enforcement.

use parking_lot::Mutex;
use sbproxy_platform::storage::{AsyncKVStore, KVStore};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Instant;

/// Info returned after a rate limit check, for adding response headers.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Whether the request was allowed.
    pub allowed: bool,
    /// The configured limit (requests per window).
    pub limit: u64,
    /// Remaining requests in the current window.
    pub remaining: u64,
    /// Seconds until the bucket fully refills (delta format).
    pub reset_secs: u64,
    /// Whether rate limit headers should be emitted.
    pub headers_enabled: bool,
    /// Whether to include the Retry-After header on 429 responses.
    pub include_retry_after: bool,
}

/// Rate limit policy using a token bucket algorithm.
///
/// Tokens refill at `requests_per_second` rate, up to `burst` capacity.
/// Each allowed request consumes one token. When the bucket is empty,
/// requests are rejected until tokens refill.
///
/// When an L2 store (Redis) is attached via [`RateLimitPolicy::with_store`], rate limiting
/// switches to a distributed *fixed-window counter* so multiple proxy
/// replicas share state. This is intentionally simpler than the token-bucket
/// algorithm (and not smoothly refilled) but it lets a cluster enforce a
/// single shared limit.
#[derive(Deserialize)]
pub struct RateLimitPolicy {
    /// Per-second token refill rate.
    #[serde(default)]
    pub requests_per_second: Option<f64>,
    /// Per-minute token refill rate (mutually exclusive with `requests_per_second`).
    #[serde(default)]
    pub requests_per_minute: Option<f64>,
    /// Maximum burst capacity. When unset, defaults to the per-second rate.
    #[serde(default)]
    pub burst: Option<u32>,
    /// Algorithm hint (`token_bucket`, `fixed_window`); the runtime picks based on backend.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Header configuration (`X-RateLimit-*`, `Retry-After`).
    #[serde(default)]
    pub headers: Option<serde_json::Value>,
    /// Optional list of IPs/CIDRs that are exempt from rate limiting.
    #[serde(default)]
    pub whitelist: Option<Vec<String>>,
    /// Optional CEL expression evaluated against the request context to
    /// derive the bucket key. Common idioms:
    ///
    /// - `connection.remote_ip`: per-IP buckets (default behaviour when
    ///   the field is unset).
    /// - `request.headers["x-api-key"]`: per-API-key buckets.
    /// - `jwt.claims.tenant_id`: per-JWT-claim buckets (the
    ///   "Volumetric Abuse Detection" pattern).
    /// - `jwt.claims.sub + ":" + jwt.claims.tenant_id`: composite keys.
    ///
    /// When evaluation fails or returns empty, the policy falls back to
    /// the default client IP / hostname behaviour. Each distinct key
    /// gets its own token bucket; the cache is bounded so unbounded
    /// key cardinality cannot exhaust memory.
    #[serde(default)]
    pub key: Option<String>,
    /// Maximum number of distinct keys tracked locally. When the cache
    /// is full, the least-recently-used key is evicted. Defaults to
    /// 100k which keeps the bucket map under ~10 MB even with long key
    /// strings.
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,
    #[serde(skip)]
    buckets: Mutex<Option<lru::LruCache<String, TokenBucket>>>,
    #[serde(skip)]
    template_bucket: Mutex<TokenBucket>,
    /// Cold tier for keys that were already rate-limited before their
    /// hot bucket was evicted. This preserves deny state across LRU
    /// pollution without storing every one-off attacker key.
    #[serde(skip)]
    cold_limited: Mutex<Option<lru::LruCache<String, Instant>>>,

    // --- Optional L2 (cluster-shared) state ---
    /// Shared counter backend (sync). When `Some`, requests are gated by
    /// a Redis-backed fixed-window counter via `spawn_blocking`. Kept
    /// for callers that have not yet migrated to `async_store`.
    #[serde(skip)]
    store: Option<Arc<dyn KVStore>>,
    /// Shared counter backend (async-native). When `Some`, `allow_with_info_async`
    /// prefers this path over the sync `store`. Uses the `redis` crate's
    /// async client directly, with no `spawn_blocking` overhead per request.
    /// See `AsyncKVStore` + `AsyncRedisKVStore` in `sbproxy-platform`.
    #[serde(skip)]
    async_store: Option<Arc<dyn AsyncKVStore>>,
    /// Optional observer invoked after every successful L2 increment.
    /// Receives the post-increment count so consumers (e.g. the mesh
    /// persistence `SharedState`) can mirror the counter into a CRDT
    /// snapshot without knowing about the underlying store. Called only
    /// on the success path; failures are silent (fail-warn posture).
    #[serde(skip)]
    observer: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    /// Fixed-window length in seconds when `store` is active. Derived from
    /// the configured rate (1 s for `requests_per_second`, 60 s for
    /// `requests_per_minute`).
    #[serde(skip)]
    window_secs: u64,
    /// Pre-computed counter-key prefix so request-hot path does not allocate
    /// more than necessary. Format: `"sbproxy:rl:<origin-id>:"`.
    #[serde(skip)]
    key_prefix: String,
}

// Manual Debug impl because `dyn KVStore` has no `Debug` bound.
impl std::fmt::Debug for RateLimitPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitPolicy")
            .field("requests_per_second", &self.requests_per_second)
            .field("requests_per_minute", &self.requests_per_minute)
            .field("burst", &self.burst)
            .field("algorithm", &self.algorithm)
            .field("headers", &self.headers)
            .field("whitelist", &self.whitelist)
            .field("key", &self.key)
            .field("max_keys", &self.max_keys)
            .field("template_bucket", &self.template_bucket)
            .field("cold_limited_attached", &self.cold_limited.lock().is_some())
            .field("store_attached", &self.store.is_some())
            .field("async_store_attached", &self.async_store.is_some())
            .field("window_secs", &self.window_secs)
            .field("key_prefix", &self.key_prefix)
            .finish()
    }
}

impl RateLimitPolicy {
    /// Get the effective requests per second rate.
    fn effective_rps(&self) -> f64 {
        if let Some(rps) = self.requests_per_second {
            rps
        } else if let Some(rpm) = self.requests_per_minute {
            rpm / 60.0
        } else {
            10.0 // Default: 10 rps
        }
    }
}

/// Internal token bucket state.
#[derive(Debug, Clone)]
pub(crate) struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self {
            tokens: 0.0,
            max_tokens: 0.0,
            refill_rate: 0.0,
            last_refill: Instant::now(),
        }
    }
}

// Methods live on the struct (rather than duplicating the arithmetic in
// the test module) so the proptest exercises exactly the math used by
// `RateLimitPolicy::allow_with_info_for`.
#[cfg(test)]
impl TokenBucket {
    pub(crate) fn for_test(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            max_tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    pub(crate) fn current_tokens(&self) -> f64 {
        self.tokens
    }

    pub(crate) fn capacity(&self) -> f64 {
        self.max_tokens
    }

    pub(crate) fn refill_with_elapsed(&mut self, dt_secs: f64) {
        self.tokens = (self.tokens + dt_secs * self.refill_rate).min(self.max_tokens);
    }

    pub(crate) fn try_acquire(&mut self, n: f64) -> bool {
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

fn default_max_keys() -> usize {
    100_000
}

impl RateLimitPolicy {
    /// Build a RateLimitPolicy from a generic JSON config value.
    ///
    /// After deserialization, initializes the token bucket with the
    /// correct capacity and refill rate. When `burst` is not explicitly
    /// set, it defaults to the effective rate (e.g. requests_per_minute)
    /// so the bucket is exhausted after exactly that many requests.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut policy: Self = serde_json::from_value(value)?;
        let rps = policy.effective_rps();

        // Compute effective burst: if not explicitly set, use the rate limit
        // value so the bucket capacity matches the configured limit.
        let effective_burst = policy.burst.unwrap_or_else(|| {
            if let Some(rpm) = policy.requests_per_minute {
                rpm.ceil() as u32
            } else if let Some(rps_val) = policy.requests_per_second {
                rps_val.ceil() as u32
            } else {
                10
            }
        });

        let template = TokenBucket {
            tokens: effective_burst as f64,
            max_tokens: effective_burst as f64,
            refill_rate: rps,
            last_refill: Instant::now(),
        };
        // The template is the seed every per-key bucket clones from. It also
        // backs the legacy single-bucket path used when `key:` is unset.
        policy.template_bucket = Mutex::new(template);
        // Per-key buckets are only allocated when a `key:` expression is
        // configured. Cap defaults to 100k via `default_max_keys`.
        policy.buckets = if policy.key.is_some() {
            let cap = policy.max_keys.max(1);
            let cap = std::num::NonZeroUsize::new(cap).expect("cap is at least 1");
            Mutex::new(Some(lru::LruCache::new(cap)))
        } else {
            Mutex::new(None)
        };
        policy.cold_limited = if policy.key.is_some() {
            let cap = policy.max_keys.max(1);
            let cap = std::num::NonZeroUsize::new(cap).expect("cap is at least 1");
            Mutex::new(Some(lru::LruCache::new(cap)))
        } else {
            Mutex::new(None)
        };

        // Window length in seconds for the Redis-backed counter path. Prefer
        // requests_per_minute when that's how the limit is declared, otherwise
        // use a 1-second window for requests_per_second.
        policy.window_secs = if policy.requests_per_minute.is_some() {
            60
        } else {
            1
        };

        Ok(policy)
    }

    /// Attach a shared L2 store so this policy enforces a cluster-wide
    /// fixed-window counter. The `origin_id` is baked into every Redis
    /// key so different origins don't share counter state.
    ///
    /// When `store` is `None` the policy keeps the in-process token bucket.
    pub fn with_store(mut self, store: Option<Arc<dyn KVStore>>, origin_id: &str) -> Self {
        self.store = store;
        self.key_prefix = format!("sbproxy:rl:{}:", origin_id);
        self
    }

    /// Attach an **async** shared L2 store. Takes precedence over the sync
    /// `store` on the request-hot path: `allow_with_info_async` calls the
    /// async backend directly via `.await` without bridging through
    /// `spawn_blocking`.
    ///
    /// `origin_id` is baked into the counter-key prefix the same way
    /// [`Self::with_store`] does it. Calling this sets the prefix only if
    /// the sync `with_store` hasn't already set it, so both setters can
    /// be chained in either order.
    pub fn with_async_store(
        mut self,
        store: Option<Arc<dyn AsyncKVStore>>,
        origin_id: &str,
    ) -> Self {
        self.async_store = store;
        if self.key_prefix.is_empty() {
            self.key_prefix = format!("sbproxy:rl:{}:", origin_id);
        }
        self
    }

    /// Attach an observer closure called after every successful L2
    /// counter increment (both async and sync paths). Designed for
    /// the mesh persistence `SharedState` pattern: the enterprise
    /// startup hook creates a closure that pushes the post-increment
    /// count into the shared CRDT, so snapshots to Redis reflect
    /// real rate-limit state instead of placeholder empties.
    ///
    /// Pass `None` to clear a previously attached observer. Observer
    /// closures must be cheap, since they run on the request-hot path.
    pub fn with_observer(mut self, observer: Option<Arc<dyn Fn(u64) + Send + Sync>>) -> Self {
        self.observer = observer;
        self
    }

    /// Effective per-window limit used by the Redis-backed fixed-window path.
    fn window_limit(&self) -> u64 {
        if let Some(rpm) = self.requests_per_minute {
            rpm.ceil() as u64
        } else if let Some(rps) = self.requests_per_second {
            rps.ceil() as u64
        } else {
            10
        }
    }

    /// Check whether rate limit headers are enabled in the config.
    fn headers_enabled(&self) -> bool {
        self.headers
            .as_ref()
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Check whether the include_retry_after option is enabled.
    fn include_retry_after(&self) -> bool {
        self.headers
            .as_ref()
            .and_then(|v| v.get("include_retry_after"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Try to consume a token. Returns true if the request is allowed,
    /// false if rate-limited.
    pub fn allow(&self) -> bool {
        self.allow_with_info().allowed
    }

    /// Try to consume a token from the default (single, shared) bucket.
    /// Equivalent to `allow_with_info_for("")`.
    pub fn allow_with_info(&self) -> RateLimitInfo {
        self.allow_with_info_for("")
    }

    /// Try to consume a token from the bucket associated with `key`.
    ///
    /// When the policy has no `key:` expression configured, every call
    /// shares the same template bucket regardless of the argument. When
    /// `key:` is set, each distinct key gets its own bucket via an LRU
    /// cache bounded by `max_keys`.
    ///
    /// This is the local-only path; it does not consult any shared L2
    /// store.
    pub fn allow_with_info_for(&self, key: &str) -> RateLimitInfo {
        let now = Instant::now();
        let headers_enabled = self.headers_enabled();
        let include_retry_after = self.include_retry_after();

        if let Some(info) = self.cold_limited_info(key, now, headers_enabled, include_retry_after) {
            return info;
        }

        // Resolve which bucket to act on. The per-key path uses the LRU
        // map and may insert a fresh bucket cloned from the template;
        // the legacy path operates on the shared template bucket.
        let mut buckets_guard = self.buckets.lock();
        let keyed_path = buckets_guard.is_some();
        let mut template_guard;
        let bucket: &mut TokenBucket = if let Some(map) = buckets_guard.as_mut() {
            if !map.contains(key) {
                let template = self.template_bucket.lock().clone();
                map.put(key.to_string(), template);
            }
            map.get_mut(key).expect("inserted just above")
        } else {
            template_guard = self.template_bucket.lock();
            &mut template_guard
        };

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_rate).min(bucket.max_tokens);
        bucket.last_refill = now;

        let limit = bucket.max_tokens as u64;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            let remaining = bucket.tokens.floor() as u64;
            let deficit = bucket.max_tokens - bucket.tokens;
            let reset_secs = if bucket.refill_rate > 0.0 {
                (deficit / bucket.refill_rate).ceil() as u64
            } else {
                0
            };
            // Drop both guards before the observer call. The observer may
            // grab a separate lock (e.g. mesh SharedState) and we don't
            // want to hold the bucket cache while it runs.
            drop(buckets_guard);
            if let Some(obs) = self.observer.as_ref() {
                obs(1);
            }
            RateLimitInfo {
                allowed: true,
                limit,
                remaining,
                reset_secs,
                headers_enabled,
                include_retry_after,
            }
        } else {
            let full_reset = if bucket.refill_rate > 0.0 {
                (bucket.max_tokens / bucket.refill_rate).ceil() as u64
            } else {
                0
            };
            if keyed_path {
                self.remember_cold_limited(key, now, full_reset);
            }
            RateLimitInfo {
                allowed: false,
                limit,
                remaining: 0,
                reset_secs: full_reset,
                headers_enabled,
                include_retry_after,
            }
        }
    }

    fn cold_limited_info(
        &self,
        key: &str,
        now: Instant,
        headers_enabled: bool,
        include_retry_after: bool,
    ) -> Option<RateLimitInfo> {
        let mut cold_guard = self.cold_limited.lock();
        let cold = cold_guard.as_mut()?;
        let until = cold.get(key).copied()?;
        if now >= until {
            cold.pop(key);
            return None;
        }

        let limit = self.template_bucket.lock().max_tokens as u64;
        Some(RateLimitInfo {
            allowed: false,
            limit,
            remaining: 0,
            reset_secs: until.duration_since(now).as_secs().max(1),
            headers_enabled,
            include_retry_after,
        })
    }

    fn remember_cold_limited(&self, key: &str, now: Instant, reset_secs: u64) {
        if reset_secs == 0 {
            return;
        }
        let mut cold_guard = self.cold_limited.lock();
        if let Some(cold) = cold_guard.as_mut() {
            cold.put(
                key.to_string(),
                now + std::time::Duration::from_secs(reset_secs),
            );
        }
    }

    /// Async variant of [`RateLimitPolicy::allow_with_info`].
    ///
    /// When a shared L2 store is attached, this enforces a *fixed-window
    /// counter* in Redis (atomic INCR + EXPIRE). The window length is
    /// derived from the rate unit (`requests_per_second` -> 1 s window,
    /// `requests_per_minute` -> 60 s window). Note this is a different
    /// algorithm from the local token bucket: it does not smoothly refill
    /// or admit bursts above the rate limit.
    ///
    /// When no store is attached, this falls back to the sync token-bucket
    /// path (same semantics as [`RateLimitPolicy::allow_with_info`]).
    ///
    /// If the Redis call fails, the request is admitted (fail-open). The
    /// alternative (fail-closed) would turn a Redis hiccup into a
    /// cluster-wide outage. The Go OSS proxy makes the same choice.
    pub async fn allow_with_info_async(&self, client_id: &str) -> RateLimitInfo {
        // Prefer the async store (no spawn_blocking overhead). Fall back
        // to the sync store via spawn_blocking for callers that have not
        // migrated yet. If neither is configured, fall all the way back
        // to the local per-key token bucket.
        if self.async_store.is_none() && self.store.is_none() {
            return self.allow_with_info_for(client_id);
        }

        let window = if self.window_secs > 0 {
            self.window_secs
        } else {
            1
        };
        let limit = self.window_limit();
        let headers_enabled = self.headers_enabled();
        let include_retry_after = self.include_retry_after();

        // Bucket the counter by wall-clock epoch so the window moves
        // forward together across replicas. Each window gets its own key.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_start = now_secs - (now_secs % window);

        let key = format!("{}{}:{}", self.key_prefix, client_id, window_start);
        let ttl = window + 1;
        let key_bytes = key.into_bytes();

        // Fail-open helper: Redis hiccups should not turn into a
        // cluster-wide outage. Matches the Go OSS proxy's choice.
        let fail_open = || RateLimitInfo {
            allowed: true,
            limit,
            remaining: limit,
            reset_secs: window,
            headers_enabled,
            include_retry_after,
        };

        let incr_result: anyhow::Result<i64> = if let Some(async_store) = self.async_store.as_ref()
        {
            // Async path: native await, no spawn_blocking tax.
            async_store.incr_with_ttl(&key_bytes, ttl).await
        } else {
            let store = self
                .store
                .clone()
                .expect("checked at function entry that at least one store is set");
            // Sync fallback path via spawn_blocking.
            match tokio::task::spawn_blocking({
                let key_bytes = key_bytes.clone();
                move || store.incr_with_ttl(&key_bytes, ttl)
            })
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "l2 rate-limit spawn_blocking join failed");
                    return fail_open();
                }
            }
        };

        let count = match incr_result {
            Ok(n) => n as u64,
            Err(e) => {
                tracing::warn!(error = %e, "l2 rate-limit INCR failed, failing open");
                return fail_open();
            }
        };

        // Push the post-increment count to the observer if one is attached.
        // Cheap (Arc clone + function call); runs outside the fail-open branch.
        if let Some(obs) = self.observer.as_ref() {
            obs(count);
        }

        let remaining = limit.saturating_sub(count);
        let reset_secs = window.saturating_sub(now_secs - window_start);

        RateLimitInfo {
            allowed: count <= limit,
            limit,
            remaining,
            reset_secs,
            headers_enabled,
            include_retry_after,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn rate_limit_policy_type() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "requests_per_second": 100.0,
            "burst": 50
        });
        let rl = RateLimitPolicy::from_config(json).unwrap();
        let policy = Policy::RateLimit(rl);
        assert_eq!(policy.policy_type(), "rate_limiting");
    }

    #[test]
    fn policy_debug_rate_limit() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "requests_per_second": 10.0,
            "burst": 5
        });
        let rl = RateLimitPolicy::from_config(json).unwrap();
        let policy = Policy::RateLimit(rl);
        let debug = format!("{:?}", policy);
        assert!(debug.contains("RateLimit"));
    }

    #[test]
    fn rate_limit_from_config() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "requests_per_second": 50.0,
            "burst": 20
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();
        assert_eq!(policy.requests_per_second, Some(50.0));
        assert_eq!(policy.burst, Some(20));
    }

    #[test]
    fn rate_limit_from_config_default_burst() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "requests_per_second": 10.0
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();
        assert_eq!(policy.burst, None);
    }

    #[test]
    fn rate_limit_from_config_defaults() {
        // Both rps and rpm are optional; defaults to 10 rps
        let json = serde_json::json!({"type": "rate_limiting"});
        let policy = RateLimitPolicy::from_config(json).unwrap();
        assert_eq!(policy.effective_rps(), 10.0);
    }

    #[test]
    fn rate_limit_from_config_rpm() {
        let json = serde_json::json!({
            "type": "rate_limiting",
            "requests_per_minute": 60
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();
        assert!((policy.effective_rps() - 1.0).abs() < 0.01);
    }

    #[test]
    fn allow_within_burst() {
        let json = serde_json::json!({
            "requests_per_second": 10.0,
            "burst": 5
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();

        for _ in 0..5 {
            assert!(policy.allow());
        }
        assert!(!policy.allow());
    }

    #[test]
    fn allow_refills_over_time() {
        let json = serde_json::json!({
            "requests_per_second": 1000.0,
            "burst": 1
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();

        assert!(policy.allow());
        assert!(!policy.allow());

        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(policy.allow());
    }

    #[test]
    fn allow_does_not_exceed_burst() {
        let json = serde_json::json!({
            "requests_per_second": 1000.0,
            "burst": 3
        });
        let policy = RateLimitPolicy::from_config(json).unwrap();

        for _ in 0..3 {
            assert!(policy.allow());
        }
        assert!(!policy.allow());

        std::thread::sleep(std::time::Duration::from_millis(10));

        let mut allowed = 0;
        for _ in 0..10 {
            if policy.allow() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 3, "should not exceed burst capacity");
    }

    #[test]
    fn evicted_limited_key_stays_limited_after_lru_pollution() {
        let policy = RateLimitPolicy::from_config(serde_json::json!({
            "requests_per_second": 0.001,
            "burst": 1,
            "key": "request.headers[\"x-api-key\"]",
            "max_keys": 2
        }))
        .unwrap();

        assert!(policy.allow_with_info_for("legit").allowed);
        assert!(!policy.allow_with_info_for("legit").allowed);

        for i in 0..20 {
            let key = format!("attacker-{i}");
            let _ = policy.allow_with_info_for(&key);
        }

        assert!(
            !policy.allow_with_info_for("legit").allowed,
            "LRU eviction must not reset an exhausted legitimate bucket"
        );
    }

    // --- TokenBucket arithmetic property tests ---
    //
    // These pair with the loom drain test that landed in PR #47. Loom
    // covers the reload state machine; proptest covers the bucket math.
    mod token_bucket_proptests {
        use super::super::TokenBucket;
        use proptest::prelude::*;

        // Floating-point comparisons in this module use this slack to
        // absorb the rounding error of repeated f64 add / multiply across
        // long operation sequences. The bucket math is one add and one
        // multiply per step, so error grows slowly; 1e-6 is comfortable.
        const FP_EPS: f64 = 1e-6;

        fn bucket_strategy() -> impl Strategy<Value = (f64, f64)> {
            (1.0f64..1.0e6, 0.0f64..1.0e6)
        }

        proptest! {
            #[test]
            fn refill_never_exceeds_capacity(
                (capacity, rate) in bucket_strategy(),
                start_tokens in 0.0f64..1.0e6,
                dt in 0.0f64..1.0e9,
            ) {
                let start = start_tokens.min(capacity);
                let mut b = TokenBucket::for_test(capacity, rate);
                b.tokens = start;
                b.refill_with_elapsed(dt);
                prop_assert!(b.current_tokens() <= capacity + FP_EPS,
                    "refill must clamp at capacity even with huge dt");
                prop_assert!(b.current_tokens() >= start - FP_EPS,
                    "refill is monotone non-decreasing in tokens");
            }

            #[test]
            fn refill_amount_is_min_of_headroom_and_dt_times_rate(
                (capacity, rate) in bucket_strategy(),
                start_tokens in 0.0f64..1.0e6,
                dt in 0.0f64..1.0e6,
            ) {
                let start = start_tokens.min(capacity);
                let mut b = TokenBucket::for_test(capacity, rate);
                b.tokens = start;
                let headroom = capacity - start;
                let earned = dt * rate;
                let expected = start + headroom.min(earned);
                b.refill_with_elapsed(dt);
                prop_assert!((b.current_tokens() - expected).abs() < FP_EPS + expected.abs() * 1e-9,
                    "expected {} got {}", expected, b.current_tokens());
            }

            #[test]
            fn try_acquire_succeeds_iff_tokens_at_least_n(
                (capacity, _rate) in bucket_strategy(),
                start_tokens in 0.0f64..1.0e6,
                n in 0.0f64..1.0e6,
            ) {
                let start = start_tokens.min(capacity);
                let mut b = TokenBucket::for_test(capacity, 0.0);
                b.tokens = start;
                let before = b.current_tokens();
                let ok = b.try_acquire(n);
                if ok {
                    prop_assert!(before >= n);
                    prop_assert!((b.current_tokens() - (before - n)).abs() < FP_EPS);
                    prop_assert!(b.current_tokens() >= -FP_EPS,
                        "successful acquire must not produce negative tokens");
                } else {
                    prop_assert!(before < n);
                    prop_assert!((b.current_tokens() - before).abs() < FP_EPS,
                        "failed acquire must leave tokens unchanged");
                }
            }

            #[test]
            fn arbitrary_op_sequence_keeps_tokens_in_bounds(
                (capacity, rate) in bucket_strategy(),
                ops in proptest::collection::vec(
                    prop_oneof![
                        (0.0f64..10.0).prop_map(Op::Advance),
                        (0.0f64..10.0).prop_map(Op::Acquire),
                    ],
                    0..64,
                ),
            ) {
                let mut b = TokenBucket::for_test(capacity, rate);
                for op in ops {
                    match op {
                        Op::Advance(dt) => b.refill_with_elapsed(dt),
                        Op::Acquire(n) => { let _ = b.try_acquire(n); }
                    }
                    prop_assert!(b.current_tokens().is_finite(),
                        "tokens must never become NaN or infinite");
                    prop_assert!(b.current_tokens() <= b.capacity() + FP_EPS,
                        "tokens must never exceed capacity");
                    prop_assert!(b.current_tokens() >= -FP_EPS,
                        "tokens must never go negative");
                }
            }
        }

        #[derive(Debug, Clone)]
        enum Op {
            Advance(f64),
            Acquire(f64),
        }
    }
}
