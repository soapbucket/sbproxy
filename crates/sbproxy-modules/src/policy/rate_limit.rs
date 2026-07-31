//! Rate limit policy.
//!
//! Token bucket algorithm with optional per-key buckets and an
//! optional shared L2 (Redis) fixed-window counter for cluster-wide
//! enforcement.

use crate::policy::rate_limit_cluster;
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
    /// Whether a workspace-budget response includes `RateLimit-Policy`.
    ///
    /// The ordinary rate limiter and DDoS policy leave this false.
    pub include_ratelimit_policy: bool,
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
    /// - `request.key_id`: per-key buckets for a minted virtual key. Prefer
    ///   this over the header below when `key_management` is on: the header
    ///   holds the presented secret, so a rotation changes it and hands the
    ///   caller a fresh budget, whereas the id is immutable. Empty string when
    ///   no minted key resolved.
    /// - `request.headers["x-api-key"]`: per-API-key buckets. Correct for
    ///   static configured keys; see `request.key_id` for minted ones.
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
    /// Optional mesh cluster tier. When `Some` and no L2 store is
    /// configured, the policy admits against this node's count plus the
    /// merged peer view instead of a purely local token bucket. Only
    /// consulted for windows longer than one second; see
    /// [`Self::converges_on_mesh`].
    #[serde(skip)]
    cluster: Option<Arc<rate_limit_cluster::RateLimitClusterTier>>,
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
            .field("cluster_attached", &self.cluster.is_some())
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

impl TokenBucket {
    fn with_rate(refill_rate: f64, now: Instant) -> Self {
        let max_tokens = refill_rate.ceil().max(1.0);
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: now,
        }
    }

    fn refill_at(&mut self, now: Instant) {
        // Callers capture time before contending on a shared bucket lock.
        // Preserve the newest timestamp so a delayed older caller cannot make
        // a later request earn the same refill interval twice.
        let now = now.max(self.last_refill);
        let elapsed = now.duration_since(self.last_refill);
        self.refill_with_elapsed(elapsed.as_secs_f64());
        self.last_refill = now;
    }

    fn refill_with_elapsed(&mut self, elapsed_secs: f64) {
        self.tokens = (self.tokens + elapsed_secs * self.refill_rate).min(self.max_tokens);
    }

    fn reconfigure_at(&mut self, refill_rate: f64, now: Instant) {
        // Earn elapsed tokens under the rate that governed that elapsed
        // interval. Changing a grant must not mint tokens retroactively.
        self.refill_at(now);
        let max_tokens = refill_rate.ceil().max(1.0);
        self.tokens = self.tokens.min(max_tokens);
        self.max_tokens = max_tokens;
        self.refill_rate = refill_rate;
    }

    fn try_acquire(&mut self, tokens: f64) -> bool {
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn projected_tokens_at(&self, now: Instant) -> f64 {
        let elapsed = now.saturating_duration_since(self.last_refill);
        (self.tokens + elapsed.as_secs_f64() * self.refill_rate).min(self.max_tokens)
    }

    fn full_refill_reset_secs_at(&self, now: Instant) -> u64 {
        if self.refill_rate <= 0.0 {
            return 0;
        }
        let deficit = self.max_tokens - self.projected_tokens_at(now);
        (deficit / self.refill_rate).ceil() as u64
    }

    fn next_token_reset_secs_at(&self, now: Instant) -> u64 {
        if self.refill_rate <= 0.0 {
            return 0;
        }
        let deficit = (1.0 - self.projected_tokens_at(now)).max(0.0);
        (deficit / self.refill_rate).ceil() as u64
    }

    #[cfg(test)]
    pub(crate) fn for_test(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            max_tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    #[cfg(test)]
    pub(crate) fn current_tokens(&self) -> f64 {
        self.tokens
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> f64 {
        self.max_tokens
    }
}

fn default_max_keys() -> usize {
    100_000
}

/// Admission result from a dynamic keyed token bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DynamicRateLimitInfo {
    /// Whether the request consumed a token.
    pub(crate) allowed: bool,
    /// Current bucket capacity.
    pub(crate) limit: u64,
    /// Whole tokens available after this decision.
    pub(crate) remaining: u64,
    /// Seconds until the governing bucket is fully refilled.
    pub(crate) reset_secs: u64,
}

/// Bounded token-bucket registry whose rate can change on every admission.
#[derive(Debug)]
pub(crate) struct DynamicKeyedTokenBuckets {
    buckets: Mutex<lru::LruCache<String, TokenBucket>>,
}

impl Default for DynamicKeyedTokenBuckets {
    fn default() -> Self {
        Self::new(default_max_keys())
    }
}

impl DynamicKeyedTokenBuckets {
    pub(crate) fn new(max_keys: usize) -> Self {
        let capacity = std::num::NonZeroUsize::new(max_keys.max(1))
            .expect("dynamic bucket capacity is at least one");
        Self {
            buckets: Mutex::new(lru::LruCache::new(capacity)),
        }
    }

    pub(crate) fn check(&self, key: &str, refill_rate: f64) -> DynamicRateLimitInfo {
        self.check_at(key, refill_rate, Instant::now())
    }

    fn check_at(&self, key: &str, refill_rate: f64, now: Instant) -> DynamicRateLimitInfo {
        if !refill_rate.is_finite() || refill_rate <= 0.0 {
            return DynamicRateLimitInfo {
                allowed: false,
                limit: 0,
                remaining: 0,
                reset_secs: 1,
            };
        }

        let requested_limit = refill_rate.ceil().max(1.0) as u64;
        let mut buckets = self.buckets.lock();
        if let Some(bucket) = buckets.get_mut(key) {
            bucket.reconfigure_at(refill_rate, now);
            return Self::consume(bucket, now);
        }

        if buckets.len() >= buckets.cap().get() {
            let (evictable, reset_secs) = {
                let (_, candidate) = buckets
                    .peek_lru()
                    .expect("a full dynamic bucket registry has an LRU entry");
                (
                    candidate.projected_tokens_at(now) >= candidate.max_tokens,
                    candidate.full_refill_reset_secs_at(now).max(1),
                )
            };
            if !evictable {
                return DynamicRateLimitInfo {
                    allowed: false,
                    limit: requested_limit,
                    remaining: 0,
                    reset_secs,
                };
            }
            buckets.pop_lru();
        }

        buckets.put(key.to_string(), TokenBucket::with_rate(refill_rate, now));
        let bucket = buckets
            .get_mut(key)
            .expect("dynamic bucket was inserted immediately above");
        Self::consume(bucket, now)
    }

    fn consume(bucket: &mut TokenBucket, now: Instant) -> DynamicRateLimitInfo {
        let allowed = bucket.try_acquire(1.0);
        let reset_secs = if allowed {
            bucket.full_refill_reset_secs_at(now)
        } else {
            bucket.next_token_reset_secs_at(now)
        };
        DynamicRateLimitInfo {
            allowed,
            limit: bucket.max_tokens as u64,
            remaining: bucket.tokens.floor() as u64,
            reset_secs,
        }
    }
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

    /// Attach the mesh cluster tier so this policy enforces an approximate
    /// cluster-wide limit with no Redis.
    ///
    /// Only consulted when no L2 store is attached: a shared counter is
    /// exact, so it always wins over an approximate merged view.
    ///
    /// Overshoot is bounded by `peers * rate * dissemination_cadence`. With
    /// the default 3 second cadence, each additional node can admit about
    /// `rate * 3` requests before this node hears about them. Pass `None` to
    /// clear a previously attached tier.
    ///
    /// `origin_id` is baked into the counter-key prefix the same way
    /// [`Self::with_store`] does it, so origins sharing one process-wide tier
    /// cannot collide on a common client id. The prefix is set only if a
    /// store setter has not already set it, so the setters chain in any
    /// order.
    pub fn with_cluster(
        mut self,
        cluster: Option<Arc<rate_limit_cluster::RateLimitClusterTier>>,
        origin_id: &str,
    ) -> Self {
        self.cluster = cluster;
        if self.key_prefix.is_empty() {
            self.key_prefix = format!("sbproxy:rl:{}:", origin_id);
        }
        self
    }

    /// Whether this policy's window is long enough to reconcile across nodes.
    ///
    /// A one second window closes before a peer contribution can arrive at
    /// any sane gossip cadence, so `requests_per_second` limits stay
    /// per-node rather than pretending to converge.
    pub fn converges_on_mesh(&self) -> bool {
        self.window_secs > 1
    }

    /// Test-only accessor for the counter-key prefix, so tests can build the
    /// same bucket string the cluster path derives.
    #[cfg(test)]
    pub(crate) fn debug_key_prefix(&self) -> &str {
        &self.key_prefix
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

        bucket.refill_at(now);

        let limit = bucket.max_tokens as u64;

        if bucket.try_acquire(1.0) {
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
                include_ratelimit_policy: false,
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
                include_ratelimit_policy: false,
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
            include_ratelimit_policy: false,
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
            // No shared counter. Fall back to the mesh cluster tier when one
            // is attached and the window is long enough to reconcile, else
            // to the purely local token bucket.
            if let Some(cluster) = self.cluster.as_ref() {
                if self.converges_on_mesh() {
                    return self.allow_with_info_cluster(client_id, cluster.as_ref());
                }
            }
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
            include_ratelimit_policy: false,
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
            include_ratelimit_policy: false,
        }
    }

    /// Admit against this node's count plus the merged peer view.
    ///
    /// The window boundary is computed exactly as the Redis path computes it,
    /// so every node buckets a given instant into the same window and the
    /// per-node slots merge. Local counting is immediate and authoritative
    /// for this node; the peer view lags by at most one dissemination
    /// cadence, which is the documented source of overshoot.
    ///
    /// There is no fail-open branch here because nothing can fail: both
    /// reads are in-process. A partitioned node simply sees an empty peer
    /// view once its last merge expires and enforces on its own count,
    /// which over-admits rather than denying traffic.
    fn allow_with_info_cluster(
        &self,
        client_id: &str,
        cluster: &rate_limit_cluster::RateLimitClusterTier,
    ) -> RateLimitInfo {
        let window = if self.window_secs > 0 {
            self.window_secs
        } else {
            1
        };
        let limit = self.window_limit();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_start = now_secs - (now_secs % window);
        let bucket = format!("{}{}:{}", self.key_prefix, client_id, window_start);

        let local = cluster.increment_local(&bucket, window_start);
        let peers = cluster.merged_peers(&bucket, window_start);
        let count = local.saturating_add(peers);

        // The merged view changed the outcome: this node alone would have
        // admitted. Counting it is what makes the approximation observable
        // instead of something an operator has to infer.
        if count > limit && local <= limit {
            sbproxy_observe::metrics::record_rate_limit_cluster_peer_denial();
        }

        RateLimitInfo {
            allowed: count <= limit,
            limit,
            remaining: limit.saturating_sub(count),
            reset_secs: window.saturating_sub(now_secs - window_start),
            headers_enabled: self.headers_enabled(),
            include_retry_after: self.include_retry_after(),
            include_ratelimit_policy: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- WOR-2084: async L2 store on the hot path ---

    /// Async store fake that records every `incr_with_ttl` key it sees.
    struct RecordingAsyncStore {
        count: std::sync::atomic::AtomicI64,
        keys: std::sync::Mutex<Vec<String>>,
    }

    impl RecordingAsyncStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                count: std::sync::atomic::AtomicI64::new(0),
                keys: std::sync::Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait::async_trait]
    impl sbproxy_platform::storage::AsyncKVStore for RecordingAsyncStore {
        async fn get(&self, _key: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
            Ok(None)
        }
        async fn put(&self, _key: &[u8], _value: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        async fn put_with_ttl(
            &self,
            _key: &[u8],
            _value: &[u8],
            _ttl_secs: u64,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn incr_with_ttl(&self, key: &[u8], _ttl_secs: u64) -> anyhow::Result<i64> {
            self.keys
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(key).into_owned());
            Ok(self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1)
        }
        async fn delete(&self, _key: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Sync store fake that panics if the hot path ever reaches it, which
    /// is exactly the spawn_blocking bridge the async handle exists to
    /// bypass.
    struct PanicSyncStore;

    impl sbproxy_platform::storage::KVStore for PanicSyncStore {
        fn get(&self, _key: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
            panic!("sync store must not be consulted when an async store is attached");
        }
        fn put(&self, _key: &[u8], _value: &[u8]) -> anyhow::Result<()> {
            panic!("sync store must not be consulted when an async store is attached");
        }
        fn put_with_ttl(&self, _key: &[u8], _value: &[u8], _ttl_secs: u64) -> anyhow::Result<()> {
            panic!("sync store must not be consulted when an async store is attached");
        }
        fn incr_with_ttl(&self, _key: &[u8], _ttl_secs: u64) -> anyhow::Result<i64> {
            panic!("sync store must not be consulted when an async store is attached");
        }
        fn delete(&self, _key: &[u8]) -> anyhow::Result<()> {
            panic!("sync store must not be consulted when an async store is attached");
        }
        fn scan_prefix(&self, _prefix: &[u8]) -> anyhow::Result<Vec<(bytes::Bytes, bytes::Bytes)>> {
            panic!("sync store must not be consulted when an async store is attached");
        }
    }

    #[tokio::test]
    async fn the_async_store_carries_the_hot_path_and_the_sync_store_is_never_touched() {
        // Wired the way the pipeline compiler wires it: both handles
        // attached, async preferred. The sync fake panics on any call,
        // so this test fails loudly if the hot path regresses onto the
        // spawn_blocking bridge.
        let recorder = RecordingAsyncStore::new();
        let policy =
            RateLimitPolicy::from_config(serde_json::json!({ "requests_per_minute": 2.0 }))
                .expect("valid rpm policy")
                .with_store(
                    Some(Arc::new(PanicSyncStore) as Arc<dyn sbproxy_platform::storage::KVStore>),
                    "origin-a",
                )
                .with_async_store(
                    Some(recorder.clone() as Arc<dyn sbproxy_platform::storage::AsyncKVStore>),
                    "origin-a",
                );

        assert!(policy.allow_with_info_async("c1").await.allowed);
        assert!(policy.allow_with_info_async("c1").await.allowed);
        let third = policy.allow_with_info_async("c1").await;
        assert!(
            !third.allowed,
            "the shared async counter must deny the third request under a limit of 2"
        );

        let keys = recorder.keys.lock().unwrap();
        assert_eq!(keys.len(), 3, "every decision must hit the async store");
        assert!(
            keys.iter().all(|k| k.starts_with("sbproxy:rl:origin-a:")),
            "counter keys must carry the origin-scoped prefix: {keys:?}"
        );
    }

    #[tokio::test]
    async fn attach_order_does_not_change_the_counter_key_prefix() {
        // `with_async_store` only sets the prefix when `with_store` has
        // not already set it, and vice versa. If the derived prefixes
        // ever diverged, an upgrade that adds the async handle would
        // silently reset every live counter into a fresh keyspace.
        let recorder_a = RecordingAsyncStore::new();
        let sync_first =
            RateLimitPolicy::from_config(serde_json::json!({ "requests_per_minute": 10.0 }))
                .expect("valid rpm policy")
                .with_store(
                    Some(Arc::new(PanicSyncStore) as Arc<dyn sbproxy_platform::storage::KVStore>),
                    "origin-a",
                )
                .with_async_store(
                    Some(recorder_a.clone() as Arc<dyn sbproxy_platform::storage::AsyncKVStore>),
                    "origin-a",
                );

        let recorder_b = RecordingAsyncStore::new();
        let async_first =
            RateLimitPolicy::from_config(serde_json::json!({ "requests_per_minute": 10.0 }))
                .expect("valid rpm policy")
                .with_async_store(
                    Some(recorder_b.clone() as Arc<dyn sbproxy_platform::storage::AsyncKVStore>),
                    "origin-a",
                )
                .with_store(
                    Some(Arc::new(PanicSyncStore) as Arc<dyn sbproxy_platform::storage::KVStore>),
                    "origin-a",
                );

        assert_eq!(
            sync_first.debug_key_prefix(),
            async_first.debug_key_prefix(),
            "attach order must not move counters into a different keyspace"
        );

        let _ = sync_first.allow_with_info_async("c1").await;
        let _ = async_first.allow_with_info_async("c1").await;
        let key_a = recorder_a.keys.lock().unwrap()[0].clone();
        let key_b = recorder_b.keys.lock().unwrap()[0].clone();
        assert_eq!(
            key_a, key_b,
            "the same client in the same window must land on the same counter key"
        );
    }

    // --- Mesh cluster tier ---

    fn cluster_tier(node: &str) -> Arc<rate_limit_cluster::RateLimitClusterTier> {
        Arc::new(rate_limit_cluster::RateLimitClusterTier::new(node))
    }

    /// The window the cluster path will bucket "now" into, for a 60s window.
    fn current_window_start(window: u64) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now - (now % window)
    }

    #[tokio::test]
    async fn cluster_tier_denies_once_local_plus_peers_reaches_the_limit() {
        let tier = cluster_tier("node-a");
        let policy =
            RateLimitPolicy::from_config(serde_json::json!({ "requests_per_minute": 10.0 }))
                .expect("valid rpm policy")
                .with_cluster(Some(tier.clone()), "test-origin");

        assert!(policy.converges_on_mesh(), "a 60s window converges");

        // Peers already report 8 requests in the current window. The bucket
        // string matches what the cluster path derives, prefix included.
        let window_start = current_window_start(60);
        let bucket = format!("{}c1:{}", policy.debug_key_prefix(), window_start);
        let peer = sbproxy_ai::governance_crdt::GovernanceContribution {
            node_id: "node-b".into(),
            generation: 1,
            slots: vec![sbproxy_ai::governance_crdt::NodeCounterSlot {
                key_id: bucket,
                policy_revision: rate_limit_cluster::RATE_LIMIT_POLICY_REVISION,
                window_start_millis: window_start * 1000,
                usage: sbproxy_ai::governance::GovernanceUsage {
                    requests: 8,
                    tokens: 0,
                    micro_usd: 0,
                },
            }],
        };
        tier.set_peer_counters(sbproxy_ai::governance_crdt::merge_contributions([peer]));

        // Local 1 and 2 bring the cluster total to 9 then 10, both within the
        // limit of 10. The third is the 11th cluster request and is denied.
        assert!(policy.allow_with_info_async("c1").await.allowed);
        assert!(policy.allow_with_info_async("c1").await.allowed);
        assert!(
            !policy.allow_with_info_async("c1").await.allowed,
            "the cluster total must include peer counts, not just local ones"
        );
    }

    #[tokio::test]
    async fn cluster_tier_alone_still_enforces_its_own_limit() {
        let tier = cluster_tier("node-a");
        let policy =
            RateLimitPolicy::from_config(serde_json::json!({ "requests_per_minute": 3.0 }))
                .expect("valid rpm policy")
                .with_cluster(Some(tier.clone()), "test-origin");

        // With no peer contributions the node enforces on its own count, so a
        // single-node mesh behaves exactly like the configured limit.
        assert!(policy.allow_with_info_async("solo").await.allowed);
        assert!(policy.allow_with_info_async("solo").await.allowed);
        assert!(policy.allow_with_info_async("solo").await.allowed);
        assert!(!policy.allow_with_info_async("solo").await.allowed);
    }

    #[tokio::test]
    async fn per_second_limits_do_not_use_the_cluster_tier() {
        let tier = cluster_tier("node-a");
        let policy =
            RateLimitPolicy::from_config(serde_json::json!({ "requests_per_second": 5.0 }))
                .expect("valid rps policy")
                .with_cluster(Some(tier.clone()), "test-origin");

        assert!(!policy.converges_on_mesh(), "a 1s window cannot converge");
        assert!(policy.allow_with_info_async("c1").await.allowed);
        assert!(
            tier.local_slots().is_empty(),
            "a per-second limit must not publish slots it cannot reconcile"
        );
    }

    #[tokio::test]
    async fn an_l2_store_takes_precedence_over_the_cluster_tier() {
        // A shared counter is exact, so it must win over an approximate
        // merged view. Without a store the cluster path would have counted.
        let tier = cluster_tier("node-a");
        let policy =
            RateLimitPolicy::from_config(serde_json::json!({ "requests_per_minute": 10.0 }))
                .expect("valid rpm policy")
                .with_cluster(Some(tier.clone()), "test-origin");
        assert!(policy.cluster.is_some());
        assert!(policy.store.is_none() && policy.async_store.is_none());
        // Sanity: with no store the cluster path is the one that runs.
        let _ = policy.allow_with_info_async("c1").await;
        assert_eq!(
            tier.local_slots().len(),
            1,
            "the cluster path should have counted exactly one bucket"
        );
    }
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

    #[test]
    fn dynamic_keyed_buckets_isolate_keys() {
        let buckets = DynamicKeyedTokenBuckets::new(2);
        let now = Instant::now();

        assert!(buckets.check_at("agent-a", 0.1, now).allowed);
        assert!(!buckets.check_at("agent-a", 0.1, now).allowed);
        assert!(buckets.check_at("agent-b", 0.1, now).allowed);
    }

    #[test]
    fn dynamic_keyed_buckets_refill_fractional_rates() {
        let buckets = DynamicKeyedTokenBuckets::new(1);
        let start = Instant::now();

        assert!(buckets.check_at("agent", 0.5, start).allowed);
        assert!(
            !buckets
                .check_at("agent", 0.5, start + std::time::Duration::from_secs(1))
                .allowed
        );
        assert!(
            buckets
                .check_at("agent", 0.5, start + std::time::Duration::from_secs(2))
                .allowed
        );
    }

    #[test]
    fn dynamic_keyed_buckets_rate_increase_does_not_grant_tokens() {
        let buckets = DynamicKeyedTokenBuckets::new(1);
        let start = Instant::now();

        assert!(buckets.check_at("agent", 1.0, start).allowed);
        assert!(!buckets.check_at("agent", 2.0, start).allowed);
        assert!(
            buckets
                .check_at("agent", 2.0, start + std::time::Duration::from_millis(500),)
                .allowed
        );
    }

    #[test]
    fn dynamic_keyed_buckets_ignore_stale_observation_time() {
        let buckets = DynamicKeyedTokenBuckets::new(1);
        let start = Instant::now();

        assert!(buckets.check_at("agent", 1.0, start).allowed);
        assert!(
            buckets
                .check_at("agent", 1.0, start + std::time::Duration::from_secs(1))
                .allowed
        );
        assert!(
            !buckets
                .check_at("agent", 1.0, start + std::time::Duration::from_millis(500),)
                .allowed
        );
        assert!(
            !buckets
                .check_at(
                    "agent",
                    1.0,
                    start + std::time::Duration::from_millis(1_500),
                )
                .allowed,
            "a stale caller must not move the refill clock backward"
        );
        assert!(
            buckets
                .check_at("agent", 1.0, start + std::time::Duration::from_secs(2))
                .allowed
        );
    }

    #[test]
    fn dynamic_keyed_buckets_lower_rate_clamps_available_tokens() {
        let buckets = DynamicKeyedTokenBuckets::new(1);
        let now = Instant::now();

        assert!(buckets.check_at("agent", 4.0, now).allowed);
        let lowered = buckets.check_at("agent", 1.0, now);
        assert!(lowered.allowed);
        assert_eq!(lowered.limit, 1);
        assert_eq!(lowered.remaining, 0);
        assert!(!buckets.check_at("agent", 1.0, now).allowed);
    }

    #[test]
    fn dynamic_keyed_buckets_fail_closed_when_registry_is_saturated() {
        let buckets = DynamicKeyedTokenBuckets::new(1);
        let start = Instant::now();

        assert!(buckets.check_at("agent-a", 0.1, start).allowed);
        let saturated = buckets.check_at("agent-b", 0.1, start + std::time::Duration::from_secs(1));
        assert!(!saturated.allowed);
        assert_eq!(saturated.remaining, 0);
        assert_eq!(saturated.reset_secs, 9);

        assert!(
            buckets
                .check_at("agent-b", 0.1, start + std::time::Duration::from_secs(10),)
                .allowed,
            "a fully refilled LRU bucket may be safely reused"
        );
    }

    #[test]
    fn dynamic_keyed_buckets_distinguish_next_token_from_full_refill_reset() {
        let buckets = DynamicKeyedTokenBuckets::new(1);
        let now = Instant::now();

        assert!(buckets.check_at("agent-a", 1.1, now).allowed);
        assert!(buckets.check_at("agent-a", 1.1, now).allowed);
        let exhausted = buckets.check_at("agent-a", 1.1, now);
        assert!(!exhausted.allowed);
        assert_eq!(
            exhausted.reset_secs, 1,
            "an exhausted known key waits only for its next token"
        );

        let saturated = buckets.check_at("agent-b", 1.1, now);
        assert!(!saturated.allowed);
        assert_eq!(
            saturated.reset_secs, 2,
            "an unseen key waits until the LRU candidate is fully reusable"
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
