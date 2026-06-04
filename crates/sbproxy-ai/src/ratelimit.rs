// SPDX-License-Identifier: BUSL-1.1
//! AI gateway rate limiting.
//!
//! The AI gateway enforces five independent caps per `(apikey, model)`
//! entity pair:
//!
//! - **RPM** - requests per minute
//! - **TPM** - tokens per minute (input + output)
//! - **RPD** - requests per day
//! - **TPD** - tokens per day (input + output)
//! - **concurrent** - in-flight requests
//!
//! Each axis is its own token bucket sized to the configured cap,
//! refilling at `cap / window_seconds`. A request is rejected the
//! moment any axis exhausts; the rejection carries a `Retry-After`
//! value derived from the slowest-recovering axis. Unset axes are
//! disabled and never gate traffic.
//!
//! Tokens for TPM / TPD are unknown at request entry because the
//! upstream model decides the output size. The limiter therefore uses
//! a two-pass protocol:
//!
//! 1. [`ModelRateLimiter::admit`] charges an estimated token cost
//!    against TPM / TPD, acquires a concurrency permit, and returns
//!    an [`Admission`] handle.
//! 2. After the response is parsed, the caller invokes
//!    [`Admission::reconcile`] with the actual token usage. Over-
//!    reservation refunds the difference; under-reservation creates a
//!    debt the bucket repays before admitting the next request.
//!
//! Dropping the [`Admission`] without reconciling refunds the full
//! reservation and releases the concurrency permit. This keeps the
//! limiter honest in error and panic paths.
//!
//! Keying is `(apikey, model)`. The apikey is normally the hashed
//! identifier the AI auth layer threads through, never the raw key.
//! An empty apikey falls back to a per-model bucket so unauthenticated
//! traffic shares one bucket per model. An empty model falls back to
//! a per-apikey aggregate so callers that omit the model field share
//! one bucket per key.

use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Default cap on the number of distinct `(apikey, model)` buckets
/// kept in memory. When the LRU is full, the least-recently-used
/// pair is evicted. Mirrors the WOR-66 rate-limit middleware default.
pub const DEFAULT_MAX_KEYS: usize = 100_000;

/// Default estimated token cost charged to TPM / TPD when the caller
/// does not pre-compute a tiktoken estimate. Chosen as a small
/// pre-flight reservation that an average chat-completion request
/// will easily exceed once the response settles.
pub const DEFAULT_ESTIMATED_TOKENS: u64 = 100;

/// One minute, in seconds. Window size for RPM and TPM.
const MINUTE: u64 = 60;
/// One day, in seconds. Window size for RPD and TPD.
const DAY: u64 = 86_400;

/// Per-model rate limit configuration.
///
/// Every axis is independent and `None` disables that axis. A
/// configuration with every field `None` admits every request and
/// is equivalent to no rate limit.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModelRateConfig {
    /// Maximum requests admitted per rolling one-minute window.
    pub requests_per_minute: Option<u64>,
    /// Maximum tokens (input + output) per rolling one-minute window.
    pub tokens_per_minute: Option<u64>,
    /// Maximum requests admitted per rolling one-day window.
    pub requests_per_day: Option<u64>,
    /// Maximum tokens (input + output) per rolling one-day window.
    pub tokens_per_day: Option<u64>,
    /// Maximum concurrent in-flight requests for this `(apikey, model)` pair.
    pub concurrent: Option<u32>,
}

/// Why a request was rejected.
///
/// Returned by [`ModelRateLimiter::admit`] when no axis admits. The
/// `Retry-After` value is the integer seconds the caller should wait
/// before retrying; it never exceeds the configured window of the
/// rejecting axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// RPM bucket exhausted.
    RequestsPerMinute,
    /// TPM bucket exhausted.
    TokensPerMinute,
    /// RPD bucket exhausted.
    RequestsPerDay,
    /// TPD bucket exhausted.
    TokensPerDay,
    /// Concurrent in-flight cap reached.
    Concurrent,
}

impl RejectReason {
    /// Stable label used as the `axis` Prometheus label for
    /// `sbproxy_ai_ratelimit_rejected_total`.
    pub fn axis_label(&self) -> &'static str {
        match self {
            RejectReason::RequestsPerMinute => "rpm",
            RejectReason::TokensPerMinute => "tpm",
            RejectReason::RequestsPerDay => "rpd",
            RejectReason::TokensPerDay => "tpd",
            RejectReason::Concurrent => "concurrent",
        }
    }
}

/// A rate-limit rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// Which axis triggered the rejection.
    pub reason: RejectReason,
    /// Seconds until the rejecting bucket admits at least one more
    /// token, suitable for use in a `Retry-After` header. Always at
    /// least 1 when the request was rejected.
    pub retry_after_secs: u64,
}

/// In-flight handle returned by [`ModelRateLimiter::admit`].
///
/// Holds the concurrency permit and the estimated reservation
/// charged against TPM / TPD. The caller must invoke
/// [`Admission::reconcile`] after the response is parsed to settle
/// the reservation against the real token usage. Dropping the handle
/// without reconciling refunds the full reservation; this is the
/// correct behaviour for upstream errors that never produced usage.
pub struct Admission {
    bucket: Arc<EntityBuckets>,
    permit: Option<OwnedSemaphorePermit>,
    reserved_tokens: u64,
    /// Model the reservation was charged to. Stamped here so the
    /// post-flight estimate-error histogram can label its
    /// observation without the caller having to thread the model
    /// string back through to `reconcile`.
    model: String,
    reconciled: bool,
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admission")
            .field("reserved_tokens", &self.reserved_tokens)
            .field("model", &self.model)
            .field("reconciled", &self.reconciled)
            .field("permit_held", &self.permit.is_some())
            .finish()
    }
}

impl Admission {
    /// Replace the pre-flight reservation with the actual token
    /// usage reported by the upstream provider. The bucket refunds
    /// over-reservation; under-reservation is charged as an
    /// additional debit. The relative estimate error is sampled into
    /// `sbproxy_ai_token_estimate_error_ratio` so operators can spot
    /// drift between the pre-flight estimator and the upstream's own
    /// token count.
    pub fn reconcile(mut self, actual_tokens: u64) {
        self.bucket
            .reconcile_tokens(self.reserved_tokens, actual_tokens);
        crate::ai_metrics::record_token_estimate_error(
            &self.model,
            self.reserved_tokens,
            actual_tokens,
        );
        self.reconciled = true;
        // Dropping releases the permit.
    }

    /// Token count this admission reserved at request entry. Exposed so
    /// the request filter can compute its own estimate-vs-actual delta
    /// for logs and audit events without having to re-parse the prompt.
    pub fn reserved_tokens(&self) -> u64 {
        self.reserved_tokens
    }

    /// Manually release the concurrency permit and refund the full
    /// reservation. Equivalent to dropping the handle.
    pub fn abort(self) {
        drop(self);
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        if !self.reconciled {
            // Caller never reported usage: refund the reservation in
            // full so an error path does not silently consume budget.
            self.bucket.reconcile_tokens(self.reserved_tokens, 0);
        }
        // Permit drops automatically and releases the concurrent slot.
        drop(self.permit.take());
    }
}

/// Per-`(apikey, model)` bucket state. Shared by `Arc` so the
/// `Admission` handle can refund without holding the outer map lock.
struct EntityBuckets {
    rpm: Mutex<TokenBucket>,
    tpm: Mutex<TokenBucket>,
    rpd: Mutex<TokenBucket>,
    tpd: Mutex<TokenBucket>,
    concurrent: Arc<Semaphore>,
}

impl EntityBuckets {
    fn new(cfg: &ModelRateConfig) -> Self {
        // Each axis is built lazily: a zero-cap bucket is disabled and
        // never gates traffic. The token bucket struct keeps its math
        // simple by always running, but `try_acquire` on a disabled
        // bucket short-circuits to "allow" via the `enabled` flag.
        Self {
            rpm: Mutex::new(TokenBucket::for_axis(cfg.requests_per_minute, MINUTE)),
            tpm: Mutex::new(TokenBucket::for_axis(cfg.tokens_per_minute, MINUTE)),
            rpd: Mutex::new(TokenBucket::for_axis(cfg.requests_per_day, DAY)),
            tpd: Mutex::new(TokenBucket::for_axis(cfg.tokens_per_day, DAY)),
            concurrent: Arc::new(Semaphore::new(
                cfg.concurrent
                    .map(|n| n as usize)
                    .unwrap_or(Semaphore::MAX_PERMITS),
            )),
        }
    }

    /// Reconcile a pre-flight reservation against actual usage.
    fn reconcile_tokens(&self, reserved: u64, actual: u64) {
        if reserved == actual {
            return;
        }
        // Both TPM and TPD see the same delta because every token
        // counted against minute-scoped budgets also counts against
        // the daily budget.
        if actual < reserved {
            let refund = (reserved - actual) as f64;
            self.tpm.lock().refund(refund);
            self.tpd.lock().refund(refund);
        } else {
            let extra = (actual - reserved) as f64;
            self.tpm.lock().charge(extra);
            self.tpd.lock().charge(extra);
        }
    }
}

/// Token bucket sized to a configured cap, refilling at `cap / window`.
///
/// `enabled = false` means the axis is unconfigured and every call
/// to `try_acquire` allows the request. This avoids a per-axis
/// `Option<TokenBucket>` everywhere; instead the bucket carries its
/// own enable flag.
#[derive(Debug)]
struct TokenBucket {
    enabled: bool,
    capacity: f64,
    /// Tokens available to spend. May go negative when a debit
    /// exceeds the current balance (the bucket "owes" tokens before
    /// the next admission).
    tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn for_axis(cap: Option<u64>, window_secs: u64) -> Self {
        match cap {
            Some(n) if n > 0 => {
                let cap_f = n as f64;
                TokenBucket {
                    enabled: true,
                    capacity: cap_f,
                    tokens: cap_f,
                    refill_rate: cap_f / window_secs as f64,
                    last_refill: Instant::now(),
                }
            }
            _ => TokenBucket {
                enabled: false,
                capacity: 0.0,
                tokens: 0.0,
                refill_rate: 0.0,
                last_refill: Instant::now(),
            },
        }
    }

    fn refill_now(&mut self, now: Instant) {
        if !self.enabled {
            return;
        }
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
            self.last_refill = now;
        }
    }

    /// Try to take `n` tokens. Returns `Ok(())` when admitted (and
    /// the tokens are debited), `Err(retry_after_secs)` when there
    /// are not enough tokens; the latter never debits.
    fn try_acquire(&mut self, n: f64, now: Instant) -> Result<(), u64> {
        if !self.enabled {
            return Ok(());
        }
        self.refill_now(now);
        if self.tokens >= n {
            self.tokens -= n;
            Ok(())
        } else {
            let deficit = n - self.tokens;
            let retry = if self.refill_rate > 0.0 {
                (deficit / self.refill_rate).ceil() as u64
            } else {
                0
            };
            Err(retry.max(1))
        }
    }

    /// Refund tokens previously debited by `try_acquire`. Clamps at
    /// the bucket capacity so refunds never inflate beyond the cap.
    fn refund(&mut self, n: f64) {
        if !self.enabled || n <= 0.0 {
            return;
        }
        self.tokens = (self.tokens + n).min(self.capacity);
    }

    /// Charge additional tokens after admission. May drive the
    /// balance negative, which forces the next call to wait out the
    /// refill before being admitted.
    fn charge(&mut self, n: f64) {
        if !self.enabled || n <= 0.0 {
            return;
        }
        self.tokens -= n;
    }
}

/// Per-`(apikey, model)` rate limiter for the AI gateway.
///
/// Holds an LRU cap of [`DEFAULT_MAX_KEYS`] entity buckets by
/// default. The limiter is cheap to clone (it is a single field
/// behind an `Arc`-like mutex); a single instance is meant to live
/// on the per-origin AI handler.
pub struct ModelRateLimiter {
    inner: Mutex<lru::LruCache<EntityKey, Arc<EntityBuckets>>>,
    /// How many tokens to reserve up-front for TPM / TPD when the
    /// caller does not provide an estimate. Defaults to
    /// [`DEFAULT_ESTIMATED_TOKENS`].
    default_estimated_tokens: u64,
}

/// Map key for the entity LRU. Stored as an owned tuple to keep the
/// `Hash` + `Eq` derivation cheap and to avoid `format!`-allocating
/// a colon-joined string on every check.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct EntityKey {
    apikey: String,
    model: String,
}

impl ModelRateLimiter {
    /// Create a new limiter with the default cap of
    /// [`DEFAULT_MAX_KEYS`] entity buckets.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_KEYS)
    }

    /// Create a limiter with an explicit LRU cap. The cap is clamped
    /// to at least 1.
    pub fn with_capacity(max_keys: usize) -> Self {
        let cap = NonZeroUsize::new(max_keys.max(1)).expect("clamped above");
        Self {
            inner: Mutex::new(lru::LruCache::new(cap)),
            default_estimated_tokens: DEFAULT_ESTIMATED_TOKENS,
        }
    }

    /// Override the default estimated-token reservation used when
    /// [`ModelRateLimiter::admit`] is called without an explicit
    /// estimate. Useful for tests and for tuning the pre-flight
    /// reservation when a tiktoken pre-estimate is unavailable.
    pub fn set_default_estimated_tokens(&mut self, est: u64) {
        self.default_estimated_tokens = est;
    }

    /// Look up the bucket-bundle for an `(apikey, model)` pair,
    /// constructing it from `cfg` on first use.
    fn entity(&self, apikey: &str, model: &str, cfg: &ModelRateConfig) -> Arc<EntityBuckets> {
        let key = EntityKey {
            apikey: apikey.to_string(),
            model: model.to_string(),
        };
        let mut map = self.inner.lock();
        if let Some(existing) = map.get(&key) {
            return Arc::clone(existing);
        }
        let fresh = Arc::new(EntityBuckets::new(cfg));
        map.put(key, Arc::clone(&fresh));
        fresh
    }

    /// Admit a request against every configured axis.
    ///
    /// `apikey` is the per-request identifier (hashed token, never
    /// the raw key). `model` is the upstream model name. `cfg`
    /// supplies the caps. `estimated_tokens` is the pre-flight
    /// token reservation charged against TPM / TPD; pass `None`
    /// to use the limiter's configured default reservation
    /// (initially [`DEFAULT_ESTIMATED_TOKENS`]).
    ///
    /// Returns an [`Admission`] handle on success. The caller must
    /// invoke [`Admission::reconcile`] after the response is parsed
    /// to settle the reservation against the real token usage. On
    /// rejection, returns the rejecting axis and a `Retry-After`
    /// value in seconds.
    pub fn admit(
        &self,
        apikey: &str,
        model: &str,
        cfg: &ModelRateConfig,
        estimated_tokens: Option<u64>,
    ) -> Result<Admission, Rejection> {
        // Tenant-blind entry point retained for existing callers and
        // tests; rejections roll up to the empty-tenant bucket.
        self.admit_with_tenant(apikey, model, "", cfg, estimated_tokens)
    }

    /// WOR-1096: tenant-attributed admission. Identical to
    /// [`Self::admit`] but stamps `tenant` onto the
    /// `sbproxy_ai_ratelimit_rejected_total` counter so a tenant that
    /// hits its TPM/RPM cap is distinguishable from global pressure.
    pub fn admit_with_tenant(
        &self,
        apikey: &str,
        model: &str,
        tenant: &str,
        cfg: &ModelRateConfig,
        estimated_tokens: Option<u64>,
    ) -> Result<Admission, Rejection> {
        let est = estimated_tokens.unwrap_or(self.default_estimated_tokens);
        let bucket = self.entity(apikey, model, cfg);
        let now = Instant::now();

        // Acquire the concurrency permit first; it is the cheapest
        // axis to roll back and it is the only async-friendly axis.
        // `try_acquire_owned` never blocks: it succeeds when a slot is
        // free or returns immediately with TryAcquireError::NoPermits.
        let permit = match Arc::clone(&bucket.concurrent).try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                return Err(self.reject(apikey, model, tenant, RejectReason::Concurrent, 1));
            }
        };

        // RPM
        if let Err(retry) = bucket.rpm.lock().try_acquire(1.0, now) {
            return Err(self.reject(
                apikey,
                model,
                tenant,
                RejectReason::RequestsPerMinute,
                retry,
            ));
        }
        // RPD
        if let Err(retry) = bucket.rpd.lock().try_acquire(1.0, now) {
            // Refund RPM so a daily reject does not eat a minute
            // slot we will never use.
            bucket.rpm.lock().refund(1.0);
            return Err(self.reject(apikey, model, tenant, RejectReason::RequestsPerDay, retry));
        }
        // TPM
        if let Err(retry) = bucket.tpm.lock().try_acquire(est as f64, now) {
            bucket.rpm.lock().refund(1.0);
            bucket.rpd.lock().refund(1.0);
            return Err(self.reject(apikey, model, tenant, RejectReason::TokensPerMinute, retry));
        }
        // TPD
        if let Err(retry) = bucket.tpd.lock().try_acquire(est as f64, now) {
            bucket.rpm.lock().refund(1.0);
            bucket.rpd.lock().refund(1.0);
            bucket.tpm.lock().refund(est as f64);
            return Err(self.reject(apikey, model, tenant, RejectReason::TokensPerDay, retry));
        }

        Ok(Admission {
            bucket,
            permit,
            reserved_tokens: est,
            model: model.to_string(),
            reconciled: false,
        })
    }

    /// Centralised rejection helper. Increments the per-axis
    /// `sbproxy_ai_ratelimit_rejected_total` counter and returns the
    /// rejection payload. Pulled out so every rejection path stays in
    /// lockstep with the metric.
    fn reject(
        &self,
        apikey: &str,
        model: &str,
        tenant: &str,
        reason: RejectReason,
        retry: u64,
    ) -> Rejection {
        crate::ai_metrics::record_ratelimit_rejected(reason.axis_label(), apikey, tenant, model);
        Rejection {
            reason,
            retry_after_secs: retry,
        }
    }

    /// Legacy entry point preserved for callers that have not yet
    /// migrated to [`ModelRateLimiter::admit`]. Returns `true` when
    /// the request is admitted under the RPM axis only. Does not
    /// enforce TPM, RPD, TPD, or concurrency.
    ///
    /// Prefer [`ModelRateLimiter::admit`] in new code: the legacy
    /// signature has no way to release a concurrency permit and no
    /// way to reconcile a token reservation.
    #[deprecated(
        since = "0.2.0",
        note = "use `ModelRateLimiter::admit` to enforce TPM/TPD/RPD/concurrent caps"
    )]
    pub fn check_rate(&self, provider: &str, model: &str, config: &ModelRateConfig) -> bool {
        // The legacy entry point keyed on `provider:model`; preserve
        // that shape under the new API by treating the provider as
        // the apikey for backward compatibility with old callers.
        match self.admit(provider, model, config, Some(0)) {
            Ok(admission) => {
                // Reconcile to 0 so the bucket releases the permit
                // without holding state once this function returns.
                admission.reconcile(0);
                true
            }
            Err(_) => false,
        }
    }

    /// Legacy entry point preserved for callers that recorded
    /// post-flight tokens against the bucket without using
    /// [`Admission::reconcile`]. Subtracts `tokens` from the TPM
    /// and TPD axes of the `(provider, model)` pair if it exists.
    #[deprecated(
        since = "0.2.0",
        note = "use `Admission::reconcile` for two-phase pre-flight + reconcile"
    )]
    pub fn record_tokens(&self, provider: &str, model: &str, tokens: u64) {
        let key = EntityKey {
            apikey: provider.to_string(),
            model: model.to_string(),
        };
        let map = self.inner.lock();
        if let Some(bucket) = map.peek(&key) {
            bucket.tpm.lock().charge(tokens as f64);
            bucket.tpd.lock().charge(tokens as f64);
        }
    }
}

impl Default for ModelRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// --- Per-surface rate limiting (Phase 8) ---

/// Per-surface rate-limit configuration.
///
/// Applied at request-filter time before any upstream call. Operators
/// configure these under the AI handler's `per_surface` map keyed by
/// the `AiSurface::label()` string (e.g. `"image_generation"`,
/// `"audio_speech"`). A given surface may be limited independently
/// from other surfaces so operators can cap expensive paths
/// (image generation, realtime audio) more strictly than chat.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SurfaceRateConfig {
    /// Maximum requests for this surface per rolling one-minute window.
    /// When unset, the surface is not RPM-limited.
    pub requests_per_minute: Option<u64>,
}

/// Tracks per-surface request rates using a sliding one-minute window.
///
/// State is keyed by the surface label string so the same limiter can
/// serve every configured origin. Concurrency safety is via the same
/// `Mutex<HashMap>` pattern as [`ModelRateLimiter`].
pub struct SurfaceRateLimiter {
    state: std::sync::Mutex<HashMap<String, SurfaceRateState>>,
}

#[derive(Debug)]
struct SurfaceRateState {
    requests: u64,
    window_start: Instant,
}

impl SurfaceRateLimiter {
    /// Create a new empty limiter with no in-flight state.
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request against `surface` is permitted under the
    /// supplied config. Returns true (and increments the counter)
    /// when allowed; returns false when the per-minute cap has been
    /// hit. Windows reset 60 seconds after the first request in
    /// each window.
    ///
    /// When `config.requests_per_minute` is `None`, the request is
    /// always allowed and no counter is incremented.
    pub fn check_rate(&self, surface: &str, config: &SurfaceRateConfig) -> bool {
        let rpm = match config.requests_per_minute {
            Some(n) => n,
            None => return true,
        };

        let mut state = match self.state.lock() {
            Ok(g) => g,
            // Mutex poisoned: a previous thread panicked while
            // holding it. Surface rate-limit state is best-effort,
            // so prefer fail-open over propagating the panic.
            Err(p) => p.into_inner(),
        };
        let entry = state
            .entry(surface.to_string())
            .or_insert(SurfaceRateState {
                requests: 0,
                window_start: Instant::now(),
            });

        if entry.window_start.elapsed().as_secs() >= MINUTE {
            entry.requests = 0;
            entry.window_start = Instant::now();
        }

        if entry.requests >= rpm {
            return false;
        }
        entry.requests += 1;
        true
    }
}

impl Default for SurfaceRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg(
        rpm: Option<u64>,
        tpm: Option<u64>,
        rpd: Option<u64>,
        tpd: Option<u64>,
        concurrent: Option<u32>,
    ) -> ModelRateConfig {
        ModelRateConfig {
            requests_per_minute: rpm,
            tokens_per_minute: tpm,
            requests_per_day: rpd,
            tokens_per_day: tpd,
            concurrent,
        }
    }

    #[test]
    fn rpm_independently_triggers_rejection() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(Some(2), None, None, None, None);
        let _a = limiter.admit("k", "gpt-4", &c, Some(0)).unwrap();
        let _b = limiter.admit("k", "gpt-4", &c, Some(0)).unwrap();
        let err = limiter.admit("k", "gpt-4", &c, Some(0)).unwrap_err();
        assert_eq!(err.reason, RejectReason::RequestsPerMinute);
        assert!(err.retry_after_secs >= 1);
    }

    #[test]
    fn tpm_independently_triggers_rejection() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(None, Some(1_000), None, None, None);
        // Burn the TPM bucket with one large reservation.
        let _a = limiter.admit("k", "gpt-4", &c, Some(1_000)).unwrap();
        let err = limiter.admit("k", "gpt-4", &c, Some(1)).unwrap_err();
        assert_eq!(err.reason, RejectReason::TokensPerMinute);
        assert!(err.retry_after_secs >= 1);
    }

    #[test]
    fn rpd_independently_triggers_rejection() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(None, None, Some(1), None, None);
        let _a = limiter.admit("k", "gpt-4", &c, Some(0)).unwrap();
        let err = limiter.admit("k", "gpt-4", &c, Some(0)).unwrap_err();
        assert_eq!(err.reason, RejectReason::RequestsPerDay);
        assert!(err.retry_after_secs >= 1);
    }

    #[test]
    fn tpd_independently_triggers_rejection() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(None, None, None, Some(1_000), None);
        let _a = limiter.admit("k", "gpt-4", &c, Some(1_000)).unwrap();
        let err = limiter.admit("k", "gpt-4", &c, Some(1)).unwrap_err();
        assert_eq!(err.reason, RejectReason::TokensPerDay);
        assert!(err.retry_after_secs >= 1);
    }

    #[test]
    fn concurrent_independently_triggers_rejection() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(None, None, None, None, Some(2));
        let _a = limiter.admit("k", "gpt-4", &c, Some(0)).unwrap();
        let _b = limiter.admit("k", "gpt-4", &c, Some(0)).unwrap();
        let err = limiter.admit("k", "gpt-4", &c, Some(0)).unwrap_err();
        assert_eq!(err.reason, RejectReason::Concurrent);
    }

    #[test]
    fn concurrent_cap_five_admits_five_rejects_sixth() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(None, None, None, None, Some(5));
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(limiter.admit("k", "gpt-4", &c, Some(0)).unwrap());
        }
        let err = limiter.admit("k", "gpt-4", &c, Some(0)).unwrap_err();
        assert_eq!(err.reason, RejectReason::Concurrent);
        // Drop one slot and a sixth call must now succeed.
        held.pop();
        let _next = limiter.admit("k", "gpt-4", &c, Some(0)).unwrap();
    }

    #[test]
    fn multi_axis_either_can_trigger() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(Some(100), Some(50), None, None, None);
        // RPM is generous; TPM trips first because the reservation
        // dwarfs the per-minute cap.
        let err = limiter.admit("k", "gpt-4", &c, Some(200)).unwrap_err();
        assert_eq!(err.reason, RejectReason::TokensPerMinute);

        // With a small estimate the same limiter trips on RPM first.
        let limiter2 = ModelRateLimiter::new();
        let c2 = cfg(Some(1), Some(10_000), None, None, None);
        let _a = limiter2.admit("k", "gpt-4", &c2, Some(1)).unwrap();
        let err2 = limiter2.admit("k", "gpt-4", &c2, Some(1)).unwrap_err();
        assert_eq!(err2.reason, RejectReason::RequestsPerMinute);
    }

    #[test]
    fn per_key_isolation() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(Some(1), None, None, None, None);
        // sk-a uses its single slot.
        let _a = limiter.admit("sk-a", "gpt-4", &c, Some(0)).unwrap();
        assert!(limiter.admit("sk-a", "gpt-4", &c, Some(0)).is_err());
        // sk-b still has its own slot.
        let _b = limiter.admit("sk-b", "gpt-4", &c, Some(0)).unwrap();
        assert!(limiter.admit("sk-b", "gpt-4", &c, Some(0)).is_err());
    }

    #[test]
    fn per_model_isolation() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(Some(1), None, None, None, None);
        let _a = limiter.admit("sk-a", "gpt-4", &c, Some(0)).unwrap();
        assert!(limiter.admit("sk-a", "gpt-4", &c, Some(0)).is_err());
        // Same key, different model: separate bucket.
        let _b = limiter.admit("sk-a", "claude-3", &c, Some(0)).unwrap();
    }

    #[test]
    fn reconcile_under_reservation_refunds_difference() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(None, Some(100), None, None, None);
        // Reserve 100, refund 70 (used only 30).
        let admission = limiter.admit("k", "gpt-4", &c, Some(100)).unwrap();
        admission.reconcile(30);

        // 70 tokens should now be available again. A new request that
        // reserves 70 must succeed; one that asks for 71 must fail.
        let _ok = limiter.admit("k", "gpt-4", &c, Some(70)).unwrap();
        // After that 70-token reservation the TPM bucket is empty,
        // so the next call (any positive reservation) trips.
        let err = limiter.admit("k", "gpt-4", &c, Some(1)).unwrap_err();
        assert_eq!(err.reason, RejectReason::TokensPerMinute);
    }

    #[test]
    fn reconcile_over_reservation_charges_extra() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(None, Some(100), None, None, None);
        // Reserve 50; actual usage was 80. The extra 30 is charged.
        let admission = limiter.admit("k", "gpt-4", &c, Some(50)).unwrap();
        admission.reconcile(80);

        // Only 20 tokens should remain; 21 must fail, 20 must pass.
        let _ok = limiter.admit("k", "gpt-4", &c, Some(20)).unwrap();
        let err = limiter.admit("k", "gpt-4", &c, Some(1)).unwrap_err();
        assert_eq!(err.reason, RejectReason::TokensPerMinute);
    }

    #[test]
    fn drop_without_reconcile_refunds_full() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(None, Some(100), None, None, None);
        {
            let _admission = limiter.admit("k", "gpt-4", &c, Some(100)).unwrap();
            // Drop without reconcile (error path simulation).
        }
        // Full refund: 100 tokens are back in the bucket.
        let _ok = limiter.admit("k", "gpt-4", &c, Some(100)).unwrap();
    }

    #[test]
    fn no_limit_admits_everything() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(None, None, None, None, None);
        let mut held = Vec::new();
        for _ in 0..1_000 {
            held.push(limiter.admit("k", "gpt-4", &c, Some(0)).unwrap());
        }
    }

    #[test]
    fn rejection_records_axis_metric() {
        use crate::ai_metrics::ratelimit_rejected_value;
        let limiter = ModelRateLimiter::new();
        let c = cfg(Some(1), None, None, None, None);
        // Use a unique apikey + model so we don't collide with any
        // other test that touches the same global counter.
        let key = "metric-test-key-rpm";
        let model = "metric-test-model";
        let before = ratelimit_rejected_value("rpm", key, "", model);
        let _a = limiter.admit(key, model, &c, Some(0)).unwrap();
        let _err = limiter.admit(key, model, &c, Some(0)).unwrap_err();
        let after = ratelimit_rejected_value("rpm", key, "", model);
        assert!(
            after >= before + 1.0,
            "expected rpm counter to tick (before={before}, after={after})"
        );
    }

    #[test]
    fn rejection_axis_labels_are_stable() {
        assert_eq!((RejectReason::RequestsPerMinute).axis_label(), "rpm");
        assert_eq!((RejectReason::TokensPerMinute).axis_label(), "tpm");
        assert_eq!((RejectReason::RequestsPerDay).axis_label(), "rpd");
        assert_eq!((RejectReason::TokensPerDay).axis_label(), "tpd");
        assert_eq!((RejectReason::Concurrent).axis_label(), "concurrent");
    }

    #[test]
    fn lru_cap_bounds_memory() {
        let limiter = ModelRateLimiter::with_capacity(2);
        let c = cfg(Some(1), None, None, None, None);
        // Three distinct keys force eviction of the oldest.
        let _ = limiter.admit("a", "m", &c, Some(0)).unwrap();
        let _ = limiter.admit("b", "m", &c, Some(0)).unwrap();
        let _ = limiter.admit("c", "m", &c, Some(0)).unwrap();
        // "a" was evicted: a fresh bucket is built, so it admits again.
        let _ = limiter.admit("a", "m", &c, Some(0)).unwrap();
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_check_rate_still_enforces_rpm() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(Some(3), None, None, None, None);
        assert!(limiter.check_rate("openai", "gpt-4", &c));
        assert!(limiter.check_rate("openai", "gpt-4", &c));
        assert!(limiter.check_rate("openai", "gpt-4", &c));
        assert!(!limiter.check_rate("openai", "gpt-4", &c));
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_record_tokens_charges_tpm_and_tpd() {
        let limiter = ModelRateLimiter::new();
        let c = cfg(None, Some(1_000), None, Some(1_000), None);
        // Prime the bucket via the legacy path.
        assert!(limiter.check_rate("openai", "gpt-4", &c));
        limiter.record_tokens("openai", "gpt-4", 1_000);
        // TPM should now be exhausted.
        let err = limiter.admit("openai", "gpt-4", &c, Some(1)).unwrap_err();
        assert_eq!(err.reason, RejectReason::TokensPerMinute);
        // Recording for a never-seen entity is a no-op.
        limiter.record_tokens("anthropic", "claude-3", 500);
    }

    // --- Surface rate limiter tests ---

    #[test]
    fn surface_rate_limit_allows_when_unconfigured() {
        let limiter = SurfaceRateLimiter::new();
        let config = SurfaceRateConfig::default();
        for _ in 0..100 {
            assert!(limiter.check_rate("image_generation", &config));
        }
    }

    #[test]
    fn surface_rate_limit_blocks_after_cap() {
        let limiter = SurfaceRateLimiter::new();
        let config = SurfaceRateConfig {
            requests_per_minute: Some(2),
        };
        assert!(limiter.check_rate("image_generation", &config));
        assert!(limiter.check_rate("image_generation", &config));
        assert!(!limiter.check_rate("image_generation", &config));
    }

    #[test]
    fn surface_rate_limits_are_per_surface() {
        let limiter = SurfaceRateLimiter::new();
        let config = SurfaceRateConfig {
            requests_per_minute: Some(1),
        };
        assert!(limiter.check_rate("image_generation", &config));
        assert!(limiter.check_rate("audio_speech", &config));
        assert!(!limiter.check_rate("image_generation", &config));
    }

    #[test]
    fn surface_rate_limit_resets_after_window() {
        let limiter = SurfaceRateLimiter::new();
        let config = SurfaceRateConfig {
            requests_per_minute: Some(1),
        };
        assert!(limiter.check_rate("image_generation", &config));
        assert!(!limiter.check_rate("image_generation", &config));

        {
            let mut state = limiter.state.lock().unwrap();
            let entry = state.get_mut("image_generation").unwrap();
            entry.window_start = Instant::now() - Duration::from_secs(MINUTE + 1);
        }

        assert!(limiter.check_rate("image_generation", &config));
    }
}
