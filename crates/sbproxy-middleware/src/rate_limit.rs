//! Per-origin rate-limit middleware (WOR-66).
//!
//! Consumes the `rate_limits:` block on a `CompiledOrigin`
//! ([`sbproxy_config::OriginRateLimitsConfig`]) and gates traffic ahead
//! of any per-origin policy chain. The middleware is intentionally
//! decoupled from the per-policy `rate_limiting` policy (which keys on
//! per-policy `requests_per_second` / `burst` knobs): this middleware
//! enforces the workspace / tenant-level budget that the config
//! compiler attaches to every compiled origin, while the policy enforces
//! a separate per-route ceiling specified inside a policy chain.
//!
//! # Algorithm
//!
//! Token bucket per `(client-key, route)`. The bucket capacity is
//! `tenant_burst`, and the refill rate is `tenant_sustained` tokens per
//! second. The per-route ceiling (`route_default`, optionally overridden
//! by `route_overrides`) puts a second bucket on top so a single noisy
//! route cannot drain the tenant budget on its own.
//!
//! When either bucket is empty the middleware returns a synthetic
//! `429 Too Many Requests` response with `Retry-After` set to the
//! number of seconds until enough tokens refill to admit one request.
//! Otherwise it returns `Outcome::Allow` and the request proceeds into
//! the policy chain.
//!
//! # Keying
//!
//! The middleware takes the `client_key` as a `&str` argument: callers
//! choose whether that is the remote IP, an API-key header value, a
//! workspace identifier, or any composite. An empty key falls through
//! to a single shared bucket (useful when no client-identity signal is
//! available yet). This matches the way other middlewares
//! ([`crate::idempotency`]) keep client-identity resolution out of the
//! middleware and inside the caller.
//!
//! # Bounded memory
//!
//! Per-key buckets live in an LRU map capped at
//! [`DEFAULT_MAX_KEYS`](crate::rate_limit::DEFAULT_MAX_KEYS) entries. The cap defends against unbounded
//! key cardinality (`key:` set to a per-request value such as a UUID)
//! exhausting memory. The LRU policy is intentionally simple: when the
//! cap is hit, the least-recently-used bucket is evicted; the next
//! request from that key starts over with a full bucket. The policy
//! crate's `RateLimitPolicy` keeps a "cold-limited" tier on top of the
//! LRU to preserve deny-state across eviction storms; this middleware
//! does not, because the tenant-level budget refills on the second-rate
//! scale and a brief eviction-induced refill window is preferable to
//! growing the deny-state cache without bound.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use http::{HeaderMap, HeaderValue, StatusCode};
use parking_lot::Mutex;
use sbproxy_config::OriginRateLimitsConfig;

/// Default cap on the per-key bucket cache. Keeps the bucket map under
/// ~10 MB even with long key strings. Operators do not set this today;
/// when they do, it will land on the config struct.
pub const DEFAULT_MAX_KEYS: usize = 100_000;

/// Outcome of running the rate-limit middleware against a single
/// request. Mirrors the shape of [`crate::idempotency::IdempotencyOutcome`]
/// so the call site can treat the two middlewares the same way.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The middleware is disabled for this origin (no `rate_limits:`
    /// block authored). The request passes through.
    Disabled,
    /// The request fits within the configured budget. Proceed into the
    /// policy chain.
    Allow,
    /// The configured budget has been exhausted. The caller should
    /// short-circuit with `429 Too Many Requests` and the included
    /// `Retry-After` value.
    Deny {
        /// HTTP status code to return. Always `429`. Returned as part of
        /// the variant so a future tightening to `503` for the soft-tier
        /// case does not break the call site.
        status: StatusCode,
        /// Number of seconds to put in the `Retry-After` response
        /// header. Always at least 1 so the header is never `0`.
        retry_after_secs: u64,
    },
}

impl Outcome {
    /// Convenience accessor: true when the outcome represents a 429.
    pub fn is_deny(&self) -> bool {
        matches!(self, Outcome::Deny { .. })
    }

    /// Convenience accessor: true when the request should proceed.
    pub fn is_allow(&self) -> bool {
        matches!(self, Outcome::Allow | Outcome::Disabled)
    }

    /// If this outcome carries a `Retry-After` value, stamp the header
    /// onto `headers` in place. No-op for [`Outcome::Allow`] and
    /// [`Outcome::Disabled`].
    pub fn apply_retry_after(&self, headers: &mut HeaderMap) {
        if let Outcome::Deny {
            retry_after_secs, ..
        } = self
        {
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                headers.insert("retry-after", v);
            }
        }
    }
}

/// Per-origin rate-limit middleware.
///
/// Constructed once per compiled origin via [`RateLimitMiddleware::new`]
/// and shared between requests. Internally synchronised: callers do not
/// need their own lock.
///
/// When `config` is `None` the middleware degrades to a no-op
/// ([`Outcome::Disabled`] on every call). This is the path taken for
/// origins whose operator did not author a `rate_limits:` block.
#[derive(Debug)]
pub struct RateLimitMiddleware {
    inner: Option<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Tenant-wide bucket. One bucket shared across all per-key buckets;
    /// each request consumes from the per-key bucket first and from this
    /// tenant bucket only on success, so the tenant bucket caps total
    /// volume across keys.
    tenant_buckets: Mutex<lru::LruCache<String, TokenBucket>>,
    /// Per-route buckets keyed on `(client_key, route)`. The route is
    /// resolved against `route_default` and `route_overrides` at lookup
    /// time so the bucket capacity matches the matching rule.
    route_buckets: Mutex<lru::LruCache<RouteKey, TokenBucket>>,
    /// Owned config so the middleware does not depend on the snapshot's
    /// lifetime. The compiler hands us an `Arc<CompiledOrigin>`, but
    /// taking a clone here keeps the middleware testable in isolation.
    config: OriginRateLimitsConfig,
    /// LRU capacity. Pulled into the inner struct so `new` is the only
    /// place that has to reason about the `NonZeroUsize` invariant.
    max_keys: NonZeroUsize,
}

/// Composite key for the per-route LRU.
///
/// Stored as owned strings so the LRU does not hold borrows back into
/// request state. The pair is hashed together so two routes from the
/// same client never collide.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RouteKey {
    /// Client identity (IP, API key, workspace, etc.). Empty when the
    /// caller did not have a client signal.
    client: String,
    /// Resolved route pattern. Either a literal path from
    /// `route_overrides` or `"__default__"` when the default ceiling
    /// applies.
    route_pattern: String,
}

/// Local token bucket. Independent of the policy-side bucket in
/// `sbproxy-modules` so the middleware crate does not have to depend on
/// the modules crate (which would invert the dependency direction in
/// the workspace). The math is identical: tokens refill linearly at
/// `refill_rate` per second, clamped at `max_tokens`.
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current token count. May be fractional during refill.
    tokens: f64,
    /// Capacity. `tokens` is clamped to this on every refill.
    max_tokens: f64,
    /// Refill rate in tokens per second.
    refill_rate: f64,
    /// Last `Instant` at which `tokens` was refreshed.
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: u32) -> Self {
        let cap = capacity.max(1) as f64;
        Self {
            tokens: cap,
            max_tokens: cap,
            refill_rate: refill_rate.max(1) as f64,
            last_refill: Instant::now(),
        }
    }

    /// Refill the bucket based on elapsed wall time, then try to
    /// consume one token. Returns `true` on success.
    fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Seconds until at least one token is available. Returns `1` even
    /// when the math rounds down so `Retry-After: 0` never goes on the
    /// wire.
    fn seconds_until_refill(&self, now: Instant) -> u64 {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let projected = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        if projected >= 1.0 {
            return 1;
        }
        if self.refill_rate <= 0.0 {
            return 1;
        }
        let needed = 1.0 - projected;
        (needed / self.refill_rate).ceil().max(1.0) as u64
    }
}

impl RateLimitMiddleware {
    /// Build a new middleware from an optional config.
    ///
    /// When `config` is `None`, the returned middleware is permanently
    /// disabled; every [`Self::check`] call returns
    /// [`Outcome::Disabled`]. This is the path taken when the
    /// `rate_limits:` block is absent from the origin's `sb.yml`.
    pub fn new(config: Option<OriginRateLimitsConfig>) -> Self {
        let inner = config.map(|cfg| {
            // `expect` here is local to a literal nonzero constant;
            // it cannot fail at runtime.
            let cap = NonZeroUsize::new(DEFAULT_MAX_KEYS).expect("DEFAULT_MAX_KEYS is nonzero");
            Inner {
                tenant_buckets: Mutex::new(lru::LruCache::new(cap)),
                route_buckets: Mutex::new(lru::LruCache::new(cap)),
                config: cfg,
                max_keys: cap,
            }
        });
        Self { inner }
    }

    /// Build a middleware wrapped in an [`Arc`]. Convenience for
    /// long-lived shared use in a request pipeline.
    pub fn new_shared(config: Option<OriginRateLimitsConfig>) -> Arc<Self> {
        Arc::new(Self::new(config))
    }

    /// True when the middleware has any config attached.
    pub fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Reserved hook for tests that need to assert the configured LRU
    /// size without poking at private fields. Returns `0` for a
    /// disabled middleware.
    #[doc(hidden)]
    pub fn max_keys(&self) -> usize {
        self.inner.as_ref().map_or(0, |i| i.max_keys.get())
    }

    /// Resolve the per-route ceiling for `path`. The first
    /// `route_overrides` entry whose pattern matches wins; otherwise
    /// the origin's `route_default` is returned. Pattern matching is
    /// either literal equality or `prefix/*` prefix matching, which
    /// keeps the resolver allocation-free on the request path.
    fn route_ceiling(cfg: &OriginRateLimitsConfig, path: &str) -> (u32, String) {
        for (pattern, ceiling) in cfg.route_overrides.iter() {
            if pattern_matches(pattern, path) {
                return (*ceiling, pattern.clone());
            }
        }
        (cfg.route_default, "__default__".to_string())
    }

    /// Gate a single request.
    ///
    /// - `client_key`: the identity to bucket on. Empty falls back to a
    ///   single shared bucket.
    /// - `path`: the request path, used to resolve the per-route
    ///   ceiling. The path is matched against `route_overrides`
    ///   patterns in iteration order; first match wins.
    ///
    /// The method holds bucket locks for the minimum span needed to
    /// refill + consume tokens. Two requests for different
    /// `(client, route)` pairs do not serialise on each other.
    pub fn check(&self, client_key: &str, path: &str) -> Outcome {
        let inner = match self.inner.as_ref() {
            Some(i) => i,
            None => return Outcome::Disabled,
        };

        let (route_ceiling, route_pattern) = Self::route_ceiling(&inner.config, path);
        // The per-route bucket refills at the route ceiling. Burst is
        // the same value so a route configured at "100 rps" admits a
        // burst of 100 and then refills at 100 / s.
        let route_burst = route_ceiling;
        let route_rate = route_ceiling;
        let now = Instant::now();

        // 1) Per-route bucket. Reject early if the route ceiling is
        //    exhausted; that avoids spending a tenant token on a
        //    request the per-route bucket would have denied anyway.
        let route_outcome = {
            let mut buckets = inner.route_buckets.lock();
            let key = RouteKey {
                client: client_key.to_string(),
                route_pattern: route_pattern.clone(),
            };
            if !buckets.contains(&key) {
                buckets.put(key.clone(), TokenBucket::new(route_burst, route_rate));
            }
            // `expect` is safe: we just put the key on the previous
            // line and hold the LRU lock across both calls.
            let bucket = buckets.get_mut(&key).expect("inserted above");
            if bucket.try_consume(now) {
                None
            } else {
                Some(bucket.seconds_until_refill(now))
            }
        };
        if let Some(retry_after_secs) = route_outcome {
            return Outcome::Deny {
                status: StatusCode::TOO_MANY_REQUESTS,
                retry_after_secs,
            };
        }

        // 2) Tenant bucket. The route bucket has already deducted one
        //    token; if the tenant bucket denies, we leave the route
        //    bucket as-is. That overshoots the route ceiling by at
        //    most one token, which is well within the per-second
        //    refill granularity.
        let tenant_outcome = {
            let mut buckets = inner.tenant_buckets.lock();
            let key = client_key.to_string();
            if !buckets.contains(&key) {
                buckets.put(
                    key.clone(),
                    TokenBucket::new(inner.config.tenant_burst, inner.config.tenant_sustained),
                );
            }
            let bucket = buckets.get_mut(&key).expect("inserted above");
            if bucket.try_consume(now) {
                None
            } else {
                Some(bucket.seconds_until_refill(now))
            }
        };
        if let Some(retry_after_secs) = tenant_outcome {
            return Outcome::Deny {
                status: StatusCode::TOO_MANY_REQUESTS,
                retry_after_secs,
            };
        }

        Outcome::Allow
    }
}

/// Match a `route_overrides` pattern against a request path.
///
/// Supports two flavours:
///
/// - Literal equality (`"/v1/agents"` matches only that exact path).
/// - Suffix-wildcard (`"/v1/agents/*"` matches any path starting with
///   `"/v1/agents/"`). The trailing `"*"` is the only wildcard
///   recognised today; richer glob support can land later without
///   breaking existing configs.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        // `"/v1/agents/*"` matches `/v1/agents/...` but not `/v1/agents`.
        path.starts_with(prefix)
            && path.len() > prefix.len()
            && path.as_bytes()[prefix.len()] == b'/'
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        // `"/v1/agents*"` (no slash) is treated as a plain prefix so
        // operators have a hatch when the path layout does not end at a
        // slash boundary.
        path.starts_with(prefix)
    } else {
        pattern == path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(tenant_burst: u32, tenant_sustained: u32, route_default: u32) -> OriginRateLimitsConfig {
        OriginRateLimitsConfig {
            tenant_burst,
            tenant_sustained,
            route_default,
            route_overrides: Default::default(),
            soft_threshold_rps: None,
        }
    }

    // 1. Request below the limit: passes through.
    #[test]
    fn below_limit_passes_through() {
        let mw = RateLimitMiddleware::new(Some(cfg(100, 100, 50)));
        for _ in 0..10 {
            let outcome = mw.check("client-a", "/v1/things");
            assert!(matches!(outcome, Outcome::Allow), "got {:?}", outcome);
        }
    }

    // 2. Request above the limit: returns 429 with Retry-After populated.
    #[test]
    fn above_limit_returns_429_with_retry_after() {
        // Route ceiling of 3 means we admit the first three and the
        // fourth gets denied by the per-route bucket. Use a low
        // sustained rate so refill cannot mask the deny inside the
        // test.
        let mw = RateLimitMiddleware::new(Some(cfg(100, 1, 3)));
        assert!(mw.check("client-a", "/api").is_allow());
        assert!(mw.check("client-a", "/api").is_allow());
        assert!(mw.check("client-a", "/api").is_allow());
        let denied = mw.check("client-a", "/api");
        match denied {
            Outcome::Deny {
                status,
                retry_after_secs,
            } => {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
                assert!(retry_after_secs >= 1, "got {retry_after_secs}");
            }
            other => panic!("expected Deny, got {other:?}"),
        }

        // Header application puts Retry-After on the wire.
        let mut headers = HeaderMap::new();
        denied.apply_retry_after(&mut headers);
        assert!(headers.get("retry-after").is_some());
    }

    // 3. Per-key isolation: two different keys each get their own bucket.
    #[test]
    fn per_key_isolation() {
        let mw = RateLimitMiddleware::new(Some(cfg(100, 1, 2)));

        // Exhaust client-a's route bucket.
        assert!(mw.check("client-a", "/api").is_allow());
        assert!(mw.check("client-a", "/api").is_allow());
        assert!(mw.check("client-a", "/api").is_deny());

        // client-b still gets a full bucket.
        assert!(mw.check("client-b", "/api").is_allow());
        assert!(mw.check("client-b", "/api").is_allow());
        assert!(mw.check("client-b", "/api").is_deny());
    }

    // 4. Bucket refill: after the configured window, a previously-limited
    //    key admits requests again.
    #[test]
    fn bucket_refills_after_window() {
        // High-rate refill so the test does not have to sleep a real
        // second to observe the bucket recovering. Both tenant and
        // route buckets configured at 1000 rps with burst 1 so the
        // first request is admitted, the second is denied, and a
        // 20 ms sleep refills well above one full token.
        let mw = RateLimitMiddleware::new(Some(cfg(1, 1000, 1000)));
        // Override the route burst by using a route that triggers the
        // default; we built `cfg` with tenant_burst=1 so the tenant
        // bucket is what runs out first.
        assert!(mw.check("client-a", "/api").is_allow());
        assert!(mw.check("client-a", "/api").is_deny());

        // Sleep for slightly longer than one tick at 1000 rps so we are
        // guaranteed at least one fresh token.
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(mw.check("client-a", "/api").is_allow());
    }

    // 5. Config: a missing or empty `rate_limits:` block disables the
    //    middleware (no 429s ever).
    #[test]
    fn disabled_when_config_absent() {
        let mw = RateLimitMiddleware::new(None);
        assert!(!mw.enabled());
        for _ in 0..1_000 {
            let outcome = mw.check("client-a", "/api");
            assert!(matches!(outcome, Outcome::Disabled));
            assert!(outcome.is_allow());
            assert!(!outcome.is_deny());
        }

        // apply_retry_after is a no-op on disabled outcomes.
        let mut headers = HeaderMap::new();
        Outcome::Disabled.apply_retry_after(&mut headers);
        assert!(headers.get("retry-after").is_none());
    }

    // Bonus: route_overrides pick the tighter ceiling.
    #[test]
    fn route_overrides_apply_first_match() {
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert("/expensive/*".to_string(), 1);
        let config = OriginRateLimitsConfig {
            tenant_burst: 1000,
            tenant_sustained: 1000,
            route_default: 100,
            route_overrides: overrides,
            soft_threshold_rps: None,
        };
        let mw = RateLimitMiddleware::new(Some(config));

        // Default route admits a comfortable burst.
        for _ in 0..50 {
            assert!(mw.check("client-a", "/cheap").is_allow());
        }
        // Expensive route is capped at 1.
        assert!(mw.check("client-a", "/expensive/llm").is_allow());
        assert!(mw.check("client-a", "/expensive/llm").is_deny());
    }

    // pattern_matches: literal vs `/*` suffix.
    #[test]
    fn pattern_matches_literal_and_suffix() {
        assert!(pattern_matches("/v1/x", "/v1/x"));
        assert!(!pattern_matches("/v1/x", "/v1/xy"));

        // `/v1/agents/*` matches deeper paths but not the bare segment.
        assert!(pattern_matches("/v1/agents/*", "/v1/agents/foo"));
        assert!(pattern_matches("/v1/agents/*", "/v1/agents/foo/bar"));
        assert!(!pattern_matches("/v1/agents/*", "/v1/agents"));
        assert!(!pattern_matches("/v1/agents/*", "/v1/other"));

        // `prefix*` (no slash) is a plain prefix.
        assert!(pattern_matches("/health*", "/healthcheck"));
        assert!(pattern_matches("/health*", "/health"));
    }

    // Tenant bucket caps cross-route volume.
    #[test]
    fn tenant_bucket_caps_cross_route_total() {
        // Tenant burst of 3 with two routes of 10 each. After three
        // requests across both routes, the tenant bucket denies.
        let mut overrides = std::collections::BTreeMap::new();
        overrides.insert("/a".to_string(), 10);
        overrides.insert("/b".to_string(), 10);
        let config = OriginRateLimitsConfig {
            tenant_burst: 3,
            tenant_sustained: 1,
            route_default: 10,
            route_overrides: overrides,
            soft_threshold_rps: None,
        };
        let mw = RateLimitMiddleware::new(Some(config));

        assert!(mw.check("client-a", "/a").is_allow());
        assert!(mw.check("client-a", "/b").is_allow());
        assert!(mw.check("client-a", "/a").is_allow());
        // Fourth request hits the tenant cap regardless of route.
        assert!(mw.check("client-a", "/b").is_deny());
    }

    // Empty client key uses a single shared bucket.
    #[test]
    fn empty_client_key_uses_shared_bucket() {
        let mw = RateLimitMiddleware::new(Some(cfg(100, 1, 2)));
        assert!(mw.check("", "/api").is_allow());
        assert!(mw.check("", "/api").is_allow());
        assert!(mw.check("", "/api").is_deny());
    }

    // new_shared returns an Arc that shares state with itself.
    #[test]
    fn new_shared_is_arc() {
        let mw = RateLimitMiddleware::new_shared(Some(cfg(100, 1, 1)));
        assert!(mw.check("client-a", "/api").is_allow());
        let cloned = Arc::clone(&mw);
        // Cloned Arc still observes the consumed token.
        assert!(cloned.check("client-a", "/api").is_deny());
    }

    // max_keys reports zero when disabled.
    #[test]
    fn max_keys_zero_when_disabled() {
        let mw = RateLimitMiddleware::new(None);
        assert_eq!(mw.max_keys(), 0);
        let mw = RateLimitMiddleware::new(Some(cfg(10, 10, 10)));
        assert_eq!(mw.max_keys(), DEFAULT_MAX_KEYS);
    }
}
