//! Idempotency-Key middleware (Wave 3 / R3.2).
//!
//! Implements the cached-retry vs conflict semantics pinned by
//! `docs/adr-end-to-end-idempotency.md` (A3.4). The middleware sits
//! ahead of policies in the handler chain. It is opt-in per origin via
//! the `idempotency:` config block.
//!
//! Flow:
//!
//! 1. Read the `Idempotency-Key` header.
//! 2. Absent: pass through. The rate-limit middleware (R2.3) consumes
//!    a slot per the normal flow.
//! 3. Present, cache miss: process the request, capture the response,
//!    persist `(workspace_id, key, body_hash, response, expires_at)`
//!    after the response is final. TTL 24 h.
//! 4. Present, cache hit, body hash matches: return the cached
//!    response. Set the request-context flag
//!    `IdempotencyOutcome::CacheHit` so the rate-limit middleware
//!    skips token-bucket consumption.
//! 5. Present, cache hit, body hash differs: return 409
//!    `ledger.idempotency_conflict`. Set `IdempotencyOutcome::Conflict`;
//!    the rate-limit middleware DOES consume a slot per the A3.4 DoS
//!    protection rule.
//!
//! Cache backends:
//!
//! - `InMemoryIdempotencyCache` for tests and single-instance
//!   deployments.
//! - `KvIdempotencyCache` for Redis-backed deployments. It wraps any
//!   `sbproxy_platform::storage::KVStore` impl, which keeps the OSS
//!   build redis-client-agnostic (the platform crate already pulls
//!   in the redis driver behind a feature flag and exposes the
//!   resulting blobs through the unified `KVStore` trait).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{HeaderMap, StatusCode};
use sbproxy_platform::storage::KVStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// --- Public surface ---

/// Default TTL for idempotency entries: 24 h, per A3.4 layer 2.
pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

/// HTTP header carrying the agent's idempotency key.
pub const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";

/// Cached response captured for a successfully processed request.
///
/// The status, headers, and body are replayed verbatim on subsequent
/// retries that match the cached body hash. Headers are stored as a
/// flat `(name, value)` list rather than a `HeaderMap` so the type
/// round-trips through `serde_json` cleanly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CachedResponse {
    /// HTTP status code as a `u16`.
    pub status: u16,
    /// Response headers as flat name / value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body. May be empty.
    pub body: Vec<u8>,
    /// SHA-256 hash of the original request body, hex-encoded.
    /// Compared against subsequent retries to detect conflicts.
    pub request_body_hash: [u8; 32],
    /// Wall-clock expiry as Unix seconds. The middleware treats
    /// `now_unix() >= expires_at` as a cache miss so a stale row in
    /// the backing store does not get replayed.
    pub expires_at_unix: u64,
}

/// Result of running the middleware before the handler chain.
///
/// The variants match the four flow branches in the ADR. The proxy's
/// rate-limit middleware reads this flag and skips token consumption
/// only when [`IdempotencyOutcome::CacheHit`] is set.
#[derive(Debug, Clone)]
pub enum IdempotencyOutcome {
    /// No `Idempotency-Key` header was present. Pass through.
    NotApplicable,
    /// Cache hit on a matching body hash. Replay the included
    /// response. Rate-limit middleware MUST NOT consume a slot.
    CacheHit(CachedResponse),
    /// Cache hit but the body hash differs. Return 409
    /// `ledger.idempotency_conflict`. Rate-limit middleware DOES
    /// consume a slot.
    Conflict,
    /// Cache miss. The request must be processed; the response should
    /// be captured via [`record_response`] after the handler chain
    /// finishes.
    Miss {
        /// The idempotency key, ready to feed back into
        /// [`record_response`].
        key: String,
        /// SHA-256 hash of the request body.
        body_hash: [u8; 32],
    },
}

impl IdempotencyOutcome {
    /// Convenience: whether this outcome represents a cache hit on a
    /// matching body. The rate-limit middleware reads this flag.
    pub fn is_cache_hit(&self) -> bool {
        matches!(self, IdempotencyOutcome::CacheHit(_))
    }

    /// Convenience: whether this outcome represents an idempotency
    /// conflict (cached entry exists but the body differs).
    pub fn is_conflict(&self) -> bool {
        matches!(self, IdempotencyOutcome::Conflict)
    }
}

/// Cache backend trait pinned by R3.2.
///
/// Implementations are scoped per `(workspace_id, key)` so two
/// workspaces using the same idempotency key never collide. The
/// `put` call is responsible for honouring the embedded
/// `expires_at_unix` field; backends that support native TTLs SHOULD
/// use them, but the middleware also re-checks expiry on every read
/// so a backend without TTLs (in-memory in tests) stays correct.
pub trait IdempotencyCache: Send + Sync {
    /// Look up a cached response for `(workspace_id, key)`. Returns
    /// `None` on miss or expiry.
    fn get(&self, workspace_id: &str, key: &str) -> Option<CachedResponse>;

    /// Persist a captured response under `(workspace_id, key)`.
    fn put(&self, workspace_id: &str, key: &str, response: CachedResponse);
}

// --- Body hashing ---

/// SHA-256 hash a request body for the idempotency-conflict check.
///
/// Empty bodies hash to the SHA-256 of the empty string; that is fine
/// because a retry with an empty body produces the same hash.
pub fn hash_body(body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(body);
    let out = h.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(out.as_slice());
    buf
}

// --- Header extraction ---

/// Extract the `Idempotency-Key` header value, trimmed.
///
/// Returns `None` when the header is absent or empty after trim.
pub fn extract_idempotency_key(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(IDEMPOTENCY_KEY_HEADER)?;
    let s = v.to_str().ok()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

// --- Middleware entry point ---

/// Inspect the inbound request and decide which branch of the
/// idempotency flow applies.
///
/// The caller passes the workspace id (already resolved by the auth
/// chain), the request headers, and the request body. The returned
/// [`IdempotencyOutcome`] tells the caller what to do next.
pub fn check_request(
    cache: &dyn IdempotencyCache,
    workspace_id: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> IdempotencyOutcome {
    let Some(key) = extract_idempotency_key(headers) else {
        return IdempotencyOutcome::NotApplicable;
    };

    let body_hash = hash_body(body);

    if let Some(existing) = cache.get(workspace_id, &key) {
        if existing.request_body_hash == body_hash {
            return IdempotencyOutcome::CacheHit(existing);
        }
        return IdempotencyOutcome::Conflict;
    }

    IdempotencyOutcome::Miss { key, body_hash }
}

/// Captured response payload, supplied to [`record_response`] after
/// the handler chain finishes processing a cache-miss request.
///
/// Grouped into a struct so the public surface stays under
/// `clippy::too_many_arguments` while keeping every required field
/// explicit at call sites.
#[derive(Debug, Clone)]
pub struct RecordedResponse {
    /// HTTP status code as a `u16`.
    pub status: u16,
    /// Response headers as flat name / value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body. May be empty.
    pub body: Vec<u8>,
    /// SHA-256 hash of the original request body.
    pub body_hash: [u8; 32],
    /// TTL in seconds. Zero is normalised to [`DEFAULT_TTL_SECS`] so a
    /// caller misconfig does not flip the row to permanently expired.
    pub ttl_secs: u64,
}

/// Persist the response captured after the handler chain finishes
/// processing a cache-miss request.
pub fn record_response(
    cache: &dyn IdempotencyCache,
    workspace_id: &str,
    key: &str,
    recorded: RecordedResponse,
) {
    let ttl = if recorded.ttl_secs == 0 {
        DEFAULT_TTL_SECS
    } else {
        recorded.ttl_secs
    };
    let expires_at_unix = now_unix().saturating_add(ttl);
    let resp = CachedResponse {
        status: recorded.status,
        headers: recorded.headers,
        body: recorded.body,
        request_body_hash: recorded.body_hash,
        expires_at_unix,
    };
    cache.put(workspace_id, key, resp);
}

/// Build the 409 conflict body documented in A3.4 / A1.2:
/// `{"error":"ledger.idempotency_conflict", ...}`.
///
/// Returned as `(status, content_type, body_bytes)` so the calling
/// handler can stamp a response without depending on a particular
/// HTTP framework type.
pub fn conflict_response() -> (StatusCode, &'static str, Vec<u8>) {
    let body = serde_json::json!({
        "error": "ledger.idempotency_conflict",
        "message": "Idempotency-Key already used with a different request body.",
    });
    (
        StatusCode::CONFLICT,
        "application/json",
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
    )
}

// --- Helpers ---

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// --- In-memory cache ---

/// In-memory [`IdempotencyCache`] for tests and single-instance
/// deployments. Backed by a `RwLock<HashMap>` keyed by
/// `(workspace_id, key)`. Entries are evicted lazily on read after
/// `expires_at_unix` has passed.
pub struct InMemoryIdempotencyCache {
    inner: std::sync::RwLock<std::collections::HashMap<(String, String), CachedResponse>>,
}

impl Default for InMemoryIdempotencyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryIdempotencyCache {
    /// Build an empty cache.
    pub fn new() -> Self {
        Self {
            inner: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl IdempotencyCache for InMemoryIdempotencyCache {
    fn get(&self, workspace_id: &str, key: &str) -> Option<CachedResponse> {
        // Read-side eviction: drop expired rows on access so a slow
        // sweeper does not let stale rows replay.
        let now = now_unix();
        let key_pair = (workspace_id.to_string(), key.to_string());
        {
            let g = self.inner.read().ok()?;
            if let Some(v) = g.get(&key_pair) {
                if v.expires_at_unix > now {
                    return Some(v.clone());
                }
            } else {
                return None;
            }
        }
        // Expired: take a write lock and evict.
        if let Ok(mut g) = self.inner.write() {
            if let Some(v) = g.get(&key_pair) {
                if v.expires_at_unix <= now {
                    g.remove(&key_pair);
                }
            }
        }
        None
    }

    fn put(&self, workspace_id: &str, key: &str, response: CachedResponse) {
        if let Ok(mut g) = self.inner.write() {
            g.insert((workspace_id.to_string(), key.to_string()), response);
        }
    }
}

// --- KVStore-backed cache (Redis or any other backend) ---

/// [`IdempotencyCache`] backed by any `KVStore` implementation. In OSS
/// deployments this is typically Redis (via `RedisKVStore` from
/// `sbproxy-platform`); in single-instance deployments operators may
/// point this at the embedded redb store.
///
/// The keyspace is `sbproxy:idem:<workspace_id>:<key>` so multiple
/// workspaces using the same key never collide.
pub struct KvIdempotencyCache {
    store: Arc<dyn KVStore>,
    ttl_secs: u64,
}

impl KvIdempotencyCache {
    /// Build a new cache wrapping `store`.
    ///
    /// `ttl_secs` is the value passed to `put_with_ttl`; backends
    /// without TTL support fall back to plain `put` and rely on the
    /// per-row `expires_at_unix` timestamp.
    pub fn new(store: Arc<dyn KVStore>, ttl_secs: u64) -> Self {
        let ttl = if ttl_secs == 0 {
            DEFAULT_TTL_SECS
        } else {
            ttl_secs
        };
        Self {
            store,
            ttl_secs: ttl,
        }
    }

    fn build_key(workspace_id: &str, key: &str) -> String {
        format!("sbproxy:idem:{workspace_id}:{key}")
    }
}

impl IdempotencyCache for KvIdempotencyCache {
    fn get(&self, workspace_id: &str, key: &str) -> Option<CachedResponse> {
        let storage_key = Self::build_key(workspace_id, key);
        let raw = self.store.get(storage_key.as_bytes()).ok()??;
        let parsed: CachedResponse = serde_json::from_slice(&raw).ok()?;
        if parsed.expires_at_unix <= now_unix() {
            // Best-effort eviction: ignore errors because the
            // sweeper / TTL expiry will catch it eventually.
            let _ = self.store.delete(storage_key.as_bytes());
            return None;
        }
        Some(parsed)
    }

    fn put(&self, workspace_id: &str, key: &str, response: CachedResponse) {
        let storage_key = Self::build_key(workspace_id, key);
        let Ok(payload) = serde_json::to_vec(&response) else {
            return;
        };
        // Try the TTL-aware path first; fall back to plain put for
        // backends that don't implement put_with_ttl.
        if self
            .store
            .put_with_ttl(storage_key.as_bytes(), &payload, self.ttl_secs)
            .is_err()
        {
            let _ = self.store.put(storage_key.as_bytes(), &payload);
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn h(headers: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in headers {
            m.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    #[test]
    fn idempotency_cache_miss_persists_response() {
        let cache = InMemoryIdempotencyCache::new();
        let headers = h(&[("Idempotency-Key", "abc-123")]);
        let body = b"{\"hello\":\"world\"}";

        let outcome = check_request(&cache, "ws_a", &headers, body);
        let (key, body_hash) = match outcome {
            IdempotencyOutcome::Miss { key, body_hash } => (key, body_hash),
            other => panic!("expected Miss, got {other:?}"),
        };

        record_response(
            &cache,
            "ws_a",
            &key,
            RecordedResponse {
                status: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: b"{\"ok\":true}".to_vec(),
                body_hash,
                ttl_secs: DEFAULT_TTL_SECS,
            },
        );

        // Retry: same key, same body => cache hit.
        let outcome = check_request(&cache, "ws_a", &headers, body);
        match outcome {
            IdempotencyOutcome::CacheHit(resp) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body, b"{\"ok\":true}");
            }
            other => panic!("expected CacheHit, got {other:?}"),
        }
    }

    #[test]
    fn idempotency_cache_hit_returns_cached_response_no_rate_limit_consumption() {
        let cache = InMemoryIdempotencyCache::new();
        let headers = h(&[("Idempotency-Key", "k1")]);
        let body = b"payload";

        // Prime the cache via a miss + record.
        let IdempotencyOutcome::Miss { key, body_hash } =
            check_request(&cache, "ws_a", &headers, body)
        else {
            panic!("expected Miss");
        };
        record_response(
            &cache,
            "ws_a",
            &key,
            RecordedResponse {
                status: 201,
                headers: vec![],
                body: b"created".to_vec(),
                body_hash,
                ttl_secs: 60,
            },
        );

        // Retry: the outcome must be a CacheHit so the rate-limit
        // middleware reads `is_cache_hit() == true` and skips token
        // bucket consumption per A3.4 / A2.5.
        let outcome = check_request(&cache, "ws_a", &headers, body);
        assert!(
            outcome.is_cache_hit(),
            "cache hit must signal rate-limit-skip"
        );
        assert!(!outcome.is_conflict());
    }

    #[test]
    fn idempotency_cache_hit_with_different_body_returns_409_does_consume_rate_limit() {
        let cache = InMemoryIdempotencyCache::new();
        let headers = h(&[("Idempotency-Key", "k2")]);

        // Prime with body A.
        let IdempotencyOutcome::Miss { key, body_hash } =
            check_request(&cache, "ws_a", &headers, b"body-A")
        else {
            panic!("expected Miss");
        };
        record_response(
            &cache,
            "ws_a",
            &key,
            RecordedResponse {
                status: 200,
                headers: vec![],
                body: vec![],
                body_hash,
                ttl_secs: 60,
            },
        );

        // Retry with body B: same key, different body => Conflict.
        let outcome = check_request(&cache, "ws_a", &headers, b"body-B");
        assert!(
            outcome.is_conflict(),
            "differing body must surface as Conflict so rate-limit consumes a slot"
        );
        assert!(!outcome.is_cache_hit());

        let (status, ct, body) = conflict_response();
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(ct, "application/json");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "ledger.idempotency_conflict");
    }

    #[test]
    fn idempotency_ttl_expiry_treats_as_cache_miss() {
        let cache = InMemoryIdempotencyCache::new();
        let headers = h(&[("Idempotency-Key", "expiring-key")]);

        // Insert directly with a past expiry to simulate a stale row.
        let stale = CachedResponse {
            status: 200,
            headers: vec![],
            body: b"old".to_vec(),
            request_body_hash: hash_body(b"x"),
            expires_at_unix: 1, // 1970-01-01
        };
        cache.put("ws_a", "expiring-key", stale);

        let outcome = check_request(&cache, "ws_a", &headers, b"x");
        match outcome {
            IdempotencyOutcome::Miss { .. } => {}
            other => panic!("expired row must read as Miss, got {other:?}"),
        }
    }

    #[test]
    fn idempotency_no_header_passes_through() {
        let cache = InMemoryIdempotencyCache::new();
        let headers = HeaderMap::new();
        let outcome = check_request(&cache, "ws_a", &headers, b"x");
        assert!(matches!(outcome, IdempotencyOutcome::NotApplicable));
        assert!(!outcome.is_cache_hit());
        assert!(!outcome.is_conflict());
    }

    #[test]
    fn idempotency_workspaces_isolated() {
        let cache = InMemoryIdempotencyCache::new();
        let headers = h(&[("Idempotency-Key", "shared")]);

        let IdempotencyOutcome::Miss { key, body_hash } =
            check_request(&cache, "ws_a", &headers, b"a")
        else {
            panic!("expected Miss in ws_a");
        };
        record_response(
            &cache,
            "ws_a",
            &key,
            RecordedResponse {
                status: 200,
                headers: vec![],
                body: vec![],
                body_hash,
                ttl_secs: 60,
            },
        );

        // Same key under a different workspace must miss.
        let outcome = check_request(&cache, "ws_b", &headers, b"a");
        match outcome {
            IdempotencyOutcome::Miss { .. } => {}
            other => panic!("ws_b must miss; cache must isolate per workspace, got {other:?}"),
        }
    }

    #[test]
    fn idempotency_empty_header_value_is_passthrough() {
        let cache = InMemoryIdempotencyCache::new();
        let headers = h(&[("Idempotency-Key", "")]);
        let outcome = check_request(&cache, "ws_a", &headers, b"x");
        // Empty string is not a usable key; treat as NotApplicable.
        assert!(matches!(outcome, IdempotencyOutcome::NotApplicable));
    }

    #[test]
    fn cached_response_round_trips_serde() {
        let resp = CachedResponse {
            status: 201,
            headers: vec![("x-custom".to_string(), "v".to_string())],
            body: b"payload".to_vec(),
            request_body_hash: hash_body(b"req"),
            expires_at_unix: 99_999_999,
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let back: CachedResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(resp, back);
    }
}
