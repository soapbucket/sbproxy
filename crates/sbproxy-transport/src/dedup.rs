//! Request deduplication via content hash.
//!
//! `DedupCache` tracks recently-completed requests by a content hash of their
//! method, path, and optional body. Subsequent identical requests within the
//! deduplication window return the cached status code immediately without
//! forwarding to the upstream.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Cache entry: (expiry instant, cached HTTP status code).
type CacheEntry = (Instant, u16);

/// Request deduplication cache.
///
/// Stores a sliding-window map of request content hashes to their last-seen
/// HTTP status code. Duplicate requests (same method + path + body) within
/// the configured window return the cached status without hitting the upstream.
pub struct DedupCache {
    cache: Mutex<HashMap<String, CacheEntry>>,
    window: Duration,
}

impl DedupCache {
    /// Create a new `DedupCache` with the given deduplication window (seconds).
    pub fn new(window_secs: u64) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            window: Duration::from_secs(window_secs),
        }
    }

    /// Check if a request hash is a duplicate.
    ///
    /// Returns the cached HTTP status code if the hash was seen within the
    /// deduplication window; `None` otherwise. Expired entries are evicted
    /// lazily on each check.
    pub fn check(&self, hash: &str) -> Option<u16> {
        let mut cache = self.cache.lock().unwrap();
        let now = Instant::now();

        // Lazy eviction: remove expired entries on each access.
        cache.retain(|_, (expiry, _)| *expiry > now);

        cache.get(hash).map(|&(_, status)| status)
    }

    /// Store a completed request's hash and HTTP status code.
    ///
    /// The entry expires after the configured window duration.
    pub fn store(&self, hash: &str, status: u16) {
        let mut cache = self.cache.lock().unwrap();
        let expiry = Instant::now() + self.window;
        cache.insert(hash.to_string(), (expiry, status));
    }

    /// Generate a content hash from method, path, and optional body bytes.
    ///
    /// Uses SHA-256 over the concatenation of `METHOD|PATH|BODY` (pipe-delimited).
    /// Returns a lowercase hex string.
    pub fn request_hash(method: &str, path: &str, body: Option<&[u8]>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update(b"|");
        hasher.update(path.as_bytes());
        hasher.update(b"|");
        match body {
            Some(b) => {
                hasher.update(b"1"); // tag: body present
                hasher.update(b);
            }
            None => {
                hasher.update(b"0"); // tag: no body
            }
        }
        hex::encode(hasher.finalize())
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn store_and_check_returns_cached_status() {
        let cache = DedupCache::new(60);
        let hash = DedupCache::request_hash("POST", "/api/orders", Some(b"{\"item\":1}"));

        // Not in cache yet.
        assert!(cache.check(&hash).is_none());

        // Store with status 201.
        cache.store(&hash, 201);

        // Now should return cached status.
        assert_eq!(cache.check(&hash), Some(201));
    }

    #[test]
    fn expired_entry_not_returned() {
        // Use a 0-second window so entries expire immediately.
        let cache = DedupCache::new(0);
        let hash = DedupCache::request_hash("GET", "/ping", None);

        cache.store(&hash, 200);

        // Wait just a tiny bit to ensure the entry has expired.
        std::thread::sleep(Duration::from_millis(5));

        // Entry should be expired and evicted.
        assert!(
            cache.check(&hash).is_none(),
            "expired entry should not be returned"
        );
    }

    #[test]
    fn different_requests_produce_different_hashes() {
        let h1 = DedupCache::request_hash("GET", "/users", None);
        let h2 = DedupCache::request_hash("GET", "/orders", None);
        let h3 = DedupCache::request_hash("POST", "/users", None);
        let h4 = DedupCache::request_hash("GET", "/users", Some(b"body"));

        assert_ne!(h1, h2, "different paths should differ");
        assert_ne!(h1, h3, "different methods should differ");
        assert_ne!(h1, h4, "presence of body should differ");
        assert_ne!(h2, h3);
        assert_ne!(h3, h4);
    }

    #[test]
    fn same_request_produces_same_hash() {
        let h1 = DedupCache::request_hash("POST", "/v1/events", Some(b"payload"));
        let h2 = DedupCache::request_hash("POST", "/v1/events", Some(b"payload"));
        assert_eq!(
            h1, h2,
            "identical request parameters should produce identical hash"
        );
    }

    #[test]
    fn hash_is_valid_hex_string() {
        let hash = DedupCache::request_hash("DELETE", "/resource/42", None);
        // SHA-256 hex is 64 lowercase hex chars.
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn multiple_requests_can_be_stored_independently() {
        let cache = DedupCache::new(60);
        let h1 = DedupCache::request_hash("GET", "/a", None);
        let h2 = DedupCache::request_hash("GET", "/b", None);

        cache.store(&h1, 200);
        cache.store(&h2, 404);

        assert_eq!(cache.check(&h1), Some(200));
        assert_eq!(cache.check(&h2), Some(404));
    }

    #[test]
    fn store_overwrites_previous_status() {
        let cache = DedupCache::new(60);
        let hash = DedupCache::request_hash("PUT", "/item/1", Some(b"data"));

        cache.store(&hash, 200);
        assert_eq!(cache.check(&hash), Some(200));

        // Overwrite with a different status.
        cache.store(&hash, 204);
        assert_eq!(cache.check(&hash), Some(204));
    }

    #[test]
    fn no_body_vs_empty_body_differ() {
        let h_none = DedupCache::request_hash("POST", "/ep", None);
        let h_empty = DedupCache::request_hash("POST", "/ep", Some(b""));
        assert_ne!(h_none, h_empty, "None body and empty body should differ");
    }
}
