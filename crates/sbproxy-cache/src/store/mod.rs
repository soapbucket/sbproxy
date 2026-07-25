//! Cache storage trait and backends.

mod encrypted;
mod file;
mod memcached;
mod memory;
mod redis;

pub use encrypted::{CacheKeyMaterial, EncryptedCacheStore};
pub use file::{FileCacheConfig, FileCacheStore};
pub use memcached::{MemcachedConfig, MemcachedStore};
pub use memory::MemoryCacheStore;
pub use redis::RedisCacheStore;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A cached HTTP response with TTL metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResponse {
    /// HTTP status code of the cached response.
    pub status: u16,
    /// Response headers as ordered name/value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// Unix timestamp (seconds) when this entry was cached.
    pub cached_at: u64,
    /// Time-to-live in seconds from `cached_at`.
    pub ttl_secs: u64,
}

impl CachedResponse {
    /// Return the stored `ETag` validator, if present.
    pub fn etag(&self) -> Option<&str> {
        self.header_value("etag")
    }

    /// Return the stored `Last-Modified` validator, if present.
    pub fn last_modified(&self) -> Option<&str> {
        self.header_value("last-modified")
    }

    /// Refresh a stored response after an upstream `304 Not Modified`.
    ///
    /// The representation status and body remain unchanged. End-to-end
    /// fields supplied by the validation response replace stored values,
    /// while `Content-Length`, hop-by-hop fields, and this proxy's cache
    /// marker are ignored.
    pub fn freshen_from_not_modified(
        &self,
        validation_headers: &[(String, String)],
        cached_at: u64,
        ttl_secs: u64,
    ) -> Self {
        let connection_fields: Vec<String> = validation_headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
            .flat_map(|(_, value)| value.split(','))
            .map(|name| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect();
        let updates: Vec<&(String, String)> = validation_headers
            .iter()
            .filter(|(name, _)| {
                !is_unstorable_validation_header(name)
                    && !connection_fields
                        .iter()
                        .any(|connection_name| connection_name.eq_ignore_ascii_case(name))
            })
            .collect();
        let mut headers: Vec<(String, String)> = self
            .headers
            .iter()
            .filter(|(stored_name, _)| {
                !updates
                    .iter()
                    .any(|(update_name, _)| update_name.eq_ignore_ascii_case(stored_name))
            })
            .cloned()
            .collect();
        headers.extend(updates.into_iter().cloned());
        Self {
            status: self.status,
            headers,
            body: self.body.clone(),
            cached_at,
            ttl_secs,
        }
    }

    fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Returns true if this entry has exceeded its TTL.
    ///
    /// The expiry sum saturates rather than wrapping. `cached_at` and
    /// `ttl_secs` come off the backing store, and a shared Redis or
    /// memcached is exactly the place someone can write a record with
    /// `ttl_secs` set to `u64::MAX`; an unchecked add would panic in a
    /// debug build. Saturating matches what the file and memcached
    /// stores already do for the same computation.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.cached_at.saturating_add(self.ttl_secs)
    }
}

fn is_unstorable_validation_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "content-length"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-sbproxy-cache"
    )
}

/// Cache storage trait. All implementations must be thread-safe.
pub trait CacheStore: Send + Sync + 'static {
    /// Look up a cached response by key. Returns None if missing or expired.
    fn get(&self, key: &str) -> Result<Option<CachedResponse>>;

    /// Look up a cached response, including expired entries.
    ///
    /// Used by the stale-while-revalidate path: the live `get` would
    /// throw away an expired entry (and trigger a backend roundtrip)
    /// even when the SWR window says we should serve it stale and
    /// revalidate in the background. The default impl falls back to
    /// `get` for backends that have no separate "include expired" path.
    fn get_including_expired(&self, key: &str) -> Result<Option<CachedResponse>> {
        self.get(key)
    }

    /// Store a cached response.
    fn put(&self, key: &str, value: &CachedResponse) -> Result<()>;

    /// Remove a cached response by key.
    fn delete(&self, key: &str) -> Result<()>;

    /// Remove every entry whose key starts with `prefix`.
    ///
    /// Used by the `invalidate_on_mutation` path: a `POST /users/42`
    /// removes every cached `GET /users/42` variant regardless of
    /// query string or Vary fingerprint. Backends that cannot
    /// efficiently scan keys (Redis, memcached) may return
    /// `Ok(0)` and rely on TTL expiry instead. Returns the number
    /// of entries removed.
    fn delete_prefix(&self, _prefix: &str) -> Result<usize> {
        Ok(0)
    }

    /// Remove all entries.
    fn clear(&self) -> Result<()>;

    /// Short backend name (`"memory"`, `"file"`, `"redis"`, ...) for
    /// operator surfaces like the admin cache manager, which uses it to
    /// explain which purge operations the backend actually supports.
    fn backend_name(&self) -> &'static str {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::CachedResponse;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[test]
    fn an_absurd_ttl_does_not_panic_on_the_expiry_check() {
        // `ttl_secs` is attacker-writable on a shared backing store, so
        // the expiry sum must saturate. An unchecked add here panics in
        // a debug build and takes the request with it.
        let entry = CachedResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
            cached_at: now_secs(),
            ttl_secs: u64::MAX,
        };
        assert!(!entry.is_expired(), "a saturated expiry is still future");

        let pinned = CachedResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
            cached_at: u64::MAX,
            ttl_secs: u64::MAX,
        };
        assert!(!pinned.is_expired(), "both fields at the maximum saturate");
    }

    #[test]
    fn a_lapsed_ttl_still_reports_expired() {
        let entry = CachedResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
            cached_at: now_secs().saturating_sub(600),
            ttl_secs: 60,
        };
        assert!(entry.is_expired());
    }

    #[test]
    fn validators_are_discoverable_after_the_json_store_roundtrip() {
        let entry = CachedResponse {
            status: 200,
            headers: vec![
                ("ETag".to_string(), r#"W/"json-v1""#.to_string()),
                (
                    "Last-Modified".to_string(),
                    "Sun, 06 Nov 1994 08:49:37 GMT".to_string(),
                ),
            ],
            body: b"body".to_vec(),
            cached_at: now_secs(),
            ttl_secs: 60,
        };

        let encoded = serde_json::to_vec(&entry).expect("serialize");
        let decoded: CachedResponse = serde_json::from_slice(&encoded).expect("deserialize");

        assert_eq!(decoded.etag(), Some(r#"W/"json-v1""#));
        assert_eq!(
            decoded.last_modified(),
            Some("Sun, 06 Nov 1994 08:49:37 GMT")
        );
    }

    #[test]
    fn not_modified_revalidation_refreshes_metadata_without_replacing_the_body() {
        let entry = CachedResponse {
            status: 200,
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("content-length".to_string(), "12".to_string()),
                ("cache-control".to_string(), "max-age=5".to_string()),
                ("etag".to_string(), r#""old""#.to_string()),
                (
                    "last-modified".to_string(),
                    "Sun, 06 Nov 1994 08:49:37 GMT".to_string(),
                ),
            ],
            body: br#"{"value":1}"#.to_vec(),
            cached_at: 10,
            ttl_secs: 5,
        };

        let refreshed = entry.freshen_from_not_modified(
            &[
                ("cache-control".to_string(), "max-age=60".to_string()),
                ("etag".to_string(), r#""new""#.to_string()),
                ("content-length".to_string(), "999".to_string()),
                ("connection".to_string(), "close".to_string()),
            ],
            20,
            60,
        );

        assert_eq!(refreshed.status, 200);
        assert_eq!(refreshed.body, entry.body);
        assert_eq!(refreshed.cached_at, 20);
        assert_eq!(refreshed.ttl_secs, 60);
        assert_eq!(refreshed.etag(), Some(r#""new""#));
        assert_eq!(
            refreshed.last_modified(),
            Some("Sun, 06 Nov 1994 08:49:37 GMT")
        );
        assert!(refreshed
            .headers
            .contains(&("content-type".to_string(), "application/json".to_string())));
        assert!(refreshed
            .headers
            .contains(&("content-length".to_string(), "12".to_string())));
        assert!(refreshed
            .headers
            .contains(&("cache-control".to_string(), "max-age=60".to_string())));
        assert!(!refreshed
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("connection")));
    }
}
