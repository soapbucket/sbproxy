//! Cache storage trait and backends.

mod encrypted;
mod file;
mod memcached;
mod memory;
mod redis;

pub use encrypted::{cache_key_ring, CacheKeyDirectory, EncryptedCacheStore, SBRC_SCHEME};
pub use file::{FileCacheConfig, FileCacheStore};
pub use memcached::{MemcachedConfig, MemcachedStore};
pub use memory::MemoryCacheStore;
pub use redis::RedisCacheStore;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::at_rest::{AtRestPosture, CacheDurability};

/// A cached HTTP response with TTL metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedResponse {
    /// Opaque write generation used for conditional background refreshes.
    ///
    /// Legacy serialized entries default to zero. Every new write receives a
    /// non-zero random generation, so a stale revalidator can replace only the
    /// exact entry it originally observed.
    #[serde(default)]
    pub generation: u64,
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
    /// Cache-config fingerprint of the origin that stored this entry
    /// (WOR-2407).
    ///
    /// The same value the entry's key carries as its last segment, so
    /// under an exact-keyed backend this is redundant by construction.
    /// It is stamped anyway for the backend where it is not: memcached
    /// hashes every key to fit the protocol's 250-byte limit, so a
    /// lookup there matches a digest of the key rather than the key.
    ///
    /// Empty on entries written before this field existed, which
    /// [`CachedResponse::serves_config`] treats as "no opinion" rather
    /// than as a mismatch.
    #[serde(default)]
    pub config_fp: String,
}

impl CachedResponse {
    /// Whether this entry may be served against an origin whose current
    /// cache-config fingerprint is `current` (WOR-2407).
    ///
    /// An unstamped entry is served. It predates the field, and the key
    /// it was found under already had to match, so refusing it would
    /// cold-start a cache to re-derive a decision the key already made.
    pub fn serves_config(&self, current: &str) -> bool {
        self.config_fp.is_empty() || self.config_fp == current
    }

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
            generation: new_cache_generation(),
            status: self.status,
            headers,
            body: self.body.clone(),
            cached_at,
            ttl_secs,
            // A 304 refreshes metadata around the same representation,
            // so the entry still belongs to the config that stored it.
            config_fp: self.config_fp.clone(),
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

/// Generate a non-zero opaque generation for a new cache write.
pub fn new_cache_generation() -> u64 {
    rand::random::<u64>() | 1
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

    /// Atomically replace `expected` only if its generation is still current.
    ///
    /// Backends that cannot guarantee atomicity return an error. Callers must
    /// then leave the current entry untouched rather than falling back to an
    /// unconditional write.
    fn compare_and_swap(
        &self,
        _key: &str,
        _expected: &CachedResponse,
        _replacement: &CachedResponse,
    ) -> Result<bool> {
        anyhow::bail!("conditional cache replacement is not supported by this backend")
    }

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

    /// Where this backend keeps entries once written.
    ///
    /// Defaults to [`CacheDurability::Ephemeral`], which is the honest
    /// answer only for an in-process map. Any backend that touches disk
    /// or a network peer must override it, because this is what the
    /// boot-time at-rest check reads to decide whether storing plaintext
    /// here is an exposure. See [`crate::at_rest`].
    fn durability(&self) -> CacheDurability {
        CacheDurability::Ephemeral
    }

    /// Whether this store seals entries before they reach the backend.
    ///
    /// Only the encryption decorator answers `true`. A backend never
    /// does, because a backend does not know whether something wrapped
    /// it.
    fn encrypts_at_rest(&self) -> bool {
        false
    }

    /// This store's declared at-rest posture.
    ///
    /// Composed from the two methods above rather than overridden, so a
    /// decorator that forwards `durability` and answers `encrypts_at_rest`
    /// gets the right answer without restating it.
    fn at_rest_posture(&self) -> AtRestPosture {
        AtRestPosture::new(self.durability(), self.encrypts_at_rest())
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

    fn entry_stamped(config_fp: &str) -> CachedResponse {
        CachedResponse {
            generation: 0,
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
            cached_at: now_secs(),
            ttl_secs: 60,
            config_fp: config_fp.to_string(),
        }
    }

    #[test]
    fn an_entry_stamped_by_another_config_is_not_served() {
        // The key already partitions on the fingerprint, so this only
        // fires where the backend matches a digest of the key rather
        // than the key itself: memcached hashes to fit its 250-byte
        // limit.
        assert!(
            !entry_stamped("00112233445566ff").serves_config("ffee5544332211a0"),
            "an entry written under another config must not be served"
        );
    }

    #[test]
    fn an_entry_stamped_by_this_config_is_served() {
        assert!(entry_stamped("00112233445566ff").serves_config("00112233445566ff"));
    }

    #[test]
    fn an_unstamped_entry_is_still_served() {
        // Written before the field existed. The key it was found under
        // already matched, so refusing it would cold-start a cache to
        // re-derive a decision the key had already made.
        assert!(
            entry_stamped("").serves_config("00112233445566ff"),
            "a legacy entry must not be discarded for lacking a stamp"
        );
    }

    #[test]
    fn a_304_refresh_keeps_the_stamp_of_the_config_that_stored_it() {
        let refreshed = entry_stamped("00112233445566ff").freshen_from_not_modified(
            &[("etag".to_string(), "\"v2\"".to_string())],
            now_secs(),
            60,
        );
        assert_eq!(
            refreshed.config_fp, "00112233445566ff",
            "revalidation keeps the representation, so it keeps its config identity"
        );
    }

    #[test]
    fn an_absurd_ttl_does_not_panic_on_the_expiry_check() {
        // `ttl_secs` is attacker-writable on a shared backing store, so
        // the expiry sum must saturate. An unchecked add here panics in
        // a debug build and takes the request with it.
        let entry = CachedResponse {
            generation: 0,
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
            cached_at: now_secs(),
            ttl_secs: u64::MAX,
            config_fp: String::new(),
        };
        assert!(!entry.is_expired(), "a saturated expiry is still future");

        let pinned = CachedResponse {
            generation: 0,
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
            cached_at: u64::MAX,
            ttl_secs: u64::MAX,
            config_fp: String::new(),
        };
        assert!(!pinned.is_expired(), "both fields at the maximum saturate");
    }

    #[test]
    fn a_lapsed_ttl_still_reports_expired() {
        let entry = CachedResponse {
            generation: 0,
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
            cached_at: now_secs().saturating_sub(600),
            ttl_secs: 60,
            config_fp: String::new(),
        };
        assert!(entry.is_expired());
    }

    #[test]
    fn validators_are_discoverable_after_the_json_store_roundtrip() {
        let entry = CachedResponse {
            generation: 0,
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
            config_fp: String::new(),
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
            generation: 0,
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
            config_fp: String::new(),
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
