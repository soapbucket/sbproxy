//! JWKS (JSON Web Key Set) fetching, caching, and key lookup.
//!
//! [`JwksCache`] holds the current set of public keys fetched from a
//! JWKS endpoint, refreshes them in the background on a configurable
//! interval, and exposes typed lookups by `kid` so the JWT validation
//! path can resolve a [`jsonwebtoken::DecodingKey`] without re-parsing
//! the JSON on every request.
//!
//! Caches are deduplicated by JWKS URL via a process-wide registry: two
//! origins pointing at the same issuer share one cache and one
//! background refresh task.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::DecodingKey;

// --- Process-wide registry ---

/// Process-wide deduplicating registry of JWKS caches keyed by URL.
///
/// Built lazily on first use so tests that never touch JWKS pay no cost
/// up front. Background refresh tasks are spawned on first cache
/// creation and live for the rest of the process; this matches the
/// existing pattern used by load-balancer health probes.
static REGISTRY: OnceLock<DashMap<String, Arc<JwksCache>>> = OnceLock::new();

/// Default refresh interval for JWKS caches when not otherwise
/// specified. Most identity providers rotate signing keys hourly or
/// less often; five minutes is a good upper bound on key-rotation
/// detection latency without hammering the IdP.
pub const DEFAULT_REFRESH_SECS: u64 = 300;

/// Get-or-create the [`JwksCache`] for a given JWKS URL.
///
/// First call for a URL spawns a background refresh task that polls
/// the endpoint every `refresh_secs` seconds; subsequent calls return
/// the same cache. When no Tokio runtime is available (e.g. during
/// synchronous unit tests) the cache is still created but the refresh
/// task is skipped.
pub fn get_or_init_cache(jwks_url: &str, refresh_secs: u64) -> Arc<JwksCache> {
    let registry = REGISTRY.get_or_init(DashMap::new);
    if let Some(existing) = registry.get(jwks_url) {
        return existing.clone();
    }
    // Build outside the entry call so we don't hold a write reference
    // across the spawn.
    let cache = Arc::new(JwksCache::new(jwks_url, refresh_secs));
    let inserted = registry
        .entry(jwks_url.to_string())
        .or_insert_with(|| cache.clone())
        .clone();
    // Race-safe: `or_insert_with` may have used a sibling thread's
    // cache, in which case we did not become the owner and skip
    // spawning the refresh task. Spawn only when we won the insert.
    if Arc::ptr_eq(&inserted, &cache) {
        spawn_refresh_task(cache.clone(), jwks_url.to_string(), refresh_secs);
    }
    inserted
}

fn spawn_refresh_task(cache: Arc<JwksCache>, url: String, refresh_secs: u64) {
    if tokio::runtime::Handle::try_current().is_err() {
        // No runtime; the cache will rely on lazy refresh from the
        // request path (see [`JwksCache::ensure_loaded`]).
        return;
    }
    let interval = Duration::from_secs(refresh_secs.max(30));
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        loop {
            if let Err(e) = cache.refresh_with(&client).await {
                tracing::warn!(
                    jwks_url = %url,
                    error = %e,
                    "JWKS refresh failed; will retry on next interval"
                );
            }
            tokio::time::sleep(interval).await;
        }
    });
}

// --- JwksCache ---

/// Thread-safe cache for JWKS public keys with TTL-based refresh detection.
pub struct JwksCache {
    /// Current set of keys, swappable without a write lock.
    keys: ArcSwap<Vec<Jwk>>,
    /// JWKS endpoint URL.
    pub jwks_url: String,
    /// Timestamp of the most recent successful refresh.
    last_refresh: Mutex<Instant>,
    /// Minimum time between refreshes.
    refresh_interval: Duration,
}

impl JwksCache {
    /// Create a new `JwksCache`.
    ///
    /// `jwks_url` is the full JWKS endpoint URL (e.g.
    /// `"https://accounts.google.com/.well-known/jwks.json"`).
    ///
    /// `refresh_secs` controls the minimum number of seconds between
    /// automatic refreshes. A value of `0` means "always refresh" and
    /// is mostly useful for tests.
    pub fn new(jwks_url: &str, refresh_secs: u64) -> Self {
        Self {
            keys: ArcSwap::from_pointee(Vec::new()),
            jwks_url: jwks_url.to_string(),
            // Start with an instant far enough in the past that the
            // first call to `needs_refresh` returns true.
            last_refresh: Mutex::new(
                Instant::now()
                    .checked_sub(Duration::from_secs(refresh_secs.saturating_add(1)))
                    .unwrap_or_else(Instant::now),
            ),
            refresh_interval: Duration::from_secs(refresh_secs),
        }
    }

    /// Returns `true` when the cache is stale and keys should be re-fetched.
    pub fn needs_refresh(&self) -> bool {
        let last = self
            .last_refresh
            .lock()
            .expect("last_refresh lock poisoned");
        last.elapsed() >= self.refresh_interval
    }

    /// Returns `true` when the cache has at least one key cached.
    pub fn is_loaded(&self) -> bool {
        !self.keys.load().is_empty()
    }

    /// Return a snapshot of the current key set as raw JWK values.
    pub fn get_keys(&self) -> Vec<Jwk> {
        (*self.keys.load_full()).clone()
    }

    /// Replace the cached keys and reset the refresh timer.
    pub fn set_keys(&self, keys: Vec<Jwk>) {
        self.keys.store(Arc::new(keys));
        let mut last = self
            .last_refresh
            .lock()
            .expect("last_refresh lock poisoned");
        *last = Instant::now();
    }

    /// Look up a key by `kid` and convert it to a [`DecodingKey`].
    ///
    /// When `kid` is `None` and exactly one key is cached, that key is
    /// returned. This handles single-key issuers that omit the `kid`
    /// header. Multiple cached keys with no `kid` is ambiguous and
    /// returns `None` so the caller fails closed.
    pub fn lookup_decoding_key(&self, kid: Option<&str>) -> Option<DecodingKey> {
        let snap = self.keys.load_full();
        let keys = snap.as_ref();
        let jwk = match kid {
            Some(want) => keys
                .iter()
                .find(|k| k.common.key_id.as_deref() == Some(want))?,
            None if keys.len() == 1 => &keys[0],
            None => return None,
        };
        DecodingKey::from_jwk(jwk).ok()
    }

    /// Fetch the JWKS endpoint and replace the cached keys on success.
    ///
    /// Used by the background refresh task and by the lazy fallback in
    /// [`Self::ensure_loaded`]. Errors propagate so the background task
    /// can log them; callers on the request path should treat any
    /// error as "keep the existing cache and let the request fail
    /// closed if it cannot find a key".
    pub async fn refresh_with(&self, client: &reqwest::Client) -> anyhow::Result<()> {
        let resp = client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("JWKS GET failed: {}", e))?;
        if !resp.status().is_success() {
            anyhow::bail!("JWKS GET returned status {}", resp.status());
        }
        let body = resp
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("JWKS body read failed: {}", e))?;
        let set: JwkSet =
            serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("JWKS parse failed: {}", e))?;
        self.set_keys(set.keys);
        Ok(())
    }

    /// Ensure the cache has at least one key, blocking the current
    /// task on a fetch when the cache is empty.
    ///
    /// Called from the request path on the very first request (before
    /// the background task has had a chance to populate the cache). On
    /// subsequent requests this is a cheap snapshot read.
    pub async fn ensure_loaded(&self, client: &reqwest::Client) -> anyhow::Result<()> {
        if self.is_loaded() {
            return Ok(());
        }
        self.refresh_with(client).await
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn rsa_jwk(kid: &str) -> Jwk {
        // Minimal RSA public key fixture. Modulus and exponent are
        // valid base64url encodings of small integers; we only need
        // jsonwebtoken to *parse* the JWK, not actually verify a token
        // against it.
        let json = serde_json::json!({
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "use": "sig",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn new_cache_needs_refresh() {
        let cache = JwksCache::new("https://issuer.example.com/jwks", 3600);
        assert!(cache.needs_refresh());
        assert!(!cache.is_loaded());
    }

    #[test]
    fn set_keys_clears_needs_refresh() {
        let cache = JwksCache::new("https://issuer.example.com/jwks", 3600);
        cache.set_keys(vec![rsa_jwk("k1")]);
        assert!(!cache.needs_refresh());
        assert!(cache.is_loaded());
    }

    #[test]
    fn lookup_by_kid_returns_match() {
        let cache = JwksCache::new("https://issuer.example.com/jwks", 3600);
        cache.set_keys(vec![rsa_jwk("k1"), rsa_jwk("k2")]);
        assert!(cache.lookup_decoding_key(Some("k1")).is_some());
        assert!(cache.lookup_decoding_key(Some("k2")).is_some());
        assert!(cache.lookup_decoding_key(Some("missing")).is_none());
    }

    #[test]
    fn lookup_without_kid_succeeds_when_single_key() {
        let cache = JwksCache::new("https://issuer.example.com/jwks", 3600);
        cache.set_keys(vec![rsa_jwk("only")]);
        assert!(cache.lookup_decoding_key(None).is_some());
    }

    #[test]
    fn lookup_without_kid_fails_when_ambiguous() {
        let cache = JwksCache::new("https://issuer.example.com/jwks", 3600);
        cache.set_keys(vec![rsa_jwk("a"), rsa_jwk("b")]);
        // Multiple keys + no kid hint -> ambiguous, must reject so the
        // caller fails closed.
        assert!(cache.lookup_decoding_key(None).is_none());
    }

    #[test]
    fn registry_returns_same_cache_for_same_url() {
        let a = get_or_init_cache("https://issuer.example.com/jwks-a", 60);
        let b = get_or_init_cache("https://issuer.example.com/jwks-a", 60);
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn registry_returns_distinct_caches_for_distinct_urls() {
        let a = get_or_init_cache("https://issuer.example.com/jwks-x", 60);
        let b = get_or_init_cache("https://issuer.example.com/jwks-y", 60);
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[tokio::test]
    async fn refresh_with_loads_keys_from_endpoint() {
        // Spin up an httptest server that returns a known JWKS document
        // and verify that refresh_with parses and caches its keys.
        use std::net::SocketAddr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let body = serde_json::json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key-1",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }
            ]
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });

        let cache = JwksCache::new(&format!("http://{}/jwks", addr), 60);
        let client = reqwest::Client::new();
        cache.refresh_with(&client).await.unwrap();
        assert!(cache.is_loaded());
        assert!(cache.lookup_decoding_key(Some("test-key-1")).is_some());
    }

    #[tokio::test]
    async fn refresh_with_propagates_http_errors() {
        // A bound port we never accept on -> connection refused after
        // we drop the listener. Use a separate port to avoid races.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let cache = JwksCache::new(&format!("http://{}/jwks", addr), 60);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let result = cache.refresh_with(&client).await;
        assert!(result.is_err());
    }
}
