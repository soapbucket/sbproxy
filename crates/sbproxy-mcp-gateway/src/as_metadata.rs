// Authorization-Server metadata cache (RFC 8414).
//
// The broker fetches the upstream AS's metadata document on a TTL
// schedule, caches the result in memory behind a `Mutex`, and falls
// closed once the cached copy exceeds `max_metadata_staleness_secs`.
// JWKS fetches piggyback on the same cache, with ETag / If-None-Match
// support so unchanged keys round-trip cheaply.
//
// 4B.2 only ships the cache itself plus a thin `fetch_or_cached` API.
// Callers (the /token handler, the /register handler, and 4B.3's
// metadata route) read through the cache; nothing here mutates state
// outside the two `Mutex`-guarded slots.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use jsonwebtoken::jwk::JwkSet;
use sbproxy_security::url_redact::redacted_url;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

const MAX_AS_METADATA_BYTES: usize = 128 * 1024;
const MAX_AS_JWKS_BYTES: usize = 256 * 1024;

// --- Document model ---

/// RFC 8414 Authorization-Server metadata. We deliberately model only
/// the fields the broker uses; unknown fields are ignored on the wire.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// The AS's issuer identifier (must equal the URL the doc was
    /// fetched from minus the .well-known suffix per RFC 8414 §3.3).
    pub issuer: String,
    /// Authorization endpoint URL.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    /// Token endpoint URL.
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// JWKS document URL.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Dynamic client registration endpoint URL (RFC 7591).
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    /// Methods the AS supports for authenticating clients at the token
    /// endpoint. The broker intersects this with its
    /// `accepted_client_auth_methods` list.
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Grant types the AS advertises. The broker filters its forwarded
    /// requests against this list.
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    /// Response types the AS advertises (`code`, `id_token`, etc.).
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    /// PKCE methods the AS supports. The broker requires `S256` to be
    /// present and ignores everything else.
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

// --- Cache ---

/// In-memory cache for the AS metadata document and its JWKS.
///
/// Cloning is intentionally not derived. Callers that need shared
/// access wrap the cache in an `Arc`, since both inner `Mutex` slots
/// are pointer-stable behind it.
pub struct AsMetadataCache {
    /// HTTP client. Re-used across fetches so we do not re-establish
    /// TLS for every refresh.
    pub http: reqwest::Client,
    /// Configured metadata document URL (typically
    /// `<issuer>/.well-known/oauth-authorization-server`).
    pub metadata_url: String,
    allow_insecure_loopback: bool,
    /// Last-fetched metadata doc plus the wall-clock fetch time. The
    /// fetch time drives the refresh / staleness policy.
    current: Mutex<Option<(Arc<AuthorizationServerMetadata>, Instant)>>,
    /// Last-fetched JWKS plus the ETag returned by the server (if any)
    /// and the wall-clock fetch time. The ETag is replayed in the
    /// `If-None-Match` header so unchanged JWKS round-trip cheaply.
    jwks: Mutex<Option<JwksEntry>>,
}

#[derive(Clone)]
struct JwksEntry {
    set: Arc<JwkSet>,
    etag: Option<String>,
    /// Wall-clock time the entry was fetched. Read by the test
    /// helpers; the production fetch path uses ETag rather than
    /// duration to decide when to refresh.
    #[allow(dead_code)]
    fetched_at: Instant,
}

impl AsMetadataCache {
    /// Build a fresh, empty cache. The first call to `fetch_or_cached`
    /// will populate it.
    pub fn new(http: reqwest::Client, metadata_url: impl Into<String>) -> Self {
        Self {
            http,
            metadata_url: metadata_url.into(),
            allow_insecure_loopback: false,
            current: Mutex::new(None),
            jwks: Mutex::new(None),
        }
    }

    /// Build a cache permitting plaintext loopback endpoints for an
    /// explicitly enabled development runtime.
    pub fn new_with_development_loopback(
        http: reqwest::Client,
        metadata_url: impl Into<String>,
    ) -> Self {
        let mut cache = Self::new(http, metadata_url);
        cache.allow_insecure_loopback = true;
        cache
    }

    /// Returns the cached metadata if it is younger than `refresh_secs`,
    /// otherwise refetches. Falls closed if the cached copy exceeds
    /// `max_staleness_secs`.
    pub async fn fetch_or_cached(
        &self,
        refresh_secs: u64,
        max_staleness_secs: u64,
    ) -> Result<Arc<AuthorizationServerMetadata>> {
        let now = Instant::now();
        let refresh = Duration::from_secs(refresh_secs.max(1));
        let max_stale = Duration::from_secs(max_staleness_secs.max(1));

        // Fast path: cached and fresh.
        {
            let guard = self.current.lock().await;
            if let Some((doc, at)) = guard.as_ref() {
                if now.duration_since(*at) < refresh {
                    return Ok(doc.clone());
                }
            }
        }

        // Slow path: refresh. We hold no lock while doing network I/O.
        match self.fetch_metadata().await {
            Ok(doc) => {
                let arc = Arc::new(doc);
                let mut guard = self.current.lock().await;
                *guard = Some((arc.clone(), Instant::now()));
                Ok(arc)
            }
            Err(refresh_err) => {
                // Refresh failed. Serve stale doc until max_staleness.
                // `refresh_err` is already a summary (see `fetch_metadata`,
                // which builds every reqwest failure it wraps through
                // `sbproxy_httpkit::request_error_summary` before this
                // point), not a raw `reqwest::Error` that could carry a
                // URL.
                let guard = self.current.lock().await;
                if let Some((doc, at)) = guard.as_ref() {
                    if now.duration_since(*at) <= max_stale {
                        tracing::warn!(
                            error = %refresh_err,
                            "as metadata refresh failed; serving stale doc"
                        );
                        return Ok(doc.clone());
                    }
                }
                Err(anyhow!(
                    "as metadata fetch failed and no fresh cache: {refresh_err}"
                ))
            }
        }
    }

    /// Fetch the JWKS at `jwks_uri`, replaying the cached ETag when
    /// possible. Falls back to the cached JWKS on a 304 response.
    pub async fn fetch_jwks(&self, jwks_uri: &str) -> Result<Arc<JwkSet>> {
        let cached_etag = {
            let guard = self.jwks.lock().await;
            guard.as_ref().and_then(|e| e.etag.clone())
        };

        let jwks_origin = redacted_url(jwks_uri);
        let (_, http) =
            crate::egress::endpoint_client(jwks_uri, self.allow_insecure_loopback).await?;
        let mut req = http.get(jwks_uri);
        if let Some(etag) = cached_etag.as_deref() {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let resp = req.send().await.map_err(|e| {
            anyhow!(
                "jwks fetch failed: {}",
                sbproxy_httpkit::request_error_summary(&e)
            )
        })?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            let guard = self.jwks.lock().await;
            if let Some(entry) = guard.as_ref() {
                tracing::info!(jwks_uri = %jwks_origin, "jwks fetch 304; reusing cache");
                return Ok(entry.set.clone());
            }
            return Err(anyhow!("jwks 304 with no cached entry"));
        }
        if !resp.status().is_success() {
            return Err(anyhow!("jwks fetch returned status {}", resp.status()));
        }

        let new_etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body =
            crate::remote_body::bounded_response_body(resp, MAX_AS_JWKS_BYTES, "AS JWKS").await?;
        let set: JwkSet =
            serde_json::from_slice(&body).map_err(|e| anyhow!("jwks parse failed: {e}"))?;
        let arc = Arc::new(set);
        let mut guard = self.jwks.lock().await;
        *guard = Some(JwksEntry {
            set: arc.clone(),
            etag: new_etag,
            fetched_at: Instant::now(),
        });
        tracing::info!(jwks_uri = %jwks_origin, "jwks fetched fresh");
        Ok(arc)
    }

    async fn fetch_metadata(&self) -> Result<AuthorizationServerMetadata> {
        tracing::info!(url = %redacted_url(&self.metadata_url), "fetching as metadata");
        let (_, http) =
            crate::egress::endpoint_client(&self.metadata_url, self.allow_insecure_loopback)
                .await?;
        let resp = http.get(&self.metadata_url).send().await.map_err(|e| {
            anyhow!(
                "metadata fetch failed: {}",
                sbproxy_httpkit::request_error_summary(&e)
            )
        })?;
        if !resp.status().is_success() {
            return Err(anyhow!("metadata fetch returned status {}", resp.status()));
        }
        let body = crate::remote_body::bounded_response_body(
            resp,
            MAX_AS_METADATA_BYTES,
            "authorization-server metadata",
        )
        .await?;
        let doc: AuthorizationServerMetadata =
            serde_json::from_slice(&body).map_err(|e| anyhow!("metadata parse failed: {e}"))?;
        Ok(doc)
    }

    // --- Test helpers ---

    /// Seed the metadata cache with a doc and a fetch timestamp.
    /// Available in tests so we can exercise the staleness branches
    /// without standing up a fake AS server.
    #[cfg(test)]
    pub async fn seed_metadata(&self, doc: AuthorizationServerMetadata, at: Instant) {
        let mut guard = self.current.lock().await;
        *guard = Some((Arc::new(doc), at));
    }

    /// Seed the JWKS cache with a key set, optional etag, and fetch
    /// timestamp.
    #[cfg(test)]
    pub async fn seed_jwks(&self, set: JwkSet, etag: Option<String>, at: Instant) {
        let mut guard = self.jwks.lock().await;
        *guard = Some(JwksEntry {
            set: Arc::new(set),
            etag,
            fetched_at: at,
        });
    }

    /// Returns the wall-clock time at which the JWKS was last fetched,
    /// for tests that assert ETag round-trip behavior.
    #[cfg(test)]
    pub async fn jwks_fetched_at(&self) -> Option<Instant> {
        self.jwks.lock().await.as_ref().map(|e| e.fetched_at)
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cache(url: &str) -> AsMetadataCache {
        // AS metadata fetch is not credential-bearing in this test, but
        // we still exercise the hardened client to mirror prod.
        AsMetadataCache::new_with_development_loopback(sbproxy_httpkit::default_outbound(), url)
    }

    fn fixture_doc() -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: Some("https://idp.example.com/oauth/authorize".to_string()),
            token_endpoint: Some("https://idp.example.com/oauth/token".to_string()),
            jwks_uri: Some("https://idp.example.com/.well-known/jwks.json".to_string()),
            registration_endpoint: None,
            token_endpoint_auth_methods_supported: vec!["client_secret_basic".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            response_types_supported: vec!["code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
        }
    }

    #[tokio::test]
    async fn cache_hit_within_ttl_serves_cached_doc() {
        let cache = cache("http://invalid.invalid/metadata");
        cache.seed_metadata(fixture_doc(), Instant::now()).await;
        let doc = cache.fetch_or_cached(60, 600).await.expect("cached doc");
        assert_eq!(doc.issuer, "https://idp.example.com");
    }

    #[tokio::test]
    async fn cache_miss_with_no_seed_attempts_fetch_and_fails_closed() {
        // Use an unroutable URL so the fetch errors quickly without
        // depending on real DNS.
        let cache = cache("http://127.0.0.1:1/.well-known/oauth-authorization-server");
        let result = cache.fetch_or_cached(1, 1).await;
        assert!(
            result.is_err(),
            "fetch must fail when no cache and upstream unreachable"
        );
    }

    #[tokio::test]
    async fn stale_within_max_staleness_serves_cached_on_fetch_failure() {
        let cache = cache("http://127.0.0.1:1/.well-known/oauth-authorization-server");
        // Seed with a fetch time that is past the refresh window but
        // inside the max-staleness window.
        let at = Instant::now() - Duration::from_secs(10);
        cache.seed_metadata(fixture_doc(), at).await;
        let doc = cache
            .fetch_or_cached(1, 600)
            .await
            .expect("should serve stale on fetch failure");
        assert_eq!(doc.issuer, "https://idp.example.com");
    }

    #[tokio::test]
    async fn past_max_staleness_fails_closed() {
        let cache = cache("http://127.0.0.1:1/.well-known/oauth-authorization-server");
        // Seed with a fetch time well past the max-staleness window.
        let at = Instant::now() - Duration::from_secs(120);
        cache.seed_metadata(fixture_doc(), at).await;
        let result = cache.fetch_or_cached(1, 60).await;
        assert!(
            result.is_err(),
            "must fail closed when stale past max_staleness"
        );
    }

    #[tokio::test]
    async fn jwks_seed_and_etag_roundtrip_basics() {
        // We cannot exercise the real network here, so this test
        // verifies the seed helpers + the public accessors. The full
        // ETag round trip is covered by the e2e suite in 4B.3.
        let cache = cache("http://127.0.0.1:1/metadata");
        let set = JwkSet { keys: vec![] };
        let now = Instant::now();
        cache
            .seed_jwks(set, Some("\"abc123\"".to_string()), now)
            .await;
        let fetched_at = cache
            .jwks_fetched_at()
            .await
            .expect("jwks should be seeded");
        assert!(fetched_at <= Instant::now());
    }
}
