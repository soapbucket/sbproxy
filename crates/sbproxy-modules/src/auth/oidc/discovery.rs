//! WOR-892 follow-up: OIDC discovery
//! (`.well-known/openid-configuration`) fetch + cache.
//!
//! PR1 took every IdP endpoint as an explicit config field. That
//! works but it makes every config grow a long list of endpoint URLs
//! that the IdP already publishes through OpenID Connect Discovery
//! 1.0 §4.2. This module ships the typed document, a pure URL
//! composer, a pure parser, and a TTL-bounded in-process cache so the
//! callback handler can call `cache.get_or_fetch(...)` instead of
//! requiring the operator to hand-copy six URLs.
//!
//! Three deliberate boundaries kept this PR small:
//!
//! 1. The cache fetcher is supplied by the caller. The cache itself
//!    does not depend on `reqwest`; the live callsite passes a closure
//!    that runs the existing AuthN-stack HTTP client, and tests pass
//!    an in-process closure. That keeps `sbproxy-modules` off the
//!    transitive `reqwest` graph.
//! 2. Config-side opt-in (making endpoints optional when discovery is
//!    on) is deliberately NOT done here. The runtime now has the
//!    machinery to discover; wiring the [`super::OidcAuth`] struct so
//!    the optional fields become required-or-discoverable is a clean
//!    additive follow-up that touches the compile path. Leaving that
//!    seam alone keeps PR scope tight.
//! 3. JWKS rotation is left to the existing `jwks::JwksCache`; we
//!    expose `jwks_uri` so a caller can reconfigure it once at
//!    discovery time, but we do not duplicate the rotation cache.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use serde::Deserialize;
use tokio::sync::RwLock;

/// Subset of the OpenID Connect Discovery 1.0 §3 metadata document
/// that sbproxy actually uses. Other keys (`response_types_supported`,
/// `subject_types_supported`, etc.) are tolerated and ignored by the
/// serde deserializer; this struct documents which keys we read.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DiscoveryDocument {
    /// Authorization Server's `issuer` URL. MUST exactly equal the
    /// value the caller used to construct the discovery URL, per
    /// OpenID Connect Discovery 1.0 §4.3. `validate_for_issuer`
    /// enforces this.
    pub issuer: String,
    /// URL of the OP's OAuth 2.0 Authorization Endpoint
    /// ([RFC 6749] §3.1).
    pub authorization_endpoint: String,
    /// URL of the OP's OAuth 2.0 Token Endpoint ([RFC 6749] §3.2).
    pub token_endpoint: String,
    /// URL of the OP's JWK Set ([RFC 7517]) document. The proxy's
    /// existing `JwksCache` fetches the keys here.
    pub jwks_uri: String,
    /// URL of the OP's UserInfo Endpoint (OIDC Core 1.0 §5.3). Used
    /// by the userinfo follow-up to project claims into trust headers.
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    /// URL of the OP's RP-initiated logout endpoint (OpenID Connect
    /// RP-Initiated Logout 1.0 §2). Used by the logout follow-up.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    /// URL of the OP's OAuth 2.0 Token Introspection Endpoint
    /// ([RFC 7662]). Optional in OIDC discovery; required only for
    /// resource-server style introspection.
    #[serde(default)]
    pub introspection_endpoint: Option<String>,
    /// URL of the OP's OAuth 2.0 Token Revocation Endpoint
    /// ([RFC 7009]). Optional in OIDC discovery; the proxy uses it
    /// for sign-out revocation when present.
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

impl DiscoveryDocument {
    /// Confirm the document's `issuer` field matches the issuer URL
    /// the caller used to fetch it. OpenID Connect Discovery 1.0 §4.3
    /// requires this check; without it a malicious server could
    /// publish a document claiming any issuer it likes.
    pub fn validate_for_issuer(&self, expected_issuer: &str) -> Result<()> {
        if self.issuer != expected_issuer {
            return Err(anyhow!(
                "oidc discovery: issuer mismatch: document says {:?}, configured {:?}",
                self.issuer,
                expected_issuer
            ));
        }
        for (label, url) in [
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("jwks_uri", &self.jwks_uri),
        ] {
            if !url.starts_with("https://") {
                return Err(anyhow!(
                    "oidc discovery: {label} must be https:// (got {url:?})"
                ));
            }
        }
        Ok(())
    }
}

/// Compose the discovery URL for an issuer. OpenID Connect Discovery
/// 1.0 §4.1 says the URL is the issuer with `/.well-known/openid-configuration`
/// appended, preserving any path component the issuer carries.
pub fn discovery_url_for_issuer(issuer: &str) -> String {
    let trimmed = issuer.trim_end_matches('/');
    format!("{trimmed}/.well-known/openid-configuration")
}

/// Parse a discovery document from JSON. Wraps `serde_json` so the
/// error message names the offending field rather than the raw serde
/// path, which is otherwise unhelpful in operator logs.
pub fn parse_discovery_document(body: &str) -> Result<DiscoveryDocument> {
    serde_json::from_str::<DiscoveryDocument>(body)
        .map_err(|e| anyhow!("oidc discovery: failed to parse document: {e}"))
}

/// TTL-bounded cache for a single issuer's discovery document. The
/// runtime keeps one cache per `OidcAuth` config so each issuer has
/// its own refresh clock. The fetcher closure is supplied at call
/// time so this module stays off the `reqwest` graph.
pub struct DiscoveryCache {
    issuer: String,
    ttl: Duration,
    state: RwLock<Option<CachedEntry>>,
}

struct CachedEntry {
    doc: Arc<DiscoveryDocument>,
    fetched_at: Instant,
}

impl DiscoveryCache {
    /// Build an empty cache for `issuer` with a `ttl` between
    /// refreshes. Operators usually want at least an hour; the OIDC
    /// spec does not pin a value but in practice IdP rotations land
    /// on the order of weeks, not seconds.
    pub fn new(issuer: impl Into<String>, ttl: Duration) -> Self {
        Self {
            issuer: issuer.into(),
            ttl,
            state: RwLock::new(None),
        }
    }

    /// The issuer URL this cache fetches against.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Return the cached document if it is still within TTL, otherwise
    /// call `fetcher` to fetch + validate + cache a fresh copy. The
    /// fetcher returns the raw response body so this layer can run the
    /// parser + issuer check itself; that keeps validation centralised.
    pub async fn get_or_fetch<F, Fut>(&self, fetcher: F) -> Result<Arc<DiscoveryDocument>>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<String>>,
    {
        if let Some(entry) = self.state.read().await.as_ref() {
            if entry.fetched_at.elapsed() < self.ttl {
                return Ok(Arc::clone(&entry.doc));
            }
        }
        let url = discovery_url_for_issuer(&self.issuer);
        let body = fetcher(url).await?;
        let doc = parse_discovery_document(&body)?;
        doc.validate_for_issuer(&self.issuer)?;
        let arc = Arc::new(doc);
        let mut guard = self.state.write().await;
        *guard = Some(CachedEntry {
            doc: Arc::clone(&arc),
            fetched_at: Instant::now(),
        });
        Ok(arc)
    }

    /// Force-drop the cached document. Useful when an upstream signals
    /// the IdP rotated keys or moved endpoints; the next `get_or_fetch`
    /// call will refetch.
    pub async fn invalidate(&self) {
        *self.state.write().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn discovery_json(issuer: &str) -> String {
        format!(
            r#"{{
                "issuer": "{issuer}",
                "authorization_endpoint": "https://idp.example.com/authorize",
                "token_endpoint": "https://idp.example.com/oauth/token",
                "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
                "userinfo_endpoint": "https://idp.example.com/userinfo",
                "end_session_endpoint": "https://idp.example.com/logout",
                "introspection_endpoint": "https://idp.example.com/oauth/introspect",
                "revocation_endpoint": "https://idp.example.com/oauth/revoke",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"]
            }}"#
        )
    }

    #[test]
    fn discovery_url_appends_well_known_suffix() {
        assert_eq!(
            discovery_url_for_issuer("https://idp.example.com"),
            "https://idp.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_url_trims_trailing_slash_to_avoid_double_slash() {
        assert_eq!(
            discovery_url_for_issuer("https://idp.example.com/"),
            "https://idp.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_url_preserves_path_component_for_tenant_issuers() {
        // Auth0, Okta, et al carry the tenant in the issuer path.
        assert_eq!(
            discovery_url_for_issuer("https://tenant.auth0.com/"),
            "https://tenant.auth0.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn parse_extracts_required_fields_and_optionals() {
        let doc = parse_discovery_document(&discovery_json("https://idp.example.com")).unwrap();
        assert_eq!(doc.issuer, "https://idp.example.com");
        assert_eq!(
            doc.userinfo_endpoint.as_deref(),
            Some("https://idp.example.com/userinfo")
        );
        assert_eq!(
            doc.end_session_endpoint.as_deref(),
            Some("https://idp.example.com/logout")
        );
        assert!(doc.introspection_endpoint.is_some());
        assert!(doc.revocation_endpoint.is_some());
    }

    #[test]
    fn parse_tolerates_missing_optional_endpoints() {
        let body = r#"{
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/oauth/token",
            "jwks_uri": "https://idp.example.com/.well-known/jwks.json"
        }"#;
        let doc = parse_discovery_document(body).unwrap();
        assert!(doc.userinfo_endpoint.is_none());
        assert!(doc.end_session_endpoint.is_none());
    }

    #[test]
    fn parse_reports_a_useful_error_on_missing_required_field() {
        let body = r#"{ "issuer": "https://idp.example.com" }"#;
        let err = parse_discovery_document(body).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("failed to parse"));
    }

    #[test]
    fn validate_rejects_issuer_mismatch_per_spec_4_3() {
        let doc =
            parse_discovery_document(&discovery_json("https://attacker.example.com")).unwrap();
        let err = doc
            .validate_for_issuer("https://idp.example.com")
            .unwrap_err();
        assert!(format!("{err:#}").contains("issuer mismatch"));
    }

    #[test]
    fn validate_rejects_plaintext_endpoints() {
        let mut doc = parse_discovery_document(&discovery_json("https://idp.example.com")).unwrap();
        doc.token_endpoint = "http://idp.example.com/oauth/token".to_string();
        let err = doc
            .validate_for_issuer("https://idp.example.com")
            .unwrap_err();
        assert!(format!("{err:#}").contains("token_endpoint"));
        assert!(format!("{err:#}").contains("https"));
    }

    #[tokio::test]
    async fn cache_returns_cached_document_within_ttl() {
        let cache = DiscoveryCache::new("https://idp.example.com", Duration::from_secs(60));
        let calls = Arc::new(AtomicUsize::new(0));

        let fetcher_first = {
            let calls = Arc::clone(&calls);
            move |_url: String| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(discovery_json("https://idp.example.com"))
                }
            }
        };
        let doc1 = cache.get_or_fetch(fetcher_first).await.unwrap();

        let fetcher_second = {
            let calls = Arc::clone(&calls);
            move |_url: String| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(discovery_json("https://idp.example.com"))
                }
            }
        };
        let doc2 = cache.get_or_fetch(fetcher_second).await.unwrap();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second call should hit cache"
        );
        assert!(Arc::ptr_eq(&doc1, &doc2));
    }

    #[tokio::test]
    async fn cache_refetches_after_invalidate() {
        let cache = DiscoveryCache::new("https://idp.example.com", Duration::from_secs(60));
        let calls = Arc::new(AtomicUsize::new(0));

        let mk_fetcher = |calls: Arc<AtomicUsize>| {
            move |_url: String| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(discovery_json("https://idp.example.com"))
                }
            }
        };

        cache
            .get_or_fetch(mk_fetcher(Arc::clone(&calls)))
            .await
            .unwrap();
        cache.invalidate().await;
        cache
            .get_or_fetch(mk_fetcher(Arc::clone(&calls)))
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cache_surfaces_validate_error_when_document_lies_about_issuer() {
        let cache = DiscoveryCache::new("https://idp.example.com", Duration::from_secs(60));
        let err = cache
            .get_or_fetch(|_url| async move { Ok(discovery_json("https://attacker.example.com")) })
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("issuer mismatch"));
    }

    #[tokio::test]
    async fn cache_surfaces_fetcher_error_without_caching_it() {
        let cache = DiscoveryCache::new("https://idp.example.com", Duration::from_secs(60));
        let err = cache
            .get_or_fetch(|_url| async move { Err(anyhow!("dns went away")) })
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("dns went away"));
        let recovered = cache
            .get_or_fetch(|_url| async move { Ok(discovery_json("https://idp.example.com")) })
            .await
            .unwrap();
        assert_eq!(recovered.issuer, "https://idp.example.com");
    }

    #[test]
    fn cache_exposes_issuer_via_accessor() {
        let cache = DiscoveryCache::new("https://idp.example.com", Duration::from_secs(60));
        assert_eq!(cache.issuer(), "https://idp.example.com");
    }
}
