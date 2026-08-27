//! HTTP fetcher for OpenID Federation 1.0 endpoints.
//!
//! The §9.2 trust-chain algorithm has two halves:
//! * **Fetch**: GET each entity's well-known configuration plus each
//!   subordinate statement from its superior's federation fetch
//!   endpoint.
//! * **Verify**: pass the resulting chain through
//!   [`crate::TrustChainResolver`].
//!
//! This module ships the fetch half. It is async because every step
//! is an outbound HTTP call, and exposes the [`FederationFetcher`]
//! trait so consumers can swap the production reqwest impl for a
//! stub in tests.
//!
//! ## Hardening
//!
//! The reqwest impl uses [`sbproxy_httpkit::default_outbound`], which
//! applies the workspace's timeout / redirect-cap / connection-pool
//! defaults. Federation fetches are not bearer-bearing (the
//! well-known and fetch endpoints are public per §9), so the looser
//! `default_outbound` policy is the right choice over a
//! token-bearing one.
//!
//! ## What this module does NOT do
//!
//! * Walk `authority_hints` to build a chain. That is
//!   [`crate::chain_composer`]'s job; the fetcher only knows how to
//!   fetch one URL at a time.
//! * Cache responses. A consumer that wants TTL caching wraps the
//!   fetcher; production deployments commonly cache for half the
//!   document's `exp` window.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use url::Url;

use crate::errors::{FederationError, FederationResult};
use crate::WELL_KNOWN_FEDERATION_PATH;

/// Default per-request timeout for federation fetches. Pinned to
/// match the OSS gateway's 30s outbound timeout; an operator that
/// needs a tighter bound can wrap [`ReqwestFederationFetcher`].
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Async fetcher trait. Implementations return the COMPACT-JWS
/// bytes the caller hands straight to
/// [`crate::verify_entity_statement`].
///
/// The trait stays narrow so a deployment that prefers a custom
/// HTTP stack (rustls config, DNS-over-HTTPS, on-disk fixtures for
/// integration tests) can swap an impl without re-implementing
/// the chain composer.
#[async_trait]
pub trait FederationFetcher: Send + Sync {
    /// Fetch the §9 self-signed Entity Configuration that an entity
    /// publishes at `<entity_id>/.well-known/openid-federation`.
    ///
    /// `entity_id` is the entity URL (the same value an entity
    /// statement carries in `iss` / `sub`). The fetcher MUST
    /// resolve the well-known path under this URL using the path
    /// suffix [`WELL_KNOWN_FEDERATION_PATH`].
    async fn fetch_entity_configuration(&self, entity_id: &str) -> FederationResult<String>;

    /// Fetch a Subordinate Statement from a superior's
    /// `federation_fetch_endpoint` (advertised in the superior's
    /// own Entity Configuration's `federation_entity` metadata
    /// block). The `sub` URL parameter is the subordinate's
    /// entity id; the response is the compact-JWS subordinate
    /// statement signed by the superior.
    async fn fetch_subordinate_statement(
        &self,
        fetch_endpoint: &str,
        subordinate: &str,
    ) -> FederationResult<String>;
}

/// Production `FederationFetcher` impl that uses
/// [`sbproxy_httpkit::default_outbound`] for hardened timeout /
/// redirect-cap defaults.
#[derive(Debug, Clone)]
pub struct ReqwestFederationFetcher {
    client: Client,
}

impl ReqwestFederationFetcher {
    /// Build a fetcher using the workspace's hardened outbound
    /// client (30s request timeout, redirect cap, connection-pool
    /// ceiling, bounded UA string).
    pub fn new() -> Self {
        Self {
            client: sbproxy_httpkit::default_outbound(),
        }
    }

    /// Build a fetcher around a caller-supplied `reqwest::Client`.
    /// Use this only when a test or operator deliberately needs a
    /// different policy (a stub in tests, a custom DNS resolver in
    /// an air-gapped deployment). Production code should call
    /// [`Self::new`] so the hardened defaults apply.
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }

    /// Compose the well-known URL for an entity. Errors when
    /// `entity_id` is not a valid HTTPS URL (the spec mandates
    /// HTTPS for federation endpoints; we reject http:// up-front).
    fn well_known_url(entity_id: &str) -> FederationResult<Url> {
        let mut url = Url::parse(entity_id)
            .map_err(|_| FederationError::FetchFailed("invalid federation entity URL".into()))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(FederationError::FetchFailed(
                "federation entity URL must not contain credentials".into(),
            ));
        }
        if url.scheme() != "https" {
            return Err(FederationError::FetchFailed(
                "federation entity URL must use https".into(),
            ));
        }
        // Append the well-known path; reqwest's `join` would drop a
        // trailing-slash-less path's tail, so do it manually.
        let new_path = if url.path().ends_with('/') {
            format!(
                "{}{}",
                url.path(),
                WELL_KNOWN_FEDERATION_PATH.trim_start_matches('/')
            )
        } else {
            format!("{}{}", url.path(), WELL_KNOWN_FEDERATION_PATH)
        };
        url.set_path(&new_path);
        Ok(url)
    }
}

impl Default for ReqwestFederationFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FederationFetcher for ReqwestFederationFetcher {
    async fn fetch_entity_configuration(&self, entity_id: &str) -> FederationResult<String> {
        let url = Self::well_known_url(entity_id)?;
        let mut resp = self
            .client
            .get(url.clone())
            .timeout(DEFAULT_FETCH_TIMEOUT)
            .header(http::header::ACCEPT, "application/entity-statement+jwt")
            .send()
            .await
            .map_err(|_| FederationError::FetchFailed("federation entity request failed".into()))?;
        if !resp.status().is_success() {
            return Err(FederationError::FetchFailed(format!(
                "federation entity request returned HTTP {}",
                resp.status()
            )));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|_| {
            FederationError::FetchFailed("federation entity response read failed".into())
        })? {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > 1_048_576 { // 1 MiB cap
                return Err(FederationError::FetchFailed("federation entity response exceeds 1 MiB".into()));
            }
        }
        String::from_utf8(bytes)
            .map_err(|_| FederationError::FetchFailed("federation entity response is not UTF-8".into()))
    }

    async fn fetch_subordinate_statement(
        &self,
        fetch_endpoint: &str,
        subordinate: &str,
    ) -> FederationResult<String> {
        let mut url = Url::parse(fetch_endpoint).map_err(|_| {
            FederationError::FetchFailed("invalid federation fetch endpoint URL".into())
        })?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(FederationError::FetchFailed(
                "federation fetch endpoint must not contain credentials".into(),
            ));
        }
        if url.scheme() != "https" {
            return Err(FederationError::FetchFailed(
                "federation fetch endpoint must use https".into(),
            ));
        }
        url.query_pairs_mut().append_pair("sub", subordinate);
        let mut resp = self
            .client
            .get(url.clone())
            .timeout(DEFAULT_FETCH_TIMEOUT)
            .header(http::header::ACCEPT, "application/entity-statement+jwt")
            .send()
            .await
            .map_err(|_| FederationError::FetchFailed("subordinate statement request failed".into()))?;
        if !resp.status().is_success() {
            return Err(FederationError::FetchFailed(format!(
                "subordinate statement request returned HTTP {}",
                resp.status()
            )));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|_| {
            FederationError::FetchFailed("subordinate statement response read failed".into())
        })? {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > 1_048_576 { // 1 MiB cap
                return Err(FederationError::FetchFailed("subordinate statement response exceeds 1 MiB".into()));
            }
        }
        String::from_utf8(bytes).map_err(|_| {
            FederationError::FetchFailed("subordinate statement response is not UTF-8".into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `well_known_url` appends the spec-defined path to an
    /// entity URL whose own path is `/`. Default case for entities
    /// that publish at their domain root.
    #[test]
    fn well_known_url_appends_path_to_domain_root() {
        let url = ReqwestFederationFetcher::well_known_url("https://acme.example").unwrap();
        assert_eq!(
            url.as_str(),
            "https://acme.example/.well-known/openid-federation"
        );
    }

    /// Entities that publish at a sub-path (e.g. behind a reverse
    /// proxy on a shared host) keep their prefix in the well-known
    /// URL.
    #[test]
    fn well_known_url_preserves_subpath() {
        let url =
            ReqwestFederationFetcher::well_known_url("https://shared.example/tenant-1").unwrap();
        assert_eq!(
            url.as_str(),
            "https://shared.example/tenant-1/.well-known/openid-federation"
        );
    }

    /// Trailing slash on the entity_id is normalised: the
    /// well-known suffix MUST NOT introduce a double slash.
    #[test]
    fn well_known_url_handles_trailing_slash() {
        let url = ReqwestFederationFetcher::well_known_url("https://acme.example/").unwrap();
        assert_eq!(
            url.as_str(),
            "https://acme.example/.well-known/openid-federation"
        );
    }

    /// The fetcher refuses `http://` URLs up-front: the §9 spec
    /// REQUIRES the federation transport be HTTPS, and a permissive
    /// fetcher would let a misconfigured operator publish their
    /// signing keys over plaintext.
    #[test]
    fn well_known_url_rejects_plaintext() {
        let err = ReqwestFederationFetcher::well_known_url("http://insecure.example").unwrap_err();
        assert!(matches!(err, FederationError::FetchFailed(_)));
    }

    /// `well_known_url` rejects a malformed entity URL with a
    /// typed `FetchFailed`.
    #[test]
    fn well_known_url_rejects_garbage() {
        let err = ReqwestFederationFetcher::well_known_url("not a url").unwrap_err();
        assert!(matches!(err, FederationError::FetchFailed(_)));
    }

    /// Credential-bearing URLs are invalid federation identifiers and
    /// the returned error cannot reflect their secret-bearing userinfo.
    #[test]
    fn security_boundary_fetcher_rejects_credentials_without_echoing_them() {
        let err = ReqwestFederationFetcher::well_known_url(
            "https://federation-user:FETCH_SECRET_CANARY@example.com",
        )
        .expect_err("credential-bearing entity IDs must be rejected");
        let message = err.to_string();
        assert!(!message.contains("FETCH_SECRET_CANARY"), "{message}");
    }

    /// Malformed attacker text can contain log delimiters and secrets;
    /// neither is copied into the bounded operator-facing error.
    #[test]
    fn security_boundary_fetcher_sanitizes_malformed_url_errors() {
        let err = ReqwestFederationFetcher::well_known_url(
            "not a url\nFETCH_SECRET_CANARY",
        )
        .expect_err("malformed entity IDs must be rejected");
        let message = err.to_string();
        assert!(!message.contains("FETCH_SECRET_CANARY"), "{message}");
        assert!(!message.contains('\n'), "{message}");
        assert!(message.len() <= 160, "fetch error must stay bounded: {message}");
    }
}
