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
//! A federation peer URL is attacker-influenced: it arrives in an
//! `authority_hints` array or a `federation_fetch_endpoint` metadata
//! field signed by some entity in the chain, not from the operator's
//! config. So the fetch runs through the workspace's governed egress
//! machinery rather than a bare client, and does it in two layers:
//!
//! * **Always.** [`sbproxy_security::ssrf::validate_url_resolved`]
//!   resolves the host and refuses the fetch outright when any answer is
//!   a loopback, RFC 1918, link-local, or otherwise special-use address.
//!   The addresses it returns are the only ones the dial is allowed to
//!   reach, so a name that resolves publicly at check time and privately
//!   at connect time is refused rather than followed. This layer needs
//!   no configuration and cannot be turned off.
//! * **When `egress.federation:` is configured.**
//!   [`sbproxy_security::governed_egress::GovernedEgress`] adds the
//!   operator's host, scheme, and port allowlist for
//!   `sbproxy_security::egress::EgressPurpose::Federation`, re-authorizes every redirect hop
//!   against it before any second connect, bounds the chain, and counts
//!   each refusal on the `sbproxy_egress_refused_total` /
//!   `GET /api/egress` surfaces.
//!
//! What that leaves: with no `egress.federation:` block, any *public*
//! address is reachable, because a federation deployment's peers are
//! discovered through the trust chain rather than listed in advance.
//! Write the allowlist when the trust anchors are known.
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
use sbproxy_security::egress::{CachedSystemResolver, EgressPurpose};
use sbproxy_security::governed_egress::GovernedEgress;
use url::Url;

use crate::errors::{FederationError, FederationResult};
use crate::WELL_KNOWN_FEDERATION_PATH;

/// Default per-request timeout for federation fetches. Pinned to
/// match the OSS gateway's 30s outbound timeout; an operator that
/// needs a tighter bound can wrap [`ReqwestFederationFetcher`].
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Ceiling on the bytes read from any federation response, redirects
/// included. An entity configuration is a compact JWS of a few
/// kilobytes; a megabyte is generous and a peer that exceeds it is
/// either broken or feeding the chain composer something it should not
/// hold in memory.
const MAX_RESPONSE_BYTES: usize = 1_048_576;

/// Attribution for the egress metric, log line, and inventory row. Not a
/// URL: the counter's `origin` label is a configuration-scoped name.
const EGRESS_ORIGIN: &str = "openid_federation";

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

/// Production `FederationFetcher` impl whose fetches run through the
/// workspace's governed egress machinery.
///
/// See the module docs for the two layers and for what the unconfigured
/// case does and does not cover.
#[derive(Debug, Clone)]
pub struct ReqwestFederationFetcher {
    /// Client used for a hop that carries no pin set, which happens only
    /// when a caller supplied its own through [`Self::with_client`].
    /// `None` is the production shape: every dial is made on a client
    /// this fetcher built from the addresses the SSRF check resolved.
    client: Option<Client>,
}

impl ReqwestFederationFetcher {
    /// Build a fetcher that dials only what the SSRF check resolved and
    /// never follows a redirect it has not re-authorized.
    pub fn new() -> Self {
        Self { client: None }
    }

    /// Build a fetcher around a caller-supplied `reqwest::Client`.
    ///
    /// Use this only when a test or operator deliberately needs a
    /// different transport policy (a stub in tests, a custom DNS
    /// resolver in an air-gapped deployment). The supplied client is
    /// used for a hop that carries no pin set, which is what happens
    /// when no `egress.federation:` allowlist is armed; the
    /// private-address refusal described in this module's docs runs
    /// either way and is not something this constructor can opt out of.
    /// Build
    /// it with `redirect(Policy::none())`: a client with a redirect
    /// policy of its own follows the hop before the governed loop can
    /// refuse it.
    pub fn with_client(client: Client) -> Self {
        Self {
            client: Some(client),
        }
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

    /// GET `url` under both egress layers and return the body as UTF-8.
    ///
    /// `what` names the document for the operator-facing error and is a
    /// fixed string chosen by the caller, never attacker text. No error
    /// this returns carries the URL, the resolved address, the SSRF
    /// refusal reason, or the transport error: a federation peer URL can
    /// itself be the thing an attacker is probing for.
    async fn governed_get(&self, url: &Url, what: &'static str) -> FederationResult<String> {
        // Layer one, unconditional. Refuses a peer that resolves to a
        // loopback, RFC 1918, link-local, CGNAT, or other special-use
        // address, and hands back the only addresses the dial may use.
        let resolved = sbproxy_security::ssrf::validate_url_resolved(url.as_str(), &[])
            .map_err(|_| FederationError::FetchFailed(format!("{what} destination refused")))?;
        let Some(host) = url.host_str() else {
            return Err(FederationError::FetchFailed(format!(
                "{what} destination refused"
            )));
        };
        // Dial the resolved addresses and nothing else, so a name that
        // answers publicly here and privately at connect time does not
        // get a second resolution to rebind through. The URL keeps its
        // host, so SNI, certificate verification, and the `Host` header
        // are all still the name the check passed.
        let pinned = sbproxy_httpkit::OutboundClientBuilder::new()
            .no_redirects()
            .request_timeout(DEFAULT_FETCH_TIMEOUT)
            .resolve_to_addrs(host, &resolved.addrs)
            .build()
            .map_err(|_| FederationError::FetchFailed(format!("{what} client build failed")))?;
        let dial = self.client.as_ref().unwrap_or(&pinned);
        let request = dial
            .get(url.clone())
            .header(http::header::ACCEPT, "application/entity-statement+jwt")
            .build()
            .map_err(|_| FederationError::FetchFailed(format!("{what} request build failed")))?;
        // Layer two, when the operator armed one: the host/scheme/port
        // allowlist, per-hop redirect re-authorization, and the four
        // refusal surfaces.
        let authorizer = sbproxy_security::egress::configured_gate(EgressPurpose::Federation);
        let resolver = CachedSystemResolver;
        let governed = GovernedEgress {
            purpose: EgressPurpose::Federation,
            authorizer: authorizer.as_ref(),
            resolver: &resolver,
            origin: EGRESS_ORIGIN,
            tenant: "unset",
            // A federation fetch carries no credential: §9 makes the
            // well-known and fetch endpoints public. Nothing to strip.
            sensitive_headers: &[],
            max_response_bytes: MAX_RESPONSE_BYTES,
            no_redirect_client: dial,
            timeout: DEFAULT_FETCH_TIMEOUT,
        };
        let response = governed
            .send(request)
            .await
            .map_err(|_| FederationError::FetchFailed(format!("{what} request failed")))?;
        if !(200..300).contains(&response.status) {
            return Err(FederationError::FetchFailed(format!(
                "{what} request returned HTTP {}",
                response.status
            )));
        }
        String::from_utf8(response.body)
            .map_err(|_| FederationError::FetchFailed(format!("{what} response is not UTF-8")))
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
        self.governed_get(&url, "federation entity").await
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
        self.governed_get(&url, "subordinate statement").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `governed_get` says when the destination never got dialed.
    /// Kept as one constant so a message change breaks every refusal
    /// test at once rather than quietly turning them into assertions
    /// that any error at all came back.
    const REFUSED_SUFFIX: &str = "destination refused";

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

    /// A federation peer that resolves to loopback is refused before any
    /// connect. `authority_hints` and `federation_fetch_endpoint` are
    /// signed by another entity in the chain, not written by this
    /// operator, so an entity that names `127.0.0.1` is asking this
    /// process to read its own admin surface and hand back the body.
    ///
    /// Refused by [`sbproxy_security::ssrf::validate_url_resolved`],
    /// which runs whether or not an `egress.federation:` allowlist is
    /// armed. Nothing in this test installs one.
    ///
    /// The assertion is on the refusal message, not on "some error came
    /// back". Nothing is listening on those ports, so a fetcher with no
    /// SSRF check at all also fails, with a transport error; asserting
    /// `FetchFailed(_)` would pass either way and prove nothing. The
    /// refused destination and the failed connect are two different
    /// messages, and only one of them means the request never went out.
    #[tokio::test]
    async fn security_boundary_a_loopback_peer_is_refused() {
        let fetcher = ReqwestFederationFetcher::new();
        for entity_id in [
            "https://127.0.0.1",
            "https://127.0.0.1:8081",
            "https://[::1]",
            "https://0.0.0.0",
        ] {
            let message = fetcher
                .fetch_entity_configuration(entity_id)
                .await
                .expect_err("a loopback federation peer must be refused")
                .to_string();
            assert!(
                message.ends_with(REFUSED_SUFFIX),
                "{entity_id} must be refused before the dial, got: {message}"
            );
        }
    }

    /// The same refusal for the RFC 1918, link-local, and CGNAT ranges,
    /// which is what an SSRF against a cloud metadata service or an
    /// internal control plane actually looks like.
    #[tokio::test]
    async fn security_boundary_a_private_range_peer_is_refused() {
        let fetcher = ReqwestFederationFetcher::new();
        for entity_id in [
            "https://10.0.0.5",
            "https://192.168.1.1",
            "https://172.16.0.1",
            "https://169.254.169.254",
            "https://100.64.0.1",
        ] {
            let message = fetcher
                .fetch_entity_configuration(entity_id)
                .await
                .expect_err("a private-range federation peer must be refused")
                .to_string();
            assert!(
                message.ends_with(REFUSED_SUFFIX),
                "{entity_id} must be refused before the dial, got: {message}"
            );
        }
    }

    /// A superior's `federation_fetch_endpoint` reaches the same guard.
    /// It is the more dangerous of the two: the well-known URL is
    /// derived from an entity id a caller might have vetted, while this
    /// one comes out of a metadata block deeper in the chain.
    #[tokio::test]
    async fn security_boundary_a_private_fetch_endpoint_is_refused() {
        let fetcher = ReqwestFederationFetcher::new();
        let message = fetcher
            .fetch_subordinate_statement("https://169.254.169.254/fetch", "https://leaf.example")
            .await
            .expect_err("a private fetch endpoint must be refused")
            .to_string();
        assert!(
            message.ends_with(REFUSED_SUFFIX),
            "a private fetch endpoint must be refused before the dial, got: {message}"
        );
    }

    /// The refusal says a destination was refused and nothing else. A
    /// message carrying the address, the port, or the resolver's own
    /// wording would answer the question the probe was asking.
    #[tokio::test]
    async fn security_boundary_the_refusal_names_no_address() {
        let fetcher = ReqwestFederationFetcher::new();
        let err = fetcher
            .fetch_entity_configuration("https://192.168.13.37:9443")
            .await
            .expect_err("a private-range federation peer must be refused");
        let message = err.to_string();
        assert!(message.ends_with(REFUSED_SUFFIX), "{message}");
        assert!(!message.contains("192.168"), "{message}");
        assert!(!message.contains("9443"), "{message}");
        assert!(!message.contains("private"), "{message}");
        assert!(message.len() <= 160, "{message}");
    }

    /// `EgressPurpose::Federation` is the key the fetcher reads and the
    /// key `arm_egress_gates_from_config` files an `egress.federation:`
    /// block under. The registry is an exact-key map with no fallback,
    /// so a label change on one side and not the other silently returns
    /// the fetcher to the unconfigured contract.
    #[test]
    fn the_federation_egress_purpose_has_its_own_label() {
        assert_eq!(EgressPurpose::Federation.as_label(), "federation");
    }

    /// Malformed attacker text can contain log delimiters and secrets;
    /// neither is copied into the bounded operator-facing error.
    #[test]
    fn security_boundary_fetcher_sanitizes_malformed_url_errors() {
        let err = ReqwestFederationFetcher::well_known_url("not a url\nFETCH_SECRET_CANARY")
            .expect_err("malformed entity IDs must be rejected");
        let message = err.to_string();
        assert!(!message.contains("FETCH_SECRET_CANARY"), "{message}");
        assert!(!message.contains('\n'), "{message}");
        assert!(
            message.len() <= 160,
            "fetch error must stay bounded: {message}"
        );
    }
}
