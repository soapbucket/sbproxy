//! OpenID Federation 1.0: entity statements, JWS sign / verify, RFC
//! 7638 key thumbprints, a well-known issuer, and a trust-chain
//! resolver.
//!
//! Implements enough of the [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
//! spec for an sbproxy deployment to establish trust with other
//! federated identity providers: an entity signs and publishes a
//! self-signed *Entity Configuration* at
//! `/.well-known/openid-federation` ([`WellKnownIssuer`]); a peer
//! walks that entity's `authority_hints` up to a pinned trust anchor
//! ([`compose_trust_chain`]) and validates every signature along the
//! way ([`TrustChainResolver`]).
//!
//! ## What this crate ships
//!
//! * [`EntityStatement`] / [`EntityStatementClaims`]: the §3 signed
//!   claim set, plus [`sign_entity_statement`] /
//!   [`verify_entity_statement`] for the compact-JWS round trip.
//! * [`FederationKeySet`] + [`jwk_thumbprint_sha256`]: the JWKS
//!   wrapper an entity statement carries under `jwks`, and the RFC
//!   7638 SHA-256 thumbprint helper for deriving a stable `kid`.
//! * [`WellKnownIssuer`]: signs an entity configuration on demand and
//!   caches the compact JWS in memory until shortly before its `exp`,
//!   so concurrent requests don't re-sign per call.
//! * [`TrustAnchor`] / [`TrustAnchorStore`] / [`TrustChainResolver`]:
//!   operator-pinned anchors plus the §9.2 chain validator that walks
//!   anchor-down, checking every signature and linkage in the chain.
//! * [`FederationFetcher`] / [`ReqwestFederationFetcher`] /
//!   [`compose_trust_chain`]: the HTTP half that walks
//!   `authority_hints` from a leaf entity to a configured anchor and
//!   hands the assembled chain to [`TrustChainResolver`].
//! * [`sign_trust_mark`] / [`verify_trust_mark`]: §7 trust marks, a
//!   separate signed assertion from a trust-mark issuer about an
//!   entity, verified against that issuer's own published JWKS.
//! * [`apply_field_policy`] / [`apply_block_policy`] /
//!   [`compose_policies`]: the seven §6.1 metadata-policy operators a
//!   superior can impose on a subordinate's published metadata.
//! * [`entity_configuration_handler`] + [`router`]: an axum handler
//!   for the well-known endpoint and a small router that also mounts
//!   an operator-facing `/admin/status` surface, so this crate can
//!   run standalone or slot into a host router with one line.
//!
//! `TrustAnchorStore` and the well-known issuer's cache are plain
//! in-memory state (a `HashMap` and an `RwLock`, respectively); this
//! crate has no database or cache-service dependency.
//!
//! See `docs/federation.md` for the operator-facing guide and
//! `examples/standalone_federation_server.rs` for a runnable
//! deployment.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Operator-facing `/admin/status` JSON surface.
pub mod admin;
/// Trust-chain composer: walks `authority_hints` from a leaf entity
/// to a configured trust anchor over HTTP.
pub mod chain_composer;
/// §3 Entity Statement model + sign / verify.
pub mod entity_statement;
/// Errors raised across this crate.
pub mod errors;
/// HTTP fetcher for OpenID Federation endpoints.
pub mod http_fetcher;
/// Axum route handler for the §9 well-known endpoint.
pub mod http_route;
/// Federation JWK set + RFC 7638 SHA-256 thumbprint.
pub mod jwk;
/// §6.1 metadata-policy operators.
pub mod metadata_policy;
/// Prometheus metrics for this crate.
pub mod metrics;
/// §9.2 trust-chain validator.
pub mod trust_chain;
/// §7 trust marks.
pub mod trust_marks;
/// §9 well-known entity-configuration issuer.
pub mod well_known;

pub use chain_composer::{compose_trust_chain, DEFAULT_MAX_CHAIN_FETCHES};
pub use entity_statement::{
    peek_claims_pub, sign_entity_statement, verify_entity_statement, EntityMetadata,
    EntityStatement, EntityStatementClaims, FederationEntityMetadata, MetadataPolicy,
};
pub use errors::{FederationError, FederationResult};
pub use http_fetcher::{FederationFetcher, ReqwestFederationFetcher, DEFAULT_FETCH_TIMEOUT};
pub use http_route::entity_configuration_handler;
pub use jwk::{jwk_thumbprint_sha256, FederationKeySet};
pub use metadata_policy::{apply_block_policy, apply_field_policy, compose_policies};
pub use trust_chain::{ResolvedTrustChain, TrustAnchor, TrustAnchorStore, TrustChainResolver};
pub use trust_marks::{
    sign_trust_mark, verify_trust_mark, SignedTrustMark, TrustMarkClaims, TRUST_MARK_CONTENT_TYPE,
    TRUST_MARK_TYP,
};
pub use well_known::{
    EntityConfigurationDocument, FederationServerConfig, SigningKeyConfig, WellKnownIssuer,
};

use std::sync::Arc;

use axum::{routing::get, Router};

/// OIDF media type for an entity statement. JWS header MUST set
/// `typ = "entity-statement+jwt"` per §3 so a downstream verifier can
/// distinguish a federation statement from an ordinary access token.
pub const ENTITY_STATEMENT_TYP: &str = "entity-statement+jwt";

/// HTTP `Content-Type` an OIDF responder MUST stamp on a well-known
/// entity-configuration response (§9). The value matches the JWS
/// `typ` with an `application/` prefix so a peer that content-sniffs
/// the response (in addition to inspecting the JWS header) sees a
/// stable, spec-defined media type.
pub const ENTITY_STATEMENT_CONTENT_TYPE: &str = "application/entity-statement+jwt";

/// OIDF well-known path for an entity configuration. Per §9 an entity
/// publishes its self-signed entity configuration at this URL.
pub const WELL_KNOWN_FEDERATION_PATH: &str = "/.well-known/openid-federation";

/// Build a standalone axum [`Router`] mounting the §9 well-known
/// entity-configuration endpoint and the `/admin/status` operator
/// surface, both keyed off the supplied [`WellKnownIssuer`].
///
/// A deployment that already has its own router (an existing
/// `sbproxy` process, an MCP gateway, a control-plane HTTP server)
/// can instead register [`entity_configuration_handler`] directly at
/// [`WELL_KNOWN_FEDERATION_PATH`] and skip this helper; `router` exists
/// so this crate is runnable on its own (see
/// `examples/standalone_federation_server.rs`) and so its own tests
/// exercise the same route wiring an embedding host would use.
pub fn router(issuer: Arc<WellKnownIssuer>) -> Router {
    Router::new()
        .route(
            WELL_KNOWN_FEDERATION_PATH,
            get(entity_configuration_handler),
        )
        .route("/admin/status", get(admin::status))
        .with_state(issuer)
}
