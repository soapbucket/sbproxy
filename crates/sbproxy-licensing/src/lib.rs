//! IAB Content Authorization Marketplace Protocol (CoMP) bridge.
//!
//! This crate implements the parts of `sbproxy-enterprise-licensing`
//! that have no OSS equivalent: the CoMP marketplace bridge (manifest
//! discovery, signed quotes, and a redeem-to-license-token endpoint so
//! AI buyers can integrate against a publisher catalog without
//! writing publisher-specific code), plus the shared Ed25519 key
//! manager and per-id revocation store behind it.
//!
//! ## What moved, and why
//!
//! The enterprise source this crate was ported from also shipped an
//! OLP issuer and a CAP issuer. Neither is here:
//!
//! * **CAP issuance** duplicates nothing OSS-side by itself (the OSS
//!   `sbproxy-modules::auth::cap` module is a verifier, not an
//!   issuer), but its handler is inseparable from enterprise-only
//!   collaborators (an `AgentVerifier` wired to a resolver chain, a
//!   per-tenant `PolicyStore`) that have no OSS-shaped equivalent to
//!   plug into, and the parent epic's own disposition scopes this
//!   port to OLP and CoMP only. Porting it here would have shipped a
//!   standalone, unwired issuer nothing else in the workspace talks
//!   to.
//! * **OLP issuance and verification** duplicates a materially more
//!   complete OSS implementation outright:
//!   `crates/sbproxy-modules/src/olp.rs` plus
//!   `crates/sbproxy-core/src/server/request_phase.rs`'s
//!   `/.well-known/olp/{token,key,introspect,revoke}` wiring already
//!   mint, verify, publish JWKS for, introspect (RFC 7662), and
//!   revoke (RFC 7009) OLP license tokens, live in the request path,
//!   config-driven, with three revocation backends. The enterprise
//!   crate's own `olp::OlpIssuer` / `OlpVerifier` covered only mint
//!   and verify. Porting it would have shipped a second, disconnected,
//!   strictly less capable OLP surface.
//!
//! Because CoMP's whole job is "hand a paying buyer a license token,"
//! [`comp::olp_bridge`] mints tokens in the *same wire format* the OSS
//! OLP issuer already emits (same claim names, same JWS `typ`), so an
//! operator who points this bridge's signing key at the value they
//! already configured on `origins.<host>.olp.signing_key` gets a token
//! their own deployment's `/.well-known/olp/introspect` can verify.
//! See [`comp::olp_bridge`] for the compatibility contract and why it
//! is a wire-format match rather than a `sbproxy-modules` dependency.
//!
//! ## Storage
//!
//! Per-jti / per-quote revocation defaults to in-memory
//! ([`revocation::InMemoryRevocation`]); [`revocation::RedisRevocation`]
//! is an already-optional adapter over the workspace `EphemeralKv`
//! trait for deployments that need a shared denylist. No Postgres,
//! ClickHouse, or NATS dependency exists anywhere in this crate.
//!
//! See `docs/comp-marketplace.md` for the operator-facing guide and
//! `examples/standalone_marketplace.rs` for a runnable deployment.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Operator-facing `/admin/status` JSON surface.
pub mod admin;
/// IAB CoMP marketplace bridge: manifest, quote, redeem.
pub mod comp;
/// Errors raised across this crate.
pub mod error;
/// Shared Ed25519 key manager for CoMP quote signatures.
pub mod keys;
/// Prometheus metrics for this crate.
pub mod metrics;
/// Per-id (license `jti` / CoMP `quote_id`) revocation store.
pub mod revocation;

pub use error::LicensingError;

use std::sync::Arc;

use axum::Router;

/// Build a standalone axum [`Router`] mounting the CoMP well-known
/// endpoints and the `/admin/status` operator surface.
///
/// A deployment that already has its own router can instead call
/// [`comp::comp_router`] directly and skip this helper; `router`
/// exists so this crate is runnable on its own (see
/// `examples/standalone_marketplace.rs`) and so its own tests
/// exercise the same route wiring an embedding host would use.
pub fn router(marketplace: Arc<comp::CompMarketplace>, keys: Arc<keys::KeyManager>) -> Router {
    let comp = comp::comp_router(marketplace.clone());
    let admin = Router::new()
        .route("/admin/status", axum::routing::get(admin::status))
        .with_state((marketplace, keys));
    comp.merge(admin)
}
