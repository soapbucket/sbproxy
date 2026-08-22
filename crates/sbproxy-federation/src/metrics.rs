//! Prometheus metrics for this crate.
//!
//! Every family carries the sanctioned `sbproxy_federation_` prefix
//! and registers into `prometheus::default_registry()`, the same
//! global registry the rest of the workspace scrapes from. A
//! deployment that mounts [`crate::router`] (or wires
//! [`crate::entity_configuration_handler`] into its own router) gets
//! these families for free the moment it exposes a
//! `prometheus::TextEncoder` `/metrics` route (see
//! `examples/standalone_federation_server.rs`).
//!
//! `docs/federation.md` documents each family and the
//! `dashboards/grafana/sbproxy-federation.json` panel that draws it.
//!
//! Each family is written from the crate's own choke point rather
//! than from a caller: [`crate::verify_entity_statement`],
//! [`crate::verify_trust_mark`], [`crate::TrustChainResolver::resolve`],
//! and [`crate::entity_configuration_handler`] each call their
//! matching `record_*` function directly, so a consumer that calls
//! this crate's public API gets accurate counts without remembering
//! to instrument the call site itself.

use std::sync::LazyLock;

use prometheus::{register_int_counter_vec, register_int_gauge, IntCounterVec, IntGauge};

/// §3 entity-statement JWS verification outcomes, labeled by
/// `outcome` (`verified`, `rejected`). Covers both self-signed
/// Entity Configurations and Subordinate Statements; the two are not
/// split into separate label values because the check
/// [`crate::verify_entity_statement`] runs is identical for both, and
/// the leaf-vs-superior distinction is already in the paired
/// decision-event log line (`event =
/// "federation_entity_statement_decision"`).
pub static ENTITY_STATEMENT_VERIFICATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "sbproxy_federation_entity_statement_verifications_total",
        "OpenID Federation entity-statement JWS verification outcomes.",
        &["outcome"]
    )
    .expect("sbproxy_federation_entity_statement_verifications_total registers exactly once")
});

/// §7 trust-mark JWS verification outcomes, labeled by `outcome`
/// (`verified`, `rejected`).
pub static TRUST_MARK_VERIFICATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "sbproxy_federation_trust_mark_verifications_total",
        "OpenID Federation trust-mark JWS verification outcomes.",
        &["outcome"]
    )
    .expect("sbproxy_federation_trust_mark_verifications_total registers exactly once")
});

/// §9.2 trust-chain resolutions, labeled by `outcome` (`resolved`,
/// `rejected`). One tick per [`crate::TrustChainResolver::resolve`]
/// call, whether driven directly or through
/// [`crate::compose_trust_chain`]'s HTTP walk.
pub static TRUST_CHAIN_RESOLUTIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "sbproxy_federation_trust_chain_resolutions_total",
        "OpenID Federation trust-chain resolution outcomes.",
        &["outcome"]
    )
    .expect("sbproxy_federation_trust_chain_resolutions_total registers exactly once")
});

/// §9 well-known entity-configuration endpoint serves, labeled by
/// `outcome` (`served`, `unavailable`).
pub static WELL_KNOWN_SERVES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "sbproxy_federation_well_known_serves_total",
        "GET /.well-known/openid-federation outcomes.",
        &["outcome"]
    )
    .expect("sbproxy_federation_well_known_serves_total registers exactly once")
});

/// Remaining lifetime, in seconds, of the entity configuration most
/// recently served from the cache, sampled at request time on every
/// successful serve. A value pinned near zero across many samples
/// means the cache is thrashing (the configured `refresh_margin` is
/// too close to `lifetime` for the request rate); a value that never
/// drops means the endpoint has not been polled recently.
pub static WELL_KNOWN_CACHE_REMAINING_SECONDS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "sbproxy_federation_well_known_cache_remaining_seconds",
        "Remaining lifetime of the entity configuration most recently served, in seconds."
    )
    .expect("sbproxy_federation_well_known_cache_remaining_seconds registers exactly once")
});

/// Record an entity-statement verification outcome.
pub fn record_entity_statement_verification(outcome: &str) {
    ENTITY_STATEMENT_VERIFICATIONS_TOTAL
        .with_label_values(&[outcome])
        .inc();
}

/// Record a trust-mark verification outcome.
pub fn record_trust_mark_verification(outcome: &str) {
    TRUST_MARK_VERIFICATIONS_TOTAL
        .with_label_values(&[outcome])
        .inc();
}

/// Record a trust-chain resolution outcome.
pub fn record_trust_chain_resolution(outcome: &str) {
    TRUST_CHAIN_RESOLUTIONS_TOTAL
        .with_label_values(&[outcome])
        .inc();
}

/// Record a well-known endpoint serve outcome.
pub fn record_well_known_serve(outcome: &str) {
    WELL_KNOWN_SERVES_TOTAL.with_label_values(&[outcome]).inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every family must register without panicking and accept a
    /// write; this is what actually proves the metric is live rather
    /// than merely declared.
    #[test]
    fn every_family_accepts_a_write() {
        record_entity_statement_verification("verified");
        record_entity_statement_verification("rejected");
        record_trust_mark_verification("verified");
        record_trust_chain_resolution("resolved");
        record_well_known_serve("served");
        WELL_KNOWN_CACHE_REMAINING_SECONDS.set(3300);
        assert_eq!(WELL_KNOWN_CACHE_REMAINING_SECONDS.get(), 3300);
    }
}
