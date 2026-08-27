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
//!
//! Every family is an `Option`. Registration can only fail when the
//! default registry already holds the name or when a name or label is
//! not a legal Prometheus identifier, and neither is a reason to end a
//! request: see `registered`.

use std::sync::LazyLock;

use prometheus::{register_int_counter_vec, register_int_gauge, IntCounterVec, IntGauge};

/// Keep a registered family, or drop it and say which one went.
///
/// `register_*!` fails on exactly two things: the default registry
/// already holds this family name, or the name or a label is not a
/// legal Prometheus identifier. Both are build-time mistakes rather
/// than runtime conditions, because every name below is a literal and
/// `LazyLock` runs each registration body once per process. Neither is
/// worth ending a request over, so the family is dropped instead: the
/// `debug_assert` turns it into a test failure, the warning names the
/// family for whoever is looking at a flat panel, and the matching
/// `record_*` call becomes a no-op.
///
/// What this cannot do: bring the family back. A process that lost a
/// registration stays without it until it restarts.
fn registered<M>(result: prometheus::Result<M>, family: &'static str) -> Option<M> {
    match result {
        Ok(metric) => Some(metric),
        Err(error) => {
            debug_assert!(
                false,
                "metric family {family} must register exactly once: {error}"
            );
            tracing::warn!(
                metric = family,
                %error,
                "metric family did not register; every panel reading it stays flat for this process"
            );
            None
        }
    }
}

/// §3 entity-statement JWS verification outcomes, labeled by
/// `outcome` (`verified`, `rejected`). Covers both self-signed
/// Entity Configurations and Subordinate Statements; the two are not
/// split into separate label values because the check
/// [`crate::verify_entity_statement`] runs is identical for both, and
/// the leaf-vs-superior distinction is already in the paired
/// decision-event log line (`event =
/// "federation_entity_statement_decision"`).
pub static ENTITY_STATEMENT_VERIFICATIONS_TOTAL: LazyLock<Option<IntCounterVec>> =
    LazyLock::new(|| {
        registered(
            register_int_counter_vec!(
                "sbproxy_federation_entity_statement_verifications_total",
                "OpenID Federation entity-statement JWS verification outcomes.",
                &["outcome"]
            ),
            "sbproxy_federation_entity_statement_verifications_total",
        )
    });

/// §7 trust-mark JWS verification outcomes, labeled by `outcome`
/// (`verified`, `rejected`).
pub static TRUST_MARK_VERIFICATIONS_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_federation_trust_mark_verifications_total",
            "OpenID Federation trust-mark JWS verification outcomes.",
            &["outcome"]
        ),
        "sbproxy_federation_trust_mark_verifications_total",
    )
});

/// §9.2 trust-chain resolutions, labeled by `outcome` (`resolved`,
/// `rejected`). One tick per [`crate::TrustChainResolver::resolve`]
/// call, whether driven directly or through
/// [`crate::compose_trust_chain`]'s HTTP walk.
pub static TRUST_CHAIN_RESOLUTIONS_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_federation_trust_chain_resolutions_total",
            "OpenID Federation trust-chain resolution outcomes.",
            &["outcome"]
        ),
        "sbproxy_federation_trust_chain_resolutions_total",
    )
});

/// §9 well-known entity-configuration endpoint serves, labeled by
/// `outcome` (`served`, `unavailable`).
pub static WELL_KNOWN_SERVES_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_federation_well_known_serves_total",
            "GET /.well-known/openid-federation outcomes.",
            &["outcome"]
        ),
        "sbproxy_federation_well_known_serves_total",
    )
});

/// Remaining lifetime, in seconds, of the entity configuration most
/// recently served from the cache, sampled at request time on every
/// successful serve. A value pinned near zero across many samples
/// means the cache is thrashing (the configured `refresh_margin` is
/// too close to `lifetime` for the request rate); a value that never
/// drops means the endpoint has not been polled recently.
pub static WELL_KNOWN_CACHE_REMAINING_SECONDS: LazyLock<Option<IntGauge>> = LazyLock::new(|| {
    registered(
        register_int_gauge!(
            "sbproxy_federation_well_known_cache_remaining_seconds",
            "Remaining lifetime of the entity configuration most recently served, in seconds."
        ),
        "sbproxy_federation_well_known_cache_remaining_seconds",
    )
});

/// Request-path peer decisions, labeled by `outcome`.
///
/// `trusted` is a caller whose named entity chained to a pinned anchor
/// and satisfied every required trust mark. `refused` is one that named
/// an entity and did not, or named none while
/// `proxy.federation.peer_trust.required` is on. The two chain-walk
/// families above count the fetch-and-verify work; this one counts the
/// admission decision the proxy actually made, which is the number an
/// operator alerts on.
pub static PEER_DECISIONS_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_federation_peer_decisions_total",
            "OpenID Federation peer-trust admission decisions on the proxy request path.",
            &["outcome"]
        ),
        "sbproxy_federation_peer_decisions_total",
    )
});

/// Record a request-path peer-trust decision.
pub fn record_peer_decision(outcome: &str) {
    if let Some(family) = PEER_DECISIONS_TOTAL.as_ref() {
        family.with_label_values(&[outcome]).inc();
    }
}

/// Record an entity-statement verification outcome. A no-op when the
/// family did not register; see `registered`.
pub fn record_entity_statement_verification(outcome: &str) {
    if let Some(family) = ENTITY_STATEMENT_VERIFICATIONS_TOTAL.as_ref() {
        family.with_label_values(&[outcome]).inc();
    }
}

/// Record a trust-mark verification outcome.
pub fn record_trust_mark_verification(outcome: &str) {
    if let Some(family) = TRUST_MARK_VERIFICATIONS_TOTAL.as_ref() {
        family.with_label_values(&[outcome]).inc();
    }
}

/// Record a trust-chain resolution outcome.
pub fn record_trust_chain_resolution(outcome: &str) {
    if let Some(family) = TRUST_CHAIN_RESOLUTIONS_TOTAL.as_ref() {
        family.with_label_values(&[outcome]).inc();
    }
}

/// Record a well-known endpoint serve outcome.
pub fn record_well_known_serve(outcome: &str) {
    if let Some(family) = WELL_KNOWN_SERVES_TOTAL.as_ref() {
        family.with_label_values(&[outcome]).inc();
    }
}

/// Record the remaining lifetime, in seconds, of the entity
/// configuration just served from the cache.
pub fn record_well_known_cache_remaining(seconds: i64) {
    if let Some(family) = WELL_KNOWN_CACHE_REMAINING_SECONDS.as_ref() {
        family.set(seconds);
    }
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
        record_well_known_cache_remaining(3300);
        record_peer_decision("trusted");
        record_peer_decision("refused");
        assert_eq!(
            WELL_KNOWN_CACHE_REMAINING_SECONDS
                .as_ref()
                .expect("the gauge registers in a fresh test process")
                .get(),
            3300
        );
    }
}
