//! Prometheus metrics for the CoMP marketplace bridge.
//!
//! Every family here carries the sanctioned `sbproxy_comp_marketplace_`
//! prefix and registers into `prometheus::default_registry()`, the
//! same global registry the rest of the workspace scrapes from. A
//! deployment that mounts this crate's router inside an existing
//! process that already exposes a Prometheus `/metrics` endpoint gets
//! these families for free; a standalone marketplace binary should
//! expose `prometheus::TextEncoder` over its own `/metrics` route
//! (see `examples/standalone_marketplace.rs`).
//!
//! `docs/comp-marketplace.md` documents each family and the
//! `dashboards/grafana/sbproxy-comp-marketplace.json` panel that draws
//! it. These families are not part of the core proxy's stable-metric
//! surface (`docs/metrics-stability.md`): they only exist, and only
//! ever carry nonzero values, on a deployment that runs this crate.
//!
//! Every family is an `Option`. Registration can only fail when the
//! default registry already holds the name or when a name or label is
//! not a legal Prometheus identifier, and neither is a reason to end a
//! request: see `registered`.

use std::sync::LazyLock;

use prometheus::{register_int_counter_vec, IntCounterVec};

/// Keep a registered family, or drop it and say which one went.
///
/// `register_*!` fails on exactly two things: the default registry
/// already holds this family name, or the name or a label is not a
/// legal Prometheus identifier. Both are build-time mistakes rather
/// than runtime conditions, because every name below is a literal and
/// `LazyLock` runs each registration body once per process. Neither is
/// worth ending a marketplace request over, so the family is dropped
/// instead: the `debug_assert` turns it into a test failure, the
/// warning names the family for whoever is looking at a flat panel,
/// and the matching `record_*` call becomes a no-op.
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

/// `GET /.well-known/iab-comp/manifest.json` serves, labeled by
/// `outcome` (`ok`, `error`).
pub static MANIFEST_SERVES_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_comp_marketplace_manifest_serves_total",
            "CoMP manifest.json serves by outcome.",
            &["outcome"]
        ),
        "sbproxy_comp_marketplace_manifest_serves_total",
    )
});

/// `POST /.well-known/iab-comp/quote` outcomes, labeled by `outcome`
/// (`ok`, `rejected`). The specific rejection reason is in the
/// structured log line (`event = "comp_quote_decision"`) this crate
/// emits alongside the counter, per `docs/comp-marketplace.md`.
pub static QUOTE_REQUESTS_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_comp_marketplace_quote_requests_total",
            "CoMP /quote outcomes by result.",
            &["outcome"]
        ),
        "sbproxy_comp_marketplace_quote_requests_total",
    )
});

/// `POST /.well-known/iab-comp/redeem` outcomes, labeled by `outcome`
/// (`ok`, `rejected`). See [`QUOTE_REQUESTS_TOTAL`] for why the
/// rejection reason itself stays in the decision-event log line
/// (`event = "comp_redeem_decision"`) rather than a second label.
pub static REDEEM_REQUESTS_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_comp_marketplace_redeem_requests_total",
            "CoMP /redeem outcomes by result.",
            &["outcome"]
        ),
        "sbproxy_comp_marketplace_redeem_requests_total",
    )
});

/// Record a manifest serve outcome. A no-op when the family did not
/// register; see `registered`.
pub fn record_manifest_serve(outcome: &str) {
    if let Some(family) = MANIFEST_SERVES_TOTAL.as_ref() {
        family.with_label_values(&[outcome]).inc();
    }
}

/// Record a `/quote` outcome.
pub fn record_quote(outcome: &str) {
    if let Some(family) = QUOTE_REQUESTS_TOTAL.as_ref() {
        family.with_label_values(&[outcome]).inc();
    }
}

/// Record a `/redeem` outcome.
pub fn record_redeem(outcome: &str) {
    if let Some(family) = REDEEM_REQUESTS_TOTAL.as_ref() {
        family.with_label_values(&[outcome]).inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Registering twice (module import + direct use) must not panic;
    /// `LazyLock` guarantees the `register_*!` macro body runs once.
    /// Every family must also be present rather than dropped, which is
    /// what proves the recording functions are not silently no-ops.
    #[test]
    fn metrics_register_without_panicking() {
        record_manifest_serve("ok");
        record_quote("ok");
        record_redeem("ok");
        assert!(MANIFEST_SERVES_TOTAL.is_some());
        assert!(QUOTE_REQUESTS_TOTAL.is_some());
        assert!(REDEEM_REQUESTS_TOTAL.is_some());
    }
}
