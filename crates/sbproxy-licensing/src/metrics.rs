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

use std::sync::LazyLock;

use prometheus::{register_int_counter_vec, IntCounterVec};

/// `GET /.well-known/iab-comp/manifest.json` serves, labeled by
/// `outcome` (`ok`, `error`).
pub static MANIFEST_SERVES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "sbproxy_comp_marketplace_manifest_serves_total",
        "CoMP manifest.json serves by outcome.",
        &["outcome"]
    )
    .expect("sbproxy_comp_marketplace_manifest_serves_total registers exactly once")
});

/// `POST /.well-known/iab-comp/quote` outcomes, labeled by `outcome`
/// (`ok`, `rejected`). The specific rejection reason is in the
/// structured log line (`event = "comp_quote_decision"`) this crate
/// emits alongside the counter, per `docs/comp-marketplace.md`.
pub static QUOTE_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "sbproxy_comp_marketplace_quote_requests_total",
        "CoMP /quote outcomes by result.",
        &["outcome"]
    )
    .expect("sbproxy_comp_marketplace_quote_requests_total registers exactly once")
});

/// `POST /.well-known/iab-comp/redeem` outcomes, labeled by `outcome`
/// (`ok`, `rejected`). See [`QUOTE_REQUESTS_TOTAL`] for why the
/// rejection reason itself stays in the decision-event log line
/// (`event = "comp_redeem_decision"`) rather than a second label.
pub static REDEEM_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "sbproxy_comp_marketplace_redeem_requests_total",
        "CoMP /redeem outcomes by result.",
        &["outcome"]
    )
    .expect("sbproxy_comp_marketplace_redeem_requests_total registers exactly once")
});

#[cfg(test)]
mod tests {
    use super::*;

    /// Registering twice (module import + direct use) must not panic;
    /// `LazyLock` guarantees the `register_*!` macro body runs once.
    #[test]
    fn metrics_register_without_panicking() {
        MANIFEST_SERVES_TOTAL.with_label_values(&["ok"]).inc();
        QUOTE_REQUESTS_TOTAL.with_label_values(&["ok"]).inc();
        REDEEM_REQUESTS_TOTAL.with_label_values(&["ok"]).inc();
    }
}
