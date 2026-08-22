//! Prometheus metrics for the MCP OAuth 2.1 broker.
//!
//! Every family here carries the sanctioned `sbproxy_mcp_gateway_`
//! prefix and registers into `prometheus::default_registry()`, the
//! same global registry the rest of the workspace scrapes from. A
//! deployment that mounts this crate's router inside an existing
//! `sbproxy` process (or any other binary that already exposes a
//! Prometheus `/metrics` endpoint via the `prometheus` crate) gets
//! these families for free; a standalone broker binary should expose
//! `prometheus::TextEncoder` over its own `/metrics` route (see
//! `examples/standalone_broker.rs`).
//!
//! `docs/mcp-oauth-gateway.md` documents each family and the
//! `dashboards/grafana/sbproxy-mcp-oauth-gateway.json` panel that
//! draws it; `scripts/check-metric-visibility.sh` is the gate that
//! keeps that pairing honest.

use std::sync::LazyLock;

use prometheus::{register_int_counter_vec, register_int_gauge, IntCounterVec, IntGauge};

/// `/authorize` outcomes, labeled by `outcome`: `redirected` (2xx/3xx,
/// the request cleared every check and the broker sent the user agent
/// onward), `rejected` (4xx, a validation or binding check failed),
/// or `error` (5xx). The label set stays this coarse because deriving
/// the specific OAuth `error` code would mean buffering and parsing
/// every response body in the metrics middleware; the per-rejection
/// reason is already in the structured log line
/// (`event = "mcp_oauth_authorize_decision"`) that
/// `docs/mcp-oauth-gateway.md` documents as the audit trail for this
/// decision.
pub static AUTHORIZE_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "sbproxy_mcp_gateway_authorize_requests_total",
        "MCP OAuth broker /authorize outcomes by result.",
        &["outcome"]
    )
    .expect("sbproxy_mcp_gateway_authorize_requests_total registers exactly once")
});

/// `/token` outcomes, labeled by `outcome`: `issued` (2xx), `rejected`
/// (4xx), or `upstream_error` (5xx, including the broker's own
/// misconfiguration responses). See [`AUTHORIZE_REQUESTS_TOTAL`] for
/// why this stays a single coarse label rather than one per grant type
/// or OAuth error code.
pub static TOKEN_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "sbproxy_mcp_gateway_token_requests_total",
        "MCP OAuth broker /token outcomes by result.",
        &["outcome"]
    )
    .expect("sbproxy_mcp_gateway_token_requests_total registers exactly once")
});

/// DPoP proof verification outcomes, labeled by `outcome` (`verified`,
/// `rejected`, `replay`).
pub static DPOP_PROOFS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "sbproxy_mcp_gateway_dpop_proofs_total",
        "RFC 9449 DPoP proof verification outcomes.",
        &["outcome"]
    )
    .expect("sbproxy_mcp_gateway_dpop_proofs_total registers exactly once")
});

/// `/revoke` and `/introspect` calls, labeled by `endpoint`
/// (`revoke`, `introspect`) and `outcome` (`ok`, `unsupported`,
/// `upstream_error`).
pub static RFC7009_RFC7662_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "sbproxy_mcp_gateway_revocation_introspection_requests_total",
        "MCP OAuth broker /revoke and /introspect outcomes.",
        &["endpoint", "outcome"]
    )
    .expect("sbproxy_mcp_gateway_revocation_introspection_requests_total registers exactly once")
});

/// Sessions currently held by whichever `SessionStore` the deployment
/// wired up, sampled at read time. Only [`crate::session::InMemorySessionStore`]
/// can report this cheaply (it is a `HashMap` behind a lock already
/// walked on every `put`); the storage-backed `RedisSessionStore` does
/// not expose a count without an expensive `SCAN`, so this stays a
/// gauge callers update explicitly rather than one this module derives
/// on its own.
pub static SESSIONS_ACTIVE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "sbproxy_mcp_gateway_sessions_active",
        "In-flight (not yet consumed) authorization sessions held by the in-memory session store."
    )
    .expect("sbproxy_mcp_gateway_sessions_active registers exactly once")
});

/// Record an `/authorize` decision outcome.
pub fn record_authorize(outcome: &str) {
    AUTHORIZE_REQUESTS_TOTAL.with_label_values(&[outcome]).inc();
}

/// Record a `/token` decision outcome.
pub fn record_token(outcome: &str) {
    TOKEN_REQUESTS_TOTAL.with_label_values(&[outcome]).inc();
}

/// Record a DPoP proof verification outcome.
pub fn record_dpop(outcome: &str) {
    DPOP_PROOFS_TOTAL.with_label_values(&[outcome]).inc();
}

/// Record a `/revoke` or `/introspect` outcome.
pub fn record_revocation_or_introspection(endpoint: &str, outcome: &str) {
    RFC7009_RFC7662_REQUESTS_TOTAL
        .with_label_values(&[endpoint, outcome])
        .inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every family must register without panicking and accept a
    /// write; this is what actually proves the metric is live rather
    /// than merely declared (the property
    /// `scripts/check-metric-visibility.sh` cannot see from source
    /// alone).
    #[test]
    fn every_family_accepts_a_write() {
        record_authorize("redirected");
        record_authorize("rejected");
        record_token("issued");
        record_dpop("verified");
        record_revocation_or_introspection("revoke", "ok");
        SESSIONS_ACTIVE.set(3);
        assert_eq!(SESSIONS_ACTIVE.get(), 3);
    }
}
