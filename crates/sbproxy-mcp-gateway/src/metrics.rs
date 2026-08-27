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
/// worth ending an OAuth request over, so the family is dropped
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
pub static AUTHORIZE_REQUESTS_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_mcp_gateway_authorize_requests_total",
            "MCP OAuth broker /authorize outcomes by result.",
            &["outcome"]
        ),
        "sbproxy_mcp_gateway_authorize_requests_total",
    )
});

/// `/token` outcomes, labeled by `outcome`: `issued` (2xx), `rejected`
/// (4xx), or `upstream_error` (5xx, including the broker's own
/// misconfiguration responses). See [`AUTHORIZE_REQUESTS_TOTAL`] for
/// why this stays a single coarse label rather than one per grant type
/// or OAuth error code.
pub static TOKEN_REQUESTS_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_mcp_gateway_token_requests_total",
            "MCP OAuth broker /token outcomes by result.",
            &["outcome"]
        ),
        "sbproxy_mcp_gateway_token_requests_total",
    )
});

/// DPoP proof verification outcomes, labeled by `outcome`. The emitted
/// vocabulary is `verified`, `nonce_required`, and `rejected`; a replay
/// is one of the things `rejected` covers, because the middleware that
/// writes this family sees the HTTP outcome rather than the
/// `DpopError` variant behind it.
pub static DPOP_PROOFS_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_mcp_gateway_dpop_proofs_total",
            "RFC 9449 DPoP proof verification outcomes.",
            &["outcome"]
        ),
        "sbproxy_mcp_gateway_dpop_proofs_total",
    )
});

/// `/revoke` and `/introspect` calls, labeled by `endpoint`
/// (`revoke`, `introspect`) and `outcome` (`ok`, `error`).
pub static RFC7009_RFC7662_REQUESTS_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_mcp_gateway_revocation_introspection_requests_total",
            "MCP OAuth broker /revoke and /introspect outcomes.",
            &["endpoint", "outcome"]
        ),
        "sbproxy_mcp_gateway_revocation_introspection_requests_total",
    )
});

/// Sessions currently held by [`crate::session::InMemorySessionStore`],
/// written on every `put`, `take`, and purge.
///
/// What it cannot see: a deployment running the storage-backed
/// `RedisSessionStore`. That store cannot report a count without an
/// expensive `SCAN`, so it leaves the gauge alone and the panel reading
/// this family stays at whatever the in-memory store last wrote, which
/// on a Redis-only deployment is zero. Read it as "in-memory sessions",
/// not as "sessions".
pub static SESSIONS_ACTIVE: LazyLock<Option<IntGauge>> = LazyLock::new(|| {
    registered(
        register_int_gauge!(
        "sbproxy_mcp_gateway_sessions_active",
        "In-flight (not yet consumed) authorization sessions held by the in-memory session store."
    ),
        "sbproxy_mcp_gateway_sessions_active",
    )
});

/// Broker enforcement decisions that are not one of the coarse
/// per-endpoint outcomes above, labeled by `surface` and `decision`.
///
/// This is the family an operator alerts on when the broker starts
/// refusing, because each of these decisions is one the proxy made and
/// none of them is visible in an HTTP status code alone:
///
/// | `surface` | `decision` | meaning |
/// | --- | --- | --- |
/// | `authorize` | `cimd_unresolved` | a URL-shaped `client_id` did not resolve to a usable metadata document |
/// | `authorize` | `rate_limited` | the per-window `/authorize` limiter refused |
/// | `authorize` | `session_capacity` | the session store is full, so no new authorization can start |
/// | `par` | `rate_limited` | the same limiter on `/par` |
/// | `resource_server` | `unauthenticated` | a token failed verification and the request got a 401 challenge |
/// | `scope` | `refused` | a verified token lacked the scope the operation maps to |
/// | `scope` | `admitted_unadvertised` | the resource does not advertise that scope, so the check did not apply: a fail-open, counted as one |
/// | `as_metadata` | `stale_fallback` | an upstream metadata refresh failed and the cached document was served past its refresh interval |
/// | `verify` | `csrf_refused` | the device-code consent form failed its origin or nonce check |
pub static DECISIONS_TOTAL: LazyLock<Option<IntCounterVec>> = LazyLock::new(|| {
    registered(
        register_int_counter_vec!(
            "sbproxy_mcp_gateway_decisions_total",
            "MCP OAuth broker enforcement decisions by surface and decision.",
            &["surface", "decision"]
        ),
        "sbproxy_mcp_gateway_decisions_total",
    )
});

/// Record an `/authorize` decision outcome. A no-op when the family
/// did not register; see `registered`.
pub fn record_authorize(outcome: &str) {
    if let Some(family) = AUTHORIZE_REQUESTS_TOTAL.as_ref() {
        family.with_label_values(&[outcome]).inc();
    }
}

/// Record a `/token` decision outcome.
pub fn record_token(outcome: &str) {
    if let Some(family) = TOKEN_REQUESTS_TOTAL.as_ref() {
        family.with_label_values(&[outcome]).inc();
    }
}

/// Record a DPoP proof verification outcome.
pub fn record_dpop(outcome: &str) {
    if let Some(family) = DPOP_PROOFS_TOTAL.as_ref() {
        family.with_label_values(&[outcome]).inc();
    }
}

/// Record the live in-memory authorization-session count.
pub fn record_sessions_active(live: usize) {
    if let Some(family) = SESSIONS_ACTIVE.as_ref() {
        // `usize` is 64-bit on every target the proxy builds for, so
        // this cannot lose a real count; a truncating `as` cast would
        // have turned an implausible one into a negative gauge.
        family.set(i64::try_from(live).unwrap_or(i64::MAX));
    }
}

/// Record a `/revoke` or `/introspect` outcome.
pub fn record_revocation_or_introspection(endpoint: &str, outcome: &str) {
    if let Some(family) = RFC7009_RFC7662_REQUESTS_TOTAL.as_ref() {
        family.with_label_values(&[endpoint, outcome]).inc();
    }
}

/// Record one broker enforcement decision. See [`DECISIONS_TOTAL`] for
/// the label vocabulary.
pub fn record_broker_decision(surface: &str, decision: &str) {
    if let Some(family) = DECISIONS_TOTAL.as_ref() {
        family.with_label_values(&[surface, decision]).inc();
    }
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
        record_broker_decision("resource_server", "unauthenticated");
        record_broker_decision("scope", "refused");
        record_sessions_active(3);
        assert_eq!(
            SESSIONS_ACTIVE
                .as_ref()
                .expect("the gauge registers in a fresh test process")
                .get(),
            3
        );
    }
}
