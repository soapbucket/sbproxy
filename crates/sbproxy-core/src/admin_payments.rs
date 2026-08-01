//! Settlement status and the reconciliation trigger, on the admin listener.
//!
//! Two routes, both authenticated by the operator gate the rest of the admin
//! surface sits behind:
//!
//! | Route | Method | Does |
//! | --- | --- | --- |
//! | `/admin/payments/status` | GET | Reports schema version, registered rails, and what the recovery worker has done |
//! | `/admin/payments/reconcile` | POST | Asks providers what happened to outstanding attempts |
//!
//! # There is no button that marks a payment paid
//!
//! Reconciliation reaches exactly one adapter method, the status query. It
//! cannot confirm, capture, settle, or retry, and there is no counterpart
//! endpoint that writes a receipt. An operator who believes a payment settled
//! and whose provider disagrees has a dispute with that provider, not a
//! control in this proxy. That is the whole reason this surface is narrow:
//! the durable ledger is the authority on whether a request was paid for, and
//! an admin override would make it merely an opinion.
//!
//! # What these responses may contain
//!
//! Counts, rails, operations, and verdicts. No intent id, quote id, tenant,
//! provider reference, payer, or amount. The
//! [`ReconciliationReport`](crate::billing_runtime::ReconciliationReport) type
//! carries none of those by construction, so a response built from it cannot
//! leak one even by accident.

#[cfg(feature = "payments")]
use crate::billing_runtime::ReconciliationReport;

/// Content type on every response here.
const JSON: &str = "application/json";

/// Status code, content type, body.
type Resp = (u16, &'static str, String);

/// Largest number of outstanding attempts one trigger may claim.
///
/// Bounded so an operator cannot turn one request into an unbounded run of
/// provider calls. The worker sweeps continuously anyway; this is for
/// answering "what happened to that payment" now rather than in a second.
const MAX_RECONCILE_LIMIT: u32 = 100;

/// Default claim size when the caller does not ask for one.
const DEFAULT_RECONCILE_LIMIT: u32 = 32;

/// Handle the payment admin routes, or return `None` to fall through.
pub fn dispatch(method: &str, path: &str) -> Option<Resp> {
    let path_only = path.split('?').next().unwrap_or(path);
    match path_only {
        "/admin/payments/status" => {
            if !method.eq_ignore_ascii_case("GET") {
                return Some(method_not_allowed("GET"));
            }
            Some(status_response())
        }
        "/admin/payments/reconcile" => {
            if !method.eq_ignore_ascii_case("POST") {
                return Some(method_not_allowed("POST"));
            }
            Some(reconcile_response(parse_limit(path)))
        }
        _ => None,
    }
}

/// Reads `?limit=` and clamps it into range.
///
/// An unparseable or absent value takes the default rather than failing: the
/// caller asked to reconcile, and the limit is a bound on effort, not part of
/// what they were asking for.
fn parse_limit(path: &str) -> u32 {
    path.split_once('?')
        .map(|(_, query)| query)
        .and_then(|query| {
            query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(key, _)| *key == "limit")
                .map(|(_, value)| value.to_string())
        })
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(DEFAULT_RECONCILE_LIMIT)
        .clamp(1, MAX_RECONCILE_LIMIT)
}

/// The bounded status snapshot.
#[cfg(feature = "payments")]
fn status_response() -> Resp {
    let pipeline = crate::reload::current_pipeline();
    let Some(payments) = pipeline.payments.as_ref() else {
        return not_configured();
    };
    let status = payments.status();
    let rails: Vec<&str> = status.rails.iter().map(|rail| rail.as_str()).collect();
    let body = serde_json::json!({
        "configured": true,
        "schema_version": status.schema_version,
        "rails": rails,
        "worker": {
            "ticks": status.worker.ticks,
            "challenges_expired": status.worker.challenges_expired,
            "leases_returned_to_retry_wait": status.worker.leases_returned_to_retry_wait,
            "leases_moved_to_needs_reconciliation": status.worker.leases_moved_to_needs_reconciliation,
            "reconciliations_succeeded": status.worker.reconciliations_succeeded,
            "reconciliations_unresolved": status.worker.reconciliations_unresolved,
            "clean_shutdown": status.worker.clean_shutdown,
        },
    });
    (200, JSON, body.to_string())
}

/// The reconciliation trigger.
#[cfg(feature = "payments")]
fn reconcile_response(limit: u32) -> Resp {
    let pipeline = crate::reload::current_pipeline();
    let Some(payments) = pipeline.payments.as_ref() else {
        return not_configured();
    };
    match payments.reconcile_now_blocking(limit) {
        Ok(reports) => (200, JSON, reconcile_body(&reports)),
        Err(error) => (
            503,
            JSON,
            serde_json::json!({ "error": error.to_string() }).to_string(),
        ),
    }
}

/// Renders the verdicts, grouped so the shape is stable when nothing moved.
#[cfg(feature = "payments")]
fn reconcile_body(reports: &[ReconciliationReport]) -> String {
    let entries: Vec<serde_json::Value> = reports
        .iter()
        .map(|report| {
            serde_json::json!({
                "rail": report.rail.as_str(),
                "operation": report.operation.as_str(),
                "verdict": report.verdict.as_str(),
            })
        })
        .collect();
    serde_json::json!({
        "claimed": reports.len(),
        "results": entries,
    })
    .to_string()
}

/// Settlement is compiled in but this configuration did not enable it.
#[cfg(feature = "payments")]
fn not_configured() -> Resp {
    (
        404,
        JSON,
        r#"{"configured":false,"error":"proxy.payments is not configured on this node"}"#
            .to_string(),
    )
}

/// Settlement is not compiled into this build.
///
/// A 404 rather than a 501, because from an operator's side the resource
/// genuinely does not exist here: this binary has no settlement store to
/// report on. The message names the feature so they know what to rebuild
/// with.
#[cfg(not(feature = "payments"))]
fn status_response() -> Resp {
    not_compiled()
}

#[cfg(not(feature = "payments"))]
fn reconcile_response(_limit: u32) -> Resp {
    not_compiled()
}

#[cfg(not(feature = "payments"))]
fn not_compiled() -> Resp {
    (
        404,
        JSON,
        r#"{"configured":false,"error":"this binary was built without the `payments` cargo feature"}"#
            .to_string(),
    )
}

/// The wrong verb on a real route.
fn method_not_allowed(expected: &str) -> Resp {
    (
        405,
        JSON,
        serde_json::json!({
            "error": format!("method not allowed; use {expected}"),
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_paths_fall_through() {
        assert!(dispatch("GET", "/admin/payments").is_none());
        assert!(dispatch("GET", "/admin/other").is_none());
    }

    #[test]
    fn verbs_are_enforced() {
        let (status, _, _) = dispatch("POST", "/admin/payments/status").expect("route exists");
        assert_eq!(status, 405);
        let (status, _, _) = dispatch("GET", "/admin/payments/reconcile").expect("route exists");
        assert_eq!(status, 405);
    }

    #[test]
    fn the_reconcile_limit_is_bounded() {
        assert_eq!(parse_limit("/admin/payments/reconcile"), 32);
        assert_eq!(parse_limit("/admin/payments/reconcile?limit=5"), 5);
        assert_eq!(
            parse_limit("/admin/payments/reconcile?limit=99999"),
            MAX_RECONCILE_LIMIT,
            "one request must not become an unbounded run of provider calls",
        );
        assert_eq!(parse_limit("/admin/payments/reconcile?limit=0"), 1);
        assert_eq!(parse_limit("/admin/payments/reconcile?limit=nonsense"), 32);
    }

    /// There is no route that marks an attempt settled.
    #[test]
    fn no_route_can_force_a_payment_through() {
        for path in [
            "/admin/payments/settle",
            "/admin/payments/succeed",
            "/admin/payments/force",
            "/admin/payments/mark-paid",
        ] {
            assert!(
                dispatch("POST", path).is_none(),
                "{path} must not be a route",
            );
        }
    }
}
