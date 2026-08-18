//! Newtype wrapper enforcer for the `Policy::Dlp`
//! variant.
//!
//! Lifts the body of the `Policy::Dlp(p)` arm that lived in
//! `crate::server::check_policies` into a
//! [`sbproxy_plugin::PolicyEnforcer`] impl. Scans the URI path +
//! query string and the request headers against the configured
//! detector set; on a hit, either denies (Block action) or stamps
//! a trust header on the request context for the upstream to see
//! (Tag action).
//!
//! Per-deny-reason label: `"dlp"`. Single denial shape (`403
//! Forbidden`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::DlpPolicy;
use sbproxy_modules::{DlpAction, DlpScanResult};
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`DlpPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct DlpEnforcer(pub Arc<DlpPolicy>);

impl PolicyEnforcer for DlpEnforcer {
    fn policy_type(&self) -> &'static str {
        "dlp"
    }

    fn enforce(
        &self,
        req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        let policy = Arc::clone(&self.0);
        let ctx = match ctx.downcast_mut::<RequestContext>() {
            Some(c) => c,
            None => {
                return Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 500,
                        message: "dlp enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let path_and_query = req.uri().to_string();
        let scan = policy.scan(&path_and_query, req.headers());
        if let DlpScanResult::Hit {
            detectors,
            spans,
            spans_dropped,
        } = scan
        {
            let detector_csv = detectors.join(",");
            match policy.action() {
                DlpAction::Block => {
                    ctx.deny_policy_type = Some("dlp");
                    let message = dlp_block_message(&detector_csv, spans.len(), spans_dropped);
                    return Box::pin(async move {
                        Ok(PolicyDecision::Deny {
                            status: 403,
                            message,
                        })
                    });
                }
                DlpAction::Tag => {
                    let entry = (policy.header_name().to_string(), detector_csv);
                    match ctx.trust_headers.as_mut() {
                        Some(v) => v.push(entry),
                        None => ctx.trust_headers = Some(vec![entry]),
                    }
                }
            }
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

/// Build the deny message for a `dlp: block` hit (WOR-2492 item 6).
///
/// This message becomes both the `403` response body and, via the
/// generic policy engine's `ctx.deny_reason`, the audit entry an
/// operator reads in the admin console's request log -- DLP's own
/// existing match-reporting surface, extended rather than replaced.
///
/// `span_count`/`spans_dropped` only, never the spans themselves: the
/// caller already has the detector names in `detector_csv`, and this
/// function has no access to (and must never gain access to) the
/// matched text, so there is nothing here that can leak it. The count
/// is the same bounded signal every other detection surface in this
/// change carries -- "there was more than we show" -- without growing
/// the message with an unbounded list of offsets.
fn dlp_block_message(detector_csv: &str, span_count: usize, spans_dropped: usize) -> String {
    let mut message = format!("dlp: detector {detector_csv} matched");
    if span_count > 0 {
        message.push_str(&format!(" ({span_count} span(s)"));
        if spans_dropped > 0 {
            message.push_str(&format!(", {spans_dropped} dropped"));
        }
        message.push(')');
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_message_names_the_detector_and_span_count() {
        let message = dlp_block_message("aws_access", 2, 0);
        assert_eq!(message, "dlp: detector aws_access matched (2 span(s))");
    }

    #[test]
    fn block_message_carries_the_dropped_count_past_the_cap() {
        let message = dlp_block_message("aws_access", 32, 5);
        assert_eq!(
            message,
            "dlp: detector aws_access matched (32 span(s), 5 dropped)"
        );
    }

    #[test]
    fn block_message_with_no_spans_omits_the_parenthetical() {
        // Defensive: `scan()` only returns `Hit` when at least one span
        // exists today, but the message builder must not assume that
        // invariant holds forever.
        let message = dlp_block_message("aws_access", 0, 0);
        assert_eq!(message, "dlp: detector aws_access matched");
    }

    /// Privacy rule: the deny message must never carry the value that
    /// matched, only the detector name and a count.
    #[test]
    fn block_message_never_carries_matched_text() {
        let planted = "AKIAIOSFODNN7EXAMPLE";
        let message = dlp_block_message("aws_access", 1, 0);
        assert!(!message.contains(planted));
    }
}
