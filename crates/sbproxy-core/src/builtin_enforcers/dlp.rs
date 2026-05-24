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
        if let DlpScanResult::Hit { detectors } = scan {
            let detector_csv = detectors.join(",");
            match policy.action() {
                DlpAction::Block => {
                    ctx.deny_policy_type = Some("dlp");
                    let message = format!("dlp: detector {detector_csv} matched");
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
