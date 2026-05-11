//! WOR-201 PR 1c.3: newtype wrapper enforcer for the
//! `Policy::Waf` variant.
//!
//! Lifts the body of the `Policy::Waf(p)` arm. Runs the configured
//! WAF engine against the request URI + headers. On
//! [`sbproxy_modules::WafResult::Blocked`] returns the policy's
//! denial message; on [`sbproxy_modules::WafResult::Error`]
//! routes by the policy's `fail_open` flag (allow with a warning
//! on `true`, deny on `false`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use sbproxy_modules::policy::WafPolicy;
use sbproxy_modules::WafResult;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`WafPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct WafEnforcer(pub Arc<WafPolicy>);

impl PolicyEnforcer for WafEnforcer {
    fn policy_type(&self) -> &'static str {
        "waf"
    }

    fn enforce(
        &self,
        req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>> {
        let policy = Arc::clone(&self.0);
        let ctx = match ctx.downcast_mut::<RequestContext>() {
            Some(c) => c,
            None => {
                return Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 500,
                        message: "waf enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let uri = req.uri().to_string();
        match policy.check_request(&uri, req.headers(), None) {
            WafResult::Clean => Box::pin(async move { Ok(PolicyDecision::Allow) }),
            WafResult::Blocked(msg) => {
                ctx.deny_policy_type = Some("waf");
                Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 403,
                        message: msg,
                    })
                })
            }
            WafResult::Error(err) => {
                if policy.fail_open {
                    tracing::warn!(error = %err, "WAF engine error, fail_open=true, allowing request");
                    Box::pin(async move { Ok(PolicyDecision::Allow) })
                } else {
                    tracing::warn!(error = %err, "WAF engine error, fail_open=false, blocking request");
                    ctx.deny_policy_type = Some("waf");
                    Box::pin(async move {
                        Ok(PolicyDecision::Deny {
                            status: 403,
                            message: "WAF engine error".to_string(),
                        })
                    })
                }
            }
        }
    }
}
