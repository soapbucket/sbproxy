//! WOR-201 PR 1c.3: newtype wrapper enforcer for the
//! `Policy::Ddos` variant.
//!
//! Lifts the body of the `Policy::Ddos(p)` arm from
//! `crate::server::check_policies`. Reads the client IP from
//! [`RequestContext::client_ip`] and runs the
//! [`sbproxy_modules::DdosPolicy::check`] state machine.
//! On block, synthesises a [`sbproxy_modules::RateLimitInfo`] with
//! the policy's per-second cap so the dispatcher's 429 response
//! handler emits the `Retry-After` header.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use sbproxy_modules::policy::DdosPolicy;
use sbproxy_modules::{DdosCheckResult, RateLimitInfo};
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`DdosPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct DdosEnforcer(pub Arc<DdosPolicy>);

impl PolicyEnforcer for DdosEnforcer {
    fn policy_type(&self) -> &'static str {
        "ddos"
    }

    fn enforce(
        &self,
        _req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>> {
        let policy = Arc::clone(&self.0);
        let ctx = match ctx.downcast_mut::<RequestContext>() {
            Some(c) => c,
            None => {
                return Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 500,
                        message: "ddos enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let Some(ip) = ctx.client_ip else {
            return Box::pin(async move { Ok(PolicyDecision::Allow) });
        };
        match policy.check(ip) {
            DdosCheckResult::Allow => Box::pin(async move { Ok(PolicyDecision::Allow) }),
            DdosCheckResult::Block { retry_after_secs } => {
                ctx.rate_limit_info = Some(RateLimitInfo {
                    allowed: false,
                    limit: policy.requests_per_second as u64,
                    remaining: 0,
                    reset_secs: retry_after_secs,
                    headers_enabled: true,
                    include_retry_after: true,
                });
                ctx.deny_policy_type = Some("ddos");
                Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 429,
                        message: "ddos protection: too many requests".to_string(),
                    })
                })
            }
        }
    }
}
