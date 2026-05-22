//! WOR-201 PR 1c.1: newtype wrapper enforcer for the
//! `Policy::ExposedCreds` variant.
//!
//! Lifts the body of the `Policy::ExposedCreds(p)` arm that
//! lived in `crate::server::check_policies` into a
//! [`sbproxy_plugin::PolicyEnforcer`] impl. The wrapper inspects
//! the inbound `Authorization: Basic` header against the
//! configured exposure list and either tags the upstream request
//! (default) or denies the call (when the policy is configured
//! with `action: block`).
//!
//! Per-deny-reason label: `"exposed_credentials"`. The Tag-action
//! path stamps a header onto [`RequestContext::trust_headers`]
//! and falls through to `Allow`; the Block-action path returns
//! `Deny` with the same status / body / label the previous arm
//! emitted.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::{ExposedCredsAction, ExposedCredsPolicy, ExposedCredsResult};
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`ExposedCredsPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct ExposedCredsEnforcer(pub Arc<ExposedCredsPolicy>);

impl PolicyEnforcer for ExposedCredsEnforcer {
    fn policy_type(&self) -> &'static str {
        "exposed_credentials"
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
                        message: "exposed_credentials enforcer: bad context".to_string(),
                    })
                });
            }
        };

        // The check operates on header views only; clone is cheap
        // because `HeaderMap` shares its backing buffer.
        let result = policy.check(req.headers());
        let ExposedCredsResult::Hit { reason } = result else {
            return Box::pin(async move { Ok(PolicyDecision::Allow) });
        };
        match policy.action() {
            ExposedCredsAction::Block => {
                ctx.deny_policy_type = Some("exposed_credentials");
                Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 403,
                        message: "credential flagged as exposed".to_string(),
                    })
                })
            }
            ExposedCredsAction::Tag => {
                let entry = (policy.header_name().to_string(), reason.to_string());
                match ctx.trust_headers.as_mut() {
                    Some(v) => v.push(entry),
                    None => ctx.trust_headers = Some(vec![entry]),
                }
                Box::pin(async move { Ok(PolicyDecision::Allow) })
            }
        }
    }
}
