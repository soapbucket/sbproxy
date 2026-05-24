//! Newtype wrapper enforcer for the `Policy::A2A`
//! variant.
//!
//! Lifts the body of the `Policy::A2A(p)` arm that lived in
//! `crate::server::check_policies` into a
//! [`sbproxy_plugin::PolicyEnforcer`] impl. Reads the inbound
//! agent-to-agent envelope from `RequestContext::a2a` and runs the
//! per-hop checks (chain depth, cycle detection, callee allowlist,
//! caller deny). Emits per-hop metrics regardless of verdict.
//!
//! Per-deny-reason labels (one per refusal class):
//!
//! - `"a2a_chain_depth_exceeded"`
//! - `"a2a_cycle_detected"`
//! - `"a2a_callee_not_allowed"`
//! - `"a2a_caller_denied"`
//! - `"a2a"` (catch-all for any future variant)

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::A2APolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`A2APolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct A2AEnforcer(pub Arc<A2APolicy>);

impl PolicyEnforcer for A2AEnforcer {
    fn policy_type(&self) -> &'static str {
        "a2a"
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
                        message: "a2a enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let a2a_ctx = match ctx.a2a.clone() {
            Some(c) => c,
            None => return Box::pin(async move { Ok(PolicyDecision::Allow) }),
        };
        let route = ctx.hostname.to_string();
        let spec_label = a2a_ctx.spec.as_label();
        let callable_endpoint = req.uri().path().to_string();
        let decision = policy.evaluate(&a2a_ctx, &callable_endpoint);
        sbproxy_observe::metrics::record_a2a_chain_depth(&route, spec_label, a2a_ctx.chain_depth);
        if decision.is_allow() {
            sbproxy_observe::metrics::record_a2a_hop(&route, spec_label, "allow");
            return Box::pin(async move { Ok(PolicyDecision::Allow) });
        }
        let reason = decision.reason_label();
        sbproxy_observe::metrics::record_a2a_hop(&route, spec_label, &format!("deny:{reason}"));
        sbproxy_observe::metrics::record_a2a_denied(&route, reason);
        let body = decision.json_body();
        let status = decision.http_status();
        ctx.a2a_denial_body = Some(body.clone());
        let policy_type: &'static str = match reason {
            "depth" => "a2a_chain_depth_exceeded",
            "cycle" => "a2a_cycle_detected",
            "callee_not_allowed" => "a2a_callee_not_allowed",
            "caller_denied" => "a2a_caller_denied",
            _ => "a2a",
        };
        ctx.deny_policy_type = Some(policy_type);
        Box::pin(async move {
            Ok(PolicyDecision::Deny {
                status,
                message: body,
            })
        })
    }
}
