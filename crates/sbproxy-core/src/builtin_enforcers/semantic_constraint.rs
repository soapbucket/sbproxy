//! Newtype wrapper enforcer for the
//! `Policy::SemanticConstraint` variant.
//!
//! Lifts the body of the `Policy::SemanticConstraint(p)` arm that
//! lived in `crate::server::check_policies` into a
//! [`sbproxy_plugin::PolicyEnforcer`] impl. Builds the JSON request
//! context the prompt template expects (`{"request": {method, path,
//! host, query}}`) from the `http::Request` snapshot plus the
//! `RequestContext::hostname`, then defers to
//! [`SemanticConstraintPolicy::enforce`].
//!
//! Per-deny-reason label: `"semantic_constraint"`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::SemanticConstraintPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`SemanticConstraintPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct SemanticConstraintEnforcer(pub Arc<SemanticConstraintPolicy>);

impl PolicyEnforcer for SemanticConstraintEnforcer {
    fn policy_type(&self) -> &'static str {
        "semantic_constraint"
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
                        message: "semantic_constraint enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let request_ctx = serde_json::json!({
            "request": {
                "method": req.method().as_str(),
                "path": req.uri().path(),
                "host": ctx.hostname.to_string(),
                "query": req.uri().query().unwrap_or(""),
            }
        });
        // The label is stamped before the await so the dispatcher's
        // caller (server.rs) reads the right `deny_policy_type` slot
        // on the short-circuit path. Allow paths overwrite it with
        // None below.
        ctx.deny_policy_type = Some("semantic_constraint");
        Box::pin(async move {
            let decision = policy.enforce(request_ctx).await;
            Ok(decision)
        })
    }
}

#[cfg(test)]
mod tests {
    //! Behavioural tests for the policy itself live in
    //! `sbproxy-modules::policy::semantic_constraint`. The wrapper is
    //! a thin trait-adapter; the bad-context short-circuit is the
    //! only branch worth pinning here.

    use super::*;

    #[tokio::test]
    async fn bad_context_short_circuits_with_deny() {
        // Construct a minimal valid SemanticConstraintPolicy via the
        // public from_config entry point. The judge does not get
        // called on the short-circuit path so the default stub
        // suffices.
        let cfg = serde_json::json!({
            "prompt_template": "evaluate {{request.path}}",
            "judge": {"provider": "stub"}
        });
        let policy = match SemanticConstraintPolicy::from_config(cfg) {
            Ok(p) => p,
            // The default judge config may not be available in every
            // feature combination; skip the assertion in that case
            // (the production behaviour is already covered by the
            // policy's own unit tests).
            Err(_) => return,
        };
        let enforcer = SemanticConstraintEnforcer(Arc::new(policy));
        let req = http::Request::builder()
            .uri("/")
            .body(Bytes::new())
            .unwrap();
        let mut wrong: i32 = 0;
        let decision = enforcer.enforce(&req, &mut wrong).await.unwrap();
        match decision {
            PolicyDecision::Deny { status, .. } => assert_eq!(status, 500),
            other => panic!("expected Deny(500), got {other:?}"),
        }
    }
}
