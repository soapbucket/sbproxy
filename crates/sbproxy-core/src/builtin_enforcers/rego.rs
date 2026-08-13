// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! [`PolicyEnforcer`] for `policy: rego`.
//!
//! The Rego twin of the `expression` enforcer, and deliberately a thin
//! one. Both call the same `decision_views` and `build_policy_context`
//! helpers, so a request looks the same to both engines and an operator
//! porting a decision between them is changing syntax rather than
//! vocabulary. (Neither is linked here: `decision_views` is private to
//! this crate, and a public doc cannot link a private item.)
//!
//! Failure is a denial. A rule that errors, names nothing, or returns a
//! document has not proved the request is allowed, which is the same
//! posture `expression` takes on a runtime error.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::rego::RegoPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Adapts [`RegoPolicy`] to the [`PolicyEnforcer`] trait surface.
pub struct RegoEnforcer(pub Arc<RegoPolicy>);

impl PolicyEnforcer for RegoEnforcer {
    fn policy_type(&self) -> &'static str {
        "rego"
    }

    fn enforce(
        &self,
        req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        let policy = Arc::clone(&self.0);
        let Some(ctx) = ctx.downcast_mut::<RequestContext>() else {
            return Box::pin(async move {
                Ok(PolicyDecision::Deny {
                    status: 500,
                    message: "rego enforcer: bad context".to_owned(),
                })
            });
        };

        let method = req.method().as_str().to_owned();
        let path = req.uri().path().to_owned();
        let query = req.uri().query().map(std::borrow::ToOwned::to_owned);
        let headers = req.headers().clone();
        let client_ip = ctx.client_ip.map(|ip| ip.to_string());
        let hostname = ctx.hostname.to_string();

        let views = super::expression::decision_views(ctx);
        let cel_ctx = sbproxy_modules::policy::expression::build_policy_context(
            &method,
            &path,
            &headers,
            query.as_deref(),
            client_ip.as_deref(),
            &hostname,
            views,
        );

        // Evaluation is synchronous and short. Doing it here rather than
        // inside the async block keeps the borrow of `ctx` out of the
        // future, which is what lets the deny path stamp
        // `deny_policy_type` before returning.
        let allowed = policy.evaluate(&cel_ctx);
        if !allowed {
            ctx.deny_policy_type = Some("rego");
            let status = policy.deny_status;
            let message = policy.deny_message.clone();
            return Box::pin(async move { Ok(PolicyDecision::Deny { status, message }) });
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DENY_POST: &str = r#"
package sbproxy

default allow := false

allow if {
    input.request.method == "GET"
}
"#;

    fn enforcer(module: &str) -> RegoEnforcer {
        RegoEnforcer(Arc::new(
            RegoPolicy::from_config(serde_json::json!({ "module": module }))
                .expect("policy compiles"),
        ))
    }

    #[tokio::test]
    async fn a_denied_request_carries_the_rego_policy_type() {
        // The deny path has to name itself, because the response
        // handler keys on `deny_policy_type` to emit the standard
        // refusal rather than a generic one.
        let enforcer = enforcer(DENY_POST);
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("/v1/chat")
            .body(Bytes::new())
            .expect("request builds");
        let mut ctx = RequestContext::new();
        let decision = enforcer
            .enforce(&req, &mut ctx as &mut dyn std::any::Any)
            .await
            .expect("enforce succeeds");
        assert!(matches!(decision, PolicyDecision::Deny { status: 403, .. }));
        assert_eq!(ctx.deny_policy_type, Some("rego"));
    }

    #[tokio::test]
    async fn an_allowed_request_passes_through() {
        let enforcer = enforcer(DENY_POST);
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri("/v1/chat")
            .body(Bytes::new())
            .expect("request builds");
        let mut ctx = RequestContext::new();
        let decision = enforcer
            .enforce(&req, &mut ctx as &mut dyn std::any::Any)
            .await
            .expect("enforce succeeds");
        assert!(matches!(decision, PolicyDecision::Allow));
        assert_eq!(ctx.deny_policy_type, None);
    }

    #[tokio::test]
    async fn a_wrong_context_carrier_denies_rather_than_admits() {
        let enforcer = enforcer(DENY_POST);
        let req = http::Request::builder()
            .uri("/")
            .body(Bytes::new())
            .expect("request builds");
        let mut not_a_context = 0_u8;
        let decision = enforcer
            .enforce(&req, &mut not_a_context as &mut dyn std::any::Any)
            .await
            .expect("enforce succeeds");
        assert!(matches!(decision, PolicyDecision::Deny { status: 500, .. }));
    }
}
