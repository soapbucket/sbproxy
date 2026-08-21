//! Newtype wrapper enforcer for the
//! `Policy::BodyThreatProtection` variant.
//!
//! The structural scan needs the complete body, so the policy-phase
//! work is only the content-type gate: when the request declares a
//! JSON- or XML-family `Content-Type` and that family's checks are
//! enabled, mark the context so `request_body_filter` buffers the
//! body for the end-of-stream scan. Any other content type (or an
//! absent one) streams through unbuffered and unscanned; a
//! wrong-content-type body misses rather than misparses, and the
//! policy never costs memory for a body it will not read
//! (mirroring the `prompt_injection_v2` opt-in buffering rule,
//! WOR-2137).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::BodyThreatProtectionPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`BodyThreatProtectionPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct BodyThreatProtectionEnforcer(pub Arc<BodyThreatProtectionPolicy>);

impl PolicyEnforcer for BodyThreatProtectionEnforcer {
    fn policy_type(&self) -> &'static str {
        "body_threat_protection"
    }

    fn enforce(
        &self,
        req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        if let Some(c) = ctx.downcast_mut::<RequestContext>() {
            let content_type = req
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok());
            if self.0.wants_body(content_type) {
                c.validate_request_body = true;
            }
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforce(policy: BodyThreatProtectionPolicy, content_type: Option<&str>) -> RequestContext {
        let mut ctx = RequestContext::new();
        let enforcer = BodyThreatProtectionEnforcer(Arc::new(policy));
        let mut builder = http::Request::builder().method("POST").uri("/orders");
        if let Some(ct) = content_type {
            builder = builder.header(http::header::CONTENT_TYPE, ct);
        }
        let req = builder.body(Bytes::new()).expect("request builds");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime builds");
        let decision = rt
            .block_on(enforcer.enforce(&req, &mut ctx))
            .expect("enforce runs");
        assert!(matches!(decision, PolicyDecision::Allow));
        ctx
    }

    fn policy(config: serde_json::Value) -> BodyThreatProtectionPolicy {
        BodyThreatProtectionPolicy::from_config(config).expect("policy compiles")
    }

    #[test]
    fn json_content_type_asks_for_the_request_body() {
        let ctx = enforce(policy(serde_json::json!({})), Some("application/json"));
        assert!(
            ctx.validate_request_body,
            "a JSON-family content type must request buffering for the body scan"
        );
    }

    #[test]
    fn xml_content_type_asks_for_the_request_body() {
        let ctx = enforce(
            policy(serde_json::json!({})),
            Some("application/xml; charset=utf-8"),
        );
        assert!(ctx.validate_request_body);
    }

    #[test]
    fn other_content_types_stream_through_unbuffered() {
        for ct in [Some("text/plain"), Some("multipart/form-data"), None] {
            let ctx = enforce(policy(serde_json::json!({})), ct);
            assert!(
                !ctx.validate_request_body,
                "content type {ct:?} must pass untouched, not buffer"
            );
        }
    }

    #[test]
    fn disabled_family_does_not_buffer() {
        let ctx = enforce(
            policy(serde_json::json!({ "json": { "enabled": false } })),
            Some("application/json"),
        );
        assert!(
            !ctx.validate_request_body,
            "a switched-off family must not cost body buffering"
        );
    }
}
