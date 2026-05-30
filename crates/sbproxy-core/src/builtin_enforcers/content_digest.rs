//! Newtype wrapper enforcer for the `Policy::ContentDigest` variant
//! (WOR-805).
//!
//! Lifts the body of the `Policy::ContentDigest(_)` arm. The actual
//! verification runs in `request_body_filter` once the body is fully
//! buffered; the policy-phase work is just to mark the context so the
//! body filter knows to accumulate. Same shape as the
//! [`super::request_validator::RequestValidatorEnforcer`] companion.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::ContentDigestPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`ContentDigestPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct ContentDigestEnforcer(pub Arc<ContentDigestPolicy>);

impl PolicyEnforcer for ContentDigestEnforcer {
    fn policy_type(&self) -> &'static str {
        "content_digest"
    }

    fn enforce(
        &self,
        _req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        if let Some(c) = ctx.downcast_mut::<RequestContext>() {
            c.validate_request_body = true;
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}
