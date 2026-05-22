//! WOR-201 PR 1c.3: newtype wrapper enforcer for the
//! `Policy::RequestValidator` variant.
//!
//! Lifts the body of the `Policy::RequestValidator(_)` arm. The
//! actual validation runs in `request_body_filter` once the body
//! is fully buffered; the policy-phase work is just to mark the
//! context so the body filter knows to accumulate.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::RequestValidatorPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`RequestValidatorPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct RequestValidatorEnforcer(pub Arc<RequestValidatorPolicy>);

impl PolicyEnforcer for RequestValidatorEnforcer {
    fn policy_type(&self) -> &'static str {
        "request_validator"
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
