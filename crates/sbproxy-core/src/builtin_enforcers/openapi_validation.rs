//! Newtype wrapper enforcer for the
//! `Policy::OpenApiValidation` variant.
//!
//! Lifts the body of the `Policy::OpenApiValidation(_)` arm. Same
//! shape as `RequestValidator`: actual validation runs in
//! `request_body_filter`; the policy-phase work is just to set the
//! body-accumulation flag on the request context.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::OpenApiValidationPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`OpenApiValidationPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct OpenApiValidationEnforcer(pub Arc<OpenApiValidationPolicy>);

impl PolicyEnforcer for OpenApiValidationEnforcer {
    fn policy_type(&self) -> &'static str {
        "openapi_validation"
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
