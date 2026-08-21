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
        req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = sbproxy_plugin::PluginResult<PolicyDecision>> + Send + '_>>
    {
        if let Some(c) = ctx.downcast_mut::<RequestContext>() {
            c.validate_request_body = true;
            // WOR-2565: when the policy's `deprecation_headers:`
            // sub-block is on and the loaded spec marks this request's
            // operation `deprecated: true`, stage the match on the
            // context. The route-settlement gate and both response
            // paths read it from there; a config-scope `deprecation:`
            // block takes precedence over it at resolution time.
            if let Some((template, config)) = self
                .0
                .spec_deprecation(req.method().as_str(), req.uri().path())
            {
                c.openapi_deprecation = Some(crate::context::SpecDeprecation {
                    template: template.to_string(),
                    config,
                });
            }
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(config: serde_json::Value) -> OpenApiValidationEnforcer {
        OpenApiValidationEnforcer(Arc::new(
            OpenApiValidationPolicy::from_config(config).expect("fixture policy compiles"),
        ))
    }

    fn deprecated_spec() -> serde_json::Value {
        serde_json::json!({
            "openapi": "3.0.3",
            "info": {"title": "t", "version": "1"},
            "paths": {
                "/v1/jobs/{id}": {
                    "get": { "deprecated": true }
                },
                "/v2/jobs/{id}": {
                    "get": {}
                }
            }
        })
    }

    async fn enforce_on(enforcer: &OpenApiValidationEnforcer, path: &str) -> RequestContext {
        let req = http::Request::builder()
            .method("GET")
            .uri(path)
            .body(Bytes::new())
            .expect("fixture request");
        let mut ctx = RequestContext::new();
        enforcer
            .enforce(&req, &mut ctx)
            .await
            .expect("enforce succeeds");
        ctx
    }

    // WOR-2565: the seam by name. `spec_deprecation` existing on the
    // policy proves nothing until this enforcer stages its result on
    // the request context, which is the only channel the response
    // path reads.
    #[tokio::test]
    async fn enforcer_stages_spec_deprecation_on_the_context() {
        let enforcer = policy(serde_json::json!({
            "spec": deprecated_spec(),
            "deprecation_headers": {
                "deprecated": "2026-09-01",
                "sunset": "2026-12-31T23:59:59Z",
                "successor": "https://api.example.com/v2/"
            }
        }));

        let hit = enforce_on(&enforcer, "/v1/jobs/42").await;
        let staged = hit
            .openapi_deprecation
            .expect("a spec-deprecated operation must stage the match");
        assert_eq!(staged.template, "/v1/jobs/{id}");
        assert_eq!(
            staged.config.deprecation_header.as_deref(),
            Some("@1788220800")
        );

        // The undeprecated sibling operation stages nothing.
        let miss = enforce_on(&enforcer, "/v2/jobs/42").await;
        assert!(miss.openapi_deprecation.is_none());
        // Body validation is still armed either way.
        assert!(miss.validate_request_body);
    }

    #[tokio::test]
    async fn without_the_sub_block_nothing_is_staged() {
        // Off by default: the same deprecated spec with no
        // `deprecation_headers:` sub-block emits nothing.
        let enforcer = policy(serde_json::json!({ "spec": deprecated_spec() }));
        let ctx = enforce_on(&enforcer, "/v1/jobs/42").await;
        assert!(ctx.openapi_deprecation.is_none());
    }
}
