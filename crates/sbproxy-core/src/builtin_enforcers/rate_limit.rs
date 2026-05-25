//! Newtype wrapper enforcer for the `Policy::RateLimit` variant.
//!
//! Calls
//! [`sbproxy_modules::policy::RateLimitPolicy::allow_with_info_for`]
//! and stashes the resulting `RateLimitInfo` on the request context
//! so the dispatcher's 429 response handler can emit the
//! `X-RateLimit-*` headers.
//!
//! When `policy.key` is a non-empty CEL expression the wrapper
//! evaluates it against the per-request CEL context (method, path,
//! headers, query, client_ip, hostname, envelope namespace, feature
//! flags) and uses the result as the rate-limit bucket key. Empty
//! evaluation or evaluation failure falls back to the client IP so
//! the policy still rate-limits something rather than degenerating
//! to a single global bucket.
//!
//! Per-deny-reason label: `"rate_limit"`. Single denial shape
//! (`429 Too Many Requests`) plus a populated
//! `ctx.rate_limit_info`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::RateLimitPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`RateLimitPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct RateLimitEnforcer(pub Arc<RateLimitPolicy>);

impl PolicyEnforcer for RateLimitEnforcer {
    fn policy_type(&self) -> &'static str {
        "rate_limit"
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
                        message: "rate_limit enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let default_client_id = ctx
            .client_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| ctx.hostname.to_string());
        let client_id = match policy.key.as_deref() {
            Some(expr) if !expr.is_empty() => {
                rate_limit_key_from_cel(req, ctx, expr).unwrap_or_else(|| default_client_id.clone())
            }
            _ => default_client_id,
        };
        // Synchronous variant of the rate-limit check. The async
        // path the original server.rs arm called only differs in
        // that it yields between buckets; the per-decision
        // semantics are identical. Synchronous keeps the ctx
        // mutation off the `.await` boundary so the trait's
        // `Send + '_` future bound holds.
        let info = policy.allow_with_info_for(&client_id);
        if !info.allowed {
            ctx.rate_limit_info = Some(info);
            ctx.deny_policy_type = Some("rate_limit");
            Box::pin(async move {
                Ok(PolicyDecision::Deny {
                    status: 429,
                    message: "rate limited".to_string(),
                })
            })
        } else {
            ctx.rate_limit_info = Some(info);
            Box::pin(async move { Ok(PolicyDecision::Allow) })
        }
    }
}

/// Evaluate a rate-limit `key:` CEL expression against the current
/// request. Returns the string-coerced result when evaluation
/// succeeds and produces a non-empty value, otherwise `None` so the
/// caller can fall back to the default IP-based key.
pub(crate) fn rate_limit_key_from_cel(
    req: &http::Request<Bytes>,
    ctx: &RequestContext,
    expr: &str,
) -> Option<String> {
    use sbproxy_extension::cel::context::{
        build_request_context, populate_envelope_namespace, populate_features_namespace,
        EnvelopeView, FeatureFlagsView,
    };
    use sbproxy_extension::cel::{CelEngine, CelValue};

    let method = req.method().as_str();
    let path = req.uri().path();
    let query = req.uri().query();
    let client_ip = ctx.client_ip.map(|ip| ip.to_string());

    let mut cel_ctx = build_request_context(
        method,
        path,
        req.headers(),
        query,
        client_ip.as_deref(),
        ctx.hostname.as_str(),
    );
    let session_str = ctx.session_id.map(|s| s.to_string());
    let parent_str = ctx.parent_session_id.map(|s| s.to_string());
    let envelope = EnvelopeView {
        user_id: ctx.user_id.as_deref(),
        user_id_source: ctx.user_id_source.map(|s| s.as_str()),
        session_id: session_str.as_deref(),
        parent_session_id: parent_str.as_deref(),
        workspace_id: None,
        properties: Some(&ctx.properties),
    };
    populate_envelope_namespace(&mut cel_ctx, &envelope);
    let features = FeatureFlagsView {
        debug: ctx.flags.debug,
        trace: ctx.flags.trace,
        no_cache: ctx.flags.no_cache,
        extra: &ctx.flags.extra,
    };
    populate_features_namespace(&mut cel_ctx, &features);

    let engine = CelEngine::new();
    let value = match engine.eval_source(expr, &cel_ctx) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, expression = expr, "rate-limit key CEL evaluation failed; falling back to default key");
            return None;
        }
    };
    let s = match value {
        CelValue::String(s) => s,
        CelValue::Int(i) => i.to_string(),
        CelValue::Float(f) => f.to_string(),
        CelValue::Bool(b) => b.to_string(),
        CelValue::Null => return None,
        CelValue::Map(_) | CelValue::List(_) => {
            tracing::warn!(
                expression = expr,
                "rate-limit key CEL expression produced a map/list; falling back to default key"
            );
            return None;
        }
    };
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    //! Behavioural tests for the rate-limit enforcer live in the
    //! existing `sbproxy-modules` rate-limiter unit suite. The
    //! wrapper itself is a thin trait-adapter; the bad-context
    //! short-circuit is the only branch worth pinning here.

    use super::*;

    #[tokio::test]
    async fn bad_context_short_circuits_with_deny() {
        let cfg = serde_json::json!({"requests_per_second": 1.0, "burst": 1});
        let policy: RateLimitPolicy = serde_json::from_value(cfg).expect("default rate-limit");
        let enforcer = RateLimitEnforcer(Arc::new(policy));
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
