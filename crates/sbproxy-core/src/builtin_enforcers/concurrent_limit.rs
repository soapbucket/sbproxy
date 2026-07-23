//! Newtype wrapper enforcer for the
//! `Policy::ConcurrentLimit` variant.
//!
//! Lifts the body of the `Policy::ConcurrentLimit(p)` arm from
//! `crate::server::check_policies`. Resolves the per-request key
//! against the configured strategy
//! ([`sbproxy_modules::policy::ConcurrentLimitPolicy::resolve_key`])
//! and tries to acquire a semaphore slot. On acquire, pushes the
//! guard onto [`RequestContext::concurrent_limit_guards`] so the
//! slot is released when the request completes; on contention,
//! returns the policy's configured status.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::ConcurrentLimitPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`ConcurrentLimitPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct ConcurrentLimitEnforcer(pub Arc<ConcurrentLimitPolicy>);

impl PolicyEnforcer for ConcurrentLimitEnforcer {
    fn policy_type(&self) -> &'static str {
        "concurrent_limit"
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
                        message: "concurrent_limit enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let origin_id = ctx.origin_idx.map(|i| i.to_string()).unwrap_or_default();
        let client_ip_str = ctx.client_ip.map(|ip| ip.to_string());
        let key = policy.resolve_key(
            &origin_id,
            req.uri().path(),
            client_ip_str.as_deref(),
            req.headers(),
        );
        match policy.try_acquire(&key) {
            Some(guard) => {
                ctx.concurrent_limit_guards.push(guard);
                Box::pin(async move { Ok(PolicyDecision::Allow) })
            }
            None => {
                let status = policy.status;
                let message = policy
                    .error_body
                    .clone()
                    .unwrap_or_else(|| "too many concurrent requests".to_string());
                ctx.deny_policy_type = Some("concurrent_limit");
                tracing::debug!(
                    key_by = %policy.key,
                    max = %policy.max,
                    "concurrent limit exceeded"
                );
                Box::pin(async move { Ok(PolicyDecision::Deny { status, message }) })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: &str) -> http::Request<Bytes> {
        http::Request::builder()
            .uri(path)
            .body(Bytes::new())
            .expect("request")
    }

    #[tokio::test]
    async fn dropping_request_context_releases_the_permit() {
        let policy = Arc::new(
            ConcurrentLimitPolicy::from_config(serde_json::json!({
                "max": 1,
                "key_by": "global"
            }))
            .expect("policy"),
        );
        let enforcer = ConcurrentLimitEnforcer(policy);

        let mut active = RequestContext::new();
        let admitted = enforcer
            .enforce(&request("/work"), &mut active)
            .await
            .expect("decision");
        assert!(matches!(admitted, PolicyDecision::Allow));

        let mut blocked = RequestContext::new();
        let denied = enforcer
            .enforce(&request("/work"), &mut blocked)
            .await
            .expect("decision");
        assert!(matches!(denied, PolicyDecision::Deny { status: 503, .. }));

        // Pingora drops the per-request context on disconnect and every
        // terminal response path. Its guard vector must release the slot.
        drop(active);

        let mut after_disconnect = RequestContext::new();
        let admitted_again = enforcer
            .enforce(&request("/work"), &mut after_disconnect)
            .await
            .expect("decision");
        assert!(matches!(admitted_again, PolicyDecision::Allow));
    }

    #[tokio::test]
    async fn route_selector_uses_the_request_path() {
        let policy = Arc::new(
            ConcurrentLimitPolicy::from_config(serde_json::json!({
                "max": 1,
                "key_by": "route"
            }))
            .expect("policy"),
        );
        let enforcer = ConcurrentLimitEnforcer(policy);

        let mut first_route = RequestContext::new();
        assert!(matches!(
            enforcer
                .enforce(&request("/first"), &mut first_route)
                .await
                .expect("decision"),
            PolicyDecision::Allow
        ));

        let mut same_route = RequestContext::new();
        assert!(matches!(
            enforcer
                .enforce(&request("/first?ignored=true"), &mut same_route)
                .await
                .expect("decision"),
            PolicyDecision::Deny { .. }
        ));

        let mut second_route = RequestContext::new();
        assert!(matches!(
            enforcer
                .enforce(&request("/second"), &mut second_route)
                .await
                .expect("decision"),
            PolicyDecision::Allow
        ));
    }

    #[tokio::test]
    async fn configured_error_body_is_returned_on_rejection() {
        let policy = Arc::new(
            ConcurrentLimitPolicy::from_config(serde_json::json!({
                "max": 1,
                "error_body": "{\"error\":\"busy\"}"
            }))
            .expect("policy"),
        );
        let enforcer = ConcurrentLimitEnforcer(policy);
        let mut active = RequestContext::new();
        assert!(matches!(
            enforcer
                .enforce(&request("/"), &mut active)
                .await
                .expect("decision"),
            PolicyDecision::Allow
        ));

        let mut blocked = RequestContext::new();
        let decision = enforcer
            .enforce(&request("/"), &mut blocked)
            .await
            .expect("decision");
        assert!(matches!(
            decision,
            PolicyDecision::Deny {
                status: 503,
                ref message
            } if message == "{\"error\":\"busy\"}"
        ));
    }
}
