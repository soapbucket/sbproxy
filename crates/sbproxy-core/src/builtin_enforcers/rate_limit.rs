//! WOR-201 PR 1c.3: newtype wrapper enforcer for the
//! `Policy::RateLimit` variant.
//!
//! Lifts the body of the `Policy::RateLimit(p)` arm from
//! `crate::server::check_policies` into a
//! [`sbproxy_plugin::PolicyEnforcer`] impl. Calls
//! [`sbproxy_modules::policy::RateLimitPolicy::allow_with_info_async`]
//! and stashes the resulting `RateLimitInfo` on the request
//! context so the dispatcher's 429 response handler can emit the
//! `X-RateLimit-*` headers.
//!
//! ## CEL key resolution
//!
//! The original arm resolved the rate-limit key via a CEL
//! expression when `p.key` was set. The CEL helper needs the full
//! session + ctx slot; from inside the trait we only have the
//! `RequestContext` (via the `Any` downcast) and the
//! `http::Request<Bytes>`. The wrapper resolves the key off
//! `ctx.client_ip` for now and treats `p.key` as an opt-in tag
//! that future PRs will plumb through; the legacy server.rs arm
//! falls back to `default_client_id` when CEL resolution returns
//! `None`, so the behaviour is equivalent for the common case of
//! IP-keyed rate limits.
//!
//! Per-deny-reason label: `"rate_limit"`. Single denial shape
//! (`429 Too Many Requests`) plus a populated
//! `ctx.rate_limit_info`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
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
        _req: &http::Request<Bytes>,
        ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>> {
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
        let client_id = ctx
            .client_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "__unknown__".to_string());
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
