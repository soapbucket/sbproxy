//! WOR-201 PR 1c.3: newtype wrapper enforcer for the
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

use anyhow::Result;
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
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>> {
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
        let key = policy.resolve_key(&origin_id, client_ip_str.as_deref(), req.headers());
        match policy.try_acquire(&key) {
            Some(guard) => {
                ctx.concurrent_limit_guards.push(guard);
                Box::pin(async move { Ok(PolicyDecision::Allow) })
            }
            None => {
                let status = policy.status;
                ctx.deny_policy_type = Some("concurrent_limit");
                tracing::debug!(key = %key, max = %policy.max, "concurrent limit exceeded");
                Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status,
                        message: "too many concurrent requests".to_string(),
                    })
                })
            }
        }
    }
}
