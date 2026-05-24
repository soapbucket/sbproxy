//! Newtype wrapper enforcer for the
//! `Policy::RequestLimit` variant.
//!
//! Lifts the body of the `Policy::RequestLimit(p)` arm from
//! `crate::server::check_policies`. Inspects header count, URL +
//! query length, max header value size, and declared Content-Length;
//! denies up-front when any cap is exceeded. On allow, forwards the
//! body-size cap into [`RequestContext::body_size_limit`] so the
//! streaming filter catches chunked uploads that lie about size.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::RequestLimitPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`RequestLimitPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct RequestLimitEnforcer(pub Arc<RequestLimitPolicy>);

impl PolicyEnforcer for RequestLimitEnforcer {
    fn policy_type(&self) -> &'static str {
        "request_limit"
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
                        message: "request_limit enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let headers = req.headers();
        let header_count = headers.len();
        let url_len = req.uri().to_string().len();
        let query_len = req.uri().query().map(|q| q.len()).unwrap_or(0);
        let max_header_size = headers.values().map(|v| v.len()).max().unwrap_or(0);
        let declared_body_size = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        if let Err(msg) = policy.check_request(
            declared_body_size,
            header_count,
            max_header_size,
            url_len,
            query_len,
        ) {
            ctx.deny_policy_type = Some("request_limit");
            tracing::debug!(detail = %msg, "request limit exceeded");
            return Box::pin(async move {
                Ok(PolicyDecision::Deny {
                    status: 413,
                    message: "request entity too large".to_string(),
                })
            });
        }
        if let Some(max) = policy.max_body_size {
            let cap = ctx.body_size_limit.map(|c| c.min(max)).unwrap_or(max);
            ctx.body_size_limit = Some(cap);
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}
