//! Newtype wrapper enforcer for the
//! `Policy::HttpFraming` variant.
//!
//! Lifts the body of the `Policy::HttpFraming(p)` arm. Defense
//! against the request-smuggling / desync class
//! (portswigger.net/research/http-desync-attacks-request-smuggling-reborn).
//! Pingora's parser strictness handles wire-level malformed input;
//! this policy adds the semantic-ambiguity layer (CL+TE, duplicate
//! CL, malformed TE, duplicate TE, control chars).
//!
//! On block, emits three observable signals (matching the legacy
//! arm exactly):
//!
//! 1. `sbproxy_http_framing_blocks_total{reason}` Prometheus counter
//! 2. `tracing::warn` on `sbproxy::http_framing`
//! 3. `SecurityAuditEntry` on the `security_audit` target

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::HttpFramingPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`HttpFramingPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct HttpFramingEnforcer(pub Arc<HttpFramingPolicy>);

impl PolicyEnforcer for HttpFramingEnforcer {
    fn policy_type(&self) -> &'static str {
        "http_framing"
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
                        message: "http_framing enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let headers = req.headers();
        if let Err(violation) = policy.check_request(headers) {
            let reason = violation.metric_reason();
            sbproxy_observe::metrics::record_http_framing_block(reason);
            tracing::warn!(
                target: "sbproxy::http_framing",
                reason = %reason,
                hostname = %ctx.hostname,
                "blocked: HTTP framing violation"
            );
            sbproxy_observe::SecurityAuditEntry::framing_violation(
                reason,
                Some(ctx.hostname.to_string()),
                ctx.client_ip,
                Some(ctx.request_id.to_string()),
                Some(req.method().as_str().to_string()),
            )
            .emit();
            let message = violation.message().to_string();
            ctx.deny_policy_type = Some("http_framing");
            return Box::pin(async move {
                Ok(PolicyDecision::Deny {
                    status: 400,
                    message,
                })
            });
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}
