//! Newtype wrapper enforcer for the
//! `Policy::IpFilter` variant.
//!
//! Lifts the body of the `Policy::IpFilter(p)` arm that lived in
//! `crate::server::check_policies` into a
//! [`sbproxy_plugin::PolicyEnforcer`] impl. Consults the parsed
//! whitelist / blacklist CIDR sets on
//! [`sbproxy_modules::policy::IpFilterPolicy`] against the client
//! IP captured on [`RequestContext::client_ip`]. A request with
//! no client IP is allowed: the original arm preserved the same
//! behaviour because internal traffic without an attributable IP
//! cannot match a CIDR.
//!
//! Per-deny-reason label: `"ip_filter"`. The policy emits a single
//! denial shape (`403 Forbidden`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::IpFilterPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`IpFilterPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct IpFilterEnforcer(pub Arc<IpFilterPolicy>);

impl PolicyEnforcer for IpFilterEnforcer {
    fn policy_type(&self) -> &'static str {
        "ip_filter"
    }

    fn enforce(
        &self,
        _req: &http::Request<Bytes>,
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
                        message: "ip_filter enforcer: bad context".to_string(),
                    })
                });
            }
        };
        let client_ip = ctx.client_ip;
        if let Some(ip) = client_ip {
            if !policy.check_ip(&ip) {
                ctx.deny_policy_type = Some("ip_filter");
                return Box::pin(async move {
                    Ok(PolicyDecision::Deny {
                        status: 403,
                        message: "forbidden".to_string(),
                    })
                });
            }
        }
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}
