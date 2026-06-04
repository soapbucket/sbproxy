//! Newtype enforcer for the `Policy::ObjectAuthz` variant.
//!
//! Resolves the caller's owner + roles from the request and asks
//! [`ObjectAuthzPolicy`] to decide. The owner comes from the verified
//! auth subject (`ctx.auth_result`) or, when the operator opts in, from
//! a trusted request header; roles come from a trusted role header. A
//! violation is reported to the security audit log and the
//! `sbproxy_object_authz_violations_total` metric, then blocked with a
//! generic 403 (or allowed through when the policy is in `test_mode`).
//!
//! The client-facing 403 is intentionally generic so the response does
//! not leak which scope owns the object; the OWASP risk tag and the
//! detailed reason go to the audit log only.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::object_authz::{OwnerSource, Principal};
use sbproxy_modules::ObjectAuthzPolicy;
use sbproxy_plugin::{AuthDecision, PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`ObjectAuthzPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct ObjectAuthzEnforcer(pub Arc<ObjectAuthzPolicy>);

impl PolicyEnforcer for ObjectAuthzEnforcer {
    fn policy_type(&self) -> &'static str {
        "object_authz"
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
                        message: "object_authz enforcer: bad context".to_string(),
                    })
                });
            }
        };

        let pcfg = policy.principal_config();

        // Resolve the caller's owner identity.
        let owner: Option<String> = match pcfg.owner_from {
            OwnerSource::Sub => match &ctx.auth_result {
                Some(AuthDecision::Allow { sub: Some(s), .. }) => Some(s.clone()),
                _ => None,
            },
            OwnerSource::Header => req
                .headers()
                .get(pcfg.owner_header.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        };

        // WOR-1139: roles come from `role_header` only when the operator
        // has explicitly trusted it. By default the header is ignored so
        // a direct client cannot send `x-roles: admin` and satisfy a BFLA
        // role rule; the rule then fails closed (no roles -> no match).
        let roles: Vec<String> = if pcfg.trust_role_header {
            req.headers()
                .get(pcfg.role_header.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|s| {
                    s.split(',')
                        .map(|r| r.trim().to_string())
                        .filter(|r| !r.is_empty())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let principal = Principal { owner, roles };
        let method = req.method().as_str().to_string();
        let path = req.uri().path().to_string();

        let decision = policy.decide(&principal, &method, &path);

        match decision {
            None => Box::pin(async move { Ok(PolicyDecision::Allow) }),
            Some(violation) => {
                let origin = ctx.hostname.to_string();
                let client_ip = ctx.client_ip;
                let request_id = ctx.request_id.to_string();

                sbproxy_observe::metrics::record_object_authz_violation(
                    &origin,
                    violation.kind.label(),
                );
                sbproxy_observe::SecurityAuditEntry::policy_violation(
                    violation.kind.event_type(),
                    format!("[{}] {}", violation.kind.owasp_tag(), violation.message),
                    403,
                    Some(origin),
                    client_ip,
                    Some(request_id),
                    Some(method),
                )
                .emit();

                if policy.test_mode() {
                    Box::pin(async move { Ok(PolicyDecision::Allow) })
                } else {
                    ctx.deny_policy_type = Some("object_authz");
                    Box::pin(async move {
                        Ok(PolicyDecision::Deny {
                            status: 403,
                            message: "forbidden: object-level authorization check failed"
                                .to_string(),
                        })
                    })
                }
            }
        }
    }
}
