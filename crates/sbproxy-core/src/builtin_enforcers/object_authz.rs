//! Newtype enforcer for the `Policy::ObjectAuthz` variant.
//!
//! Resolves the caller's owner + roles from the request and asks
//! [`ObjectAuthzPolicy`] to decide. The owner comes from the verified
//! auth subject (`ctx.auth_result`) or, when the operator opts in, from
//! a trusted request header; roles come from a trusted role header. A
//! violation is reported to the security audit log and the
//! `sbproxy_object_authz_violations_total` metric, then blocked with a
//! generic 403 (or allowed through when the policy is in `test_mode`,
//! or when the violation itself is marked `detect_only` -- see below).
//!
//! The audit record and the metric both carry the enforcement
//! disposition rather than assuming it: the metric's `enforced` label
//! is `"true"` only when the request was actually refused, and the
//! audit `status_code` is `403` only on a refusal. A violation the
//! proxy then allows through (`test_mode` or `detect_only`) records
//! `200`, so a SIEM rule pivoting on `status_code: 403` matches only
//! requests that were really blocked.
//!
//! The client-facing 403 is intentionally generic so the response does
//! not leak which scope owns the object; the OWASP risk tag and the
//! detailed reason go to the audit log only.
//!
//! A `detect_only` violation (currently: an enumeration hit produced by
//! `object_authz`'s ruleless path-shape heuristic rather than a
//! declared rule) is always audited and always allowed through,
//! regardless of `test_mode`: `test_mode` is an operator opt-in to
//! observe-without-enforcing for the whole policy, while `detect_only`
//! is the policy itself saying a particular hit is not trustworthy
//! enough to ever refuse traffic on, no matter how the operator has
//! configured enforcement.

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

        let principal = Principal {
            owner,
            roles,
            // Scopes the policy's enumeration tracker so two tenants
            // whose principals share an id string never share a budget.
            // `ctx.tenant_id` is `__default__` for un-routed and
            // single-tenant traffic, matching the label every other
            // tenant-scoped surface reports.
            tenant: ctx.tenant_id.to_string(),
        };
        let method = req.method().as_str().to_string();
        let path = req.uri().path().to_string();

        let decision = policy.decide(&principal, &method, &path);

        match decision {
            None => Box::pin(async move { Ok(PolicyDecision::Allow) }),
            Some(violation) => {
                let origin = ctx.hostname.to_string();
                let client_ip = ctx.client_ip;
                let request_id = ctx.request_id.to_string();

                // `test_mode` is an operator-wide observe-only toggle;
                // `detect_only` is per-violation and set by the policy
                // itself for hits it does not consider trustworthy
                // enough to block on (see this file's module doc).
                // Either one is enough to allow, and both the metric
                // and the audit record must say which happened.
                let (enforced, audit_status) =
                    enforcement_disposition(policy.test_mode(), violation.detect_only);

                sbproxy_observe::metrics::record_object_authz_violation(
                    &origin,
                    violation.kind.label(),
                    enforced,
                );
                sbproxy_observe::SecurityAuditEntry::policy_violation(
                    violation.kind.event_type(),
                    format!("[{}] {}", violation.kind.owasp_tag(), violation.message),
                    audit_status,
                    Some(origin),
                    client_ip,
                    Some(request_id),
                    Some(method),
                )
                .with_tenant_id(ctx.tenant_id.to_string())
                .with_key_context(
                    ctx.native_key_provider.clone(),
                    ctx.inbound_key_mode.as_str(),
                )
                .with_api_key_id(ctx.accountable_key_id())
                .emit();

                if enforced {
                    ctx.deny_policy_type = Some("object_authz");
                    Box::pin(async move {
                        Ok(PolicyDecision::Deny {
                            status: 403,
                            message: "forbidden: object-level authorization check failed"
                                .to_string(),
                        })
                    })
                } else {
                    Box::pin(async move { Ok(PolicyDecision::Allow) })
                }
            }
        }
    }
}

/// The enforcement disposition for a violation: whether the request is
/// actually refused, and the HTTP status the audit record may claim.
///
/// A `detect_only` or `test_mode` violation is allowed through, so its
/// audit record must not claim a refusal status: a SIEM rule pivoting
/// on `status_code: 403` has to match only requests the proxy really
/// blocked. An allowed disposition records `200` (the proxy proceeds;
/// the free-text reason still carries the audit-only detail).
fn enforcement_disposition(test_mode: bool, detect_only: bool) -> (bool, u16) {
    let enforced = !(test_mode || detect_only);
    (enforced, if enforced { 403 } else { 200 })
}

#[cfg(test)]
mod tests {
    use super::enforcement_disposition;

    #[test]
    fn a_refused_violation_records_the_403_it_returns() {
        assert_eq!(enforcement_disposition(false, false), (true, 403));
    }

    #[test]
    fn an_allowed_disposition_never_claims_a_refusal_status() {
        // Review finding (v1.13 phase 2): detect-only and test-mode
        // violations are allowed through, so the structured audit
        // record must not carry `status_code: 403`. Every combination
        // that allows must report 200.
        assert_eq!(enforcement_disposition(true, false), (false, 200));
        assert_eq!(enforcement_disposition(false, true), (false, 200));
        assert_eq!(enforcement_disposition(true, true), (false, 200));
    }
}
