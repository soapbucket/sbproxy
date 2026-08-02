//! WOR-1130: enforcer for the `Policy::RateLimitBudget` variant.
//!
//! Consults the process-wide workspace budget registry
//! ([`crate::rate_limit_budget`]) and, on a throttle, stashes a
//! [`sbproxy_modules::RateLimitInfo`] + `deny_policy_type =
//! "rate_limit_budget"` on the context so the dispatcher's 429 handler
//! emits the RFC 9239 `RateLimit-*` header set. A `None` registry (no
//! top-level `rate_limits:` block) is a no-op `Allow`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::rate_limit_budget::{BudgetDecision, RateLimitBudgetPolicy};
use sbproxy_modules::RateLimitInfo;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// OSS is single-tenant; all traffic resolves to the `default`
/// workspace, which is the one the top-level `rate_limits:` block sizes.
const DEFAULT_WORKSPACE: &str = "default";

/// Newtype wrapper adapting [`RateLimitBudgetPolicy`] to [`PolicyEnforcer`].
pub struct RateLimitBudgetEnforcer(pub Arc<RateLimitBudgetPolicy>);

fn response_info(policy: &RateLimitBudgetPolicy, decision: &BudgetDecision) -> RateLimitInfo {
    RateLimitInfo {
        allowed: decision.allowed,
        limit: decision.limit,
        remaining: decision.remaining,
        reset_secs: decision.reset_secs,
        headers_enabled: policy.headers_enabled(),
        include_retry_after: policy.include_retry_after(),
        include_ratelimit_policy: policy.include_ratelimit_policy(),
    }
}

fn apply_budget_decision(
    policy: &RateLimitBudgetPolicy,
    decision: &BudgetDecision,
    ctx: &mut RequestContext,
) -> PolicyDecision {
    sbproxy_observe::metrics::record_rate_limit_decision(
        DEFAULT_WORKSPACE,
        if decision.allowed {
            "allow"
        } else {
            "throttle_tenant"
        },
    );
    if decision.allowed {
        return PolicyDecision::Allow;
    }

    ctx.rate_limit_info = Some(response_info(policy, decision));
    ctx.deny_policy_type = Some("rate_limit_budget");
    PolicyDecision::Deny {
        status: 429,
        message: "rate limit budget exceeded".to_string(),
    }
}

impl PolicyEnforcer for RateLimitBudgetEnforcer {
    fn policy_type(&self) -> &'static str {
        "rate_limit_budget"
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
                        message: "rate_limit_budget enforcer: bad context".to_string(),
                    })
                });
            }
        };

        // No top-level `rate_limits:` block installed -> the marker is a
        // no-op so an origin can carry the policy without a budget.
        let Some(registry) = crate::rate_limit_budget::registry() else {
            return Box::pin(async move { Ok(PolicyDecision::Allow) });
        };

        // OSS is single-tenant: every request resolves to the `default`
        // workspace, the same key the admin `/api/rate_limits/effective`
        // query and the audit `target_id` use. (Enterprise multi-tenant
        // resolves a per-tenant workspace here.)
        let _ = &ctx.tenant_id;
        let decision = registry.check(DEFAULT_WORKSPACE);
        let outcome = apply_budget_decision(&policy, &decision, ctx);
        Box::pin(async move { Ok(outcome) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_modules::policy::rate_limit_budget::Tier;

    fn decision_count(result: &str) -> u64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "sbproxy_rate_limit_decisions_total")
            .and_then(|family| {
                family.get_metric().iter().find_map(|metric| {
                    let matches = metric.get_label().iter().all(|label| match label.name() {
                        "policy" => label.value() == DEFAULT_WORKSPACE,
                        "result" => label.value() == result,
                        _ => true,
                    });
                    matches.then(|| metric.get_counter().value() as u64)
                })
            })
            .unwrap_or_default()
    }

    #[test]
    fn workspace_budget_decisions_feed_the_alert_counter() {
        let policy = RateLimitBudgetPolicy::from_config(serde_json::json!({
            "type": "rate_limit_budget"
        }))
        .unwrap();
        let mut ctx = RequestContext::new();
        let allowed = BudgetDecision {
            allowed: true,
            tier: Tier::Normal,
            limit: 10,
            remaining: 9,
            reset_secs: 1,
            window_secs: 1,
        };
        let before_allow = decision_count("allow");
        assert!(matches!(
            apply_budget_decision(&policy, &allowed, &mut ctx),
            PolicyDecision::Allow
        ));
        assert_eq!(decision_count("allow"), before_allow + 1);

        let throttled = BudgetDecision {
            allowed: false,
            tier: Tier::Throttle,
            limit: 10,
            remaining: 0,
            reset_secs: 1,
            window_secs: 1,
        };
        let before_throttle = decision_count("throttle_tenant");
        assert!(matches!(
            apply_budget_decision(&policy, &throttled, &mut ctx),
            PolicyDecision::Deny { status: 429, .. }
        ));
        assert_eq!(decision_count("throttle_tenant"), before_throttle + 1);
    }

    #[test]
    fn response_info_honors_rate_limit_policy_header_preference() {
        let policy = RateLimitBudgetPolicy::from_config(serde_json::json!({
            "type": "rate_limit_budget",
            "headers": {
                "enabled": true,
                "include_retry_after": true,
                "include_ratelimit_policy": false
            }
        }))
        .unwrap();
        let decision = BudgetDecision {
            allowed: false,
            tier: Tier::Throttle,
            limit: 10,
            remaining: 0,
            reset_secs: 1,
            window_secs: 1,
        };

        let info = response_info(&policy, &decision);
        assert!(!info.include_ratelimit_policy);
    }
}
