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
    workspace: &str,
    ctx: &mut RequestContext,
) -> PolicyDecision {
    sbproxy_observe::metrics::record_rate_limit_decision(
        workspace,
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

        // WOR-2477: key the workspace budget by the origin's configured
        // tenant. Tenant ids come from proxy.tenants[] / origin config
        // (compiler-validated, 256-char cap, reserved `__default__`), so
        // the registry's per-key map stays operator-bounded; a request
        // cannot mint a new key. Origins with no tenant fall into the
        // `__default__` bucket, which is byte-for-byte the old behavior
        // for single-tenant deployments.
        let workspace = ctx.tenant_id.clone();
        let decision = registry.check(workspace.as_str());
        let outcome = apply_budget_decision(&policy, &decision, workspace.as_str(), ctx);
        Box::pin(async move { Ok(outcome) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_config::types::{
        RateLimitClockMode, RateLimitEscalationConfig, RateLimitsConfig, WorkspaceBudgetConfig,
    };
    use sbproxy_modules::policy::rate_limit_budget::{RateLimitBudgetRegistry, Tier};

    /// Arbitrary workspace label used by tests that only exercise the
    /// counter-emission plumbing, not tenant-keyed routing itself.
    const TEST_WORKSPACE: &str = "workspace";

    fn decision_count(policy_label: &str, result: &str) -> u64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "sbproxy_rate_limit_decisions_total")
            .and_then(|family| {
                family.get_metric().iter().find_map(|metric| {
                    let matches = metric.get_label().iter().all(|label| match label.name() {
                        "policy" => label.value() == policy_label,
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
        let before_allow = decision_count(TEST_WORKSPACE, "allow");
        assert!(matches!(
            apply_budget_decision(&policy, &allowed, TEST_WORKSPACE, &mut ctx),
            PolicyDecision::Allow
        ));
        assert_eq!(decision_count(TEST_WORKSPACE, "allow"), before_allow + 1);

        let throttled = BudgetDecision {
            allowed: false,
            tier: Tier::Throttle,
            limit: 10,
            remaining: 0,
            reset_secs: 1,
            window_secs: 1,
        };
        let before_throttle = decision_count(TEST_WORKSPACE, "throttle_tenant");
        assert!(matches!(
            apply_budget_decision(&policy, &throttled, TEST_WORKSPACE, &mut ctx),
            PolicyDecision::Deny { status: 429, .. }
        ));
        assert_eq!(
            decision_count(TEST_WORKSPACE, "throttle_tenant"),
            before_throttle + 1
        );
    }

    #[tokio::test]
    async fn tenants_get_independent_budget_buckets() {
        // One-request budget: tenant-a's second request throttles,
        // tenant-b's first request on the same enforcer does not, because
        // WOR-2477 keys the registry's per-workspace map off
        // `ctx.tenant_id` instead of a single shared default bucket.
        let registry = RateLimitBudgetRegistry::new(&RateLimitsConfig {
            workspace_default: WorkspaceBudgetConfig {
                http_rps_sustained: 1,
                http_rps_burst: 1,
                soft_threshold_rps: None,
            },
            escalation: RateLimitEscalationConfig::default(),
            clock: RateLimitClockMode::Manual,
        });
        let policy = RateLimitBudgetPolicy::from_config(serde_json::json!({
            "type": "rate_limit_budget"
        }))
        .unwrap();

        let mut ctx_a = RequestContext::new();
        ctx_a.tenant_id = "tenant-a".into();
        let workspace_a = ctx_a.tenant_id.as_str().to_string();

        // tenant-a's first request consumes its one-request budget.
        let first_a = registry.check(&workspace_a);
        assert!(matches!(
            apply_budget_decision(&policy, &first_a, &workspace_a, &mut ctx_a),
            PolicyDecision::Allow
        ));

        // tenant-a's second request throttles on its own bucket.
        let second_a = registry.check(&workspace_a);
        let before_throttle_a = decision_count(&workspace_a, "throttle_tenant");
        assert!(matches!(
            apply_budget_decision(&policy, &second_a, &workspace_a, &mut ctx_a),
            PolicyDecision::Deny { status: 429, .. }
        ));
        assert_eq!(
            decision_count(&workspace_a, "throttle_tenant"),
            before_throttle_a + 1
        );

        // tenant-b's first request is allowed: an independent bucket keyed
        // off its own tenant_id, unaffected by tenant-a's throttle.
        let mut ctx_b = RequestContext::new();
        ctx_b.tenant_id = "tenant-b".into();
        let workspace_b = ctx_b.tenant_id.as_str().to_string();
        let first_b = registry.check(&workspace_b);
        let before_allow_b = decision_count(&workspace_b, "allow");
        assert!(matches!(
            apply_budget_decision(&policy, &first_b, &workspace_b, &mut ctx_b),
            PolicyDecision::Allow
        ));
        assert_eq!(decision_count(&workspace_b, "allow"), before_allow_b + 1);
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
