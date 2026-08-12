// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Newtype wrapper enforcer for the `Policy::AgentBudget` variant
//!.
//!
//! Reads the resolved `agent_id` off the request context (the
//! `agent-class` feature populates it via the resolver chain), keys
//! the per-minute / per-hour / burst budgets against it, and maps the
//! returned [`AgentBudgetDecision`] to a [`PolicyDecision`].
//!
//! The hourly token budget is two-phase (WOR-2312): admission checks
//! the accumulated counter here, and an admitted request leaves an
//! [`AgentBudgetTokenSink`] on the context so the completion path
//! (`RequestContext::charge_agent_budget_tokens`, called from the
//! `logging` phase for buffered responses and from stream close for
//! streamed ones) can charge the measured usage under the same agent
//! key.
//!
//! When the `agent-class` feature is off the context exposes no
//! `agent_id`. The policy then behaves per its `on_anonymous` knob
//! (skip by default), so wiring still works in a stripped binary.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::{
    AgentBudgetDecision, AgentBudgetExceedReason, AgentBudgetPolicy, AgentBudgetTokenSink,
};
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use super::shared_admission::{SharedAdmission, SharedDecision};
use crate::context::RequestContext;

/// Newtype wrapper that adapts [`AgentBudgetPolicy`] to
/// [`PolicyEnforcer`].
pub struct AgentBudgetEnforcer(pub Arc<AgentBudgetPolicy>);

impl AgentBudgetEnforcer {
    /// A handle that admits this policy against its cluster-shared
    /// counter, for policies that have one.
    ///
    /// `None` for a local-only policy, which is the common case and keeps
    /// exactly the synchronous path it had.
    pub(crate) fn shared_admission(&self) -> Option<Arc<dyn SharedAdmission>> {
        if !self.0.has_shared_tier() {
            return None;
        }
        Some(Arc::new(AgentBudgetSharedAdmission {
            policy: Arc::clone(&self.0),
        }))
    }
}

/// The shared-tier half of [`AgentBudgetEnforcer`].
///
/// Split out for the same reason the rate limiter's is: the key has to be
/// derived under a context borrow that ends before the await, because a
/// future holding `&mut dyn Any` is not `Send`.
struct AgentBudgetSharedAdmission {
    policy: Arc<AgentBudgetPolicy>,
}

impl SharedAdmission for AgentBudgetSharedAdmission {
    fn shared_admission_key(
        &self,
        _req: &http::Request<Bytes>,
        ctx: &RequestContext,
    ) -> Option<String> {
        // The budget keys on the resolved agent id, not on anything from
        // the request line. An anonymous request has no key; the policy's
        // own `on_anonymous` rule decides what that means, and it decides
        // it locally, so there is nothing for the shared tier to do.
        #[cfg(feature = "agent-class")]
        {
            ctx.agent_id.as_ref().map(|a| a.as_str().to_string())
        }
        #[cfg(not(feature = "agent-class"))]
        {
            let _ = ctx;
            None
        }
    }

    fn shared_admit<'a>(
        &'a self,
        key: String,
    ) -> Pin<Box<dyn Future<Output = SharedDecision> + Send + 'a>> {
        Box::pin(async move {
            let (decision, guard) = self.policy.try_admit_async(Some(&key)).await;
            SharedDecision::AgentBudget { decision, guard }
        })
    }
}

impl PolicyEnforcer for AgentBudgetEnforcer {
    fn policy_type(&self) -> &'static str {
        "agent_budget"
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
                        message: "agent_budget enforcer: bad context".to_string(),
                    })
                });
            }
        };

        #[cfg(feature = "agent-class")]
        let agent_id_owned: Option<String> = ctx.agent_id.as_ref().map(|a| a.as_str().to_string());
        #[cfg(not(feature = "agent-class"))]
        let agent_id_owned: Option<String> = None;

        let agent_id_ref = agent_id_owned.as_deref();
        // WOR-2332/WOR-2315: when a shared counter is attached, admission
        // already happened at the `check_policies` call site, where the
        // await is legal. Take it rather than re-running the local path,
        // which would consume a second token from the local bucket and
        // double-count every request.
        //
        // `take`, not read: a chain may carry more than one agent_budget
        // policy, and the second must not inherit the first's verdict or
        // its in-flight permit.
        let (decision, guard) = match ctx.shared_agent_budget_decision.take() {
            Some(precomputed) => precomputed,
            None => policy.try_admit(agent_id_ref),
        };
        // The guard owns the in-flight slot; stash it on the context
        // so it drops when the request finishes. Reuse the
        // concurrent-limit guard slot since the lifecycle is the
        // same: held for the request body, dropped on response.
        ctx.agent_budget_guards.push(guard);

        // Post-response half of the token budget (WOR-2312): when the
        // policy caps tokens_per_hour and this request was admitted,
        // leave a sink on the context so the completion path can
        // charge the measured usage against the same agent key the
        // admission check ran under. Denied requests never dispatch
        // upstream, so they get no sink; anonymous requests under
        // `on_anonymous: skip` consume nothing by the sink's own
        // keying rules, so they get none either.
        if policy.tokens_per_hour.is_some()
            && decision.admits()
            && !matches!(decision, AgentBudgetDecision::SkippedAnonymous)
        {
            ctx.agent_budget_token_sinks.push(AgentBudgetTokenSink::new(
                Arc::clone(&policy),
                agent_id_owned,
            ));
        }

        let decision = match decision {
            AgentBudgetDecision::Allow
            | AgentBudgetDecision::SkippedAnonymous
            | AgentBudgetDecision::AllowLogged { .. }
            | AgentBudgetDecision::AllowDowngrade { .. } => PolicyDecision::Allow,
            AgentBudgetDecision::Deny { reason } => {
                ctx.deny_policy_type = Some("agent_budget");
                PolicyDecision::Deny {
                    status: 429,
                    message: deny_message(reason).to_string(),
                }
            }
        };
        Box::pin(async move { Ok(decision) })
    }
}

fn deny_message(reason: AgentBudgetExceedReason) -> &'static str {
    match reason {
        AgentBudgetExceedReason::RequestsPerMinute => "agent budget exceeded: requests per minute",
        AgentBudgetExceedReason::TokensPerHour => "agent budget exceeded: tokens per hour",
        AgentBudgetExceedReason::Burst => "agent budget exceeded: burst",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bad_context_short_circuits_with_deny() {
        let policy = AgentBudgetPolicy::from_config(serde_json::json!({
            "requests_per_minute": 1
        }))
        .expect("config");
        let enforcer = AgentBudgetEnforcer(Arc::new(policy));
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

    #[tokio::test]
    async fn response_token_usage_charges_the_hourly_budget_through_the_context_sink() {
        // WOR-2312: the two-phase token budget end to end at the
        // enforcer seam. `on_anonymous: shared` keys the bucket even
        // when no agent resolver stamped the context, so the test
        // holds with and without the `agent-class` feature.
        let policy = AgentBudgetPolicy::from_config(serde_json::json!({
            "tokens_per_hour": 100,
            "on_anonymous": "shared",
            "on_exceed": "deny"
        }))
        .expect("config");
        let enforcer = AgentBudgetEnforcer(Arc::new(policy));
        let req = http::Request::builder()
            .uri("/")
            .body(Bytes::new())
            .unwrap();

        // First request: admitted, and admission leaves the token
        // sink for the completion path.
        let mut ctx = RequestContext::new();
        let decision = enforcer.enforce(&req, &mut ctx).await.unwrap();
        assert!(matches!(decision, PolicyDecision::Allow));
        assert_eq!(ctx.agent_budget_token_sinks.len(), 1);

        // The completion seam charges the measured usage and drains
        // the sink so a second seam cannot double charge.
        ctx.charge_agent_budget_tokens(100);
        assert!(ctx.agent_budget_token_sinks.is_empty());

        // Next request on the same key: refused pre-flight against
        // the accumulated counter, same status as a request-budget
        // denial, body naming the cap that fired.
        let mut next = RequestContext::new();
        let denied = enforcer.enforce(&req, &mut next).await.unwrap();
        match denied {
            PolicyDecision::Deny { status, message } => {
                assert_eq!(status, 429);
                assert_eq!(message, "agent budget exceeded: tokens per hour");
            }
            other => panic!("expected token-budget Deny(429), got {other:?}"),
        }
        // A denied request never dispatches, so it leaves no sink to
        // charge.
        assert!(next.agent_budget_token_sinks.is_empty());
    }
}
