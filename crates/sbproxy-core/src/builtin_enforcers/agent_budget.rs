// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! Newtype wrapper enforcer for the `Policy::AgentBudget` variant
//! (WOR-506).
//!
//! Reads the resolved `agent_id` off the request context (the
//! `agent-class` feature populates it via the resolver chain), keys
//! the per-minute / per-hour / burst budgets against it, and maps the
//! returned [`AgentBudgetDecision`] to a [`PolicyDecision`].
//!
//! When the `agent-class` feature is off the context exposes no
//! `agent_id`. The policy then behaves per its `on_anonymous` knob
//! (skip by default), so wiring still works in a stripped binary.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_modules::policy::{AgentBudgetDecision, AgentBudgetExceedReason, AgentBudgetPolicy};
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

use crate::context::RequestContext;

/// Newtype wrapper that adapts [`AgentBudgetPolicy`] to
/// [`PolicyEnforcer`].
pub struct AgentBudgetEnforcer(pub Arc<AgentBudgetPolicy>);

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
        let (decision, guard) = policy.try_admit(agent_id_ref);
        // The guard owns the in-flight slot; stash it on the context
        // so it drops when the request finishes. Reuse the
        // concurrent-limit guard slot since the lifecycle is the
        // same: held for the request body, dropped on response.
        ctx.agent_budget_guards.push(guard);

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
}
