//! WOR-201 PR 1c.2: newtype wrapper enforcer for the
//! `Policy::AgentClass` variant.
//!
//! The original `Policy::AgentClass(_)` arm in
//! `crate::server::check_policies` was a no-op (`{}`). The agent
//! class resolver lives elsewhere in the pipeline; the policy
//! variant is a marker that operators include in `sb.yml` to
//! request the resolver chain run for this origin. This wrapper
//! preserves the no-op semantics: every request passes the policy
//! gate.

#![cfg(feature = "agent-class")]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use sbproxy_modules::policy::agent_class::AgentClassPolicy;
use sbproxy_plugin::{PolicyDecision, PolicyEnforcer};

/// Newtype wrapper that adapts [`AgentClassPolicy`] to the
/// [`PolicyEnforcer`] trait surface.
pub struct AgentClassEnforcer(pub Arc<AgentClassPolicy>);

impl PolicyEnforcer for AgentClassEnforcer {
    fn policy_type(&self) -> &'static str {
        "agent_class"
    }

    fn enforce(
        &self,
        _req: &http::Request<Bytes>,
        _ctx: &mut dyn std::any::Any,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision>> + Send + '_>> {
        Box::pin(async move { Ok(PolicyDecision::Allow) })
    }
}
