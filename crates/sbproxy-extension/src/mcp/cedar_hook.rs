// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cedar-backed built-in [`McpPolicyHook`] (WOR-2587).
//!
//! [`CedarMcpHook`] is the OSS `McpPolicyHook` implementation backed
//! by the Cedar policy engine ported in WOR-2585
//! (`crate::cedar::CedarEvaluator`). It runs on the exact seam every
//! `McpPolicyHook` runs on:
//! `McpFederation::call_tool_with_upstream_headers_from_snapshot` ->
//! `call_tool_with_policy_cause_and_headers_from_held_tool` ->
//! `registered_hooks_or_default().evaluate(ctx)`, which is itself the
//! only path `sbproxy-core`'s `handle_mcp_action` dispatcher takes to
//! a non-`local` upstream tool call.
//!
//! ## Alongside RBAC, not instead of it
//!
//! `ToolAccessPolicy` (this crate's [`super::access_control`]) is
//! consulted directly by `action_dispatch.rs`, by name, *before* a
//! call ever reaches the seam above: RBAC is the coarse, per-server,
//! default-deny gate, resolved against `McpAction::rbac_policies` and
//! checked against `ctx.principal`. Only once RBAC (and the argument
//! policies and quota checks that follow it) have allowed a call does
//! `action_dispatch.rs` reach `McpFederation::call_tool_with_upstream_headers_from_snapshot`,
//! where every registered `McpPolicyHook` -- including this one --
//! runs. So:
//!
//! - An RBAC deny never reaches this hook at all; registering a Cedar
//!   policy cannot re-open a call RBAC already refused.
//! - A Cedar `forbid` can still refuse a call RBAC allowed: Cedar is
//!   the finer-grained ABAC layer *on top of* RBAC's coarse gate, not
//!   a replacement for it. See
//!   `sbproxy_core::server::action_dispatch`'s
//!   `wor_2587_cedar_hook_runs_alongside_rbac_without_shadowing` test
//!   for the dispatch-seam proof of both directions.
//!
//! ## Entity construction
//!
//! Every `tools/call` maps onto the default MCP schema
//! (`crates/sbproxy-extension/data/mcp-schema.cedar`) the same way the
//! enterprise WOR-152 translator does, so a workspace can share Cedar
//! policy text across both tiers:
//!
//! - principal: `Agent::"<agent_id>"`, or `Agent::"anonymous"` when
//!   [`McpToolCallCtx::agent_id`] is `None`.
//! - action: `Action::"MCP::CallTool"` (a fixed literal; the default
//!   schema declares no other action this hook dispatches).
//! - resource: `ToolInvocation::"<mcp_server>/<tool_name>"`.
//! - context: empty. The default schema declares no context
//!   attributes for `MCP::CallTool`; materialising the full
//!   `Agent` / `Server` / `Tool` / `ArgumentBinding` entity graph so a
//!   policy can reference `resource.tool.name` or an argument value is
//!   follow-up work, tracked the same way
//!   `cedar::request_bridge::build_request`'s own doc comment already
//!   tracks the equivalent gap for its callers.
//!
//! `agent_id` and `tool_name` both come from an untrusted inbound
//! JSON-RPC request, so every id here is built through
//! [`EntityUid::from_type_name_and_id`] (which escapes arbitrary input
//! safely via `EntityId::new`) rather than interpolated into Cedar
//! source-text syntax and parsed.
//!
//! ## Verdict mapping
//!
//! [`CedarEvaluator::evaluate_uids`] already maps Cedar's
//! `Allow` / `Deny` decision onto [`PolicyDecision`], including the
//! `@confirm("reason")` annotation -> [`PolicyDecision::Confirm`]
//! extension (WOR-2587); see `cedar::evaluator` for the mapping. This
//! hook forwards that verdict unchanged.

use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::{EntityId, EntityTypeName, EntityUid};
use sbproxy_plugin::mcp::{McpPolicyHook, McpToolCallCtx};
use sbproxy_plugin::traits::PolicyDecision;

use crate::cedar::CedarEvaluator;

/// Cedar entity id used for the principal when a `tools/call` carries
/// no resolved agent identity. Matches the sentinel the enterprise
/// WOR-152 translator standardised on, so a workspace can write one
/// `forbid(principal == Agent::"anonymous", ...)` rule that means the
/// same thing whether Cedar is running OSS or enterprise.
const ANONYMOUS_AGENT_ID: &str = "anonymous";

/// Built-in OSS [`McpPolicyHook`] backed by a compiled Cedar policy
/// set.
///
/// Constructed once at config-load time from a workspace's
/// `cedar_policies` config block and held on the compiled
/// `sbproxy_modules::action::mcp::McpAction` (see that type's
/// `cedar_policy_hook` method). It only reaches
/// `sbproxy_plugin::mcp`'s global hook registry once the pipeline it
/// belongs to actually starts serving: `sbproxy_core::reload::load_pipeline`
/// installs it via `sbproxy_plugin::mcp::set_pipeline_mcp_policy_hooks`
/// at that publication boundary, not at compile time, so a
/// config-validation pass or a hot-reload candidate a lifecycle hook
/// goes on to reject never installs a hook that outlives it.
pub struct CedarMcpHook {
    evaluator: Arc<CedarEvaluator>,
    /// Server names (the `McpAction::prefixes` key space, i.e. the
    /// resolved names a `tools/call`'s `mcp_server` is drawn from)
    /// this hook's owning `mcp` action actually federates.
    ///
    /// A call for a server outside this set is not this hook's to
    /// judge: [`Self::evaluate_ctx`] answers `Allow` (a pass, not an
    /// opinion) rather than evaluating against a `PolicySet` that has
    /// never heard of the resource, which -- absent this check --
    /// Cedar's own default-deny turns into a wrong refusal (WOR-2587
    /// review). `sbproxy_plugin::mcp::set_pipeline_mcp_policy_hooks`
    /// collects every action's hook into one process-wide list and
    /// dispatch takes the first non-Allow verdict, so an unscoped hook
    /// would refuse every other action's tool calls the moment its own
    /// `PolicySet` did not happen to permit them.
    servers: std::collections::HashSet<String>,
}

impl CedarMcpHook {
    /// Wrap an already-compiled [`CedarEvaluator`] as an
    /// [`McpPolicyHook`], scoped to `servers` (the owning
    /// `McpAction`'s resolved server names).
    pub fn new(evaluator: Arc<CedarEvaluator>, servers: std::collections::HashSet<String>) -> Self {
        Self { evaluator, servers }
    }

    /// Build the Cedar principal / action / resource triple for a
    /// `tools/call` and evaluate it.
    ///
    /// Split out from [`McpPolicyHook::evaluate`] (whose signature
    /// returns a boxed future) so unit tests, and any future caller
    /// that wants a synchronous check, can call it directly.
    fn evaluate_ctx(&self, ctx: &McpToolCallCtx<'_>) -> PolicyDecision {
        if !self.servers.contains(ctx.mcp_server) {
            // Out of scope for this hook's action; defer to whichever
            // hook (or RBAC-only default) actually owns `mcp_server`.
            return PolicyDecision::Allow;
        }
        let principal = agent_uid(ctx.agent_id);
        // Fixed literal, not user input: safe to parse from Cedar
        // source-text syntax. The default MCP schema declares no
        // other action this hook has any reason to dispatch.
        let action = EntityUid::from_str(r#"Action::"MCP::CallTool""#)
            .unwrap_or_else(|e| unreachable!("MCP::CallTool action uid is a fixed literal: {e}"));
        let resource = tool_invocation_uid(ctx.mcp_server, ctx.tool_name);
        self.evaluator.evaluate_uids(principal, action, resource)
    }
}

impl McpPolicyHook for CedarMcpHook {
    fn evaluate<'a>(
        &'a self,
        ctx: McpToolCallCtx<'a>,
    ) -> Pin<Box<dyn Future<Output = PolicyDecision> + Send + 'a>> {
        // Cedar evaluation against an in-memory PolicySet is
        // synchronous CPU work; the boxed future exists to satisfy
        // the trait's object-safety contract, not to await anything.
        let decision = self.evaluate_ctx(&ctx);
        Box::pin(async move { decision })
    }
}

/// Build the `Agent::"<id>"` principal uid, or `Agent::"anonymous"`
/// when the call carries no resolved identity.
fn agent_uid(agent_id: Option<&str>) -> EntityUid {
    let ty = EntityTypeName::from_str("Agent")
        .unwrap_or_else(|e| unreachable!("Agent is a fixed schema literal: {e}"));
    let id = EntityId::new(agent_id.unwrap_or(ANONYMOUS_AGENT_ID));
    EntityUid::from_type_name_and_id(ty, id)
}

/// Build the `ToolInvocation::"<server>/<tool>"` resource uid.
fn tool_invocation_uid(mcp_server: &str, tool_name: &str) -> EntityUid {
    let ty = EntityTypeName::from_str("ToolInvocation")
        .unwrap_or_else(|e| unreachable!("ToolInvocation is a fixed schema literal: {e}"));
    let id = EntityId::new(format!("{mcp_server}/{tool_name}"));
    EntityUid::from_type_name_and_id(ty, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar::compile_all;

    /// No schema on either side: these tests pin entity construction
    /// and verdict mapping, which do not depend on schema validation.
    /// The default-schema, strict-validation path this hook uses in
    /// production is exercised end to end by the config-compile step
    /// in `sbproxy_modules::action::mcp` and by the dispatch-seam
    /// integration test in `sbproxy_core::server::action_dispatch`.
    fn hook_from_source(src: &str) -> CedarMcpHook {
        let compiled = compile_all(&[("t", src)], None).expect("compile");
        let evaluator = CedarEvaluator::new(compiled.policy_set, None).expect("new evaluator");
        CedarMcpHook::new(Arc::new(evaluator), ["srv".to_string()].into_iter().collect())
    }

    fn ctx<'a>(agent_id: Option<&'a str>, server: &'a str, tool: &'a str) -> McpToolCallCtx<'a> {
        static ARGS: serde_json::Value = serde_json::Value::Null;
        McpToolCallCtx {
            agent_id,
            mcp_server: server,
            tool_name: tool,
            arguments: &ARGS,
            correlation_id: "",
            workspace_id: "",
            audit_cause: None,
        }
    }

    /// A `permit` matching the constructed `Agent`/`ToolInvocation`
    /// pair allows the call. Pins the entity-construction contract:
    /// `mcp_server` and `tool_name` join into the resource id exactly
    /// the way a policy author would write it by hand.
    #[tokio::test]
    async fn allow_verdict_reaches_the_hook() {
        let hook = hook_from_source(
            r#"permit(
                principal == Agent::"agent-1",
                action,
                resource == ToolInvocation::"srv/tool_a"
            );"#,
        );
        let verdict = hook.evaluate(ctx(Some("agent-1"), "srv", "tool_a")).await;
        assert_eq!(verdict, PolicyDecision::Allow);
    }

    /// A `forbid` matching the pair denies the call, even though the
    /// hook's own schema and evaluator are shared across every
    /// `tools/call` this test drives.
    #[tokio::test]
    async fn deny_verdict_reaches_the_hook() {
        let hook = hook_from_source(
            r#"
            permit(principal, action, resource);
            forbid(
                principal,
                action,
                resource == ToolInvocation::"srv/dangerous_tool"
            );
            "#,
        );
        let verdict = hook
            .evaluate(ctx(Some("agent-1"), "srv", "dangerous_tool"))
            .await;
        match verdict {
            PolicyDecision::Deny { status, .. } => assert_eq!(status, 403),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    /// A `forbid` annotated `@confirm(...)` surfaces as
    /// `PolicyDecision::Confirm` through the full hook, not just
    /// through the evaluator it wraps.
    #[tokio::test]
    async fn confirm_verdict_reaches_the_hook() {
        let hook = hook_from_source(
            r#"
            permit(principal, action, resource);

            @confirm("high-risk tool requires human approval")
            forbid(
                principal,
                action,
                resource == ToolInvocation::"srv/risky_tool"
            );
            "#,
        );
        let verdict = hook
            .evaluate(ctx(Some("agent-1"), "srv", "risky_tool"))
            .await;
        match verdict {
            PolicyDecision::Confirm { reason, .. } => {
                assert_eq!(reason, "high-risk tool requires human approval");
            }
            other => panic!("expected Confirm, got {other:?}"),
        }
    }

    /// `agent_id: None` (an unauthenticated caller) maps to the
    /// `Agent::"anonymous"` sentinel, so a workspace can write one
    /// rule that governs every anonymous call.
    #[tokio::test]
    async fn anonymous_agent_maps_to_anonymous_uid() {
        let hook = hook_from_source(
            r#"forbid(
                principal == Agent::"anonymous",
                action,
                resource
            );"#,
        );
        let verdict = hook.evaluate(ctx(None, "srv", "tool_a")).await;
        assert!(matches!(verdict, PolicyDecision::Deny { .. }));
    }

    /// Rubric review (WOR-2587): this hook builds a bare
    /// `Agent::"<id>"` principal with no ancestor entities (see this
    /// module's "Entity construction" doc section), so a policy
    /// written with Cedar's `in` ancestor operator against a group
    /// entity -- the shape `sbproxy_modules::action::mcp`'s own
    /// module docs used to show as the flagship `cedar_policies:`
    /// example -- can never match, for any agent, ever. Pinning this
    /// here so the doc-example fix stays honest and so materialising
    /// real ancestor entities (tracked as follow-up work in this
    /// module's doc comment) has a test that goes green, not one that
    /// silently stops meaning anything.
    #[tokio::test]
    async fn group_membership_never_matches_without_ancestor_entities() {
        let hook = hook_from_source(
            r#"permit(
                principal in AgentClass::"trusted",
                action,
                resource == ToolInvocation::"srv/tool_a"
            );"#,
        );
        let verdict = hook.evaluate(ctx(Some("agent-1"), "srv", "tool_a")).await;
        assert!(
            matches!(verdict, PolicyDecision::Deny { .. }),
            "an `in`-based policy must never match while entities are empty, got {verdict:?}"
        );
    }

    /// A call that matches no rule at all falls through to Cedar's
    /// own default-deny, exactly like every other Cedar policy set in
    /// this codebase.
    #[tokio::test]
    async fn unmatched_call_defaults_to_deny() {
        let hook = hook_from_source(
            r#"permit(
                principal == Agent::"agent-1",
                action,
                resource == ToolInvocation::"srv/tool_a"
            );"#,
        );
        let verdict = hook
            .evaluate(ctx(Some("someone-else"), "srv", "tool_a"))
            .await;
        assert!(matches!(verdict, PolicyDecision::Deny { .. }));
    }

    /// WOR-2587 review: a hook scoped to one action's servers must not
    /// opine on a `tools/call` for a server outside that scope, even
    /// when its own policy set would otherwise default-deny an
    /// unmatched resource. Two pipeline actions can each declare
    /// `cedar_policies:` for their own, disjoint `federated_servers`;
    /// `sbproxy_plugin::mcp::set_pipeline_mcp_policy_hooks` flattens
    /// both hooks into one list and dispatch stops at the first
    /// non-Allow verdict, so an unscoped hook answering Deny for a
    /// server it has never heard of would silently shadow the other
    /// action's own (correct) verdict for that call.
    #[tokio::test]
    async fn out_of_scope_server_defers_with_allow_regardless_of_policy() {
        let hook = hook_from_source(r#"forbid(principal, action, resource);"#);
        let verdict = hook
            .evaluate(ctx(Some("agent-1"), "other-srv", "tool_a"))
            .await;
        assert_eq!(
            verdict,
            PolicyDecision::Allow,
            "a server this hook was not scoped to must be a pass, not a verdict"
        );
    }
}
