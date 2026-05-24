// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! MCP policy hook trait surface.
//!
//! The MCP federation layer calls registered [`McpPolicyHook`] impls
//! immediately before forwarding a `tools/call` JSON-RPC request to an
//! upstream MCP server. Each hook inspects the in-flight context and
//! returns a [`PolicyDecision`] that decides whether the call proceeds,
//! is denied with a JSON-RPC error, or is parked for human approval.
//!
//! ## Why a separate trait surface
//!
//! [`crate::traits::PolicyEnforcer`] is addressed by name from the
//! compiled handler chain and operates on the raw `http::Request`. The
//! MCP pre-tool-call hook runs at a fixed phase (between tool resolution
//! and `dispatch_request`) and consumes the parsed JSON-RPC view of the
//! request rather than the underlying HTTP wire format. Mixing the two
//! shapes would force every [`crate::traits::PolicyEnforcer`] to either
//! learn the MCP request shape or get spurious invocations on non-MCP
//! traffic.
//!
//! ## Registration
//!
//! Hooks register at link time through [`inventory::submit!`] using
//! [`McpPolicyHookEntry`]. The federation layer iterates registered
//! entries through [`mcp_policy_hooks`] and dispatches the first
//! matching hook. When no hooks register, [`default_no_op_hook`]
//! returns [`PolicyDecision::Allow`] so the OSS-only build forwards
//! every `tools/call` unchanged.
//!
//! ## Verdict semantics (PR β)
//!
//! - [`PolicyDecision::Allow`]: forward the call to the upstream.
//! - [`PolicyDecision::Deny`]: short-circuit with a JSON-RPC `-32603`
//!   error response carrying the deny message; upstream is never
//!   contacted.
//! - [`PolicyDecision::AllowWithHeaders`]: treated as `Allow`; the
//!   header list is dropped because JSON-RPC has no response-header
//!   surface. PR γ adds the verdict combiner that will route this
//!   through a JSON-RPC `meta` field.
//! - [`PolicyDecision::Confirm`]: currently treated as `Deny` because
//!   the `PendingConfirmStore` (PR ζ) is not yet built. Documented in
//!   the federation call site so the future cleanup is obvious.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use crate::traits::PolicyDecision;

/// Per-`tools/call` view consumed by [`McpPolicyHook::evaluate`].
///
/// All fields are borrowed for the duration of the call; the federation
/// layer constructs the view from its in-flight state and does not
/// retain it past the await. Hook impls that need owned data clone
/// inside their `evaluate` body.
#[derive(Debug)]
pub struct McpToolCallCtx<'a> {
    /// Resolved agent identifier (KYA `sub`, JWT subject, virtual key,
    /// etc.). `None` when the request was authenticated without a
    /// per-caller identity, or when the call site has not threaded an
    /// agent id through. Hook impls treat `None` as "anonymous" rather
    /// than "any".
    pub agent_id: Option<&'a str>,
    /// Logical name of the upstream MCP server that owns the requested
    /// tool. Matches `McpServerConfig.name` in the OSS federation
    /// crate. Always populated.
    pub mcp_server: &'a str,
    /// Tool name from the JSON-RPC `tools/call` params (post tool
    /// resolution, before any server-prefix rewriting). Always
    /// populated.
    pub tool_name: &'a str,
    /// Raw tool arguments from the JSON-RPC `tools/call` params, exactly
    /// as the client sent them. Hook impls inspect this for semantic
    /// pattern matching (regex, JSON path, schema validation). May be
    /// `serde_json::Value::Null` when the client omitted arguments.
    pub arguments: &'a serde_json::Value,
    /// Correlation id stamped on the request for cross-system tracing.
    /// Empty string when the call site has not threaded one through;
    /// hook impls should not branch on emptiness because the value is
    /// purely diagnostic.
    pub correlation_id: &'a str,
    /// Workspace id for multi-tenant policy lookup. Empty string when
    /// the call site has not threaded one through; the enterprise
    /// dispatcher (PR ε) treats empty as the default tenant.
    pub workspace_id: &'a str,
}

/// Pre-tool-call policy hook for MCP federation.
///
/// Implementations decide whether a `tools/call` proceeds, is denied,
/// or is parked for approval. The trait returns a pinned future rather
/// than using `async fn` so the trait stays object-safe under
/// `dyn McpPolicyHook` and the federation layer can iterate registered
/// hooks behind an `Arc<dyn McpPolicyHook>`.
pub trait McpPolicyHook: Send + Sync + 'static {
    /// Evaluate the policy against the in-flight tool call. The returned
    /// future must be `Send` so the federation can `.await` it from any
    /// pingora worker.
    fn evaluate<'a>(
        &'a self,
        ctx: McpToolCallCtx<'a>,
    ) -> Pin<Box<dyn Future<Output = PolicyDecision> + Send + 'a>>;
}

/// Inventory entry registered by enterprise crates so the OSS
/// federation discovers them at link time without any explicit
/// registration call. See [`inventory::submit!`] for the registration
/// shape used by impls.
pub struct McpPolicyHookEntry {
    /// Factory that constructs the hook. Returning an `Arc` keeps the
    /// hook clonable across the federation's iteration without
    /// forcing the trait object behind another layer of indirection.
    pub factory: fn() -> Arc<dyn McpPolicyHook>,
}

inventory::collect!(McpPolicyHookEntry);

// Runtime-installable hook registry. Mirrors the
// `identity::register_*_hook` pattern: inventory entries are immovable
// across the process lifetime, so tests use this slot to install impls
// without polluting the link-time feed. Iteration order is
// registration order; the federation in PR β reads only the first
// entry across both registries (inventory first, runtime second).
static RUNTIME_HOOKS: Mutex<Vec<Arc<dyn McpPolicyHook>>> = Mutex::new(Vec::new());

/// Install an [`McpPolicyHook`] at runtime.
///
/// Each call appends a new impl. Iteration through [`mcp_policy_hooks`]
/// returns inventory-registered impls first, then runtime-registered
/// impls in registration order. Tests and integration glue use this
/// instead of [`inventory::submit!`] because inventory entries cannot
/// be removed.
///
/// ## Panics
///
/// Panics if the internal registry mutex is poisoned, which only
/// happens if a previous caller panicked while holding the lock. The
/// registry holds the lock only long enough to push one entry, so this
/// should not occur in practice.
pub fn register_mcp_policy_hook(hook: Arc<dyn McpPolicyHook>) {
    RUNTIME_HOOKS
        .lock()
        .expect("mcp policy hook registry poisoned")
        .push(hook);
}

/// Snapshot every registered [`McpPolicyHook`] in registration order.
///
/// Inventory-feed impls come first (in link-time order) followed by
/// runtime-installed impls (in registration order). The federation
/// layer iterates this list and dispatches the first matching hook
/// (PR β semantics). PR γ will replace the first-hook shortcut with a
/// verdict combiner that aggregates across every hook in the slice.
///
/// ## Panics
///
/// Panics if the internal runtime-hook registry mutex is poisoned (a
/// prior holder panicked while holding the lock). The link-time
/// inventory feed is read without locking and does not contribute to
/// this condition.
pub fn mcp_policy_hooks() -> Vec<Arc<dyn McpPolicyHook>> {
    let mut hooks: Vec<Arc<dyn McpPolicyHook>> = inventory::iter::<McpPolicyHookEntry>()
        .map(|entry| (entry.factory)())
        .collect();
    let runtime = RUNTIME_HOOKS
        .lock()
        .expect("mcp policy hook registry poisoned")
        .clone();
    hooks.extend(runtime);
    hooks
}

/// Permissive default that returns [`PolicyDecision::Allow`] for every
/// request. The federation layer uses this when no enterprise hook is
/// registered so the OSS build forwards every `tools/call` unchanged.
pub fn default_no_op_hook() -> Arc<dyn McpPolicyHook> {
    Arc::new(NoOpMcpPolicyHook)
}

/// Default no-op hook impl. Returns [`PolicyDecision::Allow`] for every
/// invocation. Exposed publicly so enterprise crates can compose it
/// (for example, as a fallback after an inner dispatcher returns
/// `None`).
pub struct NoOpMcpPolicyHook;

impl McpPolicyHook for NoOpMcpPolicyHook {
    fn evaluate<'a>(
        &'a self,
        _ctx: McpToolCallCtx<'a>,
    ) -> Pin<Box<dyn Future<Output = PolicyDecision> + Send + 'a>> {
        Box::pin(async move { PolicyDecision::Allow })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The default no-op hook returns `Allow` for any context shape.
    /// This pins the OSS-only-build contract: with zero enterprise
    /// crates linked, the federation forwards every `tools/call`.
    #[tokio::test]
    async fn no_op_hook_returns_allow() {
        let hook = default_no_op_hook();
        let args = serde_json::json!({"q": "hello"});
        let ctx = McpToolCallCtx {
            agent_id: None,
            mcp_server: "search-server",
            tool_name: "web_search",
            arguments: &args,
            correlation_id: "",
            workspace_id: "",
        };
        let verdict = hook.evaluate(ctx).await;
        assert!(matches!(verdict, PolicyDecision::Allow));
    }

    /// The no-op hook reads every field without panicking even when
    /// the optional fields are `None` / empty. The federation layer
    /// constructs ctxs with these defaults from OSS call sites that
    /// have not yet threaded the full identity surface through.
    #[tokio::test]
    async fn no_op_hook_handles_anonymous_caller() {
        let hook = default_no_op_hook();
        let args = serde_json::Value::Null;
        let ctx = McpToolCallCtx {
            agent_id: None,
            mcp_server: "s",
            tool_name: "t",
            arguments: &args,
            correlation_id: "",
            workspace_id: "",
        };
        let verdict = hook.evaluate(ctx).await;
        assert_eq!(verdict, PolicyDecision::Allow);
    }

    // --- Test hook impl that records inputs and returns a fixed verdict. ---

    /// One observed call: `(agent_id, mcp_server, tool_name,
    /// correlation_id, workspace_id)`.
    type ObservedCall = (Option<String>, String, String, String, String);

    struct RecordingHook {
        inputs: Arc<Mutex<Vec<ObservedCall>>>,
        verdict: PolicyDecision,
    }

    impl McpPolicyHook for RecordingHook {
        fn evaluate<'a>(
            &'a self,
            ctx: McpToolCallCtx<'a>,
        ) -> Pin<Box<dyn Future<Output = PolicyDecision> + Send + 'a>> {
            self.inputs.lock().unwrap().push((
                ctx.agent_id.map(str::to_string),
                ctx.mcp_server.to_string(),
                ctx.tool_name.to_string(),
                ctx.correlation_id.to_string(),
                ctx.workspace_id.to_string(),
            ));
            let v = self.verdict.clone();
            Box::pin(async move { v })
        }
    }

    /// A hook impl can record every field it received and produce a
    /// configured verdict. Pins the contract that `evaluate` sees the
    /// caller's view exactly as the federation built it.
    #[tokio::test]
    async fn hook_observes_every_ctx_field() {
        let inputs = Arc::new(Mutex::new(Vec::new()));
        let hook: Arc<dyn McpPolicyHook> = Arc::new(RecordingHook {
            inputs: inputs.clone(),
            verdict: PolicyDecision::Deny {
                status: 403,
                message: "blocked".to_string(),
            },
        });
        let args = serde_json::json!({"target": "production"});
        let ctx = McpToolCallCtx {
            agent_id: Some("agent-42"),
            mcp_server: "prod-db",
            tool_name: "execute_sql",
            arguments: &args,
            correlation_id: "corr-abc",
            workspace_id: "ws-1",
        };
        let verdict = hook.evaluate(ctx).await;
        match verdict {
            PolicyDecision::Deny { status, message } => {
                assert_eq!(status, 403);
                assert_eq!(message, "blocked");
            }
            other => panic!("expected Deny, got {:?}", other),
        }
        let recorded = inputs.lock().unwrap().clone();
        assert_eq!(recorded.len(), 1);
        let (aid, server, tool, corr, ws) = &recorded[0];
        assert_eq!(aid.as_deref(), Some("agent-42"));
        assert_eq!(server, "prod-db");
        assert_eq!(tool, "execute_sql");
        assert_eq!(corr, "corr-abc");
        assert_eq!(ws, "ws-1");
    }
}
