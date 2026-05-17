//! Verify-before-commit extension for MCP tool calls (VIGIL pattern).
//!
//! Implements the verify-before-commit posture argued for in VIGIL
//! (arxiv 2601.05755) and reinforced by MCPTox (arxiv 2508.14925),
//! which measured a 72.8% attack success rate on o1-mini when MCP
//! tool calls were forwarded with no pre-commit verification.
//!
//! The [`VerifyBeforeCommit`] trait is the extension surface: callers
//! supply a [`VerifyContext`] describing a proposed MCP tool call and
//! receive a [`VerifyVerdict`] of `Allow`, `Deny`, or `Confirm`.
//!
//! [`StaticDescriptorVerifier`] is the built-in implementation. It is
//! configured by a YAML descriptor that maps each tool name to a
//! required-arg list, a denied-arg list, and a maximum argument-tree
//! depth. Unknown tools are allowed by default (operator opt-in
//! model); operators choose which tools to harden by listing them in
//! the descriptor.
//!
//! [`CompositeVerifier`] composes several verifiers and short-circuits
//! on the first non-`Allow` verdict, so a registry of independent
//! checks (descriptor-based, allowlist-based, signature-based, ...)
//! can be evaluated together at MCP-gateway dispatch time.
//!
//! Actual wiring into the MCP gateway dispatch path lives in
//! `sbproxy-core::server::handle_mcp_action`; this module is the
//! verifier surface only.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;

/// Context for a single verify-before-commit check.
///
/// Lifetime parameter `'a` borrows from the caller's MCP dispatch
/// scope so the verifier sees the exact tool-call payload that would
/// have been forwarded.
#[derive(Debug)]
pub struct VerifyContext<'a> {
    /// MCP tool name (matches `tools/call` `name` field).
    pub tool_name: &'a str,
    /// Tool arguments object as decoded JSON.
    pub arguments: &'a serde_json::Value,
    /// JSON-RPC request id of the in-flight `tools/call` request.
    pub request_id: &'a str,
    /// Optional agent identifier (e.g. signed agent token sub claim).
    pub agent_id: Option<&'a str>,
}

/// Verdict returned by a [`VerifyBeforeCommit`] implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyVerdict {
    /// The tool call is safe to commit and may be forwarded.
    Allow,
    /// The tool call must be rejected. `reason` is surfaced to the
    /// caller in the MCP error response.
    Deny {
        /// Operator-facing rejection reason.
        reason: String,
    },
    /// The tool call needs human confirmation before it is forwarded.
    /// `rationale` describes which heuristic flagged the call.
    Confirm {
        /// Operator-facing rationale for the confirmation step.
        rationale: String,
    },
}

/// Inspect a proposed MCP tool call and decide whether to forward it.
///
/// Implementations are stored behind `Arc<dyn VerifyBeforeCommit>` so
/// the same instance can be shared across the request pipeline.
pub trait VerifyBeforeCommit: Send + Sync {
    /// Inspect the proposed tool call and return `Allow` / `Deny` /
    /// `Confirm`.
    fn check(&self, ctx: &VerifyContext) -> VerifyVerdict;
}

/// Per-tool descriptor used by [`StaticDescriptorVerifier`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDescriptor {
    /// Argument names that must be present on every call.
    #[serde(default)]
    pub required_args: Vec<String>,
    /// Argument names that must never appear on a call.
    #[serde(default)]
    pub denied_args: Vec<String>,
    /// Maximum allowed nesting depth of the arguments JSON value.
    /// A depth greater than this escalates to `Confirm`.
    #[serde(default = "default_max_arg_depth")]
    pub max_arg_depth: u32,
}

fn default_max_arg_depth() -> u32 {
    // 8 levels is roughly the depth at which prompt-injection
    // payloads start to hide in nested structures; below that a
    // human-confirm step is almost certainly not necessary.
    8
}

/// YAML file shape accepted by
/// [`StaticDescriptorVerifier::from_yaml`].
///
/// The file is a top-level map from tool name to descriptor:
///
/// ```yaml
/// tools:
///   fs.read:
///     required_args: [path]
///     denied_args: [follow_symlinks]
///     max_arg_depth: 4
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorFile {
    /// Tool-name to descriptor map.
    pub tools: HashMap<String, ToolDescriptor>,
}

/// Built-in verifier driven by a static YAML descriptor file.
///
/// Unknown tool names return `Allow` (operator opt-in model): the
/// operator must explicitly list a tool to harden it.
#[derive(Debug, Clone, Default)]
pub struct StaticDescriptorVerifier {
    tools: HashMap<String, ToolDescriptor>,
}

impl StaticDescriptorVerifier {
    /// Build a verifier from an already-parsed descriptor map.
    pub fn new(tools: HashMap<String, ToolDescriptor>) -> Self {
        Self { tools }
    }

    /// Build a verifier from a YAML descriptor string.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        let file: DescriptorFile = serde_yaml::from_str(yaml)?;
        Ok(Self::new(file.tools))
    }

    /// Return the descriptor for `tool_name`, if any.
    pub fn descriptor(&self, tool_name: &str) -> Option<&ToolDescriptor> {
        self.tools.get(tool_name)
    }
}

impl VerifyBeforeCommit for StaticDescriptorVerifier {
    fn check(&self, ctx: &VerifyContext) -> VerifyVerdict {
        let descriptor = match self.tools.get(ctx.tool_name) {
            Some(d) => d,
            // Operator opt-in: tools not listed in the descriptor are
            // not verified by this checker.
            None => return VerifyVerdict::Allow,
        };

        // Required-arg check. Only object-shaped arguments can carry
        // named fields; anything else is treated as missing every
        // required arg.
        let args_obj = ctx.arguments.as_object();
        for required in &descriptor.required_args {
            let present = args_obj.map(|m| m.contains_key(required)).unwrap_or(false);
            if !present {
                return VerifyVerdict::Deny {
                    reason: format!(
                        "tool '{}' missing required argument '{}'",
                        ctx.tool_name, required
                    ),
                };
            }
        }

        // Denied-arg check. We walk every nested object so that a
        // denied name buried deep in the tree is still caught.
        if !descriptor.denied_args.is_empty() {
            if let Some(found) = find_denied_key(ctx.arguments, &descriptor.denied_args) {
                return VerifyVerdict::Deny {
                    reason: format!(
                        "tool '{}' contains denied argument '{}'",
                        ctx.tool_name, found
                    ),
                };
            }
        }

        // Depth check. A deeply nested argument is the shape of a
        // smuggled prompt-injection payload, so we escalate rather
        // than deny outright; the proxy surfaces a confirm step.
        let depth = value_depth(ctx.arguments);
        if depth > descriptor.max_arg_depth {
            return VerifyVerdict::Confirm {
                rationale: format!(
                    "tool '{}' argument depth {} exceeds max {}",
                    ctx.tool_name, depth, descriptor.max_arg_depth
                ),
            };
        }

        VerifyVerdict::Allow
    }
}

/// Compose several verifiers and short-circuit on the first non-`Allow`.
///
/// Order matters: earlier verifiers see the call first and their
/// verdict wins on a tie.
#[derive(Clone, Default)]
pub struct CompositeVerifier {
    /// Verifiers evaluated in order.
    pub verifiers: Vec<Arc<dyn VerifyBeforeCommit>>,
}

impl CompositeVerifier {
    /// Create an empty composite. With no verifiers attached every
    /// call returns `Allow`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a verifier to the chain.
    pub fn push(&mut self, verifier: Arc<dyn VerifyBeforeCommit>) {
        self.verifiers.push(verifier);
    }
}

impl VerifyBeforeCommit for CompositeVerifier {
    fn check(&self, ctx: &VerifyContext) -> VerifyVerdict {
        for verifier in &self.verifiers {
            let verdict = verifier.check(ctx);
            if !matches!(verdict, VerifyVerdict::Allow) {
                return verdict;
            }
        }
        VerifyVerdict::Allow
    }
}

/// Walk every nested object and return the first denied key name we
/// see.
fn find_denied_key<'a>(value: &serde_json::Value, denied: &'a [String]) -> Option<&'a str> {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if let Some(hit) = denied.iter().find(|d| d.as_str() == k.as_str()) {
                    return Some(hit.as_str());
                }
                if let Some(hit) = find_denied_key(v, denied) {
                    return Some(hit);
                }
            }
            None
        }
        serde_json::Value::Array(items) => {
            for item in items {
                if let Some(hit) = find_denied_key(item, denied) {
                    return Some(hit);
                }
            }
            None
        }
        _ => None,
    }
}

/// Compute the nesting depth of a JSON value.
///
/// A scalar (`null`, bool, number, string) is depth 0. An empty
/// object or array is depth 1. Nesting adds one per level.
fn value_depth(value: &serde_json::Value) -> u32 {
    match value {
        serde_json::Value::Object(map) => 1 + map.values().map(value_depth).max().unwrap_or(0),
        serde_json::Value::Array(items) => 1 + items.iter().map(value_depth).max().unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx<'a>(tool: &'a str, args: &'a serde_json::Value) -> VerifyContext<'a> {
        VerifyContext {
            tool_name: tool,
            arguments: args,
            request_id: "req-1",
            agent_id: None,
        }
    }

    fn fs_read_verifier() -> StaticDescriptorVerifier {
        let yaml = r#"
tools:
  fs.read:
    required_args: [path]
    denied_args: [follow_symlinks]
    max_arg_depth: 4
"#;
        StaticDescriptorVerifier::from_yaml(yaml).expect("parse descriptor")
    }

    #[test]
    fn static_required_arg_missing_returns_deny() {
        let v = fs_read_verifier();
        let args = json!({});
        let verdict = v.check(&ctx("fs.read", &args));
        match verdict {
            VerifyVerdict::Deny { reason } => {
                assert!(reason.contains("path"), "reason names the missing arg");
                assert!(reason.contains("fs.read"), "reason names the tool");
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[test]
    fn static_denied_arg_present_returns_deny() {
        let v = fs_read_verifier();
        let args = json!({"path": "/etc/passwd", "follow_symlinks": true});
        let verdict = v.check(&ctx("fs.read", &args));
        match verdict {
            VerifyVerdict::Deny { reason } => {
                assert!(reason.contains("follow_symlinks"));
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[test]
    fn static_deep_nesting_returns_confirm() {
        let v = fs_read_verifier();
        // max_arg_depth is 4. Build an object whose argument value
        // is itself nested 6 levels deep, so total depth from the
        // top-level object is 7 (> 4).
        let args = json!({
            "path": {"a": {"b": {"c": {"d": {"e": {"f": "leaf"}}}}}}
        });
        let verdict = v.check(&ctx("fs.read", &args));
        match verdict {
            VerifyVerdict::Confirm { rationale } => {
                assert!(rationale.contains("depth"));
                assert!(rationale.contains("fs.read"));
            }
            other => panic!("expected Confirm, got {:?}", other),
        }
    }

    #[test]
    fn static_clean_call_returns_allow() {
        let v = fs_read_verifier();
        let args = json!({"path": "/tmp/file.txt"});
        assert_eq!(v.check(&ctx("fs.read", &args)), VerifyVerdict::Allow);
    }

    #[test]
    fn static_unknown_tool_returns_allow_by_default() {
        // Operator opt-in: tools not present in the descriptor pass
        // through without a verdict from this checker.
        let v = fs_read_verifier();
        let args = json!({"anything": "goes"});
        assert_eq!(v.check(&ctx("not.listed", &args)), VerifyVerdict::Allow);
    }

    #[test]
    fn composite_first_non_allow_wins() {
        // Pin a deterministic verifier that always allows, then one
        // that always denies, then one that would Confirm. The Deny
        // must surface and the Confirm must never be reached.
        struct AlwaysAllow;
        impl VerifyBeforeCommit for AlwaysAllow {
            fn check(&self, _ctx: &VerifyContext) -> VerifyVerdict {
                VerifyVerdict::Allow
            }
        }
        struct AlwaysDeny;
        impl VerifyBeforeCommit for AlwaysDeny {
            fn check(&self, _ctx: &VerifyContext) -> VerifyVerdict {
                VerifyVerdict::Deny {
                    reason: "deny-wins".into(),
                }
            }
        }
        struct AlwaysConfirm;
        impl VerifyBeforeCommit for AlwaysConfirm {
            fn check(&self, _ctx: &VerifyContext) -> VerifyVerdict {
                VerifyVerdict::Confirm {
                    rationale: "should-not-reach".into(),
                }
            }
        }

        let mut composite = CompositeVerifier::new();
        composite.push(Arc::new(AlwaysAllow));
        composite.push(Arc::new(AlwaysDeny));
        composite.push(Arc::new(AlwaysConfirm));

        let args = json!({});
        let verdict = composite.check(&ctx("any", &args));
        match verdict {
            VerifyVerdict::Deny { reason } => assert_eq!(reason, "deny-wins"),
            other => panic!("expected Deny from second verifier, got {:?}", other),
        }
    }

    #[test]
    fn composite_all_allow_returns_allow() {
        // Sanity check that an empty composite (no verifiers) and a
        // composite of pure-Allow verifiers both Allow.
        let composite = CompositeVerifier::new();
        let args = json!({});
        assert_eq!(composite.check(&ctx("any", &args)), VerifyVerdict::Allow);
    }
}
