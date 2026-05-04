//! Anthropic A2A parser (Wave 7 / A7.2, `draft-anthropic-a2a-v0`).
//!
//! The Anthropic draft models A2A invocation as an MCP method call
//! where the tool is another agent. The `MCP-Method: agents.invoke`
//! header marks the request; the body envelope carries the chain
//! state. Body shape under the v0 draft:
//!
//! ```json
//! {
//!   "method": "agents.invoke",
//!   "params": {
//!     "callee": "agent:openai:gpt-5",
//!     "task_id": "01J7HZ8X9R3CAPE2E",
//!     "parent_request_id": "req-abc",
//!     "chain_depth": 2,
//!     "chain": [
//!       { "agent_id": "agent:internal:my-orchestrator",
//!         "request_id": "req-root",
//!         "timestamp_ms": 1714694400000 }
//!     ]
//!   }
//! }
//! ```
//!
//! The parser tolerates missing fields (zero-defaults the chain
//! depth, treats absent chains as empty) so partially-populated
//! envelopes still yield a usable [`A2AContext`].

use super::{A2AContext, A2ASpec, ChainHop};

/// Parse an Anthropic A2A request body into an [`A2AContext`].
///
/// `caller_agent_id` is the resolved identity of the calling agent
/// (typically from the G1.4 resolver chain); the parser stamps it
/// onto the context because the wire envelope does not echo the
/// caller (the receiving agent infers it from the connection).
///
/// Returns `None` when the body is malformed enough that no useful
/// fields can be extracted; callers should fall back to
/// [`A2AContext::empty`] in that case.
pub fn parse(body: &[u8], caller_agent_id: &str) -> Option<A2AContext> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let params = v.get("params")?;

    let callee_agent_id = params
        .get("callee")
        .and_then(|s| s.as_str())
        .map(str::to_string);
    let task_id = params
        .get("task_id")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let parent_request_id = params
        .get("parent_request_id")
        .and_then(|s| s.as_str())
        .map(str::to_string);
    let chain_depth = params
        .get("chain_depth")
        .and_then(|d| d.as_u64())
        .map(|d| d as u32)
        .unwrap_or(1)
        .max(1);

    let chain = params
        .get("chain")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|hop| {
                    Some(ChainHop {
                        agent_id: hop.get("agent_id")?.as_str()?.to_string(),
                        request_id: hop.get("request_id")?.as_str()?.to_string(),
                        timestamp_ms: hop
                            .get("timestamp_ms")
                            .and_then(|t| t.as_u64())
                            .unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Some(A2AContext {
        spec: A2ASpec::AnthropicV0,
        caller_agent_id: caller_agent_id.to_string(),
        callee_agent_id,
        task_id,
        parent_request_id,
        chain_depth,
        chain,
        raw_envelope_version: "anthropic-v0".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_envelope() {
        let body = br#"{
            "method": "agents.invoke",
            "params": {
                "callee": "agent:openai:gpt-5",
                "task_id": "task-1",
                "parent_request_id": "req-parent",
                "chain_depth": 2,
                "chain": [
                    {"agent_id": "agent:root", "request_id": "req-root", "timestamp_ms": 100}
                ]
            }
        }"#;
        let ctx = parse(body, "agent:caller").unwrap();
        assert_eq!(ctx.spec, A2ASpec::AnthropicV0);
        assert_eq!(ctx.caller_agent_id, "agent:caller");
        assert_eq!(ctx.callee_agent_id.as_deref(), Some("agent:openai:gpt-5"));
        assert_eq!(ctx.task_id, "task-1");
        assert_eq!(ctx.parent_request_id.as_deref(), Some("req-parent"));
        assert_eq!(ctx.chain_depth, 2);
        assert_eq!(ctx.chain.len(), 1);
        assert_eq!(ctx.chain[0].agent_id, "agent:root");
        assert_eq!(ctx.chain[0].request_id, "req-root");
        assert_eq!(ctx.chain[0].timestamp_ms, 100);
    }

    #[test]
    fn parse_tolerates_missing_optional_fields() {
        let body = br#"{"params": {"callee": "agent:x"}}"#;
        let ctx = parse(body, "agent:caller").unwrap();
        assert_eq!(ctx.callee_agent_id.as_deref(), Some("agent:x"));
        assert_eq!(ctx.task_id, "");
        assert_eq!(ctx.parent_request_id, None);
        assert_eq!(ctx.chain_depth, 1);
        assert!(ctx.chain.is_empty());
    }

    #[test]
    fn parse_returns_none_for_empty_body() {
        assert!(parse(b"", "agent:caller").is_none());
    }

    #[test]
    fn parse_returns_none_when_params_missing() {
        let body = br#"{"method": "agents.invoke"}"#;
        assert!(parse(body, "agent:caller").is_none());
    }

    #[test]
    fn parse_returns_none_for_invalid_json() {
        assert!(parse(b"{not json", "agent:caller").is_none());
    }

    #[test]
    fn parse_clamps_chain_depth_to_at_least_one() {
        let body = br#"{"params": {"chain_depth": 0}}"#;
        let ctx = parse(body, "agent:caller").unwrap();
        assert_eq!(ctx.chain_depth, 1);
    }

    #[test]
    fn parse_skips_malformed_chain_entries() {
        let body = br#"{
            "params": {
                "chain": [
                    {"agent_id": "ok", "request_id": "rid"},
                    {"agent_id": "missing-rid"},
                    {"request_id": "missing-aid"}
                ]
            }
        }"#;
        let ctx = parse(body, "agent:caller").unwrap();
        assert_eq!(ctx.chain.len(), 1);
        assert_eq!(ctx.chain[0].agent_id, "ok");
    }
}
