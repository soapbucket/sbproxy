//! Google A2A parser (Wave 7 / A7.2, `draft-google-a2a-v0`).
//!
//! The Google draft uses a dedicated `application/a2a+json` content
//! type with a top-level envelope. Body shape under the v0 draft:
//!
//! ```json
//! {
//!   "caller_agent_id": "agent:internal:my-orchestrator",
//!   "callee_agent_id": "agent:openai:gpt-5",
//!   "task_id": "task-abc",
//!   "parent_request_id": "req-parent",
//!   "chain": [
//!     { "agent_id": "agent:internal:my-orchestrator",
//!       "request_id": "req-root",
//!       "timestamp_ms": 1714694400000 }
//!   ]
//! }
//! ```
//!
//! The Google envelope omits `chain_depth`; the parser derives it as
//! `chain.len() + 1` (the chain holds ancestors, the +1 is this hop).
//! When the envelope is missing fields the parser falls back to
//! safe zero-defaults so the policy module can still apply
//! route-level limits.

use super::{A2AContext, A2ASpec, ChainHop};

/// Parse a Google A2A request body into an [`A2AContext`].
///
/// `caller_fallback` is used when the envelope's `caller_agent_id`
/// field is missing; the resolved identity from the G1.4 chain is
/// the natural fallback.
///
/// Returns `None` when the body is not valid JSON; missing fields
/// inside a valid object still produce a usable context.
pub fn parse(body: &[u8], caller_fallback: &str) -> Option<A2AContext> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let obj = v.as_object()?;

    let caller_agent_id = obj
        .get("caller_agent_id")
        .and_then(|s| s.as_str())
        .unwrap_or(caller_fallback)
        .to_string();
    let callee_agent_id = obj
        .get("callee_agent_id")
        .and_then(|s| s.as_str())
        .map(str::to_string);
    let task_id = obj
        .get("task_id")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let parent_request_id = obj
        .get("parent_request_id")
        .and_then(|s| s.as_str())
        .map(str::to_string);

    let chain: Vec<ChainHop> = obj
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

    let chain_depth = (chain.len() as u32).saturating_add(1);

    Some(A2AContext {
        spec: A2ASpec::GoogleV0,
        caller_agent_id,
        callee_agent_id,
        task_id,
        parent_request_id,
        chain_depth,
        chain,
        raw_envelope_version: "google-v0".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_envelope() {
        let body = br#"{
            "caller_agent_id": "agent:internal:orchestrator",
            "callee_agent_id": "agent:openai:gpt-5",
            "task_id": "task-1",
            "parent_request_id": "req-parent",
            "chain": [
                {"agent_id": "agent:root", "request_id": "req-root", "timestamp_ms": 100},
                {"agent_id": "agent:mid", "request_id": "req-mid", "timestamp_ms": 200}
            ]
        }"#;
        let ctx = parse(body, "agent:fallback").unwrap();
        assert_eq!(ctx.spec, A2ASpec::GoogleV0);
        assert_eq!(ctx.caller_agent_id, "agent:internal:orchestrator");
        assert_eq!(ctx.callee_agent_id.as_deref(), Some("agent:openai:gpt-5"));
        assert_eq!(ctx.task_id, "task-1");
        assert_eq!(ctx.parent_request_id.as_deref(), Some("req-parent"));
        assert_eq!(ctx.chain.len(), 2);
        assert_eq!(ctx.chain_depth, 3);
    }

    #[test]
    fn parse_uses_fallback_when_caller_missing() {
        let body = br#"{"callee_agent_id": "agent:x"}"#;
        let ctx = parse(body, "agent:fallback").unwrap();
        assert_eq!(ctx.caller_agent_id, "agent:fallback");
    }

    #[test]
    fn parse_returns_none_for_invalid_json() {
        assert!(parse(b"not json", "agent:f").is_none());
    }

    #[test]
    fn parse_returns_none_for_non_object_root() {
        assert!(parse(b"[1,2]", "agent:f").is_none());
    }

    #[test]
    fn parse_empty_chain_yields_depth_one() {
        let body = br#"{"caller_agent_id": "agent:c"}"#;
        let ctx = parse(body, "agent:f").unwrap();
        assert!(ctx.chain.is_empty());
        assert_eq!(ctx.chain_depth, 1);
    }

    #[test]
    fn parse_skips_malformed_chain_entries() {
        let body = br#"{
            "chain": [
                {"agent_id": "ok", "request_id": "rid"},
                {"missing": "fields"}
            ]
        }"#;
        let ctx = parse(body, "agent:f").unwrap();
        assert_eq!(ctx.chain.len(), 1);
        assert_eq!(ctx.chain_depth, 2);
    }
}
