//! Canonical, content-addressed identity for an MCP tool contract.
//!
//! A tool's identity is a digest over its contract (the fields an agent relies
//! on), not its transport-level extras. Two tools with the same contract in a
//! different key order, or carrying unrelated metadata, share a digest, so the
//! oracle reacts only when the contract itself moves.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Tool fields that make up the contract, projected before hashing. Everything
/// else (for example `_meta`) is excluded so unrelated metadata churn does not
/// change identity.
const CONTRACT_FIELDS: [&str; 6] = [
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
];

/// Content-addressed identity of a tool contract: `sha256:<hex>` over the
/// RFC 8785 (JCS) canonical form of the tool's contract projection.
///
/// Equal digests mean equal contracts. The value is stable across key
/// reordering and whitespace and is unaffected by fields outside the contract
/// projection.
pub fn contract_digest(tool: &Value) -> String {
    let projected = project_contract(tool);
    // Canonicalizing a JSON object is infallible here: a serde_json::Value
    // cannot hold NaN or infinity, the only inputs JCS rejects. The empty
    // fallback is unreachable and only keeps this path free of unwrap/panic.
    let canonical = serde_json_canonicalizer::to_vec(&projected).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(&canonical)))
}

/// The contract projection of a live federated tool.
///
/// The one place a live tool becomes a contract, so the gate and any
/// lockfile generator cannot construct different inputs for the same
/// tool and disagree about its digest (WOR-2443). Before this existed
/// the projection was built inline at the call site, which meant the
/// recipe was defined by whichever caller you happened to read.
///
/// [`FederatedTool`] carries three of the six contract fields today:
/// `title`, `outputSchema`, and `annotations` have no home on it, so
/// they are absent from the projection rather than null. That is the
/// intended behavior, since the projection includes only fields that
/// are present, but it does mean a digest over a live tool is not
/// interchangeable with a digest over a raw upstream `tools/list` entry
/// that carries the other three. Generate baselines from this function.
///
/// [`FederatedTool`]: crate::mcp::federation::FederatedTool
pub fn contract_of(tool: &crate::mcp::federation::FederatedTool) -> Value {
    serde_json::json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    })
}

/// Project a tool value down to its contract fields, dropping everything else.
fn project_contract(tool: &Value) -> Value {
    let mut out = Map::new();
    if let Some(obj) = tool.as_object() {
        for field in CONTRACT_FIELDS {
            if let Some(value) = obj.get(field) {
                out.insert(field.to_string(), value.clone());
            }
        }
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `contract_of` must stay the only way a live tool becomes a
    /// contract.
    ///
    /// This is not hypothetical. The inline projection this function
    /// replaced was reintroduced within a day, by WOR-2444 adding a
    /// second branch that needed a contract and hand-rolled one. Two
    /// projections is exactly how CONTRACT_FIELDS and the gate drifted
    /// apart the first time, and the drift is silent: both compile,
    /// both produce a digest, and they only disagree once a field is
    /// added to one of them.
    ///
    /// Greps the federation source rather than trusting review.
    #[test]
    fn nothing_hand_rolls_a_contract_projection() {
        let src = include_str!("../federation.rs");
        assert!(
            !src.contains(r#""inputSchema": tool.input_schema"#),
            "federation.rs hand-rolls a contract projection; call compat::contract_of instead, \
             so the generator and the gate cannot disagree about a digest"
        );
    }

    /// The shipped example must not be permanently in the
    /// "contract moved" state.
    ///
    /// `examples/mcp-tool-versioning/` carried a zeroed placeholder
    /// digest that could never match, so an operator following the
    /// example got a gate that fires on every refresh and learns the
    /// wrong lesson about what a drift verdict means (WOR-2443).
    ///
    /// Reads the committed file rather than a copy, so the example and
    /// the recipe cannot drift apart again without this failing.
    #[test]
    fn the_shipped_example_lockfile_digests_match_the_recipe() {
        let yaml =
            include_str!("../../../../../examples/mcp-tool-versioning/tool-versions.lock.yaml");
        let lockfile: crate::mcp::compat::Lockfile =
            serde_yaml::from_str(yaml).expect("the shipped example must parse");
        assert!(
            !lockfile.tools.is_empty(),
            "an example with no tools proves nothing"
        );
        for (name, lock) in &lockfile.tools {
            let contract = lock.contract.as_ref().unwrap_or_else(|| {
                panic!("example tool `{name}` must embed its contract so this can be checked")
            });
            assert_eq!(
                contract_digest(contract),
                lock.contract_digest,
                "example tool `{name}` has a digest the gate would not compute; regenerate it"
            );
        }
    }

    #[test]
    fn digest_is_stable_under_key_reordering() {
        let a = json!({"name": "get_weather", "description": "d", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}});
        let b = json!({"inputSchema": {"properties": {"q": {"type": "string"}}, "type": "object"}, "description": "d", "name": "get_weather"});
        assert_eq!(contract_digest(&a), contract_digest(&b));
    }

    #[test]
    fn digest_changes_when_input_schema_changes() {
        let a = json!({"name": "t", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}});
        let b = json!({"name": "t", "inputSchema": {"type": "object", "properties": {"q": {"type": "number"}}}});
        assert_ne!(contract_digest(&a), contract_digest(&b));
    }

    #[test]
    fn digest_ignores_fields_outside_the_contract() {
        let a = json!({"name": "t", "description": "d"});
        let b = json!({"name": "t", "description": "d", "_meta": {"x": 1}, "extra": true});
        assert_eq!(contract_digest(&a), contract_digest(&b));
    }

    #[test]
    fn digest_has_sha256_prefix_and_is_hex() {
        let d = contract_digest(&json!({"name": "t"}));
        assert!(d.starts_with("sha256:"), "got {d}");
        let hex = &d["sha256:".len()..];
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
