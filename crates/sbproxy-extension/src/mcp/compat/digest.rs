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
