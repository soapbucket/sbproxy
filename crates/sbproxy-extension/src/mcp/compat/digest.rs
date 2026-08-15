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

/// Tool fields whose movement changes what this gateway does, projected before
/// hashing under the v2 scheme.
///
/// The list is deliberately shorter than [`CONTRACT_FIELDS`]: `title` is a
/// display string this gateway never acts on, so hashing it would refuse a
/// tool over a label edit. `icons` and `_meta` are excluded for the same
/// reason. What remains is what changes behavior. `inputSchema` and
/// `outputSchema` are both compiled and enforced on the 2026-07-28 path;
/// `description` is the text the model reads, which is the tool-poisoning
/// surface; `annotations` carries the read-only and destructive hints a host
/// may turn into an auto-approval decision.
///
/// This matches where the ecosystem has converged. MCP SEP-3140 calls a change
/// to `inputSchema`, `description` or `annotations` material and a change to
/// `title` or `icons` not material, and the same split is the reasoning behind
/// Avro's parsing canonical form (keep what is relevant to reading the data,
/// strip `doc`) and RFC 7638's JWK thumbprint (hash the key, not the key plus
/// its attributes).
const MATERIAL_CONTRACT_FIELDS: [&str; 5] = [
    "name",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
];

/// Scheme label for the v2 contract digest.
///
/// It appears twice on purpose: as the prefix of the returned value, so a
/// reader can tell which recipe produced a stored digest, and inside the
/// hashed bytes, so a v1 and a v2 digest cannot collide even if a prefix is
/// stripped or reattached. Carrying the scheme in the value is what lets two
/// recipes coexist during a migration instead of one silently replacing the
/// other, the same way Go reserves `h1:`, buf moved from `b4` to `b5`, and OCI
/// and RFC 9278 name the algorithm in the digest itself.
const CONTRACT_DIGEST_V2_SCHEME: &str = "mcp-contract-v2-sha256";

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

/// Content-addressed identity of a tool contract under the v2 scheme:
/// `mcp-contract-v2-sha256:<hex>` over the RFC 8785 (JCS) canonical form of
/// the tool's material contract projection, domain-separated by the scheme
/// label.
///
/// Unlike [`contract_digest`], this covers `outputSchema` and `annotations`
/// and excludes `title`. See [`MATERIAL_CONTRACT_FIELDS`] for why that is the
/// set. A tool that declares none of the added fields hashes the same content
/// as it always did, because the projection only carries fields that exist.
pub fn contract_digest_v2(tool: &Value) -> String {
    let projected = project_material_contract(tool);
    // Canonicalizing a JSON object is infallible here: a serde_json::Value
    // cannot hold NaN or infinity, the only inputs JCS rejects. The empty
    // fallback is unreachable and only keeps this path free of unwrap/panic.
    let canonical = serde_json_canonicalizer::to_vec(&projected).unwrap_or_default();
    let mut hasher = Sha256::new();
    // Domain separation: the scheme label and a NUL that cannot appear in the
    // canonical JSON prefix the bytes, so the same tool never hashes alike
    // under two recipes.
    hasher.update(CONTRACT_DIGEST_V2_SCHEME.as_bytes());
    hasher.update([0]);
    hasher.update(&canonical);
    format!(
        "{CONTRACT_DIGEST_V2_SCHEME}:{}",
        hex::encode(hasher.finalize())
    )
}

/// Whether a stored digest was written under the v2 scheme.
///
/// A reader uses this to compare like with like. A digest whose scheme it does
/// not recognize is neither a match nor a mismatch, so callers treat it as
/// "cannot evaluate" rather than "changed"; hard-failing an unknown scheme
/// would turn a lockfile written by a newer build into an outage on rollback.
pub fn is_contract_digest_v2(digest: &str) -> bool {
    digest
        .strip_prefix(CONTRACT_DIGEST_V2_SCHEME)
        .is_some_and(|rest| rest.starts_with(':'))
}

/// Whether a stored digest was written under the original scheme.
pub fn is_contract_digest_v1(digest: &str) -> bool {
    digest
        .strip_prefix("sha256")
        .is_some_and(|rest| rest.starts_with(':'))
}

/// Project a tool value down to its contract fields, dropping everything else.
fn project_contract(tool: &Value) -> Value {
    project_fields(tool, &CONTRACT_FIELDS)
}

/// Project a tool value down to the fields that change gateway behavior.
fn project_material_contract(tool: &Value) -> Value {
    project_fields(tool, &MATERIAL_CONTRACT_FIELDS)
}

fn project_fields(tool: &Value, fields: &[&str]) -> Value {
    let mut out = Map::new();
    if let Some(obj) = tool.as_object() {
        for field in fields {
            if let Some(value) = obj.get(*field) {
                out.insert((*field).to_string(), value.clone());
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

    #[test]
    fn v2_digest_is_scheme_tagged_and_hex() {
        let d = contract_digest_v2(&json!({"name": "t"}));
        assert!(d.starts_with("mcp-contract-v2-sha256:"), "got {d}");
        let hex = &d["mcp-contract-v2-sha256:".len()..];
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(is_contract_digest_v2(&d));
        assert!(!is_contract_digest_v1(&d));
    }

    #[test]
    fn v2_digest_never_collides_with_v1_for_the_same_tool() {
        // Domain separation means the two recipes cannot agree even on a tool
        // whose projections are identical, so a stored digest can never be
        // compared under the wrong recipe by accident.
        let tool = json!({"name": "t", "description": "d"});
        let v1 = contract_digest(&tool);
        let v2 = contract_digest_v2(&tool);
        assert_ne!(v1["sha256:".len()..], v2["mcp-contract-v2-sha256:".len()..]);
        assert!(is_contract_digest_v1(&v1));
        assert!(!is_contract_digest_v2(&v1));
    }

    #[test]
    fn v2_digest_covers_output_schema_and_annotations() {
        // Both fields move the digest. Note the gap this scheme closes is not
        // in this function: `CONTRACT_FIELDS` already listed both. It was that
        // the gate fed it a three-field projection of the live tool, so these
        // fields never reached the hash. See the federation gate tests for the
        // end-to-end version of this.
        let base = json!({"name": "t", "inputSchema": {"type": "object"}});
        let moved_output = json!({
            "name": "t",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object", "properties": {"a": {"type": "string"}}}
        });
        let moved_annotations = json!({
            "name": "t",
            "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": false}
        });

        assert_ne!(contract_digest_v2(&base), contract_digest_v2(&moved_output));
        assert_ne!(
            contract_digest_v2(&base),
            contract_digest_v2(&moved_annotations)
        );
    }

    #[test]
    fn v2_digest_drops_title_where_v1_kept_it() {
        // The one field the newer scheme deliberately stops covering. A title
        // is a display string this gateway never acts on, so hashing it would
        // refuse a tool over a label edit.
        let plain = json!({"name": "t", "description": "d"});
        let retitled = json!({"name": "t", "description": "d", "title": "New Label"});
        assert_ne!(contract_digest(&plain), contract_digest(&retitled));
        assert_eq!(contract_digest_v2(&plain), contract_digest_v2(&retitled));
    }

    #[test]
    fn v2_digest_ignores_title_icons_and_meta() {
        // Display-only fields must not refuse a tool. Hashing `title` would
        // turn a label edit into a blocked call.
        let bare = json!({"name": "t", "description": "d"});
        let decorated = json!({
            "name": "t",
            "description": "d",
            "title": "Pretty Name",
            "icons": [{"src": "data:image/png;base64,AA==", "mimeType": "image/png"}],
            "_meta": {"vendor.example/ui": "card"}
        });
        assert_eq!(contract_digest_v2(&bare), contract_digest_v2(&decorated));
    }

    #[test]
    fn v2_digest_is_unchanged_for_a_tool_declaring_no_added_fields() {
        // The projection only carries fields that exist, so a minimal tool
        // hashes the same content under either field list. This is why an
        // existing baseline for such a tool cannot be invalidated by the new
        // scheme, only re-tagged.
        let minimal = json!({"name": "t", "description": "d", "inputSchema": {"type": "object"}});
        let with_title_only = json!({
            "name": "t", "description": "d", "inputSchema": {"type": "object"}, "title": "T"
        });
        assert_eq!(
            contract_digest_v2(&minimal),
            contract_digest_v2(&with_title_only)
        );
    }

    #[test]
    fn an_unrecognized_scheme_is_neither_v1_nor_v2() {
        for stored in ["md5:abc", "mcp-contract-v3-sha256:abc", "abc", "sha256", ""] {
            assert!(!is_contract_digest_v2(stored), "{stored}");
            assert!(!is_contract_digest_v1(stored) || stored.starts_with("sha256:"));
        }
    }
}
