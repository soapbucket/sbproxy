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
/// Covers `name`, `description`, `inputSchema`, `outputSchema` and
/// `annotations`: the fields whose movement changes what this gateway does.
/// Both schemas are compiled and enforced, the description is the text the
/// model reads, and the annotations carry the hints a host may turn into an
/// auto-approval. `title` and `icons` are excluded on purpose, being display
/// values this gateway never acts on, so a label edit cannot refuse a tool.
///
/// A tool that declares none of the fields [`contract_digest`] omitted hashes
/// the same content as it always did, because the projection only carries
/// fields that are present.
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

/// The contract a fresh baseline pins a live tool at, under the v2 scheme.
///
/// [`contract_of`] is the frozen legacy projection and carries only the
/// three fields [`FederatedTool`] itself has. A tool whose upstream
/// document survived federation intact carries the whole thing on
/// `contract`, including the `outputSchema` and `annotations` that the
/// v2 recipe grades, so a baseline generated from the legacy projection
/// would pin less than the gate compares.
///
/// A tool with no strict contract (an `inputSchema` that is not an
/// object, which the modern wire does not admit) keeps the legacy
/// projection rather than dropping out of the baseline entirely. Being
/// pinned on three fields beats not being pinned at all.
///
/// This is the generator's half of the single-owner rule in
/// [`contract_of`], and the gate's v2 branch resolves through here too,
/// so `sbproxy mcp lock` and the running gate cannot construct
/// different contracts for the same tool (WOR-2443).
///
/// [`FederatedTool`]: crate::mcp::federation::FederatedTool
pub fn baseline_contract_v2(tool: &crate::mcp::federation::FederatedTool) -> Value {
    tool.contract.as_ref().map_or_else(
        || contract_of(tool),
        crate::mcp::protocol::contracts::McpToolContract::as_value,
    )
}

/// The contract and digest a fresh v2 baseline pins `tool` at.
///
/// One call so a generator cannot pair a contract from one recipe with a
/// digest from another. The embedded contract is what lets a later
/// change be graded structurally instead of only detected.
pub fn baseline_entry_v2(tool: &crate::mcp::federation::FederatedTool) -> (Value, String) {
    let contract = baseline_contract_v2(tool);
    let digest = contract_digest_v2(&contract);
    (contract, digest)
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
    ///
    /// One function is allowed to build the same three fields:
    /// `legacy_serialized_tool_entry`, which is the frozen 2025-06-18
    /// `tools/list` wire projection. It is not a contract and must not be
    /// routed through `contract_of`, because the bytes legacy clients see and
    /// the recipe the digest hashes are separate promises. Coupling them
    /// would let a change to the digest silently change the frozen wire
    /// output, which is the thing the legacy conformance suite exists to
    /// prevent. So the check is on the enclosing function rather than on the
    /// bare substring: a genuinely new hand-rolled contract lands in some
    /// other function and still fails this.
    #[test]
    fn nothing_hand_rolls_a_contract_projection() {
        const WIRE_SERIALIZER: &str = "legacy_serialized_tool_entry";
        let src = include_str!("../federation.rs");

        let mut offenders = Vec::new();
        for (index, _) in src.match_indices(r#""inputSchema": tool.input_schema"#) {
            let enclosing = src[..index]
                .rmatch_indices("\nfn ")
                .next()
                .map(|(start, _)| {
                    let rest = &src[start + "\nfn ".len()..];
                    let end = rest.find(['(', '<', ' ']).unwrap_or(rest.len().min(80));
                    &rest[..end]
                })
                .unwrap_or("<none>");
            if enclosing != WIRE_SERIALIZER {
                offenders.push(enclosing);
            }
        }

        assert!(
            offenders.is_empty(),
            "these functions in federation.rs hand-roll a contract projection: {offenders:?}. \
             Call compat::contract_of instead, so the generator and the gate cannot disagree \
             about a digest. Only {WIRE_SERIALIZER} may build these fields itself, and only \
             because it serializes the frozen legacy wire rather than a contract."
        );
    }

    /// The exemption above has to name a function that exists, or the guard
    /// silently widens the day that function is renamed.
    #[test]
    fn the_wire_serializer_exemption_still_names_a_real_function() {
        let src = include_str!("../federation.rs");
        assert!(
            src.contains("fn legacy_serialized_tool_entry"),
            "the contract-projection guard exempts legacy_serialized_tool_entry, which no \
             longer exists; re-check whether its exemption is still warranted"
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
            // Digest under the scheme the entry declares, not a fixed
            // one. Hardcoding v1 here would keep passing after the entry
            // moved to v2, because it would be checking a recipe the
            // gate no longer applies to that entry: a test that still
            // goes green while measuring the wrong thing.
            let expected = if is_contract_digest_v2(&lock.contract_digest) {
                contract_digest_v2(contract)
            } else if is_contract_digest_v1(&lock.contract_digest) {
                contract_digest(contract)
            } else {
                panic!(
                    "example tool `{name}` declares digest scheme `{}`, which no recipe here \
                     implements",
                    lock.contract_digest
                )
            };
            assert_eq!(
                expected, lock.contract_digest,
                "example tool `{name}` has a digest the gate would not compute; regenerate it \
                 with `sbproxy mcp lock`"
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
