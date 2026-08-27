//! OpenID Federation 1.0 §6.1 metadata policy operators.
//!
//! A superior in a trust chain can constrain or augment its
//! subordinates' published metadata by carrying a `metadata_policy`
//! claim on the subordinate statement it signs. The policy is a JSON
//! object keyed by entity-type slug (e.g. `openid_provider`,
//! `oauth_authorization_server`); each value is another JSON object
//! keyed by the metadata field name (e.g. `token_endpoint_auth_methods_supported`);
//! and each field value carries one or more of the seven operators
//! the spec defines.
//!
//! ## The seven operators
//!
//! | Operator      | Meaning                                                                                              |
//! |---------------|------------------------------------------------------------------------------------------------------|
//! | `value`       | Force the field to exactly this value. Replaces whatever the leaf published.                          |
//! | `add`         | Append items to an array-valued field (the leaf MAY add its own; the policy contributes too).         |
//! | `default`     | Use this value when the leaf did not publish one. Leaf wins when present.                             |
//! | `one_of`      | The leaf's value MUST be one of these. Reject the chain when not.                                     |
//! | `subset_of`   | The leaf's value (an array) MUST be a subset of this set. Reject otherwise.                           |
//! | `superset_of` | The leaf's value (an array) MUST be a superset of this set. Reject otherwise.                         |
//! | `essential`   | The leaf MUST publish this field (boolean toggle). Reject when missing and `essential = true`.        |
//!
//! ## Application order
//!
//! The §6.1 algorithm composes policies along the chain
//! anchor-to-leaf. Each step's policy refines whatever the prior
//! step produced; the leaf's published metadata is the starting
//! point. This module ships the per-field applicator
//! ([`apply_field_policy`]) and a per-block applicator
//! ([`apply_block_policy`]) that drives it; the per-chain composer
//! lives in Stage 6 once the chain-walk + HTTP fetcher land.
//!
//! ## What this module does NOT do
//!
//! * Verify the JWS signature on the metadata-policy claim itself.
//!   The claim travels inside an Entity Statement; Stages 1-3
//!   already verified that.
//! * Decide whether the resolved metadata is "trustworthy" beyond
//!   the operator compose. That is a deployment-policy call.
//! * Apply policy to fields the spec marks as non-policyable
//!   (today every published field is policyable; this guard is
//!   reserved for future spec revisions).

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::errors::{FederationError, FederationResult};

/// Apply a `metadata_policy` block to a leaf metadata block.
///
/// Both inputs are JSON objects keyed by entity-type slug
/// (e.g. `openid_provider`); the policy object's values are
/// per-field operator maps, and the leaf object's values are the
/// raw published metadata. Returns a new object with the policy
/// applied per `apply_field_policy`.
///
/// Per §6.1 the function MUST reject the chain (return an error)
/// when any policy constraint is violated. Successful application
/// yields a JSON object the caller can substitute back into the
/// resolved chain's leaf metadata.
pub fn apply_block_policy(leaf: &Value, policy: &Value) -> FederationResult<Value> {
    let leaf_obj = leaf.as_object().ok_or_else(|| {
        FederationError::PolicyShape("metadata block must be a JSON object".into())
    })?;
    let policy_obj = policy.as_object().ok_or_else(|| {
        FederationError::PolicyShape("metadata_policy block must be a JSON object".into())
    })?;

    let mut out = leaf_obj.clone();

    // First pass: apply policy to every field the policy mentions.
    for (field, field_policy) in policy_obj {
        let current = leaf_obj.get(field).cloned().unwrap_or(Value::Null);
        let next = apply_field_policy(&current, field_policy, field)?;
        match next {
            Some(v) => {
                out.insert(field.clone(), v);
            }
            None => {
                // `default` / `add` / etc. with nothing to insert
                // and no leaf value: leave the field absent.
                out.remove(field);
            }
        }
    }

    Ok(Value::Object(out))
}

/// Apply a single field's policy operators to its leaf value.
///
/// `leaf_value` is whatever the leaf published for the field;
/// [`Value::Null`] means "field was absent". `field_policy` is the
/// per-field operator map (typically a JSON object with `value` /
/// `add` / `default` / etc. keys). `field_name` is threaded through
/// for error messages so an operator can find the offending field.
///
/// Returns `Ok(Some(resolved))` when the field is present in the
/// resolved output, `Ok(None)` when the resolved output should not
/// carry the field, and `Err` when a constraint operator
/// (`one_of`, `subset_of`, `superset_of`, `essential`) is violated.
pub fn apply_field_policy(
    leaf_value: &Value,
    field_policy: &Value,
    field_name: &str,
) -> FederationResult<Option<Value>> {
    let ops = field_policy.as_object().ok_or_else(|| {
        FederationError::PolicyShape(format!(
            "metadata_policy entry for `{field_name}` must be a JSON object"
        ))
    })?;

    let mut current = leaf_value.clone();

    // Operator precedence per §6.1: `essential` is enforced first
    // (so a missing-and-required field fails fast); `value` replaces
    // whatever the leaf had; `default` only fires when no leaf
    // value; `add` appends to arrays; the three constraint
    // operators (`one_of`, `subset_of`, `superset_of`) gate the
    // final value.

    // --- essential ---
    if let Some(Value::Bool(true)) = ops.get("essential") {
        if current.is_null() {
            return Err(FederationError::PolicyEssentialMissing {
                field: field_name.to_string(),
            });
        }
    }

    // --- value ---
    if let Some(v) = ops.get("value") {
        current = v.clone();
    }

    // --- default ---
    if current.is_null() {
        if let Some(d) = ops.get("default") {
            current = d.clone();
        }
    }

    // --- add ---
    if let Some(extra) = ops.get("add") {
        current = apply_add_operator(&current, extra, field_name)?;
    }

    // --- one_of ---
    if let Some(allowed) = ops.get("one_of") {
        if !current.is_null() {
            let allowed_arr = allowed.as_array().ok_or_else(|| {
                FederationError::PolicyShape(format!(
                    "`one_of` for `{field_name}` must be an array"
                ))
            })?;
            if !allowed_arr.iter().any(|a| a == &current) {
                return Err(FederationError::PolicyOneOfViolated {
                    field: field_name.to_string(),
                });
            }
        }
    }

    // --- subset_of ---
    if let Some(allowed) = ops.get("subset_of") {
        check_subset_of(&current, allowed, field_name)?;
    }

    // --- superset_of ---
    if let Some(required) = ops.get("superset_of") {
        check_superset_of(&current, required, field_name)?;
    }

    if current.is_null() {
        Ok(None)
    } else {
        Ok(Some(current))
    }
}

/// `add`: append the `extra` items to the current value when it is
/// an array; create a new array when the current value is absent.
/// Reject when the current value is present but not an array.
fn apply_add_operator(current: &Value, extra: &Value, field_name: &str) -> FederationResult<Value> {
    let extra_arr = extra.as_array().ok_or_else(|| {
        FederationError::PolicyShape(format!("`add` for `{field_name}` must be an array"))
    })?;
    if current.is_null() {
        return Ok(Value::Array(extra_arr.clone()));
    }
    let existing = current.as_array().ok_or_else(|| {
        FederationError::PolicyShape(format!(
            "`add` for `{field_name}` requires the field to be an array"
        ))
    })?;
    // De-dupe via BTreeSet keyed on the serialised form so order is
    // stable and `add` is idempotent against an array that already
    // includes a policy-mandated entry.
    let mut seen: BTreeSet<String> = existing.iter().map(|v| v.to_string()).collect();
    let mut combined: Vec<Value> = existing.clone();
    for item in extra_arr {
        let key = item.to_string();
        if seen.insert(key) {
            combined.push(item.clone());
        }
    }
    Ok(Value::Array(combined))
}

/// `subset_of`: the current value (an array) MUST be a subset of
/// `allowed` (an array). Empty arrays trivially satisfy. A null
/// current value satisfies vacuously: `subset_of` only constrains
/// values the leaf actually published.
fn check_subset_of(current: &Value, allowed: &Value, field_name: &str) -> FederationResult<()> {
    if current.is_null() {
        return Ok(());
    }
    let cur = current.as_array().ok_or_else(|| {
        FederationError::PolicyShape(format!(
            "`subset_of` for `{field_name}` requires the field to be an array"
        ))
    })?;
    let allowed_arr = allowed.as_array().ok_or_else(|| {
        FederationError::PolicyShape(format!("`subset_of` for `{field_name}` must be an array"))
    })?;
    let allowed_set: BTreeSet<String> = allowed_arr.iter().map(|v| v.to_string()).collect();
    for item in cur {
        if !allowed_set.contains(&item.to_string()) {
            return Err(FederationError::PolicySubsetViolated {
                field: field_name.to_string(),
                offending_value: item.to_string(),
            });
        }
    }
    Ok(())
}

/// `superset_of`: the current value (an array) MUST be a superset
/// of `required`. A null current value violates the constraint:
/// "must include X" can not be satisfied by a missing array.
fn check_superset_of(current: &Value, required: &Value, field_name: &str) -> FederationResult<()> {
    let required_arr = required.as_array().ok_or_else(|| {
        FederationError::PolicyShape(format!("`superset_of` for `{field_name}` must be an array"))
    })?;
    if current.is_null() {
        if required_arr.is_empty() {
            return Ok(());
        }
        return Err(FederationError::PolicySupersetViolated {
            field: field_name.to_string(),
            missing_value: required_arr[0].to_string(),
        });
    }
    let cur = current.as_array().ok_or_else(|| {
        FederationError::PolicyShape(format!(
            "`superset_of` for `{field_name}` requires the field to be an array"
        ))
    })?;
    let cur_set: BTreeSet<String> = cur.iter().map(|v| v.to_string()).collect();
    for item in required_arr {
        if !cur_set.contains(&item.to_string()) {
            return Err(FederationError::PolicySupersetViolated {
                field: field_name.to_string(),
                missing_value: item.to_string(),
            });
        }
    }
    Ok(())
}

/// Compose two metadata-policy blocks into one. Used by the chain
/// composer that walks from anchor down: each step's policy is
/// merged onto the running composed policy.
///
/// Field-by-field, a deeper (subordinate) policy may add a new operator
/// or monotonically strengthen an existing one. It cannot replace a
/// fixed value/default, widen `one_of` or `subset_of`, weaken
/// `superset_of`, clear `essential`, or discard a superior `add` value.
pub fn compose_policies(superior: &Value, subordinate: &Value) -> FederationResult<Value> {
    let s = superior.as_object().ok_or_else(|| {
        FederationError::PolicyShape("superior metadata_policy must be a JSON object".into())
    })?;
    let sub = subordinate.as_object().ok_or_else(|| {
        FederationError::PolicyShape("subordinate metadata_policy must be a JSON object".into())
    })?;
    let mut out: Map<String, Value> = s.clone();
    for (k, v) in sub {
        // Per entity-type block: merge field-level operator maps.
        if let (Some(out_block), Some(new_block)) = (
            out.get_mut(k).and_then(|x| x.as_object_mut()),
            v.as_object(),
        ) {
            for (field, new_ops) in new_block {
                if let (Some(prev_ops), Some(new_ops_obj)) = (
                    out_block.get_mut(field).and_then(|x| x.as_object_mut()),
                    new_ops.as_object(),
                ) {
                    for (op, val) in new_ops_obj {
                        let composed = match prev_ops.get(op) {
                            Some(previous) => compose_operator(field, op, previous, val)?,
                            None => val.clone(),
                        };
                        prev_ops.insert(op.clone(), composed);
                    }
                } else {
                    out_block.insert(field.clone(), new_ops.clone());
                }
            }
        } else {
            out.insert(k.clone(), v.clone());
        }
    }
    Ok(Value::Object(out))
}

fn compose_operator(
    field: &str,
    operator: &str,
    superior: &Value,
    subordinate: &Value,
) -> FederationResult<Value> {
    if superior == subordinate {
        return Ok(superior.clone());
    }
    match operator {
        "add" => apply_add_operator(superior, subordinate, field),
        "one_of" | "subset_of" => {
            check_subset_of(subordinate, superior, field)?;
            Ok(subordinate.clone())
        }
        "superset_of" => {
            check_superset_of(subordinate, superior, field)?;
            Ok(subordinate.clone())
        }
        "essential" => match (superior.as_bool(), subordinate.as_bool()) {
            (Some(false), Some(true)) => Ok(Value::Bool(true)),
            (Some(_), Some(_)) => Err(FederationError::PolicyShape(format!(
                "subordinate metadata_policy cannot clear `essential` for `{field}`"
            ))),
            _ => Err(FederationError::PolicyShape(format!(
                "`essential` for `{field}` must be a boolean"
            ))),
        },
        "value" | "default" => Err(FederationError::PolicyShape(format!(
            "subordinate metadata_policy conflicts with superior `{operator}` for `{field}`"
        ))),
        other => Err(FederationError::PolicyShape(format!(
            "unsupported metadata_policy operator `{other}` for `{field}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `value` overrides whatever the leaf published.
    #[test]
    fn value_replaces_leaf_value() {
        let leaf = json!({"token_endpoint_auth_methods_supported": ["client_secret_basic"]});
        let policy = json!({
            "token_endpoint_auth_methods_supported": {"value": ["private_key_jwt"]}
        });
        let resolved = apply_block_policy(&leaf, &policy).unwrap();
        assert_eq!(
            resolved["token_endpoint_auth_methods_supported"],
            json!(["private_key_jwt"])
        );
    }

    /// `default` fills the field when the leaf did not publish one.
    #[test]
    fn default_applied_only_when_leaf_missing() {
        let leaf = json!({});
        let policy = json!({
            "request_object_signing_alg_values_supported": {"default": ["RS256"]}
        });
        let resolved = apply_block_policy(&leaf, &policy).unwrap();
        assert_eq!(
            resolved["request_object_signing_alg_values_supported"],
            json!(["RS256"])
        );

        let leaf_with = json!({"request_object_signing_alg_values_supported": ["ES256"]});
        let resolved2 = apply_block_policy(&leaf_with, &policy).unwrap();
        assert_eq!(
            resolved2["request_object_signing_alg_values_supported"],
            json!(["ES256"]),
            "default must not overwrite a leaf value"
        );
    }

    /// `add` appends items to an array, deduping. Order of the
    /// leaf's items is preserved; new items append after.
    #[test]
    fn add_appends_and_dedupes() {
        let leaf = json!({"grant_types_supported": ["authorization_code"]});
        let policy = json!({
            "grant_types_supported": {"add": ["refresh_token", "authorization_code"]}
        });
        let resolved = apply_block_policy(&leaf, &policy).unwrap();
        assert_eq!(
            resolved["grant_types_supported"],
            json!(["authorization_code", "refresh_token"])
        );
    }

    /// `one_of` accepts a leaf value when it is in the allowed
    /// set and rejects otherwise.
    #[test]
    fn one_of_accepts_member_rejects_outsider() {
        let leaf = json!({"subject_type": "pairwise"});
        let policy = json!({"subject_type": {"one_of": ["pairwise", "public"]}});
        let ok = apply_block_policy(&leaf, &policy).unwrap();
        assert_eq!(ok["subject_type"], json!("pairwise"));

        let bad_leaf = json!({"subject_type": "anon"});
        let err = apply_block_policy(&bad_leaf, &policy).unwrap_err();
        assert!(
            matches!(err, FederationError::PolicyOneOfViolated { field } if field == "subject_type")
        );
    }

    /// `subset_of` accepts arrays whose every element is in the
    /// allowed set; rejects with the offending element.
    #[test]
    fn subset_of_enforces_array_membership() {
        let leaf = json!({"response_types_supported": ["code", "id_token"]});
        let policy = json!({
            "response_types_supported": {
                "subset_of": ["code", "id_token", "code id_token"]
            }
        });
        apply_block_policy(&leaf, &policy).unwrap();

        let bad_leaf = json!({"response_types_supported": ["code", "token"]});
        let err = apply_block_policy(&bad_leaf, &policy).unwrap_err();
        assert!(
            matches!(err, FederationError::PolicySubsetViolated { field, .. } if field == "response_types_supported")
        );
    }

    /// `superset_of` requires the leaf array to contain every
    /// required element; reports the missing one when not.
    #[test]
    fn superset_of_enforces_required_elements() {
        let leaf = json!({"claims_supported": ["sub", "name", "email"]});
        let policy = json!({"claims_supported": {"superset_of": ["sub", "email"]}});
        apply_block_policy(&leaf, &policy).unwrap();

        let bad_leaf = json!({"claims_supported": ["sub"]});
        let err = apply_block_policy(&bad_leaf, &policy).unwrap_err();
        assert!(
            matches!(err, FederationError::PolicySupersetViolated { field, .. } if field == "claims_supported")
        );
    }

    /// `essential = true` requires the leaf to publish the field;
    /// `default` filling the field BEFORE the essential check is
    /// not how the spec defines this. Per §6.1 `essential` checks
    /// the leaf's actual publication, so we evaluate it first.
    #[test]
    fn essential_requires_leaf_publication() {
        let leaf = json!({});
        let policy = json!({"organization_name": {"essential": true}});
        let err = apply_block_policy(&leaf, &policy).unwrap_err();
        assert!(
            matches!(err, FederationError::PolicyEssentialMissing { field } if field == "organization_name")
        );

        let leaf_with = json!({"organization_name": "Acme"});
        apply_block_policy(&leaf_with, &policy).unwrap();
    }

    /// `compose_policies`: when the subordinate adds a new
    /// operator to an existing field, both policies' constraints
    /// remain in effect on the merged block. When the subordinate
    /// introduces a brand-new field, it is copied verbatim.
    #[test]
    fn compose_merges_field_operators_and_fields() {
        let superior = json!({
            "openid_provider": {
                "subject_types_supported": {"subset_of": ["public", "pairwise"]}
            }
        });
        let subordinate = json!({
            "openid_provider": {
                "subject_types_supported": {"essential": true},
                "claims_supported": {"default": ["sub", "email"]}
            }
        });
        let composed = compose_policies(&superior, &subordinate).unwrap();
        let block = composed["openid_provider"].as_object().unwrap();
        let st = block["subject_types_supported"].as_object().unwrap();
        assert_eq!(st["subset_of"], json!(["public", "pairwise"]));
        assert_eq!(st["essential"], json!(true));
        assert_eq!(
            block["claims_supported"]["default"],
            json!(["sub", "email"])
        );
    }

    /// A pathological policy with a non-object operator map MUST
    /// surface as a typed `PolicyShape` error rather than panic.
    #[test]
    fn malformed_field_policy_returns_typed_error() {
        let leaf = json!({});
        let policy = json!({"foo": "not-an-object"});
        let err = apply_block_policy(&leaf, &policy).unwrap_err();
        assert!(matches!(err, FederationError::PolicyShape(_)));
    }

    /// `add` against a leaf field that is not an array surfaces as
    /// `PolicyShape`. Future spec revisions may relax to "convert
    /// scalar to single-element array"; today we reject for
    /// safety.
    #[test]
    fn add_against_non_array_leaf_rejected() {
        let leaf = json!({"grant_types_supported": "authorization_code"});
        let policy = json!({"grant_types_supported": {"add": ["refresh_token"]}});
        let err = apply_block_policy(&leaf, &policy).unwrap_err();
        assert!(matches!(err, FederationError::PolicyShape(_)));
    }

    fn policy_for(operator: &str, value: Value) -> Value {
        let mut operators = Map::new();
        operators.insert(operator.to_string(), value);
        json!({"openid_provider": {"field": Value::Object(operators)}})
    }

    /// Every value required by the superior's `add` remains required
    /// after a subordinate contributes its own additions.
    #[test]
    fn security_boundary_composition_unions_add_values() {
        let composed = compose_policies(
            &policy_for("add", json!(["superior"])),
            &policy_for("add", json!(["subordinate"])),
        )
        .unwrap();
        assert_eq!(
            composed["openid_provider"]["field"]["add"],
            json!(["superior", "subordinate"])
        );
    }

    #[test]
    fn security_boundary_composition_rejects_a_changed_value() {
        let result = compose_policies(
            &policy_for("value", json!("superior")),
            &policy_for("value", json!("subordinate")),
        );
        assert!(result.is_err(), "a subordinate cannot replace `value`");
    }

    #[test]
    fn security_boundary_composition_rejects_a_changed_default() {
        let result = compose_policies(
            &policy_for("default", json!("superior")),
            &policy_for("default", json!("subordinate")),
        );
        assert!(result.is_err(), "conflicting defaults must be deterministic");
    }

    #[test]
    fn security_boundary_composition_rejects_a_wider_one_of() {
        let result = compose_policies(
            &policy_for("one_of", json!(["a"])),
            &policy_for("one_of", json!(["a", "b"])),
        );
        assert!(result.is_err(), "a subordinate cannot widen `one_of`");
    }

    #[test]
    fn security_boundary_composition_rejects_a_wider_subset_of() {
        let result = compose_policies(
            &policy_for("subset_of", json!(["a"])),
            &policy_for("subset_of", json!(["a", "b"])),
        );
        assert!(result.is_err(), "a subordinate cannot widen `subset_of`");
    }

    #[test]
    fn security_boundary_composition_rejects_a_weaker_superset_of() {
        let result = compose_policies(
            &policy_for("superset_of", json!(["a", "b"])),
            &policy_for("superset_of", json!(["a"])),
        );
        assert!(result.is_err(), "a subordinate cannot weaken `superset_of`");
    }

    #[test]
    fn security_boundary_composition_cannot_clear_essential() {
        let result = compose_policies(
            &policy_for("essential", json!(true)),
            &policy_for("essential", json!(false)),
        );
        assert!(result.is_err(), "a subordinate cannot clear `essential`");
    }
}
