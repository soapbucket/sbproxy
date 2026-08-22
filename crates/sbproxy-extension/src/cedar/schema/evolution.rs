//! Schema-evolution validate-before-apply check.
//!
//! When a workspace proposes a new schema (typically by changing its
//! workspace override), every pinned policy is re-validated against
//! the proposed schema. Any policy that references an entity type or
//! action that the new schema no longer declares is captured in a
//! [`SchemaRefusalReport`]. A hot-reload path should refuse to swap
//! the compiled policy set when the report is non-empty.
//!
//! The actual Cedar validation is delegated to
//! [`crate::cedar::compile_all`], which already calls
//! `Validator::validate(&policy_set, ValidationMode::Strict)`. This
//! module wraps that with a per-policy granularity so the report can
//! name the offending policy id.

use cedar_policy::Schema;
use uuid::Uuid;

use super::SchemaRefusalReport;
use crate::cedar::{compile_all, CompilerError};

/// A pinned policy under evaluation: its persistent id plus the Cedar
/// source text. The validator does not need any other field because
/// the schema check is purely syntactic against the policy body.
#[derive(Debug, Clone)]
pub struct PinnedPolicy {
    /// Stable identifier for the policy. An audit log binds verdicts
    /// to this id, so it should be the same id used wherever the
    /// policy is otherwise addressed.
    pub policy_id: Uuid,
    /// Raw Cedar source text of the policy.
    pub cedar_source: String,
}

/// Validate every pinned policy against `proposed_schema` and return
/// a refusal report listing the failures.
///
/// An empty report means the schema change is safe to apply. A
/// non-empty report carries one entry per failing policy: the
/// `policy_id` and a list of formatted diagnostic strings (one per
/// finding from the Cedar validator). An operator-facing view
/// consumes the report; the caller refuses the swap until the
/// workspace either reverts the schema change, edits the failing
/// policies, or quarantines them.
pub fn validate_against_schema(
    pinned: &[PinnedPolicy],
    proposed_schema: &Schema,
) -> SchemaRefusalReport {
    let mut report = SchemaRefusalReport::default();
    for policy in pinned {
        let id = policy.policy_id.to_string();
        let result = compile_all(
            &[(id.as_str(), policy.cedar_source.as_str())],
            Some(proposed_schema),
        );
        if let Err(CompilerError::Validation { findings }) = result {
            // Every finding from `compile_all` is tagged with the
            // policy id; flatten them into a single Vec<String> for
            // the refusal report.
            let messages: Vec<String> = findings
                .into_iter()
                .map(|f| {
                    if f.message.is_empty() {
                        f.policy_id.clone()
                    } else {
                        f.message.clone()
                    }
                })
                .collect();
            if !messages.is_empty() {
                report.failed_policies.push((policy.policy_id, messages));
            }
        }
        // Parse failures and other compiler errors are the calling
        // bundle-compile step's problem, not the schema-evolution
        // validator's. Schema evolution only validates the type and
        // action references; a malformed policy body is out of
        // scope here.
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cedar::schema::mcp::default_schema;

    fn pin(id: Uuid, src: &str) -> PinnedPolicy {
        PinnedPolicy {
            policy_id: id,
            cedar_source: src.to_string(),
        }
    }

    #[test]
    fn empty_pinned_set_is_clean() {
        let (schema, _w) = default_schema().expect("schema");
        let report = validate_against_schema(&[], &schema);
        assert!(report.failed_policies.is_empty());
    }

    #[test]
    fn policy_referencing_known_type_passes() {
        let (schema, _w) = default_schema().expect("schema");
        let id = Uuid::new_v4();
        let src = r#"permit(principal, action == Action::"MCP::Ping", resource);"#;
        let report = validate_against_schema(&[pin(id, src)], &schema);
        assert!(
            report.failed_policies.is_empty(),
            "expected clean, got: {:?}",
            report.failed_policies
        );
    }

    #[test]
    fn policy_referencing_unknown_type_fails() {
        // Build a tiny custom schema that does NOT declare `Tool`.
        let alt = r#"
            entity Person;
            entity Doc;
            action view appliesTo { principal: [Person], resource: [Doc] };
        "#;
        let (schema, _w) = Schema::from_cedarschema_str(alt).expect("alt parse");
        let id = Uuid::new_v4();
        // References a type (`Tool`) that the proposed schema does
        // not declare; should be captured as a failure.
        let src =
            r#"permit(principal == Person::"a", action == Action::"view", resource == Tool::"x");"#;
        let report = validate_against_schema(&[pin(id, src)], &schema);
        assert!(
            !report.failed_policies.is_empty(),
            "expected non-clean report"
        );
        assert_eq!(report.failed_policies.len(), 1);
        assert_eq!(report.failed_policies[0].0, id);
        assert!(!report.failed_policies[0].1.is_empty());
    }

    #[test]
    fn report_carries_policy_id_per_failure() {
        let alt = r#"
            entity Person;
            entity Doc;
            action view appliesTo { principal: [Person], resource: [Doc] };
        "#;
        let (schema, _w) = Schema::from_cedarschema_str(alt).expect("alt parse");
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let bad =
            r#"permit(principal == Person::"a", action == Action::"view", resource == Tool::"x");"#;
        let pinned = vec![pin(id_a, bad), pin(id_b, bad)];
        let report = validate_against_schema(&pinned, &schema);
        let ids: std::collections::HashSet<Uuid> =
            report.failed_policies.iter().map(|(id, _)| *id).collect();
        assert!(ids.contains(&id_a));
        assert!(ids.contains(&id_b));
    }
}
