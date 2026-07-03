//! Structural dimension: schema-shape changes graded by variance.
//!
//! Input schemas are contravariant: a more restrictive input (a newly required
//! field, a removed property, a narrowed type or enum) rejects calls that were
//! valid before, so it is breaking. Output schemas are covariant: removing or
//! narrowing an output breaks consumers who relied on it, while widening it is
//! safe. Description, title, and annotation changes are a Patch structurally;
//! the description-semantics dimension may escalate them.

use super::schema_diff::{diff_schema, SchemaChange};
use super::{Dimension, Finding, SemverGrade};
use serde_json::Value;

const EMPTY_SCHEMA: &Value = &Value::Null;

/// Grade the structural difference between two versions of the same tool, one
/// [`Finding`] per change. Empty when the contracts are identical.
pub fn structural_findings(old_tool: &Value, new_tool: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();

    for field in ["description", "title", "annotations"] {
        if old_tool.get(field) != new_tool.get(field) {
            findings.push(patch_finding(field));
        }
    }

    for change in diff_schema(
        schema(old_tool, "inputSchema"),
        schema(new_tool, "inputSchema"),
    ) {
        findings.push(schema_finding(
            "inputSchema",
            input_schema_grade(&change),
            &change,
        ));
    }
    for change in diff_schema(
        schema(old_tool, "outputSchema"),
        schema(new_tool, "outputSchema"),
    ) {
        findings.push(schema_finding(
            "outputSchema",
            output_schema_grade(&change),
            &change,
        ));
    }

    findings
}

fn schema<'a>(tool: &'a Value, field: &str) -> &'a Value {
    tool.get(field).unwrap_or(EMPTY_SCHEMA)
}

fn patch_finding(field: &str) -> Finding {
    Finding {
        dimension: Dimension::Structural,
        grade: SemverGrade::Patch,
        pointer: field.to_string(),
        reason: format!("`{field}` changed"),
        security: false,
        confidence: None,
    }
}

fn schema_finding(field: &str, grade: SemverGrade, change: &SchemaChange) -> Finding {
    Finding {
        dimension: Dimension::Structural,
        grade,
        pointer: format!("{field}.{}", change_path(change)),
        reason: describe(field, change),
        security: false,
        confidence: None,
    }
}

/// Input schema variance (contravariant): more restrictive is breaking.
fn input_schema_grade(change: &SchemaChange) -> SemverGrade {
    match change {
        SchemaChange::RequiredAdded(_)
        | SchemaChange::PropertyRemoved(_)
        | SchemaChange::TypeChanged { .. }
        | SchemaChange::EnumNarrowed(_) => SemverGrade::Major,
        SchemaChange::RequiredRemoved(_)
        | SchemaChange::PropertyAdded(_)
        | SchemaChange::EnumWidened(_) => SemverGrade::Minor,
    }
}

/// Output schema variance (covariant): removing or narrowing is breaking,
/// widening or adding is safe for a tolerant reader.
fn output_schema_grade(change: &SchemaChange) -> SemverGrade {
    match change {
        SchemaChange::PropertyRemoved(_)
        | SchemaChange::TypeChanged { .. }
        | SchemaChange::RequiredRemoved(_) => SemverGrade::Major,
        SchemaChange::PropertyAdded(_)
        | SchemaChange::RequiredAdded(_)
        | SchemaChange::EnumWidened(_)
        | SchemaChange::EnumNarrowed(_) => SemverGrade::Minor,
    }
}

fn change_path(change: &SchemaChange) -> &str {
    match change {
        SchemaChange::PropertyAdded(p)
        | SchemaChange::PropertyRemoved(p)
        | SchemaChange::RequiredAdded(p)
        | SchemaChange::RequiredRemoved(p)
        | SchemaChange::EnumWidened(p)
        | SchemaChange::EnumNarrowed(p) => p,
        SchemaChange::TypeChanged { path, .. } => path,
    }
}

fn describe(field: &str, change: &SchemaChange) -> String {
    match change {
        SchemaChange::PropertyAdded(p) => format!("{field} property `{p}` added"),
        SchemaChange::PropertyRemoved(p) => format!("{field} property `{p}` removed"),
        SchemaChange::RequiredAdded(p) => format!("{field} property `{p}` became required"),
        SchemaChange::RequiredRemoved(p) => format!("{field} property `{p}` no longer required"),
        SchemaChange::TypeChanged { path, old, new } => {
            format!("{field} property `{path}` type changed {old} to {new}")
        }
        SchemaChange::EnumWidened(p) => format!("{field} property `{p}` enum widened"),
        SchemaChange::EnumNarrowed(p) => format!("{field} property `{p}` enum narrowed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn top(old: &Value, new: &Value) -> SemverGrade {
        super::super::max_grade(&structural_findings(old, new))
    }

    #[test]
    fn identical_tools_have_no_findings() {
        let t = json!({"name": "t", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}});
        assert!(structural_findings(&t, &t).is_empty());
    }

    #[test]
    fn description_only_change_is_patch() {
        let old = json!({"name": "t", "description": "old"});
        let new = json!({"name": "t", "description": "new"});
        assert_eq!(top(&old, &new), SemverGrade::Patch);
    }

    #[test]
    fn input_newly_required_field_is_major() {
        let old = json!({"name": "t", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}});
        let new = json!({"name": "t", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]}});
        assert_eq!(top(&old, &new), SemverGrade::Major);
    }

    #[test]
    fn input_optional_property_added_is_minor() {
        let old = json!({"name": "t", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}});
        let new = json!({"name": "t", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}, "limit": {"type": "number"}}}});
        assert_eq!(top(&old, &new), SemverGrade::Minor);
    }

    #[test]
    fn input_type_narrowed_is_major() {
        let old = json!({"name": "t", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}});
        let new = json!({"name": "t", "inputSchema": {"type": "object", "properties": {"q": {"type": "number"}}}});
        assert_eq!(top(&old, &new), SemverGrade::Major);
    }

    #[test]
    fn output_property_removed_is_major() {
        let old = json!({"name": "t", "outputSchema": {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "number"}}}});
        let new = json!({"name": "t", "outputSchema": {"type": "object", "properties": {"a": {"type": "string"}}}});
        assert_eq!(top(&old, &new), SemverGrade::Major);
    }

    #[test]
    fn output_property_added_is_minor() {
        let old = json!({"name": "t", "outputSchema": {"type": "object", "properties": {"a": {"type": "string"}}}});
        let new = json!({"name": "t", "outputSchema": {"type": "object", "properties": {"a": {"type": "string"}, "c": {"type": "boolean"}}}});
        assert_eq!(top(&old, &new), SemverGrade::Minor);
    }
}
