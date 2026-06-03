// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! Schema-drift detection for converted MCP servers (WOR-486).
//!
//! The landscape research identified schema drift as the
//! most-cited open problem in the API-to-MCP space: when the
//! upstream OpenAPI changes, MCP tools fail silently with
//! confident wrong answers. Teams hand-roll regeneration
//! pipelines in CI and live without a contract test.
//!
//! This module diffs two OpenAPI snapshots and classifies the
//! changes by severity so a CI gate can refuse to regenerate
//! the MCP tool surface on a breaking change without explicit
//! operator opt-in.
//!
//! ## Severity model
//!
//! * `DriftSeverity::None`: identical specs.
//! * `DriftSeverity::Informational`: tool added, description
//!   changed, required field made optional. Operators see these
//!   but they do not break existing callers.
//! * `DriftSeverity::Breaking`: tool removed, required field
//!   removed, type narrowed on a required field, enum narrowed.
//!   Existing callers WILL break.
//!
//! ## Exit codes (consumed by `sbproxy-mcp-drift`)
//!
//! * `0`: no drift.
//! * `1`: informational only.
//! * `2`: breaking changes present.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Overall severity of a drift report. Maps onto the CLI's exit
/// code: `None` → 0, `Informational` → 1, `Breaking` → 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftSeverity {
    /// Specs are identical.
    None,
    /// At least one change exists; none are breaking.
    Informational,
    /// At least one change would break existing callers.
    Breaking,
}

impl DriftSeverity {
    /// Stable wire form for the JSON output + the human-readable
    /// summary line.
    pub fn as_str(&self) -> &'static str {
        match self {
            DriftSeverity::None => "none",
            DriftSeverity::Informational => "informational",
            DriftSeverity::Breaking => "breaking",
        }
    }

    /// Exit code the CLI emits when this is the overall severity.
    pub fn exit_code(&self) -> i32 {
        match self {
            DriftSeverity::None => 0,
            DriftSeverity::Informational => 1,
            DriftSeverity::Breaking => 2,
        }
    }
}

/// One classified change. The CLI's text + JSON renderers walk
/// the `Vec<DriftChange>` on the report and group by severity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftChange {
    /// Severity bucket this change falls into.
    pub severity: DriftSeverity,
    /// Tool / operation id the change applies to (the OpenAPI
    /// `operationId` field). Used as the primary grouping key
    /// in the report.
    pub operation: String,
    /// Short human-readable summary the CLI prints + the audit
    /// event carries.
    pub summary: String,
    /// Closed-set change kind for downstream consumers that want
    /// to label / filter without a regex on `summary`.
    pub kind: DriftKind,
}

/// Stable closed-set vocabulary of the change types the
/// drift-detector emits. Adding a variant is a deliberate edit;
/// the CLI's JSON output keys downstream tooling off this enum
/// so a new variant is a wire-shape change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    /// New operation appeared in the current spec.
    OperationAdded,
    /// Operation present in the previous spec is gone.
    OperationRemoved,
    /// Description-only change on an existing operation.
    DescriptionChanged,
    /// New required parameter on an existing operation.
    RequiredParamAdded,
    /// Required parameter removed (breaking: existing callers
    /// supply it but the upstream now rejects it).
    RequiredParamRemoved,
    /// Required parameter made optional (informational: existing
    /// callers still supply it; new callers can omit).
    RequiredParamRelaxed,
    /// Type changed on a required parameter (breaking: the wire
    /// payload changes shape).
    RequiredParamTypeChanged,
    /// Enum narrowed: at least one value from the previous spec
    /// is missing in the current. Existing callers that submit
    /// the dropped value will be rejected.
    EnumNarrowed,
    /// Enum widened: new values added; informational.
    EnumWidened,
}

/// Result of comparing two OpenAPI snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftReport {
    /// Overall severity (the max severity across `changes`).
    pub severity: DriftSeverity,
    /// Every classified change. Empty when severity is `None`.
    pub changes: Vec<DriftChange>,
}

impl DriftReport {
    /// Compose a `DriftReport` from a list of changes. The
    /// `severity` field is the max across the list.
    pub fn from_changes(changes: Vec<DriftChange>) -> Self {
        let severity = changes
            .iter()
            .map(|c| c.severity)
            .max()
            .unwrap_or(DriftSeverity::None);
        Self { severity, changes }
    }
}

/// Diff two OpenAPI specs and classify the changes.
///
/// Inputs are `serde_json::Value` so the caller can read JSON
/// or YAML upstream. The function walks `paths.<path>.<method>`
/// entries; each operation is identified by its `operationId`
/// (falls back to `path + method`) so the diff is stable across
/// re-orderings.
///
/// Coverage today:
/// * operation added / removed
/// * operation description-only change
/// * required-parameter added / removed / relaxed
/// * required-parameter type changed
/// * required-parameter enum narrowed / widened
///
/// The diff intentionally STOPS at the parameter level: deep
/// schema diffs (oneOf, $ref chasing, additionalProperties) are
/// a follow-up.
pub fn diff_openapi(prev: &serde_json::Value, current: &serde_json::Value) -> DriftReport {
    let mut changes = Vec::new();
    let prev_ops = collect_operations(prev);
    let cur_ops = collect_operations(current);

    let prev_keys: BTreeSet<&str> = prev_ops.iter().map(|o| o.id.as_str()).collect();
    let cur_keys: BTreeSet<&str> = cur_ops.iter().map(|o| o.id.as_str()).collect();

    for added in cur_keys.difference(&prev_keys) {
        changes.push(DriftChange {
            severity: DriftSeverity::Informational,
            operation: (*added).to_string(),
            summary: format!("operation `{added}` added"),
            kind: DriftKind::OperationAdded,
        });
    }
    for removed in prev_keys.difference(&cur_keys) {
        changes.push(DriftChange {
            severity: DriftSeverity::Breaking,
            operation: (*removed).to_string(),
            summary: format!("operation `{removed}` removed"),
            kind: DriftKind::OperationRemoved,
        });
    }

    for id in prev_keys.intersection(&cur_keys) {
        let prev_op = prev_ops.iter().find(|o| &o.id == id).unwrap();
        let cur_op = cur_ops.iter().find(|o| &o.id == id).unwrap();
        diff_operation(prev_op, cur_op, &mut changes);
    }

    DriftReport::from_changes(changes)
}

/// Parsed shape of one operation entry from an OpenAPI spec.
#[derive(Debug, Clone)]
struct OperationView {
    id: String,
    description: String,
    parameters: Vec<ParameterView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParameterView {
    name: String,
    required: bool,
    /// Type slug as serialised in OpenAPI (`integer`, `string`,
    /// `array`, ...). Empty when the param did not declare one.
    ty: String,
    /// Enum values when the param declared one. Empty when not.
    enum_values: BTreeSet<String>,
}

fn collect_operations(spec: &serde_json::Value) -> Vec<OperationView> {
    let Some(paths) = spec.get("paths").and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (path, methods) in paths {
        let Some(methods) = methods.as_object() else {
            continue;
        };
        for (method, op) in methods {
            // OpenAPI 3 also has non-method keys under a path
            // (`parameters`, `summary`, ...); skip those.
            let lower = method.to_ascii_lowercase();
            if !matches!(
                lower.as_str(),
                "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
            ) {
                continue;
            }
            let id = op
                .get("operationId")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("{} {}", lower.to_uppercase(), path));
            let description = op
                .get("description")
                .and_then(|v| v.as_str())
                .or_else(|| op.get("summary").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();
            let mut parameters = Vec::new();
            if let Some(params) = op.get("parameters").and_then(|v| v.as_array()) {
                for p in params {
                    let name = p
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let required = p.get("required").and_then(|v| v.as_bool()).unwrap_or(false);
                    let schema = p.get("schema").cloned().unwrap_or(serde_json::Value::Null);
                    let ty = schema
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let enum_values = schema
                        .get("enum")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    parameters.push(ParameterView {
                        name,
                        required,
                        ty,
                        enum_values,
                    });
                }
            }
            out.push(OperationView {
                id,
                description,
                parameters,
            });
        }
    }
    out
}

fn diff_operation(prev: &OperationView, cur: &OperationView, out: &mut Vec<DriftChange>) {
    if prev.description != cur.description {
        out.push(DriftChange {
            severity: DriftSeverity::Informational,
            operation: prev.id.clone(),
            summary: format!("operation `{}` description changed", prev.id),
            kind: DriftKind::DescriptionChanged,
        });
    }
    let prev_names: BTreeSet<&str> = prev.parameters.iter().map(|p| p.name.as_str()).collect();
    let cur_names: BTreeSet<&str> = cur.parameters.iter().map(|p| p.name.as_str()).collect();

    // Added params: informational unless required.
    for name in cur_names.difference(&prev_names) {
        let p = cur.parameters.iter().find(|p| p.name == *name).unwrap();
        let severity = if p.required {
            DriftSeverity::Breaking
        } else {
            DriftSeverity::Informational
        };
        out.push(DriftChange {
            severity,
            operation: cur.id.clone(),
            summary: format!(
                "param `{}` added{}",
                name,
                if p.required { " (required)" } else { "" }
            ),
            kind: DriftKind::RequiredParamAdded,
        });
    }
    // Removed params: breaking when previously required.
    for name in prev_names.difference(&cur_names) {
        let p = prev.parameters.iter().find(|p| p.name == *name).unwrap();
        let severity = if p.required {
            DriftSeverity::Breaking
        } else {
            DriftSeverity::Informational
        };
        out.push(DriftChange {
            severity,
            operation: prev.id.clone(),
            summary: format!(
                "param `{}` removed{}",
                name,
                if p.required { " (was required)" } else { "" }
            ),
            kind: DriftKind::RequiredParamRemoved,
        });
    }
    // Common params: check required-toggle, type, enum changes.
    for name in prev_names.intersection(&cur_names) {
        let prev_p = prev.parameters.iter().find(|p| p.name == *name).unwrap();
        let cur_p = cur.parameters.iter().find(|p| p.name == *name).unwrap();
        if prev_p.required && !cur_p.required {
            out.push(DriftChange {
                severity: DriftSeverity::Informational,
                operation: prev.id.clone(),
                summary: format!("param `{}` made optional", name),
                kind: DriftKind::RequiredParamRelaxed,
            });
        }
        // required-now-where-it-was-not is the same as adding a
        // required param: breaking.
        if !prev_p.required && cur_p.required {
            out.push(DriftChange {
                severity: DriftSeverity::Breaking,
                operation: cur.id.clone(),
                summary: format!("param `{}` newly required", name),
                kind: DriftKind::RequiredParamAdded,
            });
        }
        if prev_p.ty != cur_p.ty && !prev_p.ty.is_empty() && !cur_p.ty.is_empty() {
            let severity = if prev_p.required || cur_p.required {
                DriftSeverity::Breaking
            } else {
                DriftSeverity::Informational
            };
            out.push(DriftChange {
                severity,
                operation: prev.id.clone(),
                summary: format!(
                    "param `{}` type changed: `{}` -> `{}`",
                    name, prev_p.ty, cur_p.ty
                ),
                kind: DriftKind::RequiredParamTypeChanged,
            });
        }
        if !prev_p.enum_values.is_empty() || !cur_p.enum_values.is_empty() {
            let removed: BTreeSet<&String> =
                prev_p.enum_values.difference(&cur_p.enum_values).collect();
            let added: BTreeSet<&String> =
                cur_p.enum_values.difference(&prev_p.enum_values).collect();
            if !removed.is_empty() {
                let summary = format!(
                    "param `{}` enum narrowed: removed [{}]",
                    name,
                    removed
                        .iter()
                        .map(|s| format!("`{}`", s))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                out.push(DriftChange {
                    severity: DriftSeverity::Breaking,
                    operation: prev.id.clone(),
                    summary,
                    kind: DriftKind::EnumNarrowed,
                });
            }
            if !added.is_empty() {
                let summary = format!(
                    "param `{}` enum widened: added [{}]",
                    name,
                    added
                        .iter()
                        .map(|s| format!("`{}`", s))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                out.push(DriftChange {
                    severity: DriftSeverity::Informational,
                    operation: cur.id.clone(),
                    summary,
                    kind: DriftKind::EnumWidened,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec_one() -> serde_json::Value {
        json!({
            "openapi": "3.0.0",
            "paths": {
                "/widgets": {
                    "get": {
                        "operationId": "listWidgets",
                        "description": "List all widgets",
                        "parameters": [
                            {
                                "name": "limit",
                                "required": false,
                                "schema": { "type": "integer" }
                            }
                        ]
                    }
                }
            }
        })
    }

    /// Identical specs: severity None + empty changes list.
    #[test]
    fn identical_specs_have_no_drift() {
        let report = diff_openapi(&spec_one(), &spec_one());
        assert_eq!(report.severity, DriftSeverity::None);
        assert!(report.changes.is_empty());
    }

    /// Removing an operation is a breaking change.
    #[test]
    fn removing_operation_is_breaking() {
        let prev = spec_one();
        let cur = json!({ "openapi": "3.0.0", "paths": {} });
        let report = diff_openapi(&prev, &cur);
        assert_eq!(report.severity, DriftSeverity::Breaking);
        assert!(report
            .changes
            .iter()
            .any(|c| matches!(c.kind, DriftKind::OperationRemoved)));
    }

    /// Adding an operation is informational.
    #[test]
    fn adding_operation_is_informational() {
        let prev = json!({ "openapi": "3.0.0", "paths": {} });
        let cur = spec_one();
        let report = diff_openapi(&prev, &cur);
        assert_eq!(report.severity, DriftSeverity::Informational);
        assert!(report
            .changes
            .iter()
            .any(|c| matches!(c.kind, DriftKind::OperationAdded)));
    }

    /// Description-only change is informational.
    #[test]
    fn description_change_is_informational() {
        let prev = spec_one();
        let mut cur = spec_one();
        cur["paths"]["/widgets"]["get"]["description"] = json!("List all widgets (rewritten copy)");
        let report = diff_openapi(&prev, &cur);
        assert_eq!(report.severity, DriftSeverity::Informational);
        assert!(report
            .changes
            .iter()
            .any(|c| matches!(c.kind, DriftKind::DescriptionChanged)));
    }

    /// Making a required field optional is informational.
    #[test]
    fn required_relaxed_is_informational() {
        let mut prev = spec_one();
        prev["paths"]["/widgets"]["get"]["parameters"][0]["required"] = json!(true);
        let cur = spec_one();
        let report = diff_openapi(&prev, &cur);
        assert_eq!(report.severity, DriftSeverity::Informational);
        assert!(report
            .changes
            .iter()
            .any(|c| matches!(c.kind, DriftKind::RequiredParamRelaxed)));
    }

    /// Newly required field is breaking (existing callers omit it).
    #[test]
    fn newly_required_is_breaking() {
        let prev = spec_one();
        let mut cur = spec_one();
        cur["paths"]["/widgets"]["get"]["parameters"][0]["required"] = json!(true);
        let report = diff_openapi(&prev, &cur);
        assert_eq!(report.severity, DriftSeverity::Breaking);
        assert!(report
            .changes
            .iter()
            .any(|c| matches!(c.kind, DriftKind::RequiredParamAdded)));
    }

    /// Type change on a required field is breaking.
    #[test]
    fn type_change_on_required_field_is_breaking() {
        let mut prev = spec_one();
        prev["paths"]["/widgets"]["get"]["parameters"][0]["required"] = json!(true);
        let mut cur = spec_one();
        cur["paths"]["/widgets"]["get"]["parameters"][0]["required"] = json!(true);
        cur["paths"]["/widgets"]["get"]["parameters"][0]["schema"]["type"] = json!("string");
        let report = diff_openapi(&prev, &cur);
        assert_eq!(report.severity, DriftSeverity::Breaking);
        assert!(report
            .changes
            .iter()
            .any(|c| matches!(c.kind, DriftKind::RequiredParamTypeChanged)));
    }

    /// Type change on an optional field is informational.
    #[test]
    fn type_change_on_optional_field_is_informational() {
        let prev = spec_one();
        let mut cur = spec_one();
        cur["paths"]["/widgets"]["get"]["parameters"][0]["schema"]["type"] = json!("string");
        let report = diff_openapi(&prev, &cur);
        assert_eq!(report.severity, DriftSeverity::Informational);
        assert!(report
            .changes
            .iter()
            .any(|c| matches!(c.kind, DriftKind::RequiredParamTypeChanged)));
    }

    /// Enum narrowing is breaking (dropped values would reject
    /// existing callers).
    #[test]
    fn enum_narrowing_is_breaking() {
        let mut prev = spec_one();
        prev["paths"]["/widgets"]["get"]["parameters"][0]["schema"]["enum"] =
            json!(["a", "b", "c"]);
        let mut cur = spec_one();
        cur["paths"]["/widgets"]["get"]["parameters"][0]["schema"]["enum"] = json!(["a", "b"]);
        let report = diff_openapi(&prev, &cur);
        assert_eq!(report.severity, DriftSeverity::Breaking);
        assert!(report
            .changes
            .iter()
            .any(|c| matches!(c.kind, DriftKind::EnumNarrowed)));
    }

    /// Enum widening is informational.
    #[test]
    fn enum_widening_is_informational() {
        let mut prev = spec_one();
        prev["paths"]["/widgets"]["get"]["parameters"][0]["schema"]["enum"] = json!(["a", "b"]);
        let mut cur = spec_one();
        cur["paths"]["/widgets"]["get"]["parameters"][0]["schema"]["enum"] = json!(["a", "b", "c"]);
        let report = diff_openapi(&prev, &cur);
        assert_eq!(report.severity, DriftSeverity::Informational);
        assert!(report
            .changes
            .iter()
            .any(|c| matches!(c.kind, DriftKind::EnumWidened)));
    }

    /// `DriftSeverity::exit_code` slugs pinned (the CLI gates
    /// downstream tooling on these).
    #[test]
    fn severity_exit_codes_pinned() {
        assert_eq!(DriftSeverity::None.exit_code(), 0);
        assert_eq!(DriftSeverity::Informational.exit_code(), 1);
        assert_eq!(DriftSeverity::Breaking.exit_code(), 2);
        assert_eq!(DriftSeverity::None.as_str(), "none");
        assert_eq!(DriftSeverity::Informational.as_str(), "informational");
        assert_eq!(DriftSeverity::Breaking.as_str(), "breaking");
    }

    /// Mixed change set: the overall severity is the max across
    /// the change list.
    #[test]
    fn overall_severity_is_max_across_changes() {
        let mut prev = spec_one();
        prev["paths"]["/widgets"]["get"]["parameters"][0]["required"] = json!(true);
        let mut cur = spec_one();
        cur["paths"]["/widgets"]["get"]["parameters"][0]["required"] = json!(true);
        cur["paths"]["/widgets"]["get"]["description"] = json!("rewritten");
        cur["paths"]["/widgets"]["get"]["parameters"][0]["schema"]["type"] = json!("string");
        let report = diff_openapi(&prev, &cur);
        // One Informational (description) + one Breaking (type
        // change on required) → overall Breaking.
        assert_eq!(report.severity, DriftSeverity::Breaking);
        assert!(report.changes.len() >= 2);
    }
}
