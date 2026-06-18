// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Cassette-backed MCP schema-drift detection (WOR-526).
//!
//! Cassettes are consumer contracts: they record the tools and argument
//! shapes a client relied on during a known-good run. This module
//! extracts that implied contract from mcptest-style cassettes and
//! compares it with a live `tools/list` snapshot so CI can catch MCP
//! producer drift before deploy.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::schema_drift::DriftSeverity;
use super::types::Tool;

/// Event type used by downstream audit/event sinks for cassette drift.
pub const CASSETTE_DRIFT_EVENT_TYPE: &str = "mcp.schema_drift.detected";

/// Consumer contract extracted from one cassette.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CassetteContract {
    /// Cassette identifier, normally a path or stable run id.
    pub cassette: String,
    /// Tools implied by `tools/list` snapshots and observed
    /// `tools/call` records inside the cassette.
    pub tools: Vec<CassetteToolContract>,
}

/// One tool contract extracted from a cassette or live `tools/list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CassetteToolContract {
    /// Tool name as used in `tools/call`.
    pub name: String,
    /// Optional human-readable tool description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Field-level input contract extracted from `inputSchema` and
    /// observed arguments.
    pub fields: Vec<CassetteFieldContract>,
}

/// One top-level input field in an MCP tool schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CassetteFieldContract {
    /// Field name inside the tool input object.
    pub name: String,
    /// Whether the tool schema declares the field as required.
    pub required: bool,
    /// JSON Schema type slug, if declared or inferable from observed
    /// arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ty: Option<String>,
    /// Closed enum values declared for the field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<String>,
    /// True when the field was seen in a recorded `tools/call`, even
    /// if no catalog schema declared it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub observed: bool,
}

/// Result of comparing one cassette contract against a live tool list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CassetteDriftReport {
    /// Cassette identifier used as the consumer-contract source.
    pub cassette: String,
    /// Overall severity across every change.
    pub severity: DriftSeverity,
    /// Classified changes found during comparison.
    pub changes: Vec<CassetteDriftChange>,
}

impl CassetteDriftReport {
    /// Build a report from individual changes and derive overall
    /// severity from the max change severity.
    pub fn from_changes(cassette: impl Into<String>, changes: Vec<CassetteDriftChange>) -> Self {
        let severity = changes
            .iter()
            .map(|change| change.severity)
            .max()
            .unwrap_or(DriftSeverity::None);
        Self {
            cassette: cassette.into(),
            severity,
            changes,
        }
    }

    /// Convert every change to the structured event payload expected
    /// by audit/event sinks.
    pub fn events(&self) -> Vec<CassetteDriftEvent> {
        self.changes
            .iter()
            .map(|change| CassetteDriftEvent {
                event_type: CASSETTE_DRIFT_EVENT_TYPE.to_string(),
                cassette: self.cassette.clone(),
                tool: change.tool.clone(),
                field: change.field.clone(),
                kind: change.kind,
                severity: change.severity,
                summary: change.summary.clone(),
            })
            .collect()
    }
}

/// One classified cassette-vs-live change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CassetteDriftChange {
    /// Tool the change applies to.
    pub tool: String,
    /// Field the change applies to. Absent for tool-level changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Severity bucket for this change.
    pub severity: DriftSeverity,
    /// Closed-set kind for downstream filters.
    pub kind: CassetteDriftKind,
    /// Human-readable summary.
    pub summary: String,
}

/// Stable change-kind vocabulary for cassette drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CassetteDriftKind {
    /// Live `tools/list` contains a tool absent from the cassette.
    ToolAdded,
    /// A cassette tool is absent from live `tools/list`.
    ToolRemoved,
    /// Tool description changed.
    DescriptionChanged,
    /// A live field is absent from the cassette contract.
    FieldAdded,
    /// A cassette field is absent from the live schema.
    FieldRemoved,
    /// A field changed requiredness.
    RequiredFlipped,
    /// A field type changed.
    TypeChanged,
    /// A field enum dropped values.
    EnumShrunk,
    /// A field enum gained values.
    EnumWidened,
}

/// Structured event payload for `mcp.schema_drift.detected`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CassetteDriftEvent {
    /// Event type, always [`CASSETTE_DRIFT_EVENT_TYPE`].
    pub event_type: String,
    /// Cassette identifier.
    pub cassette: String,
    /// Tool the drift applies to.
    pub tool: String,
    /// Field the drift applies to. Absent for tool-level changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Closed-set drift kind.
    pub kind: CassetteDriftKind,
    /// Drift severity.
    pub severity: DriftSeverity,
    /// Human-readable summary.
    pub summary: String,
}

/// Load a JSON, YAML, or NDJSON document from disk.
pub fn load_document(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|err| format!("reading {}: {err}", path.display()))?;
    if let Ok(value) = serde_json::from_slice(&bytes) {
        return Ok(value);
    }
    if let Ok(value) = parse_ndjson(&bytes) {
        return Ok(value);
    }
    serde_yaml::from_slice(&bytes).map_err(|err| format!("parsing {}: {err}", path.display()))
}

/// Extract the cassette's implied consumer contract.
pub fn cassette_contract_from_value(
    cassette: impl Into<String>,
    value: &Value,
) -> CassetteContract {
    let cassette = cassette.into();
    let mut accumulators = BTreeMap::<String, ToolAccumulator>::new();

    for tool in tools_from_value(value) {
        accumulators
            .entry(tool.name.clone())
            .or_insert_with(|| ToolAccumulator::new(tool.name.clone()))
            .merge_tool(&tool);
    }

    for (name, args) in tool_calls_from_value(value) {
        accumulators
            .entry(name.clone())
            .or_insert_with(|| ToolAccumulator::new(name))
            .merge_observed_args(&args);
    }

    CassetteContract {
        cassette,
        tools: accumulators
            .into_values()
            .map(ToolAccumulator::into_contract)
            .collect(),
    }
}

/// Extract MCP tool definitions from a raw `tools/list` response or
/// any cassette envelope that contains one.
pub fn tools_from_value(value: &Value) -> Vec<Tool> {
    let mut tools = BTreeMap::new();
    collect_tools(value, &mut tools);
    tools.into_values().collect()
}

/// Compare a cassette contract against a live `tools/list` document.
pub fn diff_cassette_values(
    cassette: impl Into<String>,
    cassette_value: &Value,
    live_tools_value: &Value,
) -> CassetteDriftReport {
    let cassette = cassette.into();
    let contract = cassette_contract_from_value(cassette.clone(), cassette_value);
    let live_tools = tools_from_value(live_tools_value);
    diff_cassette_against_tools(&contract, &live_tools)
}

/// Compare a cassette contract against live MCP tools.
pub fn diff_cassette_against_tools(
    cassette: &CassetteContract,
    live_tools: &[Tool],
) -> CassetteDriftReport {
    let live_contract = contract_from_tools("__live__", live_tools);
    let expected_by_name = map_tools(&cassette.tools);
    let live_by_name = map_tools(&live_contract.tools);

    let expected_names: BTreeSet<&str> = expected_by_name.keys().map(String::as_str).collect();
    let live_names: BTreeSet<&str> = live_by_name.keys().map(String::as_str).collect();
    let mut changes = Vec::new();

    for name in live_names.difference(&expected_names) {
        changes.push(change(
            *name,
            None,
            DriftSeverity::Informational,
            CassetteDriftKind::ToolAdded,
            format!("tool `{name}` added to live tools/list"),
        ));
    }
    for name in expected_names.difference(&live_names) {
        changes.push(change(
            *name,
            None,
            DriftSeverity::Breaking,
            CassetteDriftKind::ToolRemoved,
            format!("tool `{name}` removed from live tools/list"),
        ));
    }

    for name in expected_names.intersection(&live_names) {
        let expected = expected_by_name.get(*name).unwrap();
        let live = live_by_name.get(*name).unwrap();
        diff_tool(expected, live, &mut changes);
    }

    CassetteDriftReport::from_changes(cassette.cassette.clone(), changes)
}

fn parse_ndjson(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|err| err.to_string())?;
    let mut values = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_str(trimmed).map_err(|err| format!("line {}: {err}", idx + 1))?;
        values.push(value);
    }
    if values.is_empty() {
        return Err("empty document".to_string());
    }
    Ok(Value::Array(values))
}

fn contract_from_tools(cassette: impl Into<String>, tools: &[Tool]) -> CassetteContract {
    let mut accumulators = BTreeMap::<String, ToolAccumulator>::new();
    for tool in tools {
        accumulators
            .entry(tool.name.clone())
            .or_insert_with(|| ToolAccumulator::new(tool.name.clone()))
            .merge_tool(tool);
    }
    CassetteContract {
        cassette: cassette.into(),
        tools: accumulators
            .into_values()
            .map(ToolAccumulator::into_contract)
            .collect(),
    }
}

fn map_tools(tools: &[CassetteToolContract]) -> BTreeMap<String, &CassetteToolContract> {
    tools.iter().map(|tool| (tool.name.clone(), tool)).collect()
}

fn diff_tool(
    expected: &CassetteToolContract,
    live: &CassetteToolContract,
    changes: &mut Vec<CassetteDriftChange>,
) {
    if let (Some(expected_desc), Some(live_desc)) = (&expected.description, &live.description) {
        if expected_desc != live_desc {
            changes.push(change(
                &expected.name,
                None,
                DriftSeverity::Informational,
                CassetteDriftKind::DescriptionChanged,
                format!("tool `{}` description changed", expected.name),
            ));
        }
    }

    let expected_fields = map_fields(&expected.fields);
    let live_fields = map_fields(&live.fields);
    let expected_names: BTreeSet<&str> = expected_fields.keys().map(String::as_str).collect();
    let live_names: BTreeSet<&str> = live_fields.keys().map(String::as_str).collect();

    for field in live_names.difference(&expected_names) {
        let live_field = live_fields.get(*field).unwrap();
        let severity = if live_field.required {
            DriftSeverity::Breaking
        } else {
            DriftSeverity::Informational
        };
        changes.push(change(
            &expected.name,
            Some(*field),
            severity,
            CassetteDriftKind::FieldAdded,
            format!(
                "field `{}` added to tool `{}`{}",
                field,
                expected.name,
                if live_field.required {
                    " (required)"
                } else {
                    ""
                }
            ),
        ));
    }

    for field in expected_names.difference(&live_names) {
        changes.push(change(
            &expected.name,
            Some(*field),
            DriftSeverity::Breaking,
            CassetteDriftKind::FieldRemoved,
            format!("field `{}` removed from tool `{}`", field, expected.name),
        ));
    }

    for field in expected_names.intersection(&live_names) {
        let expected_field = expected_fields.get(*field).unwrap();
        let live_field = live_fields.get(*field).unwrap();
        diff_field(&expected.name, expected_field, live_field, changes);
    }
}

fn map_fields(fields: &[CassetteFieldContract]) -> BTreeMap<String, &CassetteFieldContract> {
    fields
        .iter()
        .map(|field| (field.name.clone(), field))
        .collect()
}

fn diff_field(
    tool: &str,
    expected: &CassetteFieldContract,
    live: &CassetteFieldContract,
    changes: &mut Vec<CassetteDriftChange>,
) {
    if expected.required != live.required {
        let severity = if live.required {
            DriftSeverity::Breaking
        } else {
            DriftSeverity::Informational
        };
        changes.push(change(
            tool,
            Some(expected.name.as_str()),
            severity,
            CassetteDriftKind::RequiredFlipped,
            format!(
                "field `{}` required flipped on tool `{}`: {} -> {}",
                expected.name,
                tool,
                required_label(expected.required),
                required_label(live.required)
            ),
        ));
    }

    if let (Some(expected_ty), Some(live_ty)) = (&expected.ty, &live.ty) {
        if expected_ty != live_ty {
            let severity = if expected.required || live.required || expected.observed {
                DriftSeverity::Breaking
            } else {
                DriftSeverity::Informational
            };
            changes.push(change(
                tool,
                Some(expected.name.as_str()),
                severity,
                CassetteDriftKind::TypeChanged,
                format!(
                    "field `{}` type changed on tool `{}`: `{}` -> `{}`",
                    expected.name, tool, expected_ty, live_ty
                ),
            ));
        }
    }

    let expected_enum: BTreeSet<&String> = expected.enum_values.iter().collect();
    let live_enum: BTreeSet<&String> = live.enum_values.iter().collect();
    if !expected_enum.is_empty() || !live_enum.is_empty() {
        let removed: Vec<String> = expected_enum
            .difference(&live_enum)
            .map(|value| (*value).clone())
            .collect();
        let added: Vec<String> = live_enum
            .difference(&expected_enum)
            .map(|value| (*value).clone())
            .collect();
        if !removed.is_empty() {
            changes.push(change(
                tool,
                Some(expected.name.as_str()),
                DriftSeverity::Breaking,
                CassetteDriftKind::EnumShrunk,
                format!(
                    "field `{}` enum shrunk on tool `{}`: removed [{}]",
                    expected.name,
                    tool,
                    quote_join(&removed)
                ),
            ));
        }
        if !added.is_empty() {
            changes.push(change(
                tool,
                Some(expected.name.as_str()),
                DriftSeverity::Informational,
                CassetteDriftKind::EnumWidened,
                format!(
                    "field `{}` enum widened on tool `{}`: added [{}]",
                    expected.name,
                    tool,
                    quote_join(&added)
                ),
            ));
        }
    }
}

fn change(
    tool: impl Into<String>,
    field: Option<&str>,
    severity: DriftSeverity,
    kind: CassetteDriftKind,
    summary: String,
) -> CassetteDriftChange {
    CassetteDriftChange {
        tool: tool.into(),
        field: field.map(str::to_string),
        severity,
        kind,
        summary,
    }
}

fn required_label(required: bool) -> &'static str {
    if required {
        "required"
    } else {
        "optional"
    }
}

fn quote_join(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("`{value}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn collect_tools(value: &Value, out: &mut BTreeMap<String, Tool>) {
    match value {
        Value::Object(map) => {
            if let Some(tool) = parse_tool(value) {
                out.entry(tool.name.clone()).or_insert(tool);
            }
            if let Some(items) = map.get("tools").and_then(Value::as_array) {
                for item in items {
                    if let Some(tool) = parse_tool(item) {
                        out.entry(tool.name.clone()).or_insert(tool);
                    }
                }
            }
            for child in map.values() {
                collect_tools(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_tools(item, out);
            }
        }
        _ => {}
    }
}

fn parse_tool(value: &Value) -> Option<Tool> {
    let map = value.as_object()?;
    let name = map.get("name").and_then(Value::as_str)?;
    let input_schema = map
        .get("inputSchema")
        .or_else(|| map.get("input_schema"))?
        .clone();
    let description = map
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_string);
    let annotations = map
        .get("annotations")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok());
    let meta = map.get("_meta").cloned();
    Some(Tool {
        name: name.to_string(),
        description,
        input_schema,
        annotations,
        meta,
    })
}

fn tool_calls_from_value(value: &Value) -> Vec<(String, Value)> {
    let mut calls = Vec::new();
    collect_tool_calls(value, &mut calls);
    calls
}

fn collect_tool_calls(value: &Value, out: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(map) => {
            if map.get("method").and_then(Value::as_str) == Some("tools/call") {
                if let Some(params) = map.get("params").and_then(Value::as_object) {
                    if let Some(name) = params.get("name").and_then(Value::as_str) {
                        let args = params
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| Value::Object(Default::default()));
                        out.push((name.to_string(), args));
                    }
                }
            }
            if map.get("type").and_then(Value::as_str) == Some("tool_call") {
                if let Some(name) = map.get("tool_name").and_then(Value::as_str) {
                    let args = map
                        .get("params")
                        .cloned()
                        .unwrap_or_else(|| Value::Object(Default::default()));
                    out.push((name.to_string(), args));
                }
            }
            for child in map.values() {
                collect_tool_calls(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_tool_calls(item, out);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Clone)]
struct ToolAccumulator {
    name: String,
    description: Option<String>,
    fields: BTreeMap<String, FieldAccumulator>,
}

impl ToolAccumulator {
    fn new(name: String) -> Self {
        Self {
            name,
            description: None,
            fields: BTreeMap::new(),
        }
    }

    fn merge_tool(&mut self, tool: &Tool) {
        if self.description.is_none() {
            self.description = tool.description.clone();
        }
        for field in fields_from_schema(&tool.input_schema) {
            self.fields
                .entry(field.name.clone())
                .and_modify(|existing| existing.merge(field.clone()))
                .or_insert(field);
        }
    }

    fn merge_observed_args(&mut self, args: &Value) {
        let Some(args) = args.as_object() else {
            return;
        };
        for (name, value) in args {
            let field = FieldAccumulator {
                name: name.clone(),
                required: false,
                ty: type_from_observed_value(value),
                enum_values: BTreeSet::new(),
                observed: true,
            };
            self.fields
                .entry(name.clone())
                .and_modify(|existing| existing.merge(field.clone()))
                .or_insert(field);
        }
    }

    fn into_contract(self) -> CassetteToolContract {
        CassetteToolContract {
            name: self.name,
            description: self.description,
            fields: self
                .fields
                .into_values()
                .map(FieldAccumulator::into_contract)
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct FieldAccumulator {
    name: String,
    required: bool,
    ty: Option<String>,
    enum_values: BTreeSet<String>,
    observed: bool,
}

impl FieldAccumulator {
    fn merge(&mut self, other: FieldAccumulator) {
        self.required |= other.required;
        self.observed |= other.observed;
        if self.ty.is_none() {
            self.ty = other.ty;
        }
        self.enum_values.extend(other.enum_values);
    }

    fn into_contract(self) -> CassetteFieldContract {
        CassetteFieldContract {
            name: self.name,
            required: self.required,
            ty: self.ty,
            enum_values: self.enum_values.into_iter().collect(),
            observed: self.observed,
        }
    }
}

fn fields_from_schema(schema: &Value) -> Vec<FieldAccumulator> {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

    properties
        .iter()
        .map(|(name, schema)| FieldAccumulator {
            name: name.clone(),
            required: required.contains(name.as_str()),
            ty: type_from_schema(schema),
            enum_values: enum_from_schema(schema),
            observed: false,
        })
        .collect()
}

fn type_from_schema(schema: &Value) -> Option<String> {
    if let Some(ty) = schema.get("type").and_then(Value::as_str) {
        return Some(ty.to_string());
    }
    if let Some(types) = schema.get("type").and_then(Value::as_array) {
        let mut out = types
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
        out.sort();
        if !out.is_empty() {
            return Some(out.join("|"));
        }
    }
    if schema.get("$ref").is_some() {
        return Some("$ref".to_string());
    }
    if schema.get("enum").is_some() {
        return Some("enum".to_string());
    }
    None
}

fn type_from_observed_value(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("null".to_string()),
        Value::Bool(_) => Some("boolean".to_string()),
        Value::Number(number) if number.is_i64() || number.is_u64() => Some("integer".to_string()),
        Value::Number(_) => Some("number".to_string()),
        Value::String(_) => Some("string".to_string()),
        Value::Array(_) => Some("array".to_string()),
        Value::Object(_) => Some("object".to_string()),
    }
}

fn enum_from_schema(schema: &Value) -> BTreeSet<String> {
    schema
        .get("enum")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(enum_value_label).collect())
        .unwrap_or_default()
}

fn enum_value_label(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_tools_list_and_reports_structured_event_payload() {
        let cassette = json!({
            "interactions": [{
                "response": {
                    "result": {
                        "tools": [{
                            "name": "search",
                            "description": "Search docs",
                            "inputSchema": {
                                "type": "object",
                                "required": ["query"],
                                "properties": {
                                    "query": {"type": "string"},
                                    "mode": {"type": "string", "enum": ["fast", "deep"]}
                                }
                            }
                        }]
                    }
                }
            }]
        });
        let live = json!({
            "result": {
                "tools": [{
                    "name": "search",
                    "description": "Search docs",
                    "inputSchema": {
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": {"type": "string"},
                            "mode": {"type": "string", "enum": ["fast"]}
                        }
                    }
                }]
            }
        });

        let report = diff_cassette_values("fixtures/search.json", &cassette, &live);

        assert_eq!(report.severity, DriftSeverity::Breaking);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].kind, CassetteDriftKind::EnumShrunk);
        assert_eq!(report.changes[0].tool, "search");
        assert_eq!(report.changes[0].field.as_deref(), Some("mode"));

        let events = report.events();
        assert_eq!(events[0].event_type, CASSETTE_DRIFT_EVENT_TYPE);
        assert_eq!(events[0].cassette, "fixtures/search.json");
        assert_eq!(events[0].kind, CassetteDriftKind::EnumShrunk);
    }

    #[test]
    fn extracts_observed_tool_call_shapes_from_session_ledger() {
        let cassette = json!([
            {"type": "header", "schema_version": "v1", "session_id": "s1"},
            {
                "type": "tool_call",
                "session_id": "s1",
                "tool_name": "get_weather",
                "server": "weather",
                "params": {"city": "Paris", "units": "metric"},
                "caller": "direct"
            }
        ]);
        let contract = cassette_contract_from_value("ledger.ndjson", &cassette);

        assert_eq!(contract.tools.len(), 1);
        assert_eq!(contract.tools[0].name, "get_weather");
        assert!(contract.tools[0]
            .fields
            .iter()
            .any(|field| field.name == "city" && field.ty.as_deref() == Some("string")));
        assert!(contract.tools[0].fields.iter().all(|field| field.observed));
    }

    #[test]
    fn required_live_field_added_is_breaking() {
        let cassette = json!({
            "method": "tools/call",
            "params": {"name": "search", "arguments": {"query": "rust"}}
        });
        let live = json!({
            "tools": [{
                "name": "search",
                "inputSchema": {
                    "type": "object",
                    "required": ["query", "tenant"],
                    "properties": {
                        "query": {"type": "string"},
                        "tenant": {"type": "string"}
                    }
                }
            }]
        });

        let report = diff_cassette_values("call.json", &cassette, &live);

        assert_eq!(report.severity, DriftSeverity::Breaking);
        assert!(report.changes.iter().any(|change| {
            change.kind == CassetteDriftKind::FieldAdded
                && change.field.as_deref() == Some("tenant")
                && change.severity == DriftSeverity::Breaking
        }));
    }

    #[test]
    fn ndjson_loader_accepts_session_ledger_lines() {
        let input = br#"{"type":"header","schema_version":"v1","session_id":"s1"}
{"type":"tool_call","session_id":"s1","tool_name":"search","params":{"query":"x"},"caller":"direct"}
"#;
        let value = parse_ndjson(input).expect("parse ndjson");

        assert!(value.is_array());
        let contract = cassette_contract_from_value("ledger.ndjson", &value);
        assert_eq!(contract.tools[0].name, "search");
    }

    #[test]
    fn load_document_prefers_ndjson_before_yaml() {
        let path = std::env::temp_dir().join(format!(
            "sbproxy-cassette-drift-{}.ndjson",
            std::process::id()
        ));
        std::fs::write(
            &path,
            br#"{"type":"header","schema_version":"v1","session_id":"s1"}
{"type":"tool_call","session_id":"s1","tool_name":"search","params":{"query":"x"},"caller":"direct"}
"#,
        )
        .expect("write fixture");

        let value = load_document(&path).expect("load ndjson");
        let _ = std::fs::remove_file(&path);

        assert_eq!(value.as_array().map(Vec::len), Some(2));
    }
}
