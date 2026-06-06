// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! WOR-1186: the records SBproxy emits must validate against the
//! canonical `session-ledger-v1` schema shared with mcptest. The schema
//! is vendored verbatim next to this test; if mcptest revises it, copy
//! the new version over and this test guards the new shape.

use jsonschema::JSONSchema;
use sbproxy_observe::session_ledger::{
    Caller, LedgerHeader, LedgerRecord, LedgerToolCall, LEDGER_SCHEMA_VERSION,
};

/// Compile the vendored canonical schema once per test.
fn schema() -> JSONSchema {
    let raw = include_str!("session-ledger-v1.json");
    let value: serde_json::Value = serde_json::from_str(raw).expect("schema is valid JSON");
    JSONSchema::compile(&value).expect("schema compiles")
}

fn assert_valid(schema: &JSONSchema, record: &LedgerRecord) {
    let instance = serde_json::to_value(record).expect("record serializes");
    let errors: Vec<String> = match schema.validate(&instance) {
        Ok(()) => return,
        Err(iter) => iter
            .map(|e| format!("{e} at {}", e.instance_path))
            .collect(),
    };
    panic!("record failed schema validation: {errors:?}");
}

#[test]
fn header_record_conforms_to_canonical_schema() {
    let schema = schema();
    let record = LedgerRecord::Header(LedgerHeader {
        schema_version: LEDGER_SCHEMA_VERSION.to_string(),
        session_id: "01J0SESSIONID".to_string(),
        started_at: Some("2026-06-05T12:00:00Z".to_string()),
    });
    assert_valid(&schema, &record);
}

#[test]
fn full_tool_call_record_conforms_to_canonical_schema() {
    let schema = schema();
    let record = LedgerRecord::ToolCall(LedgerToolCall {
        session_id: "01J0SESSIONID".to_string(),
        agent_id: Some("planner".to_string()),
        hop_index: 3,
        tool_name: "get_weather".to_string(),
        server: "weather".to_string(),
        params: Some(serde_json::json!({"city": "sf", "units": "metric"})),
        result: Some(serde_json::json!({"content": [{"type": "text", "text": "sunny"}]})),
        is_error: Some(false),
        started_at: Some("2026-06-05T12:00:01Z".to_string()),
        duration_ms: Some(42),
        caller: Caller::Direct,
    });
    assert_valid(&schema, &record);
}

#[test]
fn minimal_tool_call_record_conforms_to_canonical_schema() {
    // Only the schema-required fields, optionals omitted. Mirrors a
    // sessionless single-agent call with empty params.
    let schema = schema();
    let record = LedgerRecord::ToolCall(LedgerToolCall {
        session_id: "req-123".to_string(),
        agent_id: None,
        hop_index: 0,
        tool_name: "ping".to_string(),
        server: "unknown".to_string(),
        params: None,
        result: None,
        is_error: None,
        started_at: None,
        duration_ms: None,
        caller: Caller::CodeExecution,
    });
    assert_valid(&schema, &record);
}
