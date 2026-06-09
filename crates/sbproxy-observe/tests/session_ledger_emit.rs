// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! WOR-1186: end-to-end check of the emit path through a registered
//! sink. Runs in its own test binary so the set-once global sink starts
//! fresh.

use std::sync::{Arc, Mutex};

use sbproxy_observe::session_ledger::{
    emit_tool_call, set_session_ledger_sink, Caller, LedgerRecord, SessionLedgerSink,
    ToolCallObservation,
};

#[derive(Default)]
struct CapturingSink {
    records: Mutex<Vec<LedgerRecord>>,
}

impl SessionLedgerSink for CapturingSink {
    fn publish(&self, record: LedgerRecord) {
        self.records.lock().expect("lock").push(record);
    }
}

fn obs(session: &str, tool: &str, secret_arg: &str) -> ToolCallObservation {
    ToolCallObservation {
        session_id: session.to_string(),
        agent_id: Some("planner".to_string()),
        tool_name: tool.to_string(),
        server: "weather".to_string(),
        params: serde_json::json!({"key": secret_arg, "city": "sf"}),
        result: Some(serde_json::json!({"isError": false})),
        is_error: false,
        started_at: "2026-06-05T12:00:00Z".to_string(),
        duration_ms: 7,
        caller: Caller::Direct,
    }
}

#[test]
fn emit_writes_header_once_then_ordered_tool_calls_with_redaction() {
    let sink = Arc::new(CapturingSink::default());
    set_session_ledger_sink(sink.clone()).expect("first sink registration");

    // Two calls in one session, plus one call in a second session.
    emit_tool_call(obs(
        "sess-A",
        "get_weather",
        "Bearer abcdefghijklmnopqrstuvwxyz01",
    ));
    emit_tool_call(obs("sess-A", "get_forecast", "ordinary-value"));
    emit_tool_call(obs("sess-B", "get_weather", "ordinary-value"));

    let records = sink.records.lock().expect("lock").clone();

    // Expect: header(A), tool_call(A,hop0), tool_call(A,hop1), header(B), tool_call(B,hop0).
    assert_eq!(records.len(), 5, "got {records:?}");

    match &records[0] {
        LedgerRecord::Header(h) => {
            assert_eq!(h.session_id, "sess-A");
            assert_eq!(h.schema_version, "v1");
        }
        other => panic!("expected header first, got {other:?}"),
    }

    // First session-A tool call: hop 0, and the secret arg redacted.
    match &records[1] {
        LedgerRecord::ToolCall(tc) => {
            assert_eq!(tc.session_id, "sess-A");
            assert_eq!(tc.hop_index, 0);
            assert_eq!(tc.tool_name, "get_weather");
            assert_eq!(tc.agent_id.as_deref(), Some("planner"));
            let key = tc.params.as_ref().unwrap()["key"].as_str().unwrap();
            assert!(key.contains("[REDACTED]"), "secret arg not redacted: {key}");
            // Non-secret field preserved.
            assert_eq!(tc.params.as_ref().unwrap()["city"], "sf");
        }
        other => panic!("expected tool_call, got {other:?}"),
    }

    // Second session-A call advances the hop index.
    match &records[2] {
        LedgerRecord::ToolCall(tc) => {
            assert_eq!(tc.hop_index, 1);
            assert_eq!(tc.tool_name, "get_forecast");
        }
        other => panic!("expected tool_call, got {other:?}"),
    }

    // Session B emits its own header and restarts the hop index.
    match &records[3] {
        LedgerRecord::Header(h) => assert_eq!(h.session_id, "sess-B"),
        other => panic!("expected header for session B, got {other:?}"),
    }
    match &records[4] {
        LedgerRecord::ToolCall(tc) => {
            assert_eq!(tc.session_id, "sess-B");
            assert_eq!(tc.hop_index, 0);
        }
        other => panic!("expected tool_call, got {other:?}"),
    }
}
