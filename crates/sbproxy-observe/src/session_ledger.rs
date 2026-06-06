// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! WOR-1186: emit the canonical Session Ledger from live MCP traffic.
//!
//! SBproxy already sits on the MCP `tools/call` path, so it is the
//! natural runtime capture point for the **session ledger**: an
//! append-only, per-tool-call run record that behavioral eval can query
//! ("which tools, in what order, with what params") instead of parsing a
//! transcript. The record shape is defined OSS-side in mcptest
//! (`schemas/session-ledger-v1.json`) and is shared so production
//! traffic and mcptest runs speak one schema.
//!
//! A ledger is newline-delimited JSON: one [`LedgerHeader`] per session,
//! then one [`LedgerToolCall`] per call in call order. This module owns
//! the record types, a process-global [`SessionLedgerSink`] (mirroring
//! [`crate::request_sink`]), a bounded per-session hop counter, and
//! [`emit_tool_call`], the single entry point the dispatcher calls.
//!
//! Payloads (`params`, `result`) are redacted with
//! [`crate::redact::redact_secrets`] before they leave the process, the
//! same way the access log treats request bodies.
//!
//! ## Cost when disabled
//!
//! With no sink registered (the OSS default) [`emit_tool_call`] returns
//! after a single relaxed atomic load, so deployments that do not opt in
//! pay nothing on the tool-call path.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

use serde::Serialize;

use crate::redact::redact_secrets;

/// The ledger schema version this emitter conforms to. Matches the
/// `schema_version` constant in `session-ledger-v1.json`.
pub const LEDGER_SCHEMA_VERSION: &str = "v1";

/// How a tool call was issued, per the schema's `caller` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Caller {
    /// A direct model tool call (the normal `tools/call` path).
    Direct,
    /// A call emitted from a code-execution sandbox.
    CodeExecution,
}

/// One ledger record: either the per-session header or one tool call.
/// Serializes with a `type` discriminator (`"header"` / `"tool_call"`)
/// exactly as the canonical schema's `oneOf` requires.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LedgerRecord {
    /// The first line of a session: run metadata the tool calls group
    /// under.
    Header(LedgerHeader),
    /// One MCP tool call as it crossed the boundary.
    ToolCall(LedgerToolCall),
}

/// The ledger header record (schema `$defs/header`).
#[derive(Debug, Clone, Serialize)]
pub struct LedgerHeader {
    /// Ledger schema version, e.g. `"v1"`.
    pub schema_version: String,
    /// Groups every record produced by one session / agent task.
    pub session_id: String,
    /// RFC 3339 timestamp the session was first observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
}

/// The ledger tool-call record (schema `$defs/tool_call`). Optional
/// fields are omitted when absent so the emitted line stays minimal.
#[derive(Debug, Clone, Serialize)]
pub struct LedgerToolCall {
    /// Session this call belongs to; matches the header `session_id`.
    pub session_id: String,
    /// Which agent made the call; `None` for single-agent traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Zero-based position of this call within the session.
    pub hop_index: u32,
    /// Bare tool name (no `<server>__` prefix).
    pub tool_name: String,
    /// MCP server the call routed to.
    pub server: String,
    /// Structured tool arguments, redacted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    /// Tool result payload, redacted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Whether the server flagged the result as an error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
    /// RFC 3339 timestamp the call was dispatched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// Round-trip latency of the call in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// How the call was issued.
    pub caller: Caller,
}

// --- Sink ---

/// Backend for completed ledger records. `publish` must not block on
/// I/O; the OSS file sink does a buffered local append, async backends
/// should hand off to a background task and return.
pub trait SessionLedgerSink: Send + Sync {
    /// Hand a record to the backend. Sinks swallow their own failures;
    /// the dispatch site never sees an error.
    fn publish(&self, record: LedgerRecord);
}

/// A sink that emits each record as a structured `tracing` line under
/// the `session_ledger` target. Useful for capturing the ledger from a
/// log pipeline without standing up a file or broker.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoggingLedgerSink;

impl SessionLedgerSink for LoggingLedgerSink {
    fn publish(&self, record: LedgerRecord) {
        match serde_json::to_string(&record) {
            Ok(json) => tracing::info!(target: "session_ledger", "{}", json),
            Err(e) => tracing::warn!(
                target: "session_ledger",
                error = %e,
                "session ledger record serialization failed"
            ),
        }
    }
}

/// A sink that appends each record as one NDJSON line to a file, so a
/// single developer gets the same `*.ndjson` artifact mcptest writes.
/// The append is synchronous and flushed per line so the file is
/// tail-able; this matches the local-capture intent rather than a
/// high-throughput broker.
pub struct FileLedgerSink {
    writer: Mutex<std::io::BufWriter<std::fs::File>>,
}

impl FileLedgerSink {
    /// Open `path` for appending (creating it if absent).
    pub fn create(path: &std::path::Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            writer: Mutex::new(std::io::BufWriter::new(file)),
        })
    }
}

impl SessionLedgerSink for FileLedgerSink {
    fn publish(&self, record: LedgerRecord) {
        let line = match serde_json::to_string(&record) {
            Ok(line) => line,
            Err(_) => return,
        };
        if let Ok(mut w) = self.writer.lock() {
            // Best-effort: a write failure on the local artifact must
            // never disturb the tool-call path.
            let _ = writeln!(w, "{line}");
            let _ = w.flush();
        }
    }
}

static SINK: OnceLock<Arc<dyn SessionLedgerSink>> = OnceLock::new();

/// Register the process-wide ledger sink. Returns `Err` if one was
/// already registered. Call once at startup.
pub fn set_session_ledger_sink(sink: Arc<dyn SessionLedgerSink>) -> Result<(), &'static str> {
    SINK.set(sink)
        .map_err(|_| "session ledger sink already registered")
}

/// True when a sink is registered (the ledger is enabled).
pub fn is_enabled() -> bool {
    SINK.get().is_some()
}

fn dispatch(record: LedgerRecord) {
    if let Some(sink) = SINK.get() {
        sink.publish(record);
    }
}

// --- Per-session hop counter ---

/// Bounded session -> next-hop-index table. A `tools/call` advances the
/// session's hop index; the first call for a session also yields the
/// "new session" signal that triggers a header record. Bounded with
/// FIFO eviction so unbounded session cardinality cannot leak memory;
/// an evicted-then-revived session simply restarts its hop count, which
/// only affects the rare overflow case.
struct HopTable {
    next: HashMap<String, u32>,
    order: VecDeque<String>,
    cap: usize,
}

impl HopTable {
    fn new(cap: usize) -> Self {
        Self {
            next: HashMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    /// Return `(hop_index, is_new_session)` and advance the counter.
    fn advance(&mut self, session_id: &str) -> (u32, bool) {
        if let Some(slot) = self.next.get_mut(session_id) {
            let hop = *slot;
            *slot = slot.saturating_add(1);
            return (hop, false);
        }
        if self.order.len() >= self.cap {
            if let Some(evicted) = self.order.pop_front() {
                self.next.remove(&evicted);
            }
        }
        self.next.insert(session_id.to_string(), 1);
        self.order.push_back(session_id.to_string());
        (0, true)
    }
}

/// Max distinct sessions tracked for hop indexing before FIFO eviction.
const HOP_TABLE_CAP: usize = 50_000;

fn hop_table() -> &'static Mutex<HopTable> {
    static TABLE: OnceLock<Mutex<HopTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HopTable::new(HOP_TABLE_CAP)))
}

// --- Redaction ---

/// Recursively redact secrets from a JSON value, preserving structure so
/// behavioral eval can still assert on individual argument fields. Only
/// string leaves are rewritten (via [`redact_secrets`]); object keys,
/// numbers, and booleans pass through unchanged.
pub fn redact_json(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::String(s) => Value::String(redact_secrets(s)),
        Value::Array(items) => Value::Array(items.iter().map(redact_json).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_json(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

// --- Emit ---

/// One observed tool call, the input to [`emit_tool_call`]. The caller
/// passes raw `params` / `result`; redaction happens inside so every
/// call site is consistent.
pub struct ToolCallObservation {
    /// Session id (the MCP session, or a per-request fallback).
    pub session_id: String,
    /// Agent that made the call, when known.
    pub agent_id: Option<String>,
    /// Bare tool name.
    pub tool_name: String,
    /// Server the call routed to.
    pub server: String,
    /// Raw tool arguments (redacted inside).
    pub params: serde_json::Value,
    /// Raw tool result, when the call returned one (redacted inside).
    pub result: Option<serde_json::Value>,
    /// Whether the result was flagged an error.
    pub is_error: bool,
    /// RFC 3339 timestamp the call was dispatched.
    pub started_at: String,
    /// Round-trip latency in milliseconds.
    pub duration_ms: u64,
    /// How the call was issued.
    pub caller: Caller,
}

/// Emit one tool call to the ledger. No-op (one atomic load) when no
/// sink is registered. Advances the session's hop index, emits a header
/// the first time a session is seen, redacts the payloads, and
/// dispatches the record.
pub fn emit_tool_call(obs: ToolCallObservation) {
    if !is_enabled() {
        return;
    }

    let (hop_index, is_new_session) = match hop_table().lock() {
        Ok(mut table) => table.advance(&obs.session_id),
        // A poisoned lock should never bring down the tool path; fall
        // back to hop 0 without a header rather than panicking.
        Err(_) => (0, false),
    };

    if is_new_session {
        dispatch(LedgerRecord::Header(LedgerHeader {
            schema_version: LEDGER_SCHEMA_VERSION.to_string(),
            session_id: obs.session_id.clone(),
            started_at: Some(obs.started_at.clone()),
        }));
    }

    let params = redact_json(&obs.params);
    let result = obs.result.as_ref().map(redact_json);

    dispatch(LedgerRecord::ToolCall(LedgerToolCall {
        session_id: obs.session_id,
        agent_id: obs.agent_id,
        hop_index,
        tool_name: obs.tool_name,
        server: obs.server,
        params: Some(params),
        result,
        is_error: Some(obs.is_error),
        started_at: Some(obs.started_at),
        duration_ms: Some(obs.duration_ms),
        caller: obs.caller,
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_table_advances_per_session_and_flags_new() {
        let mut t = HopTable::new(8);
        assert_eq!(t.advance("s1"), (0, true));
        assert_eq!(t.advance("s1"), (1, false));
        assert_eq!(t.advance("s2"), (0, true));
        assert_eq!(t.advance("s1"), (2, false));
    }

    #[test]
    fn hop_table_evicts_fifo_when_over_cap() {
        let mut t = HopTable::new(2);
        t.advance("a");
        t.advance("b");
        // Inserting "c" evicts "a" (oldest); "a" then restarts at 0.
        t.advance("c");
        assert_eq!(t.advance("a"), (0, true));
    }

    #[test]
    fn redact_json_rewrites_string_leaves_preserving_structure() {
        let v = serde_json::json!({
            "token": "Bearer abcdefghijklmnopqrstuvwxyz0123",
            "count": 3,
            "nested": ["sk-ant-aaaaaaaaaaaaaaaaaaaaaaaaaaaa", true]
        });
        let r = redact_json(&v);
        assert_eq!(r["count"], 3);
        assert_eq!(r["nested"][1], true);
        let token = r["token"].as_str().unwrap();
        assert!(token.contains("[REDACTED]"), "token not redacted: {token}");
        let nested0 = r["nested"][0].as_str().unwrap();
        assert!(nested0.contains("[REDACTED]"), "nested secret not redacted");
    }

    #[test]
    fn header_serializes_with_type_discriminator() {
        let rec = LedgerRecord::Header(LedgerHeader {
            schema_version: "v1".to_string(),
            session_id: "s1".to_string(),
            started_at: Some("2026-06-05T00:00:00Z".to_string()),
        });
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["type"], "header");
        assert_eq!(json["schema_version"], "v1");
        assert_eq!(json["session_id"], "s1");
    }

    #[test]
    fn tool_call_serializes_with_snake_case_and_caller_enum() {
        let rec = LedgerRecord::ToolCall(LedgerToolCall {
            session_id: "s1".to_string(),
            agent_id: None,
            hop_index: 2,
            tool_name: "get_weather".to_string(),
            server: "weather".to_string(),
            params: Some(serde_json::json!({"city": "sf"})),
            result: None,
            is_error: Some(false),
            started_at: Some("2026-06-05T00:00:00Z".to_string()),
            duration_ms: Some(12),
            caller: Caller::Direct,
        });
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["type"], "tool_call");
        assert_eq!(json["hop_index"], 2);
        assert_eq!(json["tool_name"], "get_weather");
        assert_eq!(json["caller"], "direct");
        // Absent optionals are omitted, not null.
        assert!(json.get("agent_id").is_none());
        assert!(json.get("result").is_none());
    }
}
