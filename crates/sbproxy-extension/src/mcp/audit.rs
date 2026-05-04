//! MCP audit trail.
//!
//! Every MCP tool invocation should produce an audit entry that is
//! emitted to the structured log (target `mcp_audit`). Entries can be
//! collected downstream by log aggregators for compliance, debugging,
//! and analytics.

use serde::Serialize;

// --- Audit Entry ---

/// A single MCP tool invocation audit record.
#[derive(Debug, Serialize)]
pub struct McpAuditEntry {
    /// ISO 8601 timestamp when the invocation was recorded.
    pub timestamp: String,
    /// Name of the tool that was called.
    pub tool_name: String,
    /// Name of the upstream server that handled the call.
    pub server_name: String,
    /// Optional identifier of the caller (user, session, API key, etc.).
    pub caller_id: Option<String>,
    /// Arguments passed to the tool.
    pub arguments: serde_json::Value,
    /// Outcome of the invocation: `"success"` or `"error"`.
    pub result_status: String,
    /// Wall-clock duration of the call in milliseconds.
    pub duration_ms: u64,
}

impl McpAuditEntry {
    /// Emit this audit entry as a structured log event at INFO level.
    ///
    /// The log target `mcp_audit` allows callers to filter or route
    /// these events separately from application logs.
    pub fn emit(&self) {
        match serde_json::to_string(self) {
            Ok(json) => tracing::info!(target: "mcp_audit", "{}", json),
            Err(e) => tracing::warn!(
                target: "mcp_audit",
                tool = %self.tool_name,
                error = %e,
                "failed to serialize audit entry"
            ),
        }
    }
}

// --- Builder ---

/// Builder for [`McpAuditEntry`] that captures a start time and
/// computes the elapsed duration automatically.
pub struct McpAuditBuilder {
    tool_name: String,
    server_name: String,
    caller_id: Option<String>,
    arguments: serde_json::Value,
    started_at: std::time::Instant,
}

impl McpAuditBuilder {
    /// Begin recording a tool invocation.
    pub fn start(
        tool_name: impl Into<String>,
        server_name: impl Into<String>,
        caller_id: Option<String>,
        arguments: serde_json::Value,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            server_name: server_name.into(),
            caller_id,
            arguments,
            started_at: std::time::Instant::now(),
        }
    }

    /// Finish recording, build the entry, and emit it.
    ///
    /// `status` should be `"success"` or `"error"`.
    pub fn finish(self, status: &str) -> McpAuditEntry {
        let duration_ms = self.started_at.elapsed().as_millis() as u64;
        let entry = McpAuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tool_name: self.tool_name,
            server_name: self.server_name,
            caller_id: self.caller_id,
            arguments: self.arguments,
            result_status: status.to_string(),
            duration_ms,
        };
        entry.emit();
        entry
    }

    /// Convenience: finish with `"success"` status.
    pub fn success(self) -> McpAuditEntry {
        self.finish("success")
    }

    /// Convenience: finish with `"error"` status.
    pub fn error(self) -> McpAuditEntry {
        self.finish("error")
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_entry(status: &str) -> McpAuditEntry {
        McpAuditEntry {
            timestamp: "2026-04-16T12:00:00Z".to_string(),
            tool_name: "search".to_string(),
            server_name: "web_server".to_string(),
            caller_id: Some("user_123".to_string()),
            arguments: json!({"query": "hello world"}),
            result_status: status.to_string(),
            duration_ms: 42,
        }
    }

    // --- Serialization ---

    #[test]
    fn test_audit_entry_serializes_all_fields() {
        let entry = make_entry("success");
        let json = serde_json::to_string(&entry).unwrap();

        assert!(json.contains("\"timestamp\""));
        assert!(json.contains("\"tool_name\""));
        assert!(json.contains("\"server_name\""));
        assert!(json.contains("\"caller_id\""));
        assert!(json.contains("\"arguments\""));
        assert!(json.contains("\"result_status\""));
        assert!(json.contains("\"duration_ms\""));
    }

    #[test]
    fn test_audit_entry_field_values() {
        let entry = make_entry("success");
        let value: serde_json::Value = serde_json::to_value(&entry).unwrap();

        assert_eq!(value["timestamp"], "2026-04-16T12:00:00Z");
        assert_eq!(value["tool_name"], "search");
        assert_eq!(value["server_name"], "web_server");
        assert_eq!(value["caller_id"], "user_123");
        assert_eq!(value["result_status"], "success");
        assert_eq!(value["duration_ms"], 42);
        assert_eq!(value["arguments"]["query"], "hello world");
    }

    #[test]
    fn test_audit_entry_null_caller_id() {
        let entry = McpAuditEntry {
            timestamp: "2026-04-16T12:00:00Z".to_string(),
            tool_name: "ping".to_string(),
            server_name: "core".to_string(),
            caller_id: None,
            arguments: json!({}),
            result_status: "success".to_string(),
            duration_ms: 1,
        };
        let value: serde_json::Value = serde_json::to_value(&entry).unwrap();
        assert!(value["caller_id"].is_null());
    }

    #[test]
    fn test_audit_entry_error_status() {
        let entry = make_entry("error");
        let value: serde_json::Value = serde_json::to_value(&entry).unwrap();
        assert_eq!(value["result_status"], "error");
    }

    #[test]
    fn test_audit_entry_success_status() {
        let entry = make_entry("success");
        let value: serde_json::Value = serde_json::to_value(&entry).unwrap();
        assert_eq!(value["result_status"], "success");
    }

    #[test]
    fn test_audit_entry_complex_arguments() {
        let entry = McpAuditEntry {
            timestamp: "2026-04-16T12:00:00Z".to_string(),
            tool_name: "create_file".to_string(),
            server_name: "fs_server".to_string(),
            caller_id: Some("agent_007".to_string()),
            arguments: json!({
                "path": "/tmp/test.txt",
                "content": "hello",
                "mode": 0o644,
                "overwrite": true,
            }),
            result_status: "success".to_string(),
            duration_ms: 150,
        };
        let value: serde_json::Value = serde_json::to_value(&entry).unwrap();
        assert_eq!(value["arguments"]["path"], "/tmp/test.txt");
        assert_eq!(value["arguments"]["overwrite"], true);
    }

    #[test]
    fn test_emit_does_not_panic() {
        // Smoke test: emit should not panic even without a tracing subscriber.
        let entry = make_entry("success");
        entry.emit(); // Should not panic.
    }

    // --- Builder ---

    #[test]
    fn test_audit_builder_success() {
        let builder = McpAuditBuilder::start(
            "my_tool",
            "my_server",
            Some("caller_abc".to_string()),
            json!({"x": 1}),
        );
        let entry = builder.success();
        assert_eq!(entry.tool_name, "my_tool");
        assert_eq!(entry.server_name, "my_server");
        assert_eq!(entry.caller_id, Some("caller_abc".to_string()));
        assert_eq!(entry.result_status, "success");
        // Duration should be >= 0.
        assert!(entry.duration_ms < 5_000); // should finish well under 5s in a unit test
    }

    #[test]
    fn test_audit_builder_error() {
        let builder = McpAuditBuilder::start("bad_tool", "bad_server", None, json!({}));
        let entry = builder.error();
        assert_eq!(entry.result_status, "error");
        assert!(entry.caller_id.is_none());
    }

    #[test]
    fn test_audit_builder_timestamp_is_rfc3339() {
        let builder = McpAuditBuilder::start("t", "s", None, json!({}));
        let entry = builder.success();
        // Should be parseable as RFC 3339.
        chrono::DateTime::parse_from_rfc3339(&entry.timestamp)
            .expect("timestamp should be valid RFC 3339");
    }

    #[test]
    fn test_audit_entry_duration_zero_or_more() {
        let entry = make_entry("success");
        // duration_ms is u64 - always >= 0 by type.
        let _ = entry.duration_ms;
    }
}
