//! MCP tool call tracing spans.
//!
//! Provides span constructors for the MCP tool invocation pipeline so that
//! upstream tool calls are visible in distributed traces alongside regular
//! proxy request spans.

/// Create a span for a single MCP tool call.
///
/// `tool_name` is the name of the tool being invoked (e.g. `"web_search"`).
/// `server_name` identifies which MCP server hosts the tool.
pub fn tool_call_span(tool_name: &str, server_name: &str) -> tracing::Span {
    tracing::info_span!("mcp.tool_call", tool = tool_name, server = server_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_call_span_is_valid() {
        let span = tool_call_span("web_search", "brave-search-mcp");
        // Verify the span can be created and entered without panicking.
        let _guard = span.entered();
    }

    #[test]
    fn tool_call_span_different_tools() {
        let s1 = tool_call_span("code_execution", "sandbox-mcp");
        let s2 = tool_call_span("file_read", "filesystem-mcp");
        let _ = format!("{:?}", s1);
        let _ = format!("{:?}", s2);
    }
}
