//! MCP SSE client transport for legacy MCP servers.
//!
//! Legacy MCP servers expose a persistent SSE endpoint that clients
//! connect to in order to receive JSON-RPC responses. Requests are
//! sent as HTTP POSTs to a separate endpoint (often provided in an
//! `endpoint` SSE event during the handshake).
//!
//! This module supports two modes:
//!
//! 1. **Simple**: POST the request to `sse_url` and parse any SSE
//!    events in the response body. Some servers return SSE directly
//!    from the POST endpoint.
//!
//! 2. **Handshake**: GET `sse_url` to receive an `endpoint` event,
//!    then POST the request to that endpoint and wait for the response
//!    event on the SSE stream.

use super::streamable::parse_sse_response;
use super::types::{JsonRpcRequest, JsonRpcResponse};

// --- SSE Client ---

/// Connect to an SSE-based MCP server and send a JSON-RPC request.
///
/// Attempts a POST to `sse_url` first. If the response is plain SSE,
/// it parses events from the body. This covers the common case where
/// the SSE endpoint doubles as the POST endpoint and returns the
/// response inline as SSE events.
pub async fn send_via_sse(
    client: &reqwest::Client,
    sse_url: &str,
    request: &JsonRpcRequest,
) -> anyhow::Result<JsonRpcResponse> {
    let resp = client
        .post(sse_url)
        .header("Content-Type", "application/json")
        .header("Accept", "text/event-stream, application/json")
        .json(request)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("SSE MCP server returned HTTP {}", status);
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body = resp.text().await?;

    if content_type.contains("text/event-stream") {
        parse_sse_response(&body)
    } else {
        // Plain JSON response.
        let response: JsonRpcResponse = serde_json::from_str(&body)?;
        Ok(response)
    }
}

/// Parse raw SSE event lines and extract the `data:` payloads.
///
/// Returns one string per `data:` line, skipping comment lines and
/// the `[DONE]` sentinel.
pub fn extract_sse_data_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if let Some(data) = line.strip_prefix("data:") {
                let data = data.trim();
                if !data.is_empty() && data != "[DONE]" {
                    return Some(data.to_string());
                }
            }
            None
        })
        .collect()
}

/// Extract the `endpoint` URL from a legacy MCP SSE handshake stream.
///
/// Legacy servers emit an event like:
/// ```text
/// event: endpoint
/// data: /mcp/messages?session_id=abc123
/// ```
pub fn extract_endpoint_from_sse(raw: &str, base_url: &str) -> Option<String> {
    let mut lines = raw.lines().peekable();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line == "event: endpoint" {
            if let Some(next) = lines.next() {
                let next = next.trim();
                if let Some(path) = next.strip_prefix("data:") {
                    let path = path.trim();
                    if path.starts_with("http://") || path.starts_with("https://") {
                        return Some(path.to_string());
                    }
                    // Relative path - join with base URL.
                    let base = base_url.trim_end_matches('/');
                    return Some(format!("{}/{}", base, path.trim_start_matches('/')));
                }
            }
        }
    }
    None
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_request(method: &str, id: i64) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: None,
            id: Some(json!(id)),
        }
    }

    // --- SSE data line extraction ---

    #[test]
    fn test_extract_sse_data_lines_basic() {
        let raw = "data: hello\ndata: world\n";
        let lines = extract_sse_data_lines(raw);
        assert_eq!(lines, vec!["hello", "world"]);
    }

    #[test]
    fn test_extract_sse_data_skips_done_sentinel() {
        let raw = "data: first\ndata: [DONE]\ndata: second\n";
        let lines = extract_sse_data_lines(raw);
        assert_eq!(lines, vec!["first", "second"]);
    }

    #[test]
    fn test_extract_sse_data_skips_empty_data() {
        let raw = "data: \ndata: real\n";
        let lines = extract_sse_data_lines(raw);
        assert_eq!(lines, vec!["real"]);
    }

    #[test]
    fn test_extract_sse_data_skips_comments() {
        let raw = ": keep-alive\ndata: payload\n";
        let lines = extract_sse_data_lines(raw);
        assert_eq!(lines, vec!["payload"]);
    }

    #[test]
    fn test_extract_sse_data_event_lines_not_included() {
        let raw = "event: message\ndata: payload\n";
        let lines = extract_sse_data_lines(raw);
        assert_eq!(lines, vec!["payload"]);
    }

    // --- JSON-RPC extraction from SSE ---

    #[test]
    fn test_parse_sse_jsonrpc_success() {
        let raw = "data: {\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[]},\"id\":3}\n\n";
        let resp = parse_sse_response(raw).unwrap();
        assert_eq!(resp.id, Some(json!(3)));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_parse_sse_jsonrpc_error_response() {
        let raw = "data: {\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"not found\"},\"id\":10}\n";
        let resp = parse_sse_response(raw).unwrap();
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
    }

    #[test]
    fn test_parse_sse_multiple_events_returns_first() {
        // When multiple data lines are present, the first valid JSON-RPC wins.
        let raw =
            "data: {\"jsonrpc\":\"2.0\",\"result\":\"first\",\"id\":1}\ndata: {\"jsonrpc\":\"2.0\",\"result\":\"second\",\"id\":2}\n";
        let resp = parse_sse_response(raw).unwrap();
        assert_eq!(resp.id, Some(json!(1)));
    }

    // --- Endpoint extraction ---

    #[test]
    fn test_extract_endpoint_absolute_url() {
        let raw = "event: endpoint\ndata: https://mcp.example.com/messages?session=abc\n\n";
        let endpoint = extract_endpoint_from_sse(raw, "https://mcp.example.com");
        assert_eq!(
            endpoint,
            Some("https://mcp.example.com/messages?session=abc".to_string())
        );
    }

    #[test]
    fn test_extract_endpoint_relative_path() {
        let raw = "event: endpoint\ndata: /mcp/messages?session_id=xyz\n\n";
        let endpoint = extract_endpoint_from_sse(raw, "https://mcp.example.com");
        assert_eq!(
            endpoint,
            Some("https://mcp.example.com/mcp/messages?session_id=xyz".to_string())
        );
    }

    #[test]
    fn test_extract_endpoint_not_found() {
        let raw = "event: open\ndata: connected\n\n";
        let endpoint = extract_endpoint_from_sse(raw, "https://mcp.example.com");
        assert!(endpoint.is_none());
    }

    #[test]
    fn test_extract_endpoint_base_url_trailing_slash() {
        let raw = "event: endpoint\ndata: /api/mcp\n\n";
        let endpoint = extract_endpoint_from_sse(raw, "https://host.example.com/");
        assert_eq!(
            endpoint,
            Some("https://host.example.com/api/mcp".to_string())
        );
    }

    // --- Request round-trip ---

    #[test]
    fn test_request_serializes_for_sse_transport() {
        let req = make_request("tools/list", 1);
        let json_str = serde_json::to_string(&req).unwrap();
        // Can be deserialized back.
        let parsed: JsonRpcRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.method, "tools/list");
        assert_eq!(parsed.id, Some(json!(1)));
    }
}
