//! MCP Streamable HTTP transport.
//!
//! Bidirectional: HTTP POST sends JSON-RPC requests, SSE stream
//! returns responses. Supports JSON-RPC batching.

use super::types::{JsonRpcRequest, JsonRpcResponse};

// --- Streamable HTTP Send ---

/// Send a JSON-RPC request to an MCP server via Streamable HTTP.
///
/// The server receives an HTTP POST with the serialized request body,
/// and returns a JSON response (or SSE stream). This implementation
/// reads the first complete JSON object from the response body.
pub async fn send_request(
    client: &reqwest::Client,
    server_url: &str,
    request: &JsonRpcRequest,
) -> anyhow::Result<JsonRpcResponse> {
    let resp = client
        .post(server_url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(request)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("MCP server returned HTTP {}", status);
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if content_type.contains("text/event-stream") {
        // SSE response: parse events until we find a JSON-RPC response.
        let body = resp.text().await?;
        parse_sse_response(&body)
    } else {
        // Plain JSON response.
        let response: JsonRpcResponse = resp.json().await?;
        Ok(response)
    }
}

/// Send a batch of JSON-RPC requests.
///
/// The MCP server must support JSON-RPC batching. Returns one response
/// per request in the same order.
pub async fn send_batch(
    client: &reqwest::Client,
    server_url: &str,
    requests: &[JsonRpcRequest],
) -> anyhow::Result<Vec<JsonRpcResponse>> {
    if requests.is_empty() {
        return Ok(Vec::new());
    }

    let resp = client
        .post(server_url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(requests)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("MCP server returned HTTP {} for batch", status);
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if content_type.contains("text/event-stream") {
        let body = resp.text().await?;
        parse_sse_batch_response(&body)
    } else {
        let responses: Vec<JsonRpcResponse> = resp.json().await?;
        Ok(responses)
    }
}

// --- SSE Parsing Helpers ---

/// Parse an SSE response body and extract the first JSON-RPC response.
pub(crate) fn parse_sse_response(body: &str) -> anyhow::Result<JsonRpcResponse> {
    for line in body.lines() {
        let line = line.trim();
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if data == "[DONE]" || data.is_empty() {
                continue;
            }
            if let Ok(response) = serde_json::from_str::<JsonRpcResponse>(data) {
                return Ok(response);
            }
        }
    }
    anyhow::bail!("no valid JSON-RPC response found in SSE stream")
}

/// Parse an SSE response body that may contain multiple JSON-RPC responses.
fn parse_sse_batch_response(body: &str) -> anyhow::Result<Vec<JsonRpcResponse>> {
    let mut responses = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if data == "[DONE]" || data.is_empty() {
                continue;
            }
            // Try single response first, then array.
            if let Ok(response) = serde_json::from_str::<JsonRpcResponse>(data) {
                responses.push(response);
            } else if let Ok(batch) = serde_json::from_str::<Vec<JsonRpcResponse>>(data) {
                responses.extend(batch);
            }
        }
    }
    if responses.is_empty() {
        anyhow::bail!("no valid JSON-RPC responses found in SSE batch stream");
    }
    Ok(responses)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::types::JsonRpcError;
    use serde_json::json;

    fn make_request(method: &str, id: i64) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: None,
            id: Some(json!(id)),
        }
    }

    #[test]
    fn test_request_serialization() {
        let req = make_request("tools/list", 1);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"tools/list\""));
        assert!(json.contains("\"id\":1"));
    }

    #[test]
    fn test_request_with_params_serialization() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "tools/call".to_string(),
            params: Some(json!({"name": "my_tool", "arguments": {}})),
            id: Some(json!(42)),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"params\""));
        assert!(json.contains("\"my_tool\""));
    }

    #[test]
    fn test_response_deserialization_success() {
        let raw = r#"{"jsonrpc":"2.0","result":{"tools":[]},"id":1}"#;
        let resp: JsonRpcResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
        assert_eq!(resp.id, Some(json!(1)));
    }

    #[test]
    fn test_response_deserialization_error() {
        let raw =
            r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found"},"id":99}"#;
        let resp: JsonRpcResponse = serde_json::from_str(raw).unwrap();
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "method not found");
    }

    #[test]
    fn test_error_struct_serialization() {
        let err = JsonRpcError {
            code: -32700,
            message: "Parse error".to_string(),
            data: Some(json!("extra info")),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("-32700"));
        assert!(json.contains("Parse error"));
    }

    #[test]
    fn test_batch_serialization() {
        let requests = vec![make_request("tools/list", 1), make_request("ping", 2)];
        let json = serde_json::to_string(&requests).unwrap();
        // Should serialize as a JSON array.
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        assert!(json.contains("tools/list"));
        assert!(json.contains("ping"));
    }

    #[test]
    fn test_batch_deserialization() {
        let raw = r#"[
            {"jsonrpc":"2.0","result":{"tools":[]},"id":1},
            {"jsonrpc":"2.0","result":"pong","id":2}
        ]"#;
        let responses: Vec<JsonRpcResponse> = serde_json::from_str(raw).unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].id, Some(json!(1)));
        assert_eq!(responses[1].id, Some(json!(2)));
    }

    #[test]
    fn test_parse_sse_response_success() {
        let sse_body = "data: {\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[]},\"id\":1}\n\n";
        let resp = parse_sse_response(sse_body).unwrap();
        assert_eq!(resp.id, Some(json!(1)));
        assert!(resp.result.is_some());
    }

    #[test]
    fn test_parse_sse_response_with_prefix_lines() {
        let sse_body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":5}\n\n";
        let resp = parse_sse_response(sse_body).unwrap();
        assert_eq!(resp.id, Some(json!(5)));
    }

    #[test]
    fn test_parse_sse_response_skips_done() {
        let sse_body = "data: [DONE]\ndata: {\"jsonrpc\":\"2.0\",\"result\":null,\"id\":7}\n";
        let resp = parse_sse_response(sse_body).unwrap();
        assert_eq!(resp.id, Some(json!(7)));
    }

    #[test]
    fn test_parse_sse_response_no_data_fails() {
        let result = parse_sse_response("event: open\n\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_notification_has_no_id() {
        let notif = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "notifications/initialized".to_string(),
            params: None,
            id: None,
        };
        let json = serde_json::to_string(&notif).unwrap();
        // id should be serialized as null (it's Option<Value>).
        assert!(json.contains("\"id\":null") || !json.contains("\"id\""));
    }
}
