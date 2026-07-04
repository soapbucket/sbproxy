//! MCP wire-type round-trip tests.
//!
//! These exercise the `types` module the live gateway dispatch in
//! `sbproxy-core::server::action_dispatch` serializes over the wire.
//! WOR-1647 removed the standalone `McpHandler` (an unwired parallel
//! implementation whose proxy arm fabricated a `proxied to ...`
//! result); the `initialize` / `tools/list` / `tools/call` behaviour
//! it used to test is the live path's, covered end to end by the
//! `e2e/tests/mcp_*` suite.

use sbproxy_extension::mcp::*;

// --- JSON-RPC serialization ---

#[test]
fn jsonrpc_request_roundtrip() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "tools/list".to_string(),
        params: Some(serde_json::json!({"cursor": null})),
        id: Some(serde_json::json!(1)),
    };
    let json = serde_json::to_string(&req).unwrap();
    let parsed: JsonRpcRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.method, "tools/list");
    assert_eq!(parsed.id, Some(serde_json::json!(1)));
}

#[test]
fn jsonrpc_response_success_constructor() {
    let resp =
        JsonRpcResponse::success(Some(serde_json::json!(42)), serde_json::json!({"ok": true}));
    assert_eq!(resp.jsonrpc, "2.0");
    assert!(resp.result.is_some());
    assert!(resp.error.is_none());
    assert_eq!(resp.id, Some(serde_json::json!(42)));

    // Roundtrip through JSON - error field should be absent.
    let json = serde_json::to_string(&resp).unwrap();
    assert!(!json.contains("\"error\""));
}

#[test]
fn jsonrpc_response_error_constructor() {
    let resp = JsonRpcResponse::error(Some(serde_json::json!(7)), INVALID_PARAMS, "bad param");
    assert!(resp.result.is_none());
    let err = resp.error.as_ref().unwrap();
    assert_eq!(err.code, INVALID_PARAMS);
    assert_eq!(err.message, "bad param");

    // Roundtrip - result field should be absent.
    let json = serde_json::to_string(&resp).unwrap();
    assert!(!json.contains("\"result\""));
}

// --- MCP Tool types ---

#[test]
fn tool_serialization_with_annotations() {
    let tool = Tool {
        name: "get_weather".to_string(),
        description: Some("Fetch weather data".to_string()),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "location": { "type": "string" }
            }
        }),
        annotations: Some(ToolAnnotations {
            read_only_hint: true,
            open_world_hint: true,
            ..Default::default()
        }),
        meta: None,
    };
    let json = serde_json::to_value(&tool).unwrap();
    assert_eq!(json["name"], "get_weather");
    assert_eq!(json["inputSchema"]["type"], "object");
    assert_eq!(json["annotations"]["read_only_hint"], true);
    assert_eq!(json["annotations"]["destructive_hint"], false);
}

#[test]
fn tool_result_text_content() {
    let result = ToolResult {
        content: vec![Content::Text {
            text: "hello".to_string(),
        }],
        is_error: false,
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["content"][0]["type"], "text");
    assert_eq!(json["content"][0]["text"], "hello");
    assert_eq!(json["is_error"], false);
}

#[test]
fn tool_result_image_content() {
    let result = ToolResult {
        content: vec![Content::Image {
            data: "base64data".to_string(),
            mime_type: "image/png".to_string(),
        }],
        is_error: false,
    };
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["content"][0]["type"], "image");
    assert_eq!(json["content"][0]["mimeType"], "image/png");
}

#[test]
fn content_enum_tag_serialization() {
    // Text variant
    let text = Content::Text {
        text: "hi".to_string(),
    };
    let j = serde_json::to_value(&text).unwrap();
    assert_eq!(j["type"], "text");

    // Resource variant
    let res = Content::Resource {
        resource: ResourceRef {
            uri: "file:///tmp/a.txt".to_string(),
            name: Some("a.txt".to_string()),
            mime_type: Some("text/plain".to_string()),
        },
    };
    let j = serde_json::to_value(&res).unwrap();
    assert_eq!(j["type"], "resource");
    assert_eq!(j["resource"]["uri"], "file:///tmp/a.txt");

    // Roundtrip
    let parsed: Content = serde_json::from_value(j).unwrap();
    match parsed {
        Content::Resource { resource } => {
            assert_eq!(resource.uri, "file:///tmp/a.txt");
        }
        _ => panic!("expected Resource variant"),
    }
}
