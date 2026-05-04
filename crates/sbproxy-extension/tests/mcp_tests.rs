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

// --- ToolRegistry ---

fn make_tool(name: &str) -> Tool {
    Tool {
        name: name.to_string(),
        description: Some(format!("{} tool", name)),
        input_schema: serde_json::json!({"type": "object"}),
        annotations: None,
    }
}

#[test]
fn registry_register_and_get() {
    let mut reg = ToolRegistry::new();
    assert!(reg.is_empty());

    reg.register(
        make_tool("alpha"),
        ToolHandlerType::Static(serde_json::json!("a")),
    );
    reg.register(
        make_tool("beta"),
        ToolHandlerType::Proxy {
            origin: "upstream".to_string(),
        },
    );

    assert_eq!(reg.len(), 2);
    assert!(!reg.is_empty());
    assert!(reg.get("alpha").is_some());
    assert!(reg.get("gamma").is_none());
}

#[test]
fn registry_list_tools() {
    let mut reg = ToolRegistry::new();
    reg.register(
        make_tool("a"),
        ToolHandlerType::Static(serde_json::json!(1)),
    );
    reg.register(
        make_tool("b"),
        ToolHandlerType::Static(serde_json::json!(2)),
    );

    let tools = reg.list_tools();
    assert_eq!(tools.len(), 2);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"a"));
    assert!(names.contains(&"b"));
}

// --- McpHandler ---

fn make_handler() -> McpHandler {
    let mut reg = ToolRegistry::new();
    reg.register(
        make_tool("echo"),
        ToolHandlerType::Static(serde_json::json!({"echoed": true})),
    );
    reg.register(
        make_tool("proxy_tool"),
        ToolHandlerType::Proxy {
            origin: "backend".to_string(),
        },
    );
    McpHandler::new(reg, "test-server", "0.1.0")
}

fn rpc(
    method: &str,
    params: Option<serde_json::Value>,
    id: Option<serde_json::Value>,
) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params,
        id,
    }
}

#[test]
fn handler_initialize() {
    let h = make_handler();
    let req = rpc("initialize", None, Some(serde_json::json!(1)));
    let resp = h.handle_request(&req).unwrap();
    let result = resp.result.unwrap();
    assert_eq!(result["protocol_version"], "2025-06-18");
    assert_eq!(result["server_info"]["name"], "test-server");
    assert!(result["capabilities"]["tools"].is_object());
}

#[test]
fn handler_tools_list() {
    let h = make_handler();
    let req = rpc("tools/list", None, Some(serde_json::json!(2)));
    let resp = h.handle_request(&req).unwrap();
    let tools = resp.result.unwrap()["tools"].as_array().unwrap().clone();
    assert_eq!(tools.len(), 2);
}

#[test]
fn handler_tools_call_static() {
    let h = make_handler();
    let req = rpc(
        "tools/call",
        Some(serde_json::json!({"name": "echo", "arguments": {}})),
        Some(serde_json::json!(3)),
    );
    let resp = h.handle_request(&req).unwrap();
    assert!(resp.error.is_none());
    let result = resp.result.unwrap();
    assert_eq!(result["is_error"], false);
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("echoed"));
}

#[test]
fn handler_tools_call_proxy() {
    let h = make_handler();
    let req = rpc(
        "tools/call",
        Some(serde_json::json!({"name": "proxy_tool"})),
        Some(serde_json::json!(4)),
    );
    let resp = h.handle_request(&req).unwrap();
    assert!(resp.error.is_none());
    let text = resp.result.unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(text.contains("proxied to backend"));
}

#[test]
fn handler_tools_call_unknown_tool() {
    let h = make_handler();
    let req = rpc(
        "tools/call",
        Some(serde_json::json!({"name": "nope"})),
        Some(serde_json::json!(5)),
    );
    let resp = h.handle_request(&req).unwrap();
    assert!(resp.result.is_none());
    let err = resp.error.unwrap();
    assert_eq!(err.code, INVALID_PARAMS);
    assert!(err.message.contains("tool not found"));
}

#[test]
fn handler_tools_call_missing_name() {
    let h = make_handler();
    let req = rpc(
        "tools/call",
        Some(serde_json::json!({})),
        Some(serde_json::json!(6)),
    );
    let resp = h.handle_request(&req).unwrap();
    let err = resp.error.unwrap();
    assert_eq!(err.code, INVALID_PARAMS);
    assert!(err.message.contains("missing tool name"));
}

#[test]
fn handler_ping() {
    let h = make_handler();
    let req = rpc("ping", None, Some(serde_json::json!(7)));
    let resp = h.handle_request(&req).unwrap();
    assert_eq!(resp.result.unwrap(), "pong");
}

#[test]
fn handler_unknown_method() {
    let h = make_handler();
    let req = rpc("resources/list", None, Some(serde_json::json!(8)));
    let resp = h.handle_request(&req).unwrap();
    let err = resp.error.unwrap();
    assert_eq!(err.code, METHOD_NOT_FOUND);
}

#[test]
fn handler_notification_returns_none() {
    let h = make_handler();
    let req = rpc("notifications/initialized", None, None);
    assert!(h.handle_request(&req).is_none());
}
