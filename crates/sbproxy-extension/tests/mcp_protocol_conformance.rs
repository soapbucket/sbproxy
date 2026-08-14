use http::HeaderMap;
use sbproxy_extension::mcp::{
    JsonRpcRequest, Legacy2025_06_18Codec, McpImplementation, McpProtocolCodec, McpProtocolEra,
    McpServerDescription,
};
use serde_json::{json, Value};

fn fixture(raw: &str) -> Value {
    serde_json::from_str(raw).expect("fixture is valid JSON")
}

#[test]
fn mcp_protocol_legacy_initialize_request_round_trips_exactly() {
    let raw = include_str!("fixtures/mcp/legacy-initialize-request.json").trim();
    let request: JsonRpcRequest = serde_json::from_str(raw).expect("legacy request");
    assert_eq!(serde_json::to_string(&request).expect("encode"), raw);

    let decoded = Legacy2025_06_18Codec
        .decode_http(request, &HeaderMap::new())
        .expect("legacy decode");
    assert_eq!(decoded.context.era, McpProtocolEra::Legacy2025_06_18);
    assert_eq!(decoded.context.protocol_version, "2025-06-18");
}

#[test]
fn mcp_protocol_legacy_post_initialize_allows_missing_protocol_header() {
    let decoded = Legacy2025_06_18Codec
        .decode_http(
            JsonRpcRequest {
                jsonrpc: "2.0".into(),
                method: "tools/list".into(),
                params: None,
                id: Some(json!(2)),
            },
            &HeaderMap::new(),
        )
        .expect("missing protocol header remains valid");
    assert_eq!(decoded.context.era, McpProtocolEra::Legacy2025_06_18);
}

#[test]
fn mcp_protocol_legacy_rejects_unsupported_post_initialize_protocol_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "mcp-protocol-version",
        http::HeaderValue::from_static("2026-07-28"),
    );
    let error = Legacy2025_06_18Codec
        .decode_http(
            JsonRpcRequest {
                jsonrpc: "2.0".into(),
                method: "tools/list".into(),
                params: None,
                id: Some(json!(2)),
            },
            &headers,
        )
        .expect_err("unsupported legacy header is rejected");
    assert_eq!(error.0.status, http::StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::to_value(error.0.body.expect("error body")).expect("error value"),
        json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32602,
                "message": "unsupported MCP-Protocol-Version '2026-07-28' (supported: 2025-06-18)",
            },
            "id": 2,
        }),
    );
}

#[test]
fn mcp_protocol_legacy_encoder_does_not_add_modern_fields() {
    let server = McpServerDescription {
        implementation: McpImplementation {
            name: "golden-server".into(),
            version: "1.0.0".into(),
        },
        capabilities: json!({"tools": {"listChanged": true}}),
        instructions: None,
    };
    let response = Legacy2025_06_18Codec
        .encode_success(
            "initialize",
            Some(json!(1)),
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": server.capabilities,
                "serverInfo": server.implementation,
            }),
            &server,
        )
        .expect("legacy encode");
    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(
        serde_json::to_value(response.body.expect("body")).expect("value"),
        fixture(include_str!("fixtures/mcp/legacy-initialize-response.json")),
    );
}

#[test]
fn mcp_protocol_legacy_error_stays_http_200() {
    let response = Legacy2025_06_18Codec.encode_error(
        Some(json!(3)),
        -32601,
        "unknown MCP method: no/such",
        None,
    );
    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(
        serde_json::to_value(response.body.expect("body")).expect("value"),
        fixture(include_str!("fixtures/mcp/legacy-error-response.json")),
    );
}

#[test]
fn mcp_protocol_legacy_response_fixtures_are_exact_serializer_goldens() {
    for raw in [
        include_str!("fixtures/mcp/legacy-initialize-response.json").trim(),
        include_str!("fixtures/mcp/legacy-tools-list-response.json").trim(),
        include_str!("fixtures/mcp/legacy-error-response.json").trim(),
    ] {
        let response: sbproxy_extension::mcp::JsonRpcResponse =
            serde_json::from_str(raw).expect("legacy response");
        assert_eq!(serde_json::to_string(&response).expect("encode"), raw);
    }
}
