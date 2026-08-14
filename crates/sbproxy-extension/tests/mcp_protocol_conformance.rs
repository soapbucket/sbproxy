use http::HeaderMap;
use sbproxy_extension::mcp::{
    JsonRpcRequest, Legacy2025_06_18Codec, McpImplementation, McpProtocolCodec, McpProtocolEra,
    McpServerDescription, Modern2026_07_28Codec,
};
use serde_json::{json, Value};

fn fixture(raw: &str) -> Value {
    serde_json::from_str(raw).expect("fixture is valid JSON")
}

fn modern_headers(method: &str, name: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert(
        "accept",
        "application/json, text/event-stream".parse().unwrap(),
    );
    headers.insert("mcp-protocol-version", "2026-07-28".parse().unwrap());
    headers.insert("mcp-method", method.parse().unwrap());
    if let Some(name) = name {
        headers.insert("mcp-name", name.parse().unwrap());
    }
    headers
}

fn modern_request(method: &str, params: Value) -> Value {
    let mut params = params.as_object().cloned().unwrap_or_default();
    params.insert(
        "_meta".into(),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {
                "name": "conformance-client",
                "version": "1.0.0"
            },
            "io.modelcontextprotocol/clientCapabilities": {}
        }),
    );
    json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
}

fn test_server_description() -> McpServerDescription {
    McpServerDescription {
        implementation: McpImplementation {
            name: "sbproxy-mcp".into(),
            version: "1.2.3".into(),
        },
        capabilities: sbproxy_extension::mcp::protocol::modern_server_capabilities(
            true, true, true,
        ),
        instructions: Some("Federated gateway".into()),
    }
}

#[test]
fn mcp_protocol_modern_discover_is_private_zero_ttl_and_truthful() {
    let server = McpServerDescription {
        implementation: McpImplementation {
            name: "sbproxy-mcp".into(),
            version: "1.2.3".into(),
        },
        capabilities: json!({
            "tools": {"listChanged": false},
            "resources": {"listChanged": false}
        }),
        instructions: Some("Federated gateway".into()),
    };
    let result = sbproxy_extension::mcp::protocol::build_discover_result(&server);
    assert_eq!(result["resultType"], "complete");
    assert_eq!(
        result["supportedVersions"],
        json!(["2026-07-28", "2025-06-18"])
    );
    assert_eq!(result["ttlMs"], 0);
    assert_eq!(result["cacheScope"], "private");
    assert_eq!(result["capabilities"]["tools"]["listChanged"], false);
    assert!(result["capabilities"].get("extensions").is_none());
    assert_eq!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "sbproxy-mcp"
    );
}

#[test]
fn mcp_protocol_modern_discovery_filters_unimplemented_capabilities() {
    let server = McpServerDescription {
        implementation: McpImplementation {
            name: "sbproxy-mcp".into(),
            version: "1.2.3".into(),
        },
        capabilities: json!({
            "tools": {"listChanged": true},
            "experimental": {"legacy": true},
            "mcpApps": {"ui": true},
            "extensions": {"subscriptions": true},
            "tasks": {"listChanged": true}
        }),
        instructions: None,
    };
    let result = sbproxy_extension::mcp::protocol::build_discover_result(&server);
    assert_eq!(
        result["capabilities"]["tools"],
        json!({"listChanged": false})
    );
    for capability in [
        "experimental",
        "mcpApps",
        "extensions",
        "tasks",
        "subscriptions",
    ] {
        assert!(
            result["capabilities"].get(capability).is_none(),
            "{capability} must not be advertised"
        );
    }
}

#[test]
fn mcp_protocol_modern_list_result_gets_required_cache_fields() {
    let response = Modern2026_07_28Codec
        .encode_success(
            "tools/list",
            Some(json!(9)),
            json!({"tools": []}),
            &test_server_description(),
        )
        .expect("encode");
    let result = response.body.unwrap().result.unwrap();
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["ttlMs"], 0);
    assert_eq!(result["cacheScope"], "private");
}

#[test]
fn mcp_protocol_modern_call_result_omits_list_cache_fields() {
    let response = Modern2026_07_28Codec
        .encode_success(
            "tools/call",
            Some(json!(13)),
            json!({"content": []}),
            &test_server_description(),
        )
        .expect("encode");
    let result = response.body.unwrap().result.unwrap();
    assert!(result.get("ttlMs").is_none());
    assert!(result.get("cacheScope").is_none());
}

#[test]
fn mcp_protocol_modern_preserves_result_fields_and_meta_when_shaping() {
    let response = Modern2026_07_28Codec
        .encode_success(
            "resources/read",
            Some(json!(12)),
            json!({
                "contents": [],
                "_meta": {"vendor.example/trace": "preserve"}
            }),
            &test_server_description(),
        )
        .expect("encode");
    let result = response.body.unwrap().result.unwrap();
    assert_eq!(result["contents"], json!([]));
    assert_eq!(result["_meta"]["vendor.example/trace"], "preserve");
    assert_eq!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"]["version"],
        "1.2.3"
    );
}

#[test]
fn mcp_protocol_modern_unknown_method_is_http_404() {
    let response = Modern2026_07_28Codec.encode_error(
        Some(json!(10)),
        -32601,
        "unknown MCP method: no/such",
        None,
    );
    assert_eq!(response.status, http::StatusCode::NOT_FOUND);
    assert_eq!(response.body.unwrap().error.unwrap().code, -32601);
}

#[test]
fn mcp_protocol_modern_refuses_unadvertised_input_required_result() {
    let error = Modern2026_07_28Codec
        .encode_success(
            "tools/call",
            Some(json!(11)),
            json!({"resultType": "input_required", "inputRequests": []}),
            &test_server_description(),
        )
        .expect_err("MRTR generation is not supported");
    assert_eq!(error.0.body.unwrap().error.unwrap().code, -32603);
}

#[test]
fn mcp_protocol_modern_maps_errors_and_notification_responses() {
    let cases = [
        (-32700, http::StatusCode::BAD_REQUEST),
        (-32600, http::StatusCode::BAD_REQUEST),
        (-32602, http::StatusCode::BAD_REQUEST),
        (-32020, http::StatusCode::BAD_REQUEST),
        (-32021, http::StatusCode::BAD_REQUEST),
        (-32022, http::StatusCode::BAD_REQUEST),
        (-32601, http::StatusCode::NOT_FOUND),
        (-32603, http::StatusCode::OK),
    ];
    for (code, status) in cases {
        let response = Modern2026_07_28Codec.encode_error(Some(json!(4)), code, "error", None);
        assert_eq!(response.status, status, "{code}");
    }

    let notification = Modern2026_07_28Codec
        .encode_success(
            "notifications/tools/list_changed",
            None,
            json!({}),
            &test_server_description(),
        )
        .expect("notification encode");
    assert_eq!(notification.status, http::StatusCode::ACCEPTED);
    assert!(notification.body.is_none());
}

#[test]
fn mcp_protocol_modern_recognizes_only_modern_protocol_errors() {
    let recognized =
        sbproxy_extension::mcp::JsonRpcResponse::error(Some(json!(1)), -32020, "mismatch");
    let unrelated =
        sbproxy_extension::mcp::JsonRpcResponse::error(Some(json!(1)), -32602, "invalid params");
    assert!(sbproxy_extension::mcp::protocol::is_recognized_modern_error(&recognized));
    assert!(!sbproxy_extension::mcp::protocol::is_recognized_modern_error(&unrelated));
}

#[test]
fn mcp_protocol_modern_rejects_missing_metadata_as_invalid_params() {
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}
    }))
    .unwrap();
    let error =
        sbproxy_extension::mcp::decode_http_request(&body, &modern_headers("tools/list", None))
            .expect_err("missing modern metadata");
    assert_eq!(error.0.status, http::StatusCode::BAD_REQUEST);
    assert_eq!(error.0.body.unwrap().error.unwrap().code, -32602);
}

#[test]
fn mcp_protocol_modern_returns_supported_versions_without_downgrading() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    let mut headers = modern_headers("tools/list", None);
    headers.insert("mcp-protocol-version", "1900-01-01".parse().unwrap());
    let error = sbproxy_extension::mcp::decode_http_request(&body, &headers)
        .expect_err("unsupported version");
    let response = error.0.body.unwrap();
    assert_eq!(response.error.as_ref().unwrap().code, -32020);
}

#[test]
fn mcp_protocol_modern_decodes_base64_sentinel_name() {
    let name = "weather/東京";
    let body = serde_json::to_vec(&modern_request(
        "tools/call",
        json!({"name": name, "arguments": {}}),
    ))
    .unwrap();
    let encoded = sbproxy_extension::mcp::protocol::encode_header_value(name);
    let decoded = sbproxy_extension::mcp::decode_http_request(
        &body,
        &modern_headers("tools/call", Some(&encoded)),
    )
    .expect("valid encoded name");
    assert_eq!(decoded.routing_headers.name.as_deref(), Some(name));
}

#[test]
fn mcp_protocol_modern_rejects_protocol_defined_failures() {
    struct Case {
        name: &'static str,
        body: Value,
        headers: HeaderMap,
        status: http::StatusCode,
        code: i32,
    }

    let base_body = modern_request("tools/call", json!({"name": "weather", "arguments": {}}));
    let base_headers = modern_headers("tools/call", Some("weather"));
    let mut missing_protocol_header = base_headers.clone();
    missing_protocol_header.remove("mcp-protocol-version");
    let mut protocol_header_body_mismatch = base_headers.clone();
    protocol_header_body_mismatch.insert("mcp-protocol-version", "1900-01-01".parse().unwrap());
    let mut missing_method = base_headers.clone();
    missing_method.remove("mcp-method");
    let mut method_body_mismatch = base_headers.clone();
    method_body_mismatch.insert("mcp-method", "resources/list".parse().unwrap());
    let mut missing_name = base_headers.clone();
    missing_name.remove("mcp-name");
    let mut malformed_sentinel = base_headers.clone();
    malformed_sentinel.insert("mcp-name", "=?base64?%%%?=".parse().unwrap());
    let mut missing_client_capabilities = base_body.clone();
    missing_client_capabilities["params"]["_meta"]
        .as_object_mut()
        .unwrap()
        .remove("io.modelcontextprotocol/clientCapabilities");
    let mut missing_protocol_version_metadata = base_body.clone();
    missing_protocol_version_metadata["params"]["_meta"]
        .as_object_mut()
        .unwrap()
        .remove("io.modelcontextprotocol/protocolVersion");
    let mut unsupported_modern_version = base_body.clone();
    unsupported_modern_version["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
        json!("1900-01-01");
    let mut unsupported_modern_headers = base_headers.clone();
    unsupported_modern_headers.insert("mcp-protocol-version", "1900-01-01".parse().unwrap());
    let mut boolean_request_id = base_body.clone();
    boolean_request_id["id"] = json!(true);
    let wrong_content_type = {
        let mut headers = base_headers.clone();
        headers.insert("content-type", "text/plain".parse().unwrap());
        headers
    };
    let accept_missing_event_stream = {
        let mut headers = base_headers.clone();
        headers.insert("accept", "application/json".parse().unwrap());
        headers
    };

    let cases = [
        Case {
            name: "missing protocol header",
            body: base_body.clone(),
            headers: missing_protocol_header,
            status: http::StatusCode::BAD_REQUEST,
            code: -32020,
        },
        Case {
            name: "protocol header/body mismatch",
            body: base_body.clone(),
            headers: protocol_header_body_mismatch,
            status: http::StatusCode::BAD_REQUEST,
            code: -32020,
        },
        Case {
            name: "missing Mcp-Method",
            body: base_body.clone(),
            headers: missing_method,
            status: http::StatusCode::BAD_REQUEST,
            code: -32020,
        },
        Case {
            name: "Mcp-Method/body mismatch",
            body: base_body.clone(),
            headers: method_body_mismatch,
            status: http::StatusCode::BAD_REQUEST,
            code: -32020,
        },
        Case {
            name: "missing Mcp-Name for tools/call",
            body: base_body.clone(),
            headers: missing_name,
            status: http::StatusCode::BAD_REQUEST,
            code: -32020,
        },
        Case {
            name: "malformed Base64 sentinel",
            body: base_body.clone(),
            headers: malformed_sentinel,
            status: http::StatusCode::BAD_REQUEST,
            code: -32020,
        },
        Case {
            name: "missing client capabilities",
            body: missing_client_capabilities,
            headers: base_headers.clone(),
            status: http::StatusCode::BAD_REQUEST,
            code: -32602,
        },
        Case {
            name: "missing protocol version metadata",
            body: missing_protocol_version_metadata,
            headers: base_headers.clone(),
            status: http::StatusCode::BAD_REQUEST,
            code: -32602,
        },
        Case {
            name: "unsupported modern version",
            body: unsupported_modern_version,
            headers: unsupported_modern_headers,
            status: http::StatusCode::BAD_REQUEST,
            code: -32022,
        },
        Case {
            name: "boolean request id",
            body: boolean_request_id,
            headers: base_headers.clone(),
            status: http::StatusCode::BAD_REQUEST,
            code: -32600,
        },
        Case {
            name: "top-level JSON array",
            body: json!([base_body.clone()]),
            headers: base_headers.clone(),
            status: http::StatusCode::BAD_REQUEST,
            code: -32600,
        },
        Case {
            name: "wrong content type",
            body: base_body.clone(),
            headers: wrong_content_type,
            status: http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            code: -32600,
        },
        Case {
            name: "Accept missing event-stream",
            body: base_body,
            headers: accept_missing_event_stream,
            status: http::StatusCode::NOT_ACCEPTABLE,
            code: -32600,
        },
    ];

    for case in cases {
        let body = serde_json::to_vec(&case.body).unwrap();
        let error =
            sbproxy_extension::mcp::decode_http_request(&body, &case.headers).expect_err(case.name);
        assert_eq!(error.0.status, case.status, "{}", case.name);
        assert_eq!(
            error.0.body.unwrap().error.unwrap().code,
            case.code,
            "{}",
            case.name
        );
    }
}

#[test]
fn mcp_protocol_modern_unsupported_version_returns_supported_versions() {
    let mut body = modern_request("tools/call", json!({"name": "weather", "arguments": {}}));
    body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("1900-01-01");
    let mut headers = modern_headers("tools/call", Some("weather"));
    headers.insert("mcp-protocol-version", "1900-01-01".parse().unwrap());

    let error =
        sbproxy_extension::mcp::decode_http_request(&serde_json::to_vec(&body).unwrap(), &headers)
            .expect_err("unsupported modern version");
    let response = error.0.body.unwrap();
    assert_eq!(response.error.as_ref().unwrap().code, -32022);
    assert_eq!(
        response.error.unwrap().data,
        Some(json!({
            "supported": ["2026-07-28", "2025-06-18"],
            "requested": "1900-01-01",
        }))
    );
}

#[test]
fn mcp_protocol_modern_rejects_duplicate_routing_headers() {
    let body = serde_json::to_vec(&modern_request(
        "tools/call",
        json!({"name": "weather", "arguments": {}}),
    ))
    .unwrap();
    let cases = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "weather"),
        ("Mcp-Param-Cursor", "next"),
    ];

    for (header, value) in cases {
        let mut headers = modern_headers("tools/call", Some("weather"));
        if header.eq_ignore_ascii_case("mcp-param-cursor") {
            headers.insert("mcp-param-cursor", "first".parse().unwrap());
        }
        headers.append(header, value.parse().unwrap());
        let error = sbproxy_extension::mcp::decode_http_request(&body, &headers)
            .expect_err("duplicate routing header is rejected");
        assert_eq!(error.0.status, http::StatusCode::BAD_REQUEST, "{header}");
        assert_eq!(
            error.0.body.unwrap().error.unwrap().code,
            -32020,
            "{header}"
        );
    }
}

#[test]
fn mcp_protocol_modern_preserves_uninterpreted_parameter_headers() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    let mut headers = modern_headers("tools/list", None);
    headers.insert("Mcp-Param-Cursor", "=?base64?bmV4dA==?=".parse().unwrap());

    let decoded = sbproxy_extension::mcp::decode_http_request(&body, &headers)
        .expect("valid modern parameter header");
    assert_eq!(
        decoded
            .routing_headers
            .params
            .get("mcp-param-cursor")
            .expect("normalized parameter header")
            .to_str()
            .expect("parameter header text"),
        "=?base64?bmV4dA==?="
    );
}

#[test]
fn mcp_protocol_modern_header_sentinels_preserve_failure_classes() {
    use sbproxy_extension::mcp::HeaderValueError;

    assert_eq!(
        sbproxy_extension::mcp::decode_header_value("=?base64?%%%?="),
        Err(HeaderValueError::InvalidSentinel)
    );
    assert_eq!(
        sbproxy_extension::mcp::decode_header_value("=?base64?//8=?="),
        Err(HeaderValueError::InvalidUtf8)
    );
    assert_eq!(
        sbproxy_extension::mcp::decode_header_value(" unsafe "),
        Err(HeaderValueError::UnsafePlainValue)
    );
}

#[test]
fn mcp_protocol_modern_validates_mcp_name_against_each_body_selector() {
    struct SelectorCase {
        method: &'static str,
        key: &'static str,
        value: &'static str,
        case_mismatch: &'static str,
        mismatch: &'static str,
    }

    let cases = [
        SelectorCase {
            method: "tools/call",
            key: "name",
            value: "weather",
            case_mismatch: "Weather",
            mismatch: "forecast",
        },
        SelectorCase {
            method: "prompts/get",
            key: "name",
            value: "summary",
            case_mismatch: "Summary",
            mismatch: "outline",
        },
        SelectorCase {
            method: "resources/read",
            key: "uri",
            value: "file:///workspace/readme.md",
            case_mismatch: "file:///workspace/README.md",
            mismatch: "file:///workspace/other.md",
        },
    ];

    for case in cases {
        let body = modern_request(
            case.method,
            selector_params(case.key, Value::String(case.value.to_string())),
        );
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let decoded = sbproxy_extension::mcp::decode_http_request(
            &body_bytes,
            &modern_headers(case.method, Some(case.value)),
        )
        .expect("matching selector is valid");
        assert_eq!(decoded.routing_headers.name.as_deref(), Some(case.value));

        let mut missing_header = modern_headers(case.method, Some(case.value));
        missing_header.remove("mcp-name");
        assert_modern_header_mismatch(
            sbproxy_extension::mcp::decode_http_request(&body_bytes, &missing_header),
            "missing selector header",
        );

        assert_modern_header_mismatch(
            sbproxy_extension::mcp::decode_http_request(
                &body_bytes,
                &modern_headers(case.method, Some(case.mismatch)),
            ),
            "mismatched selector header",
        );
        assert_modern_header_mismatch(
            sbproxy_extension::mcp::decode_http_request(
                &body_bytes,
                &modern_headers(case.method, Some(case.case_mismatch)),
            ),
            "case-mismatched selector header",
        );

        let missing_selector = modern_request(case.method, json!({}));
        assert_modern_header_mismatch(
            sbproxy_extension::mcp::decode_http_request(
                &serde_json::to_vec(&missing_selector).unwrap(),
                &modern_headers(case.method, Some(case.value)),
            ),
            "missing selector body value",
        );
        let non_string_selector =
            modern_request(case.method, selector_params(case.key, json!(true)));
        assert_modern_header_mismatch(
            sbproxy_extension::mcp::decode_http_request(
                &serde_json::to_vec(&non_string_selector).unwrap(),
                &modern_headers(case.method, Some(case.value)),
            ),
            "non-string selector body value",
        );
    }
}

#[test]
fn mcp_protocol_modern_accepts_explicit_null_request_ids() {
    let mut body = modern_request("tools/list", json!({}));
    body["id"] = Value::Null;
    let decoded = sbproxy_extension::mcp::decode_http_request(
        &serde_json::to_vec(&body).unwrap(),
        &modern_headers("tools/list", None),
    )
    .expect("explicit null JSON-RPC id is valid");
    assert!(decoded.request.id.is_none());
}

fn selector_params(key: &str, value: Value) -> Value {
    let mut params = serde_json::Map::new();
    params.insert(key.to_string(), value);
    Value::Object(params)
}

fn assert_modern_header_mismatch(
    result: Result<sbproxy_extension::mcp::DecodedMcpRequest, sbproxy_extension::mcp::McpWireError>,
    context: &str,
) {
    let error = result.expect_err(context);
    assert_eq!(error.0.status, http::StatusCode::BAD_REQUEST, "{context}");
    assert_eq!(
        error.0.body.unwrap().error.unwrap().code,
        -32020,
        "{context}"
    );
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
