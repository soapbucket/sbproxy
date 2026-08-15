use http::HeaderMap;
use sbproxy_extension::mcp::{
    JsonRpcRequest, Legacy2025_06_18Codec, McpImplementation, McpInteger, McpProtocolCodec,
    McpProtocolEra, McpServerDescription, Modern2026_07_28Codec, ModernJsonRpcResponse,
    ModernRequestId, ModernRequestIdError,
};
use serde_json::{json, Value};

use sbproxy_extension::mcp::protocol::{
    build_mirrored_headers, classify_http_era, compile_modern_tool_contract,
    validate_mirrored_headers, McpContractError, McpModernToolResultDocument, McpSchemaLimits,
    McpToolContract, McpToolResultDocument, RawModernScan, RawModernScanLimit,
};

fn fixture(raw: &str) -> Value {
    serde_json::from_str(raw).expect("fixture is valid JSON")
}

fn wire_body_value<T: serde::Serialize>(body: Option<T>) -> Value {
    serde_json::to_value(body.expect("wire response body")).expect("serialize wire response body")
}

fn modern_integer_id(value: u64) -> ModernRequestId {
    ModernRequestId::Integer(McpInteger::Unsigned(value))
}

fn modern_request_with_raw_id(raw_id: &str) -> Vec<u8> {
    format!(
        r#"{{"jsonrpc":"2.0","id":{raw_id},"method":"tools/list","params":{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{{"name":"conformance-client","version":"1.0.0"}},"io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#
    )
    .into_bytes()
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

fn contract_with_schema(input_schema: serde_json::Value) -> McpToolContract {
    McpToolContract::try_from(serde_json::json!({
        "name": "fixture.tool",
        "description": "schema fixture",
        "inputSchema": input_schema,
    }))
    .expect("fixture tool contract")
}

fn schema_with_exact_serialized_bytes(bytes: usize) -> Value {
    let mut schema = json!({"type": "object", "description": ""});
    let fixed_bytes = serde_json::to_vec(&schema).unwrap().len();
    assert!(bytes >= fixed_bytes);
    schema["description"] = Value::String("x".repeat(bytes - fixed_bytes));
    assert_eq!(serde_json::to_vec(&schema).unwrap().len(), bytes);
    schema
}

fn schema_with_property_entries(count: usize) -> Value {
    let properties = (0..count)
        .map(|index| (format!("property_{index}"), Value::Bool(true)))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "type": "object",
        "properties": properties,
        "examples": [null]
    })
}

fn schema_with_definitions(count: usize) -> Value {
    let definitions = (0..count)
        .map(|index| (format!("definition_{index}"), Value::Bool(true)))
        .collect::<serde_json::Map<_, _>>();
    json!({"type": "object", "$defs": definitions})
}

fn schema_with_pattern_property_keys(lengths: &[usize]) -> Value {
    let pattern_properties = lengths
        .iter()
        .enumerate()
        .map(|(index, length)| {
            assert!(*length > 0);
            let suffix = char::from(b'a' + u8::try_from(index).unwrap());
            (
                format!("{}{}", "x".repeat(length - 1), suffix),
                Value::Bool(true),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    json!({"type": "object", "patternProperties": pattern_properties})
}

fn schema_with_header_projections(count: usize) -> Value {
    let properties = (0..count)
        .map(|index| {
            (
                format!("field_{index}"),
                json!({"type": "string", "x-mcp-header": format!("Field-{index}")}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    json!({"type": "object", "properties": properties})
}

fn schema_with_property_chain_depth(depth: usize) -> Value {
    assert!(matches!(depth, 32 | 33));
    // With root depth one, 15 property-map and property-schema pairs place
    // this leaf at depth 31. Its `type` string is depth 32; the optional
    // examples null is then depth 33.
    let mut leaf = json!({"type": "string"});
    if depth == 33 {
        leaf["examples"] = json!([null]);
    }
    for _ in 0..15 {
        leaf = json!({
            "type": "object",
            "properties": {"next": leaf}
        });
    }
    leaf
}

#[test]
fn mcp_protocol_contract_round_trip_preserves_every_field() {
    let raw = json!({
        "name": "weather",
        "title": "Weather",
        "description": "Forecast",
        "icons": [{"src": "data:image/png;base64,AA==", "mimeType": "image/png"}],
        "inputSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "$defs": {"city": {"type": "string"}},
            "properties": {"city": {"$ref": "#/$defs/city"}},
            "unevaluatedProperties": false
        },
        "outputSchema": {"prefixItems": [{"type": "string"}]},
        "annotations": {"readOnlyHint": true, "destructiveHint": false},
        "_meta": {"vendor.example/ui": "card"},
        "vendor.example/security": {"audience": "weather-api"}
    });
    let contract = McpToolContract::try_from(raw.clone()).expect("contract");
    assert_eq!(contract.as_value(), raw);
    assert_eq!(serde_json::to_value(&contract).expect("serialize"), raw);
    let decoded: McpToolContract = serde_json::from_value(raw.clone()).expect("deserialize");
    assert_eq!(decoded.as_value(), raw);

    let advertised = contract.with_advertised_name("gateway.weather");
    let mut expected = raw.clone();
    expected["name"] = json!("gateway.weather");
    assert_eq!(advertised.as_value(), expected);
    assert_eq!(contract.as_value(), raw);
}

#[test]
fn mcp_protocol_tool_result_round_trip_preserves_all_channels() {
    let raw = json!({
        "content": [
            {"type": "text", "text": "ok", "annotations": {"audience": ["assistant"]}},
            {"type": "audio", "data": "AA==", "mimeType": "audio/wav"},
            {"type": "resource_link", "uri": "file:///safe", "name": "safe"},
            {"type": "resource", "resource": {"uri": "file:///x", "text": "x"}}
        ],
        "structuredContent": [1, {"ok": true}],
        "isError": false,
        "_meta": {"vendor.example/result": 1}
    });
    let result = McpToolResultDocument::try_from(raw.clone()).expect("result");
    assert_eq!(result.clone().into_value(), raw);
    assert_eq!(serde_json::to_value(&result).expect("serialize"), raw);
    let decoded: McpToolResultDocument = serde_json::from_value(raw.clone()).expect("deserialize");
    assert_eq!(decoded.into_value(), raw);
}

#[test]
fn mcp_protocol_modern_tool_result_rejects_invalid_envelope_before_post_processing() {
    for invalid in [
        json!({"content": [], "_meta": "private-upstream-detail"}),
        json!({"content": [], "resultType": "input_required"}),
        json!({"content": [], "resultType": 1}),
    ] {
        assert!(
            McpModernToolResultDocument::try_from(invalid).is_err(),
            "an invalid modern result envelope reached post-processing"
        );
    }

    for valid in [
        json!({"content": []}),
        json!({"content": [], "_meta": {}}),
        json!({"content": [], "resultType": "complete"}),
    ] {
        McpModernToolResultDocument::try_from(valid).expect("valid modern result envelope");
    }

    let normalized = McpModernToolResultDocument::try_from(json!({"content": []}))
        .expect("normalize modern result")
        .into_value();
    assert_eq!(normalized["resultType"], "complete");
    assert_eq!(normalized["_meta"], json!({}));
}

#[test]
fn mcp_protocol_schema_accepts_2020_12_and_local_refs() {
    let contract = contract_with_schema(json!({
        "type": "object",
        "$defs": {"label": {"type": "string", "minLength": 1}},
        "properties": {"labels": {"type": "array", "prefixItems": [{"$ref": "#/$defs/label"}]}},
        "unevaluatedProperties": false
    }));
    let compiled = compile_modern_tool_contract(&contract, McpSchemaLimits::default())
        .expect("valid 2020-12 contract");
    assert!(compiled.input.is_valid(&json!({"labels": ["safe"]})));
}

#[test]
fn mcp_protocol_schema_accepts_only_the_supported_dialects() {
    for dialect in [
        "http://json-schema.org/draft-04/schema#",
        "http://json-schema.org/draft-06/schema#",
        "http://json-schema.org/draft-07/schema#",
        "https://json-schema.org/draft/2019-09/schema",
        "https://json-schema.org/draft/2020-12/schema",
    ] {
        let contract = contract_with_schema(json!({
            "$schema": dialect,
            "type": "object",
            "properties": {"region": {"type": "string"}}
        }));
        compile_modern_tool_contract(&contract, McpSchemaLimits::default())
            .unwrap_or_else(|error| panic!("{dialect} should compile: {error}"));
    }

    for dialect in [
        json!("https://json-schema.org/draft/2020-12/schema#"),
        json!(false),
    ] {
        let contract = contract_with_schema(json!({
            "$schema": dialect,
            "type": "object"
        }));
        assert!(matches!(
            compile_modern_tool_contract(&contract, McpSchemaLimits::default()),
            Err(McpContractError::UnsupportedSchemaDialect(_))
        ));
    }
}

#[test]
fn mcp_protocol_schema_rejects_non_object_input_schemas() {
    assert!(matches!(
        McpToolContract::try_from(json!({
            "name": "fixture.tool",
            "inputSchema": []
        })),
        Err(McpContractError::MissingObjectField("inputSchema"))
    ));

    let contract = contract_with_schema(json!({"type": "string"}));
    assert!(matches!(
        compile_modern_tool_contract(&contract, McpSchemaLimits::default()),
        Err(McpContractError::InvalidSchema(_))
    ));
}

#[test]
fn mcp_protocol_schema_enforces_serialized_byte_limit_at_boundary() {
    let limits = McpSchemaLimits::default();
    let exact = contract_with_schema(schema_with_exact_serialized_bytes(limits.max_bytes));
    compile_modern_tool_contract(&exact, limits).expect("exact byte limit is accepted");

    let one_over = contract_with_schema(schema_with_exact_serialized_bytes(limits.max_bytes + 1));
    assert!(matches!(
        compile_modern_tool_contract(&one_over, limits),
        Err(McpContractError::LimitExceeded {
            limit: "bytes",
            actual,
            maximum,
        }) if actual == limits.max_bytes + 1 && maximum == limits.max_bytes
    ));
}

#[test]
fn mcp_protocol_schema_enforces_node_limit_at_boundary() {
    let limits = McpSchemaLimits::default();
    // Root, type, properties map, examples array, and examples null are five values.
    let exact = contract_with_schema(schema_with_property_entries(limits.max_nodes - 5));
    compile_modern_tool_contract(&exact, limits).expect("exact node limit is accepted");

    let one_over = contract_with_schema(schema_with_property_entries(limits.max_nodes - 4));
    assert!(matches!(
        compile_modern_tool_contract(&one_over, limits),
        Err(McpContractError::LimitExceeded {
            limit: "nodes",
            actual,
            maximum,
        }) if actual == limits.max_nodes + 1 && maximum == limits.max_nodes
    ));
}

#[test]
fn mcp_protocol_schema_enforces_subschema_limit_at_boundary() {
    let limits = McpSchemaLimits::default();
    let exact = contract_with_schema(schema_with_definitions(limits.max_subschemas));
    compile_modern_tool_contract(&exact, limits).expect("exact subschema limit is accepted");

    let one_over = contract_with_schema(schema_with_definitions(limits.max_subschemas + 1));
    assert!(matches!(
        compile_modern_tool_contract(&one_over, limits),
        Err(McpContractError::LimitExceeded {
            limit: "subschemas",
            actual,
            maximum,
        }) if actual == limits.max_subschemas + 1 && maximum == limits.max_subschemas
    ));
}

#[test]
fn mcp_protocol_schema_enforces_per_pattern_byte_limit_at_boundary() {
    let limits = McpSchemaLimits::default();
    let exact = contract_with_schema(json!({
        "type": "object",
        "pattern": "x".repeat(limits.max_pattern_bytes)
    }));
    compile_modern_tool_contract(&exact, limits).expect("exact pattern limit is accepted");

    let one_over = contract_with_schema(json!({
        "type": "object",
        "pattern": "x".repeat(limits.max_pattern_bytes + 1)
    }));
    assert!(matches!(
        compile_modern_tool_contract(&one_over, limits),
        Err(McpContractError::LimitExceeded {
            limit: "pattern_bytes",
            actual,
            maximum,
        }) if actual == limits.max_pattern_bytes + 1 && maximum == limits.max_pattern_bytes
    ));
}

#[test]
fn mcp_protocol_schema_evaluates_a_nested_quantifier_in_linear_time() {
    // The byte caps bound how large an upstream pattern may be, never how long
    // it may run. A federated upstream is untrusted, so a nested quantifier in
    // `patternProperties` is evaluated against every key of a client-supplied
    // object, and `patternProperties` does not short-circuit on a non-matching
    // key. On a backtracking engine each of these keys burns the full
    // backtrack budget, so one request pins a worker for tens of seconds.
    // Compiling on the linear engine removes the backtracking entirely.
    let limits = McpSchemaLimits::default();
    let catastrophic = contract_with_schema(json!({
        "type": "object",
        "patternProperties": {"(a+)+$": {}}
    }));
    let compiled = compile_modern_tool_contract(&catastrophic, limits)
        .expect("a nested quantifier still compiles on the linear engine");

    // Every key matches the prefix and then fails at the anchor, which is the
    // worst case for a backtracking matcher.
    let hostile: serde_json::Map<String, Value> = (0..2_000)
        .map(|index| (format!("{}X{index}", "a".repeat(40)), json!(true)))
        .collect();

    let started = std::time::Instant::now();
    let _ = compiled.input.is_valid(&Value::Object(hostile));
    let elapsed = started.elapsed();

    // A backtracking engine needs roughly a million steps per key here, so it
    // runs for minutes. The linear engine finishes in milliseconds; the bound
    // is deliberately loose so only an engine regression trips it.
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "nested-quantifier validation took {elapsed:?}, which means backtracking is back"
    );
}

#[test]
fn mcp_protocol_schema_enforces_total_pattern_byte_limit_at_boundary() {
    let limits = McpSchemaLimits::default();
    let exact = contract_with_schema(schema_with_pattern_property_keys(&[
        limits.max_pattern_bytes,
        limits.max_pattern_bytes,
        limits.max_pattern_bytes,
        limits.max_pattern_bytes,
    ]));
    compile_modern_tool_contract(&exact, limits).expect("exact total pattern limit is accepted");

    let one_over = contract_with_schema(schema_with_pattern_property_keys(&[
        limits.max_pattern_bytes,
        limits.max_pattern_bytes,
        limits.max_pattern_bytes,
        limits.max_pattern_bytes,
        1,
    ]));
    assert!(matches!(
        compile_modern_tool_contract(&one_over, limits),
        Err(McpContractError::LimitExceeded {
            limit: "total_pattern_bytes",
            actual,
            maximum,
        }) if actual == limits.max_total_pattern_bytes + 1 && maximum == limits.max_total_pattern_bytes
    ));
}

#[test]
fn mcp_protocol_schema_enforces_depth_limit_at_boundary() {
    let limits = McpSchemaLimits::default();
    let exact = contract_with_schema(schema_with_property_chain_depth(limits.max_depth));
    compile_modern_tool_contract(&exact, limits).expect("root-depth 32 is accepted");

    let one_over = contract_with_schema(schema_with_property_chain_depth(limits.max_depth + 1));
    assert!(matches!(
        compile_modern_tool_contract(&one_over, limits),
        Err(McpContractError::LimitExceeded {
            limit: "depth",
            actual,
            maximum,
        }) if actual == limits.max_depth + 1 && maximum == limits.max_depth
    ));
}

#[test]
fn mcp_protocol_schema_rejects_external_refs_and_complexity() {
    let external = contract_with_schema(json!({
        "type": "object",
        "properties": {"x": {"$ref": "https://attacker.test/schema.json"}}
    }));
    assert!(matches!(
        compile_modern_tool_contract(&external, McpSchemaLimits::default()),
        Err(McpContractError::ExternalReference { .. })
    ));

    let dynamic = contract_with_schema(json!({
        "type": "object",
        "properties": {"x": {"$dynamicRef": "https://attacker.test/schema.json"}}
    }));
    assert!(matches!(
        compile_modern_tool_contract(&dynamic, McpSchemaLimits::default()),
        Err(McpContractError::ExternalReference {
            keyword: "$dynamicRef",
            ..
        })
    ));

    let deep = contract_with_schema((0..34).fold(
        json!({"type": "string"}),
        |inner, _| json!({"type": "object", "properties": {"x": inner}}),
    ));
    assert!(matches!(
        compile_modern_tool_contract(&deep, McpSchemaLimits::default()),
        Err(McpContractError::LimitExceeded { limit: "depth", .. })
    ));
}

#[test]
fn mcp_protocol_header_projection_enforces_nested_primitive_values() {
    let contract = contract_with_schema(json!({
        "type": "object",
        "properties": {
            "routing": {
                "type": "object",
                "properties": {
                    "region": {"type": "string", "x-mcp-header": "Region"},
                    "retries": {"type": "integer", "x-mcp-header": "Retries"},
                    "dry_run": {"type": "boolean", "x-mcp-header": "Dry-Run"}
                }
            }
        }
    }));
    let compiled = compile_modern_tool_contract(&contract, McpSchemaLimits::default()).unwrap();
    let args = json!({"routing": {"region": "東京", "retries": 2, "dry_run": true}});
    let headers = build_mirrored_headers(&compiled.header_projections, &args).unwrap();
    validate_mirrored_headers(&headers, &compiled.header_projections, &args).unwrap();
    assert!(headers["mcp-param-region"]
        .to_str()
        .unwrap()
        .starts_with("=?base64?"));
}

#[test]
fn mcp_protocol_schema_rejects_unreachable_or_invalid_header_projections() {
    let unreachable = [
        json!({
            "type": "object",
            "properties": {"items": {"type": "array", "items": {"type": "string", "x-mcp-header": "Item"}}}
        }),
        json!({
            "type": "object",
            "oneOf": [{"properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}]
        }),
        json!({
            "type": "object",
            "$defs": {"route": {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}}},
            "properties": {"routing": {"$ref": "#/$defs/route"}}
        }),
    ];
    for schema in unreachable {
        let contract = contract_with_schema(schema);
        let result = compile_modern_tool_contract(&contract, McpSchemaLimits::default());
        assert!(
            matches!(
                &result,
                Err(McpContractError::UnreachableHeaderProjection(_))
            ),
            "unexpected result: {result:?}"
        );
    }

    let duplicate = contract_with_schema(json!({
        "type": "object",
        "properties": {
            "a": {"type": "string", "x-mcp-header": "Region"},
            "b": {"type": "string", "x-mcp-header": "region"}
        }
    }));
    assert!(matches!(
        compile_modern_tool_contract(&duplicate, McpSchemaLimits::default()),
        Err(McpContractError::DuplicateHeaderProjection(_))
    ));

    let number = contract_with_schema(json!({
        "type": "object",
        "properties": {"ratio": {"type": "number", "x-mcp-header": "Ratio"}}
    }));
    assert!(matches!(
        compile_modern_tool_contract(&number, McpSchemaLimits::default()),
        Err(McpContractError::UnsupportedHeaderValueKind { .. })
    ));

    let token = contract_with_schema(json!({
        "type": "object",
        "properties": {"region": {"type": "string", "x-mcp-header": "bad header"}}
    }));
    assert!(matches!(
        compile_modern_tool_contract(&token, McpSchemaLimits::default()),
        Err(McpContractError::InvalidHeaderName(_))
    ));
}

#[test]
fn mcp_protocol_schema_enforces_header_projection_limit_at_boundary() {
    let limits = McpSchemaLimits::default();
    let exact = contract_with_schema(schema_with_header_projections(
        limits.max_header_projections,
    ));
    let compiled = compile_modern_tool_contract(&exact, limits).expect("exact projection limit");
    assert_eq!(
        compiled.header_projections.len(),
        limits.max_header_projections
    );

    let contract = contract_with_schema(schema_with_header_projections(
        limits.max_header_projections + 1,
    ));
    assert!(matches!(
        compile_modern_tool_contract(&contract, limits),
        Err(McpContractError::LimitExceeded {
            limit: "header_projections",
            actual,
            maximum,
        }) if actual == limits.max_header_projections + 1 && maximum == limits.max_header_projections
    ));
}

#[test]
fn mcp_protocol_header_projection_rejects_missing_mismatched_and_null_values() {
    let contract = contract_with_schema(json!({
        "type": "object",
        "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}
    }));
    let compiled = compile_modern_tool_contract(&contract, McpSchemaLimits::default()).unwrap();
    let args = json!({"region": "east"});
    assert!(matches!(
        validate_mirrored_headers(&HeaderMap::new(), &compiled.header_projections, &args),
        Err(McpContractError::MissingMirroredHeader(_))
    ));

    let mut mismatch = build_mirrored_headers(&compiled.header_projections, &args).unwrap();
    mismatch.insert("mcp-param-region", "west".parse().unwrap());
    assert!(matches!(
        validate_mirrored_headers(&mismatch, &compiled.header_projections, &args),
        Err(McpContractError::MirroredHeaderMismatch(_))
    ));

    let mut unexpected = HeaderMap::new();
    unexpected.insert("mcp-param-region", "east".parse().unwrap());
    assert!(matches!(
        validate_mirrored_headers(
            &unexpected,
            &compiled.header_projections,
            &json!({"region": null})
        ),
        Err(McpContractError::UnexpectedMirroredHeader(_))
    ));
}

#[test]
fn mcp_protocol_header_projection_rejects_header_for_absent_body_property() {
    let contract = contract_with_schema(json!({
        "type": "object",
        "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}
    }));
    let compiled = compile_modern_tool_contract(&contract, McpSchemaLimits::default()).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("mcp-param-region", "east".parse().unwrap());

    assert!(matches!(
        validate_mirrored_headers(&headers, &compiled.header_projections, &json!({})),
        Err(McpContractError::UnexpectedMirroredHeader(_))
    ));
}

#[test]
fn mcp_protocol_header_projection_rejects_uppercase_boolean_values() {
    let contract = contract_with_schema(json!({
        "type": "object",
        "properties": {"dry_run": {"type": "boolean", "x-mcp-header": "Dry-Run"}}
    }));
    let compiled = compile_modern_tool_contract(&contract, McpSchemaLimits::default()).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("mcp-param-dry-run", "TRUE".parse().unwrap());

    assert!(matches!(
        validate_mirrored_headers(
            &headers,
            &compiled.header_projections,
            &json!({"dry_run": true})
        ),
        Err(McpContractError::MirroredHeaderMismatch(_))
    ));
}

#[test]
fn mcp_protocol_header_projection_rejects_unsafe_integer_values() {
    let contract = contract_with_schema(json!({
        "type": "object",
        "properties": {"retries": {"type": "integer", "x-mcp-header": "Retries"}}
    }));
    let compiled = compile_modern_tool_contract(&contract, McpSchemaLimits::default()).unwrap();
    let args = json!({"retries": 9_007_199_254_740_992u64});

    assert!(matches!(
        build_mirrored_headers(&compiled.header_projections, &args),
        Err(McpContractError::UnsafeProjectedInteger(_))
    ));

    let mut headers = HeaderMap::new();
    headers.insert("mcp-param-retries", "9007199254740992".parse().unwrap());
    assert!(matches!(
        validate_mirrored_headers(&headers, &compiled.header_projections, &args),
        Err(McpContractError::UnsafeProjectedInteger(_))
    ));
}

#[test]
fn mcp_protocol_header_projection_compares_integral_numbers_numerically() {
    let contract = contract_with_schema(json!({
        "type": "object",
        "properties": {"retries": {"type": "integer", "x-mcp-header": "Retries"}}
    }));
    let compiled = compile_modern_tool_contract(&contract, McpSchemaLimits::default()).unwrap();
    let args = json!({"retries": 2.0});
    let headers = build_mirrored_headers(&compiled.header_projections, &args).unwrap();

    assert_eq!(headers["mcp-param-retries"], "2");
    validate_mirrored_headers(&headers, &compiled.header_projections, &args).unwrap();

    let integer_body = json!({"retries": 42});
    for header in ["42.0", "420e-1", "0.42e2", "42.000E+0"] {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-param-retries", header.parse().unwrap());
        validate_mirrored_headers(&headers, &compiled.header_projections, &integer_body)
            .unwrap_or_else(|_| panic!("mathematically integral header rejected: {header}"));
    }

    let zero_body = json!({"retries": 0});
    for header in ["-0", "-0.000", "-0e9"] {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-param-retries", header.parse().unwrap());
        validate_mirrored_headers(&headers, &compiled.header_projections, &zero_body)
            .unwrap_or_else(|_| panic!("signed zero header rejected: {header}"));
    }
}

#[test]
fn mcp_protocol_header_projection_rejects_inexact_or_unbounded_number_lexemes() {
    let contract = contract_with_schema(json!({
        "type": "object",
        "properties": {"retries": {"type": "integer", "x-mcp-header": "Retries"}}
    }));
    let compiled = compile_modern_tool_contract(&contract, McpSchemaLimits::default()).unwrap();
    let args = json!({"retries": 42});

    for header in [
        "42.0000000000000000000001",
        "1.5",
        "42x",
        "NaN",
        "Infinity",
        "9007199254740992",
        "1e999999",
        "0e999999",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert("mcp-param-retries", header.parse().unwrap());
        assert!(
            validate_mirrored_headers(&headers, &compiled.header_projections, &args).is_err(),
            "invalid numeric header accepted: {header}"
        );
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        "mcp-param-retries",
        format!("42{}", "0".repeat(127)).parse().unwrap(),
    );
    assert!(validate_mirrored_headers(&headers, &compiled.header_projections, &args).is_err());
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
            modern_integer_id(9),
            json!({"tools": []}),
            &test_server_description(),
        )
        .expect("encode");
    let body = wire_body_value(response.body);
    let result = &body["result"];
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["ttlMs"], 0);
    assert_eq!(result["cacheScope"], "private");
}

#[test]
fn mcp_protocol_modern_call_result_omits_list_cache_fields() {
    let response = Modern2026_07_28Codec
        .encode_success(
            "tools/call",
            modern_integer_id(13),
            json!({"content": []}),
            &test_server_description(),
        )
        .expect("encode");
    let body = wire_body_value(response.body);
    let result = &body["result"];
    assert!(result.get("ttlMs").is_none());
    assert!(result.get("cacheScope").is_none());
}

#[test]
fn mcp_protocol_modern_preserves_result_fields_and_meta_when_shaping() {
    let response = Modern2026_07_28Codec
        .encode_success(
            "resources/read",
            modern_integer_id(12),
            json!({
                "contents": [],
                "_meta": {"vendor.example/trace": "preserve"}
            }),
            &test_server_description(),
        )
        .expect("encode");
    let body = wire_body_value(response.body);
    let result = &body["result"];
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
        modern_integer_id(10),
        -32601,
        "unknown MCP method: no/such",
        None,
    );
    assert_eq!(response.status, http::StatusCode::NOT_FOUND);
    assert_eq!(wire_body_value(response.body)["error"]["code"], -32601);
}

#[test]
fn mcp_protocol_modern_refuses_unadvertised_input_required_result() {
    let error = Modern2026_07_28Codec
        .encode_success(
            "tools/call",
            modern_integer_id(11),
            json!({"resultType": "input_required", "inputRequests": []}),
            &test_server_description(),
        )
        .expect_err("MRTR generation is not supported");
    assert_eq!(wire_body_value(error.0.body)["error"]["code"], -32603);
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
        let response =
            Modern2026_07_28Codec.encode_error(modern_integer_id(4), code, "error", None);
        assert_eq!(response.status, status, "{code}");
    }

    let notification = Modern2026_07_28Codec
        .encode_success(
            "notifications/tools/list_changed",
            ModernRequestId::Absent,
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
    assert_eq!(wire_body_value(error.0.body)["error"]["code"], -32602);
}

#[test]
fn mcp_protocol_modern_returns_supported_versions_without_downgrading() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    let mut headers = modern_headers("tools/list", None);
    headers.insert("mcp-protocol-version", "1900-01-01".parse().unwrap());
    let error = sbproxy_extension::mcp::decode_http_request(&body, &headers)
        .expect_err("unsupported version");
    let response = wire_body_value(error.0.body);
    assert_eq!(response["error"]["code"], -32020);
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
            wire_body_value(error.0.body)["error"]["code"],
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
    let response = wire_body_value(error.0.body);
    assert_eq!(response["error"]["code"], -32022);
    assert_eq!(
        response["error"]["data"],
        json!({
            "supported": ["2026-07-28", "2025-06-18"],
            "requested": "1900-01-01",
        })
    );
}

#[test]
fn mcp_protocol_modern_rejects_duplicate_singleton_routing_header_lines() {
    let body = serde_json::to_vec(&modern_request(
        "tools/call",
        json!({"name": "weather", "arguments": {}}),
    ))
    .unwrap();
    let cases = [
        ("content-type", "application/json"),
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
            wire_body_value(error.0.body)["error"]["code"],
            -32020,
            "{header}"
        );
    }
}

#[test]
fn mcp_protocol_modern_accept_combines_repeated_raw_field_lines() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    let mut headers = modern_headers("tools/list", None);
    headers.remove("accept");
    headers.append(
        "accept",
        "application/json; profile=complete; q=1".parse().unwrap(),
    );
    headers.append(
        "accept",
        r#"text/event-stream; note="events,ordered""#.parse().unwrap(),
    );

    sbproxy_extension::mcp::decode_http_request(&body, &headers)
        .expect("Accept is a repeatable RFC 9110 list field");
}

#[test]
fn mcp_protocol_modern_content_type_accepts_rfc_9110_case_and_parameters() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    for content_type in [
        "application/json",
        "Application/JSON",
        "application/json; charset=utf-8",
        r#"APPLICATION/JSON; Charset="UTF-8"; profile="complete,strict""#,
    ] {
        let mut headers = modern_headers("tools/list", None);
        headers.insert("content-type", content_type.parse().unwrap());
        sbproxy_extension::mcp::decode_http_request(&body, &headers)
            .unwrap_or_else(|_| panic!("valid Content-Type rejected: {content_type}"));
    }
}

#[test]
fn mcp_protocol_modern_content_type_rejects_invalid_and_lookalike_values() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    for content_type in [
        "text/plain",
        "application/jsonp",
        "text/application/json",
        "application/json, text/plain",
        "application/json; charset =utf-8",
        r#"application/json; profile="unterminated"#,
    ] {
        let mut headers = modern_headers("tools/list", None);
        headers.insert("content-type", content_type.parse().unwrap());
        let error = sbproxy_extension::mcp::decode_http_request(&body, &headers)
            .expect_err("invalid Content-Type");
        assert_eq!(
            error.0.status,
            http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type}"
        );
        assert_eq!(
            wire_body_value(error.0.body)["error"]["code"],
            -32600,
            "{content_type}"
        );
    }

    let mut non_utf8 = modern_headers("tools/list", None);
    non_utf8.insert(
        "content-type",
        http::HeaderValue::from_bytes(b"application/json; profile=\xff").unwrap(),
    );
    let error = sbproxy_extension::mcp::decode_http_request(&body, &non_utf8)
        .expect_err("non-UTF-8 Content-Type");
    assert_eq!(error.0.status, http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[test]
fn mcp_protocol_modern_accept_parses_parameters_qvalues_and_quoted_commas() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    for accept in [
        "Application/JSON; Charset=utf-8; Q=0.125, TEXT/EVENT-STREAM; q=1.000",
        r#"application/json; note="a,b\"c", text/event-stream; note="events,ordered""#,
        "application/json;q=0, application/json;q=0.001, text/event-stream",
    ] {
        let mut headers = modern_headers("tools/list", None);
        headers.insert("accept", accept.parse().unwrap());
        sbproxy_extension::mcp::decode_http_request(&body, &headers)
            .unwrap_or_else(|_| panic!("valid Accept rejected: {accept}"));
    }
}

#[test]
fn mcp_protocol_modern_accept_requires_both_exact_positive_media_ranges() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    for accept in [
        "application/json",
        "text/event-stream",
        "application/*, text/event-stream",
        "application/json, text/*",
        "*/*",
        "application/json;q=0, text/event-stream",
        "application/json, text/event-stream;q=0.000",
        "application/jsonp, text/event-stream",
        "application/json, text/event-streaming",
    ] {
        let mut headers = modern_headers("tools/list", None);
        headers.insert("accept", accept.parse().unwrap());
        let error = sbproxy_extension::mcp::decode_http_request(&body, &headers)
            .expect_err("both exact positive media ranges are required");
        assert_eq!(error.0.status, http::StatusCode::NOT_ACCEPTABLE, "{accept}");
        assert_eq!(
            wire_body_value(error.0.body)["error"]["code"],
            -32600,
            "{accept}"
        );
    }
}

#[test]
fn mcp_protocol_modern_accept_rejects_invalid_or_duplicate_qvalues() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    for accept in [
        "application/json, text/event-stream, application/xml;q=.5",
        "application/json, text/event-stream, application/xml;q=2",
        "application/json, text/event-stream, application/xml;q=1.001",
        "application/json, text/event-stream, application/xml;q=0.0000",
        "application/json, text/event-stream, application/xml;q=bogus",
        "application/json, text/event-stream, application/xml;q=1;Q=0.5",
        r#"application/json, text/event-stream, application/xml;q="0.5""#,
    ] {
        let mut headers = modern_headers("tools/list", None);
        headers.insert("accept", accept.parse().unwrap());
        let error = sbproxy_extension::mcp::decode_http_request(&body, &headers)
            .expect_err("invalid qvalue invalidates Accept");
        assert_eq!(error.0.status, http::StatusCode::NOT_ACCEPTABLE, "{accept}");
    }
}

#[test]
fn mcp_protocol_modern_accept_bounds_combined_field_bytes() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    let oversized = format!(
        r#"application/json, text/event-stream, application/octet-stream; note="{}""#,
        "x".repeat(8_192)
    );
    let mut headers = modern_headers("tools/list", None);
    headers.insert("accept", oversized.parse().unwrap());
    let error = sbproxy_extension::mcp::decode_http_request(&body, &headers)
        .expect_err("combined Accept bytes are bounded");
    assert_eq!(error.0.status, http::StatusCode::NOT_ACCEPTABLE);
}

#[test]
fn mcp_protocol_modern_accept_bounds_nonempty_members() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    let mut at_limit = vec!["application/json", "text/event-stream"];
    at_limit.extend(std::iter::repeat_n("application/octet-stream", 62));
    let mut headers = modern_headers("tools/list", None);
    headers.insert("accept", at_limit.join(",").parse().unwrap());
    sbproxy_extension::mcp::decode_http_request(&body, &headers)
        .expect("64 non-empty Accept members are allowed");

    let mut over_limit = at_limit;
    over_limit.push("text/plain");
    headers.insert("accept", over_limit.join(",").parse().unwrap());
    let error = sbproxy_extension::mcp::decode_http_request(&body, &headers)
        .expect_err("65 non-empty Accept members are rejected");
    assert_eq!(error.0.status, http::StatusCode::NOT_ACCEPTABLE);
}

#[test]
fn mcp_protocol_modern_accept_bounds_ignored_empty_members() {
    let body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    let mut headers = modern_headers("tools/list", None);
    let at_limit = format!("{}application/json,text/event-stream", ",".repeat(16));
    headers.insert("accept", at_limit.parse().unwrap());
    sbproxy_extension::mcp::decode_http_request(&body, &headers)
        .expect("16 empty Accept members are ignored");

    let over_limit = format!("{}application/json,text/event-stream", ",".repeat(17));
    headers.insert("accept", over_limit.parse().unwrap());
    let error = sbproxy_extension::mcp::decode_http_request(&body, &headers)
        .expect_err("17 empty Accept members are rejected");
    assert_eq!(error.0.status, http::StatusCode::NOT_ACCEPTABLE);

    headers.insert("accept", ",,,".parse().unwrap());
    let error = sbproxy_extension::mcp::decode_http_request(&body, &headers)
        .expect_err("all-empty Accept is rejected");
    assert_eq!(error.0.status, http::StatusCode::NOT_ACCEPTABLE);
}

#[test]
fn mcp_protocol_modern_structural_errors_precede_media_validation() {
    let cases = [
        br#"{"jsonrpc":"2.0","id":1,"\u0069d":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#
            .as_slice(),
        br#"[{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}]"#
            .as_slice(),
    ];
    let mut headers = modern_headers("tools/list", None);
    headers.remove("content-type");

    for body in cases {
        let error = sbproxy_extension::mcp::decode_http_request(body, &headers)
            .expect_err("structural failure");
        assert_eq!(error.0.status, http::StatusCode::BAD_REQUEST);
        assert_eq!(wire_body_value(error.0.body)["error"]["code"], -32600);
    }

    let malformed = modern_request_with_raw_id("1e");
    let error = sbproxy_extension::mcp::decode_http_request(&malformed, &headers)
        .expect_err("syntax failure");
    assert_eq!(error.0.status, http::StatusCode::BAD_REQUEST);
    assert_eq!(wire_body_value(error.0.body)["error"]["code"], -32700);
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
fn mcp_protocol_modern_rejects_explicit_null_request_ids() {
    let mut body = modern_request("tools/list", json!({}));
    body["id"] = Value::Null;
    let error = sbproxy_extension::mcp::decode_http_request(
        &serde_json::to_vec(&body).unwrap(),
        &modern_headers("tools/list", None),
    )
    .expect_err("explicit null is not a modern notification id");
    assert_eq!(error.0.status, http::StatusCode::BAD_REQUEST);
    let body = wire_body_value(error.0.body);
    assert_eq!(body["error"]["code"], -32600);
    assert!(body.get("id").is_none());
}

#[test]
fn mcp_protocol_raw_scan_detects_protected_duplicates_at_every_routing_level() {
    let cases = [
        (
            "request",
            br#"{"jsonrpc":"2.0","id":1,"\u0069d":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#
                .as_slice(),
        ),
        (
            "params",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"one","\u006eame":"two","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#
                .as_slice(),
        ),
        (
            "reserved metadata",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","\u0069o.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#
                .as_slice(),
        ),
    ];

    for (scope, body) in cases {
        let scan = RawModernScan::scan(body);
        assert_eq!(
            classify_http_era(Some(&scan), &HeaderMap::new()),
            McpProtocolEra::Modern2026_07_28,
            "{scope}"
        );
        let error =
            sbproxy_extension::mcp::decode_http_request(body, &modern_headers("tools/list", None))
                .expect_err("protected duplicates are rejected before metadata decoding");
        assert_eq!(error.0.status, http::StatusCode::BAD_REQUEST, "{scope}");
        assert_eq!(wire_body_value(error.0.body)["error"]["code"], -32600);
    }
}

#[test]
fn mcp_protocol_raw_scan_decodes_escaped_keys_without_descending_into_arguments() {
    let escaped_marker = RawModernScan::scan(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"\u0069o.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#,
    );
    assert_eq!(
        classify_http_era(Some(&escaped_marker), &HeaderMap::new()),
        McpProtocolEra::Modern2026_07_28
    );

    let nested_argument = RawModernScan::scan(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","id":1,"\u0069d":2}}}"#,
    );
    assert_eq!(
        classify_http_era(Some(&nested_argument), &HeaderMap::new()),
        McpProtocolEra::Legacy2025_06_18
    );
}

#[test]
fn mcp_protocol_raw_scan_inspects_each_direct_batch_request_for_modern_markers() {
    let scan = RawModernScan::scan(
        br#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}}]"#,
    );
    assert_eq!(
        classify_http_era(Some(&scan), &HeaderMap::new()),
        McpProtocolEra::Modern2026_07_28
    );
}

#[test]
fn mcp_protocol_raw_scan_reports_the_one_mib_limit_without_changing_era() {
    // The limit is reported so the modern codec can refuse on it, but a limit
    // alone is not modern evidence: a marker-free body stays legacy so a large
    // legacy call keeps the behavior it had before the era split. The HTTP
    // layer caps the body at 1 MiB with a 413 before this scan runs anyway.
    let body = vec![b' '; 1_048_577];
    let scan = RawModernScan::scan(&body);
    assert_eq!(scan.limit_exceeded(), Some(RawModernScanLimit::BodyBytes));
    assert_eq!(
        classify_http_era(Some(&scan), &HeaderMap::new()),
        McpProtocolEra::Legacy2025_06_18
    );
}

#[test]
fn mcp_protocol_raw_scan_reports_depth_limit_without_changing_era() {
    let body = format!("{}null{}", "[".repeat(129), "]".repeat(129));
    let scan = RawModernScan::scan(body.as_bytes());
    assert_eq!(
        scan.limit_exceeded(),
        Some(RawModernScanLimit::ContainerDepth)
    );
    assert_eq!(
        classify_http_era(Some(&scan), &HeaderMap::new()),
        McpProtocolEra::Legacy2025_06_18
    );
}

#[test]
fn mcp_protocol_raw_scan_reports_item_limit_without_changing_era() {
    let body = format!("[{}]", vec!["null"; 65_537].join(","));
    let scan = RawModernScan::scan(body.as_bytes());
    assert_eq!(
        scan.limit_exceeded(),
        Some(RawModernScanLimit::VisitedItems)
    );
    // A valid 2025-06-18 tools/call carrying a 70,000-element argument array
    // hits this limit. It must still be served as legacy, not turned into a
    // modern refusal, because every real modern request also carries modern
    // headers, which no body limit can hide.
    assert_eq!(
        classify_http_era(Some(&scan), &HeaderMap::new()),
        McpProtocolEra::Legacy2025_06_18
    );
}

#[test]
fn mcp_protocol_era_classifier_selects_modern_for_every_partial_header_marker() {
    let cases = [
        ("mcp-method", b"tools/list".as_slice()),
        ("mcp-name", b"weather".as_slice()),
        ("mcp-param-region", b"west".as_slice()),
        ("mcp-protocol-version", b"2026-07-28".as_slice()),
    ];
    // Only the exact modern revision counts. An older or unparseable revision
    // is not a 2026-07-28 request, so it stays legacy and keeps that era's
    // descriptive unsupported-version error instead of a modern refusal.
    for stale in [b"2025-03-26".as_slice(), b"2024-11-05".as_slice(), b"\xff"] {
        let mut headers = HeaderMap::new();
        headers.append(
            http::HeaderName::from_static("mcp-protocol-version"),
            http::HeaderValue::from_bytes(stale).unwrap(),
        );
        assert_eq!(
            classify_http_era(None, &headers),
            McpProtocolEra::Legacy2025_06_18,
            "stale revision {stale:?} must stay legacy"
        );
    }

    for (name, value) in cases {
        let mut headers = HeaderMap::new();
        headers.append(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            http::HeaderValue::from_bytes(value).unwrap(),
        );
        assert_eq!(
            classify_http_era(None, &headers),
            McpProtocolEra::Modern2026_07_28,
            "{name}: {value:?}"
        );
    }
}

#[test]
fn mcp_protocol_era_classifier_keeps_only_marker_free_requests_legacy() {
    let mut headers = HeaderMap::new();
    headers.append("content-type", "application/json".parse().unwrap());
    headers.append(
        "accept",
        "application/json, text/event-stream".parse().unwrap(),
    );
    headers.append("mcp-protocol-version", "2025-06-18".parse().unwrap());
    let scan = RawModernScan::scan(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"arguments":{"io.modelcontextprotocol/clientInfo":{}}}}"#,
    );

    assert_eq!(
        classify_http_era(Some(&scan), &headers),
        McpProtocolEra::Legacy2025_06_18
    );
}

#[test]
fn mcp_protocol_modern_request_id_accepts_absent_string_and_integer_boundaries() {
    let cases = [
        (
            br#"{"jsonrpc":"2.0","method":"tools/list"}"#.as_slice(),
            ModernRequestId::Absent,
        ),
        (
            br#"{"jsonrpc":"2.0","id":"snowman-\u2603","method":"tools/list"}"#.as_slice(),
            ModernRequestId::String("snowman-☃".to_string()),
        ),
        (
            br#"{"jsonrpc":"2.0","id":-9223372036854775808,"method":"tools/list"}"#.as_slice(),
            ModernRequestId::Integer(McpInteger::Signed(i64::MIN)),
        ),
        (
            br#"{"jsonrpc":"2.0","id":18446744073709551615,"method":"tools/list"}"#.as_slice(),
            ModernRequestId::Integer(McpInteger::Unsigned(u64::MAX)),
        ),
    ];

    for (body, expected) in cases {
        assert_eq!(RawModernScan::scan(body).request_id(), Ok(expected));
    }
}

#[test]
fn mcp_protocol_modern_request_id_rejects_null_nonintegers_and_out_of_range() {
    let cases = [
        ("null", ModernRequestIdError::ExplicitNull),
        ("true", ModernRequestIdError::InvalidType),
        ("{}", ModernRequestIdError::InvalidType),
        ("[]", ModernRequestIdError::InvalidType),
        ("1.0", ModernRequestIdError::NonIntegerNumber),
        ("1e0", ModernRequestIdError::NonIntegerNumber),
        ("1e400", ModernRequestIdError::NonIntegerNumber),
        (
            "-9223372036854775809",
            ModernRequestIdError::IntegerOutOfRange,
        ),
        (
            "18446744073709551616",
            ModernRequestIdError::IntegerOutOfRange,
        ),
    ];

    for (raw_id, expected) in cases {
        let body = modern_request_with_raw_id(raw_id);
        assert_eq!(RawModernScan::scan(&body).request_id(), Err(expected));
    }
}

#[test]
fn mcp_protocol_modern_decoder_uses_the_strict_raw_request_id() {
    for raw_id in [
        "null",
        "false",
        "{}",
        "[]",
        "1.0",
        "1e0",
        "1e400",
        "-9223372036854775809",
        "18446744073709551616",
    ] {
        let error = sbproxy_extension::mcp::decode_http_request(
            &modern_request_with_raw_id(raw_id),
            &modern_headers("tools/list", None),
        )
        .expect_err("unsupported modern request id");
        assert_eq!(error.0.status, http::StatusCode::BAD_REQUEST, "{raw_id}");
        let body = wire_body_value(error.0.body);
        assert_eq!(body["error"]["code"], -32600, "{raw_id}");
        assert!(body.get("id").is_none(), "{raw_id}: {body}");
    }
}

#[test]
fn mcp_protocol_modern_distinguishes_malformed_json_from_unsupported_number_id() {
    let malformed = modern_request_with_raw_id("1e");
    let malformed_error = sbproxy_extension::mcp::decode_http_request(
        &malformed,
        &modern_headers("tools/list", None),
    )
    .expect_err("malformed JSON");
    let malformed_body = wire_body_value(malformed_error.0.body);
    assert_eq!(malformed_body["error"]["code"], -32700);
    assert!(malformed_body.get("id").is_none());

    let unsupported = modern_request_with_raw_id("1e400");
    let unsupported_error = sbproxy_extension::mcp::decode_http_request(
        &unsupported,
        &modern_headers("tools/list", None),
    )
    .expect_err("unsupported numeric ID profile");
    let unsupported_body = wire_body_value(unsupported_error.0.body);
    assert_eq!(unsupported_body["error"]["code"], -32600);
    assert!(unsupported_body.get("id").is_none());
}

#[test]
fn mcp_protocol_modern_scan_reuse_is_bound_to_the_borrowed_body() {
    let trusted_body = serde_json::to_vec(&modern_request("tools/list", json!({}))).unwrap();
    let trusted_scan = RawModernScan::scan(&trusted_body);
    let trusted = sbproxy_extension::mcp::decode_http_request_with_scan(
        &trusted_scan,
        &modern_headers("tools/list", None),
    )
    .expect("the scan decodes the exact body it borrows");
    assert_eq!(trusted.request.id, Some(json!(7)));

    let mut explicit_null_body = modern_request("tools/list", json!({}));
    explicit_null_body["id"] = Value::Null;
    let explicit_null_body = serde_json::to_vec(&explicit_null_body).unwrap();
    let explicit_null_scan = RawModernScan::scan(&explicit_null_body);
    sbproxy_extension::mcp::decode_http_request_with_scan(
        &explicit_null_scan,
        &modern_headers("tools/list", None),
    )
    .expect_err("a distinct body requires its own strict scan");
}

#[test]
fn mcp_protocol_modern_typed_decoder_cannot_normalize_explicit_null_to_absent() {
    let mut explicit_null = modern_request("tools/list", json!({}));
    explicit_null["id"] = Value::Null;
    let normalized: JsonRpcRequest = serde_json::from_value(explicit_null).unwrap();
    assert!(
        normalized.id.is_none(),
        "fixture demonstrates the lossy typed envelope"
    );

    let error = Modern2026_07_28Codec
        .decode_http(normalized, &modern_headers("tools/list", None))
        .expect_err("modern decoding must require the duplicate-aware raw preflight");
    assert_eq!(error.0.status, http::StatusCode::BAD_REQUEST);
    let body = wire_body_value(error.0.body);
    assert_eq!(body["error"]["code"], -32600);
    assert!(body.get("id").is_none());
}

#[test]
fn mcp_protocol_modern_envelope_failure_precedes_invalid_request_id() {
    let body = br#"{"jsonrpc":"1.0","id":null,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let error =
        sbproxy_extension::mcp::decode_http_request(body, &modern_headers("tools/list", None))
            .expect_err("crossed envelope and id failure");
    let body = wire_body_value(error.0.body);
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(body["error"]["message"], "jsonrpc field must be \"2.0\"");
    assert!(body.get("id").is_none());
}

#[test]
fn mcp_protocol_modern_envelope_failure_echoes_an_independently_valid_id() {
    let body = br#"{"jsonrpc":"1.0","id":7,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let error =
        sbproxy_extension::mcp::decode_http_request(body, &modern_headers("tools/list", None))
            .expect_err("invalid JSON-RPC envelope");
    let body = wire_body_value(error.0.body);
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(body["error"]["message"], "jsonrpc field must be \"2.0\"");
    assert_eq!(body["id"], 7);
}

#[test]
fn mcp_protocol_modern_error_response_omits_absent_id_from_wire_bytes() {
    let response = ModernJsonRpcResponse::error(ModernRequestId::Absent, -32601, "unknown method");
    assert_eq!(
        serde_json::to_string(&response).unwrap(),
        r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"unknown method"}}"#
    );
}

#[test]
fn mcp_protocol_modern_response_preserves_string_and_integer_id_types() {
    let cases = [
        (
            ModernRequestId::String("request-7".to_string()),
            r#"{"jsonrpc":"2.0","result":{"ok":true},"id":"request-7"}"#,
        ),
        (
            ModernRequestId::Integer(McpInteger::Signed(i64::MIN)),
            r#"{"jsonrpc":"2.0","result":{"ok":true},"id":-9223372036854775808}"#,
        ),
        (
            ModernRequestId::Integer(McpInteger::Unsigned(u64::MAX)),
            r#"{"jsonrpc":"2.0","result":{"ok":true},"id":18446744073709551615}"#,
        ),
    ];

    for (id, expected) in cases {
        let response = ModernJsonRpcResponse::success(id, json!({"ok": true}));
        assert_eq!(serde_json::to_string(&response).unwrap(), expected);
    }
}

#[test]
fn mcp_protocol_legacy_absent_response_id_remains_explicit_null() {
    let response = sbproxy_extension::mcp::JsonRpcResponse::error(None, -32601, "unknown method");
    assert_eq!(
        serde_json::to_string(&response).unwrap(),
        r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"unknown method"},"id":null}"#
    );
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
        wire_body_value(error.0.body)["error"]["code"],
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
