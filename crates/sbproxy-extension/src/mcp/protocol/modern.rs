//! Strict MCP 2026-07-28 ingress codec.

use super::{
    decode_header_value, DecodedMcpRequest, McpImplementation, McpProtocolCodec,
    McpProtocolContext, McpProtocolEra, McpRoutingHeaders, McpServerDescription, McpWireError,
    McpWireResponse,
};
use crate::mcp::types::{
    JsonRpcRequest, JsonRpcResponse, HEADER_MISMATCH, META_CLIENT_CAPABILITIES, META_CLIENT_INFO,
    META_PROTOCOL_VERSION, META_SERVER_INFO, MISSING_REQUIRED_CLIENT_CAPABILITY,
    MODERN_PROTOCOL_VERSION, UNSUPPORTED_PROTOCOL_VERSION,
};

const PROTECTED_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "mcp-protocol-version",
    "mcp-method",
    "mcp-name",
];

/// Codec for strict MCP 2026-07-28 request ingress.
#[derive(Debug, Clone, Copy, Default)]
pub struct Modern2026_07_28Codec;

/// Build the modern capability object from the core surfaces the gateway serves.
pub fn modern_server_capabilities(
    has_tools: bool,
    has_resources: bool,
    has_prompts: bool,
) -> serde_json::Value {
    let mut capabilities = serde_json::Map::new();
    if has_tools {
        capabilities.insert("tools".into(), serde_json::json!({"listChanged": false}));
    }
    if has_resources {
        capabilities.insert(
            "resources".into(),
            serde_json::json!({"listChanged": false}),
        );
    }
    if has_prompts {
        capabilities.insert("prompts".into(), serde_json::json!({"listChanged": false}));
    }
    serde_json::Value::Object(capabilities)
}

/// Build a private, zero-TTL modern server discovery result.
pub fn build_discover_result(server: &McpServerDescription) -> serde_json::Value {
    let capabilities = modern_server_capabilities(
        server.capabilities.get("tools").is_some(),
        server.capabilities.get("resources").is_some(),
        server.capabilities.get("prompts").is_some(),
    );
    let mut meta = serde_json::Map::new();
    meta.insert(
        META_SERVER_INFO.into(),
        serde_json::to_value(&server.implementation).expect("implementation is serializable"),
    );
    let mut result = serde_json::json!({
        "resultType": "complete",
        "supportedVersions": [
            MODERN_PROTOCOL_VERSION,
            crate::mcp::types::LEGACY_PROTOCOL_VERSION,
        ],
        "capabilities": capabilities,
        "ttlMs": 0,
        "cacheScope": "private",
        "_meta": meta,
    });
    if let Some(instructions) = &server.instructions {
        result["instructions"] = serde_json::Value::String(instructions.clone());
    }
    result
}

/// Return whether a response carries a recognized modern protocol error.
pub fn is_recognized_modern_error(response: &JsonRpcResponse) -> bool {
    response
        .error
        .as_ref()
        .is_some_and(|error| matches!(error.code, -32020 | -32021 | -32022))
}

impl McpProtocolCodec for Modern2026_07_28Codec {
    fn era(&self) -> McpProtocolEra {
        McpProtocolEra::Modern2026_07_28
    }

    fn decode_http(
        &self,
        request: JsonRpcRequest,
        headers: &http::HeaderMap,
    ) -> Result<DecodedMcpRequest, McpWireError> {
        validate_content_type(headers, request.id.clone())?;
        validate_accept(headers, request.id.clone())?;
        validate_no_duplicate_routing_headers(headers, request.id.clone())?;

        let metadata = request
            .params
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|params| params.get("_meta"))
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| invalid_params(request.id.clone(), "missing modern MCP metadata"))?;
        let body_version = metadata
            .get(META_PROTOCOL_VERSION)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                invalid_params(
                    request.id.clone(),
                    "missing modern MCP protocol version metadata",
                )
            })?;
        let capabilities = metadata
            .get(META_CLIENT_CAPABILITIES)
            .filter(|value| value.is_object())
            .cloned()
            .ok_or_else(|| {
                invalid_params(request.id.clone(), "missing modern MCP client capabilities")
            })?;
        let client_info = metadata
            .get(META_CLIENT_INFO)
            .map(|value| serde_json::from_value::<McpImplementation>(value.clone()))
            .transpose()
            .map_err(|_| invalid_params(request.id.clone(), "invalid modern MCP client info"))?;

        let protocol_header = required_header(headers, "mcp-protocol-version", request.id.clone())?;
        if protocol_header != body_version {
            return Err(header_mismatch(
                request.id.clone(),
                "MCP-Protocol-Version does not match body metadata",
            ));
        }
        if body_version != MODERN_PROTOCOL_VERSION {
            return Err(McpWireError::json(
                http::StatusCode::BAD_REQUEST,
                request.id.clone(),
                UNSUPPORTED_PROTOCOL_VERSION,
                "unsupported MCP protocol version",
                Some(serde_json::json!({
                    "supported": [MODERN_PROTOCOL_VERSION, crate::mcp::types::LEGACY_PROTOCOL_VERSION],
                    "requested": body_version,
                })),
            ));
        }

        let method_header = required_header(headers, "mcp-method", request.id.clone())?;
        if method_header != request.method {
            return Err(header_mismatch(
                request.id.clone(),
                "Mcp-Method does not match JSON-RPC method",
            ));
        }
        let selector_key = match request.method.as_str() {
            "tools/call" | "prompts/get" => Some("name"),
            "resources/read" => Some("uri"),
            _ => None,
        };
        let decoded_name = if let Some(selector_key) = selector_key {
            let name = required_header(headers, "mcp-name", request.id.clone())?;
            let decoded_name = decode_header_value(name).map_err(|_| {
                header_mismatch(request.id.clone(), "invalid Mcp-Name header value")
            })?;
            let body_selector = request
                .params
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .and_then(|params| params.get(selector_key))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    header_mismatch(request.id.clone(), "missing or invalid MCP body selector")
                })?;
            if decoded_name != body_selector {
                return Err(header_mismatch(
                    request.id.clone(),
                    "Mcp-Name does not match the JSON-RPC body selector",
                ));
            }
            Some(decoded_name)
        } else {
            None
        };

        Ok(DecodedMcpRequest {
            request,
            context: McpProtocolContext {
                era: McpProtocolEra::Modern2026_07_28,
                protocol_version: MODERN_PROTOCOL_VERSION.to_string(),
                client_capabilities: capabilities,
                client_info,
            },
            routing_headers: McpRoutingHeaders {
                method: Some(method_header.to_string()),
                name: decoded_name,
                params: mirrored_params(headers),
            },
        })
    }

    fn encode_success(
        &self,
        method: &str,
        id: Option<serde_json::Value>,
        result: serde_json::Value,
        server: &McpServerDescription,
    ) -> Result<McpWireResponse, McpWireError> {
        if id.is_none() {
            return Ok(McpWireResponse {
                status: http::StatusCode::ACCEPTED,
                headers: http::HeaderMap::new(),
                body: None,
            });
        }

        let mut result = result.as_object().cloned().ok_or_else(|| {
            internal_error(id.clone(), "modern MCP success result must be an object")
        })?;
        match result.entry("resultType") {
            serde_json::map::Entry::Vacant(entry) => {
                entry.insert(serde_json::Value::String("complete".into()));
            }
            serde_json::map::Entry::Occupied(entry)
                if entry.get() == &serde_json::Value::String("complete".into()) => {}
            serde_json::map::Entry::Occupied(_) => {
                return Err(internal_error(
                    id,
                    "modern MCP input-required results are not supported",
                ));
            }
        }

        let meta = match result.entry("_meta") {
            serde_json::map::Entry::Vacant(entry) => {
                entry.insert(serde_json::Value::Object(serde_json::Map::new()))
            }
            serde_json::map::Entry::Occupied(entry) if entry.get().is_object() => entry.into_mut(),
            serde_json::map::Entry::Occupied(_) => {
                return Err(internal_error(
                    id,
                    "modern MCP result _meta must be an object",
                ));
            }
        };
        meta.as_object_mut()
            .expect("modern MCP result metadata is an object")
            .insert(
                META_SERVER_INFO.into(),
                serde_json::to_value(&server.implementation)
                    .expect("implementation is serializable"),
            );

        if requires_cache_metadata(method) {
            result.insert("ttlMs".into(), serde_json::json!(0));
            result.insert("cacheScope".into(), serde_json::json!("private"));
        }

        Ok(McpWireResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: Some(JsonRpcResponse::success(
                id,
                serde_json::Value::Object(result),
            )),
        })
    }

    fn encode_error(
        &self,
        id: Option<serde_json::Value>,
        code: i32,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> McpWireResponse {
        McpWireResponse {
            status: modern_error_status(code),
            headers: http::HeaderMap::new(),
            body: Some(JsonRpcResponse::error_with_data(id, code, message, data)),
        }
    }
}

fn requires_cache_metadata(method: &str) -> bool {
    matches!(
        method,
        "server/discover"
            | "tools/list"
            | "prompts/list"
            | "resources/list"
            | "resources/read"
            | "resources/templates/list"
    )
}

fn modern_error_status(code: i32) -> http::StatusCode {
    match code {
        crate::mcp::types::PARSE_ERROR
        | crate::mcp::types::INVALID_REQUEST
        | crate::mcp::types::INVALID_PARAMS
        | HEADER_MISMATCH
        | MISSING_REQUIRED_CLIENT_CAPABILITY
        | UNSUPPORTED_PROTOCOL_VERSION => http::StatusCode::BAD_REQUEST,
        crate::mcp::types::METHOD_NOT_FOUND => http::StatusCode::NOT_FOUND,
        _ => http::StatusCode::OK,
    }
}

fn internal_error(id: Option<serde_json::Value>, message: &str) -> McpWireError {
    McpWireError::json(
        http::StatusCode::OK,
        id,
        crate::mcp::types::INTERNAL_ERROR,
        message,
        None,
    )
}

fn validate_content_type(
    headers: &http::HeaderMap,
    id: Option<serde_json::Value>,
) -> Result<(), McpWireError> {
    if header_value(headers, "content-type") == Some("application/json") {
        Ok(())
    } else {
        Err(McpWireError::json(
            http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            id,
            crate::mcp::types::INVALID_REQUEST,
            "Content-Type must be application/json",
            None,
        ))
    }
}

fn validate_accept(
    headers: &http::HeaderMap,
    id: Option<serde_json::Value>,
) -> Result<(), McpWireError> {
    let accepts_required_types = header_value(headers, "accept").is_some_and(|value| {
        let accepted: Vec<_> = value.split(',').map(str::trim).collect();
        accepted.contains(&"application/json") && accepted.contains(&"text/event-stream")
    });
    if accepts_required_types {
        Ok(())
    } else {
        Err(McpWireError::json(
            http::StatusCode::NOT_ACCEPTABLE,
            id,
            crate::mcp::types::INVALID_REQUEST,
            "Accept must include application/json and text/event-stream",
            None,
        ))
    }
}

fn validate_no_duplicate_routing_headers(
    headers: &http::HeaderMap,
    id: Option<serde_json::Value>,
) -> Result<(), McpWireError> {
    for name in PROTECTED_HEADERS {
        if headers.get_all(*name).iter().nth(1).is_some() {
            return Err(header_mismatch(
                id,
                "duplicate protected MCP routing header",
            ));
        }
    }

    for (name, _) in headers {
        let name = name.as_str();
        if name.starts_with("mcp-param-") && headers.get_all(name).iter().nth(1).is_some() {
            return Err(header_mismatch(
                id,
                "duplicate MCP parameter routing header",
            ));
        }
    }
    Ok(())
}

fn required_header<'a>(
    headers: &'a http::HeaderMap,
    name: &str,
    id: Option<serde_json::Value>,
) -> Result<&'a str, McpWireError> {
    header_value(headers, name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| header_mismatch(id, "missing required MCP routing header"))
}

fn header_value<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn mirrored_params(headers: &http::HeaderMap) -> http::HeaderMap {
    let mut params = http::HeaderMap::new();
    for (name, value) in headers {
        if name.as_str().starts_with("mcp-param-") {
            params.insert(name.clone(), value.clone());
        }
    }
    params
}

fn invalid_params(id: Option<serde_json::Value>, message: &str) -> McpWireError {
    McpWireError::invalid_params(id, message)
}

fn header_mismatch(id: Option<serde_json::Value>, message: &str) -> McpWireError {
    McpWireError::json(
        http::StatusCode::BAD_REQUEST,
        id,
        HEADER_MISMATCH,
        message,
        None,
    )
}
