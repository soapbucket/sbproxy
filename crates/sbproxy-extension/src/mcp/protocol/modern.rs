//! Strict MCP 2026-07-28 ingress codec.

use super::{
    decode_header_value, DecodedMcpRequest, McpImplementation, McpProtocolCodec,
    McpProtocolContext, McpProtocolEra, McpRoutingHeaders, McpServerDescription, McpWireError,
    McpWireResponse,
};
use crate::mcp::types::{
    JsonRpcRequest, JsonRpcResponse, HEADER_MISMATCH, META_CLIENT_CAPABILITIES, META_CLIENT_INFO,
    META_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSION, UNSUPPORTED_PROTOCOL_VERSION,
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
        let decoded_name = if request.method == "tools/call" {
            let name = required_header(headers, "mcp-name", request.id.clone())?;
            Some(decode_header_value(name).map_err(|_| {
                header_mismatch(request.id.clone(), "invalid Mcp-Name header value")
            })?)
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
        _method: &str,
        id: Option<serde_json::Value>,
        result: serde_json::Value,
        _server: &McpServerDescription,
    ) -> Result<McpWireResponse, McpWireError> {
        Ok(McpWireResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: Some(JsonRpcResponse::success(id, result)),
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
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: Some(JsonRpcResponse::error_with_data(id, code, message, data)),
        }
    }
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
