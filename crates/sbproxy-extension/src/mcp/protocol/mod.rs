//! Protocol-neutral MCP wire codec interfaces.

pub mod headers;
pub mod legacy;
pub mod modern;

pub use headers::{decode_header_value, encode_header_value, HeaderValueError};
pub use legacy::Legacy2025_06_18Codec;
pub use modern::{
    build_discover_result, is_recognized_modern_error, modern_server_capabilities,
    Modern2026_07_28Codec,
};

/// MCP wire-protocol era.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpProtocolEra {
    /// The frozen 2025-06-18 MCP protocol behavior.
    Legacy2025_06_18,
    /// The 2026-07-28 MCP protocol behavior.
    Modern2026_07_28,
}

/// An MCP implementation identity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct McpImplementation {
    /// Implementation name.
    pub name: String,
    /// Implementation version.
    pub version: String,
}

/// Context decoded from a protocol-specific MCP request.
#[derive(Debug, Clone, PartialEq)]
pub struct McpProtocolContext {
    /// Protocol era selected for the request.
    pub era: McpProtocolEra,
    /// Negotiated protocol version.
    pub protocol_version: String,
    /// Client capabilities advertised in `initialize`.
    pub client_capabilities: serde_json::Value,
    /// Client identity advertised in `initialize`.
    pub client_info: Option<McpImplementation>,
}

/// HTTP headers promoted into protocol routing state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpRoutingHeaders {
    /// Routing method selected by the protocol.
    pub method: Option<String>,
    /// Routing name selected by the protocol.
    pub name: Option<String>,
    /// Additional request parameters selected by the protocol.
    pub params: http::HeaderMap,
}

/// A decoded MCP request and its protocol context.
#[derive(Debug, Clone)]
pub struct DecodedMcpRequest {
    /// Original JSON-RPC request envelope.
    pub request: crate::mcp::types::JsonRpcRequest,
    /// Protocol context extracted from the request.
    pub context: McpProtocolContext,
    /// Routing headers extracted from the request.
    pub routing_headers: McpRoutingHeaders,
}

/// Protocol-specific HTTP response envelope.
#[derive(Debug, Clone)]
pub struct McpWireResponse {
    /// HTTP status code.
    pub status: http::StatusCode,
    /// HTTP response headers.
    pub headers: http::HeaderMap,
    /// Optional JSON-RPC response body.
    pub body: Option<crate::mcp::types::JsonRpcResponse>,
}

/// Protocol-specific error response envelope.
#[derive(Debug, Clone)]
pub struct McpWireError(pub McpWireResponse);

impl McpWireError {
    /// Build a JSON-RPC error response with the given HTTP status.
    pub fn json(
        status: http::StatusCode,
        id: Option<serde_json::Value>,
        code: i32,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self(McpWireResponse {
            status,
            headers: http::HeaderMap::new(),
            body: Some(crate::mcp::types::JsonRpcResponse::error_with_data(
                id, code, message, data,
            )),
        })
    }

    /// Build a JSON-RPC invalid-params response.
    pub fn invalid_params(id: Option<serde_json::Value>, message: &str) -> Self {
        Self::json(
            http::StatusCode::BAD_REQUEST,
            id,
            crate::mcp::types::INVALID_PARAMS,
            message,
            None,
        )
    }
}

/// Server properties used when encoding MCP responses.
#[derive(Debug, Clone)]
pub struct McpServerDescription {
    /// Gateway implementation identity.
    pub implementation: McpImplementation,
    /// Server capabilities.
    pub capabilities: serde_json::Value,
    /// Optional server instructions.
    pub instructions: Option<String>,
}

/// Codec for one MCP wire-protocol era.
pub trait McpProtocolCodec: Send + Sync {
    /// Return the wire-protocol era this codec implements.
    fn era(&self) -> McpProtocolEra;

    /// Decode an HTTP request into a JSON-RPC request and protocol context.
    fn decode_http(
        &self,
        request: crate::mcp::types::JsonRpcRequest,
        headers: &http::HeaderMap,
    ) -> Result<DecodedMcpRequest, McpWireError>;

    /// Encode a successful JSON-RPC result for this protocol era.
    fn encode_success(
        &self,
        method: &str,
        id: Option<serde_json::Value>,
        result: serde_json::Value,
        server: &McpServerDescription,
    ) -> Result<McpWireResponse, McpWireError>;

    /// Encode a JSON-RPC error for this protocol era.
    fn encode_error(
        &self,
        id: Option<serde_json::Value>,
        code: i32,
        message: &str,
        data: Option<serde_json::Value>,
    ) -> McpWireResponse;
}

/// Select an MCP protocol era from corroborating HTTP and JSON-RPC carriers.
pub fn classify_http_era(
    request: &crate::mcp::types::JsonRpcRequest,
    headers: &http::HeaderMap,
) -> McpProtocolEra {
    let body_version = request
        .params
        .as_ref()
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get(crate::mcp::types::META_PROTOCOL_VERSION))
        .and_then(serde_json::Value::as_str);
    let header_version = headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok());

    if body_version.is_some() || header_version == Some(crate::mcp::types::MODERN_PROTOCOL_VERSION)
    {
        McpProtocolEra::Modern2026_07_28
    } else {
        McpProtocolEra::Legacy2025_06_18
    }
}

/// Decode an MCP HTTP body through exactly one protocol-era codec.
pub fn decode_http_request(
    body: &[u8],
    headers: &http::HeaderMap,
) -> Result<DecodedMcpRequest, McpWireError> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| {
        McpWireError::json(
            http::StatusCode::BAD_REQUEST,
            None,
            crate::mcp::types::INVALID_REQUEST,
            "MCP request must be a JSON object",
            None,
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        McpWireError::json(
            http::StatusCode::BAD_REQUEST,
            None,
            crate::mcp::types::INVALID_REQUEST,
            "MCP request must be a JSON object",
            None,
        )
    })?;
    let id = object.get("id").cloned();
    if id
        .as_ref()
        .is_some_and(|value| !value.is_string() && !value.is_number() && !value.is_null())
    {
        return Err(McpWireError::json(
            http::StatusCode::BAD_REQUEST,
            None,
            crate::mcp::types::INVALID_REQUEST,
            "JSON-RPC request id must be a string, number, or null",
            None,
        ));
    }
    let request: crate::mcp::types::JsonRpcRequest =
        serde_json::from_value(value).map_err(|_| {
            McpWireError::json(
                http::StatusCode::BAD_REQUEST,
                id,
                crate::mcp::types::INVALID_REQUEST,
                "invalid JSON-RPC request",
                None,
            )
        })?;
    if request.jsonrpc != "2.0" {
        return Err(McpWireError::json(
            http::StatusCode::BAD_REQUEST,
            request.id,
            crate::mcp::types::INVALID_REQUEST,
            "JSON-RPC version must be 2.0",
            None,
        ));
    }

    match classify_http_era(&request, headers) {
        McpProtocolEra::Legacy2025_06_18 => Legacy2025_06_18Codec.decode_http(request, headers),
        McpProtocolEra::Modern2026_07_28 => Modern2026_07_28Codec.decode_http(request, headers),
    }
}
