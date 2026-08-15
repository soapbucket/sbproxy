//! Frozen MCP 2025-06-18 wire codec.

use super::{
    DecodedMcpRequest, DecodedRequestId, McpProtocolCodec, McpProtocolContext, McpProtocolEra,
    McpRoutingHeaders, McpServerDescription, McpWireError, McpWireResponse,
};
use crate::mcp::types::{
    is_supported_protocol_version, JsonRpcRequest, JsonRpcResponse, LEGACY_PROTOCOL_VERSION,
};

/// Codec preserving MCP 2025-06-18 request and response behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct Legacy2025_06_18Codec;

impl McpProtocolCodec for Legacy2025_06_18Codec {
    type RequestId = Option<serde_json::Value>;

    fn era(&self) -> McpProtocolEra {
        McpProtocolEra::Legacy2025_06_18
    }

    fn decode_http(
        &self,
        request: JsonRpcRequest,
        headers: &http::HeaderMap,
    ) -> Result<DecodedMcpRequest, McpWireError> {
        if request.method != "initialize" {
            if let Some(header_version) = headers
                .get("mcp-protocol-version")
                .and_then(|value| value.to_str().ok())
            {
                if !is_supported_protocol_version(header_version) {
                    return Err(McpWireError::invalid_params(
                        request.id.clone(),
                        &format!(
                            "unsupported MCP-Protocol-Version '{header_version}' (supported: {})",
                            crate::mcp::types::SUPPORTED_PROTOCOL_VERSIONS.join(", ")
                        ),
                    ));
                }
            }
        }

        let params = request.params.as_ref();
        let client_capabilities = params
            .and_then(|value| value.get("capabilities"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let client_info = params
            .and_then(|value| value.get("clientInfo"))
            .and_then(|value| serde_json::from_value(value.clone()).ok());

        let request_id = request.id.clone();
        Ok(DecodedMcpRequest {
            request,
            request_id: DecodedRequestId::Legacy(request_id),
            context: McpProtocolContext {
                era: McpProtocolEra::Legacy2025_06_18,
                protocol_version: LEGACY_PROTOCOL_VERSION.to_string(),
                client_capabilities,
                client_info,
            },
            routing_headers: McpRoutingHeaders::default(),
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
            body: Some(JsonRpcResponse::success(id, result).into()),
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
            body: Some(JsonRpcResponse::error_with_data(id, code, message, data).into()),
        }
    }
}
