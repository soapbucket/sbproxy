//! MCP JSON-RPC request handler.

use super::registry::ToolRegistry;
use super::types::*;

/// Handles incoming MCP JSON-RPC requests.
pub struct McpHandler {
    /// Registry of tools the server exposes via "tools/list" and "tools/call".
    pub registry: ToolRegistry,
    /// Human-readable server name returned in "initialize" responses.
    pub server_name: String,
    /// Server version returned in "initialize" responses.
    pub server_version: String,
}

impl McpHandler {
    /// Create a new MCP handler with the given tool registry and server identity.
    pub fn new(registry: ToolRegistry, name: &str, version: &str) -> Self {
        Self {
            registry,
            server_name: name.to_string(),
            server_version: version.to_string(),
        }
    }

    /// Handle an MCP JSON-RPC request. Returns `None` for notifications (no id).
    pub fn handle_request(&self, request: &JsonRpcRequest) -> Option<JsonRpcResponse> {
        // Notifications (no id) get no response.
        request.id.as_ref()?;

        let response = match request.method.as_str() {
            "initialize" => self.handle_initialize(request),
            "tools/list" => self.handle_tools_list(request),
            "tools/call" => self.handle_tools_call(request),
            "ping" => JsonRpcResponse::success(request.id.clone(), serde_json::json!("pong")),
            _ => JsonRpcResponse::error(
                request.id.clone(),
                METHOD_NOT_FOUND,
                &format!("unknown method: {}", request.method),
            ),
        };
        Some(response)
    }

    fn handle_initialize(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        let result = InitializeResult {
            protocol_version: "2025-06-18".to_string(),
            capabilities: ServerCapabilities {
                tools: Some(serde_json::json!({})),
                resources: None,
                prompts: None,
            },
            server_info: ServerInfo {
                name: self.server_name.clone(),
                version: self.server_version.clone(),
            },
        };
        JsonRpcResponse::success(req.id.clone(), serde_json::to_value(result).unwrap())
    }

    fn handle_tools_list(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        let tools = self.registry.list_tools();
        JsonRpcResponse::success(req.id.clone(), serde_json::json!({ "tools": tools }))
    }

    fn handle_tools_call(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        let params = req.params.as_ref();
        let tool_name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str());

        match tool_name {
            Some(name) => match self.registry.get(name) {
                Some(registered) => match &registered.handler {
                    super::registry::ToolHandlerType::Static(value) => {
                        let result = ToolResult {
                            content: vec![Content::Text {
                                text: serde_json::to_string(value).unwrap_or_default(),
                            }],
                            is_error: false,
                        };
                        JsonRpcResponse::success(
                            req.id.clone(),
                            serde_json::to_value(result).unwrap(),
                        )
                    }
                    super::registry::ToolHandlerType::Proxy { origin } => {
                        // Proxy dispatch would happen here in production.
                        let result = ToolResult {
                            content: vec![Content::Text {
                                text: format!("proxied to {}", origin),
                            }],
                            is_error: false,
                        };
                        JsonRpcResponse::success(
                            req.id.clone(),
                            serde_json::to_value(result).unwrap(),
                        )
                    }
                },
                None => JsonRpcResponse::error(
                    req.id.clone(),
                    INVALID_PARAMS,
                    &format!("tool not found: {}", name),
                ),
            },
            None => JsonRpcResponse::error(req.id.clone(), INVALID_PARAMS, "missing tool name"),
        }
    }
}
