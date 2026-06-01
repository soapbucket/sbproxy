//! MCP JSON-RPC request handler.

use super::registry::ToolRegistry;
use super::types::*;

/// Per-origin context the handler reads when answering `initialize`.
///
/// WOR-195 wires the `experimental.agentSkillsUrl` advertisement onto
/// the `initialize` response when the host origin has `agent_skills:`
/// configured. The advertisement is the absolute URL of the origin's
/// `/.well-known/agent-skills/index.json` manifest. Building the URL
/// requires the request authority (Host header) and the proxy's TLS
/// posture (https vs http); both are threaded into [`McpHandler`] via
/// this struct so the handler stays free of any direct Pingora /
/// HTTP dependency.
#[derive(Debug, Clone, Default)]
pub struct InitializeContext {
    /// `true` when the origin has at least one `agent_skills:` entry.
    /// `false` (or unset) suppresses the advertisement entirely so
    /// the field is omitted rather than emitted as null.
    pub has_agent_skills: bool,
    /// Request authority (Host header), e.g. `api.example.com`. Used
    /// to build the absolute manifest URL.
    pub request_authority: Option<String>,
    /// Request scheme, `https` or `http`. The proxy's TLS posture
    /// determines this; the handler does not derive it from spoofable
    /// headers.
    pub request_scheme: String,
}

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
    ///
    /// Advertises Agent Skills via `experimental.agentSkillsUrl` when
    /// the caller passes a non-default [`InitializeContext`] through
    /// [`Self::handle_request_with_context`]. The plain
    /// `handle_request` keeps the historical no-context behaviour for
    /// callers that do not yet thread origin context.
    pub fn handle_request(&self, request: &JsonRpcRequest) -> Option<JsonRpcResponse> {
        self.handle_request_with_context(request, &InitializeContext::default())
    }

    /// Like [`Self::handle_request`] but threads per-origin context for
    /// `initialize` responses. WOR-195: populates
    /// `experimental.agentSkillsUrl` when `ctx.has_agent_skills` is
    /// true; omits the field entirely otherwise.
    pub fn handle_request_with_context(
        &self,
        request: &JsonRpcRequest,
        ctx: &InitializeContext,
    ) -> Option<JsonRpcResponse> {
        // Notifications (no id) get no response.
        request.id.as_ref()?;

        let response = match request.method.as_str() {
            "initialize" => self.handle_initialize(request, ctx),
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

    fn handle_initialize(&self, req: &JsonRpcRequest, ctx: &InitializeContext) -> JsonRpcResponse {
        // WOR-195: when the origin has `agent_skills:` configured,
        // advertise the manifest URL under `experimental.agentSkillsUrl`.
        // The manifest itself filters by visibility (public vs
        // authenticated) at serve time, so the path advertised here is
        // the same regardless of caller identity; anonymous callers
        // simply receive a smaller manifest.
        //
        // TODO: emit `notifications/resources/list_changed`
        // when the manifest regenerates so connected clients refresh
        // automatically. Out of scope for the first ship.
        let experimental = if ctx.has_agent_skills {
            let scheme = if ctx.request_scheme.is_empty() {
                "https"
            } else {
                ctx.request_scheme.as_str()
            };
            let url = match ctx.request_authority.as_deref() {
                Some(auth) => format!("{scheme}://{auth}/.well-known/agent-skills/index.json"),
                // No authority known (defensive fallback): emit the
                // path-only form so a downstream client can still
                // resolve it against whatever transport URL it used.
                None => "/.well-known/agent-skills/index.json".to_string(),
            };
            Some(serde_json::json!({ "agentSkillsUrl": url }))
        } else {
            None
        };

        let result = InitializeResult {
            protocol_version: "2025-06-18".to_string(),
            capabilities: ServerCapabilities {
                tools: Some(serde_json::json!({})),
                resources: None,
                prompts: None,
                experimental,
                // The embedded standalone handler has no federation
                // context and therefore no upstream `mcpApps`
                // capability to mirror. The federation-aware
                // dispatcher in sbproxy-core advertises it when an
                // upstream supports SEP-1865.
                mcp_apps: None,
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
        let start = std::time::Instant::now();
        let params = req.params.as_ref();
        let tool_name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str());

        let (response, result_label, metric_tool) = match tool_name {
            Some(name) => match self.registry.get(name) {
                Some(registered) => match &registered.handler {
                    super::registry::ToolHandlerType::Static(value) => {
                        let result = ToolResult {
                            content: vec![Content::Text {
                                text: serde_json::to_string(value).unwrap_or_default(),
                            }],
                            is_error: false,
                        };
                        (
                            JsonRpcResponse::success(
                                req.id.clone(),
                                serde_json::to_value(result).unwrap(),
                            ),
                            "ok",
                            name.to_string(),
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
                        (
                            JsonRpcResponse::success(
                                req.id.clone(),
                                serde_json::to_value(result).unwrap(),
                            ),
                            "ok",
                            name.to_string(),
                        )
                    }
                },
                None => (
                    JsonRpcResponse::error(
                        req.id.clone(),
                        INVALID_PARAMS,
                        &format!("tool not found: {}", name),
                    ),
                    "tool_not_found",
                    name.to_string(),
                ),
            },
            None => (
                JsonRpcResponse::error(req.id.clone(), INVALID_PARAMS, "missing tool name"),
                "tool_not_found",
                "__missing__".to_string(),
            ),
        };
        let elapsed = start.elapsed().as_secs_f64();
        sbproxy_observe::metrics::record_mcp_tool_dispatch(&metric_tool, result_label, elapsed);
        response
    }
}
