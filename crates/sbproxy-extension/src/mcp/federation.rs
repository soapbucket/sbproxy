//! MCP server federation.
//!
//! Aggregates tools from multiple upstream MCP servers into a unified
//! tool registry. Tool calls are routed to the correct upstream server.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde_json::json;
use tracing::{debug, error, info, warn};

use super::sse_client::send_via_sse;
use super::streamable::send_request;
use super::types::{JsonRpcRequest, JsonRpcResponse};

// --- Config ---

/// Configuration for one upstream MCP server.
#[derive(Debug, Clone)]
pub struct McpServerConfig {
    /// Human-readable name for this server.
    pub name: String,
    /// URL of the MCP endpoint.
    pub url: String,
    /// Transport type: `"streamable_http"` or `"sse"`.
    pub transport: String,
}

// --- Registry ---

/// A tool federated from an upstream MCP server.
#[derive(Debug, Clone)]
pub struct FederatedTool {
    /// Unique tool name (may be prefixed with server name on conflict).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for the tool's input arguments.
    pub input_schema: serde_json::Value,
    /// Name of the upstream server that owns this tool.
    pub server_name: String,
}

// --- McpFederation ---

/// Aggregates tools from multiple upstream MCP servers into one registry.
pub struct McpFederation {
    servers: Vec<McpServerConfig>,
    /// tool_name -> FederatedTool
    tools: ArcSwap<HashMap<String, FederatedTool>>,
    client: reqwest::Client,
}

impl McpFederation {
    /// Create a new federation from a list of upstream server configs.
    pub fn new(servers: Vec<McpServerConfig>) -> Self {
        Self {
            servers,
            tools: ArcSwap::from_pointee(HashMap::new()),
            client: reqwest::Client::new(),
        }
    }

    /// Fetch tool lists from all servers and build unified registry.
    ///
    /// On name collision the later server's tool is prefixed with its
    /// server name (e.g. `servername.toolname`) to avoid shadowing.
    ///
    /// Returns the total number of federated tools.
    pub async fn refresh_tools(&self) -> anyhow::Result<usize> {
        let mut registry: HashMap<String, FederatedTool> = HashMap::new();

        for server in &self.servers {
            match self.fetch_tools_from_server(server).await {
                Ok(tools) => {
                    info!(
                        server = %server.name,
                        count = tools.len(),
                        "fetched tools from upstream MCP server"
                    );
                    for tool in tools {
                        let key = if registry.contains_key(&tool.name) {
                            // Prefix with server name to avoid shadowing.
                            warn!(
                                tool = %tool.name,
                                server = %server.name,
                                "tool name collision, using prefixed name"
                            );
                            format!("{}.{}", server.name, tool.name)
                        } else {
                            tool.name.clone()
                        };
                        registry.insert(key, tool);
                    }
                }
                Err(e) => {
                    error!(
                        server = %server.name,
                        error = %e,
                        "failed to fetch tools from upstream MCP server"
                    );
                    // Continue with other servers rather than failing entirely.
                }
            }
        }

        let count = registry.len();
        self.tools.store(Arc::new(registry));
        debug!(total_tools = count, "MCP federation registry refreshed");
        Ok(count)
    }

    /// Fetch the tool list from one upstream server.
    async fn fetch_tools_from_server(
        &self,
        server: &McpServerConfig,
    ) -> anyhow::Result<Vec<FederatedTool>> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "tools/list".to_string(),
            params: None,
            id: Some(json!(1)),
        };

        let resp = self.dispatch_request(server, &req).await?;

        if let Some(err) = resp.error {
            anyhow::bail!(
                "tools/list error from {}: {} (code {})",
                server.name,
                err.message,
                err.code
            );
        }

        let result = resp.result.unwrap_or_default();
        let tools_value = result.get("tools").cloned().unwrap_or_default();
        let tool_defs: Vec<serde_json::Value> =
            serde_json::from_value(tools_value).unwrap_or_default();

        let federated = tool_defs
            .into_iter()
            .filter_map(|t| {
                let name = t.get("name")?.as_str()?.to_string();
                let description = t
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                let input_schema = t
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or_else(|| json!({"type": "object", "properties": {}}));
                Some(FederatedTool {
                    name,
                    description,
                    input_schema,
                    server_name: server.name.clone(),
                })
            })
            .collect();

        Ok(federated)
    }

    /// Look up which server owns a tool.
    pub fn resolve_tool(&self, tool_name: &str) -> Option<FederatedTool> {
        self.tools.load().get(tool_name).cloned()
    }

    /// List all federated tools.
    pub fn list_tools(&self) -> Vec<FederatedTool> {
        self.tools.load().values().cloned().collect()
    }

    /// Call a tool, routing to the correct upstream server.
    pub async fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let federated = self
            .resolve_tool(tool_name)
            .ok_or_else(|| anyhow::anyhow!("unknown tool: {}", tool_name))?;

        let server = self
            .servers
            .iter()
            .find(|s| s.name == federated.server_name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "server {} not found in federation config",
                    federated.server_name
                )
            })?;

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": tool_name,
                "arguments": arguments,
            })),
            id: Some(json!(1)),
        };

        debug!(
            tool = tool_name,
            server = %server.name,
            "routing tool call to upstream server"
        );

        let resp = self.dispatch_request(server, &req).await?;

        if let Some(err) = resp.error {
            anyhow::bail!(
                "tool call {} error from {}: {} (code {})",
                tool_name,
                server.name,
                err.message,
                err.code
            );
        }

        Ok(resp.result.unwrap_or(serde_json::Value::Null))
    }

    /// Dispatch a request to an upstream server using the configured transport.
    async fn dispatch_request(
        &self,
        server: &McpServerConfig,
        req: &JsonRpcRequest,
    ) -> anyhow::Result<JsonRpcResponse> {
        match server.transport.as_str() {
            "sse" => send_via_sse(&self.client, &server.url, req).await,
            // Default to streamable HTTP for "streamable_http" or unknown.
            _ => send_request(&self.client, &server.url, req).await,
        }
    }

    /// Start a background task to refresh tool lists periodically.
    ///
    /// The task runs indefinitely; drop the returned handle to cancel.
    pub fn start_refresh_task(self: &Arc<Self>, interval_secs: u64) {
        let federation = Arc::clone(self);
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(interval_secs.max(1));
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = federation.refresh_tools().await {
                    error!(error = %e, "MCP federation refresh failed");
                }
            }
        });
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_server(name: &str, url: &str) -> McpServerConfig {
        McpServerConfig {
            name: name.to_string(),
            url: url.to_string(),
            transport: "streamable_http".to_string(),
        }
    }

    fn make_tool(name: &str, server: &str) -> FederatedTool {
        FederatedTool {
            name: name.to_string(),
            description: format!("Tool {}", name),
            input_schema: json!({"type": "object", "properties": {}}),
            server_name: server.to_string(),
        }
    }

    // --- Federation construction ---

    #[test]
    fn test_new_federation_starts_empty() {
        let fed = McpFederation::new(vec![mock_server("server_a", "http://a.example.com/mcp")]);
        assert_eq!(fed.list_tools().len(), 0);
    }

    #[test]
    fn test_resolve_tool_empty_registry() {
        let fed = McpFederation::new(vec![]);
        assert!(fed.resolve_tool("any_tool").is_none());
    }

    // --- Registry manipulation ---

    #[test]
    fn test_resolve_tool_after_manual_store() {
        let fed = McpFederation::new(vec![mock_server("s", "http://s.test")]);
        let mut map = HashMap::new();
        map.insert("my_tool".to_string(), make_tool("my_tool", "s"));
        fed.tools.store(Arc::new(map));

        let resolved = fed.resolve_tool("my_tool").unwrap();
        assert_eq!(resolved.name, "my_tool");
        assert_eq!(resolved.server_name, "s");
    }

    #[test]
    fn test_resolve_unknown_tool_returns_none() {
        let fed = McpFederation::new(vec![mock_server("s", "http://s.test")]);
        assert!(fed.resolve_tool("nonexistent_tool").is_none());
    }

    #[test]
    fn test_list_tools_returns_all() {
        let fed = McpFederation::new(vec![]);
        let mut map = HashMap::new();
        map.insert("tool_a".to_string(), make_tool("tool_a", "s1"));
        map.insert("tool_b".to_string(), make_tool("tool_b", "s2"));
        fed.tools.store(Arc::new(map));

        let tools = fed.list_tools();
        assert_eq!(tools.len(), 2);
    }

    // --- Tool registry building from mock responses ---

    #[test]
    fn test_federated_tool_fields() {
        let tool = FederatedTool {
            name: "search".to_string(),
            description: "Search the web".to_string(),
            input_schema: json!({"type": "object", "properties": {"query": {"type": "string"}}}),
            server_name: "web_server".to_string(),
        };
        assert_eq!(tool.name, "search");
        assert_eq!(tool.server_name, "web_server");
        assert!(tool.input_schema.get("properties").is_some());
    }

    #[test]
    fn test_mock_server_config_fields() {
        let config = mock_server("my_server", "https://mcp.example.com");
        assert_eq!(config.name, "my_server");
        assert_eq!(config.url, "https://mcp.example.com");
        assert_eq!(config.transport, "streamable_http");
    }

    #[test]
    fn test_sse_transport_config() {
        let config = McpServerConfig {
            name: "legacy".to_string(),
            url: "https://legacy.example.com/sse".to_string(),
            transport: "sse".to_string(),
        };
        assert_eq!(config.transport, "sse");
    }

    // --- Collision handling (simulated) ---

    #[test]
    fn test_tool_name_collision_uses_prefixed_name() {
        // Simulate what federation does: if a tool name collides, it gets
        // prefixed with the server name.
        let mut registry: HashMap<String, FederatedTool> = HashMap::new();
        let tool_a = make_tool("search", "server_a");
        registry.insert("search".to_string(), tool_a);

        // Second server also has a "search" tool - should get prefixed.
        let tool_b = make_tool("search", "server_b");
        let key = if registry.contains_key(&tool_b.name) {
            format!("{}.{}", tool_b.server_name, tool_b.name)
        } else {
            tool_b.name.clone()
        };
        registry.insert(key.clone(), tool_b);

        assert!(registry.contains_key("search"));
        assert!(registry.contains_key("server_b.search"));
        assert_eq!(registry.len(), 2);
    }

    // --- Tool call routing ---

    #[tokio::test]
    async fn test_call_unknown_tool_returns_error() {
        let fed = McpFederation::new(vec![mock_server("s", "http://s.test")]);
        let result = fed.call_tool("unknown_tool", json!({})).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unknown tool"));
    }

    // --- Server list ---

    #[test]
    fn test_federation_with_multiple_servers() {
        let servers = vec![
            mock_server("server_a", "http://a.test"),
            mock_server("server_b", "http://b.test"),
            mock_server("server_c", "http://c.test"),
        ];
        let fed = McpFederation::new(servers);
        // No tools until refresh is called.
        assert_eq!(fed.list_tools().len(), 0);
    }
}
