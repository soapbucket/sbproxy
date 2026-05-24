//! MCP server federation.
//!
//! Aggregates tools from multiple upstream MCP servers into a unified
//! tool registry. Tool calls are routed to the correct upstream server.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use sbproxy_plugin::mcp::{default_no_op_hook, mcp_policy_hooks, McpPolicyHook, McpToolCallCtx};
use sbproxy_plugin::traits::PolicyDecision;
use serde_json::json;
use tracing::{debug, error, info, warn};

use super::sse_client::send_via_sse;
use super::streamable::send_request;
use super::types::{JsonRpcRequest, JsonRpcResponse};

/// Outcome of [`McpFederation::call_tool_with_policy`].
///
/// Mirrors the shape the JSON-RPC dispatcher in `sbproxy-core::server`
/// already understands: an `Allow` returns the upstream's result, a
/// `Deny` returns a JSON-RPC error code (`-32603`) and a message, and
/// the caller is responsible for wrapping either into a
/// [`JsonRpcResponse`]. Returning a dedicated outcome (rather than a
/// flat `Result`) keeps the deny path observable without forcing every
/// future hook addition to invent a fresh error string.
#[derive(Debug, Clone)]
pub enum McpCallOutcome {
    /// Policy permitted the call; the upstream returned this result.
    Allowed(serde_json::Value),
    /// Policy blocked the call. The caller emits a JSON-RPC error with
    /// the carried message; the upstream was never contacted.
    DeniedByPolicy {
        /// JSON-RPC error code to surface. PR β always emits
        /// [`INTERNAL_ERROR`](super::types::INTERNAL_ERROR) (`-32603`).
        code: i32,
        /// Human-readable deny reason returned in the JSON-RPC error
        /// message.
        message: String,
    },
}

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
    /// True when the upstream signalled that this tool returns a stream
    /// of chunks rather than a single response value. The codemode TS
    /// emitter renders streaming tools with an `AsyncIterable<Output>`
    /// signature so agents can `for await` over the response. Recognised
    /// signals (any one is enough): a top-level `streaming: true` boolean
    /// on the tool definition, the Speakeasy-style `x-streaming: true`
    /// extension, or an `outputContentType` of `text/event-stream` or
    /// `application/x-ndjson`.
    pub streaming: bool,
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
                let streaming = tool_advertises_streaming(&t);
                Some(FederatedTool {
                    name,
                    description,
                    input_schema,
                    server_name: server.name.clone(),
                    streaming,
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

    /// Emit a Cloudflare-Code-Mode-compatible TypeScript
    /// module covering every federated tool currently in the
    /// registry.
    ///
    /// `callback_base_url` is the URL the emitted module uses to
    /// reach the gateway for each tool call (the runtime stub posts
    /// to `{callback_base_url}/call/{tool}`). Pass the gateway's
    /// `/.well-known/mcp` base if you serve this module at the
    /// gateway itself.
    ///
    /// The tools are returned in lexicographic order so the
    /// emitted module is reproducible across calls. Operators that
    /// depend on byte-stability for Etag computation can hash the
    /// returned string.
    pub fn codemode_ts(&self, callback_base_url: &str) -> String {
        let mut tools: Vec<FederatedTool> = self.tools.load().values().cloned().collect();
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        super::codemode_ts::emit_codemode_ts(&tools, callback_base_url)
    }

    /// Call a tool, routing to the correct upstream server.
    ///
    /// Backward-compatible wrapper around
    /// [`Self::call_tool_with_policy`] for callers that have not yet
    /// threaded the agent identity / workspace / correlation context
    /// through. The hook still runs against the empty defaults, so an
    /// enterprise hook that policies on the tool name alone still
    /// fires; hooks that require an agent id observe `None` and treat
    /// the call as anonymous.
    pub async fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        match self
            .call_tool_with_policy(tool_name, arguments, None, "", "")
            .await?
        {
            McpCallOutcome::Allowed(value) => Ok(value),
            McpCallOutcome::DeniedByPolicy { code, message } => {
                anyhow::bail!(
                    "tool call {} denied by mcp policy hook: {} (code {})",
                    tool_name,
                    message,
                    code
                );
            }
        }
    }

    /// Call a tool, running the registered [`McpPolicyHook`] before
    /// forwarding to the upstream.
    ///
    /// `agent_id`, `correlation_id`, and `workspace_id` are threaded
    /// through to the hook so multi-tenant policy dispatchers can scope
    /// their lookups. Empty strings (for `correlation_id` /
    /// `workspace_id`) and `None` (for `agent_id`) are the documented
    /// "unset" sentinels.
    ///
    /// PR β policy verdict semantics (mirrored in the
    /// [`sbproxy_plugin::mcp`] rustdoc):
    ///
    /// - [`PolicyDecision::Allow`] / [`PolicyDecision::AllowWithHeaders`]:
    ///   forward to the upstream. The header list on
    ///   `AllowWithHeaders` is dropped because JSON-RPC has no response
    ///   header surface; PR γ will route those headers through the
    ///   `_meta` field once the verdict combiner lands.
    /// - [`PolicyDecision::Deny`]: short-circuit with
    ///   [`McpCallOutcome::DeniedByPolicy`] carrying the deny message.
    ///   The upstream is never contacted.
    /// - [`PolicyDecision::Confirm`]: temporarily treated as `Deny`
    ///   pending the `PendingConfirmStore` work in PR ζ. The verdict is
    ///   still labelled `confirm` on the
    ///   `sbproxy_mcp_policy_hook_invocations_total` metric so the
    ///   future migration is observable. Future cleanup: replace this
    ///   branch with a call into `PendingConfirmStore::park`.
    ///
    /// PR β walks registered hooks in registration order and takes the
    /// first non-Allow verdict; an all-Allow chain forwards as if no
    /// hook had run. PR γ will replace this with a verdict combiner
    /// that aggregates across every registered hook (intersection of
    /// Allows, union of Denies, queue Confirms behind one another).
    /// When no hooks are registered the federation falls through to
    /// the [`default_no_op_hook`] and `Allow` is always returned.
    pub async fn call_tool_with_policy(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        agent_id: Option<&str>,
        correlation_id: &str,
        workspace_id: &str,
    ) -> anyhow::Result<McpCallOutcome> {
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

        // PR β: walk registered policy hooks in registration order
        // and take the first non-Allow verdict. With at most one
        // enterprise hook installed (the default until PR γ lands the
        // verdict combiner), this collapses to "call the first hook
        // and use its verdict". When every hook returns Allow we still
        // forward, which matches the no-hook-installed case where the
        // OSS default no-op produces Allow. When no hooks are
        // registered at all, the federation falls through to the
        // [`default_no_op_hook`] and Allow is returned.
        let hooks = registered_hooks_or_default();
        let verdict = {
            let mut chosen = PolicyDecision::Allow;
            for hook in &hooks {
                let ctx = McpToolCallCtx {
                    agent_id,
                    mcp_server: server.name.as_str(),
                    tool_name,
                    arguments: &arguments,
                    correlation_id,
                    workspace_id,
                };
                let v = hook.evaluate(ctx).await;
                if !matches!(v, PolicyDecision::Allow) {
                    chosen = v;
                    break;
                }
            }
            chosen
        };

        match verdict {
            PolicyDecision::Allow | PolicyDecision::AllowWithHeaders { .. } => {
                sbproxy_observe::metrics::record_mcp_policy_hook_invocation(
                    "allow",
                    server.name.as_str(),
                    tool_name,
                );
            }
            PolicyDecision::Deny { message, .. } => {
                sbproxy_observe::metrics::record_mcp_policy_hook_invocation(
                    "deny",
                    server.name.as_str(),
                    tool_name,
                );
                debug!(
                    tool = tool_name,
                    server = %server.name,
                    reason = %message,
                    "MCP tool call denied by policy hook"
                );
                return Ok(McpCallOutcome::DeniedByPolicy {
                    code: super::types::INTERNAL_ERROR,
                    message,
                });
            }
            PolicyDecision::Confirm { reason, .. } => {
                // PR β temporary: treat Confirm as Deny until the
                // PendingConfirmStore (PR ζ) is wired. Verdict label
                // stays "confirm" so dashboards can spot when the
                // store eventually flips the path live.
                sbproxy_observe::metrics::record_mcp_policy_hook_invocation(
                    "confirm",
                    server.name.as_str(),
                    tool_name,
                );
                debug!(
                    tool = tool_name,
                    server = %server.name,
                    reason = %reason,
                    "MCP tool call held by policy hook; PR β denies pending PendingConfirmStore"
                );
                return Ok(McpCallOutcome::DeniedByPolicy {
                    code: super::types::INTERNAL_ERROR,
                    message: format!("confirmation required: {}", reason),
                });
            }
        }

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

        Ok(McpCallOutcome::Allowed(
            resp.result.unwrap_or(serde_json::Value::Null),
        ))
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

/// Detect whether an upstream MCP `tools/list` entry advertises a
/// streaming response. The MCP spec does not pin the streaming
/// signal yet, so the federation recognises three conventions any
/// one of which is enough:
///
/// 1. A top-level `streaming: true` boolean on the tool definition,
///    matching the shape `@cloudflare/codemode` v0.2.1 emits.
/// 2. An `x-streaming: true` extension, matching the Speakeasy
///    annotation style.
/// 3. An `outputContentType` (or `output_content_type` snake-case
///    alias) of `text/event-stream` or `application/x-ndjson`,
///    derived from the upstream's declared response media type.
fn tool_advertises_streaming(tool: &serde_json::Value) -> bool {
    if tool.get("streaming").and_then(|v| v.as_bool()) == Some(true) {
        return true;
    }
    if tool.get("x-streaming").and_then(|v| v.as_bool()) == Some(true) {
        return true;
    }
    let content_type = tool
        .get("outputContentType")
        .or_else(|| tool.get("output_content_type"))
        .and_then(|v| v.as_str());
    matches!(
        content_type,
        Some("text/event-stream") | Some("application/x-ndjson")
    )
}

/// Return the registered policy hooks, or a single-element list with
/// the default no-op hook when nothing is registered.
///
/// PR β walks this list and takes the first non-Allow verdict. PR γ
/// will replace this iteration with a verdict combiner that aggregates
/// every hook's output. Falling through to [`default_no_op_hook`] when
/// no hooks register keeps the OSS-only build returning
/// [`PolicyDecision::Allow`] for every tool call.
fn registered_hooks_or_default() -> Vec<Arc<dyn McpPolicyHook>> {
    let hooks = mcp_policy_hooks();
    if hooks.is_empty() {
        vec![default_no_op_hook()]
    } else {
        hooks
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
            streaming: false,
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

    // --- WOR-410: codemode.ts emission against the federation ---

    #[test]
    fn wor_410_codemode_ts_includes_every_federated_tool() {
        let fed = McpFederation::new(vec![]);
        let mut map = HashMap::new();
        map.insert(
            "search_docs".to_string(),
            FederatedTool {
                name: "search_docs".to_string(),
                description: "Search documentation".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"]
                }),
                server_name: "docs".to_string(),
                streaming: false,
            },
        );
        map.insert(
            "open_pr".to_string(),
            FederatedTool {
                name: "open_pr".to_string(),
                description: "Open a pull request".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "draft": {"type": "boolean"}
                    },
                    "required": ["title"]
                }),
                server_name: "gh".to_string(),
                streaming: false,
            },
        );
        fed.tools.store(Arc::new(map));

        let out = fed.codemode_ts("https://gw.example/.well-known/mcp");
        assert!(out.contains("export interface SearchDocsInput"));
        assert!(out.contains("export interface OpenPrInput"));
        assert!(out.contains("search_docs:"));
        assert!(out.contains("open_pr:"));
        assert!(out.contains("https://gw.example/.well-known/mcp/call/"));
    }

    #[test]
    fn wor_410_codemode_ts_is_reproducible_across_calls() {
        // Tools sort lexicographically before emission so a hash of
        // the output stays stable as long as the registry does.
        let fed = McpFederation::new(vec![]);
        let mut map = HashMap::new();
        map.insert("z_tool".to_string(), make_tool("z_tool", "s"));
        map.insert("a_tool".to_string(), make_tool("a_tool", "s"));
        fed.tools.store(Arc::new(map));

        let a = fed.codemode_ts("http://x");
        let b = fed.codemode_ts("http://x");
        assert_eq!(a, b);

        // a_tool must appear before z_tool in the namespace block.
        let idx_a = a.find("a_tool:").expect("a_tool present");
        let idx_z = a.find("z_tool:").expect("z_tool present");
        assert!(idx_a < idx_z);
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
            streaming: false,
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

    // --- WOR-487: streaming detection ---

    #[test]
    fn tool_advertises_streaming_via_top_level_flag() {
        let t = json!({"name": "stream", "streaming": true});
        assert!(tool_advertises_streaming(&t));
    }

    #[test]
    fn tool_advertises_streaming_via_x_streaming_extension() {
        let t = json!({"name": "stream", "x-streaming": true});
        assert!(tool_advertises_streaming(&t));
    }

    #[test]
    fn tool_advertises_streaming_via_event_stream_content_type() {
        let t = json!({"name": "stream", "outputContentType": "text/event-stream"});
        assert!(tool_advertises_streaming(&t));
    }

    #[test]
    fn tool_advertises_streaming_via_ndjson_content_type() {
        let t = json!({"name": "stream", "output_content_type": "application/x-ndjson"});
        assert!(tool_advertises_streaming(&t));
    }

    #[test]
    fn tool_not_streaming_by_default() {
        let t = json!({"name": "plain"});
        assert!(!tool_advertises_streaming(&t));
    }

    #[test]
    fn tool_streaming_false_is_not_streaming() {
        let t = json!({"name": "plain", "streaming": false});
        assert!(!tool_advertises_streaming(&t));
    }

    #[test]
    fn tool_unrelated_content_type_is_not_streaming() {
        let t = json!({"name": "plain", "outputContentType": "application/json"});
        assert!(!tool_advertises_streaming(&t));
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

    // --- WOR-152 PR β: policy hook integration ---
    //
    // These tests register hooks via `register_mcp_policy_hook` rather
    // than `inventory::submit!`. Inventory entries cannot be removed,
    // which would make the tests order-dependent; the runtime registry
    // sits behind the inventory feed and only fires when the
    // inventory-registered hook (if any) doesn't already short-circuit
    // the call. The hooks below scope themselves to a unique
    // `correlation_id` so they only ever match the test that installed
    // them, even when the binary runs them in parallel.

    use sbproxy_plugin::mcp::{register_mcp_policy_hook, McpPolicyHook, McpToolCallCtx};
    use sbproxy_plugin::traits::PolicyDecision;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex as StdMutex;

    /// One observed call: `(agent_id, mcp_server, tool_name,
    /// correlation_id, workspace_id)`.
    type ObservedCall = (Option<String>, String, String, String, String);

    /// Hook that only acts when `correlation_id` matches the configured
    /// value. Every other call falls through to `Allow` so concurrent
    /// tests with different correlation ids cannot collide.
    struct ScopedHook {
        match_correlation: &'static str,
        verdict: PolicyDecision,
        observed: Arc<StdMutex<Vec<ObservedCall>>>,
    }

    impl McpPolicyHook for ScopedHook {
        fn evaluate<'a>(
            &'a self,
            ctx: McpToolCallCtx<'a>,
        ) -> Pin<Box<dyn Future<Output = PolicyDecision> + Send + 'a>> {
            if ctx.correlation_id == self.match_correlation {
                self.observed.lock().unwrap().push((
                    ctx.agent_id.map(str::to_string),
                    ctx.mcp_server.to_string(),
                    ctx.tool_name.to_string(),
                    ctx.correlation_id.to_string(),
                    ctx.workspace_id.to_string(),
                ));
                let v = self.verdict.clone();
                Box::pin(async move { v })
            } else {
                Box::pin(async move { PolicyDecision::Allow })
            }
        }
    }

    /// Build a federation pre-loaded with one tool so resolution
    /// succeeds. The URL is an unrouteable port on 127.0.0.1 so the
    /// only way the call can succeed is the policy hook short-circuiting
    /// before `dispatch_request` fires.
    fn fed_with_tool(server: &str, tool: &str) -> McpFederation {
        let fed = McpFederation::new(vec![mock_server(
            server,
            "http://127.0.0.1:1/never-reached",
        )]);
        let mut map = HashMap::new();
        map.insert(tool.to_string(), make_tool(tool, server));
        fed.tools.store(Arc::new(map));
        fed
    }

    /// Deny short-circuits the call. The upstream is never contacted,
    /// so even though the server URL is unrouteable, the call returns
    /// a `DeniedByPolicy` outcome carrying the hook's message. Pins
    /// the contract that a Deny verdict never reaches `dispatch_request`.
    #[tokio::test]
    async fn deny_short_circuits_before_upstream() {
        let corr = "wor152-beta-deny-test";
        let observed = Arc::new(StdMutex::new(Vec::new()));
        register_mcp_policy_hook(Arc::new(ScopedHook {
            match_correlation: corr,
            verdict: PolicyDecision::Deny {
                status: 403,
                message: "policy hook denied the call".to_string(),
            },
            observed: observed.clone(),
        }));

        let fed = fed_with_tool("deny-server", "deny-tool");
        let out = fed
            .call_tool_with_policy(
                "deny-tool",
                json!({"q": "hi"}),
                Some("agent-x"),
                corr,
                "ws-1",
            )
            .await
            .expect("call_tool_with_policy must succeed when the hook denies");

        match out {
            McpCallOutcome::DeniedByPolicy { code, message } => {
                assert_eq!(code, super::super::types::INTERNAL_ERROR);
                assert!(
                    message.contains("policy hook denied"),
                    "deny reason must round-trip into the outcome, got {message}"
                );
            }
            McpCallOutcome::Allowed(_) => panic!("expected DeniedByPolicy, got Allowed"),
        }

        let observed = observed.lock().unwrap().clone();
        assert_eq!(observed.len(), 1, "hook must have run exactly once");
        let (aid, server, tool, c_id, ws) = &observed[0];
        assert_eq!(aid.as_deref(), Some("agent-x"));
        assert_eq!(server, "deny-server");
        assert_eq!(tool, "deny-tool");
        assert_eq!(c_id, corr);
        assert_eq!(ws, "ws-1");
    }

    /// Allow lets the call continue to the upstream. The upstream URL
    /// here is unrouteable, so the dispatch must fail with a network
    /// error rather than a `DeniedByPolicy` outcome. The failure mode
    /// pins that Allow does NOT short-circuit; only Deny does. The
    /// hook also observes the exact `(agent_id, mcp_server, tool_name)`
    /// values it should have received.
    #[tokio::test]
    async fn allow_reaches_upstream_dispatch() {
        let corr = "wor152-beta-allow-test";
        let observed = Arc::new(StdMutex::new(Vec::new()));
        register_mcp_policy_hook(Arc::new(ScopedHook {
            match_correlation: corr,
            verdict: PolicyDecision::Allow,
            observed: observed.clone(),
        }));

        let fed = fed_with_tool("allow-server", "allow-tool");
        let result = fed
            .call_tool_with_policy(
                "allow-tool",
                json!({"k": "v"}),
                Some("agent-allow"),
                corr,
                "ws-allow",
            )
            .await;

        // Allow falls through to dispatch. The unrouteable URL produces
        // a transport error; that error path is what proves the hook
        // did not short-circuit the request.
        assert!(
            result.is_err(),
            "Allow must reach the upstream dispatch, which fails on the unrouteable test URL"
        );

        let observed = observed.lock().unwrap().clone();
        assert_eq!(observed.len(), 1, "hook must have run exactly once");
        let (aid, server, tool, _c_id, _ws) = &observed[0];
        assert_eq!(
            aid.as_deref(),
            Some("agent-allow"),
            "hook must receive the agent_id the federation passed"
        );
        assert_eq!(
            server, "allow-server",
            "hook must receive the resolved upstream MCP server name"
        );
        assert_eq!(
            tool, "allow-tool",
            "hook must receive the requested tool name"
        );
    }

    /// Confirm is temporarily treated as Deny (PR β semantics, pending
    /// the PendingConfirmStore in PR ζ). Pins the documented temporary
    /// behaviour so the migration is observable when PR ζ flips it.
    #[tokio::test]
    async fn confirm_is_treated_as_deny_until_pending_store_lands() {
        let corr = "wor152-beta-confirm-test";
        register_mcp_policy_hook(Arc::new(ScopedHook {
            match_correlation: corr,
            verdict: PolicyDecision::confirm("approval required for prod write", None, None),
            observed: Arc::new(StdMutex::new(Vec::new())),
        }));

        let fed = fed_with_tool("confirm-server", "confirm-tool");
        let out = fed
            .call_tool_with_policy("confirm-tool", json!({}), None, corr, "")
            .await
            .expect("Confirm must produce a clean outcome, not a network error");

        match out {
            McpCallOutcome::DeniedByPolicy { code, message } => {
                assert_eq!(code, super::super::types::INTERNAL_ERROR);
                assert!(
                    message.contains("approval required for prod write"),
                    "Confirm reason must round-trip into the deny message, got {message}"
                );
            }
            McpCallOutcome::Allowed(_) => {
                panic!("Confirm must currently produce DeniedByPolicy (PR β)")
            }
        }
    }

    /// With no enterprise hook registered, the OSS-only build falls
    /// through to `default_no_op_hook` and Allow is always returned.
    /// We use an `unknown_tool` so the call fails on tool resolution
    /// rather than on transport; that lets us pin "no hook short-circuit"
    /// without spawning a mock upstream.
    #[tokio::test]
    async fn unregistered_hook_falls_through_to_no_op_allow() {
        // Use a never-matched correlation_id so any hook a previous
        // test registered does not fire. The default no-op hook should
        // be the only one whose verdict counts.
        let corr = "wor152-beta-noop-test-unique-cid";

        let fed = fed_with_tool("nohook-server", "nohook-tool");
        // The hook (whichever fires) sees the inputs we pass and
        // returns Allow. Allow then runs dispatch, which fails on the
        // unrouteable URL. The transport error message must NOT
        // mention "denied by mcp policy hook"; that string only
        // appears on the Deny path.
        let result = fed
            .call_tool_with_policy("nohook-tool", json!({}), None, corr, "")
            .await;
        let err = result.expect_err("the unrouteable upstream must fail dispatch");
        let msg = err.to_string();
        assert!(
            !msg.contains("denied by mcp policy hook"),
            "no-op hook must not produce a deny path, got {msg}"
        );
    }
}
