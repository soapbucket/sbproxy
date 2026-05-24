//! MCP discovery manifest (WOR-806).
//!
//! Builds the JSON document SBproxy serves at
//! `/.well-known/mcp-server` (and the Cloudflare Agent-Readiness
//! variant `/.well-known/mcp/server-card.json`) so an autonomous agent
//! can discover the gateway's MCP endpoint, protocol version,
//! transport, and tool catalogue without first opening a JSON-RPC
//! session.
//!
//! This is the inverse of east-west passive discovery (observing
//! `initialize`): here SBproxy *serves* the discovery surface. DNS TXT
//! discovery and progressive (search/execute) tool discovery are
//! tracked as follow-up increments of WOR-806.

/// The two well-known paths that serve the same discovery manifest:
/// the IETF `draft-serra-mcp-discovery-uri` path and the Cloudflare
/// Agent-Readiness server-card path.
pub const SERVER_MANIFEST_PATHS: [&str; 2] = [
    "/.well-known/mcp-server",
    "/.well-known/mcp/server-card.json",
];

/// Content type for the discovery manifest.
pub const SERVER_MANIFEST_CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// A tool entry advertised in the discovery manifest.
#[derive(Debug, Clone)]
pub struct DiscoveryTool {
    /// Tool name as exposed by the gateway (post-prefixing).
    pub name: String,
    /// Human-readable description.
    pub description: String,
}

/// Build the MCP discovery manifest for a gateway.
///
/// - `name` / `version`: the gateway's MCP server identity (the same
///   values returned in an `initialize` response).
/// - `protocol_version`: the MCP protocol version the gateway speaks.
/// - `endpoint`: the absolute URL where JSON-RPC requests are accepted
///   (the gateway root, e.g. `https://mcp.example.com/`).
/// - `tools`: the advertised tool catalogue (already filtered by any
///   `tool_allowlist`).
pub fn build_server_manifest(
    name: &str,
    version: &str,
    protocol_version: &str,
    endpoint: &str,
    tools: &[DiscoveryTool],
) -> serde_json::Value {
    let tool_values: Vec<serde_json::Value> = tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
            })
        })
        .collect();
    serde_json::json!({
        "name": name,
        "version": version,
        "protocolVersion": protocol_version,
        "transport": "streamable-http",
        "endpoint": endpoint,
        "capabilities": { "tools": { "listChanged": false } },
        "tools": tool_values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> DiscoveryTool {
        DiscoveryTool {
            name: name.to_string(),
            description: format!("{name} description"),
        }
    }

    #[test]
    fn manifest_has_identity_endpoint_and_transport() {
        let m = build_server_manifest(
            "sbproxy-mcp",
            "1.0.0",
            "2025-06-18",
            "https://mcp.example.com/",
            &[tool("search"), tool("fetch")],
        );
        assert_eq!(m["name"], "sbproxy-mcp");
        assert_eq!(m["version"], "1.0.0");
        assert_eq!(m["protocolVersion"], "2025-06-18");
        assert_eq!(m["transport"], "streamable-http");
        assert_eq!(m["endpoint"], "https://mcp.example.com/");
        assert!(m["capabilities"]["tools"].is_object());
    }

    #[test]
    fn manifest_lists_advertised_tools() {
        let m = build_server_manifest(
            "g",
            "0.1",
            "2025-06-18",
            "https://h/",
            &[tool("alpha"), tool("beta")],
        );
        let tools = m["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "alpha");
        assert_eq!(tools[1]["name"], "beta");
        assert_eq!(tools[0]["description"], "alpha description");
    }

    #[test]
    fn manifest_is_valid_json_with_no_tools() {
        let m = build_server_manifest("g", "0.1", "2025-06-18", "https://h/", &[]);
        assert!(m["tools"].as_array().unwrap().is_empty());
        // Round-trips through serialization.
        let s = serde_json::to_string(&m).unwrap();
        let back: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back["name"], "g");
    }
}
