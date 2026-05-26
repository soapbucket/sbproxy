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
//! `initialize`): here SBproxy *serves* the discovery surface. The
//! manifest also advertises the recommended DNS TXT record
//! (`_mcp.{domain}`) an operator publishes for resolver-based
//! discovery; see [`build_dns_txt_record`].

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
    authorization: Option<serde_json::Value>,
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
    let mut doc = serde_json::json!({
        "name": name,
        "version": version,
        "protocolVersion": protocol_version,
        "transport": "streamable-http",
        "endpoint": endpoint,
        "capabilities": { "tools": { "listChanged": false } },
        "tools": tool_values,
    });
    // DNS-based discovery hint (WOR-806): advertise the recommended
    // `_mcp.{domain}` TXT record an operator publishes so a
    // resolver-based agent can locate this manifest without a
    // well-known probe. SBproxy serves HTTP, not DNS, so it emits the
    // canonical record rather than publishing it.
    if let Some(host) = host_from_endpoint(endpoint) {
        let (record, value) = build_dns_txt_record(host);
        if let Some(obj) = doc.as_object_mut() {
            obj.insert(
                "dnsDiscovery".to_string(),
                serde_json::json!({ "record": record, "value": value }),
            );
        }
    }
    // RFC 9728 auth discovery pointer (WOR-806): when the gateway is
    // OAuth-protected, advertise where to find the protected-resource
    // metadata so an agent can discover its authorization server.
    if let (Some(auth), Some(obj)) = (authorization, doc.as_object_mut()) {
        obj.insert("authorization".to_string(), auth);
    }
    doc
}

/// Build the recommended MCP DNS-discovery TXT record for `domain`
/// (draft-morrison-mcp-dns-discovery style).
///
/// Returns the record name (`_mcp.{domain}`) and its value, which points
/// a resolver-based agent at the gateway's `/.well-known/mcp-server`
/// discovery manifest over HTTPS. The value uses the `v=mcp1; uri=...`
/// shape, mirroring the `_dmarc` / `_mta-sts` TXT conventions. SBproxy
/// serves HTTP, not DNS, so it emits the canonical record for an operator
/// to publish in their zone rather than publishing it itself.
pub fn build_dns_txt_record(domain: &str) -> (String, String) {
    let name = format!("_mcp.{domain}");
    let value = format!("v=mcp1; uri=https://{domain}/.well-known/mcp-server");
    (name, value)
}

/// Extract the host (no scheme, port, or path) from an absolute endpoint
/// URL such as `https://mcp.example.com:8443/`. Returns `None` when the
/// endpoint has no parseable host.
fn host_from_endpoint(endpoint: &str) -> Option<&str> {
    let after_scheme = endpoint.split("://").nth(1).unwrap_or(endpoint);
    let host_port = after_scheme.split('/').next().unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Well-known path for RFC 9728 OAuth 2.0 Protected Resource Metadata.
pub const OAUTH_PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";

/// Build an RFC 9728 OAuth 2.0 Protected Resource Metadata document for
/// an OAuth-protected MCP gateway (WOR-806).
///
/// `resource` is the gateway's canonical URL; `authorization_servers`
/// lists the issuer URLs a client can obtain a token from;
/// `scopes_supported` is optional. `bearer_methods_supported` is fixed
/// to `["header"]` (the MCP transport carries the bearer in the
/// `Authorization` header).
pub fn build_oauth_protected_resource(
    resource: &str,
    authorization_servers: &[String],
    scopes_supported: &[String],
) -> serde_json::Value {
    let mut doc = serde_json::json!({
        "resource": resource,
        "authorization_servers": authorization_servers,
        "bearer_methods_supported": ["header"],
    });
    if !scopes_supported.is_empty() {
        if let Some(obj) = doc.as_object_mut() {
            obj.insert(
                "scopes_supported".to_string(),
                serde_json::Value::Array(
                    scopes_supported
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }
    }
    doc
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
            None,
        );
        assert_eq!(m["name"], "sbproxy-mcp");
        assert_eq!(m["version"], "1.0.0");
        assert_eq!(m["protocolVersion"], "2025-06-18");
        assert_eq!(m["transport"], "streamable-http");
        assert_eq!(m["endpoint"], "https://mcp.example.com/");
        assert!(m["capabilities"]["tools"].is_object());
        // No authorization block when not OAuth-protected.
        assert!(m.get("authorization").is_none());
    }

    #[test]
    fn manifest_lists_advertised_tools() {
        let m = build_server_manifest(
            "g",
            "0.1",
            "2025-06-18",
            "https://h/",
            &[tool("alpha"), tool("beta")],
            None,
        );
        let tools = m["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "alpha");
        assert_eq!(tools[1]["name"], "beta");
        assert_eq!(tools[0]["description"], "alpha description");
    }

    #[test]
    fn manifest_is_valid_json_with_no_tools() {
        let m = build_server_manifest("g", "0.1", "2025-06-18", "https://h/", &[], None);
        assert!(m["tools"].as_array().unwrap().is_empty());
        // Round-trips through serialization.
        let s = serde_json::to_string(&m).unwrap();
        let back: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back["name"], "g");
    }

    #[test]
    fn manifest_carries_authorization_pointer_when_present() {
        let auth = serde_json::json!({
            "type": "oauth2",
            "resourceMetadata": "https://h/.well-known/oauth-protected-resource"
        });
        let m = build_server_manifest("g", "0.1", "2025-06-18", "https://h/", &[], Some(auth));
        assert_eq!(m["authorization"]["type"], "oauth2");
        assert_eq!(
            m["authorization"]["resourceMetadata"],
            "https://h/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn oauth_protected_resource_has_required_rfc9728_fields() {
        let doc = build_oauth_protected_resource(
            "https://mcp.example.com/",
            &["https://issuer.example.com".to_string()],
            &["mcp.read".to_string(), "mcp.call".to_string()],
        );
        assert_eq!(doc["resource"], "https://mcp.example.com/");
        assert_eq!(
            doc["authorization_servers"][0],
            "https://issuer.example.com"
        );
        assert_eq!(doc["bearer_methods_supported"][0], "header");
        assert_eq!(doc["scopes_supported"][0], "mcp.read");
    }

    #[test]
    fn oauth_protected_resource_omits_empty_scopes() {
        let doc = build_oauth_protected_resource("https://h/", &["https://i".to_string()], &[]);
        assert!(doc.get("scopes_supported").is_none());
        assert!(doc["authorization_servers"].is_array());
    }

    #[test]
    fn dns_txt_record_points_at_well_known_manifest() {
        let (record, value) = build_dns_txt_record("mcp.example.com");
        assert_eq!(record, "_mcp.mcp.example.com");
        assert_eq!(
            value,
            "v=mcp1; uri=https://mcp.example.com/.well-known/mcp-server"
        );
    }

    #[test]
    fn manifest_advertises_dns_discovery_record_stripping_port_and_path() {
        let m = build_server_manifest(
            "g",
            "0.1",
            "2025-06-18",
            "https://mcp.example.com:8443/mcp",
            &[],
            None,
        );
        assert_eq!(m["dnsDiscovery"]["record"], "_mcp.mcp.example.com");
        assert_eq!(
            m["dnsDiscovery"]["value"],
            "v=mcp1; uri=https://mcp.example.com/.well-known/mcp-server"
        );
    }

    #[test]
    fn host_parsing_returns_none_for_hostless_endpoint() {
        assert_eq!(host_from_endpoint("https://"), None);
        assert_eq!(
            host_from_endpoint("mcp.example.com/"),
            Some("mcp.example.com")
        );
    }
}
