//! JSON-RPC 2.0 and MCP protocol types.

use serde::{Deserialize, Serialize};

// --- JSON-RPC 2.0 Error Codes ---

/// JSON-RPC 2.0 parse error: invalid JSON received by the server.
pub const PARSE_ERROR: i32 = -32700;
/// JSON-RPC 2.0 invalid request: payload is not a valid request object.
pub const INVALID_REQUEST: i32 = -32600;
/// JSON-RPC 2.0 method not found: requested method does not exist.
pub const METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC 2.0 invalid params: method parameters are invalid.
pub const INVALID_PARAMS: i32 = -32602;
/// JSON-RPC 2.0 internal error: server encountered an unexpected failure.
pub const INTERNAL_ERROR: i32 = -32603;

// --- Protocol version negotiation (WOR-1641) ---

/// MCP protocol revisions this gateway can serve, newest first. One
/// entry today: `2025-03-26` is deliberately absent because that
/// revision requires servers to accept JSON-RPC batches, which the
/// gateway does not, and advertising a version whose MUSTs we break
/// is the exact capability lie this list exists to prevent.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18"];

/// Newest protocol revision the gateway serves.
pub const LATEST_PROTOCOL_VERSION: &str = SUPPORTED_PROTOCOL_VERSIONS[0];

/// True when the gateway can serve the given protocol revision.
pub fn is_supported_protocol_version(version: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

/// Spec-correct `initialize` negotiation: echo the client's requested
/// revision when the gateway supports it, otherwise answer with the
/// newest revision the gateway does support (the client then decides
/// whether to continue). A missing request defaults to the newest.
pub fn negotiate_protocol_version(requested: Option<&str>) -> &'static str {
    match requested {
        Some(v) => SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .find(|s| **s == v)
            .copied()
            .unwrap_or(LATEST_PROTOCOL_VERSION),
        None => LATEST_PROTOCOL_VERSION,
    }
}

// --- JSON-RPC 2.0 ---

/// JSON-RPC 2.0 request envelope used by all MCP methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC protocol version, always the literal "2.0".
    pub jsonrpc: String,
    /// RPC method name (e.g. "tools/list", "tools/call", "initialize").
    pub method: String,
    /// Method-specific parameters object.
    #[serde(default)]
    pub params: Option<serde_json::Value>,
    /// Request id. `None` indicates a notification with no expected response.
    pub id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response envelope returned from MCP methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC protocol version, always the literal "2.0".
    pub jsonrpc: String,
    /// Successful result payload, mutually exclusive with `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error object populated when the request fails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Echo of the originating request id.
    pub id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 error object returned in the `error` field of a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Numeric error code; see the constants in this module for standard values.
    pub code: i32,
    /// Short human-readable error description.
    pub message: String,
    /// Optional additional data attached to the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    /// Build a successful JSON-RPC 2.0 response with the given result payload.
    pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Build an error JSON-RPC 2.0 response with the given code and message.
    pub fn error(id: Option<serde_json::Value>, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
            id,
        }
    }
}

// --- MCP Types ---

/// An MCP tool definition as returned by "tools/list".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Unique tool identifier referenced by "tools/call".
    pub name: String,
    /// Optional human-readable description of what the tool does.
    pub description: Option<String>,
    /// JSON Schema describing the tool's input parameters.
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
    /// Optional behavioural hints exposed to the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
    /// Opaque `_meta` block per the OpenAI Apps SDK / MCP Apps
    /// (SEP-1865) extension. When an upstream advertises a tool
    /// with a UI template id and version under `_meta`, the
    /// gateway preserves the entire JSON value verbatim so an
    /// Apps-SDK client receives the field unchanged. Base-MCP
    /// clients ignore the unknown key per the MCP spec, so the
    /// graceful-degradation contract is automatic.
    #[serde(default, rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

/// Optional hints about tool behavior.
///
/// Wire spelling is the spec's camelCase (`readOnlyHint`, ...); the
/// snake_case aliases keep annotations from older sbproxy nodes
/// parseable (same interop bug as [`InitializeResult`]).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    /// Hint that the tool does not mutate any state.
    #[serde(default, alias = "read_only_hint")]
    pub read_only_hint: bool,
    /// Hint that the tool may perform destructive operations.
    #[serde(default, alias = "destructive_hint")]
    pub destructive_hint: bool,
    /// Hint that repeated invocations are safe to retry.
    #[serde(default, alias = "idempotent_hint")]
    pub idempotent_hint: bool,
    /// Hint that the tool interacts with an open world (e.g. the public internet).
    #[serde(default, alias = "open_world_hint")]
    pub open_world_hint: bool,
}

/// "tools/call" response result body.
///
/// The wire spelling is the spec's `isError`; strict SDK clients
/// ignore the snake_case `is_error` this struct used to emit, which
/// silently dropped tool error flags. The alias keeps results from
/// older sbproxy nodes and snake_case upstreams parseable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResult {
    /// Ordered list of content blocks returned from the tool.
    pub content: Vec<Content>,
    /// Indicates whether the tool reported an application-level error.
    #[serde(default, alias = "is_error")]
    pub is_error: bool,
}

/// Content block within a tool result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Content {
    /// Plain UTF-8 text content.
    #[serde(rename = "text")]
    Text {
        /// Text payload.
        text: String,
    },
    /// Inline image content encoded as base64 with a mime type.
    #[serde(rename = "image")]
    Image {
        /// Base64-encoded image bytes.
        data: String,
        /// IANA mime type of the image.
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    /// Reference to a resource accessible via its URI.
    #[serde(rename = "resource")]
    Resource {
        /// Resource reference describing the embedded resource.
        resource: ResourceRef,
    },
}

/// Reference to a resource embedded in content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRef {
    /// Fully qualified resource URI.
    pub uri: String,
    /// Optional human-readable name for display.
    pub name: Option<String>,
    /// Optional IANA mime type describing the resource contents.
    #[serde(rename = "mimeType")]
    pub mime_type: Option<String>,
}

/// "resources/list" entry describing a discoverable MCP resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    /// Fully qualified resource URI.
    pub uri: String,
    /// Display name shown to clients.
    pub name: String,
    /// Optional description of the resource.
    pub description: Option<String>,
    /// Optional IANA mime type of the resource contents.
    #[serde(rename = "mimeType")]
    pub mime_type: Option<String>,
}

/// Server capabilities returned in the "initialize" response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Capability descriptor for tool methods, when supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<serde_json::Value>,
    /// Capability descriptor for resource methods, when supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<serde_json::Value>,
    /// Capability descriptor for prompt methods, when supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<serde_json::Value>,
    /// Experimental, non-stable capability descriptors. The Agent
    /// Skills v0.2.0 wiring uses this slot to advertise a manifest
    /// URL via the `agentSkillsUrl` key, so MCP clients that have
    /// learned how to fetch and verify the manifest can discover
    /// skills without out-of-band configuration. Omitted when the
    /// origin does not configure `agent_skills`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<serde_json::Value>,
    /// OpenAI Apps SDK / MCP Apps (SEP-1865) capability. Advertised
    /// (mirrored from any upstream that exposes it) so Apps-SDK
    /// clients know to look for UI templates on tools and to read
    /// resources via `resources/list` + `resources/read`. The exact
    /// JSON shape of this object is opaque to the gateway today: we
    /// pass through whatever the upstream sent so a vendor-specific
    /// sub-key (template ids, cache hints) reaches the client
    /// unchanged. Absent when no upstream advertises it.
    #[serde(default, rename = "mcpApps", skip_serializing_if = "Option::is_none")]
    pub mcp_apps: Option<serde_json::Value>,
}

/// "initialize" response result body.
///
/// Serialized in camelCase: the MCP wire format requires
/// `protocolVersion` and `serverInfo`, and the official SDKs
/// hard-fail the handshake on the snake_case spellings this struct
/// used to emit (found by validating the framework integration docs
/// against a spec-conformant client).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    /// MCP protocol version implemented by the server.
    pub protocol_version: String,
    /// Capabilities advertised by the server.
    pub capabilities: ServerCapabilities,
    /// Server identity information.
    pub server_info: ServerInfo,
}

/// Server identity information returned during initialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Server display name.
    pub name: String,
    /// Server software version string.
    pub version: String,
}

#[cfg(test)]
mod protocol_version_tests {
    use super::*;

    #[test]
    fn negotiation_echoes_supported_version() {
        assert_eq!(
            negotiate_protocol_version(Some(LATEST_PROTOCOL_VERSION)),
            LATEST_PROTOCOL_VERSION
        );
    }

    #[test]
    fn negotiation_falls_back_to_latest_for_unknown() {
        assert_eq!(
            negotiate_protocol_version(Some("2025-03-26")),
            LATEST_PROTOCOL_VERSION
        );
        assert_eq!(
            negotiate_protocol_version(Some("1999-01-01")),
            LATEST_PROTOCOL_VERSION
        );
    }

    #[test]
    fn negotiation_defaults_to_latest_when_missing() {
        assert_eq!(negotiate_protocol_version(None), LATEST_PROTOCOL_VERSION);
    }

    #[test]
    fn supported_check_matches_list() {
        assert!(is_supported_protocol_version("2025-06-18"));
        assert!(!is_supported_protocol_version("2025-03-26"));
        assert!(!is_supported_protocol_version(""));
    }

    #[test]
    fn latest_is_first_in_supported_list() {
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS[0], LATEST_PROTOCOL_VERSION);
        assert!(SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .all(|v| is_supported_protocol_version(v)));
    }
}
