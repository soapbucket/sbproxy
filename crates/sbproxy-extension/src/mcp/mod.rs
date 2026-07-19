//! MCP (Model Context Protocol) handler.
//!
//! Implements a JSON-RPC 2.0 based protocol for exposing tools and resources
//! to LLMs via the Model Context Protocol.
//!
//! ## Modules
//!
//! - [`types`] - Shared JSON-RPC 2.0 and MCP protocol types.
//! - [`streamable`] - Streamable HTTP transport for calling upstream MCP servers.
//! - [`sse_client`] - Legacy SSE transport for calling upstream MCP servers.
//! - [`federation`] - Aggregate tools from multiple upstream servers; the live
//!   gateway dispatch in `sbproxy-core` calls into this.
//! - [`sessions`] - Streamable HTTP session store (`Mcp-Session-Id`).
//! - [`discovery`] - Well-known manifest and RFC 9728 OAuth metadata builders.
//! - [`codemode_ts`] - Cloudflare Code Mode TypeScript module emitter.
//! - [`openapi_convert`] - Convert OpenAPI 3.x specs to MCP tools and routes.
//! - [`rest_to_mcp`] - Expose REST APIs as MCP servers.
//! - [`compat`] - Tool-versioning compatibility oracle.
//! - [`access_control`] - Principal-aware tool ACLs and per-tool quotas.
//! - [`schema_drift`] / [`cassette_drift`] - CI drift detection (drift CLI).
//! - [`egress`] - Deterministic allowlist for gateway-originated traffic.
//! - [`stdio`] - Supervised local stdio MCP transport.

pub mod access_control;
pub mod cassette_drift;
pub mod codemode_ts;
pub mod compat;
pub mod discovery;
pub mod egress;
pub mod federation;
pub mod openapi_convert;
pub mod quarantine;
pub mod rest_to_mcp;
/// Tool rollout plane: multiple live versions of one tool with
/// per-consumer resolution (call `_meta`, session requirements,
/// principal pins, catalogue aliases, default), version routing,
/// adapters, and sunset handling.
pub mod rollout;
/// WOR-486: schema-drift detection for converted MCP servers.
/// Diffs two OpenAPI snapshots and classifies the changes by
/// severity so a CI gate can refuse to regenerate the MCP tool
/// surface on a breaking change without explicit operator
/// opt-in. Consumed by the `sbproxy-mcp-drift` CLI.
pub mod schema_drift;
pub mod sessions;
pub mod sse_client;
pub mod stdio;
pub mod streamable;
pub mod types;

pub use access_control::{
    parse_quota_window, McpPrincipalSelector, QuotaClock, QuotaExceeded, QuotaKey, SystemClock,
    ToolAccessDecision, ToolAccessPolicy, ToolAccessRule, ToolQuotaRate, ToolQuotaRule,
    ToolQuotaStore,
};
pub use cassette_drift::{
    cassette_contract_from_value, diff_cassette_against_tools, diff_cassette_values,
    tools_from_value, CassetteContract, CassetteDriftChange, CassetteDriftEvent, CassetteDriftKind,
    CassetteDriftReport, CassetteFieldContract, CassetteToolContract, CASSETTE_DRIFT_EVENT_TYPE,
};
pub use egress::{EgressDenied, EgressMode, EgressPolicy, SystemHostResolver};
pub use federation::{
    FederatedTool, FederationIoSettings, McpCallOutcome, McpFederation, McpServerConfig,
    NamespaceMode, OpenApiBacking, SerializedToolEntry, SerializedTools, ToolVersioningGate,
    VersioningMode,
};
pub use openapi_convert::{openapi_to_mcp_tools, openapi_to_routes, OpenApiRoute};
pub use rest_to_mcp::{create_mcp_handler, execute_tool_as_rest, RestToMcpConfig};
pub use stdio::{encode_stdio_url, StdioCommand};
pub use types::*;
