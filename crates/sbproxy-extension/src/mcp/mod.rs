//! MCP (Model Context Protocol) handler.
//!
//! Implements a JSON-RPC 2.0 based protocol for exposing tools and resources
//! to LLMs via the Model Context Protocol.
//!
//! ## Modules
//!
//! - [`handler`] - JSON-RPC 2.0 request dispatcher for an embedded MCP server.
//! - [`registry`] - Tool registry used by the embedded server.
//! - [`types`] - Shared JSON-RPC 2.0 and MCP protocol types.
//! - [`streamable`] - Streamable HTTP transport for calling upstream MCP servers.
//! - [`sse_client`] - Legacy SSE transport for calling upstream MCP servers.
//! - [`federation`] - Aggregate tools from multiple upstream servers.
//! - [`audit`] - Structured audit log for every tool invocation.
//! - [`code_mode`] - Compress tool schemas to reduce token usage.
//! - [`openapi_convert`] - Convert OpenAPI 3.x specs to MCP tool definitions.
//! - [`guardrails`] - Safety controls for MCP tool invocations.
//! - [`context_opt`] - Optimize context window usage by prioritising frequently-used tools.
//! - [`rest_to_mcp`] - Expose REST APIs as MCP servers.
//! - [`verify_before_commit`] - VIGIL-pattern verify-before-commit checks for tool calls.
//! - [`cassette_drift`] - Compare mcptest cassette contracts against live `tools/list`.

pub mod access_control;
pub mod apps_validators;
pub mod audit;
pub mod cassette_drift;
pub mod code_mode;
pub mod codemode_from_openapi;
pub mod codemode_ts;
pub mod context_opt;
pub mod discovery;
/// WOR-507: east-west MCP federation discovery via passive
/// `initialize` observation. Builds an inventory of every MCP
/// server an agent has reached and emits a drift event when a
/// server's advertised tool list changes.
pub mod discovery_inventory;
pub mod federation;
pub mod guardrails;
pub mod handler;
pub mod openapi_convert;
pub mod registry;
pub mod rest_to_mcp;
/// WOR-486: schema-drift detection for converted MCP servers.
/// Diffs two OpenAPI snapshots and classifies the changes by
/// severity so a CI gate can refuse to regenerate the MCP tool
/// surface on a breaking change without explicit operator
/// opt-in. Consumed by the `sbproxy-mcp-drift` CLI.
pub mod schema_drift;
pub mod spans;
pub mod sse_client;
pub mod streamable;
pub mod types;
pub mod verify_before_commit;

pub use access_control::{
    parse_quota_window, McpPrincipalSelector, QuotaClock, QuotaExceeded, QuotaKey, SystemClock,
    ToolAccessDecision, ToolAccessPolicy, ToolAccessRule, ToolQuotaRate, ToolQuotaRule,
    ToolQuotaStore,
};
pub use audit::{McpAuditBuilder, McpAuditEntry};
pub use cassette_drift::{
    cassette_contract_from_value, diff_cassette_against_tools, diff_cassette_values,
    tools_from_value, CassetteContract, CassetteDriftChange, CassetteDriftEvent, CassetteDriftKind,
    CassetteDriftReport, CassetteFieldContract, CassetteToolContract, CASSETTE_DRIFT_EVENT_TYPE,
};
pub use code_mode::{compress_tool_schema, estimate_token_reduction};
pub use codemode_from_openapi::{emit_codemode_from_openapi, openapi_to_federated_tools};
pub use context_opt::ToolUsageTracker;
pub use federation::{
    FederatedTool, McpCallOutcome, McpFederation, McpServerConfig, NamespaceMode,
};
pub use guardrails::{check_tool_invocation, McpGuardrailConfig};
pub use handler::{InitializeContext, McpHandler};
pub use openapi_convert::openapi_to_mcp_tools;
pub use registry::{ToolHandlerType, ToolRegistry};
pub use rest_to_mcp::{create_mcp_handler, execute_tool_as_rest, RestToMcpConfig};
pub use types::*;
pub use verify_before_commit::{
    CompositeVerifier, DescriptorFile, StaticDescriptorVerifier, ToolDescriptor,
    VerifyBeforeCommit, VerifyContext, VerifyVerdict,
};
