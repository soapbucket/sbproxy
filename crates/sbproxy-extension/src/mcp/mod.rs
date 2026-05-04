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

pub mod access_control;
pub mod audit;
pub mod code_mode;
pub mod context_opt;
pub mod federation;
pub mod guardrails;
pub mod handler;
pub mod openapi_convert;
pub mod registry;
pub mod rest_to_mcp;
pub mod spans;
pub mod sse_client;
pub mod streamable;
pub mod types;

pub use access_control::ToolAccessPolicy;
pub use audit::{McpAuditBuilder, McpAuditEntry};
pub use code_mode::{compress_tool_schema, estimate_token_reduction};
pub use context_opt::ToolUsageTracker;
pub use federation::{FederatedTool, McpFederation, McpServerConfig};
pub use guardrails::{check_tool_invocation, McpGuardrailConfig};
pub use handler::McpHandler;
pub use openapi_convert::openapi_to_mcp_tools;
pub use registry::{ToolHandlerType, ToolRegistry};
pub use rest_to_mcp::{create_mcp_handler, execute_tool_as_rest, RestToMcpConfig};
pub use types::*;
