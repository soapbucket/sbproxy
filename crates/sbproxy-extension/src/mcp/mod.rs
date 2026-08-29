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
//! - [`federation`] - Aggregate tools, resources, and prompts from multiple
//!   upstream servers; the live gateway dispatch in `sbproxy-core` calls
//!   into this.
//! - [`sessions`] - Streamable HTTP session store (`Mcp-Session-Id`).
//! - [`discovery`] - Well-known manifest and RFC 9728 OAuth metadata builders.
//! - [`codemode_ts`] - Cloudflare Code Mode TypeScript module emitter.
//! - [`openapi_convert`] - Convert OpenAPI 3.x specs to MCP tools and routes.
//! - [`compat`] - Tool-versioning compatibility oracle.
//! - [`access_control`] - Principal-aware tool ACLs and per-tool quotas.
//! - [`cedar_hook`] - `CedarMcpHook`, the built-in Cedar-backed
//!   `McpPolicyHook` (WOR-2587). Runs alongside `access_control`'s
//!   RBAC gate, not instead of it.
//! - [`schema_drift`] / [`cassette_drift`] - CI drift detection (drift CLI).
//! - [`egress`] - Deterministic allowlist for gateway-originated traffic.
//! - [`auth`] - Run-as-user upstream credential minting (WOR-1792).
//! - [`auth_state`] - Server runtime vs per-tool-call auth challenges
//!   (WOR-2110).
//! - [`stdio`] - Supervised persistent stdio sessions for local MCP
//!   servers (one child per configured server, WOR-2453).
//! - [`peer_profile`] - Per-tenant downgrade-resistant negotiation
//!   profiles for federated peers (WOR-2384).

pub mod access_control;
pub mod auth;
pub mod auth_state;
pub mod cassette_drift;
pub mod cedar_hook;
pub mod codemode_ts;
pub mod compat;
pub mod concealed_text;
pub mod discovery;
pub mod egress;
pub mod federation;
pub mod openapi_convert;
pub mod peer_profile;
pub mod poisoned_text;
pub mod protocol;
pub mod quarantine;
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
pub use cedar_hook::CedarMcpHook;
pub use egress::{EgressDenied, EgressMode, EgressPolicy, SystemHostResolver};
pub use federation::{
    FederatedPrompt, FederatedTool, FederationIoSettings, LocalBacking, McpCallOutcome,
    McpFederation, McpPolicyDenialKind, McpPolicyDeniedError, McpServerConfig, NamespaceMode,
    OpenApiBacking, PromptCatalogSnapshot, SerializedToolEntry, SerializedTools,
    ToolVersioningGate, VersioningMode,
};
pub use openapi_convert::{openapi_to_mcp_tools, openapi_to_routes, OpenApiRoute};
pub use peer_profile::{
    McpPeerProfile, ObservationVerdict, PeerDowngradeKind, PeerDowngradePolicy, PinMismatch,
    PEER_DOWNGRADE_RULE_ID, PROTOCOL_PIN_MISMATCH_RULE_ID,
};
pub use protocol::{
    classify_http_era, decode_header_value, decode_http_request, decode_http_request_with_scan,
    encode_header_value, DecodedMcpRequest, DecodedRequestId, HeaderValueError,
    Legacy2025_06_18Codec, McpImplementation, McpProtocolCodec, McpProtocolContext, McpProtocolEra,
    McpRoutingHeaders, McpServerDescription, McpWireBody, McpWireError, McpWireResponse,
    Modern2026_07_28Codec, RawModernScan, RawModernScanLimit,
};
pub use stdio::{encode_stdio_url, StdioCommand};
pub use types::*;
