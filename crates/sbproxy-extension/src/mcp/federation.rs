//! MCP server federation.
//!
//! Aggregates tools from multiple upstream MCP servers into a unified
//! tool registry. Tool calls are routed to the correct upstream server.
//! The same aggregate-then-route shape covers the resource surface
//! (`resources/list` + `resources/read`) and the prompt surface
//! (`prompts/list` + `prompts/get`).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwap;
use reqwest::Url;
use sbproxy_plugin::mcp::{default_no_op_hook, mcp_policy_hooks, McpPolicyHook, McpToolCallCtx};
use sbproxy_plugin::traits::PolicyDecision;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{debug, error, info, warn};

use super::egress::{EgressPolicy, SystemHostResolver};
use super::protocol::{
    compile_modern_tool_contract, CompiledMcpToolContract, McpContractError, McpSchemaLimits,
    McpToolContract,
};
use super::sse_client::send_via_sse;
use super::streamable::send_request;
use super::types::{JsonRpcRequest, JsonRpcResponse, META_TRACEPARENT, SEP_414_RESERVED_META_KEYS};
use sbproxy_security::egress::{AuthorizedDestination, EgressPurpose, HostResolver};

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

/// How a federated server's tool and resource names are namespaced when
/// aggregated into the gateway's unified registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceMode {
    /// Keep each name bare and only prefix it with the server name when it
    /// collides with a name an earlier server already advertised (default).
    #[default]
    OnCollision,
    /// Always prefix every tool and resource from this server with the
    /// server name, so the whole upstream is namespaced even without a
    /// collision.
    Always,
}

/// An OpenAPI-backed upstream (WOR-1648): the gateway derives tools
/// from a spec and dispatches `tools/call` as REST requests, instead
/// of speaking MCP to the upstream. Turns an existing REST API into
/// governed MCP tools with no code.
#[derive(Debug, Clone)]
pub struct OpenApiBacking {
    /// Base URL the REST calls target (e.g. `https://api.example.com`).
    pub base_url: String,
    /// Tools derived from the spec (`name`/`description`/`inputSchema`).
    pub tools: Vec<serde_json::Value>,
    /// tool name -> (HTTP method, path template).
    pub routes: HashMap<String, (String, String)>,
    /// Deterministic egress policy for REST calls made on behalf of
    /// this OpenAPI-backed server.
    pub egress_policy: EgressPolicy,
    /// Static headers attached to every REST dispatch for this server
    /// (WOR-2314), typically a shared service credential such as an
    /// admin API's Basic auth resolved from the environment at config
    /// load. A per-call minted header of the same name (run-as-user)
    /// wins; names compare case-insensitively. Values may be secrets
    /// and are never logged by this module.
    pub headers: Vec<(String, String)>,
}

/// Configuration for one upstream MCP server.
#[derive(Debug, Clone)]
pub struct McpServerConfig {
    /// Human-readable name for this server.
    pub name: String,
    /// URL of the MCP endpoint.
    pub url: String,
    /// Transport type: `"streamable_http"` or `"sse"`.
    pub transport: String,
    /// How this server's names are namespaced in the unified registry.
    pub namespace: NamespaceMode,
    /// WOR-1648: when set, this upstream is served from an OpenAPI
    /// spec (tools derived locally, `tools/call` dispatched as REST)
    /// rather than by speaking MCP to `url`.
    pub openapi: Option<OpenApiBacking>,
}

/// Resolve the advertised (and registry-key) name for a tool or resource
/// from `server_name`, given the names already taken in the registry.
///
/// In [`NamespaceMode::Always`] every name is prefixed with the server name
/// up front. In [`NamespaceMode::OnCollision`] the bare name is kept unless
/// it is already taken, in which case it is disambiguated with the
/// server-qualified form. `sep` is `'.'` for tools and `'/'` for resources.
/// The returned name is what the gateway advertises to clients *and* keys
/// the registry by, so what a client sees is exactly what routes.
fn federated_name(
    server_name: &str,
    namespace: NamespaceMode,
    sep: char,
    raw: &str,
    taken: impl Fn(&str) -> bool,
) -> String {
    let base = match namespace {
        NamespaceMode::Always => format!("{server_name}{sep}{raw}"),
        NamespaceMode::OnCollision => raw.to_string(),
    };
    if !taken(&base) {
        return base;
    }
    // Disambiguate against the server-qualified form. If that is also taken
    // (a same-server duplicate, which `tools/list` should not produce), fall
    // back to the base and let the caller overwrite.
    let qualified = format!("{server_name}{sep}{raw}");
    if qualified != base && !taken(&qualified) {
        qualified
    } else {
        base
    }
}

// --- Registry ---

/// A tool federated from an upstream MCP server.
#[derive(Clone)]
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
    /// WOR-818: opaque `_meta` block per the OpenAI Apps SDK /
    /// MCP Apps (SEP-1865) extension. Preserved verbatim from the
    /// upstream so an Apps-SDK client receives any vendor-specific
    /// UI template id, version, etag, or audit-cause field unchanged.
    /// Base-MCP clients ignore the unknown key per the spec.
    pub meta: Option<serde_json::Value>,
    /// Complete upstream tool document, with only the advertised
    /// name rewritten during federation. A strict contract exists
    /// only when `inputSchema` is an object, as required by the
    /// modern wire. Its absence deliberately does not discard the
    /// legacy-compatible entry in [`Self::legacy_document`].
    pub contract: Option<McpToolContract>,
    /// Original legacy-compatible upstream document, present only
    /// when no strict contract can exist. This retains a valid
    /// string-named tool whose inputSchema is missing or not an
    /// object, because the frozen legacy path historically listed and
    /// routed those definitions. The legacy convenience fields carry
    /// the exact old wire projection, including the synthesized
    /// schema for a missing inputSchema. Valid and OpenAPI documents
    /// live losslessly in [`Self::contract`] without a duplicate.
    pub legacy_document: Option<Value>,
    /// Precompiled modern input/output validators and header
    /// projections. `None` keeps the tool available to legacy clients
    /// while excluding it from modern discovery and modern lookup.
    pub modern_contract: Option<Arc<CompiledMcpToolContract>>,
    /// Stable, safe class describing why this tool has no modern
    /// compiled contract. This deliberately excludes raw schemas,
    /// references, and header values so it is safe to log.
    pub modern_incompatibility: Option<String>,
}

impl std::fmt::Debug for FederatedTool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = bounded_control_free_identifier(&self.name, 96);
        let server_name = bounded_control_free_identifier(&self.server_name, 96);
        formatter
            .debug_struct("FederatedTool")
            .field("name", &name)
            .field("server_name", &server_name)
            .field("streaming", &self.streaming)
            .field("has_meta", &self.meta.is_some())
            .field("has_contract", &self.contract.is_some())
            .field("has_legacy_document", &self.legacy_document.is_some())
            .field("modern_compiled", &self.modern_contract.is_some())
            .field(
                "modern_incompatibility",
                &self
                    .modern_incompatibility
                    .as_deref()
                    .map(bounded_modern_incompatibility_class),
            )
            .finish()
    }
}

/// Whether the frozen legacy projection includes an upstream `_meta`
/// block. MCP upstreams historically preserved it; OpenAPI-derived
/// tools historically did not.
#[derive(Debug, Clone, Copy)]
enum LegacyMetaProjection {
    Preserve,
    Omit,
}

impl FederatedTool {
    /// Build a federated tool from the complete upstream document
    /// before deriving routing conveniences. A non-object document
    /// or one without a string name is fundamentally unusable. In
    /// contrast, a missing or non-object inputSchema is retained
    /// exactly as the frozen legacy parser handled it and marked
    /// modern-ineligible.
    fn from_contract_document(
        document: Value,
        server_name: String,
        streaming: bool,
    ) -> Result<Self, McpContractError> {
        Self::from_document_with_legacy_meta(
            document,
            server_name,
            streaming,
            LegacyMetaProjection::Preserve,
        )
    }

    /// Construct an OpenAPI-derived tool. Its complete source
    /// document remains available to modern clients, while the
    /// legacy projection deliberately retains the historical absence
    /// of `_meta`.
    fn from_openapi_document(
        document: Value,
        server_name: String,
        streaming: bool,
    ) -> Result<Self, McpContractError> {
        Self::from_document_with_legacy_meta(
            document,
            server_name,
            streaming,
            LegacyMetaProjection::Omit,
        )
    }

    fn from_document_with_legacy_meta(
        document: Value,
        server_name: String,
        streaming: bool,
        legacy_meta_projection: LegacyMetaProjection,
    ) -> Result<Self, McpContractError> {
        let object = document
            .as_object()
            .ok_or(McpContractError::ToolMustBeObject)?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or(McpContractError::MissingStringField("name"))?
            .to_string();
        let description = object
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let input_schema = object
            .get("inputSchema")
            .cloned()
            .unwrap_or_else(|| json!({"type": "object", "properties": {}}));
        let modern_incompatibility = match object.get("inputSchema") {
            None => Some("missing_input_schema".to_string()),
            Some(schema) if !schema.is_object() => Some("non_object_input_schema".to_string()),
            Some(_) => None,
        };
        let meta = match legacy_meta_projection {
            LegacyMetaProjection::Preserve => object.get("_meta").cloned(),
            LegacyMetaProjection::Omit => None,
        };

        // Keep strict parsing exactly where the modern representation
        // begins. This must not be weakened to accommodate a frozen
        // legacy malformed definition.
        let contract = McpToolContract::try_from(document.clone()).ok();
        debug_assert!(contract.is_some() || modern_incompatibility.is_some());
        let legacy_document = contract.is_none().then_some(document);

        Ok(Self {
            name,
            description,
            input_schema,
            server_name,
            streaming,
            meta,
            contract,
            legacy_document,
            modern_contract: None,
            modern_incompatibility,
        })
    }

    /// Rewrite only the strict contract or legacy fallback name, then
    /// keep the frozen routing conveniences in lockstep. A malformed
    /// legacy definition has no strict contract, so its raw fallback
    /// is the authoritative source for this rewrite.
    fn advertise_as(&mut self, advertised_name: &str) {
        if let Some(contract) = self.contract.as_ref() {
            self.contract = Some(contract.with_advertised_name(advertised_name));
            self.sync_convenience_fields();
        } else {
            self.name = advertised_name.to_string();
        }
        if let Some(document) = self.legacy_document.as_mut().and_then(Value::as_object_mut) {
            document.insert(
                "name".to_string(),
                Value::String(advertised_name.to_string()),
            );
        }
    }

    /// Compile the modern representation once per catalogue refresh.
    /// A compile failure does not remove a legacy-compatible tool;
    /// it becomes modern-ineligible with a safe, stable class only.
    fn compile_modern_contract(&mut self) {
        let Some(contract) = self.contract.as_ref() else {
            self.modern_contract = None;
            if self.modern_incompatibility.is_none() {
                self.modern_incompatibility = Some("missing_input_schema".to_string());
            }
            return;
        };
        match compile_modern_tool_contract(contract, McpSchemaLimits::default()) {
            Ok(compiled) => {
                self.modern_contract = Some(Arc::new(compiled));
                self.modern_incompatibility = None;
            }
            Err(error) => {
                let class = modern_incompatibility_class(&error);
                self.modern_contract = None;
                self.modern_incompatibility = Some(class.to_string());
            }
        }
    }

    fn sync_convenience_fields(&mut self) {
        let Some(contract) = self.contract.as_ref() else {
            return;
        };
        self.name = contract.name().to_string();
        self.description = contract.description().unwrap_or_default().to_string();
        self.input_schema = contract.input_schema().clone();
    }

    /// A strict complete document is the authoritative prerequisite for every
    /// modern catalogue use. Compilation separately controls whether that
    /// strict document is discoverable: an incompatible strict contract still
    /// participates in the lossless publication digest so changes cannot be
    /// silently suppressed.
    fn is_modern_eligible(&self) -> bool {
        self.contract.is_some()
    }

    /// Whether a strict modern contract also compiled for caller-facing
    /// discovery and ingress validation.
    fn is_modern_discoverable(&self) -> bool {
        self.is_modern_eligible() && self.modern_contract.is_some()
    }

    /// Name CodeMode should emit. Valid tools read the strict contract;
    /// frozen malformed legacy definitions use their preserved routing
    /// convenience instead.
    pub(crate) fn codemode_name(&self) -> &str {
        match self.contract.as_ref() {
            Some(contract) => contract.name(),
            None => &self.name,
        }
    }

    /// Description CodeMode should emit, preserving the old fallback
    /// semantics when a strict modern contract is unavailable.
    pub(crate) fn codemode_description(&self) -> &str {
        match self.contract.as_ref() {
            Some(contract) => contract.description().unwrap_or_default(),
            None => &self.description,
        }
    }

    /// Input schema CodeMode should emit. The fallback intentionally
    /// permits a non-object schema because that is what the legacy
    /// CodeMode behavior observed.
    pub(crate) fn codemode_input_schema(&self) -> &Value {
        match self.contract.as_ref() {
            Some(contract) => contract.input_schema(),
            None => &self.input_schema,
        }
    }
}

/// Convert a contract compilation error into the bounded vocabulary
/// that is safe for a catalog-refresh log and a persisted modern
/// incompatibility marker. Do not include the error text here: some
/// variants carry an upstream schema or external reference.
fn modern_incompatibility_class(error: &McpContractError) -> &'static str {
    match error {
        McpContractError::ToolMustBeObject => "tool_not_object",
        McpContractError::ToolResultMustBeObject => "tool_result_not_object",
        McpContractError::MissingStringField(_) => "missing_string_field",
        McpContractError::MissingObjectField(_) => "missing_object_field",
        McpContractError::MissingArrayField(_) => "missing_array_field",
        McpContractError::InvalidToolResultMeta => "invalid_tool_result_meta",
        McpContractError::UnsupportedToolResultType => "unsupported_tool_result_type",
        McpContractError::UnsupportedSchemaDialect(_) => "unsupported_schema_dialect",
        McpContractError::InvalidSchema(_) => "invalid_schema",
        McpContractError::ExternalReference { .. } => "external_reference",
        McpContractError::LimitExceeded { .. } => "schema_limit_exceeded",
        McpContractError::UnreachableHeaderProjection(_) => "unreachable_header_projection",
        McpContractError::DuplicateHeaderProjection(_) => "duplicate_header_projection",
        McpContractError::InvalidHeaderName(_) => "invalid_header_name",
        McpContractError::UnsupportedHeaderValueKind { .. } => "unsupported_header_value_kind",
        McpContractError::MissingMirroredHeader(_) => "missing_mirrored_header",
        McpContractError::UnexpectedMirroredHeader(_) => "unexpected_mirrored_header",
        McpContractError::MirroredHeaderMismatch(_) => "mirrored_header_mismatch",
        McpContractError::UnsafeProjectedInteger(_) => "unsafe_projected_integer",
    }
}

/// Convert an incompatibility marker to the closed label vocabulary used for
/// catalog-change telemetry. `FederatedTool` remains publicly constructible,
/// so an externally assembled entry may carry an unexpected marker; it maps
/// to one bounded bucket rather than becoming a log-cardinality label.
fn bounded_modern_incompatibility_class(class: &str) -> &'static str {
    match class {
        "missing_input_schema" => "missing_input_schema",
        "non_object_input_schema" => "non_object_input_schema",
        "tool_not_object" => "tool_not_object",
        "tool_result_not_object" => "tool_result_not_object",
        "missing_string_field" => "missing_string_field",
        "missing_object_field" => "missing_object_field",
        "missing_array_field" => "missing_array_field",
        "invalid_tool_result_meta" => "invalid_tool_result_meta",
        "unsupported_tool_result_type" => "unsupported_tool_result_type",
        "unsupported_schema_dialect" => "unsupported_schema_dialect",
        "invalid_schema" => "invalid_schema",
        "external_reference" => "external_reference",
        "schema_limit_exceeded" => "schema_limit_exceeded",
        _ => "other",
    }
}

const MAX_MODERN_INCOMPATIBILITY_CHANGE_EVENTS: usize = 32;
const MAX_MODERN_INCOMPATIBILITY_IDENTIFIER_BYTES: usize = 96;

/// One bounded, non-secret modern eligibility transition suitable for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ModernIncompatibilityChange {
    kind: &'static str,
    class: &'static str,
    tool: String,
    server: String,
}

fn bounded_control_free_identifier(value: &str, max_bytes: usize) -> String {
    let mut bounded = String::with_capacity(value.len().min(max_bytes));
    for character in value.chars() {
        let safe = if character.is_control()
            || matches!(
                character,
                '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            ) {
            '\u{fffd}'
        } else {
            character
        };
        if bounded.len() + safe.len_utf8() > max_bytes {
            break;
        }
        bounded.push(safe);
    }
    if bounded.is_empty() {
        bounded.push_str("<empty>");
    }
    bounded
}

fn modern_incompatibility_change(
    kind: &'static str,
    tool: &FederatedTool,
) -> Option<ModernIncompatibilityChange> {
    let class = tool.modern_incompatibility.as_deref()?;
    Some(ModernIncompatibilityChange {
        kind,
        class: bounded_modern_incompatibility_class(class),
        tool: bounded_control_free_identifier(
            &tool.name,
            MAX_MODERN_INCOMPATIBILITY_IDENTIFIER_BYTES,
        ),
        server: bounded_control_free_identifier(
            &tool.server_name,
            MAX_MODERN_INCOMPATIBILITY_IDENTIFIER_BYTES,
        ),
    })
}

/// Diff incompatible entries by stable catalog identity, not aggregate count.
/// The result is sorted and capped so a hostile catalog cannot amplify logs.
fn modern_incompatibility_changes(
    previous: &HashMap<String, FederatedTool>,
    next: &HashMap<String, FederatedTool>,
) -> Vec<ModernIncompatibilityChange> {
    let mut identities: Vec<&String> = previous.keys().chain(next.keys()).collect();
    identities.sort_unstable();
    identities.dedup();

    let mut changes = Vec::new();
    for identity in identities {
        let before = previous.get(identity);
        let after = next.get(identity);
        let before_state = before.and_then(|tool| {
            tool.modern_incompatibility.as_deref().map(|class| {
                (
                    bounded_modern_incompatibility_class(class),
                    tool.server_name.as_str(),
                    tool.name.as_str(),
                )
            })
        });
        let after_state = after.and_then(|tool| {
            tool.modern_incompatibility.as_deref().map(|class| {
                (
                    bounded_modern_incompatibility_class(class),
                    tool.server_name.as_str(),
                    tool.name.as_str(),
                )
            })
        });

        let change = match (before_state, after_state) {
            (None, Some(_)) => after.and_then(|tool| modern_incompatibility_change("added", tool)),
            (Some(_), None) => {
                before.and_then(|tool| modern_incompatibility_change("removed", tool))
            }
            (Some(before_state), Some(after_state)) if before_state != after_state => {
                after.and_then(|tool| modern_incompatibility_change("changed", tool))
            }
            _ => None,
        };
        if let Some(change) = change {
            changes.push(change);
            if changes.len() == MAX_MODERN_INCOMPATIBILITY_CHANGE_EVENTS {
                break;
            }
        }
    }
    changes
}

/// Count modern-ineligible tools by a closed, non-sensitive class vocabulary.
/// Tool names, server names, schemas, and reference values deliberately do
/// not enter this aggregate.
fn modern_incompatibility_summary(
    registry: &HashMap<String, FederatedTool>,
) -> BTreeMap<&'static str, usize> {
    let mut summary = BTreeMap::new();
    for tool in registry.values() {
        let Some(class) = tool.modern_incompatibility.as_deref() else {
            continue;
        };
        *summary
            .entry(bounded_modern_incompatibility_class(class))
            .or_default() += 1;
    }
    summary
}

/// Return the next aggregate only when its bounded incompatibility state
/// changed. This is the testable guard around catalog-change-only telemetry.
#[cfg(test)]
fn modern_incompatibility_change_summary(
    previous: &HashMap<String, FederatedTool>,
    next: &HashMap<String, FederatedTool>,
) -> Option<BTreeMap<&'static str, usize>> {
    let previous_summary = modern_incompatibility_summary(previous);
    let next_summary = modern_incompatibility_summary(next);
    (previous_summary != next_summary).then_some(next_summary)
}

/// A resource federated from an upstream MCP server. Mirrors
/// [`FederatedTool`] but for the `resources/list` + `resources/read`
/// surface, which Apps-SDK / SEP-1865 clients use to fetch UI
/// templates declared on tools.
#[derive(Debug, Clone)]
pub struct FederatedResource {
    /// Resource URI (may be prefixed with server name on conflict).
    pub uri: String,
    /// Display name shown to clients.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Optional IANA mime type.
    pub mime_type: Option<String>,
    /// Name of the upstream server that owns this resource.
    pub server_name: String,
    /// Original upstream URI (pre-prefix) so the gateway can
    /// forward `resources/read` to the right server with the URI
    /// the upstream advertised. Equal to `uri` when no collision
    /// triggered the prefix.
    pub upstream_uri: String,
}

/// A prompt federated from an upstream MCP server. Mirrors
/// [`FederatedTool`] for the `prompts/list` + `prompts/get` surface,
/// and namespaces on exactly the same rules: `'.'` separator,
/// [`NamespaceMode`] per server, prefix on collision. A prompt name
/// clash across two upstreams therefore behaves like a tool name
/// clash, which is the only way a client can route both.
#[derive(Debug, Clone)]
pub struct FederatedPrompt {
    /// Advertised prompt name (may be prefixed with the server name).
    pub name: String,
    /// Original name the upstream advertised, so `prompts/get` reaches
    /// it with the name it knows. Equal to `name` when no collision
    /// (and no `namespace: always`) triggered the prefix.
    pub upstream_name: String,
    /// Optional display title (added by MCP 2025-06-18).
    pub title: Option<String>,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Verbatim `arguments` array from the upstream definition, when
    /// the prompt declares one. Passed through unparsed: the gateway
    /// does not validate prompt arguments, the owning server does.
    pub arguments: Option<serde_json::Value>,
    /// Name of the upstream server that owns this prompt.
    pub server_name: String,
    /// Opaque `_meta` block, preserved verbatim for the same reason
    /// [`FederatedTool::meta`] is.
    pub meta: Option<serde_json::Value>,
}

// --- McpFederation ---

/// Upstream IO limits for every HTTP exchange the federation makes
/// (catalogue refreshes, tool calls, resource reads). WOR-1639: the
/// client previously had no timeout at all, so one hung upstream
/// stalled every registry-reading request indefinitely, and response
/// bodies were buffered without bound.
#[derive(Debug, Clone)]
pub struct FederationIoSettings {
    /// TCP connect deadline per upstream exchange.
    pub connect_timeout: std::time::Duration,
    /// Whole-request deadline per upstream exchange. Per-server
    /// `timeout:` values wrap `tools/call` with a shorter deadline;
    /// this is the ceiling everything else (refreshes, resource
    /// reads) is bounded by.
    pub request_timeout: std::time::Duration,
    /// Maximum upstream response bytes ever buffered per exchange.
    pub max_response_bytes: usize,
}

impl Default for FederationIoSettings {
    fn default() -> Self {
        Self {
            connect_timeout: std::time::Duration::from_secs(5),
            request_timeout: std::time::Duration::from_secs(30),
            max_response_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Enforcement mode for the tool-versioning gate (WOR-1635).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersioningMode {
    /// Violations are logged and counted; traffic is unaffected.
    Warn,
    /// Violating tools are filtered from `tools/list` and their
    /// `tools/call` fails with a typed error.
    Block,
}

/// Tool-versioning gate configuration (WOR-1635): the committed
/// lockfile baseline plus the operator-declared current versions.
/// The lockfile is (re)read at each catalogue change, not at compile
/// time, so config compilation stays IO-free; an unreadable or
/// invalid lockfile fails open (nothing blocked) with a loud error
/// event and a `lockfile_error` verdict metric.
pub struct ToolVersioningGate {
    /// Path to the committed lockfile (YAML, see
    /// [`super::compat::Lockfile`]).
    pub lockfile_path: String,
    /// Operator-declared current version per advertised tool name.
    /// A changed tool absent from this map is linted against its
    /// lockfile version, i.e. treated as "no bump declared".
    pub declared_versions: HashMap<String, semver::Version>,
    /// Warn or block.
    pub mode: VersioningMode,
    /// Description-semantics judges (WOR-1637). Empty skips the
    /// dimension entirely, exactly as the oracle promises; more than
    /// one runs a jury whose agreement sets the confidence.
    pub judges: Vec<Arc<dyn super::compat::Judge>>,
}

/// One immutable publication of every value that must agree with a
/// federated tool catalogue. Readers load this once, so a refresh can
/// never expose a new tool registry under an old generation or an old
/// version-gate verdict.
struct ToolCatalogState {
    /// Advertised tool name to complete federated entry.
    tools: Arc<HashMap<String, FederatedTool>>,
    /// Version-gate verdicts for exactly this registry.
    version_blocked: Arc<HashMap<String, String>>,
    /// Frozen legacy content digest for change detection.
    legacy_digest: u64,
    /// Collision-resistant lossless strict-contract digest for modern
    /// publication. This is deliberately distinct from the frozen legacy
    /// `u64` compatibility oracle.
    modern_digest: [u8; 32],
    /// Generation of the frozen legacy catalogue.
    tools_generation: u64,
    /// Generation of the complete modern catalogue.
    modern_tools_generation: u64,
    /// Generation of the CodeMode discovery view. It advances for a
    /// frozen legacy tool change or a version-gate verdict change,
    /// because either changes which tool calls CodeMode may advertise.
    codemode_generation: u64,
    /// Prebuilt frozen legacy catalogue for `tools/list` readers.
    legacy_serialized: Arc<SerializedTools>,
    /// Prebuilt complete modern catalogue for modern discovery readers.
    modern_serialized: Arc<ModernSerializedTools>,
}

impl ToolCatalogState {
    fn empty() -> Self {
        Self {
            tools: Arc::new(HashMap::new()),
            version_blocked: Arc::new(HashMap::new()),
            legacy_digest: 0,
            // The empty modern publication must have the same digest as a
            // registry containing only malformed legacy fallbacks, otherwise
            // the first such legacy-only refresh would spuriously churn the
            // modern generation and cache identity.
            modern_digest: modern_tools_registry_digest(&HashMap::new()),
            tools_generation: 0,
            modern_tools_generation: 0,
            codemode_generation: 0,
            legacy_serialized: Arc::new(SerializedTools {
                generation: 0,
                entries: Vec::new(),
                full_array: "[]".to_string(),
            }),
            modern_serialized: Arc::new(ModernSerializedTools {
                generation: 0,
                entries: Vec::new(),
                full_array: "[]".to_string(),
            }),
        }
    }
}

/// A coherent read handle for one immutable tool-catalogue publication.
///
/// Keep this handle alive while combining a listed or resolved tool with
/// its version-gate verdict. It prevents a refresh from splitting those
/// coupled decisions across two different catalogues.
#[derive(Clone)]
pub struct ToolCatalogSnapshot {
    state: Arc<ToolCatalogState>,
    /// Private per-federation identity. This prevents an opaque snapshot from
    /// one federation being replayed through another federation's server
    /// configuration.
    owner: Arc<()>,
}

impl ToolCatalogSnapshot {
    /// Frozen legacy `tools/list` snapshot matching this verdict map.
    pub fn serialized_tools(&self) -> Arc<SerializedTools> {
        Arc::clone(&self.state.legacy_serialized)
    }

    /// Complete modern `tools/list` snapshot matching this verdict map.
    pub fn serialized_modern_tools(&self) -> Arc<ModernSerializedTools> {
        Arc::clone(&self.state.modern_serialized)
    }

    /// Version-gate verdicts for exactly the tools in this snapshot.
    pub fn version_blocked(&self) -> &HashMap<String, String> {
        self.state.version_blocked.as_ref()
    }

    /// Frozen legacy generation for this publication.
    pub fn tools_generation(&self) -> u64 {
        self.state.tools_generation
    }

    /// Complete modern generation for this publication.
    pub fn modern_tools_generation(&self) -> u64 {
        self.state.modern_tools_generation
    }

    /// List every federated tool from this exact publication. Pair
    /// the result with [`Self::version_blocked`] from this same handle
    /// before exposing a discovery or policy surface.
    pub fn list_tools(&self) -> Vec<FederatedTool> {
        self.state.tools.values().cloned().collect()
    }

    /// Borrow every tool from this exact publication without cloning its
    /// complete contract document. Discovery paths that only serialize or
    /// inspect entries should prefer this iterator over [`Self::list_tools`].
    pub fn iter_tools(&self) -> impl Iterator<Item = &FederatedTool> {
        self.state.tools.values()
    }

    /// Resolve one federated tool from this exact publication. Use
    /// [`Self::resolve_tool_with_version_block`] when the caller also
    /// needs the matching version-gate verdict.
    pub fn resolve_tool(&self, tool_name: &str) -> Option<FederatedTool> {
        self.state.tools.get(tool_name).cloned()
    }

    /// Resolve a tool and its version-gate verdict from one publication.
    pub fn resolve_tool_with_version_block(
        &self,
        tool_name: &str,
    ) -> (Option<FederatedTool>, Option<String>) {
        (
            self.state.tools.get(tool_name).cloned(),
            self.state.version_blocked.get(tool_name).cloned(),
        )
    }
}

/// A coherent read handle for one immutable prompt-catalogue publication.
///
/// Retain this handle from the ownership decision through dispatch. Its fields
/// are private so callers cannot forge a server mapping after authorization.
#[derive(Clone)]
pub struct PromptCatalogSnapshot {
    prompts: Arc<HashMap<String, FederatedPrompt>>,
    owner: Arc<()>,
}

impl PromptCatalogSnapshot {
    /// Clone every internally consistent prompt from this publication.
    pub fn list_prompts(&self) -> Vec<FederatedPrompt> {
        self.prompts
            .iter()
            .filter(|(name, prompt)| name.as_str() == prompt.name)
            .map(|(_, prompt)| prompt.clone())
            .collect()
    }

    /// Resolve a prompt without consulting a later live publication.
    pub fn resolve_prompt(&self, name: &str) -> Option<&FederatedPrompt> {
        self.prompts.get(name).filter(|prompt| prompt.name == name)
    }
}

/// Aggregates tools from multiple upstream MCP servers into one registry.
pub struct McpFederation {
    servers: Vec<McpServerConfig>,
    /// Immutable registry, version-gate, digest, generation, and
    /// pre-serialized catalogue publication for the tool surface.
    tool_catalog: ArcSwap<ToolCatalogState>,
    /// Private identity bound into every [`ToolCatalogSnapshot`].
    tool_catalog_owner: Arc<()>,
    /// resource_uri -> FederatedResource. WOR-818: populated by
    /// `refresh_resources` so OpenAI Apps SDK clients can fetch
    /// UI templates declared on tools through the gateway.
    resources: ArcSwap<HashMap<String, FederatedResource>>,
    /// prompt_name -> FederatedPrompt. Populated by `refresh_prompts`
    /// from the upstreams that declare the `prompts` capability;
    /// every other upstream contributes nothing.
    prompts: ArcSwap<HashMap<String, FederatedPrompt>>,
    /// Private identity bound into every [`PromptCatalogSnapshot`].
    prompt_catalog_owner: Arc<()>,
    /// server_name -> the `capabilities` object the upstream returned
    /// from `initialize`, refreshed by `refresh_server_capabilities`.
    /// One probe per upstream per cycle feeds every registry that
    /// needs to know what an upstream supports, so adding a surface
    /// does not add a handshake.
    server_capabilities: ArcSwap<HashMap<String, serde_json::Value>>,
    /// WOR-818: mcpApps capability values mirrored from any
    /// upstream that advertised one. Empty when no upstream
    /// supports SEP-1865. The first non-empty value is what the
    /// gateway re-advertises on its own `initialize`.
    mcp_apps_capability: ArcSwap<Option<serde_json::Value>>,
    client: reqwest::Client,
    /// REST-tool client with automatic redirects disabled. OpenAPI
    /// tools must inspect each redirect target before following it so
    /// an allowed host cannot bounce the gateway to an unlisted one.
    openapi_client: reqwest::Client,
    /// Maximum upstream response bytes buffered per exchange
    /// (WOR-1639); passed to every transport send.
    max_response_bytes: usize,
    /// Supervision deadline for local stdio MCP exchanges.
    stdio_timeout: std::time::Duration,
    /// TCP connect deadline, kept so per-dial pinned OpenAPI clients
    /// (WOR-2080) carry the same bounds as the shared clients.
    connect_timeout: std::time::Duration,
    /// Whole-request deadline, kept for the same per-dial clients.
    request_timeout: std::time::Duration,
    /// Monotonic cross-surface change signal. It advances for a
    /// frozen-legacy tool change or a resource change, preserving the
    /// existing notification behavior. Tool cache identities instead
    /// live in the immutable catalogue state's dedicated generations.
    generation: std::sync::atomic::AtomicU64,
    /// Resource-registry-only generation, for
    /// `resources/list_changed` notifications (WOR-1642).
    resources_generation: std::sync::atomic::AtomicU64,
    /// Content digest of the last stored resource registry (plus the
    /// mirrored mcpApps capability). Zero until the first refresh.
    resources_digest: std::sync::atomic::AtomicU64,
    /// Content digest of the last stored prompt registry. Zero until
    /// the first refresh. The prompt registry deliberately does not
    /// move [`Self::generation`]: that counter keys the serialized
    /// `tools/list` and codemode.ts caches, and a prompt change
    /// invalidates neither. Nor is there a `prompts/list_changed`
    /// notification to drive, because the gateway does not push one
    /// (see the capability it advertises).
    prompts_digest: std::sync::atomic::AtomicU64,
    /// Set once `ensure_ready` has spawned the periodic refresh task.
    refresh_task_started: std::sync::atomic::AtomicBool,
    /// Set once the cold-start prime (one tools + capabilities +
    /// resources + prompts fetch) has run. Requests after that serve
    /// the ArcSwap snapshot and never fan out to upstreams inline.
    primed: std::sync::atomic::AtomicBool,
    /// Serialises the cold-start prime so N concurrent first
    /// requests trigger exactly one upstream fan-out.
    prime_lock: tokio::sync::Mutex<()>,
    /// Serialises tool fetch, versioning, and publication. In
    /// particular, no digest or registry mutation happens before the
    /// final versioning await completes, so cancellation leaves the
    /// previous snapshot coherent and retryable.
    tools_refresh_lock: tokio::sync::Mutex<()>,
    /// Tool-versioning gate (WOR-1635); `None` disables the oracle.
    versioning: Option<ToolVersioningGate>,
    /// WOR-1640: per-generation codemode.ts module + ETag, so the
    /// well-known route re-emits and re-hashes only when the
    /// catalogue (or callback base) changes.
    codemode_cache: ArcSwap<CodemodeCache>,
}

/// Pre-serialized frozen legacy tool catalogue for one legacy
/// registry generation (WOR-1640).
pub struct SerializedTools {
    /// Frozen legacy tool generation this snapshot was built from.
    pub generation: u64,
    /// One entry per advertised tool, sorted by name.
    pub entries: Vec<SerializedToolEntry>,
    /// The full catalogue as a serialized JSON array.
    pub full_array: String,
}

/// Pre-serialized complete modern tool catalogue for one modern
/// registry generation. It holds only entries with a strict,
/// compiled caller-facing contract and never changes the legacy cache
/// identity.
pub struct ModernSerializedTools {
    /// Modern-catalogue generation this snapshot was built from.
    pub generation: u64,
    /// One complete contract entry per modern-compatible advertised
    /// tool, sorted by name.
    pub entries: Vec<SerializedToolEntry>,
    /// The complete modern-compatible catalogue as a serialized JSON
    /// array.
    pub full_array: String,
}

/// One pre-serialized tool entry (WOR-1640).
pub struct SerializedToolEntry {
    /// Advertised (possibly namespaced) tool name.
    pub name: String,
    /// Owning upstream server name, for per-server policy lookups.
    pub server_name: String,
    /// The era-specific serialized tool object. Legacy entries carry
    /// the frozen projection; modern entries carry the full contract.
    pub json: String,
}

/// Cached codemode.ts emission for one (generation, callback base)
/// pair (WOR-1640).
struct CodemodeCache {
    generation: u64,
    callback_base: String,
    module: Arc<String>,
    /// Strong ETag: quoted lowercase hex SHA-256 of the module bytes.
    etag: String,
}

impl McpFederation {
    /// Create a new federation from a list of upstream server
    /// configs, with default IO limits.
    pub fn new(servers: Vec<McpServerConfig>) -> Self {
        Self::with_io(servers, FederationIoSettings::default())
    }

    /// Create a new federation with explicit upstream IO limits.
    pub fn with_io(servers: Vec<McpServerConfig>, io: FederationIoSettings) -> Self {
        Self::with_io_versioned(servers, io, None)
    }

    /// Create a new federation with explicit IO limits and an
    /// optional tool-versioning gate (WOR-1635).
    pub fn with_io_versioned(
        servers: Vec<McpServerConfig>,
        io: FederationIoSettings,
        versioning: Option<ToolVersioningGate>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(io.connect_timeout)
            .timeout(io.request_timeout)
            .pool_max_idle_per_host(8)
            .build()
            // Builder failure here means TLS backend initialisation
            // failed; a clientless federation is useless, so fall
            // back to the default client (same behaviour as before
            // WOR-1639) rather than panicking in a constructor.
            .unwrap_or_default();
        let openapi_client = reqwest::Client::builder()
            .connect_timeout(io.connect_timeout)
            .timeout(io.request_timeout)
            .pool_max_idle_per_host(8)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            servers,
            tool_catalog: ArcSwap::from_pointee(ToolCatalogState::empty()),
            tool_catalog_owner: Arc::new(()),
            resources: ArcSwap::from_pointee(HashMap::new()),
            prompts: ArcSwap::from_pointee(HashMap::new()),
            prompt_catalog_owner: Arc::new(()),
            server_capabilities: ArcSwap::from_pointee(HashMap::new()),
            mcp_apps_capability: ArcSwap::from_pointee(None),
            client,
            openapi_client,
            max_response_bytes: io.max_response_bytes,
            stdio_timeout: io.request_timeout,
            connect_timeout: io.connect_timeout,
            request_timeout: io.request_timeout,
            generation: std::sync::atomic::AtomicU64::new(0),
            resources_generation: std::sync::atomic::AtomicU64::new(0),
            resources_digest: std::sync::atomic::AtomicU64::new(0),
            prompts_digest: std::sync::atomic::AtomicU64::new(0),
            refresh_task_started: std::sync::atomic::AtomicBool::new(false),
            primed: std::sync::atomic::AtomicBool::new(false),
            prime_lock: tokio::sync::Mutex::new(()),
            tools_refresh_lock: tokio::sync::Mutex::new(()),
            versioning,
            codemode_cache: ArcSwap::from_pointee(CodemodeCache {
                generation: u64::MAX,
                callback_base: String::new(),
                module: Arc::new(String::new()),
                etag: String::new(),
            }),
        }
    }

    /// Fetch tool lists from all servers and build unified registry.
    ///
    /// On name collision the later server's tool is prefixed with its
    /// server name (e.g. `servername.toolname`) to avoid shadowing.
    ///
    /// Returns the total number of federated tools.
    pub async fn refresh_tools(&self) -> anyhow::Result<usize> {
        let _refresh_guard = self.tools_refresh_lock.lock().await;
        let mut registry: HashMap<String, FederatedTool> = HashMap::new();
        let mut peers_up: i64 = 0;

        for server in &self.servers {
            match self.fetch_tools_from_server(server).await {
                Ok(tools) => {
                    peers_up += 1;
                    info!(
                        server = %server.name,
                        count = tools.len(),
                        "fetched tools from upstream MCP server"
                    );
                    for mut tool in tools {
                        let advertised =
                            federated_name(&server.name, server.namespace, '.', &tool.name, |n| {
                                registry.contains_key(n)
                            });
                        if advertised != tool.name {
                            warn!(
                                tool = %tool.name,
                                server = %server.name,
                                advertised = %advertised,
                                "federated tool name namespaced (collision or always-namespace)"
                            );
                        }
                        // Advertise the resolved name so the client sees and
                        // calls the same name `resolve_tool` routes by.
                        tool.advertise_as(&advertised);
                        // Compilation happens after namespacing, once per
                        // refresh. A failure is a modern eligibility result,
                        // never a reason to remove a legacy tool.
                        tool.compile_modern_contract();
                        registry.insert(advertised, tool);
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

        sbproxy_observe::metrics::set_mcp_federation_peers_up(peers_up);

        let count = registry.len();
        let digest = tools_registry_digest(&registry);
        let modern_digest = modern_tools_registry_digest(&registry);
        // Do not mutate either digest before the versioning await.
        // An aborted refresh must leave the prior registry, digests,
        // generations, and cache identities coherent so the identical
        // retry can publish. The refresh lock makes these loads a
        // single-writer comparison rather than a best-effort race.
        let current_catalog = self.tool_catalog.load_full();
        let legacy_changed = current_catalog.legacy_digest != digest;
        let modern_changed = current_catalog.modern_digest != modern_digest;
        if legacy_changed || modern_changed {
            let incompatibility_changes =
                modern_incompatibility_changes(current_catalog.tools.as_ref(), &registry);
            let incompatibility_summary = (!incompatibility_changes.is_empty())
                .then(|| modern_incompatibility_summary(&registry));
            // WOR-1635: grade the changed catalogue against the
            // lockfile baseline before publishing it. Modern-only
            // fields must never perturb the legacy oracle.
            let version_blocked = if legacy_changed {
                self.evaluate_tool_versioning_snapshot(&registry).await
            } else {
                None
            };
            self.publish_tool_refresh(
                registry,
                digest,
                modern_digest,
                legacy_changed,
                modern_changed,
                version_blocked,
            );
            for change in &incompatibility_changes {
                warn!(
                    target: "sbproxy::mcp::catalog",
                    kind = change.kind,
                    class = change.class,
                    tool = %change.tool,
                    server = %change.server,
                    "MCP modern catalog incompatibility changed"
                );
            }
            if let Some(classes) = incompatibility_summary {
                let total: usize = classes.values().sum();
                warn!(
                    target: "sbproxy::mcp::catalog",
                    total,
                    emitted = incompatibility_changes.len(),
                    classes = ?classes,
                    "MCP modern catalog incompatibility summary changed"
                );
            }
            debug!(total_tools = count, "MCP federation registry refreshed");
        } else {
            debug!(
                total_tools = count,
                "MCP federation registry unchanged; swap skipped"
            );
        }
        Ok(count)
    }

    /// Fetch the tool list from one upstream server.
    async fn fetch_tools_from_server(
        &self,
        server: &McpServerConfig,
    ) -> anyhow::Result<Vec<FederatedTool>> {
        // WOR-1648: an OpenAPI-backed server serves tools from its
        // spec, no MCP round-trip.
        if let Some(backing) = &server.openapi {
            let federated = backing
                .tools
                .iter()
                .filter_map(|t| {
                    FederatedTool::from_openapi_document(
                        t.clone(),
                        server.name.clone(),
                        // Preserve the existing OpenAPI behaviour:
                        // converted REST tools are single-response
                        // tools unless a later adapter explicitly
                        // introduces streaming.
                        false,
                    )
                    .ok()
                })
                .collect();
            return Ok(federated);
        }

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "tools/list".to_string(),
            params: None,
            id: Some(json!(1)),
        };

        let resp = self.dispatch_request(server, &req, &[]).await?;

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
                let streaming = tool_advertises_streaming(&t);
                FederatedTool::from_contract_document(t, server.name.clone(), streaming).ok()
            })
            .collect();

        Ok(federated)
    }

    /// Look up which server owns a tool.
    ///
    /// This compatibility accessor is unsafe to combine with a later
    /// [`Self::version_blocked`] or serialized-catalogue read for a coupled
    /// policy decision: a refresh may publish between independent calls. Use
    /// [`Self::tool_catalog_snapshot`] and retain that snapshot instead.
    pub fn resolve_tool(&self, tool_name: &str) -> Option<FederatedTool> {
        let catalog = self.tool_catalog.load();
        catalog.tools.get(tool_name).cloned()
    }

    /// Load one immutable tool-catalogue publication for a coupled
    /// read. Keep this snapshot while combining a tool with its
    /// version-gate verdict or serialized discovery view.
    pub fn tool_catalog_snapshot(&self) -> ToolCatalogSnapshot {
        ToolCatalogSnapshot {
            state: self.tool_catalog.load_full(),
            owner: Arc::clone(&self.tool_catalog_owner),
        }
    }

    /// Resolve a tool and its version-gate verdict from the same
    /// immutable publication. This is the dispatch-safe alternative
    /// to separately calling [`Self::version_blocked`] and
    /// [`Self::resolve_tool`].
    pub fn resolve_tool_with_version_block(
        &self,
        tool_name: &str,
    ) -> (Option<FederatedTool>, Option<String>) {
        self.tool_catalog_snapshot()
            .resolve_tool_with_version_block(tool_name)
    }

    /// Look up a tool only when it has a compiled caller-facing modern
    /// contract. This lets modern ingress validate the resolved
    /// advertised contract before any rollout adapter or dispatch
    /// gate, while a legacy caller continues to use [`Self::resolve_tool`].
    pub fn resolve_modern_tool(&self, tool_name: &str) -> Option<FederatedTool> {
        let catalog = self.tool_catalog.load();
        catalog
            .tools
            .get(tool_name)
            .filter(|tool| tool.is_modern_discoverable())
            .cloned()
    }

    /// List all federated tools.
    ///
    /// This compatibility accessor is unsafe to combine with a separate
    /// version-gate or serialized-catalogue read. Coupled discovery and
    /// policy surfaces must retain one [`Self::tool_catalog_snapshot`].
    pub fn list_tools(&self) -> Vec<FederatedTool> {
        let catalog = self.tool_catalog.load();
        catalog.tools.values().cloned().collect()
    }

    /// List the subset of tools that have complete, compiled modern
    /// contracts. The separate method keeps legacy discovery and
    /// routing independent from modern eligibility.
    pub fn list_modern_tools(&self) -> Vec<FederatedTool> {
        let catalog = self.tool_catalog.load();
        catalog
            .tools
            .values()
            .filter(|tool| tool.is_modern_discoverable())
            .cloned()
            .collect()
    }

    /// WOR-818: fetch the `mcpApps` capability mirrored from the
    /// upstream initialize fan-out. None when no upstream has
    /// advertised SEP-1865 yet. The gateway re-advertises whatever
    /// shape it gets so vendor-specific sub-keys reach the client.
    pub fn mcp_apps_capability(&self) -> Option<serde_json::Value> {
        self.mcp_apps_capability.load().as_ref().clone()
    }

    /// List all federated resources.
    pub fn list_resources(&self) -> Vec<FederatedResource> {
        self.resources.load().values().cloned().collect()
    }

    /// Look up which server owns a resource URI.
    pub fn resolve_resource(&self, uri: &str) -> Option<FederatedResource> {
        self.resources.load().get(uri).cloned()
    }

    /// WOR-818: fetch resource lists from every server plus any
    /// `mcpApps` capability they advertise during `initialize`. The
    /// resource registry mirrors the tool registry: server-name
    /// prefix on URI collisions, ArcSwap publishing for the hot
    /// `resources/list` path.
    ///
    /// Returns the total resource count. Per-server failures log
    /// and continue; one bad upstream does not blank the registry
    /// (same policy as `refresh_tools`).
    pub async fn refresh_resources(&self) -> anyhow::Result<usize> {
        let mut registry: HashMap<String, FederatedResource> = HashMap::new();
        // The capability snapshot published by
        // [`Self::refresh_server_capabilities`] is the single answer to
        // "what does this upstream support", so this pass no longer
        // runs an `initialize` of its own. First upstream in configured
        // order still wins, which is the order the inline probe used.
        let capabilities = self.server_capabilities.load();
        let apps_cap: Option<serde_json::Value> = self
            .servers
            .iter()
            .find_map(|s| capabilities.get(&s.name)?.get("mcpApps").cloned());

        for server in &self.servers {
            match self.fetch_resources_from_server(server).await {
                Ok(resources) => {
                    info!(
                        server = %server.name,
                        count = resources.len(),
                        "fetched resources from upstream MCP server"
                    );
                    for mut resource in resources {
                        let advertised = federated_name(
                            &server.name,
                            server.namespace,
                            '/',
                            &resource.uri,
                            |n| registry.contains_key(n),
                        );
                        if advertised != resource.uri {
                            warn!(
                                uri = %resource.uri,
                                server = %server.name,
                                advertised = %advertised,
                                "federated resource uri namespaced (collision or always-namespace)"
                            );
                        }
                        // Advertise the resolved uri; `upstream_uri` keeps the
                        // original so `resources/read` still forwards the URI
                        // the upstream advertised.
                        resource.uri = advertised.clone();
                        registry.insert(advertised, resource);
                    }
                }
                Err(e) => {
                    warn!(
                        server = %server.name,
                        error = %e,
                        "failed to fetch resources from upstream MCP server"
                    );
                }
            }
        }

        let count = registry.len();
        let digest = resources_registry_digest(&registry, &apps_cap);
        if self
            .resources_digest
            .swap(digest, std::sync::atomic::Ordering::AcqRel)
            != digest
        {
            self.resources.store(Arc::new(registry));
            self.mcp_apps_capability.store(Arc::new(apps_cap));
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.resources_generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            debug!(
                total_resources = count,
                "MCP federation resources refreshed"
            );
        } else {
            debug!(
                total_resources = count,
                "MCP federation resources unchanged; swap skipped"
            );
        }
        Ok(count)
    }

    /// Probe every MCP upstream's `initialize` once and publish the
    /// `capabilities` object each one advertised.
    ///
    /// Every registry that has to know what an upstream supports reads
    /// this snapshot rather than handshaking for itself, so the number
    /// of `initialize` round trips is one per upstream per refresh
    /// cycle no matter how many surfaces the gateway federates. Call it
    /// before [`Self::refresh_resources`] (which reads `mcpApps` out of
    /// it) and [`Self::refresh_prompts`] (which reads `prompts`).
    ///
    /// OpenAPI-backed upstreams are skipped: they speak REST, not MCP,
    /// so there is no handshake to run and no capability to read.
    /// Per-upstream failures log and continue; an upstream missing from
    /// the snapshot simply declares nothing.
    ///
    /// Returns the number of upstreams that answered.
    pub async fn refresh_server_capabilities(&self) -> usize {
        let mut snapshot: HashMap<String, serde_json::Value> = HashMap::new();
        for server in &self.servers {
            if server.openapi.is_some() {
                continue;
            }
            match self.fetch_server_capabilities(server).await {
                Ok(caps) => {
                    snapshot.insert(server.name.clone(), caps);
                }
                Err(e) => {
                    warn!(
                        server = %server.name,
                        error = %e,
                        "failed to read capabilities from upstream MCP server"
                    );
                }
            }
        }
        let count = snapshot.len();
        self.server_capabilities.store(Arc::new(snapshot));
        count
    }

    /// True when `server_name` declared the named capability on its
    /// last `initialize`. An upstream that never answered, or one the
    /// gateway never probes (OpenAPI-backed), declares nothing.
    fn server_declares(&self, server_name: &str, capability: &str) -> bool {
        self.server_capabilities
            .load()
            .get(server_name)
            .and_then(|c| c.get(capability))
            .is_some()
    }

    /// Initialize the upstream and return the whole `capabilities`
    /// object it advertised, or `Value::Null` when it advertised none.
    async fn fetch_server_capabilities(
        &self,
        server: &McpServerConfig,
    ) -> anyhow::Result<serde_json::Value> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "initialize".to_string(),
            params: Some(json!({
                "protocolVersion": super::types::LATEST_PROTOCOL_VERSION,
                "clientInfo": { "name": "sbproxy", "version": env!("CARGO_PKG_VERSION") },
                "capabilities": {},
            })),
            id: Some(json!(1)),
        };
        let resp = self.dispatch_request(server, &req, &[]).await?;
        if let Some(err) = resp.error {
            anyhow::bail!(
                "initialize error from {}: {} (code {})",
                server.name,
                err.message,
                err.code
            );
        }
        let result = resp.result.unwrap_or_default();
        Ok(result.get("capabilities").cloned().unwrap_or_default())
    }

    /// Fetch the resource list from one upstream server. Pure
    /// pass-through: the gateway does not validate URI shape, mime
    /// type, or template metadata here.
    async fn fetch_resources_from_server(
        &self,
        server: &McpServerConfig,
    ) -> anyhow::Result<Vec<FederatedResource>> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "resources/list".to_string(),
            params: None,
            id: Some(json!(1)),
        };
        let resp = self.dispatch_request(server, &req, &[]).await?;
        if let Some(err) = resp.error {
            anyhow::bail!(
                "resources/list error from {}: {} (code {})",
                server.name,
                err.message,
                err.code
            );
        }
        let result = resp.result.unwrap_or_default();
        let list = result.get("resources").cloned().unwrap_or_default();
        let defs: Vec<serde_json::Value> = serde_json::from_value(list).unwrap_or_default();
        let federated = defs
            .into_iter()
            .filter_map(|r| {
                let uri = r.get("uri")?.as_str()?.to_string();
                let name = r
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&uri)
                    .to_string();
                let description = r
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let mime_type = r.get("mimeType").and_then(|v| v.as_str()).map(String::from);
                Some(FederatedResource {
                    uri: uri.clone(),
                    upstream_uri: uri,
                    name,
                    description,
                    mime_type,
                    server_name: server.name.clone(),
                })
            })
            .collect();
        Ok(federated)
    }

    /// Read a resource through the federation. Routes to the
    /// correct upstream server based on the URI; the upstream
    /// receives the original (pre-prefix) URI it advertised so
    /// vendor servers do not have to know about the gateway's
    /// collision-avoidance scheme.
    pub async fn read_resource(&self, uri: &str) -> anyhow::Result<serde_json::Value> {
        let outcome = self.read_resource_inner(uri).await;
        let label = match &outcome {
            Ok(_) => "ok",
            Err(e) => {
                let msg = format!("{e:#}").to_ascii_lowercase();
                if msg.contains("unknown resource uri") || msg.contains("unknown server") {
                    "not_found"
                } else {
                    "upstream_error"
                }
            }
        };
        sbproxy_observe::metrics::record_mcp_resource_fetch(label);
        outcome
    }

    async fn read_resource_inner(&self, uri: &str) -> anyhow::Result<serde_json::Value> {
        let resource = self
            .resolve_resource(uri)
            .ok_or_else(|| anyhow::anyhow!("unknown resource uri: {uri}"))?;
        let server = self
            .servers
            .iter()
            .find(|s| s.name == resource.server_name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "resource {} maps to unknown server {}",
                    uri,
                    resource.server_name
                )
            })?;
        // SEP-414: a `resources/read` is work done for one inbound
        // caller, on that caller's thread of execution, so it carries
        // the trace context the same way `tools/call` does.
        let trace_pairs = sbproxy_observe::telemetry::propagation_pairs();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "resources/read".to_string(),
            params: Some(merge_trace_context(
                json!({ "uri": resource.upstream_uri }),
                &trace_pairs,
            )),
            id: Some(json!(1)),
        };
        let resp = self.dispatch_request(server, &req, &[]).await?;
        if let Some(err) = resp.error {
            anyhow::bail!(
                "resources/read error from {}: {} (code {})",
                server.name,
                err.message,
                err.code
            );
        }
        Ok(resp.result.unwrap_or_default())
    }

    // --- Prompts ---

    /// Load one immutable prompt-catalogue publication.
    ///
    /// Keep this handle from owner authorization through
    /// [`Self::get_prompt_from_snapshot`] so a refresh cannot replace the
    /// selected upstream between those steps.
    pub fn prompt_catalog_snapshot(&self) -> PromptCatalogSnapshot {
        PromptCatalogSnapshot {
            prompts: self.prompts.load_full(),
            owner: Arc::clone(&self.prompt_catalog_owner),
        }
    }

    /// List every federated prompt from one fresh registry publication.
    ///
    /// Callers that combine this list with another decision should retain one
    /// [`PromptCatalogSnapshot`] instead of calling this compatibility method.
    pub fn list_prompts(&self) -> Vec<FederatedPrompt> {
        self.prompt_catalog_snapshot().list_prompts()
    }

    /// Look up which server owns a prompt in one fresh publication.
    ///
    /// Never combine this compatibility lookup with a later authorization or
    /// dispatch. Retain one [`PromptCatalogSnapshot`] for coupled decisions.
    pub fn resolve_prompt(&self, name: &str) -> Option<FederatedPrompt> {
        self.prompt_catalog_snapshot().resolve_prompt(name).cloned()
    }

    /// The `prompts` capability object the gateway may honestly
    /// advertise on its own `initialize`, or `None` when no federated
    /// upstream declares one.
    ///
    /// `listChanged` is `false` deliberately. The gateway's
    /// server-to-client stream pushes `tools/list_changed` and
    /// `resources/list_changed` and nothing else, so a `true` here
    /// would be the same species of capability lie that keeps
    /// `2025-03-26` out of
    /// [`SUPPORTED_PROTOCOL_VERSIONS`](super::types::SUPPORTED_PROTOCOL_VERSIONS).
    pub fn prompts_capability(&self) -> Option<serde_json::Value> {
        let capabilities = self.server_capabilities.load();
        let declared = self.servers.iter().any(|s| {
            capabilities
                .get(&s.name)
                .and_then(|c| c.get("prompts"))
                .is_some()
        });
        declared.then(|| json!({ "listChanged": false }))
    }

    /// Fetch `prompts/list` from every upstream that declares the
    /// `prompts` capability and merge the answers into one registry,
    /// namespaced on exactly the rules tools use.
    ///
    /// Three classes of upstream contribute nothing rather than
    /// failing the whole refresh: an OpenAPI-backed server (it speaks
    /// REST and has no prompts to have), a server that declared no
    /// `prompts` capability (asking would earn a `-32601`), and a
    /// server whose `prompts/list` errored or timed out. One upstream
    /// without prompts must not blank the prompts of the upstreams
    /// that have them, which is the policy `refresh_tools` and
    /// `refresh_resources` already hold.
    ///
    /// Reads the capability snapshot published by
    /// [`Self::refresh_server_capabilities`], so call that first.
    ///
    /// Returns the total number of federated prompts.
    pub async fn refresh_prompts(&self) -> anyhow::Result<usize> {
        let mut fetched: Vec<(String, NamespaceMode, Vec<FederatedPrompt>)> = Vec::new();
        for server in &self.servers {
            if server.openapi.is_some() {
                continue;
            }
            if !self.server_declares(&server.name, "prompts") {
                debug!(
                    server = %server.name,
                    "upstream declares no prompts capability; contributing no prompts"
                );
                continue;
            }
            match self.fetch_prompts_from_server(server).await {
                Ok(prompts) => {
                    info!(
                        server = %server.name,
                        count = prompts.len(),
                        "fetched prompts from upstream MCP server"
                    );
                    fetched.push((server.name.clone(), server.namespace, prompts));
                }
                Err(e) => {
                    warn!(
                        server = %server.name,
                        error = %e,
                        "failed to fetch prompts from upstream MCP server"
                    );
                }
            }
        }

        let registry = merge_federated_prompts(fetched);
        let count = registry.len();
        let digest = prompts_registry_digest(&registry);
        if self
            .prompts_digest
            .swap(digest, std::sync::atomic::Ordering::AcqRel)
            != digest
        {
            self.prompts.store(Arc::new(registry));
            debug!(total_prompts = count, "MCP federation prompts refreshed");
        } else {
            debug!(
                total_prompts = count,
                "MCP federation prompts unchanged; swap skipped"
            );
        }
        Ok(count)
    }

    /// Fetch the prompt list from one upstream server. Pure
    /// pass-through: the gateway does not validate argument schemas
    /// or template shape here, the owning server does.
    async fn fetch_prompts_from_server(
        &self,
        server: &McpServerConfig,
    ) -> anyhow::Result<Vec<FederatedPrompt>> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "prompts/list".to_string(),
            params: None,
            id: Some(json!(1)),
        };
        let resp = self.dispatch_request(server, &req, &[]).await?;
        if let Some(err) = resp.error {
            anyhow::bail!(
                "prompts/list error from {}: {} (code {})",
                server.name,
                err.message,
                err.code
            );
        }
        let result = resp.result.unwrap_or_default();
        let list = result.get("prompts").cloned().unwrap_or_default();
        let defs: Vec<serde_json::Value> = serde_json::from_value(list).unwrap_or_default();
        let federated = defs
            .into_iter()
            .filter_map(|p| {
                let name = p.get("name")?.as_str()?.to_string();
                Some(FederatedPrompt {
                    upstream_name: name.clone(),
                    name,
                    title: p.get("title").and_then(|v| v.as_str()).map(String::from),
                    description: p
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    arguments: p.get("arguments").cloned(),
                    server_name: server.name.clone(),
                    meta: p.get("_meta").cloned(),
                })
            })
            .collect();
        Ok(federated)
    }

    /// Fetch a prompt through one fresh prompt-catalogue publication.
    ///
    /// This compatibility wrapper is safe only when no separate authorization
    /// decision preceded it. Authorization-aware callers must use
    /// [`Self::get_prompt_from_snapshot`] with the exact held snapshot.
    pub async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        let catalog = self.prompt_catalog_snapshot();
        self.get_prompt_from_snapshot(&catalog, name, arguments)
            .await
    }

    /// Fetch a prompt using the exact immutable publication held by a prior
    /// ownership and authorization decision.
    ///
    /// The upstream receives the name it advertised, so a vendor
    /// server never has to know about the gateway's
    /// collision-avoidance scheme. That is the contract
    /// [`Self::read_resource`] already holds for resource URIs.
    pub async fn get_prompt_from_snapshot(
        &self,
        catalog: &PromptCatalogSnapshot,
        name: &str,
        arguments: Option<serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        if !Arc::ptr_eq(&self.prompt_catalog_owner, &catalog.owner) {
            anyhow::bail!("invalid prompt catalogue snapshot");
        }
        let prompt = catalog
            .resolve_prompt(name)
            .ok_or_else(|| anyhow::anyhow!("unknown prompt: {name}"))?;
        let server = self
            .servers
            .iter()
            .find(|s| s.name == prompt.server_name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "prompt {} maps to unknown server {}",
                    name,
                    prompt.server_name
                )
            })?;
        let mut params = json!({ "name": prompt.upstream_name });
        if let (Some(args), Some(obj)) = (arguments, params.as_object_mut()) {
            obj.insert("arguments".to_string(), args);
        }
        // SEP-414: a `prompts/get` is work done for one inbound
        // caller, on that caller's thread of execution, so it carries
        // the trace context `tools/call` and `resources/read` do.
        let trace_pairs = sbproxy_observe::telemetry::propagation_pairs();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "prompts/get".to_string(),
            params: Some(merge_trace_context(params, &trace_pairs)),
            id: Some(json!(1)),
        };
        let resp = self.dispatch_request(server, &req, &[]).await?;
        if let Some(err) = resp.error {
            anyhow::bail!(
                "prompts/get error from {}: {} (code {})",
                server.name,
                err.message,
                err.code
            );
        }
        Ok(resp.result.unwrap_or_default())
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
        let catalog = self.tool_catalog.load_full();
        codemode_ts_for_catalog(&catalog, callback_base_url)
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
        self.call_tool_with_upstream_headers(tool_name, arguments, &[])
            .await
    }

    /// Call a tool with optional upstream HTTP headers (WOR-1792).
    ///
    /// Use this after [`super::auth::mint_upstream_authorization`] so
    /// the minted `Authorization` reaches the upstream POST. Headers
    /// are never logged and never injected into tool arguments.
    pub async fn call_tool_with_upstream_headers(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        upstream_headers: &[(String, String)],
    ) -> anyhow::Result<serde_json::Value> {
        match self
            .call_tool_with_policy_cause_and_headers(
                tool_name,
                arguments,
                None,
                "",
                "",
                None,
                upstream_headers,
            )
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

    /// Call a tool using the exact immutable catalogue publication held by a
    /// prior decision. The snapshot type cannot be constructed outside this
    /// module, so callers cannot forge or mutate the server routing fields
    /// after policy and version-gate checks. Core dispatch uses this after
    /// those gates so publication cannot replace the selected upstream before
    /// the outbound request.
    pub async fn call_tool_with_upstream_headers_from_snapshot(
        &self,
        catalog: &ToolCatalogSnapshot,
        tool_name: &str,
        arguments: serde_json::Value,
        upstream_headers: &[(String, String)],
    ) -> anyhow::Result<serde_json::Value> {
        if !Arc::ptr_eq(&self.tool_catalog_owner, &catalog.owner) {
            anyhow::bail!("tool catalogue snapshot belongs to another federation");
        }
        let (held_tool, version_blocked) = catalog.resolve_tool_with_version_block(tool_name);
        if version_blocked.is_some() {
            anyhow::bail!("tool is blocked by the held catalogue version gate");
        }
        match self
            .call_tool_with_policy_cause_and_headers_from_held_tool(
                held_tool,
                tool_name,
                arguments,
                None,
                "",
                "",
                None,
                upstream_headers,
            )
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
    /// An empty `correlation_id` is not passed to the hook verbatim.
    /// WOR-2139 resolves it to the active W3C trace id, the same trace
    /// the upstream receives in `params._meta.traceparent`, so a hook
    /// verdict and the tool call it gated share a key. It stays empty
    /// when nothing is traced. A caller that supplies its own value
    /// keeps it.
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
        self.call_tool_with_policy_and_cause(
            tool_name,
            arguments,
            agent_id,
            correlation_id,
            workspace_id,
            None,
        )
        .await
    }

    /// WOR-818 PR2 variant of [`Self::call_tool_with_policy`] that
    /// additionally threads the OpenAI Apps SDK `params.audit.cause`
    /// value to the policy hooks. Existing callers stay on the
    /// `_with_policy` shim and lose no behaviour; new callers that
    /// have extracted the cause from the inbound JSON-RPC envelope
    /// surface it here so an enterprise hook can audit which UI
    /// element triggered the call.
    pub async fn call_tool_with_policy_and_cause(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        agent_id: Option<&str>,
        correlation_id: &str,
        workspace_id: &str,
        audit_cause: Option<&str>,
    ) -> anyhow::Result<McpCallOutcome> {
        self.call_tool_with_policy_cause_and_headers(
            tool_name,
            arguments,
            agent_id,
            correlation_id,
            workspace_id,
            audit_cause,
            &[],
        )
        .await
    }

    /// Policy-aware tool call that also forwards upstream HTTP headers
    /// (run-as-user Authorization) on the wire.
    ///
    /// This is where the outbound `tools/call` envelope is built, so it
    /// is also where SEP-414 trace context is attached: the active
    /// trace goes into `params._meta` with unprefixed keys, which
    /// reaches the upstream on every transport including stdio. See
    /// `merge_trace_context` for why the body rather than a header.
    #[allow(clippy::too_many_arguments)] // policy identity + audit + upstream auth seams
    pub async fn call_tool_with_policy_cause_and_headers(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        agent_id: Option<&str>,
        correlation_id: &str,
        workspace_id: &str,
        audit_cause: Option<&str>,
        upstream_headers: &[(String, String)],
    ) -> anyhow::Result<McpCallOutcome> {
        let catalog = self.tool_catalog_snapshot();
        self.call_tool_with_policy_cause_and_headers_from_held_tool(
            catalog.resolve_tool(tool_name),
            tool_name,
            arguments,
            agent_id,
            correlation_id,
            workspace_id,
            audit_cause,
            upstream_headers,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)] // policy identity + held catalog entry seam
    async fn call_tool_with_policy_cause_and_headers_from_held_tool(
        &self,
        federated: Option<FederatedTool>,
        tool_name: &str,
        arguments: serde_json::Value,
        agent_id: Option<&str>,
        correlation_id: &str,
        workspace_id: &str,
        audit_cause: Option<&str>,
        upstream_headers: &[(String, String)],
    ) -> anyhow::Result<McpCallOutcome> {
        let federated = federated.ok_or_else(|| anyhow::anyhow!("unknown tool: {}", tool_name))?;
        if federated.name != tool_name {
            anyhow::bail!("held tool name mismatch");
        }
        // Once a snapshot entry was accepted, every hook, outbound
        // request, and OpenAPI route must use its advertised name,
        // not a separate caller-supplied string.
        let tool_name = federated.name.as_str();

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

        // WOR-2139: read the active trace context once, up front, and
        // use it for both things that need it below: the hook's
        // `correlation_id` and the SEP-414 `_meta` block on the
        // outbound request. Reading it twice could hand the hook one
        // trace id and the upstream another if the span changed in
        // between, which is precisely the correlation failure this
        // change exists to fix.
        let trace_pairs = sbproxy_observe::telemetry::propagation_pairs();
        // The caller's own correlation id wins whenever it set one.
        // Empty is the documented "unset" sentinel, and every
        // production caller passes it, so fall back to the active
        // trace id: it is a real value, and it is the same trace the
        // upstream is about to receive in `params._meta.traceparent`,
        // so a hook's logs join to the tool call they gated. Still
        // empty when nothing is traced.
        let correlation_id = if correlation_id.is_empty() {
            trace_id_from_traceparent(&trace_pairs).unwrap_or("")
        } else {
            correlation_id
        };

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
                    audit_cause,
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

        // WOR-1648: an OpenAPI-backed tool dispatches as a REST call
        // instead of an MCP tools/call.
        if let Some(backing) = &server.openapi {
            return self
                .call_openapi_tool(
                    server,
                    backing,
                    &federated.name,
                    &arguments,
                    upstream_headers,
                )
                .await;
        }

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "tools/call".to_string(),
            params: Some(merge_trace_context(
                json!({
                    "name": tool_name,
                    "arguments": arguments,
                }),
                &trace_pairs,
            )),
            id: Some(json!(1)),
        };

        debug!(
            tool = tool_name,
            server = %server.name,
            "routing tool call to upstream server"
        );

        let resp = self
            .dispatch_request(server, &req, upstream_headers)
            .await?;

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

    /// WOR-1648: dispatch an OpenAPI-backed tool as a REST request.
    /// Path parameters are substituted from the arguments; for a GET
    /// the remaining arguments become the query string, otherwise
    /// they form the JSON body. The response is wrapped in the MCP
    /// tool-result content shape so a base-MCP client sees a normal
    /// result. `federated_name` is the resolved (possibly namespaced)
    /// name; the route table is keyed by the tool's original name, so
    /// we strip any `<server>.` prefix first.
    async fn call_openapi_tool(
        &self,
        server: &McpServerConfig,
        backing: &OpenApiBacking,
        federated_name: &str,
        arguments: &serde_json::Value,
        upstream_headers: &[(String, String)],
    ) -> anyhow::Result<McpCallOutcome> {
        self.call_openapi_tool_with_resolver(
            server,
            backing,
            federated_name,
            arguments,
            upstream_headers,
            &SystemHostResolver,
        )
        .await
    }

    /// [`Self::call_openapi_tool`] with an injected resolver, so tests
    /// can simulate a DNS answer that changes between authorization and
    /// dial without live DNS (WOR-2080). Production always passes
    /// [`SystemHostResolver`].
    async fn call_openapi_tool_with_resolver(
        &self,
        server: &McpServerConfig,
        backing: &OpenApiBacking,
        federated_name: &str,
        arguments: &serde_json::Value,
        upstream_headers: &[(String, String)],
        resolver: &dyn HostResolver,
    ) -> anyhow::Result<McpCallOutcome> {
        let bare = federated_name
            .strip_prefix(&format!("{}.", server.name))
            .unwrap_or(federated_name);
        let (method, path_template) = backing
            .routes
            .get(bare)
            .or_else(|| backing.routes.get(federated_name))
            .ok_or_else(|| anyhow::anyhow!("no OpenAPI route for tool {federated_name}"))?;

        // Substitute {param} path segments from the arguments, and
        // collect the leftovers for query/body.
        let args_obj = arguments.as_object().cloned().unwrap_or_default();
        let mut consumed = std::collections::HashSet::new();
        let mut path = path_template.clone();
        for (k, v) in &args_obj {
            let placeholder = format!("{{{k}}}");
            if path.contains(&placeholder) {
                let rendered = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                path = path.replace(&placeholder, &urlencoding_encode(&rendered));
                consumed.insert(k.clone());
            }
        }
        let base = backing.base_url.trim_end_matches('/');
        let url = Url::parse(&format!("{base}{path}"))
            .map_err(|e| anyhow::anyhow!("invalid OpenAPI REST URL for {federated_name}: {e}"))?;
        // Deny unlisted hosts before any I/O (WOR-1791 / G2).
        let mut dest = backing
            .egress_policy
            .authorize(EgressPurpose::OpenApiTool, url.as_str(), resolver)
            .map_err(|e| anyhow::anyhow!("egress denied: {e:?}"))?;

        let leftovers: serde_json::Map<String, serde_json::Value> = args_obj
            .into_iter()
            .filter(|(k, _)| !consumed.contains(k))
            .collect();

        let is_get = method.eq_ignore_ascii_case("GET");
        let http_method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid HTTP method {method}: {e}"))?;
        let query: Vec<(String, String)> = if is_get {
            leftovers
                .iter()
                .map(|(k, v)| {
                    let val = match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    (k.clone(), val)
                })
                .collect()
        } else {
            Vec::new()
        };
        let body = if !is_get && !leftovers.is_empty() {
            Some(serde_json::Value::Object(leftovers))
        } else {
            None
        };

        let mut redirects = 0usize;
        let resp = loop {
            // WOR-2080: immediately before connect, re-verify this
            // hop's dial addresses against the pins recorded when the
            // destination was authorized, and hand the connector only
            // the verified set. A DNS answer that changed since the
            // egress check refuses here instead of being dialled.
            let client = self.openapi_dial_client(backing, &dest, resolver)?;
            let mut builder = client.request(http_method.clone(), dest.url.clone());
            // WOR-2139: an OpenAPI-backed tool dispatches as a plain
            // REST request, so its carrier is the HTTP header, not the
            // `_meta` block a JSON-RPC body would have carried. Header
            // injection is re-applied per redirect attempt so a
            // followed hop is traced too, and `traceparent` is not a
            // credential, so it rides along on an authorized redirect
            // rather than being stripped with the Authorization.
            builder = sbproxy_observe::telemetry::inject_into_reqwest(builder);
            for (name, value) in upstream_headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            // WOR-2314: static per-server headers ride on the same
            // wire as the minted run-as-user set, re-applied per
            // redirect attempt under the same egress authorization. A
            // per-call header of the same name wins so run-as-user
            // minting cannot be shadowed by config.
            for (name, value) in &backing.headers {
                if upstream_headers
                    .iter()
                    .any(|(existing, _)| existing.eq_ignore_ascii_case(name))
                {
                    continue;
                }
                builder = builder.header(name.as_str(), value.as_str());
            }
            if !query.is_empty() {
                builder = builder.query(&query);
            }
            if let Some(body) = &body {
                builder = builder.json(body);
            }
            let resp = builder.send().await.map_err(|e| {
                sbproxy_observe::metrics::record_mcp_upstream_io_failure(classify_io_failure(
                    &anyhow::anyhow!(e.to_string()),
                ));
                anyhow::anyhow!("openapi REST call to {} failed: {e}", dest.url)
            })?;
            if !resp.status().is_redirection() {
                break resp;
            }
            let Some(location) = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
            else {
                break resp;
            };
            redirects += 1;
            if redirects > 10 {
                anyhow::bail!("openapi REST call to {} exceeded redirect limit", dest.url);
            }
            // Re-authorize redirect target before any second connect.
            // The loop top then re-verifies the new hop's pins before
            // its dial, so every hop gets the same rebind defense.
            let (next, _strip) = backing
                .egress_policy
                .authorize_redirect(&dest, location, resolver)
                .map_err(|e| anyhow::anyhow!("egress denied: {e:?}"))?;
            dest = next;
        };
        let status = resp.status();
        let body = super::streamable::read_body_capped(resp, self.max_response_bytes).await?;
        let text = String::from_utf8_lossy(&body).to_string();
        // Present the REST response as MCP tool-result content. A
        // non-2xx status maps to isError so the caller sees a tool
        // error, not a transport success.
        Ok(McpCallOutcome::Allowed(json!({
            "content": [{"type": "text", "text": text}],
            "isError": !status.is_success(),
        })))
    }

    /// Build the client for one OpenAPI dial of `dest` (WOR-2080).
    ///
    /// A pinned destination gets a per-dial client whose resolver
    /// override carries exactly the verified pin set, so the connector
    /// cannot re-resolve the host on its own; a rebound DNS answer is
    /// refused with the closed `DnsPinMismatch` reason before any
    /// connect. An unpinned destination (legacy allow-by-default
    /// egress records no pins) keeps the shared re-resolving client,
    /// preserving pre-WOR-2080 behaviour for that explicit opt-out.
    fn openapi_dial_client(
        &self,
        backing: &OpenApiBacking,
        dest: &AuthorizedDestination,
        resolver: &dyn HostResolver,
    ) -> anyhow::Result<reqwest::Client> {
        let Some(addrs) = backing
            .egress_policy
            .verified_dial_addrs(dest, resolver)
            .map_err(|e| anyhow::anyhow!("egress denied: {e:?}"))?
        else {
            return Ok(self.openapi_client.clone());
        };
        let host = dest
            .url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("authorized OpenAPI URL lost its host"))?;
        // Unlike the constructor's shared clients, a builder failure
        // here must not fall back to a default client: a default
        // client would re-resolve and silently drop the pin defense.
        reqwest::Client::builder()
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addrs)
            .build()
            .map_err(|e| anyhow::anyhow!("pinned OpenAPI client construction failed: {e}"))
    }

    /// Dispatch a request to an upstream server using the configured transport.
    ///
    /// `extra_headers` are attached on HTTP transports (streamable / SSE).
    /// Non-empty headers on `stdio` fail closed: there is no safe
    /// secret-delivery path for local child processes yet.
    async fn dispatch_request(
        &self,
        server: &McpServerConfig,
        req: &JsonRpcRequest,
        extra_headers: &[(String, String)],
    ) -> anyhow::Result<JsonRpcResponse> {
        let result = match server.transport.as_str() {
            "sse" => {
                send_via_sse(
                    &self.client,
                    &server.url,
                    req,
                    self.max_response_bytes,
                    extra_headers,
                )
                .await
            }
            "stdio" => {
                if !extra_headers.is_empty() {
                    anyhow::bail!(
                        "run-as-user credentials cannot be delivered over stdio transport"
                    );
                }
                super::stdio::send_via_stdio(
                    &server.url,
                    req,
                    self.max_response_bytes,
                    self.stdio_timeout,
                )
                .await
            }
            // Default to streamable HTTP for "streamable_http" or unknown.
            _ => {
                send_request(
                    &self.client,
                    &server.url,
                    req,
                    self.max_response_bytes,
                    extra_headers,
                )
                .await
            }
        };
        if let Err(e) = &result {
            sbproxy_observe::metrics::record_mcp_upstream_io_failure(classify_io_failure(e));
        }
        result
    }

    /// Test-only: publish a tool registry and its matching version-gate
    /// verdicts directly, then bump both catalog generations. `None`
    /// represents an unblocked publication. Production refreshes use the
    /// same synchronous publication seam after their final await.
    ///
    /// Keeping one test-support entry point avoids widening the public API
    /// every time the immutable publication gains another coupled field.
    #[doc(hidden)]
    pub fn seed_tools_for_test(
        &self,
        tools: HashMap<String, FederatedTool>,
        version_blocked: Option<HashMap<String, String>>,
    ) {
        let legacy_digest = tools_registry_digest(&tools);
        let modern_digest = modern_tools_registry_digest(&tools);
        self.publish_tool_refresh(
            tools,
            legacy_digest,
            modern_digest,
            true,
            true,
            Some(version_blocked.unwrap_or_default()),
        );
        self.primed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Publish every state component of a completed refresh without
    /// awaiting. Keeping this seam synchronous means cancellation can
    /// only occur before publication, leaving the previous coherent
    /// snapshot in place for an identical retry.
    fn publish_tool_refresh(
        &self,
        registry: HashMap<String, FederatedTool>,
        legacy_digest: u64,
        modern_digest: [u8; 32],
        legacy_changed: bool,
        modern_changed: bool,
        version_blocked: Option<HashMap<String, String>>,
    ) {
        debug_assert!(legacy_changed || modern_changed);

        let previous = self.tool_catalog.load_full();
        let version_blocked = version_blocked
            .map(Arc::new)
            .unwrap_or_else(|| Arc::clone(&previous.version_blocked));
        let verdict_changed = previous.version_blocked.as_ref() != version_blocked.as_ref();
        let tools_generation = previous.tools_generation + u64::from(legacy_changed);
        let modern_tools_generation = previous.modern_tools_generation + u64::from(modern_changed);
        let codemode_generation =
            previous.codemode_generation + u64::from(legacy_changed || verdict_changed);
        // Build both read snapshots before the one ArcSwap store.
        // Readers that retain either the old or new state therefore
        // always see its matching registry, verdicts, generations, and
        // serialized bytes. There is no await after this point.
        let legacy_serialized = if legacy_changed {
            Arc::new(build_legacy_serialized_tools(&registry, tools_generation))
        } else {
            Arc::clone(&previous.legacy_serialized)
        };
        let modern_serialized = if modern_changed {
            Arc::new(build_modern_serialized_tools(
                &registry,
                modern_tools_generation,
            ))
        } else {
            Arc::clone(&previous.modern_serialized)
        };
        let next = ToolCatalogState {
            tools: Arc::new(registry),
            version_blocked,
            legacy_digest: if legacy_changed {
                legacy_digest
            } else {
                previous.legacy_digest
            },
            modern_digest: if modern_changed {
                modern_digest
            } else {
                previous.modern_digest
            },
            tools_generation,
            modern_tools_generation,
            codemode_generation,
            legacy_serialized,
            modern_serialized,
        };
        self.tool_catalog.store(Arc::new(next));
        if legacy_changed {
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
    }

    /// Current cross-surface generation. Starts at zero and bumps once
    /// per frozen-legacy tool or resource refresh that actually
    /// changes its registry. Tool caches use immutable state-local
    /// generations, so resource changes cannot perturb tool cache
    /// identities.
    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Tool-registry generation (WOR-1642): bumps only when the tool
    /// catalogue changes, driving `tools/list_changed` notifications.
    pub fn tools_generation(&self) -> u64 {
        self.tool_catalog.load().tools_generation
    }

    /// Modern tool-catalogue generation. It advances for a complete
    /// modern field change even when the frozen legacy projection,
    /// global generation, and CodeMode cache remain unchanged.
    pub fn modern_tools_generation(&self) -> u64 {
        self.tool_catalog.load().modern_tools_generation
    }

    /// Resource-registry generation (WOR-1642): bumps only when the
    /// resource catalogue (or mirrored mcpApps capability) changes.
    pub fn resources_generation(&self) -> u64 {
        self.resources_generation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Pre-serialized frozen legacy tool catalogue for the current
    /// immutable publication. Publication builds it before swapping
    /// the state, so this read cannot pair old bytes with a new tool.
    ///
    /// This compatibility accessor is unsafe to combine with a separate
    /// [`Self::version_blocked`] read. Coupled discovery callers must retain
    /// one [`Self::tool_catalog_snapshot`] and read both values from it.
    pub fn serialized_tools(&self) -> Arc<SerializedTools> {
        let catalog = self.tool_catalog.load_full();
        legacy_serialized_tools_for_catalog(&catalog)
    }

    /// Pre-serialized complete modern catalogue for the current
    /// modern generation. This is intentionally distinct from
    /// [`Self::serialized_tools`] so a title, icon, outputSchema, or
    /// extension-only change cannot replace the frozen legacy cache.
    ///
    /// For a coupled discovery or policy decision, use
    /// [`Self::tool_catalog_snapshot`] rather than combining this accessor
    /// with a later registry or verdict read.
    pub fn serialized_modern_tools(&self) -> Arc<ModernSerializedTools> {
        let catalog = self.tool_catalog.load_full();
        Arc::clone(&catalog.modern_serialized)
    }

    /// Codemode.ts module + strong ETag for the current visible generation
    /// and callback base (WOR-1640). Re-emits and re-hashes only when
    /// either changes; a warm cache hit is a lock-free load.
    pub fn codemode_ts_cached(&self, callback_base: &str) -> (Arc<String>, String) {
        let catalog = self.tool_catalog.load_full();
        let generation = catalog.codemode_generation;
        let current = self.codemode_cache.load_full();
        if current.generation == generation && current.callback_base == callback_base {
            return (Arc::clone(&current.module), current.etag.clone());
        }
        let module = Arc::new(codemode_ts_for_catalog(&catalog, callback_base));
        let digest = <sha2::Sha256 as sha2::Digest>::digest(module.as_bytes());
        let etag = format!("\"{}\"", hex::encode(digest));
        // Do not cache an old module under a later state generation
        // if publication raced this cold miss. Returning the coherent
        // held snapshot is safe; the next reader will build the newer
        // state from its own snapshot.
        let still_current = self.tool_catalog.load_full();
        if Arc::ptr_eq(&catalog, &still_current) {
            self.codemode_cache.store(Arc::new(CodemodeCache {
                generation,
                callback_base: callback_base.to_string(),
                module: Arc::clone(&module),
                etag: etag.clone(),
            }));
        }
        (module, etag)
    }

    /// Advertised tool names currently blocked by the version gate,
    /// mapped to the violation detail (WOR-1635). Empty when the gate
    /// is off, in warn mode, or has nothing to block.
    ///
    /// This compatibility accessor is unsafe to combine with a separate
    /// registry, resolve, or serialized-catalogue read. Use
    /// [`Self::tool_catalog_snapshot`] for coupled decisions.
    pub fn version_blocked(&self) -> Arc<HashMap<String, String>> {
        let catalog = self.tool_catalog.load_full();
        Arc::clone(&catalog.version_blocked)
    }

    /// Replace only the verdict map while retaining every other
    /// component of one immutable publication. This is exercised by
    /// the test-only direct versioning seam; production refreshes
    /// publish a fresh registry and verdict map together.
    #[cfg(test)]
    fn publish_tool_version_blocked(&self, version_blocked: HashMap<String, String>) {
        let current = self.tool_catalog.load_full();
        if current.version_blocked.as_ref() == &version_blocked {
            return;
        }
        self.tool_catalog.store(Arc::new(ToolCatalogState {
            tools: Arc::clone(&current.tools),
            version_blocked: Arc::new(version_blocked),
            legacy_digest: current.legacy_digest,
            modern_digest: current.modern_digest,
            tools_generation: current.tools_generation,
            modern_tools_generation: current.modern_tools_generation,
            codemode_generation: current.codemode_generation + 1,
            legacy_serialized: Arc::clone(&current.legacy_serialized),
            modern_serialized: Arc::clone(&current.modern_serialized),
        }));
    }

    /// WOR-1635: diff a freshly fetched catalogue against the
    /// lockfile baseline, lint declared bumps, and (in Block mode)
    /// publish the violating tool set. Runs only when the catalogue
    /// content changed. Fail-open: an unreadable lockfile clears the
    /// blocked set and reports `lockfile_error`.
    #[cfg(test)]
    async fn evaluate_tool_versioning(&self, registry: &HashMap<String, FederatedTool>) {
        if let Some(blocked) = self.evaluate_tool_versioning_snapshot(registry).await {
            let legacy_digest = tools_registry_digest(registry);
            let modern_digest = modern_tools_registry_digest(registry);
            let current = self.tool_catalog.load_full();
            let legacy_changed = current.legacy_digest != legacy_digest;
            let modern_changed = current.modern_digest != modern_digest;
            if legacy_changed || modern_changed {
                self.publish_tool_refresh(
                    registry.clone(),
                    legacy_digest,
                    modern_digest,
                    legacy_changed,
                    modern_changed,
                    Some(blocked),
                );
            } else {
                // Test-only direct evaluation still keeps a matching
                // registry and verdict in one immutable publication.
                self.publish_tool_version_blocked(blocked);
            }
        }
    }

    /// Evaluate the versioning gate without publishing its result.
    /// `refresh_tools` awaits this before it mutates any catalogue
    /// state, then commits the returned blocked set alongside the
    /// matching registry and digests in [`Self::publish_tool_refresh`].
    async fn evaluate_tool_versioning_snapshot(
        &self,
        registry: &HashMap<String, FederatedTool>,
    ) -> Option<HashMap<String, String>> {
        let gate = self.versioning.as_ref()?;
        let lockfile = match std::fs::read_to_string(&gate.lockfile_path)
            .map_err(anyhow::Error::from)
            .and_then(|y| super::compat::Lockfile::from_yaml(&y))
        {
            Ok(l) => l,
            Err(e) => {
                error!(
                    lockfile = %gate.lockfile_path,
                    error = %e,
                    "tool-versioning lockfile unreadable; gate fails open"
                );
                sbproxy_observe::metrics::record_mcp_tool_compat_verdict("none", "lockfile_error");
                return Some(HashMap::new());
            }
        };

        let mut blocked: HashMap<String, String> = HashMap::new();
        for (name, tool) in registry {
            let Some(lock) = lockfile.tools.get(name) else {
                // New tool: nothing to diff against.
                continue;
            };
            let live_contract = legacy_compatibility_contract(tool);
            let live_digest = super::compat::contract_digest(&live_contract);
            if live_digest == lock.contract_digest {
                continue;
            }
            // Contract moved: grade it. With the full baseline
            // contract in the lockfile the grade is structural;
            // digest-only baselines can still prove "changed", which
            // is at least a patch.
            let verdict = match lock.contract.as_ref() {
                Some(old_contract) => {
                    let inputs = super::compat::OracleInputs {
                        tool: name,
                        old_tool: old_contract,
                        new_tool: &live_contract,
                        old_response: None,
                        new_response: None,
                    };
                    if gate.judges.is_empty() {
                        super::compat::evaluate_compatibility(&inputs)
                    } else {
                        // WOR-1637: run the description-semantics
                        // jury. A judge failure falls back to the
                        // deterministic dimensions so the gate never
                        // hard-fails on a model hiccup.
                        let judge_refs: Vec<&dyn super::compat::Judge> =
                            gate.judges.iter().map(|j| j.as_ref()).collect();
                        match super::compat::evaluate_compatibility_full(
                            &inputs,
                            &super::compat::SemanticsConfig::default(),
                            &judge_refs,
                        )
                        .await
                        {
                            Ok(v) => v,
                            Err(e) => {
                                warn!(
                                    tool = %name,
                                    error = %e,
                                    "description-semantics judge failed; falling back to structural grade"
                                );
                                sbproxy_observe::metrics::record_mcp_tool_compat_verdict(
                                    "none",
                                    "judge_error",
                                );
                                super::compat::evaluate_compatibility(&inputs)
                            }
                        }
                    }
                }
                None => super::compat::CompatibilityVerdict {
                    tool: name.clone(),
                    from_digest: lock.contract_digest.clone(),
                    to_digest: live_digest,
                    grade: super::compat::SemverGrade::Patch,
                    findings: Vec::new(),
                    behavioral_evaluated: false,
                    needs_confirmation: false,
                },
            };
            let declared = gate.declared_versions.get(name).unwrap_or(&lock.semver);
            let grade_label = match verdict.grade {
                super::compat::SemverGrade::None => "none",
                super::compat::SemverGrade::Patch => "patch",
                super::compat::SemverGrade::Minor => "minor",
                super::compat::SemverGrade::Major => "major",
            };
            match super::compat::lint_bump(&lock.semver, declared, &verdict) {
                super::compat::BumpVerdict::Ok => {
                    sbproxy_observe::metrics::record_mcp_tool_compat_verdict(grade_label, "ok");
                    info!(
                        target: "sbproxy::audit",
                        event = "mcp.tool_versioning.changed",
                        tool = %name,
                        grade = grade_label,
                        prior = %lock.semver,
                        declared = %declared,
                        "tool contract changed with a matching version bump"
                    );
                }
                super::compat::BumpVerdict::Violation { detail, .. } => {
                    if verdict.needs_confirmation {
                        // WOR-1637: a split jury is a signal to a
                        // human, not a hard verdict; report it and
                        // leave traffic alone even in block mode.
                        sbproxy_observe::metrics::record_mcp_tool_compat_verdict(
                            grade_label,
                            "needs_confirmation",
                        );
                        warn!(
                            target: "sbproxy::audit",
                            event = "mcp.tool_versioning.needs_confirmation",
                            tool = %name,
                            grade = grade_label,
                            detail = %detail,
                            "jury split on the description change; confirm manually"
                        );
                        continue;
                    }
                    sbproxy_observe::metrics::record_mcp_tool_compat_verdict(
                        grade_label,
                        "violation",
                    );
                    warn!(
                        target: "sbproxy::audit",
                        event = "mcp.tool_versioning.violation",
                        tool = %name,
                        grade = grade_label,
                        mode = ?gate.mode,
                        detail = %detail,
                        security = verdict.findings.iter().any(|f| f.security),
                        "tool contract changed without a matching version bump"
                    );
                    if gate.mode == VersioningMode::Block {
                        blocked.insert(name.clone(), detail);
                    }
                }
            }
        }
        // Tools that vanished from the live catalogue but exist in
        // the baseline: report, never block (there is nothing left
        // to block).
        for locked_name in lockfile.tools.keys() {
            if !registry.contains_key(locked_name) {
                sbproxy_observe::metrics::record_mcp_tool_compat_verdict("major", "removed_tool");
                warn!(
                    target: "sbproxy::audit",
                    event = "mcp.tool_versioning.removed",
                    tool = %locked_name,
                    "locked tool no longer advertised by any upstream"
                );
            }
        }
        Some(blocked)
    }

    /// Make the federation servable: spawn the periodic refresh task
    /// on first use and run the cold-start prime (one tools fetch, one
    /// capability probe, one resources fetch, one prompts fetch)
    /// exactly once, single-flight. Requests arriving after the prime
    /// serve the ArcSwap snapshot and never fan out to upstreams
    /// inline; the background task is the only steady-state refresher.
    ///
    /// A prime failure still marks the federation primed: serving an
    /// empty catalogue until the next interval tick beats retrying
    /// the fan-out on every inbound request (the failure mode this
    /// replaces).
    pub async fn ensure_ready(self: &Arc<Self>, interval: std::time::Duration) {
        if !self
            .refresh_task_started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.start_refresh_task(interval);
        }
        if self.primed.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let _guard = self.prime_lock.lock().await;
        if self.primed.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        if let Err(e) = self.refresh_tools().await {
            error!(error = %e, "MCP federation initial tool refresh failed");
        }
        // Capabilities first: both refreshes below read the snapshot
        // it publishes rather than handshaking for themselves.
        self.refresh_server_capabilities().await;
        if let Err(e) = self.refresh_resources().await {
            error!(error = %e, "MCP federation initial resource refresh failed");
        }
        if let Err(e) = self.refresh_prompts().await {
            error!(error = %e, "MCP federation initial prompt refresh failed");
        }
        self.primed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Start a background task to refresh the tool, resource, and
    /// prompt registries periodically.
    ///
    /// The task holds only a `Weak` reference: when a hot reload
    /// rebuilds the action and drops the last `Arc`, the task exits
    /// at its next tick instead of pinning the federation (and its
    /// upstream fan-out) forever.
    pub fn start_refresh_task(self: &Arc<Self>, interval: std::time::Duration) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let interval = interval.max(std::time::Duration::from_secs(1));
            loop {
                tokio::time::sleep(interval).await;
                let Some(federation) = weak.upgrade() else {
                    debug!("MCP federation dropped; refresh task exiting");
                    break;
                };
                if let Err(e) = federation.refresh_tools().await {
                    error!(error = %e, "MCP federation tool refresh failed");
                }
                federation.refresh_server_capabilities().await;
                if let Err(e) = federation.refresh_resources().await {
                    error!(error = %e, "MCP federation resource refresh failed");
                }
                if let Err(e) = federation.refresh_prompts().await {
                    error!(error = %e, "MCP federation prompt refresh failed");
                }
            }
        });
    }
}

// --- WOR-2139: SEP-414 trace-context propagation ---

/// Merge the active trace context into a JSON-RPC `params` value's
/// `_meta` block, per SEP-414.
///
/// # Why the body and not a header
///
/// MCP has three transports here and only two of them have headers at
/// all. `dispatch_request` refuses to put anything header-shaped on
/// the stdio transport, because a local child process has no safe
/// delivery path for one. `params._meta` rides inside the JSON-RPC
/// body, so it is the single carrier that reaches every upstream the
/// gateway can talk to. That is what decides it.
///
/// # Why the keys are bare
///
/// SEP-414 reserves the trace-context keys inside `_meta` unprefixed,
/// as a documented exception to MCP's DNS-prefixing rule. See
/// [`super::types::META_TRACEPARENT`] for the SEP's own statement of
/// why. The reserved set is the filter: anything a propagator emits
/// that SEP-414 does not reserve gets no exception from the prefixing
/// rule, so it is dropped rather than written bare.
///
/// # Merging
///
/// An existing `_meta` is merged into, never replaced, so a caller's
/// own metadata survives. The trace keys themselves are authoritative
/// on this hop and do overwrite: the gateway is the one that knows
/// which trace this outbound call belongs to, and a stale inbound
/// `traceparent` left in place would point at the wrong parent. An
/// existing `_meta` that is not a JSON object is left exactly as it
/// is; reshaping a caller's value to make room for our own is worse
/// than propagating nothing.
///
/// With nothing to propagate, `params` comes back untouched and no
/// `_meta` key is created. An empty `_meta` would read downstream as a
/// broken trace rather than an absent one.
fn merge_trace_context(params: serde_json::Value, pairs: &[(String, String)]) -> serde_json::Value {
    let reserved: Vec<(&str, &str)> = pairs
        .iter()
        .filter(|(key, _)| SEP_414_RESERVED_META_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    if reserved.is_empty() {
        return params;
    }
    match params {
        serde_json::Value::Object(mut obj) => {
            let meta = obj
                .entry("_meta")
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            if let Some(meta_obj) = meta.as_object_mut() {
                for (key, value) in reserved {
                    meta_obj.insert(
                        key.to_string(),
                        serde_json::Value::String(value.to_string()),
                    );
                }
            }
            serde_json::Value::Object(obj)
        }
        // No `_meta` slot exists on a non-object params, and inventing
        // one would change the method's shape on the wire.
        other => other,
    }
}

/// The 32-hex trace id out of a W3C `traceparent` pair, when the pairs
/// carry a usable one.
///
/// Shape is `version "-" trace-id "-" parent-id "-" flags`. Returns
/// `None` for a missing, malformed, or all-zero trace id; all-zero is
/// the value W3C defines as invalid, and treating it as an identifier
/// would collapse every untraced call onto one correlation key.
fn trace_id_from_traceparent(pairs: &[(String, String)]) -> Option<&str> {
    let traceparent = pairs
        .iter()
        .find(|(key, _)| key == META_TRACEPARENT)
        .map(|(_, value)| value.as_str())?;
    let trace_id = traceparent.split('-').nth(1)?;
    let usable = trace_id.len() == 32
        && trace_id.bytes().all(|b| b.is_ascii_hexdigit())
        && trace_id.bytes().any(|b| b != b'0');
    usable.then_some(trace_id)
}

/// Percent-encode a path-parameter value (WOR-1648). Encodes
/// everything outside the RFC 3986 unreserved set so a value with a
/// slash or space cannot break out of its path segment.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Classify an upstream IO failure for the
/// `sbproxy_mcp_upstream_io_failures_total{kind}` counter. Reqwest
/// errors carry typed timeout/connect flags; the response byte cap is
/// recognised by its marker string since it crosses the transport
/// module boundary as `anyhow`.
fn classify_io_failure(e: &anyhow::Error) -> &'static str {
    if let Some(re) = e.downcast_ref::<reqwest::Error>() {
        if re.is_timeout() {
            return "timeout";
        }
        if re.is_connect() {
            return "connect";
        }
    }
    if e.to_string()
        .contains(super::streamable::RESPONSE_CAP_MARKER)
    {
        return "response_cap";
    }
    "other"
}

/// Render CodeMode from exactly one loaded catalogue state. The lazy
/// cache uses this rather than calling back through `McpFederation`,
/// which would otherwise permit a refresh between its generation read
/// and its tool read.
fn codemode_ts_for_catalog(catalog: &ToolCatalogState, callback_base_url: &str) -> String {
    let mut tools: Vec<&FederatedTool> = catalog
        .tools
        .values()
        .filter(|tool| !catalog.version_blocked.contains_key(&tool.name))
        .collect();
    tools.sort_by(|a, b| a.codemode_name().cmp(b.codemode_name()));
    super::codemode_ts::emit_codemode_ts_refs(tools, callback_base_url)
}

/// Return the legacy snapshot held by one immutable publication.
/// Kept as a helper so barrier tests exercise the same reader path as
/// the public `serialized_tools` method.
fn legacy_serialized_tools_for_catalog(catalog: &ToolCatalogState) -> Arc<SerializedTools> {
    Arc::clone(&catalog.legacy_serialized)
}

/// Build the frozen legacy catalogue before its enclosing state is
/// published. Its field order and per-entry projection intentionally
/// stay identical to the pre-lossless serializer.
fn build_legacy_serialized_tools(
    registry: &HashMap<String, FederatedTool>,
    generation: u64,
) -> SerializedTools {
    let mut entries: Vec<SerializedToolEntry> = registry
        .values()
        .map(legacy_serialized_tool_entry)
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    SerializedTools {
        generation,
        full_array: serialized_tool_array(&entries),
        entries,
    }
}

/// Build the complete modern discovery catalogue before publication.
/// Only compiled strict contracts are visible, but all strict entries
/// remain in the immutable registry for lossless observation.
fn build_modern_serialized_tools(
    registry: &HashMap<String, FederatedTool>,
    generation: u64,
) -> ModernSerializedTools {
    let mut entries: Vec<SerializedToolEntry> = registry
        .values()
        .filter_map(modern_serialized_tool_entry)
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    ModernSerializedTools {
        generation,
        full_array: serialized_tool_array(&entries),
        entries,
    }
}

fn serialized_tool_array(entries: &[SerializedToolEntry]) -> String {
    let mut full_array =
        String::with_capacity(entries.iter().map(|entry| entry.json.len() + 1).sum());
    full_array.push('[');
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            full_array.push(',');
        }
        full_array.push_str(&entry.json);
    }
    full_array.push(']');
    full_array
}

/// Frozen legacy `tools/list` projection for one federated tool.
///
/// Keep this byte-for-byte equivalent to the pre-lossless serializer:
/// clients on the 2025-06-18 wire see only name, description,
/// inputSchema, and optional `_meta`, even when the internal modern
/// contract carries additional fields.
fn legacy_serialized_tool_entry(tool: &FederatedTool) -> SerializedToolEntry {
    let mut obj = serde_json::json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    });
    if let (Some(meta), Some(map)) = (&tool.meta, obj.as_object_mut()) {
        map.insert("_meta".to_string(), meta.clone());
    }
    SerializedToolEntry {
        name: tool.name.clone(),
        server_name: tool.server_name.clone(),
        json: obj.to_string(),
    }
}

/// Complete modern `tools/list` entry for one tool that has already
/// passed modern contract compilation.
fn modern_serialized_tool_entry(tool: &FederatedTool) -> Option<SerializedToolEntry> {
    if !tool.is_modern_discoverable() {
        return None;
    }
    let contract = tool.contract.as_ref()?;
    Some(SerializedToolEntry {
        name: contract.name().to_string(),
        server_name: tool.server_name.clone(),
        json: contract.as_value().to_string(),
    })
}

/// The frozen legacy compatibility-oracle input. Keep this shape
/// separate from [`FederatedTool::contract`]: modern-only Tool fields
/// must not reclassify an existing lockfile entry.
fn legacy_compatibility_contract(tool: &FederatedTool) -> serde_json::Value {
    serde_json::json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    })
}

/// Order-independent content digest of a tool registry. Two
/// registries with the same tools (same names, descriptions,
/// schemas, owners, streaming flags, and `_meta` blocks) produce the
/// same digest regardless of `HashMap` iteration order.
fn tools_registry_digest(registry: &HashMap<String, FederatedTool>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut keys: Vec<&String> = registry.keys().collect();
    keys.sort();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for k in keys {
        let t = &registry[k];
        t.name.hash(&mut h);
        t.description.hash(&mut h);
        t.server_name.hash(&mut h);
        t.streaming.hash(&mut h);
        t.input_schema.to_string().hash(&mut h);
        match &t.meta {
            Some(m) => m.to_string().hash(&mut h),
            None => 0u8.hash(&mut h),
        }
    }
    h.finish()
}

/// Order-independent digest of the lossless modern representation.
///
/// This is deliberately separate from [`tools_registry_digest`]. It
/// detects additions such as title, icons, outputSchema, annotations,
/// and vendor extensions so the modern catalogue is refreshed, while
/// the legacy versioning and notification paths continue to compare
/// exactly their historical fields.
fn modern_tools_registry_digest(registry: &HashMap<String, FederatedTool>) -> [u8; 32] {
    use sha2::Digest;

    // The modern digest also controls publication of the lossless
    // registry, not only its visible serialized snapshot. Retain every
    // strict contract even when compilation made it modern-ineligible,
    // so a changed hidden contract or incompatibility state publishes.
    // Exclude only malformed legacy fallbacks, which have no strict
    // contract and no modern state to publish.
    let mut tools: Vec<(&FederatedTool, &McpToolContract)> = registry
        .values()
        .filter(|tool| tool.is_modern_eligible())
        .filter_map(|tool| tool.contract.as_ref().map(|contract| (tool, contract)))
        .collect();
    tools.sort_by(|(left, _), (right, _)| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.server_name.cmp(&right.server_name))
    });
    let mut hasher = sha2::Sha256::new();
    hash_lossless_length(&mut hasher, tools.len());
    for (tool, contract) in tools {
        // Hash the advertised identity independently from the complete
        // document. This makes the visible routing identity explicit
        // even though the strict contract also carries its `name`.
        hash_lossless_text(&mut hasher, 7, &tool.name);
        hash_lossless_text(&mut hasher, 8, &tool.server_name);
        hasher.update([9, u8::from(tool.streaming)]);
        // Preserve the safe eligibility state separately from the
        // complete document. This includes strict contracts that are
        // hidden from modern discovery but still need registry updates.
        hasher.update([10, u8::from(tool.modern_contract.is_some())]);
        match tool.modern_incompatibility.as_deref() {
            Some(class) => hash_lossless_text(&mut hasher, 11, class),
            None => hasher.update([12]),
        }
        // Hash the lossless JSON tree directly instead of routing it
        // through JCS. JCS coerces JSON numbers through IEEE-754,
        // making adjacent integer values above 2^53 and -0/0 collide.
        // This encoder sorts object keys while preserving each
        // serde_json::Number's textual representation exactly.
        hash_lossless_json_value(&contract.as_value(), &mut hasher);
    }
    let digest = hasher.finalize();
    let mut output = [0; 32];
    output.copy_from_slice(&digest);
    output
}

/// Hash a JSON value in deterministic object-key order without
/// normalizing `serde_json::Number`. Type tags and byte lengths make
/// this an unambiguous recursive encoding rather than concatenated
/// display text. In particular, the input numbers `9007199254740992`,
/// `9007199254740993`, `-0.0`, and `0.0` retain distinct encodings.
fn hash_lossless_json_value(value: &Value, hasher: &mut sha2::Sha256) {
    match value {
        Value::Null => sha2::Digest::update(hasher, [0]),
        Value::Bool(false) => sha2::Digest::update(hasher, [1]),
        Value::Bool(true) => sha2::Digest::update(hasher, [2]),
        Value::Number(number) => {
            sha2::Digest::update(hasher, [3]);
            hash_lossless_bytes(hasher, number.to_string().as_bytes());
        }
        Value::String(text) => {
            sha2::Digest::update(hasher, [4]);
            hash_lossless_bytes(hasher, text.as_bytes());
        }
        Value::Array(values) => {
            sha2::Digest::update(hasher, [5]);
            hash_lossless_length(hasher, values.len());
            for value in values {
                hash_lossless_json_value(value, hasher);
            }
        }
        Value::Object(object) => {
            sha2::Digest::update(hasher, [6]);
            hash_lossless_length(hasher, object.len());
            let mut members: Vec<(&String, &Value)> = object.iter().collect();
            members.sort_by_key(|(key, _)| *key);
            for (key, value) in members {
                hash_lossless_bytes(hasher, key.as_bytes());
                hash_lossless_json_value(value, hasher);
            }
        }
    }
}

/// Hash a text field with a distinct type tag, preserving its bytes exactly.
fn hash_lossless_text(hasher: &mut sha2::Sha256, tag: u8, text: &str) {
    sha2::Digest::update(hasher, [tag]);
    hash_lossless_bytes(hasher, text.as_bytes());
}

/// Prefix a byte string with a platform-independent decimal length. The
/// delimiter makes the encoding unambiguous without a truncating numeric cast.
fn hash_lossless_bytes(hasher: &mut sha2::Sha256, bytes: &[u8]) {
    hash_lossless_length(hasher, bytes.len());
    sha2::Digest::update(hasher, bytes);
}

/// Encode a `usize` structurally without relying on target-width casts.
fn hash_lossless_length(hasher: &mut sha2::Sha256, length: usize) {
    sha2::Digest::update(hasher, [0xff]);
    sha2::Digest::update(hasher, length.to_string().as_bytes());
    sha2::Digest::update(hasher, [0]);
}

/// Merge per-server prompt lists into one namespaced registry.
///
/// Split out from [`McpFederation::refresh_prompts`] because this is
/// the whole of the namespacing contract and it is worth testing
/// without upstream IO: servers are folded in configured order, and
/// each prompt takes the name [`federated_name`] resolves against the
/// names already claimed. That is the same call `refresh_tools` makes
/// with the same `'.'` separator, so a prompt name colliding across
/// two upstreams disambiguates exactly the way a tool name does.
fn merge_federated_prompts(
    per_server: Vec<(String, NamespaceMode, Vec<FederatedPrompt>)>,
) -> HashMap<String, FederatedPrompt> {
    let mut registry: HashMap<String, FederatedPrompt> = HashMap::new();
    for (server_name, namespace, prompts) in per_server {
        for mut prompt in prompts {
            let advertised =
                federated_name(&server_name, namespace, '.', &prompt.upstream_name, |n| {
                    registry.contains_key(n)
                });
            if advertised != prompt.upstream_name {
                warn!(
                    prompt = %prompt.upstream_name,
                    server = %server_name,
                    advertised = %advertised,
                    "federated prompt name namespaced (collision or always-namespace)"
                );
            }
            // Advertise the resolved name; `upstream_name` keeps the
            // original so `prompts/get` still reaches the owning
            // server with the name it published.
            prompt.name = advertised.clone();
            registry.insert(advertised, prompt);
        }
    }
    registry
}

/// Order-independent content digest of a prompt registry, so a
/// steady-state refresh that observes the same prompts does not churn
/// the `ArcSwap`.
fn prompts_registry_digest(registry: &HashMap<String, FederatedPrompt>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut keys: Vec<&String> = registry.keys().collect();
    keys.sort();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for k in keys {
        let p = &registry[k];
        p.name.hash(&mut h);
        p.upstream_name.hash(&mut h);
        p.title.hash(&mut h);
        p.description.hash(&mut h);
        p.server_name.hash(&mut h);
        match &p.arguments {
            Some(a) => a.to_string().hash(&mut h),
            None => 0u8.hash(&mut h),
        }
        match &p.meta {
            Some(m) => m.to_string().hash(&mut h),
            None => 0u8.hash(&mut h),
        }
    }
    h.finish()
}

/// Order-independent content digest of a resource registry plus the
/// mirrored mcpApps capability (both are stored by the same refresh,
/// so one digest guards both swaps).
fn resources_registry_digest(
    registry: &HashMap<String, FederatedResource>,
    apps_cap: &Option<serde_json::Value>,
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut keys: Vec<&String> = registry.keys().collect();
    keys.sort();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for k in keys {
        let r = &registry[k];
        r.uri.hash(&mut h);
        r.name.hash(&mut h);
        r.description.hash(&mut h);
        r.mime_type.hash(&mut h);
        r.server_name.hash(&mut h);
        r.upstream_uri.hash(&mut h);
    }
    match apps_cap {
        Some(v) => v.to_string().hash(&mut h),
        None => 0u8.hash(&mut h),
    }
    h.finish()
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
            namespace: NamespaceMode::default(),
            openapi: None,
        }
    }

    #[test]
    fn federated_name_on_collision_prefixes_only_when_taken() {
        use std::collections::HashSet;
        let taken: HashSet<String> = ["search".to_string()].into_iter().collect();
        // Default mode keeps the bare name when it is free...
        assert_eq!(
            federated_name("gh", NamespaceMode::OnCollision, '.', "create_issue", |n| {
                taken.contains(n)
            }),
            "create_issue"
        );
        // ...and disambiguates with the server name when it collides, so the
        // advertised name is the one that actually routes.
        assert_eq!(
            federated_name("gh", NamespaceMode::OnCollision, '.', "search", |n| taken
                .contains(n)),
            "gh.search"
        );
    }

    #[test]
    fn federated_name_always_prefixes_every_name() {
        let none_taken = |_: &str| false;
        // `Always` namespaces every name up front, even with no collision.
        assert_eq!(
            federated_name("gh", NamespaceMode::Always, '.', "search", none_taken),
            "gh.search"
        );
        // Resources use a slash separator.
        assert_eq!(
            federated_name("docs", NamespaceMode::Always, '/', "file://x", none_taken),
            "docs/file://x"
        );
    }

    fn make_tool(name: &str, server: &str) -> FederatedTool {
        make_tool_with_schema(
            name,
            &format!("Tool {name}"),
            json!({"type": "object", "properties": {}}),
            server,
            false,
        )
    }

    fn make_tool_with_schema(
        name: &str,
        description: &str,
        input_schema: serde_json::Value,
        server: &str,
        streaming: bool,
    ) -> FederatedTool {
        FederatedTool::from_contract_document(
            json!({
                "name": name,
                "description": description,
                "inputSchema": input_schema,
            }),
            server.to_string(),
            streaming,
        )
        .expect("federation fixture contract")
    }

    fn full_tool_document(name: &str) -> serde_json::Value {
        json!({
            "name": name,
            "title": "Search",
            "description": "Search the indexed documents",
            "inputSchema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                },
                "required": ["query"]
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "results": {"type": "array"}
                }
            },
            "icons": [{"src": "https://cdn.example.test/search.svg", "mimeType": "image/svg+xml"}],
            "annotations": {"readOnlyHint": true},
            "_meta": {"openai/widget": {"templateId": "search-card"}},
            "vendor.example/security": {"audience": "repos"}
        })
    }

    fn tool_list_server(tool_lists: Vec<serde_json::Value>) -> McpServerConfig {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("tool-list fixture bind failed: {error}"));
        let port = listener
            .local_addr()
            .expect("tool-list fixture address")
            .port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};

            for tools in tool_lists {
                let (mut stream, _) = listener
                    .accept()
                    .unwrap_or_else(|error| panic!("tool-list fixture accept failed: {error}"));
                let mut request = [0_u8; 8192];
                let _ = stream.read(&mut request);
                let body = json!({
                    "jsonrpc": "2.0",
                    "result": {"tools": tools},
                    "id": 1,
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        mock_server("legacy-fixture", &format!("http://127.0.0.1:{port}/mcp"))
    }

    /// A one-call upstream fixture. It stays nonblocking until either
    /// one request arrives or the test releases it, so a proof that a
    /// replacement server received zero calls never leaves a thread
    /// parked in `accept`.
    fn tool_call_server(
        name: &str,
        result_text: &str,
    ) -> (
        McpServerConfig,
        Arc<std::sync::atomic::AtomicUsize>,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("tool-call fixture bind failed: {error}"));
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|error| panic!("tool-call fixture nonblocking setup failed: {error}"));
        let port = listener
            .local_addr()
            .expect("tool-call fixture address")
            .port();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_thread = Arc::clone(&calls);
        let (stop, stop_rx) = std::sync::mpsc::channel();
        let result_text = result_text.to_string();
        let handle = std::thread::spawn(move || {
            use std::io::{Read, Write};

            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        calls_for_thread.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        stream
                            .set_nonblocking(false)
                            .expect("tool-call fixture stream blocking setup");
                        let mut request = [0_u8; 8192];
                        // The fixture never inspects the request, so one
                        // possibly-partial read is enough to unblock the peer.
                        let _request_bytes = stream
                            .read(&mut request)
                            .expect("tool-call fixture request read");
                        let body = json!({
                            "jsonrpc": "2.0",
                            "result": {"content": [{"type": "text", "text": result_text}]},
                            "id": 1,
                        })
                        .to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        stream
                            .write_all(response.as_bytes())
                            .expect("tool-call fixture response write");
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        match stop_rx.try_recv() {
                            Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                            Err(std::sync::mpsc::TryRecvError::Empty) => {
                                std::thread::sleep(std::time::Duration::from_millis(1));
                            }
                        }
                    }
                    Err(error) => panic!("tool-call fixture accept failed: {error}"),
                }
            }
        });
        (
            mock_server(name, &format!("http://127.0.0.1:{port}/mcp")),
            calls,
            stop,
            handle,
        )
    }

    #[tokio::test]
    async fn task_5b_missing_input_schema_remains_legacy_usable() {
        let server = tool_list_server(vec![json!([{
            "name": "missing_input",
            "description": "Legacy missing schema"
        }])]);
        let federation = McpFederation::new(vec![server]);
        let initial_modern_snapshot = federation.serialized_modern_tools();

        assert_eq!(federation.refresh_tools().await.expect("refresh"), 1);
        let tool = federation
            .resolve_tool("missing_input")
            .expect("missing inputSchema must remain legacy-routable");
        assert!(tool.modern_contract.is_none());
        assert_eq!(
            tool.modern_incompatibility.as_deref(),
            Some("missing_input_schema")
        );
        assert!(federation.resolve_modern_tool("missing_input").is_none());
        assert_eq!(
            federation.modern_tools_generation(),
            0,
            "an initial malformed legacy-only definition must not create a modern generation"
        );
        assert!(Arc::ptr_eq(
            &initial_modern_snapshot,
            &federation.serialized_modern_tools()
        ));

        let legacy = federation.serialized_tools();
        assert_eq!(
            legacy.full_array,
            "[{\"description\":\"Legacy missing schema\",\"inputSchema\":{\"properties\":{},\"type\":\"object\"},\"name\":\"missing_input\"}]"
        );
        assert_eq!(
            serde_json::to_string(&legacy_compatibility_contract(&tool))
                .expect("legacy compatibility JSON"),
            "{\"description\":\"Legacy missing schema\",\"inputSchema\":{\"properties\":{},\"type\":\"object\"},\"name\":\"missing_input\"}"
        );
        let codemode = federation.codemode_ts("https://gateway.example");
        assert!(codemode.contains("export interface MissingInputInput"));
        assert!(codemode.contains("['missing_input']:"));
        assert!(codemode.contains("[key: string]: unknown;"));
    }

    #[tokio::test]
    async fn task_5b_non_object_input_schema_remains_legacy_usable() {
        let server = tool_list_server(vec![json!([{
            "name": "scalar_input",
            "description": "Legacy scalar schema",
            "inputSchema": "opaque-schema"
        }])]);
        let federation = McpFederation::new(vec![server]);

        assert_eq!(federation.refresh_tools().await.expect("refresh"), 1);
        let tool = federation
            .resolve_tool("scalar_input")
            .expect("non-object inputSchema must remain legacy-routable");
        assert!(tool.modern_contract.is_none());
        assert_eq!(
            tool.modern_incompatibility.as_deref(),
            Some("non_object_input_schema")
        );
        assert!(federation.resolve_modern_tool("scalar_input").is_none());

        let legacy = federation.serialized_tools();
        assert_eq!(
            legacy.full_array,
            "[{\"description\":\"Legacy scalar schema\",\"inputSchema\":\"opaque-schema\",\"name\":\"scalar_input\"}]"
        );
        assert_eq!(
            serde_json::to_string(&legacy_compatibility_contract(&tool))
                .expect("legacy compatibility JSON"),
            "{\"description\":\"Legacy scalar schema\",\"inputSchema\":\"opaque-schema\",\"name\":\"scalar_input\"}"
        );
        let codemode = federation.codemode_ts("https://gateway.example");
        assert!(codemode.contains("export interface ScalarInputInput"));
        assert!(codemode.contains("['scalar_input']:"));
        assert!(codemode.contains("[key: string]: unknown;"));
    }

    #[test]
    fn task_5b_namespacing_rewrites_the_malformed_legacy_fallback_only() {
        let mut tool = FederatedTool::from_contract_document(
            json!({
                "name": "opaque",
                "description": "Legacy-only scalar schema",
                "inputSchema": "opaque-schema"
            }),
            "catalog".to_string(),
            false,
        )
        .expect("a string-named legacy tool remains usable");

        tool.advertise_as("catalog.opaque");

        assert!(tool.contract.is_none());
        assert_eq!(tool.name, "catalog.opaque");
        assert_eq!(tool.input_schema, json!("opaque-schema"));
        let fallback = tool
            .legacy_document
            .as_ref()
            .expect("malformed tool retains its legacy fallback");
        assert_eq!(fallback["name"], "catalog.opaque");
        assert_eq!(fallback["inputSchema"], "opaque-schema");
    }

    #[tokio::test]
    async fn task_5b_openapi_meta_is_modern_only() {
        let backing = OpenApiBacking {
            base_url: "https://api.example.test".to_string(),
            tools: vec![json!({
                "name": "search",
                "description": "OpenAPI search",
                "inputSchema": {"type": "object", "properties": {}},
                "_meta": {"vendor.example/ui": "search-card"}
            })],
            routes: HashMap::new(),
            headers: Vec::new(),
            egress_policy: EgressPolicy::allow_all("test"),
        };
        let federation = McpFederation::new(vec![McpServerConfig {
            name: "openapi".to_string(),
            url: backing.base_url.clone(),
            transport: "streamable_http".to_string(),
            namespace: NamespaceMode::default(),
            openapi: Some(backing),
        }]);

        assert_eq!(federation.refresh_tools().await.expect("refresh"), 1);
        let tool = federation.resolve_tool("search").expect("OpenAPI tool");
        assert!(tool.meta.is_none(), "OpenAPI _meta is modern-only");
        assert!(tool.contract.is_some(), "OpenAPI document stays lossless");
        assert!(
            tool.legacy_document.is_none(),
            "valid OpenAPI documents do not duplicate their full contract"
        );
        let legacy = federation.serialized_tools();
        assert_eq!(
            legacy.full_array,
            "[{\"description\":\"OpenAPI search\",\"inputSchema\":{\"properties\":{},\"type\":\"object\"},\"name\":\"search\"}]"
        );
        let modern: serde_json::Value =
            serde_json::from_str(&federation.serialized_modern_tools().full_array)
                .expect("modern catalogue JSON");
        assert_eq!(modern[0]["_meta"]["vendor.example/ui"], "search-card");
    }

    fn prepared_tool(document: serde_json::Value, server: &str, advertised: &str) -> FederatedTool {
        let mut tool = FederatedTool::from_contract_document(document, server.to_string(), false)
            .expect("fixture must have a usable legacy contract");
        tool.advertise_as(advertised);
        tool.compile_modern_contract();
        tool
    }

    #[test]
    fn task_5b_retains_full_contract_and_freezes_legacy_projection() {
        let original = full_tool_document("search");
        let tool = prepared_tool(original.clone(), "alpha", "alpha.search");
        let mut expected_modern = original.clone();
        expected_modern["name"] = json!("alpha.search");

        assert_eq!(tool.name, "alpha.search");
        assert_eq!(
            tool.contract
                .as_ref()
                .expect("valid fixture has a strict contract")
                .name(),
            "alpha.search"
        );
        assert_eq!(
            tool.contract
                .as_ref()
                .expect("valid fixture has a strict contract")
                .description(),
            Some("Search the indexed documents")
        );
        assert_eq!(
            tool.contract
                .as_ref()
                .expect("valid fixture has a strict contract")
                .as_value(),
            expected_modern
        );
        let mut before_without_name = original.as_object().cloned().expect("tool object");
        let mut after_without_name = tool
            .contract
            .as_ref()
            .expect("valid fixture has a strict contract")
            .as_value()
            .as_object()
            .cloned()
            .expect("tool object");
        before_without_name.remove("name");
        after_without_name.remove("name");
        assert_eq!(
            after_without_name, before_without_name,
            "namespacing must change only the complete contract name"
        );
        assert_eq!(tool.description, "Search the indexed documents");
        assert_eq!(tool.input_schema, original["inputSchema"]);
        assert_eq!(tool.meta, Some(original["_meta"].clone()));
        assert!(
            tool.legacy_document.is_none(),
            "valid contracts do not retain a duplicate raw fallback"
        );
        assert!(tool.modern_contract.is_some());
        assert!(tool.modern_incompatibility.is_none());

        const LEGACY_GOLDEN: &str = "[{\"_meta\":{\"openai/widget\":{\"templateId\":\"search-card\"}},\"description\":\"Search the indexed documents\",\"inputSchema\":{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"properties\":{\"query\":{\"type\":\"string\"}},\"required\":[\"query\"],\"type\":\"object\"},\"name\":\"alpha.search\"}]";
        let legacy_entry = legacy_serialized_tool_entry(&tool);
        assert_eq!(format!("[{}]", legacy_entry.json), LEGACY_GOLDEN);
        assert!(!legacy_entry.json.contains("outputSchema"));
        assert!(!legacy_entry.json.contains("vendor.example/security"));

        let expected_compatibility_contract = json!({
            "name": "alpha.search",
            "description": "Search the indexed documents",
            "inputSchema": original["inputSchema"].clone(),
        });
        assert_eq!(
            legacy_compatibility_contract(&tool),
            expected_compatibility_contract
        );
        assert_eq!(
            crate::mcp::compat::contract_digest(&legacy_compatibility_contract(&tool)),
            crate::mcp::compat::contract_digest(&expected_compatibility_contract),
            "modern-only fields must not enter the frozen compatibility oracle"
        );

        let fed = McpFederation::new(vec![]);
        let mut registry = HashMap::new();
        registry.insert(tool.name.clone(), tool);
        fed.seed_tools_for_test(registry, None);
        let serialized = fed.serialized_tools();
        assert_eq!(serialized.full_array, LEGACY_GOLDEN);
        assert_eq!(
            fed.serialized_modern_tools().full_array,
            format!("[{}]", expected_modern)
        );
    }

    #[test]
    fn task_5b_inconsistent_public_contract_state_fails_closed_without_panicking() {
        let mut tool = prepared_tool(full_tool_document("search"), "alpha", "alpha.search");
        assert!(
            tool.modern_contract.is_some(),
            "fixture starts as a modern-eligible strict contract"
        );

        // `FederatedTool` has public fields for compatibility with existing
        // construction sites. A caller can therefore create this impossible
        // internal combination. Refresh and cache paths must fail closed, not
        // panic while serializing or hashing it.
        tool.contract = None;
        let original_name = tool.name.clone();
        let original_description = tool.description.clone();
        let original_input_schema = tool.input_schema.clone();
        tool.sync_convenience_fields();
        assert_eq!(tool.name, original_name);
        assert_eq!(tool.description, original_description);
        assert_eq!(tool.input_schema, original_input_schema);

        let registry = HashMap::from([(tool.name.clone(), tool)]);
        assert!(
            build_modern_serialized_tools(&registry, 1)
                .entries
                .is_empty(),
            "a modern marker without its authoritative contract is not serializable"
        );
        let federation = McpFederation::new(vec![]);
        federation.seed_tools_for_test(registry.clone(), None);
        assert!(
            federation.resolve_modern_tool("alpha.search").is_none(),
            "modern lookup must reject a compiled marker without its strict contract"
        );
        assert!(
            federation.list_modern_tools().is_empty(),
            "modern listing must reject a compiled marker without its strict contract"
        );
        assert_eq!(
            modern_tools_registry_digest(&registry),
            modern_tools_registry_digest(&HashMap::new()),
            "a missing strict contract is excluded from the modern digest"
        );
    }

    #[test]
    fn task_5b_modern_catalog_is_deterministic_and_keeps_complete_documents() {
        let mut alpha_document = full_tool_document("alpha");
        alpha_document["title"] = json!("Alpha Search");
        let mut zeta_document = full_tool_document("zeta");
        zeta_document["title"] = json!("Zeta Search");
        let alpha = prepared_tool(alpha_document, "alpha-server", "alpha");
        let zeta = prepared_tool(zeta_document, "zeta-server", "zeta");

        let fed = McpFederation::new(vec![]);
        let mut registry = HashMap::new();
        registry.insert(zeta.name.clone(), zeta);
        registry.insert(alpha.name.clone(), alpha);
        fed.seed_tools_for_test(registry, None);

        let serialized = fed.serialized_modern_tools();
        let names: Vec<&str> = serialized
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
        let documents: serde_json::Value =
            serde_json::from_str(&serialized.full_array).expect("modern catalogue JSON");
        assert_eq!(documents[0]["title"], "Alpha Search");
        assert_eq!(
            documents[0]["icons"][0]["src"],
            "https://cdn.example.test/search.svg"
        );
        assert_eq!(
            documents[0]["outputSchema"]["properties"]["results"]["type"],
            "array"
        );
        assert_eq!(documents[0]["vendor.example/security"]["audience"], "repos");
        assert_eq!(
            documents[0]["_meta"]["openai/widget"]["templateId"],
            "search-card"
        );
    }

    #[test]
    fn task_5b_modern_incompatible_tools_remain_legacy_usable_but_are_hidden_modernly() {
        let valid = prepared_tool(full_tool_document("valid"), "catalog", "valid");
        let invalid = prepared_tool(
            json!({
                "name": "unsafe",
                "description": "Legacy-compatible but modern-invalid",
                "inputSchema": {
                    "type": "object",
                    "$dynamicRef": "https://untrusted.example.test/schema"
                }
            }),
            "catalog",
            "unsafe",
        );

        assert!(invalid.modern_contract.is_none());
        assert_eq!(
            invalid.modern_incompatibility.as_deref(),
            Some("external_reference")
        );
        assert!(
            !invalid
                .modern_incompatibility
                .as_deref()
                .unwrap_or_default()
                .contains("untrusted.example.test"),
            "the incompatibility state must be safe to log"
        );

        let fed = McpFederation::new(vec![]);
        let mut registry = HashMap::new();
        registry.insert(valid.name.clone(), valid);
        registry.insert(invalid.name.clone(), invalid);
        fed.seed_tools_for_test(registry, None);

        assert!(fed.resolve_tool("unsafe").is_some());
        assert!(fed.resolve_modern_tool("unsafe").is_none());
        assert!(fed.resolve_modern_tool("valid").is_some());
        let legacy = fed.serialized_tools();
        let modern = fed.serialized_modern_tools();
        assert_eq!(legacy.entries.len(), 2);
        assert_eq!(modern.entries.len(), 1);
        assert!(legacy.full_array.contains("unsafe"));
        assert!(!modern.full_array.contains("unsafe"));
    }

    #[test]
    fn task_5b_modern_incompatibility_telemetry_is_summary_change_only() {
        let invalid = prepared_tool(
            json!({
                "name": "untrusted-upstream-tool-name",
                "description": "Legacy-compatible but modern-invalid",
                "inputSchema": {
                    "type": "object",
                    "$dynamicRef": "https://untrusted.example.test/schema"
                }
            }),
            "catalog",
            "untrusted-upstream-tool-name",
        );
        let original = HashMap::from([(invalid.name.clone(), invalid)]);
        let renamed_invalid = prepared_tool(
            json!({
                "name": "a-different-untrusted-tool-name",
                "description": "Legacy-compatible but modern-invalid",
                "inputSchema": {
                    "type": "object",
                    "$dynamicRef": "https://another-untrusted.example.test/schema"
                }
            }),
            "catalog",
            "a-different-untrusted-tool-name",
        );
        let same_summary = HashMap::from([(renamed_invalid.name.clone(), renamed_invalid)]);

        assert_eq!(
            modern_incompatibility_change_summary(&HashMap::new(), &original),
            Some(std::collections::BTreeMap::from([(
                "external_reference",
                1
            )])),
            "the aggregate records only the closed incompatibility class"
        );
        assert_eq!(
            modern_incompatibility_change_summary(&original, &original),
            None,
            "an unchanged invalid catalogue emits no repeated change telemetry"
        );
        assert_eq!(
            modern_incompatibility_change_summary(&original, &same_summary),
            None,
            "tool names and external references never enter the aggregate labels"
        );
    }

    #[test]
    fn task_5b_modern_incompatibility_telemetry_detects_same_class_entry_replacement_safely() {
        let previous_tool = prepared_tool(
            json!({
                "name": "old\ncontrol\r\u{061c}\u{200e}\u{200f}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}tool",
                "description": "SCHEMA_SECRET_PREVIOUS",
                "inputSchema": {
                    "type": "object",
                    "$dynamicRef": "https://schema.example/PRIVATE_REFERENCE_PREVIOUS"
                },
                "vendor.example/private": {
                    "authorization": "HEADER_SECRET_PREVIOUS"
                }
            }),
            "old\ncontrol\r\u{061c}\u{200e}\u{200f}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}server",
            "old\ncontrol\r\u{061c}\u{200e}\u{200f}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}tool",
        );
        let next_tool = prepared_tool(
            json!({
                "name": "new\u{0007}control\t\u{2066}\u{2067}\u{2068}\u{2069}tool",
                "description": "SCHEMA_SECRET_NEXT",
                "inputSchema": {
                    "type": "object",
                    "$dynamicRef": "https://schema.example/PRIVATE_REFERENCE_NEXT"
                },
                "vendor.example/private": {
                    "authorization": "HEADER_SECRET_NEXT"
                }
            }),
            "new\u{0007}control\t\u{2066}\u{2067}\u{2068}\u{2069}server",
            "new\u{0007}control\t\u{2066}\u{2067}\u{2068}\u{2069}tool",
        );
        let previous = HashMap::from([(previous_tool.name.clone(), previous_tool)]);
        let next = HashMap::from([(next_tool.name.clone(), next_tool)]);

        let changes = modern_incompatibility_changes(&previous, &next);
        assert!(
            !changes.is_empty(),
            "replacing one incompatible entry with another of the same class is still a change"
        );
        assert!(
            changes.len() <= 32,
            "one refresh must emit a fixed bounded number of incompatibility events"
        );
        for change in &changes {
            assert!(
                matches!(change.kind, "added" | "removed" | "changed"),
                "change kind must come from a closed vocabulary"
            );
            assert_eq!(
                change.class, "external_reference",
                "incompatibility class must use the existing closed vocabulary"
            );
            for identifier in [&change.tool, &change.server] {
                assert!(
                    !identifier.is_empty(),
                    "change identifiers stay attributable"
                );
                assert!(
                    identifier.len() <= 96,
                    "change identifiers must have a fixed byte bound"
                );
                assert!(
                    !identifier.chars().any(char::is_control),
                    "change identifiers must strip control characters"
                );
                assert!(
                    !identifier.chars().any(|character| matches!(
                        character,
                        '\u{061c}'
                            | '\u{200e}'
                            | '\u{200f}'
                            | '\u{202a}'..='\u{202e}'
                            | '\u{2066}'..='\u{2069}'
                    )),
                    "change identifiers must strip Unicode bidi controls"
                );
            }
        }
        let rendered = format!("{changes:?}");
        for secret in [
            "SCHEMA_SECRET_PREVIOUS",
            "SCHEMA_SECRET_NEXT",
            "PRIVATE_REFERENCE_PREVIOUS",
            "PRIVATE_REFERENCE_NEXT",
            "HEADER_SECRET_PREVIOUS",
            "HEADER_SECRET_NEXT",
        ] {
            assert!(
                !rendered.contains(secret),
                "incompatibility telemetry leaked contract data: {secret}"
            );
        }

        let many: HashMap<String, FederatedTool> = (0..256)
            .map(|index| {
                let name = format!("invalid-{index}");
                let tool = prepared_tool(
                    json!({
                        "name": name,
                        "inputSchema": {
                            "type": "object",
                            "$dynamicRef": format!("https://schema.example/{index}")
                        }
                    }),
                    "bulk-server",
                    &format!("invalid-{index}"),
                );
                (tool.name.clone(), tool)
            })
            .collect();
        let bounded_changes = modern_incompatibility_changes(&HashMap::new(), &many);
        assert!(
            !bounded_changes.is_empty(),
            "a non-empty new incompatibility set must emit at least one change"
        );
        assert!(
            bounded_changes.len() <= 32,
            "an attacker-controlled catalogue cannot create unbounded change events"
        );
    }

    #[test]
    fn task_5b_federated_tool_debug_redacts_lossless_contract_documents() {
        let tool = prepared_tool(
            json!({
                "name": "safe-debug-name",
                "description": "DESCRIPTION_SECRET_MARKER",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "credential": {
                            "type": "string",
                            "description": "SCHEMA_SECRET_MARKER"
                        }
                    }
                },
                "outputSchema": {
                    "type": "object",
                    "description": "OUTPUT_SECRET_MARKER"
                },
                "vendor.example/private": {
                    "authorization": "UNKNOWN_EXTENSION_SECRET_MARKER"
                }
            }),
            "safe-debug-server",
            "safe-debug-name",
        );

        let rendered = format!("{tool:?}");
        assert!(rendered.contains("FederatedTool"));
        for secret in [
            "DESCRIPTION_SECRET_MARKER",
            "SCHEMA_SECRET_MARKER",
            "OUTPUT_SECRET_MARKER",
            "UNKNOWN_EXTENSION_SECRET_MARKER",
        ] {
            assert!(
                !rendered.contains(secret),
                "FederatedTool Debug leaked the complete contract: {secret}"
            );
        }
        assert!(
            rendered.len() <= 512,
            "FederatedTool Debug must stay bounded independently of schema size"
        );
    }

    #[test]
    fn task_5b_modern_digest_tracks_complete_fields_without_moving_legacy_digest() {
        let baseline = prepared_tool(full_tool_document("search"), "catalog", "search");
        let mut changed_document = full_tool_document("search");
        changed_document["vendor.example/security"]["audience"] = json!("administrators");
        let changed = prepared_tool(changed_document, "catalog", "search");

        let mut baseline_registry = HashMap::new();
        baseline_registry.insert("search".to_string(), baseline);
        let mut changed_registry = HashMap::new();
        changed_registry.insert("search".to_string(), changed);

        assert_eq!(
            tools_registry_digest(&baseline_registry),
            tools_registry_digest(&changed_registry),
            "legacy digest must retain its historical field set"
        );
        assert_ne!(
            modern_tools_registry_digest(&baseline_registry),
            modern_tools_registry_digest(&changed_registry),
            "modern digest must invalidate a lossless vendor-field change"
        );
    }

    #[test]
    fn task_5b_modern_digest_preserves_non_jcs_numbers() {
        let mut high_a = full_tool_document("numeric");
        high_a["vendor.example/number"] = json!(9_007_199_254_740_992_u64);
        let mut high_b = high_a.clone();
        high_b["vendor.example/number"] = json!(9_007_199_254_740_993_u64);

        let mut negative_zero = full_tool_document("numeric");
        negative_zero["vendor.example/number"] = json!(-0.0_f64);
        let mut positive_zero = negative_zero.clone();
        positive_zero["vendor.example/number"] = json!(0.0_f64);

        let registry_for = |document| {
            let tool = prepared_tool(document, "catalog", "numeric");
            HashMap::from([("numeric".to_string(), tool)])
        };

        assert_ne!(
            modern_tools_registry_digest(&registry_for(high_a)),
            modern_tools_registry_digest(&registry_for(high_b)),
            "lossless modern digest must not IEEE-754-round adjacent integers"
        );
        assert_ne!(
            modern_tools_registry_digest(&registry_for(negative_zero)),
            modern_tools_registry_digest(&registry_for(positive_zero)),
            "lossless modern digest must preserve a negative-zero Number"
        );
    }

    #[tokio::test]
    async fn task_5b_modern_only_refresh_keeps_legacy_generations_and_cache_identity() {
        let baseline = full_tool_document("search");
        let mut modern_only_change = baseline.clone();
        modern_only_change["title"] = json!("Search v2");
        let server = tool_list_server(vec![json!([baseline]), json!([modern_only_change])]);
        let federation = McpFederation::new(vec![server]);

        federation.refresh_tools().await.expect("baseline refresh");
        let legacy_generation = federation.generation();
        let legacy_tools_generation = federation.tools_generation();
        let modern_generation = federation.modern_tools_generation();
        let legacy_snapshot = federation.serialized_tools();
        let modern_snapshot = federation.serialized_modern_tools();
        let (codemode_snapshot, codemode_etag) =
            federation.codemode_ts_cached("https://gateway.example");

        federation
            .refresh_tools()
            .await
            .expect("modern-only refresh");

        assert_eq!(federation.generation(), legacy_generation);
        assert_eq!(federation.tools_generation(), legacy_tools_generation);
        assert!(federation.modern_tools_generation() > modern_generation);
        assert!(Arc::ptr_eq(
            &legacy_snapshot,
            &federation.serialized_tools()
        ));
        assert!(!Arc::ptr_eq(
            &modern_snapshot,
            &federation.serialized_modern_tools()
        ));
        let (codemode_after, codemode_etag_after) =
            federation.codemode_ts_cached("https://gateway.example");
        assert!(Arc::ptr_eq(&codemode_snapshot, &codemode_after));
        assert_eq!(codemode_etag, codemode_etag_after);
        assert!(federation
            .serialized_modern_tools()
            .full_array
            .contains("Search v2"));
    }

    #[tokio::test]
    async fn task_5b_legacy_only_membership_does_not_churn_modern_cache() {
        let visible = full_tool_document("visible");
        let legacy_only = json!({
            "name": "legacy-only",
            "description": "Retained only by the frozen legacy projection"
        });
        let server = tool_list_server(vec![
            json!([visible.clone()]),
            json!([visible.clone(), legacy_only]),
            json!([visible]),
        ]);
        let federation = McpFederation::new(vec![server]);

        federation.refresh_tools().await.expect("baseline refresh");
        let baseline_generation = federation.generation();
        let baseline_tools_generation = federation.tools_generation();
        let modern_generation = federation.modern_tools_generation();
        let modern_snapshot = federation.serialized_modern_tools();

        federation
            .refresh_tools()
            .await
            .expect("legacy-only addition refresh");
        assert!(federation.generation() > baseline_generation);
        assert!(federation.tools_generation() > baseline_tools_generation);
        assert_eq!(federation.modern_tools_generation(), modern_generation);
        assert!(Arc::ptr_eq(
            &modern_snapshot,
            &federation.serialized_modern_tools()
        ));
        assert!(federation.resolve_tool("legacy-only").is_some());
        assert!(federation.resolve_modern_tool("legacy-only").is_none());

        let addition_generation = federation.generation();
        let addition_tools_generation = federation.tools_generation();
        federation
            .refresh_tools()
            .await
            .expect("legacy-only removal refresh");
        assert!(federation.generation() > addition_generation);
        assert!(federation.tools_generation() > addition_tools_generation);
        assert_eq!(federation.modern_tools_generation(), modern_generation);
        assert!(Arc::ptr_eq(
            &modern_snapshot,
            &federation.serialized_modern_tools()
        ));
        assert!(federation.resolve_tool("legacy-only").is_none());
    }

    #[tokio::test]
    async fn task_5b_strict_ineligible_change_publishes_lossless_contract() {
        let mut baseline = full_tool_document("strict-ineligible");
        baseline["inputSchema"] = json!({
            "type": "object",
            "$dynamicRef": "https://untrusted.example.test/schema"
        });
        let mut modern_only_change = baseline.clone();
        modern_only_change["title"] = json!("Changed but still ineligible");
        let server = tool_list_server(vec![json!([baseline]), json!([modern_only_change])]);
        let federation = McpFederation::new(vec![server]);

        federation.refresh_tools().await.expect("baseline refresh");
        let legacy_generation = federation.generation();
        let legacy_tools_generation = federation.tools_generation();
        let modern_generation = federation.modern_tools_generation();
        let modern_snapshot = federation.serialized_modern_tools();
        assert!(federation
            .resolve_modern_tool("strict-ineligible")
            .is_none());

        federation
            .refresh_tools()
            .await
            .expect("strict ineligible refresh");

        assert_eq!(federation.generation(), legacy_generation);
        assert_eq!(federation.tools_generation(), legacy_tools_generation);
        assert!(federation.modern_tools_generation() > modern_generation);
        assert!(!Arc::ptr_eq(
            &modern_snapshot,
            &federation.serialized_modern_tools()
        ));
        let tool = federation
            .resolve_tool("strict-ineligible")
            .expect("strict ineligible entry remains in the registry");
        assert!(tool.contract.is_some());
        assert!(tool.modern_contract.is_none());
        assert_eq!(
            tool.modern_incompatibility.as_deref(),
            Some("external_reference")
        );
        assert_eq!(
            tool.contract
                .as_ref()
                .expect("strict contract remains lossless")
                .as_value()["title"],
            "Changed but still ineligible"
        );
    }

    // --- Prompts ---

    fn make_prompt(name: &str, server: &str) -> FederatedPrompt {
        FederatedPrompt {
            name: name.to_string(),
            upstream_name: name.to_string(),
            title: None,
            description: Some(format!("Prompt {name}")),
            arguments: None,
            server_name: server.to_string(),
            meta: None,
        }
    }

    /// The whole point of prompt namespacing: two upstreams that both
    /// publish `code_review` must both stay reachable, and the second
    /// one gets the server-qualified name a tool collision would get.
    #[test]
    fn prompt_name_collision_across_servers_namespaces_like_a_tool() {
        let registry = merge_federated_prompts(vec![
            (
                "gh".to_string(),
                NamespaceMode::OnCollision,
                vec![
                    make_prompt("code_review", "gh"),
                    make_prompt("triage", "gh"),
                ],
            ),
            (
                "gl".to_string(),
                NamespaceMode::OnCollision,
                vec![make_prompt("code_review", "gl")],
            ),
        ]);

        assert_eq!(registry.len(), 3, "every prompt stays reachable");
        // First server in configured order keeps the bare name.
        assert_eq!(registry["code_review"].server_name, "gh");
        // The collider is advertised (and keyed) server-qualified.
        let collided = registry
            .get("gl.code_review")
            .expect("collision disambiguates with the server name");
        assert_eq!(collided.server_name, "gl");
        assert_eq!(collided.name, "gl.code_review");
        // The upstream still hears the name it published.
        assert_eq!(collided.upstream_name, "code_review");
        // A non-colliding name on the same server is untouched.
        assert_eq!(registry["triage"].name, "triage");
    }

    /// `namespace: always` prefixes every prompt up front, with the
    /// `'.'` separator tools use rather than the `'/'` resources use.
    #[test]
    fn prompt_namespace_always_prefixes_without_a_collision() {
        let registry = merge_federated_prompts(vec![(
            "gh".to_string(),
            NamespaceMode::Always,
            vec![make_prompt("code_review", "gh")],
        )]);
        assert_eq!(registry.len(), 1);
        let prompt = registry
            .get("gh.code_review")
            .expect("always-namespace prefixes every prompt");
        assert_eq!(prompt.upstream_name, "code_review");
    }

    #[test]
    fn resolve_prompt_round_trips_and_unknown_is_none() {
        let fed = McpFederation::new(vec![mock_server("gh", "http://gh.test")]);
        let mut map = HashMap::new();
        let mut prompt = make_prompt("gh.code_review", "gh");
        prompt.upstream_name = "code_review".to_string();
        map.insert("gh.code_review".to_string(), prompt);
        fed.prompts.store(Arc::new(map));

        let resolved = fed
            .resolve_prompt("gh.code_review")
            .expect("advertised name routes");
        assert_eq!(resolved.server_name, "gh");
        assert_eq!(resolved.upstream_name, "code_review");
        assert_eq!(fed.list_prompts().len(), 1);
        // The bare upstream name is not what the gateway advertised,
        // so it must not route either.
        assert!(fed.resolve_prompt("code_review").is_none());
        assert!(fed.resolve_prompt("no_such_prompt").is_none());
    }

    #[tokio::test]
    async fn get_prompt_on_an_unknown_name_never_reaches_an_upstream() {
        // The URL is unroutable on purpose: resolving must fail before
        // any dial, so the error is "unknown prompt" and not a
        // connect failure.
        let fed = McpFederation::new(vec![mock_server("gh", "http://127.0.0.1:1/mcp")]);
        let err = fed
            .get_prompt("no_such_prompt", None)
            .await
            .expect_err("unknown prompt must not dial");
        assert!(
            format!("{err:#}").contains("unknown prompt"),
            "expected an unknown-prompt error, got: {err:#}"
        );
    }

    #[tokio::test]
    async fn task_5b_prompt_dispatch_stays_bound_to_the_authorized_snapshot_owner() {
        let (allowed_server, allowed_calls, _allowed_stop, allowed_handle) =
            tool_call_server("allowed", "allowed prompt owner");
        let (denied_server, denied_calls, denied_stop, denied_handle) =
            tool_call_server("denied", "denied replacement owner");
        let federation = McpFederation::new(vec![allowed_server, denied_server]);

        federation.prompts.store(Arc::new(HashMap::from([(
            "shared".to_string(),
            make_prompt("shared", "allowed"),
        )])));
        let authorized = federation.prompt_catalog_snapshot();

        federation.prompts.store(Arc::new(HashMap::from([(
            "shared".to_string(),
            make_prompt("shared", "denied"),
        )])));

        let result = federation
            .get_prompt_from_snapshot(&authorized, "shared", None)
            .await
            .expect("dispatch must retain the authorized prompt owner");
        assert_eq!(result["content"][0]["text"], "allowed prompt owner");

        allowed_handle.join().expect("allowed prompt fixture join");
        let _ = denied_stop.send(());
        denied_handle.join().expect("denied prompt fixture join");
        assert_eq!(allowed_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            denied_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a replacement owner that was never authorized must receive no request"
        );
    }

    #[tokio::test]
    async fn task_5b_foreign_prompt_snapshot_is_rejected_before_network_io() {
        let (source_server, source_calls, source_stop, source_handle) =
            tool_call_server("shared", "source federation");
        let (target_server, target_calls, target_stop, target_handle) =
            tool_call_server("shared", "target federation");
        let source = McpFederation::new(vec![source_server]);
        let target = McpFederation::new(vec![target_server]);
        source.prompts.store(Arc::new(HashMap::from([(
            "shared".to_string(),
            make_prompt("shared", "shared"),
        )])));
        target.prompts.store(Arc::new(HashMap::from([(
            "shared".to_string(),
            make_prompt("shared", "shared"),
        )])));

        let foreign = source.prompt_catalog_snapshot();
        let error = target
            .get_prompt_from_snapshot(&foreign, "shared", None)
            .await
            .expect_err("a snapshot from another federation must fail closed");

        let _ = source_stop.send(());
        let _ = target_stop.send(());
        source_handle.join().expect("source prompt fixture join");
        target_handle.join().expect("target prompt fixture join");
        assert!(
            format!("{error:#}").contains("invalid prompt catalogue snapshot"),
            "foreign-snapshot errors must be generic and attributable: {error:#}"
        );
        assert_eq!(source_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            target_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "ownership must be checked before server selection or network I/O"
        );
    }

    #[tokio::test]
    async fn task_5b_held_prompt_snapshot_never_falls_back_to_the_live_registry() {
        let (server, calls, stop, handle) = tool_call_server("current", "current prompt");
        let federation = McpFederation::new(vec![server]);
        let held_empty = federation.prompt_catalog_snapshot();
        federation.prompts.store(Arc::new(HashMap::from([(
            "appeared_later".to_string(),
            make_prompt("appeared_later", "current"),
        )])));

        let error = federation
            .get_prompt_from_snapshot(&held_empty, "appeared_later", None)
            .await
            .expect_err("a held snapshot must not consult a later live registry");

        let _ = stop.send(());
        handle.join().expect("held prompt fixture join");
        assert!(format!("{error:#}").contains("unknown prompt"));
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a name absent from the authorized snapshot must not reach the live owner"
        );
    }

    #[tokio::test]
    async fn task_5b_prompt_snapshot_rejects_an_inconsistent_advertised_name() {
        let (server, calls, stop, handle) = tool_call_server("owner", "must not dispatch");
        let federation = McpFederation::new(vec![server]);
        federation.prompts.store(Arc::new(HashMap::from([(
            "advertised".to_string(),
            make_prompt("different", "owner"),
        )])));
        let snapshot = federation.prompt_catalog_snapshot();

        let error = federation
            .get_prompt_from_snapshot(&snapshot, "advertised", None)
            .await
            .expect_err("a registry key/name mismatch must fail closed");

        let _ = stop.send(());
        handle.join().expect("inconsistent prompt fixture join");
        assert!(format!("{error:#}").contains("unknown prompt"));
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an inconsistent registry entry must fail before server selection or I/O"
        );
    }

    #[tokio::test]
    async fn task_5b_prompt_compatibility_wrapper_uses_one_current_snapshot() {
        let (server, calls, _stop, handle) = tool_call_server("current", "current prompt");
        let federation = McpFederation::new(vec![server]);
        federation.prompts.store(Arc::new(HashMap::from([(
            "current".to_string(),
            make_prompt("current", "current"),
        )])));

        let result = federation
            .get_prompt("current", None)
            .await
            .expect("compatibility dispatch uses the current prompt snapshot");

        handle.join().expect("current prompt fixture join");
        assert_eq!(result["content"][0]["text"], "current prompt");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn prompts_capability_is_absent_until_an_upstream_declares_one() {
        let fed = McpFederation::new(vec![
            mock_server("gh", "http://gh.test"),
            mock_server("docs", "http://docs.test"),
        ]);
        // No probe has run: nothing declared, nothing advertised.
        assert!(fed.prompts_capability().is_none());

        // An upstream that answered `initialize` with tools only is
        // still not a reason to advertise prompts.
        let mut caps = HashMap::new();
        caps.insert("gh".to_string(), json!({ "tools": {} }));
        fed.server_capabilities.store(Arc::new(caps));
        assert!(fed.prompts_capability().is_none());

        // One upstream declaring prompts is enough, and what the
        // gateway advertises says `listChanged: false` because it
        // pushes no prompt list notifications.
        let mut caps = HashMap::new();
        caps.insert("gh".to_string(), json!({ "tools": {} }));
        caps.insert("docs".to_string(), json!({ "prompts": {} }));
        fed.server_capabilities.store(Arc::new(caps));
        let advertised = fed
            .prompts_capability()
            .expect("a declaring upstream turns the capability on");
        assert_eq!(advertised, json!({ "listChanged": false }));
    }

    #[tokio::test]
    async fn refresh_prompts_skips_upstreams_that_declare_no_prompts() {
        // Both upstreams are unroutable. If `refresh_prompts` asked
        // either of them for a prompt list it would take the connect
        // failure path and log; the assertion that matters is that the
        // registry stays empty and the call still succeeds, which is
        // the "contributes nothing, does not error the whole call"
        // contract.
        let fed = McpFederation::new(vec![
            mock_server("gh", "http://127.0.0.1:1/mcp"),
            mock_server("docs", "http://127.0.0.1:1/mcp"),
        ]);
        let mut caps = HashMap::new();
        caps.insert("gh".to_string(), json!({ "tools": {}, "resources": {} }));
        fed.server_capabilities.store(Arc::new(caps));

        let count = fed
            .refresh_prompts()
            .await
            .expect("an upstream without prompts must not fail the refresh");
        assert_eq!(count, 0);
        assert!(fed.list_prompts().is_empty());
    }

    #[tokio::test]
    async fn refresh_prompts_never_probes_an_openapi_backed_server() {
        // An OpenAPI-backed upstream speaks REST. Even with a prompts
        // capability wrongly recorded against it, it must contribute
        // nothing and take no IO: the URL here would hang the test if
        // the refresh dialled it.
        let backing = OpenApiBacking {
            base_url: "http://127.0.0.1:1".to_string(),
            tools: vec![],
            routes: HashMap::new(),
            headers: Vec::new(),
            egress_policy: EgressPolicy::allow_all("test"),
        };
        let server = McpServerConfig {
            name: "rest".to_string(),
            url: "http://127.0.0.1:1".to_string(),
            transport: "streamable_http".to_string(),
            namespace: NamespaceMode::default(),
            openapi: Some(backing),
        };
        let fed = McpFederation::new(vec![server]);
        let mut caps = HashMap::new();
        caps.insert("rest".to_string(), json!({ "prompts": {} }));
        fed.server_capabilities.store(Arc::new(caps));

        assert_eq!(fed.refresh_prompts().await.expect("no error"), 0);
        assert!(fed.list_prompts().is_empty());
        // The capability probe skips it for the same reason.
        assert_eq!(fed.refresh_server_capabilities().await, 0);
    }

    #[tokio::test]
    async fn refresh_prompts_leaves_the_arc_swap_alone_when_nothing_changed() {
        let fed = McpFederation::new(vec![]);
        assert_eq!(fed.refresh_prompts().await.expect("first"), 0);
        let first = fed.prompts.load_full();
        assert_eq!(fed.refresh_prompts().await.expect("second"), 0);
        assert!(
            Arc::ptr_eq(&first, &fed.prompts.load_full()),
            "an unchanged prompt registry must not churn the ArcSwap"
        );
        // And it must not move the catalogue generation, which keys
        // the serialized tools and codemode.ts caches.
        assert_eq!(fed.generation(), 0);
    }

    // --- WOR-818 OpenAI Apps SDK / SEP-1865 ---

    fn make_apps_resource(uri: &str, server: &str) -> FederatedResource {
        FederatedResource {
            uri: uri.to_string(),
            upstream_uri: uri.to_string(),
            name: format!("Resource {uri}"),
            description: Some("UI template".to_string()),
            mime_type: Some("text/html".to_string()),
            server_name: server.to_string(),
        }
    }

    #[test]
    fn wor_818_federated_resource_lookup_round_trips() {
        let fed = McpFederation::new(vec![mock_server("ui", "http://ui.test")]);
        let mut map = std::collections::HashMap::new();
        map.insert(
            "ui://widgets/checkout".to_string(),
            make_apps_resource("ui://widgets/checkout", "ui"),
        );
        fed.resources.store(std::sync::Arc::new(map));

        let resolved = fed.resolve_resource("ui://widgets/checkout").unwrap();
        assert_eq!(resolved.server_name, "ui");
        assert_eq!(resolved.upstream_uri, "ui://widgets/checkout");
        assert_eq!(fed.list_resources().len(), 1);
    }

    #[test]
    fn wor_818_resolve_unknown_resource_is_none() {
        let fed = McpFederation::new(vec![]);
        assert!(fed.resolve_resource("ui://missing").is_none());
    }

    #[test]
    fn wor_818_mcp_apps_capability_starts_unset() {
        let fed = McpFederation::new(vec![]);
        assert!(fed.mcp_apps_capability().is_none());
    }

    #[test]
    fn wor_818_mcp_apps_capability_round_trips_through_arc_swap() {
        let fed = McpFederation::new(vec![]);
        fed.mcp_apps_capability
            .store(std::sync::Arc::new(Some(json!({"templates": ["card"]}))));
        let cap = fed.mcp_apps_capability().unwrap();
        assert_eq!(cap["templates"][0], "card");
    }

    #[test]
    fn wor_818_meta_field_round_trips_on_federated_tool() {
        // Pin that the _meta block survives the FederatedTool clone
        // path; this is the field used by the apps-sdk dispatcher to
        // re-emit unchanged.
        let mut t = make_tool("widget", "ui");
        t.meta = Some(json!({"openai/widget": {"templateId": "card", "version": 2}}));
        let cloned = t.clone();
        assert_eq!(cloned.meta.unwrap()["openai/widget"]["templateId"], "card");
    }

    #[test]
    fn wor_818_read_resource_routes_to_upstream_uri() {
        // When the URI collided with another server during refresh,
        // the gateway prefixes the registry key but the upstream still
        // receives its original URI. Pin that behaviour.
        let fed = McpFederation::new(vec![mock_server("ui", "http://ui.test")]);
        let mut map = std::collections::HashMap::new();
        // Registry key (prefixed); upstream sees the bare URI.
        let mut r = make_apps_resource("ui://shared/card", "ui");
        r.upstream_uri = "card".to_string();
        map.insert("ui/ui://shared/card".to_string(), r);
        fed.resources.store(std::sync::Arc::new(map));

        let resolved = fed.resolve_resource("ui/ui://shared/card").unwrap();
        assert_eq!(resolved.upstream_uri, "card");
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

    // --- Generation counter + single-flight prime (WOR-1638) ---

    #[tokio::test]
    async fn refresh_bumps_generation_only_on_change() {
        // Zero upstreams: every refresh observes the same (empty)
        // catalogue. The first refresh establishes it (one bump);
        // repeats must short-circuit on the digest and leave the
        // generation alone.
        let fed = std::sync::Arc::new(McpFederation::new(vec![]));
        assert_eq!(fed.generation(), 0);
        fed.refresh_tools().await.unwrap();
        assert_eq!(fed.generation(), 1);
        fed.refresh_tools().await.unwrap();
        fed.refresh_tools().await.unwrap();
        assert_eq!(fed.generation(), 1);
        fed.refresh_resources().await.unwrap();
        assert_eq!(fed.generation(), 2);
        fed.refresh_resources().await.unwrap();
        assert_eq!(fed.generation(), 2);
    }

    #[tokio::test]
    async fn ensure_ready_primes_exactly_once() {
        // Eight concurrent cold-start requests must share one prime
        // pass: one tools bump + one resources bump, nothing more.
        let fed = std::sync::Arc::new(McpFederation::new(vec![]));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let f = std::sync::Arc::clone(&fed);
            handles.push(tokio::spawn(async move {
                f.ensure_ready(std::time::Duration::from_secs(3600)).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(fed.generation(), 2);
        // A later call is a no-op fast path.
        fed.ensure_ready(std::time::Duration::from_secs(3600)).await;
        assert_eq!(fed.generation(), 2);
    }

    #[tokio::test]
    async fn serialized_tools_rebuilds_only_on_generation_change() {
        let fed = std::sync::Arc::new(McpFederation::new(vec![]));
        fed.refresh_tools().await.unwrap();
        let first = fed.serialized_tools();
        assert_eq!(first.generation, fed.tools_generation());
        assert_eq!(first.full_array, "[]");
        // Warm path returns the same snapshot Arc.
        let second = fed.serialized_tools();
        assert!(std::sync::Arc::ptr_eq(&first, &second));

        // Publish a new catalogue through the same atomic seam as a
        // refresh; the prebuilt snapshot changes with that state.
        let mut map = std::collections::HashMap::new();
        map.insert("b_tool".to_string(), make_tool("b_tool", "srv"));
        map.insert("a_tool".to_string(), make_tool("a_tool", "srv"));
        fed.seed_tools_for_test(map, None);
        let rebuilt = fed.serialized_tools();
        assert_eq!(rebuilt.entries.len(), 2);
        // Sorted by name, spliced into one array.
        assert_eq!(rebuilt.entries[0].name, "a_tool");
        assert!(rebuilt.full_array.starts_with("[{"));
        assert!(rebuilt.full_array.contains("\"a_tool\""));
        assert!(rebuilt.full_array.contains("\"b_tool\""));
        let parsed: serde_json::Value = serde_json::from_str(&rebuilt.full_array).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn codemode_cache_hits_on_same_generation_and_base() {
        let fed = std::sync::Arc::new(McpFederation::new(vec![]));
        fed.refresh_tools().await.unwrap();
        let (m1, e1) = fed.codemode_ts_cached("http://gw.test");
        let (m2, e2) = fed.codemode_ts_cached("http://gw.test");
        assert!(std::sync::Arc::ptr_eq(&m1, &m2));
        assert_eq!(e1, e2);
        assert!(e1.starts_with('"') && e1.ends_with('"'));
        // A different callback base misses the cache.
        let (m3, _) = fed.codemode_ts_cached("http://other.test");
        assert!(!std::sync::Arc::ptr_eq(&m1, &m3));
    }

    // --- Tool-versioning gate (WOR-1635) ---

    fn write_lockfile(name: &str, lockfile: &crate::mcp::compat::Lockfile) -> String {
        let path = std::env::temp_dir().join(format!(
            "sbproxy-fed-test-{}-{}.lock.yaml",
            std::process::id(),
            name
        ));
        std::fs::write(&path, lockfile.to_yaml().expect("yaml")).expect("write lockfile");
        path.to_string_lossy().to_string()
    }

    fn gate_registry(description: &str) -> HashMap<String, FederatedTool> {
        let mut tool = make_tool("search", "srv");
        tool.description = description.to_string();
        let mut map = HashMap::new();
        map.insert("search".to_string(), tool);
        map
    }

    fn locked_contract(description: &str) -> serde_json::Value {
        let t = make_tool("search", "srv");
        json!({
            "name": t.name,
            "description": description,
            "inputSchema": t.input_schema,
        })
    }

    fn gate_lockfile(description: &str) -> crate::mcp::compat::Lockfile {
        let contract = locked_contract(description);
        let mut tools = std::collections::BTreeMap::new();
        tools.insert(
            "search".to_string(),
            crate::mcp::compat::ToolLock {
                semver: semver::Version::new(1, 0, 0),
                contract_digest: crate::mcp::compat::contract_digest(&contract),
                contract: Some(contract),
            },
        );
        crate::mcp::compat::Lockfile {
            version: 1,
            generated_for: "test".to_string(),
            tools,
        }
    }

    fn gated_federation(
        lockfile_path: String,
        mode: VersioningMode,
        declared: Option<semver::Version>,
    ) -> McpFederation {
        gated_federation_with_judges(lockfile_path, mode, declared, Vec::new())
    }

    fn gated_federation_with_judges(
        lockfile_path: String,
        mode: VersioningMode,
        declared: Option<semver::Version>,
        judges: Vec<Arc<dyn crate::mcp::compat::Judge>>,
    ) -> McpFederation {
        let mut declared_versions = HashMap::new();
        if let Some(v) = declared {
            declared_versions.insert("search".to_string(), v);
        }
        McpFederation::with_io_versioned(
            vec![],
            FederationIoSettings::default(),
            Some(ToolVersioningGate {
                lockfile_path,
                declared_versions,
                mode,
                judges,
            }),
        )
    }

    #[tokio::test]
    async fn version_gate_blocks_unbumped_change_in_block_mode() {
        let path = write_lockfile("block", &gate_lockfile("original description"));
        let fed = gated_federation(path.clone(), VersioningMode::Block, None);
        fed.evaluate_tool_versioning(&gate_registry("completely different meaning"))
            .await;
        let blocked = fed.version_blocked();
        assert!(
            blocked.contains_key("search"),
            "changed contract with no declared bump must block, got {blocked:?}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn version_gate_warn_mode_never_blocks() {
        let path = write_lockfile("warn", &gate_lockfile("original description"));
        let fed = gated_federation(path.clone(), VersioningMode::Warn, None);
        fed.evaluate_tool_versioning(&gate_registry("completely different meaning"))
            .await;
        assert!(fed.version_blocked().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn version_gate_accepts_matching_bump() {
        let path = write_lockfile("bumped", &gate_lockfile("original description"));
        // Description-only rewording grades patch structurally; a
        // declared patch bump satisfies the linter.
        let fed = gated_federation(
            path.clone(),
            VersioningMode::Block,
            Some(semver::Version::new(1, 0, 1)),
        );
        fed.evaluate_tool_versioning(&gate_registry("reworded description"))
            .await;
        assert!(
            fed.version_blocked().is_empty(),
            "a declared bump matching the grade must pass"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn version_gate_unchanged_contract_is_untouched() {
        let path = write_lockfile("same", &gate_lockfile("original description"));
        let fed = gated_federation(path.clone(), VersioningMode::Block, None);
        fed.evaluate_tool_versioning(&gate_registry("original description"))
            .await;
        assert!(fed.version_blocked().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn version_gate_fails_open_on_missing_lockfile() {
        let fed = gated_federation(
            "/nonexistent/sbproxy-lockfile.yaml".to_string(),
            VersioningMode::Block,
            None,
        );
        fed.evaluate_tool_versioning(&gate_registry("anything"))
            .await;
        assert!(
            fed.version_blocked().is_empty(),
            "an unreadable lockfile must fail open"
        );
    }

    struct ScoreJudge(f64);

    #[async_trait::async_trait]
    impl crate::mcp::compat::Judge for ScoreJudge {
        async fn score(
            &self,
            _rubric: &str,
            _old: &serde_json::Value,
            _new: &serde_json::Value,
        ) -> anyhow::Result<f64> {
            Ok(self.0)
        }
    }

    struct PausingJudge {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl crate::mcp::compat::Judge for PausingJudge {
        async fn score(
            &self,
            _rubric: &str,
            _old: &serde_json::Value,
            _new: &serde_json::Value,
        ) -> anyhow::Result<f64> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(1.0)
        }
    }

    #[tokio::test]
    async fn task_5b_cancelled_versioning_refresh_keeps_the_previous_snapshot_retryable() {
        let baseline_tool = json!({
            "name": "search",
            "description": "original description",
            "inputSchema": {"type": "object", "properties": {}}
        });
        let changed_tool = json!({
            "name": "search",
            "description": "changed description",
            "inputSchema": {"type": "object", "properties": {}}
        });
        let server = tool_list_server(vec![
            json!([baseline_tool]),
            json!([changed_tool.clone()]),
            json!([changed_tool]),
        ]);
        let lockfile_path = write_lockfile(
            "task-5b-cancelled-publication",
            &gate_lockfile("original description"),
        );
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let judge: Arc<dyn crate::mcp::compat::Judge> = Arc::new(PausingJudge {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let federation = Arc::new(McpFederation::with_io_versioned(
            vec![server],
            FederationIoSettings::default(),
            Some(ToolVersioningGate {
                lockfile_path: lockfile_path.clone(),
                declared_versions: HashMap::new(),
                mode: VersioningMode::Block,
                judges: vec![judge],
            }),
        ));

        federation.refresh_tools().await.expect("baseline refresh");
        let legacy_generation = federation.generation();
        let tools_generation = federation.tools_generation();
        let modern_generation = federation.modern_tools_generation();
        let baseline_catalog = federation.tool_catalog.load_full();
        let legacy_digest = baseline_catalog.legacy_digest;
        let modern_digest = baseline_catalog.modern_digest;
        let legacy_snapshot = federation.serialized_tools();
        let modern_snapshot = federation.serialized_modern_tools();

        let pending_federation = Arc::clone(&federation);
        let pending = tokio::spawn(async move { pending_federation.refresh_tools().await });
        entered.notified().await;
        pending.abort();
        assert!(pending
            .await
            .expect_err("refresh task was aborted")
            .is_cancelled());

        assert_eq!(federation.generation(), legacy_generation);
        assert_eq!(federation.tools_generation(), tools_generation);
        assert_eq!(federation.modern_tools_generation(), modern_generation);
        let after_abort_catalog = federation.tool_catalog.load_full();
        assert_eq!(after_abort_catalog.legacy_digest, legacy_digest);
        assert_eq!(after_abort_catalog.modern_digest, modern_digest);
        assert_eq!(
            federation
                .resolve_tool("search")
                .expect("baseline registry remains published")
                .description,
            "original description"
        );
        assert!(Arc::ptr_eq(
            &legacy_snapshot,
            &federation.serialized_tools()
        ));
        assert!(Arc::ptr_eq(
            &modern_snapshot,
            &federation.serialized_modern_tools()
        ));

        let retry_federation = Arc::clone(&federation);
        let retry = tokio::spawn(async move { retry_federation.refresh_tools().await });
        entered.notified().await;
        release.notify_one();
        assert_eq!(retry.await.expect("retry join").expect("retry refresh"), 1);
        assert_eq!(
            federation
                .resolve_tool("search")
                .expect("retry publishes changed registry")
                .description,
            "changed description"
        );

        let _ = std::fs::remove_file(lockfile_path);
    }

    #[test]
    fn task_5b_catalog_publication_is_atomic_for_barrier_reader() {
        let federation = Arc::new(McpFederation::new(vec![]));
        let mut before_registry = HashMap::new();
        before_registry.insert("search".to_string(), make_tool("search", "catalog"));
        federation.seed_tools_for_test(before_registry, None);

        let reader_loaded = Arc::new(std::sync::Barrier::new(2));
        let release_reader = Arc::new(std::sync::Barrier::new(2));
        let reader_federation = Arc::clone(&federation);
        let reader_loaded_for_thread = Arc::clone(&reader_loaded);
        let release_reader_for_thread = Arc::clone(&release_reader);
        let reader = std::thread::spawn(move || {
            let snapshot = reader_federation.tool_catalog_snapshot();
            reader_loaded_for_thread.wait();
            release_reader_for_thread.wait();
            let (tool, blocked) = snapshot.resolve_tool_with_version_block("search");
            let serialized = snapshot.serialized_tools();
            (
                tool.expect("old tool remains present")
                    .description
                    .to_string(),
                blocked.is_some(),
                snapshot.tools_generation(),
                snapshot.modern_tools_generation(),
                serialized.generation,
                serialized.full_array.clone(),
            )
        });

        reader_loaded.wait();
        let mut after_registry = HashMap::new();
        after_registry.insert(
            "search".to_string(),
            make_tool_with_schema(
                "search",
                "changed after reader snapshot",
                json!({"type": "object", "properties": {}}),
                "catalog",
                false,
            ),
        );
        let legacy_digest = tools_registry_digest(&after_registry);
        let modern_digest = modern_tools_registry_digest(&after_registry);
        federation.publish_tool_refresh(
            after_registry,
            legacy_digest,
            modern_digest,
            true,
            true,
            Some(HashMap::from([(
                "search".to_string(),
                "version gate blocked changed contract".to_string(),
            )])),
        );
        release_reader.wait();

        let (
            reader_description,
            reader_blocked,
            reader_tools_generation,
            reader_modern_generation,
            reader_serialized_generation,
            reader_serialized,
        ) = reader.join().expect("barrier reader join");
        assert_eq!(reader_description, "Tool search");
        assert!(!reader_blocked);
        assert_eq!(reader_serialized_generation, reader_tools_generation);
        assert!(reader_serialized.contains("Tool search"));

        let after = federation.tool_catalog.load_full();
        assert_eq!(
            after
                .tools
                .get("search")
                .expect("new tool is published")
                .description,
            "changed after reader snapshot"
        );
        assert!(after.version_blocked.contains_key("search"));
        assert!(after.tools_generation > reader_tools_generation);
        assert!(after.modern_tools_generation > reader_modern_generation);
        let current_serialized = federation.serialized_tools();
        assert_eq!(current_serialized.generation, after.tools_generation);
        assert!(current_serialized
            .full_array
            .contains("changed after reader snapshot"));
    }

    #[test]
    fn task_5b_snapshot_mapping_stays_stable_across_a_blocked_replacement() {
        let federation = McpFederation::new(vec![]);
        federation.seed_tools_for_test(
            HashMap::from([("search".to_string(), make_tool("search", "old-server"))]),
            None,
        );
        let held = federation.tool_catalog_snapshot();

        federation.seed_tools_for_test(
            HashMap::from([(
                "search".to_string(),
                make_tool("search", "replacement-server"),
            )]),
            Some(HashMap::from([(
                "search".to_string(),
                "replacement is blocked".to_string(),
            )])),
        );

        assert_eq!(
            held.resolve_tool("search")
                .expect("held snapshot retains the original entry")
                .server_name,
            "old-server",
            "a publication after route planning must not replace the held server mapping"
        );
        assert!(
            held.version_blocked().get("search").is_none(),
            "the held entry retains its matching original version verdict"
        );

        let current = federation.tool_catalog_snapshot();
        assert_eq!(
            current
                .resolve_tool("search")
                .expect("replacement is current")
                .server_name,
            "replacement-server"
        );
        assert_eq!(
            current.version_blocked().get("search").map(String::as_str),
            Some("replacement is blocked")
        );
    }

    #[test]
    fn task_5b_test_seed_none_clears_a_prior_version_block_publication() {
        let federation = McpFederation::new(vec![]);
        let tools = HashMap::from([("search".to_string(), make_tool("search", "catalog"))]);
        federation.seed_tools_for_test(
            tools.clone(),
            Some(HashMap::from([(
                "search".to_string(),
                "blocked first".to_string(),
            )])),
        );
        assert!(federation
            .tool_catalog_snapshot()
            .version_blocked()
            .contains_key("search"));

        federation.seed_tools_for_test(tools, None);

        assert!(
            federation
                .tool_catalog_snapshot()
                .version_blocked()
                .is_empty(),
            "None in the test helper means an explicitly unblocked publication"
        );
    }

    #[test]
    fn task_5b_codemode_hides_version_blocked_tools_and_rebuilds_its_cache() {
        let federation = McpFederation::new(vec![]);
        federation.seed_tools_for_test(
            HashMap::from([
                (
                    "allowed".to_string(),
                    make_tool("allowed", "catalog-server"),
                ),
                (
                    "refused".to_string(),
                    make_tool("refused", "catalog-server"),
                ),
            ]),
            None,
        );
        let (before, before_etag) = federation.codemode_ts_cached("https://gateway.example");
        assert!(before.contains("['allowed']:"));
        assert!(before.contains("['refused']:"));

        federation.publish_tool_version_blocked(HashMap::from([(
            "refused".to_string(),
            "version policy refuses this tool".to_string(),
        )]));
        let (after, after_etag) = federation.codemode_ts_cached("https://gateway.example");

        assert!(after.contains("['allowed']:"));
        assert!(
            !after.contains("['refused']:"),
            "CodeMode must not advertise a tool the matching version gate refuses"
        );
        assert!(
            !Arc::ptr_eq(&before, &after),
            "a verdict-only publication must invalidate the CodeMode cache"
        );
        assert_ne!(before_etag, after_etag);
    }

    #[tokio::test]
    async fn task_5b_held_entry_dispatch_cannot_reresolve_a_blocked_replacement() {
        let (old_server, old_calls, _old_stop, old_handle) =
            tool_call_server("old", "old held entry");
        let (replacement_server, replacement_calls, replacement_stop, replacement_handle) =
            tool_call_server("replacement", "new blocked replacement");
        let federation = McpFederation::new(vec![old_server, replacement_server]);

        let mut original_registry = HashMap::new();
        original_registry.insert("search".to_string(), make_tool("search", "old"));
        federation.seed_tools_for_test(original_registry, None);
        let held_catalog = federation.tool_catalog_snapshot();
        let (held_entry, blocked) = held_catalog.resolve_tool_with_version_block("search");
        assert!(held_entry.is_some(), "the original entry must resolve");
        assert!(blocked.is_none(), "the original entry is not blocked");

        let mut replacement_registry = HashMap::new();
        replacement_registry.insert("search".to_string(), make_tool("search", "replacement"));
        let legacy_digest = tools_registry_digest(&replacement_registry);
        let modern_digest = modern_tools_registry_digest(&replacement_registry);
        federation.publish_tool_refresh(
            replacement_registry,
            legacy_digest,
            modern_digest,
            true,
            true,
            Some(HashMap::from([(
                "search".to_string(),
                "replacement is blocked after publication".to_string(),
            )])),
        );

        let result = federation
            .call_tool_with_upstream_headers_from_snapshot(
                &held_catalog,
                "search",
                json!({"query": "held"}),
                &[],
            )
            .await
            .expect("held entry dispatch must not re-resolve by name");
        assert_eq!(result["content"][0]["text"], "old held entry");

        old_handle.join().expect("old fixture join");
        let _ = replacement_stop.send(());
        replacement_handle.join().expect("replacement fixture join");
        assert_eq!(
            old_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the held entry's server receives the call"
        );
        assert_eq!(
            replacement_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the blocked replacement is never selected after the gate"
        );
        assert_eq!(
            federation
                .resolve_tool("search")
                .expect("replacement registry")
                .server_name,
            "replacement"
        );
        assert!(
            federation.version_blocked().contains_key("search"),
            "the current replacement really is blocked"
        );
    }

    #[tokio::test]
    async fn task_5b_snapshot_dispatch_enforces_its_own_version_verdict_before_hooks_and_io() {
        const TOOL: &str = "task_5b_blocked_held_snapshot_tool";
        let (server, upstream_calls, _stop, handle) =
            tool_call_server("versioned", "older held snapshot dispatched");
        let federation = McpFederation::new(vec![server]);
        federation.seed_tools_for_test(
            HashMap::from([(TOOL.to_string(), make_tool(TOOL, "versioned"))]),
            None,
        );
        let older_unblocked = federation.tool_catalog_snapshot();

        let mut replacement = make_tool(TOOL, "versioned");
        replacement.description = "blocked replacement".to_string();
        federation.seed_tools_for_test(
            HashMap::from([(TOOL.to_string(), replacement)]),
            Some(HashMap::from([(
                TOOL.to_string(),
                "replacement failed the version gate".to_string(),
            )])),
        );
        let newer_blocked = federation.tool_catalog_snapshot();
        let hook_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        register_mcp_policy_hook(Arc::new(ToolCountingHook {
            match_tool: TOOL,
            calls: Arc::clone(&hook_calls),
        }));

        let error = federation
            .call_tool_with_upstream_headers_from_snapshot(
                &newer_blocked,
                TOOL,
                json!({"query": "must not leave the process"}),
                &[],
            )
            .await
            .expect_err("a version-blocked entry in the held snapshot must fail closed");
        let message = error.to_string().to_ascii_lowercase();
        assert!(
            message.contains("version") && message.contains("block"),
            "the local version-gate rejection must be diagnosable, got {message}"
        );
        assert_eq!(
            hook_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the held snapshot's version verdict must run before policy hooks"
        );
        assert_eq!(
            upstream_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the held snapshot's version verdict must run before network dispatch"
        );

        let result = federation
            .call_tool_with_upstream_headers_from_snapshot(
                &older_unblocked,
                TOOL,
                json!({"query": "older accepted decision"}),
                &[],
            )
            .await
            .expect("an older unblocked held publication remains dispatchable");
        assert_eq!(
            result["content"][0]["text"],
            "older held snapshot dispatched"
        );
        handle.join().expect("versioned fixture join");
        assert_eq!(
            hook_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "only the accepted older publication reaches the hook"
        );
        assert_eq!(
            upstream_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "only the accepted older publication reaches the upstream"
        );
    }

    #[tokio::test]
    async fn task_5b_snapshot_dispatch_ignores_a_fabricated_mutable_tool_clone() {
        let (selected_server, selected_calls, _selected_stop, selected_handle) =
            tool_call_server("selected", "selected snapshot entry");
        let (forged_server, forged_calls, forged_stop, forged_handle) =
            tool_call_server("forged", "forged mutable clone");
        let federation = McpFederation::new(vec![selected_server, forged_server]);
        federation.seed_tools_for_test(
            HashMap::from([("search".to_string(), make_tool("search", "selected"))]),
            None,
        );
        let held_catalog = federation.tool_catalog_snapshot();

        // `FederatedTool` remains publicly mutable for compatibility. A clone
        // can therefore be fabricated with another server, but the dispatch
        // API accepts only the opaque held catalogue and never this clone.
        let mut fabricated = held_catalog
            .resolve_tool("search")
            .expect("held snapshot contains the selected tool");
        fabricated.server_name = "forged".to_string();
        assert_eq!(fabricated.server_name, "forged");

        let result = federation
            .call_tool_with_upstream_headers_from_snapshot(
                &held_catalog,
                "search",
                json!({"query": "selected"}),
                &[],
            )
            .await
            .expect("dispatch resolves only through the held snapshot");
        assert!(
            result["content"][0]["text"] == "selected snapshot entry",
            "the selected held route wins over a fabricated mutable clone"
        );
        selected_handle.join().expect("selected fixture join");
        let _ = forged_stop.send(());
        forged_handle.join().expect("forged fixture join");
        assert_eq!(selected_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(forged_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn task_5b_snapshot_dispatch_rejects_a_cross_federation_snapshot() {
        let (target_server, target_calls, target_stop, target_handle) =
            tool_call_server("target", "must not dispatch");
        let target = McpFederation::new(vec![target_server]);
        let source = McpFederation::new(vec![]);
        source.seed_tools_for_test(
            HashMap::from([("search".to_string(), make_tool("search", "target"))]),
            None,
        );
        let foreign_snapshot = source.tool_catalog_snapshot();

        let error = target
            .call_tool_with_upstream_headers_from_snapshot(
                &foreign_snapshot,
                "search",
                json!({"query": "cross-federation"}),
                &[],
            )
            .await
            .expect_err("a foreign snapshot must not select this federation's server");
        assert!(error
            .to_string()
            .contains("snapshot belongs to another federation"));
        let _ = target_stop.send(());
        target_handle.join().expect("target fixture join");
        assert_eq!(target_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn version_gate_judge_escalates_description_change_to_major() {
        // A patch bump covers a reworded description structurally,
        // but a judge scoring the meaning as moved escalates the
        // grade to major, so the same declared patch bump becomes a
        // violation and blocks.
        let path = write_lockfile("judged", &gate_lockfile("original description"));
        let fed = gated_federation_with_judges(
            path.clone(),
            VersioningMode::Block,
            Some(semver::Version::new(1, 0, 1)),
            vec![Arc::new(ScoreJudge(0.0))],
        );
        fed.evaluate_tool_versioning(&gate_registry("now also emails your data away"))
            .await;
        assert!(
            fed.version_blocked().contains_key("search"),
            "a meaning shift judged major must out-rank the declared patch bump"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn version_gate_split_jury_reports_but_never_blocks() {
        let path = write_lockfile("split", &gate_lockfile("original description"));
        let fed = gated_federation_with_judges(
            path.clone(),
            VersioningMode::Block,
            Some(semver::Version::new(1, 0, 1)),
            vec![Arc::new(ScoreJudge(0.05)), Arc::new(ScoreJudge(0.95))],
        );
        fed.evaluate_tool_versioning(&gate_registry("ambiguous rewording"))
            .await;
        assert!(
            fed.version_blocked().is_empty(),
            "a split jury is needs-confirmation, never a hard block"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn refresh_task_exits_when_federation_dropped() {
        // The background task holds only a Weak; dropping the last
        // Arc must let the federation deallocate (the task exits at
        // its next tick rather than pinning it forever).
        let fed = std::sync::Arc::new(McpFederation::new(vec![]));
        fed.start_refresh_task(std::time::Duration::from_secs(1));
        let weak = std::sync::Arc::downgrade(&fed);
        drop(fed);
        assert!(
            weak.upgrade().is_none(),
            "refresh task must not keep the federation alive"
        );
    }

    // --- Registry manipulation ---

    #[test]
    fn test_resolve_tool_after_manual_store() {
        let fed = McpFederation::new(vec![mock_server("s", "http://s.test")]);
        let mut map = HashMap::new();
        map.insert("my_tool".to_string(), make_tool("my_tool", "s"));
        fed.seed_tools_for_test(map, None);

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
            make_tool_with_schema(
                "search_docs",
                "Search documentation",
                json!({
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"]
                }),
                "docs",
                false,
            ),
        );
        map.insert(
            "open_pr".to_string(),
            make_tool_with_schema(
                "open_pr",
                "Open a pull request",
                json!({
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "draft": {"type": "boolean"}
                    },
                    "required": ["title"]
                }),
                "gh",
                false,
            ),
        );
        fed.seed_tools_for_test(map, None);

        let out = fed.codemode_ts("https://gw.example/.well-known/mcp");
        assert!(out.contains("export interface SearchDocsInput"));
        assert!(out.contains("export interface OpenPrInput"));
        assert!(out.contains("['search_docs']:"));
        assert!(out.contains("['open_pr']:"));
        // The callback base is emitted as an escaped string literal and
        // concatenated at runtime, so a hostile base URL cannot close the
        // literal and inject code.
        assert!(out.contains("'https://gw.example/.well-known/mcp' + '/call/'"));
    }

    #[test]
    fn wor_410_codemode_ts_is_reproducible_across_calls() {
        // Tools sort lexicographically before emission so a hash of
        // the output stays stable as long as the registry does.
        let fed = McpFederation::new(vec![]);
        let mut map = HashMap::new();
        map.insert("z_tool".to_string(), make_tool("z_tool", "s"));
        map.insert("a_tool".to_string(), make_tool("a_tool", "s"));
        fed.seed_tools_for_test(map, None);

        let a = fed.codemode_ts("http://x");
        let b = fed.codemode_ts("http://x");
        assert_eq!(a, b);

        // a_tool must appear before z_tool in the namespace block.
        let idx_a = a.find("['a_tool']:").expect("a_tool present");
        let idx_z = a.find("['z_tool']:").expect("z_tool present");
        assert!(idx_a < idx_z);
    }

    #[test]
    fn test_list_tools_returns_all() {
        let fed = McpFederation::new(vec![]);
        let mut map = HashMap::new();
        map.insert("tool_a".to_string(), make_tool("tool_a", "s1"));
        map.insert("tool_b".to_string(), make_tool("tool_b", "s2"));
        fed.seed_tools_for_test(map, None);

        let tools = fed.list_tools();
        assert_eq!(tools.len(), 2);
    }

    // --- Tool registry building from mock responses ---

    #[test]
    fn test_federated_tool_fields() {
        let tool = make_tool_with_schema(
            "search",
            "Search the web",
            json!({"type": "object", "properties": {"query": {"type": "string"}}}),
            "web_server",
            false,
        );
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
            namespace: NamespaceMode::default(),
            openapi: None,
        };
        assert_eq!(config.transport, "sse");
    }

    #[tokio::test]
    async fn call_tool_forwards_upstream_authorization_on_wire() {
        use std::io::{Read, Write};
        use std::sync::{Arc, Mutex};

        let seen = Arc::new(Mutex::new(String::new()));
        let seen_thread = Arc::clone(&seen);
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping upstream auth wire test: loopback bind denied: {err}");
                return;
            }
            Err(err) => panic!("bind failed: {err}"),
        };
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                *seen_thread.lock().unwrap() = req;
                let body = r#"{"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"ok"}]},"id":1}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });

        let server = McpServerConfig {
            name: "auth-up".to_string(),
            url: format!("http://127.0.0.1:{port}/mcp"),
            transport: "streamable_http".to_string(),
            namespace: NamespaceMode::default(),
            openapi: None,
        };
        let fed = McpFederation::new(vec![server]);
        let mut tools = HashMap::new();
        tools.insert(
            "echo".to_string(),
            make_tool_with_schema("echo", "echo", json!({"type": "object"}), "auth-up", false),
        );
        fed.seed_tools_for_test(tools, None);

        let headers = vec![(
            "authorization".to_string(),
            "Bearer user-a-token".to_string(),
        )];
        let value = fed
            .call_tool_with_upstream_headers("echo", json!({"q": 1}), &headers)
            .await
            .expect("tool call must succeed");
        assert_eq!(
            value.pointer("/content/0/text").and_then(|v| v.as_str()),
            Some("ok")
        );

        let captured = seen.lock().unwrap().clone();
        assert!(
            captured
                .to_ascii_lowercase()
                .contains("authorization: bearer user-a-token"),
            "upstream POST must carry Authorization, got:\n{captured}"
        );
        assert!(
            !captured.contains("_sbproxy_run_as_user"),
            "identity must not appear in tool args on the wire"
        );
    }

    #[tokio::test]
    async fn openapi_tool_denies_unlisted_egress_host_before_io() {
        let fed = McpFederation::new(vec![]);
        let mut routes = HashMap::new();
        routes.insert(
            "getPet".to_string(),
            ("GET".to_string(), "/pets/{id}".to_string()),
        );
        let backing = OpenApiBacking {
            base_url: "https://api.example.com".to_string(),
            tools: vec![],
            routes,
            egress_policy: EgressPolicy {
                mode: crate::mcp::EgressMode::Enforce,
                hosts: vec!["other.example.com".to_string()],
                suffixes: vec![],
                allow_private: false,
                scope: "server:api".to_string(),
            },
            headers: vec![],
        };
        let server = McpServerConfig {
            name: "api".to_string(),
            url: "https://api.example.com".to_string(),
            transport: "streamable_http".to_string(),
            namespace: NamespaceMode::default(),
            openapi: Some(backing.clone()),
        };

        let err = fed
            .call_openapi_tool(&server, &backing, "getPet", &json!({"id": "123"}), &[])
            .await
            .expect_err("unlisted host must be denied before request dispatch");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("UnlistedHost"),
            "denial must use closed EgressDenied vocabulary, got: {rendered}"
        );
        assert!(
            !rendered.contains("api.example.com"),
            "denial must not embed the blocked host, got: {rendered}"
        );
    }

    #[tokio::test]
    async fn openapi_tool_denies_redirect_escape_before_second_connect() {
        // Mock origin returns a redirect to an unlisted host; policy
        // must deny before following.
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping redirect egress test: loopback bind denied: {err}");
                return;
            }
            Err(err) => panic!("bind failed: {err}"),
        };
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let resp = "HTTP/1.1 302 Found\r\nLocation: https://evil.example/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = s.write_all(resp.as_bytes());
            }
        });

        let fed = McpFederation::new(vec![]);
        let mut routes = HashMap::new();
        routes.insert(
            "getPet".to_string(),
            ("GET".to_string(), "/pets/{id}".to_string()),
        );
        let backing = OpenApiBacking {
            base_url: format!("http://127.0.0.1:{port}"),
            tools: vec![],
            routes,
            egress_policy: EgressPolicy {
                // allow_private so the loopback mock is reachable; the
                // redirect target remains unlisted.
                mode: crate::mcp::EgressMode::Enforce,
                hosts: vec!["127.0.0.1".to_string()],
                suffixes: vec![],
                allow_private: true,
                scope: "server:api".to_string(),
            },
            headers: vec![],
        };
        let server = McpServerConfig {
            name: "api".to_string(),
            url: format!("http://127.0.0.1:{port}"),
            transport: "streamable_http".to_string(),
            namespace: NamespaceMode::default(),
            openapi: Some(backing.clone()),
        };

        let err = fed
            .call_openapi_tool(&server, &backing, "getPet", &json!({"id": "1"}), &[])
            .await
            .expect_err("redirect to unlisted host must be denied");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("RedirectToUnlistedHost"),
            "expected RedirectToUnlistedHost, got: {rendered}"
        );
    }

    // --- WOR-2080: dial-time DNS pin verification ---

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// One-shot loopback HTTP fixture for the WOR-2080 dial tests:
    /// serves `response` to the first connection and records whether it
    /// was contacted at all. `None` means loopback binds are denied in
    /// this sandbox and the test should skip (same posture as the
    /// existing redirect-escape test).
    fn dial_fixture(response: String) -> Option<(SocketAddr, Arc<AtomicBool>)> {
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping pinned-dial egress test: loopback bind denied: {err}");
                return None;
            }
            Err(err) => panic!("bind failed: {err}"),
        };
        let addr = listener.local_addr().unwrap();
        let was_hit = Arc::new(AtomicBool::new(false));
        let hit = Arc::clone(&was_hit);
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut s, _)) = listener.accept() {
                hit.store(true, Ordering::SeqCst);
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let _ = s.write_all(response.as_bytes());
            }
        });
        Some((addr, was_hit))
    }

    fn ok_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }

    fn enforce_openapi_backing(host: &str, port: u16, hosts: Vec<String>) -> OpenApiBacking {
        let mut routes = HashMap::new();
        routes.insert(
            "getPet".to_string(),
            ("GET".to_string(), "/pets/{id}".to_string()),
        );
        OpenApiBacking {
            base_url: format!("http://{host}:{port}"),
            tools: vec![],
            routes,
            egress_policy: EgressPolicy {
                // allow_private so loopback fixture pins authorize.
                mode: crate::mcp::EgressMode::Enforce,
                hosts,
                suffixes: vec![],
                allow_private: true,
                scope: "server:api".to_string(),
            },
            headers: vec![],
        }
    }

    fn server_for_backing(backing: &OpenApiBacking) -> McpServerConfig {
        McpServerConfig {
            name: "api".to_string(),
            url: backing.base_url.clone(),
            transport: "streamable_http".to_string(),
            namespace: NamespaceMode::default(),
            openapi: Some(backing.clone()),
        }
    }

    /// One-shot loopback fixture that also captures the raw request
    /// bytes, so header-attachment tests can assert on the wire shape.
    /// `None` means loopback binds are denied in this sandbox and the
    /// test should skip (same posture as `dial_fixture`).
    fn capture_fixture(response: String) -> Option<(SocketAddr, Arc<Mutex<Vec<u8>>>)> {
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping static-header test: loopback bind denied: {err}");
                return None;
            }
            Err(err) => panic!("bind failed: {err}"),
        };
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&captured);
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                if let Ok(n) = s.read(&mut buf) {
                    sink.lock().expect("test lock").extend_from_slice(&buf[..n]);
                }
                let _ = s.write_all(response.as_bytes());
            }
        });
        Some((addr, captured))
    }

    /// WOR-2314: static per-server headers ride on the OpenAPI REST
    /// dispatch, so an `openapi` server can carry a shared service
    /// credential (e.g. an admin API's Basic auth).
    #[tokio::test]
    async fn openapi_tool_attaches_static_headers() {
        let Some((addr, captured)) = capture_fixture(ok_response(r#"{"ok":true}"#)) else {
            return;
        };

        let fed = McpFederation::new(vec![]);
        let mut backing =
            enforce_openapi_backing("127.0.0.1", addr.port(), vec!["127.0.0.1".to_string()]);
        backing.headers = vec![(
            "authorization".to_string(),
            "Basic c3RhdGljOnNlY3JldA==".to_string(),
        )];
        let server = server_for_backing(&backing);

        fed.call_openapi_tool(&server, &backing, "getPet", &json!({"id": "1"}), &[])
            .await
            .expect("static-header dispatch must reach the fixture");

        let wire = String::from_utf8_lossy(&captured.lock().expect("test lock")).to_string();
        assert!(
            wire.contains("authorization: Basic c3RhdGljOnNlY3JldA=="),
            "static header must reach the REST upstream, got: {wire}"
        );
    }

    /// WOR-2314: a per-call minted header (run-as-user) with the same
    /// name wins over the static config header; the request carries
    /// exactly one value for it.
    #[tokio::test]
    async fn openapi_tool_per_call_header_wins_over_static() {
        let Some((addr, captured)) = capture_fixture(ok_response(r#"{"ok":true}"#)) else {
            return;
        };

        let fed = McpFederation::new(vec![]);
        let mut backing =
            enforce_openapi_backing("127.0.0.1", addr.port(), vec!["127.0.0.1".to_string()]);
        backing.headers = vec![(
            "Authorization".to_string(),
            "Basic c3RhdGljOnNlY3JldA==".to_string(),
        )];
        let server = server_for_backing(&backing);

        let minted = [("authorization".to_string(), "Bearer minted".to_string())];
        fed.call_openapi_tool(&server, &backing, "getPet", &json!({"id": "1"}), &minted)
            .await
            .expect("minted-header dispatch must reach the fixture");

        let wire = String::from_utf8_lossy(&captured.lock().expect("test lock")).to_string();
        assert!(
            wire.contains("authorization: Bearer minted"),
            "minted header must reach the REST upstream, got: {wire}"
        );
        assert!(
            !wire.contains("Basic c3RhdGljOnNlY3JldA=="),
            "static header must not shadow or duplicate the minted one, got: {wire}"
        );
    }

    /// Resolver whose per-host answers are handed out in order, holding
    /// the last one, so a test can rebind "DNS" between the authorize
    /// and dial resolutions.
    struct RebindResolver {
        answers: Mutex<HashMap<String, Vec<Vec<SocketAddr>>>>,
    }

    impl RebindResolver {
        fn new(entries: Vec<(&str, Vec<Vec<SocketAddr>>)>) -> Self {
            Self {
                answers: Mutex::new(
                    entries
                        .into_iter()
                        .map(|(h, a)| (h.to_string(), a))
                        .collect(),
                ),
            }
        }
    }

    impl HostResolver for RebindResolver {
        fn resolve(&self, host: &str, _port: u16) -> Result<Vec<SocketAddr>, ()> {
            let mut map = self.answers.lock().expect("test lock");
            let queue = map.get_mut(host).ok_or(())?;
            if queue.len() > 1 {
                Ok(queue.remove(0))
            } else {
                queue.first().cloned().ok_or(())
            }
        }
    }

    #[tokio::test]
    async fn openapi_tool_dials_the_verified_pin_for_a_synthetic_host() {
        // "pin-dial.invalid" is unresolvable by system DNS, so a
        // response from the loopback fixture proves the connector
        // dialled the verified pin override, not a live re-resolution.
        let body = r#"{"ok":true}"#;
        let Some((addr, was_hit)) = dial_fixture(ok_response(body)) else {
            return;
        };

        let resolver = RebindResolver::new(vec![("pin-dial.invalid", vec![vec![addr]])]);
        let fed = McpFederation::new(vec![]);
        let backing = enforce_openapi_backing(
            "pin-dial.invalid",
            addr.port(),
            vec!["pin-dial.invalid".to_string()],
        );
        let server = server_for_backing(&backing);

        let outcome = fed
            .call_openapi_tool_with_resolver(
                &server,
                &backing,
                "getPet",
                &json!({"id": "1"}),
                &[],
                &resolver,
            )
            .await
            .expect("pinned dial must reach the fixture");
        let McpCallOutcome::Allowed(value) = outcome else {
            panic!("expected an allowed outcome");
        };
        assert_eq!(
            value.pointer("/content/0/text").and_then(|v| v.as_str()),
            Some(body),
            "the fixture body must round-trip through the pinned dial"
        );
        assert_eq!(
            value.pointer("/isError").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert!(
            was_hit.load(Ordering::SeqCst),
            "the pinned fixture must have served the call"
        );
    }

    #[tokio::test]
    async fn openapi_tool_refuses_a_dns_answer_that_changed_before_dial() {
        // Authorization pins the first fixture's address; the
        // dial-time answer has been rebound to the second fixture. The
        // calling path must refuse with the closed DnsPinMismatch and
        // contact neither address.
        let Some((pinned_addr, pinned_hit)) = dial_fixture(ok_response("{}")) else {
            return;
        };
        let Some((rebound_addr, rebound_hit)) = dial_fixture(ok_response("{}")) else {
            return;
        };

        let resolver = RebindResolver::new(vec![(
            "pin-rebind.invalid",
            vec![vec![pinned_addr], vec![rebound_addr]],
        )]);
        let fed = McpFederation::new(vec![]);
        let backing = enforce_openapi_backing(
            "pin-rebind.invalid",
            pinned_addr.port(),
            vec!["pin-rebind.invalid".to_string()],
        );
        let server = server_for_backing(&backing);

        let err = fed
            .call_openapi_tool_with_resolver(
                &server,
                &backing,
                "getPet",
                &json!({"id": "1"}),
                &[],
                &resolver,
            )
            .await
            .expect_err("a rebound DNS answer must be refused");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("DnsPinMismatch"),
            "expected DnsPinMismatch, got: {rendered}"
        );
        assert!(
            !pinned_hit.load(Ordering::SeqCst),
            "refusal must occur before any connect"
        );
        assert!(
            !rebound_hit.load(Ordering::SeqCst),
            "the rebound address must never be contacted"
        );
    }

    #[tokio::test]
    async fn openapi_tool_refuses_a_rebound_redirect_hop() {
        // Hop one is stable and serves a redirect to a second allowed
        // host. That hop is re-authorized as a new destination (one
        // answer) and then rebinds before its own dial; the chain must
        // refuse with DnsPinMismatch instead of following the rebound
        // answer.
        let Some((rebound_addr, rebound_hit)) = dial_fixture(ok_response("{}")) else {
            return;
        };
        let redirect = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://hop-two.invalid:{}/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            rebound_addr.port()
        );
        let Some((hop_one_addr, hop_one_hit)) = dial_fixture(redirect) else {
            return;
        };
        // Hop two's authorize-time answer; the refusal fires before its
        // dial, so no listener sits behind it.
        let authorize_addr: SocketAddr = "127.0.0.1:9".parse().unwrap();

        let resolver = RebindResolver::new(vec![
            ("hop-one.invalid", vec![vec![hop_one_addr]]),
            (
                "hop-two.invalid",
                vec![vec![authorize_addr], vec![rebound_addr]],
            ),
        ]);
        let fed = McpFederation::new(vec![]);
        let backing = enforce_openapi_backing(
            "hop-one.invalid",
            hop_one_addr.port(),
            vec!["hop-one.invalid".to_string(), "hop-two.invalid".to_string()],
        );
        let server = server_for_backing(&backing);

        let err = fed
            .call_openapi_tool_with_resolver(
                &server,
                &backing,
                "getPet",
                &json!({"id": "1"}),
                &[],
                &resolver,
            )
            .await
            .expect_err("a rebound redirect hop must be refused");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("DnsPinMismatch"),
            "expected DnsPinMismatch, got: {rendered}"
        );
        assert!(
            hop_one_hit.load(Ordering::SeqCst),
            "hop one must have served the redirect"
        );
        assert!(
            !rebound_hit.load(Ordering::SeqCst),
            "the rebound hop-two address must never be contacted"
        );
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
    fn test_tool_name_collision_advertises_prefixed_name() {
        // The collision fix: the later server's tool must be ADVERTISED under
        // the prefixed name (its `tool.name`), not merely keyed by it, so a
        // client both sees and can call the disambiguated name.
        let mut registry: HashMap<String, FederatedTool> = HashMap::new();

        let mut tool_a = make_tool("search", "server_a");
        let advertised_a = federated_name(
            "server_a",
            NamespaceMode::OnCollision,
            '.',
            tool_a
                .contract
                .as_ref()
                .expect("fixture has a strict contract")
                .name(),
            |n| registry.contains_key(n),
        );
        tool_a.advertise_as(&advertised_a);
        registry.insert(tool_a.name.clone(), tool_a);

        // Second server also has a "search" tool: it must be disambiguated.
        let mut tool_b = make_tool("search", "server_b");
        let advertised_b = federated_name(
            "server_b",
            NamespaceMode::OnCollision,
            '.',
            tool_b
                .contract
                .as_ref()
                .expect("fixture has a strict contract")
                .name(),
            |n| registry.contains_key(n),
        );
        tool_b.advertise_as(&advertised_b);
        registry.insert(tool_b.name.clone(), tool_b);

        assert!(registry.contains_key("search"));
        assert!(registry.contains_key("server_b.search"));
        assert_eq!(registry.len(), 2);
        // Advertised name equals the routing key on both entries.
        assert_eq!(registry.get("search").unwrap().name, "search");
        assert_eq!(
            registry.get("server_b.search").unwrap().name,
            "server_b.search"
        );
        assert_eq!(
            registry
                .get("search")
                .unwrap()
                .contract
                .as_ref()
                .expect("fixture has a strict contract")
                .name(),
            "search"
        );
        assert_eq!(
            registry
                .get("server_b.search")
                .unwrap()
                .contract
                .as_ref()
                .expect("fixture has a strict contract")
                .name(),
            "server_b.search"
        );
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

    struct ToolCountingHook {
        match_tool: &'static str,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl McpPolicyHook for ToolCountingHook {
        fn evaluate<'a>(
            &'a self,
            ctx: McpToolCallCtx<'a>,
        ) -> Pin<Box<dyn Future<Output = PolicyDecision> + Send + 'a>> {
            if ctx.tool_name == self.match_tool {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Box::pin(async move { PolicyDecision::Allow })
        }
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
        fed.seed_tools_for_test(map, None);
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

    // --- WOR-2139: SEP-414 trace-context propagation ---
    //
    // The key names are spelled as literals here rather than through
    // the `super::types` constants on purpose: these tests pin what
    // goes on the wire, so renaming a constant must not be able to
    // change the assertion along with the code it guards.

    fn fake_trace_pairs() -> Vec<(String, String)> {
        vec![
            (
                "traceparent".to_string(),
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
            ),
            ("tracestate".to_string(), "vendor=1".to_string()),
        ]
    }

    #[test]
    fn wor_2139_tools_call_params_carry_unprefixed_trace_context() {
        let params = merge_trace_context(
            json!({"name": "search", "arguments": {"q": "hi"}}),
            &fake_trace_pairs(),
        );
        assert_eq!(
            params["_meta"]["traceparent"],
            json!("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
        );
        assert_eq!(params["_meta"]["tracestate"], json!("vendor=1"));
        assert!(
            params["_meta"]
                .get("io.modelcontextprotocol.traceparent")
                .is_none(),
            "a namespaced traceparent is exactly what SEP-414 reserves the bare key to prevent"
        );
        // The method's own params are left as the caller built them.
        assert_eq!(params["name"], json!("search"));
        assert_eq!(params["arguments"]["q"], json!("hi"));
    }

    #[test]
    fn wor_2139_existing_meta_is_merged_not_replaced() {
        let params = merge_trace_context(
            json!({
                "name": "widget",
                "arguments": {},
                "_meta": {
                    "openai/widget": {"templateId": "card"},
                    "traceparent": "00-11111111111111111111111111111111-2222222222222222-00",
                }
            }),
            &fake_trace_pairs(),
        );
        // A caller's unrelated metadata survives the merge.
        assert_eq!(
            params["_meta"]["openai/widget"]["templateId"],
            json!("card")
        );
        // The trace keys are authoritative on this hop: the gateway
        // knows which trace the outbound call belongs to, and a stale
        // inbound traceparent would name the wrong parent.
        assert_eq!(
            params["_meta"]["traceparent"],
            json!("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
        );
    }

    #[test]
    fn wor_2139_no_trace_context_adds_no_meta_key() {
        let params = merge_trace_context(json!({"name": "search", "arguments": {}}), &[]);
        assert!(
            params.get("_meta").is_none(),
            "an untraced call must carry no _meta at all rather than an empty one: {params}"
        );
    }

    #[test]
    fn wor_2139_keys_sep_414_does_not_reserve_are_dropped() {
        // Only the SEP-414 set is exempt from MCP's prefixing rule, so
        // another propagator's output must not be written bare, and
        // must not conjure an otherwise empty _meta block either.
        let pairs = vec![
            ("x-b3-traceid".to_string(), "abc".to_string()),
            ("uber-trace-id".to_string(), "def".to_string()),
        ];
        let params = merge_trace_context(json!({"name": "s", "arguments": {}}), &pairs);
        assert!(
            params.get("_meta").is_none(),
            "unreserved propagator keys must not reach _meta: {params}"
        );
    }

    #[test]
    fn wor_2139_non_object_meta_is_left_untouched() {
        let params = merge_trace_context(
            json!({"name": "s", "arguments": {}, "_meta": "opaque"}),
            &fake_trace_pairs(),
        );
        assert_eq!(
            params["_meta"],
            json!("opaque"),
            "reshaping a caller's _meta to make room for ours is worse than propagating nothing"
        );
    }

    #[test]
    fn wor_2139_non_object_params_pass_through() {
        let params = merge_trace_context(json!("not-an-object"), &fake_trace_pairs());
        assert_eq!(params, json!("not-an-object"));
    }

    #[test]
    fn wor_2139_trace_id_extraction_rejects_unusable_values() {
        assert_eq!(
            trace_id_from_traceparent(&fake_trace_pairs()),
            Some("0af7651916cd43dd8448eb211c80319c")
        );
        assert_eq!(trace_id_from_traceparent(&[]), None);
        let all_zero = vec![(
            "traceparent".to_string(),
            "00-00000000000000000000000000000000-b7ad6b7169203331-00".to_string(),
        )];
        assert_eq!(
            trace_id_from_traceparent(&all_zero),
            None,
            "W3C defines the all-zero trace id as invalid; accepting it would collapse \
             every untraced call onto one correlation key"
        );
        let malformed = vec![("traceparent".to_string(), "garbage".to_string())];
        assert_eq!(trace_id_from_traceparent(&malformed), None);
        let short = vec![("traceparent".to_string(), "00-abc-def-01".to_string())];
        assert_eq!(trace_id_from_traceparent(&short), None);
    }

    /// End of the wire, not the helper: an untraced `tools/call` must
    /// reach the upstream with no `_meta` block at all. Nothing
    /// installs a `tracing-opentelemetry` layer in this crate's tests,
    /// so there is no active trace here, which is exactly the case
    /// being pinned. The traced counterpart is pinned one layer down,
    /// on `propagation_pairs` in `sbproxy-observe`.
    #[tokio::test]
    async fn wor_2139_untraced_tools_call_sends_no_meta_on_the_wire() {
        use std::io::{Read, Write};
        use std::sync::{Arc, Mutex};

        let seen = Arc::new(Mutex::new(String::new()));
        let seen_thread = Arc::clone(&seen);
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping trace-context wire test: loopback bind denied: {err}");
                return;
            }
            Err(err) => panic!("bind failed: {err}"),
        };
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let n = s.read(&mut buf).unwrap_or(0);
                *seen_thread.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = r#"{"jsonrpc":"2.0","result":{"content":[]},"id":1}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });

        let server = McpServerConfig {
            name: "trace-up".to_string(),
            url: format!("http://127.0.0.1:{port}/mcp"),
            transport: "streamable_http".to_string(),
            namespace: NamespaceMode::default(),
            openapi: None,
        };
        let fed = McpFederation::new(vec![server]);
        let mut tools = HashMap::new();
        tools.insert("echo".to_string(), make_tool("echo", "trace-up"));
        fed.seed_tools_for_test(tools, None);

        fed.call_tool("echo", json!({"q": 1}))
            .await
            .expect("tool call must succeed");

        let captured = seen.lock().unwrap().clone();
        assert!(
            !captured.contains("_meta"),
            "an untraced call must not ship an empty or placeholder _meta, got:\n{captured}"
        );
        assert!(
            !captured.to_ascii_lowercase().contains("traceparent"),
            "no traceparent should appear on any surface of an untraced call, got:\n{captured}"
        );
    }
}
