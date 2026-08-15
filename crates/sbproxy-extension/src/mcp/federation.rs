//! MCP server federation.
//!
//! Aggregates tools from multiple upstream MCP servers into a unified
//! tool registry. Tool calls are routed to the correct upstream server.
//! The same aggregate-then-route shape covers the resource surface
//! (`resources/list` + `resources/read`) and the prompt surface
//! (`prompts/list` + `prompts/get`).

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use reqwest::Url;
use sbproxy_plugin::mcp::{default_no_op_hook, mcp_policy_hooks, McpPolicyHook, McpToolCallCtx};
use sbproxy_plugin::traits::PolicyDecision;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, error, info, warn};

use super::egress::{EgressPolicy, SystemHostResolver};
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
    /// WOR-818: opaque `_meta` block per the OpenAI Apps SDK /
    /// MCP Apps (SEP-1865) extension. Preserved verbatim from the
    /// upstream so an Apps-SDK client receives any vendor-specific
    /// UI template id, version, etag, or audit-cause field unchanged.
    /// Base-MCP clients ignore the unknown key per the spec.
    pub meta: Option<serde_json::Value>,
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
    /// Refuse a tool that has no lockfile entry at all (WOR-2444).
    ///
    /// Off by default because it changes behavior for anyone who adds a
    /// tool without regenerating the lockfile: every newly advertised
    /// tool starts refused until the baseline is updated.
    ///
    /// On, it is what actually closes the rename escape. Digest
    /// correlation catches a tool renamed but otherwise unchanged; a
    /// rename that *also* edits the contract matches no baseline by
    /// construction and is indistinguishable from a new tool, so the
    /// only thing that stops it being served ungated is refusing
    /// unlocked tools. A pinning gate that serves whatever it has not
    /// seen before is pinning the tools an upstream chooses not to
    /// rename.
    ///
    /// Only consulted under [`VersioningMode::Block`]; in warn mode the
    /// gate blocks nothing by definition.
    pub block_unlocked: bool,
    /// Description-semantics judges (WOR-1637). Empty skips the
    /// dimension entirely, exactly as the oracle promises; more than
    /// one runs a jury whose agreement sets the confidence.
    pub judges: Vec<Arc<dyn super::compat::Judge>>,
}

/// Aggregates tools from multiple upstream MCP servers into one registry.
pub struct McpFederation {
    servers: Vec<McpServerConfig>,
    /// tool_name -> FederatedTool
    tools: ArcSwap<HashMap<String, FederatedTool>>,
    /// resource_uri -> FederatedResource. WOR-818: populated by
    /// `refresh_resources` so OpenAI Apps SDK clients can fetch
    /// UI templates declared on tools through the gateway.
    resources: ArcSwap<HashMap<String, FederatedResource>>,
    /// prompt_name -> FederatedPrompt. Populated by `refresh_prompts`
    /// from the upstreams that declare the `prompts` capability;
    /// every other upstream contributes nothing.
    prompts: ArcSwap<HashMap<String, FederatedPrompt>>,
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
    /// Monotonic catalogue generation. Bumps once per refresh that
    /// actually changed the tool or resource registry (content
    /// digest short-circuit), so consumers can key caches on it and
    /// emit `list_changed` notifications only on real change.
    generation: std::sync::atomic::AtomicU64,
    /// Tool-registry-only generation, for `tools/list_changed`
    /// notifications (WOR-1642).
    tools_generation: std::sync::atomic::AtomicU64,
    /// Resource-registry-only generation, for
    /// `resources/list_changed` notifications (WOR-1642).
    resources_generation: std::sync::atomic::AtomicU64,
    /// Content digest of the last stored tool registry. Zero until
    /// the first refresh.
    tools_digest: std::sync::atomic::AtomicU64,
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
    /// Tool-versioning gate (WOR-1635); `None` disables the oracle.
    versioning: Option<ToolVersioningGate>,
    /// Advertised names currently blocked by the version gate, with
    /// the violation detail (only populated in Block mode).
    version_blocked: ArcSwap<HashMap<String, String>>,
    /// WOR-1640: per-generation pre-serialized tool catalogue, so
    /// `tools/list` responses are string splices instead of
    /// per-request `FederatedTool` clones and re-serialization.
    serialized_tools: ArcSwap<SerializedTools>,
    /// WOR-1640: per-generation codemode.ts module + ETag, so the
    /// well-known route re-emits and re-hashes only when the
    /// catalogue (or callback base) changes.
    codemode_cache: ArcSwap<CodemodeCache>,
}

/// Pre-serialized tool catalogue for one registry generation
/// (WOR-1640). `entries` carry the routing fields needed for
/// per-request filtering; `full_array` is the whole catalogue as a
/// serialized JSON array for the unfiltered fast path.
pub struct SerializedTools {
    /// Registry generation this snapshot was built from.
    pub generation: u64,
    /// One entry per advertised tool, sorted by name.
    pub entries: Vec<SerializedToolEntry>,
    /// The full catalogue as a serialized JSON array.
    pub full_array: String,
}

/// One pre-serialized tool entry (WOR-1640).
pub struct SerializedToolEntry {
    /// Advertised (possibly namespaced) tool name.
    pub name: String,
    /// Owning upstream server name, for per-server policy lookups.
    pub server_name: String,
    /// The serialized tool object (`{"name":...,"description":...,
    /// "inputSchema":...}` plus `_meta` when present).
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
            tools: ArcSwap::from_pointee(HashMap::new()),
            resources: ArcSwap::from_pointee(HashMap::new()),
            prompts: ArcSwap::from_pointee(HashMap::new()),
            server_capabilities: ArcSwap::from_pointee(HashMap::new()),
            mcp_apps_capability: ArcSwap::from_pointee(None),
            client,
            openapi_client,
            max_response_bytes: io.max_response_bytes,
            stdio_timeout: io.request_timeout,
            connect_timeout: io.connect_timeout,
            request_timeout: io.request_timeout,
            generation: std::sync::atomic::AtomicU64::new(0),
            tools_generation: std::sync::atomic::AtomicU64::new(0),
            resources_generation: std::sync::atomic::AtomicU64::new(0),
            tools_digest: std::sync::atomic::AtomicU64::new(0),
            resources_digest: std::sync::atomic::AtomicU64::new(0),
            prompts_digest: std::sync::atomic::AtomicU64::new(0),
            refresh_task_started: std::sync::atomic::AtomicBool::new(false),
            primed: std::sync::atomic::AtomicBool::new(false),
            prime_lock: tokio::sync::Mutex::new(()),
            versioning,
            version_blocked: ArcSwap::from_pointee(HashMap::new()),
            serialized_tools: ArcSwap::from_pointee(SerializedTools {
                // u64::MAX never equals a live generation, so the
                // first call rebuilds.
                generation: u64::MAX,
                entries: Vec::new(),
                full_array: "[]".to_string(),
            }),
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
                        tool.name = advertised.clone();
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
        // Swap only on real change so steady-state refreshes do not
        // churn the ArcSwap and the generation only moves when the
        // catalogue does.
        if self
            .tools_digest
            .swap(digest, std::sync::atomic::Ordering::AcqRel)
            != digest
        {
            // WOR-1635: grade the changed catalogue against the
            // lockfile baseline before publishing it.
            self.evaluate_tool_versioning(&registry).await;
            self.tools.store(Arc::new(registry));
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.tools_generation
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
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
                        streaming: false,
                        meta: None,
                    })
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
                let meta = t.get("_meta").cloned();
                Some(FederatedTool {
                    name,
                    description,
                    input_schema,
                    server_name: server.name.clone(),
                    streaming,
                    meta,
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

    /// List every federated prompt currently in the registry.
    pub fn list_prompts(&self) -> Vec<FederatedPrompt> {
        self.prompts.load().values().cloned().collect()
    }

    /// Look up which server owns an advertised prompt name.
    pub fn resolve_prompt(&self, name: &str) -> Option<FederatedPrompt> {
        self.prompts.load().get(name).cloned()
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

    /// Fetch a prompt through the federation, routing by the
    /// advertised (possibly namespaced) name.
    ///
    /// The upstream receives the name it advertised, so a vendor
    /// server never has to know about the gateway's
    /// collision-avoidance scheme. That is the contract
    /// [`Self::read_resource`] already holds for resource URIs.
    pub async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        let prompt = self
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

    /// Test-only: publish a tool registry directly and bump the
    /// generation, so a test can exercise the read path without
    /// upstream IO. The serialized snapshot rebuilds on the next
    /// `serialized_tools` call via the generation bump.
    #[doc(hidden)]
    pub fn seed_tools_for_test(&self, tools: HashMap<String, FederatedTool>) {
        self.tools.store(Arc::new(tools));
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.tools_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Current catalogue generation. Starts at zero and bumps once
    /// per refresh that actually changed the tool or resource
    /// registry, so it is a stable cache key for anything derived
    /// from the catalogue (serialized `tools/list` bodies, the
    /// codemode.ts module, `list_changed` notifications).
    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Tool-registry generation (WOR-1642): bumps only when the tool
    /// catalogue changes, driving `tools/list_changed` notifications.
    pub fn tools_generation(&self) -> u64 {
        self.tools_generation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Resource-registry generation (WOR-1642): bumps only when the
    /// resource catalogue (or mirrored mcpApps capability) changes.
    pub fn resources_generation(&self) -> u64 {
        self.resources_generation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Pre-serialized tool catalogue for the current generation
    /// (WOR-1640). Rebuilt at most once per catalogue change; on a
    /// warm snapshot this is a lock-free load with zero clones and
    /// zero serialization. Concurrent rebuilds after a generation
    /// bump are idempotent (last store wins).
    pub fn serialized_tools(&self) -> Arc<SerializedTools> {
        let generation = self.generation();
        let current = self.serialized_tools.load_full();
        if current.generation == generation {
            return current;
        }
        let tools = self.tools.load();
        let mut entries: Vec<SerializedToolEntry> = tools
            .values()
            .map(|t| {
                let mut obj = serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                });
                if let (Some(m), Some(map)) = (&t.meta, obj.as_object_mut()) {
                    map.insert("_meta".to_string(), m.clone());
                }
                SerializedToolEntry {
                    name: t.name.clone(),
                    server_name: t.server_name.clone(),
                    json: obj.to_string(),
                }
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut full_array = String::with_capacity(entries.iter().map(|e| e.json.len() + 1).sum());
        full_array.push('[');
        for (i, e) in entries.iter().enumerate() {
            if i > 0 {
                full_array.push(',');
            }
            full_array.push_str(&e.json);
        }
        full_array.push(']');
        let built = Arc::new(SerializedTools {
            generation,
            entries,
            full_array,
        });
        self.serialized_tools.store(Arc::clone(&built));
        built
    }

    /// Codemode.ts module + strong ETag for the current generation
    /// and callback base (WOR-1640). Re-emits and re-hashes only when
    /// either changes; a warm cache hit is a lock-free load.
    pub fn codemode_ts_cached(&self, callback_base: &str) -> (Arc<String>, String) {
        let generation = self.generation();
        let current = self.codemode_cache.load_full();
        if current.generation == generation && current.callback_base == callback_base {
            return (Arc::clone(&current.module), current.etag.clone());
        }
        let module = Arc::new(self.codemode_ts(callback_base));
        let digest = <sha2::Sha256 as sha2::Digest>::digest(module.as_bytes());
        let etag = format!("\"{}\"", hex::encode(digest));
        self.codemode_cache.store(Arc::new(CodemodeCache {
            generation,
            callback_base: callback_base.to_string(),
            module: Arc::clone(&module),
            etag: etag.clone(),
        }));
        (module, etag)
    }

    /// Advertised tool names currently blocked by the version gate,
    /// mapped to the violation detail (WOR-1635). Empty when the gate
    /// is off, in warn mode, or has nothing to block.
    pub fn version_blocked(&self) -> Arc<HashMap<String, String>> {
        self.version_blocked.load_full()
    }

    /// WOR-1635: diff a freshly fetched catalogue against the
    /// lockfile baseline, lint declared bumps, and (in Block mode)
    /// publish the violating tool set. Runs only when the catalogue
    /// content changed. Fail-open: an unreadable lockfile clears the
    /// blocked set and reports `lockfile_error`.
    /// Resolve a live contract to the baseline it was pinned under, ignoring
    /// the tool's name.
    ///
    /// The contract digest covers the name, so a renamed tool never matches
    /// a baseline digest directly. This re-digests the live contract with
    /// the baseline's name substituted in: if the two agree, everything
    /// except the name is identical and this is the same pinned tool wearing
    /// a different label.
    ///
    /// Only usable against baselines that captured their full contract.
    /// Digest-only entries (the pre-WOR-1635 shape) cannot be re-digested
    /// under another name, so a rename away from one of those is not
    /// detectable here and falls through to the unlocked path.
    fn by_digest_match<'a>(
        by_digest: &'a HashMap<&str, (&'a String, &'a super::compat::ToolLock)>,
        live_contract: &serde_json::Value,
    ) -> Option<&'a String> {
        for (old_name, lock) in by_digest.values() {
            let Some(baseline) = lock.contract.as_ref() else {
                continue;
            };
            let mut candidate = live_contract.clone();
            if let Some(obj) = candidate.as_object_mut() {
                obj.insert(
                    "name".to_string(),
                    serde_json::Value::String((*old_name).clone()),
                );
            }
            if super::compat::contract_digest(&candidate) == lock.contract_digest
                && &candidate == baseline
            {
                return Some(old_name);
            }
        }
        None
    }

    async fn evaluate_tool_versioning(&self, registry: &HashMap<String, FederatedTool>) {
        let Some(gate) = self.versioning.as_ref() else {
            return;
        };
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
                self.version_blocked.store(Arc::new(HashMap::new()));
                return;
            }
        };

        // WOR-2444: a rename used to escape this gate entirely. The old
        // name vanished into the removal sweep, which reports and never
        // blocks because "there is nothing left to block", and the new
        // name hit the unlocked `continue` below and was served with no
        // baseline. Correct in isolation, wrong in aggregate: there is
        // nothing left to block under the old name, and the thing that
        // replaced it is exactly what should have been.
        //
        // Indexing the baseline by digest closes the identical-rename
        // half: a tool renamed but otherwise unchanged resolves to the
        // baseline it was approved under. It cannot close the general
        // case, because a rename that also edits the contract matches
        // no baseline by construction. `block_unlocked` is what closes
        // that, and the two are complementary rather than alternatives.
        let mut by_digest: HashMap<&str, (&String, &super::compat::ToolLock)> = HashMap::new();
        for (locked_name, lock) in &lockfile.tools {
            by_digest.insert(lock.contract_digest.as_str(), (locked_name, lock));
        }

        let mut blocked: HashMap<String, String> = HashMap::new();
        let mut renamed_from: HashMap<String, String> = HashMap::new();
        for (name, tool) in registry {
            let Some(lock) = lockfile.tools.get(name) else {
                let live_contract = serde_json::json!({
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                });
                // The digest covers the name, so an identical rename does
                // not collide here. Compare against the baseline's own
                // contract with the name projected out.
                let renamed = Self::by_digest_match(&by_digest, &live_contract);
                if let Some(old_name) = renamed {
                    // A rename is at least Minor: the advertised name is
                    // the routing key, so callers pinned to the old one
                    // break even when every field behind it is identical.
                    sbproxy_observe::metrics::record_mcp_tool_compat_verdict(
                        "minor",
                        "renamed_tool",
                    );
                    warn!(
                        target: "sbproxy::audit",
                        event = "mcp.tool_versioning.renamed",
                        tool = %name,
                        previous_tool = %old_name,
                        "locked tool reappeared under a new name; the pinned baseline follows the \
                         contract, not the name"
                    );
                    renamed_from.insert(name.clone(), old_name.clone());
                    continue;
                }
                if gate.block_unlocked && gate.mode == VersioningMode::Block {
                    // The posture that actually closes the escape. A
                    // rename that also edits the contract matches no
                    // baseline, so it is indistinguishable from a new
                    // tool; refusing unlocked tools is the only thing
                    // that stops it being served ungated. Opt-in,
                    // because it changes behavior for anyone who adds a
                    // tool without regenerating the lockfile.
                    sbproxy_observe::metrics::record_mcp_tool_compat_verdict(
                        "major",
                        "unlocked_tool",
                    );
                    warn!(
                        target: "sbproxy::audit",
                        event = "mcp.tool_versioning.unlocked",
                        tool = %name,
                        "tool is not in the lockfile and block_unlocked is set; refusing"
                    );
                    blocked.insert(
                        name.clone(),
                        "tool is not in the version lockfile".to_string(),
                    );
                } else {
                    // New tool: nothing to diff against.
                    sbproxy_observe::metrics::record_mcp_tool_compat_verdict(
                        "none",
                        "unlocked_tool",
                    );
                }
                continue;
            };
            let live_contract = serde_json::json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            });
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
        let renamed_to: HashMap<&str, &String> = renamed_from
            .iter()
            .map(|(new_name, old_name)| (old_name.as_str(), new_name))
            .collect();
        for locked_name in lockfile.tools.keys() {
            if renamed_to.contains_key(locked_name.as_str()) {
                // Already reported as a rename. Counting it as a removal
                // too would double-report one event and make the removal
                // rate read high whenever an upstream renames.
                continue;
            }
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
        self.version_blocked.store(Arc::new(blocked));
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
        FederatedTool {
            name: name.to_string(),
            description: format!("Tool {}", name),
            input_schema: json!({"type": "object", "properties": {}}),
            server_name: server.to_string(),
            streaming: false,
            meta: None,
        }
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
        assert_eq!(first.generation, fed.generation());
        assert_eq!(first.full_array, "[]");
        // Warm path returns the same snapshot Arc.
        let second = fed.serialized_tools();
        assert!(std::sync::Arc::ptr_eq(&first, &second));

        // Manually store a catalogue and bump the generation the way
        // a refresh would; the next call must rebuild.
        let mut map = std::collections::HashMap::new();
        map.insert("b_tool".to_string(), make_tool("b_tool", "srv"));
        map.insert("a_tool".to_string(), make_tool("a_tool", "srv"));
        fed.tools.store(std::sync::Arc::new(map));
        fed.generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
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

    thread_local! {
        /// Lets a test opt the gate into refusing unlocked tools
        /// without changing the signature of helpers every other test
        /// in this module already calls (WOR-2444).
        static BLOCK_UNLOCKED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Run `body` with the unlocked-tool refusal enabled.
    fn with_block_unlocked<T>(body: impl FnOnce() -> T) -> T {
        BLOCK_UNLOCKED.with(|b| b.set(true));
        let out = body();
        BLOCK_UNLOCKED.with(|b| b.set(false));
        out
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
                block_unlocked: BLOCK_UNLOCKED.with(|b| b.get()),
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

    /// The same registry `gate_registry` builds, under another name.
    fn renamed_registry(new_name: &str, description: &str) -> HashMap<String, FederatedTool> {
        let mut tool = make_tool(new_name, "srv");
        tool.description = description.to_string();
        let mut map = HashMap::new();
        map.insert(new_name.to_string(), tool);
        map
    }

    #[tokio::test]
    async fn a_renamed_tool_resolves_to_the_baseline_it_was_pinned_under() {
        // WOR-2444 acceptance 1. Before this, the old name fell into the
        // removal sweep (report, never block) and the new name hit the
        // unlocked `continue`, so a rename produced no verdict tied to
        // the pinned tool at all.
        let path = write_lockfile("rename", &gate_lockfile("original description"));
        let fed = gated_federation(path.clone(), VersioningMode::Block, None);
        fed.evaluate_tool_versioning(&renamed_registry("search_v2", "original description"))
            .await;
        // A rename of an otherwise-identical contract is graded, not
        // blocked: the contract an operator approved is unchanged.
        assert!(
            fed.version_blocked().is_empty(),
            "an identical rename is a rename, not a contract violation"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn a_rename_cannot_smuggle_a_contract_that_would_have_been_blocked() {
        // WOR-2444 acceptance 2, and the reason digest correlation is
        // not sufficient on its own. Renaming *and* editing the contract
        // matches no baseline by construction, so it is indistinguishable
        // from a new tool. Refusing unlocked tools is what closes it.
        let path = write_lockfile("smuggle", &gate_lockfile("original description"));

        // Under the same name this contract blocks, which is the thing
        // the rename is trying to get around.
        let fed = gated_federation(path.clone(), VersioningMode::Block, None);
        fed.evaluate_tool_versioning(&gate_registry("completely different meaning"))
            .await;
        assert!(
            fed.version_blocked().contains_key("search"),
            "precondition: this contract is blocked under its pinned name"
        );

        // Renamed, it is served ungated unless the posture is on.
        let fed = gated_federation(path.clone(), VersioningMode::Block, None);
        fed.evaluate_tool_versioning(&renamed_registry(
            "search_v2",
            "completely different meaning",
        ))
        .await;
        assert!(
            fed.version_blocked().is_empty(),
            "documents the residual gap: without block_unlocked a renamed, edited tool is served"
        );

        let fed =
            with_block_unlocked(|| gated_federation(path.clone(), VersioningMode::Block, None));
        fed.evaluate_tool_versioning(&renamed_registry(
            "search_v2",
            "completely different meaning",
        ))
        .await;
        assert!(
            fed.version_blocked().contains_key("search_v2"),
            "with block_unlocked the rename cannot serve what its pinned name could not"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn an_unlocked_tool_is_served_unless_the_posture_says_otherwise() {
        // The default has to stay permissive: refusing every newly
        // advertised tool changes behavior for anyone who adds one
        // without regenerating the lockfile.
        let path = write_lockfile("unlocked", &gate_lockfile("original description"));
        let fed = gated_federation(path.clone(), VersioningMode::Block, None);
        fed.evaluate_tool_versioning(&renamed_registry("brand_new", "a tool nobody pinned"))
            .await;
        assert!(fed.version_blocked().is_empty());
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
                meta: None,
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
                meta: None,
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
            meta: None,
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
            FederatedTool {
                name: "echo".to_string(),
                description: "echo".to_string(),
                input_schema: json!({"type": "object"}),
                server_name: "auth-up".to_string(),
                streaming: false,
                meta: None,
            },
        );
        fed.seed_tools_for_test(tools);

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
        tool_a.name = federated_name(
            "server_a",
            NamespaceMode::OnCollision,
            '.',
            &tool_a.name,
            |n| registry.contains_key(n),
        );
        registry.insert(tool_a.name.clone(), tool_a);

        // Second server also has a "search" tool: it must be disambiguated.
        let mut tool_b = make_tool("search", "server_b");
        tool_b.name = federated_name(
            "server_b",
            NamespaceMode::OnCollision,
            '.',
            &tool_b.name,
            |n| registry.contains_key(n),
        );
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
        fed.seed_tools_for_test(tools);

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
