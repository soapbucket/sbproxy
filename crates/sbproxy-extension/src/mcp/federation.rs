//! MCP server federation.
//!
//! Aggregates tools from multiple upstream MCP servers into a unified
//! tool registry. Tool calls are routed to the correct upstream server.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use sbproxy_plugin::mcp::{default_no_op_hook, mcp_policy_hooks, McpPolicyHook, McpToolCallCtx};
use sbproxy_plugin::traits::PolicyDecision;
use serde::Deserialize;
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

/// Aggregates tools from multiple upstream MCP servers into one registry.
pub struct McpFederation {
    servers: Vec<McpServerConfig>,
    /// tool_name -> FederatedTool
    tools: ArcSwap<HashMap<String, FederatedTool>>,
    /// resource_uri -> FederatedResource. WOR-818: populated by
    /// `refresh_resources` so OpenAI Apps SDK clients can fetch
    /// UI templates declared on tools through the gateway.
    resources: ArcSwap<HashMap<String, FederatedResource>>,
    /// WOR-818: mcpApps capability values mirrored from any
    /// upstream that advertised one. Empty when no upstream
    /// supports SEP-1865. The first non-empty value is what the
    /// gateway re-advertises on its own `initialize`.
    mcp_apps_capability: ArcSwap<Option<serde_json::Value>>,
    client: reqwest::Client,
    /// Maximum upstream response bytes buffered per exchange
    /// (WOR-1639); passed to every transport send.
    max_response_bytes: usize,
    /// Monotonic catalogue generation. Bumps once per refresh that
    /// actually changed the tool or resource registry (content
    /// digest short-circuit), so consumers can key caches on it and
    /// emit `list_changed` notifications only on real change.
    generation: std::sync::atomic::AtomicU64,
    /// Content digest of the last stored tool registry. Zero until
    /// the first refresh.
    tools_digest: std::sync::atomic::AtomicU64,
    /// Content digest of the last stored resource registry (plus the
    /// mirrored mcpApps capability). Zero until the first refresh.
    resources_digest: std::sync::atomic::AtomicU64,
    /// Set once `ensure_ready` has spawned the periodic refresh task.
    refresh_task_started: std::sync::atomic::AtomicBool,
    /// Set once the cold-start prime (one tools + resources fetch)
    /// has run. Requests after that serve the ArcSwap snapshot and
    /// never fan out to upstreams inline.
    primed: std::sync::atomic::AtomicBool,
    /// Serialises the cold-start prime so N concurrent first
    /// requests trigger exactly one upstream fan-out.
    prime_lock: tokio::sync::Mutex<()>,
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
        Self {
            servers,
            tools: ArcSwap::from_pointee(HashMap::new()),
            resources: ArcSwap::from_pointee(HashMap::new()),
            mcp_apps_capability: ArcSwap::from_pointee(None),
            client,
            max_response_bytes: io.max_response_bytes,
            generation: std::sync::atomic::AtomicU64::new(0),
            tools_digest: std::sync::atomic::AtomicU64::new(0),
            resources_digest: std::sync::atomic::AtomicU64::new(0),
            refresh_task_started: std::sync::atomic::AtomicBool::new(false),
            primed: std::sync::atomic::AtomicBool::new(false),
            prime_lock: tokio::sync::Mutex::new(()),
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
            self.tools.store(Arc::new(registry));
            self.generation
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
        let mut apps_cap: Option<serde_json::Value> = None;

        for server in &self.servers {
            // Pull capabilities first so we always know whether the
            // server speaks SEP-1865, even when its resources/list
            // is empty.
            if apps_cap.is_none() {
                if let Ok(Some(cap)) = self.fetch_mcp_apps_capability(server).await {
                    apps_cap = Some(cap);
                }
            }
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

    /// Initialize the upstream and extract its `mcpApps` capability,
    /// if any. Returns Ok(None) for upstreams that complete
    /// initialize but do not advertise SEP-1865.
    async fn fetch_mcp_apps_capability(
        &self,
        server: &McpServerConfig,
    ) -> anyhow::Result<Option<serde_json::Value>> {
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
        let resp = self.dispatch_request(server, &req).await?;
        if let Some(err) = resp.error {
            anyhow::bail!(
                "initialize error from {}: {} (code {})",
                server.name,
                err.message,
                err.code
            );
        }
        let result = resp.result.unwrap_or_default();
        Ok(result
            .get("capabilities")
            .and_then(|c| c.get("mcpApps"))
            .cloned())
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
        let resp = self.dispatch_request(server, &req).await?;
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
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "resources/read".to_string(),
            params: Some(json!({ "uri": resource.upstream_uri })),
            id: Some(json!(1)),
        };
        let resp = self.dispatch_request(server, &req).await?;
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
        let result = match server.transport.as_str() {
            "sse" => send_via_sse(&self.client, &server.url, req, self.max_response_bytes).await,
            // Default to streamable HTTP for "streamable_http" or unknown.
            _ => send_request(&self.client, &server.url, req, self.max_response_bytes).await,
        };
        if let Err(e) = &result {
            sbproxy_observe::metrics::record_mcp_upstream_io_failure(classify_io_failure(e));
        }
        result
    }

    /// Current catalogue generation. Starts at zero and bumps once
    /// per refresh that actually changed the tool or resource
    /// registry, so it is a stable cache key for anything derived
    /// from the catalogue (serialized `tools/list` bodies, the
    /// codemode.ts module, `list_changed` notifications).
    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
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

    /// Make the federation servable: spawn the periodic refresh task
    /// on first use and run the cold-start prime (one tools fetch +
    /// one resources fetch) exactly once, single-flight. Requests
    /// arriving after the prime serve the ArcSwap snapshot and never
    /// fan out to upstreams inline; the background task is the only
    /// steady-state refresher.
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
        if let Err(e) = self.refresh_resources().await {
            error!(error = %e, "MCP federation initial resource refresh failed");
        }
        self.primed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Start a background task to refresh the tool and resource
    /// registries periodically.
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
                if let Err(e) = federation.refresh_resources().await {
                    error!(error = %e, "MCP federation resource refresh failed");
                }
            }
        });
    }
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
        map.insert(
            "b_tool".to_string(),
            make_tool("b_tool", "srv"),
        );
        map.insert(
            "a_tool".to_string(),
            make_tool("a_tool", "srv"),
        );
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
}
