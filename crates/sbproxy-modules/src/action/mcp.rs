//! MCP (Model Context Protocol) gateway action.
//!
//! Wires the MCP federation library in `sbproxy-extension` into a
//! configurable top-level action. A user declares a list of upstream
//! MCP servers in `sb.yml`; the proxy aggregates their tool catalogues
//! into one virtual MCP endpoint and routes `tools/call` JSON-RPC
//! requests to the right upstream.
//!
//! Schema (matches the public marketing surface):
//!
//! ```yaml
//! origins:
//!   "mcp.example.com":
//!     action:
//!       type: mcp
//!       mode: gateway
//!       server_info:
//!         name: my-mcp
//!         version: "1.0.0"
//!       rbac_policies:
//!         read_only:
//!           default_allow: false
//!           tool_access:
//!             - principals:
//!                 - virtual_key: vk_frontend_*
//!                   team: frontend
//!               allowed: [gh.search_repos, db.query]
//!         admin:
//!           default_allow: false
//!           tool_access:
//!             - principals:
//!                 - role: admin
//!               allowed: ["*"]
//!       federated_servers:
//!         - origin: github.example.com
//!           prefix: gh
//!           rbac: read_only
//!           timeout: 10s
//!         - origin: postgres.example.com
//!           prefix: db
//!           rbac: admin
//!           timeout: 5s
//!       guardrails:
//!         - type: tool_allowlist
//!           allow: [gh.search_repos, db.query]
//! ```
//!
//! The `rbac:` field on each `federated_servers[]` references a key
//! in the top-level `rbac_policies` map. The matching
//! `ToolAccessPolicy` is consulted for every `tools/call` against
//! that upstream, using the inbound `Principal` (tenant, virtual
//! key, team, role, project, sub) to pick the matching ACL row.
//! WOR-1065 + WOR-1066: the policy is default-deny; an operator who
//! wants the legacy open-by-default behaviour sets
//! `default_allow: true` on each policy. See
//! `docs/migration-mcp-rbac.md` for upgrade examples.
//! The `timeout:` field caps each upstream `tools/call` at the
//! request layer (not just the connection layer) via
//! `tokio::time::timeout`.
//!
//! The action is a thin adapter on top of
//! [`sbproxy_extension::mcp::McpFederation`]. Tool aggregation, name
//! collision handling, and the underlying transports all live in the
//! library; this module only translates YAML into library API calls
//! and applies a small allowlist guardrail at request time.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use sbproxy_extension::mcp::sessions::SessionStore;
use sbproxy_extension::mcp::{
    EgressPolicy, FederationIoSettings, McpFederation, McpServerConfig, NamespaceMode,
    ToolAccessPolicy, ToolQuotaStore, ToolVersioningGate, VersioningMode,
};
use serde::Deserialize;

// --- Wire format ---

/// Top-level MCP action config as parsed from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct McpActionConfig {
    /// Operating mode. Only `gateway` is implemented today; any
    /// future modes (e.g. `embedded` for an in-proxy tool registry)
    /// fall through this field.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Identity returned by the gateway in MCP `initialize` responses.
    #[serde(default)]
    pub server_info: Option<McpServerInfoConfig>,
    /// Named tool-access policies (RBAC labels). Each entry maps a
    /// label to a [`ToolAccessPolicy`]; per-server `rbac` fields
    /// reference a label in this table. WOR-186.
    #[serde(default)]
    pub rbac_policies: HashMap<String, ToolAccessPolicy>,
    /// List of upstream MCP servers to federate.
    #[serde(default)]
    pub federated_servers: Vec<McpFederatedServerConfig>,
    /// Default egress policy for OpenAPI-backed REST tool calls.
    /// Per-server `egress` overrides this block. Omitted preserves
    /// the legacy allow-all behavior.
    #[serde(default)]
    pub egress: Option<EgressPolicy>,
    /// Inline guardrails applied at the gateway boundary before a
    /// `tools/call` is forwarded to its upstream.
    #[serde(default)]
    pub guardrails: Vec<McpGuardrailEntry>,
    /// Progressive tool discovery (WOR-806). When `true`, `tools/list`
    /// advertises only two meta-tools, `search` and `execute`, instead
    /// of the full federated catalogue: the agent calls `search` to
    /// find relevant tools and `execute` to invoke one by name. This
    /// keeps a large catalogue out of the model's context window (the
    /// Anthropic code-execution / Cloudflare Code Mode pattern).
    /// Defaults to the full-catalogue listing.
    #[serde(default)]
    pub progressive_discovery: bool,
    /// OAuth protection metadata for RFC 9728 discovery (WOR-806). When
    /// set, the gateway serves `/.well-known/oauth-protected-resource`
    /// and advertises the pointer in its discovery manifest so an agent
    /// can find the authorization server. Absent means the gateway
    /// advertises no OAuth auth-discovery surface.
    #[serde(default)]
    pub oauth: Option<McpOAuthConfig>,
    /// How often the background task re-fetches upstream tool and
    /// resource catalogues. Accepts Go duration syntax (`60s`, `5m`).
    /// Defaults to 60 seconds. Inbound requests always serve the
    /// cached snapshot; this interval is the only steady-state
    /// upstream fan-out.
    #[serde(default, with = "duration_str")]
    pub refresh_interval: Option<Duration>,
    /// TCP connect deadline for every upstream exchange (WOR-1639).
    /// Go duration syntax; defaults to 5s.
    #[serde(default, with = "duration_str")]
    pub upstream_connect_timeout: Option<Duration>,
    /// Whole-request deadline for every upstream exchange
    /// (WOR-1639): catalogue refreshes, tool calls, resource reads.
    /// Per-server `timeout:` values can only shorten it for
    /// `tools/call`. Go duration syntax; defaults to 30s.
    #[serde(default, with = "duration_str")]
    pub upstream_timeout: Option<Duration>,
    /// Maximum upstream response bytes buffered per exchange
    /// (WOR-1639). An upstream body over this cap fails the exchange
    /// with a typed error instead of ballooning memory. Defaults to
    /// 8 MiB.
    #[serde(default)]
    pub max_upstream_response_bytes: Option<usize>,
    /// Tool-versioning gate (WOR-1635): diff the live federated
    /// catalogue against a committed lockfile baseline and lint
    /// declared version bumps. `mode: warn` logs and counts;
    /// `mode: block` filters violating tools from `tools/list` and
    /// fails their `tools/call` with a typed error. The lockfile is
    /// read at refresh time, never at config compile, and an
    /// unreadable lockfile fails open with a loud error.
    #[serde(default)]
    pub tool_versioning: Option<McpToolVersioningConfig>,
    /// Optional MCP session management (WOR-1642). When enabled the
    /// gateway assigns an `Mcp-Session-Id` during `initialize`,
    /// requires it on every later request, serves 404 for unknown or
    /// expired ids (the client's cue to re-initialize), and ends a
    /// session on `DELETE`. Off by default: the gateway stays
    /// stateless and ignores session headers entirely.
    #[serde(default)]
    pub sessions: Option<McpSessionConfig>,
    /// Optional compaction for verbose MCP tool-result text blocks.
    /// Disabled by default.
    #[serde(default)]
    pub token_compaction: Option<McpTokenCompactionConfig>,
    /// Optional quarantine gate for suspicious MCP tool output.
    /// Disabled by default.
    #[serde(default)]
    pub dual_llm_quarantine: Option<McpDualLlmQuarantineConfig>,
    /// Per-tool-call cost attribution (WOR-1644). MCP has no usage
    /// meter, so cost comes from this optional price map: a USD
    /// figure per advertised (namespaced) tool name. Counts and
    /// durations are always recorded; cost rows appear only for
    /// priced tools.
    #[serde(default)]
    pub tool_pricing: HashMap<String, f64>,
    /// Usage sinks for MCP tool calls (WOR-1644). Reuses the same
    /// sink surface as the AI path (JSONL, webhook, ledger, Langfuse,
    /// Datadog), so an operator meters tool spend in the same place
    /// as model spend. Empty (the default) emits metrics and the
    /// ledger only.
    #[serde(default)]
    pub usage_sinks: Vec<sbproxy_ai::usage_sink::UsageSinkConfig>,
}

/// Tool-versioning gate config (WOR-1635).
#[derive(Debug, Clone, Deserialize)]
pub struct McpToolVersioningConfig {
    /// Path to the committed lockfile (YAML), as generated by
    /// `sbproxy-mcp-drift`. Resolved relative to the proxy's working
    /// directory at refresh time.
    pub lockfile: String,
    /// `warn` (default) or `block`.
    #[serde(default)]
    pub mode: McpVersioningModeConfig,
    /// Operator-declared current version per advertised tool name.
    /// A changed tool absent from this map is linted as "no bump
    /// declared" against its lockfile version.
    #[serde(default)]
    pub declared_versions: HashMap<String, String>,
    /// Description-semantics judges (WOR-1637). Empty (the default)
    /// skips the model-judged dimension entirely; the verdict is
    /// structural and digest-based only. More than one judge runs a
    /// jury: agreement sets the confidence, and a split jury reports
    /// needs-confirmation instead of blocking.
    #[serde(default)]
    pub judges: Vec<McpJudgeConfig>,
}

/// One description-semantics judge (WOR-1637): a BYOK
/// OpenAI-compatible chat-completions endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct McpJudgeConfig {
    /// Chat-completions endpoint URL to POST to.
    pub endpoint: String,
    /// Environment variable holding the bearer API key. The key
    /// itself never lives in config.
    pub api_key_env: String,
    /// Optional `model` body field for endpoints that need one.
    #[serde(default)]
    pub model: Option<String>,
    /// Per-call timeout. Go duration syntax; defaults to 5s.
    #[serde(default, with = "duration_str")]
    pub timeout: Option<Duration>,
    /// Token-equivalent budget before judge calls hard-fail (and the
    /// gate falls back to structural grading). Defaults to 100000.
    #[serde(default)]
    pub budget_tokens: Option<u64>,
}

/// Wire form of the versioning mode (WOR-1635).
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpVersioningModeConfig {
    /// Log and count violations; traffic unaffected.
    #[default]
    Warn,
    /// Filter violating tools and fail their calls.
    Block,
}

/// MCP session management config (WOR-1642).
#[derive(Debug, Clone, Deserialize)]
pub struct McpSessionConfig {
    /// Master switch. `false` keeps the stateless behaviour even if
    /// the block is present.
    #[serde(default)]
    pub enabled: bool,
    /// Sliding idle TTL for a session. Go duration syntax; defaults
    /// to 30 minutes.
    #[serde(default, with = "duration_str")]
    pub ttl: Option<Duration>,
}

/// Opt-in MCP tool-result compaction config (WOR-1795).
#[derive(Debug, Clone, Deserialize)]
pub struct McpTokenCompactionConfig {
    /// Master switch. `false` keeps results unchanged even if the
    /// block is present.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum UTF-8 bytes retained per text content block. Defaults
    /// to 8192.
    #[serde(default)]
    pub max_text_bytes: Option<usize>,
}

/// Opt-in MCP tool-output quarantine config (WOR-1789).
#[derive(Debug, Clone, Deserialize)]
pub struct McpDualLlmQuarantineConfig {
    /// Master switch.
    #[serde(default)]
    pub enabled: bool,
    /// Case-insensitive substrings that mark a tool result as
    /// quarantined pending review by a secondary judge.
    #[serde(default)]
    pub suspicious_patterns: Vec<String>,
}

/// OAuth 2.0 Protected Resource Metadata (RFC 9728) for the MCP gateway.
#[derive(Debug, Clone, Deserialize)]
pub struct McpOAuthConfig {
    /// Issuer URLs a client can obtain a token from.
    pub authorization_servers: Vec<String>,
    /// Optional list of scopes the resource recognises.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// Server identity advertised by the gateway during MCP initialization.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct McpServerInfoConfig {
    /// Human-readable server name (e.g. `my-mcp`).
    #[serde(default)]
    pub name: String,
    /// Semver string for the gateway (e.g. `1.0.0`).
    #[serde(default)]
    pub version: String,
}

/// One upstream MCP server to federate.
#[derive(Debug, Clone, Deserialize)]
pub struct McpFederatedServerConfig {
    /// Upstream MCP endpoint. Either a full URL
    /// (`https://example.com/mcp`) or a bare hostname; bare hostnames
    /// are normalised to `https://<host>/mcp`.
    pub origin: String,
    /// Optional namespace label for this upstream. It sets the server name
    /// used to disambiguate name collisions, and, when `namespace: always`
    /// is set, the prefix every tool and resource is exposed under
    /// (`<prefix>.<tool>` / `<prefix>/<uri>`). When unset, a name is derived
    /// from the origin.
    #[serde(default)]
    pub prefix: Option<String>,
    /// How this upstream's tool and resource names are namespaced in the
    /// unified registry. `on_collision` (default) keeps bare names and only
    /// prefixes on a clash; `always` prefixes every name with the server
    /// label so the whole upstream is namespaced.
    #[serde(default)]
    pub namespace: NamespaceMode,
    /// Optional RBAC label for the upstream. References a key in the
    /// top-level `rbac_policies` map; the matching
    /// [`ToolAccessPolicy`] is consulted at request time using the
    /// caller's auth subject as the virtual key. WOR-186.
    #[serde(default)]
    pub rbac: Option<String>,
    /// Optional per-server request timeout. Accepts Go duration syntax
    /// (`10s`, `500ms`). Wraps the `tools/call` dispatch in
    /// `tokio::time::timeout` so a hung upstream cannot stall the
    /// request layer. WOR-186.
    #[serde(default, with = "duration_str")]
    pub timeout: Option<Duration>,
    /// Attach a bounded caller identity envelope to outbound tool
    /// arguments so the upstream can authorize as the authenticated
    /// user. Defaults off to preserve existing tool schemas.
    #[serde(default)]
    pub run_as_user_auth: bool,
    /// Transport name. Defaults to `streamable_http`; alternative is `sse`.
    #[serde(default)]
    pub transport: Option<String>,
    /// Local executable for `transport: stdio`.
    #[serde(default)]
    pub command: Option<String>,
    /// Arguments for `transport: stdio`.
    #[serde(default)]
    pub args: Vec<String>,
    /// Upstream kind (WOR-1648). `mcp` (default) speaks MCP to the
    /// origin; `openapi` derives tools from an OpenAPI spec and
    /// dispatches `tools/call` as REST requests against the origin.
    #[serde(rename = "type", default)]
    pub server_type: Option<String>,
    /// Inline OpenAPI 3.x spec (JSON/YAML-decoded value) for an
    /// `openapi` server. Mutually exclusive with `spec_path`.
    #[serde(default)]
    pub spec: Option<serde_json::Value>,
    /// Filesystem path to an OpenAPI spec (JSON or YAML) for an
    /// `openapi` server, read at config-load time so a bad spec fails
    /// startup, not the hot path.
    #[serde(default)]
    pub spec_path: Option<String>,
    /// Egress policy for this upstream's OpenAPI REST calls. Applies
    /// only when `type: openapi`; omitted inherits action-level
    /// `egress`, then allow-all.
    #[serde(default)]
    pub egress: Option<EgressPolicy>,
}

/// One entry in the gateway-level guardrails list.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpGuardrailEntry {
    /// Allow only the named (already-prefixed) tools through `tools/call`.
    /// An empty `allow` list denies every call.
    ToolAllowlist {
        /// Fully-qualified tool names (e.g. `gh.search_repos`).
        #[serde(default)]
        allow: Vec<String>,
    },
    /// Deny a session once it combines tool access, private-data
    /// access, and external communication. Tool patterns use the same
    /// trailing-`*` glob convention as injected MCP filters.
    LethalTrifecta {
        /// Tool patterns classified as private-data access.
        #[serde(default)]
        private_data_tools: Vec<String>,
        /// Tool patterns classified as external communication.
        #[serde(default)]
        external_comm_tools: Vec<String>,
    },
}

fn default_mode() -> String {
    "gateway".to_string()
}

// --- Compiled action ---

/// Compiled MCP gateway action.
///
/// Construction does no network IO; the upstream tool catalogue is
/// fetched lazily on the first request (and refreshed on a background
/// task once the action begins serving traffic).
pub struct McpAction {
    /// Operating mode (`gateway` today).
    pub mode: String,
    /// Server identity reported in MCP `initialize` responses.
    pub server_name: String,
    /// Server version reported in MCP `initialize` responses.
    pub server_version: String,
    /// Per-server prefix table, keyed by upstream `name` for O(1)
    /// policy and timeout resolution on the request path (WOR-1640).
    pub prefixes: HashMap<String, McpServerPrefix>,
    /// Named RBAC policies declared at the top level. Looked up by
    /// the per-server `rbac` label at `tools/call` time. WOR-186.
    pub rbac_policies: HashMap<String, ToolAccessPolicy>,
    /// Underlying federation handle from `sbproxy-extension`.
    pub federation: Arc<McpFederation>,
    /// Collapsed allowlist (union of every `tool_allowlist` guardrail).
    /// `None` when no allowlist guardrail was configured (open
    /// access). A set so per-tool checks are O(1) (WOR-1640).
    pub tool_allowlist: Option<HashSet<String>>,
    /// Optional lethal-trifecta guardrail. When present, `tools/call`
    /// records risk into the MCP session and denies calls that would
    /// combine tool access, private data, and external communication.
    pub lethal_trifecta: Option<McpLethalTrifectaGuardrail>,
    /// When `true`, `tools/list` advertises the `search` / `execute`
    /// meta-tools instead of the full catalogue (WOR-806).
    pub progressive_discovery: bool,
    /// OAuth Protected Resource Metadata (RFC 9728) for auth discovery,
    /// or `None` when the gateway advertises no OAuth surface (WOR-806).
    pub oauth: Option<McpOAuthConfig>,
    /// Process-wide sliding-window quota store for per-tool quotas
    /// declared on `rbac_policies[].tool_quotas[]` (WOR-1065). One
    /// store per action so the counters live for the lifetime of
    /// the compiled origin chain; counters are wiped on hot reload
    /// since reload rebuilds the action.
    pub quota_store: Arc<ToolQuotaStore>,
    /// Background catalogue refresh interval (default 60s). Passed to
    /// `McpFederation::ensure_ready` on each request; the task spawns
    /// lazily on the first request so compile time does no IO and
    /// needs no async runtime.
    pub refresh_interval: Duration,
    /// True when any federated server carries an `rbac:` label, i.e.
    /// `tools/list` responses depend on the inbound principal and the
    /// unfiltered fast path must not be used (WOR-1640).
    pub has_principal_scoped_tools: bool,
    /// Session store when `sessions.enabled` (WOR-1642); `None`
    /// keeps the gateway stateless. Like the quota store, sessions
    /// live for the lifetime of the compiled origin chain and a hot
    /// reload invalidates them (the spec's 404-then-reinitialize
    /// flow covers exactly this).
    pub sessions: Option<Arc<SessionStore>>,
    /// Opt-in result compaction config.
    pub token_compaction: Option<McpTokenCompactionConfig>,
    /// Opt-in tool-output quarantine config.
    pub dual_llm_quarantine: Option<McpDualLlmQuarantineConfig>,
    /// Per-tool USD price map for cost attribution (WOR-1644).
    pub tool_pricing: HashMap<String, f64>,
    /// Built usage sinks for MCP tool-call attribution (WOR-1644),
    /// shared across requests. Empty when none are configured.
    pub usage_sinks: Vec<Arc<dyn sbproxy_ai::usage_sink::UsageSink>>,
}

/// Per-upstream metadata captured at compile time. Kept outside
/// `McpServerConfig` so the federation library stays unchanged.
#[derive(Debug, Clone)]
pub struct McpServerPrefix {
    /// Stable server name (matches `McpServerConfig::name`).
    pub name: String,
    /// Optional namespace prefix applied to the upstream's tools.
    pub prefix: Option<String>,
    /// Optional RBAC label. Resolved against `rbac_policies` at
    /// request time. WOR-186.
    pub rbac: Option<String>,
    /// Optional per-server request timeout. WOR-186.
    pub timeout: Option<Duration>,
    /// True when outbound tool calls should carry caller identity for
    /// run-as-user upstream authorization.
    pub run_as_user_auth: bool,
}

/// Configured tool classifications for the lethal-trifecta guardrail.
#[derive(Debug, Clone, Default)]
pub struct McpLethalTrifectaGuardrail {
    /// Private-data tool globs.
    pub private_data_tools: Vec<String>,
    /// External-communication tool globs.
    pub external_comm_tools: Vec<String>,
}

impl McpLethalTrifectaGuardrail {
    /// Classify one tool call into session-risk bits.
    pub fn classify(&self, tool_name: &str) -> sbproxy_extension::mcp::sessions::SessionRisk {
        sbproxy_extension::mcp::sessions::SessionRisk {
            tool_access: true,
            private_data: self
                .private_data_tools
                .iter()
                .any(|p| sbproxy_util::prefix_glob_match(p, tool_name)),
            external_comm: self
                .external_comm_tools
                .iter()
                .any(|p| sbproxy_util::prefix_glob_match(p, tool_name)),
        }
    }
}

impl McpAction {
    /// Compile an `McpAction` from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let cfg: McpActionConfig = serde_json::from_value(value)?;
        Self::from_parsed(cfg)
    }

    /// Compile an `McpAction` from already-deserialised config. Split
    /// out from `from_config` so unit tests skip the JSON round-trip.
    pub fn from_parsed(cfg: McpActionConfig) -> anyhow::Result<Self> {
        if cfg.mode != "gateway" {
            anyhow::bail!(
                "mcp action: unsupported mode '{}' (only 'gateway' is implemented)",
                cfg.mode
            );
        }
        if cfg.federated_servers.is_empty() {
            anyhow::bail!("mcp action: federated_servers must not be empty");
        }

        // WOR-186: every per-server `rbac` label must reference a key
        // declared in the top-level `rbac_policies` map. A missing
        // entry would otherwise silently fall through to "no policy
        // = allow everything", which is the exact failure mode the
        // ticket is closing.
        for upstream in &cfg.federated_servers {
            if let Some(label) = upstream.rbac.as_deref() {
                if !cfg.rbac_policies.contains_key(label) {
                    anyhow::bail!(
                        "mcp action: federated_servers[].rbac '{}' is not declared in rbac_policies (origin '{}')",
                        label,
                        upstream.origin
                    );
                }
            }
        }

        let info = cfg.server_info.unwrap_or_default();
        let server_name = if info.name.is_empty() {
            "sbproxy-mcp".to_string()
        } else {
            info.name
        };
        let server_version = if info.version.is_empty() {
            "0.1.0".to_string()
        } else {
            info.version
        };

        // --- Build the federation server list + prefix table ---
        let mut server_configs: Vec<McpServerConfig> =
            Vec::with_capacity(cfg.federated_servers.len());
        let mut prefixes: HashMap<String, McpServerPrefix> =
            HashMap::with_capacity(cfg.federated_servers.len());
        let action_egress = cfg
            .egress
            .clone()
            .unwrap_or_else(|| EgressPolicy::allow_all("action"));

        for upstream in cfg.federated_servers {
            // The upstream `name` doubles as the implicit collision-prefix
            // inside the federation library. Use the user-supplied prefix
            // when present so library-level collision handling matches the
            // operator's intent.
            let name = upstream
                .prefix
                .clone()
                .unwrap_or_else(|| derive_server_name(&upstream.origin));
            let transport = upstream
                .transport
                .clone()
                .unwrap_or_else(|| "streamable_http".to_string());

            // WOR-1648: an `openapi` server derives its tools from a
            // spec and dispatches REST; the origin is the REST base
            // URL, not an MCP endpoint.
            let is_openapi = upstream.server_type.as_deref() == Some("openapi");
            let is_stdio = transport == "stdio";
            let (url, openapi) = if is_stdio {
                let command = upstream.command.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "mcp action: stdio server '{}' needs command",
                        upstream.origin
                    )
                })?;
                (
                    sbproxy_extension::mcp::encode_stdio_url(command, &upstream.args),
                    None,
                )
            } else if is_openapi {
                let base_url = normalize_rest_origin(&upstream.origin);
                let spec = load_openapi_spec(&upstream)?;
                let tools = sbproxy_extension::mcp::openapi_to_mcp_tools(&spec);
                if tools.is_empty() {
                    anyhow::bail!(
                        "mcp action: openapi server '{}' produced no tools from its spec",
                        upstream.origin
                    );
                }
                let routes = sbproxy_extension::mcp::openapi_to_routes(&spec)
                    .into_iter()
                    .map(|r| (r.name, (r.method, r.path)))
                    .collect();
                (
                    base_url.clone(),
                    Some(sbproxy_extension::mcp::OpenApiBacking {
                        base_url,
                        tools,
                        routes,
                        egress_policy: upstream
                            .egress
                            .clone()
                            .unwrap_or_else(|| action_egress.clone())
                            .with_scope(format!("server:{name}")),
                    }),
                )
            } else {
                (normalize_origin(&upstream.origin)?, None)
            };

            server_configs.push(McpServerConfig {
                name: name.clone(),
                url,
                transport,
                namespace: upstream.namespace,
                openapi,
            });
            prefixes.insert(
                name.clone(),
                McpServerPrefix {
                    name,
                    prefix: upstream.prefix,
                    rbac: upstream.rbac,
                    timeout: upstream.timeout,
                    run_as_user_auth: upstream.run_as_user_auth,
                },
            );
        }

        // WOR-1635: parse the versioning gate. Declared versions
        // must be valid semver; a typo here is a config error, not a
        // silent no-op at refresh time.
        let versioning = match cfg.tool_versioning.as_ref() {
            None => None,
            Some(tv) => {
                if tv.lockfile.trim().is_empty() {
                    anyhow::bail!("mcp action: tool_versioning.lockfile must not be empty");
                }
                let mut declared_versions = HashMap::new();
                for (tool, version) in &tv.declared_versions {
                    let parsed = version.parse::<semver::Version>().map_err(|e| {
                        anyhow::anyhow!(
                            "mcp action: tool_versioning.declared_versions['{tool}'] is not semver: {e}"
                        )
                    })?;
                    declared_versions.insert(tool.clone(), parsed);
                }
                let mut judges: Vec<Arc<dyn sbproxy_extension::mcp::compat::Judge>> =
                    Vec::with_capacity(tv.judges.len());
                for judge in &tv.judges {
                    let endpoint = judge.endpoint.parse::<url::Url>().map_err(|e| {
                        anyhow::anyhow!(
                            "mcp action: tool_versioning.judges endpoint '{}' is not a URL: {e}",
                            judge.endpoint
                        )
                    })?;
                    judges.push(Arc::new(sbproxy_ai::judge::CompatJudge::new(
                        sbproxy_ai::judge::CompatJudgeConfig {
                            endpoint,
                            api_key_env: judge.api_key_env.clone(),
                            model: judge.model.clone(),
                            timeout_ms: judge
                                .timeout
                                .map(|d| d.as_millis().min(u128::from(u32::MAX)) as u32)
                                .unwrap_or(5_000),
                            budget_tokens: judge.budget_tokens.unwrap_or(100_000),
                        },
                    )));
                }
                Some(ToolVersioningGate {
                    lockfile_path: tv.lockfile.clone(),
                    declared_versions,
                    mode: match tv.mode {
                        McpVersioningModeConfig::Warn => VersioningMode::Warn,
                        McpVersioningModeConfig::Block => VersioningMode::Block,
                    },
                    judges,
                })
            }
        };

        let mut io = FederationIoSettings::default();
        if let Some(t) = cfg.upstream_connect_timeout {
            io.connect_timeout = t;
        }
        if let Some(t) = cfg.upstream_timeout {
            io.request_timeout = t;
        }
        if let Some(cap) = cfg.max_upstream_response_bytes {
            io.max_response_bytes = cap;
        }
        let federation = Arc::new(McpFederation::with_io_versioned(
            server_configs,
            io,
            versioning,
        ));

        // --- Collapse guardrails ---
        let tool_allowlist = collapse_allowlists(&cfg.guardrails);
        let lethal_trifecta = collapse_lethal_trifecta(&cfg.guardrails);

        let has_principal_scoped_tools = prefixes.values().any(|p| p.rbac.is_some());

        // WOR-1646: publish an injectable source so a virtual key can
        // reference this gateway's live catalogue by its
        // `server_info.name`. Cloned data (cheap) so the action still
        // owns its fields.
        register_inject_source(
            &server_name,
            Arc::new(McpInjectSource {
                federation: Arc::clone(&federation),
                prefixes: prefixes.clone(),
                rbac_policies: cfg.rbac_policies.clone(),
            }),
        );

        Ok(Self {
            mode: cfg.mode,
            server_name,
            server_version,
            prefixes,
            rbac_policies: cfg.rbac_policies,
            federation,
            tool_allowlist,
            lethal_trifecta,
            progressive_discovery: cfg.progressive_discovery,
            oauth: cfg.oauth,
            quota_store: Arc::new(ToolQuotaStore::new()),
            refresh_interval: cfg.refresh_interval.unwrap_or(Duration::from_secs(60)),
            has_principal_scoped_tools,
            sessions: cfg.sessions.as_ref().filter(|s| s.enabled).map(|s| {
                Arc::new(SessionStore::new(
                    s.ttl.unwrap_or(Duration::from_secs(30 * 60)),
                ))
            }),
            token_compaction: cfg.token_compaction.filter(|c| c.enabled),
            dual_llm_quarantine: cfg.dual_llm_quarantine.filter(|c| c.enabled),
            tool_pricing: cfg.tool_pricing,
            usage_sinks: sbproxy_ai::usage_sink::build_sinks(&cfg.usage_sinks),
        })
    }

    /// USD cost for one call of `tool`, from the price map (WOR-1644).
    /// `None` when the tool is unpriced.
    pub fn tool_cost(&self, tool: &str) -> Option<f64> {
        self.tool_pricing.get(tool).copied()
    }

    /// Resolve the [`ToolAccessPolicy`] that governs a given upstream.
    /// Returns `None` when the upstream has no `rbac` label set;
    /// in that case the dispatcher treats every tool as allowed,
    /// which preserves backwards compatibility with existing configs.
    /// WOR-186.
    pub fn policy_for_server(&self, server_name: &str) -> Option<&ToolAccessPolicy> {
        let label = self.prefix_for(server_name)?.rbac.as_deref()?;
        self.rbac_policies.get(label)
    }

    /// Per-server timeout for `tools/call`. `None` when not configured;
    /// the dispatcher uses an unbounded await in that case (matching
    /// pre-WOR-186 behaviour for upstreams that don't opt in).
    pub fn timeout_for_server(&self, server_name: &str) -> Option<Duration> {
        self.prefix_for(server_name)?.timeout
    }

    /// Whether this upstream opted into run-as-user MCP auth.
    pub fn run_as_user_for_server(&self, server_name: &str) -> bool {
        self.prefix_for(server_name)
            .map(|p| p.run_as_user_auth)
            .unwrap_or(false)
    }

    /// Returns true when the named tool is allowed by the configured
    /// guardrails. With no `tool_allowlist` guardrail this is always
    /// true (open access).
    pub fn is_tool_allowed(&self, tool_name: &str) -> bool {
        match &self.tool_allowlist {
            None => true,
            Some(set) => set.contains(tool_name),
        }
    }

    /// Look up the per-server prefix entry by name.
    pub fn prefix_for(&self, server_name: &str) -> Option<&McpServerPrefix> {
        self.prefixes.get(server_name)
    }
}

impl std::fmt::Debug for McpAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpAction")
            .field("mode", &self.mode)
            .field("server_name", &self.server_name)
            .field("server_version", &self.server_version)
            .field("prefixes", &self.prefixes)
            .field("tool_allowlist", &self.tool_allowlist)
            .field("lethal_trifecta", &self.lethal_trifecta)
            .finish()
    }
}

// --- Helpers ---

/// Normalise a user-supplied `origin:` field into a full upstream URL.
/// A bare hostname becomes `https://<host>/mcp`; anything starting with
/// `http://` or `https://` is passed through unchanged.
fn normalize_origin(origin: &str) -> anyhow::Result<String> {
    let trimmed = origin.trim();
    if trimmed.is_empty() {
        anyhow::bail!("mcp action: federated_servers[].origin must not be empty");
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("https://{}/mcp", trimmed))
    }
}

/// Normalise a REST base URL for an OpenAPI-backed server (WOR-1648).
/// A bare hostname becomes `https://<host>`; a scheme is preserved.
/// Unlike [`normalize_origin`], no `/mcp` suffix is appended: the
/// path template from each route is what determines the request path.
fn normalize_rest_origin(origin: &str) -> String {
    let trimmed = origin.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    }
}

/// Load an OpenAPI spec for an `openapi` federated server (WOR-1648),
/// from the inline `spec:` value or the `spec_path:` file. Reading and
/// parsing happen at config-load time so a bad spec fails startup.
fn load_openapi_spec(upstream: &McpFederatedServerConfig) -> anyhow::Result<serde_json::Value> {
    match (&upstream.spec, &upstream.spec_path) {
        (Some(_), Some(_)) => anyhow::bail!(
            "mcp action: openapi server '{}' sets both spec and spec_path; pick one",
            upstream.origin
        ),
        (Some(spec), None) => Ok(spec.clone()),
        (None, Some(path)) => {
            let raw = std::fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!("mcp action: reading openapi spec_path '{path}': {e}")
            })?;
            // Accept JSON or YAML; serde_yaml parses JSON too, but try
            // JSON first for a crisper error on a malformed JSON spec.
            serde_json::from_str(&raw)
                .or_else(|_| serde_yaml::from_str(&raw))
                .map_err(|e| anyhow::anyhow!("mcp action: parsing openapi spec '{path}': {e}"))
        }
        (None, None) => anyhow::bail!(
            "mcp action: openapi server '{}' needs spec or spec_path",
            upstream.origin
        ),
    }
}

/// Derive a stable server name when no `prefix:` was provided. Strips
/// the scheme and trailing path so two distinct origins keep distinct
/// names in the federation registry.
fn derive_server_name(origin: &str) -> String {
    let no_scheme = origin
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    no_scheme
        .split('/')
        .next()
        .unwrap_or(no_scheme)
        .replace([':', '.'], "_")
}

fn collapse_allowlists(guardrails: &[McpGuardrailEntry]) -> Option<HashSet<String>> {
    let mut found = false;
    let mut union: HashSet<String> = HashSet::new();
    for entry in guardrails {
        match entry {
            McpGuardrailEntry::ToolAllowlist { allow } => {
                found = true;
                union.extend(allow.iter().cloned());
            }
            McpGuardrailEntry::LethalTrifecta { .. } => {}
        }
    }
    if found {
        Some(union)
    } else {
        None
    }
}

fn collapse_lethal_trifecta(
    guardrails: &[McpGuardrailEntry],
) -> Option<McpLethalTrifectaGuardrail> {
    let mut found = false;
    let mut private_data_tools = Vec::new();
    let mut external_comm_tools = Vec::new();
    for entry in guardrails {
        if let McpGuardrailEntry::LethalTrifecta {
            private_data_tools: private,
            external_comm_tools: external,
        } = entry
        {
            found = true;
            private_data_tools.extend(private.iter().cloned());
            external_comm_tools.extend(external.iter().cloned());
        }
    }
    found.then_some(McpLethalTrifectaGuardrail {
        private_data_tools,
        external_comm_tools,
    })
}

// --- duration parser for serde ---

mod duration_str {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(d: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Option<String> = Option::deserialize(d)?;
        match raw {
            None => Ok(None),
            Some(s) => parse(&s).map(Some).map_err(serde::de::Error::custom),
        }
    }

    fn parse(s: &str) -> Result<Duration, String> {
        sbproxy_util::parse_duration(s)
    }
}

// --- Tests ---

/// A registered source of federated MCP tools that a virtual key can
/// inject by name (WOR-1646). Holds the live federation snapshot plus
/// the RBAC data needed to filter the injected set by the key's
/// principal, so an injected catalogue never exposes a tool the MCP
/// action would refuse to call for that principal.
pub struct McpInjectSource {
    federation: Arc<McpFederation>,
    prefixes: HashMap<String, McpServerPrefix>,
    rbac_policies: HashMap<String, ToolAccessPolicy>,
}

impl McpInjectSource {
    fn policy_for_server(&self, server_name: &str) -> Option<&ToolAccessPolicy> {
        let label = self.prefixes.get(server_name)?.rbac.as_deref()?;
        self.rbac_policies.get(label)
    }

    /// Resolve the current federated catalogue to provider tool JSON,
    /// RBAC-filtered by `principal` and optionally narrowed to tool
    /// names matching one of `filter` (trailing-`*` glob or exact).
    /// An empty `filter` includes every allowed tool.
    pub fn resolve_tools(
        &self,
        principal: &sbproxy_plugin::Principal,
        filter: &[String],
        format: sbproxy_ai::identity::McpToolFormat,
    ) -> Vec<serde_json::Value> {
        let snapshot = self.federation.serialized_tools();
        let mut out = Vec::new();
        for entry in &snapshot.entries {
            // RBAC: skip a tool the owning upstream's policy denies.
            if let Some(policy) = self.policy_for_server(&entry.server_name) {
                if !matches!(
                    policy.check(principal, &entry.name),
                    sbproxy_extension::mcp::ToolAccessDecision::Allow,
                ) {
                    continue;
                }
            }
            if !filter.is_empty()
                && !filter
                    .iter()
                    .any(|f| sbproxy_util::prefix_glob_match(f, &entry.name))
            {
                continue;
            }
            // The entry JSON is `{"name","description","inputSchema",_meta?}`.
            let parsed: serde_json::Value = match serde_json::from_str(&entry.json) {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.push(to_provider_tool(&parsed, format));
        }
        out
    }
}

/// Convert one federated tool object to the requested provider shape.
fn to_provider_tool(
    tool: &serde_json::Value,
    format: sbproxy_ai::identity::McpToolFormat,
) -> serde_json::Value {
    let name = tool.get("name").cloned().unwrap_or(serde_json::Value::Null);
    let description = tool
        .get("description")
        .cloned()
        .unwrap_or(serde_json::Value::String(String::new()));
    let schema = tool
        .get("inputSchema")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({"type": "object"}));
    match format {
        sbproxy_ai::identity::McpToolFormat::Openai => serde_json::json!({
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": schema,
            }
        }),
        sbproxy_ai::identity::McpToolFormat::Anthropic => serde_json::json!({
            "name": name,
            "description": description,
            "input_schema": schema,
        }),
    }
}

/// Process-global registry of injectable MCP sources, keyed by the
/// gateway's `server_info.name` (WOR-1646). An `McpAction` registers
/// itself on compile; a virtual key's `inject_mcp.ref` looks it up at
/// request time. A mutex guards the read-modify-write so concurrent
/// registrations (parallel config compiles, tests) cannot lose an
/// entry to a lost update.
fn inject_registry() -> &'static std::sync::Mutex<HashMap<String, Arc<McpInjectSource>>> {
    static REGISTRY: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Arc<McpInjectSource>>>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Register an injectable source under `name`, replacing any prior
/// entry (a hot reload rebuilds the action).
pub fn register_inject_source(name: &str, source: Arc<McpInjectSource>) {
    let mut map = match inject_registry().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.insert(name.to_string(), source);
}

/// Look up an injectable MCP source by name (WOR-1646). `None` when no
/// `mcp` action has registered under that name yet.
pub fn lookup_inject_source(name: &str) -> Option<Arc<McpInjectSource>> {
    let map = match inject_registry().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- WOR-1646: federation-sourced injection ---

    #[test]
    fn openapi_server_compiles_with_inline_spec() {
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "egress": {
                "mode": "deny_by_default",
                "suffixes": ["example.com"]
            },
            "federated_servers": [{
                "type": "openapi",
                "origin": "api.example.com",
                "spec": {
                    "openapi": "3.0.0",
                    "info": {"title": "t", "version": "1"},
                    "paths": {"/pets/{id}": {"get": {"operationId": "getPet"}}}
                }
            }]
        });
        let action = McpAction::from_config(value).expect("compile");
        assert_eq!(action.prefixes.len(), 1);
    }

    #[test]
    fn openapi_server_accepts_per_server_egress_override() {
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "egress": {
                "mode": "deny_by_default",
                "hosts": ["api.example.com"]
            },
            "federated_servers": [{
                "type": "openapi",
                "origin": "api.internal.example",
                "egress": {
                    "mode": "deny_by_default",
                    "hosts": ["api.internal.example"]
                },
                "spec": {
                    "openapi": "3.0.0",
                    "info": {"title": "t", "version": "1"},
                    "paths": {"/pets": {"get": {"operationId": "listPets"}}}
                }
            }]
        });

        let action = McpAction::from_config(value).expect("compile");
        assert_eq!(action.prefixes.len(), 1);
    }

    #[test]
    fn lethal_trifecta_guardrail_compiles_and_classifies_tools() {
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{ "origin": "example.com" }],
            "guardrails": [{
                "type": "lethal_trifecta",
                "private_data_tools": ["db.*"],
                "external_comm_tools": ["slack.post", "email.*"]
            }]
        });

        let action = McpAction::from_config(value).expect("compile");
        let guardrail = action.lethal_trifecta.expect("guardrail");
        let db = guardrail.classify("db.query");
        assert!(db.tool_access);
        assert!(db.private_data);
        assert!(!db.external_comm);

        let email = guardrail.classify("email.send");
        assert!(email.tool_access);
        assert!(!email.private_data);
        assert!(email.external_comm);

        let slack = guardrail.classify("slack.post");
        assert!(slack.external_comm);
    }

    #[test]
    fn run_as_user_auth_is_opt_in_per_server() {
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{
                "origin": "github.example.com",
                "prefix": "gh",
                "run_as_user_auth": true
            }]
        });

        let action = McpAction::from_config(value).expect("compile");
        assert!(action.run_as_user_for_server("gh"));
        assert!(!action.run_as_user_for_server("missing"));
    }

    #[test]
    fn stdio_transport_requires_command_and_compiles_when_present() {
        let missing = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{
                "origin": "local",
                "transport": "stdio"
            }]
        }))
        .expect_err("stdio command required");
        assert!(missing.to_string().contains("needs command"));

        let action = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{
                "origin": "local",
                "prefix": "local",
                "transport": "stdio",
                "command": "python3",
                "args": ["-c", "print('ready')"]
            }]
        }))
        .expect("compile");
        assert!(action.prefix_for("local").is_some());
    }

    #[test]
    fn token_compaction_is_disabled_by_default_and_enabled_explicitly() {
        let disabled = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{ "origin": "example.com" }]
        }))
        .expect("compile");
        assert!(disabled.token_compaction.is_none());

        let enabled = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "token_compaction": { "enabled": true, "max_text_bytes": 128 },
            "federated_servers": [{ "origin": "example.com" }]
        }))
        .expect("compile");
        let cfg = enabled.token_compaction.expect("enabled");
        assert_eq!(cfg.max_text_bytes, Some(128));
    }

    #[test]
    fn dual_llm_quarantine_is_enabled_explicitly() {
        let action = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "dual_llm_quarantine": {
                "enabled": true,
                "suspicious_patterns": ["ignore previous instructions"]
            },
            "federated_servers": [{ "origin": "example.com" }]
        }))
        .expect("compile");

        let cfg = action.dual_llm_quarantine.expect("enabled");
        assert_eq!(
            cfg.suspicious_patterns,
            vec!["ignore previous instructions"]
        );
    }

    #[test]
    fn openapi_server_rejects_missing_spec() {
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{"type": "openapi", "origin": "api.example.com"}]
        });
        let err = McpAction::from_config(value).expect_err("must reject");
        assert!(
            err.to_string().contains("spec"),
            "error must mention the missing spec, got: {err}"
        );
    }

    #[test]
    fn to_provider_tool_openai_and_anthropic_shapes() {
        let tool = json!({
            "name": "search",
            "description": "find things",
            "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
        });
        let openai = to_provider_tool(&tool, sbproxy_ai::identity::McpToolFormat::Openai);
        assert_eq!(openai["type"], "function");
        assert_eq!(openai["function"]["name"], "search");
        assert_eq!(openai["function"]["parameters"]["type"], "object");

        let anthropic = to_provider_tool(&tool, sbproxy_ai::identity::McpToolFormat::Anthropic);
        assert_eq!(anthropic["name"], "search");
        assert_eq!(anthropic["input_schema"]["type"], "object");
        assert!(anthropic.get("type").is_none());
    }

    #[test]
    fn glob_match_semantics() {
        use sbproxy_util::prefix_glob_match as glob_match;
        assert!(glob_match("gh.*", "gh.search"));
        assert!(glob_match("search", "search"));
        assert!(!glob_match("gh.*", "db.query"));
        assert!(!glob_match("search", "search_repos"));
    }

    #[test]
    fn inject_source_registers_and_resolves_rbac_filtered() {
        // A gateway with a default-deny policy allowing only `search`
        // registers under its server name; resolving the source for an
        // anonymous principal yields just the allowed tool.
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "server_info": {"name": "toolhub_test_1646", "version": "1.0.0"},
            "rbac_policies": {
                "ro": {"default_allow": false, "tool_access": [{"principals": [], "allowed": ["gh.search"]}]}
            },
            "federated_servers": [
                {"origin": "test.sbproxy.dev", "prefix": "gh", "rbac": "ro"}
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        // Seed the federation registry directly (no network) so the
        // resolve path has a catalogue to filter.
        let mut map = std::collections::HashMap::new();
        for name in ["gh.search", "gh.delete_repo"] {
            map.insert(
                name.to_string(),
                sbproxy_extension::mcp::FederatedTool {
                    name: name.to_string(),
                    description: "t".to_string(),
                    input_schema: json!({"type": "object"}),
                    server_name: "gh".to_string(),
                    streaming: false,
                    meta: None,
                },
            );
        }
        action.federation.seed_tools_for_test(map);

        let source = lookup_inject_source("toolhub_test_1646").expect("source registered");
        let principal = sbproxy_plugin::Principal::anonymous();
        let tools =
            source.resolve_tools(&principal, &[], sbproxy_ai::identity::McpToolFormat::Openai);
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t["function"]["name"].as_str())
            .collect();
        assert_eq!(
            names,
            vec!["gh.search"],
            "RBAC-denied tool must be filtered out"
        );
    }

    #[test]
    fn compiles_with_minimal_config() {
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [
                { "origin": "github.example.com" }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        assert_eq!(action.mode, "gateway");
        assert_eq!(action.server_name, "sbproxy-mcp");
        assert_eq!(action.server_version, "0.1.0");
        assert_eq!(action.prefixes.len(), 1);
        assert!(action.tool_allowlist.is_none());
    }

    #[test]
    fn rejects_empty_federated_servers() {
        let value = json!({
            "type": "mcp",
            "federated_servers": []
        });
        assert!(McpAction::from_config(value).is_err());
    }

    #[test]
    fn rejects_unknown_mode() {
        let value = json!({
            "type": "mcp",
            "mode": "embedded",
            "federated_servers": [{ "origin": "example.com" }]
        });
        assert!(McpAction::from_config(value).is_err());
    }

    #[test]
    fn parses_full_marketing_shape() {
        // WOR-186 + WOR-1065 + WOR-1066: `rbac` and `timeout` are now
        // part of the happy-path fixture, and the RBAC policy uses
        // the principal-aware selector shape (default-deny, with
        // `principals[]` + `allowed[]` on every rule).
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "server_info": { "name": "my-mcp", "version": "1.0.0" },
            "rbac_policies": {
                "read_only": {
                    "default_allow": false,
                    "tool_access": [
                        {
                            "principals": [{ "virtual_key": "alice" }],
                            "allowed": ["gh.search_repos", "db.query"]
                        }
                    ]
                },
                "admin": {
                    "default_allow": false,
                    "tool_access": [
                        {
                            "principals": [{ "role": "admin" }],
                            "allowed": ["*"]
                        }
                    ]
                }
            },
            "federated_servers": [
                {
                    "origin": "github.example.com",
                    "prefix": "gh",
                    "rbac": "read_only",
                    "timeout": "10s"
                },
                {
                    "origin": "postgres.example.com",
                    "prefix": "db",
                    "rbac": "admin",
                    "timeout": "5s"
                }
            ],
            "guardrails": [
                {
                    "type": "tool_allowlist",
                    "allow": ["gh.search_repos", "db.query"]
                }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        assert_eq!(action.server_name, "my-mcp");
        assert_eq!(action.server_version, "1.0.0");
        assert_eq!(action.prefixes.len(), 2);

        let gh = action.prefix_for("gh").expect("gh prefix entry");
        assert_eq!(gh.rbac.as_deref(), Some("read_only"));
        assert_eq!(gh.timeout, Some(Duration::from_secs(10)));

        let db = action.prefix_for("db").expect("db prefix entry");
        assert_eq!(db.rbac.as_deref(), Some("admin"));
        assert_eq!(db.timeout, Some(Duration::from_secs(5)));

        // RBAC labels resolve to the correct policy. The new schema
        // carries `tool_access` rules with principal selectors; the
        // legacy `key_permissions` map is gone.
        let read_only = action.policy_for_server("gh").expect("gh policy");
        assert!(!read_only.default_allow);
        assert_eq!(read_only.tool_access.len(), 1);

        let admin = action.policy_for_server("db").expect("db policy");
        assert!(!admin.default_allow);
        assert_eq!(admin.tool_access.len(), 1);
        assert_eq!(admin.tool_access[0].allowed, vec!["*".to_string()]);

        // Per-server timeout helper.
        assert_eq!(
            action.timeout_for_server("gh"),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            action.timeout_for_server("db"),
            Some(Duration::from_secs(5))
        );

        let allow = action.tool_allowlist.as_ref().expect("allowlist");
        assert!(allow.iter().any(|t| t == "gh.search_repos"));
        assert!(allow.iter().any(|t| t == "db.query"));
        assert!(action.is_tool_allowed("gh.search_repos"));
        assert!(!action.is_tool_allowed("gh.delete_repo"));
    }

    /// Per-server `rbac` must reference a declared label.
    /// A typo in the upstream config silently allowing every tool is
    /// the exact failure mode this guard prevents.
    #[test]
    fn rejects_undeclared_rbac_label() {
        let value = json!({
            "type": "mcp",
            "rbac_policies": {
                "read_only": { "default_allow": false, "tool_access": [] }
            },
            "federated_servers": [
                { "origin": "github.example.com", "rbac": "admin" }
            ]
        });
        let err = McpAction::from_config(value).unwrap_err().to_string();
        assert!(
            err.contains("admin"),
            "error should call out the missing label, got: {err}",
        );
    }

    /// An action that only sets `rbac` but no `rbac_policies`
    /// table at all must not silently fall through.
    #[test]
    fn rejects_rbac_without_policy_table() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "github.example.com", "rbac": "read_only" }
            ]
        });
        let err = McpAction::from_config(value).unwrap_err().to_string();
        assert!(
            err.contains("rbac_policies") || err.contains("read_only"),
            "error must mention the missing policy or the rbac_policies table, got: {err}",
        );
    }

    /// A valid `timeout:` field is now stored on the action
    /// (no longer a hard config error).
    #[test]
    fn timeout_field_is_stored_on_action() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "github.example.com", "prefix": "gh", "timeout": "250ms" }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        assert_eq!(
            action.timeout_for_server("gh"),
            Some(Duration::from_millis(250)),
        );
    }

    #[test]
    fn full_url_origin_is_passed_through() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "https://mcp.example.com:8443/api" }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        assert_eq!(action.prefixes.len(), 1);
        // We do not expose the underlying server URL on the action, but
        // the prefix-derived name should still be deterministic.
        assert!(action.prefixes.values().all(|p| !p.name.is_empty()));
    }

    #[test]
    fn bare_hostname_normalises_to_https_mcp() {
        // Internal helper test: protects the wire-shape doc.
        assert_eq!(
            normalize_origin("github.example.com").unwrap(),
            "https://github.example.com/mcp"
        );
        assert_eq!(
            normalize_origin("https://example.com/mcp").unwrap(),
            "https://example.com/mcp"
        );
        assert!(normalize_origin("   ").is_err());
    }

    #[test]
    fn empty_allowlist_blocks_everything() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [{ "origin": "example.com" }],
            "guardrails": [
                { "type": "tool_allowlist", "allow": [] }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        assert!(!action.is_tool_allowed("anything"));
    }

    #[test]
    fn no_guardrails_allows_everything() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [{ "origin": "example.com" }]
        });
        let action = McpAction::from_config(value).expect("compile");
        assert!(action.is_tool_allowed("any.tool"));
    }

    #[test]
    fn multiple_allowlists_union() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [{ "origin": "example.com" }],
            "guardrails": [
                { "type": "tool_allowlist", "allow": ["a", "b"] },
                { "type": "tool_allowlist", "allow": ["b", "c"] }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        let allow = action.tool_allowlist.unwrap();
        assert_eq!(allow.len(), 3, "union should dedupe overlapping entries");
        assert!(allow.contains("a"));
        assert!(allow.contains("b"));
        assert!(allow.contains("c"));
    }

    #[test]
    fn duration_parsing_accepts_common_units() {
        // The duration parser still has to round-trip the wire shape
        // correctly so that, once the dispatcher wires `timeout`
        // through, an existing config keeps working. We exercise it
        // directly via `from_parsed` with a hand-built struct that
        // skips the `from_config` rejection.
        use super::McpFederatedServerConfig;
        for (raw, expected) in [
            ("250ms", Duration::from_millis(250)),
            ("30s", Duration::from_secs(30)),
            ("2m", Duration::from_secs(120)),
        ] {
            let entry = McpFederatedServerConfig {
                origin: "a.example.com".to_string(),
                prefix: None,
                namespace: NamespaceMode::default(),
                rbac: None,
                timeout: Some(parse_duration_via_serde(raw)),
                run_as_user_auth: false,
                transport: None,
                command: None,
                args: Vec::new(),
                server_type: None,
                spec: None,
                spec_path: None,
                egress: None,
            };
            assert_eq!(entry.timeout, Some(expected), "parsed {raw}");
        }
    }

    /// Helper: round-trip a duration string through the serde
    /// `duration_str` parser without going through the public config
    /// loader (which now rejects unwired `timeout` fields).
    fn parse_duration_via_serde(raw: &str) -> Duration {
        // Wrap the value in a synthetic struct so we can re-use the
        // serde adapter without exposing private internals.
        #[derive(serde::Deserialize)]
        struct W {
            #[serde(with = "super::duration_str")]
            t: Option<Duration>,
        }
        let v: W = serde_json::from_value(json!({ "t": raw })).unwrap();
        v.t.unwrap()
    }

    #[test]
    fn invalid_duration_is_rejected() {
        // The parser-level error (bad unit) must surface as a config
        // error even before the WOR-42 fail-loud rejection kicks in.
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "a.example.com", "timeout": "10 hrs" }
            ]
        });
        assert!(McpAction::from_config(value).is_err());
    }

    #[test]
    fn server_name_falls_back_to_derived_when_no_prefix() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "github.example.com" }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        // No explicit prefix, so the derived name comes from the host.
        assert!(action.prefixes.contains_key("github_example_com"));
    }
}
