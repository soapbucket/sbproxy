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
    FederationIoSettings, McpFederation, McpServerConfig, NamespaceMode, ToolAccessPolicy,
    ToolQuotaStore,
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
    /// Optional MCP session management (WOR-1642). When enabled the
    /// gateway assigns an `Mcp-Session-Id` during `initialize`,
    /// requires it on every later request, serves 404 for unknown or
    /// expired ids (the client's cue to re-initialize), and ends a
    /// session on `DELETE`. Off by default: the gateway stays
    /// stateless and ignores session headers entirely.
    #[serde(default)]
    pub sessions: Option<McpSessionConfig>,
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
    /// Transport name. Defaults to `streamable_http`; alternative is `sse`.
    #[serde(default)]
    pub transport: Option<String>,
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

        for upstream in cfg.federated_servers {
            let url = normalize_origin(&upstream.origin)?;
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

            server_configs.push(McpServerConfig {
                name: name.clone(),
                url,
                transport,
                namespace: upstream.namespace,
            });
            prefixes.insert(
                name.clone(),
                McpServerPrefix {
                    name,
                    prefix: upstream.prefix,
                    rbac: upstream.rbac,
                    timeout: upstream.timeout,
                },
            );
        }

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
        let federation = Arc::new(McpFederation::with_io(server_configs, io));

        // --- Collapse guardrails ---
        let tool_allowlist = collapse_allowlists(&cfg.guardrails);

        let has_principal_scoped_tools = prefixes.values().any(|p| p.rbac.is_some());

        Ok(Self {
            mode: cfg.mode,
            server_name,
            server_version,
            prefixes,
            rbac_policies: cfg.rbac_policies,
            federation,
            tool_allowlist,
            progressive_discovery: cfg.progressive_discovery,
            oauth: cfg.oauth,
            quota_store: Arc::new(ToolQuotaStore::new()),
            refresh_interval: cfg
                .refresh_interval
                .unwrap_or(Duration::from_secs(60)),
            has_principal_scoped_tools,
            sessions: cfg.sessions.as_ref().filter(|s| s.enabled).map(|s| {
                Arc::new(SessionStore::new(
                    s.ttl.unwrap_or(Duration::from_secs(30 * 60)),
                ))
            }),
        })
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
        }
    }
    if found {
        Some(union)
    } else {
        None
    }
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
        let s = s.trim();
        if s.is_empty() {
            return Err("empty duration".into());
        }
        let (num_part, unit) = split_unit(s);
        let value: u64 = num_part
            .parse()
            .map_err(|e| format!("invalid duration number '{}': {}", num_part, e))?;
        match unit {
            "ms" => Ok(Duration::from_millis(value)),
            "s" | "" => Ok(Duration::from_secs(value)),
            "m" => Ok(Duration::from_secs(value * 60)),
            other => Err(format!(
                "unsupported duration unit '{}' (use ms, s, m)",
                other
            )),
        }
    }

    fn split_unit(s: &str) -> (&str, &str) {
        let split_at = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        (&s[..split_at], &s[split_at..])
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        assert!(allow.contains(&"a".to_string()));
        assert!(allow.contains(&"b".to_string()));
        assert!(allow.contains(&"c".to_string()));
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
                transport: None,
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
