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
//!       federated_servers:
//!         - origin: github.example.com
//!           prefix: gh
//!         - origin: postgres.example.com
//!           prefix: db
//!       guardrails:
//!         - type: tool_allowlist
//!           allow: [gh.search_repos, db.query]
//! ```
//!
//! The `rbac:` and `timeout:` per-server fields are reserved for a
//! future cut: they parse but the federation dispatcher does not yet
//! enforce them. Setting either is a hard config error today.
//!
//! The action is a thin adapter on top of
//! [`sbproxy_extension::mcp::McpFederation`]. Tool aggregation, name
//! collision handling, and the underlying transports all live in the
//! library; this module only translates YAML into library API calls
//! and applies a small allowlist guardrail at request time.

use std::sync::Arc;
use std::time::Duration;

use sbproxy_extension::mcp::{McpFederation, McpServerConfig};
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
    /// List of upstream MCP servers to federate.
    #[serde(default)]
    pub federated_servers: Vec<McpFederatedServerConfig>,
    /// Inline guardrails applied at the gateway boundary before a
    /// `tools/call` is forwarded to its upstream.
    #[serde(default)]
    pub guardrails: Vec<McpGuardrailEntry>,
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
    /// Optional namespace prefix applied to every tool from this
    /// upstream. When set, tools are exposed as `<prefix>.<tool>`
    /// instead of `<tool>`.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Optional RBAC label for the upstream. Stored on the action and
    /// available to downstream policy enforcement, but not yet wired
    /// through the federation library at the per-request layer.
    /// TODO: thread through `ToolAccessPolicy` once virtual-key
    /// resolution lands at the action boundary.
    #[serde(default)]
    pub rbac: Option<String>,
    /// Optional per-server request timeout. Accepts Go duration syntax
    /// (`10s`, `500ms`). Stored on the action; the federation client
    /// shares one `reqwest::Client` so per-server enforcement is a
    /// TODO: switch to a per-server client builder.
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
    /// Per-server prefix table, keyed by upstream `name`.
    pub prefixes: Vec<McpServerPrefix>,
    /// Underlying federation handle from `sbproxy-extension`.
    pub federation: Arc<McpFederation>,
    /// Collapsed allowlist (union of every `tool_allowlist` guardrail).
    /// `None` when no allowlist guardrail was configured (open access).
    pub tool_allowlist: Option<Vec<String>>,
}

/// Per-upstream metadata captured at compile time. Kept outside
/// `McpServerConfig` so the federation library stays unchanged.
#[derive(Debug, Clone)]
pub struct McpServerPrefix {
    /// Stable server name (matches `McpServerConfig::name`).
    pub name: String,
    /// Optional namespace prefix applied to the upstream's tools.
    pub prefix: Option<String>,
    /// Optional RBAC label (TODO at the dispatch layer).
    pub rbac: Option<String>,
    /// Optional per-server timeout (TODO at the dispatch layer).
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

        // Reject the unimplemented `rbac:` and `timeout:` per-server
        // fields at compile time. Accepting them silently would let an
        // operator believe an RBAC-bound or timeout-bound upstream is
        // actually enforced when the federation library currently
        // ignores both. Better to fail loudly until the dispatcher
        // wires these through.
        for upstream in &cfg.federated_servers {
            if upstream.rbac.is_some() {
                anyhow::bail!(
                    "mcp action: federated_servers[].rbac is not yet enforced; \
                     remove the field until per-server RBAC dispatch lands \
                     (origin '{}')",
                    upstream.origin
                );
            }
            if upstream.timeout.is_some() {
                anyhow::bail!(
                    "mcp action: federated_servers[].timeout is not yet enforced; \
                     remove the field until per-server timeout dispatch lands \
                     (origin '{}')",
                    upstream.origin
                );
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
        let mut prefixes: Vec<McpServerPrefix> = Vec::with_capacity(cfg.federated_servers.len());

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
            });
            prefixes.push(McpServerPrefix {
                name,
                prefix: upstream.prefix,
                rbac: upstream.rbac,
                timeout: upstream.timeout,
            });
        }

        let federation = Arc::new(McpFederation::new(server_configs));

        // --- Collapse guardrails ---
        let tool_allowlist = collapse_allowlists(&cfg.guardrails);

        Ok(Self {
            mode: cfg.mode,
            server_name,
            server_version,
            prefixes,
            federation,
            tool_allowlist,
        })
    }

    /// Returns true when the named tool is allowed by the configured
    /// guardrails. With no `tool_allowlist` guardrail this is always
    /// true (open access).
    pub fn is_tool_allowed(&self, tool_name: &str) -> bool {
        match &self.tool_allowlist {
            None => true,
            Some(list) => list.iter().any(|t| t == tool_name),
        }
    }

    /// Look up the per-server prefix entry by name.
    pub fn prefix_for(&self, server_name: &str) -> Option<&McpServerPrefix> {
        self.prefixes.iter().find(|p| p.name == server_name)
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

fn collapse_allowlists(guardrails: &[McpGuardrailEntry]) -> Option<Vec<String>> {
    let mut found = false;
    let mut union: Vec<String> = Vec::new();
    for entry in guardrails {
        match entry {
            McpGuardrailEntry::ToolAllowlist { allow } => {
                found = true;
                for name in allow {
                    if !union.contains(name) {
                        union.push(name.clone());
                    }
                }
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
        // Note: `rbac` and `timeout` are intentionally omitted here.
        // Both fields parse but currently fall through the federation
        // dispatcher, so we reject them at compile time (see
        // `rejects_unwired_rbac` / `rejects_unwired_timeout`). Restore
        // them in this fixture once the dispatch layer enforces them.
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "server_info": { "name": "my-mcp", "version": "1.0.0" },
            "federated_servers": [
                {
                    "origin": "github.example.com",
                    "prefix": "gh"
                },
                {
                    "origin": "postgres.example.com",
                    "prefix": "db"
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
        assert!(gh.rbac.is_none());
        assert!(gh.timeout.is_none());

        let db = action.prefix_for("db").expect("db prefix entry");
        assert!(db.timeout.is_none());

        let allow = action.tool_allowlist.as_ref().expect("allowlist");
        assert!(allow.iter().any(|t| t == "gh.search_repos"));
        assert!(allow.iter().any(|t| t == "db.query"));
        assert!(action.is_tool_allowed("gh.search_repos"));
        assert!(!action.is_tool_allowed("gh.delete_repo"));
    }

    #[test]
    fn rejects_unwired_rbac() {
        // WOR-42: per-server `rbac` is parsed but not yet enforced
        // by the federation dispatcher. Until it is, accept it as a
        // hard config error so operators do not believe an RBAC-bound
        // upstream is actually constrained.
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "github.example.com", "rbac": "read_only" }
            ]
        });
        let err = McpAction::from_config(value).unwrap_err().to_string();
        assert!(
            err.contains("rbac"),
            "error should mention the rbac field, got: {err}"
        );
    }

    #[test]
    fn rejects_unwired_timeout() {
        // WOR-42: per-server `timeout` is parsed but not yet enforced
        // by the federation dispatcher (it shares one HTTP client
        // across all upstreams). Same fail-loud pattern as `rbac`.
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "github.example.com", "timeout": "10s" }
            ]
        });
        let err = McpAction::from_config(value).unwrap_err().to_string();
        assert!(
            err.contains("timeout"),
            "error should mention the timeout field, got: {err}"
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
        assert!(!action.prefixes[0].name.is_empty());
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
        assert_eq!(action.prefixes[0].name, "github_example_com");
    }
}
