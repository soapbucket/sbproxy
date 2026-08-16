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
//! `default_allow: true` on each policy. WOR-2314: once any
//! `rbac_policies` are declared, every federated server must carry
//! an `rbac:` label; an unlabeled server is a config compile error
//! rather than a silent allow-all. See
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use sbproxy_extension::mcp::access_control::McpPrincipalSelector;
use sbproxy_extension::mcp::rollout::{
    AdapterPair, PinSpec, RolloutPlan, RolloutSpec, SunsetBehavior, ToolRolloutSpec, VersionSpec,
};
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
    /// Trusted public origin and browser Origin allowlist for the strict
    /// 2026-07-28 Streamable HTTP endpoint. Marker-free legacy traffic does
    /// not consult this block. An exact route derives its trusted host here
    /// and binds the connection scheme and effective port per request.
    /// Wildcard routes and actions compiled outside a route require an
    /// explicit block; otherwise modern traffic fails closed with HTTP 421.
    #[serde(default)]
    pub modern_http: Option<McpModernHttpConfig>,
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

/// HTTP trust configuration for MCP 2026-07-28 requests.
///
/// Unknown fields are refused rather than ignored: every key here turns a
/// protection on, so a typo that silently left one off would read as
/// configured hardening that is not actually in effect.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpModernHttpConfig {
    /// Exact externally visible HTTP(S) origin of this MCP action.
    pub public_origin: String,
    /// Additional browser origins allowed to call the endpoint. The public
    /// origin is always included automatically.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Reject unknown `Mcp-Param-*` fields instead of transparently ignoring
    /// them. This is an SBProxy hardening mode, not base MCP behavior.
    #[serde(default)]
    pub strict_parameter_headers: bool,
}

/// Tool-versioning gate config (WOR-1635).
#[derive(Debug, Clone, Deserialize)]
pub struct McpToolVersioningConfig {
    /// Path to the committed lockfile (YAML): one contract digest,
    /// declared semver, and optionally the embedded contract per
    /// tool. Resolved relative to the proxy's working directory at
    /// refresh time. Required for the version-bump gate
    /// (`declared_versions` / `judges`); optional when only
    /// `rollout` is configured.
    #[serde(default)]
    pub lockfile: Option<String>,
    /// `warn` (default) or `block`.
    #[serde(default)]
    pub mode: McpVersioningModeConfig,
    /// Refuse a tool with no lockfile entry at all (WOR-2444).
    ///
    /// Off by default, because turning it on means every newly
    /// advertised tool is refused until the lockfile is regenerated,
    /// which changes behavior for anyone who adds a tool.
    ///
    /// On, it is what closes the rename escape. A tool renamed but
    /// otherwise unchanged is matched back to its baseline by contract
    /// digest and graded as a rename. A rename that also edits the
    /// contract matches no baseline by construction, so it is
    /// indistinguishable from a new tool, and refusing unlocked tools
    /// is the only thing that stops it being served ungated. A pinning
    /// gate that serves whatever it has not seen before is pinning only
    /// the tools an upstream chooses not to rename.
    ///
    /// Only consulted under `mode: block`; warn mode blocks nothing.
    #[serde(default)]
    pub block_unlocked: bool,
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
    /// Tool rollout plane: publish several versions of one tool at
    /// once, resolve per consumer (call `_meta`, session
    /// requirements, principal pins, catalogue aliases, default),
    /// route or adapt each version, and sunset old ones.
    #[serde(default)]
    pub rollout: Option<McpRolloutConfig>,
}

/// Rollout block under `tool_versioning`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct McpRolloutConfig {
    /// Per-tool rollout, keyed by the base (unversioned) tool name.
    #[serde(default)]
    pub tools: HashMap<String, McpRolloutToolConfig>,
    /// Identity pins: the first entry whose selector matches the
    /// authenticated principal supplies that principal's version
    /// requirements.
    #[serde(default)]
    pub pins: Vec<McpRolloutPinConfig>,
}

/// Rollout configuration for one tool.
#[derive(Debug, Clone, Deserialize)]
pub struct McpRolloutToolConfig {
    /// Published versions, newest and oldest alike. At least one.
    pub versions: Vec<McpRolloutVersionConfig>,
    /// Version served when nothing more specific matches. Must be
    /// one of `versions`. Absent means the highest version.
    #[serde(default)]
    pub default: Option<String>,
    /// Advertise `"{tool}_v{major}"` catalogue aliases so clients
    /// without identity or `_meta` support can still choose a major.
    /// On by default.
    #[serde(default = "default_true")]
    pub aliases: bool,
}

fn default_true() -> bool {
    true
}

/// One published version of a tool.
#[derive(Debug, Clone, Deserialize)]
pub struct McpRolloutVersionConfig {
    /// Semver string, e.g. `"1.4.0"`.
    pub version: String,
    /// Federated server (its `prefix`, or the name derived from its
    /// origin) that serves this version natively. Absent means the
    /// version dispatches to the tool's default-version server,
    /// normally through an adapter.
    #[serde(default)]
    pub server: Option<String>,
    /// Request/response adapters translating this version onto a
    /// newer upstream once its native server is retired.
    #[serde(default)]
    pub adapter: Option<McpRolloutAdapterConfig>,
    /// Inline contract (a `tools/list` tool object) advertised for
    /// this version when no live upstream serves it. Absent falls
    /// back to the lockfile's embedded contract, then to the live
    /// schema.
    #[serde(default)]
    pub contract: Option<serde_json::Value>,
    /// `YYYY-MM-DD` date after which this version is past sunset.
    #[serde(default)]
    pub sunset: Option<String>,
    /// `warn` (default) keeps serving past sunset and annotates;
    /// `block` fails `tools/call` with a typed error.
    #[serde(default)]
    pub after_sunset: McpSunsetBehaviorConfig,
}

/// Post-sunset behavior.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpSunsetBehaviorConfig {
    /// Keep serving, annotate, count.
    #[default]
    Warn,
    /// Fail calls to the sunset version.
    Block,
}

/// Adapter script references for one version. Runtime-prefixed;
/// JavaScript (`js:`) is supported today.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct McpRolloutAdapterConfig {
    /// Transforms caller arguments into the upstream's shape.
    #[serde(default)]
    pub request: Option<String>,
    /// Transforms the upstream result back into the caller's shape.
    #[serde(default)]
    pub response: Option<String>,
}

/// One identity pin: principal selectors and the requirements they
/// pin. An empty `principals` list matches every principal.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct McpRolloutPinConfig {
    /// Selectors, same shape as the RBAC `principals` rows. Any
    /// match applies the pin.
    #[serde(default)]
    pub principals: Vec<McpPrincipalSelector>,
    /// `{tool: semver requirement}`, e.g. `search: "^1"`.
    #[serde(default)]
    pub tools: HashMap<String, String>,
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
///
/// When enabled, untrusted tool text blocks are evaluated by a
/// secondary LLM judge (`ToolOutputJudge`) before any served
/// ledger/outcome or compaction. Fail closed on timeout, malformed
/// judge response, or egress denial. Reason codes are digest/closed
/// vocabulary only, never matched text or raw tool output.
#[derive(Debug, Clone, Deserialize)]
pub struct McpDualLlmQuarantineConfig {
    /// Master switch.
    #[serde(default)]
    pub enabled: bool,
    /// Judge model HTTP endpoint (OpenAI-compatible chat completions).
    /// Required when `enabled` is true.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Optional model id included in the judge request body.
    #[serde(default)]
    pub model: Option<String>,
    /// Maximum time to wait for a judge response. Go duration syntax.
    #[serde(default, with = "duration_str")]
    pub timeout: Option<Duration>,
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
    /// caller's auth subject as the virtual key. WOR-186. Required on
    /// every server once `rbac_policies` is non-empty (WOR-2314).
    #[serde(default)]
    pub rbac: Option<String>,
    /// Optional per-server request timeout. Accepts Go duration syntax
    /// (`10s`, `500ms`). Wraps the `tools/call` dispatch in
    /// `tokio::time::timeout` so a hung upstream cannot stall the
    /// request layer. WOR-186.
    #[serde(default, with = "duration_str")]
    pub timeout: Option<Duration>,
    /// Opt into run-as-user upstream Authorization minting (WOR-1792).
    /// When true, `upstream_auth` is required and credentials are
    /// attached as HTTP Authorization headers, never as tool args.
    /// Defaults off. `stdio` + run-as-user is a config error.
    #[serde(default)]
    pub run_as_user_auth: bool,
    /// How to mint upstream Authorization when `run_as_user_auth` is
    /// true. See [`sbproxy_extension::mcp::auth::McpUpstreamAuthConfig`].
    #[serde(default)]
    pub upstream_auth: Option<sbproxy_extension::mcp::auth::McpUpstreamAuthConfig>,
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
    /// Static headers attached to every REST request an `openapi`
    /// server dispatches (WOR-2314). Values pass through `${VAR}`
    /// config interpolation, so a shared service credential (e.g. an
    /// admin API's Basic auth) lives in the environment, not the
    /// file. Rejected on non-`openapi` servers so a header that would
    /// silently never be sent fails loudly instead. Setting an
    /// `authorization` header here alongside `run_as_user_auth` is a
    /// config error; pick one credential source.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Protocol negotiation pin for this upstream (WOR-2384). `"auto"`
    /// (default) negotiates: the gateway remembers, per tenant, the best
    /// era this upstream has demonstrated and refuses (or, under
    /// `downgrade: warn`, flags) a later contact that looks weaker. A
    /// pinned literal era (`"2025-06-18"` or `"2026-07-28"`) never
    /// negotiates: an upstream that ever answers `initialize` with any
    /// other `protocolVersion` is refused, regardless of `downgrade:`.
    #[serde(default = "default_federated_protocol")]
    pub protocol: String,
    /// Downgrade-resistance mode applied when `protocol: auto` and this
    /// upstream's contact looks weaker than what it has previously
    /// demonstrated, on either axis: a legacy-only answer after having
    /// shown the modern era, or a successful call needing no
    /// credentials after having required them before. `warn` (default)
    /// logs and counts the downgrade; the call still proceeds. `block`
    /// refuses the call until the operator pins `protocol:` explicitly
    /// or edits this server entry (which starts a fresh profile; see
    /// [`sbproxy_extension::mcp::peer_profile::peer_key`]). Ignored
    /// when `protocol:` is pinned. WOR-2384.
    #[serde(default)]
    pub downgrade: McpDowngradePolicy,
}

fn default_federated_protocol() -> String {
    "auto".to_string()
}

/// Wire form of `federated_servers[].downgrade` (WOR-2384). See
/// [`McpFederatedServerConfig::downgrade`].
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpDowngradePolicy {
    /// Log and count a downgrade; the call proceeds.
    #[default]
    Warn,
    /// Refuse a call whose contact looks weaker than this peer's
    /// recorded profile.
    Block,
}

impl From<McpDowngradePolicy> for sbproxy_extension::mcp::peer_profile::PeerDowngradePolicy {
    fn from(value: McpDowngradePolicy) -> Self {
        match value {
            McpDowngradePolicy::Warn => {
                sbproxy_extension::mcp::peer_profile::PeerDowngradePolicy::Warn
            }
            McpDowngradePolicy::Block => {
                sbproxy_extension::mcp::peer_profile::PeerDowngradePolicy::Block
            }
        }
    }
}

impl McpDowngradePolicy {
    /// Wire name, used as one of the four [`sbproxy_extension::mcp::peer_profile::peer_key`]
    /// inputs so editing `downgrade:` alone still starts a fresh peer
    /// profile.
    fn peer_key_component(self) -> &'static str {
        match self {
            McpDowngradePolicy::Warn => "warn",
            McpDowngradePolicy::Block => "block",
        }
    }
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

/// Failure class for the pre-authentication MCP 2026-07-28 HTTP security
/// check. The gateway maps Origin failures to 403 and authority failures to
/// 421 without constructing a JSON-RPC body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpModernHttpRejection {
    /// No compiled trusted public origin exists for the action.
    MissingTrustAnchor,
    /// Host, `:authority`, connection scheme, or trusted authority disagrees.
    Authority,
    /// The browser Origin is malformed, duplicated, or not allowlisted.
    Origin,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CanonicalHttpOrigin {
    scheme: String,
    host: String,
    port: u16,
}

impl CanonicalHttpOrigin {
    fn parse_config(value: &str, field: &str) -> anyhow::Result<Self> {
        let parsed = url::Url::parse(value)
            .map_err(|_| anyhow::anyhow!("mcp action: {field} must be an HTTP(S) origin"))?;
        Self::from_url(&parsed)
            .ok_or_else(|| anyhow::anyhow!("mcp action: {field} must be an HTTP(S) origin"))
    }

    fn from_authority(scheme: &str, authority: &str) -> Option<Self> {
        if !matches!(scheme, "http" | "https") || authority.is_empty() {
            return None;
        }
        let parsed = url::Url::parse(&format!("{scheme}://{authority}")).ok()?;
        Self::from_url(&parsed)
    }

    fn from_url(parsed: &url::Url) -> Option<Self> {
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return None;
        }
        Some(Self {
            scheme: parsed.scheme().to_ascii_lowercase(),
            host: parsed.host_str()?.to_ascii_lowercase(),
            port: parsed.port_or_known_default()?,
        })
    }
}

#[derive(Debug, Clone)]
enum ModernHttpTrustAnchor {
    Explicit(CanonicalHttpOrigin),
    ExactRouteHost(String),
}

impl ModernHttpTrustAnchor {
    /// Whether `origin`, reached over `connection_scheme`, is an
    /// authority this gateway answers to.
    ///
    /// This is the authority test only. The browser `Origin` is a
    /// different question with a different answer, and comparing it
    /// through here would widen same-origin to mean same-host; see the
    /// `Origin` branch of `validate_request`.
    ///
    /// The two variants disagree about the port, deliberately. An
    /// explicit `public_origin` is the operator writing down the URL
    /// clients use, port included, so it is compared whole. A
    /// route-derived anchor is a hostname lifted from the origin key,
    /// which carries no port at all, so there is nothing to compare
    /// against; assuming the scheme's default would refuse every
    /// gateway not listening on 80 or 443, which is most of them.
    ///
    /// What the authority test establishes is that the request is
    /// addressed to a name this gateway serves, and the port is not part
    /// of that. An operator who wants the authority's port pinned as
    /// well says so with `public_origin`.
    fn matches(&self, connection_scheme: &str, origin: &CanonicalHttpOrigin) -> bool {
        match self {
            Self::Explicit(anchor) => origin == anchor,
            Self::ExactRouteHost(host) => {
                origin.scheme == connection_scheme && &origin.host == host
            }
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledModernHttpSecurity {
    trust_anchor: ModernHttpTrustAnchor,
    allowed_origins: HashSet<CanonicalHttpOrigin>,
    strict_parameter_headers: bool,
}

impl CompiledModernHttpSecurity {
    fn compile(config: &McpModernHttpConfig) -> anyhow::Result<Self> {
        let public_origin =
            CanonicalHttpOrigin::parse_config(&config.public_origin, "modern_http.public_origin")?;
        let mut allowed_origins = HashSet::with_capacity(config.allowed_origins.len() + 1);
        allowed_origins.insert(public_origin.clone());
        for origin in &config.allowed_origins {
            allowed_origins.insert(CanonicalHttpOrigin::parse_config(
                origin,
                "modern_http.allowed_origins[]",
            )?);
        }
        Ok(Self {
            trust_anchor: ModernHttpTrustAnchor::Explicit(public_origin),
            allowed_origins,
            strict_parameter_headers: config.strict_parameter_headers,
        })
    }

    fn derive_exact_route_host(route_host: &str) -> Option<Self> {
        if route_host.contains('*') {
            return None;
        }
        let parsed = url::Url::parse(&format!("http://{route_host}")).ok()?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.port().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return None;
        }
        Some(Self {
            trust_anchor: ModernHttpTrustAnchor::ExactRouteHost(
                parsed.host_str()?.to_ascii_lowercase(),
            ),
            allowed_origins: HashSet::new(),
            strict_parameter_headers: false,
        })
    }

    fn validate_request(
        &self,
        connection_scheme: &str,
        uri_authority: Option<&str>,
        headers: &http::HeaderMap,
    ) -> Result<(), McpModernHttpRejection> {
        let host_values: Vec<_> = headers.get_all("host").iter().collect();
        if host_values.len() > 1 {
            return Err(McpModernHttpRejection::Authority);
        }
        let host = host_values
            .first()
            .map(|value| value.to_str())
            .transpose()
            .map_err(|_| McpModernHttpRejection::Authority)?;
        let host_origin = match host {
            Some(value) => Some(
                CanonicalHttpOrigin::from_authority(connection_scheme, value)
                    .ok_or(McpModernHttpRejection::Authority)?,
            ),
            None => None,
        };
        let uri_origin = match uri_authority {
            Some(value) => Some(
                CanonicalHttpOrigin::from_authority(connection_scheme, value)
                    .ok_or(McpModernHttpRejection::Authority)?,
            ),
            None => None,
        };
        if let (Some(host_origin), Some(uri_origin)) = (&host_origin, &uri_origin) {
            if host_origin != uri_origin {
                return Err(McpModernHttpRejection::Authority);
            }
        }
        let request_origin = uri_origin
            .or(host_origin)
            .ok_or(McpModernHttpRejection::Authority)?;
        if !self
            .trust_anchor
            .matches(connection_scheme, &request_origin)
        {
            return Err(McpModernHttpRejection::Authority);
        }

        let origin_values: Vec<_> = headers.get_all("origin").iter().collect();
        if origin_values.len() > 1 {
            return Err(McpModernHttpRejection::Origin);
        }
        if let Some(value) = origin_values.first() {
            let value = value.to_str().map_err(|_| McpModernHttpRejection::Origin)?;
            let origin = CanonicalHttpOrigin::parse_config(value, "Origin")
                .map_err(|_| McpModernHttpRejection::Origin)?;
            // Same-origin is the web platform's definition, ports included,
            // and it is compared against a full origin under either anchor.
            // A declared `public_origin` is that origin. A derived anchor has
            // no port of its own, so the comparison uses the request's own
            // origin, which carries the port the client dialed and has just
            // been accepted as this gateway's.
            //
            // Reusing the port-blind anchor test here would be a real
            // widening rather than a convenience: a page served from
            // `http://localhost:3000` would count as same-origin with a
            // gateway on `http://localhost:8080` and could drive `tools/call`
            // from the browser. Ports are exactly what separates two local
            // origins.
            let trusted_origin = match &self.trust_anchor {
                ModernHttpTrustAnchor::Explicit(origin) => origin,
                ModernHttpTrustAnchor::ExactRouteHost(_) => &request_origin,
            };
            let is_same_origin = &origin == trusted_origin;
            if !is_same_origin && !self.allowed_origins.contains(&origin) {
                return Err(McpModernHttpRejection::Origin);
            }
        }
        Ok(())
    }
}

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
    /// Compiled tool-rollout plan (`tool_versioning.rollout`):
    /// versioned catalogue views, per-consumer resolution, adapters,
    /// and sunset handling. `None` when rollout is not configured.
    pub rollout_plan: Option<Arc<RolloutPlan>>,
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
    modern_http: Option<CompiledModernHttpSecurity>,
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
    /// Opt-in tool-output quarantine config (metadata; the live judge
    /// is [`Self::tool_output_judge`]).
    pub dual_llm_quarantine: Option<McpDualLlmQuarantineConfig>,
    /// Dual-LLM quarantine judge. Present when
    /// `dual_llm_quarantine.enabled` compiled successfully.
    pub tool_output_judge: Option<Arc<dyn sbproxy_extension::mcp::quarantine::ToolOutputJudge>>,
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
    /// True when outbound tool calls mint per-caller Authorization.
    pub run_as_user_auth: bool,
    /// Upstream auth minting config when `run_as_user_auth` is true.
    pub upstream_auth: Option<sbproxy_extension::mcp::auth::McpUpstreamAuthConfig>,
    /// Configured protocol pin: `"auto"` or a literal era string. See
    /// [`McpFederatedServerConfig::protocol`]. WOR-2384.
    pub protocol: String,
    /// Downgrade-resistance mode when `protocol == "auto"`. See
    /// [`McpFederatedServerConfig::downgrade`]. WOR-2384.
    pub downgrade: McpDowngradePolicy,
    /// This server entry's identity key in the peer-profile registry,
    /// computed once at compile time from `(name, origin, protocol,
    /// downgrade)`. See
    /// [`sbproxy_extension::mcp::peer_profile::peer_key`]. WOR-2384.
    pub peer_key: String,
}

impl McpServerPrefix {
    /// The pinned protocol era, or `None` for `protocol: auto`.
    pub fn protocol_pin(&self) -> Option<&str> {
        (self.protocol != "auto").then_some(self.protocol.as_str())
    }
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

/// HTTP judge transport for dual-LLM quarantine (WOR-1789 / GS).
///
/// Documents [`sbproxy_extension::mcp::quarantine::HttpToolOutputJudge::EGRESS_PURPOSE`]
/// (`EgressPurpose::AiJudge`). A process-level authorizer is not yet
/// threaded through `McpAction` compile; omitted authorizer preserves
/// the G2 legacy-allow posture for ungated destinations.
struct GovernedJudgeTransport {
    client: reqwest::Client,
    endpoint: String,
    timeout: Duration,
}

#[async_trait::async_trait]
impl sbproxy_extension::mcp::quarantine::JudgeTransport for GovernedJudgeTransport {
    async fn call_judge(
        &self,
        request_body: &[u8],
    ) -> Result<Vec<u8>, sbproxy_extension::mcp::quarantine::JudgeTransportError> {
        use sbproxy_extension::mcp::quarantine::JudgeTransportError;
        use sbproxy_security::egress::EgressPurpose;
        let _purpose = EgressPurpose::AiJudge;
        let _ = sbproxy_extension::mcp::quarantine::HttpToolOutputJudge::<Self>::EGRESS_PURPOSE;
        let request = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .body(request_body.to_vec());
        match tokio::time::timeout(self.timeout, request.send()).await {
            Err(_) => Err(JudgeTransportError::Timeout),
            Ok(Err(_)) => Err(JudgeTransportError::TransportFailure),
            Ok(Ok(resp)) => {
                if !resp.status().is_success() {
                    return Err(JudgeTransportError::TransportFailure);
                }
                match resp.bytes().await {
                    Ok(b) if !b.is_empty() => Ok(b.to_vec()),
                    _ => Err(JudgeTransportError::TransportFailure),
                }
            }
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
        let modern_http = cfg
            .modern_http
            .as_ref()
            .map(CompiledModernHttpSecurity::compile)
            .transpose()?;

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

        // WOR-2314: once any RBAC policy is declared, every federated
        // server must carry an explicit `rbac:` label. An unlabeled
        // server resolves no policy at dispatch time and would
        // silently allow every tool, undoing default-deny for exactly
        // the upstream the operator forgot to label. Deliberate
        // allow-all stays expressible: bind the server to a policy
        // with `default_allow: true`.
        if !cfg.rbac_policies.is_empty() {
            for upstream in &cfg.federated_servers {
                if upstream.rbac.is_none() {
                    anyhow::bail!(
                        "mcp action: federated_servers[] origin '{}' has no rbac label while rbac_policies are configured; add `rbac: <label>` (a policy with `default_allow: true` keeps deliberate allow-all)",
                        upstream.origin
                    );
                }
            }
        }

        // WOR-2384: a pinned `protocol:` must name one of the two eras
        // the gateway actually speaks; a typo here would otherwise
        // silently behave as if `protocol:` had never been set (the
        // upstream is compared against no pin), and the operator would
        // have no way to notice the pin never took effect.
        for upstream in &cfg.federated_servers {
            if upstream.protocol != "auto"
                && upstream.protocol != sbproxy_extension::mcp::types::LEGACY_PROTOCOL_VERSION
                && upstream.protocol != sbproxy_extension::mcp::types::MODERN_PROTOCOL_VERSION
            {
                anyhow::bail!(
                    "mcp action: federated_servers[].protocol '{}' must be \"auto\", \"{}\", or \"{}\" (origin '{}')",
                    upstream.protocol,
                    sbproxy_extension::mcp::types::LEGACY_PROTOCOL_VERSION,
                    sbproxy_extension::mcp::types::MODERN_PROTOCOL_VERSION,
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

            // WOR-1792: stdio + run-as-user is a hard config error until
            // a safe secret-delivery path exists for local children.
            if upstream.run_as_user_auth {
                let auth_cfg = upstream.upstream_auth.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "mcp action: federated_servers[].run_as_user_auth requires upstream_auth (origin '{}')",
                        upstream.origin
                    )
                })?;
                let kind = match transport.as_str() {
                    "stdio" => sbproxy_extension::mcp::auth::McpTransportKind::Stdio,
                    "sse" => sbproxy_extension::mcp::auth::McpTransportKind::Sse,
                    _ => sbproxy_extension::mcp::auth::McpTransportKind::Http,
                };
                sbproxy_extension::mcp::auth::validate_run_as_user_config(auth_cfg, kind).map_err(
                    |e| {
                        anyhow::anyhow!(
                            "mcp action: run_as_user_auth incompatible with transport '{}' on origin '{}': {e}",
                            transport,
                            upstream.origin
                        )
                    },
                )?;
            }

            // WOR-1648: an `openapi` server derives its tools from a
            // spec and dispatches REST; the origin is the REST base
            // URL, not an MCP endpoint.
            let is_openapi = upstream.server_type.as_deref() == Some("openapi");
            let is_stdio = transport == "stdio";

            // WOR-2314: static headers ride only on the OpenAPI REST
            // dispatch. On an MCP transport they would silently never
            // be sent, so reject rather than ignore.
            if !upstream.headers.is_empty() && !is_openapi {
                anyhow::bail!(
                    "mcp action: federated_servers[].headers requires type: openapi (origin '{}')",
                    upstream.origin
                );
            }
            if upstream.run_as_user_auth
                && upstream
                    .headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("authorization"))
            {
                anyhow::bail!(
                    "mcp action: openapi server '{}' sets both headers.authorization and run_as_user_auth; pick one",
                    upstream.origin
                );
            }
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
                        headers: upstream
                            .headers
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
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
            // WOR-2384: computed before `upstream.protocol` /
            // `upstream.downgrade` are moved into the struct literal
            // below. Any edit to `name`, `origin`, `protocol`, or
            // `downgrade` on this entry produces a different key, which
            // is the entire "reload of the server entry resets the
            // profile" mechanism -- see `peer_key`'s doc comment.
            let peer_key = sbproxy_extension::mcp::peer_profile::peer_key(
                &name,
                &upstream.origin,
                &upstream.protocol,
                upstream.downgrade.peer_key_component(),
            );
            prefixes.insert(
                name.clone(),
                McpServerPrefix {
                    name,
                    prefix: upstream.prefix,
                    rbac: upstream.rbac,
                    timeout: upstream.timeout,
                    run_as_user_auth: upstream.run_as_user_auth,
                    upstream_auth: upstream.upstream_auth,
                    protocol: upstream.protocol,
                    downgrade: upstream.downgrade,
                    peer_key,
                },
            );
        }

        // WOR-1635: parse the versioning gate. Declared versions
        // must be valid semver; a typo here is a config error, not a
        // silent no-op at refresh time.
        let rollout_plan = compile_rollout(cfg.tool_versioning.as_ref(), &server_configs)?;

        let versioning = match cfg.tool_versioning.as_ref() {
            None => None,
            Some(tv) => match tv.lockfile.as_deref() {
                None => {
                    if !tv.declared_versions.is_empty() || !tv.judges.is_empty() {
                        anyhow::bail!(
                            "mcp action: tool_versioning.declared_versions and \
                             tool_versioning.judges require tool_versioning.lockfile"
                        );
                    }
                    None
                }
                Some(lockfile) => {
                    if lockfile.trim().is_empty() {
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
                        lockfile_path: lockfile.to_string(),
                        declared_versions,
                        mode: match tv.mode {
                            McpVersioningModeConfig::Warn => VersioningMode::Warn,
                            McpVersioningModeConfig::Block => VersioningMode::Block,
                        },
                        block_unlocked: tv.block_unlocked,
                        judges,
                    })
                }
            },
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

        let dual_llm_quarantine = cfg.dual_llm_quarantine.filter(|c| c.enabled);
        let tool_output_judge = match dual_llm_quarantine.as_ref() {
            Some(qcfg) => {
                let endpoint = qcfg
                    .endpoint
                    .as_deref()
                    .filter(|e| !e.is_empty())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "mcp action: dual_llm_quarantine.enabled requires dual_llm_quarantine.endpoint"
                        )
                    })?
                    .to_string();
                let timeout = qcfg.timeout.unwrap_or(Duration::from_secs(10));
                let transport = GovernedJudgeTransport {
                    client: reqwest::Client::new(),
                    endpoint,
                    timeout,
                };
                let judge = sbproxy_extension::mcp::quarantine::HttpToolOutputJudge::new(
                    transport,
                    sbproxy_extension::mcp::quarantine::DualLlmJudgeConfig {
                        timeout,
                        model: qcfg.model.clone(),
                    },
                );
                Some(Arc::new(judge)
                    as Arc<
                        dyn sbproxy_extension::mcp::quarantine::ToolOutputJudge,
                    >)
            }
            None => None,
        };

        Ok(Self {
            mode: cfg.mode,
            server_name,
            server_version,
            prefixes,
            rbac_policies: cfg.rbac_policies,
            federation,
            rollout_plan,
            tool_allowlist,
            lethal_trifecta,
            progressive_discovery: cfg.progressive_discovery,
            oauth: cfg.oauth,
            modern_http,
            quota_store: Arc::new(ToolQuotaStore::new()),
            refresh_interval: cfg.refresh_interval.unwrap_or(Duration::from_secs(60)),
            has_principal_scoped_tools,
            sessions: cfg.sessions.as_ref().filter(|s| s.enabled).map(|s| {
                Arc::new(SessionStore::new(
                    s.ttl.unwrap_or(Duration::from_secs(30 * 60)),
                ))
            }),
            token_compaction: cfg.token_compaction.filter(|c| c.enabled),
            dual_llm_quarantine,
            tool_output_judge,
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
    /// Config compile requires an `rbac` label on every federated
    /// server once any `rbac_policies` are declared (WOR-2314), so
    /// this returns `None` only for actions with no RBAC configured
    /// at all (or an unknown server name). The dispatcher treats
    /// `None` as allowed, which preserves the behavior of non-RBAC
    /// deployments. WOR-186.
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

    /// Upstream auth minting config for a run-as-user server.
    pub fn upstream_auth_for_server(
        &self,
        server_name: &str,
    ) -> Option<&sbproxy_extension::mcp::auth::McpUpstreamAuthConfig> {
        self.prefix_for(server_name)?.upstream_auth.as_ref()
    }

    /// Dual-LLM quarantine judge when configured.
    pub fn tool_output_judge(
        &self,
    ) -> Option<&dyn sbproxy_extension::mcp::quarantine::ToolOutputJudge> {
        self.tool_output_judge.as_deref()
    }

    /// Bind an exact configured route hostname as the modern HTTP trust
    /// anchor when the action did not declare an explicit `modern_http`
    /// origin. Wildcard and otherwise non-canonical route keys remain
    /// unbound and therefore fail closed for modern traffic.
    ///
    /// The binding is idempotent: an explicit origin or an earlier exact
    /// route binding is never overwritten. The request's authenticated
    /// connection scheme supplies the HTTP(S) scheme at validation time. It
    /// supplies no port, and none is assumed: an origin key names a host, so
    /// a derived anchor compares the host and takes the client at its word
    /// about which port it dialed. An operator who wants the port pinned
    /// declares `modern_http.public_origin`.
    pub fn bind_exact_route_authority(&mut self, route_host: &str) {
        if self.modern_http.is_none() {
            self.modern_http = CompiledModernHttpSecurity::derive_exact_route_host(route_host);
        }
    }

    /// Validate the trusted authority and optional browser Origin for a
    /// 2026-07-28 HTTP request. Call this before authentication, catalogue
    /// priming, policy evaluation, or upstream access.
    pub fn validate_modern_http_request(
        &self,
        connection_scheme: &str,
        uri_authority: Option<&str>,
        headers: &http::HeaderMap,
    ) -> Result<(), McpModernHttpRejection> {
        self.modern_http
            .as_ref()
            .ok_or(McpModernHttpRejection::MissingTrustAnchor)?
            .validate_request(connection_scheme, uri_authority, headers)
    }

    /// Whether the configured authoritative endpoint rejects unknown
    /// `Mcp-Param-*` headers rather than transparently ignoring them.
    pub fn strict_modern_parameter_headers(&self) -> bool {
        self.modern_http
            .as_ref()
            .is_some_and(|security| security.strict_parameter_headers)
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

    /// Build the immutable catalogue source a pipeline may expose to an AI
    /// virtual key for this MCP action.
    ///
    /// Construction is pure. The owning compiled pipeline installs the
    /// returned source under its route tenant only after the entire candidate
    /// generation has compiled successfully. Keeping
    /// registration out of action construction prevents a rejected reload
    /// from mutating the live request path.
    pub fn inject_source(&self) -> Arc<McpInjectSource> {
        Arc::new(McpInjectSource {
            federation: Arc::clone(&self.federation),
            prefixes: self.prefixes.clone(),
            rbac_policies: self.rbac_policies.clone(),
            tool_allowlist: self.tool_allowlist.clone(),
        })
    }

    /// Look up the per-server prefix entry by name.
    pub fn prefix_for(&self, server_name: &str) -> Option<&McpServerPrefix> {
        self.prefixes.get(server_name)
    }
}

/// Compile the `tool_versioning.rollout` block into a validated
/// [`RolloutPlan`]: semver and requirement parsing, server-name
/// checks against the federated set, and adapter runtime checks.
fn compile_rollout(
    tv: Option<&McpToolVersioningConfig>,
    server_configs: &[McpServerConfig],
) -> anyhow::Result<Option<Arc<RolloutPlan>>> {
    let Some(r) = tv.and_then(|tv| tv.rollout.as_ref()) else {
        return Ok(None);
    };
    let server_names: HashSet<&str> = server_configs.iter().map(|s| s.name.as_str()).collect();

    let mut tools = HashMap::new();
    for (name, t) in &r.tools {
        let mut versions = Vec::with_capacity(t.versions.len());
        for vc in &t.versions {
            if let Some(server) = &vc.server {
                if !server_names.contains(server.as_str()) {
                    anyhow::bail!(
                        "mcp action: rollout tool '{name}' version '{}': unknown \
                         federated server '{server}' (known: {})",
                        vc.version,
                        {
                            let mut known: Vec<&str> = server_names.iter().copied().collect();
                            known.sort_unstable();
                            known.join(", ")
                        }
                    );
                }
            }
            let adapter = match &vc.adapter {
                None => None,
                Some(a) => {
                    for adapter_ref in [&a.request, &a.response].into_iter().flatten() {
                        if !adapter_ref.starts_with("js:") {
                            anyhow::bail!(
                                "mcp action: rollout tool '{name}' version '{}': \
                                 adapter '{adapter_ref}' must be a js: reference \
                                 (only JavaScript adapters are supported today)",
                                vc.version
                            );
                        }
                    }
                    Some(AdapterPair {
                        request: a.request.clone(),
                        response: a.response.clone(),
                    })
                }
            };
            versions.push(VersionSpec {
                version: vc.version.clone(),
                server: vc.server.clone(),
                adapter,
                contract: vc.contract.clone(),
                sunset: vc.sunset.clone(),
                after_sunset: match vc.after_sunset {
                    McpSunsetBehaviorConfig::Warn => SunsetBehavior::Warn,
                    McpSunsetBehaviorConfig::Block => SunsetBehavior::Block,
                },
            });
        }
        tools.insert(
            name.clone(),
            ToolRolloutSpec {
                versions,
                default: t.default.clone(),
                aliases: t.aliases,
            },
        );
    }

    let mut pins = Vec::new();
    for p in &r.pins {
        if p.principals.is_empty() {
            // An empty selector list pins every principal.
            pins.push(PinSpec {
                selector: McpPrincipalSelector::default(),
                requirements: p.tools.clone(),
            });
        } else {
            for sel in &p.principals {
                pins.push(PinSpec {
                    selector: sel.clone(),
                    requirements: p.tools.clone(),
                });
            }
        }
    }

    let plan = RolloutPlan::compile(&RolloutSpec { tools, pins })
        .map_err(|e| anyhow::anyhow!("mcp action: {e}"))?;
    Ok(Some(Arc::new(plan)))
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
    tool_allowlist: Option<HashSet<String>>,
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
        // Discovery and the version-gate verdict must come from one
        // publication. A fresh verdict lookup after this list load could
        // otherwise expose a refused entry during a catalogue refresh.
        let catalog = self.federation.tool_catalog_snapshot();
        let snapshot = catalog.serialized_tools();
        let version_blocked = catalog.version_blocked();
        let mut out = Vec::new();
        for entry in &snapshot.entries {
            if version_blocked.contains_key(&entry.name) {
                continue;
            }
            if self
                .tool_allowlist
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&entry.name))
            {
                continue;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn federated_tool(name: &str, server: &str) -> sbproxy_extension::mcp::FederatedTool {
        let input_schema = json!({"type": "object", "properties": {}});
        let contract = sbproxy_extension::mcp::protocol::McpToolContract::try_from(json!({
            "name": name,
            "description": "injected fixture",
            "inputSchema": input_schema.clone(),
        }))
        .expect("injected fixture contract");
        sbproxy_extension::mcp::FederatedTool {
            name: name.to_string(),
            description: "injected fixture".to_string(),
            input_schema,
            server_name: server.to_string(),
            streaming: false,
            meta: None,
            contract: Some(contract),
            legacy_document: None,
            modern_contract: None,
            modern_incompatibility: None,
        }
    }

    // --- Tool rollout plane ---

    fn openapi_server(prefix: &str, origin: &str) -> serde_json::Value {
        json!({
            "type": "openapi",
            "origin": origin,
            "prefix": prefix,
            "spec": {
                "openapi": "3.0.0",
                "info": {"title": "t", "version": "1"},
                "paths": {"/search": {"get": {"operationId": "search"}}}
            }
        })
    }

    fn rollout_action(rollout: serde_json::Value) -> serde_json::Value {
        json!({
            "type": "mcp",
            "mode": "gateway",
            "egress": {
                "mode": "deny_by_default",
                "hosts": ["legacy.example.com", "new.example.com"]
            },
            "federated_servers": [
                openapi_server("legacy-api", "legacy.example.com"),
                openapi_server("new-api", "new.example.com")
            ],
            "tool_versioning": {"rollout": rollout}
        })
    }

    fn modern_http_action(modern_http: serde_json::Value) -> McpAction {
        McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "modern_http": modern_http,
            "federated_servers": [{ "origin": "upstream.example.com" }]
        }))
        .expect("modern HTTP fixture must compile")
    }

    #[test]
    fn task_5c_modern_http_compiles_exact_public_and_allowed_origins() {
        let action = modern_http_action(json!({
            "public_origin": "https://mcp.example.com",
            "allowed_origins": [
                "https://console.example.com:443",
                "http://localhost:3000"
            ],
            "strict_parameter_headers": true
        }));

        let mut same_origin = http::HeaderMap::new();
        same_origin.append("host", "mcp.example.com:443".parse().unwrap());
        same_origin.append("origin", "https://mcp.example.com".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", Some("mcp.example.com"), &same_origin,),
            Ok(())
        );

        let mut allowlisted = http::HeaderMap::new();
        allowlisted.append("host", "mcp.example.com".parse().unwrap());
        allowlisted.append("origin", "https://console.example.com".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", None, &allowlisted),
            Ok(())
        );

        let mut non_browser = http::HeaderMap::new();
        non_browser.append("host", "mcp.example.com".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", None, &non_browser),
            Ok(())
        );
        assert!(action.strict_modern_parameter_headers());
    }

    #[test]
    fn task_5c_modern_http_rejects_untrusted_authority_and_origin_separately() {
        let action = modern_http_action(json!({
            "public_origin": "https://mcp.example.com:443",
            "allowed_origins": ["https://console.example.com"]
        }));

        let mut evil = http::HeaderMap::new();
        evil.append("host", "evil.example".parse().unwrap());
        evil.append("origin", "https://evil.example".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", None, &evil),
            Err(McpModernHttpRejection::Authority)
        );

        let mut denied_origin = http::HeaderMap::new();
        denied_origin.append("host", "mcp.example.com".parse().unwrap());
        denied_origin.append("origin", "https://evil.example".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", None, &denied_origin),
            Err(McpModernHttpRejection::Origin)
        );

        let mut conflicting = http::HeaderMap::new();
        conflicting.append("host", "mcp.example.com".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", Some("other.example.com"), &conflicting,),
            Err(McpModernHttpRejection::Authority)
        );

        let mut duplicate_host = http::HeaderMap::new();
        duplicate_host.append("host", "mcp.example.com".parse().unwrap());
        duplicate_host.append("host", "mcp.example.com".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", None, &duplicate_host),
            Err(McpModernHttpRejection::Authority)
        );

        let mut duplicate_origin = http::HeaderMap::new();
        duplicate_origin.append("host", "mcp.example.com".parse().unwrap());
        duplicate_origin.append("origin", "https://mcp.example.com".parse().unwrap());
        duplicate_origin.append("origin", "https://mcp.example.com".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", None, &duplicate_origin),
            Err(McpModernHttpRejection::Origin)
        );
    }

    #[test]
    fn a_route_derived_anchor_takes_the_client_at_its_word_about_the_port() {
        // The bug this pins: a gateway on 8080 whose origin key is a bare
        // hostname used to assume port 80 and refuse every real client, since
        // a client dialing 8080 sends `Host: mcp.example.com:8080`.
        let mut action = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{ "origin": "upstream.example.com" }]
        }))
        .expect("legacy-only MCP config remains valid");
        action.bind_exact_route_authority("mcp.example.com");

        for authority in [
            "mcp.example.com",
            "mcp.example.com:80",
            "mcp.example.com:8080",
        ] {
            let mut headers = http::HeaderMap::new();
            headers.append("host", authority.parse().unwrap());
            assert_eq!(
                action.validate_modern_http_request("http", None, &headers),
                Ok(()),
                "{authority}"
            );
        }

        // The host is still compared, which is the half that stops a page on
        // another site from reaching this gateway.
        let mut wrong_host = http::HeaderMap::new();
        wrong_host.append("host", "evil.example.com:8080".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("http", None, &wrong_host),
            Err(McpModernHttpRejection::Authority)
        );

        // And so is the scheme, so an `Origin` naming plain HTTP is not the
        // same origin as the HTTPS endpoint that served the page.
        let mut downgraded_origin = http::HeaderMap::new();
        downgraded_origin.append("host", "mcp.example.com:8443".parse().unwrap());
        downgraded_origin.append("origin", "http://mcp.example.com".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", None, &downgraded_origin),
            Err(McpModernHttpRejection::Origin)
        );
    }

    #[test]
    fn a_page_on_another_port_of_the_same_host_is_not_same_origin() {
        // Loosening the authority test must not loosen the browser one.
        // This is the canonical local shape: a dev server or a local tool's
        // UI on one port, the gateway on another. The web platform calls
        // those different origins, and so does this.
        let mut action = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{ "origin": "upstream.example.com" }]
        }))
        .expect("legacy-only MCP config remains valid");
        action.bind_exact_route_authority("localhost");

        let mut cross_port = http::HeaderMap::new();
        cross_port.append("host", "localhost:8080".parse().unwrap());
        cross_port.append("origin", "http://localhost:3000".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("http", None, &cross_port),
            Err(McpModernHttpRejection::Origin)
        );

        // The gateway's own page still is, on whatever port it runs.
        let mut same_port = http::HeaderMap::new();
        same_port.append("host", "localhost:8080".parse().unwrap());
        same_port.append("origin", "http://localhost:8080".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("http", None, &same_port),
            Ok(())
        );
    }

    #[test]
    fn a_declared_public_origin_still_compares_the_port() {
        // The escape hatch: an operator who writes the port down gets it
        // matched, which is the whole reason `public_origin` exists.
        let action = modern_http_action(json!({
            "public_origin": "https://mcp.example.com"
        }));

        let mut declared = http::HeaderMap::new();
        declared.append("host", "mcp.example.com:443".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", None, &declared),
            Ok(())
        );

        let mut other_port = http::HeaderMap::new();
        other_port.append("host", "mcp.example.com:8443".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", None, &other_port),
            Err(McpModernHttpRejection::Authority)
        );
    }

    #[test]
    fn task_5c_modern_http_fails_closed_without_a_trust_anchor() {
        let action = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{ "origin": "upstream.example.com" }]
        }))
        .expect("legacy-only MCP config remains valid");
        let mut headers = http::HeaderMap::new();
        headers.append("host", "mcp.example.com".parse().unwrap());
        assert_eq!(
            action.validate_modern_http_request("https", None, &headers),
            Err(McpModernHttpRejection::MissingTrustAnchor)
        );
    }

    #[test]
    fn task_5c_modern_http_rejects_non_origin_configuration() {
        for public_origin in [
            "ftp://mcp.example.com",
            "https://user@mcp.example.com",
            "https://mcp.example.com/path",
            "https://mcp.example.com/?query=1",
            "https://mcp.example.com/#fragment",
        ] {
            let error = McpAction::from_config(json!({
                "type": "mcp",
                "mode": "gateway",
                "modern_http": { "public_origin": public_origin },
                "federated_servers": [{ "origin": "upstream.example.com" }]
            }))
            .expect_err("non-origin public value must fail config compile");
            assert!(
                error.to_string().contains("modern_http.public_origin"),
                "configuration error must identify the field: {error}"
            );
        }
    }

    #[test]
    fn task_5c_modern_http_rejects_unknown_hardening_fields() {
        let error = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "modern_http": {
                "public_origin": "https://mcp.example.com",
                "strict_parameter_header": true
            },
            "federated_servers": [{ "origin": "upstream.example.com" }]
        }))
        .expect_err("a misspelled hardening field must fail config compilation");

        let message = error.to_string();
        assert!(message.contains("strict_parameter_header"), "{message}");
    }

    #[test]
    fn rollout_compiles_without_lockfile_and_exposes_plan() {
        let action = McpAction::from_config(rollout_action(json!({
            "tools": {"search": {"versions": [
                {"version": "1.4.0", "server": "legacy-api"},
                {"version": "2.0.0", "server": "new-api"}
            ]}}
        })))
        .expect("compile");
        let plan = action.rollout_plan.as_ref().expect("rollout plan");
        assert!(plan.manages("search"));
        // Aliases are on by default.
        assert!(plan.manages("search_v1"));
        assert!(plan.manages("search_v2"));
    }

    #[test]
    fn rollout_rejects_unknown_server() {
        let err = McpAction::from_config(rollout_action(json!({
            "tools": {"search": {"versions": [
                {"version": "1.4.0", "server": "no-such-server"}
            ]}}
        })))
        .expect_err("unknown server must fail config compile");
        assert!(
            err.to_string().contains("unknown federated server"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rollout_rejects_non_js_adapter() {
        let err = McpAction::from_config(rollout_action(json!({
            "tools": {"search": {"versions": [
                {"version": "1.4.0", "adapter": {"request": "cel:args"}},
                {"version": "2.0.0", "server": "new-api"}
            ]}}
        })))
        .expect_err("non-js adapter must fail config compile");
        assert!(err.to_string().contains("js:"), "unexpected error: {err}");
    }

    #[test]
    fn rollout_rejects_bad_pin_requirement() {
        let err = McpAction::from_config(rollout_action(json!({
            "tools": {"search": {"versions": [
                {"version": "2.0.0", "server": "new-api"}
            ]}},
            "pins": [{"principals": [{"team": "checkout"}],
                      "tools": {"search": "not a range"}}]
        })))
        .expect_err("bad pin requirement must fail config compile");
        assert!(
            err.to_string().contains("semver range"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn declared_versions_without_lockfile_is_config_error() {
        let err = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "egress": {"mode": "deny_by_default", "hosts": ["legacy.example.com"]},
            "federated_servers": [openapi_server("legacy-api", "legacy.example.com")],
            "tool_versioning": {"declared_versions": {"search": "1.0.0"}}
        }))
        .expect_err("declared_versions without lockfile must fail");
        assert!(
            err.to_string().contains("lockfile"),
            "unexpected error: {err}"
        );
    }

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
    fn openapi_server_accepts_static_headers() {
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{
                "type": "openapi",
                "origin": "http://127.0.0.1:9090",
                "headers": {"authorization": "Basic c2VydmljZTpzZWNyZXQ="},
                "spec": {
                    "openapi": "3.0.0",
                    "info": {"title": "t", "version": "1"},
                    "paths": {"/api/health": {"get": {"operationId": "get_health"}}}
                }
            }]
        });
        let action = McpAction::from_config(value).expect("compile");
        assert_eq!(action.prefixes.len(), 1);
    }

    #[test]
    fn static_headers_on_mcp_server_is_config_error() {
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{
                "origin": "github.example.com",
                "headers": {"x-team": "frontend"}
            }]
        });
        let err = McpAction::from_config(value).expect_err("headers need type: openapi");
        assert!(
            err.to_string().contains("requires type: openapi"),
            "error must name the constraint, got: {err}"
        );
    }

    #[test]
    fn static_authorization_plus_run_as_user_is_config_error() {
        let value = json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{
                "type": "openapi",
                "origin": "http://api.internal.example",
                "headers": {"Authorization": "Basic c2VydmljZTpzZWNyZXQ="},
                "run_as_user_auth": true,
                "upstream_auth": {
                    "type": "service_credential",
                    "credential_ref": "vault://svc"
                },
                "spec": {
                    "openapi": "3.0.0",
                    "info": {"title": "t", "version": "1"},
                    "paths": {"/pets": {"get": {"operationId": "listPets"}}}
                }
            }]
        });
        let err = McpAction::from_config(value).expect_err("two credential sources must fail");
        assert!(
            err.to_string().contains("pick one"),
            "error must tell the operator to pick one source, got: {err}"
        );
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
                "run_as_user_auth": true,
                "upstream_auth": {
                    "type": "per_user_credential",
                    "credential_template": "vault://users/{subject_id}/token"
                }
            }]
        });

        let action = McpAction::from_config(value).expect("compile");
        assert!(action.run_as_user_for_server("gh"));
        assert!(!action.run_as_user_for_server("missing"));
        assert!(action.upstream_auth_for_server("gh").is_some());
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
                "endpoint": "https://judge.example/v1/chat/completions",
                "model": "judge-model"
            },
            "federated_servers": [{ "origin": "example.com" }]
        }))
        .expect("compile");

        let cfg = action.dual_llm_quarantine.as_ref().expect("enabled");
        assert_eq!(
            cfg.endpoint.as_deref(),
            Some("https://judge.example/v1/chat/completions")
        );
        assert_eq!(cfg.model.as_deref(), Some("judge-model"));
        assert!(action.tool_output_judge().is_some());
    }

    #[test]
    fn dual_llm_quarantine_requires_endpoint_when_enabled() {
        let err = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "dual_llm_quarantine": { "enabled": true },
            "federated_servers": [{ "origin": "example.com" }]
        }))
        .expect_err("endpoint required");
        assert!(
            err.to_string().contains("endpoint"),
            "error must mention endpoint, got: {err}"
        );
    }

    #[test]
    fn stdio_plus_run_as_user_is_config_error() {
        let err = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{
                "origin": "local-tools",
                "transport": "stdio",
                "command": "/usr/bin/true",
                "run_as_user_auth": true,
                "upstream_auth": {
                    "type": "service_credential",
                    "credential_ref": "vault://svc"
                }
            }]
        }))
        .expect_err("stdio + run_as_user must fail");
        assert!(
            err.to_string().contains("run_as_user") || err.to_string().contains("stdio"),
            "error must mention run_as_user/stdio, got: {err}"
        );
    }

    #[test]
    fn run_as_user_requires_upstream_auth_config() {
        let err = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "federated_servers": [{
                "origin": "github.example.com",
                "prefix": "gh",
                "run_as_user_auth": true
            }]
        }))
        .expect_err("upstream_auth required");
        assert!(
            err.to_string().contains("upstream_auth"),
            "error must mention upstream_auth, got: {err}"
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
    fn inject_source_builds_and_resolves_rbac_filtered() {
        // A gateway with a default-deny policy allowing only `search`
        // builds an immutable source; resolving it for an anonymous
        // principal yields just the allowed tool.
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
            map.insert(name.to_string(), federated_tool(name, "gh"));
        }
        action.federation.seed_tools_for_test(map, None);

        let source = action.inject_source();
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
    fn task_5b_injected_catalogue_omits_version_blocked_tools() {
        let action = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "server_info": {"name": "task-5b-version-blocked-injection", "version": "1.0.0"},
            "federated_servers": [
                {"origin": "test.sbproxy.dev", "prefix": "gh"}
            ]
        }))
        .expect("fixture config compiles");
        action.federation.seed_tools_for_test(
            std::collections::HashMap::from([(
                "gh.search".to_string(),
                federated_tool("gh.search", "gh"),
            )]),
            Some(std::collections::HashMap::from([(
                "gh.search".to_string(),
                "version policy refuses this tool".to_string(),
            )])),
        );

        let source = action.inject_source();
        let tools = source.resolve_tools(
            &sbproxy_plugin::Principal::anonymous(),
            &[],
            sbproxy_ai::identity::McpToolFormat::Openai,
        );
        assert!(
            tools.is_empty(),
            "an injected catalogue must not expose a tool the version gate refuses"
        );
    }

    #[test]
    fn task_5b_injected_catalogue_composes_allowlist_rbac_and_version_gate() {
        let action = McpAction::from_config(json!({
            "type": "mcp",
            "mode": "gateway",
            "server_info": {"name": "task-5b-composed-injection", "version": "1.0.0"},
            "rbac_policies": {
                "reader": {
                    "default_allow": false,
                    "tool_access": [{
                        "principals": [],
                        "allowed": [
                            "gh.allowed",
                            "gh.not_allowlisted",
                            "gh.blocked_version"
                        ]
                    }]
                }
            },
            "federated_servers": [{
                "origin": "test.sbproxy.dev",
                "prefix": "gh",
                "rbac": "reader"
            }],
            "guardrails": [{
                "type": "tool_allowlist",
                "allow": ["gh.allowed", "gh.denied_rbac", "gh.blocked_version"]
            }]
        }))
        .expect("composed injection fixture compiles");
        action.federation.seed_tools_for_test(
            std::collections::HashMap::from([
                ("gh.allowed".to_string(), federated_tool("gh.allowed", "gh")),
                (
                    "gh.not_allowlisted".to_string(),
                    federated_tool("gh.not_allowlisted", "gh"),
                ),
                (
                    "gh.denied_rbac".to_string(),
                    federated_tool("gh.denied_rbac", "gh"),
                ),
                (
                    "gh.blocked_version".to_string(),
                    federated_tool("gh.blocked_version", "gh"),
                ),
            ]),
            Some(std::collections::HashMap::from([(
                "gh.blocked_version".to_string(),
                "version policy refuses this tool".to_string(),
            )])),
        );

        let tools = action.inject_source().resolve_tools(
            &sbproxy_plugin::Principal::anonymous(),
            &["gh.*".to_string()],
            sbproxy_ai::identity::McpToolFormat::Openai,
        );
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|tool| tool["function"]["name"].as_str())
            .collect();
        assert_eq!(
            names,
            vec!["gh.allowed"],
            "virtual-key injection must expose the intersection of the request filter, action allowlist, RBAC, and held version verdict"
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

    /// WOR-2314: once `rbac_policies` exist, an unlabeled federated
    /// server is a hard config error naming that server, instead of
    /// a silent allow-all for exactly the upstream the operator
    /// forgot to label.
    #[test]
    fn rejects_unlabeled_server_when_rbac_policies_configured() {
        let value = json!({
            "type": "mcp",
            "rbac_policies": {
                "read_only": { "default_allow": false, "tool_access": [] }
            },
            "federated_servers": [
                { "origin": "github.example.com", "prefix": "gh", "rbac": "read_only" },
                { "origin": "postgres.example.com", "prefix": "db" }
            ]
        });
        let err = McpAction::from_config(value).unwrap_err().to_string();
        assert!(
            err.contains("postgres.example.com"),
            "error must name the unlabeled server, got: {err}",
        );
        assert!(
            err.contains("rbac"),
            "error must point at the missing rbac label, got: {err}",
        );
    }

    /// Deliberate allow-all stays expressible under WOR-2314: bind
    /// the server to a policy with `default_allow: true`.
    #[test]
    fn explicit_allow_all_label_still_compiles() {
        let value = json!({
            "type": "mcp",
            "rbac_policies": {
                "legacy_open": { "default_allow": true }
            },
            "federated_servers": [
                { "origin": "github.example.com", "prefix": "gh", "rbac": "legacy_open" }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        let policy = action.policy_for_server("gh").expect("gh policy");
        assert!(policy.default_allow);
    }

    /// An action that declares no `rbac_policies` at all keeps the
    /// legacy open behavior: unlabeled servers compile and resolve
    /// no policy, and the dispatcher allows every tool (WOR-2314).
    #[test]
    fn unlabeled_servers_unchanged_without_rbac_policies() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "github.example.com", "prefix": "gh" }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        assert!(action.policy_for_server("gh").is_none());
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
                upstream_auth: None,
                transport: None,
                command: None,
                args: Vec::new(),
                server_type: None,
                spec: None,
                spec_path: None,
                headers: BTreeMap::new(),
                egress: None,
                protocol: default_federated_protocol(),
                downgrade: McpDowngradePolicy::default(),
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

    // --- WOR-2384: federated_servers[].protocol / .downgrade ---

    #[test]
    fn protocol_and_downgrade_default_to_auto_and_warn() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "example.com" }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        let prefix = action
            .prefixes
            .values()
            .next()
            .expect("one federated server compiled");
        assert_eq!(prefix.protocol, "auto");
        assert_eq!(prefix.protocol_pin(), None);
        assert_eq!(prefix.downgrade, McpDowngradePolicy::Warn);
    }

    #[test]
    fn a_pinned_legacy_protocol_compiles_and_is_reported_by_protocol_pin() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "example.com", "protocol": "2025-06-18", "downgrade": "block" }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        let prefix = action.prefixes.values().next().expect("compiled");
        assert_eq!(prefix.protocol_pin(), Some("2025-06-18"));
        assert_eq!(prefix.downgrade, McpDowngradePolicy::Block);
    }

    #[test]
    fn a_pinned_modern_protocol_compiles() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "example.com", "protocol": "2026-07-28" }
            ]
        });
        let action = McpAction::from_config(value).expect("compile");
        let prefix = action.prefixes.values().next().expect("compiled");
        assert_eq!(prefix.protocol_pin(), Some("2026-07-28"));
    }

    #[test]
    fn an_unrecognised_protocol_pin_is_rejected() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "example.com", "protocol": "2025-03-26" }
            ]
        });
        let err = McpAction::from_config(value).expect_err("unknown era must be refused");
        assert!(
            err.to_string().contains("federated_servers[].protocol"),
            "error should name the offending key: {err}"
        );
    }

    #[test]
    fn an_unrecognised_downgrade_mode_is_rejected_by_serde() {
        let value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "example.com", "downgrade": "ignore" }
            ]
        });
        assert!(McpAction::from_config(value).is_err());
    }

    #[test]
    fn editing_downgrade_alone_changes_the_peer_key() {
        // The peer_key is one of the mechanisms behind "reload of the
        // server entry resets the profile" (see
        // `sbproxy_extension::mcp::peer_profile::peer_key`); this pins
        // that even a same-origin, same-protocol-pin edit to only
        // `downgrade:` still produces a different compiled key.
        let warn_value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "example.com", "downgrade": "warn" }
            ]
        });
        let block_value = json!({
            "type": "mcp",
            "federated_servers": [
                { "origin": "example.com", "downgrade": "block" }
            ]
        });
        let warn_action = McpAction::from_config(warn_value).expect("compile");
        let block_action = McpAction::from_config(block_value).expect("compile");
        let warn_key = &warn_action
            .prefixes
            .values()
            .next()
            .expect("compiled")
            .peer_key;
        let block_key = &block_action
            .prefixes
            .values()
            .next()
            .expect("compiled")
            .peer_key;
        assert_ne!(warn_key, block_key);
    }
}
