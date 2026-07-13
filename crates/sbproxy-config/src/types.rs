//! Configuration structs that map directly to the YAML config format.
//!
//! These types are serde-deserializable and represent the user-facing
//! config surface. Plugin-specific fields (action, auth, policies, etc.)
//! are kept as `serde_json::Value` for deferred parsing by the module layer.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Top-Level Config ---

/// Top-level config file structure (sb.yml).
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ConfigFile {
    /// Optional source descriptor.
    ///
    /// When set, the config compiler resolves the listed source(s)
    /// before parsing the rest of the file. The remaining fields on
    /// `ConfigFile` are still honored: the file the source resolves
    /// to is itself a `ConfigFile`. When unset (the historical
    /// default), the file is treated as inline config.
    #[serde(default)]
    pub source: Option<ConfigSource>,
    /// Server-wide settings parsed from the top-level `proxy:` block.
    #[serde(default)]
    pub proxy: ProxyServerConfig,
    /// Map of hostname to per-origin configuration.
    #[serde(default)]
    pub origins: HashMap<String, RawOriginConfig>,
    /// Optional structured-JSON access-log emission, off by default.
    /// When enabled, every completed request emits one JSON line via
    /// the tracing `access_log` target. See [`AccessLogConfig`] for
    /// filtering and sampling controls.
    #[serde(default)]
    pub access_log: Option<AccessLogConfig>,
    /// Top-level agent-class catalog selection and resolver tuning.
    /// When unset, the binary constructs a resolver from the embedded
    /// default catalog (so per-agent metric labels keep firing);
    /// operators only set this block when they want to point at a
    /// hosted feed, merge a custom catalog, or change the rDNS /
    /// bot-auth / cache settings.
    #[serde(default)]
    pub agent_classes: Option<AgentClassesConfig>,
    /// WOR-1130: top-level workspace rate-limit budget + auto-suspend
    /// escalation (the R2.3 / A2.5 contract). Distinct from the
    /// per-origin `rate_limits` policy: this is a workspace-wide ceiling
    /// with a soft / throttle / auto-suspend state machine.
    #[serde(default)]
    pub rate_limits: Option<RateLimitsConfig>,
    /// WOR-1130: audit sink selection for admin-action audit rows
    /// (e.g. the auto-suspend transition). `memory` keeps the last N
    /// rows queryable via `/api/audit/recent` (used by tests + ops).
    #[serde(default)]
    pub audit: Option<AuditConfig>,
    /// WOR-1186: emit the canonical session ledger (per-tool-call run
    /// records) from the live MCP `tools/call` path. Off unless this
    /// block is present and `enabled: true`.
    #[serde(default)]
    pub session_ledger: Option<SessionLedgerConfig>,
}

/// WOR-1130: top-level workspace rate-limit budget configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RateLimitsConfig {
    /// Budget applied to the default workspace (the only workspace in
    /// the OSS single-tenant build; enterprise multi-tenant resolves a
    /// per-tenant budget).
    #[serde(default)]
    pub workspace_default: WorkspaceBudgetConfig,
    /// Throttle -> auto-suspend escalation tuning.
    #[serde(default)]
    pub escalation: RateLimitEscalationConfig,
    /// Clock source for the token-bucket refill + suspend cool-down.
    /// `system` (default) uses wall time; `manual` advances only via
    /// the `/api/rate_limits/clock/advance` admin endpoint (tests).
    #[serde(default)]
    pub clock: RateLimitClockMode,
}

/// WOR-1130: the per-workspace request budget.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct WorkspaceBudgetConfig {
    /// Sustained inbound HTTP requests-per-second ceiling (the token
    /// bucket refill rate).
    #[serde(default = "default_http_rps_sustained")]
    pub http_rps_sustained: u32,
    /// Burst ceiling (the token bucket capacity). Requests above this
    /// within one window are throttled.
    #[serde(default = "default_http_rps_burst")]
    pub http_rps_burst: u32,
    /// Soft observation threshold. Traffic above this but below the
    /// sustained ceiling emits `sbproxy_rate_limit_total{result="soft"}`
    /// without throttling, so operators see the climb early.
    #[serde(default)]
    pub soft_threshold_rps: Option<u32>,
}

impl Default for WorkspaceBudgetConfig {
    fn default() -> Self {
        Self {
            http_rps_sustained: default_http_rps_sustained(),
            http_rps_burst: default_http_rps_burst(),
            soft_threshold_rps: None,
        }
    }
}

fn default_http_rps_sustained() -> u32 {
    1000
}
fn default_http_rps_burst() -> u32 {
    2000
}

/// WOR-1130: throttle -> auto-suspend escalation tuning.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RateLimitEscalationConfig {
    /// Consecutive-throttle count that promotes a workspace from
    /// `Throttle` to `AutoSuspend`. A2.5 default is 1000.
    #[serde(default = "default_abuse_threshold")]
    pub abuse_threshold_throttle_to_suspend: u32,
    /// Cool-down (seconds) a workspace stays auto-suspended before it
    /// drops back to `Throttle`. A2.5 default is 3600.
    #[serde(default = "default_auto_suspend_cooldown_secs")]
    pub auto_suspend_cooldown_secs: u32,
}

impl Default for RateLimitEscalationConfig {
    fn default() -> Self {
        Self {
            abuse_threshold_throttle_to_suspend: default_abuse_threshold(),
            auto_suspend_cooldown_secs: default_auto_suspend_cooldown_secs(),
        }
    }
}

fn default_abuse_threshold() -> u32 {
    1000
}
fn default_auto_suspend_cooldown_secs() -> u32 {
    3600
}

/// WOR-1130: clock source for the rate-limit budget.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitClockMode {
    /// Wall-clock time (production default).
    #[default]
    System,
    /// Test clock advanced only via the admin endpoint.
    Manual,
}

/// WOR-1130: audit sink selection.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct AuditConfig {
    /// Where admin-action audit rows are kept.
    #[serde(default)]
    pub sink: AuditSinkKind,
}

/// WOR-1130: audit sink kinds.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuditSinkKind {
    /// Keep the last N rows in memory, queryable via `/api/audit/recent`.
    #[default]
    Memory,
    /// Emit to the structured `security_audit` tracing target only.
    Tracing,
}

/// WOR-1186: session-ledger emission configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct SessionLedgerConfig {
    /// Turn ledger emission on. When false (the default), the
    /// `tools/call` path pays a single atomic load and emits nothing.
    #[serde(default)]
    pub enabled: bool,
    /// Where ledger records go.
    #[serde(default)]
    pub sink: SessionLedgerSinkKind,
    /// NDJSON output path for the `file` sink. Required when
    /// `sink: file`; ignored otherwise.
    #[serde(default)]
    pub path: Option<String>,
}

/// WOR-1186: session-ledger sink kinds.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SessionLedgerSinkKind {
    /// Emit each record as a structured `session_ledger` tracing line.
    #[default]
    Logging,
    /// Append each record as one NDJSON line to `path`.
    File,
}

/// Where to load a `sb.yml` config text from.
///
/// The default (no `source:` field at all) means the file is the
/// config: the surrounding `ConfigFile` is treated as inline content
/// and consumed directly. When `source:` is present, the compiler
/// resolves it to a config text string before parsing.
///
/// Three kinds are recognised today:
///
/// * `local` keeps the historical behaviour - the inline file is the
///   config. This is the form that round-trips when an operator writes
///   `source: { kind: local }` explicitly.
/// * `git` points at a remote git repository, an optional revision
///   (branch, tag, or commit), and a path within the repository to
///   the actual config file.
/// * `git_overlay` composes one base source with one or more overlay
///   sources, merging each in order. A `db` form is reserved for a
///   later iteration but is intentionally not part of this primitive
///   yet.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConfigSource {
    /// The inline file is the config; nothing is fetched. This is the
    /// historical behaviour and the implied default when `source:`
    /// is omitted.
    Local,
    /// Clone a git repository and read a single file inside it as the
    /// config text.
    Git {
        /// Repository URL (https, ssh, or any URL `git clone` accepts).
        repo: String,
        /// Optional branch, tag, or commit sha. When `None`, the
        /// default branch is used.
        #[serde(default)]
        revision: Option<String>,
        /// Path inside the repository to the config file, relative
        /// to the repository root.
        path: String,
    },
    /// Compose a base source with one or more overlays. Each overlay
    /// is merged onto the accumulated result in the order it appears
    /// in the list.
    GitOverlay {
        /// The base source the overlays are layered on top of.
        base: Box<ConfigSource>,
        /// Overlays applied in order; each is itself a `ConfigSource`
        /// so overlays can chain arbitrarily deep (subject to the
        /// recursion cap enforced by the loader).
        overlays: Vec<ConfigSource>,
    },
}

// --- Agent-class top-level config ---

/// Top-level `agent_classes:` block. Tunes the agent-class resolver
/// the binary constructs at startup and threads through the request
/// pipeline.
///
/// The block is fully optional: when absent the binary builds the
/// resolver from `AgentClassCatalog::defaults()` plus the default
/// resolver tuning. Most operators leave it untouched.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AgentClassesConfig {
    /// Catalog source. `builtin` (default) loads the embedded YAML
    /// catalog. `inline` loads the entries in `entries`. `hosted-feed`
    /// fetches from `hosted_feed.url`. `merged` loads the hosted feed
    /// and overlays it on top of the embedded defaults so an operator's
    /// feed only needs to ship deltas.
    #[serde(default = "default_agent_classes_catalog")]
    pub catalog: String,
    /// Inline catalog entries. Used when `catalog: inline`; each entry
    /// is validated by the runtime against the same schema as the
    /// embedded catalog.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<serde_json::Value>,
    /// Hosted-feed configuration. Required when `catalog: hosted-feed`
    /// or `catalog: merged`.
    #[serde(default)]
    pub hosted_feed: Option<HostedFeedConfig>,
    /// Resolver tuning (rDNS toggle, bot-auth toggle, cache size).
    /// Each field has a sensible default; this block is rarely needed.
    #[serde(default)]
    pub resolver: AgentClassResolverConfig,
}

impl Default for AgentClassesConfig {
    fn default() -> Self {
        Self {
            catalog: default_agent_classes_catalog(),
            entries: Vec::new(),
            hosted_feed: None,
            resolver: AgentClassResolverConfig::default(),
        }
    }
}

fn default_agent_classes_catalog() -> String {
    "builtin".to_string()
}

/// Hosted-feed source for the agent-class catalog.
///
/// Pulled at startup and refreshed on a schedule the registry owns.
/// The fetch loop is not implemented in this crate; the field is
/// reserved here so YAML written against the merged or hosted-feed
/// shapes parses cleanly.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct HostedFeedConfig {
    /// Feed URL. Plain `http://` is allowed only against `127.0.0.1`
    /// and `localhost` for local development; the registry crate
    /// enforces HTTPS at fetch time for any other host.
    pub url: String,
    /// Bootstrap public keys (base64-encoded ed25519 keys) used to
    /// verify the feed's detached signature on the first fetch.
    /// Empty in dev configs; required for production.
    #[serde(default)]
    pub bootstrap_keys: Vec<String>,
}

/// Resolver-tuning knobs for the agent-class chain.
///
/// All fields have sensible defaults: rDNS verification on, bot-auth
/// keyid lookup on, 10 000-entry verdict cache. Operators set fields
/// only when they need to disable a specific signal (typically rDNS
/// in environments without a working PTR resolver).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AgentClassResolverConfig {
    /// Run forward-confirmed reverse-DNS as resolver step 2. Default
    /// `true`. Disable when the runtime has no working DNS resolver.
    #[serde(default = "default_resolver_rdns_enabled")]
    pub rdns_enabled: bool,
    /// Honour the verified Web Bot Auth `keyid` as resolver step 1.
    /// Default `true`. Off forces the resolver to fall through to
    /// rDNS / UA matching even when bot-auth verified the request.
    #[serde(default = "default_resolver_bot_auth_keyid_enabled")]
    pub bot_auth_keyid_enabled: bool,
    /// Per-process verdict cache capacity (rDNS verdicts only).
    /// 10 000 is the default; bump for very high-cardinality IP
    /// populations.
    #[serde(default = "default_resolver_cache_size")]
    pub cache_size: usize,
}

impl Default for AgentClassResolverConfig {
    fn default() -> Self {
        Self {
            rdns_enabled: default_resolver_rdns_enabled(),
            bot_auth_keyid_enabled: default_resolver_bot_auth_keyid_enabled(),
            cache_size: default_resolver_cache_size(),
        }
    }
}

fn default_resolver_rdns_enabled() -> bool {
    true
}

fn default_resolver_bot_auth_keyid_enabled() -> bool {
    true
}

fn default_resolver_cache_size() -> usize {
    10_000
}

// --- Server Config ---

/// Server-level proxy configuration parsed from the top-level `proxy:`
/// block of sb.yml.
///
/// This is the composite home for every server-wide knob the request
/// path reads before routing reaches an origin: listener ports, TLS /
/// ACME sources, optional metrics and alerting, the admin API, secrets
/// resolution, and the optional shared-state backends (L2 cache +
/// messenger). Out-of-tree top-level blocks live in
/// [`Self::extensions`] and are ignored by the compiler.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProxyServerConfig {
    /// HTTP listener port. Defaults to 8080.
    #[serde(default = "default_http_port")]
    pub http_bind_port: u16,
    /// Enable HTTP/2 cleartext (h2c) on the plain HTTP listener.
    ///
    /// When `true`, the proxy detects the HTTP/2 connection preface on
    /// the unencrypted port and serves the connection as HTTP/2. This
    /// is required for plaintext gRPC clients that do not negotiate
    /// TLS+ALPN. When `false` (the default), the listener speaks
    /// HTTP/1.1 only and rejects raw h2 prefaces as malformed
    /// requests. TLS-fronted HTTP/2 is unaffected and continues to
    /// work via ALPN on `https_bind_port`.
    #[serde(default)]
    pub http2_cleartext: bool,
    /// Optional HTTPS listener port. When set, `tls_cert_file` +
    /// `tls_key_file` (or `acme`) must be configured too.
    pub https_bind_port: Option<u16>,
    /// Path to a PEM-encoded TLS certificate. Ignored when `acme` is
    /// configured.
    pub tls_cert_file: Option<String>,
    /// Path to the PEM-encoded TLS key matching `tls_cert_file`.
    pub tls_key_file: Option<String>,
    /// ACME (Let's Encrypt-style) certificate management. When set,
    /// overrides the manual `tls_cert_file` / `tls_key_file` pair.
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    /// Optional HTTP/3 (QUIC) listener configuration.
    ///
    /// Temporarily inert: HTTP/3 is disabled until native QUIC support lands
    /// in the underlying proxy engine. The field still parses so existing
    /// configs keep loading, but enabling it only logs a warning and does not
    /// start a listener.
    #[serde(default)]
    pub http3: Option<Http3Config>,
    /// Metrics collection settings, including cardinality limiting.
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    /// Top-level observability block: groups `log` (tracing-subscriber
    /// filter / format / sampling) and `telemetry` (OTLP exporter)
    /// under one block so an operator configures the whole surface
    /// from YAML instead of CLI flags + env vars.
    ///
    /// When absent, CLI / env precedence still applies; the YAML
    /// fields are a third source of truth that wins over the existing
    /// `RUST_LOG` default but loses to `--log-level` / `SB_LOG_LEVEL`.
    #[serde(default)]
    pub observability: Option<ObservabilityConfig>,
    /// Alert notification channel configuration.
    #[serde(default)]
    pub alerting: Option<AlertingConfig>,
    /// Embedded admin/stats API server configuration.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
    /// Canonical desired state and lifecycle policy for models hosted by SBproxy.
    #[serde(default)]
    pub model_host: Option<crate::model_host::ModelHostControlConfig>,
    /// Optional shared cluster substrate for keys, metrics, and managed models.
    #[serde(default)]
    pub cluster: Option<crate::cluster::ClusterConfig>,
    /// Secrets management configuration.
    #[serde(default)]
    pub secrets: Option<SecretsConfig>,
    /// Dynamic key-management configuration (WOR-1546): the mutable key store,
    /// policy cache, at-rest crypto, OIDC claim mapping, and an optional
    /// declarative seed. Distinct from the static `credentials:` block, which
    /// keeps working and lowers into the same store as config-sourced records.
    #[serde(default)]
    pub key_management: Option<KeyManagementConfig>,
    /// Optional L2 cache / shared-state backend. When set with `driver: redis`,
    /// rate limit counters and response cache entries are stored in the
    /// external backend so multiple proxy replicas share state.
    ///
    /// Accepted under either `l2_cache` (canonical) or
    /// `l2_cache_settings` (alias).
    #[serde(default, rename = "l2_cache_settings", alias = "l2_cache")]
    pub l2_cache: Option<L2CacheConfig>,
    /// Optional Cache Reserve (long-tail cold tier) configuration.
    ///
    /// When `enabled`, response-cache entries that pass the admission
    /// filter are mirrored to the configured backend (memory,
    /// filesystem, or Redis). On a hot miss the proxy consults the
    /// reserve before falling through to origin and promotes the
    /// entry back into the hot tier on hit.
    #[serde(default)]
    pub cache_reserve: Option<CacheReserveConfig>,
    /// Optional shared message bus for inter-component eventing (config
    /// updates, semantic-cache purges, etc.). When unset, components that
    /// need a bus degrade to no-op semantics.
    ///
    /// YAML key: `messenger_settings`.
    #[serde(default, rename = "messenger_settings")]
    pub messenger_settings: Option<MessengerSettings>,
    /// CIDR ranges (or bare IPs) whose `X-Forwarded-For` / `X-Real-IP` /
    /// `Forwarded` headers the proxy will trust. When SBProxy is itself
    /// behind a load balancer or CDN (Cloudflare, ALB, Fly.io, ...), set
    /// this to the upstream proxy's source range so the real client IP
    /// can be recovered from the forwarding chain. Connections from any
    /// peer outside this list have their inbound forwarding headers
    /// stripped before processing, so they cannot be spoofed.
    ///
    /// Empty by default. The TCP peer is treated as the client and no
    /// inbound forwarding metadata is honored.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Correlation-ID propagation policy. By default, the proxy honours
    /// any inbound `X-Request-Id` header, generates one if absent,
    /// forwards the value to the upstream, and echoes it in the
    /// downstream response. Set fields here to change the header name
    /// or disable.
    #[serde(default)]
    pub correlation_id: CorrelationIdConfig,
    /// Optional mTLS (mutual TLS) client certificate verification on
    /// the HTTPS listener. When set, the TLS handshake requires (or
    /// optionally accepts) a client certificate signed by the
    /// configured CA bundle. Cert metadata that Pingora exposes
    /// (organization, serial number, fingerprint) is forwarded to
    /// the upstream as `X-Client-Cert-*` headers. Requires
    /// `https_bind_port` to be set.
    #[serde(default)]
    pub mtls: Option<MtlsListenerConfig>,
    /// Optional override for the embedded AI provider catalog. When
    /// set, the AI gateway loads provider metadata (auth header,
    /// auth prefix, base URL, wire format, capabilities) from this
    /// YAML file at startup instead of the version compiled into the
    /// binary.
    #[serde(default)]
    pub ai_providers_file: Option<String>,
    /// Optional override for the embedded user-agent / device-parser
    /// regex catalog. Reserved for the (separate) UA-parser swap to
    /// a regex-driven implementation; the current pure-Rust device
    /// parser ignores this value but preserving the field shape now
    /// keeps existing sb.yml files forward-compatible.
    #[serde(default)]
    pub device_parser_file: Option<String>,
    /// Optional synthetic-transaction probe driving an in-process
    /// request through the compiled handler chain on a fixed cadence
    /// and reporting the verdict on `/readyz`. Disabled by
    /// default; opt in for deployments that want `/readyz` to fail
    /// when the proxy is unable to service its own requests.
    #[serde(default)]
    pub synthetic_probe: Option<SyntheticProbeConfig>,
    /// Scripting runtime limits. Today this block carries the Lua
    /// sandbox knobs (execution-time budget, memory budget, pattern
    /// API gating); other languages (CEL, JavaScript, WebAssembly)
    /// keep their own knobs elsewhere until they have similar enforcement
    /// surfaces. When omitted, the documented defaults are applied
    /// (see [`LuaSandboxConfig::default`]).
    #[serde(default)]
    pub scripting: ScriptingConfig,
    /// Opaque extensions for out-of-tree top-level config blocks.
    /// The compiler never parses these; extension consumers read
    /// their own keys.
    #[serde(default)]
    // WOR-1081: schemars 0.8 does not know about `serde_yaml::Value`,
    // so model the schema as an arbitrary JSON object (the wire form
    // round-trips through serde_json equivalently for extension data).
    #[schemars(with = "serde_json::Map<String, serde_json::Value>")]
    pub extensions: HashMap<String, serde_yaml::Value>,
    /// Tunable client-side timeouts for the proxy's outbound HTTP
    /// helpers (forward-auth, callbacks, mirrors, SWR refreshes, bot-
    /// auth directory). Defaults match the prior hardcoded literals
    /// so existing configs see no behaviour change. See
    /// [`HttpClientTimeoutsConfig`] for the field list.
    #[serde(default)]
    pub http_client_timeouts: HttpClientTimeoutsConfig,
    /// Web Bot Auth signing identity (WOR-805). When set, the proxy
    /// publishes the derived Ed25519 public key as an HTTP Message
    /// Signatures directory at
    /// `/.well-known/http-message-signatures-directory` so verifiers
    /// (including SBproxy's own inbound `bot_auth` directory client)
    /// can check the Web Bot Auth signatures the proxy produces. The
    /// 32-byte seed is also the key the proxy signs its outbound
    /// requests with. Absent keeps the endpoint off so existing
    /// configs are unaffected.
    #[serde(default)]
    pub web_bot_auth: Option<WebBotAuthConfig>,
    /// WOR-1053: declared tenants. Each entry carries an `id`
    /// referenced by `origin.tenant_id`. Future PRs add per-tenant
    /// `credentials`, `policies`, and `vault` blocks; PR1 lands the
    /// scope so the rest of the credentials epic can land against a
    /// stable tenant resolver.
    ///
    /// When empty, every origin resolves to the synthetic
    /// `__default__` tenant. Existing single-tenant configs see no
    /// behaviour change. An origin that names a tenant not declared
    /// here fails config compile.
    #[serde(default)]
    pub tenants: Vec<ProxyTenantConfig>,
    /// Canonical credentials block at proxy scope. The full schema
    /// lives in [`CredentialBlock`]. Tenant and origin scopes carry
    /// matching `credentials:` fields; resolution at request time
    /// walks origin -> tenant -> proxy, with most-restrictive
    /// policies winning across the merged set.
    ///
    /// The legacy `virtual_keys:` YAML key under
    /// `origins[].action.providers` is rejected at config compile;
    /// operators migrate to the canonical block per
    /// `docs/migration-credentials.md`.
    #[serde(default)]
    pub credentials: Vec<CredentialBlock>,
}

/// Web Bot Auth signing identity for the proxy. See the
/// [`ProxyServerConfig::web_bot_auth`] field.
///
/// The proxy holds one Ed25519 keypair, identified by `key_id`. Its
/// public half is published in the hosted signatures directory; its
/// private seed signs outbound requests to upstreams that require Web
/// Bot Auth. Treat `ed25519_seed_hex` as a secret (source it via an
/// env interpolation rather than committing it).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, schemars::JsonSchema)]
pub struct WebBotAuthConfig {
    /// Key id advertised as the JWK `kid` and the RFC 9421 `keyid`.
    /// Must be non-empty.
    pub key_id: String,
    /// Ed25519 private seed as 64 hex characters (32 bytes). The
    /// public key is derived and published; the seed never leaves the
    /// proxy. Validated at config-compile time.
    pub ed25519_seed_hex: String,
    /// Absolute URL of this proxy's published key directory
    /// (`/.well-known/http-message-signatures-directory`). When set, an
    /// origin that opts into outbound Web Bot Auth signing stamps a
    /// `Signature-Agent` header with this value so the upstream verifier
    /// can fetch the key. Optional: omitting it still signs, just without
    /// the discovery pointer.
    #[serde(default)]
    pub directory_url: Option<String>,
}

impl Default for ProxyServerConfig {
    fn default() -> Self {
        Self {
            http_bind_port: default_http_port(),
            http2_cleartext: false,
            https_bind_port: None,
            tls_cert_file: None,
            tls_key_file: None,
            acme: None,
            http3: None,
            metrics: None,
            observability: None,
            alerting: None,
            admin: None,
            model_host: None,
            cluster: None,
            secrets: None,
            key_management: None,
            l2_cache: None,
            cache_reserve: None,
            messenger_settings: None,
            ai_providers_file: None,
            device_parser_file: None,
            trusted_proxies: Vec::new(),
            correlation_id: CorrelationIdConfig::default(),
            mtls: None,
            synthetic_probe: None,
            scripting: ScriptingConfig::default(),
            extensions: HashMap::new(),
            http_client_timeouts: HttpClientTimeoutsConfig::default(),
            web_bot_auth: None,
            tenants: Vec::new(),
            credentials: Vec::new(),
        }
    }
}

// --- Dynamic key management (WOR-1546) ---

fn default_keystore_path() -> String {
    "/var/lib/sbproxy/keystore.redb".to_string()
}
fn default_keystore_prefix() -> String {
    "sbproxy/keystore".to_string()
}
fn default_key_cache_ttl_secs() -> u64 {
    60
}
fn default_key_cache_negative_ttl_secs() -> u64 {
    5
}
fn default_key_cache_max_entries() -> usize {
    10_000
}

/// Top-level `key_management:` block: the runtime key plane (mutable store,
/// policy cache, at-rest crypto, OIDC claim map, declarative seed).
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct KeyManagementConfig {
    /// Turn the dynamic key plane on. When false (default), inbound auth keeps
    /// using the compiled virtual-key registry and this block is inert.
    #[serde(default)]
    pub enabled: bool,
    /// Store backend (system of record).
    #[serde(default)]
    pub store: KeyStoreConfig,
    /// In-memory policy cache in front of the store.
    #[serde(default)]
    pub cache: KeyCacheConfig,
    /// At-rest crypto material.
    #[serde(default)]
    pub crypto: KeyCryptoConfig,
    /// Allow the admin API to override config-seeded records on reload. When
    /// false (default), config-seeded records are authoritative and re-asserted
    /// on every reload.
    #[serde(default)]
    pub allow_api_override: bool,
    /// When the store is unreachable, allow the request through in a degraded
    /// mode. Default false: fail closed (deny).
    #[serde(default)]
    pub failure_mode_allow: bool,
    /// Optional OIDC/JWT claim to virtual-key mapping.
    #[serde(default)]
    pub oidc_claim_map: Option<OidcClaimMapConfig>,
    /// Optional declarative seed of keys and credentials.
    #[serde(default)]
    pub seed: KeySeedConfig,
}

/// Which store backend backs the key plane.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum KeyStoreBackend {
    /// redb embedded store (default).
    #[default]
    Embedded,
    /// Redis store / coherence tier.
    Redis,
    /// Secrets-manager-direct: a configured vault backend is the system of record.
    SecretsManager,
}

/// `key_management.store:` block.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct KeyStoreConfig {
    /// Backend selector.
    #[serde(default)]
    pub backend: KeyStoreBackend,
    /// Embedded redb file path (backend `embedded`).
    #[serde(default = "default_keystore_path")]
    pub path: String,
    /// Redis connection URL (backend `redis`).
    #[serde(default)]
    pub url: Option<String>,
    /// Treat Redis as the source of truth rather than a coherence tier
    /// (backend `redis`).
    #[serde(default)]
    pub redis_source_of_truth: bool,
    /// Secret-reference namespace prefix (backend `secrets_manager`).
    #[serde(default = "default_keystore_prefix")]
    pub prefix: String,
    /// External secrets-manager connection (backend `secrets_manager`).
    #[serde(default)]
    pub secrets_manager: SecretsManagerStoreConfig,
}

impl Default for KeyStoreConfig {
    fn default() -> Self {
        Self {
            backend: KeyStoreBackend::Embedded,
            path: default_keystore_path(),
            url: None,
            redis_source_of_truth: false,
            prefix: default_keystore_prefix(),
            secrets_manager: SecretsManagerStoreConfig::default(),
        }
    }
}

fn default_kv_v2() -> bool {
    true
}

fn default_vault_token_env() -> String {
    "VAULT_TOKEN".to_string()
}

/// External secrets manager backing the `secrets_manager` store backend. Only
/// writable managers are supported (HashiCorp Vault, AWS Secrets Manager, and an
/// in-memory `local` store for dev/tests).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SecretsManagerProvider {
    /// In-memory, non-persistent. Dev and tests only.
    #[default]
    Local,
    /// HashiCorp Vault KV (token auth, token read from `token_env`).
    Hashicorp,
    /// AWS Secrets Manager via the default credential chain.
    Aws,
}

/// `key_management.store.secrets_manager:` connection block.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SecretsManagerStoreConfig {
    /// Which external manager.
    #[serde(default)]
    pub provider: SecretsManagerProvider,
    /// HashiCorp Vault address (provider `hashicorp`), e.g.
    /// `https://vault.example/v1`.
    #[serde(default)]
    pub address: Option<String>,
    /// KV mount path (provider `hashicorp`) or path prefix (provider `aws`).
    #[serde(default)]
    pub mount: Option<String>,
    /// Use KV engine v2 (provider `hashicorp`). Default true.
    #[serde(default = "default_kv_v2")]
    pub kv_v2: bool,
    /// Environment variable holding the Vault token (provider `hashicorp`).
    /// Default `VAULT_TOKEN`.
    #[serde(default = "default_vault_token_env")]
    pub token_env: String,
    /// Optional `X-Vault-Namespace` (provider `hashicorp`, Vault Enterprise).
    #[serde(default)]
    pub namespace: Option<String>,
    /// AWS region (provider `aws`), e.g. `us-east-1`.
    #[serde(default)]
    pub region: Option<String>,
}

impl Default for SecretsManagerStoreConfig {
    fn default() -> Self {
        Self {
            provider: SecretsManagerProvider::Local,
            address: None,
            mount: None,
            kv_v2: default_kv_v2(),
            token_env: default_vault_token_env(),
            namespace: None,
            region: None,
        }
    }
}

/// Which optional second cache tier sits behind the in-memory L1.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum KeyCacheTier {
    /// L1 only (default).
    #[default]
    None,
    /// Redis L2 tier.
    Redis,
    /// Mesh distributed-cache tier.
    Mesh,
}

/// `key_management.cache:` block.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct KeyCacheConfig {
    /// Positive-entry TTL in seconds (default 60).
    #[serde(default = "default_key_cache_ttl_secs")]
    pub ttl_secs: u64,
    /// Negative (known-absent) entry TTL in seconds (default 5).
    #[serde(default = "default_key_cache_negative_ttl_secs")]
    pub negative_ttl_secs: u64,
    /// Soft cap on cached entries per kind (default 10000).
    #[serde(default = "default_key_cache_max_entries")]
    pub max_entries: usize,
    /// Optional second cache tier.
    #[serde(default)]
    pub tier: KeyCacheTier,
    /// Redis URL for the redis cache tier (when `tier: redis`). Falls back to
    /// the store URL when unset.
    #[serde(default)]
    pub redis_url: Option<String>,
    /// Node id for the mesh cache tier (when `tier: mesh`). Defaults to the
    /// machine hostname.
    #[serde(default)]
    pub mesh_node_id: Option<String>,
    /// Mesh cluster bootstrap for the mesh cache tier. When set, the node joins
    /// a gossip cluster and the cache routes by consistent hash, so a key cached
    /// on one replica is reachable from the others. When absent, the mesh tier
    /// runs single-node.
    #[serde(default)]
    pub mesh: Option<MeshClusterConfig>,
}

fn default_gossip_port() -> u16 {
    7946
}
fn default_transport_port() -> u16 {
    8946
}

/// `key_management.cache.mesh:` cluster bootstrap for the mesh cache tier.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MeshClusterConfig {
    /// Static seed peers (`host:port`) to join. An empty list bootstraps a
    /// single-node cluster.
    #[serde(default)]
    pub seeds: Vec<String>,
    /// UDP port for the gossip protocol.
    #[serde(default = "default_gossip_port")]
    pub gossip_port: u16,
    /// TCP port for the cross-node cache RPC transport. `0` requests an
    /// OS-assigned ephemeral port.
    #[serde(default = "default_transport_port")]
    pub transport_port: u16,
    /// Address this node advertises to peers (`host:port`). Defaults to the
    /// gossip bind when unset.
    #[serde(default)]
    pub advertise_addr: Option<String>,
    /// Address this node advertises for typed-state transport (`host:port`).
    /// Defaults to the gossip-advertised host and `transport_port`.
    #[serde(default)]
    pub transport_advertise_addr: Option<String>,
    /// Optional cluster-wide shared secret (AES-256-GCM) for the gossip and
    /// transport wire. Accepts an inline value or `env:NAME`. Plaintext when
    /// unset.
    #[serde(default)]
    pub shared_key: Option<String>,
    /// Optional peer mTLS (mutually-authenticated TLS) for the mesh transport.
    /// When set, inbound connections must present a CA-signed client
    /// certificate and outbound connections present this node's certificate,
    /// all verified against the configured CA. Plaintext when unset.
    #[serde(default)]
    pub peer_tls: Option<MeshPeerTlsConfig>,
}

/// `key_management.cache.mesh.peer_tls:` mutual-TLS material (file paths) for
/// the mesh peer transport.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MeshPeerTlsConfig {
    /// Path to this node's PEM certificate chain (leaf first).
    pub cert_file: String,
    /// Path to this node's PEM private key.
    pub key_file: String,
    /// Path to the PEM CA certificate that signs every peer.
    pub ca_file: String,
    /// Logical server name the peer certificates are issued for (their SAN);
    /// outbound connections verify peers against it. Defaults to
    /// `sbproxy-mesh`.
    #[serde(default = "default_mesh_tls_server_name")]
    pub server_name: String,
}

fn default_mesh_tls_server_name() -> String {
    "sbproxy-mesh".to_string()
}

impl Default for MeshClusterConfig {
    fn default() -> Self {
        Self {
            seeds: Vec::new(),
            gossip_port: default_gossip_port(),
            transport_port: default_transport_port(),
            advertise_addr: None,
            transport_advertise_addr: None,
            shared_key: None,
            peer_tls: None,
        }
    }
}

impl Default for KeyCacheConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_key_cache_ttl_secs(),
            negative_ttl_secs: default_key_cache_negative_ttl_secs(),
            max_entries: default_key_cache_max_entries(),
            tier: KeyCacheTier::None,
            redis_url: None,
            mesh_node_id: None,
            mesh: None,
        }
    }
}

/// `key_management.crypto:` block. Both values accept a secret reference
/// (`vault://`, `env:`, `file:`, ...) resolved at boot, or an inline value
/// (discouraged outside tests).
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct KeyCryptoConfig {
    /// Server pepper for inbound virtual-key hashing. When unset, a
    /// process-ephemeral pepper is generated, so stored hashes do not survive a
    /// restart; set this in production.
    #[serde(default)]
    pub pepper: Option<String>,
    /// Master key for upstream-credential envelope encryption. Required to store
    /// encrypted upstream credentials; vault-ref credentials do not need it.
    #[serde(default)]
    pub master_key: Option<String>,
}

/// `key_management.oidc_claim_map:` block.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct OidcClaimMapConfig {
    /// The verified JWT/OIDC claim whose value names the virtual-key record to
    /// resolve, so the bearer-token and OIDC front doors converge on one record.
    pub claim_field: String,
}

/// `key_management.seed:` block: declarative records applied at boot.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct KeySeedConfig {
    /// Inbound virtual keys.
    #[serde(default)]
    pub keys: Vec<SeedKeyConfig>,
    /// Upstream provider credentials.
    #[serde(default)]
    pub credentials: Vec<SeedCredentialConfig>,
}

/// A seeded inbound virtual key.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SeedKeyConfig {
    /// Stable public id and token prefix.
    pub key_id: String,
    /// Plaintext secret hashed at boot. Mutually exclusive with `secret_hash`.
    #[serde(default)]
    pub secret: Option<String>,
    /// Precomputed HMAC-SHA256 hash (hex) when the operator hashed offline.
    #[serde(default)]
    pub secret_hash: Option<String>,
    /// Human-readable name, surfaced on access logs.
    #[serde(default)]
    pub name: Option<String>,
    /// Max requests per minute.
    #[serde(default)]
    pub max_requests_per_minute: Option<u64>,
    /// Max total tokens for this key's budget window.
    #[serde(default)]
    pub max_budget_tokens: Option<u64>,
    /// Max total cost in USD for this key's budget window.
    #[serde(default)]
    pub max_budget_usd: Option<f64>,
    /// Models this key may use (empty = all).
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// Models this key may not use.
    #[serde(default)]
    pub blocked_models: Vec<String>,
    /// Providers this key may use (empty = all).
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    /// Named PII redaction rules that must be active before this key can
    /// dispatch upstream (empty = none required).
    #[serde(default)]
    pub require_pii_redaction: Vec<String>,
    /// Inbound principal selectors allowed to present this key (empty = any).
    /// Each entry is a principal-selector object (virtual_key, team, project,
    /// user, role, claim).
    #[serde(default)]
    pub principal_selectors: Vec<serde_json::Value>,
    /// Pin a model for requests on this key; the gateway overwrites the request
    /// body `model` before routing.
    #[serde(default)]
    pub route_to_model: Option<String>,
    /// Provider tool definitions injected into the request when this key
    /// authenticates, replacing any client-supplied tools.
    #[serde(default)]
    pub inject_tools: Vec<serde_json::Value>,
    /// Skip the body-aware prompt-injection scan for this key. Default false.
    #[serde(default)]
    pub bypass_prompt_injection: bool,
    /// Project attribution.
    #[serde(default)]
    pub project: Option<String>,
    /// User attribution.
    #[serde(default)]
    pub user: Option<String>,
    /// Owning tenant.
    #[serde(default)]
    pub tenant: Option<String>,
    /// RFC 3339 expiry instant; past it the key is unusable.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// A seeded upstream credential.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SeedCredentialConfig {
    /// Stable id.
    pub id: String,
    /// Operator-facing name.
    #[serde(default)]
    pub name: Option<String>,
    /// Provider this credential authenticates to.
    #[serde(default)]
    pub provider: Option<String>,
    /// Credential kind (default `ai_provider`).
    #[serde(default)]
    pub kind: Option<String>,
    /// A secret reference (`vault://`, `awssm://`, ...). Stored as vault-ref
    /// material and resolved at use.
    #[serde(default)]
    pub vault_ref: Option<String>,
    /// A plaintext secret to envelope-encrypt at boot (needs
    /// `crypto.master_key`).
    #[serde(default)]
    pub secret: Option<String>,
    /// Owning tenant.
    #[serde(default)]
    pub tenant: Option<String>,
}

// --- Scripting engine sandbox config (WOR-594 + WOR-595) ---

/// Per-engine scripting sandbox limits, exposed under the
/// `proxy.scripting:` block of sb.yml.
///
/// Today this block carries sub-blocks for the Lua engine
/// and the JavaScript engine. The CEL and WebAssembly
/// engines manage their own budgets separately. Operators who omit
/// the block get the documented defaults from each sub-block.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ScriptingConfig {
    /// Lua sandbox limits. Always populated, even when the operator
    /// omitted the block, so callers never have to special-case
    /// `None`.
    #[serde(default)]
    pub lua: LuaScriptingConfig,
    /// JavaScript engine sandbox knobs. Covers the QuickJS-backed
    /// `JsEngine` used by transforms, request matchers, and WAF
    /// custom rules.
    #[serde(default)]
    pub javascript: JsScriptingConfig,
}

/// JavaScript engine config block (`proxy.scripting.javascript:`).
///
/// Wraps the sandbox limits the engine enforces every time it runs a
/// script. Adding fresh knobs here (module loader settings, host
/// bindings, ...) should keep `sandbox:` as its own sub-block so
/// existing configs keep parsing.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct JsScriptingConfig {
    /// Sandbox limits: CPU time budget, heap memory cap, and native
    /// stack cap. See [`JsSandboxConfig`].
    #[serde(default)]
    pub sandbox: JsSandboxConfig,
}

/// JavaScript sandbox limits enforced on every script execution.
///
///
/// The `budget_ms` field is the CPU time budget for a single
/// `execute` / `call_function` / `match_request` / `waf_match` call.
/// QuickJS calls the engine's interrupt handler periodically during
/// evaluation; when the elapsed wall-clock time exceeds `budget_ms`
/// the interrupt handler returns `true`, which aborts the script with
/// an uncatchable exception that surfaces in Rust as a structured
/// timeout error.
///
/// The `memory_mb` and `stack_kb` fields are passed through to
/// `Runtime::set_memory_limit` and `Runtime::set_max_stack_size`
/// respectively. They guard against runaway allocations and deeply
/// recursive scripts in the same way the CPU budget guards against
/// `while (true) {}`.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct JsSandboxConfig {
    /// Wall-clock CPU budget per script execution. Defaults to 100
    /// ms, which is comfortably above any reasonable transform /
    /// matcher script but well under the per-request timeout budget
    /// of a typical request.
    #[serde(default = "default_js_budget_ms")]
    pub budget_ms: u64,
    /// Maximum heap memory the QuickJS runtime is allowed to allocate
    /// for the lifetime of this engine instance. Defaults to 16 MB.
    #[serde(default = "default_js_memory_mb")]
    pub memory_mb: usize,
    /// Maximum native stack size for the QuickJS runtime, in
    /// kilobytes. Defaults to 1024 KB (1 MB).
    #[serde(default = "default_js_stack_kb")]
    pub stack_kb: usize,
}

impl Default for JsSandboxConfig {
    fn default() -> Self {
        Self {
            budget_ms: default_js_budget_ms(),
            memory_mb: default_js_memory_mb(),
            stack_kb: default_js_stack_kb(),
        }
    }
}

fn default_js_budget_ms() -> u64 {
    100
}

fn default_js_memory_mb() -> usize {
    16
}

fn default_js_stack_kb() -> usize {
    1024
}

#[cfg(test)]
mod scripting_config_tests {
    use super::*;

    #[test]
    fn defaults_match_documentation() {
        let cfg = JsSandboxConfig::default();
        assert_eq!(cfg.budget_ms, 100);
        assert_eq!(cfg.memory_mb, 16);
        assert_eq!(cfg.stack_kb, 1024);
    }

    #[test]
    fn empty_scripting_block_uses_defaults() {
        let cfg: ScriptingConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(cfg.javascript.sandbox.budget_ms, 100);
        assert_eq!(cfg.javascript.sandbox.memory_mb, 16);
        assert_eq!(cfg.javascript.sandbox.stack_kb, 1024);
    }

    #[test]
    fn empty_javascript_block_uses_defaults() {
        let yaml = "javascript: {}\n";
        let cfg: ScriptingConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.javascript.sandbox.budget_ms, 100);
    }

    #[test]
    fn operator_can_override_budget_ms() {
        let yaml = r#"
javascript:
  sandbox:
    budget_ms: 250
"#;
        let cfg: ScriptingConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.javascript.sandbox.budget_ms, 250);
        // Other fields still default.
        assert_eq!(cfg.javascript.sandbox.memory_mb, 16);
        assert_eq!(cfg.javascript.sandbox.stack_kb, 1024);
    }

    #[test]
    fn operator_can_override_all_sandbox_fields() {
        let yaml = r#"
javascript:
  sandbox:
    budget_ms: 50
    memory_mb: 32
    stack_kb: 2048
"#;
        let cfg: ScriptingConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.javascript.sandbox.budget_ms, 50);
        assert_eq!(cfg.javascript.sandbox.memory_mb, 32);
        assert_eq!(cfg.javascript.sandbox.stack_kb, 2048);
    }

    #[test]
    fn scripting_block_round_trips_through_yaml() {
        let original = ScriptingConfig {
            lua: LuaScriptingConfig::default(),
            javascript: JsScriptingConfig {
                sandbox: JsSandboxConfig {
                    budget_ms: 75,
                    memory_mb: 8,
                    stack_kb: 512,
                },
            },
        };
        let yaml = serde_yaml::to_string(&original).unwrap();
        let decoded: ScriptingConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(decoded.javascript.sandbox.budget_ms, 75);
        assert_eq!(decoded.javascript.sandbox.memory_mb, 8);
        assert_eq!(decoded.javascript.sandbox.stack_kb, 512);
    }

    #[test]
    fn proxy_block_accepts_scripting_subblock() {
        let yaml = r#"
http_bind_port: 8080
scripting:
  javascript:
    sandbox:
      budget_ms: 200
"#;
        let cfg: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.scripting.javascript.sandbox.budget_ms, 200);
    }
}

// --- Synthetic probe config ---

/// Configuration for the in-process synthetic-transaction probe.
///
///
/// When enabled, a background task fires a request through the
/// compiled pipeline against the configured `hostname` on a fixed
/// cadence. The request never leaves the process: the synthetic
/// origin is required to use a non-network action (typically
/// `static`, `mock`, `echo`, or `noop`) so `/readyz` can verify the
/// handler chain end to end without making the readiness check
/// dependent on a real upstream.
///
/// The probe verdict is reported as a `synthetic_pipeline` component
/// in the `/readyz` body and increments
/// `sbproxy_synthetic_probe_failures_total{reason}` whenever the
/// driver records a failure.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SyntheticProbeConfig {
    /// Master switch. Disabled by default so operators with strict
    /// request-cost budgets do not pay for a synthetic transaction
    /// they did not opt into.
    #[serde(default)]
    pub enabled: bool,
    /// Sentinel hostname routed to the synthetic origin. Defaults to
    /// `__synthetic.local` per the synthetic-probe convention; pick another value if
    /// it collides with an existing origin in your deployment.
    #[serde(default = "default_synthetic_hostname")]
    pub hostname: String,
    /// Path issued on the synthetic request. Defaults to
    /// `/readyz/synthetic`.
    #[serde(default = "default_synthetic_path")]
    pub path: String,
    /// Cadence between synthetic runs.
    #[serde(default = "default_synthetic_interval_secs")]
    pub interval_secs: u64,
    /// Per-run timeout budget. The driver records a `timeout`
    /// failure if a single synthetic round trip exceeds this.
    #[serde(default = "default_synthetic_timeout_ms")]
    pub timeout_ms: u64,
    /// Maximum age (in seconds) the cached probe outcome can have
    /// before the readiness probe reports `Unhealthy`. Set this to
    /// roughly 3x `interval_secs`. Defaults to `interval_secs * 3`
    /// when zero.
    #[serde(default)]
    pub stale_after_secs: u64,
}

impl Default for SyntheticProbeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hostname: default_synthetic_hostname(),
            path: default_synthetic_path(),
            interval_secs: default_synthetic_interval_secs(),
            timeout_ms: default_synthetic_timeout_ms(),
            stale_after_secs: 0,
        }
    }
}

impl SyntheticProbeConfig {
    /// Effective staleness window in seconds, applying the default
    /// of `interval_secs * 3` when the explicit value is zero.
    pub fn effective_stale_after_secs(&self) -> u64 {
        if self.stale_after_secs == 0 {
            self.interval_secs.saturating_mul(3).max(1)
        } else {
            self.stale_after_secs
        }
    }
}

fn default_synthetic_hostname() -> String {
    "__synthetic.local".to_string()
}

fn default_synthetic_path() -> String {
    "/readyz/synthetic".to_string()
}

fn default_synthetic_interval_secs() -> u64 {
    30
}

fn default_synthetic_timeout_ms() -> u64 {
    1000
}

// --- Lua scripting runtime limits ---

/// Lua scripting runtime configuration. Wraps the sandbox limits so
/// future Lua-specific tunables (preloaded libraries, request-binding
/// budgets, etc.) have a stable home.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct LuaScriptingConfig {
    /// Per-script execution limits.
    #[serde(default)]
    pub sandbox: LuaSandboxConfig,
}

/// Sandbox configuration applied to every Lua script invocation.
///
/// Three knobs:
///
/// * `max_execution_ms` is a wall-clock budget enforced through the
///   Luau interrupt callback. Once exceeded, the script is aborted
///   with an `Error::external` propagated back to the caller.
/// * `max_memory_mb` caps the Lua VM's total allocator footprint.
///   Allocations past the limit fail the script with
///   `Error::MemoryError`, which is far cheaper than letting a
///   runaway script OOM the proxy process.
/// * `allow_patterns` gates the Lua pattern API (`string.find`,
///   `string.match`, `string.gmatch`). The pattern engine has known
///   pathological inputs that can lock a worker, so operators who do
///   not need patterns can drop them entirely.
///
/// The on-the-wire field uses `max_memory_mb` (megabytes) because
/// that is the unit operators reason about; the engine converts to
/// bytes internally.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct LuaSandboxConfig {
    /// Wall-clock execution budget per Lua invocation, in
    /// milliseconds. Default: 100 ms.
    #[serde(default = "default_lua_max_execution_ms")]
    pub max_execution_ms: u64,
    /// Hard cap on the Lua VM's allocator footprint, in megabytes.
    /// Default: 8 MB.
    #[serde(default = "default_lua_max_memory_mb")]
    pub max_memory_mb: usize,
    /// Whether to expose the Lua pattern API (`string.find`,
    /// `string.match`, `string.gmatch`). Default: `true` for back
    /// compatibility; flip to `false` to disable pattern matching.
    #[serde(default = "default_lua_allow_patterns")]
    pub allow_patterns: bool,
}

impl Default for LuaSandboxConfig {
    fn default() -> Self {
        Self {
            max_execution_ms: default_lua_max_execution_ms(),
            max_memory_mb: default_lua_max_memory_mb(),
            allow_patterns: default_lua_allow_patterns(),
        }
    }
}

impl LuaSandboxConfig {
    /// Effective memory cap in bytes (`max_memory_mb * 1024 * 1024`),
    /// saturating on overflow. The engine consumes bytes, so this
    /// keeps the unit conversion in one place.
    pub fn max_memory_bytes(&self) -> usize {
        self.max_memory_mb.saturating_mul(1024 * 1024)
    }
}

fn default_lua_max_execution_ms() -> u64 {
    100
}

fn default_lua_max_memory_mb() -> usize {
    8
}

fn default_lua_allow_patterns() -> bool {
    true
}

/// mTLS client certificate verification on the HTTPS listener.
///
/// When set, the proxy configures the OpenSSL `SslAcceptor` underneath
/// Pingora's `add_tls_with_settings` to verify the client certificate
/// against the configured CA bundle.
///
/// What we expose to the upstream after a successful handshake:
///   * `X-Client-Cert-Verified: 1`
///   * `X-Client-Cert-Organization: <Subject's O field, when present>`
///   * `X-Client-Cert-Serial: <hex serial>`
///   * `X-Client-Cert-Fingerprint: <hex sha256 of the cert>`
///
/// CN and SAN extraction is a follow-up because Pingora 0.8's
/// `SslDigest` does not expose the parsed Subject CN directly. When
/// `require: true`, requests without a valid client cert are rejected
/// during the TLS handshake and never reach `request_filter`.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MtlsListenerConfig {
    /// Path to a PEM-encoded CA bundle used to verify client certs.
    pub client_ca_file: String,
    /// When `true` (default), the TLS handshake fails if the client
    /// does not present a certificate. When `false`, the handshake
    /// succeeds without a cert and `X-Client-Cert-Verified: 0` is set
    /// (so upstreams can choose whether to reject anonymous traffic).
    #[serde(default = "default_mtls_require")]
    pub require: bool,
    /// Optional allowlist of regex patterns the client certificate's
    /// Common Name must match. When non-empty, a certificate that passes
    /// CA-chain validation is still rejected during the handshake if its
    /// CN matches none of these patterns. Empty (the default) accepts any
    /// CN signed by the configured CA (WOR-1155).
    #[serde(default)]
    pub allowed_cn_patterns: Vec<String>,
}

fn default_mtls_require() -> bool {
    true
}

/// Correlation-ID propagation policy.
///
/// The proxy mints a per-request correlation identifier early in the
/// request lifecycle. With the default policy:
///
/// 1. If the inbound request carries `header` (default `X-Request-Id`),
///    its value is adopted as the request's correlation ID. This lets
///    upstream callers (a frontend, an API client, another proxy)
///    correlate their traces with ours.
/// 2. Otherwise the proxy generates a 32-hex-character UUID v4 and
///    uses that.
/// 3. The chosen value is set on the upstream request (under the
///    same header name) so the upstream sees the same correlation ID
///    the proxy used in its logs / webhooks.
/// 4. The chosen value is echoed back to the client on the response,
///    unless `echo_response` is `false`.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CorrelationIdConfig {
    /// Master switch. Default: `true`.
    #[serde(default = "default_correlation_id_enabled")]
    pub enabled: bool,
    /// Header name to read on ingress, set on the upstream, and echo
    /// on the response. Default: `X-Request-Id`.
    #[serde(default = "default_correlation_id_header")]
    pub header: String,
    /// Whether to echo the correlation ID on the downstream response.
    /// Default: `true`.
    #[serde(default = "default_correlation_id_echo")]
    pub echo_response: bool,
}

impl Default for CorrelationIdConfig {
    fn default() -> Self {
        Self {
            enabled: default_correlation_id_enabled(),
            header: default_correlation_id_header(),
            echo_response: default_correlation_id_echo(),
        }
    }
}

fn default_correlation_id_enabled() -> bool {
    true
}

fn default_correlation_id_header() -> String {
    "X-Request-Id".to_string()
}

fn default_correlation_id_echo() -> bool {
    true
}

#[cfg(test)]
mod correlation_id_tests {
    use super::*;

    #[test]
    fn defaults_match_documented_behaviour() {
        let cfg = CorrelationIdConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.header, "X-Request-Id");
        assert!(cfg.echo_response);
    }

    #[test]
    fn header_name_overridable() {
        let json = serde_json::json!({"header": "X-Correlation-Id"});
        let cfg: CorrelationIdConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.header, "X-Correlation-Id");
        assert!(cfg.enabled);
        assert!(cfg.echo_response);
    }

    #[test]
    fn can_disable() {
        let json = serde_json::json!({"enabled": false});
        let cfg: CorrelationIdConfig = serde_json::from_value(json).unwrap();
        assert!(!cfg.enabled);
    }

    #[test]
    fn can_disable_echo() {
        let json = serde_json::json!({"echo_response": false});
        let cfg: CorrelationIdConfig = serde_json::from_value(json).unwrap();
        assert!(!cfg.echo_response);
        assert!(cfg.enabled);
    }

    #[test]
    fn empty_block_uses_defaults() {
        let json = serde_json::json!({});
        let cfg: CorrelationIdConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.header, "X-Request-Id");
        assert!(cfg.enabled);
        assert!(cfg.echo_response);
    }
}

// --- Mirror Config (per-origin shadow traffic) ---

/// Per-origin shadow-traffic configuration.
///
/// When set on an origin, the proxy fires a fire-and-forget copy of
/// each request at `url` and discards the response. The primary
/// upstream is never blocked by mirror delivery. Useful for safe
/// rollouts of new backends and replay-driven testing.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MirrorConfig {
    /// Mirror upstream URL (http:// or https://). IPv6 hosts must be
    /// bracketed in the URL (e.g. `http://[2001:db8::1]:8080`) per RFC
    /// 3986.
    pub url: String,
    /// Sample rate in `[0.0, 1.0]`. `1.0` (default) mirrors every
    /// request; `0.1` mirrors ~10%. Sampling is per-request and uses a
    /// uniform PRNG; do not rely on exact counts.
    #[serde(default = "default_mirror_sample_rate")]
    pub sample_rate: f32,
    /// Mirror request timeout in milliseconds. Independent from the
    /// primary upstream timeout. Default 5000ms.
    #[serde(default = "default_mirror_timeout_ms")]
    pub timeout_ms: u64,
    /// Whether to tee the inbound request body into the mirror
    /// request. Default `false`: the mirror sees only method, path,
    /// query, and headers (sufficient for read endpoints, GET-mostly
    /// traffic, and any case where shadow-replaying writes is unsafe).
    /// Set to `true` to enable body teeing for shadow-replay of
    /// POST/PUT/PATCH endpoints during migrations.
    #[serde(default)]
    pub mirror_body: bool,
    /// Maximum bytes of body to mirror. Bodies larger than this cap
    /// are skipped (the mirror is fired without a body) so a single
    /// large upload cannot blow up proxy memory. Default `1048576`
    /// (1 MiB).
    #[serde(default = "default_mirror_body_cap")]
    pub max_body_bytes: usize,
}

fn default_mirror_sample_rate() -> f32 {
    1.0
}

fn default_mirror_timeout_ms() -> u64 {
    5000
}

fn default_mirror_body_cap() -> usize {
    1024 * 1024 // 1 MiB
}

// --- Response Cache Config (per-origin) ---

/// Per-origin response-cache configuration.
///
/// When `enabled` is true, the proxy will attempt to serve cacheable requests
/// out of a key/value store (in-process by default, Redis when the top-level
/// `l2_cache` block is set). See `CompiledPipeline` for where the backing store
/// is selected.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ResponseCacheConfig {
    /// Global on/off switch for response caching on this origin.
    #[serde(default)]
    pub enabled: bool,

    /// Cache entry TTL in seconds. Accepts either `ttl_secs`
    /// (canonical) or `ttl` (alias). Values may be supplied as bare
    /// integers (`60`) or humanized strings (`60s`, `5m`, `2h30m`).
    /// Defaults to 300 seconds.
    #[serde(
        default = "default_response_cache_ttl",
        alias = "ttl",
        deserialize_with = "crate::duration::deserialize_secs"
    )]
    pub ttl_secs: u64,

    /// HTTP methods that are eligible for caching. Defaults to `["GET"]` when
    /// unset. Accepts either `cacheable_methods` (canonical) or `methods`
    /// (alias).
    #[serde(default, alias = "methods")]
    pub cacheable_methods: Vec<String>,

    /// HTTP status codes that are eligible for caching. Defaults to `[200]`
    /// when unset. Accepts either `cacheable_status` (canonical) or
    /// `status_codes` (alias).
    #[serde(default, alias = "status_codes")]
    pub cacheable_status: Vec<u16>,

    /// Upper bound on the in-memory cache size (entries) when the local
    /// `MemoryCacheStore` is used. Ignored for the Redis backend, which is
    /// governed by the Redis server's own eviction policy.
    #[serde(default = "default_response_cache_max_size")]
    pub max_size: usize,

    /// Request headers whose values are folded into the cache key, so
    /// variants of the same path with different `Accept-Encoding` /
    /// `Accept-Language` etc. cache independently. The list is matched
    /// case-insensitively. Aliased as `vary_by` for parity with the
    /// docs/Cloudflare-style schema.
    #[serde(default, alias = "vary_by")]
    pub vary: Vec<String>,

    /// Query-string normalization applied at cache-key build time.
    /// Defaults to `sort` so callers see today's behavior unchanged.
    #[serde(default)]
    pub query_normalize: QueryNormalize,

    /// When set, the proxy serves an expired entry within
    /// `ttl + stale_while_revalidate` seconds while triggering a
    /// background revalidation. Stale replays carry the
    /// `x-sbproxy-cache: STALE` marker.
    #[serde(default, alias = "swr_secs")]
    pub stale_while_revalidate: Option<u64>,

    /// When true (default), `POST` / `PUT` / `PATCH` / `DELETE` to a
    /// path evicts every cached `GET` entry for the same workspace +
    /// hostname + path, across every Vary fingerprint.
    #[serde(default = "default_invalidate_on_mutation")]
    pub invalidate_on_mutation: bool,
}

/// Query-string normalization policy applied when computing the cache key.
#[derive(Debug, Clone, Deserialize, Serialize, Default, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum QueryNormalize {
    /// Drop the query string from the cache key entirely.
    IgnoreAll,
    /// Sort query params alphabetically by name, preserving values
    /// and duplicates. This is the default and matches today's
    /// behavior closely enough that pre-existing configs see no
    /// change in cache distribution.
    #[default]
    Sort,
    /// Keep only the named params (case-sensitive). Drop the rest.
    /// The retained params are sorted for deterministic keys.
    Allowlist {
        /// Param names to retain. All others are dropped from the
        /// cache key.
        #[serde(default)]
        allowlist: Vec<String>,
    },
}

fn default_invalidate_on_mutation() -> bool {
    true
}

fn default_response_cache_ttl() -> u64 {
    300
}

fn default_response_cache_max_size() -> usize {
    10_000
}

impl Default for ResponseCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_secs: default_response_cache_ttl(),
            cacheable_methods: Vec::new(),
            cacheable_status: Vec::new(),
            max_size: default_response_cache_max_size(),
            vary: Vec::new(),
            query_normalize: QueryNormalize::default(),
            stale_while_revalidate: None,
            invalidate_on_mutation: default_invalidate_on_mutation(),
        }
    }
}

// --- L2 Cache Config ---

/// Top-level shared-state / L2 cache backend configuration.
///
/// Turns rate-limit buckets and response-cache entries into
/// cluster-wide shared state so multiple proxy replicas coordinate
/// against the same counters and cache pool. YAML key:
/// `l2_cache_settings`.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct L2CacheConfig {
    /// Backend driver. Currently only `"redis"` is supported.
    pub driver: String,
    /// Driver-specific parameters.
    #[serde(default)]
    pub params: L2CacheParams,
}

/// Driver-specific parameters for the [`L2CacheConfig`].
///
/// Kept separate from `L2CacheConfig` so future drivers can add fields
/// (auth, pool size) without churning the parent struct.
#[derive(Debug, Clone, Deserialize, Serialize, Default, schemars::JsonSchema)]
pub struct L2CacheParams {
    /// Connection DSN. For `redis` drivers this is a `redis://host:port[/db]`
    /// URL. Only the host:port portion is parsed today; the DB index is ignored.
    #[serde(default)]
    pub dsn: String,
}

// --- Cache Reserve Config ---

/// Top-level Cache Reserve configuration.
///
/// Cache Reserve is a long-tail cold tier sitting under the per-origin
/// response cache. Items evicted from the hot cache are admitted into
/// the reserve subject to a sample rate and size threshold; on a hot
/// miss the proxy consults the reserve before going to origin and
/// promotes the entry back into the hot tier on hit.
///
/// Backend selection is open-ended via [`CacheReserveBackendConfig`]
/// so the in-tree memory / filesystem / redis backends can be
/// extended without touching this schema.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CacheReserveConfig {
    /// Master switch. When `false`, the reserve is not built and the
    /// hot cache behaves exactly as it does without this block.
    #[serde(default)]
    pub enabled: bool,

    /// Backend wiring. Required when `enabled == true`.
    #[serde(default)]
    pub backend: Option<CacheReserveBackendConfig>,

    /// Fraction (0.0 to 1.0) of hot-cache writes that are mirrored to
    /// the reserve. Defaults to `0.1`. The reserve is meant for
    /// long-tail content; sampling controls reserve write amplification
    /// and (on object-store backends) per-request operation cost.
    #[serde(default = "default_reserve_sample_rate")]
    pub sample_rate: f64,

    /// Skip mirroring entries whose TTL is below this threshold. Items
    /// that won't outlive a typical hot-cache eviction window aren't
    /// worth carrying in the reserve. Defaults to 3600 seconds.
    #[serde(default = "default_reserve_min_ttl")]
    pub min_ttl: u64,

    /// Skip oversize objects. Defaults to 1 MiB. Set to `0` to disable
    /// the upper bound (not recommended for object-store backends).
    #[serde(default = "default_reserve_max_size_bytes")]
    pub max_size_bytes: u64,
}

impl Default for CacheReserveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: None,
            sample_rate: default_reserve_sample_rate(),
            min_ttl: default_reserve_min_ttl(),
            max_size_bytes: default_reserve_max_size_bytes(),
        }
    }
}

/// Backend selector for [`CacheReserveConfig`].
///
/// Tagged externally on `type`. The built-in variants are listed
/// below; out-of-tree builds may register additional types via their
/// own startup path (the in-tree pipeline ignores unknown types after
/// logging a warning).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CacheReserveBackendConfig {
    /// In-process map. For tests and ephemeral single-replica setups.
    Memory,
    /// Filesystem-backed reserve. One file per key under `path`.
    Filesystem {
        /// Root directory under which entries are written.
        path: String,
    },
    /// Redis-backed reserve.
    Redis {
        /// Redis connection URL (`redis://host:port[/db]`).
        redis_url: String,
        /// Optional key prefix override. Defaults to
        /// `"sbproxy:reserve:"`.
        #[serde(default)]
        key_prefix: Option<String>,
    },
    /// Catch-all for backends registered out-of-tree (e.g. an
    /// `s3` backend). The in-tree pipeline ignores these with a
    /// warning; an out-of-tree startup hook intercepts the variant
    /// before the warning fires.
    #[serde(other)]
    Other,
}

fn default_reserve_sample_rate() -> f64 {
    0.1
}

fn default_reserve_min_ttl() -> u64 {
    3600
}

fn default_reserve_max_size_bytes() -> u64 {
    1_048_576
}

// --- Messenger Settings ---

/// Configuration for the shared message bus used by inter-component events
/// (config updates, semantic-cache purges, etc.).
///
/// The `driver` selects the backend implementation:
/// * `"memory"` - in-process bounded mpsc channels (single-replica use only).
/// * `"redis"`  - Redis Streams over the DSN in `params.dsn`.
/// * `"sqs"`    - AWS SQS; requires `params.queue_url`, `params.region`,
///   `params.api_key`.
/// * `"gcp_pubsub"` - GCP Pub/Sub; requires `params.project`, `params.topic`,
///   `params.subscription`, `params.access_token`.
///
/// Unknown drivers cause `build_messenger` to return an error; the caller
/// decides whether to treat that as fatal or fall back to no-bus semantics.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MessengerSettings {
    /// Backend driver name.
    pub driver: String,
    /// Free-form string parameters consumed by the driver-specific factory.
    #[serde(default)]
    pub params: HashMap<String, String>,
}

// --- Admin Config ---

/// Configuration for the embedded read-only admin/stats API server.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AdminConfig {
    /// Whether the admin server is enabled. Defaults to false.
    #[serde(default)]
    pub enabled: bool,
    /// Port to listen on. Defaults to 9090.
    #[serde(default = "default_admin_port")]
    pub port: u16,
    /// HTTP Basic Auth username. Defaults to "admin".
    #[serde(default = "default_admin_user")]
    pub username: String,
    /// HTTP Basic Auth password. Defaults to "changeme".
    #[serde(default = "default_admin_pass")]
    pub password: String,
    /// Maximum number of recent requests to retain in the log ring buffer.
    /// Defaults to 1000.
    #[serde(default = "default_max_log")]
    pub max_log_entries: usize,
    /// WOR-800 PR5: filesystem path to a redb file that persists the
    /// prompt-store runtime overlay. When set, every successful
    /// `POST /admin/prompts/.../versions` and `PUT /admin/prompts/.../pin`
    /// also writes through to the file, and the file's existing
    /// contents are hydrated into the in-memory overlay at boot.
    /// Absent means PR3-style ephemeral mutations.
    #[serde(default)]
    pub prompt_persistence_path: Option<std::path::PathBuf>,
    /// URL template for trace deep-links in the admin UI. The literal
    /// `{trace_id}` is replaced with the request's trace id, e.g.
    /// `https://jaeger.internal/trace/{trace_id}`. Unset renders trace
    /// ids as plain text (no broken default link).
    #[serde(default)]
    pub trace_url_template: Option<String>,
    /// Optional TLS for the admin server (WOR-1717). When set, the admin
    /// endpoint and the built-in UI are served over HTTPS using the PEM
    /// certificate and key at the configured paths, instead of plaintext
    /// HTTP. Leave unset to serve plaintext (loopback default).
    #[serde(default)]
    pub tls: Option<AdminTlsConfig>,
    /// WOR-1717: address the admin server binds. Defaults to `127.0.0.1`
    /// (loopback only). Set to `0.0.0.0` or a specific interface for
    /// remote admin, and pair it with `allow_ips` and `tls`.
    #[serde(default)]
    pub bind: Option<String>,
    /// WOR-1717: IP / CIDR allowlist for admin clients. Empty means
    /// loopback-only (`127.0.0.1`, `::1`), the safe default. List CIDRs to
    /// permit remote admin from known networks.
    #[serde(default)]
    pub allow_ips: Vec<String>,
    /// WOR-1717: allowed CORS origins for the admin API, so a separately
    /// hosted SPA or dev server can call it cross-origin with credentials.
    /// Empty means no CORS headers are emitted (same-origin only).
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// WOR-1716: additional admin operators with roles, for RBAC and an
    /// attributable audit trail. The top-level `username` / `password` is
    /// the implicit full-access `admin` operator; each entry here adds a
    /// read-only or admin identity that logs in with its own credentials.
    #[serde(default)]
    pub operators: Vec<AdminOperator>,
}

/// TLS material for the admin server (WOR-1717): filesystem paths to a
/// PEM certificate chain and its matching private key. Both are required
/// together; supplying `tls` makes the admin server, including the
/// built-in UI, serve HTTPS instead of plaintext HTTP.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AdminTlsConfig {
    /// Path to the PEM certificate chain file.
    pub cert: std::path::PathBuf,
    /// Path to the PEM private key file (PKCS#8 or RSA).
    pub key: std::path::PathBuf,
}

/// An admin operator identity with a role, for RBAC (WOR-1716).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AdminOperator {
    /// Login username.
    pub username: String,
    /// Login password.
    pub password: String,
    /// Role governing which admin actions this operator may perform.
    #[serde(default)]
    pub role: AdminRole,
}

/// Admin RBAC role (WOR-1716). `read_only` may call read (GET) endpoints
/// only; `admin` may call every admin route.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum AdminRole {
    /// Read-only: GET / read endpoints only; state-changing routes 403.
    ReadOnly,
    /// Full admin: every admin route.
    #[default]
    Admin,
}

fn default_admin_port() -> u16 {
    9090
}

fn default_admin_user() -> String {
    "admin".to_string()
}

fn default_admin_pass() -> String {
    "changeme".to_string()
}

fn default_max_log() -> usize {
    1000
}

fn default_http_port() -> u16 {
    8080
}

// --- HTTP Client Timeouts ---

/// Tunable client-side timeouts for the proxy's outbound HTTP helpers.
///
/// Several internal code paths build pooled `reqwest::Client` instances
/// to call out to operator-controlled services: forward-auth services,
/// callback / webhook receivers, mirror destinations, stale-while-
/// revalidate refreshes against origin upstreams, and Web Bot Auth
/// directory lookups. Each helper used to bake a `Duration::from_secs`
/// literal into a `LazyLock`-built client, which meant operators had
/// to fork the binary to extend a timeout for a slow auth service or
/// shorten one for an aggressive deadline budget.
///
/// All fields default to the prior hardcoded values so existing
/// configs see no behaviour change. Operators only set a field here
/// to nudge a specific timeout.
///
/// Example:
///
/// ```yaml
/// proxy:
///   http_client_timeouts:
///     forward_auth_client_secs: 60
///     callback_client_secs: 15
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct HttpClientTimeoutsConfig {
    /// Outer client-level timeout for the shared forward-auth
    /// `reqwest::Client`. The per-request timeout from each
    /// `forward_auth.timeout` field still applies on top. Defaults
    /// to 30s.
    #[serde(default = "default_forward_auth_client_secs")]
    pub forward_auth_client_secs: u64,
    /// Per-request fallback timeout for a forward-auth subrequest
    /// when the auth provider's own `timeout` field is unset.
    /// Defaults to 5s.
    #[serde(default = "default_forward_auth_request_secs")]
    pub forward_auth_request_secs: u64,
    /// Client-level timeout for the Web Bot Auth directory client
    /// that fetches signed directories from agent operators.
    /// Defaults to 5s.
    #[serde(default = "default_bot_auth_directory_client_secs")]
    pub bot_auth_directory_client_secs: u64,
    /// Client-level timeout for the stale-while-revalidate refresh
    /// client that re-fetches expired cache entries in the
    /// background. Defaults to 30s to match the conservative outer
    /// ceiling the rest of the proxy uses for outbound HTTP.
    #[serde(default = "default_swr_client_secs")]
    pub swr_client_secs: u64,
    /// Client-level timeout for the callback / webhook client that
    /// fires audit-mode webhooks and other fire-and-forget POSTs.
    /// Defaults to 10s.
    #[serde(default = "default_callback_client_secs")]
    pub callback_client_secs: u64,
}

impl Default for HttpClientTimeoutsConfig {
    fn default() -> Self {
        Self {
            forward_auth_client_secs: default_forward_auth_client_secs(),
            forward_auth_request_secs: default_forward_auth_request_secs(),
            bot_auth_directory_client_secs: default_bot_auth_directory_client_secs(),
            swr_client_secs: default_swr_client_secs(),
            callback_client_secs: default_callback_client_secs(),
        }
    }
}

fn default_forward_auth_client_secs() -> u64 {
    30
}

fn default_forward_auth_request_secs() -> u64 {
    5
}

fn default_bot_auth_directory_client_secs() -> u64 {
    5
}

fn default_swr_client_secs() -> u64 {
    30
}

fn default_callback_client_secs() -> u64 {
    10
}

// --- ACME Config ---

/// ACME (Automatic Certificate Management Environment) configuration for automatic TLS.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AcmeConfig {
    /// Master switch for ACME-managed TLS certificates.
    #[serde(default)]
    pub enabled: bool,
    /// Account contact email registered with the ACME directory.
    #[serde(default)]
    pub email: String,
    /// ACME directory URL. Defaults to Let's Encrypt production.
    #[serde(default = "default_acme_directory")]
    pub directory_url: String,
    /// Allowed ACME challenge types in priority order. Defaults to
    /// `[http-01]`, the only type the proxy currently drives; `tls-alpn-01`
    /// is accepted in the list but is not yet served.
    #[serde(default = "default_challenge_types")]
    pub challenge_types: Vec<String>,
    /// Backing store for issued certificates (`redb`, `sqlite`, etc.).
    #[serde(default = "default_storage_backend")]
    pub storage_backend: String,
    /// Filesystem path for the certificate store.
    #[serde(default = "default_storage_path")]
    pub storage_path: String,
    /// Number of days before expiry to attempt renewal.
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_challenge_types() -> Vec<String> {
    // WOR-1771: only http-01 is driven by the proxy today; tls-alpn-01 is
    // not, so leading with it made a default `acme:` config fail issuance
    // ("challenge type 'tls-alpn-01' selected but only http-01 is driven").
    // Default to http-01 so a fresh config issues; add tls-alpn-01 back when
    // the listener drives it.
    vec!["http-01".to_string()]
}

fn default_storage_backend() -> String {
    "redb".to_string()
}

fn default_storage_path() -> String {
    "/var/lib/sbproxy/certs".to_string()
}

fn default_renew_before_days() -> u32 {
    30
}

// --- Metrics Config ---

/// Metrics collection configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MetricsConfig {
    /// Max unique label values allowed per metric label before new values are
    /// collapsed to `__other__`. Defaults to 1 000.
    #[serde(default = "default_max_cardinality")]
    pub max_cardinality_per_label: usize,
    /// Per-label cardinality overrides.
    #[serde(default)]
    pub cardinality: MetricsCardinalityConfig,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            max_cardinality_per_label: default_max_cardinality(),
            cardinality: MetricsCardinalityConfig::default(),
        }
    }
}

fn default_max_cardinality() -> usize {
    1000
}

/// Per-label metrics cardinality overrides.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MetricsCardinalityConfig {
    /// Optional override for the `hostname` label cap.
    pub hostname_cap: Option<usize>,
}

// --- Access Log Config ---

/// Structured-JSON access-log emission, off by default.
///
/// When `enabled` is true, every completed request emits one JSON line
/// via the tracing `access_log` target after status, method, and sampling
/// filters are applied. The actual record shape is `AccessLogEntry` in
/// `sbproxy-observe`; this struct only governs whether and which records
/// are emitted.
///
/// Filter semantics:
/// - `status_codes` empty matches every status; non-empty restricts to
///   the listed codes.
/// - `methods` empty matches every method; non-empty restricts to the
///   listed methods (case-insensitive on emit).
/// - `sample_rate` is applied last and accepts a value in `[0.0, 1.0]`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AccessLogConfig {
    /// Master switch. When false (the default), no access-log lines are
    /// emitted regardless of the other fields.
    #[serde(default)]
    pub enabled: bool,
    /// Probability in `[0.0, 1.0]` that a matching request is logged.
    /// Defaults to `1.0` (log every match).
    #[serde(default = "default_access_log_sample_rate")]
    pub sample_rate: f64,
    /// HTTP status codes to log. Empty (the default) means log all
    /// statuses.
    #[serde(default)]
    pub status_codes: Vec<u16>,
    /// HTTP methods to log. Empty (the default) means log all methods.
    /// Comparison is case-insensitive.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Header capture configuration. Off by default; opt in by listing
    /// header names (or `*`) in `request` / `response`. Captured values
    /// land in the `request_headers` / `response_headers` fields of the
    /// emitted entry.
    #[serde(default)]
    pub capture_headers: CaptureHeadersConfig,
    /// Log every request at or above this latency, regardless of
    /// `sample_rate`. `None` preserves sampler-only behaviour.
    #[serde(default)]
    pub slow_request_threshold_ms: Option<f64>,
    /// Log every 5xx response regardless of `sample_rate`.
    #[serde(default)]
    pub always_log_errors: bool,
    /// Output sink. Defaults to stderr/tracing target.
    #[serde(default)]
    pub output: AccessLogOutputConfig,
}

impl AccessLogConfig {
    /// Decide whether a completed request should be emitted to the
    /// access log given this config's filters. Sampling is *not*
    /// applied here; callers run the sampler after this gate.
    pub fn should_emit(&self, status: u16, method: &str) -> bool {
        self.matches_filters(status, method)
    }

    /// Decide whether a request passes non-sampling filters.
    pub fn matches_filters(&self, status: u16, method: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if !self.status_codes.is_empty() && !self.status_codes.contains(&status) {
            return false;
        }
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
        {
            return false;
        }
        true
    }

    /// Return true when a matching request bypasses sampling.
    pub fn forces_emit(&self, status: u16, latency_ms: f64) -> bool {
        (self.always_log_errors && status >= 500)
            || self
                .slow_request_threshold_ms
                .map(|threshold| latency_ms >= threshold)
                .unwrap_or(false)
    }

    /// Decide whether a request should be sampled after filters.
    pub fn should_sample(&self, status: u16, latency_ms: f64, roll: f64) -> bool {
        if self.forces_emit(status, latency_ms) {
            return true;
        }
        if self.sample_rate >= 1.0 {
            return true;
        }
        if self.sample_rate <= 0.0 {
            return false;
        }
        roll < self.sample_rate
    }
}

fn default_access_log_sample_rate() -> f64 {
    1.0
}

/// Access-log output sink.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AccessLogOutputConfig {
    /// Sink type: `stderr` (default) or `file`.
    #[serde(default = "default_access_log_output_type", rename = "type")]
    pub output_type: String,
    /// File path when `type: file`.
    #[serde(default)]
    pub path: Option<String>,
    /// Rotate before writing when the file is at least this size.
    #[serde(default = "default_access_log_max_size_mb")]
    pub max_size_mb: u64,
    /// Number of rotated backups to retain.
    #[serde(default = "default_access_log_max_backups")]
    pub max_backups: usize,
    /// Gzip rotated files.
    #[serde(default)]
    pub compress: bool,
}

impl Default for AccessLogOutputConfig {
    fn default() -> Self {
        Self {
            output_type: default_access_log_output_type(),
            path: None,
            max_size_mb: default_access_log_max_size_mb(),
            max_backups: default_access_log_max_backups(),
            compress: false,
        }
    }
}

fn default_access_log_output_type() -> String {
    "stderr".to_string()
}

fn default_access_log_max_size_mb() -> u64 {
    100
}

fn default_access_log_max_backups() -> usize {
    7
}

/// Allowlist-driven header capture for the access log.
///
/// Lists are matched after lowercasing both the configured names and
/// the inbound header names. Two pattern shapes are accepted:
///
/// * Exact name (`"user-agent"`, `"x-cache"`).
/// * `"*"` to capture every header (subject to the sensitive-header
///   denylist below).
/// * Trailing-glob (`"x-ratelimit-*"`) to capture every header whose
///   name starts with the prefix before the `*`. Only one trailing
///   `*` is supported; embedded wildcards are treated as literal.
///
/// A hardcoded denylist of sensitive headers (`authorization`,
/// `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key`) is
/// excluded from `*` and glob matches. To capture one of these, list
/// it by exact name; the proxy logs a `WARN` at config load so the
/// choice is visible.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CaptureHeadersConfig {
    /// Request-side allowlist. Empty (the default) captures nothing.
    #[serde(default)]
    pub request: Vec<String>,
    /// Response-side allowlist. Empty (the default) captures nothing.
    #[serde(default)]
    pub response: Vec<String>,
    /// Per-value byte cap. Captured header values longer than this are
    /// truncated to the cap with a trailing `"..."` (the suffix counts
    /// toward the cap). Defaults to 1024.
    #[serde(default = "default_capture_max_value_bytes")]
    pub max_value_bytes: usize,
    /// Run the `sbproxy-security` PII redactor over captured header
    /// values. Off by default. Independent from the cheap secret-key
    /// scan that already runs over every emitted access-log line.
    #[serde(default)]
    pub redact_pii: bool,
    /// Optional rule-name filter for `redact_pii`. Empty (the default)
    /// uses the full built-in rule set; non-empty restricts to the
    /// listed rule names (`email`, `us_ssn`, `credit_card`, `phone_us`,
    /// `ipv4`, `openai_key`, `anthropic_key`, `aws_access`,
    /// `github_token`).
    ///
    /// The same rule list is shared by [`Self::redact_pii_other_fields`]
    /// when that knob is on, so operators only configure one rule list
    /// for both the header scope and the non-header scope.
    #[serde(default)]
    pub redact_pii_rules: Vec<String>,
    /// Run the same `sbproxy-security` PII redactor over the non-header
    /// access-log fields that can carry PII: `path`, `user_id`,
    /// `properties` values (keys are left untouched), and `model`. Off
    /// by default. Independent of [`Self::redact_pii`] so operators can
    /// adopt header redaction first and the broader scope later (or
    /// either alone). Reuses [`Self::redact_pii_rules`] for the rule
    /// filter; the cheap `redact_secrets` pass over the full JSON line
    /// still runs regardless of this knob.
    #[serde(default)]
    pub redact_pii_other_fields: bool,
}

impl Default for CaptureHeadersConfig {
    fn default() -> Self {
        Self {
            request: Vec::new(),
            response: Vec::new(),
            max_value_bytes: default_capture_max_value_bytes(),
            redact_pii: false,
            redact_pii_rules: Vec::new(),
            redact_pii_other_fields: false,
        }
    }
}

fn default_capture_max_value_bytes() -> usize {
    1024
}

/// Header names excluded from `*` and glob matches. Listing one of
/// these by exact name still works (intentional opt-in).
pub const SENSITIVE_HEADER_DENYLIST: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
];

/// Compiled allowlist suitable for the request hot path. Built once
/// per config-reload from a [`CaptureHeadersConfig`] list.
#[derive(Debug, Clone, Default)]
pub struct CompiledHeaderAllowlist {
    /// Exact lowercase header names. Hashset lookup is O(1).
    pub exact: std::collections::HashSet<String>,
    /// Lowercase prefixes from trailing-glob patterns (`"x-foo-*"` ->
    /// `"x-foo-"`). Linear scan; expected to be short.
    pub prefixes: Vec<String>,
    /// True when the original list contained `"*"`.
    pub wildcard: bool,
}

impl CompiledHeaderAllowlist {
    /// Compile a raw allowlist from config. Returns the compiled form
    /// and a `Vec<String>` of warnings (one per denylisted name listed
    /// by exact match) so the caller can log them at startup.
    pub fn compile(raw: &[String]) -> (Self, Vec<String>) {
        let mut compiled = Self::default();
        let mut warnings = Vec::new();
        for entry in raw {
            let entry = entry.trim().to_ascii_lowercase();
            if entry.is_empty() {
                continue;
            }
            if entry == "*" {
                compiled.wildcard = true;
                continue;
            }
            if let Some(prefix) = entry.strip_suffix('*') {
                compiled.prefixes.push(prefix.to_string());
                continue;
            }
            if SENSITIVE_HEADER_DENYLIST.contains(&entry.as_str()) {
                warnings.push(entry.clone());
            }
            compiled.exact.insert(entry);
        }
        (compiled, warnings)
    }

    /// True when this allowlist captures nothing.
    pub fn is_empty(&self) -> bool {
        !self.wildcard && self.exact.is_empty() && self.prefixes.is_empty()
    }

    /// Decide whether `header_name` (already lowercased) should be
    /// captured. The denylist always wins for `*` and glob matches;
    /// exact matches override the denylist.
    pub fn matches(&self, header_name: &str) -> bool {
        if self.exact.contains(header_name) {
            return true;
        }
        let denied = SENSITIVE_HEADER_DENYLIST.contains(&header_name);
        if denied {
            return false;
        }
        if self.wildcard {
            return true;
        }
        self.prefixes.iter().any(|p| header_name.starts_with(p))
    }
}

// --- Alerting Config ---

/// Top-level alerting configuration block.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AlertingConfig {
    /// List of notification channels to fire alerts to.
    #[serde(default)]
    pub channels: Vec<AlertChannelConfig>,
}

/// Top-level observability block: groups the `log` and `telemetry`
/// sub-blocks so an operator can configure both from YAML rather than
/// CLI flags + env vars. Re-uses the existing `LoggingConfig` and
/// `TelemetryConfig` shapes from `sbproxy-observe`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ObservabilityConfig {
    /// `tracing-subscriber` configuration: level, format, per-level
    /// sampling. CLI / env still wins where applicable; this block is
    /// the YAML source-of-truth for everything else.
    #[serde(default)]
    pub log: Option<ObservabilityLogConfig>,
    /// OTLP exporter configuration. When `enabled = true`, the
    /// configured endpoint receives traces and (optionally) metrics.
    #[serde(default)]
    pub telemetry: Option<ObservabilityTelemetryConfig>,
    /// Durable windowed usage rollups. On by default; omit the block
    /// to accept the defaults.
    #[serde(default)]
    pub usage_rollups: Option<UsageRollupsConfig>,
}

/// Durable spend-rollup configuration (hour and day usage buckets in
/// an embedded database, so the admin spend API serves windowed
/// history that survives restarts). Buckets are keyed by provider,
/// model, tenant, team, credential id, and project, and aggregate
/// request counts, tokens, cost, and an outcome split. Rows carry no
/// prompt content and no raw key material, so the file is safe to
/// back up. Aggregation is deterministic.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct UsageRollupsConfig {
    /// Whether rollups are recorded. Defaults to `true`. When the
    /// store path cannot be opened the proxy logs a warning and runs
    /// with rollups off instead of failing boot.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Rollup database file path. Default
    /// `/var/lib/sbproxy/usage-rollups.redb`.
    #[serde(default)]
    pub path: Option<String>,
    /// Days of hourly buckets to keep before compacting into daily
    /// buckets. Default 90.
    #[serde(default = "default_rollup_hourly_days")]
    pub retention_hourly_days: u32,
    /// Days of daily buckets to keep. Default 395 (about 13 months).
    #[serde(default = "default_rollup_daily_days")]
    pub retention_daily_days: u32,
}

impl Default for UsageRollupsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            retention_hourly_days: default_rollup_hourly_days(),
            retention_daily_days: default_rollup_daily_days(),
        }
    }
}

fn default_rollup_hourly_days() -> u32 {
    90
}

fn default_rollup_daily_days() -> u32 {
    395
}

/// Subset of `sbproxy-observe::LoggingConfig` that lands in the public
/// config schema. Kept in `sbproxy-config` so the YAML round-trips
/// through serde without dragging a serde dependency back into the
/// observe crate.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ObservabilityLogConfig {
    /// Log level filter. `debug | info | warn | error`. Default `info`.
    #[serde(default)]
    pub level: Option<String>,
    /// Output format. `compact | pretty | json`. Default `compact`.
    #[serde(default)]
    pub format: Option<String>,
    /// Per-level emission sampling rates. Default 1.0 / 0.1 / 0.01.
    #[serde(default)]
    pub sampling: Option<ObservabilitySamplingConfig>,
    /// Operator-extensible redaction block. `fields` extends the
    /// built-in field-key denylist; `patterns` adds regex masks that
    /// run after the field-key pass. The built-in baseline (the
    /// hard-coded denylist in `sbproxy-observe::logging::apply_redaction`)
    /// always runs first and is not disable-able from YAML.
    #[serde(default)]
    pub redact: Option<ObservabilityRedactConfig>,
    /// WOR-1045: log sink fan-out (`stdout`, `stderr`, `file`, ...).
    /// When empty, the legacy single-tracing-subscriber path keeps
    /// driving stdout. Each declared sink has a unique `name` within
    /// this scope; duplicates fail config compilation. Tenant + origin
    /// sink scopes are blocked on the WOR-1051 credentials epic.
    ///
    /// Dispatch wiring (writing each emitted line to each matching
    /// sink) lands in PR2. PR1 parses + validates the schema so an
    /// operator's e2e fixture (`e2e/tests/redaction.rs`) no longer
    /// errors at parse time.
    #[serde(default)]
    pub sinks: Vec<ObservabilitySinkConfig>,
    /// Operator-defined custom access-log fields. Each entry adds a key
    /// to the access line's `custom` object, computed per request from
    /// either a static value with `${...}` variable interpolation or a
    /// script (CEL / Lua / JS) evaluated against the request context.
    /// Lets operators pivot logs on dimensions the built-in schema does
    /// not carry (region, deployment, a derived risk score, a hashed
    /// account id, ...) without forking the binary. Configurable at
    /// proxy, tenant, and origin scope; the sets compose per request as
    /// proxy then tenant then origin, with a more-specific scope's field
    /// overriding a less-specific field of the same `name`.
    #[serde(default)]
    pub custom_fields: Vec<CustomLogFieldConfig>,
}

/// One operator-defined custom access-log field.
///
/// Exactly one value source must be set: either `value` (a static
/// string with `${...}` variable interpolation) or `source` together
/// with `engine` (a script). Supplying both, or neither, is a config
/// error. `engine` must be one of `cel`, `lua`, `js`. (`wasm` is
/// rejected: it is a compiled module, not inline source.)
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CustomLogFieldConfig {
    /// Key the computed value lands under in the access line's `custom`
    /// object. Must be unique within the scope.
    pub name: String,
    /// Static value with `${...}` variable interpolation. Mutually
    /// exclusive with `source` / `engine`. Supported variables include
    /// `${env.NAME}`, `${tenant_id}`, `${method}`, `${path}`,
    /// `${host}`, `${status}`, `${provider}`, `${model}`,
    /// `${request.header.NAME}`, and `${attribution.KEY}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Scripting engine for `source`. One of `cel`, `lua`, `js`.
    /// Required when `source` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    /// Script source evaluated against the request context; its result
    /// is stringified into the field. Mutually exclusive with `value`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Operator-extensible redaction config. Sits under
/// `proxy.observability.log.redact:` (today) and will surface at
/// tenant and origin scopes once multi-tenant scaffolding lands.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ObservabilityRedactConfig {
    /// Additional JSON field keys whose values are replaced with
    /// `[REDACTED:<NAME>]`. Matched case-insensitively against the
    /// keys produced by `serde_json`'s renderer. Always additive on
    /// top of the built-in denylist; tenants and origins cannot
    /// disable the baseline.
    #[serde(default)]
    pub fields: Vec<String>,
    /// Regex masks applied to the rendered JSON after the field-key
    /// pass. Each pattern is compiled at config-load; invalid regex
    /// is a `compile_config` error.
    #[serde(default)]
    pub patterns: Vec<ObservabilityRedactPattern>,
    /// Optional rule-driven PII redactor. When enabled, the global
    /// `sbproxy-security::pii::PiiRedactor` runs as a fourth pass
    /// after the value pattern scrubber, the field denylist + operator
    /// fields, and the operator regex patterns. Rules are looked up
    /// in `sbproxy-security::pii::default_rules()` by name (`email`,
    /// `credit_card`, `us_ssn`, `phone_us`, `ipv4`, `openai_key`,
    /// `anthropic_key`, `aws_access`, `github_token`, `slack_token`,
    /// `iban`).
    #[serde(default)]
    pub pii: Option<ObservabilityPiiConfig>,
}

/// Operator-controlled PII redaction at the log layer. Mirrors the
/// per-origin `PiiConfig` used by the AI handler but applies to every
/// emitted log line, regardless of origin.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ObservabilityPiiConfig {
    /// Master switch. When `Some(false)`, the redactor is never built
    /// and the pipeline shorts the PII pass at this scope (and any
    /// more-specific scope that inherits without overriding).
    /// When `None`, the scope inherits its parent's `enabled` flag
    /// (proxy default is "off"); `Some(true)` turns the pass on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Names of the built-in rules to enable. When empty at the proxy
    /// scope, all default rules are enabled (the spirit of "PII
    /// redaction on" is the least-surprising default). At a tenant or
    /// origin scope the list is ADDED to the parent's resolved set,
    /// not replaced.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Names of built-in rules to opt out of even when included by
    /// `rules:` or by the default-all behaviour. The matching name is
    /// case-sensitive. At a tenant or origin scope the list is
    /// SUBTRACTED from the resolved set (parent inheritance plus this
    /// scope's `rules:` additions).
    #[serde(default)]
    pub disable: Vec<String>,
}

/// One named regex mask. `name` is reported on cardinality / counter
/// metrics; `replacement` defaults to `[REDACTED:<NAME>]` when empty.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ObservabilityRedactPattern {
    /// Operator-supplied label; appears in metrics + the marker.
    pub name: String,
    /// PCRE-style regex (Rust `regex` crate flavour).
    pub pattern: String,
    /// Replacement string. Defaults to `[REDACTED:<NAME_UPPER>]` when
    /// empty; can include `$1` backrefs if the pattern has groups.
    #[serde(default)]
    pub replacement: Option<String>,
}

/// WOR-1045: one declared log sink. Multiple sinks fan out from a
/// single emit; a tenant-scoped sink only receives lines whose
/// resolved `Principal.tenant_id` matches the tenant scope. PR1 lands
/// the schema and uniqueness validation; dispatch wiring lands in PR2.
///
/// ## Field schema
///
/// * `name` is unique within the declaring scope. The same name may
///   appear once at proxy scope and once at tenant scope; cross-scope
///   collisions are intentional (a tenant `acme-loki` sink is a
///   different thing from the proxy `acme-loki` sink).
/// * `target` selects which internal channel feeds this sink:
///   `access_log`, `error_log`, `audit_log`, `trace_exporter`,
///   `external_log`. The channel maps 1:1 onto the existing
///   `sbproxy_observe::logging::Sink` enum.
/// * `format` is the wire shape: `compact | pretty | json`. When omitted
///   the parent `proxy.observability.log.format` decides.
/// * `output` is the where: `stdout | stderr | file`. `otlp` lands
///   under WOR-1046; `syslog` is a planned follow-up.
/// * `profile` is the redaction shape: `internal` keeps JA3/JA4 and
///   raw query strings; `external` strips them. Tenant-scoped sinks
///   default to `external` because the operator usually does not
///   control the downstream backend.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ObservabilitySinkConfig {
    /// Unique name within the declaring scope (proxy / tenant / origin).
    /// Duplicates within a scope are rejected at config compile.
    pub name: String,
    /// Which internal channel feeds this sink. One of
    /// `access_log | error_log | audit_log | trace_exporter | external_log`.
    /// Unknown values fail compilation.
    pub target: String,
    /// Wire format. One of `compact | pretty | json`. Defaults to
    /// the parent `observability.log.format` when omitted.
    #[serde(default)]
    pub format: Option<String>,
    /// Where the line goes. `output: { type: stdout }` keeps the
    /// legacy stdout behaviour; `file` reuses the access-log rotation
    /// stack; `otlp` lands under WOR-1046.
    pub output: ObservabilitySinkOutput,
    /// Redaction profile applied to this sink's lines. One of
    /// `internal | external`. `external` strips JA3/JA4 fingerprints
    /// and raw query strings in addition to the standard redactions.
    /// Tenant-scoped sinks default to `external`.
    #[serde(default)]
    pub profile: Option<String>,
}

/// WOR-1045 + WOR-1046: tagged-union of supported sink output types.
/// Each variant carries its own configuration.
///
/// Variants: `stdout`, `stderr`, `file`, `otlp`. `syslog` remains a
/// planned follow-up. Unknown `type:` values fail compilation.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ObservabilitySinkOutput {
    /// Write to process stdout. The default for a freshly-installed
    /// proxy.
    #[default]
    Stdout,
    /// Write to process stderr. Useful for routing the audit channel
    /// separately from access on systemd-journald.
    Stderr,
    /// Append to a file with optional rotation. Reuses the
    /// access-log rotation stack
    /// (`sbproxy_observe::access_log` rotation + gzip path).
    File {
        /// Absolute path to the output file. The parent directory
        /// must exist; the file is created on first write.
        path: String,
        /// Maximum file size before rotation. Defaults to 100 MiB.
        #[serde(default)]
        max_size_mb: Option<u64>,
        /// Number of rotated backups to keep. Defaults to 7.
        #[serde(default)]
        max_backups: Option<u32>,
        /// Whether to gzip rotated backups. Defaults to true.
        #[serde(default)]
        compress: Option<bool>,
    },
    /// WOR-1046: forward the rendered structured-log line to an OTLP
    /// log collector. The exporter wraps `opentelemetry_otlp::LogExporter`
    /// and ships records through a `BatchLogProcessor`. When `transport`
    /// and `timeout_secs` are omitted the sink inherits the values
    /// already declared on the top-level `telemetry:` block so a single
    /// operator config does not have to repeat collector coordinates.
    Otlp {
        /// OTLP collector endpoint (e.g.
        /// `http://otel-collector:4318/v1/logs` for HTTP/proto,
        /// `http://otel-collector:4317` for gRPC). The path component
        /// is honoured for HTTP transport; the gRPC variant uses the
        /// host:port only.
        endpoint: String,
        /// Transport selector: `http` or `grpc`. Defaults to whatever
        /// the top-level `telemetry.transport` declares; `grpc` when
        /// that block is absent.
        #[serde(default)]
        transport: Option<String>,
        /// Per-export timeout in seconds. Defaults to 10 seconds when
        /// omitted; honoured by the underlying OTLP exporter's HTTP /
        /// gRPC client.
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
}

/// Per-level sample rates for the structured-log emitter.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ObservabilitySamplingConfig {
    /// Fraction of `info` lines to emit (default 1.0).
    #[serde(default)]
    pub info: Option<f64>,
    /// Fraction of `debug` lines to emit (default 0.1).
    #[serde(default)]
    pub debug: Option<f64>,
    /// Fraction of `trace` lines to emit (default 0.01).
    #[serde(default)]
    pub trace: Option<f64>,
}

/// Subset of `sbproxy-observe::TelemetryConfig` exposed in the YAML.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ObservabilityTelemetryConfig {
    /// Whether OTLP export is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// OTLP collector endpoint URL.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Transport: `http` or `grpc`. Default `grpc`.
    #[serde(default)]
    pub transport: Option<String>,
    /// `service.name` resource attribute. Default `sbproxy`.
    #[serde(default)]
    pub service_name: Option<String>,
    /// Head-based sampling probability for unsampled roots. Default 0.1.
    #[serde(default)]
    pub sample_rate: Option<f64>,
    /// Always-sample errors / policy blocks / ledger denials. Default true.
    #[serde(default)]
    pub always_sample_errors: Option<bool>,
    /// Keep any completed trace at or above this derived USD cost.
    #[serde(default)]
    pub keep_over_budget_usd: Option<f64>,
    /// Keep any completed trace at or above this wall-clock latency.
    #[serde(default)]
    pub keep_slower_than_secs: Option<f64>,
    /// Propagation format: `w3c` (default), `b3`, `jaeger`.
    #[serde(default)]
    pub propagation: Option<String>,
    /// Free-form resource attributes attached to every span.
    #[serde(default)]
    pub resource_attrs: std::collections::BTreeMap<String, String>,
    /// Mirror metrics over OTLP in addition to the Prometheus scrape.
    #[serde(default)]
    pub export_metrics: bool,
    /// Period for the OTLP metric exporter, seconds. Default 30s.
    #[serde(default)]
    pub metrics_interval_secs: Option<u64>,
    /// Additional headers sent with every OTLP export request (traces,
    /// metrics, and any OTLP log sink). Values may be literals or
    /// secret references (`${VAR}`, `file:`, `vault://`, `secret://`,
    /// and the other backend URI schemes); references resolve at boot
    /// and the proxy refuses to start when one cannot be resolved, so
    /// a raw reference never reaches the collector. Hosted backends
    /// (Grafana Cloud, Honeycomb, Langfuse Cloud, Datadog) authenticate
    /// with these headers.
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
}

/// Configuration for a single alert notification channel.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AlertChannelConfig {
    /// Channel type: `"webhook"`, `"slack"`, `"pagerduty"`, or `"log"`.
    #[serde(rename = "type")]
    pub channel_type: String,
    /// Webhook URL. Required for `webhook` (any receiver) and `slack`
    /// (the incoming-webhook URL); unused by `pagerduty` and `log`.
    pub url: Option<String>,
    /// Additional HTTP headers for webhook delivery.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// PagerDuty Events API v2 routing key (required when
    /// `channel_type == "pagerduty"`). Accepts secret references.
    #[serde(default)]
    pub routing_key: Option<String>,
}

// --- HTTP/3 Config ---

/// HTTP/3 (QUIC) configuration.
///
/// Temporarily inert: HTTP/3 is disabled until native QUIC support lands in
/// the underlying proxy engine. These fields still parse, but the listener is
/// not started; enabling it logs a warning instead.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Http3Config {
    /// Whether to enable the HTTP/3 (QUIC) listener.
    ///
    /// Currently ignored: HTTP/3 is temporarily disabled (see the struct
    /// docs). Setting this to `true` logs a warning and starts no listener.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum number of concurrent QUIC streams per connection.
    #[serde(default = "default_max_streams")]
    pub max_streams: u32,
    /// Idle timeout for QUIC connections, in seconds.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u32,
}

fn default_max_streams() -> u32 {
    100
}

fn default_idle_timeout() -> u32 {
    30
}

// --- Origin Config ---

// --- ConnectionPoolConfig ---

/// Per-origin connection pool tuning parameters.
///
/// Controls how many concurrent connections are maintained to an upstream,
/// how long idle connections are kept alive, and the maximum lifetime of
/// any individual connection.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ConnectionPoolConfig {
    /// Maximum number of concurrent connections to the upstream.
    ///
    /// Additional requests will queue until a connection is available.
    /// Default: 128.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Maximum idle time before a connection is closed, in seconds.
    ///
    /// Connections that have been unused for longer than this will be
    /// dropped from the pool.  Default: 90 s.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u32,

    /// Maximum total lifetime of a connection, in seconds.
    ///
    /// Connections older than this will be closed and replaced even if they
    /// are still healthy.  Default: 300 s.
    #[serde(default = "default_max_lifetime_secs")]
    pub max_lifetime_secs: u32,
}

fn default_max_connections() -> u32 {
    128
}

fn default_idle_timeout_secs() -> u32 {
    90
}

fn default_max_lifetime_secs() -> u32 {
    300
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            idle_timeout_secs: default_idle_timeout_secs(),
            max_lifetime_secs: default_max_lifetime_secs(),
        }
    }
}

/// WOR-1053: declared tenant. PR1 only carries the `id`; PR2+ adds
/// per-tenant `credentials`, `policies`, `vault`, and `observability`
/// blocks alongside the multi-tenant inheritance fan-out.
///
/// A reserved tenant id of `__default__` is the synthetic default
/// every origin resolves to when `origin.tenant_id` is absent. The
/// operator never declares `__default__` explicitly; doing so fails
/// config compile.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProxyTenantConfig {
    /// Operator-supplied stable identifier. Referenced from
    /// `origin.tenant_id` and stamped on every request the origin
    /// serves. Length capped to 256 ASCII characters at compile.
    pub id: String,
    /// Tenant-scoped credentials block. Inherits proxy-scope
    /// credentials of the same name unless overridden here.
    #[serde(default)]
    pub credentials: Vec<CredentialBlock>,
    /// Tenant-scoped observability block. Today the only nested
    /// surface is `log.redact.pii`, which composes against the
    /// proxy-scope `observability.log.redact.pii` block (see
    /// [`ObservabilityPiiConfig`]). Origin-scope and proxy-scope
    /// values compose in the same shape; resolution at emit time
    /// walks origin -> tenant -> proxy with most-specific-wins on
    /// `enabled` and a rules set that inherits + extends + disables.
    /// Absent leaves the tenant inheriting whatever proxy scope
    /// declared (or no PII pass at all).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<TenantObservabilityConfig>,
}

/// Tenant-scope observability sub-tree. The `log.redact` block (PII
/// rules, patterns, and field denylist), `log.sinks` (tenant-scoped
/// fan-out, filtered by `Principal.tenant_id`), `log.custom_fields`
/// (tenant-scoped access-log fields that override proxy-scope fields of
/// the same name), and `cardinality` (per-tenant metric label budget)
/// are all consumed at runtime.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TenantObservabilityConfig {
    /// Tenant-scoped log block. See [`TenantObservabilityLogConfig`].
    #[serde(default)]
    pub log: TenantObservabilityLogConfig,
    /// WOR-1067: per-tenant cardinality budget. Caps the unique label
    /// value count across `sbproxy_requests_total` and friends for
    /// just this tenant so a noisy tenant cannot demote labels for
    /// every other tenant. Omitting the block leaves this tenant on
    /// the proxy-wide budget (today's behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardinality: Option<TenantCardinalityConfig>,
}

/// WOR-1067: per-tenant cardinality budget. The runtime installs one
/// dedicated label-value tracker per declared tenant; overflows on
/// tenant B do not touch tenant A's accepted-value set. The
/// `__default__` tenant continues to use the proxy-wide
/// `CardinalityLimiter` (in `sbproxy-observe`) so single-tenant
/// deployments stay bit-for-bit identical to pre-WOR-1067 behaviour.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TenantCardinalityConfig {
    /// Maximum unique label values per metric, per label name, for
    /// requests resolving to this tenant. When omitted the
    /// observability stack falls back to its per-tenant default cap
    /// ([`crate::types::TENANT_CARDINALITY_DEFAULT_MAX_SERIES`]) so
    /// an operator can declare an `observability.cardinality:` block
    /// with no fields to opt this tenant in to the default per-tenant
    /// budget without having to pick a number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_series: Option<u32>,
}

/// WOR-1067: default per-tenant cardinality cap used when a tenant
/// declares an `observability.cardinality:` block with no
/// `max_series:` value. Picked so a noisy tenant can still cover a
/// reasonable agent / route fan-out without taking the proxy-wide
/// budget down with it.
pub const TENANT_CARDINALITY_DEFAULT_MAX_SERIES: u32 = 10_000;

/// Tenant-scope `log:` sub-block. Mirrors the proxy-scope
/// `ObservabilityLogConfig`; today exposes the redaction leaf plus the
/// tenant-scoped sinks fan-out (WOR-1045 PR2). The dispatcher routes
/// every record whose resolved `Principal.tenant_id` matches this
/// tenant into each declared sink; cross-tenant records never reach
/// here.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TenantObservabilityLogConfig {
    /// Tenant-scope `redact:` sub-block. See
    /// [`TenantObservabilityRedactConfig`].
    #[serde(default)]
    pub redact: TenantObservabilityRedactConfig,
    /// Tenant-scoped log sinks. Each sink's `name` is unique within
    /// this tenant; the same name may also appear at proxy scope (they
    /// are different sinks). Sinks at this scope default to the
    /// `external` redaction profile because the downstream backend is
    /// usually outside the operator's trust boundary.
    #[serde(default)]
    pub sinks: Vec<ObservabilitySinkConfig>,
    /// Tenant-scoped custom access-log fields. Same shape as the
    /// proxy-scope `custom_fields:`. A field defined here overrides a
    /// proxy-scope field with the same `name` for requests resolved to
    /// this tenant; an origin-scope field overrides both.
    #[serde(default)]
    pub custom_fields: Vec<CustomLogFieldConfig>,
}

/// Tenant-scope `redact:` sub-block. Today only `pii:` is honoured;
/// the field-key and pattern overrides remain proxy-scope only because
/// they touch the rendered JSON, which is tenant-agnostic in the
/// emitter.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct TenantObservabilityRedactConfig {
    /// WOR-1042: tenant-scope additions to the field-key denylist.
    /// Additive only; a tenant CANNOT disable a proxy-level field
    /// denylist entry because the security baseline always applies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// WOR-1042: tenant-scope additions to the regex pattern set.
    /// Additive on top of the proxy-scope patterns. Use `disable:`
    /// (below) to opt out of a more-general proxy-scope pattern by
    /// name (e.g. a healthcare tenant disabling a `phone_us` mask).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<ObservabilityRedactPattern>,
    /// WOR-1042: names of proxy-scope `patterns:` entries to opt out
    /// of at this tenant. Targets only the operator-supplied regex
    /// pass; the built-in field-key denylist is never disable-able.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disable: Vec<String>,
    /// Tenant-scope override for the proxy-scope PII pass. Resolution
    /// rules: the tenant inherits the proxy-scope `enabled` flag and
    /// the proxy-scope rule set, then ADDS its own `rules:` entries
    /// and SUBTRACTS its own `disable:` entries. An explicit
    /// `enabled: false` opts the tenant out even when proxy-scope
    /// enables PII. See [`ObservabilityPiiConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii: Option<ObservabilityPiiConfig>,
}

/// Canonical credentials block. Sits under
/// `proxy.credentials`, `tenants[].credentials`, or
/// `origins[].credentials`. A request resolves matching credentials
/// by walking origin -> tenant -> proxy scopes; the first scope that
/// produces a match for the request's principal serves the credential.
///
/// The credential carries:
///
/// * Which provider produces it (`type`, `provider`).
/// * Where the secret material lives (`key`, a provider-specific
///   secret reference such as `vault://`, `awssm://`, `gcpsm://`,
///   `k8ssecret://`, `secretfile://`, or `secret://`, or a legacy
///   `${ENV}` / `file:` / `secret:` reference).
/// * Which inbound principals can use it (`principals` selectors).
/// * Per-credential attribution metadata (`attrs`).
/// * Allow / deny model lists that stack on top of the origin-level
///   allowlist (most-restrictive wins).
/// * Per-credential sub-policies (rate limit, PII redaction, ...).
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CredentialBlock {
    /// Operator-supplied stable name. Unique within the declaring
    /// scope. Used to identify the credential in metrics and logs.
    pub name: String,
    /// Credential kind. Closed enum (`ai_provider`, `bearer`,
    /// `api_key`, `jwt`, `basic`, `oidc_client`,
    /// `outbound_token_exchange`, `outbound_client_credentials`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Provider name for `type: ai_provider` credentials. Matches an
    /// entry in the origin's `providers:` list. Ignored for non-AI
    /// credential kinds.
    #[serde(default)]
    pub provider: Option<String>,
    /// Secret material reference. Provider-specific schemes include
    /// `vault://`, `awssm://`, `gcpsm://`, `k8ssecret://`,
    /// `secretfile://`, and `secret://`; legacy `${ENV}`, `file:`,
    /// and `secret:` forms also remain valid. The resolver dispatches
    /// at runtime; the config parser carries it as a string.
    #[serde(default)]
    pub key: Option<String>,
    /// Principal selectors that match this credential to inbound
    /// principals. An empty list matches every principal; downstream
    /// resolution then uses the first credential whose selectors
    /// match the request.
    #[serde(default)]
    pub principals: Vec<PrincipalSelector>,
    /// Attribution attributes copied onto matched principals.
    #[serde(default)]
    pub attrs: CredentialAttrs,
    /// Model allow / deny lists. Stacks on top of the origin-level
    /// allowlist (most-restrictive wins).
    #[serde(default)]
    pub models: Option<CredentialModels>,
    /// Sub-policies that only fire when this credential matches.
    #[serde(default)]
    pub policies: Vec<CredentialPolicy>,
    /// Pin the upstream `model` field. When set, the AI dispatch
    /// rewrites the request's `model` before sending it to the
    /// provider; the client-supplied value is ignored. Mirrors the
    /// `route_to_model` field on the underlying `VirtualKeyConfig`.
    #[serde(default)]
    pub route_to_model: Option<String>,
    /// Replace the request's `tools` array with these entries. The
    /// shape is provider-native (`function` objects today); the AI
    /// dispatch forwards the array verbatim. Empty == no injection.
    /// Mirrors `inject_tools` on the underlying `VirtualKeyConfig`.
    #[serde(default)]
    pub inject_tools: Vec<serde_json::Value>,
    /// WOR-1646: inject a federated MCP gateway's live catalogue as
    /// this credential's tool surface. Raw passthrough of the
    /// `InjectMcpRef` shape (`{ref, format, filter}`) on the
    /// underlying `VirtualKeyConfig`; resolved at request time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject_mcp: Option<serde_json::Value>,
}

/// Selector matching an inbound principal to a credential. At least
/// one field must be set; an entirely empty selector is rejected at
/// compile.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct PrincipalSelector {
    /// Glob matching `Principal.virtual_key.name`. `*` matches any
    /// virtual key. `vk_frontend_*` matches every key with that
    /// prefix.
    #[serde(default)]
    pub virtual_key: Option<String>,
    /// Match `Principal.attrs.team`.
    #[serde(default)]
    pub team: Option<String>,
    /// Match `Principal.attrs.project`.
    #[serde(default)]
    pub project: Option<String>,
    /// Match `Principal.attrs.user`.
    #[serde(default)]
    pub user: Option<String>,
    /// Match any of the principal's `attrs.roles`.
    #[serde(default)]
    pub role: Option<String>,
    /// Match an exact key=value entry on `Principal.attrs.claims`.
    /// Serialised as a flat map for readability.
    #[serde(default)]
    pub claim: std::collections::BTreeMap<String, String>,
}

/// Attribution attributes copied onto matched principals.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CredentialAttrs {
    /// Project the credential's spend rolls up to.
    #[serde(default)]
    pub project: Option<String>,
    /// User the credential is owned by (independent of who the
    /// inbound request authenticates as).
    #[serde(default)]
    pub user: Option<String>,
    /// Team grouping. Drives the team partition on the
    /// per-credential attribution metric.
    #[serde(default)]
    pub team: Option<String>,
    /// Cost center. Lifted onto `Principal.attrs.metadata` under
    /// the `cost_center` key for back-compat with the existing
    /// access-log surface.
    #[serde(default)]
    pub cost_center: Option<String>,
    /// Operator-supplied tags. Each tag becomes a separate
    /// attribution row.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Free-form metadata copied verbatim onto
    /// `Principal.attrs.metadata`.
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
    /// Per-credential budget. Sits inside `attrs:` because budget
    /// is an attribution-side concern; the budget enforcer reads
    /// the matched principal's attrs to apply caps.
    #[serde(default)]
    pub budget: Option<CredentialBudget>,
}

/// Per-credential budget. Reset windows use the LiteLLM-style
/// `30s|30m|30h|30d` syntax.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CredentialBudget {
    /// Maximum tokens (input + output combined) per reset window.
    #[serde(default)]
    pub max_tokens: Option<u64>,
    /// Maximum USD spend per reset window.
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
    /// Reset window. Parsed at config-load.
    #[serde(default)]
    pub reset: Option<String>,
}

/// Model allow / deny lists scoped to this credential. Stacks on top
/// of the origin-level allowlist. Most-restrictive wins.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CredentialModels {
    /// Models this credential is allowed to use. Empty allows all
    /// origin-allowed models.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Models this credential is explicitly denied. Stacks on top of
    /// `allow`: a model that is in `allow` but also in `deny` is
    /// denied.
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Sub-policy attached to a credential. Closed enum; out-of-tree
/// policies plug in through the existing plugin registry rather than
/// widening this enum.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialPolicy {
    /// Per-credential rate limit. Stacks on top of the origin-level
    /// rate limit (most-restrictive wins).
    RateLimit {
        /// Requests per minute cap.
        #[serde(default)]
        rpm: Option<u64>,
    },
    /// Require PII redaction for the named rule set on every request
    /// served by this credential. The names match
    /// `sbproxy_security::pii::default_rules`.
    RequirePiiRedaction {
        /// Rule names that MUST run on every request.
        rules: Vec<String>,
    },
}

/// A single origin config as it appears in YAML.
/// Plugin-specific fields are kept as `serde_json::Value` for deferred parsing.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RawOriginConfig {
    /// Action describing what the origin does (proxy, redirect, static, etc.).
    pub action: serde_json::Value,
    /// WOR-1053: declared tenant for this origin. Must match an `id`
    /// under `proxy.tenants[]`; absent resolves to the synthetic
    /// `__default__` tenant so existing single-tenant configs keep
    /// working unchanged.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Canonical credentials block at origin scope. Overrides + adds
    /// to the tenant + proxy scopes. See [`CredentialBlock`].
    #[serde(default)]
    pub credentials: Vec<CredentialBlock>,
    /// Authentication block (also accepted under YAML alias `auth`).
    #[serde(default, alias = "auth")]
    pub authentication: Option<serde_json::Value>,
    /// Policy entries (rate limit, WAF, IP filter, etc.) evaluated in order.
    #[serde(default)]
    pub policies: Vec<serde_json::Value>,
    /// Transform pipeline applied to request and response bodies.
    #[serde(default)]
    pub transforms: Vec<serde_json::Value>,
    /// Request modifiers (header rewrites, path edits, etc.).
    #[serde(default)]
    pub request_modifiers: Vec<RequestModifierConfig>,
    /// Response modifiers applied after the action returns.
    #[serde(default)]
    pub response_modifiers: Vec<ResponseModifierConfig>,
    /// Optional CORS configuration.
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    /// Optional HSTS configuration.
    #[serde(default)]
    pub hsts: Option<HstsConfig>,
    /// Optional response compression configuration.
    #[serde(default)]
    pub compression: Option<CompressionConfig>,
    /// Optional session cookie configuration (also accepted as `session_config`).
    #[serde(default, alias = "session_config")]
    pub session: Option<SessionConfig>,
    /// Per-origin custom-properties capture. Mirrors
    /// [`sbproxy_observe::PropertiesConfig`]; absent means the proxy
    /// uses the type's `Default` (capture on, no echo, no redaction).
    #[serde(default)]
    pub properties: Option<sbproxy_observe::PropertiesConfig>,
    /// Per-origin session-id capture. Mirrors
    /// [`sbproxy_observe::SessionsConfig`]; absent means the proxy uses
    /// the type's `Default` (capture on, `Anonymous` auto-generate).
    #[serde(default)]
    pub sessions: Option<sbproxy_observe::SessionsConfig>,
    /// Per-origin user-id capture. Mirrors
    /// [`sbproxy_observe::UserConfig`]; absent means the proxy uses the
    /// type's `Default` (capture on, 256-byte cap).
    #[serde(default)]
    pub user: Option<sbproxy_observe::UserConfig>,
    /// When true, redirect plain HTTP requests to HTTPS.
    #[serde(default)]
    pub force_ssl: bool,
    /// Whitelist of HTTP methods this origin accepts; empty allows all.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Path-based forward rules to inline child origins.
    #[serde(default)]
    pub forward_rules: Vec<RawForwardRule>,
    /// Origin used when the primary upstream fails.
    #[serde(default)]
    pub fallback_origin: Option<serde_json::Value>,
    /// Per-origin response-cache configuration (raw, compiled later).
    #[serde(default)]
    pub response_cache: Option<serde_json::Value>,
    /// Static variables available for template interpolation.
    #[serde(default)]
    pub variables: HashMap<String, serde_json::Value>,
    /// Hooks invoked when a request enters the origin.
    #[serde(default)]
    pub on_request: Vec<serde_json::Value>,
    /// Hooks invoked when a response is being returned.
    #[serde(default)]
    pub on_response: Vec<serde_json::Value>,
    /// Bot detection configuration.
    #[serde(default)]
    pub bot_detection: Option<serde_json::Value>,
    /// Threat protection (IP reputation, blocklist) configuration.
    #[serde(default)]
    pub threat_protection: Option<serde_json::Value>,
    /// Configuration for rate-limit response headers (`X-RateLimit-*`, `Retry-After`).
    #[serde(default)]
    pub rate_limit_headers: Option<serde_json::Value>,
    /// Per-status custom error response bodies. Each entry covers one
    /// or more HTTP status codes and contributes a content-typed body
    /// the proxy substitutes when it generates the matching status.
    /// Multiple entries for the same status are content-negotiated
    /// against the inbound request's `Accept` header.
    #[serde(default)]
    pub error_pages: Option<Vec<ErrorPageEntry>>,
    /// RFC 9457 `application/problem+json` default-renderer
    /// configuration. When enabled, proxy-generated errors that are
    /// not matched by an [`ErrorPageEntry`] render as a structured
    /// problem-details body. Composes with `error_pages`: custom
    /// pages still win when authored. See [`ProblemDetailsConfig`].
    #[serde(default)]
    pub problem_details: Option<ProblemDetailsConfig>,
    /// RFC 9209 `Proxy-Status` response header configuration. When
    /// enabled, the proxy stamps a structured `Proxy-Status` header
    /// on every non-2xx response so downstream clients can diagnose
    /// forwarding errors without scraping the body. The identity
    /// token defaults to `sbproxy` and can be overridden for fleet-
    /// wide branding (e.g. `acme-edge`).
    #[serde(default)]
    pub proxy_status: Option<ProxyStatusConfig>,
    /// Traffic capture / mirroring configuration.
    #[serde(default)]
    pub traffic_capture: Option<serde_json::Value>,
    /// Shadow traffic mirror, fire-and-forget copy of each request to
    /// a separate upstream. See [`MirrorConfig`].
    #[serde(default)]
    pub mirror: Option<MirrorConfig>,
    /// HTTP message signatures configuration (RFC 9421).
    #[serde(default)]
    pub message_signatures: Option<MessageSignaturesConfig>,
    /// WOR-808 PR7: RSL Open License Protocol issuer configuration.
    /// When set, the proxy serves `/.well-known/olp/token` (issuance)
    /// and `/.well-known/olp/key` (JWK publication) on the origin so
    /// crawlers following a `WWW-Authenticate: License` challenge can
    /// obtain and verify license tokens.
    #[serde(default)]
    pub olp: Option<OlpConfig>,
    /// WOR-805 AC#4: opt in to publishing SBproxy's own Web Bot
    /// Auth signing-key directory at
    /// `/.well-known/http-message-signatures-directory` and the
    /// Signature Agent Card discovery doc. Verifiers that fetch
    /// the directory can then verify the signatures SBproxy attaches
    /// to outbound requests when the corresponding
    /// `MessageSignatureSigner` runs upstream of the proxy.
    #[serde(default)]
    pub web_bot_auth_publish: Option<WebBotAuthPublishConfig>,
    /// RFC 8594-style idempotency-key middleware. Opt in per origin to
    /// have the proxy short-circuit retries of POST/PUT/PATCH (or any
    /// configured method) carrying a repeated `Idempotency-Key`
    /// header. See [`IdempotencyConfig`].
    #[serde(default)]
    pub idempotency: Option<IdempotencyConfig>,
    /// Per-origin connection pool tuning.  Falls back to proxy-wide defaults
    /// when not specified.
    #[serde(default)]
    pub connection_pool: Option<ConnectionPoolConfig>,
    /// Opaque per-origin extensions for out-of-tree config blocks.
    ///
    /// The compiler never parses these values. Extension consumers
    /// (e.g. a semantic-cache hook) read their own nested keys by
    /// name. Mirrors the server-level `proxy.extensions` pattern so
    /// the schema stays neutral.
    #[serde(default)]
    // WOR-1081: schemars 0.8 does not know about `serde_yaml::Value`,
    // so model the schema as an arbitrary JSON object (the wire form
    // round-trips through serde_json equivalently for extension data).
    #[schemars(with = "serde_json::Map<String, serde_json::Value>")]
    pub extensions: HashMap<String, serde_yaml::Value>,
    /// When true, the gateway exposes a per-host OpenAPI document at
    /// `/.well-known/openapi.json` (and `.yaml`) for this origin. Off by
    /// default: emission is opt-in so origins do not leak route shape
    /// without the operator's consent.
    #[serde(default)]
    pub expose_openapi: bool,
    /// Per-origin streaming safety rule identifiers. Forwarded to the
    /// stream-safety hook so each origin can enforce its own subset
    /// (e.g. `["pii", "toxicity"]`). Empty disables streaming safety
    /// for the origin even when the hook is wired.
    #[serde(default)]
    pub stream_safety: Vec<String>,
    /// Per-origin default content shape used when the agent's
    /// `Accept` header is `*/*` or absent. Threaded into the
    /// synthesised `auto_content_negotiate` config by
    /// [`crate::compile_origin`]. Recognised values: `markdown`,
    /// `json`, `html`, `pdf`, `other`. Unset falls back to `html`.
    #[serde(default)]
    pub default_content_shape: Option<String>,
    /// Per-origin `Content-Signal` response header value. Closed
    /// enum (validated at compile time): `ai-train`, `search`,
    /// `ai-input`. When set, the proxy stamps
    /// `Content-Signal: <value>` on 200 responses for this origin
    /// and the projection cache (`licenses.xml`, `tdmrep.json`)
    /// reflects the same signal. An unset value means "no signal
    /// asserted" and the proxy stamps `TDM-Reservation: 1` instead.
    #[serde(default)]
    pub content_signal: Option<String>,
    /// Per-origin override for the Markdown projection's
    /// tokens-per-byte ratio. Threads into the synthesised
    /// `html_to_markdown` transform's `token_bytes_ratio` field and
    /// the projection fallback path so the `x-markdown-tokens`
    /// response header and the JSON envelope's `token_estimate` field
    /// both honour the override. Unset falls back to
    /// `DEFAULT_TOKEN_BYTES_RATIO` (0.25).
    #[serde(default)]
    pub token_bytes_ratio: Option<f32>,
    /// Per-origin Agent Skills v0.2.0 advertisement. When
    /// non-empty, the proxy serves `GET /.well-known/agent-skills/index.json`
    /// for this origin and re-hosts each path-absolute or relative
    /// artifact at the URL declared in the entry. Empty (or absent)
    /// keeps the well-known endpoint disabled for the origin so v1
    /// configs compile unchanged.
    #[serde(default)]
    pub agent_skills: Vec<AgentSkillEntry>,
    /// Per-origin `/AGENTS.md` body (WOR-809). When set, the proxy
    /// serves it verbatim at `GET /AGENTS.md` (content type
    /// `text/markdown`) per the AGENTS.md agent-instructions
    /// convention. Independent of `ai_crawl_control`. Absent keeps the
    /// endpoint off.
    #[serde(default)]
    pub agents_md: Option<String>,
    /// Per-origin `/ai.txt` body (WOR-809). When set, the proxy serves
    /// it verbatim at `GET /ai.txt` per the Spawning ai.txt
    /// convention. Independent of `ai_crawl_control`. Absent keeps the
    /// endpoint off.
    #[serde(default)]
    pub ai_txt: Option<String>,
    /// Per-origin agents.json manifest (WOR-820). When set, the proxy
    /// serves `GET /.well-known/agents.json` (the Wildcard agents.json
    /// v0.1 spec): operator-authored `info` + `flows`, with `sources`
    /// defaulting to the origin's emitted OpenAPI document. Independent
    /// of `ai_crawl_control`. Absent keeps the endpoint off.
    #[serde(default)]
    pub agents_json: Option<AgentsJsonConfig>,
    /// Per-origin outbound credential resolver (WOR-802). When set, the
    /// proxy mints/resolves a credential and stamps it on the request it
    /// sends upstream (RFC 8693 token exchange, OAuth client-credentials,
    /// or a vault-resolved secret). Kept as JSON for deferred
    /// compilation in `sbproxy-core` (the typed enum lives in
    /// `sbproxy-modules`). Secret fields use the standard `${ENV}`
    /// interpolation, resolved at config load.
    #[serde(default)]
    pub outbound_credential: Option<serde_json::Value>,
    /// Opt this origin into outbound Web Bot Auth signing (WOR-805).
    /// When `true` and `proxy.web_bot_auth` is configured, the proxy
    /// signs the request it sends upstream with the proxy's Ed25519 key
    /// (RFC 9421, `tag=web-bot-auth`), so an upstream that demands Web
    /// Bot Auth accepts SBproxy as a verified agent. Default `false`.
    #[serde(default)]
    pub outbound_web_bot_auth: bool,
    /// Origin-scope observability block. Today the only nested surface
    /// is `log.redact.pii`, which composes against the tenant-scope
    /// block (or proxy-scope when the origin has no tenant). See
    /// [`OriginObservabilityConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<OriginObservabilityConfig>,
}

/// Origin-scope observability sub-tree. The `log.redact` block,
/// `log.sinks` (origin-scoped fan-out, filtered by the stamped `route`),
/// and `log.custom_fields` (the most-specific access-log fields, which
/// override tenant- and proxy-scope fields of the same name) are all
/// consumed at runtime.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct OriginObservabilityConfig {
    /// Origin-scope log block. See [`OriginObservabilityLogConfig`].
    #[serde(default)]
    pub log: OriginObservabilityLogConfig,
}

/// Origin-scope `log:` sub-block. Mirrors the proxy-scope and
/// tenant-scope shape; exposes redaction plus origin-scoped sinks
/// (WOR-1045 PR2). The dispatcher routes every record whose stamped
/// `route` matches this origin's hostname into each declared sink.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct OriginObservabilityLogConfig {
    /// Origin-scope `redact:` sub-block. See
    /// [`OriginObservabilityRedactConfig`].
    #[serde(default)]
    pub redact: OriginObservabilityRedactConfig,
    /// Origin-scoped log sinks. Each sink's `name` is unique within
    /// this origin; cross-scope collisions with a tenant or proxy
    /// `sinks:` entry are intentional (they are different sinks).
    /// Sinks at this scope default to the `external` redaction profile.
    #[serde(default)]
    pub sinks: Vec<ObservabilitySinkConfig>,
    /// Origin-scoped custom access-log fields. Same shape as the
    /// proxy-scope `custom_fields:`. A field defined here is the most
    /// specific: it overrides a tenant- or proxy-scope field with the
    /// same `name` for requests routed to this origin.
    #[serde(default)]
    pub custom_fields: Vec<CustomLogFieldConfig>,
}

/// Origin-scope `redact:` sub-block. Carries the per-origin overrides
/// for the field-key denylist (WOR-1042 `fields:`, additive), the
/// operator regex pass (WOR-1042 `patterns:` + `disable:`), and the
/// rule-driven PII redactor (WOR-1043 `pii:`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct OriginObservabilityRedactConfig {
    /// WOR-1042: origin-scope additions to the field-key denylist.
    /// Additive only on top of the merged proxy + tenant set; an
    /// origin cannot disable a parent denylist entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// WOR-1042: origin-scope additions to the regex pattern set.
    /// Additive on top of proxy + tenant. Use `disable:` to opt out
    /// of a more-general pattern by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<ObservabilityRedactPattern>,
    /// WOR-1042: pattern names to opt out of at this origin. Resolved
    /// against the merged proxy + tenant pattern set; the built-in
    /// field-key denylist is never disable-able.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disable: Vec<String>,
    /// Origin-scope override for the tenant-scope (or proxy-scope
    /// when the origin has no tenant) PII pass. Resolution rules:
    /// the origin inherits the parent scope's `enabled` flag and rule
    /// set, then ADDS its own `rules:` entries and SUBTRACTS its own
    /// `disable:` entries. An explicit `enabled: false` opts the
    /// origin out even when parent scopes enable PII. See
    /// [`ObservabilityPiiConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii: Option<ObservabilityPiiConfig>,
}

/// Per-origin agents.json manifest configuration (WOR-820). See the
/// [`RawOriginConfig::agents_json`] field and the agents.json v0.1 spec
/// at <https://github.com/wild-card-ai/agents-json>.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, schemars::JsonSchema)]
pub struct AgentsJsonConfig {
    /// `info` block (title, version, description).
    pub info: AgentsJsonInfo,
    /// API sources. When omitted, the proxy emits a single source
    /// pointing at this origin's `/.well-known/openapi.json`. Each
    /// entry must carry an `id` and a `path` per the spec.
    #[serde(default)]
    pub sources: Option<Vec<serde_json::Value>>,
    /// Operator-authored flow objects, emitted verbatim. Each flow must
    /// be schema-valid (`id`, `title`, `description`, `actions`,
    /// `fields`); the proxy does not synthesize flows.
    #[serde(default)]
    pub flows: Vec<serde_json::Value>,
    /// Optional `overrides` array, emitted verbatim when present.
    #[serde(default)]
    pub overrides: Option<Vec<serde_json::Value>>,
}

/// The `info` block of an agents.json manifest.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, schemars::JsonSchema)]
pub struct AgentsJsonInfo {
    /// Human-readable manifest title.
    pub title: String,
    /// Manifest version string.
    pub version: String,
    /// Manifest description.
    #[serde(default)]
    pub description: String,
}

// --- Agent Skills v0.2.0 ---

/// One entry in an origin's `agent_skills:` advertisement.
///
/// The shape mirrors the v0.2.0 manifest entry described at
/// `https://schemas.agentskills.io/discovery/0.2.0/schema.json`:
/// every entry carries a stable name, a kind discriminator, a human
/// description, and the URL the agent fetches to retrieve the artifact.
/// A `digest` field is computed at config-load time by hashing the
/// resolved artifact bytes; the per-request handler re-hashes the body
/// on every serve and refuses to ship a tampered artifact.
///
/// The optional safety knobs (`max_decompression_ratio`, `max_entries`,
/// `max_expanded_bytes`, `max_clock_skew_secs`) cap archive parsing so
/// a malicious origin cannot zip-bomb a downstream agent. All four
/// have sensible defaults, and v1 configs that omit `agent_skills:`
/// pay nothing for the new schema field.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AgentSkillEntry {
    /// Stable identifier (used as the manifest `name` and as the
    /// audit-event subject). Must be unique within the origin's
    /// `agent_skills:` list.
    pub name: String,
    /// Discriminator: `skill-md` for a single Markdown body or
    /// `archive` for a `.tar.gz` / `.zip` bundle. The v0.2.0 spec
    /// reserves these two values; any other input is rejected at
    /// config-load time.
    #[serde(rename = "type")]
    pub kind: String,
    /// Human-readable description surfaced in the manifest. Reads
    /// like a one-line capability summary.
    pub description: String,
    /// URL the agent fetches to retrieve the artifact. May be:
    ///
    /// - A path-absolute reference (`/skills/foo.md`) re-hosted by
    ///   the proxy on the same origin.
    /// - A fully-qualified URL fetched once at config-load and
    ///   re-emitted verbatim in the manifest (the proxy does not
    ///   re-host external artifacts).
    /// - A relative reference (`skills/foo.md`) resolved per RFC 3986
    ///   against the request authority at serve time.
    pub url: String,
    /// Visibility gate. `public` (default) returns the entry to every
    /// caller. `authenticated` filters the entry out of the manifest
    /// served to anonymous callers; the proxy still recomputes the
    /// digest per request so caching does not leak filtered entries.
    #[serde(default = "default_agent_skill_visibility")]
    pub visibility: String,
    /// Local filesystem path to the artifact body, when the operator
    /// hosts the file alongside the config. Used for `skill-md`
    /// entries with a path-absolute or relative `url`. When neither
    /// `path` nor `body` is set and `url` is path-absolute, the
    /// compiler resolves the path relative to the workspace root.
    #[serde(default)]
    pub path: Option<String>,
    /// Inline literal body. Useful for short skill files without
    /// having to commit a separate Markdown file. Mutually exclusive
    /// with `path`; when both are set the compiler prefers `path`.
    #[serde(default)]
    pub body: Option<String>,
    /// Maximum decompression ratio (compressed:expanded) tolerated for
    /// `archive` entries. Default 100. Refuses to extract archives
    /// whose total expanded size exceeds the cap.
    #[serde(default)]
    pub max_decompression_ratio: Option<u32>,
    /// Maximum entry count per archive. Default 1000.
    #[serde(default)]
    pub max_entries: Option<u32>,
    /// Maximum expanded byte budget per archive. Default 10 MiB.
    #[serde(default)]
    pub max_expanded_bytes: Option<u64>,
    /// Per-entry clock-skew tolerance in seconds for any time-sensitive
    /// header attached to the artifact response. Default 60. Reserved:
    /// the v0.2.0 ship attaches no such header today; the field exists
    /// so a follow-up that signs each artifact body can wire its own
    /// freshness check without a config-schema break.
    #[serde(default)]
    pub max_clock_skew_secs: Option<u32>,
}

fn default_agent_skill_visibility() -> String {
    "public".to_string()
}

// --- Middleware Configs ---

/// CORS configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CorsConfig {
    /// Origins permitted by `Access-Control-Allow-Origin`. Alias: `allow_origins`.
    #[serde(default, alias = "allow_origins")]
    pub allowed_origins: Vec<String>,
    /// Methods permitted by `Access-Control-Allow-Methods`. Alias: `allow_methods`.
    #[serde(default, alias = "allow_methods")]
    pub allowed_methods: Vec<String>,
    /// Request headers permitted by `Access-Control-Allow-Headers`. Alias: `allow_headers`.
    #[serde(default, alias = "allow_headers")]
    pub allowed_headers: Vec<String>,
    /// Response headers exposed via `Access-Control-Expose-Headers`.
    #[serde(default)]
    pub expose_headers: Vec<String>,
    /// Optional preflight cache duration in seconds (`Access-Control-Max-Age`).
    #[serde(default)]
    pub max_age: Option<u64>,
    /// When true, sends `Access-Control-Allow-Credentials: true`.
    #[serde(default)]
    pub allow_credentials: bool,
    /// Legacy `enable: true` flag (alias: `enabled`). Accepted but not
    /// checked at runtime because the presence of the cors block is
    /// sufficient.
    #[serde(default, alias = "enabled")]
    pub enable: Option<bool>,
}

/// HSTS configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct HstsConfig {
    /// `max-age` directive of the `Strict-Transport-Security` header, in seconds.
    #[serde(default = "default_hsts_max_age")]
    pub max_age: u64,
    /// When true, emits the `includeSubDomains` HSTS directive.
    #[serde(default)]
    pub include_subdomains: bool,
    /// When true, emits the `preload` HSTS directive.
    #[serde(default)]
    pub preload: bool,
}

fn default_hsts_max_age() -> u64 {
    31_536_000
}

/// Compression configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CompressionConfig {
    /// Master switch for response compression. Alias: `enable`.
    #[serde(default = "default_true", alias = "enable")]
    pub enabled: bool,
    /// Allowed algorithms in priority order (e.g. `["br", "gzip"]`).
    #[serde(default)]
    pub algorithms: Vec<String>,
    /// Minimum response size, in bytes, before compression is applied.
    #[serde(default)]
    pub min_size: usize,
    /// Compression level. Reserved; not currently honored by the runtime.
    #[serde(default)]
    pub level: Option<u32>,
}

fn default_true() -> bool {
    true
}

/// Session configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SessionConfig {
    /// Name of the session cookie.
    pub cookie_name: Option<String>,
    /// Cookie lifetime in seconds. Alias: `cookie_max_age`.
    #[serde(default, alias = "cookie_max_age")]
    pub max_age: Option<u64>,
    /// When true, sets the `HttpOnly` cookie attribute.
    #[serde(default)]
    pub http_only: bool,
    /// When true, sets the `Secure` cookie attribute (HTTPS only).
    #[serde(default)]
    pub secure: bool,
    /// `SameSite` cookie attribute. Alias: `cookie_same_site`.
    #[serde(default, alias = "cookie_same_site")]
    pub same_site: Option<String>,
    /// When true, allow sessions over non-SSL connections.
    #[serde(default)]
    pub allow_non_ssl: bool,
}

// --- Forward rule configs ---

/// One forward rule on an origin: a set of matcher entries plus the inline
/// child origin to dispatch to when any entry hits.
///
/// Compiled at config-load time. The runtime walks the `rules` of each
/// forward rule against the incoming request and uses the first matching
/// entry's `origin`. Within a single entry the present matchers (path,
/// header, query) are ANDed; across entries they are ORed.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RawForwardRule {
    /// Path matchers. The rule fires when any one of these matches the request path.
    #[serde(default)]
    pub rules: Vec<ForwardRuleMatcher>,
    /// Inline child origin executed when the rule fires.
    pub origin: ForwardRuleOrigin,
    /// Parameter declarations that apply to every matcher in this rule.
    ///
    /// Mirrors the OpenAPI 3.0 Parameter Object verbatim so emission is a
    /// near-direct map. Used by OpenAPI emission to populate
    /// `paths.<path>.<method>.parameters[]` and is exposed on the request
    /// context as `path_params` after the matcher captures values.
    #[serde(default)]
    pub parameters: Vec<Parameter>,
}

/// An OpenAPI 3.0 Parameter Object declared on a forward rule.
///
/// Field names and shapes mirror the OpenAPI spec exactly so emission is a
/// direct passthrough. The `schema` field is kept as `serde_json::Value`
/// because the OpenAPI Schema Object is large and we forward it verbatim.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Parameter {
    /// Parameter name. For path params this must match a `{name}` segment
    /// in one of the rule's `template` matchers.
    pub name: String,
    /// Where the parameter appears: `path`, `query`, or `header`.
    #[serde(rename = "in")]
    pub location: ParameterLocation,
    /// Whether the parameter is required. Path params are always required
    /// per the OpenAPI spec; emission enforces this even when `false`.
    #[serde(default)]
    pub required: bool,
    /// Free-form description surfaced in the emitted spec.
    #[serde(default)]
    pub description: Option<String>,
    /// OpenAPI Schema Object (e.g. `{ "type": "integer", "format": "int64" }`).
    /// Forwarded verbatim into the emitted spec.
    #[serde(default)]
    pub schema: serde_json::Value,
}

/// Location of an OpenAPI parameter (`in:` field).
///
/// Matches the OpenAPI 3.0 enum exactly. `cookie` is intentionally not
/// supported here yet because the gateway has no per-cookie capture story.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ParameterLocation {
    /// A captured `{name}` segment from a `template` matcher.
    Path,
    /// A query string parameter.
    Query,
    /// A request header.
    Header,
}

/// One match entry inside a forward rule's `rules:` list.
///
/// Each entry may carry any combination of `path`, `header`, and `query`
/// matchers. Within a single entry the matchers are ANDed: every present
/// matcher must succeed for the entry to fire. Across entries in the
/// same rule the semantics are OR: any matching entry triggers the rule.
/// The shorthand `match: <prefix>` is equivalent to `path: { prefix: ... }`.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ForwardRuleMatcher {
    /// Structured path matcher.
    #[serde(default)]
    pub path: Option<PathMatcher>,
    /// Shorthand for a prefix match. Equivalent to `path: { prefix: <value> }`.
    #[serde(default, rename = "match")]
    pub match_prefix: Option<String>,
    /// Header equality / prefix matcher.
    #[serde(default)]
    pub header: Option<HeaderMatcher>,
    /// Query parameter matcher.
    #[serde(default)]
    pub query: Option<QueryMatcher>,
}

/// Match a request header by exact value or value prefix.
///
/// Exactly one of `value` or `prefix` should be set. When both are present
/// `value` wins (exact comparison). Header name matching is case-insensitive
/// per RFC 7230; value comparison is case-sensitive.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct HeaderMatcher {
    /// Header name (case-insensitive lookup).
    pub name: String,
    /// Required exact value.
    #[serde(default)]
    pub value: Option<String>,
    /// Required value prefix. Ignored when `value` is set.
    #[serde(default)]
    pub prefix: Option<String>,
}

/// Match a query string parameter by exact value.
///
/// The query string is parsed as `application/x-www-form-urlencoded`. The
/// matcher succeeds if any occurrence of `name` equals `value`. When `value`
/// is omitted the matcher succeeds whenever the parameter is present at all.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct QueryMatcher {
    /// Query parameter name (case-sensitive).
    pub name: String,
    /// Required exact value. When `None`, presence of the parameter is enough.
    #[serde(default)]
    pub value: Option<String>,
}

/// A path matcher inside a forward rule.
///
/// Exactly one of `prefix`, `exact`, `template`, or `regex` should be set.
/// Precedence when more than one is provided: `template` > `regex` > `exact` >
/// `prefix`. Templates and regex are evaluated lazily, so origins that only
/// use prefix/exact pay no regex cost.
///
/// Template syntax (`/users/{id}/posts/{post_id}`) supports named segments,
/// catch-all (`/static/{*rest}`), and optional per-segment regex constraints
/// (`/users/{id:[0-9]+}`). Constraint compilation happens at config-load time;
/// the runtime only re-validates constrained params after the trie match.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct PathMatcher {
    /// Matches any path that starts with this prefix.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Matches only this exact path string.
    #[serde(default)]
    pub exact: Option<String>,
    /// OpenAPI-style path template with named segments. Captured params
    /// are exposed on the request context as `path_params` for downstream
    /// modifiers, CEL/Lua scripts, and metrics labels.
    #[serde(default)]
    pub template: Option<String>,
    /// Whole-path regex escape hatch. Use named captures (`(?P<id>...)`)
    /// to surface params on the request context.
    #[serde(default)]
    pub regex: Option<String>,
}

/// Inline child origin used when a forward rule fires. Carries the action plus
/// optional request modifiers and identifying metadata.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ForwardRuleOrigin {
    /// Optional identifier used in metrics and logs.
    #[serde(default)]
    pub id: Option<String>,
    /// Optional hostname tag (informational; the parent origin's hostname is what routed the request).
    #[serde(default)]
    pub hostname: Option<String>,
    /// Optional workspace identifier.
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// Optional version label.
    #[serde(default)]
    pub version: Option<String>,
    /// Action executed when the rule fires. Stays as raw JSON because action
    /// types are plugin-extensible (registered via the inventory crate).
    pub action: serde_json::Value,
    /// Optional request modifiers applied before the action runs.
    #[serde(default)]
    pub request_modifiers: Vec<RequestModifierConfig>,
}

// --- Modifier Configs ---

/// Request modifier entry.
///
/// Each modifier entry can contain one or more of: `headers`, `url`, `query`,
/// `method`, `body`, or `lua_script`. Multiple modifier entries in the list
/// are applied in order.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RequestModifierConfig {
    /// Header set/add/remove operations.
    #[serde(default)]
    pub headers: Option<HeaderModifiers>,
    /// URL path rewrite rules.
    #[serde(default)]
    pub url: Option<UrlModifier>,
    /// Query parameter modifications.
    #[serde(default)]
    pub query: Option<QueryModifier>,
    /// Override the HTTP method (e.g., "POST", "PUT").
    #[serde(default)]
    pub method: Option<String>,
    /// Body replacement.
    #[serde(default)]
    pub body: Option<BodyModifier>,
    /// Optional Lua script for dynamic request modification.
    #[serde(default)]
    pub lua_script: Option<String>,
    /// Optional JavaScript script for dynamic request modification.
    #[serde(default)]
    pub js_script: Option<String>,
}

/// URL path rewrite configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct UrlModifier {
    /// Path rewrite rules.
    #[serde(default)]
    pub path: Option<PathRewrite>,
}

/// Path rewrite: replace a substring in the path.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct PathRewrite {
    /// Replace a substring in the path.
    #[serde(default)]
    pub replace: Option<PathReplace>,
}

/// A simple string-replace operation on the URL path.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct PathReplace {
    /// The substring to search for.
    pub old: String,
    /// The replacement string.
    pub new: String,
}

/// Query parameter modification operations.
#[derive(Debug, Clone, Deserialize, Serialize, Default, schemars::JsonSchema)]
pub struct QueryModifier {
    /// Set (overwrite) query parameters.
    #[serde(default)]
    pub set: HashMap<String, String>,
    /// Add query parameters (appended even if the key already exists).
    #[serde(default)]
    pub add: HashMap<String, String>,
    /// Remove query parameters by name.
    #[serde(default, alias = "delete")]
    pub remove: Vec<String>,
}

/// Body replacement configuration for request modifiers.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BodyModifier {
    /// Replace the request body with this JSON value.
    #[serde(default)]
    pub replace_json: Option<serde_json::Value>,
    /// Replace the request body with this string.
    #[serde(default)]
    pub replace: Option<String>,
}

/// Response modifier entry.
///
/// Each modifier entry can contain one or more of: `headers`, `status`, `body`,
/// or `lua_script`. Multiple modifier entries in the list are applied in order.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ResponseModifierConfig {
    /// Header set/add/remove operations.
    #[serde(default)]
    pub headers: Option<HeaderModifiers>,
    /// Override the response status code and optional reason text.
    #[serde(default)]
    pub status: Option<StatusOverride>,
    /// Response body replacement.
    #[serde(default)]
    pub body: Option<ResponseBodyModifier>,
    /// Optional Lua script for dynamic response modification.
    #[serde(default)]
    pub lua_script: Option<String>,
    /// Optional JavaScript script for dynamic response modification.
    #[serde(default)]
    pub js_script: Option<String>,
}

/// Status code override for response modifiers.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct StatusOverride {
    /// The HTTP status code to set.
    pub code: u16,
    /// Optional reason phrase (not sent in HTTP/2, informational only).
    #[serde(default)]
    pub text: Option<String>,
}

/// Body replacement configuration for response modifiers.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ResponseBodyModifier {
    /// Replace the response body with this string.
    #[serde(default)]
    pub replace: Option<String>,
    /// Replace the response body with this JSON value.
    #[serde(default)]
    pub replace_json: Option<serde_json::Value>,
}

/// Header modification operations (set, add, remove).
#[derive(Debug, Clone, Deserialize, Serialize, Default, schemars::JsonSchema)]
pub struct HeaderModifiers {
    /// Headers to set, replacing any existing value.
    #[serde(default)]
    pub set: HashMap<String, String>,
    /// Headers to append (preserves existing values).
    #[serde(default)]
    pub add: HashMap<String, String>,
    /// Headers to remove. Alias: `delete`.
    #[serde(default, alias = "delete")]
    pub remove: Vec<String>,
}

// --- Secrets Config ---

/// Top-level secrets management configuration.
///
/// Controls which vault backend is used to resolve `secret:` references in
/// config values and how secret rotation is handled.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SecretsConfig {
    /// Backend to use for resolving secrets.
    ///
    /// Supported values: `"env"` (default), `"local"`, `"hashicorp"`.
    #[serde(default = "default_secrets_backend")]
    pub backend: String,
    /// HashiCorp Vault connection settings. Required when `backend = "hashicorp"`.
    #[serde(default)]
    pub hashicorp: Option<HashiCorpSecretsConfig>,
    /// Logical name to vault path mapping. INERT since the removal of
    /// the `secret:<name>` colon form it served (WOR-1785); still
    /// parsed for schema-v1 compatibility, and boot warns when set.
    /// Use `secret://<backend>/<name>` references instead.
    #[serde(default)]
    pub map: HashMap<String, String>,
    /// Secret rotation settings.
    #[serde(default)]
    pub rotation: Option<RotationConfig>,
    /// Fallback strategy when the vault backend is unavailable.
    ///
    /// Supported values: `"cache"` (default), `"reject"`, `"env"`.
    #[serde(default = "default_fallback")]
    pub fallback: String,
    /// Named secret backends that provider-URI references resolve against
    /// (WOR-1767). A `secret://<name>/<key>` reference resolves against the
    /// `local` backend named `<name>`; `secretfile://<name>/<key>` against
    /// the `file` backend named `<name>`. An unresolved reference in an
    /// `api_key` or `client_secret` fails startup rather than reaching the
    /// wire verbatim.
    #[serde(default)]
    pub backends: Vec<SecretBackendConfig>,
}

/// One named secret backend for provider-URI resolution (WOR-1767).
///
/// Config-native (does not depend on the vault crate). The binary builds a
/// vault manager from these at boot.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretBackendConfig {
    /// In-config secrets, referenced as `secret://<name>/<key>`. Entry
    /// values may themselves be `${ENV}` so real secrets stay out of YAML.
    Local {
        /// Backend name used in the `secret://<name>/...` reference.
        name: String,
        /// Key to value map.
        #[serde(default)]
        entries: HashMap<String, String>,
    },
    /// A YAML/JSON secrets file, referenced as `secretfile://<name>/<key>`.
    File {
        /// Backend name used in the `secretfile://<name>/...` reference.
        name: String,
        /// Path to the secrets file.
        path: std::path::PathBuf,
        /// File format.
        #[serde(default)]
        format: SecretFileFormat,
    },
    /// HashiCorp Vault KV, referenced as `vault://<name>/<path>`.
    Hashicorp {
        /// Backend name used in the `vault://<name>/...` reference.
        name: String,
        /// Vault server URL, e.g. `https://vault.example/v1`.
        addr: String,
        /// KV mount path.
        #[serde(default = "default_secret_mount")]
        mount: String,
        /// KV engine version.
        #[serde(default)]
        engine: SecretKvEngine,
        /// Cache TTL in seconds for resolved reads.
        #[serde(default)]
        cache_ttl_secs: Option<u64>,
        /// Optional Vault Enterprise namespace.
        #[serde(default)]
        namespace: Option<String>,
        /// Authentication method.
        auth: HashiCorpBackendAuth,
    },
    /// AWS Secrets Manager, referenced as `awssm://<name>/<secret-id>`.
    Aws {
        /// Backend name used in the `awssm://<name>/...` reference.
        name: String,
        /// AWS region.
        region: String,
        /// Path prefix every read must stay inside.
        mount_prefix: String,
        /// Cache TTL in seconds for resolved reads.
        #[serde(default)]
        cache_ttl_secs: Option<u64>,
        /// Authentication method.
        auth: AwsBackendAuth,
    },
    /// GCP Secret Manager, referenced as `gcpsm://<name>/<secret>`.
    Gcp {
        /// Backend name used in the `gcpsm://<name>/...` reference.
        name: String,
        /// Default GCP project id for short references.
        #[serde(default)]
        project_id: Option<String>,
        /// Secret Manager API endpoint override.
        #[serde(default)]
        endpoint: Option<String>,
        /// Cache TTL in seconds for resolved reads.
        #[serde(default)]
        cache_ttl_secs: Option<u64>,
        /// Authentication method (defaults to Application Default Credentials).
        #[serde(default)]
        auth: GcpBackendAuth,
    },
    /// Kubernetes Secrets, referenced as `k8ssecret://<name>/<secret>/<key>`.
    K8s {
        /// Backend name used in the `k8ssecret://<name>/...` reference.
        name: String,
        /// Namespace the backend reads Secret objects from.
        namespace: String,
        /// Cache TTL in seconds for resolved reads.
        #[serde(default)]
        cache_ttl_secs: Option<u64>,
        /// Authentication method.
        auth: K8sBackendAuth,
    },
}

/// Format of a `file` secret backend's contents (WOR-1767).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretFileFormat {
    /// YAML (default).
    #[default]
    Yaml,
    /// JSON.
    Json,
}

/// HashiCorp KV engine version for a `hashicorp` secret backend (WOR-1767).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretKvEngine {
    /// KV version 1.
    V1,
    /// KV version 2 (default).
    #[default]
    V2,
}

fn default_secret_mount() -> String {
    "secret".to_string()
}

/// Authentication for a `hashicorp` secret backend (WOR-1767).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HashiCorpBackendAuth {
    /// Static token.
    Token {
        /// Vault token (may be `${ENV}`).
        token: String,
    },
    /// AppRole role_id + secret_id.
    Approle {
        /// AppRole role id.
        role_id: String,
        /// AppRole secret id (may be `${ENV}`).
        secret_id: String,
        /// AppRole auth mount.
        #[serde(default)]
        mount: Option<String>,
    },
    /// Kubernetes service-account JWT exchange.
    Kubernetes {
        /// Vault role bound to the service account.
        role: String,
        /// Path to the service-account JWT.
        #[serde(default)]
        jwt_path: Option<String>,
        /// Kubernetes auth mount.
        #[serde(default)]
        mount: Option<String>,
    },
}

/// Authentication for an `aws` secret backend (WOR-1767).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AwsBackendAuth {
    /// Static access keys.
    StaticKeys {
        /// Access key id (may be `${ENV}`).
        access_key_id: String,
        /// Secret access key (may be `${ENV}`).
        secret_access_key: String,
        /// Optional session token (may be `${ENV}`).
        #[serde(default)]
        session_token: Option<String>,
    },
    /// The AWS default credential chain (env, instance profile, ...).
    DefaultChain,
    /// Assume an IAM role for cross-account access.
    AssumedRole {
        /// Role ARN to assume.
        role_arn: String,
        /// Optional external id from the trust policy.
        #[serde(default)]
        external_id: Option<String>,
        /// Optional session name.
        #[serde(default)]
        session_name: Option<String>,
    },
}

/// Authentication for a `gcp` secret backend (WOR-1767). Externally tagged
/// to match the bare-string `application_default` default.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GcpBackendAuth {
    /// Application Default Credentials (default).
    #[default]
    ApplicationDefault,
    /// A service-account key file on disk.
    ServiceAccountKeyFile {
        /// Path to the key file.
        path: String,
    },
    /// Inline service-account key JSON (may be `${ENV}`).
    ServiceAccountKeyJson {
        /// The key JSON.
        json: String,
    },
    /// An external-account (Workload Identity Federation) file.
    ExternalAccountFile {
        /// Path to the external-account file.
        path: String,
    },
}

/// Authentication for a `k8s` secret backend (WOR-1767).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum K8sBackendAuth {
    /// In-cluster service-account credentials.
    InCluster,
    /// A kubeconfig file.
    Kubeconfig {
        /// Path to the kubeconfig.
        path: String,
        /// Optional context name.
        #[serde(default)]
        context: Option<String>,
    },
}

/// HashiCorp Vault connection settings.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct HashiCorpSecretsConfig {
    /// Vault server address (e.g. `"https://vault.example.com:8200"`).
    pub addr: String,
    /// Vault token. When omitted the `VAULT_TOKEN` environment variable is used.
    #[serde(default)]
    pub token: Option<String>,
    /// KV secrets engine mount path. Defaults to `"secret"`.
    #[serde(default = "default_mount")]
    pub mount: String,
}

/// Secret rotation configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct RotationConfig {
    /// Seconds the previous secret value remains valid after rotation.
    /// Defaults to 300 (5 minutes).
    #[serde(default = "default_grace")]
    pub grace_period_secs: u64,
    /// How often (seconds) to re-fetch secrets from the vault backend.
    /// Defaults to 60.
    #[serde(default = "default_re_resolve")]
    pub re_resolve_interval_secs: u64,
}

fn default_secrets_backend() -> String {
    "env".to_string()
}

fn default_fallback() -> String {
    "cache".to_string()
}

fn default_mount() -> String {
    "secret".to_string()
}

fn default_grace() -> u64 {
    300
}

fn default_re_resolve() -> u64 {
    60
}

/// RFC 9209 `Proxy-Status` response header configuration.
///
/// When `enabled`, the proxy stamps a structured `Proxy-Status`
/// header on every non-2xx response. The header carries the proxy
/// identity, the upstream status, and an optional `error` parameter
/// derived from the upstream failure mode. Operators consuming the
/// header can diagnose forwarding errors without scraping the body.
///
/// Spec: <https://www.rfc-editor.org/rfc/rfc9209.html>.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProxyStatusConfig {
    /// Whether to stamp the `Proxy-Status` header on non-2xx responses.
    /// Defaults to `false`; opt in per origin so existing operator
    /// dashboards that match on bare status codes are not surprised.
    #[serde(default)]
    pub enabled: bool,
    /// Proxy identity token used as the first parameter of the header
    /// (per RFC 9209's grammar). Defaults to `sbproxy`. Operators
    /// running a fleet can override this for branding
    /// (e.g. `acme-edge`, `sbproxy-eu-west-1`).
    #[serde(default)]
    pub identity: Option<String>,
}

/// Status code spec for an [`ErrorPageEntry`]. Either a single integer
/// (`status: 401`) or a list (`status: [401, 403]`). The list form is
/// the historical authored shape; the single-int form is a sugar.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum StatusSpec {
    /// Single status code.
    Single(u16),
    /// Multiple status codes; any match counts.
    Multi(Vec<u16>),
}

impl StatusSpec {
    /// Returns true when `status` is covered by this spec.
    pub fn matches(&self, status: u16) -> bool {
        match self {
            Self::Single(s) => *s == status,
            Self::Multi(arr) => arr.contains(&status),
        }
    }

    /// Yield every status code this spec covers, in authored order.
    pub fn iter(&self) -> Box<dyn Iterator<Item = u16> + '_> {
        match self {
            Self::Single(s) => Box::new(std::iter::once(*s)),
            Self::Multi(arr) => Box::new(arr.iter().copied()),
        }
    }
}

/// One per-status custom error page entry. Multiple entries for the
/// same status code are content-negotiated against the inbound request's
/// `Accept` header.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ErrorPageEntry {
    /// Which HTTP status code(s) this entry covers.
    pub status: StatusSpec,
    /// `Content-Type` to advertise on the response.
    pub content_type: String,
    /// Response body. When `template = true`, the proxy substitutes
    /// `{{ status_code }}` and `{{ request.path }}` (with or without
    /// surrounding whitespace) at request time.
    pub body: String,
    /// When true, treat `body` as a template and run substitution.
    #[serde(default)]
    pub template: bool,
}

/// RFC 9457 Problem Details default-renderer configuration.
///
/// When enabled, any proxy-generated error response that is *not*
/// already matched by a custom [`ErrorPageEntry`] is rendered as
/// `application/problem+json` per RFC 9457. The two configs compose:
/// operators can author per-status custom pages and still opt in to
/// problem-details as a structured fallback for everything else.
///
/// Spec: <https://www.rfc-editor.org/rfc/rfc9457.html>.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProblemDetailsConfig {
    /// Whether to render unmatched proxy-generated errors as
    /// `application/problem+json`. Defaults to `false`; existing
    /// operators see no behavior change unless they opt in.
    #[serde(default)]
    pub enabled: bool,
    /// Base URI for the `type` field. When set to e.g.
    /// `https://api.example.com/errors`, status 503 renders as
    /// `type: https://api.example.com/errors/503`. When unset, the
    /// renderer emits the RFC 9457 default `about:blank`.
    #[serde(default)]
    pub type_base_uri: Option<String>,
    /// When true (the default), the renderer copies the proxy's
    /// internal error message into the `detail` field. Operators who
    /// route problem responses to external clients can set this to
    /// false to avoid leaking upstream error text.
    #[serde(default = "default_include_detail")]
    pub include_detail: bool,
}

fn default_include_detail() -> bool {
    true
}

/// RFC 8594-style idempotency middleware configuration.
///
/// When `enabled`, the proxy reads an idempotency key from the
/// configured request header (default: `Idempotency-Key`), hashes the
/// request body for conflict detection, and serves cached responses on
/// retries. Workspace-isolated keys mean two workspaces using the same
/// key never collide. The middleware engages only on the listed HTTP
/// methods; defaults to POST, PUT, and PATCH.
///
/// Backed by `sbproxy_middleware::idempotency` (the cache backend
/// trait + memory / Redis impls). For Redis-backed clusters set
/// `backend: redis`; the cache binds to the cluster L2 store at
/// compile time. Single-instance deployments leave `backend: memory`
/// (the default).
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
pub struct IdempotencyConfig {
    /// Whether to engage the idempotency middleware on this origin.
    /// Defaults to false; opt in per origin.
    #[serde(default)]
    pub enabled: bool,
    /// Request header name carrying the idempotency key. Defaults to
    /// `Idempotency-Key`.
    #[serde(default)]
    pub header_name: Option<String>,
    /// Time-to-live for cached entries, in seconds. Defaults to 86400
    /// (24 hours).
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// HTTP methods the middleware engages on. Defaults to
    /// `[POST, PUT, PATCH]`. Other methods (idempotent by HTTP spec)
    /// pass through unaffected.
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    /// Cache backend selector. `memory` (the default) uses an
    /// in-process LRU; `redis` binds to the cluster L2 store at
    /// compile time. Operators who set `redis` without configuring
    /// `proxy.l2_store` get an error at config-validate time.
    #[serde(default)]
    pub backend: IdempotencyBackend,
    /// Maximum request body size in bytes that the middleware will
    /// buffer for the cache check. Requests larger than this cap
    /// gracefully degrade: the middleware skips caching for that
    /// request and stamps `x-sbproxy-idempotency:
    /// SKIPPED-OVERSIZE-REQUEST` on the response so operators can
    /// see the skip. Defaults to 1 MiB.
    #[serde(default)]
    pub max_request_body_bytes: Option<usize>,
    /// Maximum response body size in bytes that will be buffered for
    /// caching. Responses larger than this cap stream to the client
    /// uncached; the next retry with the same key falls through to
    /// the upstream. Defaults to 1 MiB.
    #[serde(default)]
    pub max_response_body_bytes: Option<usize>,
    /// Process-wide cap on the number of concurrent buffered
    /// idempotency requests *for this origin*. When the pool is
    /// exhausted, new requests skip caching and stream normally;
    /// `x-sbproxy-idempotency: SKIPPED-POOL-FULL` is stamped so
    /// operators can spot pool pressure. Defaults to 256, which at
    /// the default per-request cap gives a 256 MiB worst-case
    /// memory budget per origin.
    #[serde(default)]
    pub max_concurrent_buffers: Option<usize>,
}

/// Default cap on request body bytes the middleware will buffer
/// for the cache check (1 MiB). Above this, the middleware skips
/// caching.
pub const DEFAULT_IDEMPOTENCY_MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// Default cap on response body bytes the middleware will buffer
/// for caching (1 MiB). Above this, the response streams through
/// uncached.
pub const DEFAULT_IDEMPOTENCY_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Default pool cap: how many concurrent buffered idempotency
/// requests per origin (256).
pub const DEFAULT_IDEMPOTENCY_MAX_CONCURRENT_BUFFERS: usize = 256;

/// Cache backend for [`IdempotencyConfig`].
#[derive(
    Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum IdempotencyBackend {
    /// In-process cache. Default. Suitable for single-instance
    /// deployments and per-replica idempotency in clusters where
    /// retries land on the same replica.
    #[default]
    Memory,
    /// Cluster-wide cache backed by the shared L2 store
    /// (`proxy.l2_store`). Required for clusters where retries may
    /// land on different replicas.
    Redis,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_observability_log_block() {
        let yaml = r#"
log:
  level: debug
  format: json
  sampling:
    info: 1.0
    debug: 0.5
    trace: 0.01
telemetry:
  enabled: true
  endpoint: http://otel-collector:4317
  transport: grpc
  service_name: sbproxy-dev
  sample_rate: 0.2
  always_sample_errors: true
  keep_over_budget_usd: 0.25
  keep_slower_than_secs: 2.5
  resource_attrs:
    deployment.environment: dev
"#;
        let obs: ObservabilityConfig = serde_yaml::from_str(yaml).unwrap();
        let log = obs.log.expect("log block parses");
        assert_eq!(log.level.as_deref(), Some("debug"));
        assert_eq!(log.format.as_deref(), Some("json"));
        let sampling = log.sampling.expect("sampling parses");
        assert_eq!(sampling.info, Some(1.0));
        assert_eq!(sampling.debug, Some(0.5));
        let telemetry = obs.telemetry.expect("telemetry parses");
        assert!(telemetry.enabled);
        assert_eq!(telemetry.transport.as_deref(), Some("grpc"));
        assert_eq!(telemetry.service_name.as_deref(), Some("sbproxy-dev"));
        assert_eq!(telemetry.sample_rate, Some(0.2));
        assert_eq!(telemetry.always_sample_errors, Some(true));
        assert_eq!(telemetry.keep_over_budget_usd, Some(0.25));
        assert_eq!(telemetry.keep_slower_than_secs, Some(2.5));
        assert_eq!(
            telemetry.resource_attrs.get("deployment.environment"),
            Some(&"dev".to_string())
        );
    }

    /// WOR-1045 PR1: the proxy-scoped sinks block parses with stdout,
    /// stderr, and file output variants. Per-sink `format` and
    /// `profile` are optional (inherit from the parent). The
    /// untagged-enum dispatch on `output: { type: ... }` picks the
    /// right variant; unknown types fail at parse time (covered by
    /// `parse_observability_sinks_rejects_unknown_output_type`).
    #[test]
    fn parse_observability_sinks_block() {
        let yaml = r#"
log:
  level: info
  format: json
  sinks:
    - name: stdout
      target: access_log
      format: json
      output: { type: stdout }
      profile: internal
    - name: stderr-audit
      target: audit_log
      output: { type: stderr }
    - name: file-archive
      target: audit_log
      format: json
      output:
        type: file
        path: /var/log/sbproxy/audit.json
        max_size_mb: 100
        max_backups: 7
        compress: true
      profile: internal
"#;
        let obs: ObservabilityConfig = serde_yaml::from_str(yaml).unwrap();
        let log = obs.log.expect("log block parses");
        assert_eq!(log.sinks.len(), 3);
        assert_eq!(log.sinks[0].name, "stdout");
        assert_eq!(log.sinks[0].target, "access_log");
        assert!(matches!(
            log.sinks[0].output,
            ObservabilitySinkOutput::Stdout
        ));
        assert!(matches!(
            log.sinks[1].output,
            ObservabilitySinkOutput::Stderr
        ));
        match &log.sinks[2].output {
            ObservabilitySinkOutput::File {
                path,
                max_size_mb,
                max_backups,
                compress,
            } => {
                assert_eq!(path, "/var/log/sbproxy/audit.json");
                assert_eq!(*max_size_mb, Some(100));
                assert_eq!(*max_backups, Some(7));
                assert_eq!(*compress, Some(true));
            }
            other => panic!("expected file output variant, got {other:?}"),
        }
    }

    /// WOR-1045 PR1: an unknown `output.type` value fails at parse
    /// time. The tagged-enum dispatch means we get a serde error
    /// without needing a post-parse validation pass.
    #[test]
    fn parse_observability_sinks_rejects_unknown_output_type() {
        let yaml = r#"
log:
  sinks:
    - name: bogus
      target: access_log
      output: { type: pigeon_carrier }
"#;
        let err = serde_yaml::from_str::<ObservabilityConfig>(yaml)
            .expect_err("unknown output type should fail to parse");
        let msg = err.to_string();
        assert!(
            msg.contains("pigeon_carrier") || msg.contains("variant"),
            "unhelpful error: {msg}"
        );
    }

    /// WOR-1046: an `otlp` output variant round-trips through the
    /// untagged enum. Endpoint, transport, and timeout all parse as
    /// expected; the dispatcher uses these to build an OTLP-logs
    /// exporter at startup.
    #[test]
    fn otlp_output_round_trips() {
        let yaml = r#"
log:
  sinks:
    - name: otel-collector
      target: access_log
      output:
        type: otlp
        endpoint: http://otel-collector:4318/v1/logs
        transport: http
        timeout_secs: 5
"#;
        let obs: ObservabilityConfig = serde_yaml::from_str(yaml).unwrap();
        let log = obs.log.expect("log block parses");
        assert_eq!(log.sinks.len(), 1);
        assert_eq!(log.sinks[0].name, "otel-collector");
        match &log.sinks[0].output {
            ObservabilitySinkOutput::Otlp {
                endpoint,
                transport,
                timeout_secs,
            } => {
                assert_eq!(endpoint, "http://otel-collector:4318/v1/logs");
                assert_eq!(transport.as_deref(), Some("http"));
                assert_eq!(*timeout_secs, Some(5));
            }
            other => panic!("expected otlp output variant, got {other:?}"),
        }
    }

    /// WOR-1045 PR2: a tenant `observability.log.sinks:` block
    /// deserialises with the same `ObservabilitySinkConfig` shape as
    /// the proxy scope. The dispatcher reads this list at config
    /// compile and routes records whose `tenant_id` matches into each
    /// declared sink.
    #[test]
    fn tenant_sinks_block_round_trips() {
        let yaml = r#"
http_bind_port: 8080
tenants:
  - id: acme
    observability:
      log:
        sinks:
          - name: acme-stdout
            target: access_log
            output: { type: stdout }
"#;
        let proxy: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(proxy.tenants.len(), 1);
        let tenant = &proxy.tenants[0];
        let obs = tenant.observability.as_ref().expect("tenant obs parses");
        assert_eq!(obs.log.sinks.len(), 1);
        assert_eq!(obs.log.sinks[0].name, "acme-stdout");
        assert_eq!(obs.log.sinks[0].target, "access_log");
        assert!(matches!(
            obs.log.sinks[0].output,
            ObservabilitySinkOutput::Stdout
        ));
    }

    /// WOR-1045 PR2: an origin `observability.log.sinks:` block
    /// deserialises with the same shape. The dispatcher resolves the
    /// origin scope by matching the record's `route` against the
    /// origin's hostname.
    #[test]
    fn origin_sinks_block_round_trips() {
        let yaml = r#"
action:
  type: proxy
  url: https://upstream.local
observability:
  log:
    sinks:
      - name: per-origin-file
        target: audit_log
        output:
          type: file
          path: /var/log/sbproxy/origin-acme.json
"#;
        let origin: RawOriginConfig = serde_yaml::from_str(yaml).unwrap();
        let obs = origin
            .observability
            .as_ref()
            .expect("origin obs block parses");
        assert_eq!(obs.log.sinks.len(), 1);
        assert_eq!(obs.log.sinks[0].name, "per-origin-file");
        match &obs.log.sinks[0].output {
            ObservabilitySinkOutput::File { path, .. } => {
                assert_eq!(path, "/var/log/sbproxy/origin-acme.json");
            }
            other => panic!("expected file output variant, got {other:?}"),
        }
    }

    /// WOR-1053 PR1: an empty `proxy.tenants:` field is the default;
    /// every origin resolves to the synthetic `__default__` tenant
    /// and existing single-tenant configs see no behaviour change.
    #[test]
    fn proxy_tenants_defaults_empty() {
        let proxy: ProxyServerConfig = ProxyServerConfig::default();
        assert!(proxy.tenants.is_empty());
    }

    /// WOR-1053 PR1: a declared tenant parses with just an `id`. The
    /// future per-tenant blocks (credentials / policies / vault) land
    /// in later PRs against the same type.
    #[test]
    fn parse_proxy_tenants_block() {
        let yaml = r#"
http_bind_port: 8080
tenants:
  - id: acme-corp
  - id: beta-corp
"#;
        let proxy: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(proxy.tenants.len(), 2);
        assert_eq!(proxy.tenants[0].id, "acme-corp");
        assert_eq!(proxy.tenants[1].id, "beta-corp");
    }

    /// WOR-1045 PR1: empty `sinks:` field is the default. An operator
    /// who never wrote a sinks block keeps the legacy stdout behaviour.
    #[test]
    fn observability_sinks_defaults_empty() {
        let yaml = r#"
log:
  level: info
"#;
        let obs: ObservabilityConfig = serde_yaml::from_str(yaml).unwrap();
        let log = obs.log.expect("log block parses");
        assert!(log.sinks.is_empty());
    }

    #[test]
    fn observability_defaults_to_none() {
        // ProxyServerConfig::default sets observability to None so an
        // operator who never wrote the YAML block keeps existing
        // behaviour (CLI / env only).
        let proxy: ProxyServerConfig = ProxyServerConfig::default();
        assert!(proxy.observability.is_none());
    }

    #[test]
    fn parse_url_rewrite_modifier() {
        let yaml = r#"
url:
  path:
    replace:
      old: "/old-path"
      new: "/echo"
"#;
        let modifier: RequestModifierConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(modifier.url.is_some());
        let url_mod = modifier.url.unwrap();
        let replace = url_mod.path.unwrap().replace.unwrap();
        assert_eq!(replace.old, "/old-path");
        assert_eq!(replace.new, "/echo");
    }

    #[test]
    fn parse_query_modifier() {
        let yaml = r#"
query:
  set:
    injected: "from-proxy"
  add:
    extra: "added"
"#;
        let modifier: RequestModifierConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(modifier.query.is_some());
        let q = modifier.query.unwrap();
        assert_eq!(
            q.set.get("injected").map(|s| s.as_str()),
            Some("from-proxy")
        );
        assert_eq!(q.add.get("extra").map(|s| s.as_str()), Some("added"));
    }

    #[test]
    fn parse_method_modifier() {
        let yaml = r#"method: POST"#;
        let modifier: RequestModifierConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(modifier.method.as_deref(), Some("POST"));
    }

    #[test]
    fn parse_body_modifier() {
        let yaml = r#"
body:
  replace_json: {"injected": true, "source": "proxy"}
"#;
        let modifier: RequestModifierConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(modifier.body.is_some());
        let body = modifier.body.unwrap();
        assert!(body.replace_json.is_some());
        let json = body.replace_json.unwrap();
        assert_eq!(json["injected"], true);
        assert_eq!(json["source"], "proxy");
    }

    #[test]
    fn parse_response_status_override() {
        let yaml = r#"
status:
  code: 201
  text: "Created By Proxy"
"#;
        let modifier: ResponseModifierConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(modifier.status.is_some());
        let status = modifier.status.unwrap();
        assert_eq!(status.code, 201);
        assert_eq!(status.text.as_deref(), Some("Created By Proxy"));
    }

    #[test]
    fn parse_response_body_modifier() {
        let yaml = r#"
body:
  replace: "replaced by response modifier"
"#;
        let modifier: ResponseModifierConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(modifier.body.is_some());
        let body = modifier.body.unwrap();
        assert_eq!(
            body.replace.as_deref(),
            Some("replaced by response modifier")
        );
    }

    #[test]
    fn parse_case25_request_modifiers_yaml() {
        // Fixtures live in the checked-in `e2e/` tree which may not be
        // present on every checkout (historically a symlink into the Go
        // repo). Skip rather than panic when the file is missing.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../e2e/cases/25-request-modifiers-advanced/sb.yml"
        );
        let Ok(yaml) = std::fs::read_to_string(path) else {
            eprintln!("skipping parse_case25: fixture missing at {path}");
            return;
        };
        let config: ConfigFile = serde_yaml::from_str(&yaml).unwrap();
        assert!(config.origins.contains_key("urlrewrite.test"));
        assert!(config.origins.contains_key("querymod.test"));
        assert!(config.origins.contains_key("methodmod.test"));
        assert!(config.origins.contains_key("bodymod.test"));
        assert!(config.origins.contains_key("headermod.test"));
        assert!(config.origins.contains_key("luamod.test"));

        // URL rewrite
        let urlmod = &config.origins["urlrewrite.test"].request_modifiers[0];
        assert!(urlmod.url.is_some());

        // Query modifier
        let querymod = &config.origins["querymod.test"].request_modifiers[0];
        assert!(querymod.query.is_some());

        // Method modifier
        let methodmod = &config.origins["methodmod.test"].request_modifiers[0];
        assert_eq!(methodmod.method.as_deref(), Some("POST"));

        // Body modifier
        let bodymod = &config.origins["bodymod.test"].request_modifiers[0];
        assert!(bodymod.body.is_some());
    }

    #[test]
    fn parse_js_script_request_modifier() {
        let yaml = r#"
js_script: |
  function modify_request(req, ctx) {
    req.headers["X-Injected"] = "from-js";
    return req;
  }
"#;
        let modifier: RequestModifierConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(modifier.js_script.is_some());
        assert!(modifier.js_script.unwrap().contains("modify_request"));
    }

    #[test]
    fn parse_js_script_response_modifier() {
        let yaml = r#"
js_script: |
  function modify_response(res, ctx) {
    res.headers["X-Injected"] = "from-js";
    return res;
  }
"#;
        let modifier: ResponseModifierConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(modifier.js_script.is_some());
        assert!(modifier.js_script.unwrap().contains("modify_response"));
    }

    // --- AcmeConfig tests ---

    #[test]
    fn acme_config_defaults() {
        let yaml = r#"
enabled: true
email: "admin@example.com"
"#;
        let acme: AcmeConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(acme.enabled);
        assert_eq!(acme.email, "admin@example.com");
        assert_eq!(
            acme.directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(acme.challenge_types, vec!["http-01"]);
        assert_eq!(acme.storage_backend, "redb");
        assert_eq!(acme.storage_path, "/var/lib/sbproxy/certs");
        assert_eq!(acme.renew_before_days, 30);
    }

    #[test]
    fn acme_config_explicit_values() {
        let yaml = r#"
enabled: true
email: "certs@mycompany.com"
directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory"
challenge_types:
  - "http-01"
storage_backend: "sqlite"
storage_path: "/data/certs"
renew_before_days: 14
"#;
        let acme: AcmeConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(acme.enabled);
        assert_eq!(acme.email, "certs@mycompany.com");
        assert_eq!(
            acme.directory_url,
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(acme.challenge_types, vec!["http-01"]);
        assert_eq!(acme.storage_backend, "sqlite");
        assert_eq!(acme.storage_path, "/data/certs");
        assert_eq!(acme.renew_before_days, 14);
    }

    #[test]
    fn acme_config_disabled_by_default() {
        let yaml = r#"
email: "admin@example.com"
"#;
        let acme: AcmeConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!acme.enabled);
    }

    // --- Http3Config tests ---

    #[test]
    fn http3_config_defaults() {
        let yaml = r#"
enabled: true
"#;
        let http3: Http3Config = serde_yaml::from_str(yaml).unwrap();
        assert!(http3.enabled);
        assert_eq!(http3.max_streams, 100);
        assert_eq!(http3.idle_timeout_secs, 30);
    }

    #[test]
    fn http3_config_explicit_values() {
        let yaml = r#"
enabled: true
max_streams: 500
idle_timeout_secs: 60
"#;
        let http3: Http3Config = serde_yaml::from_str(yaml).unwrap();
        assert!(http3.enabled);
        assert_eq!(http3.max_streams, 500);
        assert_eq!(http3.idle_timeout_secs, 60);
    }

    #[test]
    fn http3_config_disabled_by_default() {
        let yaml = r#"{}"#;
        let http3: Http3Config = serde_yaml::from_str(yaml).unwrap();
        assert!(!http3.enabled);
        assert_eq!(http3.max_streams, 100);
        assert_eq!(http3.idle_timeout_secs, 30);
    }

    // --- ProxyServerConfig with acme and http3 tests ---

    #[test]
    fn proxy_server_config_acme_and_http3_absent() {
        let yaml = r#"
http_bind_port: 8080
"#;
        let config: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.acme.is_none());
        assert!(config.http3.is_none());
    }

    #[test]
    fn proxy_server_config_with_acme() {
        let yaml = r#"
http_bind_port: 80
https_bind_port: 443
acme:
  enabled: true
  email: "admin@example.com"
"#;
        let config: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.acme.is_some());
        let acme = config.acme.unwrap();
        assert!(acme.enabled);
        assert_eq!(acme.email, "admin@example.com");
        assert_eq!(
            acme.directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert!(config.http3.is_none());
    }

    #[test]
    fn proxy_server_config_with_http3() {
        let yaml = r#"
http_bind_port: 80
http3:
  enabled: true
  max_streams: 200
"#;
        let config: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.http3.is_some());
        let http3 = config.http3.unwrap();
        assert!(http3.enabled);
        assert_eq!(http3.max_streams, 200);
        assert_eq!(http3.idle_timeout_secs, 30);
        assert!(config.acme.is_none());
    }

    #[test]
    fn proxy_server_config_with_both_acme_and_http3() {
        let yaml = r#"
http_bind_port: 80
https_bind_port: 443
acme:
  enabled: true
  email: "tls@example.com"
  renew_before_days: 7
http3:
  enabled: true
  max_streams: 300
  idle_timeout_secs: 45
"#;
        let config: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        let acme = config.acme.unwrap();
        assert!(acme.enabled);
        assert_eq!(acme.email, "tls@example.com");
        assert_eq!(acme.renew_before_days, 7);
        let http3 = config.http3.unwrap();
        assert!(http3.enabled);
        assert_eq!(http3.max_streams, 300);
        assert_eq!(http3.idle_timeout_secs, 45);
    }

    #[test]
    fn proxy_server_config_default_has_no_acme_or_http3() {
        let config = ProxyServerConfig::default();
        assert!(config.acme.is_none());
        assert!(config.http3.is_none());
        assert_eq!(config.http_bind_port, 8080);
    }

    // --- ScriptingConfig / LuaSandboxConfig tests ---

    #[test]
    fn lua_sandbox_config_default_matches_documented_values() {
        let cfg = LuaSandboxConfig::default();
        assert_eq!(cfg.max_execution_ms, 100);
        assert_eq!(cfg.max_memory_mb, 8);
        assert!(cfg.allow_patterns);
        assert_eq!(cfg.max_memory_bytes(), 8 * 1024 * 1024);
    }

    #[test]
    fn scripting_config_default_carries_lua_defaults() {
        let cfg = ScriptingConfig::default();
        assert_eq!(cfg.lua.sandbox, LuaSandboxConfig::default());
    }

    #[test]
    fn proxy_server_config_omitted_scripting_uses_defaults() {
        let yaml = r#"
http_bind_port: 8080
"#;
        let config: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.scripting.lua.sandbox.max_execution_ms, 100);
        assert_eq!(config.scripting.lua.sandbox.max_memory_mb, 8);
        assert!(config.scripting.lua.sandbox.allow_patterns);
    }

    #[test]
    fn proxy_server_config_lua_sandbox_overridable_from_yaml() {
        let yaml = r#"
http_bind_port: 8080
scripting:
  lua:
    sandbox:
      max_execution_ms: 250
      max_memory_mb: 64
      allow_patterns: false
"#;
        let config: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        let sandbox = config.scripting.lua.sandbox;
        assert_eq!(sandbox.max_execution_ms, 250);
        assert_eq!(sandbox.max_memory_mb, 64);
        assert!(!sandbox.allow_patterns);
        assert_eq!(sandbox.max_memory_bytes(), 64 * 1024 * 1024);
    }

    #[test]
    fn proxy_server_config_lua_sandbox_partial_override_keeps_defaults() {
        let yaml = r#"
http_bind_port: 8080
scripting:
  lua:
    sandbox:
      max_execution_ms: 500
"#;
        let config: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        let sandbox = config.scripting.lua.sandbox;
        assert_eq!(sandbox.max_execution_ms, 500);
        assert_eq!(sandbox.max_memory_mb, 8);
        assert!(sandbox.allow_patterns);
    }

    #[test]
    fn lua_sandbox_config_max_memory_bytes_saturates_on_overflow() {
        let cfg = LuaSandboxConfig {
            max_execution_ms: 100,
            max_memory_mb: usize::MAX,
            allow_patterns: true,
        };
        // Saturating multiplication clamps at usize::MAX rather than panicking.
        assert_eq!(cfg.max_memory_bytes(), usize::MAX);
    }

    // --- ConnectionPoolConfig tests ---

    #[test]
    fn connection_pool_defaults() {
        let cfg = ConnectionPoolConfig::default();
        assert_eq!(cfg.max_connections, 128);
        assert_eq!(cfg.idle_timeout_secs, 90);
        assert_eq!(cfg.max_lifetime_secs, 300);
    }

    #[test]
    fn connection_pool_deserialize_defaults() {
        let yaml = r#"{}"#;
        let cfg: ConnectionPoolConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.max_connections, 128);
        assert_eq!(cfg.idle_timeout_secs, 90);
        assert_eq!(cfg.max_lifetime_secs, 300);
    }

    #[test]
    fn connection_pool_deserialize_explicit() {
        let yaml = r#"
max_connections: 64
idle_timeout_secs: 30
max_lifetime_secs: 120
"#;
        let cfg: ConnectionPoolConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.max_connections, 64);
        assert_eq!(cfg.idle_timeout_secs, 30);
        assert_eq!(cfg.max_lifetime_secs, 120);
    }

    #[test]
    fn connection_pool_partial_deserialize() {
        let yaml = r#"max_connections: 256"#;
        let cfg: ConnectionPoolConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.max_connections, 256);
        assert_eq!(cfg.idle_timeout_secs, 90);
        assert_eq!(cfg.max_lifetime_secs, 300);
    }

    #[test]
    fn origin_config_with_connection_pool() {
        let yaml = r#"
action:
  type: proxy
  url: "http://upstream.internal"
connection_pool:
  max_connections: 32
  idle_timeout_secs: 45
"#;
        let origin: RawOriginConfig = serde_yaml::from_str(yaml).unwrap();
        let pool = origin
            .connection_pool
            .expect("connection_pool should be set");
        assert_eq!(pool.max_connections, 32);
        assert_eq!(pool.idle_timeout_secs, 45);
        assert_eq!(pool.max_lifetime_secs, 300); // default
    }

    #[test]
    fn origin_config_without_connection_pool() {
        let yaml = r#"
action:
  type: proxy
  url: "http://upstream.internal"
"#;
        let origin: RawOriginConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(origin.connection_pool.is_none());
    }

    #[test]
    fn parse_case26_response_modifiers_yaml() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../e2e/cases/26-response-modifiers-advanced/sb.yml"
        );
        let Ok(yaml) = std::fs::read_to_string(path) else {
            eprintln!("skipping parse_case26: fixture missing at {path}");
            return;
        };
        let config: ConfigFile = serde_yaml::from_str(&yaml).unwrap();
        assert!(config.origins.contains_key("statusmod.test"));
        assert!(config.origins.contains_key("respbody.test"));

        // Status override
        let statusmod = &config.origins["statusmod.test"].response_modifiers[0];
        assert!(statusmod.status.is_some());
        assert_eq!(statusmod.status.as_ref().unwrap().code, 201);

        // Body replacement
        let bodymod = &config.origins["respbody.test"].response_modifiers[0];
        assert!(bodymod.body.is_some());
        assert_eq!(
            bodymod.body.as_ref().unwrap().replace.as_deref(),
            Some("replaced by response modifier")
        );
    }

    // --- SecretsConfig tests ---

    #[test]
    fn secrets_config_defaults() {
        let yaml = r#"{}"#;
        let cfg: SecretsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.backend, "env");
        assert_eq!(cfg.fallback, "cache");
        assert!(cfg.hashicorp.is_none());
        assert!(cfg.map.is_empty());
        assert!(cfg.rotation.is_none());
    }

    #[test]
    fn secrets_config_hashicorp_backend() {
        let yaml = r#"
backend: hashicorp
hashicorp:
  addr: "https://vault.example.com:8200"
  token: "s.abc123"
  mount: "kv"
fallback: reject
"#;
        let cfg: SecretsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.backend, "hashicorp");
        assert_eq!(cfg.fallback, "reject");
        let hc = cfg.hashicorp.unwrap();
        assert_eq!(hc.addr, "https://vault.example.com:8200");
        assert_eq!(hc.token.as_deref(), Some("s.abc123"));
        assert_eq!(hc.mount, "kv");
    }

    #[test]
    fn secrets_config_map_deserialization() {
        let yaml = r#"
backend: env
map:
  openai_key: "secret/data/prod/openai_key"
  db_password: "secret/data/prod/db_password"
"#;
        let cfg: SecretsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            cfg.map.get("openai_key").map(|s| s.as_str()),
            Some("secret/data/prod/openai_key")
        );
        assert_eq!(
            cfg.map.get("db_password").map(|s| s.as_str()),
            Some("secret/data/prod/db_password")
        );
    }

    #[test]
    fn secrets_config_backends_deserialization() {
        // WOR-1767: the provider-URI backend surface.
        let yaml = r#"
backend: env
backends:
  - type: local
    name: app
    entries:
      openai_key: "${OPENAI_KEY}"
  - type: file
    name: shared
    path: /etc/sbproxy/secrets.yaml
    format: json
"#;
        let cfg: SecretsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.backends.len(), 2);
        match &cfg.backends[0] {
            SecretBackendConfig::Local { name, entries } => {
                assert_eq!(name, "app");
                assert_eq!(
                    entries.get("openai_key").map(|s| s.as_str()),
                    Some("${OPENAI_KEY}")
                );
            }
            other => panic!("expected local backend, got {other:?}"),
        }
        match &cfg.backends[1] {
            SecretBackendConfig::File { name, path, format } => {
                assert_eq!(name, "shared");
                assert_eq!(path.to_str(), Some("/etc/sbproxy/secrets.yaml"));
                assert!(matches!(format, SecretFileFormat::Json));
            }
            other => panic!("expected file backend, got {other:?}"),
        }
        // Default: no backends when omitted.
        let bare: SecretsConfig = serde_yaml::from_str("backend: env\n").unwrap();
        assert!(bare.backends.is_empty());
    }

    #[test]
    fn secrets_config_cloud_backends_deserialization() {
        // WOR-1785: the cloud backend variants + their auth sub-enums.
        let yaml = r#"
backend: env
backends:
  - type: hashicorp
    name: primary
    addr: https://vault.example/v1
    engine: v2
    auth:
      type: approle
      role_id: acme
      secret_id: "${VAULT_SECRET_ID}"
  - type: aws
    name: aws1
    region: us-east-1
    mount_prefix: prod/sbproxy
    auth:
      type: default_chain
  - type: gcp
    name: gcp1
    project_id: acme-prod
    auth: application_default
  - type: k8s
    name: k8s1
    namespace: apps
    auth:
      type: in_cluster
"#;
        let cfg: SecretsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.backends.len(), 4);
        match &cfg.backends[0] {
            SecretBackendConfig::Hashicorp {
                name,
                engine,
                auth,
                mount,
                ..
            } => {
                assert_eq!(name, "primary");
                // mount defaults to "secret" when omitted.
                assert_eq!(mount, "secret");
                assert!(matches!(engine, SecretKvEngine::V2));
                assert!(matches!(auth, HashiCorpBackendAuth::Approle { .. }));
            }
            other => panic!("expected hashicorp backend, got {other:?}"),
        }
        assert!(matches!(
            &cfg.backends[1],
            SecretBackendConfig::Aws {
                auth: AwsBackendAuth::DefaultChain,
                ..
            }
        ));
        assert!(matches!(
            &cfg.backends[2],
            SecretBackendConfig::Gcp {
                auth: GcpBackendAuth::ApplicationDefault,
                ..
            }
        ));
        assert!(matches!(
            &cfg.backends[3],
            SecretBackendConfig::K8s {
                auth: K8sBackendAuth::InCluster,
                ..
            }
        ));
    }

    #[test]
    fn secrets_config_rotation_block() {
        let yaml = r#"
backend: env
rotation:
  grace_period_secs: 600
  re_resolve_interval_secs: 120
"#;
        let cfg: SecretsConfig = serde_yaml::from_str(yaml).unwrap();
        let rot = cfg.rotation.unwrap();
        assert_eq!(rot.grace_period_secs, 600);
        assert_eq!(rot.re_resolve_interval_secs, 120);
    }

    #[test]
    fn secrets_config_rotation_defaults() {
        let yaml = r#"
rotation: {}
"#;
        let cfg: RotationConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.grace_period_secs, 300);
        assert_eq!(cfg.re_resolve_interval_secs, 60);
    }

    #[test]
    fn hashicorp_config_default_mount() {
        let yaml = r#"
addr: "https://vault.example.com:8200"
"#;
        let hc: HashiCorpSecretsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(hc.mount, "secret");
        assert!(hc.token.is_none());
    }

    #[test]
    fn proxy_server_config_with_secrets() {
        let yaml = r#"
http_bind_port: 8080
secrets:
  backend: hashicorp
  hashicorp:
    addr: "https://vault.internal:8200"
"#;
        let cfg: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        let secrets = cfg.secrets.unwrap();
        assert_eq!(secrets.backend, "hashicorp");
        let hc = secrets.hashicorp.unwrap();
        assert_eq!(hc.addr, "https://vault.internal:8200");
    }

    #[test]
    fn proxy_server_config_default_has_no_secrets() {
        let cfg = ProxyServerConfig::default();
        assert!(cfg.secrets.is_none());
    }

    #[test]
    fn extensions_field_accepts_arbitrary_nested_yaml() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    classifier:
      endpoint: "http://127.0.0.1:9500"
    semantic_cache:
      enabled: true
origins: {}
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).expect("parse");
        let ext = cfg.proxy.extensions;
        assert!(ext.contains_key("classifier"), "classifier ext present");
        assert!(
            ext.contains_key("semantic_cache"),
            "semantic_cache ext present"
        );
        let cls = ext.get("classifier").unwrap();
        assert_eq!(
            cls.get("endpoint").unwrap().as_str().unwrap(),
            "http://127.0.0.1:9500"
        );
    }

    #[test]
    fn extensions_field_defaults_to_empty() {
        let yaml = r#"
proxy:
  http_bind_port: 8080
origins: {}
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).expect("parse");
        assert!(cfg.proxy.extensions.is_empty());
    }

    #[test]
    fn origin_extensions_accepts_arbitrary_nested_yaml() {
        // Per-origin enterprise extensions (e.g. semantic_cache) live in
        // a sibling opaque map that OSS never inspects.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    extensions:
      semantic_cache:
        enabled: true
        ttl_secs: 1200
        key_template: "{embedding_model}:{lsh_bucket}"
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).expect("parse");
        let origin = &cfg.origins["api.example.com"];
        let sc = origin
            .extensions
            .get("semantic_cache")
            .expect("semantic_cache extension parsed");
        assert!(sc.get("enabled").unwrap().as_bool().unwrap());
        assert_eq!(sc.get("ttl_secs").unwrap().as_u64().unwrap(), 1200);
        assert_eq!(
            sc.get("key_template").unwrap().as_str().unwrap(),
            "{embedding_model}:{lsh_bucket}"
        );
    }

    #[test]
    fn origin_extensions_defaults_to_empty() {
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).expect("parse");
        assert!(cfg.origins["api.example.com"].extensions.is_empty());
    }

    // --- Access log config tests ---

    #[test]
    fn access_log_defaults_to_none_when_absent() {
        let yaml = r#"
origins: {}
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).expect("parse");
        assert!(cfg.access_log.is_none());
    }

    #[test]
    fn access_log_parses_with_defaults() {
        let yaml = r#"
access_log:
  enabled: true
origins: {}
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).expect("parse");
        let al = cfg.access_log.expect("access_log present");
        assert!(al.enabled);
        assert!((al.sample_rate - 1.0).abs() < f64::EPSILON);
        assert!(al.status_codes.is_empty());
        assert!(al.methods.is_empty());
    }

    #[test]
    fn access_log_parses_full_filter() {
        let yaml = r#"
access_log:
  enabled: true
  sample_rate: 0.25
  status_codes: [200, 500]
  methods: ["GET", "POST"]
  slow_request_threshold_ms: 1000
  always_log_errors: true
  output:
    type: file
    path: /tmp/sbproxy-access.log
    max_size_mb: 10
    max_backups: 3
    compress: true
origins: {}
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).expect("parse");
        let al = cfg.access_log.expect("access_log present");
        assert!(al.enabled);
        assert!((al.sample_rate - 0.25).abs() < f64::EPSILON);
        assert_eq!(al.status_codes, vec![200, 500]);
        assert_eq!(al.methods, vec!["GET".to_string(), "POST".to_string()]);
        assert_eq!(al.slow_request_threshold_ms, Some(1000.0));
        assert!(al.always_log_errors);
        assert_eq!(al.output.output_type, "file");
        assert_eq!(al.output.path.as_deref(), Some("/tmp/sbproxy-access.log"));
        assert_eq!(al.output.max_size_mb, 10);
        assert_eq!(al.output.max_backups, 3);
        assert!(al.output.compress);
    }

    #[test]
    fn access_log_should_emit_disabled_short_circuits() {
        let cfg = AccessLogConfig {
            enabled: false,
            sample_rate: 1.0,
            status_codes: vec![],
            methods: vec![],
            capture_headers: CaptureHeadersConfig::default(),
            ..Default::default()
        };
        assert!(!cfg.should_emit(200, "GET"));
    }

    #[test]
    fn access_log_should_emit_empty_filters_match_all() {
        let cfg = AccessLogConfig {
            enabled: true,
            sample_rate: 1.0,
            status_codes: vec![],
            methods: vec![],
            capture_headers: CaptureHeadersConfig::default(),
            ..Default::default()
        };
        assert!(cfg.should_emit(200, "GET"));
        assert!(cfg.should_emit(500, "DELETE"));
    }

    #[test]
    fn access_log_should_emit_status_filter() {
        let cfg = AccessLogConfig {
            enabled: true,
            sample_rate: 1.0,
            status_codes: vec![500, 502, 503],
            methods: vec![],
            capture_headers: CaptureHeadersConfig::default(),
            ..Default::default()
        };
        assert!(cfg.should_emit(500, "GET"));
        assert!(cfg.should_emit(502, "POST"));
        assert!(!cfg.should_emit(200, "GET"));
        assert!(!cfg.should_emit(404, "GET"));
    }

    #[test]
    fn access_log_should_emit_method_filter_case_insensitive() {
        let cfg = AccessLogConfig {
            enabled: true,
            sample_rate: 1.0,
            status_codes: vec![],
            methods: vec!["POST".to_string(), "DELETE".to_string()],
            capture_headers: CaptureHeadersConfig::default(),
            ..Default::default()
        };
        assert!(cfg.should_emit(200, "POST"));
        assert!(cfg.should_emit(204, "delete"));
        assert!(cfg.should_emit(204, "DeLeTe"));
        assert!(!cfg.should_emit(200, "GET"));
    }

    #[test]
    fn access_log_should_emit_combined_filters() {
        let cfg = AccessLogConfig {
            enabled: true,
            sample_rate: 1.0,
            status_codes: vec![500],
            methods: vec!["POST".to_string()],
            capture_headers: CaptureHeadersConfig::default(),
            ..Default::default()
        };
        assert!(cfg.should_emit(500, "POST"));
        assert!(!cfg.should_emit(500, "GET"));
        assert!(!cfg.should_emit(200, "POST"));
    }

    #[test]
    fn access_log_forces_slow_and_error_after_filters() {
        let cfg = AccessLogConfig {
            enabled: true,
            sample_rate: 0.0,
            status_codes: vec![],
            methods: vec!["GET".to_string()],
            capture_headers: CaptureHeadersConfig::default(),
            slow_request_threshold_ms: Some(1000.0),
            always_log_errors: true,
            output: AccessLogOutputConfig::default(),
        };

        assert!(cfg.matches_filters(200, "GET"));
        assert!(cfg.should_sample(200, 1200.0, 0.99));
        assert!(cfg.should_sample(503, 10.0, 0.99));
        assert!(!cfg.should_sample(200, 10.0, 0.99));
        assert!(
            !cfg.matches_filters(503, "POST"),
            "method filters still run before forced emission"
        );
    }

    // --- capture_headers parsing + matching tests ---

    #[test]
    fn capture_headers_defaults_when_absent() {
        let yaml = r#"
access_log:
  enabled: true
origins: {}
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).expect("parse");
        let al = cfg.access_log.expect("access_log");
        assert!(al.capture_headers.request.is_empty());
        assert!(al.capture_headers.response.is_empty());
        assert_eq!(al.capture_headers.max_value_bytes, 1024);
        assert!(!al.capture_headers.redact_pii);
        assert!(
            !al.capture_headers.redact_pii_other_fields,
            "redact_pii_other_fields must default off (WOR-118)"
        );
    }

    #[test]
    fn capture_headers_parses_full_block() {
        let yaml = r#"
access_log:
  enabled: true
  capture_headers:
    request: ["user-agent", "x-foo-*"]
    response: ["x-cache", "*"]
    max_value_bytes: 256
    redact_pii: true
    redact_pii_rules: ["email", "credit_card"]
    redact_pii_other_fields: true
origins: {}
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).expect("parse");
        let ch = cfg.access_log.expect("access_log").capture_headers;
        assert_eq!(ch.request, vec!["user-agent", "x-foo-*"]);
        assert_eq!(ch.response, vec!["x-cache", "*"]);
        assert_eq!(ch.max_value_bytes, 256);
        assert!(ch.redact_pii);
        assert_eq!(ch.redact_pii_rules, vec!["email", "credit_card"]);
        assert!(
            ch.redact_pii_other_fields,
            "WOR-118 knob round-trips through the YAML"
        );
    }

    #[test]
    fn compiled_allowlist_exact_match_lowercases() {
        let (compiled, warnings) =
            CompiledHeaderAllowlist::compile(&["User-Agent".to_string(), "X-Cache".to_string()]);
        assert!(warnings.is_empty());
        assert!(compiled.matches("user-agent"));
        assert!(compiled.matches("x-cache"));
        assert!(!compiled.matches("referer"));
    }

    #[test]
    fn compiled_allowlist_glob_prefix_matches() {
        let (compiled, _) = CompiledHeaderAllowlist::compile(&["x-ratelimit-*".to_string()]);
        assert!(compiled.matches("x-ratelimit-remaining"));
        assert!(compiled.matches("x-ratelimit-reset"));
        assert!(!compiled.matches("x-cache"));
    }

    #[test]
    fn compiled_allowlist_wildcard_captures_all() {
        let (compiled, _) = CompiledHeaderAllowlist::compile(&["*".to_string()]);
        assert!(compiled.wildcard);
        assert!(compiled.matches("user-agent"));
        assert!(compiled.matches("anything"));
    }

    #[test]
    fn compiled_allowlist_denylist_blocks_wildcard() {
        let (compiled, _) = CompiledHeaderAllowlist::compile(&["*".to_string()]);
        for sensitive in SENSITIVE_HEADER_DENYLIST {
            assert!(
                !compiled.matches(sensitive),
                "wildcard must not capture {sensitive}"
            );
        }
    }

    #[test]
    fn compiled_allowlist_denylist_blocks_glob() {
        let (compiled, _) = CompiledHeaderAllowlist::compile(&["x-*".to_string()]);
        // x-api-key is in the denylist; a glob hit must not bypass it.
        assert!(!compiled.matches("x-api-key"));
        assert!(compiled.matches("x-cache"));
    }

    #[test]
    fn compiled_allowlist_exact_overrides_denylist_with_warning() {
        let (compiled, warnings) = CompiledHeaderAllowlist::compile(&[
            "authorization".to_string(),
            "x-api-key".to_string(),
        ]);
        assert!(compiled.matches("authorization"));
        assert!(compiled.matches("x-api-key"));
        assert_eq!(warnings.len(), 2);
        assert!(warnings.contains(&"authorization".to_string()));
        assert!(warnings.contains(&"x-api-key".to_string()));
    }

    #[test]
    fn compiled_allowlist_empty_when_no_entries() {
        let (compiled, warnings) = CompiledHeaderAllowlist::compile(&[]);
        assert!(compiled.is_empty());
        assert!(warnings.is_empty());
        assert!(!compiled.matches("user-agent"));
    }

    #[test]
    fn compiled_allowlist_skips_blank_entries() {
        let (compiled, warnings) =
            CompiledHeaderAllowlist::compile(&["".to_string(), "   ".to_string()]);
        assert!(compiled.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn status_spec_single_matches_only_that_code() {
        let s = StatusSpec::Single(401);
        assert!(s.matches(401));
        assert!(!s.matches(403));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![401]);
    }

    #[test]
    fn status_spec_multi_matches_any_listed() {
        let s = StatusSpec::Multi(vec![401, 403, 429]);
        assert!(s.matches(401));
        assert!(s.matches(429));
        assert!(!s.matches(500));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![401, 403, 429]);
    }

    #[test]
    fn error_page_entry_parses_single_status_yaml() {
        let yaml = r#"
status: 401
content_type: application/json
template: true
body: '{"error":"unauthorized","code":{{ status_code }}}'
"#;
        let entry: ErrorPageEntry = serde_yaml::from_str(yaml).unwrap();
        assert!(entry.template);
        assert!(matches!(entry.status, StatusSpec::Single(401)));
        assert_eq!(entry.content_type, "application/json");
    }

    #[test]
    fn error_page_entry_parses_multi_status_yaml() {
        let yaml = r#"
status: [401, 403]
content_type: text/html
body: "<h1>Denied</h1>"
"#;
        let entry: ErrorPageEntry = serde_yaml::from_str(yaml).unwrap();
        assert!(!entry.template);
        match entry.status {
            StatusSpec::Multi(arr) => assert_eq!(arr, vec![401, 403]),
            _ => panic!("expected Multi variant"),
        }
    }

    #[test]
    fn problem_details_defaults_to_include_detail_true() {
        let yaml = r#"
enabled: true
"#;
        let pd: ProblemDetailsConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(pd.enabled);
        assert!(pd.include_detail);
        assert!(pd.type_base_uri.is_none());
    }

    #[test]
    fn problem_details_parses_type_base_uri_and_suppresses_detail() {
        let yaml = r#"
enabled: true
type_base_uri: "https://api.example.com/errors"
include_detail: false
"#;
        let pd: ProblemDetailsConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(pd.enabled);
        assert!(!pd.include_detail);
        assert_eq!(
            pd.type_base_uri.as_deref(),
            Some("https://api.example.com/errors")
        );
    }

    #[test]
    fn error_pages_array_shape_parses_at_origin_level() {
        // Matches the historical authored shape used by examples/error-pages
        // and the conformance suite: error_pages is a top-level YAML array.
        let yaml = r#"
action:
  type: proxy
  url: http://upstream
error_pages:
  - status: 401
    content_type: application/json
    body: '{"error":"unauthorized"}'
  - status: [403, 404]
    content_type: text/plain
    body: "denied"
"#;
        let origin: RawOriginConfig = serde_yaml::from_str(yaml).unwrap();
        let pages = origin.error_pages.expect("error_pages parses");
        assert_eq!(pages.len(), 2);
        assert!(pages[0].status.matches(401));
        assert!(pages[1].status.matches(403));
        assert!(pages[1].status.matches(404));
    }

    /// WOR-1043 PR2: a `tenants[].observability.log.redact.pii:` block
    /// deserialises into [`TenantObservabilityConfig`] and the rule
    /// list survives. Round-trip ensures the nested `log.redact.pii`
    /// path matches the on-disk YAML shape the ticket spelled out.
    #[test]
    fn tenant_observability_redact_pii_round_trips() {
        let yaml = r#"
id: hipaa-tenant
observability:
  log:
    redact:
      pii:
        enabled: true
        rules: [email, us_ssn]
        disable: [phone_us]
"#;
        let tenant: ProxyTenantConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tenant.id, "hipaa-tenant");
        let pii = tenant
            .observability
            .as_ref()
            .expect("observability block parses")
            .log
            .redact
            .pii
            .as_ref()
            .expect("pii block parses");
        assert_eq!(pii.enabled, Some(true));
        assert_eq!(pii.rules, vec!["email".to_string(), "us_ssn".to_string()]);
        assert_eq!(pii.disable, vec!["phone_us".to_string()]);
    }

    /// WOR-1043 PR3: an `origins[hostname].observability.log.redact.pii:`
    /// block deserialises into [`OriginObservabilityConfig`] and the
    /// rule list survives. Origin scope mirrors the tenant shape; the
    /// composer at startup intersects the lists.
    #[test]
    fn origin_observability_redact_pii_round_trips() {
        let yaml = r#"
action:
  type: proxy
  url: http://upstream
tenant_id: hipaa-tenant
observability:
  log:
    redact:
      pii:
        rules: [billing_account]
"#;
        let origin: RawOriginConfig = serde_yaml::from_str(yaml).unwrap();
        let pii = origin
            .observability
            .as_ref()
            .expect("observability block parses")
            .log
            .redact
            .pii
            .as_ref()
            .expect("pii block parses");
        assert_eq!(pii.enabled, None);
        assert_eq!(pii.rules, vec!["billing_account".to_string()]);
        assert!(pii.disable.is_empty());
    }

    /// WOR-1043 PR1 back-compat: a tenant with no `observability`
    /// block parses cleanly. Belt-and-suspenders coverage so the new
    /// optional field doesn't accidentally require an empty stub.
    #[test]
    fn tenant_without_observability_parses() {
        let yaml = "id: plain-tenant";
        let tenant: ProxyTenantConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tenant.id, "plain-tenant");
        assert!(tenant.observability.is_none());
    }
}

/// RFC 9421 HTTP Message Signatures verification configuration.
///
/// When `verify: true`, the proxy enforces RFC 9421 signature
/// verification on every inbound request to this origin. Requests
/// without a valid `Signature-Input` + `Signature` header pair
/// matching the configured `key_id` are rejected with `401
/// Unauthorized` and `WWW-Authenticate: Signature` before any
/// downstream auth provider runs.
///
/// `algorithm` is `hmac_sha256` or `ed25519`. `key` carries the
/// shared secret (HMAC) or the base64/hex-encoded raw 32-byte
/// public key (Ed25519). `required_components` is the optional set
/// of canonical components every accepted signature must cover.
/// `clock_skew_seconds` defaults to 30s.
///
/// Spec: <https://www.rfc-editor.org/rfc/rfc9421.html>.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct MessageSignaturesConfig {
    /// Whether to enforce signature verification on inbound requests.
    #[serde(default)]
    pub verify: bool,
    /// Required signature algorithm (`hmac_sha256` or `ed25519`).
    pub algorithm: String,
    /// The `keyid` value the signer is expected to advertise.
    pub key_id: String,
    /// Verification key material.
    pub key: String,
    /// Optional canonical components every accepted signature must cover.
    #[serde(default)]
    pub required_components: Vec<String>,
    /// Optional clock skew tolerance in seconds. Defaults to 30s.
    #[serde(default = "default_signature_clock_skew_seconds")]
    pub clock_skew_seconds: u64,
}

fn default_signature_clock_skew_seconds() -> u64 {
    30
}

/// WOR-808 PR7: Open License Protocol (OLP) issuer configuration.
///
/// When set, the proxy stands up two well-known endpoints on the
/// origin:
///
/// - `POST /.well-known/olp/token` — issues a license token signed
///   with the configured Ed25519 key, body shaped per RFC 6749
///   (`access_token` + `token_type: "License"` + `expires_in`).
/// - `GET /.well-known/olp/key` — publishes the verification JWK
///   set (RFC 7517) so external introspectors can verify tokens
///   without contacting the issuer per-token.
///
/// WOR-805 AC#4: Web Bot Auth publish config. When enabled the
/// proxy serves two unauthenticated well-known endpoints on this
/// origin:
///
/// * `GET /.well-known/http-message-signatures-directory` — JWKS
///   document carrying SBproxy's own Ed25519 signing-key public
///   key. Verifiers (Cloudflare, AWS WAF, any third-party origin
///   that runs a Web Bot Auth verifier) fetch this to verify the
///   `Signature-Input` + `Signature` headers SBproxy attaches to
///   outbound requests.
/// * `GET /.well-known/web-bot-auth/agent-card` — the discovery
///   document that points verifiers at the directory; carries the
///   operator-facing agent name, description, and contact URL.
///
/// `public_key_hex` is the 32-byte Ed25519 public key, hex-encoded
/// (the SECRET side never crosses this config; the signer that
/// runs upstream of the proxy holds it). `key_id` is the `kid` the
/// signer advertises and the directory JWK publishes.
///
/// Operators who do not configure this block expose neither
/// endpoint; requests to those paths fall through to the upstream
/// proxy (or return 404 if no route matches).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct WebBotAuthPublishConfig {
    /// Whether the publish endpoints are enabled.
    #[serde(default)]
    pub enabled: bool,
    /// `kid` the JWK + Signature Agent Card advertise. Stable
    /// across rotations of unrelated keys so an old `keyid=`
    /// reference in a signed request still resolves.
    pub key_id: String,
    /// Ed25519 public key, hex-encoded (32 bytes → 64 hex chars).
    pub public_key_hex: String,
    /// Operator-facing agent name on the Signature Agent Card.
    pub agent_name: String,
    /// `directory_url` the agent card points at. Must be `https://`;
    /// every Web Bot Auth verifier rejects plaintext.
    pub directory_url: String,
    /// Optional description shown alongside the agent name.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional contact URL (mailto:, https://, etc.) for misuse
    /// reports.
    #[serde(default)]
    pub contact_url: Option<String>,
    /// Optional 32-byte Ed25519 private seed, hex-encoded (64 hex
    /// chars). When set, the directory and agent-card HTTP responses
    /// are self-signed per RFC 9421 over `("content-digest")` with
    /// `tag="web-bot-auth"` and `keyid=key_id`. Verifiers can then
    /// confirm the body they fetched was emitted by the holder of
    /// the key the directory advertises, closing the trust loop
    /// without relying solely on TLS. Absent leaves the responses
    /// unsigned; the Web Bot Auth IETF draft permits both shapes and
    /// verifiers MAY treat unsigned directories as lower-trust. The
    /// secret-resolver pass honours secret references at config load
    /// so the raw seed never has to live in the YAML.
    #[serde(default)]
    pub signing_key_hex: Option<String>,
}

/// `/introspect` (RFC 7662) is deferred to a follow-up PR because
/// it requires a revocation / nonce store.
#[derive(
    Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq, schemars::JsonSchema,
)]
pub struct OlpConfig {
    /// Master toggle. When false the well-known endpoints 404.
    #[serde(default)]
    pub enabled: bool,
    /// Ed25519 signing key, hex-encoded 32-byte seed. Operators
    /// generate one with `openssl rand -hex 32` or read it from a
    /// secret store. The secret-resolver pass honours provider-specific
    /// references at config-load time, mirroring how other key-material
    /// fields work.
    pub signing_key: String,
    /// `kid` the JWS header advertises. Rotation appends a new key
    /// with a new kid and trusts both for the cutover window.
    pub key_id: String,
    /// Issuer URL stamped onto issued tokens (typically the proxy's
    /// public base URL such as `https://api.example.com`).
    pub issuer: String,
    /// Default scope token list (space-separated, per RFC 8693
    /// §2.2.1). Mints with `scope_override == None` use this value.
    #[serde(default = "default_olp_scope")]
    pub default_scope: String,
    /// Default TTL applied to issued tokens (seconds). Mints with
    /// `ttl_secs_override == None` use this value.
    #[serde(default = "default_olp_ttl_secs")]
    pub default_ttl_secs: u64,
    /// WOR-808 PR8: optional Encrypted Media Standard content-key
    /// seed (hex-encoded). When set, every issued OLP token carries
    /// an RFC 7800 `cnf.jwk` claim with a per-token AES-256-GCM key
    /// derived via HKDF(seed, salt=jti, info="ems-content-key").
    /// Decryptors that retain the jti can recompute the key without
    /// storing the material. Absent leaves the cnf claim off the
    /// token so EMS-unaware clients keep working.
    #[serde(default)]
    pub content_key_seed: Option<String>,

    /// WOR-808 PR9: introspect / revoke surface. Absent leaves both
    /// `/.well-known/olp/introspect` (RFC 7662) and
    /// `/.well-known/olp/revoke` (RFC 7009) 404'd. Set to enable.
    #[serde(default)]
    pub introspect: Option<OlpIntrospectConfig>,
}

/// WOR-808 PR9: RFC 7662 OAuth Token Introspection + RFC 7009 Token
/// Revocation configuration for the OLP issuer.
///
/// When this block is present the proxy exposes:
///
/// * `POST /.well-known/olp/introspect` — RFC 7662 §2 introspection.
///   Returns `{ "active": true, ... }` for valid + un-revoked tokens
///   issued by this origin's signing key, mirroring every OLP claim.
///   Returns `{ "active": false }` for any token that does not
///   verify, has expired, or has been revoked (§2.2 forbids leaking
///   the reason).
/// * `POST /.well-known/olp/revoke` — RFC 7009 §2. Writes the token's
///   `jti` to the configured revocation store with a TTL that matches
///   the token's remaining lifetime, so subsequent introspections
///   return `active: false`.
///
/// Both endpoints share one `auth` policy because the same actor that
/// can ask "is this token active" should also be able to assert "this
/// token is no longer trusted." Rate-limiting on `active: false`
/// responses (RFC 7662 §2.1 scan-attack defence) and DPoP-bound
/// confirmation checks ship in a follow-up PR.
#[derive(
    Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq, Default, schemars::JsonSchema,
)]
pub struct OlpIntrospectConfig {
    /// Master toggle. When false the well-known endpoints 404 even if
    /// the rest of the block is configured. Lets an operator wire the
    /// auth + store ahead of time and flip it on later.
    #[serde(default)]
    pub enabled: bool,
    /// Path the introspection endpoint binds to. Defaults to
    /// `/.well-known/olp/introspect` so the OLP cluster of endpoints
    /// stays under one prefix.
    #[serde(default = "default_introspect_path")]
    pub introspect_path: String,
    /// Path the revocation endpoint binds to. Defaults to
    /// `/.well-known/olp/revoke`.
    #[serde(default = "default_revoke_path")]
    pub revoke_path: String,
    /// Caller auth policy. Required for both endpoints; RFC 7662 §2.1
    /// MUSTs "some form of authorization" to prevent token-scanning.
    /// Defaults to `mode: self` which uses the token-being-introspected
    /// as its own proof of possession (works without any operator
    /// configuration).
    #[serde(default)]
    pub auth: OlpIntrospectAuth,
    /// `Basic` realm advertised on 401 challenges. Defaults to
    /// `"olp-introspect"`; operators with multi-tenant deployments
    /// often want one realm per tenant for log clarity.
    #[serde(default = "default_introspect_realm")]
    pub realm: String,
    /// Revocation-store backend. Without a store, `/revoke` 503s and
    /// `/introspect` reports `active: true` for every otherwise-valid
    /// token (RFC 7662 §2.2's "active" is only signature + exp). The
    /// `memory` default is sufficient for a single-process dev box
    /// but does NOT survive restart; production deployments should
    /// pick `redb` or `redis`.
    #[serde(default)]
    pub revocation_store: OlpRevocationStoreConfig,
    /// Whether to mirror the token's optional `cnf` (RFC 7800)
    /// confirmation claim onto the introspect response. Defaults to
    /// true so EMS-bound tokens carry their content key through to
    /// the relying party in one round trip; operators concerned about
    /// disclosing the key over a shared introspect connection can
    /// flip to false to require the RP to fetch the JWS directly.
    #[serde(default = "default_olp_introspect_mirror_cnf")]
    pub mirror_cnf: bool,
}

fn default_introspect_path() -> String {
    "/.well-known/olp/introspect".to_string()
}

fn default_revoke_path() -> String {
    "/.well-known/olp/revoke".to_string()
}

fn default_introspect_realm() -> String {
    "olp-introspect".to_string()
}

fn default_olp_introspect_mirror_cnf() -> bool {
    true
}

/// Auth policy for the introspect + revoke endpoints. Three modes:
///
/// * `self` (default) — the caller proves possession of the token by
///   sending the same value in `Authorization: License <token>`
///   *and* in the `token=` form parameter. Reasonable for the common
///   "RP introspects tokens it already holds" case and requires no
///   operator credential management.
/// * `basic` — HTTP Basic with operator-managed credentials. Pass
///   `{ username, password_hash }` pairs in `clients`; passwords are
///   stored as Argon2id hashes. RFC 7662 §2.1's "client
///   authentication" path.
/// * `none` — no auth. ONLY appropriate for fully-private deployments
///   behind a service mesh that already authenticates the caller.
///   The proxy logs a `warn!` at startup when this is selected.
#[derive(
    Debug, Clone, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum OlpIntrospectAuth {
    /// Caller proves possession of the token they are introspecting.
    #[default]
    #[serde(rename = "self")]
    SelfProof,
    /// HTTP Basic with operator-managed credentials.
    Basic {
        /// One entry per authorized caller. Empty list rejects every
        /// request with 401 so an operator cannot accidentally
        /// deploy `mode: basic` without setting up any credentials.
        clients: Vec<OlpIntrospectBasicClient>,
    },
    /// No auth (private-deployment escape hatch).
    None,
}

/// One `mode: basic` credential.
#[derive(
    Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq, schemars::JsonSchema,
)]
pub struct OlpIntrospectBasicClient {
    /// Username sent over Basic auth.
    pub username: String,
    /// Argon2id hash of the password (PHC string format, as produced
    /// by `argon2 -t 3 -m 65536 -p 4 -i`). The proxy verifies with
    /// the same parameters; supports secret references via the
    /// secret-resolver pass.
    pub password_hash: String,
}

/// Revocation-store backend selector.
#[derive(
    Debug, Clone, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum OlpRevocationStoreConfig {
    /// Process-local, lost on restart. Default; appropriate for dev
    /// and CI only.
    #[default]
    Memory,
    /// On-disk redb file. Single-process; survives restart, ACID.
    /// Production default for single-replica deployments.
    Redb {
        /// Filesystem path to the redb file. The path is created on
        /// first use; the operator MUST ensure the directory is
        /// writable by the proxy user.
        path: std::path::PathBuf,
    },
    /// Redis (shared across replicas). Use for horizontally-scaled
    /// deployments where a token revoked on one replica must be
    /// observed by all the others.
    Redis {
        /// `redis://` connection URL. Pool size and timeouts inherit
        /// the workspace `redis` defaults.
        url: String,
    },
}

fn default_olp_scope() -> String {
    "ai-input".to_string()
}

fn default_olp_ttl_secs() -> u64 {
    3600
}
