//! Configuration structs that map directly to the YAML config format.
//!
//! These types are serde-deserializable and represent the user-facing
//! config surface. Plugin-specific fields (action, auth, policies, etc.)
//! are kept as `serde_json::Value` for deferred parsing by the module layer.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Top-Level Config ---

/// Top-level config file structure (sb.yml).
#[derive(Debug, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentClassesConfig {
    /// Catalog source. `builtin` (default) loads the embedded YAML
    /// catalog. `hosted-feed` fetches from `hosted_feed.url`. `merged`
    /// loads the hosted feed and overlays it on top of the embedded
    /// defaults so an operator's feed only needs to ship deltas.
    #[serde(default = "default_agent_classes_catalog")]
    pub catalog: String,
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    #[serde(default)]
    pub http3: Option<Http3Config>,
    /// Metrics collection settings, including cardinality limiting.
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    /// Alert notification channel configuration.
    #[serde(default)]
    pub alerting: Option<AlertingConfig>,
    /// Embedded admin/stats API server configuration.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
    /// Secrets management configuration.
    #[serde(default)]
    pub secrets: Option<SecretsConfig>,
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
}

/// Web Bot Auth signing identity for the proxy. See the
/// [`ProxyServerConfig::web_bot_auth`] field.
///
/// The proxy holds one Ed25519 keypair, identified by `key_id`. Its
/// public half is published in the hosted signatures directory; its
/// private seed signs outbound requests to upstreams that require Web
/// Bot Auth. Treat `ed25519_seed_hex` as a secret (source it via an
/// env interpolation rather than committing it).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct WebBotAuthConfig {
    /// Key id advertised as the JWK `kid` and the RFC 9421 `keyid`.
    /// Must be non-empty.
    pub key_id: String,
    /// Ed25519 private seed as 64 hex characters (32 bytes). The
    /// public key is derived and published; the seed never leaves the
    /// proxy. Validated at config-compile time.
    pub ed25519_seed_hex: String,
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
            alerting: None,
            admin: None,
            secrets: None,
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
        }
    }
}

// --- Scripting engine sandbox config (WOR-594 + WOR-595) ---

/// Per-engine scripting sandbox limits, exposed under the
/// `proxy.scripting:` block of sb.yml.
///
/// Today this block carries sub-blocks for the Lua engine
/// and the JavaScript engine. The CEL and WebAssembly
/// engines manage their own budgets separately. Operators who omit
/// the block get the documented defaults from each sub-block.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MtlsListenerConfig {
    /// Path to a PEM-encoded CA bundle used to verify client certs.
    pub client_ca_file: String,
    /// When `true` (default), the TLS handshake fails if the client
    /// does not present a certificate. When `false`, the handshake
    /// succeeds without a cert and `X-Client-Cert-Verified: 0` is set
    /// (so upstreams can choose whether to reject anonymous traffic).
    #[serde(default = "default_mtls_require")]
    pub require: bool,
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessengerSettings {
    /// Backend driver name.
    pub driver: String,
    /// Free-form string parameters consumed by the driver-specific factory.
    #[serde(default)]
    pub params: HashMap<String, String>,
}

// --- Admin Config ---

/// Configuration for the embedded read-only admin/stats API server.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// Allowed ACME challenge types in priority order (e.g. `tls-alpn-01`, `http-01`).
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
    vec!["tls-alpn-01".to_string(), "http-01".to_string()]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlertingConfig {
    /// List of notification channels to fire alerts to.
    #[serde(default)]
    pub channels: Vec<AlertChannelConfig>,
}

/// Configuration for a single alert notification channel.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlertChannelConfig {
    /// Channel type: `"webhook"` or `"log"`.
    #[serde(rename = "type")]
    pub channel_type: String,
    /// Webhook URL (required when `channel_type == "webhook"`).
    pub url: Option<String>,
    /// Additional HTTP headers for webhook delivery.
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

// --- HTTP/3 Config ---

/// HTTP/3 (QUIC) configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Http3Config {
    /// Whether to enable the HTTP/3 (QUIC) listener.
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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

/// A single origin config as it appears in YAML.
/// Plugin-specific fields are kept as `serde_json::Value` for deferred parsing.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawOriginConfig {
    /// Action describing what the origin does (proxy, redirect, static, etc.).
    pub action: serde_json::Value,
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
    /// Per-origin rate-limit budget. When present, the rate-limit
    /// middleware is mounted ahead of policies in the handler chain.
    /// When absent, the middleware stays off (backwards compatible
    /// with sb.yml configs that use the per-policy
    /// `type: rate_limiting` block).
    #[serde(default)]
    pub rate_limits: Option<OriginRateLimitsConfig>,
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
}

/// Per-origin agents.json manifest configuration (WOR-820). See the
/// [`RawOriginConfig::agents_json`] field and the agents.json v0.1 spec
/// at <https://github.com/wild-card-ai/agents-json>.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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

// --- Per-origin rate limits ---

/// Per-origin rate-limit budget configuration.
///
/// Per-tenant and per-route token buckets, with an optional
/// `route_overrides:` map that lets an operator pin a specific route
/// to a tighter ceiling than the origin default.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OriginRateLimitsConfig {
    /// Tenant-level burst. Effective ceiling that a single tenant
    /// may briefly exceed when arriving in bursts.
    #[serde(default = "default_tenant_burst")]
    pub tenant_burst: u32,
    /// Tenant-level sustained ceiling (rps). Long-running traffic is
    /// flattened to this rate.
    #[serde(default = "default_tenant_sustained")]
    pub tenant_sustained: u32,
    /// Per-route default ceiling (rps). Used when the request path
    /// has no entry in `route_overrides`.
    #[serde(default = "default_route_default")]
    pub route_default: u32,
    /// Per-route ceiling overrides keyed by literal path or `/prefix/*`
    /// pattern. The first matching entry wins, in iteration order.
    #[serde(default)]
    pub route_overrides: std::collections::BTreeMap<String, u32>,
    /// Optional soft-tier ceiling. When `Some`, requests above this
    /// rate but below `tenant_sustained` are tagged but not
    /// throttled (useful for telemetry-driven escalation). `None`
    /// disables the soft tier.
    #[serde(default)]
    pub soft_threshold_rps: Option<u32>,
}

impl Default for OriginRateLimitsConfig {
    fn default() -> Self {
        Self {
            tenant_burst: default_tenant_burst(),
            tenant_sustained: default_tenant_sustained(),
            route_default: default_route_default(),
            route_overrides: std::collections::BTreeMap::new(),
            soft_threshold_rps: None,
        }
    }
}

fn default_tenant_burst() -> u32 {
    2_000
}

fn default_tenant_sustained() -> u32 {
    1_000
}

fn default_route_default() -> u32 {
    100
}

// --- Middleware Configs ---

/// CORS configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UrlModifier {
    /// Path rewrite rules.
    #[serde(default)]
    pub path: Option<PathRewrite>,
}

/// Path rewrite: replace a substring in the path.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathRewrite {
    /// Replace a substring in the path.
    #[serde(default)]
    pub replace: Option<PathReplace>,
}

/// A simple string-replace operation on the URL path.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathReplace {
    /// The substring to search for.
    pub old: String,
    /// The replacement string.
    pub new: String,
}

/// Query parameter modification operations.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatusOverride {
    /// The HTTP status code to set.
    pub code: u16,
    /// Optional reason phrase (not sent in HTTP/2, informational only).
    #[serde(default)]
    pub text: Option<String>,
}

/// Body replacement configuration for response modifiers.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseBodyModifier {
    /// Replace the response body with this string.
    #[serde(default)]
    pub replace: Option<String>,
    /// Replace the response body with this JSON value.
    #[serde(default)]
    pub replace_json: Option<serde_json::Value>,
}

/// Header modification operations (set, add, remove).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretsConfig {
    /// Backend to use for resolving secrets.
    ///
    /// Supported values: `"env"` (default), `"local"`, `"hashicorp"`.
    #[serde(default = "default_secrets_backend")]
    pub backend: String,
    /// HashiCorp Vault connection settings. Required when `backend = "hashicorp"`.
    #[serde(default)]
    pub hashicorp: Option<HashiCorpSecretsConfig>,
    /// Logical name to vault path mapping.
    ///
    /// Allows config files to refer to stable logical names while the physical
    /// vault path can change independently.
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
}

/// HashiCorp Vault connection settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
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
        assert_eq!(acme.challenge_types, vec!["tls-alpn-01", "http-01"]);
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
