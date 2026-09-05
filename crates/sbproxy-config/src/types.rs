//! Configuration structs that map directly to the YAML config format.
//!
//! These types are serde-deserializable and represent the user-facing
//! config surface. Plugin-specific fields (action, auth, policies, etc.)
//! are kept as `serde_json::Value` for deferred parsing by the module layer.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// --- Top-Level Config ---

/// Top-level config file structure (sb.yml).
///
/// This is the one container in the schema without
/// `#[serde(deny_unknown_fields)]` (WOR-1140). Every nested container
/// rejects an unknown key outright, which turns a typo in a server,
/// security, or origin block into a boot error rather than a silent drop
/// to the field's default. The root stays permissive so that an unknown
/// top-level key reaches the `serde_ignored` pass in
/// [`crate::compile_config`] as a diagnosable condition instead of dying
/// as an untyped parse error, and that pass then decides what it is
/// worth.
///
/// It decides on one question: does dropping the key change behavior?
/// A descriptive leftover (`id`, `config_version`, `workspace_id`) warns
/// and compiles. A flat schema-v1 key that carries origin behavior
/// (`hostname`, `action`, `authentication`, `policies`, ...) is refused,
/// because this type has no field for any of them and never translated
/// them into `origins`: a file in that shape used to compile into a
/// proxy with no origin at all. Go compatibility is deprecated; see
/// `MIGRATION.md` and `tests/v1_compat.rs`.
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
    /// Extension bundle discovery sources. Paths stay unresolved in this
    /// parsed representation and are interpreted only by the runtime loader.
    #[serde(default)]
    pub extensions: crate::extensions::ExtensionBundlesConfig,
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
    /// operators set this block to provide an inline catalog or change
    /// the rDNS / bot-auth / cache settings. Hosted-feed fields remain
    /// parseable for compatibility but are not fetched by the OSS
    /// runtime.
    #[serde(default)]
    pub agent_classes: Option<AgentClassesConfig>,
    /// WOR-1130: top-level workspace rate-limit budget + auto-suspend
    /// escalation (the R2.3 / A2.5 contract). Distinct from the
    /// per-origin `rate_limits` policy: this is a workspace-wide ceiling
    /// with a soft / throttle / auto-suspend state machine.
    #[serde(default)]
    pub rate_limits: Option<RateLimitsConfig>,
    /// Durable form of the audit trail. Absent, or present with the
    /// default `sink: memory`, keeps every audit channel in the bounded
    /// in-memory ring and on its tracing target, both of which die with
    /// the process. `sink: chain` additionally appends every
    /// `security_audit` event to a hash-chained, signed file.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
    /// Operator-authored egress allowlists that arm the AiProvider,
    /// UsageSink, ModelArtifact, TokenExchange, and Telemetry purposes
    /// (WOR-2476, WOR-2481). Absent, or a sub-block omitted within it,
    /// keeps the corresponding purpose exactly as ungated as it was
    /// before this section existed. See [`EgressTopLevelConfig`].
    #[serde(default)]
    pub egress: Option<EgressTopLevelConfig>,
    /// WOR-1186: emit the canonical session ledger (per-tool-call run
    /// records) from the live MCP `tools/call` path. Off unless this
    /// block is present and `enabled: true`.
    #[serde(default)]
    pub session_ledger: Option<SessionLedgerConfig>,
    /// Where completed request events go. Absent, or present with the
    /// default `sink: none`, keeps the dispatch on the request path a
    /// no-op and every event is discarded.
    #[serde(default)]
    pub request_events: Option<RequestEventsConfig>,
    /// Where typed proxy events go. Absent, or present with the default
    /// `sink: none`, means the eighteen event types stay in-process and
    /// nothing leaves the proxy.
    #[serde(default)]
    pub events: Option<EventsConfig>,
    /// Process-wide feature flags available to CEL through
    /// `flag_enabled(name, key)`. An absent or empty list installs an
    /// empty runtime store, including on hot reload.
    #[serde(default)]
    pub flags: Vec<FeatureFlagConfig>,
    /// WOR-1804: how `sbproxy update` behaves for the binary and the
    /// managed inference engines. Optional; an absent block is the same
    /// as the defaults (stable channel, no background check).
    #[serde(default)]
    pub update: UpdateConfig,
    /// WOR-2436: what an origin is before any project has an opinion
    /// about it.
    ///
    /// The same shape as one entry under `origins:`, held untyped
    /// because the composition resolver merges `policies:`,
    /// `transforms:`, `request_modifiers:` and `response_modifiers:`
    /// by a `name:` key that the typed modifier structs reject
    /// (`RequestModifierConfig` is `deny_unknown_fields` and has no
    /// `name` field). Every entry in those four lists must carry a
    /// `name:`, because a default has to be addressable to be
    /// overridable, and each may carry `locked: true` to refuse a
    /// project override. See [`crate::origin_profile`].
    ///
    /// Authority-writable on purpose: this block is the platform
    /// setting a security floor, which is the whole reason it exists.
    /// Its sibling `origin_sources` is not, and is on
    /// [`crate::AUTHORITY_DENIED_PATHS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Map<String, serde_json::Value>>")]
    pub origin_defaults: Option<serde_yaml::Mapping>,
    /// WOR-2436: which project repositories the aggregator pulls, what
    /// hosts each one answers on, and the environment tier the pinning
    /// rule is judged against. See [`OriginSourcesConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_sources: Option<OriginSourcesConfig>,
}

/// One process-wide feature flag exposed to CEL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeatureFlagConfig {
    /// Unique name passed as the first argument to `flag_enabled`.
    pub name: String,
    /// Value returned when none of the configured rules match.
    #[serde(default)]
    pub default: bool,
    /// Allow/block lists and sticky rollout rules.
    #[serde(default)]
    pub rules: FeatureFlagRuleConfig,
}

/// Rules for a process-wide feature flag.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeatureFlagRuleConfig {
    /// Bucketing keys that always evaluate to true.
    #[serde(default)]
    pub allow_list: Vec<String>,
    /// Bucketing keys that always evaluate to false.
    #[serde(default)]
    pub block_list: Vec<String>,
    /// Sticky rollout cutoff in the inclusive range 0..=100.
    #[serde(default)]
    #[schemars(range(max = 100))]
    pub rollout_percent: u32,
}

#[cfg(test)]
mod feature_flag_config_tests {
    use super::*;

    #[test]
    fn schema_rejects_unknown_flag_fields_and_caps_rollout() {
        let flag_schema =
            serde_json::to_value(schemars::schema_for!(FeatureFlagConfig)).expect("flag schema");
        assert_eq!(flag_schema["additionalProperties"], false);

        let rule_schema = serde_json::to_value(schemars::schema_for!(FeatureFlagRuleConfig))
            .expect("rule schema");
        assert_eq!(rule_schema["additionalProperties"], false);
        assert_eq!(
            rule_schema["properties"]["rollout_percent"]["maximum"].as_f64(),
            Some(100.0)
        );
    }
}

/// Which release stream `sbproxy update` follows for the binary and the
/// managed inference engines (WOR-1804).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum UpdateChannel {
    /// Track the latest stable release. The default.
    #[default]
    Stable,
    /// Track the newest release, pre-releases included.
    Latest,
    /// Never move automatically. Every artifact is held; only an
    /// `sbproxy update` run that explicitly targets an artifact may
    /// replace it.
    Pinned,
}

/// The `update:` block: how `sbproxy update` behaves (WOR-1804).
///
/// Pinning always wins. A `path` / `brew` / `apt`-managed artifact, or
/// one pinned to an explicit version or digest, is reported but never
/// replaced unless a run explicitly targets it. A background check (see
/// `auto`) only ever reports; applying an update is always an explicit
/// `sbproxy update` run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfig {
    /// Release stream the binary and managed engines follow.
    #[serde(default)]
    pub channel: UpdateChannel,
    /// When true, a background freshness check runs every
    /// `check_interval` and reports to `sbproxy doctor` and the logs. A
    /// background check never replaces an artifact; it only reports.
    #[serde(default)]
    pub auto: bool,
    /// How often the background check runs, in seconds. Accepts a
    /// humanized duration (`6h`, `1d`) or bare seconds. Only consulted
    /// when `auto` is true. Defaults to once a day.
    #[serde(
        default = "default_update_check_interval_secs",
        deserialize_with = "crate::duration::deserialize_secs"
    )]
    pub check_interval_secs: u64,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            channel: UpdateChannel::default(),
            auto: false,
            check_interval_secs: default_update_check_interval_secs(),
        }
    }
}

/// Default background freshness-check interval: once a day.
fn default_update_check_interval_secs() -> u64 {
    86_400
}

#[cfg(test)]
mod update_config_tests {
    use super::*;

    #[test]
    fn absent_block_uses_defaults() {
        // An existing config with no `update:` block parses unchanged and
        // yields the stable, no-background defaults.
        let cfg: ConfigFile = serde_yaml::from_str("proxy: {}\n").unwrap();
        assert_eq!(cfg.update.channel, UpdateChannel::Stable);
        assert!(!cfg.update.auto);
        assert_eq!(cfg.update.check_interval_secs, 86_400);
    }

    #[test]
    fn empty_update_block_uses_defaults() {
        let cfg: UpdateConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(cfg, UpdateConfig::default());
        assert_eq!(cfg.channel, UpdateChannel::Stable);
    }

    #[test]
    fn parses_channel_and_auto_and_humanized_interval() {
        let cfg: UpdateConfig =
            serde_yaml::from_str("channel: pinned\nauto: true\ncheck_interval_secs: 6h\n").unwrap();
        assert_eq!(cfg.channel, UpdateChannel::Pinned);
        assert!(cfg.auto);
        assert_eq!(cfg.check_interval_secs, 21_600);
    }

    #[test]
    fn channel_round_trips_snake_case() {
        let cfg: UpdateConfig = serde_yaml::from_str("channel: latest\n").unwrap();
        assert_eq!(cfg.channel, UpdateChannel::Latest);
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["channel"], "latest");
    }
}

/// WOR-1130: top-level workspace rate-limit budget configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Where the audit trail is durably recorded.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Which durable form the audit trail takes. The in-memory ring and
    /// the `config_audit` / `security_audit` / `key_audit` tracing
    /// targets are unconditional and are not what this selects.
    #[serde(default)]
    pub sink: AuditSinkKind,
    /// Chain file for the `chain` sink. Required when `sink: chain`;
    /// refused otherwise, because a path that names no file is a
    /// deployment that believes it has a trail. Parent directories are
    /// created at boot.
    #[serde(default)]
    pub path: Option<String>,
    /// Signing identity for the `chain` sink. The only value this build
    /// resolves is [`ATTESTATION_SIGN_WITH_WEB_BOT_AUTH`], and that block
    /// must be present. Required when `sink: chain`; refused otherwise.
    #[serde(default)]
    pub sign_with: Option<String>,
    /// Optional path where `config_audit` events are chained. Opt-in; when
    /// absent, `config_audit` remains a tracing stream and is not durably
    /// recorded, preserving exactly the old behavior. Requires `sink: chain`.
    /// Must differ from `path`, `key_path`, and `admin_path`: every audit
    /// channel has a different payload format and verifies independently.
    #[serde(default)]
    pub config_path: Option<String>,
    /// Optional path where `key_audit` mutations are chained (WOR-2478).
    /// Opt-in, same terms as `config_path`. The chained record is metadata
    /// plus a keyed-HMAC fingerprint of each before/after field, never the
    /// raw diff `key_audit`'s tracing target carries; see
    /// `sbproxy_observe::audit`'s module docs. Requires `sink: chain`.
    /// Must differ from `path`, `config_path`, and `admin_path`.
    #[serde(default)]
    pub key_path: Option<String>,
    /// Optional path where authenticated admin-console actions are
    /// chained (WOR-2478): mutating admin API calls, logins, and content
    /// inspection, the same events the `sbproxy::admin::audit` tracing
    /// target and the admin ring's `admin` channel already carry. Opt-in,
    /// same terms as `config_path`. Requires `sink: chain`. Must differ
    /// from `path`, `config_path`, and `key_path`.
    #[serde(default)]
    pub admin_path: Option<String>,
}

/// Accepted audit sink names.
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
    /// No durable trail. Events reach the bounded in-memory ring behind
    /// `/api/audit/events` and the tracing targets, and both are lost
    /// when the process is.
    #[default]
    Memory,
    /// Retained for the error message. `compile_config` refuses this
    /// value: emission to the tracing targets is unconditional and always
    /// was, so selecting it never selected anything. Use `memory` for the
    /// same behavior under an honest name, or `chain` for a trail that
    /// survives a restart.
    Tracing,
    /// Append every `security_audit` event to a SHA-256 hash-chained,
    /// Ed25519-signed file at `path`, signed by the identity `sign_with`
    /// names. Editing or removing a record breaks the chain, and
    /// `sbproxy audit verify` re-derives it from genesis. `config_path`,
    /// `key_path`, and `admin_path` opt the `config_audit`, `key_audit`,
    /// and admin-console channels into their own chain files under the
    /// same signing identity (WOR-2478).
    Chain,
}

/// Top-level `egress:` section: operator-authored allowlists that arm the
/// per-purpose egress gates (WOR-2476), plus the OTLP exporter gate
/// (WOR-2481).
///
/// Reuses the mode/hosts/allow_private vocabulary the per-tool MCP/OpenAPI
/// `egress:` block already ships
/// (`sbproxy_extension::mcp::egress::EgressPolicy`); this crate cannot
/// depend on `sbproxy-extension` (that dependency runs the other way), so
/// the shape is redeclared here rather than shared by type.
///
/// Every sub-block is independently optional. A purpose whose sub-block is
/// omitted stays legacy ungated: `AiClient`'s documented `None` contract,
/// the classifier hooks' legacy ungated dispatch, the usage sinks'
/// unauthenticated dispatch, the model-artifact fetcher's unauthenticated
/// download, the non-MCP token-exchange resolver, and the OTLP exporters
/// all keep behaving exactly as they did before this section existed.
/// `compile_config` compiles each configured sub-block into a
/// [`sbproxy_security::egress::EgressAuthorizer`] once, on
/// [`crate::snapshot::CompiledConfig::egress`]; nothing downstream parses
/// this raw struct directly.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressTopLevelConfig {
    /// Arms `EgressPurpose::AiProvider`: every upstream AI provider
    /// dispatch the AI gateway's client makes.
    #[serde(default)]
    pub ai_providers: Option<EgressPurposeConfig>,
    /// Arms `EgressPurpose::AgentOrchestration`: HTTP invocations made by
    /// configured AI toolkit workflows. Agent endpoints fail closed unless
    /// this purpose is configured with `mode: deny_by_default`.
    #[serde(default)]
    pub agent_orchestration: Option<EgressPurposeConfig>,
    /// Arms `EgressPurpose::ClassifierHook`: the stock intent and
    /// prompt-aware provider-quality classifier RPCs.
    #[serde(default)]
    pub classifier_hooks: Option<EgressPurposeConfig>,
    /// Arms Langfuse, Datadog, and object-store usage-sink deliveries
    /// under `EgressPurpose::UsageSink`, and webhook deliveries under
    /// `EgressPurpose::Webhook` (a separate, pre-existing purpose the
    /// webhook sink authorizes under internally): one config knob, two
    /// purposes armed from the same allowlist.
    #[serde(default)]
    pub usage_sinks: Option<EgressPurposeConfig>,
    /// Arms `EgressPurpose::ModelArtifact`: the model-host artifact
    /// fetcher's HTTP downloads.
    #[serde(default)]
    pub model_artifacts: Option<EgressPurposeConfig>,
    /// Arms `EgressPurpose::TokenExchange`: every OAuth token-endpoint
    /// call this proxy makes, the non-MCP outbound credential
    /// resolver's and the MCP run-as-user token exchange's
    /// (`sbproxy_extension::mcp::auth`) alike. A per-server `egress:`
    /// block gates that server's upstream connects and OpenAPI tool
    /// calls and does not reach this purpose, so this sub-block is the
    /// only way to arm a token endpoint.
    #[serde(default)]
    pub token_exchange: Option<EgressPurposeConfig>,
    /// Arms `EgressPurpose::Federation`: the OpenID Federation fetcher's
    /// entity-configuration and subordinate-statement GETs
    /// (`crates/sbproxy-federation`). Unlike every other sub-block here,
    /// omitting this one does not leave the purpose unguarded: the
    /// fetcher refuses a peer that resolves to a private, loopback, or
    /// link-local address whether or not an allowlist is armed, and it
    /// never follows a redirect it has not re-authorized. What this
    /// sub-block adds on top is the host, scheme, and port allowlist, so
    /// a federation peer outside the trust anchors an operator wrote
    /// down cannot be dialed at all.
    #[serde(default)]
    pub federation: Option<EgressPurposeConfig>,
    /// Arms `EgressPurpose::Telemetry` (WOR-2481): the OTLP trace, metric,
    /// and log exporter endpoints. Authorized once at boot, where each
    /// exporter is constructed. A config reload re-verifies the
    /// already-running trace and metric exporters' endpoints against the
    /// new allowlist and refuses the reload if either is now denied; the
    /// log exporter is rebuilt on every reload and re-authorizes itself
    /// then.
    #[serde(default)]
    pub telemetry: Option<EgressPurposeConfig>,
}

/// One purpose's allowlist under the top-level `egress:` section.
///
/// Shares its vocabulary with the per-tool MCP/OpenAPI `egress:` block;
/// see `sbproxy_extension::mcp::egress::EgressPolicy` for the enforcement
/// semantics this compiles to. `hosts` (exact match), `ports`, and
/// `allow_private` are supported here; the per-tool block's `suffixes`
/// has no equivalent in this section.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressPurposeConfig {
    /// Default behavior for hosts that do not match `hosts`.
    /// `allow_by_default` (the default) is inert: the purpose stays
    /// legacy ungated even though `hosts` is present, mirroring the
    /// per-tool block's `EgressMode::AllowByDefault` short-circuit. Set
    /// `deny_by_default` to actually arm the gate.
    #[serde(default)]
    pub mode: EgressPurposeMode,
    /// Exact hostnames, compared case-insensitively. Ignored under
    /// `allow_by_default`.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// When true, resolved private/link-local addresses are permitted for
    /// hosts on this allowlist (operator opt-in).
    #[serde(default)]
    pub allow_private: bool,
    /// Permitted destination ports. Defaults to `[80, 443]`, the
    /// scheme-standard HTTP/HTTPS ports most sub-blocks dial. An
    /// override is required for a purpose that does not: `telemetry`'s
    /// OTLP endpoint is commonly `4317` (gRPC) or `4318` (HTTP), never
    /// `80`/`443`, so the default here would refuse every destination
    /// that sub-block reaches with `DisallowedPort` and there would be
    /// no `hosts:` fix an operator could make to recover. Refused if
    /// present but empty, or if it names port `0`: either would
    /// silently refuse every destination this purpose reaches with no
    /// indication why.
    #[serde(default = "default_egress_ports")]
    pub ports: Vec<u16>,
}

impl Default for EgressPurposeConfig {
    fn default() -> Self {
        Self {
            mode: EgressPurposeMode::default(),
            hosts: Vec::new(),
            allow_private: false,
            ports: default_egress_ports(),
        }
    }
}

fn default_egress_ports() -> Vec<u16> {
    vec![80, 443]
}

/// Egress behavior when a destination host does not match `hosts`
/// (mirrors `sbproxy_extension::mcp::egress::EgressMode`, minus its
/// `enforce` alias).
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
pub enum EgressPurposeMode {
    /// Only explicitly listed `hosts` may be contacted; compiles to a
    /// real `EgressAuthorizer` that fails closed.
    DenyByDefault,
    /// All hosts may be contacted. Legacy default: an omitted `mode:`, or
    /// an omitted sub-block entirely, compiles to no authorizer at all.
    #[default]
    AllowByDefault,
}

impl EgressPurposeMode {
    /// True when this mode arms a real authorizer (fails closed).
    pub fn is_enforce(self) -> bool {
        matches!(self, Self::DenyByDefault)
    }
}

/// WOR-1186: session-ledger emission configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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

/// Request-event egress configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestEventsConfig {
    /// Which backend receives each completed request event.
    #[serde(default)]
    pub sink: RequestEventSinkKind,
    /// NDJSON output path for the `file` sink. Required when
    /// `sink: file`; ignored otherwise.
    #[serde(default)]
    pub path: Option<String>,
    /// Broker settings for `sink: nats`. Ignored otherwise.
    #[serde(default)]
    pub nats: Option<RequestEventsNatsConfig>,
    /// Warehouse settings for `sink: clickhouse`. Ignored otherwise.
    #[serde(default)]
    pub clickhouse: Option<RequestEventsClickHouseConfig>,
    /// Path to an embedded store holding the delivery watermark, so an
    /// operator reconciling a broker or a warehouse against the proxy has
    /// a checkpoint that survives a restart. Absent means no watermark is
    /// kept, which costs nothing and answers nothing.
    #[serde(default)]
    pub watermark_store_path: Option<std::path::PathBuf>,
    /// Bound on the hand-off queue between the request path and the
    /// delivery worker, for the `nats` and `clickhouse` sinks. A full
    /// queue drops the incoming event and counts the drop rather than
    /// making a request wait on a broker.
    #[serde(default = "default_request_events_queue_capacity")]
    pub queue_capacity: usize,
}

/// Broker settings for `request_events.sink: nats`.
///
/// The address is `host:port`, not a URL: the core NATS protocol this
/// speaks is plain TCP, and a `nats://` string would suggest a URL parser
/// that is not there.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestEventsNatsConfig {
    /// `host:port` of the broker.
    pub address: String,
    /// Prefix every subject starts with. The published subject is
    /// `<prefix>.<workspace_id>.<event_type>`, with the workspace id
    /// sanitized so it cannot add a level or name a wildcard.
    #[serde(default = "default_nats_subject_prefix")]
    pub subject_prefix: String,
    /// Secret reference for the broker's authentication token, resolved
    /// through `proxy.secrets`. A literal here is refused the same way
    /// every other credential reference is.
    #[serde(default)]
    pub token: Option<String>,
}

/// Warehouse settings for `request_events.sink: clickhouse`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestEventsClickHouseConfig {
    /// HTTP endpoint, for example `http://clickhouse.internal:8123`.
    pub url: String,
    /// Database name. Refused unless it matches `[A-Za-z0-9_]+`.
    #[serde(default = "default_clickhouse_database")]
    pub database: String,
    /// Table name. Refused unless it matches `[A-Za-z0-9_]+`. The proxy
    /// never applies DDL; create the table first.
    #[serde(default = "default_clickhouse_table")]
    pub table: String,
    /// Optional user.
    #[serde(default)]
    pub user: Option<String>,
    /// Secret reference for the password, resolved through
    /// `proxy.secrets`.
    #[serde(default)]
    pub password: Option<String>,
}

fn default_request_events_queue_capacity() -> usize {
    8_192
}

fn default_nats_subject_prefix() -> String {
    "sb.events".to_string()
}

fn default_clickhouse_database() -> String {
    "sbproxy".to_string()
}

fn default_clickhouse_table() -> String {
    "sbproxy_request_events".to_string()
}

/// Request-event sink kinds.
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
pub enum RequestEventSinkKind {
    /// Discard every event. The default, and the only behavior the
    /// proxy had before the block existed.
    #[default]
    None,
    /// Emit each event as a structured `request_event` tracing line.
    Logging,
    /// Append each event as one NDJSON line to `path`.
    File,
    /// Publish one JSON message per event to a NATS subject tree.
    /// Requires `request_events.nats`.
    Nats,
    /// Insert batches into a ClickHouse table over its HTTP interface.
    /// Requires `request_events.clickhouse`.
    ClickHouse,
}

/// Egress for the typed proxy events.
///
/// Distinct from [`RequestEventsConfig`], and the difference is the
/// stream rather than the transport. `request_events:` carries the
/// capture envelope: one fully populated record per terminating request,
/// for analytics and billing reconciliation. `events:` carries the
/// lifecycle events an operator wants to react to (a policy denial, an
/// auth failure, a config reload) and can filter down to just those, so
/// a SIEM subscription does not cost one delivery per request served.
///
/// Delivery never runs on the request path. The publish site puts the
/// event on a bounded queue and returns; a background worker owns the
/// file handle or the HTTP client. When the queue is full the event is
/// dropped and counted on `sbproxy_events_dropped_total`, because the
/// alternative is a slow SIEM adding latency to every denied request.
///
/// Shutdown does not flush; see `docs/events.md`.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsConfig {
    /// Which backend receives each selected event.
    #[serde(default)]
    pub sink: EventSinkKind,
    /// NDJSON output path for the `file` sink. Required when
    /// `sink: file`; refused otherwise, because a path nothing writes to
    /// describes a deployment that believes it has an event log.
    #[serde(default)]
    pub path: Option<String>,
    /// Destination URL for the `webhook` sink. Required when
    /// `sink: webhook`; refused otherwise. Validated against the SSRF
    /// guard at boot and again before every batch.
    #[serde(default)]
    pub url: Option<String>,
    /// Shared secret the `webhook` sink signs each batch with
    /// (HMAC-SHA256, sent as `X-Sbproxy-Signature: v1=<hex>` over
    /// `<timestamp>.<body>`, the same construction the alert webhook
    /// uses).
    ///
    /// Accepts a secret reference (`${VAR}`, `file:`, `secret://`,
    /// `vault://`, and the other backend URI schemes) and is the only
    /// way to give the sink a credential: there is no plaintext
    /// alternative field. Optional, but an unsigned POST is a payload
    /// any host that can reach the endpoint can forge.
    #[serde(default)]
    pub signing_secret: Option<String>,
    /// Which of the eighteen event types to deliver. Empty or absent means
    /// all of them.
    ///
    /// Names are the snake_case wire names (`policy_denied`,
    /// `auth_denied`, `config_reloaded`, ...). An unrecognized name is
    /// refused with the accepted list rather than skipped, so a typo
    /// cannot present as a sink that is working and quiet.
    #[serde(default)]
    pub types: Vec<String>,
    /// Event type names for which delivery must never be silently
    /// dropped (WOR-2384). Empty by default, meaning every type keeps
    /// the best-effort, drop-and-count contract every other event type
    /// has.
    ///
    /// Names come from the same closed set `types:` accepts, and an
    /// unrecognized one is refused the same way, with the accepted list
    /// in the message. A name here does not have to also appear in
    /// `types:`, but an operator who lists one without also selecting it
    /// there has configured every governed call to be refused: nothing
    /// would ever be able to deliver that type, and a caller listed here
    /// treats "nothing can deliver this" the same as "delivery failed".
    ///
    /// The only publisher that reads this today is the MCP tool-call
    /// funnel, for `mcp_governance_decision`: when the type is named
    /// here and the record cannot be queued, the tool call is refused
    /// with a JSON-RPC internal error rather than served un-evidenced.
    #[serde(default)]
    pub fail_closed: Vec<String>,
    /// Bound on the hand-off queue between the publish site and the
    /// delivery worker. Defaults to 4096. Refused when `sink: none`, and
    /// refused at zero, which would drop every event while looking
    /// configured.
    #[serde(default)]
    pub queue_capacity: Option<usize>,
}

/// Redacted `Debug` (WOR-2606). `signing_secret` is the HMAC key the
/// webhook receiver verifies, so reading it lets an attacker forge an
/// event feed the operator's downstream trusts. The config-side twin of
/// `EventSinkTarget::Webhook`, redacted in the same round.
impl std::fmt::Debug for EventsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventsConfig")
            .field("sink", &self.sink)
            .field("path", &self.path)
            .field("url", &self.url)
            .field(
                "signing_secret",
                &self.signing_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("types", &self.types)
            .field("fail_closed", &self.fail_closed)
            .field("queue_capacity", &self.queue_capacity)
            .finish_non_exhaustive()
    }
}

/// Accepted `events.sink` values.
///
/// Kafka, NATS, and EventBridge are not here. Each needs a client
/// library, a partitioning decision, and a delivery-guarantee story that
/// a bounded queue and a best-effort POST do not have. They are
/// follow-ups, and until they land their names are refused by the
/// deserializer rather than accepted into a sink that would not deliver.
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
pub enum EventSinkKind {
    /// Publish nothing. The default, and the only behavior the proxy had
    /// before the block existed.
    #[default]
    None,
    /// Append each event as one NDJSON line to `path`.
    File,
    /// POST batches of events to `url`.
    Webhook,
}

/// Where to load a `sb.yml` config text from.
///
/// The default (no `source:` field at all) means the file is the
/// config: the surrounding `ConfigFile` is treated as inline content
/// and consumed directly. When `source:` is present, the compiler
/// resolves it to a config text string before parsing.
///
/// Three kinds are recognized today:
///
/// * `local` keeps the historical behavior - the inline file is the
///   config. This is the form that round-trips when an operator writes
///   `source: { kind: local }` explicitly.
/// * `git` points at a remote git repository, an optional revision
///   (branch, tag, or commit), and a path within the repository to
///   the actual config file.
/// * `git_overlay` composes one base source with one or more overlay
///   sources, merging each in order. A `db` form is reserved for a
///   later iteration but is intentionally not part of this primitive
///   yet.
///
/// A git source is transport trust: HTTPS plus whatever the git host
/// authenticated, and nothing more. Pin `revision` to a full commit sha
/// and set `verify_signature` to close most of that gap; see
/// [`crate::source`] for the resolution contract.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ConfigSource {
    /// The inline file is the config; nothing is fetched. This is the
    /// historical behavior and the implied default when `source:`
    /// is omitted.
    Local,
    /// Clone a git repository and read a single file inside it as the
    /// config text.
    Git {
        /// Repository URL (https, ssh, or any URL `git clone` accepts).
        repo: String,
        /// Optional branch, tag, or full commit sha. When `None`, the
        /// default branch is used. A full commit sha is a pin: the
        /// loader verifies the resolved `HEAD` equals it, so a branch
        /// moving underneath the node cannot be followed silently.
        #[serde(default)]
        revision: Option<String>,
        /// Path inside the repository to the config file, relative
        /// to the repository root.
        path: String,
        /// Optional credential reference for a private repository, as
        /// `env:NAME`, `${NAME}`, `file:/path`, or `secret://backend/name`.
        /// An inline literal is refused: a token in a config file is a
        /// token in every copy of that file.
        #[serde(default)]
        credential: Option<String>,
        /// Require a valid signature on the resolved tag or commit.
        /// Off by default, because most repositories are not signed.
        #[serde(default)]
        verify_signature: bool,
        /// Treat the fetched document as externally authored: it may
        /// not carry a host-backed secret reference (`env:NAME`,
        /// `file:PATH`, `vault://env/NAME`) and may not name a host
        /// path the proxy opens (WOR-2433).
        ///
        /// Off by default, and deliberately: turning it on for
        /// everybody would be a fail-closed upgrade on running fleets.
        /// A GitOps repository that names a host path anywhere would
        /// refuse its own config on the release that changed the
        /// default, and a node that boots into a refusal serves
        /// nothing. The host-path half also has no substitute spelling,
        /// because a path still has to be a path on this host, so the
        /// only place to move one is a layer this node owns.
        ///
        /// It is not silent while it is off: a document that reaches
        /// for this host logs one warning naming the **first** finding
        /// the check reaches, at boot and again whenever a refresh
        /// brings a revision this process has not already checked,
        /// naming the source and the key and never the value. First
        /// rather than every, because the check stops at the first
        /// thing it refuses: a document naming both a host path and an
        /// `env:` reference reports one of them now and the other once
        /// you fix it.
        ///
        /// Per source leaf, not per tree. A `git_overlay` resolves each
        /// `kind: git` node with its own `confine`, so an overlay left
        /// unconfined keeps its own powers and warns on its own.
        ///
        /// Turn it on when the repository is written by somebody other
        /// than whoever runs this proxy; the document then gets the same
        /// treatment a config-authority bundle gets. A secret still has
        /// a spelling under it: `${VAR}` survives confinement and is
        /// substituted before the parse, which is what
        /// `proxy.cluster.security.shared_key` and every other
        /// secret-bearing field can use. See the `Confined fragments`
        /// section of docs/configuration.md.
        #[serde(default)]
        confine: bool,
        /// Hard timeout for one fetch, in seconds. The child `git`
        /// process is killed when it expires; a config-load path with
        /// no timeout hangs startup.
        #[serde(default = "default_source_timeout_secs")]
        timeout_secs: u64,
        /// How often to re-resolve this source while the proxy runs, in
        /// seconds. `0` disables refresh, so the document is resolved
        /// once at boot and on every ordinary reload.
        #[serde(default = "default_source_refresh_secs")]
        refresh_interval_secs: u64,
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

/// Default hard timeout for one git fetch, in seconds.
///
/// Long enough for a shallow clone of a config repository over a slow
/// link, short enough that a hung remote does not hold boot open.
fn default_source_timeout_secs() -> u64 {
    60
}

/// Default refresh cadence for a git source, in seconds.
///
/// A GitOps deployment wants the repository to be the live source of
/// truth, so refresh is on by default. Set `refresh_interval_secs: 0`
/// to resolve once at boot instead.
fn default_source_refresh_secs() -> u64 {
    60
}

// --- Project-owned origin profiles: the runtime half (WOR-2436) ---

/// Top-level `origin_sources:` block: which project repositories the
/// aggregator pulls, and the tier its pinning rule is judged against.
///
/// A project repository commits a hostless origin profile
/// ([`crate::origin_profile::OriginProfile`]). It never names a
/// hostname, because a hostname is an environment fact. This block is
/// where the runtime config supplies the facts the project does not
/// have: the hosts each declared profile origin answers on, the values
/// for the inputs the profile declares, and the last word through
/// `overrides:`.
///
/// The whole block is on [`crate::AUTHORITY_DENIED_PATHS`]. `source` is
/// denied because a fragment that can set it redirects the fleet at one
/// repository; this block names N repositories whose Lua, WASM and JS
/// bodies the `{{ }}` interpolator deliberately never reads, so an
/// authority able to write it turns into arbitrary code fetch on every
/// node that trusts it.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginSourcesConfig {
    /// Which tier this runtime config document is. See
    /// [`EnvironmentTier`].
    #[serde(default)]
    pub tier: EnvironmentTier,
    /// How often the aggregator polls, how long it waits before
    /// composing, and how many repositories it reads at once.
    #[serde(default)]
    pub aggregator: OriginAggregatorConfig,
    /// The project repositories composed into `origins:`.
    #[serde(default)]
    pub entries: Vec<OriginSourceEntry>,
}

/// Timings and bounds for `sbproxy aggregate` (WOR-2437, WOR-2438).
///
/// Inside `origin_sources` rather than under `proxy:` for the same
/// reason [`EnvironmentTier`] is: this block is on
/// [`crate::AUTHORITY_DENIED_PATHS`], so an authority cannot reach in
/// and set a poll interval on a fleet that did not ask for one.
///
/// Every default here is stated in `docs/configuration.md` alongside
/// what it costs in requests per hour per repository, because that
/// number is the one a platform team gets asked about by whoever runs
/// the git server.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginAggregatorConfig {
    /// How often each unpinned entry is asked whether its revision
    /// moved, in seconds.
    ///
    /// One `git ls-remote` per unpinned entry per interval, so the cost
    /// is `3600 / poll_interval_secs` requests per hour per repository.
    /// The default of 120 is Argo CD's `--app-resync` default and gives
    /// 30 requests per hour per repository. An entry pinned to a full
    /// commit sha is polled zero times, because a sha cannot move.
    #[serde(default = "default_aggregator_poll_interval_secs")]
    pub poll_interval_secs: u64,
    /// How long a moved entry waits for others to move before the
    /// aggregator composes, in seconds.
    ///
    /// Project repositories merge on their own cadences and nothing
    /// coordinates them, so three teams merging inside one minute would
    /// otherwise be three published revisions and three fleet-wide
    /// pipeline rebuilds. Zero composes immediately.
    #[serde(default = "default_aggregator_debounce_secs")]
    pub debounce_secs: u64,
    /// The ceiling on that wait, in seconds.
    ///
    /// A continuously-changing entry would otherwise reset the debounce
    /// window forever and never publish at all. Measured from the first
    /// movement in the current window, not from the last.
    #[serde(default = "default_aggregator_max_deferral_secs")]
    pub max_deferral_secs: u64,
    /// How many repositories are fetched at once.
    ///
    /// Serial resolution with per-entry timeouts means fifty entries can
    /// hold one compose open for fifty times one timeout, so the pool is
    /// bounded rather than absent and rather than unbounded.
    #[serde(default = "default_aggregator_concurrency")]
    pub concurrency: usize,
    /// Hard deadline for all of one compose's fetches, in seconds.
    ///
    /// Distinct from the per-entry `timeout_secs`: that one bounds a
    /// single repository, this one bounds the whole round, so a pool of
    /// slow-but-not-timing-out repositories cannot hold a compose open
    /// past it.
    #[serde(default = "default_aggregator_deadline_secs")]
    pub deadline_secs: u64,
}

impl Default for OriginAggregatorConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: default_aggregator_poll_interval_secs(),
            debounce_secs: default_aggregator_debounce_secs(),
            max_deferral_secs: default_aggregator_max_deferral_secs(),
            concurrency: default_aggregator_concurrency(),
            deadline_secs: default_aggregator_deadline_secs(),
        }
    }
}

/// Default aggregator poll cadence, in seconds. Argo CD's
/// `--app-resync` default, and 30 requests per hour per repository.
fn default_aggregator_poll_interval_secs() -> u64 {
    120
}

/// Default coalescing window, in seconds.
fn default_aggregator_debounce_secs() -> u64 {
    15
}

/// Default ceiling on the coalescing window, in seconds.
fn default_aggregator_max_deferral_secs() -> u64 {
    120
}

/// Default bound on concurrent repository fetches.
fn default_aggregator_concurrency() -> usize {
    8
}

/// Default hard deadline for one compose's fetches, in seconds.
fn default_aggregator_deadline_secs() -> u64 {
    300
}

/// The tier of the runtime config document, which is what the
/// production pinning rule keys off.
///
/// Deliberately a property of the runtime document rather than of an
/// entry. A rule that read the entry own `environment:` field would be
/// no rule at all: an entry that wants to track a branch would simply
/// write `environment: dev` and be granted what it asked for. A
/// self-declared constraint is not a constraint. The entry
/// `environment:` selects which `environments:` layer of the profile
/// applies, and nothing more.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentTier {
    /// The default. An entry may follow a branch, or pin nothing at all
    /// and follow the default branch.
    #[default]
    Development,
    /// Every entry must pin an immutable revision: a full commit sha,
    /// or a tag spelled `refs/tags/<name>`. A bare name is refused
    /// because git does not tell a tag from a branch by spelling, and a
    /// rule that guessed would be a rule a branch could walk through.
    Production,
}

impl EnvironmentTier {
    /// Every tier, so a per-tier metric series can be written for all of
    /// them on every load rather than only for the one in force.
    pub const ALL: [Self; 2] = [Self::Development, Self::Production];

    /// The tier as the metric label and admin field an operator reads.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
        }
    }
}

/// One project repository, and the runtime facts that deploy it.
///
/// The git fields are the [`ConfigSource::Git`] set rather than a
/// narrower struct of their own. Omitting `credential` would mean no
/// private project repositories, omitting `verify_signature` would take
/// away the check the whole pinning trust story leans on, and omitting
/// `timeout_secs` would mean one unreachable project repository can
/// hold a compose open.
///
/// Two `ConfigSource::Git` fields are deliberately absent.
/// `refresh_interval_secs` is the aggregator poll cadence and belongs
/// to the aggregator rather than to one entry. `confine` is absent
/// because a project profile is **always** confined: the flag exists so
/// an operator can opt a repository they own into the boundary, and
/// there is no repository here the operator authored.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginSourceEntry {
    /// Stable name for this entry, unique within `origin_sources`. Every
    /// refusal the composition raises names it, so make it the name an
    /// operator would recognize.
    pub name: String,
    /// Repository URL, in any form `git clone` accepts.
    pub repo: String,
    /// Branch, tag, or full commit sha this entry is pinned to. Absent
    /// follows the default branch, which
    /// [`EnvironmentTier::Production`] refuses.
    #[serde(default)]
    pub revision: Option<String>,
    /// Path inside the repository to the profile document, relative to
    /// the repository root. Conventionally `sbproxy/origin.yaml`.
    pub path: String,
    /// Optional credential reference for a private repository, as
    /// `env:NAME`, `${NAME}`, `file:/path`, or `secret://backend/name`.
    /// An inline literal is refused, exactly as `source.credential`
    /// refuses one: a token in a config file is a token in every copy
    /// of that file.
    #[serde(default)]
    pub credential: Option<String>,
    /// Require a valid signature on the resolved tag or commit. Off by
    /// default, because most repositories are not signed.
    #[serde(default)]
    pub verify_signature: bool,
    /// Hard timeout for one fetch of this repository, in seconds.
    #[serde(default = "default_source_timeout_secs")]
    pub timeout_secs: u64,
    /// Which `environments:` layer of the profile applies. Absent means
    /// the profile `base:` layer alone. This selects a layer and grants
    /// nothing; see [`EnvironmentTier`].
    #[serde(default)]
    pub environment: Option<String>,
    /// Hosts each declared profile origin answers on, keyed by the
    /// profile origin name.
    ///
    /// A map rather than a bare list because a profile may declare more
    /// than one origin from day one: an API host plus a webhook host is
    /// the common case, and changing this from a list to a map later
    /// would break every committed entry.
    #[serde(default)]
    pub hosts: std::collections::BTreeMap<String, Vec<String>>,
    /// Values for the inputs the profile declares.
    ///
    /// A value lands in the profile document through `{{vars.NAME}}`
    /// and is then checked as document text, so a host-backed secret
    /// reference (`env:NAME`, `file:/path`, `vault://env/NAME`) is
    /// refused here just as it is refused anywhere else in an
    /// externally authored document. Supply a provider URI
    /// (`secret://backend/name`) instead: it resolves only against a
    /// backend the operator declared under `proxy.secrets`, which is a
    /// path no project can write.
    #[serde(default)]
    #[schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")]
    pub inputs: std::collections::BTreeMap<String, serde_yaml::Value>,
    /// The runtime last word for this entry, layered after everything
    /// the project wrote.
    ///
    /// Same untyped origin shape as `origin_defaults`, and merged the
    /// same way. The runtime bookends the stack, so a project can be
    /// given room without being given the last word.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Map<String, serde_json::Value>>")]
    pub overrides: Option<serde_yaml::Mapping>,
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
#[serde(deny_unknown_fields)]
pub struct AgentClassesConfig {
    /// Catalog source. `builtin` (default) loads the embedded YAML and
    /// `inline` loads `entries`. The compatibility values `hosted-feed`
    /// and `merged` currently warn and fall back to the embedded
    /// defaults; the OSS runtime does not fetch `hosted_feed.url`.
    #[serde(default = "default_agent_classes_catalog")]
    pub catalog: String,
    /// Inline catalog entries. Used when `catalog: inline`; each entry
    /// is validated by the runtime against the same schema as the
    /// embedded catalog.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<serde_json::Value>,
    /// Compatibility-only hosted-feed configuration. It remains
    /// parseable but the OSS runtime does not fetch or merge it.
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
/// Reserved so YAML written against the `hosted-feed` or `merged`
/// shapes parses cleanly. The OSS runtime does not fetch, refresh, or
/// verify this feed; selecting either catalog value warns and falls
/// back to the embedded defaults.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostedFeedConfig {
    /// Reserved feed URL. It is accepted but not fetched or validated
    /// by the OSS runtime.
    pub url: String,
    /// Reserved bootstrap public keys. They are accepted but no
    /// signature verification is installed in the OSS runtime.
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
#[serde(deny_unknown_fields)]
pub struct AgentClassResolverConfig {
    /// Run forward-confirmed reverse-DNS as resolver step 2. Default
    /// `true`. Disable when the runtime has no working DNS resolver.
    #[serde(default = "default_resolver_rdns_enabled")]
    pub rdns_enabled: bool,
    /// Honor the verified Web Bot Auth `keyid` as resolver step 1.
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

/// Process-owned settings for the embedded compression-state database.
///
/// This block controls where the process opens its durable Local backend.
/// It is intentionally independent of route-level compression policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CompressionStateRuntimeConfig {
    /// Explicit absolute path to the redb database file.
    ///
    /// When omitted, startup selects the first suitable platform state
    /// directory. Validation checks only the string contract; filesystem
    /// availability is a startup concern.
    pub local_path: Option<String>,
}

// --- Config history (WOR-2456) ---

/// Default directory for the durable config-revision ring. See
/// [`ConfigHistoryConfig::dir`].
fn default_config_history_dir() -> String {
    "/var/lib/sbproxy/config-history".to_string()
}

/// Default number of applied entries the ring retains. See
/// [`ConfigHistoryConfig::keep`].
const fn default_config_history_keep() -> usize {
    20
}

/// Default number of rejected entries the ring retains. See
/// [`ConfigHistoryConfig::keep_rejected`].
const fn default_config_history_keep_rejected() -> usize {
    10
}

/// Default soak window, in seconds. See [`ConfigSoakConfig::window_secs`].
const fn default_soak_window_secs() -> u64 {
    120
}

/// Default minimum request sample. See [`ConfigSoakConfig::min_requests`].
const fn default_soak_min_requests() -> u64 {
    50
}

/// Default tolerated error-rate increase. See
/// [`ConfigSoakConfig::max_error_rate_delta`].
const fn default_soak_max_error_rate_delta() -> f64 {
    0.05
}

/// Default for the soak's three boolean switches, all of which are on: a
/// subsystem that stayed on prior state, or an upstream that stopped
/// answering, are exactly the failures the soak exists to catch.
const fn default_soak_flag() -> bool {
    true
}

/// Default operator-probe cadence, in seconds. See
/// [`ConfigSoakProbeConfig::interval_secs`].
const fn default_soak_probe_interval_secs() -> u64 {
    10
}

/// Default operator-probe per-request timeout, in milliseconds.
const fn default_soak_probe_timeout_ms() -> u64 {
    2_000
}

/// Default status the operator probe must observe.
const fn default_soak_probe_expect_status() -> u16 {
    200
}

/// The soak window a newly applied revision must survive before it is
/// promoted to last known good (WOR-2458).
///
/// Compiling is not evidence that a config works. A dead upstream URL, a
/// rate limit of 10 that should have been 10000, an auth block that
/// rejects the caller carrying most of the traffic, and a WAF rule that
/// matches everything all compile cleanly. So a committed reload arms a
/// window, four signals report into it, and only a window that closes on
/// a passing verdict promotes the revision to last known good.
///
/// # The verdict is three-way
///
/// Modeled on Argo Rollouts' analysis runs, which complete
/// `Successful`, `Failed`, or `Inconclusive`, with `Inconclusive`
/// pausing a rollout rather than promoting or aborting it. A node that
/// took four requests overnight and 500'd one of them has a 25% error
/// rate and no information: the request-outcome signal abstains below
/// `min_requests` rather than reporting a failure. One
/// abstaining signal never fails a soak, but a window where *every*
/// signal abstained is `Inconclusive` and does not promote, because
/// promoting on a soak that measured nothing is promote-on-apply
/// wearing a timer.
///
/// # Enabled by default once history is
///
/// `proxy.config_history` is itself opt-in and disabled by default. A
/// node that opted into the ring but not into the soak would record
/// revisions whose `lkg` pointer never moves, which leaves the boot
/// fallback (`proxy.config_history.boot`) with nothing to boot from. So
/// this block defaults on inside a block that defaults off.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigSoakConfig {
    /// Master switch. On by default; see the type's own documentation
    /// for why an opt-in block defaults its soak on.
    #[serde(default = "default_soak_flag")]
    pub enabled: bool,
    /// How long a newly applied revision must survive before the window
    /// closes and a verdict is reached. Defaults to 120 seconds.
    ///
    /// `POST /admin/config/confirm` short-circuits it, which is the
    /// Junos `commit confirmed` ergonomic: a deployment pipeline that
    /// ran its own smoke test calls that instead of sleeping out the
    /// window.
    #[serde(default = "default_soak_window_secs")]
    pub window_secs: u64,
    /// Fewest requests the window must observe before the
    /// request-outcome signal reports anything but `abstain`. Defaults
    /// to 50.
    #[serde(default = "default_soak_min_requests")]
    pub min_requests: u64,
    /// How much the error rate may rise, as a fraction between 0 and 1,
    /// against the rate measured when the window armed, before the
    /// request-outcome signal fails. Defaults to 0.05.
    #[serde(default = "default_soak_max_error_rate_delta")]
    pub max_error_rate_delta: f64,
    /// Whether a reload that published while any subsystem stayed on
    /// prior state fails its soak. On by default, and when it fails it
    /// fails immediately rather than waiting the window out: the
    /// evidence is already in hand and no traffic is needed to confirm
    /// it.
    #[serde(default = "default_soak_flag")]
    pub require_no_degraded_subsystems: bool,
    /// Whether an unhealthy upstream, an open circuit breaker, or an
    /// ejected outlier fails the soak. On by default. This is the signal
    /// that catches a config which repointed an origin at a dead
    /// address on a node with almost no traffic.
    #[serde(default = "default_soak_flag")]
    pub require_upstream_health: bool,
    /// An optional operator-declared probe. Absent by default: the
    /// other three signals need no configuration, and this one is for
    /// whatever the operator knows and the proxy does not.
    #[serde(default)]
    pub probe: Option<ConfigSoakProbeConfig>,
    /// Whether a failed soak re-applies the last known good revision on
    /// its own. **Off by default**, and the only key in this block that
    /// is (WOR-2461).
    ///
    /// # Why this one defaults off
    ///
    /// A node that undoes an operator's change without being asked is
    /// surprising in a way that costs trust, and the failure mode is
    /// asymmetric: a flapping upstream during a deploy window reverts a
    /// good config, the operator re-applies it, it reverts again, and
    /// the safety feature is now the incident. With it off the soak
    /// still runs and still promotes, so the operator gets a correct
    /// last-known-good pointer, a metric, an event, and an alert, with
    /// none of that risk. Calibrate the thresholds against real traffic
    /// with this off before arming it.
    ///
    /// Junos `commit confirmed` is the closest prior art and it is
    /// deliberately not what this is: there the operator opts in per
    /// commit and the rollback timer is armed for that one change.
    /// Here the opt-in is per node and standing, which is a bigger
    /// promise, so it is off until someone makes it.
    ///
    /// # It arms only for a diff an arc-swap can undo
    ///
    /// A `Restart` or `Breaking` diff (listener ports, admin block,
    /// cluster identity, an origin's action or auth type) cannot be
    /// undone by swapping the pipeline pointer back, and half-reverting
    /// would leave the process in a state neither config describes.
    /// Those get boot fallback and `POST /admin/config/rollback`
    /// instead. The stored `blast_radius` on the ring entry decides it.
    #[serde(default)]
    pub auto_revert: bool,
}

impl Default for ConfigSoakConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: default_soak_window_secs(),
            min_requests: default_soak_min_requests(),
            max_error_rate_delta: default_soak_max_error_rate_delta(),
            require_no_degraded_subsystems: true,
            require_upstream_health: true,
            probe: None,
            auto_revert: false,
        }
    }
}

impl ConfigSoakConfig {
    /// Rejects a zero window and an error-rate delta outside 0..=1.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message naming the offending field.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.window_secs == 0 {
            return Err(
                "proxy.config_history.soak.window_secs must be at least 1 when the soak is \
                 enabled; a zero window would promote on apply, which is the defect the soak \
                 exists to fix"
                    .to_string(),
            );
        }
        if !(0.0..=1.0).contains(&self.max_error_rate_delta) {
            return Err(format!(
                "proxy.config_history.soak.max_error_rate_delta must be between 0 and 1, got {}",
                self.max_error_rate_delta
            ));
        }
        if let Some(probe) = &self.probe {
            probe.validate()?;
        }
        Ok(())
    }
}

/// An operator-declared HTTP probe the soak window runs alongside its
/// other three signals (WOR-2458).
///
/// # This dials whatever URL you name, with no allowlist
///
/// The probe client is a plain HTTP client. It does **not** route
/// through the egress guard that screens the proxy's other outbound
/// dials, so `url` is a config-reachable fetch to any address this host
/// can reach, loopback and link-local included. What keeps that bounded
/// is that `proxy.config_history` sits on
/// `AUTHORITY_DENIED_PATHS`: a config-authority
/// document cannot set this key, so the only writer is an operator with
/// write access to the node's own configuration file, who can already
/// point an origin anywhere. Treat it the way you treat an origin URL,
/// and prefer a loopback health endpoint on this node.
///
/// Deliberately separate from `proxy.synthetic_probe`, which the soak
/// also reads. The synthetic
/// driver fires an in-process request through the compiled handler chain
/// against a non-network origin, so a passing run proves the chain
/// executes and proves nothing about whether any upstream is reachable.
/// An operator who wants a real upstream exercised declares this
/// instead, and both can be on at once.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigSoakProbeConfig {
    /// URL to `GET` on each probe tick.
    pub url: String,
    /// Status the response must carry. Defaults to 200.
    #[serde(default = "default_soak_probe_expect_status")]
    pub expect_status: u16,
    /// Seconds between probe ticks. Defaults to 10.
    #[serde(default = "default_soak_probe_interval_secs")]
    pub interval_secs: u64,
    /// Per-request timeout in milliseconds. Defaults to 2000. A probe
    /// that times out fails the soak; it does not abstain.
    #[serde(default = "default_soak_probe_timeout_ms")]
    pub timeout_ms: u64,
}

impl ConfigSoakProbeConfig {
    /// Rejects an empty URL and a zero interval.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message naming the offending field.
    pub fn validate(&self) -> Result<(), String> {
        if self.url.trim().is_empty() {
            return Err("proxy.config_history.soak.probe.url must not be empty".to_string());
        }
        if self.interval_secs == 0 {
            return Err(
                "proxy.config_history.soak.probe.interval_secs must be at least 1".to_string(),
            );
        }
        if self.timeout_ms == 0 {
            // reqwest treats a zero timeout as "already expired", so
            // every tick would fail, the operator-probe signal would
            // fail every soak, and the last-known-good pointer would
            // never advance again.
            return Err(
                "proxy.config_history.soak.probe.timeout_ms must be at least 1".to_string(),
            );
        }
        Ok(())
    }
}

/// What a node does when the config it was told to boot on does not
/// work (WOR-2459).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BootFallbackMode {
    /// Exit, the way every release before this one did. The default, so
    /// enabling the ring does not silently change how a broken config
    /// behaves.
    Off,
    /// Walk the ring for a revision that boots, starting from the entry
    /// the last-known-good pointer names.
    LastKnownGood,
}

impl BootFallbackMode {
    /// Stable wire name, matching what the CLI flag and the environment
    /// variable accept.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::LastKnownGood => "last-known-good",
        }
    }

    /// Parse a CLI flag or environment-variable value.
    ///
    /// Accepts both spellings of the enabled mode (`last-known-good` and
    /// `last_known_good`) because the flag is typed by hand at 3am and
    /// the config file spells it with an underscore.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "false" => Some(Self::Off),
            "last-known-good" | "last_known_good" | "lkg" => Some(Self::LastKnownGood),
            _ => None,
        }
    }
}

/// Default boot attempts before an entry is retired as unbootable.
const fn default_boot_max_attempts() -> u32 {
    3
}

/// Default seconds a boot must serve before it counts as successful.
const fn default_boot_success_secs() -> u64 {
    30
}

/// How a node boots when its own config file does not work (WOR-2459).
///
/// # Why a boot counter
///
/// An entry that was good in October need not construct after an upgrade
/// that tightened validation. Borrowed from systemd-boot's boot
/// counting: `boot_attempts` on the entry being tried is incremented on
/// disk *before* the attempt and cleared once the process has bound its
/// listeners and served for `success_secs`. An entry that fails
/// `max_attempts` times is retired as unbootable and the walk
/// continues down the ring. The ring is finite, so the walk terminates.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigBootConfig {
    /// What to do when the configured document does not boot. Defaults
    /// to `off`, so today's behavior is unchanged
    /// unless asked for. `--config-fallback` and `SB_CONFIG_FALLBACK`
    /// override this, and deliberately win: a rescue boot must not
    /// depend on the file being right.
    #[serde(default = "default_boot_fallback")]
    pub fallback: BootFallbackMode,
    /// How many times one ring entry may be tried before it is retired
    /// as unbootable. Defaults to 3.
    #[serde(default = "default_boot_max_attempts")]
    pub max_attempts: u32,
    /// How long a booted process must serve before its entry's boot
    /// counter is cleared. Defaults to 30 seconds.
    #[serde(default = "default_boot_success_secs")]
    pub success_secs: u64,
}

/// Default boot fallback mode. See [`ConfigBootConfig::fallback`].
const fn default_boot_fallback() -> BootFallbackMode {
    BootFallbackMode::Off
}

impl Default for ConfigBootConfig {
    fn default() -> Self {
        Self {
            fallback: BootFallbackMode::Off,
            max_attempts: default_boot_max_attempts(),
            success_secs: default_boot_success_secs(),
        }
    }
}

impl ConfigBootConfig {
    /// Rejects a zero attempt ceiling.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message naming the offending field.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_attempts == 0 {
            return Err(
                "proxy.config_history.boot.max_attempts must be at least 1; zero would retire \
                 every candidate without trying it"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// Durable last-known-good config history (WOR-2456): every config this
/// proxy applies is kept as a content-addressed entry on local disk, so a
/// rollback can restore a prior revision without depending on git history
/// or any other external system being reachable at the moment it is
/// needed.
///
/// Disabled by default. An example elsewhere may show `enabled: true`,
/// but that is the example, not this build's shipping default; every
/// other opt-in proxy-level block in this schema defaults the same way.
///
/// Once enabled, the block names process-owned local storage, which is
/// why [`crate::config_merge::AUTHORITY_DENIED_PATHS`] carries
/// `proxy.config_history` for the same reason it carries
/// `proxy.compression_state`: the ring's directory is a fact about this
/// machine, not something a fleet-wide authority document should be able
/// to repoint.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigHistoryConfig {
    /// Master switch. Disabled by default so an existing deployment does
    /// not start writing config revisions to local disk without an
    /// explicit opt-in.
    #[serde(default)]
    pub enabled: bool,
    /// Directory the revision ring lives in. Defaults to
    /// `/var/lib/sbproxy/config-history`.
    #[serde(default = "default_config_history_dir")]
    pub dir: String,
    /// Number of applied entries the ring retains, beyond whichever
    /// entry the last-known-good pointer names (that entry is never
    /// evicted). Must be at least 1; see [`Self::validate`]. Defaults to
    /// 20.
    #[serde(default = "default_config_history_keep")]
    pub keep: usize,
    /// Accepted, not yet wired. Nothing writes the ring's `rejected/`
    /// directory in this release, so this field has no observable
    /// effect today; a config that fails to apply is not recorded
    /// anywhere. Parsed and stored for forward compatibility: once the
    /// writer ships, it bounds how many rejected candidates the ring
    /// retains for operator inspection. Defaults to 10.
    #[serde(default = "default_config_history_keep_rejected")]
    pub keep_rejected: usize,
    /// The soak window a newly applied revision must survive before it
    /// is promoted to last known good (WOR-2458). Defaults to a soak
    /// that is on; see the `soak` block's own documentation for why an
    /// opt-in block defaults its soak on.
    #[serde(default)]
    pub soak: ConfigSoakConfig,
    /// What this node does when the config it was told to boot on does
    /// not work (WOR-2459). Defaults to today's behavior: exit.
    #[serde(default)]
    pub boot: ConfigBootConfig,
}

impl Default for ConfigHistoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_config_history_dir(),
            keep: default_config_history_keep(),
            keep_rejected: default_config_history_keep_rejected(),
            soak: ConfigSoakConfig::default(),
            boot: ConfigBootConfig::default(),
        }
    }
}

impl ConfigHistoryConfig {
    /// Rejects a `keep` below 1.
    ///
    /// A ring that retains zero applied entries could never hold a
    /// rollback target, which defeats the point of the block.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message naming the offending field.
    pub fn validate(&self) -> Result<(), String> {
        if self.keep < 1 {
            return Err(format!(
                "proxy.config_history.keep must be at least 1, got {}",
                self.keep
            ));
        }
        self.soak.validate()?;
        self.boot.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod config_history_tests {
    use super::*;

    #[test]
    fn config_history_disabled_by_default() {
        let cfg = ConfigHistoryConfig::default();
        assert!(
            !cfg.enabled,
            "the ticket's YAML shows enabled: true as an example, not the shipping default"
        );
        assert_eq!(cfg.dir, "/var/lib/sbproxy/config-history");
        assert_eq!(cfg.keep, 20);
        assert_eq!(cfg.keep_rejected, 10);
    }

    /// WOR-2458. The soak block is on inside a block that is off, so
    /// enabling the ring gets a moving last-known-good pointer rather
    /// than one that never advances.
    #[test]
    fn config_history_soak_defaults_are_the_ticket_values() {
        let cfg = ConfigHistoryConfig::default();
        assert!(cfg.soak.enabled, "an enabled ring soaks by default");
        assert_eq!(cfg.soak.window_secs, 120);
        assert_eq!(cfg.soak.min_requests, 50);
        assert!((cfg.soak.max_error_rate_delta - 0.05).abs() < f64::EPSILON);
        assert!(cfg.soak.require_no_degraded_subsystems);
        assert!(cfg.soak.require_upstream_health);
        assert!(cfg.soak.probe.is_none());
    }

    /// WOR-2459. `off` is the default, so a node that turns on the ring
    /// does not silently change what a broken config does.
    #[test]
    fn config_history_boot_defaults_to_off() {
        let cfg = ConfigHistoryConfig::default();
        assert_eq!(cfg.boot.fallback, BootFallbackMode::Off);
        assert_eq!(cfg.boot.max_attempts, 3);
        assert_eq!(cfg.boot.success_secs, 30);
    }

    /// WOR-2459. The flag is typed by hand under pressure; both
    /// spellings and the config-file spelling all resolve.
    #[test]
    fn boot_fallback_mode_parses_both_spellings_and_refuses_a_typo() {
        assert_eq!(BootFallbackMode::parse("off"), Some(BootFallbackMode::Off));
        assert_eq!(
            BootFallbackMode::parse("last-known-good"),
            Some(BootFallbackMode::LastKnownGood)
        );
        assert_eq!(
            BootFallbackMode::parse("LAST_KNOWN_GOOD"),
            Some(BootFallbackMode::LastKnownGood)
        );
        assert_eq!(BootFallbackMode::parse("last-known-goo"), None);
        assert_eq!(BootFallbackMode::Off.as_str(), "off");
        assert_eq!(BootFallbackMode::LastKnownGood.as_str(), "last-known-good");
    }

    /// `fallback: off` is what the documentation shows, so it has to
    /// parse as the enum rather than as a YAML 1.1 boolean.
    #[test]
    fn boot_fallback_off_parses_from_bare_yaml_off() {
        let cfg: ConfigHistoryConfig =
            serde_yaml::from_str("enabled: true\nboot:\n  fallback: off\n")
                .expect("bare off parses");
        assert_eq!(cfg.boot.fallback, BootFallbackMode::Off);
    }

    /// The blocks parse from YAML with the keys the documentation names.
    #[test]
    fn config_history_parses_the_soak_and_boot_sub_blocks() {
        let yaml = r#"
enabled: true
dir: /var/lib/sbproxy/config-history
soak:
  window_secs: 60
  min_requests: 10
  max_error_rate_delta: 0.02
  require_no_degraded_subsystems: true
  require_upstream_health: false
  probe:
    url: http://127.0.0.1:8080/healthz
    expect_status: 204
    interval_secs: 5
boot:
  fallback: last_known_good
  max_attempts: 2
  success_secs: 15
"#;
        let cfg: ConfigHistoryConfig = serde_yaml::from_str(yaml).expect("parses");
        assert_eq!(cfg.soak.window_secs, 60);
        assert_eq!(cfg.soak.min_requests, 10);
        assert!(!cfg.soak.require_upstream_health);
        let probe = cfg.soak.probe.clone().expect("probe block");
        assert_eq!(probe.url, "http://127.0.0.1:8080/healthz");
        assert_eq!(probe.expect_status, 204);
        assert_eq!(probe.interval_secs, 5);
        assert_eq!(probe.timeout_ms, 2_000, "the default carries through");
        assert_eq!(cfg.boot.fallback, BootFallbackMode::LastKnownGood);
        assert_eq!(cfg.boot.max_attempts, 2);
        assert_eq!(cfg.boot.success_secs, 15);
        assert!(
            !cfg.soak.auto_revert,
            "auto_revert is the one key in this block that defaults off, and a block that \
             names every other soak key without naming it must still come back off",
        );
        cfg.validate().expect("valid");
    }

    /// WOR-2461. `auto_revert` ships off, and it is the only key in the
    /// soak block that does. Pinned as its own test rather than as an
    /// assertion inside another, because a default flipping on is the
    /// one change here that would take production action without an
    /// operator asking.
    #[test]
    fn auto_revert_is_off_by_default_and_opting_in_is_explicit() {
        assert!(
            !ConfigSoakConfig::default().auto_revert,
            "a node that undoes an operator's change without being asked is surprising in a \
             way that costs trust",
        );
        assert!(
            !ConfigHistoryConfig::default().soak.auto_revert,
            "and it stays off through the block that turns the soak itself on",
        );
        let armed: ConfigHistoryConfig =
            serde_yaml::from_str("enabled: true\nsoak:\n  auto_revert: true\n").expect("parses");
        assert!(armed.soak.auto_revert, "opting in is one key");
        assert!(
            armed.soak.enabled,
            "and arming the revert does not require restating that the soak is on",
        );
        armed.validate().expect("valid");
    }

    /// A zero window would promote on apply, which is the defect the
    /// soak exists to fix.
    #[test]
    fn config_history_validate_rejects_a_zero_soak_window() {
        let mut cfg = ConfigHistoryConfig::default();
        cfg.soak.window_secs = 0;
        let error = cfg.validate().expect_err("zero window");
        assert!(error.contains("soak.window_secs"), "{error}");
    }

    /// Zero attempts would retire every candidate without trying it,
    /// which is an exhausted ring dressed as a fallback.
    #[test]
    fn config_history_validate_rejects_zero_boot_attempts() {
        let mut cfg = ConfigHistoryConfig::default();
        cfg.boot.max_attempts = 0;
        let error = cfg.validate().expect_err("zero attempts");
        assert!(error.contains("boot.max_attempts"), "{error}");
    }

    #[test]
    fn config_history_validate_rejects_keep_below_one() {
        let cfg = ConfigHistoryConfig {
            keep: 0,
            ..ConfigHistoryConfig::default()
        };
        let error = cfg.validate().expect_err("keep of 0 must be rejected");
        assert!(error.contains("proxy.config_history.keep"), "{error}");
    }

    #[test]
    fn config_history_validate_accepts_keep_of_one() {
        let cfg = ConfigHistoryConfig {
            keep: 1,
            ..ConfigHistoryConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn proxy_block_accepts_config_history_subblock() {
        let yaml = r#"
http_bind_port: 8080
config_history:
  enabled: true
  dir: /var/lib/sbproxy/config-history
  keep: 20
  keep_rejected: 10
"#;
        let cfg: ProxyServerConfig = serde_yaml::from_str(yaml).unwrap();
        let history = cfg.config_history.expect("config_history block");
        assert!(history.enabled);
        assert_eq!(history.dir, "/var/lib/sbproxy/config-history");
        assert_eq!(history.keep, 20);
        assert_eq!(history.keep_rejected, 10);
    }

    #[test]
    fn config_history_absent_by_default_on_the_proxy_block() {
        let cfg: ProxyServerConfig = serde_yaml::from_str("http_bind_port: 8080\n").unwrap();
        assert!(cfg.config_history.is_none());
    }
}

const fn default_classifier_hook_timeout_ms() -> u64 {
    500
}

const fn default_quality_minimum_score() -> f64 {
    0.75
}

fn default_classifier_hook_auth_header() -> String {
    "authorization".to_string()
}

fn default_classifier_hook_auth_scheme() -> String {
    "Bearer".to_string()
}

/// Classifier-sidecar hooks installed into the stock proxy runtime.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassifierHooksConfig {
    /// HTTP(S) gRPC endpoint of the minimal or rich classifier sidecar.
    pub endpoint: String,
    /// End-to-end deadline for one hook decision.
    #[serde(default = "default_classifier_hook_timeout_ms")]
    pub timeout_ms: u64,
    /// Optional transport-level TLS configuration for HTTPS endpoints.
    #[serde(default)]
    pub tls: Option<ClassifierHooksTlsConfig>,
    /// Optional request authentication presented to the classifier service.
    #[serde(default)]
    pub authentication: Option<ClassifierHooksAuthenticationConfig>,
    /// Optional classifier-backed prompt intent detection.
    #[serde(default)]
    pub intent: Option<ClassifierIntentHookConfig>,
    /// Optional classifier-backed provider quality routing.
    #[serde(default)]
    pub quality: Option<ClassifierQualityHookConfig>,
}

/// TLS material for a classifier-hook gRPC endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassifierHooksTlsConfig {
    /// Optional CA bundle used to verify the remote classifier.
    ///
    /// Resolved through the process secret resolver so the value may be a
    /// provider URI, `${ENV}`, `env:NAME`, or `file:/path`.
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// Override for the TLS server name / SNI. Defaults to the endpoint host.
    #[serde(default)]
    pub server_name: Option<String>,
    /// Optional client certificate presented to the classifier for mTLS.
    #[serde(default)]
    pub client_identity: Option<ClassifierHooksClientIdentityConfig>,
}

/// Client certificate + private key for classifier-hook mTLS.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassifierHooksClientIdentityConfig {
    /// Client certificate chain in PEM format, supplied via a secret reference.
    pub cert_pem: String,
    /// Client private key in PEM format, supplied via a secret reference.
    pub key_pem: String,
}

/// Request authentication presented to the classifier hook service.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ClassifierHooksAuthenticationConfig {
    /// Bearer-style metadata authentication on every gRPC request.
    Bearer {
        /// Secret reference for the bearer token value.
        credential: String,
        /// Metadata key that carries the token. Defaults to `authorization`.
        #[serde(default = "default_classifier_hook_auth_header")]
        header: String,
        /// Optional value prefix. Defaults to `Bearer`.
        #[serde(default = "default_classifier_hook_auth_scheme")]
        scheme: String,
    },
}

/// Model used to classify a prompt into the five stock intent labels.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ClassifierIntentHookConfig {
    /// Logical classifier model id loaded by the sidecar.
    pub model: String,
}

impl Default for ClassifierIntentHookConfig {
    fn default() -> Self {
        Self {
            model: "intent".to_string(),
        }
    }
}

/// Classifier-backed provider scorer for prompt-aware routing.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ClassifierQualityHookConfig {
    /// Minimum positive-label score eligible to win provider selection.
    #[serde(default = "default_quality_minimum_score")]
    pub minimum_score: f64,
    /// Per-provider classifier model and positive-label contract.
    pub provider_models: HashMap<String, ClassifierProviderModelConfig>,
}

impl Default for ClassifierQualityHookConfig {
    fn default() -> Self {
        Self {
            minimum_score: default_quality_minimum_score(),
            provider_models: HashMap::new(),
        }
    }
}

/// One provider's prompt-quality classifier contract.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassifierProviderModelConfig {
    /// Logical classifier model id loaded by the sidecar.
    pub model: String,
    /// Label whose score represents this provider's suitability.
    pub label: String,
}

impl ClassifierHooksConfig {
    /// Validate all sidecar hook resource and scoring bounds.
    pub fn validate(&self) -> anyhow::Result<()> {
        const MAX_ENDPOINT_BYTES: usize = 2_048;
        const MAX_IDENTIFIER_BYTES: usize = 256;
        const MAX_PROVIDER_MODELS: usize = 64;
        const MAX_SECRET_REFERENCE_BYTES: usize = 2_048;
        if self.endpoint.trim().is_empty() || self.endpoint.len() > MAX_ENDPOINT_BYTES {
            anyhow::bail!("classifier_hooks.endpoint must contain 1..={MAX_ENDPOINT_BYTES} bytes");
        }
        let endpoint = self.endpoint.trim().parse::<http::Uri>().map_err(|_| {
            anyhow::anyhow!("classifier_hooks.endpoint must be an absolute http:// or https:// URI")
        })?;
        let scheme = endpoint.scheme_str().ok_or_else(|| {
            anyhow::anyhow!("classifier_hooks.endpoint must include an http:// or https:// scheme")
        })?;
        if !matches!(scheme, "http" | "https") {
            anyhow::bail!("classifier_hooks.endpoint must use http:// or https://");
        }
        let host = endpoint
            .host()
            .ok_or_else(|| anyhow::anyhow!("classifier_hooks.endpoint must include a host"))?;
        let local_endpoint = endpoint_host_is_local(host);
        if !(1..=30_000).contains(&self.timeout_ms) {
            anyhow::bail!("classifier_hooks.timeout_ms must be between 1 and 30000");
        }
        if self.tls.is_some() && scheme != "https" {
            anyhow::bail!("classifier_hooks.tls requires an https:// endpoint");
        }
        if !local_endpoint && scheme != "https" {
            anyhow::bail!("classifier_hooks.endpoint must use https:// for nonlocal destinations");
        }
        if !local_endpoint
            && self.authentication.is_none()
            && self
                .tls
                .as_ref()
                .and_then(|tls| tls.client_identity.as_ref())
                .is_none()
        {
            anyhow::bail!(
                "classifier_hooks requires bearer authentication or mTLS for nonlocal destinations"
            );
        }
        if let Some(tls) = self.tls.as_ref() {
            if let Some(ca_pem) = tls.ca_pem.as_deref() {
                validate_classifier_secret_reference(
                    ca_pem,
                    "classifier_hooks.tls.ca_pem",
                    MAX_SECRET_REFERENCE_BYTES,
                )?;
            }
            if let Some(server_name) = tls.server_name.as_deref() {
                validate_classifier_identifier(
                    server_name,
                    "classifier_hooks.tls.server_name",
                    MAX_IDENTIFIER_BYTES,
                )?;
            }
            if let Some(identity) = tls.client_identity.as_ref() {
                validate_classifier_secret_reference(
                    &identity.cert_pem,
                    "classifier_hooks.tls.client_identity.cert_pem",
                    MAX_SECRET_REFERENCE_BYTES,
                )?;
                validate_classifier_secret_reference(
                    &identity.key_pem,
                    "classifier_hooks.tls.client_identity.key_pem",
                    MAX_SECRET_REFERENCE_BYTES,
                )?;
            }
        }
        if let Some(authentication) = self.authentication.as_ref() {
            match authentication {
                ClassifierHooksAuthenticationConfig::Bearer {
                    credential,
                    header,
                    scheme,
                } => {
                    validate_classifier_secret_reference(
                        credential,
                        "classifier_hooks.authentication.credential",
                        MAX_SECRET_REFERENCE_BYTES,
                    )?;
                    validate_classifier_identifier(
                        header,
                        "classifier_hooks.authentication.header",
                        MAX_IDENTIFIER_BYTES,
                    )?;
                    if http::header::HeaderName::from_bytes(header.as_bytes()).is_err() {
                        anyhow::bail!(
                            "classifier_hooks.authentication.header must be a valid HTTP metadata name"
                        );
                    }
                    validate_classifier_identifier(
                        scheme,
                        "classifier_hooks.authentication.scheme",
                        MAX_IDENTIFIER_BYTES,
                    )?;
                }
            }
        }
        if self.intent.is_none() && self.quality.is_none() {
            anyhow::bail!("classifier_hooks must enable intent, quality, or both");
        }
        if let Some(intent) = self.intent.as_ref() {
            validate_classifier_identifier(
                &intent.model,
                "classifier_hooks.intent.model",
                MAX_IDENTIFIER_BYTES,
            )?;
        }
        if let Some(quality) = self.quality.as_ref() {
            if !quality.minimum_score.is_finite() || !(0.0..=1.0).contains(&quality.minimum_score) {
                anyhow::bail!(
                    "classifier_hooks.quality.minimum_score must be finite and in [0, 1]"
                );
            }
            if quality.provider_models.is_empty()
                || quality.provider_models.len() > MAX_PROVIDER_MODELS
            {
                anyhow::bail!(
                    "classifier_hooks.quality.provider_models must contain 1..={MAX_PROVIDER_MODELS} entries"
                );
            }
            for (provider, model) in &quality.provider_models {
                validate_classifier_identifier(
                    provider,
                    "classifier_hooks.quality.provider_models provider name",
                    MAX_IDENTIFIER_BYTES,
                )?;
                validate_classifier_identifier(
                    &model.model,
                    "classifier_hooks.quality.provider_models.model",
                    MAX_IDENTIFIER_BYTES,
                )?;
                validate_classifier_identifier(
                    &model.label,
                    "classifier_hooks.quality.provider_models.label",
                    MAX_IDENTIFIER_BYTES,
                )?;
            }
        }
        Ok(())
    }
}

fn validate_classifier_identifier(value: &str, path: &str, maximum: usize) -> anyhow::Result<()> {
    if value.trim().is_empty() || value.len() > maximum {
        anyhow::bail!("{path} must contain 1..={maximum} bytes");
    }
    Ok(())
}

fn validate_classifier_secret_reference(
    value: &str,
    path: &str,
    maximum: usize,
) -> anyhow::Result<()> {
    if value.trim().is_empty() || value.len() > maximum {
        anyhow::bail!("{path} must contain 1..={maximum} bytes");
    }
    if !is_secret_reference(value) {
        anyhow::bail!(
            "{path} must be a secret reference (`env:NAME`, `${{NAME}}`, `file:/path`, or `secret://backend/name`), not inline material"
        );
    }
    Ok(())
}

pub(crate) fn endpoint_host_is_local(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

/// Bounded, generation-pinned AI workflow and evaluation configuration.
///
/// The runtime resolves agent credentials only while constructing a candidate
/// pipeline. This parsed form therefore retains secret references, never the
/// referenced secret material itself.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AiToolkitConfig {
    /// Optional overrides for the runtime's conservative public limits.
    pub limits: AiToolkitLimitsConfig,
    /// Governed agent endpoints available to workflows.
    pub agents: Vec<AiToolkitAgentConfig>,
    /// Finite-state workflows compiled into this pipeline generation.
    pub workflows: Vec<AiToolkitWorkflowConfig>,
    /// Immutable evaluation dataset versions seeded at publication.
    pub datasets: Vec<AiToolkitDatasetConfig>,
    /// Stable weighted prompt rollouts selected on the live request path.
    pub prompt_rollouts: Vec<AiToolkitPromptRolloutConfig>,
}

/// Optional overrides for AI toolkit resource and deadline limits.
///
/// An omitted field inherits the runtime default. Keeping these overrides
/// optional avoids copying runtime defaults into the config compiler, where
/// the two sets of values could drift.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AiToolkitLimitsConfig {
    /// Maximum configured agents.
    pub max_agents: Option<usize>,
    /// Maximum capabilities advertised by one agent.
    pub max_capabilities_per_agent: Option<usize>,
    /// Maximum configured workflows.
    pub max_workflows: Option<usize>,
    /// Maximum distinct dataset names retained per scope.
    pub max_datasets: Option<usize>,
    /// Maximum immutable versions retained per dataset.
    pub max_dataset_versions: Option<usize>,
    /// Maximum immutable dataset versions retained across all scopes (hard maximum 16,384).
    pub max_dataset_versions_total: Option<usize>,
    /// Maximum entries in one dataset version.
    pub max_dataset_entries: Option<usize>,
    /// Maximum serialized dataset-entry bytes retained across all scopes (hard maximum 512 MiB).
    pub max_dataset_bytes_total: Option<usize>,
    /// Maximum configured prompt rollouts.
    pub max_rollouts: Option<usize>,
    /// Maximum versions in one prompt rollout.
    pub max_rollout_versions: Option<usize>,
    /// Maximum recent operation summaries retained per scope.
    pub max_retained_operations: Option<usize>,
    /// Maximum serialized request bytes accepted by a toolkit operation.
    pub max_request_bytes: Option<usize>,
    /// Maximum serialized response bytes accepted from an agent or retained.
    pub max_response_bytes: Option<usize>,
    /// Maximum bytes in a public identifier.
    pub max_identifier_bytes: Option<usize>,
    /// Maximum bytes in a public description.
    pub max_description_bytes: Option<usize>,
    /// Maximum bytes in one serialized JSON schema.
    pub max_schema_bytes: Option<usize>,
    /// Maximum bytes resolved from one agent credential reference.
    pub max_secret_bytes: Option<usize>,
    /// Maximum cases evaluated by one run.
    pub max_evaluation_cases: Option<usize>,
    /// Maximum custom metrics evaluated by one run.
    pub max_metrics: Option<usize>,
    /// Maximum offline-judge criteria evaluated by one run.
    pub max_judge_criteria: Option<usize>,
    /// Maximum concurrent governed agent calls.
    pub agent_concurrency: Option<usize>,
    /// Maximum concurrent evaluation cases.
    pub evaluation_concurrency: Option<usize>,
    /// Default workflow deadline when a run does not supply one.
    pub default_workflow_timeout_ms: Option<u64>,
    /// Hard ceiling for every workflow deadline.
    pub max_workflow_timeout_ms: Option<u64>,
}

/// One governed agent endpoint available within an origin's tenant scope.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiToolkitAgentConfig {
    /// Stable configured origin id (or hostname) that owns this agent.
    pub origin: String,
    /// Stable agent id within the origin scope.
    pub id: String,
    /// HTTP endpoint invoked through the agent-orchestration egress gate.
    pub endpoint: String,
    /// Authentication material expressed only as a secret reference.
    pub auth: AiToolkitAgentAuthConfig,
    /// Capabilities advertised by this agent.
    #[serde(default)]
    pub capabilities: Vec<AiToolkitCapabilityConfig>,
}

/// Agent authentication configuration retained as an unresolved reference.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiToolkitAgentAuthConfig {
    /// Secret reference used to derive the agent bearer credential.
    pub shared_secret: String,
}

/// Redacted `Debug` (WOR-2640). The config-side twin of the toolkit
/// agent input this change's first half protected. The field doc calls
/// it a secret reference, and it is one until the resolver pass
/// substitutes the real value into it; after that this struct holds
/// the bearer credential the proxy presents to the agent.
impl std::fmt::Debug for AiToolkitAgentAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiToolkitAgentAuthConfig")
            .field("shared_secret", &"[REDACTED]")
            .finish()
    }
}

/// One discoverable agent capability and its request/response schemas.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiToolkitCapabilityConfig {
    /// Stable capability name used by workflow actions.
    pub name: String,
    /// Bounded operator-facing description.
    #[serde(default)]
    pub description: String,
    /// JSON Schema for the agent request body.
    pub input_schema: serde_json::Value,
    /// JSON Schema for the agent response body.
    pub output_schema: serde_json::Value,
}

/// One finite-state workflow owned by an origin scope.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiToolkitWorkflowConfig {
    /// Stable configured origin id (or hostname) that owns this workflow.
    pub origin: String,
    /// Stable workflow name within the origin scope.
    pub name: String,
    /// State entered first.
    pub initial_state: String,
    /// Maximum transitions in one execution.
    pub max_steps: usize,
    /// Whole-workflow deadline in milliseconds.
    pub timeout_ms: u64,
    /// Bounded workflow graph.
    pub states: Vec<AiToolkitWorkflowStateConfig>,
}

/// One state in a configured AI toolkit workflow.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiToolkitWorkflowStateConfig {
    /// Stable state name.
    pub name: String,
    /// Capability name discovered and invoked when this state runs.
    pub action: String,
    /// Outcome label to next-state name. An absent match completes the run.
    #[serde(default)]
    pub transitions: HashMap<String, String>,
}

/// One immutable evaluation dataset version seeded from configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiToolkitDatasetConfig {
    /// Stable configured origin id (or hostname) that owns this dataset.
    pub origin: String,
    /// Dataset name within the origin scope.
    pub name: String,
    /// Explicit immutable version; zero is invalid.
    pub version: u32,
    /// Bounded evaluation cases.
    #[serde(default)]
    pub entries: Vec<AiToolkitDatasetEntryConfig>,
}

/// One input/expected-output pair in a configured evaluation dataset.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiToolkitDatasetEntryConfig {
    /// Input supplied to the evaluated model or offline response set.
    pub input: String,
    /// Optional expected output used by correctness metrics.
    #[serde(default)]
    pub expected_output: Option<String>,
    /// Bounded caller metadata retained with the case.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// One stable weighted prompt rollout owned by an origin scope.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiToolkitPromptRolloutConfig {
    /// Stable configured origin id (or hostname) that owns this rollout.
    pub origin: String,
    /// Prompt name used by bare request references.
    pub name: String,
    /// Stable operator-controlled cohort salt.
    pub salt: String,
    /// Weighted immutable prompt versions.
    pub versions: Vec<AiToolkitPromptRolloutVersionConfig>,
}

/// One immutable member of a weighted prompt rollout.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiToolkitPromptRolloutVersionConfig {
    /// Positive numeric prompt version.
    pub version: u32,
    /// Prompt template/content selected for this version.
    pub content: String,
    /// Finite non-negative relative weight.
    pub weight: f64,
}

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
#[serde(deny_unknown_fields)]
pub struct ProxyServerConfig {
    /// HTTP listener port. Defaults to 8080.
    #[serde(default = "default_http_port")]
    pub http_bind_port: u16,
    /// Address the public listeners bind. Defaults to `0.0.0.0`, every
    /// interface.
    ///
    /// Applies to both [`Self::http_bind_port`] and
    /// [`Self::https_bind_port`], deliberately. Two fields would let an
    /// operator lock down HTTP, leave HTTPS on every interface, and
    /// believe the box was closed; one field cannot be half-applied.
    ///
    /// A server deployment wants the default, which is why it is the
    /// default. Set `127.0.0.1` when the proxy serves only processes on
    /// the same machine, or a specific interface address to pick one
    /// NIC. `sbproxy run` and `sbproxy service install` generate
    /// `127.0.0.1` (WOR-2199): they configure one machine for itself,
    /// and the address they print has to be the address they bound.
    ///
    /// This is not a substitute for authentication. It limits who can
    /// reach the listener, not what they may do once they reach it.
    #[serde(default)]
    pub bind_address: Option<String>,
    /// The availability zone this proxy considers itself in, e.g.
    /// `"us-east-1a"` (WOR-2328).
    ///
    /// Load balancer targets whose `targets[].zone` label matches are
    /// preferred by target selection, with per-request spillover across
    /// zones when no same-zone target is healthy. When unset, the
    /// `SB_ZONE` environment variable fills in at pipeline compile
    /// time (see [`Self::resolve_zone`]), which is how a Kubernetes
    /// deployment feeds in the node's `topology.kubernetes.io/zone`
    /// label. Config wins over the environment so a deployment that
    /// states its zone here can never be re-zoned by a stray variable.
    /// With neither set, target selection ignores zone labels entirely
    /// and warns at boot when labels are authored anyway.
    #[serde(default)]
    pub zone: Option<String>,
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
    /// Reserved HTTP/3 (QUIC) listener configuration.
    ///
    /// The block remains in the schema for forward compatibility. Omission or
    /// `enabled: false` compiles, but `enabled: true` is rejected because this
    /// build does not serve HTTP/3. Native support is tracked in WOR-1969.
    #[serde(default)]
    pub http3: Option<Http3Config>,
    /// Metrics collection settings, including cardinality limiting.
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    /// Top-level observability block: live log sinks, redaction and custom
    /// fields plus the OTLP exporter and durable usage rollups. The parent log
    /// level, format, and sampling fields are compatibility-only; process
    /// tracing uses CLI/environment selection and built-in sampling defaults.
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
    /// Optional classifier-sidecar hooks for intent and quality routing.
    #[serde(default)]
    pub classifier_hooks: Option<ClassifierHooksConfig>,
    /// Optional bounded AI workflow, evaluation, and rollout runtime.
    #[serde(default)]
    pub ai_toolkit: Option<AiToolkitConfig>,
    /// Optional shared cluster substrate for keys, metrics, and managed models.
    #[serde(default)]
    pub cluster: Option<crate::cluster::ClusterConfig>,
    /// Optional config-authority participation: subscribe to signed
    /// configuration bundles published by an upstream authority.
    ///
    /// The whole block sits on [`crate::config_merge::AUTHORITY_DENIED_PATHS`],
    /// so a bundle can never repoint a subscriber at a different authority
    /// or relax its verification.
    #[serde(default)]
    pub config_authority: Option<ConfigAuthorityConfig>,
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
    /// WOR-2666: optional behavioral anomaly detection.
    ///
    /// When `enabled`, the proxy keeps a rolling per-agent-class
    /// histogram of the categorical signals it already collects (TLS
    /// fingerprint, ML classification, headless-library detection) plus
    /// a per-IP request rate, and flags observations that sit in the
    /// long tail. Absent or disabled, no histogram is built and the
    /// detector hook is not installed.
    #[serde(default)]
    pub anomaly: Option<AnomalyConfig>,
    /// Optional Cache Reserve (long-tail cold tier) configuration.
    ///
    /// When `enabled`, response-cache entries that pass the admission
    /// filter are mirrored to the configured backend: memory,
    /// filesystem, Redis, object storage (S3, Google Cloud Storage,
    /// Azure Blob, or a local directory, with optional at-rest
    /// sealing), or S3 with AWS KMS envelope encryption. On a hot miss
    /// the proxy consults the reserve before falling through to origin
    /// and promotes the entry back into the hot tier on hit.
    #[serde(default)]
    pub cache_reserve: Option<CacheReserveConfig>,
    /// Optional selection of the shared response-cache backing store.
    ///
    /// One store serves every origin: the cache key already carries
    /// workspace, hostname, method, and path, so origins never collide.
    /// When this block is absent, the store is chosen the way it always
    /// was, Redis if `l2_cache` is set and an in-process map otherwise,
    /// so an existing config keeps the backend it has today.
    #[serde(default)]
    pub response_cache_store: Option<ResponseCacheStoreConfig>,
    /// Process-owned path configuration for durable Local compression state.
    #[serde(default)]
    pub compression_state: Option<CompressionStateRuntimeConfig>,
    /// Durable last-known-good config history (WOR-2456): the ring of
    /// every config this proxy has applied, kept on local disk so a
    /// rollback has somewhere to restore from. Absent (the default)
    /// keeps the proxy's existing behavior exactly; no ring is written.
    /// See [`ConfigHistoryConfig`].
    #[serde(default)]
    pub config_history: Option<ConfigHistoryConfig>,
    /// Shared message bus. Not supported in this build: setting it fails
    /// config compile (WOR-2166). The block still parses so the failure is
    /// an explanatory diagnostic rather than an unknown-key error, and so
    /// an archived schema-v1 document reaches that diagnostic.
    ///
    /// It was never wired to anything. Nothing subscribed to a topic and
    /// nothing published on one, so an accepted bus moved no events. Config
    /// distribution across replicas is `proxy.config_authority`; cache
    /// invalidation is `POST /admin/cache/purge` against a shared Redis
    /// tier configured through `proxy.l2_cache`.
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
    /// Correlation-ID propagation policy. By default, the proxy honors
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
    /// Refused at config compile. The device parser in this build
    /// matches on compiled-in rules and has no code path that loads a
    /// regex catalog from disk, so a path here named a file the proxy
    /// never opened. Compare [`Self::ai_providers_file`] just above,
    /// which is the same idea for the provider catalog and is read at
    /// startup.
    ///
    /// Retained as a parseable field so the failure explains itself
    /// rather than reading as an unknown key.
    #[serde(default)]
    pub device_parser_file: Option<String>,
    /// Optional synthetic-transaction probe driving an in-process
    /// request through the compiled handler chain on a fixed cadence
    /// and reporting the verdict on `/readyz`. Disabled by
    /// default; opt in for deployments that want `/readyz` to fail
    /// when the proxy is unable to service its own requests.
    #[serde(default)]
    pub synthetic_probe: Option<SyntheticProbeConfig>,
    /// Optional agent registry: a signed catalog of known agents plus an
    /// owner-approval queue for agents that ask to register themselves.
    /// Disabled by default. State lives in one embedded redb file named by
    /// `store_path`; nothing here needs a database or a sidecar.
    #[serde(default)]
    pub agent_registry: Option<AgentRegistryConfig>,
    /// Optional outbound webhook notifications: many subscriptions, each
    /// with its own filter and signing key, bounded retries, and a durable
    /// deadletter queue with replay. Disabled by default. State lives in
    /// one embedded redb file named by `store_path`.
    #[serde(default)]
    pub notifications: Option<NotificationsConfig>,
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
    /// so existing configs see no behavior change. See
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
    /// Consumption attestation (WOR-2127): whether this proxy asserts
    /// what a call is going to cost, records what it actually
    /// consumed, and what it charges for. Absent leaves the whole
    /// mechanism off, so an existing config is unaffected. See
    /// [`AttestationConfig`].
    #[serde(default)]
    pub attestation: Option<AttestationConfig>,
    /// WOR-1053: declared tenants. Each entry carries an `id`
    /// referenced by `origin.tenant_id`. Future PRs add per-tenant
    /// `credentials`, `policies`, and `vault` blocks; PR1 lands the
    /// scope so the rest of the credentials epic can land against a
    /// stable tenant resolver.
    ///
    /// When empty, every origin resolves to the synthetic
    /// `__default__` tenant. Existing single-tenant configs see no
    /// behavior change. An origin that names a tenant not declared
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
    /// OpenID Federation entity-statement serving for this proxy process.
    /// Absent, or present with `enabled: false`, leaves the well-known
    /// endpoint unmounted.
    #[serde(default)]
    pub federation: Option<FederationConfig>,
    /// Durable payment settlement. When absent, the proxy keeps its
    /// existing non-settlement crawl-ledger behavior exactly. When
    /// present, a paid request reaches the origin only after its
    /// durable intent has committed `Succeeded`.
    ///
    /// The block is always parsed, on every build, so `sbproxy
    /// validate` reads the same document everywhere. The consumer
    /// compares [`crate::payments::PaymentsConfig::required_features`]
    /// against its own compiled feature set and fails startup naming
    /// the missing feature, so a configured rail that was not compiled
    /// in never reaches a first request.
    #[serde(default)]
    pub payments: Option<crate::payments::PaymentsConfig>,
}

const fn default_federation_lifetime_secs() -> u64 {
    3600
}

const fn default_federation_refresh_margin_secs() -> u64 {
    300
}

/// `proxy.federation`: the signing identity served by the normal proxy
/// listener at `/.well-known/openid-federation`.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationConfig {
    /// Whether the process mounts the well-known entity-statement route.
    #[serde(default)]
    pub enabled: bool,
    /// Externally visible HTTPS entity identifier used for `iss` and `sub`.
    pub entity_id: String,
    /// Private signing-key location and JWS header selection.
    pub signing_key: FederationSigningKeyConfig,
    /// Public JWKS embedded in the signed entity statement.
    pub published_jwks: serde_json::Value,
    /// Lifetime of each generated entity statement.
    #[serde(default = "default_federation_lifetime_secs")]
    pub lifetime_secs: u64,
    /// Time before expiry at which the cached statement is regenerated.
    #[serde(default = "default_federation_refresh_margin_secs")]
    pub refresh_margin_secs: u64,
    /// Entity URLs of this entity's superiors, published in the entity
    /// statement as `authority_hints`.
    ///
    /// OpenID Federation 1.0 s3 makes this required for every entity
    /// that is not itself a Trust Anchor, and a peer's resolver walks
    /// it: `compose_trust_chain` reads `authority_hints` from the leaf
    /// it fetched and returns no chain when the array is empty. A
    /// statement published without it is anchor-shaped, so no peer can
    /// chain this proxy to anything.
    #[serde(default)]
    pub authority_hints: Vec<String>,
    /// Inbound peer verification. Absent leaves the proxy publishing
    /// its own identity and verifying nobody.
    #[serde(default)]
    pub peer_trust: Option<FederationPeerTrustConfig>,
}

const fn default_federation_peer_cache_ttl_secs() -> u64 {
    600
}

/// Default total fetch budget for one trust-chain walk.
fn default_federation_max_chain_fetches() -> usize {
    16
}

/// Default total byte budget for one trust-chain walk (2 MiB).
fn default_federation_max_chain_bytes() -> u64 {
    2 * 1024 * 1024
}

/// Default wall-clock budget for one trust-chain walk.
fn default_federation_max_chain_duration_ms() -> u64 {
    5_000
}

/// Default cap on `authority_hints` per entity configuration.
fn default_federation_max_authority_hints() -> usize {
    8
}

/// Default per-source chain-walk rate, in walks per minute.
fn default_federation_peer_walks_per_minute() -> u32 {
    30
}

const fn default_federation_max_chain_depth() -> usize {
    5
}

fn default_federation_peer_header() -> String {
    "x-federation-entity-id".to_string()
}

/// `proxy.federation.peer_trust`: verify the entity a request claims to
/// come from against pinned trust anchors, on the request path.
///
/// A peer names itself in a header. The proxy fetches that entity's
/// self-signed configuration, walks its `authority_hints` up to one of
/// the anchors below through the governed `egress.federation` client,
/// validates every signature and linkage in the chain, checks any
/// required trust marks, and either stamps the verified entity id onto
/// the request or refuses it. Every step publishes the decision events
/// and metrics `docs/federation.md` documents.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationPeerTrustConfig {
    /// Refuse a request that names no peer, or whose peer does not
    /// resolve to an anchor.
    ///
    /// `false` still refuses a request whose named peer fails to
    /// resolve: an unverifiable claim is worse than no claim. What it
    /// permits is a request that makes no claim at all, which is the
    /// shape for a proxy that federates with some callers and serves
    /// ordinary traffic from the rest.
    #[serde(default)]
    pub required: bool,
    /// Request header the peer names itself in.
    #[serde(default = "default_federation_peer_header")]
    pub header: String,
    /// Pinned trust anchors. At least one is required.
    pub trust_anchors: Vec<FederationTrustAnchorConfig>,
    /// Trust-mark identifiers a verified peer must additionally carry,
    /// each signed by an anchor above and published in the peer's own
    /// entity configuration.
    #[serde(default)]
    pub required_trust_marks: Vec<String>,
    /// Maximum statements in an accepted chain.
    #[serde(default = "default_federation_max_chain_depth")]
    pub max_chain_depth: usize,
    /// How long a resolved peer decision is reused before the chain is
    /// walked again. A chain walk is several outbound HTTPS fetches, so
    /// re-running it per request would put a peer's availability on
    /// this proxy's request path.
    #[serde(default = "default_federation_peer_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Total outbound fetches one chain walk may spend.
    ///
    /// This is the bound that matters, and it is not `max_chain_depth`.
    /// `authority_hints` is an array: one entity naming five thousand
    /// superiors costs five thousand fetches at depth 1, and a depth
    /// cap never fires. A well-formed chain spends about two fetches
    /// per level, so the default covers a four-level federation that
    /// has to try a second superior at one level.
    #[serde(default = "default_federation_max_chain_fetches")]
    pub max_chain_fetches: usize,
    /// Total bytes one chain walk may read across every fetch.
    ///
    /// Each fetch is separately capped at 1 MiB by the fetcher; this
    /// bounds the sum, so a peer serving a maximum-size document at
    /// every hop cannot make one request hold the product of the two.
    #[serde(default = "default_federation_max_chain_bytes")]
    pub max_chain_bytes: u64,
    /// Wall-clock budget for one chain walk, in milliseconds.
    ///
    /// Every fetch has its own connect and read timeout. Without an
    /// aggregate deadline, a peer that answers just inside the
    /// per-fetch timeout at every hop holds the request open for the
    /// product of the two. The walk stops here whatever it has found.
    #[serde(default = "default_federation_max_chain_duration_ms")]
    pub max_chain_duration_ms: u64,
    /// Most `authority_hints` a single entity configuration may
    /// publish before the walk refuses the document.
    ///
    /// Refused rather than truncated: silently ignoring an operator's
    /// superiors turns a configuration error into an unexplained
    /// refusal further down.
    #[serde(default = "default_federation_max_authority_hints")]
    pub max_authority_hints: usize,
    /// Chain walks one source address may start per minute.
    ///
    /// The decision cache is keyed on the peer address and the claimed
    /// entity id, so a caller that rotates the entity id it claims
    /// misses the cache every time. This is what stops that from
    /// becoming one walk per request.
    #[serde(default = "default_federation_peer_walks_per_minute")]
    pub walks_per_minute: u32,
}

/// One pinned OpenID Federation trust anchor.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationTrustAnchorConfig {
    /// The anchor's entity URL.
    pub entity_id: String,
    /// The anchor's published JWKS, as the `{"keys": [...]}` object.
    /// This is the pin: every chain is verified against these keys, so
    /// they come from the operator rather than from the network.
    pub jwks: serde_json::Value,
}

/// Private-key reference and protected JWS header fields for federation
/// entity-statement signing.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationSigningKeyConfig {
    /// PEM file read only when a runtime pipeline is constructed.
    pub pem_file: String,
    /// Asymmetric JWS algorithm name, such as `ES256`.
    pub algorithm: String,
    /// Key identifier stamped into the protected JWS header.
    pub kid: String,
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
#[serde(deny_unknown_fields)]
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

// --- Consumption attestation (WOR-2127) ---

/// The one `sign_with` target this build knows how to resolve.
///
/// A config path rather than a key name, because the operator is
/// pointing at an identity that already exists in their document rather
/// than declaring a second one. Kept as a validated string so the day a
/// second signing identity ships, an old config still parses and the
/// error tells the operator what is on offer.
pub const ATTESTATION_SIGN_WITH_WEB_BOT_AUTH: &str = "proxy.web_bot_auth";

/// Largest `queue.max_entries` this build accepts.
///
/// The queue is an in-process hold for claims that have not settled
/// yet. Past ten million entries an operator is describing a database,
/// and sizing one by accident (an extra zero) should fail at config
/// compile rather than at the memory ceiling.
pub const MAX_ATTESTATION_QUEUE_ENTRIES: usize = 10_000_000;

const fn default_attestation_queue_max_entries() -> usize {
    100_000
}

const fn default_attestation_failure_mode() -> FailureMode {
    FailureMode::Degraded
}

const fn default_measured_per() -> u64 {
    1
}

/// What part this proxy plays in attesting to consumption.
///
/// The two halves answer the two halves of a billing dispute and are
/// independently useful, which is why this is four values rather than a
/// boolean. A claim is made before the call and says what it is going
/// to cost; a receipt is written after it and says what it actually
/// consumed. A gateway in front of somebody else's metered API wants
/// [`Self::Claim`] alone. A proxy selling its own upstream wants
/// [`Self::Receipt`] alone. An operator reselling metered capacity
/// wants [`Self::Both`], because they have to answer to a buyer and a
/// supplier at once.
///
/// This build implements the receipt half only. `compile_config`
/// refuses [`Self::Claim`] and [`Self::Both`], at the proxy block and
/// at a per-origin override alike, because nothing writes a claim
/// before a call is served, nothing reads
/// [`AttestationConfig::queue`], and no ceiling is computed for
/// [`AttestationConfig::enforcement_mode`] to act on. Both variants
/// stay in the vocabulary so the refusal can name what is missing
/// instead of reporting an unknown value.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRole {
    /// Attest to nothing. The default, and what every config that does
    /// not mention the block gets.
    #[default]
    Off,
    /// Assert what a call is going to cost, before it is served. Not
    /// implemented in this build: a config that names it is refused at
    /// compile.
    Claim,
    /// Record what a call actually consumed, after it is served.
    Receipt,
    /// Both halves. The posture for reselling metered capacity. Not
    /// implemented in this build either, because the claim half is not:
    /// a config that names it is refused at compile.
    Both,
}

impl AttestationRole {
    /// True when this role asserts a cost before the call is served.
    pub fn makes_claims(self) -> bool {
        matches!(self, Self::Claim | Self::Both)
    }

    /// True when this role records consumption after the call is
    /// served. The half that needs a signing identity, because a
    /// receipt nobody can verify is a log line.
    pub fn writes_receipts(self) -> bool {
        matches!(self, Self::Receipt | Self::Both)
    }
}

/// The billing answer for one outcome, in the configuration
/// vocabulary.
///
/// A deliberate mirror of `sbproxy_meter::Billable` rather than a
/// re-export. The meter crate depends on no other crate in this
/// workspace, which is what lets an operator metering a plain REST API
/// compile it without the AI stack; deriving [`schemars::JsonSchema`]
/// on its types would end that. So the wire vocabulary lives here, the
/// billing vocabulary lives there, and `sbproxy-core` converts between
/// them. The two are kept in step by
/// `sbproxy_meter::BillableOutcome::ALL`: adding an outcome there stops
/// the conversion compiling until this surface answers for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BillableRule {
    /// Bill every unit the call produced.
    Yes,
    /// Bill nothing. The call is still recorded, because a receipt that
    /// omits the free calls cannot be reconciled against a request log.
    No,
    /// Bill the work the origin actually performed, even though the
    /// request was cut short.
    Partial,
    /// Fold this attempt into the invoice line its claim names, so a
    /// flaky origin costs the buyer once rather than once per attempt.
    Collapse,
}

/// `proxy.attestation.billable`: what the operator charges for.
///
/// Every field is `Option` so that an incomplete block is a config
/// error this crate can describe rather than a serde error that names
/// one missing field at a time. The operator owes an answer for all
/// eight, and [`Self::missing_outcomes`] hands them the whole list in
/// one message. Nothing is defaulted: an unstated billing rule still
/// runs, it just runs as whatever the code happened to do, and nobody
/// discovers what that was until a buyer asks.
///
/// `cache_hit` is the case that proves the rule. A vendor selling
/// compute can argue a cache hit cost them nothing; a vendor selling
/// answers can argue the answer is what was bought and where it came
/// from is their business. Both are positions real companies hold, so
/// this surface holds neither.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AttestationBillableConfig {
    /// The response was served to the client in full.
    pub delivered: Option<BillableRule>,
    /// The client went away before the response finished.
    pub client_disconnected: Option<BillableRule>,
    /// The origin rejected the request as the caller's fault.
    pub origin_4xx: Option<BillableRule>,
    /// The origin failed.
    pub origin_5xx: Option<BillableRule>,
    /// A policy refused the call before it reached the origin.
    pub policy_blocked: Option<BillableRule>,
    /// A rate limit rejected the call.
    pub rate_limited: Option<BillableRule>,
    /// The response was served from cache without touching the origin.
    pub cache_hit: Option<BillableRule>,
    /// One attempt of a call that was retried.
    pub retry: Option<BillableRule>,
}

impl AttestationBillableConfig {
    /// Every outcome the operator has not answered, in the order
    /// `sbproxy_meter::BillableOutcome::ALL` declares them.
    ///
    /// Returned rather than checked so the caller can name the whole
    /// set in one error. An operator who left three outcomes blank
    /// should not have to compile three times to find that out.
    pub fn missing_outcomes(&self) -> Vec<&'static str> {
        let answered: [(&'static str, bool); 8] = [
            ("delivered", self.delivered.is_some()),
            ("client_disconnected", self.client_disconnected.is_some()),
            ("origin_4xx", self.origin_4xx.is_some()),
            ("origin_5xx", self.origin_5xx.is_some()),
            ("policy_blocked", self.policy_blocked.is_some()),
            ("rate_limited", self.rate_limited.is_some()),
            ("cache_hit", self.cache_hit.is_some()),
            ("retry", self.retry.is_some()),
        ];
        answered
            .into_iter()
            .filter_map(|(name, given)| (!given).then_some(name))
            .collect()
    }
}

/// `proxy.attestation.queue`: where claims wait until they settle.
///
/// A claim is written when the call starts and settled when it
/// finishes, and the gap between those is where a crash loses money.
/// The queue is that gap made durable.
///
/// Nothing writes this queue today. The claim half is not implemented
/// in this build and [`AttestationRole::Claim`] is refused at config
/// compile, so the block is validated and its path resolved, and no
/// file or directory is created for it.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttestationQueueConfig {
    /// Filesystem path of the queue. Required: an attestation role with
    /// nowhere to hold unsettled claims silently drops them on restart,
    /// which is the failure the whole mechanism exists to prevent.
    pub path: String,
    /// How many unsettled claims to hold before the configured
    /// [`AttestationConfig::failure_mode`] applies. Defaults to
    /// 100,000, which is roughly a minute of unsettled work at a
    /// thousand requests a second.
    #[serde(default = "default_attestation_queue_max_entries")]
    pub max_entries: usize,
}

/// `proxy.attestation.ledger`: where settled records are chained.
///
/// The ledger answers the half of a billing dispute a signature cannot:
/// "I made calls you never credited". Each record is hash-chained to
/// the one before it, so a gap is visible rather than merely absent.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttestationLedgerConfig {
    /// Filesystem path of the append-only ledger file.
    pub path: String,
}

/// Which observed quantity a measured unit counts, in the
/// configuration vocabulary.
///
/// A deliberate mirror of `sbproxy_meter::MeasuredQuantity` rather than
/// a re-export, for the same reason [`BillableRule`] mirrors
/// `sbproxy_meter::Billable`. The meter crate depends on no other crate
/// in this workspace, which is what lets an operator metering a plain
/// REST API compile it without the gateway around it; deriving
/// [`schemars::JsonSchema`] on its types would end that. So the config
/// vocabulary lives here, the metering vocabulary lives there, and
/// `sbproxy-core` converts between them. Both spell the variants the
/// same way on the wire, so a config written against one reads the same
/// as a receipt written by the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttestationMeasuredQuantity {
    /// The request itself, which is always one. What a flat per-call
    /// charge is built from.
    Requests,
    /// Request bytes received from the client.
    BytesIn,
    /// Response bytes written to the client. What was actually written,
    /// so a response that was cut short bills what crossed the wire.
    BytesOut,
    /// Wall-clock milliseconds the request was in flight.
    DurationMs,
}

/// `proxy.attestation.measured[]`: one unit the proxy counted itself.
///
/// The only unit source with nothing outside the process in it. The
/// proxy saw the bytes and held the clock, so nobody else contributed
/// to the number and there is no third party whose word has to be
/// taken. That is why it is the resolver to reach for first: a route
/// weight is only as honest as the document it was read from, and an
/// origin header is only as honest as the party being paid for it,
/// whereas this one is arithmetic over things that demonstrably
/// happened.
///
/// A partial unit is billed as a whole one. Twelve thousand and
/// forty-three bytes against a kibibyte rule is twelve units, not
/// eleven and a bit, because the operator delivered those bytes and
/// there is no fraction of a kibibyte to hand back. See
/// `sbproxy_meter::MeasuredRule`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttestationMeasuredConfig {
    /// Unit name that appears on the invoice line, for example
    /// `egress_kib`. Unique across every resolver: two units sharing a
    /// name on one receipt is an invoice line that cannot be read.
    pub name: String,
    /// The observed quantity this entry counts. See
    /// [`AttestationMeasuredQuantity`].
    pub quantity: AttestationMeasuredQuantity,
    /// How much of the raw quantity makes one unit.
    ///
    /// This is the key that turns bytes into kibibytes: `1024` against
    /// [`AttestationMeasuredQuantity::BytesOut`] bills one unit per
    /// kibibyte written. A divisor rather than a multiplier because the
    /// raw quantity is always the smaller currency and the invoice line
    /// is always the larger one. Nobody sells thousandths of a request,
    /// but plenty of people sell kibibytes and compute-seconds, and
    /// writing `per: 1000` against `duration_ms` says "a second" in the
    /// units the proxy actually observed rather than asking the
    /// operator to express a rate as a fraction.
    ///
    /// Defaults to `1`, which bills one unit per observed item and is
    /// the only sensible reading of an entry that omits it. Zero is
    /// rejected at config compile: a divisor of zero has no answer to
    /// fall back on, and the request path is the wrong place to find
    /// that out.
    #[serde(default = "default_measured_per")]
    pub per: u64,
}

/// `proxy.attestation.route_weights[]`: one route the operator priced.
///
/// The simplest thing an operator can say about what a call costs, and
/// the only one that needs nothing from anybody: the weight is written
/// down, so the number is a pure function of the route and the document
/// it was read from. That document is already signed, so naming its
/// revision on the receipt is all it takes for a buyer to check the
/// price themselves. See `sbproxy_meter::RouteWeightTable`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttestationRouteWeightConfig {
    /// Unit name that appears on the invoice line, for example
    /// `search_call`. Repeating a name across entries is how one line
    /// gets different prices on different routes; see [`Self::path`].
    pub name: String,
    /// HTTP method this entry prices, or absent for any method.
    /// Matched case-insensitively.
    #[serde(default)]
    pub method: Option<String>,
    /// The path this entry prices: either exact (`/v1/search`) or a
    /// prefix ending in `/*` (`/v1/search/*`), which covers everything
    /// below that segment and deliberately not the segment itself.
    ///
    /// When several entries share a [`Self::name`] and all match, the
    /// most specific wins: a named method beats an unnamed one, an exact
    /// path beats a prefix, and a longer prefix beats a shorter one. One
    /// name still bills one line.
    pub path: String,
    /// What one matching call costs.
    ///
    /// Zero is allowed and means the route is metered and free, which is
    /// not the same as having no entry for it. No entry means this line
    /// does not price the route at all, and the receipt then carries no
    /// unit rather than a zero.
    pub weight: u64,
}

/// `proxy.attestation.origin_headers[]`: one count the upstream reports.
///
/// The only unit source that can be wrong without the proxy being wrong,
/// because the party supplying the number is the party being paid for
/// it. That is not a reason to refuse it: an API selling result rows has
/// to bill result rows, and only the origin knows how many there were.
/// What the proxy does instead is attest rather than vouch. The receipt
/// records the header name and the value exactly as it arrived, so the
/// claim on the invoice is "the origin sent this", which is a claim the
/// proxy can actually stand behind.
///
/// There is deliberately no knob for what to do with a value that will
/// not parse. Substituting a number the proxy counted would put the
/// proxy's provenance on the origin's claim, and a receipt that cannot
/// separate "the origin lied" from "the proxy miscounted" is worthless
/// in the dispute it exists for. A value that does not parse bills zero
/// and goes on the receipt verbatim. See
/// `sbproxy_meter::OriginHeaderRule`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttestationOriginHeaderConfig {
    /// Unit name that appears on the invoice line, for example
    /// `result_row`. Unique across every resolver: two units sharing a
    /// name on one receipt is an invoice line that cannot be read.
    pub name: String,
    /// Response header the count is read from. Matched
    /// case-insensitively, and quoted back on the receipt in the
    /// spelling written here.
    ///
    /// A header rather than a body path. Reading a JSON body means
    /// buffering one, and what that costs a streaming response is its
    /// own decision rather than a side effect of a metering key.
    pub header: String,
}

/// `proxy.attestation`: the proxy-wide consumption attestation block.
///
/// Off unless [`Self::role`] says otherwise, and inert in every config
/// that does not mention it. When a role is set, the queue, the ledger,
/// and a complete [`AttestationBillableConfig`] all become required,
/// because a role with any of them missing is a proxy that claims to
/// meter and does not.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AttestationConfig {
    /// Which halves of attestation this proxy performs. See
    /// [`AttestationRole`]. Individual origins may narrow or widen this
    /// through `origins.<host>.attestation.role`.
    pub role: AttestationRole,
    /// What happens when attestation itself cannot run: the queue is
    /// full, the ledger will not accept an append, the signing identity
    /// is unusable.
    ///
    /// Defaults to [`FailureMode::Degraded`], which departs from the
    /// `closed` default the rest of this config surface takes, and the
    /// departure is the point. Fail-closed is right for a control that
    /// enforces a security boundary, because a control that silently
    /// admits traffic when it breaks is worse than no control at all.
    /// Billing is not a security boundary. A full ledger disk taking
    /// the whole API down is a worse outcome than a provable hole in
    /// the record, and `degraded` is precisely the posture that leaves
    /// the hole detectable: the call proceeds, the guarantee is marked
    /// as not made, and the gap is countable so an operator can alert
    /// on it and reconcile afterwards. An operator who genuinely cannot
    /// serve unbilled traffic sets `closed` and means it.
    #[serde(default = "default_attestation_failure_mode")]
    pub failure_mode: FailureMode,
    /// What happens when attestation *does* reach a verdict and that
    /// verdict is "refuse": a claim that exceeds an agreement's ceiling,
    /// for instance. [`EnforcementMode::Observe`] is the rollout
    /// posture, and it is a different question from
    /// [`Self::failure_mode`]: a control can reasonably observe while it
    /// is being tuned and still need to fail closed when its backend
    /// disappears.
    ///
    /// The only verdict attestation reaches is a claim measured against
    /// an agreement's ceiling, and the claim half is not implemented in
    /// this build, so this key records a posture nothing acts on yet.
    pub enforcement_mode: EnforcementMode,
    /// Which existing signing identity signs receipts, as the config
    /// path that declares it. The only accepted value today is
    /// [`ATTESTATION_SIGN_WITH_WEB_BOT_AUTH`], and that block must
    /// actually be configured. Required whenever the role writes
    /// receipts.
    pub sign_with: Option<String>,
    /// Where unsettled claims wait. Required when the role is not
    /// [`AttestationRole::Off`].
    pub queue: Option<AttestationQueueConfig>,
    /// Where settled records are chained. Required when the role is not
    /// [`AttestationRole::Off`].
    pub ledger: Option<AttestationLedgerConfig>,
    /// What the operator charges for. Required, and required complete,
    /// when the role is not [`AttestationRole::Off`].
    pub billable: Option<AttestationBillableConfig>,
    /// Units this proxy counted for itself. See
    /// [`AttestationMeasuredConfig`].
    ///
    /// Listed first because it is the resolver that needs nothing from
    /// anybody, and a receipt is easier to argue about when an
    /// unarguable line is sitting next to the contested ones.
    pub measured: Vec<AttestationMeasuredConfig>,
    /// Routes priced in this document. See
    /// [`AttestationRouteWeightConfig`].
    ///
    /// A sibling list rather than a variant of one `units:` block, and
    /// the same goes for [`Self::measured`] and [`Self::origin_headers`].
    /// Each resolver has its own provenance and its own way of being
    /// wrong, so each declares itself in its own vocabulary and none of
    /// them can be mistaken for another when a receipt is read back. It
    /// also means the expression resolver arrives later as a fourth list
    /// rather than as a variant every existing entry has to be
    /// retrofitted into.
    pub route_weights: Vec<AttestationRouteWeightConfig>,
    /// Counts this proxy reads back from its upstreams. See
    /// [`AttestationOriginHeaderConfig`].
    pub origin_headers: Vec<AttestationOriginHeaderConfig>,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            role: AttestationRole::Off,
            // Not `FailureMode::default()`. See the field's rustdoc:
            // billing is not a security boundary, so this one control
            // defaults away from the surface-wide `closed`.
            failure_mode: default_attestation_failure_mode(),
            enforcement_mode: EnforcementMode::Block,
            sign_with: None,
            queue: None,
            ledger: None,
            billable: None,
            measured: Vec::new(),
            route_weights: Vec::new(),
            origin_headers: Vec::new(),
        }
    }
}

/// `origins.<host>.attestation`: per-origin attestation overrides.
///
/// Two fields, and they are here for different reasons. `role` is an
/// override, because one gateway commonly fronts both a partner API it
/// resells (claims) and its own service (receipts). `agreement_id` has
/// no proxy-wide equivalent at all: it names the commercial agreement
/// the units are billed under, and that is a property of who is on the
/// other end of the connection, never of the proxy.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct OriginAttestationConfig {
    /// Narrows or widens `proxy.attestation.role` for this origin.
    /// Absent inherits the proxy-wide role.
    pub role: Option<AttestationRole>,
    /// The commercial agreement this origin's units are billed under.
    /// Without it a receipt says how much was consumed but not which
    /// contract turns that into money.
    pub agreement_id: Option<String>,
}

/// Address the public listeners bind when the operator names none.
///
/// Every interface. A reverse proxy's job is usually to be reachable, so
/// this preserves what every existing config already gets. The commands
/// that generate a config for one machine override it; see
/// [`ProxyServerConfig::bind_address`].
pub const DEFAULT_PUBLIC_BIND_ADDRESS: &str = "0.0.0.0";

impl ProxyServerConfig {
    /// The address the public HTTP and HTTPS listeners bind.
    ///
    /// Falls back to [`DEFAULT_PUBLIC_BIND_ADDRESS`]. The value is
    /// validated at config compile by
    /// [`Self::validate_bind_address`], so the listener path can format
    /// it into a socket address without re-checking.
    pub fn effective_bind_address(&self) -> &str {
        self.bind_address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_PUBLIC_BIND_ADDRESS)
    }

    /// Reject a `bind_address` that is not an IP literal.
    ///
    /// Refused at config load rather than at bind time, and refused
    /// rather than warned past. A misspelled bind address that falls
    /// back to a default is the failure this whole field exists to
    /// prevent: the operator believes they restricted the listener and
    /// the proxy is on every interface. There is no safe direction to
    /// guess in, so the config does not load.
    ///
    /// Hostnames are refused too. A name can resolve to several
    /// addresses, or to a different one after a DNS change, and a
    /// listener that silently moves between interfaces is not something
    /// an operator can reason about.
    pub fn validate_bind_address(&self) -> anyhow::Result<()> {
        let Some(raw) = self.bind_address.as_deref() else {
            return Ok(());
        };
        let value = raw.trim();
        if value.is_empty() {
            anyhow::bail!(
                "proxy.bind_address is empty. Remove the field to bind every interface \
                 ({DEFAULT_PUBLIC_BIND_ADDRESS}), or set an IP address such as 127.0.0.1."
            );
        }
        if value.parse::<std::net::IpAddr>().is_err() {
            anyhow::bail!(
                "proxy.bind_address {value:?} is not an IP address. Use an IP literal such \
                 as 0.0.0.0 (every interface), 127.0.0.1 (this machine only), or the address \
                 of one interface. Hostnames are not accepted: a name can resolve to more \
                 than one address, and a listener that moves is not one an operator can \
                 reason about."
            );
        }
        Ok(())
    }

    /// The zone this proxy considers itself in (WOR-2328).
    ///
    /// `proxy.zone` when set, otherwise the `SB_ZONE` environment
    /// variable, the knob a Kubernetes deployment populates from the
    /// node's `topology.kubernetes.io/zone` label. `None` means the
    /// proxy has no zone identity and load balancer target selection
    /// ignores `targets[].zone` labels entirely.
    ///
    /// Read once per pipeline compilation, never on the request path.
    pub fn resolve_zone(&self) -> Option<String> {
        Self::resolve_zone_from(
            self.zone.as_deref(),
            std::env::var("SB_ZONE").ok().as_deref(),
        )
    }

    /// Precedence core of [`Self::resolve_zone`], separated from the
    /// process environment so tests can drive both inputs without
    /// mutating shared state: config wins, blank values on either side
    /// count as unset, and the winner is trimmed.
    pub fn resolve_zone_from(config_zone: Option<&str>, env_zone: Option<&str>) -> Option<String> {
        config_zone
            .map(str::trim)
            .filter(|zone| !zone.is_empty())
            .or_else(|| env_zone.map(str::trim).filter(|zone| !zone.is_empty()))
            .map(str::to_string)
    }
}

impl Default for ProxyServerConfig {
    fn default() -> Self {
        Self {
            http_bind_port: default_http_port(),
            bind_address: None,
            zone: None,
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
            classifier_hooks: None,
            ai_toolkit: None,
            cluster: None,
            config_authority: None,
            secrets: None,
            key_management: None,
            l2_cache: None,
            anomaly: None,
            cache_reserve: None,
            response_cache_store: None,
            compression_state: None,
            config_history: None,
            messenger_settings: None,
            ai_providers_file: None,
            device_parser_file: None,
            trusted_proxies: Vec::new(),
            correlation_id: CorrelationIdConfig::default(),
            mtls: None,
            synthetic_probe: None,
            agent_registry: None,
            notifications: None,
            scripting: ScriptingConfig::default(),
            extensions: HashMap::new(),
            http_client_timeouts: HttpClientTimeoutsConfig::default(),
            web_bot_auth: None,
            attestation: None,
            tenants: Vec::new(),
            credentials: Vec::new(),
            federation: None,
            payments: None,
        }
    }
}

// --- Config authority: subscriber side ---

/// Default poll cadence against the upstream authority, in seconds.
const DEFAULT_CONFIG_AUTHORITY_POLL_SECS: u64 = 30;

/// Default staleness window for a cached bundle, in seconds.
const DEFAULT_CONFIG_AUTHORITY_STALENESS_SECS: u64 = 24 * 60 * 60;

/// Shortest poll cadence a subscriber may configure, in seconds.
///
/// A one-second poll is a denial-of-service tool aimed at the authority,
/// and no configuration distribution needs sub-five-second latency.
pub const MIN_CONFIG_AUTHORITY_POLL_SECS: u64 = 5;

/// Longest poll cadence a subscriber may configure, in seconds.
pub const MAX_CONFIG_AUTHORITY_POLL_SECS: u64 = 24 * 60 * 60;

/// Longest staleness window a subscriber may configure, in seconds.
///
/// Past a month a cached bundle is an archaeological record rather than a
/// configuration, so the schema refuses to call it fresh.
pub const MAX_CONFIG_AUTHORITY_STALENESS_SECS: u64 = 30 * 24 * 60 * 60;

/// Largest accepted path or identifier in this block, in bytes.
const MAX_CONFIG_AUTHORITY_VALUE_BYTES: usize = 4_096;

const fn default_config_authority_poll_secs() -> u64 {
    DEFAULT_CONFIG_AUTHORITY_POLL_SECS
}

const fn default_config_authority_staleness_secs() -> u64 {
    DEFAULT_CONFIG_AUTHORITY_STALENESS_SECS
}

/// `proxy.config_authority`: how this node takes part in config authority.
///
/// Both halves live here, and they are mutually exclusive.
/// [`Self::upstream`] makes this node a subscriber: it pulls signed
/// bundles from an authority, verifies them, merges them over the local
/// document, and applies the result through the ordinary reload
/// transaction. [`Self::publish`] makes it an authority: it validates,
/// signs, and serves bundles to subscribers of its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigAuthorityConfig {
    /// Upstream authority this node subscribes to. Absent means this node
    /// pulls no remote configuration.
    pub upstream: Option<ConfigAuthorityUpstreamConfig>,
    /// Publication settings that make this node an authority. Absent
    /// means this node serves no bundles.
    pub publish: Option<ConfigAuthorityPublishConfig>,
}

impl ConfigAuthorityConfig {
    /// Whether this node publishes bundles to subscribers of its own.
    ///
    /// Feeds the one-role rule in [`Self::validate`]: a node that both
    /// publishes and subscribes is refused, because the deny list keeps a
    /// bundle from rewriting `proxy.config_authority` and the republished
    /// provenance would name this node rather than the authority the
    /// values came from.
    pub const fn publishes_bundles(&self) -> bool {
        self.publish.is_some()
    }

    /// Validate the block, including the rules that cross fields.
    ///
    /// Run from `compile_config`, so `sbproxy validate` reports these
    /// before a node boots on them.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigAuthorityConfigError`] when a node both subscribes
    /// and publishes, or when either half fails any of its own rules. See
    /// [`ConfigAuthorityUpstreamConfig::validate`] and
    /// [`ConfigAuthorityPublishConfig::validate`].
    pub fn validate(&self) -> Result<(), ConfigAuthorityConfigError> {
        if let Some(upstream) = &self.upstream {
            // One node cannot be both the authority and a subscriber of
            // another authority: the deny list stops a bundle from
            // rewriting `proxy.config_authority`, so a node in both roles
            // would republish a document it does not fully own, and the
            // provenance an auditor reads downstream would name this node
            // rather than the authority the values actually came from.
            if self.publishes_bundles() {
                return Err(ConfigAuthorityConfigError::BothRoles);
            }
            upstream.validate()?;
        }
        if let Some(publish) = &self.publish {
            publish.validate()?;
        }
        Ok(())
    }
}

/// Default per-subscriber request budget on the bundle listener, per minute.
///
/// A subscriber polls once per interval and the shortest interval the
/// schema accepts is [`MIN_CONFIG_AUTHORITY_POLL_SECS`], so twelve
/// requests a minute is the most a well-behaved subscriber ever needs.
/// The rest is headroom for a retry or a manual `curl`, and it still
/// leaves no room for a node polling in a loop.
const DEFAULT_PUBLISH_SUBSCRIBER_RATE_LIMIT: u64 = 30;

/// Default fleet-wide request budget on the bundle listener, per minute.
///
/// The per-subscriber cap alone does not bound the authority: a thousand
/// nodes restarting together each stay inside their own limit while
/// collectively saturating it. This is the cap that turns a restart storm
/// into a queue of `429`s the subscribers retry through, rather than an
/// authority that stops answering anyone.
const DEFAULT_PUBLISH_TOTAL_RATE_LIMIT: u64 = 1_200;

/// Largest per-subscriber or fleet-wide rate limit the schema accepts.
///
/// Neither limit can be set to zero: an authority with no bound is an
/// authority one misconfigured subscriber can take down, and the whole
/// fleet loses configuration distribution with it.
pub const MAX_PUBLISH_RATE_LIMIT: u64 = 1_000_000;

const fn default_publish_subscriber_rate_limit() -> u64 {
    DEFAULT_PUBLISH_SUBSCRIBER_RATE_LIMIT
}

/// Default for `proxy.config_authority.publish.archive_keep`.
const fn default_publish_archive_keep() -> usize {
    crate::config_authority::DEFAULT_ARCHIVE_KEEP
}

const fn default_publish_total_rate_limit() -> u64 {
    DEFAULT_PUBLISH_TOTAL_RATE_LIMIT
}

/// `proxy.config_authority.publish`: this node signs and serves
/// configuration bundles to subscribers.
///
/// ```yaml
/// proxy:
///   config_authority:
///     publish:
///       authority_id: control-plane-eu
///       key_id: authority-2026-07
///       signing_key_file: /etc/sbproxy/authority-signing.key
///       store_dir: /var/lib/sbproxy/config-authority
///       bind: 0.0.0.0:9443
///       tls:
///         cert_file: /etc/sbproxy/authority.pem
///         key_file: /etc/sbproxy/authority-key.pem
/// ```
///
/// The bundle endpoint gets its own listener on [`Self::bind`], separate
/// from the admin server, and serves exactly one path. Publication,
/// status, and subscriber management are admin routes on the admin
/// listener, because those are operator actions authenticated with
/// operator credentials, while a bundle fetch is a fleet action
/// authenticated with a per-subscriber credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigAuthorityPublishConfig {
    /// Stable identifier stamped into every bundle this node signs.
    /// Subscribers read it as `authority_id` in the envelope.
    pub authority_id: String,
    /// Key ID stamped into every envelope, selecting which entry of a
    /// subscriber's `verifying_keys_file` verifies the signature.
    ///
    /// Rotation publishes under a new ID while subscribers still trust the
    /// old one, so this changes without a synchronized fleet restart.
    pub key_id: String,
    /// Path to the Ed25519 signing key: one standard-base64 32-byte seed.
    ///
    /// Must be owner-only on unix. A node with `publish` configured and no
    /// readable signing key refuses to start, because an authority that
    /// cannot sign cannot serve, and finding that out at the first publish
    /// attempt means finding it out during a change window.
    pub signing_key_file: String,
    /// Directory holding the durable revision counter, the current and
    /// previous signed bundles, and the subscriber registry.
    pub store_dir: String,
    /// `host:port` for the bundle listener, for example `0.0.0.0:9443`.
    ///
    /// Its own listener, not the admin port: subscribers authenticate with
    /// a per-subscriber credential rather than operator credentials, and
    /// nothing on this listener answers `/admin/*`, `/metrics`, or the UI.
    pub bind: String,
    /// TLS material for the bundle listener.
    ///
    /// Required whenever [`Self::bind`] is not a loopback address. The
    /// admin listener leaves TLS optional on a remote bind; this one does
    /// not, because the credential a subscriber presents here is a
    /// long-lived fleet credential and the payload is the whole
    /// configuration.
    #[serde(default)]
    pub tls: Option<ConfigAuthorityPublishTlsConfig>,
    /// Requests one subscriber may make per minute before the listener
    /// answers `429`.
    #[serde(default = "default_publish_subscriber_rate_limit")]
    pub rate_limit_per_subscriber_per_minute: u64,
    /// Requests the listener serves per minute across the whole fleet
    /// before it answers `429`.
    #[serde(default = "default_publish_total_rate_limit")]
    pub rate_limit_total_per_minute: u64,
    /// How many earlier revisions the authority keeps so a rollback can
    /// name one of them.
    ///
    /// The authority has always kept the current bundle and the one
    /// before it, which is enough to undo the last publish. This bounds
    /// the ring beside those two, which is what lets
    /// `POST /admin/config-authority/rollback` accept a `to_revision`
    /// from further back than one step.
    ///
    /// This counts revisions a rollback can name, so the revision
    /// currently being served does not use up a slot and the ring holds
    /// `archive_keep + 1` files.
    ///
    /// Zero keeps no ring and leaves the one-step rollback exactly as it
    /// was. The maximum is 200. At the maximum, and with a configuration
    /// document at the 4 MiB wire limit, the ring is bounded at 1.58 GiB
    /// of disk; a real document makes the default ring cost kilobytes.
    #[serde(default = "default_publish_archive_keep")]
    pub archive_keep: usize,
}

impl ConfigAuthorityPublishConfig {
    /// Whether [`Self::bind`] names a loopback address.
    ///
    /// A bind that does not parse counts as remote, so an unparseable
    /// value cannot slip past the TLS requirement by being unreadable.
    /// [`Self::validate`] rejects it separately with a clearer message.
    pub fn binds_loopback_only(&self) -> bool {
        self.bind
            .trim()
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|addr| addr.ip().to_canonical().is_loopback())
    }

    /// The parsed listener address.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigAuthorityConfigError::PublishBind`] when `bind` is
    /// not an IP address and port.
    pub fn socket_addr(&self) -> Result<std::net::SocketAddr, ConfigAuthorityConfigError> {
        self.bind
            .trim()
            .parse()
            .map_err(|_| ConfigAuthorityConfigError::PublishBind {
                bind: self.bind.clone(),
                reason: "must be an IP address and port, for example 0.0.0.0:9443 or \
                         127.0.0.1:9443; a hostname is not accepted because the listener binds \
                         rather than resolves",
            })
    }

    /// Validate every rule this block owns.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigAuthorityConfigError`] when an identifier or path
    /// is empty or oversized, when `authority_id` or `key_id` carries a
    /// character the signature envelope refuses, when `bind` is not a
    /// fixed IP address and port, when a non-loopback bind carries no
    /// `tls` block, or when a rate limit is zero, above
    /// [`MAX_PUBLISH_RATE_LIMIT`], or smaller than the per-subscriber
    /// limit it is supposed to bound.
    pub fn validate(&self) -> Result<(), ConfigAuthorityConfigError> {
        for (field, value) in [
            ("authority_id", &self.authority_id),
            ("key_id", &self.key_id),
            ("signing_key_file", &self.signing_key_file),
            ("store_dir", &self.store_dir),
            ("bind", &self.bind),
        ] {
            validate_publish_value(field, value)?;
        }
        // The envelope bounds these two more tightly than a filesystem
        // path does, so a value that would produce a bundle no subscriber
        // accepts is caught here rather than at the first publish.
        for (field, value) in [
            ("authority_id", &self.authority_id),
            ("key_id", &self.key_id),
        ] {
            if !crate::config_bundle::is_valid_bundle_identifier(value) {
                return Err(ConfigAuthorityConfigError::PublishIdentifier { field });
            }
        }
        if self.socket_addr()?.port() == 0 {
            return Err(ConfigAuthorityConfigError::PublishBind {
                bind: self.bind.clone(),
                reason: "must name a fixed port; port 0 would move on every restart and no \
                         subscriber URL could point at it",
            });
        }
        if let Some(tls) = &self.tls {
            validate_publish_value("tls.cert_file", &tls.cert_file)?;
            validate_publish_value("tls.key_file", &tls.key_file)?;
        } else if !self.binds_loopback_only() {
            return Err(ConfigAuthorityConfigError::PublishTlsRequired {
                bind: self.bind.clone(),
            });
        }
        for (field, found) in [
            (
                "rate_limit_per_subscriber_per_minute",
                self.rate_limit_per_subscriber_per_minute,
            ),
            (
                "rate_limit_total_per_minute",
                self.rate_limit_total_per_minute,
            ),
        ] {
            if found == 0 || found > MAX_PUBLISH_RATE_LIMIT {
                return Err(ConfigAuthorityConfigError::PublishRateLimit { field, found });
            }
        }
        if self.rate_limit_total_per_minute < self.rate_limit_per_subscriber_per_minute {
            return Err(ConfigAuthorityConfigError::PublishRateLimitInverted {
                total: self.rate_limit_total_per_minute,
                per_subscriber: self.rate_limit_per_subscriber_per_minute,
            });
        }
        if self.archive_keep > crate::config_authority::MAX_ARCHIVE_KEEP {
            return Err(ConfigAuthorityConfigError::PublishArchiveKeep {
                found: self.archive_keep,
            });
        }
        Ok(())
    }
}

/// TLS material for the config-authority bundle listener.
///
/// Both fields are required together. Unlike the admin listener's TLS
/// block, this one is mandatory on any non-loopback bind.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigAuthorityPublishTlsConfig {
    /// Path to the PEM certificate chain, leaf first.
    pub cert_file: String,
    /// Path to the PEM private key (PKCS#8 or RSA).
    pub key_file: String,
}

/// Validate one bounded, non-empty, control-character-free publish value.
fn validate_publish_value(
    field: &'static str,
    value: &str,
) -> Result<(), ConfigAuthorityConfigError> {
    if value.trim().is_empty()
        || value.len() > MAX_CONFIG_AUTHORITY_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ConfigAuthorityConfigError::PublishValue { field });
    }
    Ok(())
}

/// `proxy.config_authority.upstream`: the authority this node pulls
/// signed configuration bundles from.
///
/// ```yaml
/// proxy:
///   config_authority:
///     upstream:
///       url: https://control.example.com
///       mode: overlay
///       subscriber_id: edge-01
///       credential: env:SB_CONFIG_TOKEN
///       verifying_keys_file: /etc/sbproxy/authority-keys.json
///       poll_interval: 30s
///       cache_path: /var/lib/sbproxy/config-bundle.json
///       max_staleness: 24h
///       require_bundle_on_boot: false
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigAuthorityUpstreamConfig {
    /// Absolute base URL of the authority, for example
    /// `https://control.example.com`. The subscriber appends its own
    /// path; a path on this URL is kept as a prefix.
    ///
    /// Must be `https` unless [`Self::allow_insecure_http`] is set.
    pub url: String,
    /// Whether a bundle merges over the local document or replaces it.
    ///
    /// Required rather than defaulted: the answer decides whether the
    /// local file still describes what this node serves, which is not a
    /// question to answer by omission.
    pub mode: crate::config_bundle::BundleMode,
    /// Stable identity this node presents to the authority. Sent on
    /// every fetch so an authority can scope what it publishes.
    pub subscriber_id: String,
    /// Reference to the bearer credential presented to the authority.
    ///
    /// Resolved through the process secret resolver, so the accepted
    /// forms are `env:NAME`, `${NAME}`, `file:/path`, and a
    /// provider-URI reference such as `secret://backend/name`. An inline
    /// literal is refused: a token committed to a config file is a token
    /// in every git history that ever held it.
    #[serde(default)]
    pub credential: Option<String>,
    /// Path to the JSON file naming every key this subscriber trusts.
    /// See `VerifyingKeySet::from_file` for the file shape.
    pub verifying_keys_file: String,
    /// How often the subscriber polls the authority, in seconds. Accepts
    /// a humanized duration (`30s`, `5m`) or bare seconds.
    ///
    /// The real interval carries jitter, so a fleet restarting together
    /// does not synchronize onto the authority.
    #[serde(
        rename = "poll_interval",
        alias = "poll_interval_secs",
        default = "default_config_authority_poll_secs",
        deserialize_with = "crate::duration::deserialize_secs"
    )]
    pub poll_interval_secs: u64,
    /// Where the verified bundle is cached so the node can boot on the
    /// last known configuration when the authority is unreachable. The
    /// anti-replay cursor is stored beside it.
    pub cache_path: String,
    /// How old a cached bundle may be and still be used at boot, in
    /// seconds. Accepts a humanized duration (`24h`, `7d`) or bare
    /// seconds.
    ///
    /// A running node that exceeds this window keeps serving and logs at
    /// error level every cycle; the window is a boot-time gate, not a
    /// kill switch on a node that is already up.
    #[serde(
        rename = "max_staleness",
        alias = "max_staleness_secs",
        default = "default_config_authority_staleness_secs",
        deserialize_with = "crate::duration::deserialize_secs"
    )]
    pub max_staleness_secs: u64,
    /// Whether the node refuses to start without a usable bundle.
    ///
    /// Absent means `false` under `mode: overlay` and `true` under
    /// `mode: replace`. An explicit `false` under `mode: replace` is a
    /// config error rather than a silently overridden value: under
    /// replace the local document is not a servable configuration, so
    /// there would be nothing to boot on.
    #[serde(default)]
    pub require_bundle_on_boot: Option<bool>,
    /// Permit a plaintext `http://` authority URL. Development only.
    ///
    /// Bundle signatures are checked either way, so this does not let an
    /// attacker forge a configuration, but it does expose the credential
    /// this node presents and reveals the whole configuration to anyone
    /// on the path.
    #[serde(default)]
    pub allow_insecure_http: bool,
    /// Acknowledge that `hmac_sha256` entries in the verifying-key file
    /// may verify bundles. Development only.
    ///
    /// A shared secret is symmetric: every subscriber holding it can
    /// forge a bundle for every other subscriber. Off by default, and
    /// verification refuses those bundles until it is on.
    #[serde(default)]
    pub allow_shared_secret_keys: bool,
}

impl ConfigAuthorityUpstreamConfig {
    /// Whether this node refuses to start without a usable bundle.
    ///
    /// Resolves the documented default: `replace` implies `true`,
    /// `overlay` implies `false`, and an explicit value wins in the
    /// combinations [`Self::validate`] accepts.
    pub fn requires_bundle_on_boot(&self) -> bool {
        self.require_bundle_on_boot
            .unwrap_or(self.mode == crate::config_bundle::BundleMode::Replace)
    }

    /// The merge mode this subscriber applies a bundle with.
    pub fn merge_mode(&self) -> crate::config_merge::MergeMode {
        match self.mode {
            crate::config_bundle::BundleMode::Overlay => crate::config_merge::MergeMode::Overlay,
            crate::config_bundle::BundleMode::Replace => crate::config_merge::MergeMode::Replace,
        }
    }

    /// Validate every rule this block owns.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigAuthorityConfigError`] when the URL is not an
    /// absolute `https` URL (and `allow_insecure_http` is unset), when
    /// an identifier or path is empty or oversized, when the credential
    /// is an inline literal rather than a reference, when a duration is
    /// outside its documented bounds, or when `mode: replace` is paired
    /// with an explicit `require_bundle_on_boot: false`.
    pub fn validate(&self) -> Result<(), ConfigAuthorityConfigError> {
        validate_authority_url(&self.url, self.allow_insecure_http)?;
        validate_authority_value("subscriber_id", &self.subscriber_id)?;
        validate_authority_value("verifying_keys_file", &self.verifying_keys_file)?;
        validate_authority_value("cache_path", &self.cache_path)?;
        if let Some(credential) = self.credential.as_deref() {
            validate_authority_value("credential", credential)?;
            if !is_secret_reference(credential) {
                return Err(ConfigAuthorityConfigError::InlineCredential);
            }
        }
        if self.poll_interval_secs < MIN_CONFIG_AUTHORITY_POLL_SECS
            || self.poll_interval_secs > MAX_CONFIG_AUTHORITY_POLL_SECS
        {
            return Err(ConfigAuthorityConfigError::PollInterval {
                found: self.poll_interval_secs,
            });
        }
        if self.max_staleness_secs < self.poll_interval_secs
            || self.max_staleness_secs > MAX_CONFIG_AUTHORITY_STALENESS_SECS
        {
            return Err(ConfigAuthorityConfigError::MaxStaleness {
                found: self.max_staleness_secs,
                poll_interval_secs: self.poll_interval_secs,
            });
        }
        if self.mode == crate::config_bundle::BundleMode::Replace
            && self.require_bundle_on_boot == Some(false)
        {
            return Err(ConfigAuthorityConfigError::ReplaceWithoutBundleOnBoot);
        }
        Ok(())
    }
}

/// Why a `proxy.config_authority` block was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigAuthorityConfigError {
    /// The node both subscribes to an authority and publishes to
    /// subscribers of its own.
    #[error("proxy.config_authority declares both `upstream` and a publishing role; one node cannot both subscribe to an authority and publish to subscribers, because the deny list keeps a bundle from rewriting proxy.config_authority and the republished provenance would name this node rather than the authority the values came from")]
    BothRoles,
    /// The authority URL was not usable.
    #[error("proxy.config_authority.upstream.url {url:?} is invalid: {reason}")]
    Url {
        /// URL as configured.
        url: String,
        /// What was wrong with it.
        reason: &'static str,
    },
    /// A required identifier or path was empty, oversized, or carried
    /// control characters.
    #[error("proxy.config_authority.upstream.{field} must be a bounded value with no control characters")]
    Value {
        /// Offending field name.
        field: &'static str,
    },
    /// The credential was an inline literal rather than a reference.
    #[error("proxy.config_authority.upstream.credential must be a secret reference (`env:NAME`, `${{NAME}}`, `file:/path`, or `secret://backend/name`), not an inline token: a token in a config file is a token in every copy of that file")]
    InlineCredential,
    /// The poll interval was outside its documented bounds.
    #[error("proxy.config_authority.upstream.poll_interval is {found}s; it must be between {MIN_CONFIG_AUTHORITY_POLL_SECS}s and {MAX_CONFIG_AUTHORITY_POLL_SECS}s")]
    PollInterval {
        /// Configured interval, in seconds.
        found: u64,
    },
    /// The staleness window was outside its documented bounds.
    #[error("proxy.config_authority.upstream.max_staleness is {found}s; it must be at least the {poll_interval_secs}s poll interval and no more than {MAX_CONFIG_AUTHORITY_STALENESS_SECS}s")]
    MaxStaleness {
        /// Configured window, in seconds.
        found: u64,
        /// Configured poll interval, in seconds.
        poll_interval_secs: u64,
    },
    /// `mode: replace` was paired with an explicit
    /// `require_bundle_on_boot: false`.
    #[error("proxy.config_authority.upstream sets `mode: replace` with `require_bundle_on_boot: false`; under replace the local document is not a servable configuration, so there is nothing to boot on. Remove the field (replace implies true) or switch to `mode: overlay`")]
    ReplaceWithoutBundleOnBoot,
    /// A required publish identifier or path was empty, oversized, or
    /// carried control characters.
    #[error(
        "proxy.config_authority.publish.{field} must be a bounded value with no control characters"
    )]
    PublishValue {
        /// Offending field name.
        field: &'static str,
    },
    /// A publish identifier carried a character the signed envelope
    /// refuses.
    #[error("proxy.config_authority.publish.{field} must be printable ASCII limited to letters, digits, and `. - _ :`; the signed bundle envelope refuses anything else, so a bundle carrying this value would be rejected by every subscriber")]
    PublishIdentifier {
        /// Offending field name.
        field: &'static str,
    },
    /// The publish listener bind was not a usable address and port.
    #[error("proxy.config_authority.publish.bind {bind:?} is invalid: {reason}")]
    PublishBind {
        /// Bind as configured.
        bind: String,
        /// What was wrong with it.
        reason: &'static str,
    },
    /// The publish listener binds off loopback with no TLS material.
    #[error("proxy.config_authority.publish.bind is `{bind}`, which is not a loopback address, and no `tls` block is set. The bundle listener refuses to start rather than serve plaintext: subscribers present a long-lived fleet credential on it and the response body is the whole configuration. Set publish.tls.cert_file and publish.tls.key_file, or bind to loopback and terminate TLS in front")]
    PublishTlsRequired {
        /// Bind as configured.
        bind: String,
    },
    /// A publish rate limit was zero or above the accepted maximum.
    #[error("proxy.config_authority.publish.{field} is {found}; it must be between 1 and {MAX_PUBLISH_RATE_LIMIT} requests per minute (the bundle listener's rate limit cannot be turned off, because an unbounded authority is one a single misconfigured subscriber can take down and the whole fleet loses config distribution with it)")]
    PublishRateLimit {
        /// Offending field name.
        field: &'static str,
        /// Configured value.
        found: u64,
    },
    /// `archive_keep` was above the accepted maximum.
    #[error("proxy.config_authority.publish.archive_keep is {found}; it must be at most {max} (the archive is bounded because every entry is a whole signed configuration on the authority's disk, and at {max} a document at the wire limit already reaches {ceiling} bytes)", max = crate::config_authority::MAX_ARCHIVE_KEEP, ceiling = crate::config_authority::MAX_ARCHIVE_BYTES)]
    PublishArchiveKeep {
        /// Configured value.
        found: usize,
    },
    /// The fleet-wide rate limit was below the per-subscriber limit it is
    /// supposed to bound.
    #[error("proxy.config_authority.publish.rate_limit_total_per_minute is {total}, below the {per_subscriber} allowed to a single subscriber; the fleet-wide cap is meant to bound the sum, so a value under the per-subscriber cap means one subscriber can exhaust the whole authority")]
    PublishRateLimitInverted {
        /// Configured fleet-wide limit.
        total: u64,
        /// Configured per-subscriber limit.
        per_subscriber: u64,
    },
}

/// Every prefix the process secret resolver resolves **off the machine
/// that resolves it**, in the order
/// `SecretResolver::resolve_with_limit` tests them
/// (`crates/sbproxy-vault/src/resolver.rs:135-165`), paired with what
/// each one reads.
///
/// The single place this crate spells the resolver's reference
/// vocabulary. [`is_secret_reference`] and
/// [`host_backed_secret_reference`] both classify through
/// [`host_backed_prefix`] rather than matching a scheme literal of
/// their own, which is what `scripts/check-secret-resolver-drift.py`
/// asks of every call site: a second hand-rolled parse of this syntax
/// is a detector that can drift narrower than the resolver enforcing
/// it, and this branch shipped exactly that until CI said so
/// (WOR-2433).
///
/// The `${VAR}` form the resolver also reads from the environment is
/// deliberately absent: it is a template spelling, refused earlier and
/// by name in [`crate::confined_template`], and folding it in here would
/// make [`host_backed_secret_reference`] report a template as a secret
/// reference to every caller that asks which host resource a value
/// opens.
pub(crate) const HOST_BACKED_SECRET_PREFIXES: &[(&str, HostSecretSource)] = &[
    // Checked before the provider-URI parse, so the legacy alias keeps
    // its environment semantics rather than being read as a `vault`
    // backend named `env`.
    ("vault://env/", HostSecretSource::LegacyVaultEnvironment),
    ("env:", HostSecretSource::Environment),
    ("file:", HostSecretSource::HostFile),
];

/// Which host resource `trimmed` names, if it names one.
///
/// The one prefix match in this crate. Callers ask this rather than
/// spelling a scheme themselves, so the vocabulary has exactly one
/// definition and a new prefix reaches every detector at once.
fn host_backed_prefix(trimmed: &str) -> Option<HostSecretSource> {
    HOST_BACKED_SECRET_PREFIXES
        .iter()
        .find_map(|(prefix, source)| {
            trimmed
                .strip_prefix(prefix)
                .filter(|rest| !rest.is_empty())
                .map(|_| *source)
        })
}

/// Whether `value` names a secret rather than carrying one inline.
///
/// Mirrors the forms the process secret resolver accepts. Deliberately a
/// shape check only: `sbproxy validate` must not need the environment
/// variable to be exported or the secret backend to be reachable.
///
/// `pub`, not `pub(crate)`: this shape check is shared beyond
/// `sbproxy-config`. `sbproxy-extension`'s bundle config vars reuse it to
/// decide which attachment config values to resolve as secret references
/// and which resolved values to mask in diagnostics (WOR-2289), rather
/// than duplicating a third copy of this heuristic.
pub fn is_secret_reference(value: &str) -> bool {
    let trimmed = value.trim();
    if host_backed_prefix(trimmed).is_some() {
        return true;
    }
    if trimmed.starts_with("${") && trimmed.ends_with('}') && trimmed.len() > 3 {
        return true;
    }
    // A provider-URI reference (`secret://`, `vault://`, `awssm://`, ...).
    // Matched structurally rather than against a scheme allowlist, which
    // lives in the vault crate; an unknown scheme fails loudly at
    // resolution rather than being mistaken for an inline token here.
    match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            !scheme.is_empty()
                && scheme
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'+' | b'.'))
                && !matches!(scheme, "http" | "https")
                && !rest.is_empty()
        }
        None => false,
    }
}

/// What a secret reference reads on the machine that resolves it, when
/// it reads the host directly rather than an operator-declared backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSecretSource {
    /// `env:NAME` - the process environment.
    Environment,
    /// `vault://env/NAME` - the legacy alias for the same read.
    LegacyVaultEnvironment,
    /// `file:/path` - an arbitrary path on the host filesystem.
    HostFile,
}

impl HostSecretSource {
    /// The reference spelling, for an error message. Never the value.
    #[must_use]
    pub fn form(self) -> &'static str {
        match self {
            Self::Environment => "env:NAME",
            Self::LegacyVaultEnvironment => "vault://env/NAME",
            Self::HostFile => "file:PATH",
        }
    }

    /// What the form reads, for an error message.
    #[must_use]
    pub fn reads(self) -> &'static str {
        match self {
            Self::Environment | Self::LegacyVaultEnvironment => "the process environment",
            Self::HostFile => "a file on the host filesystem",
        }
    }
}

/// Whether `value` is a secret reference the process resolver reads
/// straight off the host, rather than through a backend the operator
/// declared under `proxy.secrets`.
///
/// This is the shape half of a guard whose enforcing half lives in
/// another crate. `sbproxy-vault`'s `SecretResolver::resolve_with_limit`
/// (`crates/sbproxy-vault/src/resolver.rs:135-165`) tests four prefixes
/// before it reaches the backend manager, in this order: the legacy
/// `vault://env/NAME` alias, a whole-value `${VAR}`, `env:NAME`, and
/// `file:PATH`. The first, third and fourth are what this returns; the
/// second is a template form the confined pass
/// ([`crate::confined_template`]) already refuses as `${VAR}`.
///
/// # What this cannot see
///
/// `sbproxy-config` does not depend on `sbproxy-vault` and cannot, so
/// this is a mirror rather than a call, and a new host-backed prefix
/// added to that resolver will not appear here on its own. Three things
/// hold it. The mirror has exactly one spelling in this crate, the
/// crate-private `HOST_BACKED_SECRET_PREFIXES` table, which this
/// function and [`is_secret_reference`] both classify through, so the
/// two can no longer disagree with each other; this doc names the
/// resolver's exact
/// function and line range; and `sbproxy-vault`'s
/// `every_host_backed_prefix_is_mirrored_by_the_confined_pass` pins the
/// resolver's prefix set with a failure message pointing back here.
/// `every_host_backed_prefix_the_resolver_reads_is_refused` walks the
/// table from the other end, asserting each prefix is classified, is
/// refused by the confined pass, and cannot be smuggled past either by
/// surrounding whitespace. The mirror is deliberately the wider of the
/// two everywhere they differ,
/// and they differ twice. `vault://env/` is matched on the scheme and
/// authority alone, while the resolver additionally requires a
/// syntactically valid variable name, so a fragment writing a malformed
/// one is refused rather than waved through. And the value is trimmed
/// before the prefixes are tested, while the resolver tests the raw
/// value, so a leading space cannot smuggle a reference past this and
/// into a field that trims later.
///
/// Provider-URI schemes (`secret://`, `vault://<backend>/`, `awssm://`,
/// `gcpsm://`, `k8ssecret://`, `secretfile://<backend>/`) are
/// deliberately absent: each resolves only against a backend named under
/// `proxy.secrets`, which is in [`crate::AUTHORITY_DENIED_PATHS`] and is
/// not a field an externally authored document may set, so the operator
/// still chooses what those reach.
#[must_use]
pub fn host_backed_secret_reference(value: &str) -> Option<HostSecretSource> {
    let trimmed = value.trim();
    // Two questions, both answered by shared code rather than by a
    // scheme literal written here. Is this a secret reference at all?
    // [`is_secret_reference`] decides, so this detector can never call
    // something a bare literal that the crate's own classifier calls a
    // reference. And if it is, which host resource does it open?
    // [`host_backed_prefix`] decides, off the one table that names the
    // resolver's vocabulary.
    //
    // There is no carve-out for `file://`, because the resolver has
    // none: its branch is a bare `strip_prefix("file:")`, so
    // `file:///etc/sbproxy/creds` reaches
    // `read_to_string("///etc/sbproxy/creds")`, which POSIX resolves to
    // `/etc/sbproxy/creds`. Sparing the git transport spelling would
    // leave this narrower than the enforcer at the one spelling an
    // author would reach for. Nothing needs the exemption: a `source:`
    // block is read off the operator's own local document, the loader
    // never hands a fetched document's `source:` back to git, and
    // `source` is on [`crate::AUTHORITY_DENIED_PATHS`], so no externally
    // authored document names a git transport at all.
    if !is_secret_reference(trimmed) {
        return None;
    }
    host_backed_prefix(trimmed)
}

/// Validate one bounded, non-empty, control-character-free value.
fn validate_authority_value(
    field: &'static str,
    value: &str,
) -> Result<(), ConfigAuthorityConfigError> {
    if value.trim().is_empty()
        || value.len() > MAX_CONFIG_AUTHORITY_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ConfigAuthorityConfigError::Value { field });
    }
    Ok(())
}

/// Validate the authority URL: absolute, `https` unless explicitly
/// downgraded, with a host and no query or fragment.
fn validate_authority_url(
    url: &str,
    allow_insecure_http: bool,
) -> Result<(), ConfigAuthorityConfigError> {
    let invalid = |reason: &'static str| ConfigAuthorityConfigError::Url {
        url: url.to_string(),
        reason,
    };
    validate_authority_value("url", url).map_err(|_| invalid("empty or oversized"))?;
    if url.contains('?') || url.contains('#') {
        return Err(invalid(
            "must not carry a query string or fragment; the subscriber appends its own path",
        ));
    }
    let uri: http::Uri = url.parse().map_err(|_| invalid("is not a valid URL"))?;
    let scheme = uri.scheme_str().ok_or_else(|| {
        invalid("must be absolute, including the scheme, for example https://control.example.com")
    })?;
    if uri.host().is_none_or(str::is_empty) {
        return Err(invalid("must name a host"));
    }
    match scheme {
        "https" => Ok(()),
        "http" if allow_insecure_http => Ok(()),
        "http" => Err(invalid(
            "is plaintext http; set allow_insecure_http: true to accept the exposed \
             credential and configuration, or use https",
        )),
        _ => Err(invalid(
            "must use the https scheme (or http in development)",
        )),
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
fn default_governance_lease_ttl_secs() -> u64 {
    120
}
fn default_governance_terminal_retention_secs() -> u64 {
    300
}

/// Consistency guarantee for governed key admission and accounting.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceConsistency {
    /// Process-local atomic counters. Fast and safe on one gateway, but totals
    /// across multiple gateways are approximate.
    #[default]
    Approximate,
    /// Cluster-wide atomic reservations backed by Redis scripts.
    Strict,
}

/// Shared backend used for strict governed key accounting.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernanceBackendConfig {
    /// A dedicated Redis connection. This is intentionally explicit and is not
    /// inherited from the key store or cache configuration.
    Redis {
        /// Redis or TLS-enabled Redis connection URL.
        url: String,
    },
}

impl std::fmt::Debug for GovernanceBackendConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redis { .. } => formatter
                .debug_struct("Redis")
                .field("url", &"[redacted]")
                .finish(),
        }
    }
}

/// `key_management.governance:` admission, accounting, and introspection
/// controls for governed virtual keys.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct KeyGovernanceConfig {
    /// Accounting consistency. Approximate is the backward-compatible default.
    pub consistency: GovernanceConsistency,
    /// Dedicated backend for strict accounting.
    pub backend: Option<GovernanceBackendConfig>,
    /// Reservation lease duration. Expired reservations are released when a
    /// gateway exits before settling or releasing them.
    pub lease_ttl_secs: u64,
    /// Retention for settled, released, and expired reservation outcomes.
    /// Must be at least the lease duration so retries remain idempotent.
    pub terminal_retention_secs: u64,
    /// Superseded by `failure_posture`. Behavior when the governance
    /// backend cannot serve a reserve call at request time
    /// (`GovernanceError::BackendUnavailable`). The default denies the
    /// request (fail closed): governed limits must not be silently
    /// bypassed by a backend outage. Setting `allow_unreserved` admits the
    /// request instead, but every such decision is always audited on the
    /// `security_audit` channel and counted on
    /// `sbproxy_governance_fail_open_total`.
    ///
    ///
    /// Still parsed, and still the value used when `failure_posture` is
    /// absent, so an existing config keeps behaving exactly as it did.
    /// Nothing in the runtime reads this field directly any more: the read
    /// path goes through [`KeyGovernanceConfig::failure_posture`], which
    /// reports `allow_unreserved` as `degraded` because the call proceeds
    /// without the reservation this control exists to make.
    #[serde(default)]
    pub failure_mode: GovernanceFailureMode,
    /// Failure posture for a governance backend outage, in the shared
    /// [`FailureMode`] vocabulary.
    ///
    ///
    /// Set this in preference to `failure_mode`. When present it wins;
    /// when absent the legacy `failure_mode` value is converted
    /// (`closed` stays `closed`, `allow_unreserved` becomes `degraded`).
    /// It is `Option` on purpose, so "the operator said nothing" stays
    /// distinguishable from "the operator explicitly asked for the
    /// default".
    ///
    ///
    /// `closed` denies with 503. `degraded` admits without a reservation
    /// and records that fact on the `security_audit` channel and on
    /// `sbproxy_governance_fail_open_total`. `open` also admits but
    /// records neither, which is why `degraded` is the honest spelling of
    /// the old `allow_unreserved`. `observe` is meaningless here and is
    /// rejected at config-compile time: a reserve call that could not
    /// reach its backend produced no counterfactual verdict to record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_posture: Option<FailureMode>,
    /// Behavior when a governed key carries a `total_micro_usd` limit but
    /// the resolved model has no rate to estimate a pre-request cost
    /// ceiling from. The default (`zero_cost`) admits with no monetary
    /// pre-gate; `require_rate` denies instead, since a limit that cannot
    /// be pre-gated must not be silently treated as unlimited.
    #[serde(default)]
    pub missing_rate: GovernanceMissingRatePolicy,
    /// Reserved caller-introspection switch. The OSS runtime does not install
    /// `GET /api/v1/key`; retained for config compatibility.
    pub key_introspection: bool,
    /// Require AI requests to resolve to a governed key instead of accepting
    /// origin credentials or anonymous access.
    pub require_governed_key: bool,
}

impl Default for KeyGovernanceConfig {
    fn default() -> Self {
        Self {
            consistency: GovernanceConsistency::Approximate,
            backend: None,
            lease_ttl_secs: default_governance_lease_ttl_secs(),
            terminal_retention_secs: default_governance_terminal_retention_secs(),
            failure_mode: GovernanceFailureMode::default(),
            failure_posture: None,
            missing_rate: GovernanceMissingRatePolicy::default(),
            key_introspection: false,
            require_governed_key: false,
        }
    }
}

/// What a control does when it cannot reach a decision.
///
/// A "control" here is anything that gates a request and can itself
/// fail: a policy whose backend is unreachable, a guardrail whose
/// provider times out, a detector that never engaged, a store that
/// cannot be read. The question is always the same, so the knob is too,
/// and it is spelled `failure_posture` everywhere it appears:
///
/// ```yaml
/// failure_posture: closed     # refuse the request
/// failure_posture: open       # admit it
/// failure_posture: degraded   # admit it, but record that the guarantee was not made
/// failure_posture: observe    # admit it, and record what would have happened
/// ```
///
/// # The four postures
///
/// Only [`Closed`](Self::Closed) refuses. The other three all admit the
/// request and differ in what they leave behind, which is the part that
/// matters six months later when someone asks whether a control was
/// actually protecting anything:
///
/// - **`open`** admits and claims nothing. Cheapest, and the least
///   recoverable after the fact.
/// - **`degraded`** admits while explicitly marking the guarantee as
///   not made. This is the posture behind the existing
///   `AllowUnreserved` modes: the request proceeds, but no quota was
///   reserved and no governance decision was recorded, and that fact is
///   itself counted so it can be alerted on.
/// - **`observe`** admits and records the decision the control *would*
///   have taken. For rolling a control out against live traffic before
///   letting it refuse anything.
///
/// # Relationship to `test_mode` and tag actions
///
/// `observe` is deliberately close in spirit to the WAF's `test_mode`
/// and the prompt-injection `Tag` action, and the overlap is worth
/// naming so the two do not drift into meaning different things. They
/// are not the same axis:
///
/// - `test_mode` / `Tag` describe what the control does when it
///   **works** and finds a hit.
/// - `failure_posture: observe` describes what it does when it **cannot
///   run at all**.
///
/// A control can legitimately be in `test_mode` and still need a
/// failure posture, because "the detector matched" and "the detector
/// was unreachable" are different events. Where a site already has
/// `test_mode`, leave it alone and let `failure_posture` govern only the
/// cannot-decide path.
///
/// # Why this type exists
///
/// The same decision was previously spelled six different ways across
/// the config surface: `fail_open: bool`, `fail_closed: bool`,
/// `failure_mode_allow: bool`, two separately-declared `failure_mode`
/// enums, an `on_failure` enum, and an unvalidated `on_error: String`.
/// Two of those booleans carry **opposite** polarity, so `true` means
/// "admit" in one struct and "refuse" in another. An operator had to
/// re-derive the meaning at every site, and a reviewer had to check the
/// field name before they could read a diff.
///
/// New and migrated controls take `failure_posture: FailureMode`. The
/// name is deliberately not `failure_mode`: two blocks already declare a
/// field by that exact name carrying a narrower enum, and a test pins
/// that `failure_mode: open` must fail to parse there. One new word that
/// works at every site beats one that collides at two.
///
/// The legacy fields still parse, because [`schema-v1` compatibility] is
/// pinned by test, and each site's `failure_posture()` accessor converts
/// from them when the new key is absent. They carry no `#[deprecated]`
/// attribute on purpose: `-D warnings` would then turn every remaining
/// read into a build failure, including the conversion itself. They are
/// deprecated in prose and by having no other reader left.
///
/// # Choosing a default
///
/// Default closed for anything that enforces a security boundary: a
/// control that silently admits traffic when it breaks is worse than no
/// control, because the config still advertises protection and the
/// dashboard still reads green.
///
/// Default open only where refusing would take the gateway down over a
/// non-security concern, and say so at the site. A policy-expression
/// bug should not black-hole every request; an unreachable authorization
/// backend should.
///
/// [`schema-v1` compatibility]: https://github.com/soapbucket/sbproxy
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    /// Refuse the request. The safe default for anything enforcing a
    /// security boundary: a control that silently admits traffic when
    /// it breaks is worse than no control, because the config still
    /// advertises protection and the dashboard still reads green.
    #[default]
    Closed,
    /// Admit the request and claim nothing. Cheapest, and the least
    /// recoverable after the fact.
    Open,
    /// Admit the request while explicitly marking the guarantee as not
    /// made. The posture behind the legacy `AllowUnreserved` modes: the
    /// call proceeds, but no quota was reserved and no governance
    /// decision was recorded, and that fact is counted so it can be
    /// alerted on.
    Degraded,
    /// Admit the request and record the decision the control would have
    /// taken. For rolling a control out against live traffic before
    /// letting it refuse anything.
    Observe,
}

impl FailureMode {
    /// True when this posture lets the request proceed.
    ///
    /// Three of the four postures admit; they differ in what they leave
    /// behind, not in whether traffic flows. Callers deciding "do I
    /// return Deny" want this; callers deciding "what do I record" want
    /// to match on the variant.
    pub fn admits(self) -> bool {
        !matches!(self, Self::Closed)
    }

    /// True when the control should record what it would have done.
    pub fn records_counterfactual(self) -> bool {
        matches!(self, Self::Observe)
    }

    /// True when the request proceeds without the guarantee this
    /// control exists to provide. Separately countable from a plain
    /// `Open` so an operator can alert on lost guarantees specifically.
    pub fn guarantee_waived(self) -> bool {
        matches!(self, Self::Degraded)
    }

    /// Build from a legacy `fail_open`-style boolean, where `true`
    /// means admit. Use at call sites migrating off such a field so the
    /// polarity conversion lives in one place rather than being
    /// re-derived per site.
    pub fn from_fail_open(fail_open: bool) -> Self {
        if fail_open {
            Self::Open
        } else {
            Self::Closed
        }
    }

    /// Build from a legacy `fail_closed`-style boolean, where `true`
    /// means refuse. The inverse polarity of [`Self::from_fail_open`],
    /// and the reason both constructors are named rather than left to a
    /// bare `if` at each site.
    pub fn from_fail_closed(fail_closed: bool) -> Self {
        if fail_closed {
            Self::Closed
        } else {
            Self::Open
        }
    }

    /// Stable label for metrics and audit events.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::Degraded => "degraded",
            Self::Observe => "observe",
        }
    }
}

/// What a control does when it *does* reach a decision and that
/// decision is "refuse".
///
/// This is the second of two axes, and keeping them apart is the point.
/// [`FailureMode`] answers "the control could not run, now what".
/// `EnforcementMode` answers "the control ran, it matched, now what".
/// Those are different events and an operator needs both: a detector
/// can reasonably be in `observe` while it is being tuned, and still
/// need to fail closed when its backend disappears.
///
/// This type replaces the ad-hoc spellings of the same idea that grew
/// per policy: the WAF's `test_mode: bool`, the prompt-injection
/// `Tag` action, and similar. They all meant "match, but do not
/// block". `observe` is spelled the same here as in [`FailureMode`] on
/// purpose, so one word means one thing across the config surface.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Refuse the request when the control matches.
    #[default]
    Block,
    /// Admit the request but record the match. The rollout posture.
    Observe,
}

impl EnforcementMode {
    /// True when a match should refuse the request.
    pub fn blocks(self) -> bool {
        matches!(self, Self::Block)
    }

    /// Build from a legacy `test_mode`-style boolean, where `true`
    /// means "log but do not block".
    pub fn from_test_mode(test_mode: bool) -> Self {
        if test_mode {
            Self::Observe
        } else {
            Self::Block
        }
    }

    /// Stable label for metrics and audit events.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Observe => "observe",
        }
    }
}

/// Superseded by [`FailureMode`]. Behavior when the governance backend
/// cannot serve a reserve call
/// (`sbproxy_ai::governance::GovernanceStore::reserve`).
///
/// Applies only to a reserve call that fails with
/// `GovernanceError::BackendUnavailable`. Every other reserve error
/// (invalid request shape, a reservation id reused with different input,
/// a hit against a real governed limit, arithmetic overflow) is unrelated
/// to backend availability and is not affected by this setting.
///
/// Kept because `failure_mode: closed | allow_unreserved` is pinned by
/// test and by shipped configs. Read it through
/// [`KeyGovernanceConfig::failure_posture`], never directly.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceFailureMode {
    /// Deny the request (`503`) when the governance backend is
    /// unavailable.
    #[default]
    Closed,
    /// Admit the request without a governance reservation when the
    /// backend is unavailable. Always emits a `security_audit` event and
    /// increments `sbproxy_governance_fail_open_total` so the decision
    /// stays observable.
    AllowUnreserved,
}

/// Behavior when a governed key's monetary limit cannot be pre-gated
/// because the resolved model has no rate to estimate a cost ceiling
/// from.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceMissingRatePolicy {
    /// Treat the estimated cost as zero. No monetary pre-gate applies to
    /// this request; a key's `total_micro_usd` limit is still enforced at
    /// settlement, from actually billed usage.
    #[default]
    ZeroCost,
    /// Deny the request when the key carries a `total_micro_usd` limit
    /// but the resolved model has no rate: a limit that cannot be
    /// pre-gated must not be silently treated as unlimited.
    RequireRate,
}

/// Validation failure for governed key admission configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid key governance configuration: {message}")]
pub struct KeyGovernanceConfigError {
    message: String,
}

impl KeyGovernanceConfigError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl KeyGovernanceConfig {
    /// This control's posture expressed in the shared [`FailureMode`]
    /// vocabulary. The one read path for a governance backend outage.
    ///
    /// Precedence: an explicit `failure_posture` wins; otherwise the
    /// legacy `failure_mode` is converted. `closed` maps to
    /// [`FailureMode::Closed`], and `allow_unreserved` maps to
    /// [`FailureMode::Degraded`] rather than a plain open, because the
    /// request proceeds without the reservation this control exists to
    /// make and that fact is separately recorded.
    ///
    /// Reading the posture only here is the point of the whole exercise:
    /// a config key that nothing reads reproduces the defect this key
    /// exists to fix, so `failure_mode` has no other consumer left.
    pub fn failure_posture(&self) -> FailureMode {
        if let Some(explicit) = self.failure_posture {
            return explicit;
        }
        match self.failure_mode {
            GovernanceFailureMode::Closed => FailureMode::Closed,
            GovernanceFailureMode::AllowUnreserved => FailureMode::Degraded,
        }
    }

    /// Reject a posture that has no meaning for a governance reserve call.
    ///
    /// [`FailureMode::Observe`] records the decision a control *would*
    /// have taken. A reserve call that never reached its backend produced
    /// no such decision, so accepting `observe` here would mean silently
    /// picking some other behavior on the operator's behalf. Refusing at
    /// config-compile time is the honest alternative.
    ///
    /// # Errors
    ///
    /// Returns the operator-facing message, naming the exact config path,
    /// when the posture cannot be honored at this site.
    pub fn validate_failure_posture(&self) -> Result<(), String> {
        if self.failure_posture == Some(FailureMode::Observe) {
            return Err(
                "key_management.governance.failure_posture: `observe` is meaningless for a \
                 governance backend outage, because a reserve call that never reached its \
                 backend has no counterfactual verdict to record. Use `closed`, `degraded`, \
                 or `open`."
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Reservation lease duration converted to runtime milliseconds.
    pub fn lease_ttl_millis(&self) -> Result<u64, KeyGovernanceConfigError> {
        self.lease_ttl_secs.checked_mul(1_000).ok_or_else(|| {
            KeyGovernanceConfigError::invalid("lease_ttl_secs overflows milliseconds")
        })
    }

    /// Terminal outcome retention converted to runtime milliseconds.
    pub fn terminal_retention_millis(&self) -> Result<u64, KeyGovernanceConfigError> {
        self.terminal_retention_secs
            .checked_mul(1_000)
            .ok_or_else(|| {
                KeyGovernanceConfigError::invalid("terminal_retention_secs overflows milliseconds")
            })
    }

    /// Validate governance invariants before pipeline construction or reload.
    pub fn validate(&self) -> Result<(), KeyGovernanceConfigError> {
        self.validate_failure_posture()
            .map_err(KeyGovernanceConfigError::invalid)?;
        if self.lease_ttl_secs == 0 {
            return Err(KeyGovernanceConfigError::invalid(
                "lease_ttl_secs must be positive",
            ));
        }
        if self.terminal_retention_secs == 0 {
            return Err(KeyGovernanceConfigError::invalid(
                "terminal_retention_secs must be positive",
            ));
        }
        if self.terminal_retention_secs < self.lease_ttl_secs {
            return Err(KeyGovernanceConfigError::invalid(
                "terminal_retention_secs must be at least lease_ttl_secs",
            ));
        }
        self.lease_ttl_millis()?;
        self.terminal_retention_millis()?;

        match (self.consistency, &self.backend) {
            (GovernanceConsistency::Approximate, Some(_)) => {
                return Err(KeyGovernanceConfigError::invalid(
                    "redis governance backend requires strict consistency",
                ));
            }
            (GovernanceConsistency::Strict, None) => {
                return Err(KeyGovernanceConfigError::invalid(
                    "strict governance requires an explicit redis backend",
                ));
            }
            (GovernanceConsistency::Approximate, None)
            | (GovernanceConsistency::Strict, Some(_)) => {}
        }

        if let Some(GovernanceBackendConfig::Redis { url }) = &self.backend {
            if !url.starts_with("redis://") && !url.starts_with("rediss://") {
                return Err(KeyGovernanceConfigError::invalid(
                    "redis backend URL must start with redis:// or rediss://",
                ));
            }
            let authority = url
                .split_once("://")
                .map(|(_, authority)| authority)
                .unwrap_or_default()
                .split('/')
                .next()
                .unwrap_or_default();
            let host = authority
                .rsplit_once('@')
                .map_or(authority, |(_, host)| host);
            if host.is_empty() || host.starts_with(':') {
                return Err(KeyGovernanceConfigError::invalid(
                    "redis backend URL must include a host",
                ));
            }
        }

        Ok(())
    }
}

/// One entry in `key_management.inbound.headers:`.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboundHeaderConfig {
    /// Header name, matched case-insensitively.
    pub name: String,
    /// Prefix stripped from the value before the token shape is tested,
    /// matched case-insensitively. Empty for raw-value headers such as
    /// `x-api-key`.
    #[serde(default)]
    pub scheme: String,
}

/// One rule mapping an inbound credential's shape to a provider label, for
/// attribution of native (non-minted) keys.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderHintConfig {
    /// Provider label stamped on the request when this rule matches
    /// (canonical AI-provider spelling: `anthropic`, `openai`, ...).
    pub provider: String,
    /// Header the credential arrives in, matched case-insensitively.
    pub header: String,
    /// Scheme prefix stripped before the value test, matched
    /// case-insensitively. Empty for raw-value headers.
    #[serde(default)]
    pub scheme: String,
    /// Prefix the credential value must start with (`sk-ant-`). Empty
    /// matches any non-empty value.
    #[serde(default)]
    pub value_prefix: String,
    /// A second header that must also be present for this rule to match
    /// (`anthropic-version`). `None` requires nothing extra.
    #[serde(default)]
    pub also_header: Option<String>,
}

/// Default admission policy for caller-owned native provider keys.
///
/// Native keys cannot carry an SBproxy policy record because the caller, not
/// the operator, owns their secret. This block supplies the equivalent default
/// policy for every native key recognized by `provider_hints`. Leaving it
/// absent fails closed for recognized native-key traffic.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeKeyPolicyConfig {
    /// Canonical provider labels admitted to use caller-owned credentials.
    ///
    /// Matching is case-insensitive and ignores surrounding whitespace. The
    /// list must be non-empty and may not contain duplicates.
    pub allowed_providers: Vec<String>,
    /// Max requests per minute for each origin/provider native-key bucket.
    #[serde(default)]
    pub max_requests_per_minute: Option<u64>,
    /// Max input and output tokens per minute.
    #[serde(default)]
    pub max_tokens_per_minute: Option<u64>,
    /// Max total tokens for the native-key budget window.
    #[serde(default)]
    pub max_budget_tokens: Option<u64>,
    /// Max total cost in USD for the native-key budget window.
    #[serde(default)]
    pub max_budget_usd: Option<f64>,
    /// Models native-key traffic may use (empty = all).
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// Models native-key traffic may not use.
    #[serde(default)]
    pub blocked_models: Vec<String>,
    /// Named PII redaction rules that must be active before dispatch.
    #[serde(default)]
    pub require_pii_redaction: Vec<String>,
}

impl NativeKeyPolicyConfig {
    /// Whether this policy admits the canonical provider label.
    pub fn allows(&self, provider: &str) -> bool {
        self.allowed_providers
            .iter()
            .any(|allowed| allowed.trim().eq_ignore_ascii_case(provider.trim()))
    }
}

/// `key_management.inbound:` block. Controls which request headers are swept
/// for a minted key, and whether a route refuses requests that carry none.
///
/// The header a key arrives in is a property of the calling tool, not of the
/// key: to know which header holds the key you would have to have resolved it
/// already. So extraction is configured per route here rather than per key.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyInboundConfig {
    /// Ordered candidate headers. One well-shaped minted token resolves; two
    /// distinct tokens are ambiguous and fail closed. An empty list disables
    /// the sweep and leaves the legacy `authorization` path as the only front
    /// door.
    #[serde(default = "default_inbound_headers")]
    pub headers: Vec<InboundHeaderConfig>,
    /// Deny with 401 when no minted key resolved. Off by default, so an
    /// upgrade changes nothing. Set per origin to make the proxy the only door
    /// on a route that has no other auth provider.
    #[serde(default)]
    pub require: bool,
    /// Ordered rules attributing a native (non-minted) inbound credential to
    /// a provider. First matching hint wins, so more specific value prefixes
    /// belong before general ones. A matching hint then enters native-key
    /// policy admission; a credential matching no hint remains unattributed.
    #[serde(default = "default_provider_hints")]
    pub provider_hints: Vec<ProviderHintConfig>,
    /// Explicit default policy for recognized caller-owned native provider
    /// keys. Absent by default, which fails closed if a provider hint matches.
    #[serde(default)]
    pub native_key_policy: Option<NativeKeyPolicyConfig>,
}

impl Default for KeyInboundConfig {
    fn default() -> Self {
        Self {
            headers: default_inbound_headers(),
            require: false,
            provider_hints: default_provider_hints(),
            native_key_policy: None,
        }
    }
}

/// Built-in attribution rules for the common provider key shapes.
///
/// Ordered most-specific first: `sk-ant-` and `sk-or-` must precede the bare
/// `sk-` rule or every Anthropic and OpenRouter key would attribute to OpenAI.
fn default_provider_hints() -> Vec<ProviderHintConfig> {
    fn hint(
        provider: &str,
        header: &str,
        scheme: &str,
        value_prefix: &str,
        also_header: Option<&str>,
    ) -> ProviderHintConfig {
        ProviderHintConfig {
            provider: provider.to_string(),
            header: header.to_string(),
            scheme: scheme.to_string(),
            value_prefix: value_prefix.to_string(),
            also_header: also_header.map(str::to_string),
        }
    }
    vec![
        hint("anthropic", "x-api-key", "", "sk-ant-", None),
        hint("anthropic", "authorization", "Bearer ", "sk-ant-", None),
        // A non-Anthropic-shaped x-api-key still attributes to Anthropic when
        // the SDK's version header rides along.
        hint("anthropic", "x-api-key", "", "", Some("anthropic-version")),
        hint("openrouter", "authorization", "Bearer ", "sk-or-", None),
        hint("gemini", "x-goog-api-key", "", "", None),
        hint("azure", "api-key", "", "", None),
        // Last: the loose OpenAI shape, which would otherwise swallow the
        // more specific prefixes above.
        hint("openai", "authorization", "Bearer ", "sk-", None),
    ]
}

/// Header names that may never be swept: standard hop-by-hop and framing
/// headers, the widely used de-facto `proxy-connection` hop-by-hop header, plus
/// `cookie`, which has its own redaction and capture rules.
pub const FORBIDDEN_SWEEP_HEADERS: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "content-length",
    "transfer-encoding",
    "cookie",
];

/// Whether a header is unavailable as an inbound or outbound credential
/// carrier.
///
/// In addition to headers that cannot be swept safely, credentials may not
/// claim realtime handshake metadata, distributed tracing state, outbound
/// Web Bot Auth signature fields, or headers promoted into governance, logs,
/// and capture envelopes. Those values have independent protocol meaning or
/// leave the raw request-header surface before generic secret redaction can
/// protect them.
pub fn credential_header_is_reserved(header: &str) -> bool {
    let lower = header.trim().to_ascii_lowercase();
    FORBIDDEN_SWEEP_HEADERS.contains(&lower.as_str())
        || matches!(
            lower.as_str(),
            "upgrade"
                | "openai-beta"
                | "proxy-authorization"
                | "proxy-authenticate"
                | "traceparent"
                | "tracestate"
                | "signature-input"
                | "signature"
                | "signature-agent"
                | "x-user-id"
                | "x-end-user"
                | "x-sbproxy-tag"
                | "x-sb-user-id"
                | "x-sb-session-id"
                | "x-sb-parent-session-id"
                | "user-agent"
                | "referer"
                | "b3"
                | "x-b3-traceid"
                | "x-b3-spanid"
                | "x-b3-sampled"
                | "x-b3-parentspanid"
        )
        || lower.starts_with("sec-websocket-")
        || lower.starts_with("x-a2a-")
        || lower.starts_with("x-sb-property-")
}

fn default_inbound_headers() -> Vec<InboundHeaderConfig> {
    vec![
        InboundHeaderConfig {
            name: "authorization".to_string(),
            scheme: "Bearer ".to_string(),
        },
        InboundHeaderConfig {
            name: "x-api-key".to_string(),
            scheme: String::new(),
        },
        InboundHeaderConfig {
            name: "x-sb-api".to_string(),
            scheme: String::new(),
        },
    ]
}

impl KeyInboundConfig {
    /// Reject header names that are not valid HTTP field names, are hop-by-hop
    /// or framing headers, or repeat case-insensitively.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message naming the offending entry.
    pub fn validate(&self) -> Result<(), String> {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for entry in &self.headers {
            let lower = entry.name.trim().to_ascii_lowercase();
            if lower.is_empty() || http::header::HeaderName::from_bytes(lower.as_bytes()).is_err() {
                return Err(format!(
                    "key_management.inbound.headers: {:?} is not a valid HTTP header name",
                    entry.name
                ));
            }
            if credential_header_is_reserved(&lower) {
                return Err(format!(
                    "key_management.inbound.headers: {:?} may not carry a key",
                    entry.name
                ));
            }
            if !seen.insert(lower) {
                return Err(format!(
                    "key_management.inbound.headers: {:?} is listed more than once",
                    entry.name
                ));
            }
        }
        for hint in &self.provider_hints {
            if hint.provider.trim().is_empty() {
                return Err(
                    "key_management.inbound.provider_hints: provider must not be empty".to_string(),
                );
            }
            for name in std::iter::once(hint.header.as_str()).chain(hint.also_header.as_deref()) {
                let lower = name.trim().to_ascii_lowercase();
                if lower.is_empty()
                    || http::header::HeaderName::from_bytes(lower.as_bytes()).is_err()
                {
                    return Err(format!(
                        "key_management.inbound.provider_hints: {name:?} is not a valid HTTP header name"
                    ));
                }
            }
            if credential_header_is_reserved(&hint.header) {
                return Err(format!(
                    "key_management.inbound.provider_hints: {:?} may not carry a key",
                    hint.header
                ));
            }
        }
        if let Some(policy) = &self.native_key_policy {
            if policy.allowed_providers.is_empty() {
                return Err(
                    "key_management.inbound.native_key_policy.allowed_providers must not be empty"
                        .to_string(),
                );
            }
            let mut providers = std::collections::HashSet::new();
            for provider in &policy.allowed_providers {
                let canonical = provider.trim().to_ascii_lowercase();
                if canonical.is_empty() {
                    return Err(
                        "key_management.inbound.native_key_policy.allowed_providers entries must not be empty"
                            .to_string(),
                    );
                }
                if !providers.insert(canonical) {
                    return Err(format!(
                        "key_management.inbound.native_key_policy.allowed_providers: {provider:?} is listed more than once"
                    ));
                }
            }
            for (name, value) in [
                ("max_requests_per_minute", policy.max_requests_per_minute),
                ("max_tokens_per_minute", policy.max_tokens_per_minute),
            ] {
                if value == Some(0) {
                    return Err(format!(
                        "key_management.inbound.native_key_policy.{name} must be greater than zero"
                    ));
                }
            }
            if policy
                .max_budget_usd
                .is_some_and(|value| !value.is_finite() || value < 0.0)
            {
                return Err(
                    "key_management.inbound.native_key_policy.max_budget_usd must be finite and non-negative"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    /// Lowercased names of every swept header, for the redaction and capture
    /// denylists so a custom header does not have to be added to them by hand.
    pub fn header_names(&self) -> Vec<String> {
        self.headers
            .iter()
            .map(|entry| entry.name.trim().to_ascii_lowercase())
            .collect()
    }

    /// Lowercased union of every primary header that may carry an inbound
    /// credential.
    ///
    /// This includes minted/configured carriers and provider-hint carriers.
    /// `provider_hints[].also_header` is deliberately excluded: it is only
    /// match metadata and never contains the credential value.
    pub fn credential_carrier_names(&self) -> Vec<String> {
        let mut names = Vec::with_capacity(self.headers.len() + self.provider_hints.len());
        for name in self
            .headers
            .iter()
            .map(|entry| entry.name.as_str())
            .chain(self.provider_hints.iter().map(|hint| hint.header.as_str()))
        {
            let canonical = name.trim().to_ascii_lowercase();
            if !canonical.is_empty() && !names.contains(&canonical) {
                names.push(canonical);
            }
        }
        names
    }

    /// Whether `header_name` is a primary inbound credential carrier.
    ///
    /// Match-only `provider_hints[].also_header` metadata is deliberately
    /// excluded because it never contains the credential value.
    pub fn is_credential_carrier(&self, header_name: &str) -> bool {
        let canonical = header_name.trim();
        self.headers
            .iter()
            .any(|entry| entry.name.trim().eq_ignore_ascii_case(canonical))
            || self
                .provider_hints
                .iter()
                .any(|hint| hint.header.trim().eq_ignore_ascii_case(canonical))
    }
}

/// Top-level `key_management:` block: the runtime key plane (mutable store,
/// policy cache, governance, at-rest crypto, OIDC claim map, declarative seed).
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// Governed key admission, accounting, and authenticated introspection.
    #[serde(default)]
    pub governance: KeyGovernanceConfig,
    /// At-rest crypto material.
    #[serde(default)]
    pub crypto: KeyCryptoConfig,
    /// Which inbound headers carry a minted key, and whether one is required.
    #[serde(default)]
    pub inbound: KeyInboundConfig,
    /// Allow the admin API to override config-seeded records on reload. When
    /// false (default), config-seeded records are authoritative and re-asserted
    /// on every reload.
    #[serde(default)]
    pub allow_api_override: bool,
    /// Superseded by `failure_posture`. When the store is unreachable,
    /// allow the request through in a degraded mode. Default false: fail
    /// closed (deny).
    ///
    ///
    /// Note the polarity this field is named into: `true` here means
    /// ALLOW, that is, fail open. Other booleans in this config carry
    /// the opposite sense, which is the inconsistency [`FailureMode`]
    /// exists to retire.
    ///
    ///
    /// Still parsed, and still the value used when `failure_posture` is
    /// absent, so an existing config keeps behaving exactly as it did.
    /// Nothing in the runtime reads this field directly any more: every
    /// store-outage decision goes through
    /// [`KeyManagementConfig::failure_posture`].
    #[serde(default)]
    pub failure_mode_allow: bool,
    /// Failure posture for a key-store outage, in the shared
    /// [`FailureMode`] vocabulary.
    ///
    ///
    /// Set this in preference to `failure_mode_allow`. When present it
    /// wins; when absent the legacy boolean is converted (`false` becomes
    /// `closed`, `true` becomes `degraded`). It is `Option` on purpose,
    /// so "the operator said nothing" stays distinguishable from "the
    /// operator explicitly asked for the default".
    ///
    ///
    /// `closed` refuses with 503. `degraded` and `open` both let the
    /// request fall through to the origin's own configured auth, which is
    /// what `failure_mode_allow: true` has always done: it is not a
    /// blanket admit. `degraded` is the honest label for it, because the
    /// request proceeds with no per-key policy, no budget, and no
    /// attribution, and that fact is recorded rather than passed over in
    /// silence. `observe` is meaningless here and is rejected at
    /// config-compile time: an unreachable store produced no
    /// counterfactual verdict to record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_posture: Option<FailureMode>,
    /// Optional OIDC/JWT claim to virtual-key mapping.
    #[serde(default)]
    pub oidc_claim_map: Option<OidcClaimMapConfig>,
    /// Optional declarative seed of keys and credentials.
    #[serde(default)]
    pub seed: KeySeedConfig,
    /// Read and access audit for key and credential resolution (WOR-2570).
    #[serde(default)]
    pub read_audit: KeyReadAuditConfig,
    /// Break-glass emergency access to the key and credential admin API
    /// (WOR-2573).
    #[serde(default)]
    pub break_glass: BreakGlassConfig,
}

impl KeyManagementConfig {
    /// What the key plane does when the store cannot be reached, in the
    /// shared [`FailureMode`] vocabulary. The one read path for a
    /// key-store outage.
    ///
    /// Precedence: an explicit `failure_posture` wins; otherwise the
    /// legacy `failure_mode_allow` boolean is converted. `false` maps to
    /// [`FailureMode::Closed`], which is a 503. `true` maps to
    /// [`FailureMode::Degraded`] rather than [`FailureMode::Open`]: the
    /// request does proceed, but only by falling through to the origin's
    /// own configured auth, with no per-key policy, no budget, and no
    /// attribution. That is a guarantee waived, not a guarantee that was
    /// never claimed, and it is worth being able to alert on separately.
    ///
    /// Both admitting postures behave identically at the four call sites
    /// that read this. They differ in what they leave behind, which is
    /// the whole distinction [`FailureMode`] exists to draw.
    pub fn failure_posture(&self) -> FailureMode {
        if let Some(explicit) = self.failure_posture {
            return explicit;
        }
        if self.failure_mode_allow {
            FailureMode::Degraded
        } else {
            FailureMode::Closed
        }
    }

    /// Reject a posture that has no meaning for a key-store outage, at
    /// this block or at the nested `governance:` block.
    ///
    /// [`FailureMode::Observe`] records the decision a control *would*
    /// have taken. A store that could not be read produced no such
    /// decision, so accepting `observe` would mean silently picking some
    /// other behavior on the operator's behalf.
    ///
    /// # Errors
    ///
    /// Returns the operator-facing message, naming the exact config path,
    /// when the posture cannot be honored at the site that declares it.
    pub fn validate_failure_posture(&self) -> Result<(), String> {
        if self.failure_posture == Some(FailureMode::Observe) {
            return Err(
                "key_management.failure_posture: `observe` is meaningless for a key-store \
                 outage, because a store that could not be read has no counterfactual verdict \
                 to record. Use `closed`, `degraded`, or `open`."
                    .to_string(),
            );
        }
        self.governance.validate_failure_posture()
    }
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
    /// Cluster mesh replicated store (WOR-2064): records live on the
    /// durable replicated state substrate configured by
    /// `proxy.cluster.replication`, so a key minted on one node resolves
    /// on its peers with no external store. Requires `proxy.cluster` with
    /// a `replication` block. Consistency is pinned by the backend
    /// (quorum writes, quorum reads, revocation written at one) and is
    /// not operator-configurable; the replication factor comes from the
    /// cluster's replication block.
    Mesh,
}

/// `key_management.store:` block.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// Legacy compatibility switch. Selecting `backend: redis` already makes
    /// Redis the key store; this value does not change runtime behavior.
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// How `shared_key` becomes the AES-256-GCM wire key.
    ///
    /// Defaults to `sha256`, which is what every cluster runs today, so
    /// an upgrade never changes the key a node seals under. `hkdf` moves
    /// the mesh onto the same purpose-separated derivation every other
    /// key in this workspace uses.
    ///
    /// Nodes open under both derivations regardless of this setting, so
    /// a cluster can be flipped one node at a time without partitioning.
    /// See `docs/mesh-replication.md`.
    #[serde(default)]
    pub key_derivation: MeshKeyDerivation,
    /// Optional peer mTLS (mutually-authenticated TLS) for the mesh transport.
    /// When set, inbound connections must present a CA-signed client
    /// certificate and outbound connections present this node's certificate,
    /// all verified against the configured CA. Plaintext when unset.
    #[serde(default)]
    pub peer_tls: Option<MeshPeerTlsConfig>,
}

/// How the mesh derives its AES-256-GCM wire key from the shared secret.
///
/// Both derivations are always accepted on the receive side, so this only
/// selects what a node seals under and a cluster can be migrated one node
/// at a time.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MeshKeyDerivation {
    /// `SHA-256(secret)`. The original scheme and the default, so an
    /// upgrade never changes an existing cluster's key.
    #[default]
    Sha256,
    /// HKDF-SHA256 under a mesh-specific purpose, matching how every
    /// other key in this workspace is derived.
    Hkdf,
}

/// `key_management.cache.mesh.peer_tls:` mutual-TLS material (file paths) for
/// the mesh peer transport.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
            key_derivation: MeshKeyDerivation::default(),
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

/// `key_management.crypto.root_of_trust:` block (WOR-2568). Present means
/// the customer holds the root of trust for the upstream-credential
/// envelope; absent means sbproxy's own `master_key` does.
///
/// One field answers "is our root of trust customer-held right now", which
/// is deliberate: before this block existed the only way to answer it was
/// to audit which reference `master_key` happened to carry, and every
/// answer that audit could give was "no", because a resolved reference is
/// a copy.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootOfTrustConfig {
    /// Which external key service performs the wrap and unwrap.
    pub provider: RootOfTrustProvider,
    /// Base address of the key service, for example
    /// `https://vault.internal:8200`.
    pub address: String,
    /// Transit mount path. Defaults to `transit`, matching Vault's own
    /// default mount.
    #[serde(default = "default_transit_mount")]
    pub mount: String,
    /// Name of the Transit key that wraps sbproxy's data keys. Created and
    /// owned by the customer; sbproxy never creates it.
    pub key_name: String,
    /// Secret reference for the token sbproxy authenticates with
    /// (`env:`, `file:`, `vault://`, ...). Resolved once at boot. Losing
    /// this token is a second, independent way for the customer to cut
    /// sbproxy off.
    pub token: String,
    /// Optional Vault Enterprise namespace header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// How long an unwrapped data key may be reused before the external
    /// service is consulted again.
    ///
    /// This number *is* the deployment's revocation-latency bound and is
    /// reported verbatim on `GET /admin/crypto/root-of-trust`. Larger
    /// trades a longer window in which a revoked grant still works for
    /// fewer calls to the key service. The resolved-credential cache is
    /// clamped to this value for customer-managed envelopes, so raising
    /// `proxy.secrets.rotation.re_resolve_interval_secs` cannot quietly
    /// extend it.
    #[serde(default = "default_unwrap_cache_ttl_secs")]
    pub unwrap_cache_ttl_secs: u64,
    /// How often to probe the key service for reachability and continued
    /// authorization, in seconds. Feeds the admin surface's
    /// last-successful-check timestamp and the liveness metric. Zero
    /// disables the background probe; the on-demand path still fails
    /// closed.
    #[serde(default = "default_root_liveness_interval_secs")]
    pub liveness_interval_secs: u64,
}

/// Redacting `Debug` (the rule `HashiCorpBackendAuth` and
/// `HashiCorpSecretsConfig` already carry in this file). `token` is a secret
/// reference and `resolve_crypto_field` deliberately exempts inline
/// literals, so an operator may legitimately write the token itself here;
/// `address` is unparsed and may carry userinfo. `finish_non_exhaustive`
/// so a later credential-shaped field is omitted by default.
impl std::fmt::Debug for RootOfTrustConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootOfTrustConfig")
            .field("provider", &self.provider)
            .field("mount", &self.mount)
            .field("key_name", &self.key_name)
            .field("address", &"[REDACTED]")
            .field("token", &"[REDACTED]")
            .field("unwrap_cache_ttl_secs", &self.unwrap_cache_ttl_secs)
            .field("liveness_interval_secs", &self.liveness_interval_secs)
            .finish_non_exhaustive()
    }
}

/// External key services that can hold the root of trust.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum RootOfTrustProvider {
    /// HashiCorp Vault's Transit secrets engine (encryption as a service).
    /// The caller never receives the key, only ciphertext or plaintext.
    #[default]
    VaultTransit,
}

fn default_transit_mount() -> String {
    "transit".to_string()
}

fn default_unwrap_cache_ttl_secs() -> u64 {
    60
}

fn default_root_liveness_interval_secs() -> u64 {
    30
}

/// `key_management.crypto.rotation:` block (WOR-2567): the named crypto
/// period for each class of key material, and the grace window a rotated
/// upstream credential keeps its previous material usable for.
///
/// NIST SP 800-57 Part 1 Rev 5 frames a key's life as generation,
/// activation, active use, rotation, destruction, and expects a deployment
/// to *state* its crypto period rather than leave "rotate periodically" as
/// the whole policy. These defaults are that statement; the runtime reads
/// them to compute rotation age and to warn when a record is past due.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyRotationCadenceConfig {
    /// Crypto period for inbound virtual keys, in days. Default 90.
    #[serde(default = "default_inbound_key_period_days")]
    pub inbound_key_days: u32,
    /// Crypto period for upstream provider credentials, in days.
    /// Default 90: a provider API key is a bearer credential with no
    /// binding to the caller, so it sits at the short end of NIST's range
    /// rather than the one to two years a TLS key gets.
    #[serde(default = "default_credential_period_days")]
    pub credential_days: u32,
    /// Crypto period for the envelope master key, in days. Default 365,
    /// the symmetric data-encryption-key end of NIST's range. Under a
    /// customer-managed root this is the customer's Transit key rotation
    /// cadence, not sbproxy's.
    #[serde(default = "default_master_period_days")]
    pub master_key_days: u32,
    /// How long a rotated upstream credential keeps serving its previous
    /// material when the new material cannot be resolved, in seconds.
    /// Default 300. Mirrors the dual-validity window `rotate_key` already
    /// gives inbound keys; zero disables the overlap.
    #[serde(default = "default_credential_rotation_grace_secs")]
    pub credential_grace_secs: u64,
}

impl Default for KeyRotationCadenceConfig {
    fn default() -> Self {
        Self {
            inbound_key_days: default_inbound_key_period_days(),
            credential_days: default_credential_period_days(),
            master_key_days: default_master_period_days(),
            credential_grace_secs: default_credential_rotation_grace_secs(),
        }
    }
}

fn default_inbound_key_period_days() -> u32 {
    90
}

fn default_credential_period_days() -> u32 {
    90
}

fn default_master_period_days() -> u32 {
    365
}

fn default_credential_rotation_grace_secs() -> u64 {
    300
}

/// `key_management.read_audit:` block (WOR-2570): the read half of the key
/// audit trail.
///
/// `audit.key_path` records who *changed* a key or credential. This records
/// who *resolved* one for use, which is the question a breach investigation
/// actually asks and a different question from the first.
///
/// Cost-bounded on purpose, following the shape Vault's audit devices take
/// for volume versus detail: the counter moves on every resolution, and the
/// chained detail record fires at most once per credential per window.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyReadAuditConfig {
    /// Emit chained detail records for credential resolutions. The volume
    /// counter is unconditional and is not gated by this.
    #[serde(default)]
    pub enabled: bool,
    /// Minimum seconds between detail records for the same credential.
    /// Default 300. The first resolution in each window emits; the rest
    /// are counted and not recorded, so cost scales with credential count
    /// rather than with request rate.
    #[serde(default = "default_read_audit_window_secs")]
    pub detail_window_secs: u64,
    /// HMAC the credential id in the detail record, so a chain handed to
    /// an auditor does not enumerate which credentials exist while still
    /// letting an investigator confirm a specific id with
    /// `sbproxy audit hash`. Default true, matching Vault's audit-device
    /// posture of hashing sensitive string fields and passing timestamps,
    /// outcomes, and other non-identifying fields through in the clear.
    #[serde(default = "default_true")]
    pub hash_identifiers: bool,
}

impl Default for KeyReadAuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            detail_window_secs: default_read_audit_window_secs(),
            hash_identifiers: true,
        }
    }
}

fn default_read_audit_window_secs() -> u64 {
    300
}

/// `key_management.break_glass:` block (WOR-2573): the pre-staged,
/// time-boxed, quorum-approved emergency path into the key and credential
/// admin API.
///
/// Every vault product surveyed converges on the same shape, and the shape
/// is the point: a break-glass grant should be expensive to use quietly and
/// cheap to review afterwards.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassConfig {
    /// Turn the break-glass endpoints on. Off by default: an emergency
    /// path nobody configured is an emergency path nobody reviews.
    #[serde(default)]
    pub enabled: bool,
    /// Operators who may approve a grant, by admin username. A requester
    /// is never counted among their own approvers even when listed here.
    #[serde(default)]
    pub approvers: Vec<String>,
    /// How many distinct approvers a grant needs before it activates.
    /// Default 2. Must be at least 1 and no greater than the number of
    /// configured approvers, or config compile refuses the block.
    #[serde(default = "default_break_glass_quorum")]
    pub quorum: usize,
    /// Hard cap on a grant's requested TTL, in seconds. Default 3600.
    /// A request naming more is refused rather than silently clamped, so
    /// the requester finds out at request time instead of at expiry.
    #[serde(default = "default_break_glass_max_ttl_secs")]
    pub max_ttl_secs: u64,
    /// How long after expiry a grant with no reviewer sign-off stays on
    /// the review queue, in seconds. Default 86400, the 24-hour
    /// post-access review window the surveyed products converge on.
    /// Grants past this are still listed and still flagged; the number
    /// drives the overdue marker, not deletion.
    #[serde(default = "default_break_glass_review_window_secs")]
    pub review_window_secs: u64,
}

impl Default for BreakGlassConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            approvers: Vec::new(),
            quorum: default_break_glass_quorum(),
            max_ttl_secs: default_break_glass_max_ttl_secs(),
            review_window_secs: default_break_glass_review_window_secs(),
        }
    }
}

fn default_break_glass_quorum() -> usize {
    2
}

fn default_break_glass_max_ttl_secs() -> u64 {
    3600
}

fn default_break_glass_review_window_secs() -> u64 {
    86_400
}

/// `key_management.crypto:` block. Both values accept a secret reference
/// (`vault://`, `env:`, `file:`, ...) resolved at boot, or an inline value
/// (discouraged outside tests).
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// Let the process mint an ephemeral `pepper` or `master_key` when the
    /// operator pinned neither (WOR-2567).
    ///
    /// Default false, and the default is the change: a restart with no
    /// pinned pepper silently invalidates every stored key hash, and the
    /// failure surfaces as a flood of 401s rather than as a boot refusal.
    /// Vault and comparable products refuse to start without a resolvable
    /// root key rather than minting one, and that is now the behavior here.
    /// Set true for a single-process local development run, where a key
    /// plane whose hashes do not outlive the process is exactly what is
    /// wanted.
    #[serde(default)]
    pub allow_ephemeral_secrets: bool,
    /// Customer-managed root of trust for the upstream-credential envelope
    /// (WOR-2568). Absent means sbproxy's own `master_key` is the root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_of_trust: Option<RootOfTrustConfig>,
    /// Named crypto periods and the credential rotation grace window
    /// (WOR-2567).
    #[serde(default)]
    pub rotation: KeyRotationCadenceConfig,
}

/// `key_management.oidc_claim_map:` block.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OidcClaimMapConfig {
    /// The verified JWT/OIDC claim whose value names the virtual-key record to
    /// resolve, so the bearer-token and OIDC front doors converge on one record.
    pub claim_field: String,
}

/// `key_management.seed:` block: declarative records applied at boot.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeySeedConfig {
    /// Inbound virtual keys.
    #[serde(default)]
    pub keys: Vec<SeedKeyConfig>,
    /// Upstream provider credentials.
    #[serde(default)]
    pub credentials: Vec<SeedCredentialConfig>,
}

/// A seeded inbound virtual key.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// Max input and output tokens per minute.
    #[serde(default)]
    pub max_tokens_per_minute: Option<u64>,
    /// Served-model admission lane (`interactive`, `standard`, or `batch`).
    #[serde(default)]
    pub priority: Option<String>,
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
    /// Providers this key may not use. Blocks override allows.
    #[serde(default)]
    pub blocked_providers: Vec<String>,
    /// Caller-supplied tool allowlist. `None` is unrestricted and an empty
    /// list denies every caller-supplied tool.
    #[serde(default)]
    pub allowed_tools: Option<Vec<String>>,
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
    /// Route-local compression selector (`on`, `off`, or a named profile).
    #[serde(default)]
    pub compression_profile: Option<String>,
    /// Provider tool definitions injected into the request when this key
    /// authenticates, replacing any client-supplied tools.
    #[serde(default)]
    pub inject_tools: Vec<serde_json::Value>,
    /// Federated MCP catalog reference injected for this key.
    #[serde(default)]
    pub inject_mcp: Option<serde_json::Value>,
    /// Skip the body-aware prompt-injection scan for this key. Default false.
    #[serde(default)]
    pub bypass_prompt_injection: bool,
    /// Consent to the origin's opt-in redacted content capture for
    /// console inspection. Default false. A sample is retained only
    /// when the AI origin also sets `capture_content: true`, so both
    /// the operator and the key owner must opt in.
    #[serde(default)]
    pub allow_content_capture: bool,
    /// Project attribution.
    #[serde(default)]
    pub project: Option<String>,
    /// User attribution.
    #[serde(default)]
    pub user: Option<String>,
    /// Free-form grouping tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Free-form string metadata for audit and usage attribution.
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
    /// Owning tenant.
    #[serde(default)]
    pub tenant: Option<String>,
    /// RFC 3339 expiry instant; past it the key is unusable.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Redacted `Debug` (WOR-2606). `secret` is the plaintext inbound key
/// an operator seeds, hashed at boot: whoever reads it authenticates as
/// this key for as long as it exists.
///
/// `secret_hash` deliberately stays. It is the precomputed HMAC an
/// operator supplies instead of the plaintext, the proxy compares a
/// presented key's hash against it, and knowing a hash does not produce
/// its preimage. It is also the identifier that says *which* seeded key
/// a config-load error is about.
///
/// Curated and `finish_non_exhaustive`, so a credential-shaped field
/// added to this block later is absent from the output rather than
/// printed.
impl std::fmt::Debug for SeedKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedKeyConfig")
            .field("key_id", &self.key_id)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .field("secret_hash", &self.secret_hash)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A seeded upstream credential.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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

/// Redacted `Debug` (WOR-2606). `secret` is the upstream credential
/// this seeded entry presents. `vault_ref` stays: it names where the
/// real value comes from and is not itself one.
impl std::fmt::Debug for SeedCredentialConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedCredentialConfig")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("kind", &self.kind)
            .field("vault_ref", &self.vault_ref)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

// --- Scripting engine sandbox config (WOR-594 + WOR-595) ---

/// Per-engine scripting sandbox limits, exposed under the
/// `proxy.scripting:` block of sb.yml.
///
/// Both the Lua and the JavaScript sub-block are installed into their live
/// engines at boot and refreshed on reload. CEL and WebAssembly manage their
/// own budgets separately.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScriptingConfig {
    /// Lua sandbox limits. Always populated, even when the operator
    /// omitted the block, so callers never have to special-case
    /// `None`.
    #[serde(default)]
    pub lua: LuaScriptingConfig,
    /// JavaScript sandbox limits. Always populated, even when the
    /// operator omitted the block, so callers never have to
    /// special-case `None`.
    #[serde(default)]
    pub javascript: JsScriptingConfig,
}

/// JavaScript engine config block (`proxy.scripting.javascript:`).
///
/// The boot and reload paths install this sandbox into the process-wide handle
/// every `JsEngine::new` reads, so an operator override reaches the live
/// QuickJS engines.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Agent registry: the signed catalog subscriber plus the owner-approval
/// queue for agent self-registration.
///
/// Both halves keep their state in one embedded redb file at `store_path`.
/// The catalog is refreshed from `feed_path`, verified against
/// `key_directory_path`, which is itself verified against `bootstrap_keys`.
/// A registry with no feed configured still runs: the approval queue is
/// useful on its own, and the catalog then serves whatever the store last
/// cached.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentRegistryConfig {
    /// Master switch. Disabled by default, so a config that names the block
    /// without turning it on opens no store file.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the embedded store file holding the catalog cache and the
    /// registration queue. Created owner-only if absent.
    pub store_path: std::path::PathBuf,
    /// Path to the signed catalog feed. Absent means no refresh is
    /// possible and `POST /admin/agent-registry/refresh` says so.
    #[serde(default)]
    pub feed_path: Option<std::path::PathBuf>,
    /// Path to the signed key directory that names the feed signing keys.
    #[serde(default)]
    pub key_directory_path: Option<std::path::PathBuf>,
    /// Bootstrap public keys, keyed by the key id the directory's signature
    /// names, valued as base64 of the raw 32-byte Ed25519 public key.
    ///
    /// Bootstrap keys vouch for the feed publisher's key directory, which in
    /// turn vouches for the per-period keys that sign individual feeds. Only
    /// public material appears here, so this block belongs in version
    /// control with the rest of the config.
    ///
    /// An empty map means no key directory can be trusted and therefore no
    /// feed can be applied. The registry refuses rather than falling back to
    /// a key shipped in the binary, because a build carrying a known public
    /// key is a build where whoever holds the private half signs
    /// directories.
    #[serde(default)]
    pub bootstrap_keys: std::collections::BTreeMap<String, String>,
    /// How far past its own `expires_at` a feed may still be applied.
    /// Zero, the default, means the publisher's expiry is honored exactly.
    #[serde(default)]
    pub stale_grace_secs: u64,
    /// How long an identical resubmission is treated as a retry of the
    /// pending one rather than a new registration. One hour by default.
    #[serde(default = "default_agent_registry_duplicate_window_secs")]
    pub duplicate_window_secs: u64,
    /// How long a rotated-away client secret keeps authenticating. Thirty
    /// days by default, so a fleet can pick up a new secret without a
    /// synchronized restart.
    #[serde(default = "default_agent_registry_rotation_grace_secs")]
    pub rotation_grace_secs: u64,
}

impl AgentRegistryConfig {
    /// Refuse a block that cannot do what it appears to promise.
    ///
    /// Two shapes are accepted at parse and are nonetheless wrong. A feed
    /// path with no key directory has nothing to verify against, and a feed
    /// path with no bootstrap keys has nothing to verify the directory
    /// against; either way every refresh would fail at runtime, and an
    /// operator would read the resulting empty catalog as the publisher
    /// having nothing to say.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        match (self.feed_path.is_some(), self.key_directory_path.is_some()) {
            (true, false) => {
                return Err(
                    "agent_registry.feed_path is set without key_directory_path, so no feed \
                     could ever be verified"
                        .to_string(),
                )
            }
            (false, true) => {
                return Err(
                    "agent_registry.key_directory_path is set without feed_path, so there is \
                     nothing to verify"
                        .to_string(),
                )
            }
            _ => {}
        }
        if self.feed_path.is_some() && self.bootstrap_keys.is_empty() {
            return Err(
                "agent_registry names a feed but no bootstrap_keys, so the key directory it \
                 depends on can never be trusted"
                    .to_string(),
            );
        }
        for (kid, public_key) in &self.bootstrap_keys {
            if kid.trim().is_empty() {
                return Err("agent_registry.bootstrap_keys needs a non-empty key id".to_string());
            }
            if public_key.trim().is_empty() {
                return Err(format!(
                    "agent_registry bootstrap key {kid} has an empty public key"
                ));
            }
        }
        Ok(())
    }
}

impl Default for AgentRegistryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            store_path: std::path::PathBuf::from("agent-registry.redb"),
            feed_path: None,
            key_directory_path: None,
            bootstrap_keys: std::collections::BTreeMap::new(),
            stale_grace_secs: 0,
            duplicate_window_secs: default_agent_registry_duplicate_window_secs(),
            rotation_grace_secs: default_agent_registry_rotation_grace_secs(),
        }
    }
}

/// Outbound webhook notifications.
///
/// Distinct from `events:`, which is one collector for the SIEM feed. This
/// is the customer-facing side: several destinations, each with its own
/// event-type filter and its own signing key, managed at runtime through
/// the admin API rather than by editing this file.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NotificationsConfig {
    /// Master switch. Disabled by default, so a config that names the block
    /// without turning it on opens no store file.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the embedded store file holding the subscriptions and the
    /// deadletter queue. Created owner-only.
    ///
    /// The file holds live HMAC signing secrets, which unlike an inbound
    /// API key cannot be stored as a one-way hash: the notifier has to
    /// re-derive a signature on every delivery. Put it on the volume you
    /// already trust with the rest of your configuration.
    pub store_path: std::path::PathBuf,
    /// Bound on the hand-off queue between the request path and the
    /// delivery worker. A full queue drops the incoming event and counts
    /// the drop rather than making a request wait on a customer's endpoint.
    #[serde(default = "default_notifications_queue_capacity")]
    pub queue_capacity: usize,
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            store_path: std::path::PathBuf::from("notifications.redb"),
            queue_capacity: default_notifications_queue_capacity(),
        }
    }
}

fn default_notifications_queue_capacity() -> usize {
    4_096
}

fn default_agent_registry_duplicate_window_secs() -> u64 {
    3_600
}

fn default_agent_registry_rotation_grace_secs() -> u64 {
    30 * 24 * 3_600
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
#[serde(deny_unknown_fields)]
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
///   `string.match`, `string.gmatch`, `string.gsub`). The pattern
///   engine has known pathological inputs that can lock a worker, and
///   `max_execution_ms` cannot preempt one because the matcher runs
///   inside the C string library where the interrupt never fires. So
///   operators who do not need patterns can drop them entirely.
///
/// The on-the-wire field uses `max_memory_mb` (megabytes) because
/// that is the unit operators reason about; the engine converts to
/// bytes internally.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// `string.match`, `string.gmatch`, `string.gsub`). Those four are
    /// the whole pattern-taking surface of the `string` table; the
    /// rest of it (`upper`, `len`, `sub`, `rep`, and the others) stays
    /// available either way. Default: `true` for back compatibility;
    /// flip to `false` to disable pattern matching.
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    fn defaults_match_documented_behavior() {
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// variants of the same path with different `Accept-Language` etc.
    /// cache independently. The list is matched case-insensitively.
    /// Aliased as `vary_by` for parity with the docs/Cloudflare-style
    /// schema.
    ///
    /// This is the operator's list, on top of what the host varies on
    /// by itself. Tenant, caller identity, and the negotiated content
    /// coding are already in every key and do not need listing here;
    /// removing a name from this list cannot widen a key past any of
    /// them.
    #[serde(default, alias = "vary_by")]
    pub vary: Vec<String>,

    /// Query-string normalization applied at cache-key build time.
    /// Defaults to `sort` so callers see today's behavior unchanged.
    #[serde(default)]
    pub query_normalize: QueryNormalize,

    /// Operator-controlled cache generation for this origin.
    ///
    /// Folded into the origin's cache-config fingerprint, so bumping it
    /// rotates this origin's entries and nothing else. Defaults to 0.
    ///
    /// The fingerprint already moves on its own for any config change
    /// that alters what the upstream returns. This exists for the case
    /// it cannot see: an upstream that changed its response shape with
    /// no sbproxy config change at all. Rotating is cheap and safe, the
    /// old entries simply age out on their existing TTLs, so an
    /// unnecessary bump costs one cold start rather than correctness.
    #[serde(default)]
    pub epoch: u64,

    /// When set, the proxy serves an expired entry within
    /// `ttl + stale_while_revalidate` seconds while triggering a
    /// background revalidation. Stale replays carry the
    /// `x-sbproxy-cache: STALE` marker.
    #[serde(default, alias = "swr_secs")]
    pub stale_while_revalidate: Option<u64>,

    /// When true (default), `POST` / `PUT` / `PATCH` / `DELETE` to a
    /// path evicts every cached `GET` entry for the same workspace +
    /// tenant + hostname + path, across every caller and every Vary
    /// fingerprint.
    #[serde(default = "default_invalidate_on_mutation")]
    pub invalidate_on_mutation: bool,

    /// Key material sealing this origin's entries in the shared store.
    ///
    /// Absent means "follow `proxy.response_cache_store.encryption`",
    /// which under the default [`PerOriginKeyMode::Inherit`] is the
    /// store-wide key and under [`PerOriginKeyMode::Required`] is a
    /// startup failure naming this origin.
    #[serde(default)]
    pub encryption: Option<OriginCacheEncryptionConfig>,

    /// Operator-authored `cache.key` decision event.
    ///
    /// Runs on the request, before the lookup, because a key has to
    /// exist before anything can be looked up under it. Returns the
    /// dimensions to fold into the key, or declines and leaves `vary:`
    /// in charge.
    ///
    /// It can only **add** dimensions. The workspace, tenant, hostname,
    /// method, path, and caller-identity fields are stamped by the host
    /// on every key whatever the event returns, so a policy can narrow
    /// a key and can never widen one past its own tenant or its own
    /// caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_event: Option<DecisionScriptConfig>,

    /// Operator-authored `cache.admit` decision event.
    ///
    /// Runs on the response, after the body is buffered, because
    /// whether something is worth storing depends on status, size, and
    /// content, none of which exist at request time. Returns `store`
    /// and an optional `ttl_secs`, or declines and leaves
    /// `cacheable_status` and `ttl_secs` in charge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admit_event: Option<DecisionScriptConfig>,
}

/// An inline script answering one decision event.
///
/// Deliberately the same shape as [`CustomLogFieldConfig`]'s `source` +
/// `engine` pair rather than a second mechanism: one surface with the
/// engine as an operator choice is the pattern already shipping, and
/// generalizing it is the point of the decision-event work.
///
/// The accepted engines are narrower than `custom_fields`, and the two
/// refusals say why rather than leaving it to be discovered:
///
/// * `wasm`, because a compiled module is not inline source. A WASM
///   hook answers these events through the extension-bundle registry.
/// * `cel`, because these events return a **document** and CEL
///   evaluates to one scalar. Supporting it would mean a token grammar
///   for packing a document into a string, which is what
///   `route_to:gpt-4o-mini` already did once.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionScriptConfig {
    /// Engine for `source`. One of `lua`, `js`.
    pub engine: String,
    /// Script source, evaluated against the event's input context. Its
    /// result is the event's output document.
    pub source: String,
}

/// Query-string normalization policy applied when computing the cache key.
#[derive(Debug, Clone, Deserialize, Serialize, Default, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
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
            key_event: None,
            admit_event: None,
            ttl_secs: default_response_cache_ttl(),
            cacheable_methods: Vec::new(),
            cacheable_status: Vec::new(),
            max_size: default_response_cache_max_size(),
            vary: Vec::new(),
            query_normalize: QueryNormalize::default(),
            epoch: 0,
            stale_while_revalidate: None,
            invalidate_on_mutation: default_invalidate_on_mutation(),
            encryption: None,
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
#[serde(deny_unknown_fields)]
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
#[derive(Clone, Deserialize, Serialize, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct L2CacheParams {
    /// Redis connection DSN. Supports `redis://`, `rediss://`, credentials,
    /// bracketed IPv6 addresses, and a non-negative logical database.
    #[serde(default)]
    pub dsn: String,
    /// Optional path to PEM-encoded Redis trust anchors for a private CA.
    #[serde(default)]
    pub ca_file: Option<String>,
    /// Optional path to a PEM-encoded Redis client certificate chain.
    /// Must be configured together with `key_file` and requires `rediss://`.
    #[serde(default)]
    pub cert_file: Option<String>,
    /// Optional path to the PEM-encoded Redis client private key.
    /// Must be configured together with `cert_file` and requires `rediss://`.
    #[serde(default)]
    pub key_file: Option<String>,
}

impl std::fmt::Debug for L2CacheParams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("L2CacheParams")
            .field("dsn_configured", &!self.dsn.is_empty())
            .field("ca_file_configured", &self.ca_file.is_some())
            .field("cert_file_configured", &self.cert_file.is_some())
            .field("key_file_configured", &self.key_file.is_some())
            .finish()
    }
}

// --- Anomaly detection config (WOR-2666) ---

/// Behavioral anomaly detection over the signals the proxy already
/// collects.
///
/// The detector is comparative, not a rule set: it learns what a given
/// agent class normally looks like and flags what does not fit. That
/// makes it useful exactly where a signature list is not, and it also
/// means it says nothing at all until it has a baseline, which
/// [`Self::min_observations`] is the floor for.
///
/// # What it cannot survive
///
/// The histogram is in memory and has no persistence option. A restart
/// empties the window, and the detector is silent again until it has
/// re-learned a baseline. That is a deliberate consequence of the rule
/// that nothing here may require an external store: the alternative is
/// a database the proxy cannot start without. Operators running short
/// deployments, or restarting often, should expect the detector to
/// spend a meaningful fraction of its life below
/// `min_observations` and read `sbproxy_anomaly_detected_total`
/// accordingly.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnomalyConfig {
    /// Master switch. When `false`, no histogram is built and no
    /// detector hook is installed.
    #[serde(default)]
    pub enabled: bool,

    /// Observations a dimension needs before the detector will call
    /// anything an outlier.
    ///
    /// Below this the histogram cannot tell "rare" from "first time
    /// ever", and a detector that flags every first sighting is a
    /// detector nobody reads.
    #[serde(default = "default_anomaly_min_observations")]
    pub min_observations: u64,

    /// Relative frequency below which an observed value is an outlier.
    /// Defaults to `0.01`: a fingerprint has to have been under 1% of
    /// the window's traffic for its class before it is flagged.
    #[serde(default = "default_anomaly_outlier_frequency")]
    pub outlier_frequency: f64,

    /// Multiple of the per-IP mean at which today's request count for
    /// one IP is a rate spike. Defaults to `10.0`.
    #[serde(default = "default_anomaly_rate_spike_multiplier")]
    pub rate_spike_multiplier: f64,

    /// Mean per-IP rate below which the rate-spike check does not
    /// engage, so a single burst against an idle class is not a spike.
    #[serde(default = "default_anomaly_rate_spike_min_mean")]
    pub rate_spike_min_mean: f64,

    /// What admission does with the reputation score. Both thresholds
    /// are unset by default, which leaves the score advisory.
    #[serde(default)]
    pub reputation: AnomalyReputationConfig,
}

/// Admission thresholds on the reputation score (WOR-2666).
///
/// The score is published whether or not anything acts on it, and
/// nothing acts on it until an operator names a number. That split is
/// deliberate and it is the same one Cloudflare's threat score has: the
/// gateway computes it always, and a rule decides what it means. An
/// operator watches the gauge for a while, sees what their own traffic
/// scores, and only then writes a floor.
///
/// # Read this before setting one
///
/// The score is keyed on the agent class the resolver produced, and
/// that class is a *claim* unless the resolver source was a verified
/// one (`bot_auth`, `kya`, `rdns`, `tls_fingerprint`). Anyone can send
/// GPTBot's `User-Agent`, be resolved into the `gptbot` class, and
/// misbehave there, which moves the score the real GPTBot is then
/// admitted against. The decision record carries the resolver source
/// for exactly this reason, so a rule written after the fact can tell
/// the two apart.
///
/// The class `unknown` is a single shared bucket for everything the
/// resolver did not recognize. A floor that catches `unknown` catches
/// most of the unclassified web with it.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnomalyReputationConfig {
    /// Score below which admission refuses the request with a `403`.
    ///
    /// Unset by default. `0.0` to `1.0`, where 1.0 is a class that has
    /// produced no anomalies in the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_below: Option<f64>,

    /// Score below which admission answers `429` instead of proxying.
    ///
    /// Unset by default. Set above `deny_below` to get a two-step
    /// posture; `deny_below` wins when a score is under both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_below: Option<f64>,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_observations: default_anomaly_min_observations(),
            outlier_frequency: default_anomaly_outlier_frequency(),
            rate_spike_multiplier: default_anomaly_rate_spike_multiplier(),
            rate_spike_min_mean: default_anomaly_rate_spike_min_mean(),
            reputation: AnomalyReputationConfig::default(),
        }
    }
}

fn default_anomaly_min_observations() -> u64 {
    50
}

fn default_anomaly_outlier_frequency() -> f64 {
    0.01
}

fn default_anomaly_rate_spike_multiplier() -> f64 {
    10.0
}

fn default_anomaly_rate_spike_min_mean() -> f64 {
    5.0
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
/// so the in-tree memory / filesystem / redis / object-storage
/// backends can be extended without touching this schema.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// Retired (WOR-2673): the AWS-SDK S3 backend with KMS envelope
    /// encryption. [`Self::ObjectStore`] with `backend: s3` replaces
    /// it and reaches the same buckets.
    ///
    /// This variant still deserializes, and the config compiler still
    /// refuses it by name, on purpose. This enum carries
    /// `#[serde(other)]`, so deleting the variant outright would have
    /// made an existing `type: s3` block parse as "a backend
    /// registered out of tree": the config would load, the proxy would
    /// serve, the startup log would carry one `warn!`, and the cold
    /// tier would be gone. Every field is optional here because none
    /// of them is read for behavior; they exist so a real operator
    /// config parses far enough to reach a refusal that names its
    /// replacement.
    ///
    /// See `docs/cache-reserve.md` for the field-by-field migration,
    /// including the one behavior that does not carry over: KMS-wrapped
    /// per-object data keys. The replacement seals locally with
    /// AES-256-GCM, or leaves sealing to the bucket's own SSE-KMS.
    S3 {
        /// Ignored. Was the source S3 bucket.
        #[serde(default)]
        bucket: Option<String>,
        /// Ignored. Was the AWS region the bucket lives in.
        #[serde(default)]
        region: Option<String>,
        /// Ignored, and the field whose behavior does not carry over.
        /// Was the KMS key that wrapped each object's data key.
        #[serde(default)]
        kms_key_id: Option<String>,
        /// Ignored. Was the key prefix prepended to every object.
        #[serde(default)]
        prefix: Option<String>,
        /// Ignored. Was a diagnostics-only hint; cross-region
        /// replication was always configured at the bucket level.
        #[serde(default)]
        replication_target_bucket: Option<String>,
        /// Ignored. Was the switch between local envelope encryption
        /// and S3 bucket-default SSE-KMS.
        #[serde(default)]
        sse_kms_bucket_default: Option<bool>,
    },
    /// WOR-2673: object storage. One variant covers S3, Google Cloud
    /// Storage, Azure Blob Storage, and a local directory, because they
    /// all reach the proxy through the same `object_store` trait. The
    /// field names are the `storage` action's, so an operator who has
    /// configured that already knows this.
    ObjectStore {
        /// `s3`, `gcs`, `azure`, or `local`.
        #[serde(default = "default_reserve_object_backend")]
        backend: String,
        /// Bucket name, or the container name on Azure. Required for
        /// every backend but `local`.
        #[serde(default)]
        bucket: Option<String>,
        /// Root directory for the `local` backend. Required there and
        /// refused elsewhere.
        #[serde(default)]
        path: Option<String>,
        /// Region, for `s3`. Falls back to the provider's own
        /// environment discovery (`AWS_REGION`) when omitted.
        #[serde(default)]
        region: Option<String>,
        /// Endpoint override, for `s3`. Set this for MinIO, Cloudflare
        /// R2, Backblaze B2, or any other S3-compatible store.
        #[serde(default)]
        endpoint: Option<String>,
        /// Key prefix inside the bucket. Defaults to
        /// `sbproxy/reserve/`, so the reserve can share a bucket
        /// without colliding with anything else in it.
        #[serde(default)]
        prefix: Option<String>,
        /// Optional at-rest sealing, applied before an entry leaves the
        /// process. Absent or `enabled: false` writes payloads as the
        /// cache produced them.
        #[serde(default)]
        encryption: Option<CacheReserveEncryptionConfig>,
    },
    /// Catch-all for backends registered out-of-tree. The in-tree
    /// pipeline ignores these with a warning; an out-of-tree startup
    /// hook intercepts the variant before the warning fires.
    #[serde(other)]
    Other,
}

/// At-rest sealing for the object-storage cache reserve (WOR-2673).
///
/// The same reference syntax, the same rotation shape, and the same
/// no-plaintext-fallback rule as
/// [`ResponseCacheEncryptionConfig`]: a key that is missing,
/// unresolvable, or shorter than 16 bytes aborts startup rather than
/// being used verbatim or silently skipped.
///
/// Derived under its own HKDF purpose, so pointing this and the response
/// cache at one operator secret still yields two unrelated keys.
///
/// This is deliberately not a cloud KMS integration. A KMS call to
/// unwrap a data key would put a network round trip on the read path of
/// a tier whose purpose is to be cheaper than the origin, and would make
/// a reachable KMS a hard requirement for reading the cache at all.
/// Bucket-level SSE-KMS is configured on the bucket and composes with
/// this setting rather than competing with it.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CacheReserveEncryptionConfig {
    /// Master switch. Defaults to `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Secret reference for the active key, used to seal new entries and
    /// to open entries sealed under it. Required when `enabled` is
    /// `true`.
    ///
    /// Resolved like every other config secret: a provider URI
    /// (`secret://backend/name`, `vault://...`), a `file:/path`
    /// reference, or a whole-value `${ENV_VAR}`. The resolved value
    /// should be 32 random bytes (base64 or hex encoded), not a
    /// passphrase.
    #[serde(default)]
    pub key: Option<String>,

    /// Retired keys, used only to open entries sealed before a rotation.
    /// Same reference syntax as [`Self::key`].
    ///
    /// To rotate: move the current `key` into this list and name the new
    /// one as `key`. Entries reseal under the active key as they are
    /// rewritten; entries whose key leaves this list stop opening and
    /// are treated as misses.
    #[serde(default)]
    pub previous_keys: Vec<String>,
}

fn default_reserve_object_backend() -> String {
    "s3".to_string()
}

/// Default key prefix for the object-storage reserve.
pub const DEFAULT_RESERVE_OBJECT_PREFIX: &str = "sbproxy/reserve/";

fn default_reserve_sample_rate() -> f64 {
    0.1
}

fn default_reserve_min_ttl() -> u64 {
    3600
}

fn default_reserve_max_size_bytes() -> u64 {
    1_048_576
}

// --- Response Cache Store Config ---

/// Top-level selection of the response cache's backing store.
///
/// The response cache is process-wide: `CompiledPipeline` builds one
/// store and every origin whose `response_cache.enabled` is true shares
/// it. Origins do not collide because the cache key already includes
/// workspace, hostname, method, path, canonical query, and the Vary
/// fingerprint.
///
/// YAML key: `proxy.response_cache_store`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseCacheStoreConfig {
    /// Which store holds cached responses. Defaults to the in-process
    /// map.
    #[serde(default)]
    pub backend: ResponseCacheBackendConfig,

    /// Optional encryption of cached payloads at rest. Absent or
    /// `enabled: false` stores payloads as the backend receives them.
    #[serde(default)]
    pub encryption: Option<ResponseCacheEncryptionConfig>,
}

/// Backend selector for [`ResponseCacheStoreConfig`].
///
/// Tagged externally on `type`. This is a closed set: unlike
/// `cache_reserve`, the response-cache store has no out-of-tree
/// registration path, so an unrecognized `type` is a parse error rather
/// than a silent fallback.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ResponseCacheBackendConfig {
    /// In-process map, capped by the largest per-origin
    /// `response_cache.max_size`. Per-replica, so a multi-replica
    /// deployment caches independently. The default.
    #[default]
    Memory,
    /// One file per entry under `path`, named by the SHA-256 of the
    /// cache key. Survives a restart and is shared by every process
    /// pointed at the same directory. Prefix purge is unavailable
    /// because keys are hashed into filenames, so
    /// `invalidate_on_mutation` is a no-op on this backend and entries
    /// fall out by TTL.
    File {
        /// Directory holding the cache files. Created at startup if it
        /// does not exist; startup fails if it cannot be created.
        path: String,
        /// Ceiling on the total size of the directory, in megabytes.
        /// `0`, the default, means no ceiling. When set, each write
        /// walks the directory to measure it, so leave it at `0` unless
        /// the disk budget is real.
        #[serde(default)]
        max_size_mb: u64,
    },
    /// Memcached over the ASCII protocol. Shared across replicas.
    /// Stale-while-revalidate and prefix purge are both unavailable:
    /// memcached expires items server-side and offers no key scan.
    Memcached {
        /// Server hostname or IP.
        #[serde(default = "default_memcached_host")]
        host: String,
        /// Server port.
        #[serde(default = "default_memcached_port")]
        port: u16,
    },
    /// Redis, reusing the connection configured under
    /// `proxy.l2_cache`. Selecting this without an `l2_cache` block is
    /// a startup error.
    Redis,
}

/// At-rest encryption settings for the prompt-persistence redb file.
///
/// Persisted `NamedPrompt` records are sealed with AES-256-GCM before
/// they reach redb. Keys stay readable because hydration is a prefix
/// scan over `prompts:<host>:<name>`, and the key is authenticated as
/// associated data so a sealed value cannot be moved to another
/// host or prompt name.
///
/// Same reference syntax and the same no-plaintext-fallback rule as
/// [`ResponseCacheEncryptionConfig`]: a key that is missing,
/// unresolvable, or shorter than 16 bytes aborts startup. That is
/// deliberately stricter than the surrounding prompt-persistence
/// behavior, where an unreadable file only degrades to ephemeral
/// mutations. An unreadable file loses saved prompts; a key the operator
/// asked for and cannot supply would silently write secrets in the
/// clear.
///
/// Derived under its own HKDF purpose, so pointing this and the response
/// cache at one operator secret still yields two unrelated keys.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PromptPersistenceEncryptionConfig {
    /// Master switch. Defaults to `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Secret reference for the active key. Used to seal new records and
    /// to open records sealed under it.
    ///
    /// Resolved through the same mechanism as every other config secret:
    /// a provider URI (`secret://backend/name`, `vault://...`) against a
    /// backend declared under `proxy.secrets.backends`, a `file:/path`
    /// reference, or a whole-value `${ENV_VAR}`. Required when
    /// [`Self::enabled`] is `true`.
    ///
    /// The resolved value should be 32 random bytes (base64 or hex
    /// encoded) rather than a human-chosen passphrase.
    #[serde(default)]
    pub key: Option<String>,

    /// Retired keys, used only to open records sealed before a rotation.
    /// Same reference syntax as [`Self::key`].
    ///
    /// To rotate: move the current `key` into this list and name the new
    /// one as `key`. Records reseal under the active key the next time
    /// they are written.
    #[serde(default)]
    pub previous_keys: Vec<String>,
}

/// At-rest encryption settings for [`ResponseCacheStoreConfig`].
///
/// Cached response headers and bodies are sealed with AES-256-GCM
/// before they reach the backing store. Status, cache time, and TTL
/// stay readable because the file and memcached backends need them to
/// compute expiry; status is authenticated so it cannot be altered.
///
/// There is no plaintext fallback. A key that is missing, unresolvable,
/// or shorter than 16 bytes aborts startup.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseCacheEncryptionConfig {
    /// Master switch. Defaults to `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Secret reference for the active key. Used to seal new entries
    /// and to open entries sealed under it.
    ///
    /// Resolved through the same mechanism as every other config
    /// secret: a provider URI (`secret://backend/name`, `vault://...`)
    /// against a backend declared under `proxy.secrets.backends`, a
    /// `file:/path` reference, or a whole-value `${ENV_VAR}`. An
    /// unresolvable reference aborts startup rather than being used as
    /// key material verbatim. Required when `enabled` is `true`.
    ///
    /// The resolved value should be 32 random bytes (base64 or hex
    /// encoded), not a human-chosen passphrase: the logged key
    /// fingerprint is a weak offline oracle against a short passphrase,
    /// but not against 256 bits of real entropy.
    #[serde(default)]
    pub key: Option<String>,

    /// Retired keys, used only to open entries sealed before a
    /// rotation. Same reference syntax as [`Self::key`].
    ///
    /// To rotate: move the current `key` into this list and name the
    /// new one as `key`. Entries reseal under the active key as they
    /// are rewritten. Removing a reference from this list retires its
    /// entries; they are evicted the next time they are read.
    #[serde(default)]
    pub previous_keys: Vec<String>,

    /// What happens when an origin that caches does not declare its own
    /// key under `origins.<host>.response_cache.encryption`.
    ///
    /// Defaults to [`PerOriginKeyMode::Inherit`], which is the
    /// backwards-compatible behavior and is safe on its own terms: the
    /// origin is bound into the associated data either way, so an entry
    /// sealed for one origin never opens as another even when both
    /// inherit this key. Set [`PerOriginKeyMode::Required`] when the
    /// deployment's threat model needs every tenant to hold key material
    /// nobody else holds.
    #[serde(default)]
    pub per_origin_keys: PerOriginKeyMode,
}

/// How the response cache treats an origin that declares no key of its own.
///
/// Both modes bind the origin into the AEAD associated data, so
/// cross-origin isolation is cryptographic in both. The difference is
/// whether tenants share master key material.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PerOriginKeyMode {
    /// An origin with no key of its own uses the store-wide key. The
    /// default, and what every config written before per-origin keys
    /// existed gets.
    ///
    /// Cross-origin isolation still holds, because the origin id is
    /// authenticated in every envelope. What an operator does *not* get
    /// is key separation: one leaked store-wide key opens every tenant's
    /// entries.
    #[default]
    Inherit,
    /// Every origin with `response_cache.enabled: true` must declare its
    /// own `encryption.key`. Startup fails, naming each origin that does
    /// not, rather than quietly sealing that tenant under shared
    /// material.
    Required,
}

/// Per-origin at-rest encryption keys for the shared response cache.
///
/// Lives at `origins.<host>.response_cache.encryption`. The backing store
/// and its `enabled` switch stay global at
/// `proxy.response_cache_store.encryption`; this block only says which key
/// material seals *this* origin's entries. Declaring it while store-wide
/// encryption is off is a config error rather than a silent no-op, because
/// an operator who wrote a key here plainly expected sealing to happen.
///
/// Reference syntax and the no-plaintext-fallback rule are identical to
/// [`ResponseCacheEncryptionConfig`]: an unresolvable reference aborts
/// startup with an error naming this origin.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginCacheEncryptionConfig {
    /// Secret reference for this origin's active key. When absent, the
    /// behavior follows [`ResponseCacheEncryptionConfig::per_origin_keys`].
    #[serde(default)]
    pub key: Option<String>,

    /// This origin's retired keys, used only to open entries sealed
    /// before a rotation. Rotating one origin does not touch any other.
    #[serde(default)]
    pub previous_keys: Vec<String>,
}

fn default_memcached_host() -> String {
    "127.0.0.1".to_string()
}

fn default_memcached_port() -> u16 {
    11211
}

// --- Messenger Settings ---

/// Shape of the `proxy.messenger_settings` block, retained only so the
/// compiler can refuse it with an explanation (WOR-2166).
///
/// No value of this type is ever turned into a running bus. `compile_config`
/// rejects the config the moment the block is present, whatever the driver
/// says, because this build has no runtime consumer for a message bus: no
/// production code subscribes to a topic and none publishes on one. The
/// driver string is read for the diagnostic and nothing else.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessengerSettings {
    /// Backend driver name. Quoted back in the rejection diagnostic so an
    /// operator sees which bus they configured; no backend is constructed.
    pub driver: String,
    /// Free-form string parameters the driver factory used to consume.
    /// Nothing reads them: the block is refused before any driver runs.
    #[serde(default)]
    pub params: HashMap<String, String>,
}

// --- Admin Config ---

/// Configuration for the embedded read-only admin/stats API server.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// Maximum admin API requests per client IP per minute. The global
    /// cap across all clients is ten times this value. Must be between
    /// 1 and 100000; the limiter cannot be turned off. Defaults to 240.
    #[serde(default = "default_admin_rate_limit")]
    pub rate_limit_per_minute: u64,
    /// WOR-800 PR5: filesystem path to a redb file that persists the
    /// prompt-store runtime overlay. When set, every successful
    /// `POST /admin/prompts/.../versions` and `PUT /admin/prompts/.../pin`
    /// also writes through to the file, and the file's existing
    /// contents are hydrated into the in-memory overlay at boot.
    /// Absent means PR3-style ephemeral mutations.
    #[serde(default)]
    pub prompt_persistence_path: Option<std::path::PathBuf>,
    /// At-rest encryption for [`Self::prompt_persistence_path`]. Absent
    /// or disabled stores prompt records as plaintext JSON, which is the
    /// pre-existing behavior and stays the default so an upgrade cannot
    /// orphan an existing file.
    #[serde(default)]
    pub prompt_persistence_encryption: Option<PromptPersistenceEncryptionConfig>,
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

/// Redacted `Debug` (WOR-2640). `password` is the HTTP Basic password
/// for the admin API, in plaintext, and its default is `changeme`,
/// which is exactly the value most likely to still be in place when
/// something formats this struct into a config-load diagnostic. The
/// username stays, along with every listener and policy field: those
/// are what an operator debugging a refused admin request needs, and
/// none of them authenticates anything.
///
/// Curated rather than exhaustive, ending `finish_non_exhaustive`, so
/// a credential-shaped field added to this block later is absent from
/// the output rather than printed.
impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminConfig")
            .field("enabled", &self.enabled)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("max_log_entries", &self.max_log_entries)
            .field("rate_limit_per_minute", &self.rate_limit_per_minute)
            .field("prompt_persistence_path", &self.prompt_persistence_path)
            .field("trace_url_template", &self.trace_url_template)
            .field("bind", &self.bind)
            .field("allow_ips", &self.allow_ips)
            .field("cors_origins", &self.cors_origins)
            .field("operators", &self.operators)
            .finish_non_exhaustive()
    }
}

/// TLS material for the admin server (WOR-1717): filesystem paths to a
/// PEM certificate chain and its matching private key. Both are required
/// together; supplying `tls` makes the admin server, including the
/// built-in UI, serve HTTPS instead of plaintext HTTP.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdminTlsConfig {
    /// Path to the PEM certificate chain file.
    pub cert: std::path::PathBuf,
    /// Path to the PEM private key file (PKCS#8 or RSA).
    pub key: std::path::PathBuf,
}

/// An admin operator identity with a role, for RBAC (WOR-1716).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdminOperator {
    /// Login username.
    pub username: String,
    /// HMAC-SHA256 hash of the login password, hex-encoded, using the same
    /// pepper as the inbound key plane (sbproxy-keystore::crypto).
    /// Compute with `sbproxy admin hash-password`.
    pub password_hash: String,
    /// Role governing which admin actions this operator may perform.
    #[serde(default)]
    pub role: AdminRole,
    /// Billing tenant whose metered consumption this operator may read
    /// (WOR-2131). Absent means the whole deployment, which is what every
    /// operator written before this field existed keeps getting.
    ///
    /// A receipt names one buyer's traffic, so the meter routes treat a
    /// cross-tenant read as a disclosure rather than a reporting mistake:
    /// naming a tenant here narrows `/api/meter/*` to that tenant and
    /// refuses a request for any other. The scope is read from this
    /// document on every request rather than carried in the session token,
    /// so revoking it is a config reload rather than a wait for tokens to
    /// expire.
    #[serde(default)]
    pub tenant: Option<String>,
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

/// The shipped default admin username, so a first run works without any
/// credential config. Public so every consumer of the default reads this
/// constant instead of repeating the literal; the same string used to be
/// hardcoded in three places, which is how such a default drifts.
pub const DEFAULT_ADMIN_USERNAME: &str = "admin";

/// The shipped default admin password, the counterpart to
/// [`DEFAULT_ADMIN_USERNAME`]. Public for the same reason, plus one of
/// its own: because it is a published constant, a config that still uses
/// it is unauthenticated in practice, so `compile_config` compares
/// against this value and rejects it whenever the admin surface is
/// reachable off loopback.
pub const DEFAULT_ADMIN_PASSWORD: &str = "changeme";

fn default_admin_user() -> String {
    DEFAULT_ADMIN_USERNAME.to_string()
}

fn default_admin_pass() -> String {
    DEFAULT_ADMIN_PASSWORD.to_string()
}

fn default_max_log() -> usize {
    1000
}

fn default_admin_rate_limit() -> u64 {
    240
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
/// configs see no behavior change. Operators only set a field here
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// Backing store for issued certificates: `redb`, `sqlite`, `file`,
    /// `redis`, `s3`, `gcs`, `azure`, or `memory`. Anything else is
    /// rejected.
    #[serde(default = "default_storage_backend")]
    pub storage_backend: String,
    /// Where the certificate store lives. The meaning depends on
    /// `storage_backend`: a filesystem directory for `redb`, `sqlite`, and
    /// `file`, a `host:port` for `redis`, and a bucket URL such as
    /// `s3://bucket/prefix` for `s3`, `gcs`, and `azure`. Ignored by the
    /// `memory` backend.
    #[serde(default = "default_storage_path")]
    pub storage_path: String,
    /// Number of days before expiry to attempt renewal.
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
    /// PEM file holding a trusted root for the **ACME directory endpoint**,
    /// for a CA that is not in the system trust store.
    ///
    /// This is about trusting the ACME server you talk to, not the
    /// certificates it issues. A private or test CA (step-ca, Pebble, an
    /// internal ACME server) presents a directory endpoint signed by a
    /// root the host does not know, and without this the client refuses
    /// the connection before any order begins.
    ///
    /// Named and shaped after Caddy's `acme_ca_root`, deliberately.
    /// Verification stays **on**: the root is added to the trust store
    /// rather than the check being skipped, so a misconfigured or
    /// intercepted directory is still refused. There is no
    /// "skip verification" knob here and there should not be one.
    ///
    /// Read at issuance time rather than cached, so a rotated test CA does
    /// not need a restart. A missing or unparseable file refuses the
    /// issuance with an error naming the path; it never falls back to
    /// system roots, because falling back would silently restore the
    /// verification failure this setting exists to fix.
    #[serde(default)]
    pub ca_root: Option<String>,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// `sample_rate`. `None` preserves sampler-only behavior.
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
/// these by exact name still works as an intentional opt-in, except
/// `dpop`: sender-constraining proofs are never loggable.
pub const SENSITIVE_HEADER_DENYLIST: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "dpop",
    // Default sidecar header for a minted virtual key. It matches none of the
    // `-key` / `-secret` / `-token` suffix rules the log redactor uses, so
    // without this entry a `capture_headers: ["*"]` glob logs a live key.
    // Operator-configured sweep headers are added dynamically at reload.
    "x-sb-api",
];

/// Extra header names excluded from `*` and glob capture, on top of
/// [`SENSITIVE_HEADER_DENYLIST`].
///
/// Holds every primary carrier named by `key_management.inbound.headers` and
/// `key_management.inbound.provider_hints`, set at load and on every reload.
/// Without it a custom carrier could be captured by a
/// `capture_headers: ["*"]` glob.
static EXTRA_SENSITIVE_HEADERS: std::sync::OnceLock<
    std::sync::RwLock<std::sync::Arc<Vec<String>>>,
> = std::sync::OnceLock::new();

fn extra_sensitive_slot() -> &'static std::sync::RwLock<std::sync::Arc<Vec<String>>> {
    EXTRA_SENSITIVE_HEADERS.get_or_init(|| std::sync::RwLock::new(std::sync::Arc::new(Vec::new())))
}

/// Replace the operator-configured set of key-bearing headers that globs must
/// never capture. Pass [`KeyInboundConfig::credential_carrier_names`].
pub fn set_extra_sensitive_headers(names: Vec<String>) {
    let lowered: Vec<String> = names
        .into_iter()
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    if let Ok(mut slot) = extra_sensitive_slot().write() {
        *slot = std::sync::Arc::new(lowered);
    }
}

/// Whether `header_name` is sensitive: on the built-in denylist, or named by
/// the operator's inbound credential configuration.
pub fn is_sensitive_header(header_name: &str) -> bool {
    if SENSITIVE_HEADER_DENYLIST.contains(&header_name) {
        return true;
    }
    extra_sensitive_slot()
        .read()
        .map(|slot| slot.iter().any(|n| n == header_name))
        .unwrap_or(false)
}

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
            if is_sensitive_header(&entry) {
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
    /// exact matches override the denylist except for DPoP proofs,
    /// which are never loggable.
    pub fn matches(&self, header_name: &str) -> bool {
        self.matches_with_sensitive(header_name, is_sensitive_header)
    }

    /// Decide whether `header_name` should be captured using the supplied
    /// sensitive-header predicate.
    ///
    /// Request paths that pin a compiled config generation use this form so
    /// a concurrent reload cannot change which custom credential carriers
    /// are excluded from wildcard and prefix captures.
    pub fn matches_with_sensitive(
        &self,
        header_name: &str,
        is_sensitive: impl Fn(&str) -> bool,
    ) -> bool {
        if header_name == "dpop" {
            return false;
        }
        if self.exact.contains(header_name) {
            return true;
        }
        let denied = is_sensitive(header_name);
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
#[serde(deny_unknown_fields)]
pub struct AlertingConfig {
    /// List of notification channels to fire alerts to.
    #[serde(default)]
    pub channels: Vec<AlertChannelConfig>,
}

/// Top-level observability block grouping the log surfaces, telemetry, and
/// durable usage rollups. The process-logger `level` and `format` under `log`
/// are installed, below the CLI flags and `RUST_LOG`; `sampling` is not.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    /// Log sinks, redaction, custom fields, and the process logger's level
    /// and format.
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ObservabilityLogConfig {
    /// Process log level: a bare level (`trace`, `debug`, `info`, `warn`,
    /// `error`) or any `tracing-subscriber` per-target directive such as
    /// `sbproxy_ai=debug,h2=warn`.
    ///
    /// Third in precedence, behind `--log-level` (with its `SB_LOG_LEVEL`
    /// env form) and `RUST_LOG`, and ahead of the `info` default. A process
    /// started with either of those two keeps them for its whole life; this
    /// value is what a deployment that sets neither gets. Applied again on
    /// every config reload, so SIGHUP picks up an edit without a restart.
    #[serde(default)]
    pub level: Option<String>,
    /// Process output format: `compact`, `pretty`, or `json`. Behind
    /// `--log-format` (with its `SB_LOG_FORMAT` env form) and ahead of the
    /// `compact` default. Any other value is reported on stderr at startup
    /// and falls back rather than being silently accepted.
    ///
    /// Restart-only, unlike `level`: the output layer is built once and the
    /// runtime reload handle covers the filter alone. A reload logs the new
    /// value nowhere and keeps rendering in the old format. Sinks under
    /// `sinks:` carry their own independent `format`.
    #[serde(default)]
    pub format: Option<String>,
    /// Per-level sampling rates for the process logger. Parsed, validated,
    /// and inert: no emitter consults them, so the process logger drops no
    /// line at any rate. Per-request access-log sampling is a different
    /// key, `access_log.sample_rate:`, and that one is live.
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
    /// Decision-event audit publication. Absent means off, which is
    /// also what `enabled: false` means: no decision event publishes an
    /// audit record at this scope.
    #[serde(default)]
    pub decision_audit: Option<DecisionAuditConfig>,
}

/// Operator control over which decision events publish an audit record.
///
/// Every decision point in the pipeline (cache admission, cache-key
/// derivation, routing, auth, policy) already produces a `reason` string
/// saying what it decided and why. This block is what turns that
/// rationale into an OCSF audit record instead of letting it be decoded
/// and dropped.
///
/// ```yaml
/// observability:
///   log:
///     decision_audit:
///       enabled: true
///       events:
///         cache.admit: true
/// ```
///
/// Proxy scope only in this release. The tenant and origin log blocks
/// deny unknown fields and carry no `decision_audit` key, so a block
/// written under either one fails config load rather than composing or
/// being ignored. When scoping does land it will compose the way
/// `custom_fields` does, per key rather than per block: a more-specific
/// scope naming one event must not wipe the entries a less-specific
/// scope set for the others.
///
/// # This block is the only thing that decides what publishes
///
/// No event carries a default of its own. Every label is off until a
/// setting here says otherwise, and there is nowhere else to look. An
/// earlier draft kept a second per-event default outside the config,
/// which is how an operator ends up believing a feed is on: the two
/// disagreed, and the one nothing consulted was the one that read as
/// authoritative.
///
/// The security ordering behind that draft is worth keeping, as the
/// shape a later release should default on once the events have
/// emitters. `auth`, `policy`, `rate_limit`, `waf`, both AI guardrail
/// events, `ai.tool_call`, `mcp.tool`, and `payment.lifecycle` are the
/// security-relevant ones, and an operator who can afford only part of
/// the feed wants those. `cache.key` is security-relevant and also the
/// densest event in the set, once per cacheable request, so it stays an
/// explicit opt-in rather than riding a default. `route.decide` is
/// worth publishing when a decision crosses a provider or
/// data-residency boundary and is noise otherwise, which is a question
/// about the decision rather than about the event, so it needs the
/// routing event config to carry that predicate before any default for
/// it means anything.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionAuditConfig {
    /// Master switch for the block. `Some(true)` publishes every event
    /// the `events` map does not name, except `ai.stream.event`, which
    /// is never published by any setting; `Some(false)` and `None` are
    /// both **off**, as is an absent block.
    ///
    /// Accepted at proxy, tenant, and origin scope. A tenant or origin
    /// block composes over the proxy one per event label, so naming
    /// `route.decide` under a tenant inherits the proxy's `cache.admit`
    /// rather than replacing the map; see [`DecisionAuditScopes`].
    ///
    /// `None` reads as off rather than as inherit, because a scope that
    /// wrote no block asked for nothing and the composition already
    /// gives a wider scope its say.
    ///
    /// Off is the default because the decision events differ by orders
    /// of magnitude in how often they fire. `cache.key` runs once per
    /// cacheable request, so a master switch with permissive defaults
    /// would hand an operator a per-request SIEM feed on their busiest
    /// origin the moment they flipped it. That is an ingest bill rather
    /// than a control, and the usual answer to a feed nobody can afford
    /// is to turn the whole thing off, which takes the
    /// security-relevant events with it. Opting in per event costs one
    /// line and keeps that choice available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Per-event override of the master switch, keyed by the event's
    /// stable label
    /// ([`sbproxy_observe::decision::DecisionEvent::as_label`]):
    /// `cache.admit`, `cache.key`, `route.decide`, `auth`, `policy`,
    /// and the rest. `true` publishes that event's records, `false`
    /// silences it. An event this map does not name falls back to the
    /// master switch.
    ///
    /// A key naming no known event is refused at config load rather
    /// than ignored, because a typo'd label is a feed the operator
    /// believes they turned on and nobody is watching.
    /// `ai.stream.event: true` is refused by value for the same reason
    /// the block defaults off: that event fires once per streamed
    /// chunk. `ai.close` carries the stream's summary instead. That one
    /// label is also the single exception to the fallback above: it
    /// never publishes, master switch or not.
    ///
    /// A `BTreeMap` rather than a `HashMap`, matching `custom_fields`:
    /// the composed set is iterated to resolve the emission policy, and
    /// a hash order would make two proxies holding identical config
    /// walk it differently.
    #[serde(default)]
    pub events: std::collections::BTreeMap<String, bool>,
    /// Which wire shape a `policy` decision publishes (WOR-2448).
    ///
    /// Policy decisions have always published a `PolicyVerdictEvent`
    /// under the `policy_verdict_event:` prefix, serialized through its
    /// serde derive. Every other decision publishes a `DecisionAudit`
    /// rendered as OCSF under `decision_audit_event:`. Same bus, same
    /// class of event, two formats, so an analyst reconstructing every
    /// control decision on one request parses both and joins them by
    /// hand.
    ///
    /// This selects between them for the `policy` event, and nothing
    /// else. Exactly one record is published either way: emitting both
    /// during a migration would double volume on the densest event in
    /// the system and give an analyst two rows for one decision.
    ///
    /// `legacy` is the default this release, so an upgrade changes
    /// nothing your filters depend on and a startup warning names the
    /// deprecation instead. Set `decision` once your consumer reads the
    /// shared shape. The default changes in the next major release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_record_format: Option<PolicyRecordFormat>,
}

/// Wire shape for `policy` decision records (WOR-2448).
///
/// A deprecation dial rather than a preference. The two variants are the
/// before and after of one migration, and `legacy` exists to give
/// operators a release in which to move their consumers rather than to
/// be a supported alternative.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRecordFormat {
    /// `policy_verdict_event:` carrying a serde-serialized
    /// `PolicyVerdictEvent`. The shape shipped since the audit bus
    /// landed, and the default this release.
    ///
    /// Its known gap is that it carries no free-text reason, so the most
    /// security-relevant event in the system is the one that cannot say
    /// why it decided. That gap is not fixable in this shape without
    /// changing it, which is what the migration is for.
    #[default]
    Legacy,
    /// `decision_audit_event:` carrying a `DecisionAudit` rendered as
    /// OCSF API Activity 6003, with the policy id, surface, verdict, and
    /// latency as selectable fields under `unmapped`, plus the reason
    /// the legacy shape has no room for.
    ///
    /// One shape for every control decision, which is the only version
    /// of this surface an analyst can query as a whole.
    Decision,
}

impl PolicyRecordFormat {
    /// Stable label, for log lines and tests.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Decision => "decision",
        }
    }
}

impl DecisionAuditConfig {
    /// What this config asks for on `event_label`, at one scope.
    ///
    /// The one place the precedence lives, so no emitting site can read
    /// the two fields in its own order: a per-event entry wins outright,
    /// otherwise the master switch decides, and an absent master switch
    /// is off. An absent block is off too, which is why this is a method
    /// on the config rather than on an `Option` wrapper: a caller with
    /// no block written cannot accidentally get a permissive default out
    /// of it.
    ///
    /// [`DecisionAuditScopes::publishes`] is what the request path
    /// calls; this is the single-scope form it composes.
    pub fn publishes(&self, event_label: &str) -> bool {
        use sbproxy_observe::decision::DecisionEvent;

        // `ai.stream.event` is off by construction, ahead of both the
        // per-event map and the master switch. It fires once per streamed
        // chunk, so a per-event audit record is an ingest bill rather
        // than a control; `ai.close` carries the same stream's summary
        // once the response finishes.
        //
        // The load-time refusal in `validate_decision_audit` covers
        // `events: {ai.stream.event: true}` and stays, because config
        // asking for a feed it cannot have should fail loudly rather
        // than be silently ignored. What it cannot cover is the master
        // switch: `enabled: true` with no `events:` map names no event,
        // compiles clean, and would fall through to `unwrap_or` here and
        // turn the per-chunk feed on for any caller. Refusing the label
        // in the one place the precedence lives makes it unreachable for
        // every emitter, including the ones that do not exist yet.
        if event_label == DecisionEvent::AiStreamEvent.as_label() {
            return false;
        }
        if let Some(explicit) = self.events.get(event_label) {
            return *explicit;
        }
        self.enabled.unwrap_or(false)
    }
}

/// The composed `decision_audit:` blocks for one compiled config.
///
/// Built once at compile time and read per decision, the same shape the
/// operator redaction state uses, and for the same reason: the
/// precedence has to live in one place or each emit site invents its
/// own. [`DecisionAuditScopes::publishes`] is the only resolver.
///
/// Composition is **per event label**, not per block. A tenant that
/// names `route.decide` inherits the proxy's `cache.admit` setting
/// rather than replacing the whole map, because the replacing version
/// means enabling one tenant's routing audit silently disables its
/// cache audit, and a silently disabled audit feed is the failure this
/// whole surface is built to avoid.
#[derive(Debug, Clone, Default)]
pub struct DecisionAuditScopes {
    /// `proxy.observability.log.decision_audit`.
    pub proxy: Option<DecisionAuditConfig>,
    /// Keyed by tenant id.
    pub tenants: std::collections::BTreeMap<String, DecisionAuditConfig>,
    /// Keyed by the origin's config key, which is what
    /// `RequestContext::hostname` carries for a non-wildcard origin.
    pub origins: std::collections::BTreeMap<String, DecisionAuditConfig>,
}

impl DecisionAuditScopes {
    /// Which wire shape `policy` records take for this process
    /// (WOR-2448).
    ///
    /// Read from the proxy scope only, and deliberately not composed per
    /// tenant or origin the way [`Self::publishes`] is. Two tenants
    /// cannot sensibly disagree about the encoding of a shared bus: the
    /// drain stamps one prefix per record kind and a consumer's filter
    /// selects one parser's input, so a per-tenant format would hand
    /// that parser records it cannot read. Emission is per scope;
    /// encoding is per process.
    ///
    /// The proxy block is also the only place `decision_audit:` is
    /// accepted today, so there is no scope this could be written at and
    /// silently ignored.
    pub fn policy_record_format(&self) -> PolicyRecordFormat {
        self.proxy
            .as_ref()
            .and_then(|c| c.policy_record_format)
            .unwrap_or_default()
    }

    /// Whether any scope configured anything at all.
    ///
    /// The emit sites test this first so a deployment that never wrote
    /// the block pays one `bool` rather than three map lookups per
    /// decision.
    pub fn is_empty(&self) -> bool {
        self.proxy.is_none() && self.tenants.is_empty() && self.origins.is_empty()
    }

    /// Whether one event publishes at one request's scope.
    ///
    /// `route` is the origin's config key. Passing something else (the
    /// request `Host` under a wildcard origin, say) silently skips the
    /// origin scope, which is the same trap the redaction resolver has
    /// and is why both take the value from the same place.
    pub fn publishes(&self, event_label: &str, tenant: Option<&str>, route: Option<&str>) -> bool {
        use sbproxy_observe::decision::DecisionEvent;

        // Unreachable at every scope, for the reason the proxy-scope
        // resolver gives: it fires once per streamed chunk.
        if event_label == DecisionEvent::AiStreamEvent.as_label() {
            return false;
        }

        let origin = route.and_then(|r| self.origins.get(r));
        let tenant = tenant.and_then(|t| self.tenants.get(t));
        let scopes = [origin, tenant, self.proxy.as_ref()];

        // Per-key first, most specific wins.
        for scope in scopes.into_iter().flatten() {
            if let Some(explicit) = scope.events.get(event_label) {
                return *explicit;
            }
        }
        // Then the master switch from the most specific scope that sets
        // one. A scope that writes `events:` alone does not shadow a
        // wider scope's `enabled:`.
        for scope in scopes.into_iter().flatten() {
            if let Some(enabled) = scope.enabled {
                return enabled;
            }
        }
        false
    }
}

/// One operator-defined custom access-log field.
///
/// Exactly one value source must be set: either `value` (a static
/// string with `${...}` variable interpolation) or `source` together
/// with `engine` (a script). Supplying both, or neither, is a config
/// error. `engine` must be one of `cel`, `lua`, `js`. (`wasm` is
/// rejected: it is a compiled module, not inline source.)
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// `rules:` or by the default-all behavior. The matching name is
    /// case-sensitive. At a tenant or origin scope the list is
    /// SUBTRACTED from the resolved set (parent inheritance plus this
    /// scope's `rules:` additions).
    #[serde(default)]
    pub disable: Vec<String>,
}

/// One named regex mask. `name` is reported on cardinality / counter
/// metrics; `replacement` defaults to `[REDACTED:<NAME>]` when empty.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// legacy stdout behavior; `file` reuses the access-log rotation
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
#[serde(deny_unknown_fields)]
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
        /// is honored for HTTP transport; the gRPC variant uses the
        /// host:port only.
        endpoint: String,
        /// Transport selector: `http` or `grpc`. Defaults to whatever
        /// the top-level `telemetry.transport` declares; `grpc` when
        /// that block is absent.
        #[serde(default)]
        transport: Option<String>,
        /// Per-export timeout in seconds. Defaults to 10 seconds when
        /// omitted; honored by the underlying OTLP exporter's HTTP /
        /// gRPC client.
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
}

/// Per-level sample rates for the structured-log emitter.
///
/// Every rate here is inert. The emitter has no sampling call site at
/// all: it renders, redacts, and writes every record, so setting `debug:
/// 0.0` drops nothing and setting `1.0` restores nothing. Documented
/// rather than removed because the rates round-trip through existing
/// configs; the surface that does throttle logs today is
/// `access_log.sample_rate:`.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservabilitySamplingConfig {
    /// Fraction of `info` lines that would be emitted. Inert.
    #[serde(default)]
    pub info: Option<f64>,
    /// Fraction of `debug` lines that would be emitted. Inert.
    #[serde(default)]
    pub debug: Option<f64>,
    /// Fraction of `trace` lines that would be emitted. Inert.
    #[serde(default)]
    pub trace: Option<f64>,
}

/// Subset of `sbproxy-observe::TelemetryConfig` exposed in the YAML.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// Propagation format. Only `w3c` (the default) is wired; the
    /// binary refuses to start with any other value.
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
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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

/// Redacted `Debug` (WOR-2606). Two carriers, and the second is the
/// one that is easy to miss. `routing_key` is the PagerDuty integration
/// key and its own field doc says it accepts secret references, so
/// after resolution it holds the credential. `headers` is
/// operator-authored and is where an `Authorization:` value goes when a
/// channel needs one, which makes every value in it a possible
/// credential; the *names* stay, because which headers are configured
/// is the useful half of that map for a diagnostic.
impl std::fmt::Debug for AlertChannelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertChannelConfig")
            .field("channel_type", &self.channel_type)
            .field("url", &self.url)
            .field(
                "headers",
                &self.headers.keys().map(String::as_str).collect::<Vec<_>>(),
            )
            .field(
                "routing_key",
                &self.routing_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish_non_exhaustive()
    }
}

// --- HTTP/3 Config ---

/// HTTP/3 (QUIC) configuration.
///
/// The shape is reserved for forward compatibility. The config compiler
/// accepts an omitted or disabled block, but rejects `enabled: true` because
/// this build does not serve HTTP/3. Native support is tracked in WOR-1969.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Http3Config {
    /// Whether to enable the HTTP/3 (QUIC) listener.
    ///
    /// Must remain `false` in this build. Setting it to `true` fails config
    /// compilation because HTTP/3 is not served.
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

/// Legacy per-origin connection-pool shape.
///
/// One field is live. `idle_timeout_secs` is the legacy spelling of the
/// upstream idle deadline and feeds the origin's resolved
/// [`UpstreamTimeouts`] when `timeouts.idle_ms` is not set.
///
/// The other two parse and are then refused at config compile. They are
/// retained as `Option` rather than deleted outright so an archived
/// schema-v1 document reaches an explanatory diagnostic instead of an
/// unknown-key error, the same call `proxy.messenger_settings` took.
///
/// Neither has a Pingora primitive behind it in this build.
/// `pingora_core::upstreams::peer::PeerOptions`, the per-peer struct
/// `proxy_http.rs` tunes, carries no pool-size and no maximum-lifetime
/// field. The only pool-size knob in the vendored fork is
/// `ConnectorOptions::keepalive_pool_size`, which is set once per
/// connector from the server config and so cannot express a per-origin
/// limit, and `pingora-pool` has no age-based eviction at all. Wiring
/// either one is a change to Pingora, not a change here.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectionPoolConfig {
    /// Refused at config compile. Pingora sizes the upstream keepalive
    /// pool per connector, not per origin, so this never bounded
    /// anything.
    #[serde(default)]
    pub max_connections: Option<u32>,

    /// Maximum idle time before a pooled upstream connection is closed, in
    /// seconds.
    ///
    /// Legacy spelling of `timeouts.idle_ms`; setting both fails config
    /// compile. Default: 90 s.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u32,

    /// Refused at config compile. Pingora's connection pool has no
    /// age-based eviction, so no upstream connection was ever retired on
    /// this deadline.
    #[serde(default)]
    pub max_lifetime_secs: Option<u32>,
}

fn default_idle_timeout_secs() -> u32 {
    90
}

impl Default for ConnectionPoolConfig {
    /// Mirrors serde, not `u32::default()`.
    ///
    /// `resolve_upstream_timeouts` compares an authored
    /// `idle_timeout_secs` against this value to tell "the operator left
    /// the key out" from "the operator wrote a number". A derived
    /// `Default` would put `0` here and make every authored value look
    /// like a conflict, so the 90 s serde default is repeated
    /// deliberately.
    fn default() -> Self {
        Self {
            max_connections: None,
            idle_timeout_secs: default_idle_timeout_secs(),
            max_lifetime_secs: None,
        }
    }
}

// --- UpstreamTimeoutsConfig ---

/// Default deadline for one upstream TCP connect attempt, in milliseconds.
pub const DEFAULT_UPSTREAM_CONNECT_TIMEOUT_MS: u64 = 5_000;

/// Default deadline across all connect attempts for one upstream selection,
/// including TLS, in milliseconds.
pub const DEFAULT_UPSTREAM_TOTAL_CONNECT_TIMEOUT_MS: u64 = 10_000;

/// Default per-read socket deadline on an upstream connection, in
/// milliseconds.
pub const DEFAULT_UPSTREAM_READ_TIMEOUT_MS: u64 = 30_000;

/// Default per-write socket deadline on an upstream connection, in
/// milliseconds.
pub const DEFAULT_UPSTREAM_WRITE_TIMEOUT_MS: u64 = 30_000;

/// Default idle time before a pooled upstream connection is closed, in
/// milliseconds.
pub const DEFAULT_UPSTREAM_IDLE_TIMEOUT_MS: u64 = 90_000;

/// Per-origin upstream timeout overrides.
///
/// Every field is optional. An absent field resolves to the matching
/// `DEFAULT_UPSTREAM_*` constant at config compile time, so the request path
/// always reads a concrete [`UpstreamTimeouts`]. A value of `0` fails config
/// compile: a zero deadline fails the operation the moment it starts and is
/// never what an operator meant.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTimeoutsConfig {
    /// Deadline for one upstream TCP connect attempt, in milliseconds.
    /// Default: 5000 (5 s).
    #[serde(default)]
    pub connect_ms: Option<u64>,

    /// Deadline across all connect attempts for one upstream selection,
    /// including TLS, in milliseconds. Default: 10000 (10 s).
    #[serde(default)]
    pub total_connect_ms: Option<u64>,

    /// Per-read socket deadline on the upstream connection, in milliseconds.
    /// Default: 30000 (30 s).
    #[serde(default)]
    pub read_ms: Option<u64>,

    /// Per-write socket deadline on the upstream connection, in milliseconds.
    /// Default: 30000 (30 s).
    #[serde(default)]
    pub write_ms: Option<u64>,

    /// Idle time before a pooled upstream connection is closed, in
    /// milliseconds. Service discovery caps the effective value at half the
    /// DNS refresh window. Default: 90000 (90 s).
    #[serde(default)]
    pub idle_ms: Option<u64>,
}

/// Fully resolved upstream timeouts for one origin.
///
/// Built by the config compiler from [`UpstreamTimeoutsConfig`] plus the
/// legacy `connection_pool.idle_timeout_secs`, with absent fields resolved
/// to the `DEFAULT_UPSTREAM_*` constants. The request path reads these
/// `Duration`s directly; no `Option` remains by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamTimeouts {
    /// Deadline for one upstream TCP connect attempt.
    pub connect: Duration,
    /// Deadline across all connect attempts for one upstream selection,
    /// including TLS.
    pub total_connect: Duration,
    /// Per-read socket deadline on the upstream connection.
    pub read: Duration,
    /// Per-write socket deadline on the upstream connection.
    pub write: Duration,
    /// Idle time before a pooled upstream connection is closed. Service
    /// discovery caps the effective value further at peer-selection time;
    /// the smaller of the two always wins.
    pub idle: Duration,
}

impl Default for UpstreamTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_millis(DEFAULT_UPSTREAM_CONNECT_TIMEOUT_MS),
            total_connect: Duration::from_millis(DEFAULT_UPSTREAM_TOTAL_CONNECT_TIMEOUT_MS),
            read: Duration::from_millis(DEFAULT_UPSTREAM_READ_TIMEOUT_MS),
            write: Duration::from_millis(DEFAULT_UPSTREAM_WRITE_TIMEOUT_MS),
            idle: Duration::from_millis(DEFAULT_UPSTREAM_IDLE_TIMEOUT_MS),
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct TenantObservabilityConfig {
    /// Tenant-scoped log block. See [`TenantObservabilityLogConfig`].
    #[serde(default)]
    pub log: TenantObservabilityLogConfig,
    /// WOR-1067: per-tenant cardinality budget. Caps the unique label
    /// value count across `sbproxy_requests_total` and friends for
    /// just this tenant so a noisy tenant cannot demote labels for
    /// every other tenant. Omitting the block leaves this tenant on
    /// the proxy-wide budget (today's behavior).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardinality: Option<TenantCardinalityConfig>,
}

/// WOR-1067: per-tenant cardinality budget. The runtime installs one
/// dedicated label-value tracker per declared tenant; overflows on
/// tenant B do not touch tenant A's accepted-value set. The
/// `__default__` tenant continues to use the proxy-wide
/// `CardinalityLimiter` (in `sbproxy-observe`) so single-tenant
/// deployments stay bit-for-bit identical to pre-WOR-1067 behavior.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct TenantObservabilityLogConfig {
    /// Scoped `decision_audit:` additions, composed per event label
    /// against the wider scopes rather than replacing them.
    ///
    /// The same shape as the proxy-scope block. Composition is per key,
    /// matching `custom_fields:`: a scope naming one event must not
    /// silence the events a wider scope turned on, because that would
    /// make enabling one tenant's routing audit quietly disable its
    /// cache audit. Precedence for a given event is origin, then
    /// tenant, then proxy, and an event no scope names is off.
    ///
    /// `enabled:` composes the same way: the most specific scope that
    /// sets it wins for the events nobody names explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_audit: Option<DecisionAuditConfig>,
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

/// Tenant-scope `redact:` sub-block. Today only `pii:` is honored;
/// the field-key and pattern overrides remain proxy-scope only because
/// they touch the rendered JSON, which is tenant-agnostic in the
/// emitter.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
///   `azurekv://`, `k8ssecret://`, `secretfile://`, or `secret://`,
///   or a legacy `${ENV}` / `file:` reference).
/// * Which inbound principals can use it (`principals` selectors).
/// * Per-credential attribution metadata (`attrs`).
/// * Allow / deny model lists that stack on top of the origin-level
///   allowlist (most-restrictive wins).
/// * Per-credential sub-policies (rate limit, PII redaction, ...).
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// `vault://`, `awssm://`, `gcpsm://`, `azurekv://`,
    /// `k8ssecret://`, `secretfile://`, and `secret://`; legacy
    /// `${ENV}` and `file:` forms also remain valid. The removed `secret:<name>` form is
    /// rejected. The resolver dispatches at runtime; the config parser
    /// carries the value as a string.
    #[serde(default)]
    pub key: Option<String>,
    /// Principal selectors that match this credential to inbound
    /// principals. An empty list matches every principal; downstream
    /// resolution then uses the first credential whose selectors
    /// match the request.
    #[serde(default)]
    pub principals: Vec<PrincipalSelector>,
    /// Attribution attributes lowered onto matched principals. Individual
    /// compatibility-only fields are documented on their definitions.
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
    /// Select `on`, `off`, or a named route-local compression profile.
    #[serde(default)]
    pub compression_profile: Option<String>,
    /// Replace the request's `tools` array with these entries. The
    /// shape is provider-native (`function` objects today); the AI
    /// dispatch forwards the array verbatim. Empty == no injection.
    /// Mirrors `inject_tools` on the underlying `VirtualKeyConfig`.
    #[serde(default)]
    pub inject_tools: Vec<serde_json::Value>,
    /// Caller-supplied tool allowlist for this credential. Omitted is
    /// unrestricted and an explicit empty list denies every caller tool.
    #[serde(default)]
    pub allowed_tools: Option<Vec<String>>,
    /// WOR-1646: inject a federated MCP gateway's live catalog as
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
#[serde(deny_unknown_fields)]
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
    /// Serialized as a flat map for readability.
    #[serde(default)]
    pub claim: std::collections::BTreeMap<String, String>,
}

/// Attribution attributes copied onto matched principals.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialAttrs {
    /// Project the credential's spend rolls up to.
    #[serde(default)]
    pub project: Option<String>,
    /// User the credential is owned by (independent of who the
    /// inbound request authenticates as).
    #[serde(default)]
    pub user: Option<String>,
    /// Team the credential's spend rolls up to. Copied onto
    /// `Principal.attrs.team`, which feeds the access log's `team`
    /// column, the attribution tag set behind the `team` metric label,
    /// and the usage rollup dimension. This is the write end of the
    /// same dimension `principals[].team` selects on.
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

/// Per-credential budget. The token and cost caps are lowered into
/// the live credential registry. `reset` remains a reserved,
/// compatibility-only field and does not install a reset schedule.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialBudget {
    /// Maximum input + output tokens enforced for this credential.
    #[serde(default)]
    pub max_tokens: Option<u64>,
    /// Maximum USD spend enforced for this credential.
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
    /// Reserved reset-window hint. It is accepted but not parsed or
    /// enforced by the OSS runtime.
    #[serde(default)]
    pub reset: Option<String>,
}

/// Model allow / deny lists scoped to this credential. Stacks on top
/// of the origin-level allowlist. Most-restrictive wins.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// Schema-only mirror of the deferred outbound credential enum. Runtime
/// parsing remains in `sbproxy-modules`; this keeps generated editor tooling
/// precise without introducing a crate dependency cycle.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
enum OutboundCredentialSchema {
    TokenExchange {
        token_endpoint: String,
        audience: String,
        #[serde(default)]
        scope: Option<String>,
        #[serde(default)]
        subject_token_issuers: Vec<String>,
        #[serde(default)]
        allowed_audiences: Vec<String>,
        #[serde(default = "default_outbound_act_depth")]
        act_depth_cap: usize,
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        client_secret: Option<String>,
        #[serde(default)]
        dpop: Option<OutboundDpopSchema>,
    },
    ClientCredentials {
        token_endpoint: String,
        client_id: String,
        client_secret: String,
        #[serde(default)]
        scope: Option<String>,
        #[serde(default)]
        audience: Option<String>,
        #[serde(default)]
        dpop: Option<OutboundDpopSchema>,
    },
    VaultSecret {
        secret: String,
        #[serde(default = "default_outbound_credential_header")]
        header: String,
        #[serde(default = "default_outbound_credential_scheme")]
        scheme: String,
        #[serde(default)]
        dpop: Option<OutboundDpopSchema>,
    },
}

/// Redacted `Debug` (WOR-2606). The authored-config shim for the three
/// outbound credential shapes that `sbproxy_modules` redacts at
/// runtime. Crate-private, which narrows the blast radius but does not
/// close it: a `{:?}` inside this crate prints the same values, and
/// this is the side a config-load diagnostic formats.
impl std::fmt::Debug for OutboundCredentialSchema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenExchange {
                token_endpoint,
                audience,
                client_id,
                ..
            } => f
                .debug_struct("TokenExchange")
                .field("token_endpoint", token_endpoint)
                .field("audience", audience)
                .field("client_id", client_id)
                .field("client_secret", &"[REDACTED]")
                .finish_non_exhaustive(),
            Self::ClientCredentials {
                token_endpoint,
                client_id,
                ..
            } => f
                .debug_struct("ClientCredentials")
                .field("token_endpoint", token_endpoint)
                .field("client_id", client_id)
                .field("client_secret", &"[REDACTED]")
                .finish_non_exhaustive(),
            Self::VaultSecret { header, scheme, .. } => f
                .debug_struct("VaultSecret")
                .field("secret", &"[REDACTED]")
                .field("header", header)
                .field("scheme", scheme)
                .finish_non_exhaustive(),
        }
    }
}

fn default_outbound_act_depth() -> usize {
    4
}

fn default_outbound_credential_header() -> String {
    "authorization".to_string()
}

fn default_outbound_credential_scheme() -> String {
    "Bearer".to_string()
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct OutboundDpopSchema {
    /// Existing provider URI or `file:` secret reference. Inline PEM is
    /// rejected and SBproxy never generates this key.
    key: String,
    /// Public-only JWK matching the referenced private key.
    jwk: serde_json::Value,
    /// Asymmetric signing algorithm accepted for RFC 9449 proofs.
    alg: OutboundDpopAlgorithmSchema,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
enum OutboundDpopAlgorithmSchema {
    ES256,
    ES384,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    EdDSA,
}

/// One Proxy-Wasm HTTP filter attached to an origin.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyWasmFilterAttachment {
    /// Stable hook type declared by an installed Proxy-Wasm bundle.
    #[serde(rename = "type")]
    pub type_name: String,
    /// Plugin configuration exposed through `proxy_get_buffer_bytes`.
    #[serde(default = "empty_json_object")]
    pub config: serde_json::Value,
    /// Optional origin-specific override for the bundle failure posture.
    #[serde(default)]
    pub failure_posture: Option<FailureMode>,
}

fn empty_json_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// A single origin config as it appears in YAML.
/// Plugin-specific fields are kept as `serde_json::Value` for deferred parsing.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// Either a single provider mapping (`type: api_key`, ...) or a
    /// list of two or more provider mappings tried in declared order
    /// with OR semantics: the first provider that accepts the request
    /// wins, and a request every provider rejects gets the first
    /// provider's denial with every provider's challenge merged onto
    /// it.
    #[serde(default, alias = "auth")]
    pub authentication: Option<serde_json::Value>,
    /// Policy entries (rate limit, WAF, IP filter, etc.) evaluated in order.
    #[serde(default)]
    pub policies: Vec<serde_json::Value>,
    /// Transform pipeline applied to request and response bodies.
    #[serde(default)]
    pub transforms: Vec<serde_json::Value>,
    /// Proxy-Wasm HTTP filters evaluated in declaration order.
    #[serde(default)]
    pub filters: Vec<ProxyWasmFilterAttachment>,
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
    /// RFC 9745 / RFC 8594 API deprecation announcement for the whole
    /// origin. Matching responses carry `Deprecation`, `Sunset`, and
    /// the `successor-version` / `deprecation` Link relations per what
    /// is configured; `/.well-known/openapi.json` marks the origin's
    /// operations `deprecated: true`. A forward rule's own
    /// `deprecation:` block overrides this one for the requests it
    /// matches. See [`DeprecationConfig`].
    #[serde(default)]
    pub deprecation: Option<DeprecationConfig>,
    /// Refused at config compile. Nothing ever read this block, and
    /// because it is an untyped value nothing ever validated it either:
    /// a typo inside it was indistinguishable from a correct setting.
    /// Live request mirroring is [`MirrorConfig`] under `mirror`.
    ///
    /// Retained as a parseable field so the failure names the
    /// replacement rather than reading as an unknown key.
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
    /// WOR-2673: IAB Content Authorization Marketplace Protocol (CoMP)
    /// bridge. When set, the proxy serves
    /// `/.well-known/iab-comp/{manifest.json,quote,redeem}` on this
    /// origin, so an AI buyer can read the licensing catalog, get a
    /// signed price, and redeem a paid acceptance for an OLP license
    /// token without any publisher-specific integration.
    ///
    /// Requires this origin's [`Self::olp`] block: the bridge mints
    /// with that issuer's signing key, so the token it hands back is
    /// one this same origin's `/.well-known/olp/introspect` verifies.
    #[serde(default)]
    pub comp: Option<CompMarketplaceConfig>,
    /// WOR-805 AC#4: opt in to publishing SBproxy's own Web Bot
    /// Auth signing-key directory at
    /// `/.well-known/http-message-signatures-directory` and the
    /// Signature Agent Card discovery doc. Verifiers that fetch
    /// the directory can then verify the signatures SBproxy attaches
    /// to outbound requests when the corresponding
    /// `MessageSignatureSigner` runs upstream of the proxy.
    #[serde(default)]
    pub web_bot_auth_publish: Option<WebBotAuthPublishConfig>,
    /// `Idempotency-Key` middleware, per
    /// `draft-ietf-httpapi-idempotency-key-header`. Opt in per origin to
    /// have the proxy short-circuit retries of POST/PUT/PATCH (or any
    /// configured method) carrying a repeated `Idempotency-Key`
    /// header. See [`IdempotencyConfig`].
    #[serde(default)]
    pub idempotency: Option<IdempotencyConfig>,
    /// Compatibility-only per-origin connection-pool shape, except for
    /// `idle_timeout_secs`, which is the legacy spelling of `timeouts.idle_ms`.
    /// Pingora's built-in pool settings apply regardless of the other values.
    #[serde(default)]
    pub connection_pool: Option<ConnectionPoolConfig>,
    /// Per-origin upstream transport deadlines (connect, read, write, idle).
    /// Absent fields resolve to the built-in defaults at config compile time.
    /// See [`UpstreamTimeoutsConfig`].
    #[serde(default)]
    pub timeouts: Option<UpstreamTimeoutsConfig>,
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
    /// [`crate::compile_origin`]. Recognized values: `markdown`,
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
    /// both honor the override. Unset falls back to
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
    #[schemars(with = "Option<OutboundCredentialSchema>")]
    pub outbound_credential: Option<serde_json::Value>,
    /// Opt this origin into outbound Web Bot Auth signing (WOR-805).
    /// When `true` and `proxy.web_bot_auth` is configured, the proxy
    /// signs the request it sends upstream with the proxy's Ed25519 key
    /// (RFC 9421, `tag=web-bot-auth`), so an upstream that demands Web
    /// Bot Auth accepts SBproxy as a verified agent. Default `false`.
    #[serde(default)]
    pub outbound_web_bot_auth: bool,
    /// Per-origin consumption attestation overrides (WOR-2127). Absent
    /// leaves the origin on the proxy-wide role with no agreement named.
    /// Authoring this block without a `proxy.attestation` block fails
    /// config compile: a per-origin role with no queue, ledger, or
    /// billing table behind it can never produce a record. See
    /// [`OriginAttestationConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<OriginAttestationConfig>,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct OriginObservabilityLogConfig {
    /// Scoped `decision_audit:` additions, composed per event label
    /// against the wider scopes rather than replacing them.
    ///
    /// The same shape as the proxy-scope block. Composition is per key,
    /// matching `custom_fields:`: a scope naming one event must not
    /// silence the events a wider scope turned on, because that would
    /// make enabling one tenant's routing audit quietly disable its
    /// cache audit. Precedence for a given event is origin, then
    /// tenant, then proxy, and an event no scope names is off.
    ///
    /// `enabled:` composes the same way: the most specific scope that
    /// sets it wins for the events nobody names explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_audit: Option<DecisionAuditConfig>,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// - A relative reference (`skills/foo.md`), which names the same
    ///   artifact as the path-absolute spelling and resolves the same
    ///   way.
    /// - A fully-qualified URL fetched once at config-load and
    ///   re-emitted verbatim in the manifest (the proxy does not
    ///   re-host external artifacts).
    ///
    /// The two re-hosted spellings resolve against the path prefix the
    /// serving surface answers on, not against the manifest's own
    /// directory: the bare path for this `agent_skills:` block, and
    /// `/.well-known/agent-skills/<listing>/` for the same entry shape
    /// under a Listing's `spec.skills[]`.
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
#[serde(deny_unknown_fields)]
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

impl CorsConfig {
    /// Whether this block asks for `allowed_origins: ["*"]` together with
    /// `allow_credentials: true`.
    ///
    /// Browsers refuse that pair per the Fetch standard, so the proxy
    /// refuses it too: the config compiler fails the load and the CORS
    /// middleware emits no headers if it ever sees one anyway. Both sides
    /// call this one predicate so the load-time refusal cannot end up
    /// narrower than the runtime one.
    pub fn wildcard_with_credentials(&self) -> bool {
        self.allow_credentials && self.allowed_origins.iter().any(|o| o == "*")
    }
}

/// HSTS configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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

/// Codec tokens `compression.algorithms` accepts, in the order the
/// negotiator falls back to when an origin lists none.
///
/// Anything outside this list fails config load rather than quietly
/// disabling compression for the origin.
pub const COMPRESSION_ALGORITHM_TOKENS: [&str; 3] = ["zstd", "br", "gzip"];

/// Compression configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompressionConfig {
    /// Master switch for response compression. Alias: `enable`.
    #[serde(default = "default_true", alias = "enable")]
    pub enabled: bool,
    /// Allowed algorithms in priority order (e.g. `["br", "gzip"]`). The
    /// first entry the client's `Accept-Encoding` accepts is the one
    /// served, so list your preferred codec first. Valid entries are
    /// `zstd`, `br`, and `gzip`; any other name fails config load. Leave
    /// the list empty to take the built-in order, best ratio first:
    /// `zstd`, then `br`, then `gzip`.
    #[serde(default)]
    pub algorithms: Vec<String>,
    /// Minimum response size, in bytes, before compression is applied.
    #[serde(default)]
    pub min_size: usize,
    /// Encoder effort setting, clamped into the negotiated algorithm's
    /// native range (gzip 0-9, brotli 0-11, zstd 1-22). Absent keeps each
    /// library's default.
    #[serde(default)]
    pub level: Option<u32>,
}

fn default_true() -> bool {
    true
}

/// Session configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
/// header, query, body, method) are ANDed; across entries they are ORed.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// RFC 9745 / RFC 8594 API deprecation announcement scoped to the
    /// requests this rule matches. Overrides the origin-level
    /// `deprecation:` block for them, so `/v1/*` can be deprecated
    /// while `/v2/*` on the same origin is not. See
    /// [`DeprecationConfig`].
    #[serde(default)]
    pub deprecation: Option<DeprecationConfig>,
}

/// An OpenAPI 3.0 Parameter Object declared on a forward rule.
///
/// Field names and shapes mirror the OpenAPI spec exactly so emission is a
/// direct passthrough. The `schema` field is kept as `serde_json::Value`
/// because the OpenAPI Schema Object is large and we forward it verbatim.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
/// Each entry may carry any combination of `path`, `header`, `query`,
/// `body`, and `method` matchers. Within a single entry the matchers are
/// ANDed: every present matcher must succeed for the entry to fire. Across
/// entries in the same rule the semantics are OR: any matching entry
/// triggers the rule. The shorthand `match: <prefix>` is equivalent to
/// `path: { prefix: ... }`.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// JSON request-body field matcher.
    #[serde(default)]
    pub body: Option<BodyMatcher>,
    /// HTTP method matcher. A single method or a list of them; the entry
    /// fires when the request method equals any listed one. Methods are
    /// normalized to uppercase at config-load time, so `post` and `POST`
    /// are the same matcher.
    #[serde(default)]
    pub method: Option<MethodSpec>,

    /// CEL predicate ANDed with the structured matchers above.
    ///
    /// Exists for the conditions the structured fields cannot express:
    /// OR, negation, and comparisons across two parts of the request.
    /// It is evaluated last, only once every structured matcher in the
    /// entry has already passed, so a rule that fails on a cheap path
    /// check never pays for it.
    ///
    /// The bindings available here are the request as it arrived, and
    /// nothing that a later pipeline pass produces. See
    /// `docs/scripting.md`.
    #[serde(default)]
    pub when: Option<String>,
}

/// HTTP method spec for a [`ForwardRuleMatcher`]. Either a single method
/// (`method: POST`) or a list (`method: [POST, PUT]`). Tokens are
/// normalized to uppercase when the matcher compiles, so `post` and `POST`
/// mean the same thing; an empty list or a token that is not a valid HTTP
/// method token fails config load.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum MethodSpec {
    /// Single HTTP method.
    Single(String),
    /// Multiple methods; any match counts.
    Multi(Vec<String>),
}

#[cfg(test)]
mod forward_rule_method_tests {
    use super::*;

    #[test]
    fn method_accepts_a_single_string() {
        let matcher: ForwardRuleMatcher =
            serde_json::from_value(serde_json::json!({"method": "POST"})).unwrap();
        assert!(matches!(
            matcher.method,
            Some(MethodSpec::Single(ref m)) if m == "POST"
        ));
    }

    #[test]
    fn method_accepts_a_list() {
        let matcher: ForwardRuleMatcher =
            serde_json::from_value(serde_json::json!({"method": ["GET", "POST"]})).unwrap();
        assert!(matches!(
            matcher.method,
            Some(MethodSpec::Multi(ref m)) if m == &["GET".to_string(), "POST".to_string()]
        ));
    }

    #[test]
    fn method_defaults_to_absent() {
        let matcher: ForwardRuleMatcher =
            serde_json::from_value(serde_json::json!({"match": "/api/"})).unwrap();
        assert!(matcher.method.is_none());
    }

    #[test]
    fn method_rejects_a_non_string_shape() {
        assert!(
            serde_json::from_value::<ForwardRuleMatcher>(serde_json::json!({"method": 7})).is_err()
        );
        assert!(serde_json::from_value::<ForwardRuleMatcher>(
            serde_json::json!({"method": {"name": "POST"}})
        )
        .is_err());
    }

    #[test]
    fn an_empty_list_parses_here_and_is_refused_at_compile() {
        // Serde accepts the shape; the compile step in the pipeline is what
        // rejects a list that could never match. This pins the split so the
        // rejection message stays a config-load error, not a parse error.
        let matcher: ForwardRuleMatcher =
            serde_json::from_value(serde_json::json!({"method": []})).unwrap();
        assert!(matches!(matcher.method, Some(MethodSpec::Multi(ref m)) if m.is_empty()));
    }

    #[test]
    fn unknown_matcher_keys_are_still_rejected() {
        // The Go-era plural `methods` stays an unknown key; the supported
        // field is singular `method`.
        let error =
            serde_json::from_value::<ForwardRuleMatcher>(serde_json::json!({"methods": ["GET"]}))
                .unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
    }
}

/// Match a request header by exact value or value prefix.
///
/// Exactly one of `value` or `prefix` should be set. When both are present
/// `value` wins (exact comparison). Header name matching is case-insensitive
/// per RFC 7230; value comparison is case-sensitive.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct QueryMatcher {
    /// Query parameter name (case-sensitive).
    pub name: String,
    /// Required exact value. When `None`, presence of the parameter is enough.
    #[serde(default)]
    pub value: Option<String>,
}

/// Default value and hard ceiling for `BodyMatcher::max_bytes`, in bytes.
///
/// 65536 is the size of the replay buffer the proxy fills when it reads a
/// request body during route selection. Bytes beyond it are not retained, so a
/// matcher configured to read further would be asking to inspect bytes that
/// cannot also be forwarded upstream. Config compilation refuses a larger
/// value rather than accepting one that silently cannot be honored.
pub const BODY_MATCH_MAX_BYTES: u64 = 65_536;

/// Match a field inside a JSON request body, addressed by RFC 6901 JSON Pointer.
///
/// This exists because the field an operator most wants to route on is often
/// in the body rather than the URL. `model`, `stream`, and `tools` are body
/// fields in the OpenAI, Anthropic, and Bedrock request shapes, so without
/// this matcher two models cannot be given different rate limits, different
/// upstream credentials, or different guardrail chains without collapsing
/// them onto one origin.
///
/// Exactly one of `value` or `prefix` should be set. When both are present
/// `value` wins (exact comparison). When neither is set the matcher succeeds
/// whenever the pointer resolves to any JSON value at all, including `null`,
/// an object, or an array, which is how you route on "this request uses
/// tools" without naming a tool.
///
/// Numbers and booleans are compared against their JSON text form, so
/// `pointer: /stream` with `value: "true"` matches `{"stream": true}`.
///
/// Selecting a route on a body field means the body has to be buffered before
/// the route is known, so this matcher is the one part of routing with a size
/// limit. `max_bytes` caps it, defaulting to 65536 and never exceeding it,
/// because 65536 is the fixed size of the replay buffer that lets the
/// buffered bytes still be forwarded upstream byte for byte.
///
/// Five things make this matcher miss rather than fail the request: a body
/// larger than `max_bytes`, a body that is not JSON, a body that does not
/// parse, a pointer that resolves to nothing, and a pointer that resolves to
/// an object or array while `value` or `prefix` asked for a scalar. In every
/// one of those cases the entry does not fire and routing carries on to the
/// next entry, then the next rule, then the origin's own action, which is the
/// same header-only routing that would have happened without the matcher.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BodyMatcher {
    /// RFC 6901 JSON Pointer to the field, for example `/model` or
    /// `/messages/0/role`. An empty pointer addresses the whole document.
    pub pointer: String,
    /// Required exact value.
    #[serde(default)]
    pub value: Option<String>,
    /// Required value prefix. Ignored when `value` is set.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Largest request body this matcher will read, in bytes. Defaults to
    /// 65536. Config compilation refuses a larger value.
    #[serde(default)]
    pub max_bytes: Option<u64>,
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
#[serde(deny_unknown_fields)]
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
/// optional request modifiers. Compatibility metadata fields remain parseable
/// but are not copied into the compiled child origin.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForwardRuleOrigin {
    /// Optional identifier used in metrics and logs.
    #[serde(default)]
    pub id: Option<String>,
    /// Compatibility-only hostname tag. The parent origin's hostname
    /// routes the request; this value is not consumed.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Compatibility-only workspace identifier; not consumed.
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// Compatibility-only version label; not consumed.
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
/// `method`, `body`, `lua_script`, `js_script`, or `rego_module` /
/// `rego_module_path`. Multiple modifier entries in the list are applied in
/// order.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// Optional inline Rego module for dynamic request modification
    /// (WOR-2482). The module's `data.sbproxy.modify_request` rule
    /// evaluates against the same document `lua_script` / `js_script`
    /// receive as `req` and `ctx`, merged into one `input`, and returns
    /// `{"set_headers": {...}}`, the same shape those scripts return.
    /// Mutually exclusive with `rego_module_path`. See
    /// `docs/scripting.md`.
    #[serde(default)]
    pub rego_module: Option<String>,
    /// Filesystem path to a `.rego` file, read once when the config
    /// compiles (and again on every reload), in place of an inline
    /// `rego_module`. Mutually exclusive with `rego_module`.
    #[serde(default)]
    pub rego_module_path: Option<String>,
    /// Rego only: evaluation budget in milliseconds. Defaults to 50, the
    /// same bound `policy: rego` and `ai_routing_policy`'s Rego form
    /// use. Must be greater than zero; a zero budget is refused at
    /// config compile.
    #[serde(default)]
    pub rego_budget_ms: Option<u64>,
    /// Parse `rego_module` (or the file at `rego_module_path`) as
    /// pre-OPA-1.0 Rego v0 (no `if`/`contains` required) instead of the
    /// v1 default. A compatibility escape hatch for a module pasted from
    /// an older OPA install.
    #[serde(default)]
    pub rego_v0: bool,
}

/// URL path rewrite configuration.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UrlModifier {
    /// Path rewrite rules.
    #[serde(default)]
    pub path: Option<PathRewrite>,
}

/// Path rewrite: replace a substring in the path.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathRewrite {
    /// Replace a substring in the path.
    #[serde(default)]
    pub replace: Option<PathReplace>,
}

/// A simple string-replace operation on the URL path.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathReplace {
    /// The substring to search for.
    pub old: String,
    /// The replacement string.
    pub new: String,
}

/// Query parameter modification operations.
#[derive(Debug, Clone, Deserialize, Serialize, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
/// Each modifier entry can contain one or more of: `headers`, `status`,
/// `body`, `lua_script`, `js_script`, or `rego_module` /
/// `rego_module_path`. Multiple modifier entries in the list are applied in
/// order.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseModifierConfig {
    /// Header set/add/remove operations.
    #[serde(default)]
    pub headers: Option<HeaderModifiers>,
    /// Override the response status code and, optionally via `text`, the
    /// HTTP/1.x reason phrase.
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
    /// Optional inline Rego module for dynamic response modification
    /// (WOR-2482). The module's `data.sbproxy.modify_response` rule
    /// evaluates against the same document `lua_script` / `js_script`
    /// receive as `resp` and `ctx`, merged into one `input`, and returns
    /// `{"set_headers": {...}}`, the same shape those scripts return.
    /// Mutually exclusive with `rego_module_path`. See
    /// `docs/scripting.md`.
    #[serde(default)]
    pub rego_module: Option<String>,
    /// Filesystem path to a `.rego` file, read once when the config
    /// compiles (and again on every reload), in place of an inline
    /// `rego_module`. Mutually exclusive with `rego_module`.
    #[serde(default)]
    pub rego_module_path: Option<String>,
    /// Rego only: evaluation budget in milliseconds. Defaults to 50, the
    /// same bound `policy: rego` and `ai_routing_policy`'s Rego form
    /// use. Must be greater than zero; a zero budget is refused at
    /// config compile.
    #[serde(default)]
    pub rego_budget_ms: Option<u64>,
    /// Parse `rego_module` (or the file at `rego_module_path`) as
    /// pre-OPA-1.0 Rego v0 (no `if`/`contains` required) instead of the
    /// v1 default. A compatibility escape hatch for a module pasted from
    /// an older OPA install.
    #[serde(default)]
    pub rego_v0: bool,
}

/// Status code override for response modifiers.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusOverride {
    /// The HTTP status code to set.
    pub code: u16,
    /// Custom reason phrase emitted on the HTTP/1.x status line. Absent
    /// means the canonical phrase for `code`. HTTP/2 has no reason phrase
    /// on the wire, so the value is ignored there.
    #[serde(default)]
    pub text: Option<String>,
}

/// Body replacement configuration for response modifiers.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
/// The live surface is [`SecretsConfig::backends`], selected by provider URI
/// references. The legacy single-backend and rotation fields remain parseable
/// for compatibility but are not consumed by the OSS runtime.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Legacy single-backend selector. Use [`SecretsConfig::backends`].
    #[serde(default = "default_secrets_backend")]
    pub backend: String,
    /// Legacy HashiCorp block. Declare a named `hashicorp` backend instead.
    #[serde(default)]
    pub hashicorp: Option<HashiCorpSecretsConfig>,
    /// Logical name to vault path mapping. INERT since the removal of
    /// the `secret:<name>` colon form it served (WOR-1785); still
    /// parsed for schema-v1 compatibility, and boot warns when set.
    /// Use `secret://<backend>/<name>` references instead.
    #[serde(default)]
    pub map: HashMap<String, String>,
    /// How resolved upstream credentials are re-read and how a failed
    /// re-read behaves. Consumed by the key plane (WOR-2327).
    #[serde(default)]
    pub rotation: Option<RotationConfig>,
    /// Legacy fallback selector; provider URI resolution fails loudly and does
    /// not consult this value.
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
#[serde(deny_unknown_fields)]
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
    /// Azure Key Vault, referenced as `azurekv://<name>/<secret>`.
    Azure {
        /// Backend name used in the `azurekv://<name>/...` reference.
        name: String,
        /// Key Vault URL, e.g. `https://acme-prod.vault.azure.net`.
        vault_url: String,
        /// Cache TTL in seconds for resolved reads.
        #[serde(default)]
        cache_ttl_secs: Option<u64>,
        /// Authentication method (defaults to managed identity).
        #[serde(default)]
        auth: AzureBackendAuth,
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
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
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

/// Redacted `Debug` (WOR-2640). This is the config-side twin of
/// `sbproxy_vault::HashiCorpAuth`, which was given a redacting `Debug`
/// while this one kept the derive, so the same Vault token and AppRole
/// `secret_id` were protected at runtime and printed at config load.
/// The load-time diagnostic is the likelier of the two to reach a log.
///
/// The role id, the role name, the JWT path and the mount all stay:
/// they name which auth method was tried and none of them
/// authenticates anything on its own. An AppRole `role_id` is
/// deliberately kept for the same reason Vault treats it as the
/// username half of the pair.
impl std::fmt::Debug for HashiCorpBackendAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token { .. } => f
                .debug_struct("Token")
                .field("token", &"[REDACTED]")
                .finish(),
            Self::Approle { role_id, mount, .. } => f
                .debug_struct("Approle")
                .field("role_id", role_id)
                .field("secret_id", &"[REDACTED]")
                .field("mount", mount)
                .finish(),
            Self::Kubernetes {
                role,
                jwt_path,
                mount,
            } => f
                .debug_struct("Kubernetes")
                .field("role", role)
                .field("jwt_path", jwt_path)
                .field("mount", mount)
                .finish(),
        }
    }
}

/// Authentication for an `aws` secret backend (WOR-1767).
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
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

/// Redacted `Debug` (WOR-2606). The config-side twin of
/// `sbproxy_vault::AwsAuth`, which has been redacted since the first
/// half of WOR-2640 while this one kept the derive: the same secret
/// access key and session token were protected at runtime and printed
/// at config load, and the load-time diagnostic is the likelier of the
/// two to reach a log.
///
/// The access key id, the role ARN, the external id and the session
/// name all stay. None authenticates anything on its own and each is
/// what tells one misconfigured backend from another. Presence rather
/// than a flat marker for the session token, because whether one was
/// supplied is what explains a 403.
impl std::fmt::Debug for AwsBackendAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaticKeys {
                access_key_id,
                session_token,
                ..
            } => f
                .debug_struct("StaticKeys")
                .field("access_key_id", access_key_id)
                .field("secret_access_key", &"[REDACTED]")
                .field(
                    "session_token",
                    &session_token.as_ref().map(|_| "[REDACTED]"),
                )
                .finish(),
            Self::DefaultChain => f.write_str("DefaultChain"),
            Self::AssumedRole {
                role_arn,
                external_id,
                session_name,
            } => f
                .debug_struct("AssumedRole")
                .field("role_arn", role_arn)
                .field("external_id", external_id)
                .field("session_name", session_name)
                .finish(),
        }
    }
}

/// Authentication for a `gcp` secret backend (WOR-1767). Externally tagged
/// to match the bare-string `application_default` default.
#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
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

/// Authentication for an `azure` secret backend. Externally tagged to
/// match the bare-string `managed_identity` default.
#[derive(Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum AzureBackendAuth {
    /// System-assigned managed identity (default).
    #[default]
    ManagedIdentity,
    /// User-assigned managed identity, selected by client id.
    UserAssignedIdentity {
        /// Client id of the user-assigned identity.
        client_id: String,
    },
    /// Service-principal client credentials.
    ServicePrincipal {
        /// Microsoft Entra tenant id.
        tenant_id: String,
        /// App registration client id.
        client_id: String,
        /// App registration client secret (may be `${ENV}`).
        client_secret: String,
        /// Optional authority host override for sovereign clouds.
        #[serde(default)]
        authority: Option<String>,
    },
    /// The logged-in Azure CLI (`az account get-access-token`).
    AzureCli,
}

/// Redacted `Debug` (WOR-2640). The config-side twin of
/// `sbproxy_vault::AzureKeyVaultAuth`, protected at runtime and
/// printed at config load until now. `client_secret` is an app
/// registration's credential; the tenant id, the client id and the
/// authority stay, because they are what tells one misconfigured
/// service principal from another and none is a secret.
impl std::fmt::Debug for AzureBackendAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManagedIdentity => f.write_str("ManagedIdentity"),
            Self::UserAssignedIdentity { client_id } => f
                .debug_struct("UserAssignedIdentity")
                .field("client_id", client_id)
                .finish(),
            Self::ServicePrincipal {
                tenant_id,
                client_id,
                authority,
                ..
            } => f
                .debug_struct("ServicePrincipal")
                .field("tenant_id", tenant_id)
                .field("client_id", client_id)
                .field("client_secret", &"[REDACTED]")
                .field("authority", authority)
                .finish(),
            Self::AzureCli => f.write_str("AzureCli"),
        }
    }
}

/// Authentication for a `k8s` secret backend (WOR-1767).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
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

/// Legacy HashiCorp Vault connection settings.
///
/// The OSS resolver consumes the `hashicorp` variant in
/// [`SecretsConfig::backends`], not this compatibility block.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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

/// Redacted `Debug` (WOR-2606). A second Vault client token beside the
/// `HashiCorpBackendAuth` already registered, in the legacy
/// compatibility block. Same value, same reach, same rule.
impl std::fmt::Debug for HashiCorpSecretsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashiCorpSecretsConfig")
            .field("addr", &self.addr)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("mount", &self.mount)
            .finish()
    }
}

/// Secret-rotation behavior for credentials the proxy resolves from a
/// backend and presents upstream.
///
/// Read at boot into `sbproxy_vault::RotationPolicy` and applied by the
/// key plane. Process-owned like the rest of `proxy.secrets`: a reload
/// that changes it is refused with a restart message.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RotationConfig {
    /// How long a resolved credential may still be served after
    /// re-resolution has **failed**, measured from the end of the
    /// re-resolve window. Defaults to 300 (5 minutes).
    ///
    /// This is availability, not credential overlap: the proxy presents
    /// upstream credentials rather than validating them, so it has no
    /// old-value acceptance window to honor. What this prevents is a
    /// briefly unreachable backend turning every request carrying a bound
    /// credential into a 503. A deleted or revoked credential is never
    /// served out of this window.
    #[serde(default = "default_grace")]
    pub grace_period_secs: u64,
    /// How long a resolved credential is served before the backend is
    /// consulted again. Defaults to 60, which is the value the key plane
    /// hardcoded before this block was consumed.
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
#[serde(deny_unknown_fields)]
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

/// API deprecation announcement for an origin or a forward rule.
///
/// When present, matching responses carry the standard deprecation
/// headers: `Deprecation` (RFC 9745, an RFC 9651 structured-field Date
/// such as `@1767225599`), `Sunset` (RFC 8594, an HTTP-date), and the
/// `successor-version` (RFC 5829) and `deprecation` (RFC 9745) Link
/// relations. A block at origin scope covers every route the origin
/// serves; a block on a forward rule covers only requests that rule
/// matches and overrides the origin block for them.
///
/// Specs: <https://www.rfc-editor.org/rfc/rfc9745.html>,
/// <https://www.rfc-editor.org/rfc/rfc8594.html>,
/// <https://www.rfc-editor.org/rfc/rfc5829.html>.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeprecationConfig {
    /// When the resource is (or will be) deprecated. A date
    /// (`2026-09-01`) or RFC 3339 timestamp (`2026-09-01T00:00:00Z`)
    /// emits `Deprecation: @<unix>`; past and future instants are both
    /// valid per RFC 9745. A bare `true` marks the route deprecated for
    /// OpenAPI emission and metrics but emits no `Deprecation` header,
    /// because RFC 9745 requires a Date value (the draft-era literal
    /// `true` did not survive into the RFC); config compile warns and
    /// suggests a date. `false` is refused: remove the block instead.
    #[serde(default)]
    pub deprecated: Option<DeprecatedStamp>,
    /// When the resource is expected to become unresponsive. A date or
    /// RFC 3339 timestamp; emits `Sunset: <HTTP-date>` per RFC 8594.
    /// Config compile refuses a sunset earlier than `deprecated`
    /// (RFC 9745 section 3: the Sunset timestamp MUST NOT be earlier
    /// than the Deprecation one).
    #[serde(default)]
    pub sunset: Option<String>,
    /// URL of the successor version of this resource. Emits
    /// `Link: <url>; rel="successor-version"` (RFC 5829).
    #[serde(default)]
    pub successor: Option<String>,
    /// URL of human-readable deprecation documentation. Emits
    /// `Link: <url>; rel="deprecation"` (RFC 9745).
    #[serde(default)]
    pub link: Option<String>,
    /// What happens to requests after the `sunset` instant passes.
    /// `serve` (the default) keeps handling them with the headers
    /// attached; `gone` refuses them with `410 Gone` and a JSON body
    /// naming the successor. Requires `sunset` to be set.
    #[serde(default)]
    pub after_sunset: AfterSunset,
}

/// The `deprecated:` field of a [`DeprecationConfig`]: either a bare
/// boolean or a date / RFC 3339 timestamp string.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum DeprecatedStamp {
    /// Bare `true` (deprecated, no announced instant) or `false`
    /// (refused at config compile).
    Flag(bool),
    /// The deprecation instant: `YYYY-MM-DD` (midnight UTC) or an
    /// RFC 3339 timestamp.
    Date(String),
}

/// Post-sunset posture for a [`DeprecationConfig`].
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AfterSunset {
    /// Keep serving requests, headers attached. The default, so a
    /// forgotten config never takes an API down by surprise.
    #[default]
    Serve,
    /// Refuse requests with `410 Gone` once the sunset instant passes.
    Gone,
}

/// Compiled form of a [`DeprecationConfig`]: instants parsed, header
/// values precomputed, so the response path stamps strings without
/// re-formatting per request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledDeprecation {
    /// Unix seconds of the deprecation instant. `None` for a bare
    /// `deprecated: true` (or a sunset-only block), which emits no
    /// `Deprecation` header.
    pub deprecated_at: Option<i64>,
    /// Unix seconds of the sunset instant. `None` when no `sunset:`
    /// is configured.
    pub sunset_at: Option<i64>,
    /// Precomputed `Deprecation` header value (`@<unix>`, RFC 9651
    /// structured-field Date per RFC 9745).
    pub deprecation_header: Option<String>,
    /// Precomputed `Sunset` header value (IMF-fixdate per RFC 8594).
    pub sunset_header: Option<String>,
    /// Successor-version URL, emitted as
    /// `Link: <url>; rel="successor-version"`.
    pub successor: Option<String>,
    /// Deprecation-documentation URL, emitted as
    /// `Link: <url>; rel="deprecation"`.
    pub link: Option<String>,
    /// When true, requests after the sunset instant get `410 Gone`.
    pub gone_after_sunset: bool,
}

/// Parse a config-authored instant: `YYYY-MM-DD` (midnight UTC) or an
/// RFC 3339 timestamp. Returns unix seconds.
fn parse_config_instant(field: &str, value: &str) -> anyhow::Result<i64> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(value) {
        return Ok(dt.timestamp());
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        let midnight = date
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| anyhow::anyhow!("{field}: {value:?} has no midnight"))?;
        return Ok(midnight.and_utc().timestamp());
    }
    anyhow::bail!(
        "{field}: {value:?} is not a date (YYYY-MM-DD) or RFC 3339 timestamp (YYYY-MM-DDTHH:MM:SSZ)"
    )
}

/// Format unix seconds as an RFC 9110 IMF-fixdate (the `Sunset` wire
/// form RFC 8594 requires), e.g. `Wed, 31 Dec 2025 23:59:59 GMT`.
fn format_http_date(unix: i64) -> anyhow::Result<String> {
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(unix, 0)
        .ok_or_else(|| anyhow::anyhow!("timestamp {unix} is out of range for an HTTP-date"))?;
    Ok(dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
}

/// Refuse Link-relation URLs that would corrupt the header framing.
fn check_link_url(field: &str, scope: &str, url: &str) -> anyhow::Result<()> {
    if url.is_empty() || url.contains(['<', '>', '"']) || url.contains(char::is_whitespace) {
        anyhow::bail!(
            "deprecation.{field} for {scope} must be a URL without whitespace or angle brackets; got {url:?}"
        );
    }
    Ok(())
}

/// Compile a [`DeprecationConfig`] block: parse the instants, refuse
/// the combinations the RFCs rule out, and precompute the header
/// strings. `scope` names the origin or forward rule in errors.
///
/// Refusals, each with a named reason:
/// - an unparseable `deprecated:` or `sunset:` value,
/// - `deprecated: false` (remove the block instead),
/// - a `sunset` earlier than the `deprecated` instant (RFC 9745
///   section 3 MUST NOT),
/// - `after_sunset: gone` without a `sunset:` to pass,
/// - a block that sets neither `deprecated` nor `sunset`.
///
/// A bare `deprecated: true` compiles, but emits no `Deprecation`
/// header because RFC 9745 requires an RFC 9651 Date value and the
/// draft-era literal `true` did not survive into the RFC. Config
/// compile pairs this function with [`warn_dateless_deprecated`] so
/// the operator hears about the dateless form once per load.
pub fn compile_deprecation(
    raw: &DeprecationConfig,
    scope: &str,
) -> anyhow::Result<CompiledDeprecation> {
    let deprecated_at = match &raw.deprecated {
        None => None,
        Some(DeprecatedStamp::Flag(false)) => {
            anyhow::bail!(
                "deprecation.deprecated for {scope} is `false`; remove the `deprecation:` block instead of disabling it in place"
            );
        }
        // The bare flag compiles (it still drives OpenAPI emission and
        // metrics) but announces no instant; config compile calls
        // [`warn_dateless_deprecated`] so the operator hears about it
        // once per load rather than once per spec emission.
        Some(DeprecatedStamp::Flag(true)) => None,
        Some(DeprecatedStamp::Date(value)) => Some(parse_config_instant(
            &format!("deprecation.deprecated for {scope}"),
            value,
        )?),
    };

    let sunset_at = raw
        .sunset
        .as_deref()
        .map(|value| parse_config_instant(&format!("deprecation.sunset for {scope}"), value))
        .transpose()?;

    if raw.deprecated.is_none() && sunset_at.is_none() {
        anyhow::bail!(
            "deprecation block for {scope} sets neither `deprecated` nor `sunset`; nothing would be announced"
        );
    }
    if let (Some(dep), Some(sun)) = (deprecated_at, sunset_at) {
        if sun < dep {
            anyhow::bail!(
                "deprecation.sunset for {scope} is earlier than deprecation.deprecated; RFC 9745 section 3 forbids a Sunset timestamp before the Deprecation one"
            );
        }
    }
    if raw.after_sunset == AfterSunset::Gone && sunset_at.is_none() {
        anyhow::bail!(
            "deprecation.after_sunset for {scope} is `gone` but no `sunset:` is configured; the posture could never take effect"
        );
    }
    if let Some(url) = raw.successor.as_deref() {
        check_link_url("successor", scope, url)?;
    }
    if let Some(url) = raw.link.as_deref() {
        check_link_url("link", scope, url)?;
    }

    Ok(CompiledDeprecation {
        deprecated_at,
        sunset_at,
        deprecation_header: deprecated_at.map(|ts| format!("@{ts}")),
        sunset_header: sunset_at.map(format_http_date).transpose()?,
        successor: raw.successor.clone(),
        link: raw.link.clone(),
        gone_after_sunset: raw.after_sunset == AfterSunset::Gone,
    })
}

/// Warn once about a bare `deprecated: true` in a [`DeprecationConfig`].
///
/// Called at config compile (never on the emission or request paths,
/// which re-run [`compile_deprecation`] freely): the dateless form is
/// legal but emits no `Deprecation` header, because RFC 9745 requires
/// an RFC 9651 Date value, and an operator who wrote `true` expecting
/// the draft-era literal deserves to hear why the header is missing.
pub fn warn_dateless_deprecated(raw: &DeprecationConfig, scope: &str) {
    if matches!(raw.deprecated, Some(DeprecatedStamp::Flag(true))) {
        tracing::warn!(
            scope = %scope,
            "deprecation.deprecated is a bare `true`: no `Deprecation` header will be emitted, because RFC 9745 requires a date value (`Deprecation: @<unix>`); set a date, e.g. `deprecated: 2026-09-01`"
        );
    }
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// `Idempotency-Key` middleware configuration, per
/// `draft-ietf-httpapi-idempotency-key-header`.
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
#[serde(deny_unknown_fields)]
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
    /// How long the request that took an idempotency key holds it
    /// before another request may take it over, in seconds. Defaults
    /// to 60.
    ///
    /// This is the bound on how long a request that died mid-flight can
    /// wedge one key, and nothing else. Raise it above the slowest
    /// response this origin produces: a lease that runs out while its
    /// owner is still working lets a retry through to the upstream,
    /// which is the duplicate call the middleware exists to prevent.
    /// An origin fronting an AI completion or a payment with a 3DS
    /// step-up wants a larger value. Lowering it makes a crashed
    /// request's key free sooner and makes duplicates more likely; a
    /// request that ends cleanly releases its key immediately either
    /// way, so the lease only governs the requests that did not.
    ///
    /// A response is stored under `ttl_secs`, which is hours, not under
    /// this. The two lifetimes are unrelated: an upstream slower than
    /// the lease still caches its response.
    ///
    /// Zero is refused at config-validate time rather than silently
    /// normalized, because a zero lease expires the instant it is taken
    /// and would turn single-flight off without saying so.
    #[serde(default)]
    pub claim_lease_secs: Option<u64>,
    /// How long an overlapping request waits for the key holder's
    /// response before answering 409 `ledger.idempotency_in_flight`, in
    /// milliseconds. Defaults to 3000.
    ///
    /// A retry that arrives while the original request is still running
    /// waits this long and then replays the original's response, so the
    /// client sees its answer rather than an error. Set it to 0 to
    /// answer 409 immediately, which is the floor
    /// `draft-ietf-httpapi-idempotency-key-header` describes. Raising
    /// it past the client's own timeout buys nothing: the client gives
    /// up first and the wait is abandoned.
    ///
    /// A waiting request holds a slot in a pool sized by
    /// `max_concurrent_buffers`, separate from the buffering pool, so a
    /// long wait cannot spend the slots other keys need.
    #[serde(default)]
    pub claim_wait_ms: Option<u64>,
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

    // --- proxy.zone resolution (WOR-2328) ---
    //
    // Driven through the pure precedence core rather than the
    // env-reading wrapper so no test mutates the process environment.

    #[test]
    fn zone_resolution_prefers_config_over_env() {
        assert_eq!(
            ProxyServerConfig::resolve_zone_from(Some("us-east-1a"), Some("us-west-2a")),
            Some("us-east-1a".to_string()),
            "a config that states its zone must never be re-zoned by SB_ZONE"
        );
    }

    #[test]
    fn zone_resolution_falls_back_to_env() {
        assert_eq!(
            ProxyServerConfig::resolve_zone_from(None, Some("us-west-2a")),
            Some("us-west-2a".to_string())
        );
        assert_eq!(
            ProxyServerConfig::resolve_zone_from(Some("   "), Some("us-west-2a")),
            Some("us-west-2a".to_string()),
            "a blank proxy.zone counts as unset"
        );
    }

    #[test]
    fn zone_resolution_trims_and_treats_blank_as_unset() {
        assert_eq!(
            ProxyServerConfig::resolve_zone_from(Some(" us-east-1a "), None),
            Some("us-east-1a".to_string())
        );
        assert_eq!(ProxyServerConfig::resolve_zone_from(None, Some("  ")), None);
        assert_eq!(ProxyServerConfig::resolve_zone_from(None, None), None);
    }

    #[test]
    fn proxy_zone_parses_and_defaults_to_none() {
        let proxy: ProxyServerConfig = serde_yaml::from_str("zone: eu-central-1a").unwrap();
        assert_eq!(proxy.zone.as_deref(), Some("eu-central-1a"));
        assert!(ProxyServerConfig::default().zone.is_none());
    }

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

    #[test]
    fn decision_audit_is_absent_when_the_operator_does_not_ask_for_it() {
        let yaml = r#"
log:
  level: info
"#;
        let obs: ObservabilityConfig = serde_yaml::from_str(yaml).unwrap();
        let log = obs.log.expect("log block parses");
        assert!(
            log.decision_audit.is_none(),
            "a log block that never mentions decision_audit must not synthesize one; the audit \
             feed stays off until somebody asks for it"
        );
    }

    #[test]
    fn decision_audit_parses_a_per_event_toggle() {
        let yaml = r#"
log:
  decision_audit:
    enabled: true
    events:
      cache.admit: true
"#;
        let obs: ObservabilityConfig = serde_yaml::from_str(yaml).unwrap();
        let audit = obs
            .log
            .expect("log block parses")
            .decision_audit
            .expect("decision_audit block parses");
        assert_eq!(audit.enabled, Some(true));
        assert_eq!(audit.events.get("cache.admit"), Some(&true));
    }

    /// An unset master switch parses as `None`, not `Some(false)`. Both
    /// resolve to off today, since proxy is the only scope that accepts
    /// the block and there is no parent to inherit from. The
    /// distinction is kept in the type because it is what a later
    /// tenant/origin slice needs: `None` inherits and `Some(false)`
    /// overrides, the same shape `ObservabilityPiiConfig::enabled`
    /// carries.
    #[test]
    fn decision_audit_leaves_an_unset_master_switch_as_none() {
        let yaml = r#"
log:
  decision_audit:
    events:
      cache.admit: true
"#;
        let obs: ObservabilityConfig = serde_yaml::from_str(yaml).unwrap();
        let audit = obs
            .log
            .expect("log block parses")
            .decision_audit
            .expect("decision_audit block parses");
        assert_eq!(audit.enabled, None);
    }

    /// Parse a proxy-scoped `decision_audit` block out of a `log:` YAML
    /// fragment, the way the neighboring parse tests do. Going through
    /// serde rather than building the struct by hand keeps these tests
    /// on the operator's surface: a field renamed in the schema fails
    /// them here rather than passing against a literal nobody writes.
    fn parse_decision_audit(yaml: &str) -> DecisionAuditConfig {
        let obs: ObservabilityConfig = serde_yaml::from_str(yaml).unwrap();
        obs.log
            .expect("log block parses")
            .decision_audit
            .expect("decision_audit block parses")
    }

    /// No block at all publishes nothing. Asserted through the same
    /// `Option` shape the request path uses (`audit_publishes` in
    /// `sbproxy-core`), because that is where the absent case is
    /// decided: `publishes` is never reached, so a permissive default
    /// could only arrive by a caller writing `unwrap_or_default()`
    /// there.
    #[test]
    fn decision_audit_absent_block_publishes_nothing() {
        let audit: Option<DecisionAuditConfig> = None;
        assert!(
            !audit
                .as_ref()
                .is_some_and(|cfg| cfg.publishes("cache.admit")),
            "a config with no decision_audit block must publish no records"
        );
    }

    /// An unset master switch with an empty `events` map is off. This is
    /// the shape a config lands in after somebody deletes the last
    /// per-event entry, and it must not read as "everything".
    #[test]
    fn decision_audit_unset_master_switch_publishes_nothing() {
        let audit = parse_decision_audit(
            r#"
log:
  decision_audit: {}
"#,
        );
        assert_eq!(audit.enabled, None);
        assert!(
            !audit.publishes("cache.admit"),
            "an unset master switch with no per-event entry is off"
        );
    }

    /// `enabled: true` with no `events:` map turns on every event the
    /// map does not name, with exactly one exception: `ai.stream.event`
    /// fires once per streamed chunk and is off by construction. The
    /// exception is the reason `publishes` refuses the label itself
    /// rather than leaving it to the load-time validator, which only
    /// ever sees the `events` map and so cannot see this config at all.
    #[test]
    fn decision_audit_master_switch_spares_the_per_chunk_stream_event() {
        let audit = parse_decision_audit(
            r#"
log:
  decision_audit:
    enabled: true
"#,
        );
        assert!(
            audit.events.is_empty(),
            "the fixture must exercise the master switch alone"
        );
        assert!(
            audit.publishes("cache.admit"),
            "the master switch turns on an event the map does not name"
        );
        assert!(
            audit.publishes("ai.close"),
            "the stream summary event is a normal event under the master switch"
        );
        assert!(
            !audit.publishes("ai.stream.event"),
            "the per-chunk stream event must stay off under the master switch; \
             `ai.close` carries the summary instead"
        );
    }

    /// A per-event `true` wins over a `false` master switch, and turns
    /// on only the event it names.
    #[test]
    fn decision_audit_per_event_true_beats_a_false_master_switch() {
        let audit = parse_decision_audit(
            r#"
log:
  decision_audit:
    enabled: false
    events:
      cache.admit: true
"#,
        );
        assert!(
            audit.publishes("cache.admit"),
            "the per-event entry wins over the master switch"
        );
        assert!(
            !audit.publishes("route.decide"),
            "an event the map does not name follows the master switch, which is off"
        );
    }

    /// And a per-event `false` wins over a `true` master switch, so the
    /// override works in both directions rather than only as an opt-in.
    #[test]
    fn decision_audit_per_event_false_beats_a_true_master_switch() {
        let audit = parse_decision_audit(
            r#"
log:
  decision_audit:
    enabled: true
    events:
      cache.admit: false
"#,
        );
        assert!(
            !audit.publishes("cache.admit"),
            "the per-event entry silences the event the master switch would have turned on"
        );
        assert!(
            audit.publishes("route.decide"),
            "silencing one event must not silence the rest"
        );
    }

    /// Writing the per-chunk event's `false` down is legal and answers
    /// the same way the refusal does. An operator recording that a feed
    /// is off should not get a different answer from one who never
    /// mentioned it.
    #[test]
    fn decision_audit_explicit_stream_event_false_stays_off() {
        let audit = parse_decision_audit(
            r#"
log:
  decision_audit:
    enabled: true
    events:
      ai.stream.event: false
"#,
        );
        assert!(
            !audit.publishes("ai.stream.event"),
            "an explicitly silenced per-chunk feed stays silent"
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
    /// and existing single-tenant configs see no behavior change.
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
    /// who never wrote a sinks block keeps the legacy stdout behavior.
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
        // behavior (CLI / env only).
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

    /// `Default` has to agree with serde on the one live field.
    /// `resolve_upstream_timeouts` reads
    /// `ConnectionPoolConfig::default().idle_timeout_secs` to decide
    /// whether an authored value conflicts with `timeouts.idle_ms`, so a
    /// derived `Default` putting `0` here would turn every authored idle
    /// value into a spurious conflict error.
    #[test]
    fn connection_pool_default_idle_matches_the_serde_default() {
        let from_impl = ConnectionPoolConfig::default();
        let from_serde: ConnectionPoolConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(from_impl.idle_timeout_secs, 90);
        assert_eq!(from_serde.idle_timeout_secs, 90);
        assert_eq!(from_impl.idle_timeout_secs, from_serde.idle_timeout_secs);
    }

    /// The two refused fields are absent unless authored, which is what
    /// lets the compiler tell "operator set this" from "operator left it
    /// out" and refuse only the former.
    #[test]
    fn connection_pool_refused_fields_are_none_when_unset() {
        let cfg: ConnectionPoolConfig = serde_yaml::from_str("idle_timeout_secs: 30").unwrap();
        assert_eq!(cfg.idle_timeout_secs, 30);
        assert!(cfg.max_connections.is_none());
        assert!(cfg.max_lifetime_secs.is_none());
    }

    /// They still parse. Refusal is the compiler's job, and it needs the
    /// authored value to exist so the diagnostic can be specific.
    #[test]
    fn connection_pool_refused_fields_still_parse_when_authored() {
        let yaml = r#"
max_connections: 64
idle_timeout_secs: 30
max_lifetime_secs: 120
"#;
        let cfg: ConnectionPoolConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.max_connections, Some(64));
        assert_eq!(cfg.idle_timeout_secs, 30);
        assert_eq!(cfg.max_lifetime_secs, Some(120));
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
        assert_eq!(pool.max_connections, Some(32));
        assert_eq!(pool.idle_timeout_secs, 45);
        assert!(pool.max_lifetime_secs.is_none());
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

    // --- UpstreamTimeoutsConfig tests ---

    #[test]
    fn upstream_timeouts_deserialize_empty_is_all_unset() {
        let yaml = r#"{}"#;
        let cfg: UpstreamTimeoutsConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.connect_ms.is_none());
        assert!(cfg.total_connect_ms.is_none());
        assert!(cfg.read_ms.is_none());
        assert!(cfg.write_ms.is_none());
        assert!(cfg.idle_ms.is_none());
    }

    #[test]
    fn upstream_timeouts_deserialize_explicit() {
        let yaml = r#"
connect_ms: 1000
total_connect_ms: 2000
read_ms: 3000
write_ms: 4000
idle_ms: 5000
"#;
        let cfg: UpstreamTimeoutsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.connect_ms, Some(1000));
        assert_eq!(cfg.total_connect_ms, Some(2000));
        assert_eq!(cfg.read_ms, Some(3000));
        assert_eq!(cfg.write_ms, Some(4000));
        assert_eq!(cfg.idle_ms, Some(5000));
    }

    #[test]
    fn upstream_timeouts_partial_deserialize() {
        let yaml = r#"read_ms: 120000"#;
        let cfg: UpstreamTimeoutsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.read_ms, Some(120_000));
        assert!(cfg.connect_ms.is_none());
        assert!(cfg.total_connect_ms.is_none());
        assert!(cfg.write_ms.is_none());
        assert!(cfg.idle_ms.is_none());
    }

    #[test]
    fn upstream_timeouts_rejects_unknown_keys() {
        let yaml = r#"connect_timeout_ms: 1000"#;
        let result: Result<UpstreamTimeoutsConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "misspelled key must not parse");
    }

    #[test]
    fn upstream_timeouts_resolved_defaults_match_the_consts() {
        let resolved = UpstreamTimeouts::default();
        assert_eq!(
            resolved.connect,
            Duration::from_millis(DEFAULT_UPSTREAM_CONNECT_TIMEOUT_MS)
        );
        assert_eq!(
            resolved.total_connect,
            Duration::from_millis(DEFAULT_UPSTREAM_TOTAL_CONNECT_TIMEOUT_MS)
        );
        assert_eq!(
            resolved.read,
            Duration::from_millis(DEFAULT_UPSTREAM_READ_TIMEOUT_MS)
        );
        assert_eq!(
            resolved.write,
            Duration::from_millis(DEFAULT_UPSTREAM_WRITE_TIMEOUT_MS)
        );
        assert_eq!(
            resolved.idle,
            Duration::from_millis(DEFAULT_UPSTREAM_IDLE_TIMEOUT_MS)
        );
    }

    #[test]
    fn origin_config_with_timeouts() {
        let yaml = r#"
action:
  type: proxy
  url: "http://upstream.internal"
timeouts:
  connect_ms: 2500
  read_ms: 60000
"#;
        let origin: RawOriginConfig = serde_yaml::from_str(yaml).unwrap();
        let timeouts = origin.timeouts.expect("timeouts should be set");
        assert_eq!(timeouts.connect_ms, Some(2500));
        assert_eq!(timeouts.read_ms, Some(60_000));
        assert!(timeouts.idle_ms.is_none());
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
  - type: azure
    name: azure1
    vault_url: https://acme-prod.vault.azure.net
    auth: managed_identity
  - type: azure
    name: azure2
    vault_url: https://acme-ci.vault.azure.net
    auth:
      service_principal:
        tenant_id: my-tenant
        client_id: my-app
        client_secret: "${AZURE_CLIENT_SECRET}"
  - type: k8s
    name: k8s1
    namespace: apps
    auth:
      type: in_cluster
"#;
        let cfg: SecretsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.backends.len(), 6);
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
        match &cfg.backends[3] {
            SecretBackendConfig::Azure {
                name,
                vault_url,
                auth,
                ..
            } => {
                assert_eq!(name, "azure1");
                assert_eq!(vault_url, "https://acme-prod.vault.azure.net");
                assert!(matches!(auth, AzureBackendAuth::ManagedIdentity));
            }
            other => panic!("expected azure backend, got {other:?}"),
        }
        match &cfg.backends[4] {
            SecretBackendConfig::Azure { auth, .. } => match auth {
                AzureBackendAuth::ServicePrincipal {
                    tenant_id,
                    client_id,
                    client_secret,
                    authority,
                } => {
                    assert_eq!(tenant_id, "my-tenant");
                    assert_eq!(client_id, "my-app");
                    assert_eq!(client_secret, "${AZURE_CLIENT_SECRET}");
                    assert!(authority.is_none());
                }
                other => panic!("expected service-principal auth, got {other:?}"),
            },
            other => panic!("expected azure backend, got {other:?}"),
        }
        assert!(matches!(
            &cfg.backends[5],
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
        // The fixture used to be `rotation: {}`, which only parsed as a
        // `RotationConfig` because serde dropped the unknown `rotation`
        // wrapper key. With `deny_unknown_fields` the struct parses the
        // block's contents, so the fixture is the empty block itself.
        let cfg: RotationConfig = serde_yaml::from_str("{}").unwrap();
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
    custom_metadata:
      enabled: true
origins: {}
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).expect("parse");
        let ext = cfg.proxy.extensions;
        assert!(ext.contains_key("classifier"), "classifier ext present");
        assert!(
            ext.contains_key("custom_metadata"),
            "custom_metadata ext present"
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
        // Per-origin extensions live in a sibling opaque map that nothing
        // in this workspace inspects. The map keeps arbitrary nested
        // shapes intact for whoever reads it.
        let yaml = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: http://localhost:3000
    extensions:
      custom_metadata:
        enabled: true
        ttl_secs: 1200
        label: "{team}:{tier}"
"#;
        let cfg: ConfigFile = serde_yaml::from_str(yaml).expect("parse");
        let origin = &cfg.origins["api.example.com"];
        let custom = origin
            .extensions
            .get("custom_metadata")
            .expect("custom_metadata extension parsed");
        assert!(custom.get("enabled").unwrap().as_bool().unwrap());
        assert_eq!(custom.get("ttl_secs").unwrap().as_u64().unwrap(), 1200);
        assert_eq!(
            custom.get("label").unwrap().as_str().unwrap(),
            "{team}:{tier}"
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
/// `algorithm` is `hmac_sha256`, `ed25519`, or `ecdsa_p256_sha256`.
/// `key` carries the shared secret (HMAC), the base64/hex-encoded
/// raw 32-byte public key (Ed25519), or the base64/hex-encoded
/// uncompressed SEC1 public point of 65 bytes (ECDSA P-256).
/// `required_components` is the optional set of canonical components
/// every accepted signature must cover. `clock_skew_seconds`
/// defaults to 30s.
///
/// A signature that covers `content-digest` also has its body
/// checked: the proxy buffers the request body, recomputes the
/// digest, and rejects a mismatch. The body must fit the 64 KiB
/// replay buffer, and a larger one is rejected rather than passed
/// unverified.
///
/// Spec: <https://www.rfc-editor.org/rfc/rfc9421.html>.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageSignaturesConfig {
    /// Whether to enforce signature verification on inbound requests.
    #[serde(default)]
    pub verify: bool,
    /// Required signature algorithm (`hmac_sha256`, `ed25519`, or
    /// `ecdsa_p256_sha256`).
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
/// - `POST /.well-known/olp/token` issues a license token signed
///   with the configured Ed25519 key, body shaped per RFC 6749
///   (`access_token` + `token_type: "License"` + `expires_in`).
/// - `GET /.well-known/olp/key` publishes the verification JWK
///   set (RFC 7517) so external introspectors can verify tokens
///   without contacting the issuer per-token.
///
/// WOR-805 AC#4: Web Bot Auth publish config. When enabled the
/// proxy serves two unauthenticated well-known endpoints on this
/// origin:
///
/// * `GET /.well-known/http-message-signatures-directory`: JWKS
///   document carrying SBproxy's own Ed25519 signing-key public
///   key. Verifiers (Cloudflare, AWS WAF, any third-party origin
///   that runs a Web Bot Auth verifier) fetch this to verify the
///   `Signature-Input` + `Signature` headers SBproxy attaches to
///   outbound requests.
/// * `GET /.well-known/web-bot-auth/agent-card`: the discovery
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
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
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
    /// secret-resolver pass honors secret references at config load
    /// so the raw seed never has to live in the YAML.
    #[serde(default)]
    pub signing_key_hex: Option<String>,
}

/// Redacted `Debug` (WOR-2606). `signing_key_hex` is a 32-byte Ed25519
/// *private* seed. Anything that reads it signs directory and agent
/// card responses that every Web Bot Auth verifier will accept as this
/// operator's, which is the whole trust loop the block exists to close.
///
/// The key id, the *public* key, the agent name and the directory URL
/// all stay: they are published on purpose, and they are what names the
/// deployment a diagnostic is about.
impl std::fmt::Debug for WebBotAuthPublishConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebBotAuthPublishConfig")
            .field("enabled", &self.enabled)
            .field("key_id", &self.key_id)
            .field("public_key_hex", &self.public_key_hex)
            .field("agent_name", &self.agent_name)
            .field("directory_url", &self.directory_url)
            .field("description", &self.description)
            .field("contact_url", &self.contact_url)
            .field(
                "signing_key_hex",
                &self.signing_key_hex.as_ref().map(|_| "[REDACTED]"),
            )
            .finish_non_exhaustive()
    }
}

/// `/introspect` (RFC 7662) is deferred to a follow-up PR because
/// it requires a revocation / nonce store.
#[derive(Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OlpConfig {
    /// Master toggle. When false the well-known endpoints 404.
    #[serde(default)]
    pub enabled: bool,
    /// Ed25519 signing key, hex-encoded 32-byte seed. Operators
    /// generate one with `openssl rand -hex 32` or read it from a
    /// secret store. The secret-resolver pass honors provider-specific
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

    /// Tokens one source IP may mint per minute at
    /// `POST /.well-known/olp/token`. Defaults to 60.
    ///
    /// That endpoint is unauthenticated by design: an RSL crawler
    /// following a `WWW-Authenticate: License` challenge has no
    /// credential yet, and a request carrying no `client_credentials`
    /// form falls back to an anonymous `sub`. Every call mints a fresh
    /// Ed25519-signed bearer license token. Without a bound, one source
    /// mints them at whatever rate the CPU allows, and the endpoint
    /// answers before authentication and before the policy chain where
    /// an origin's own rate limits live, so nothing else on the request
    /// path sees it (WOR-2673).
    ///
    /// The budget is a token bucket keyed on the **raw socket peer**,
    /// not `X-Forwarded-For`. On an unauthenticated endpoint a
    /// forgeable header is not an identity: a caller that picks a new
    /// `X-Forwarded-For` per request would get a fresh full bucket
    /// every time and grow the tracking map while doing it. A
    /// deployment behind a load balancer therefore budgets the balancer,
    /// which is the honest reading of who the proxy is actually talking
    /// to.
    ///
    /// This value is both the burst and the steady-state rate: the
    /// bucket holds this many tokens and refills at one sixtieth of it
    /// per second, the same shape
    /// [`OlpIntrospectConfig`]'s inactive-response limiter uses.
    ///
    /// `0` is refused at config compile. There is deliberately no
    /// "unlimited" setting: an unauthenticated mint endpoint whose
    /// bound is one typo away from being off is not bounded.
    #[serde(default = "default_olp_token_rate_limit_per_minute")]
    pub token_rate_limit_per_minute: u32,
}

/// Default for [`OlpConfig::token_rate_limit_per_minute`].
///
/// Sixty per minute, so a well-behaved crawler minting one token per
/// license and caching it for the token's TTL is never near the bound,
/// and a client looping the endpoint is cut to roughly one mint per
/// second. Matches `INTROSPECT_CAPACITY` on the sibling limiter so an
/// operator reading both sees one number.
fn default_olp_token_rate_limit_per_minute() -> u32 {
    60
}

/// Redacted `Debug` (WOR-2606). Two seeds. `signing_key` is a
/// hex-encoded 32-byte Ed25519 seed resolved from a secret store at
/// config load, and every license token the proxy mints is signed with
/// it: reading it mints tokens the verifier accepts. `content_key_seed`
/// is the HKDF input every per-token AES-256-GCM content key is derived
/// from, so reading it decrypts every EMS payload the deployment has
/// ever issued a token for, past ones included.
///
/// The `kid`, the issuer, and the default scope all stay: they are
/// advertised in the JWS header and the well-known document and they
/// name the deployment a load error is about. Curated and
/// `finish_non_exhaustive`, so a key-shaped field added to this block
/// later is absent rather than printed.
impl std::fmt::Debug for OlpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OlpConfig")
            .field("enabled", &self.enabled)
            .field("signing_key", &"[REDACTED]")
            .field("key_id", &self.key_id)
            .field("issuer", &self.issuer)
            .field(
                "token_rate_limit_per_minute",
                &self.token_rate_limit_per_minute,
            )
            .field("default_scope", &self.default_scope)
            .field(
                "content_key_seed",
                &self.content_key_seed.as_ref().map(|_| "[REDACTED]"),
            )
            .finish_non_exhaustive()
    }
}

/// WOR-2673: IAB Content Authorization Marketplace Protocol (CoMP)
/// bridge, on a per-origin basis.
///
/// CoMP is the discovery-and-purchase front door to the license tokens
/// the origin's `olp:` block already issues. It publishes a signed
/// catalog of licensing tiers, prices a buyer's requested volume into a
/// signed quote, and converts a signed, paid acceptance of that quote
/// into an OLP license token. Three well-known endpoints:
///
/// * `GET  /.well-known/iab-comp/manifest.json`
/// * `POST /.well-known/iab-comp/quote`
/// * `POST /.well-known/iab-comp/redeem`
///
/// YAML key: `origins.<host>.comp`. See `docs/comp-marketplace.md`.
///
/// The bridge does not carry its own OLP issuer. It signs the license
/// token it returns with the same key `origins.<host>.olp.signing_key`
/// names, under the same `kid`, so the token verifies against the
/// origin's own `/.well-known/olp/introspect` with no extra trust
/// configuration. `olp.enabled: true` on the same origin is therefore
/// required, and the config compiler refuses the block without it.
#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompMarketplaceConfig {
    /// Master toggle. When false the three well-known endpoints 404.
    #[serde(default)]
    pub enabled: bool,

    /// Master key the CoMP quote-signing key is derived from, as a
    /// hex- or base64-encoded value of at least 32 bytes.
    ///
    /// Resolved like every other config secret: a provider URI
    /// (`secret://backend/name`, `vault://...`), a `file:/path`
    /// reference, or a whole-value `${ENV_VAR}`. HKDF-SHA256 expands
    /// it into one Ed25519 signing key per [`Self::rotation_id`], so
    /// rotation is a label change rather than the minting and
    /// distribution of a new raw seed.
    ///
    /// This is not the OLP token key. Quote signatures live in their
    /// own `comp-...` kid namespace precisely so a quote signature can
    /// never be replayed as a license token.
    pub master_key: String,

    /// Rotation label the active quote-signing key is derived under,
    /// for example `2026-q3-001`. Bumping it derives and publishes a
    /// new `comp-<rotation_id>` kid; the previous one keeps verifying
    /// until the process restarts.
    pub rotation_id: String,

    /// Publisher identity the manifest advertises.
    pub publisher: CompPublisherConfig,

    /// Licensing tiers the manifest publishes. At least one is
    /// required, and at least one must be `authorization: olp`, since
    /// that is the only kind `redeem` can mint a token for.
    #[serde(default)]
    pub tiers: Vec<CompTierConfig>,

    /// Buyer verification keys, by `kid`. A redeem request is signed
    /// by the buyer and refused unless its `kid` resolves here, so this
    /// list is the onboarding boundary: a buyer whose key is absent
    /// cannot redeem anything at any price.
    #[serde(default)]
    pub buyer_keys: Vec<CompBuyerKeyConfig>,

    /// SHA-256 of the canonical JSON of the manifest, in
    /// `sha256:<hex>` form, published in the manifest itself.
    ///
    /// Computed over the manifest with this field cleared when it is
    /// omitted, which is what the CoMP field is specified to be. Set it
    /// explicitly only when an out-of-band process (a signed catalog
    /// feed, a marketplace aggregator) owns the value.
    #[serde(default)]
    pub manifest_hash: Option<String>,

    /// Honor a redeem whose `quote_id` this process never issued.
    /// Defaults to `false`.
    ///
    /// The bridge keeps its issued-quote ledger in memory, matching the
    /// no-external-store rule this port ships under, so a reload or a
    /// restart forgets every quote it signed. With the default, a buyer
    /// holding a quote from before that restart is refused and has to
    /// ask for a new one, which costs it one round trip.
    ///
    /// Turning this on removes that refusal, and removes with it the
    /// only thing standing between an onboarded buyer key and a token
    /// per call with a fabricated `quote_id`, no quote, and no price.
    /// A deployment that turns it on should be running a shared
    /// revocation denylist, because that check is then the only durable
    /// one left. See `docs/comp-marketplace.md`.
    #[serde(default)]
    pub allow_unknown_quotes: bool,
}

/// Redacted `Debug` (WOR-2673). `master_key` is the HKDF input every
/// CoMP quote-signing key is derived from: reading it forges a
/// publisher quote at any price, which a buyer's client has no way to
/// tell from a real one. Everything else in this block is published in
/// the manifest the bridge serves to anyone who asks, so it stays.
/// Curated and `finish_non_exhaustive`, so a key-shaped field added
/// later is absent rather than printed.
impl std::fmt::Debug for CompMarketplaceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompMarketplaceConfig")
            .field("enabled", &self.enabled)
            .field("master_key", &"[REDACTED]")
            .field("rotation_id", &self.rotation_id)
            .field("publisher", &self.publisher)
            .field("tiers", &self.tiers)
            .field("buyer_keys", &self.buyer_keys)
            .field("manifest_hash", &self.manifest_hash)
            .field("allow_unknown_quotes", &self.allow_unknown_quotes)
            .finish_non_exhaustive()
    }
}

/// Publisher identity block of the CoMP manifest.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompPublisherConfig {
    /// Legal or trading name of the publisher.
    pub name: String,
    /// Licensing contact address a buyer can reach a human at.
    pub contact: String,
    /// RFC 3339 timestamp of the publisher's marketplace verification,
    /// when a marketplace has issued one. Advisory; nothing in the
    /// proxy checks it.
    #[serde(default)]
    pub verified_at: Option<String>,
}

/// One licensing tier in the CoMP manifest.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompTierConfig {
    /// Stable tier identifier a buyer names in a quote request.
    pub id: String,
    /// Display name.
    pub name: String,
    /// One-line description of what the tier licenses.
    pub description: String,
    /// License URN this tier grants, stamped into the minted token's
    /// `license_urn` claim.
    pub license: String,
    /// Content shape: `html`, `json-envelope`, or `bulk-archive`.
    pub shape: String,
    /// Acquisition flow: `public`, `cap`, or `olp`. Only `olp` tiers
    /// can be redeemed for a license token.
    pub authorization: String,
    /// Route allow-list glob echoed to the buyer. Advisory: the
    /// marketplace bridge publishes it, and the origin's own policies
    /// enforce access.
    pub route_glob: String,
    /// Pricing block.
    pub pricing: CompTierPricingConfig,
    /// Rate ceiling advertised for the tier.
    #[serde(default)]
    pub rate_caps: Option<CompRateCapsConfig>,
}

/// Pricing block of a CoMP tier.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompTierPricingConfig {
    /// `free`, `per_request`, or `flat_rate`.
    pub model: String,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Whole-unit amount. For `free` and `flat_rate`.
    #[serde(default)]
    pub amount: Option<u64>,
    /// Micro-unit amount (millionths of a currency unit). For
    /// `per_request`.
    #[serde(default)]
    pub amount_micros: Option<u64>,
}

/// Rate ceiling advertised for a CoMP tier.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompRateCapsConfig {
    /// Maximum requests per second.
    pub max_rps: f64,
    /// Maximum bytes per day.
    pub max_bytes_per_day: u64,
}

/// One onboarded buyer's verification key.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompBuyerKeyConfig {
    /// Key id the buyer names in its redeem signature header.
    pub kid: String,
    /// Ed25519 public key, base64url without padding, 32 bytes
    /// decoded. Public by definition, so it carries no secret and is
    /// not resolved through the secret layer.
    pub public_key: String,
}

/// WOR-808 PR9: RFC 7662 OAuth Token Introspection + RFC 7009 Token
/// Revocation configuration for the OLP issuer.
///
/// When this block is present the proxy exposes:
///
/// * `POST /.well-known/olp/introspect`: RFC 7662 §2 introspection.
///   Returns `{ "active": true, ... }` for valid + un-revoked tokens
///   issued by this origin's signing key, mirroring every OLP claim.
///   Returns `{ "active": false }` for any token that does not
///   verify, has expired, or has been revoked (§2.2 forbids leaking
///   the reason).
/// * `POST /.well-known/olp/revoke`: RFC 7009 §2. Writes the token's
///   `jti` to the configured revocation store with a TTL that matches
///   the token's remaining lifetime, so subsequent introspections
///   return `active: false`.
///
/// Both endpoints share one `auth` policy because the same actor that
/// can ask "is this token active" should also be able to assert "this
/// token is no longer trusted." Rate-limiting on `active: false`
/// responses (RFC 7662 §2.1 scan-attack defense) and DPoP-bound
/// confirmation checks ship in a follow-up PR.
#[derive(
    Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq, Default, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
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
/// * `self` (default): the caller proves possession of the token by
///   sending the same value in `Authorization: License <token>`
///   *and* in the `token=` form parameter. Reasonable for the common
///   "RP introspects tokens it already holds" case and requires no
///   operator credential management.
/// * `basic`: HTTP Basic with operator-managed credentials. Pass
///   `{ username, password_hash }` pairs in `clients`; passwords are
///   stored as Argon2id hashes. RFC 7662 §2.1's "client
///   authentication" path.
/// * `none`: no auth. ONLY appropriate for fully-private deployments
///   behind a service mesh that already authenticates the caller.
///   The proxy logs a `warn!` at startup when this is selected.
#[derive(
    Debug, Clone, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

#[cfg(test)]
mod config_authority_tests {
    use super::*;
    use crate::config_bundle::BundleMode;
    use crate::config_merge::MergeMode;

    /// The block from the field documentation, so the documented example
    /// is also the parsed fixture.
    const UPSTREAM_YAML: &str = r#"
upstream:
  url: https://control.example.com
  mode: overlay
  subscriber_id: edge-01
  credential: env:SB_CONFIG_TOKEN
  verifying_keys_file: /etc/sbproxy/authority-keys.json
  poll_interval: 30s
  cache_path: /var/lib/sbproxy/config-bundle.json
  max_staleness: 24h
  require_bundle_on_boot: false
"#;

    fn parse(yaml: &str) -> ConfigAuthorityConfig {
        serde_yaml::from_str(yaml).expect("config_authority parses")
    }

    fn base_upstream() -> ConfigAuthorityUpstreamConfig {
        parse(UPSTREAM_YAML).upstream.expect("upstream present")
    }

    #[test]
    fn documented_block_parses_and_validates() {
        let authority = parse(UPSTREAM_YAML);
        authority.validate().expect("documented block validates");
        let upstream = authority.upstream.expect("upstream present");
        assert_eq!(upstream.url, "https://control.example.com");
        assert_eq!(upstream.mode, BundleMode::Overlay);
        assert_eq!(upstream.merge_mode(), MergeMode::Overlay);
        assert_eq!(upstream.subscriber_id, "edge-01");
        assert_eq!(upstream.credential.as_deref(), Some("env:SB_CONFIG_TOKEN"));
        // Humanized durations land on the seconds fields.
        assert_eq!(upstream.poll_interval_secs, 30);
        assert_eq!(upstream.max_staleness_secs, 86_400);
        assert!(!upstream.requires_bundle_on_boot());
        assert!(!upstream.allow_insecure_http);
        assert!(!upstream.allow_shared_secret_keys);
    }

    #[test]
    fn omitted_durations_take_their_defaults() {
        let authority = parse(
            r#"
upstream:
  url: https://control.example.com
  mode: overlay
  subscriber_id: edge-01
  verifying_keys_file: /etc/sbproxy/authority-keys.json
  cache_path: /var/lib/sbproxy/config-bundle.json
"#,
        );
        let upstream = authority.upstream.expect("upstream present");
        assert_eq!(upstream.poll_interval_secs, 30);
        assert_eq!(upstream.max_staleness_secs, 86_400);
        assert!(upstream.credential.is_none());
    }

    #[test]
    fn absent_block_and_absent_upstream_both_validate() {
        assert!(ConfigAuthorityConfig::default().upstream.is_none());
        ConfigAuthorityConfig::default()
            .validate()
            .expect("an empty block is not a misconfiguration");
    }

    #[test]
    fn replace_implies_require_bundle_on_boot() {
        let authority = parse(
            r#"
upstream:
  url: https://control.example.com
  mode: replace
  subscriber_id: edge-01
  verifying_keys_file: /etc/sbproxy/authority-keys.json
  cache_path: /var/lib/sbproxy/config-bundle.json
"#,
        );
        authority
            .validate()
            .expect("replace without the field is fine");
        let upstream = authority.upstream.expect("upstream present");
        assert_eq!(upstream.merge_mode(), MergeMode::Replace);
        assert!(
            upstream.requires_bundle_on_boot(),
            "replace has nothing to serve without a bundle",
        );
    }

    #[test]
    fn replace_with_explicit_false_is_refused_rather_than_overridden() {
        let authority = parse(
            r#"
upstream:
  url: https://control.example.com
  mode: replace
  subscriber_id: edge-01
  verifying_keys_file: /etc/sbproxy/authority-keys.json
  cache_path: /var/lib/sbproxy/config-bundle.json
  require_bundle_on_boot: false
"#,
        );
        let error = authority.validate().expect_err("must be refused");
        assert_eq!(
            error,
            ConfigAuthorityConfigError::ReplaceWithoutBundleOnBoot
        );
        let message = error.to_string();
        assert!(message.contains("nothing to boot on"), "{message}");
    }

    #[test]
    fn overlay_keeps_an_explicit_true() {
        let authority = parse(
            r#"
upstream:
  url: https://control.example.com
  mode: overlay
  subscriber_id: edge-01
  verifying_keys_file: /etc/sbproxy/authority-keys.json
  cache_path: /var/lib/sbproxy/config-bundle.json
  require_bundle_on_boot: true
"#,
        );
        authority.validate().expect("valid");
        assert!(authority
            .upstream
            .expect("upstream present")
            .requires_bundle_on_boot());
    }

    #[test]
    fn plaintext_http_needs_the_escape_hatch() {
        let mut upstream = base_upstream();
        upstream.url = "http://control.example.com".to_string();
        let error = upstream.validate().expect_err("plaintext must be refused");
        let message = error.to_string();
        assert!(message.contains("allow_insecure_http"), "{message}");

        upstream.allow_insecure_http = true;
        upstream
            .validate()
            .expect("the acknowledged development form is accepted");
    }

    #[test]
    fn the_url_must_be_absolute_https_with_a_host_and_no_query() {
        for (url, label) in [
            ("control.example.com", "no scheme"),
            ("/config-authority", "path only"),
            ("https:///bundle", "no host"),
            ("ftp://control.example.com", "unsupported scheme"),
            ("https://control.example.com?tenant=a", "query string"),
            ("https://control.example.com#frag", "fragment"),
            ("", "empty"),
        ] {
            let mut upstream = base_upstream();
            upstream.url = url.to_string();
            // `allow_insecure_http` must not launder any of these.
            upstream.allow_insecure_http = true;
            assert!(
                matches!(
                    upstream.validate(),
                    Err(ConfigAuthorityConfigError::Url { .. })
                ),
                "{label} ({url:?}) must be refused",
            );
        }

        // A base path is kept; the subscriber appends its own path under it.
        let mut upstream = base_upstream();
        upstream.url = "https://control.example.com/fleet".to_string();
        upstream.validate().expect("a base path is allowed");
    }

    #[test]
    fn the_credential_must_be_a_reference_not_an_inline_token() {
        for reference in [
            "env:SB_CONFIG_TOKEN",
            "${SB_CONFIG_TOKEN}",
            "file:/etc/sbproxy/authority-token",
            "secret://primary/authority-token",
            "vault://primary/secret/data/authority",
        ] {
            let mut upstream = base_upstream();
            upstream.credential = Some(reference.to_string());
            upstream
                .validate()
                .unwrap_or_else(|error| panic!("{reference} must be accepted: {error}"));
        }

        for inline in [
            "sk-live-abcdef",
            "Bearer sk-live-abcdef",
            "https://control.example.com/token",
            "",
        ] {
            let mut upstream = base_upstream();
            upstream.credential = Some(inline.to_string());
            assert!(
                upstream.validate().is_err(),
                "{inline:?} must be refused as an inline credential",
            );
        }
    }

    #[test]
    fn durations_are_bounded_and_ordered() {
        let mut upstream = base_upstream();
        upstream.poll_interval_secs = 1;
        assert!(matches!(
            upstream.validate(),
            Err(ConfigAuthorityConfigError::PollInterval { found: 1 })
        ));

        let mut upstream = base_upstream();
        upstream.poll_interval_secs = MAX_CONFIG_AUTHORITY_POLL_SECS + 1;
        assert!(matches!(
            upstream.validate(),
            Err(ConfigAuthorityConfigError::PollInterval { .. })
        ));

        // A staleness window shorter than one poll interval declares every
        // bundle stale the moment it arrives.
        let mut upstream = base_upstream();
        upstream.poll_interval_secs = 300;
        upstream.max_staleness_secs = 60;
        assert!(matches!(
            upstream.validate(),
            Err(ConfigAuthorityConfigError::MaxStaleness { .. })
        ));

        let mut upstream = base_upstream();
        upstream.max_staleness_secs = MAX_CONFIG_AUTHORITY_STALENESS_SECS + 1;
        assert!(matches!(
            upstream.validate(),
            Err(ConfigAuthorityConfigError::MaxStaleness { .. })
        ));
    }

    #[test]
    fn empty_identifiers_and_paths_are_refused() {
        for (label, mutate) in [
            (
                "subscriber_id",
                (|upstream: &mut ConfigAuthorityUpstreamConfig| {
                    upstream.subscriber_id = String::new();
                }) as fn(&mut ConfigAuthorityUpstreamConfig),
            ),
            ("verifying_keys_file", |upstream| {
                upstream.verifying_keys_file = "  ".to_string();
            }),
            ("cache_path", |upstream| {
                upstream.cache_path = String::new();
            }),
        ] {
            let mut upstream = base_upstream();
            mutate(&mut upstream);
            assert!(
                matches!(
                    upstream.validate(),
                    Err(ConfigAuthorityConfigError::Value { field }) if field == label
                ),
                "{label} must be refused when empty",
            );
        }
    }

    #[test]
    fn a_misspelled_key_is_refused_rather_than_defaulted() {
        let error = serde_yaml::from_str::<ConfigAuthorityConfig>(
            r#"
upstream:
  url: https://control.example.com
  mode: overlay
  subscriber_id: edge-01
  verifying_keys_file: /etc/sbproxy/authority-keys.json
  cache_path: /var/lib/sbproxy/config-bundle.json
  poll_intervall: 30s
"#,
        )
        .expect_err("a typo must not silently take the default");
        assert!(error.to_string().contains("poll_intervall"), "{error}");
    }

    // --- publish half -------------------------------------------------

    /// The block from the field documentation, so the documented example
    /// is also the parsed fixture.
    const PUBLISH_YAML: &str = r#"
publish:
  authority_id: control-plane-eu
  key_id: authority-2026-07
  signing_key_file: /etc/sbproxy/authority-signing.key
  store_dir: /var/lib/sbproxy/config-authority
  bind: 0.0.0.0:9443
  tls:
    cert_file: /etc/sbproxy/authority.pem
    key_file: /etc/sbproxy/authority-key.pem
"#;

    fn base_publish() -> ConfigAuthorityPublishConfig {
        parse(PUBLISH_YAML).publish.expect("publish present")
    }

    #[test]
    fn the_documented_publish_block_parses_and_validates() {
        let authority = parse(PUBLISH_YAML);
        assert!(authority.publishes_bundles());
        assert!(authority.upstream.is_none());
        authority.validate().expect("documented block validates");
        let publish = authority.publish.expect("publish present");
        assert_eq!(publish.authority_id, "control-plane-eu");
        assert_eq!(publish.key_id, "authority-2026-07");
        assert_eq!(publish.bind, "0.0.0.0:9443");
        assert_eq!(publish.socket_addr().expect("addr").port(), 9443);
        assert!(!publish.binds_loopback_only());
        let tls = publish.tls.expect("tls present");
        assert_eq!(tls.cert_file, "/etc/sbproxy/authority.pem");
        assert_eq!(tls.key_file, "/etc/sbproxy/authority-key.pem");
        // The rate limits are on by default and the fleet cap bounds the
        // per-subscriber one.
        assert_eq!(publish.rate_limit_per_subscriber_per_minute, 30);
        assert_eq!(publish.rate_limit_total_per_minute, 1_200);
    }

    #[test]
    fn publishing_and_subscribing_at_once_is_refused() {
        // The seam CA-03 left behind: with a publish block present the
        // conflict rule is finally reachable.
        let mut authority = parse(UPSTREAM_YAML);
        authority.publish = Some(base_publish());
        assert!(authority.publishes_bundles());
        let error = authority
            .validate()
            .expect_err("one node cannot be both an authority and a subscriber");
        assert_eq!(error, ConfigAuthorityConfigError::BothRoles);
        let message = error.to_string();
        assert!(message.contains("upstream"), "{message}");
        assert!(message.contains("publish"), "{message}");
        // Each half alone still validates, which pins the failure on the
        // combination rather than on either block.
        authority.upstream = None;
        authority.validate().expect("publish alone is fine");
        assert!(parse(UPSTREAM_YAML).validate().is_ok());
    }

    #[test]
    fn a_non_loopback_bind_without_tls_is_refused() {
        let mut publish = base_publish();
        publish.tls = None;
        let error = publish
            .validate()
            .expect_err("a remote bundle listener must terminate TLS");
        assert_eq!(
            error,
            ConfigAuthorityConfigError::PublishTlsRequired {
                bind: "0.0.0.0:9443".to_string()
            }
        );
        let message = error.to_string();
        assert!(message.contains("refuses to start"), "{message}");
        assert!(message.contains("cert_file"), "{message}");

        // Loopback without TLS is the local-development path and stays
        // valid, which is the one place this differs from proxy.admin.
        for bind in ["127.0.0.1:9443", "[::1]:9443", "[::ffff:127.0.0.1]:9443"] {
            let mut loopback = base_publish();
            loopback.tls = None;
            loopback.bind = bind.to_string();
            assert!(loopback.binds_loopback_only(), "{bind}");
            loopback
                .validate()
                .unwrap_or_else(|error| panic!("{bind} must validate: {error}"));
        }

        // And TLS on a remote bind is accepted, so the rule is about the
        // missing block rather than about the bind.
        base_publish().validate().expect("remote bind with tls");
    }

    #[test]
    fn an_unusable_bind_is_refused_rather_than_treated_as_loopback() {
        for (bind, needle) in [
            // A hostname cannot be bound, only resolved.
            ("authority.example.com:9443", "IP address and port"),
            ("0.0.0.0", "IP address and port"),
            // Port 0 would move on every restart.
            ("127.0.0.1:0", "fixed port"),
        ] {
            let mut publish = base_publish();
            publish.bind = bind.to_string();
            let error = publish.validate().expect_err("must be refused");
            assert!(error.to_string().contains(needle), "{bind}: {error}");
        }

        // A bind that does not parse counts as remote, so an unreadable
        // value cannot slip past the TLS requirement by being unreadable.
        let mut unparseable = base_publish();
        unparseable.bind = "authority.example.com:9443".to_string();
        unparseable.tls = None;
        assert!(!unparseable.binds_loopback_only());
    }

    #[test]
    fn publish_identifiers_the_envelope_would_refuse_are_caught_at_compile_time() {
        for field in ["authority_id", "key_id"] {
            let mut publish = base_publish();
            // A space is fine in a filesystem path and fatal in a bundle
            // identifier, so the two are validated separately.
            match field {
                "authority_id" => publish.authority_id = "control plane".to_string(),
                _ => publish.key_id = "key/2026".to_string(),
            }
            let error = publish.validate().expect_err("must be refused");
            assert_eq!(
                error,
                ConfigAuthorityConfigError::PublishIdentifier { field }
            );
            assert!(
                error.to_string().contains("every subscriber"),
                "the message must name the consequence: {error}"
            );
        }
    }

    /// A named edit that blanks one required field of a publish block.
    type PublishFieldSetter = (&'static str, fn(&mut ConfigAuthorityPublishConfig));

    #[test]
    fn every_required_publish_value_is_refused_when_empty() {
        let setters: [PublishFieldSetter; 5] = [
            ("authority_id", |publish| {
                publish.authority_id = String::new();
            }),
            ("key_id", |publish| publish.key_id = String::new()),
            ("signing_key_file", |publish| {
                publish.signing_key_file = "   ".to_string();
            }),
            ("store_dir", |publish| publish.store_dir = String::new()),
            ("bind", |publish| publish.bind = String::new()),
        ];
        for (field, apply) in setters {
            let mut publish = base_publish();
            apply(&mut publish);
            assert_eq!(
                publish.validate(),
                Err(ConfigAuthorityConfigError::PublishValue { field }),
                "{field} must be refused when empty",
            );
        }
        for field in ["tls.cert_file", "tls.key_file"] {
            let mut publish = base_publish();
            let tls = publish.tls.as_mut().expect("tls present");
            if field.ends_with("cert_file") {
                tls.cert_file = String::new();
            } else {
                tls.key_file = String::new();
            }
            assert_eq!(
                publish.validate(),
                Err(ConfigAuthorityConfigError::PublishValue { field }),
            );
        }
    }

    #[test]
    fn the_bundle_listener_rate_limits_cannot_be_turned_off_or_inverted() {
        for field in [
            "rate_limit_per_subscriber_per_minute",
            "rate_limit_total_per_minute",
        ] {
            let mut publish = base_publish();
            if field.starts_with("rate_limit_per_subscriber") {
                publish.rate_limit_per_subscriber_per_minute = 0;
            } else {
                publish.rate_limit_total_per_minute = 0;
            }
            let error = publish.validate().expect_err("zero is not off");
            assert_eq!(
                error,
                ConfigAuthorityConfigError::PublishRateLimit { field, found: 0 }
            );
            assert!(
                error.to_string().contains("cannot be turned off"),
                "{error}"
            );

            let mut over = base_publish();
            if field.starts_with("rate_limit_per_subscriber") {
                over.rate_limit_per_subscriber_per_minute = MAX_PUBLISH_RATE_LIMIT + 1;
                over.rate_limit_total_per_minute = MAX_PUBLISH_RATE_LIMIT + 1;
            } else {
                over.rate_limit_total_per_minute = MAX_PUBLISH_RATE_LIMIT + 1;
            }
            assert!(matches!(
                over.validate(),
                Err(ConfigAuthorityConfigError::PublishRateLimit { .. })
            ));
        }

        let mut inverted = base_publish();
        inverted.rate_limit_per_subscriber_per_minute = 100;
        inverted.rate_limit_total_per_minute = 50;
        let error = inverted
            .validate()
            .expect_err("a fleet cap below the per-subscriber cap bounds nothing");
        assert_eq!(
            error,
            ConfigAuthorityConfigError::PublishRateLimitInverted {
                total: 50,
                per_subscriber: 100,
            }
        );
    }

    #[test]
    fn a_misspelled_publish_key_is_refused_rather_than_defaulted() {
        let error = serde_yaml::from_str::<ConfigAuthorityConfig>(
            r#"
publish:
  authority_id: control-plane-eu
  key_id: authority-2026-07
  signing_key_file: /etc/sbproxy/authority-signing.key
  store_dir: /var/lib/sbproxy/config-authority
  bind: 127.0.0.1:9443
  rate_limit_totall_per_minute: 10
"#,
        )
        .expect_err("a typo must not silently take the default");
        assert!(
            error.to_string().contains("rate_limit_totall_per_minute"),
            "{error}"
        );
    }
}

#[cfg(test)]
mod inbound_key_header_tests {
    use super::*;

    #[test]
    fn native_key_policy_requires_a_nonempty_unique_provider_allowlist() {
        let mut cfg = KeyInboundConfig {
            native_key_policy: Some(NativeKeyPolicyConfig {
                allowed_providers: vec!["openai".to_string(), "anthropic".to_string()],
                ..NativeKeyPolicyConfig::default()
            }),
            ..KeyInboundConfig::default()
        };
        assert!(cfg.validate().is_ok());

        cfg.native_key_policy = Some(NativeKeyPolicyConfig {
            allowed_providers: Vec::new(),
            ..NativeKeyPolicyConfig::default()
        });
        assert!(cfg
            .validate()
            .unwrap_err()
            .contains("allowed_providers must not be empty"));

        cfg.native_key_policy = Some(NativeKeyPolicyConfig {
            allowed_providers: vec!["OpenAI".to_string(), " openai ".to_string()],
            ..NativeKeyPolicyConfig::default()
        });
        assert!(cfg
            .validate()
            .unwrap_err()
            .contains("listed more than once"));
    }

    #[test]
    fn native_key_policy_is_absent_by_default_so_native_traffic_fails_closed() {
        assert!(KeyInboundConfig::default().native_key_policy.is_none());
    }

    #[test]
    fn native_key_policy_accepts_key_record_governance_fields() {
        let cfg: KeyInboundConfig = serde_yaml::from_str(
            r#"
native_key_policy:
  allowed_providers: [openai]
  max_requests_per_minute: 12
  max_tokens_per_minute: 3456
  max_budget_tokens: 7890
  max_budget_usd: 1.25
  allowed_models: [gpt-5]
  blocked_models: [gpt-4]
  require_pii_redaction: [email]
"#,
        )
        .expect("native KeyRecord policy fields should deserialize");

        let policy = cfg.native_key_policy.expect("policy");
        assert_eq!(policy.max_requests_per_minute, Some(12));
        assert_eq!(policy.max_tokens_per_minute, Some(3456));
        assert_eq!(policy.max_budget_tokens, Some(7890));
        assert_eq!(policy.max_budget_usd, Some(1.25));
        assert_eq!(policy.allowed_models, ["gpt-5"]);
        assert_eq!(policy.blocked_models, ["gpt-4"]);
        assert_eq!(policy.require_pii_redaction, ["email"]);
    }

    #[test]
    fn native_key_policy_rejects_zero_limits_and_invalid_cost_budget() {
        let mut cfg = KeyInboundConfig {
            native_key_policy: Some(NativeKeyPolicyConfig {
                allowed_providers: vec!["openai".to_string()],
                max_requests_per_minute: Some(0),
                ..NativeKeyPolicyConfig::default()
            }),
            ..KeyInboundConfig::default()
        };
        assert!(cfg
            .validate()
            .unwrap_err()
            .contains("must be greater than zero"));

        cfg.native_key_policy = Some(NativeKeyPolicyConfig {
            allowed_providers: vec!["openai".to_string()],
            max_budget_usd: Some(f64::NAN),
            ..NativeKeyPolicyConfig::default()
        });
        assert!(cfg.validate().unwrap_err().contains("finite"));
    }

    #[test]
    fn inbound_header_defaults_cover_the_three_common_shapes() {
        let cfg = KeyInboundConfig::default();
        let names: Vec<&str> = cfg.headers.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["authorization", "x-api-key", "x-sb-api"]);
        assert_eq!(cfg.headers[0].scheme, "Bearer ");
        assert_eq!(cfg.headers[1].scheme, "");
        assert!(
            !cfg.require,
            "require is opt-in so an upgrade changes nothing"
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn inbound_validation_rejects_invalid_header_names() {
        let bad = KeyInboundConfig {
            headers: vec![InboundHeaderConfig {
                name: "not a header".into(),
                scheme: String::new(),
            }],
            require: false,
            provider_hints: Vec::new(),
            native_key_policy: None,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn inbound_validation_rejects_hop_by_hop_and_framing_headers() {
        for forbidden in FORBIDDEN_SWEEP_HEADERS {
            let cfg = KeyInboundConfig {
                headers: vec![InboundHeaderConfig {
                    name: (*forbidden).to_string(),
                    scheme: String::new(),
                }],
                require: false,
                provider_hints: Vec::new(),
                native_key_policy: None,
            };
            assert!(cfg.validate().is_err(), "{forbidden} must be rejected");
        }
    }

    #[test]
    fn inbound_validation_rejects_realtime_protocol_and_proxy_owned_headers() {
        for forbidden in [
            "OpenAI-Beta",
            "SEC-WebSocket-Key",
            "Upgrade",
            "TraceParent",
            "TRACESTATE",
            "Signature-Input",
            "Signature",
            "Signature-Agent",
        ] {
            let cfg = KeyInboundConfig {
                headers: vec![InboundHeaderConfig {
                    name: forbidden.to_string(),
                    scheme: String::new(),
                }],
                require: false,
                provider_hints: Vec::new(),
                native_key_policy: None,
            };
            assert!(cfg.validate().is_err(), "{forbidden} must be rejected");
        }
    }

    #[test]
    fn inbound_validation_rejects_observability_and_capture_owned_headers() {
        for forbidden in [
            "X-Sb-User-Id",
            "x-sb-session-id",
            "X-SB-PARENT-SESSION-ID",
            "x-sb-property-credential",
            "User-Agent",
            "Referer",
            "b3",
            "x-b3-traceid",
            "x-b3-spanid",
            "x-b3-sampled",
            "x-b3-parentspanid",
            "x-user-id",
            "x-end-user",
            "x-sbproxy-tag",
            "x-a2a-caller-agent-id",
            "x-a2a-callee-agent-id",
            "x-a2a-task-id",
            "x-a2a-parent-request-id",
            "x-a2a-chain-depth",
            "x-a2a-chain",
        ] {
            for provider_hint in [false, true] {
                let cfg = KeyInboundConfig {
                    headers: if provider_hint {
                        Vec::new()
                    } else {
                        vec![InboundHeaderConfig {
                            name: format!("  {forbidden}  "),
                            scheme: String::new(),
                        }]
                    },
                    require: false,
                    provider_hints: if provider_hint {
                        vec![ProviderHintConfig {
                            provider: "custom".into(),
                            header: format!("  {forbidden}  "),
                            scheme: String::new(),
                            value_prefix: String::new(),
                            also_header: None,
                        }]
                    } else {
                        Vec::new()
                    },
                    native_key_policy: None,
                };
                assert!(
                    cfg.validate().is_err(),
                    "{forbidden} must not be a primary credential carrier"
                );
            }
        }
    }

    #[test]
    fn inbound_validation_rejects_case_insensitive_duplicates() {
        let dupe = KeyInboundConfig {
            headers: vec![
                InboundHeaderConfig {
                    name: "x-api-key".into(),
                    scheme: String::new(),
                },
                InboundHeaderConfig {
                    name: "X-API-Key".into(),
                    scheme: String::new(),
                },
            ],
            require: false,
            provider_hints: Vec::new(),
            native_key_policy: None,
        };
        assert!(dupe.validate().is_err());
    }

    #[test]
    fn inbound_empty_header_list_is_valid_and_disables_the_sweep() {
        let cfg = KeyInboundConfig {
            headers: vec![],
            require: false,
            provider_hints: Vec::new(),
            native_key_policy: None,
        };
        assert!(cfg.validate().is_ok());
        assert!(cfg.header_names().is_empty());
    }

    #[test]
    fn header_names_are_lowercased_for_the_redaction_denylists() {
        let cfg = KeyInboundConfig {
            headers: vec![InboundHeaderConfig {
                name: "  X-Tool-Auth  ".into(),
                scheme: String::new(),
            }],
            require: false,
            provider_hints: Vec::new(),
            native_key_policy: None,
        };
        assert_eq!(cfg.header_names(), ["x-tool-auth"]);
    }

    #[test]
    fn credential_carrier_names_include_provider_hint_headers_only() {
        let cfg = KeyInboundConfig {
            headers: vec![
                InboundHeaderConfig {
                    name: "  X-Tool-Auth  ".into(),
                    scheme: String::new(),
                },
                InboundHeaderConfig {
                    name: "Authorization".into(),
                    scheme: "Bearer ".into(),
                },
            ],
            require: false,
            provider_hints: vec![
                ProviderHintConfig {
                    provider: "openai".into(),
                    header: "X-Native-Provider-Key".into(),
                    scheme: String::new(),
                    value_prefix: "native-".into(),
                    also_header: Some("X-Provider-Version".into()),
                },
                ProviderHintConfig {
                    provider: "openai".into(),
                    header: "authorization".into(),
                    scheme: "Bearer ".into(),
                    value_prefix: "sk-".into(),
                    also_header: None,
                },
            ],
            native_key_policy: None,
        };

        assert_eq!(
            cfg.credential_carrier_names(),
            ["x-tool-auth", "authorization", "x-native-provider-key"]
        );
        assert!(
            !cfg.credential_carrier_names()
                .contains(&"x-provider-version".to_string()),
            "also_header is match metadata, not a credential carrier"
        );
    }

    #[test]
    fn provider_hint_primary_carriers_reuse_reserved_header_rules() {
        for reserved in [
            "cookie",
            "host",
            "keep-alive",
            "proxy-connection",
            "te",
            "trailer",
            "traceparent",
            "proxy-authorization",
            "sec-websocket-protocol",
        ] {
            let cfg = KeyInboundConfig {
                headers: Vec::new(),
                require: false,
                provider_hints: vec![ProviderHintConfig {
                    provider: "openai".into(),
                    header: reserved.into(),
                    scheme: String::new(),
                    value_prefix: String::new(),
                    also_header: None,
                }],
                native_key_policy: None,
            };
            assert!(
                cfg.validate().is_err(),
                "{reserved} must not be a provider-hint credential carrier"
            );
        }
    }

    #[test]
    fn provider_hint_match_metadata_may_use_reserved_headers() {
        let cfg = KeyInboundConfig {
            headers: Vec::new(),
            require: false,
            provider_hints: vec![ProviderHintConfig {
                provider: "openai".into(),
                header: "x-provider-key".into(),
                scheme: String::new(),
                value_prefix: String::new(),
                also_header: Some("traceparent".into()),
            }],
            native_key_policy: None,
        };

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn every_default_sweep_header_is_excluded_from_capture_globs() {
        // A swept header carries a live secret. If a default one is missing
        // from the denylist, `capture_headers: ["*"]` logs it in plaintext.
        for entry in KeyInboundConfig::default().headers {
            assert!(
                SENSITIVE_HEADER_DENYLIST.contains(&entry.name.as_str()),
                "{} must be excluded from capture globs",
                entry.name
            );
        }
    }
}

#[cfg(test)]
mod sweep_header_capture_tests {
    use super::*;

    #[test]
    fn a_configured_sweep_header_is_excluded_from_a_wildcard_glob() {
        // Same trap as the log redactor: a custom name is on no static list,
        // so `capture_headers: ["*"]` would capture a live minted key.
        let (compiled, _) = CompiledHeaderAllowlist::compile(&["*".to_string()]);

        set_extra_sensitive_headers(Vec::new());
        assert!(
            compiled.matches("x-tool-auth"),
            "precondition: a wildcard captures it when nothing marks it sensitive"
        );

        set_extra_sensitive_headers(vec!["x-tool-auth".to_string()]);
        assert!(!compiled.matches("x-tool-auth"));

        // An exact listing still wins, which is the documented opt-in.
        let (exact, warnings) = CompiledHeaderAllowlist::compile(&["x-tool-auth".to_string()]);
        assert!(exact.matches("x-tool-auth"));
        assert_eq!(warnings, vec!["x-tool-auth".to_string()]);

        set_extra_sensitive_headers(Vec::new());
    }

    #[test]
    fn the_builtin_denylist_still_applies_with_no_extras_configured() {
        set_extra_sensitive_headers(Vec::new());
        let (compiled, _) = CompiledHeaderAllowlist::compile(&["*".to_string()]);
        for name in SENSITIVE_HEADER_DENYLIST {
            assert!(!compiled.matches(name), "{name} must stay excluded");
        }
    }

    // --- WOR-2199: the public bind address ---

    #[test]
    fn bind_address_defaults_to_every_interface() {
        // The default has to stay 0.0.0.0 or every existing config
        // silently loses reachability on upgrade. This is the one
        // behavior in the feature that must not change.
        let cfg = ProxyServerConfig::default();
        assert_eq!(cfg.effective_bind_address(), DEFAULT_PUBLIC_BIND_ADDRESS);
        assert_eq!(cfg.effective_bind_address(), "0.0.0.0");
        cfg.validate_bind_address()
            .expect("an absent field is valid");
    }

    #[test]
    fn a_configured_bind_address_is_used_verbatim() {
        for addr in ["127.0.0.1", "::1", "10.1.2.3", "0.0.0.0"] {
            let cfg = ProxyServerConfig {
                bind_address: Some(addr.to_string()),
                ..Default::default()
            };
            cfg.validate_bind_address()
                .unwrap_or_else(|e| panic!("{addr} must validate: {e}"));
            assert_eq!(cfg.effective_bind_address(), addr);
        }
    }

    #[test]
    fn surrounding_whitespace_does_not_change_the_interface() {
        // A trailing space in YAML must not turn a loopback bind into
        // something that fails to parse and gets reported as invalid,
        // nor into a different address.
        let cfg = ProxyServerConfig {
            bind_address: Some("  127.0.0.1  ".to_string()),
            ..Default::default()
        };
        cfg.validate_bind_address()
            .expect("padded address validates");
        assert_eq!(cfg.effective_bind_address(), "127.0.0.1");
    }

    #[test]
    fn a_hostname_is_refused_rather_than_resolved() {
        // A name can resolve to several addresses, or to a different
        // one later. Accepting it would make the listener's interface
        // depend on DNS, which is not something an operator can reason
        // about when they are trying to restrict reach.
        let cfg = ProxyServerConfig {
            bind_address: Some("localhost".to_string()),
            ..Default::default()
        };
        let err = cfg
            .validate_bind_address()
            .expect_err("a hostname must not be accepted");
        let msg = err.to_string();
        assert!(msg.contains("localhost"), "{msg}");
        assert!(msg.contains("not an IP address"), "{msg}");
    }

    #[test]
    fn a_malformed_address_fails_instead_of_falling_back() {
        // The failure this whole field exists to prevent: an operator
        // restricts the listener, fat-fingers it, and gets every
        // interface while believing otherwise. There is no safe
        // direction to guess in, so it does not load.
        for bad in ["127.0.0.999", "127.0.0", "not-an-ip", ""] {
            let cfg = ProxyServerConfig {
                bind_address: Some(bad.to_string()),
                ..Default::default()
            };
            assert!(
                cfg.validate_bind_address().is_err(),
                "{bad:?} must be refused rather than defaulted"
            );
        }
    }
}

/// How `decision_audit:` composes across scopes (WOR-2405).
#[cfg(test)]
mod decision_audit_scope_tests {
    use super::*;

    fn audit_cfg(yaml: &str) -> DecisionAuditConfig {
        serde_yaml::from_str(yaml).expect("fixture parses")
    }

    #[test]
    fn a_per_event_entry_wins_over_the_master_switch() {
        let cfg = audit_cfg("enabled: true\nevents:\n  cache.admit: true\n  cache.key: false\n");
        assert!(cfg.publishes("cache.admit"));
        assert!(!cfg.publishes("cache.key"));
        assert!(
            cfg.publishes("route.decide"),
            "unnamed events follow the switch"
        );
    }

    #[test]
    fn the_per_chunk_event_is_off_at_every_scope() {
        // Off by construction ahead of both the map and the switch, and
        // the scope resolver has to agree with the single-scope one or
        // a tenant block becomes a way around it.
        let cfg = audit_cfg("enabled: true\n");
        assert!(!cfg.publishes("ai.stream.event"));

        let scopes = DecisionAuditScopes {
            proxy: Some(audit_cfg("enabled: true\n")),
            tenants: [("acme".to_owned(), audit_cfg("enabled: true\n"))]
                .into_iter()
                .collect(),
            origins: Default::default(),
        };
        assert!(!scopes.publishes("ai.stream.event", Some("acme"), None));
    }

    #[test]
    fn a_scope_composes_per_event_rather_than_replacing_the_block() {
        // The finding this shape exists to prevent: a tenant that turns
        // on its routing audit must not thereby silence the cache audit
        // the proxy scope turned on for it.
        let scopes = DecisionAuditScopes {
            proxy: Some(audit_cfg("events:\n  cache.admit: true\n")),
            tenants: [(
                "acme".to_owned(),
                audit_cfg("events:\n  route.decide: true\n"),
            )]
            .into_iter()
            .collect(),
            origins: Default::default(),
        };
        assert!(
            scopes.publishes("cache.admit", Some("acme"), None),
            "the tenant named a different event, so the proxy's entry still stands"
        );
        assert!(scopes.publishes("route.decide", Some("acme"), None));
        assert!(
            !scopes.publishes("route.decide", Some("other"), None),
            "another tenant does not inherit acme's entry"
        );
    }

    #[test]
    fn the_most_specific_scope_wins_per_event() {
        let scopes = DecisionAuditScopes {
            proxy: Some(audit_cfg("events:\n  cache.admit: true\n")),
            tenants: [(
                "acme".to_owned(),
                audit_cfg("events:\n  cache.admit: false\n"),
            )]
            .into_iter()
            .collect(),
            origins: [(
                "api.example.test".to_owned(),
                audit_cfg("events:\n  cache.admit: true\n"),
            )]
            .into_iter()
            .collect(),
        };
        assert!(
            scopes.publishes("cache.admit", Some("acme"), Some("api.example.test")),
            "origin beats tenant"
        );
        assert!(
            !scopes.publishes("cache.admit", Some("acme"), None),
            "tenant beats proxy"
        );
        assert!(
            scopes.publishes("cache.admit", None, None),
            "proxy is the floor"
        );
    }

    #[test]
    fn a_scoped_events_map_does_not_shadow_a_wider_master_switch() {
        // A tenant writing `events:` alone has said nothing about the
        // events it did not name, so the proxy's `enabled:` still
        // decides them. The other reading silently disables a feed.
        let scopes = DecisionAuditScopes {
            proxy: Some(audit_cfg("enabled: true\n")),
            tenants: [(
                "acme".to_owned(),
                audit_cfg("events:\n  route.decide: false\n"),
            )]
            .into_iter()
            .collect(),
            origins: Default::default(),
        };
        assert!(
            !scopes.publishes("route.decide", Some("acme"), None),
            "the tenant named this one"
        );
        assert!(
            scopes.publishes("cache.admit", Some("acme"), None),
            "it named nothing about this one, so the proxy switch still applies"
        );
    }

    #[test]
    fn an_absent_block_is_off_and_cheap() {
        let scopes = DecisionAuditScopes::default();
        assert!(scopes.is_empty());
        assert!(!scopes.publishes("cache.admit", Some("acme"), Some("api.example.test")));
    }

    /// WOR-2640: the config-side twins.
    ///
    /// Three of these carry the same values as runtime types that were
    /// given a redacting `Debug` in the first half of this ticket, and
    /// kept the derive: the Vault token and AppRole `secret_id`, the
    /// Entra client secret, and the toolkit agent's shared secret were
    /// protected where they are used and printed where they are loaded.
    /// A config-load diagnostic is the likelier of the two to reach a
    /// log. `AdminConfig.password` is the fourth, and its default is
    /// `changeme`, which is what makes it worth naming.
    #[test]
    fn debug_never_renders_a_config_side_credential() {
        const SENTINEL: &str = "SENTINEL-SECRET-9f3a";

        let admin = AdminConfig {
            enabled: true,
            port: 9090,
            username: "operator".to_string(),
            password: SENTINEL.to_string(),
            max_log_entries: 1000,
            rate_limit_per_minute: 240,
            prompt_persistence_path: None,
            prompt_persistence_encryption: None,
            trace_url_template: None,
            tls: None,
            bind: None,
            allow_ips: Vec::new(),
            cors_origins: Vec::new(),
            operators: Vec::new(),
        };
        let rendered = format!("{admin:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the admin password reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("operator") && rendered.contains("9090"),
            "the username and port must survive: {rendered}"
        );

        let token = HashiCorpBackendAuth::Token {
            token: SENTINEL.to_string(),
        };
        assert!(
            !format!("{token:?}").contains(SENTINEL),
            "the Vault token reached Debug: {token:?}"
        );

        let approle = HashiCorpBackendAuth::Approle {
            role_id: "role-1".to_string(),
            secret_id: SENTINEL.to_string(),
            mount: None,
        };
        let rendered = format!("{approle:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the AppRole secret id reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("role-1"),
            "the role id must survive: it is the username half of the pair: {rendered}"
        );

        let principal = AzureBackendAuth::ServicePrincipal {
            tenant_id: "tenant-1".to_string(),
            client_id: "client-1".to_string(),
            client_secret: SENTINEL.to_string(),
            authority: None,
        };
        let rendered = format!("{principal:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the Entra client secret reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("tenant-1") && rendered.contains("client-1"),
            "the tenant and client ids must survive: {rendered}"
        );

        let toolkit = AiToolkitAgentAuthConfig {
            shared_secret: SENTINEL.to_string(),
        };
        assert!(
            !format!("{toolkit:?}").contains(SENTINEL),
            "the toolkit shared secret reached Debug: {toolkit:?}"
        );
    }

    /// WOR-2606: the config-side twins the first sweep did not reach.
    ///
    /// Each of these was derived while the value it carries was already
    /// protected somewhere else, or is a signing key whose only reader
    /// is a config-load diagnostic. The rule is the one the first sweep
    /// used: the credential goes, the identifier that names what failed
    /// stays.
    #[test]
    fn debug_never_renders_a_remaining_config_side_credential() {
        const SENTINEL: &str = "SENTINEL-TWIN-3b7e";

        // The HMAC key a webhook receiver verifies. Reading it forges an
        // event feed the operator's downstream trusts.
        let events = EventsConfig {
            sink: EventSinkKind::Webhook,
            url: Some("https://siem.example.test/ingest".to_string()),
            signing_secret: Some(SENTINEL.to_string()),
            fail_closed: vec!["auth.denied".to_string()],
            ..EventsConfig::default()
        };
        let rendered = format!("{events:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the event webhook signing secret reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("siem.example.test"),
            "the destination must survive: it names which sink failed: {rendered}"
        );

        // The plaintext inbound key an operator seeds. Whoever reads it
        // authenticates as this key for as long as it exists.
        let seed_key: SeedKeyConfig = serde_json::from_value(serde_json::json!({
            "key_id": "sb-key-1",
            "secret": SENTINEL,
            "secret_hash": "sha256:abcdef",
            "name": "billing service",
        }))
        .expect("seed key fixture parses");
        let rendered = format!("{seed_key:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the seeded inbound key reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("sb-key-1") && rendered.contains("sha256:abcdef"),
            "the key id and the precomputed hash must survive: the hash is what \
             says which seeded key a load error is about, and a hash is not its \
             own preimage: {rendered}"
        );

        let seed_credential = SeedCredentialConfig {
            id: "cred-1".to_string(),
            name: Some("openai prod".to_string()),
            provider: Some("openai".to_string()),
            kind: Some("api_key".to_string()),
            vault_ref: Some("vault:kv/openai#key".to_string()),
            secret: Some(SENTINEL.to_string()),
            tenant: Some("acme".to_string()),
        };
        let rendered = format!("{seed_credential:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the seeded upstream credential reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("vault:kv/openai#key") && rendered.contains("acme"),
            "the vault reference and tenant must survive: a reference names where \
             the real value comes from and is not one: {rendered}"
        );

        // Two carriers, and the second is the one that is easy to miss.
        // `headers` is where an `Authorization:` value goes.
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), SENTINEL.to_string());
        let channel = AlertChannelConfig {
            channel_type: "pagerduty".to_string(),
            url: Some("https://events.pagerduty.com/v2/enqueue".to_string()),
            headers,
            routing_key: Some(SENTINEL.to_string()),
        };
        let rendered = format!("{channel:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "an alert channel credential reached Debug through routing_key or \
             headers: {rendered}"
        );
        assert!(
            rendered.contains("Authorization") && rendered.contains("pagerduty"),
            "the header names and the channel type must survive: which headers are \
             configured is the useful half of that map: {rendered}"
        );

        // The authored-config shim for the three outbound credential
        // shapes `sbproxy_modules` redacts at runtime.
        for shim in [
            OutboundCredentialSchema::TokenExchange {
                token_endpoint: "https://idp.example.test/token".to_string(),
                audience: "https://api.example.test".to_string(),
                scope: None,
                subject_token_issuers: Vec::new(),
                allowed_audiences: Vec::new(),
                act_depth_cap: 4,
                client_id: Some("client-1".to_string()),
                client_secret: Some(SENTINEL.to_string()),
                dpop: None,
            },
            OutboundCredentialSchema::ClientCredentials {
                token_endpoint: "https://idp.example.test/token".to_string(),
                client_id: "client-1".to_string(),
                client_secret: SENTINEL.to_string(),
                scope: None,
                audience: None,
                dpop: None,
            },
            OutboundCredentialSchema::VaultSecret {
                secret: SENTINEL.to_string(),
                header: "authorization".to_string(),
                scheme: "Bearer".to_string(),
                dpop: None,
            },
        ] {
            assert!(
                !format!("{shim:?}").contains(SENTINEL),
                "an outbound credential shim reached Debug: {shim:?}"
            );
        }

        // The twin of `sbproxy_vault::AwsAuth`, protected since the
        // first half of WOR-2640 while this one kept the derive.
        let aws = AwsBackendAuth::StaticKeys {
            access_key_id: "AKIAEXAMPLE".to_string(),
            secret_access_key: SENTINEL.to_string(),
            session_token: Some(SENTINEL.to_string()),
        };
        let rendered = format!("{aws:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the AWS secret key or session token reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("AKIAEXAMPLE"),
            "the access key id must survive: it authenticates nothing alone and \
             tells one misconfigured backend from another: {rendered}"
        );
        assert!(
            format!("{:?}", AwsBackendAuth::DefaultChain).contains("DefaultChain"),
            "the credential-free variant must still name itself"
        );

        // A second Vault client token, in the legacy compatibility block.
        let hashicorp = HashiCorpSecretsConfig {
            addr: "https://vault.example.test:8200".to_string(),
            token: Some(SENTINEL.to_string()),
            mount: "secret".to_string(),
        };
        let rendered = format!("{hashicorp:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the legacy Vault token reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("vault.example.test:8200"),
            "the Vault address must survive: {rendered}"
        );

        // A 32-byte Ed25519 private seed. Reading it signs directory and
        // agent card responses every verifier accepts as this operator's.
        let publish = WebBotAuthPublishConfig {
            enabled: true,
            key_id: "kid-1".to_string(),
            public_key_hex: "aa".repeat(32),
            agent_name: "acme-agent".to_string(),
            directory_url: "https://acme.example.test/.well-known".to_string(),
            description: None,
            contact_url: None,
            signing_key_hex: Some(SENTINEL.to_string()),
        };
        let rendered = format!("{publish:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the Web Bot Auth signing seed reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("kid-1") && rendered.contains(&"aa".repeat(32)),
            "the key id and the public key must survive: both are published on \
             purpose and they name the deployment: {rendered}"
        );

        // Two seeds in one block. The signing key mints tokens; the
        // content-key seed derives every EMS payload key ever issued.
        let olp: OlpConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "signing_key": SENTINEL,
            "key_id": "olp-kid-1",
            "issuer": "https://api.example.test",
            "content_key_seed": SENTINEL,
        }))
        .expect("olp fixture parses");
        let rendered = format!("{olp:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "an OLP seed reached Debug through signing_key or content_key_seed: \
             {rendered}"
        );
        assert!(
            rendered.contains("olp-kid-1") && rendered.contains("api.example.test"),
            "the kid and issuer must survive: both are advertised in the JWS \
             header and the well-known document: {rendered}"
        );

        // The HKDF input every CoMP quote-signing key is derived from
        // (WOR-2673). Reading it forges a publisher quote at any price,
        // which a buyer's client cannot tell from a real one.
        let comp: CompMarketplaceConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "master_key": SENTINEL,
            "rotation_id": "2026-q3-001",
            "publisher": { "name": "Example Co.", "contact": "licensing@example.test" },
            "tiers": [],
            "buyer_keys": [],
        }))
        .expect("comp fixture parses");
        let rendered = format!("{comp:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the CoMP master key reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("2026-q3-001") && rendered.contains("Example Co."),
            "the rotation label and the publisher must survive: both are published in \
             the manifest this bridge serves to anyone who asks: {rendered}"
        );
    }
}

#[cfg(test)]
mod host_backed_secret_reference_tests {
    use super::*;

    /// WOR-2433, after CI's secret-resolver drift guard. Both detectors
    /// classify through [`HOST_BACKED_SECRET_PREFIXES`] now, so the
    /// property worth asserting is over that table rather than over
    /// three hand-written strings: adding a prefix reaches
    /// `is_secret_reference` and `host_backed_secret_reference`
    /// together, and this fails if it ever reaches only one.
    #[test]
    fn every_prefix_in_the_shared_table_is_classified_by_both_detectors() {
        assert!(
            !HOST_BACKED_SECRET_PREFIXES.is_empty(),
            "an empty table would make every assertion below vacuous",
        );
        for (prefix, expected) in HOST_BACKED_SECRET_PREFIXES {
            // `//host/x` is the shape the historical `file://`
            // carve-out spared: the resolver has no such carve-out, so
            // neither may this.
            for tail in ["NAME", "/etc/sbproxy/creds", "a/b", "x", "//host/x"] {
                let value = format!("{prefix}{tail}");
                assert!(
                    is_secret_reference(&value),
                    "`{value}` is a reference the resolver reads and the shared classifier \
                     does not call one",
                );
                assert_eq!(
                    host_backed_secret_reference(&value),
                    Some(*expected),
                    "`{value}` is read off this host and was not classified as such",
                );
                // Whitespace cannot smuggle a reference past the
                // detector and into a field that trims later.
                for padded in [
                    format!(" {value}"),
                    format!("{value} "),
                    format!("\t{value}\n"),
                ] {
                    assert_eq!(
                        host_backed_secret_reference(&padded),
                        Some(*expected),
                        "`{padded:?}` slipped past the detector",
                    );
                }
            }
            // A prefix with nothing after it names no host resource,
            // because the resolver would have nothing to look up.
            // `is_secret_reference` is deliberately not asserted here:
            // `vault://env/` is still a syntactic provider URI to it,
            // and the wider of the two answers is the safe one for a
            // classifier whose job is to decide what must not be
            // printed inline.
            assert!(host_backed_secret_reference(prefix).is_none(), "`{prefix}`");
        }
    }

    /// The two detectors are ordered, not merely consistent: everything
    /// host-backed is a reference, and the operator-declared provider
    /// URIs are references that are *not* host-backed, which is the
    /// distinction `ConfinementPolicy::remote_document` rests on.
    #[test]
    fn a_provider_uri_is_a_reference_but_is_not_host_backed() {
        for value in [
            "secret://backend/name",
            "vault://prod/api-key",
            "awssm://prod/pepper",
            "gcpsm://p/s",
            "k8ssecret://ns/name",
            "secretfile://backend/name",
        ] {
            assert!(is_secret_reference(value), "`{value}`");
            assert!(
                host_backed_secret_reference(value).is_none(),
                "`{value}` resolves only against a backend the operator declared under \
                 proxy.secrets, so it must not be reported as a host read",
            );
        }
        // And an inline literal is neither.
        for value in [
            "hunter2",
            "",
            "   ",
            "https://example.test/x",
            "not-a-reference",
        ] {
            assert!(!is_secret_reference(value), "`{value}`");
            assert!(host_backed_secret_reference(value).is_none(), "`{value}`");
        }
    }

    /// Registry sentinel for `RootOfTrustConfig`
    /// (`scripts/secret-debug-registry.txt`).
    ///
    /// The config-side twin of `TransitConfig`. `token` is a secret
    /// reference and `resolve_crypto_field` deliberately exempts inline
    /// literals, so an operator may legitimately write the token itself
    /// here; `address` is unparsed and may carry userinfo.
    #[test]
    fn debug_never_renders_the_root_of_trust_token_or_address() {
        const SENTINEL: &str = "SENTINEL-ROT-9c4a";

        let root = RootOfTrustConfig {
            provider: RootOfTrustProvider::VaultTransit,
            address: format!("https://sbproxy:{SENTINEL}@vault.internal:8200"),
            mount: "transit".to_string(),
            key_name: "sbproxy-root".to_string(),
            token: format!("hvs.{SENTINEL}"),
            namespace: None,
            unwrap_cache_ttl_secs: 60,
            liveness_interval_secs: 30,
        };
        let rendered = format!("{root:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "the root-of-trust token or address reached Debug: {rendered}"
        );
        assert!(
            rendered.contains("RootOfTrustConfig")
                && rendered.contains("transit")
                && rendered.contains("sbproxy-root"),
            "the identifier, mount, and key name must survive so a misconfiguration is \
             diagnosable: {rendered}"
        );
        assert!(
            rendered.contains("[REDACTED]"),
            "the redaction must be visible rather than the field simply vanishing: {rendered}"
        );
    }
}
