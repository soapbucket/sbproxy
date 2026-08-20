//! Compiled, immutable configuration snapshot.
//!
//! `CompiledOrigin` is the performance-optimized form of an origin config,
//! ready for zero-allocation request processing. `CompiledConfig` holds all
//! compiled origins plus the hostname routing map.

use std::collections::HashMap;
use std::sync::Arc;

use compact_str::CompactString;
use sbproxy_platform::storage::KVStore;
use smallvec::SmallVec;

use crate::types::{
    AccessLogConfig, AgentClassesConfig, AgentSkillEntry, AgentsJsonConfig, CompressionConfig,
    CorsConfig, ErrorPageEntry, HstsConfig, IdempotencyConfig, MessageSignaturesConfig,
    MirrorConfig, OlpConfig, OriginAttestationConfig, ProblemDetailsConfig, ProxyServerConfig,
    ProxyStatusConfig, ProxyWasmFilterAttachment, RequestModifierConfig, ResponseCacheConfig,
    ResponseModifierConfig, SessionConfig, UpstreamTimeouts, WebBotAuthPublishConfig,
};

/// Fully compiled, immutable origin ready for request processing.
///
/// The action, auth, policies, and transforms fields use `serde_json::Value`
/// as placeholders until the module crate defines concrete enum types.
#[derive(Clone)]
pub struct CompiledOrigin {
    /// Hostname this origin matches (e.g. `api.example.com`).
    pub hostname: CompactString,
    /// Stable identifier for this origin within its workspace.
    pub origin_id: CompactString,
    /// Digest of the config that decides what this origin's upstream
    /// returns, folded into every response-cache key it produces.
    ///
    /// Keeps a node from reading entries a differently-configured node
    /// wrote out of a shared store during a rolling change. Computed
    /// once here by [`crate::cache_identity::origin_cache_fingerprint`];
    /// the request path only reads it. See that module for what the
    /// projection covers and why it is narrow.
    pub cache_config_fingerprint: CompactString,
    /// Workspace that owns this origin (used for multi-tenant isolation).
    pub workspace_id: CompactString,
    /// WOR-1053: tenant this origin resolves to. `__default__` for
    /// single-tenant deployments; an explicit id when
    /// `origin.tenant_id` matches a declared `proxy.tenants[].id`.
    /// Stamped on every `RequestContext` the origin serves so
    /// downstream auth / policy / vault resolution can pick the
    /// tenant-scoped block.
    pub tenant_id: CompactString,

    /// Action configuration (proxy, redirect, static, etc.) as JSON until module-layer compilation.
    pub action_config: serde_json::Value,
    /// Optional authentication configuration as JSON until module-layer compilation.
    pub auth_config: Option<serde_json::Value>,
    /// Policy configurations (rate limit, WAF, IP filter, etc.) as JSON until module-layer compilation.
    pub policy_configs: Vec<serde_json::Value>,
    /// Transform configurations (JSON shape, encoding, etc.) as JSON until module-layer compilation.
    pub transform_configs: Vec<serde_json::Value>,
    /// Proxy-Wasm HTTP filter attachments in declaration order.
    pub filters: Vec<ProxyWasmFilterAttachment>,

    /// CORS configuration applied before the action runs.
    pub cors: Option<CorsConfig>,
    /// HSTS configuration emitting `Strict-Transport-Security` headers.
    pub hsts: Option<HstsConfig>,
    /// Response compression configuration.
    pub compression: Option<CompressionConfig>,
    /// Session cookie / storage configuration.
    pub session: Option<SessionConfig>,
    /// Per-origin custom-properties capture. When `None`,
    /// [`sbproxy_observe::PropertiesConfig::default`] applies at the
    /// call site.
    pub properties: Option<sbproxy_observe::PropertiesConfig>,
    /// Per-origin session-id capture. When `None`,
    /// [`sbproxy_observe::SessionsConfig::default`] applies at the
    /// call site.
    pub sessions: Option<sbproxy_observe::SessionsConfig>,
    /// Per-origin user-id capture. When `None`,
    /// [`sbproxy_observe::UserConfig::default`] applies at the call
    /// site.
    pub user: Option<sbproxy_observe::UserConfig>,
    /// When true, redirect plain HTTP requests to HTTPS.
    pub force_ssl: bool,
    /// Whitelist of HTTP methods this origin accepts.
    pub allowed_methods: SmallVec<[http::Method; 4]>,
    /// Request modifiers (header set/remove, path rewrite, etc.) executed before the action.
    pub request_modifiers: SmallVec<[RequestModifierConfig; 2]>,
    /// Response modifiers executed after the action returns.
    pub response_modifiers: SmallVec<[ResponseModifierConfig; 2]>,
    /// Per-origin static variables available for template interpolation.
    pub variables: Option<Box<HashMap<CompactString, serde_json::Value>>>,
    /// Forward rules: path-based routing to inline origins (kept as JSON for deferred compilation).
    pub forward_rules: Vec<serde_json::Value>,
    /// Fallback origin: serves when the primary upstream fails (kept as JSON for deferred compilation).
    pub fallback_origin: Option<serde_json::Value>,
    /// Per-status custom error response bodies. Each entry covers one
    /// or more HTTP status codes; multiple entries for the same code
    /// are content-negotiated against the inbound request's `Accept`
    /// header. See [`ErrorPageEntry`].
    pub error_pages: Option<Vec<ErrorPageEntry>>,
    /// RFC 9457 problem-details default renderer. When `Some` with
    /// `enabled = true`, proxy-generated errors that are *not* matched
    /// by an [`ErrorPageEntry`] render as `application/problem+json`.
    /// See [`ProblemDetailsConfig`].
    pub problem_details: Option<ProblemDetailsConfig>,
    /// RFC 9209 `Proxy-Status` response header configuration. When
    /// `Some` with `enabled = true`, the response filter stamps a
    /// structured `Proxy-Status` header on every non-2xx response.
    /// See [`ProxyStatusConfig`].
    pub proxy_status: Option<ProxyStatusConfig>,
    /// RFC 9745 / RFC 8594 deprecation announcement covering every
    /// route this origin serves, compiled (instants parsed, header
    /// values precomputed) at config load. A forward rule's own block
    /// overrides this one for the requests it matches; the per-rule
    /// compiled form lives on the runtime's compiled forward rules.
    /// See [`crate::types::CompiledDeprecation`].
    pub deprecation: Option<crate::types::CompiledDeprecation>,
    /// RFC 9421 HTTP Message Signatures verification. When `Some` with
    /// `verify = true`, the request filter enforces signature verification
    /// on every inbound request to this origin ahead of any downstream auth
    /// provider. See [`MessageSignaturesConfig`].
    pub message_signatures: Option<MessageSignaturesConfig>,
    /// WOR-808 PR7: Open License Protocol (OLP) issuer config. When
    /// `Some` with `enabled = true`, the data-plane serves
    /// `/.well-known/olp/token` (issuance) and
    /// `/.well-known/olp/key` (JWK publication). See [`OlpConfig`].
    pub olp: Option<OlpConfig>,
    /// WOR-805 AC#4: Web Bot Auth publish config. When `Some` with
    /// `enabled = true`, the data-plane serves
    /// `/.well-known/http-message-signatures-directory` and
    /// `/.well-known/web-bot-auth/agent-card`. See
    /// [`WebBotAuthPublishConfig`].
    pub web_bot_auth_publish: Option<WebBotAuthPublishConfig>,
    /// RFC 8594-style idempotency middleware configuration. When
    /// `Some` with `enabled = true`, the request body filter buffers
    /// the request body for the configured methods, hashes it, and
    /// short-circuits cache hits / conflicts before the action runs.
    /// See [`IdempotencyConfig`]. The actual cache backend is
    /// instantiated at pipeline-compile time in `sbproxy-core`.
    pub idempotency: Option<IdempotencyConfig>,
    /// Fully resolved upstream transport deadlines for this origin's
    /// proxied requests. Always concrete: absent YAML fields resolved
    /// to the built-in defaults at compile time, so the request path
    /// reads plain `Duration`s. Forward-rule inline origins inherit
    /// these values because peer selection reads them off the parent
    /// compiled origin. See [`UpstreamTimeouts`].
    pub timeouts: UpstreamTimeouts,
    /// Bot detection configuration (kept as JSON for deferred compilation).
    pub bot_detection: Option<serde_json::Value>,
    /// Threat protection configuration (kept as JSON for deferred compilation).
    pub threat_protection: Option<serde_json::Value>,
    /// on_request callbacks (kept as JSON for deferred compilation).
    pub on_request: Vec<serde_json::Value>,
    /// on_response callbacks (kept as JSON for deferred compilation).
    pub on_response: Vec<serde_json::Value>,
    /// Per-origin response-cache configuration. `None` means no cache.
    pub response_cache: Option<ResponseCacheConfig>,
    /// Optional shadow-traffic mirror configuration. When set, the proxy
    /// fires a fire-and-forget copy of each request at `mirror.url` and
    /// discards the response, useful for safe rollouts and replay-driven
    /// testing.
    pub mirror: Option<MirrorConfig>,
    /// Opaque per-origin extensions for out-of-tree config blocks.
    ///
    /// The compiler never inspects these values. Extension consumers
    /// read their own nested keys by name (mirrors the server-level
    /// `extensions` pattern).
    pub extensions: HashMap<String, serde_yaml::Value>,
    /// When true, the gateway intercepts `/.well-known/openapi.json` and
    /// `/.well-known/openapi.yaml` for this hostname and serves a
    /// per-host OpenAPI document derived from this config snapshot.
    pub expose_openapi: bool,
    /// Streaming safety rule identifiers enforced for this origin's
    /// AI responses. Threaded through `StreamSafetyCtx.rules` to the
    /// stream-safety hook.
    pub stream_safety: Vec<String>,
    /// Synthesised content-negotiate config emitted by
    /// [`crate::compile_origin`] when the origin has an
    /// `ai_crawl_control` policy or any content-shaping transform
    /// (`boilerplate`, `citation_block`, `json_envelope`). The runtime
    /// calls the content-negotiate resolver at request entry with this
    /// config to stamp the per-request content shape. `None` means
    /// the origin doesn't need content negotiation. Stored as opaque
    /// JSON so this crate stays independent of the modules crate.
    pub auto_content_negotiate: Option<serde_json::Value>,
    /// Per-origin `Content-Signal` response header value, validated
    /// at compile time against the closed enum
    /// `{ai-train, search, ai-input}`. Stored as a static-string
    /// reference so the response filter stamps the wire form without
    /// re-formatting on every request. `None` means the origin
    /// asserts no signal; the proxy stamps `TDM-Reservation: 1` on
    /// those responses instead.
    pub content_signal: Option<&'static str>,
    /// Per-origin Markdown projection tokens-per-byte ratio. `None`
    /// means the proxy uses the `DEFAULT_TOKEN_BYTES_RATIO` constant
    /// (0.25) at the call site. Threaded into the auto-wired
    /// `html_to_markdown` transform's `token_bytes_ratio` field at
    /// compile time so the `x-markdown-tokens` response header, the
    /// JSON envelope's `token_estimate`, and any downstream synthetic
    /// projection all share one source of truth.
    pub token_bytes_ratio: Option<f32>,
    /// Per-origin Agent Skills v0.2.0 advertisement.
    /// Empty when the origin does not opt in. Carried verbatim from
    /// the YAML so the projection module can resolve artifact bytes,
    /// stamp digests, and cache the manifest body.
    pub agent_skills: Vec<AgentSkillEntry>,
    /// Per-origin `/AGENTS.md` body served verbatim (WOR-809). `None`
    /// keeps the endpoint off for the origin.
    pub agents_md: Option<String>,
    /// Per-origin `/ai.txt` body served verbatim (WOR-809). `None`
    /// keeps the endpoint off for the origin.
    pub ai_txt: Option<String>,
    /// Per-origin agents.json manifest config (WOR-820). `None` keeps
    /// `/.well-known/agents.json` off for the origin.
    pub agents_json: Option<AgentsJsonConfig>,
    /// Per-origin outbound credential resolver config (WOR-802), kept
    /// as JSON for deferred compilation in `sbproxy-core`. `None` means
    /// the proxy adds no minted credential to upstream requests.
    pub outbound_credential: Option<serde_json::Value>,
    /// Opt this origin into outbound Web Bot Auth signing (WOR-805).
    /// When `true` and `proxy.web_bot_auth` is set, the proxy signs the
    /// upstream request with its Ed25519 key (RFC 9421, `tag=web-bot-auth`).
    pub outbound_web_bot_auth: bool,
    /// Per-origin consumption attestation overrides (WOR-2127). `None`
    /// leaves the origin on `proxy.attestation`'s role with no
    /// agreement named. The resolved posture the request path actually
    /// runs under is computed once per pipeline generation, not per
    /// request; see `sbproxy_core::attestation`.
    pub attestation: Option<OriginAttestationConfig>,
    /// WOR-1043 PR3: origin-scope observability overrides. Today the
    /// only nested surface is `log.redact.pii`, composed against the
    /// tenant-scope (or proxy-scope) PII pass at config-load. `None`
    /// keeps the origin inheriting whatever the parent scope decided.
    pub observability: Option<crate::types::OriginObservabilityConfig>,
    /// WOR-2491: per-item outcome of expanding this origin's
    /// `owasp_api_top10` pack entry, computed by
    /// `owasp_api_pack::expand_owasp_pack` in `compiler::compile_origin`.
    /// `None` means the origin had no `owasp_api_top10` policy. See
    /// [`crate::owasp_api_pack::PackManifest`].
    pub owasp_pack_manifest: Option<crate::owasp_api_pack::PackManifest>,
}

/// Per-purpose egress authorizers compiled once from the top-level
/// `egress:` config section (WOR-2476, WOR-2481 for `telemetry`).
///
/// Each field is `None` when its sub-block was omitted from `egress:`
/// (or `egress:` itself was omitted), or when the sub-block's `mode` is
/// the default `allow_by_default`. Consumers treat `None` as the purpose's
/// legacy ungated contract: `AiClient`'s documented `None`, the usage
/// sinks' and model-artifact fetcher's `with_egress` builders left
/// unset, the outbound-credential resolver's unauthenticated token
/// exchange, and the OTLP exporters dialing without a boot-time check.
/// `sbproxy_core::server::lifecycle` installs each `Some` value into
/// `sbproxy_security::egress`'s process-wide configured-gate registry so
/// consumers reached well past config compile (a lazily-built usage
/// sink, an artifact fetcher, a per-request token exchange) read the
/// same authorizer with no parameter threaded through the layers between.
#[derive(Clone, Default)]
pub struct CompiledEgressGates {
    /// Arms `EgressPurpose::AiProvider`.
    pub ai_providers: Option<sbproxy_security::egress::EgressAuthorizer>,
    /// Arms `EgressPurpose::UsageSink`.
    pub usage_sinks: Option<sbproxy_security::egress::EgressAuthorizer>,
    /// Arms `EgressPurpose::ModelArtifact`.
    pub model_artifacts: Option<sbproxy_security::egress::EgressAuthorizer>,
    /// Arms `EgressPurpose::TokenExchange` for the non-MCP resolver.
    pub token_exchange: Option<sbproxy_security::egress::EgressAuthorizer>,
    /// Arms `EgressPurpose::Telemetry` (WOR-2481).
    pub telemetry: Option<sbproxy_security::egress::EgressAuthorizer>,
}

/// The complete compiled config: all origins plus host-based routing.
#[derive(Clone, Default)]
pub struct CompiledConfig {
    /// Extension bundle discovery configuration preserved for the pipeline
    /// candidate loader. This crate does not resolve paths or fetch sources.
    pub extension_bundles: crate::extensions::ExtensionBundlesConfig,
    /// All compiled origins, in the order they were registered.
    pub origins: Vec<CompiledOrigin>,
    /// Maps hostname to index into `origins`.
    pub host_map: HashMap<CompactString, usize>,
    /// Server-level configuration (listen addresses, TLS, timeouts, etc.).
    pub server: ProxyServerConfig,
    /// Optional cluster-wide L2 store (Redis today). When `Some`, rate
    /// limit counters and response cache entries transparently use this
    /// shared backend so multiple proxy replicas share state.
    pub l2_store: Option<Arc<dyn KVStore>>,
    /// Mesh node handle, when the `mesh:` extension is configured.
    /// Type-erased as `Arc<dyn Any + Send + Sync>` so this crate
    /// stays independent of any concrete mesh implementation. Boot
    /// code downcasts to the concrete mesh node type.
    pub mesh: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// Optional structured-JSON access-log emission settings. `None`
    /// (the default) means no access-log lines are emitted; the
    /// request-path logging hook short-circuits before sampling.
    pub access_log: Option<AccessLogConfig>,
    /// Decision-event audit publication, lifted off
    /// `observability.log.decision_audit:` once at compile time so a
    /// decision point on the request path never walks the raw config to
    /// find out whether anyone is listening. `None` means no decision
    /// event publishes an audit record at all, which is also where an
    /// absent block and an explicit `enabled: false` land.
    ///
    /// Ask [`crate::types::DecisionAuditConfig::publishes`] rather than
    /// reading `enabled` and `events` at the call site. The precedence
    /// (a per-event entry beats the master switch, an unset master
    /// switch is off) lives on the type, and re-deriving it per emitting
    /// site is how two decision points end up disagreeing about whether
    /// the same config turned them on.
    pub decision_audit: crate::types::DecisionAuditScopes,
    /// Parsed top-level `agent_classes:` block. `None` means the
    /// operator did not author the block; the binary startup code
    /// constructs a resolver from defaults in that case. `Some(_)`
    /// carries the catalog selection and resolver tuning. Hosted-feed
    /// fields remain compatibility-only; the OSS runtime falls back to
    /// the built-in catalog instead of fetching them.
    pub agent_classes: Option<AgentClassesConfig>,
    /// WOR-1130: parsed top-level `rate_limits:` workspace budget +
    /// auto-suspend escalation. `None` means no workspace ceiling is
    /// configured. The binary installs a process-wide budget registry
    /// from this at startup.
    pub rate_limits: Option<crate::types::RateLimitsConfig>,
    /// Durable form of the audit trail. `None` (or `sink: memory`) leaves
    /// every channel on the bounded in-memory ring and its tracing
    /// target, neither of which survives the process. `sink: chain` makes
    /// the binary open a hash-chained, signed file at startup and feed
    /// every `security_audit` event into it.
    pub audit: Option<crate::types::AuditConfig>,
    /// WOR-1186: session-ledger emission config. `None` (or
    /// `enabled: false`) leaves the ledger off. The binary registers a
    /// ledger sink from this at startup.
    pub session_ledger: Option<crate::types::SessionLedgerConfig>,
    /// Request-event egress config. `None` (or `sink: none`) leaves
    /// the dispatch on the request path a no-op. The binary registers
    /// the process-wide sink from this at startup.
    pub request_events: Option<crate::types::RequestEventsConfig>,
    /// Typed-proxy-event egress config. `None` (or `sink: none`) leaves
    /// every publish site a single relaxed load. The binary starts the
    /// bounded queue and its delivery worker from this at startup; a
    /// reload does not restart it.
    pub events: Option<crate::types::EventsConfig>,
    /// Process-wide flags compiled from the top-level `flags:` block.
    /// The binary atomically replaces the live CEL store from this
    /// complete snapshot at boot and after every successful reload.
    pub flags: Vec<crate::types::FeatureFlagConfig>,
    /// Per-purpose egress authorizers compiled from the top-level
    /// `egress:` block (WOR-2476, WOR-2481). Default (every field `None`)
    /// when `egress:` is absent, which arms nothing and preserves every
    /// purpose's legacy ungated contract. See [`CompiledEgressGates`].
    pub egress: CompiledEgressGates,
}

impl CompiledConfig {
    /// Look up a compiled origin by hostname.
    ///
    /// Exact keys are checked first, so an exact origin always beats a
    /// wildcard. On a miss the hostname is walked one leading label at a
    /// time and each remaining suffix is probed under its `*.` spelling,
    /// so the longest matching suffix wins and `*.example.com` matches
    /// `a.example.com` and `a.b.example.com` but never `example.com`
    /// itself. Comparison is byte-exact: callers strip the port before
    /// resolving, and no case folding or IDN normalization is applied.
    pub fn resolve_origin(&self, hostname: &str) -> Option<&CompiledOrigin> {
        if let Some(&idx) = self.host_map.get(hostname) {
            return Some(&self.origins[idx]);
        }
        // Wildcard walk. This runs on cold paths only (admin surfaces,
        // projection transforms, tests); the request path goes through
        // the core `HostRouter`, which precomputes a suffix map instead
        // of rebuilding `*.suffix` probe keys per label.
        let mut rest = hostname;
        let mut probe = String::with_capacity(hostname.len() + 2);
        while let Some((label, suffix)) = rest.split_once('.') {
            if label.is_empty() {
                // A hostname with an empty label is malformed; a
                // wildcard matches one or more real labels, never an
                // empty one.
                return None;
            }
            if !suffix.is_empty() {
                probe.clear();
                probe.push_str("*.");
                probe.push_str(suffix);
                if let Some(&idx) = self.host_map.get(probe.as_str()) {
                    return Some(&self.origins[idx]);
                }
            }
            rest = suffix;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Default-constructed snapshots must have no mesh node attached; the
    // pipeline lifecycle extension is responsible for populating the field when
    // the `mesh:` extension is configured.
    #[test]
    fn compiled_config_default_has_no_mesh() {
        let cfg = CompiledConfig::default();
        assert!(cfg.mesh.is_none());
        assert!(cfg.l2_store.is_none());
        assert!(cfg.access_log.is_none());
        // Off is the default for decision audits too, and `None` here is
        // the whole of it: no per-event map to consult and no master
        // switch to inherit.
        assert!(cfg.decision_audit.is_empty());
        // WOR-2476/WOR-2481: an absent `egress:` block arms nothing.
        assert!(cfg.egress.ai_providers.is_none());
        assert!(cfg.egress.usage_sinks.is_none());
        assert!(cfg.egress.model_artifacts.is_none());
        assert!(cfg.egress.token_exchange.is_none());
        assert!(cfg.egress.telemetry.is_none());
    }
}
