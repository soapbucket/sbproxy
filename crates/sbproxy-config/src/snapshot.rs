//! Compiled, immutable configuration snapshot.
//!
//! `CompiledOrigin` is the performance-optimized form of an origin config,
//! ready for zero-allocation request processing. `CompiledConfig` holds all
//! compiled origins plus the hostname routing map.

use std::collections::HashMap;
use std::sync::Arc;

use compact_str::CompactString;
use sbproxy_platform::messenger::Messenger;
use sbproxy_platform::storage::KVStore;
use smallvec::SmallVec;

use crate::types::{
    AccessLogConfig, AgentClassesConfig, CompressionConfig, CorsConfig, HstsConfig, MirrorConfig,
    OriginRateLimitsConfig, ProxyServerConfig, RequestModifierConfig, ResponseCacheConfig,
    ResponseModifierConfig, SessionConfig,
};

/// Fully compiled, immutable origin ready for request processing.
///
/// The action, auth, policies, and transforms fields use `serde_json::Value`
/// as placeholders until the module crate defines concrete enum types.
pub struct CompiledOrigin {
    /// Hostname this origin matches (e.g. `api.example.com`).
    pub hostname: CompactString,
    /// Stable identifier for this origin within its workspace.
    pub origin_id: CompactString,
    /// Workspace that owns this origin (used for multi-tenant isolation).
    pub workspace_id: CompactString,

    /// Action configuration (proxy, redirect, static, etc.) as JSON until module-layer compilation.
    pub action_config: serde_json::Value,
    /// Optional authentication configuration as JSON until module-layer compilation.
    pub auth_config: Option<serde_json::Value>,
    /// Policy configurations (rate limit, WAF, IP filter, etc.) as JSON until module-layer compilation.
    pub policy_configs: Vec<serde_json::Value>,
    /// Transform configurations (JSON shape, encoding, etc.) as JSON until module-layer compilation.
    pub transform_configs: Vec<serde_json::Value>,

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
    /// Custom error pages configuration (kept as JSON for deferred evaluation).
    pub error_pages: Option<serde_json::Value>,
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
    /// Per-origin rate-limit budget. `None` means the operator did
    /// not author a `rate_limits:` block and the rate-limit middleware
    /// stays off for this origin. `Some(_)` carries the typed budget
    /// so the request pipeline can mount the middleware ahead of
    /// policies.
    pub rate_limits: Option<OriginRateLimitsConfig>,
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
}

/// The complete compiled config: all origins plus host-based routing.
#[derive(Default)]
pub struct CompiledConfig {
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
    /// Optional shared message bus. Built from
    /// `proxy.messenger_settings` at compile time. When `Some`,
    /// components such as a semantic-cache purge subscriber can fan
    /// events across replicas; when `None`, those components must
    /// degrade to no-op semantics.
    pub messenger: Option<Arc<dyn Messenger>>,
    /// Mesh node handle, when the `mesh:` extension is configured.
    /// Type-erased as `Arc<dyn Any + Send + Sync>` so this crate
    /// stays independent of any concrete mesh implementation. Boot
    /// code downcasts to the concrete mesh node type.
    pub mesh: Option<Arc<dyn std::any::Any + Send + Sync>>,
    /// Optional structured-JSON access-log emission settings. `None`
    /// (the default) means no access-log lines are emitted; the
    /// request-path logging hook short-circuits before sampling.
    pub access_log: Option<AccessLogConfig>,
    /// Parsed top-level `agent_classes:` block. `None` means the
    /// operator did not author the block; the binary startup code
    /// constructs a resolver from defaults in that case. `Some(_)`
    /// carries the typed catalog source / hosted-feed URL / resolver
    /// tuning so the binary can build the correct `AgentClassResolver`
    /// at startup.
    pub agent_classes: Option<AgentClassesConfig>,
}

impl CompiledConfig {
    /// Look up a compiled origin by hostname.
    pub fn resolve_origin(&self, hostname: &str) -> Option<&CompiledOrigin> {
        self.host_map.get(hostname).map(|&idx| &self.origins[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Default-constructed snapshots must have no mesh node attached; the
    // enterprise startup hook is responsible for populating the field when
    // the `mesh:` extension is configured.
    #[test]
    fn compiled_config_default_has_no_mesh() {
        let cfg = CompiledConfig::default();
        assert!(cfg.mesh.is_none());
        assert!(cfg.l2_store.is_none());
        assert!(cfg.messenger.is_none());
        assert!(cfg.access_log.is_none());
    }
}
