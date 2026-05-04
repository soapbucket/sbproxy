//! Action module - enum dispatch for built-in action handlers.

pub mod a2a;
mod aiproxy;
pub mod content_negotiate;
pub mod graphql;
pub mod grpc;
pub mod grpc_web;
mod loadbalancer;
pub mod mcp;
pub mod routing;
pub mod storage;
pub mod versioning;
pub mod websocket;
pub use a2a::*;
pub use aiproxy::*;
pub use content_negotiate::{resolve_shapes, ContentNegotiateConfig, NegotiatedShapes};
pub use graphql::*;
pub use grpc::*;
pub use grpc_web::GrpcWebTranscoder;
pub use loadbalancer::*;
pub use mcp::{
    McpAction, McpActionConfig, McpFederatedServerConfig, McpGuardrailEntry, McpServerInfoConfig,
    McpServerPrefix,
};
pub use routing::{
    build_routing_strategy, list_routing_strategies, AlwaysFirstHealthyStrategy, LoraAwareStrategy,
    RoutingRequest, RoutingStrategy, RoutingStrategyRegistration, TargetState,
};
pub use storage::*;
pub use versioning::*;
pub use websocket::*;

use std::collections::HashMap;

use sbproxy_plugin::ActionHandler;
use serde::Deserialize;

/// Action handler - enum dispatch for built-in types.
/// Each variant holds its compiled config inline (no Box indirection).
/// New variants are added as modules are implemented.
pub enum Action {
    /// Reverse proxy to upstream.
    Proxy(ProxyAction),
    /// HTTP redirect (301, 302, 307, 308).
    Redirect(RedirectAction),
    /// Serve a fixed static response.
    Static(StaticAction),
    /// Echo request details back as JSON.
    Echo(EchoAction),
    /// Return a fixed JSON mock response.
    Mock(MockAction),
    /// Return a 1x1 transparent GIF tracking pixel.
    Beacon(BeaconAction),
    /// Distribute requests across multiple upstream targets.
    /// Wrapped in `Arc` so background tasks (active health probes) can
    /// hold a stable handle to the action without copying its state.
    LoadBalancer(std::sync::Arc<LoadBalancerAction>),
    /// AI proxy action (boxed because it is large and behind feature flag).
    AiProxy(Box<AiProxyAction>),
    /// Proxy requests to an upstream WebSocket server.
    WebSocket(WebSocketAction),
    /// Proxy requests to an upstream gRPC server.
    Grpc(GrpcAction),
    /// Proxy GraphQL requests to an upstream HTTP endpoint.
    GraphQL(GraphQLAction),
    /// Serve files from object storage (S3, GCS, Azure, local).
    Storage(CompiledStorage),
    /// Proxy requests to an A2A (Agent-to-Agent) endpoint.
    A2a(A2aAction),
    /// Federate one or more upstream MCP (Model Context Protocol)
    /// servers behind a single virtual MCP endpoint. Boxed because the
    /// federation handle holds an `Arc` plus per-server metadata and
    /// keeps the enum's stack footprint small.
    Mcp(Box<McpAction>),
    /// Placeholder for future variants - keeps the enum populated.
    Noop,
    /// Third-party plugin (only case using dynamic dispatch).
    Plugin(Box<dyn ActionHandler>),
}

/// Proxy action config - reverse-proxies requests to an upstream URL.
#[derive(Debug, Deserialize)]
pub struct ProxyAction {
    /// Upstream URL to forward requests to.
    pub url: String,
    /// When true, strip the matched origin path before forwarding.
    #[serde(default)]
    pub strip_base_path: bool,
    /// When true, forward the original query string to the upstream.
    #[serde(default)]
    pub preserve_query: bool,
    /// Override the `Host` request header sent to the upstream. By default
    /// the proxy uses the upstream URL's hostname (so vhost-routed upstreams
    /// like Vercel, Cloudflare, S3, ALBs work without configuration). Set
    /// this when the upstream expects a different `Host`.
    #[serde(default)]
    pub host_override: Option<String>,
    /// Controls for which forwarding headers to set on the upstream
    /// request. Each header is enabled by default; flip the matching
    /// `disable_*_header` field to opt out. Flattened into the action
    /// config so YAML can use flat keys (`disable_via_header: true`).
    #[serde(flatten, default)]
    pub forwarding: ForwardingHeaderControls,
    /// Optional upstream retry policy. When set with `max_attempts >
    /// 1`, the proxy retries on connect errors / timeouts.
    #[serde(default)]
    pub retry: Option<RetryConfig>,
    /// Optional DNS-based service discovery. When set, the proxy
    /// periodically resolves the upstream hostname and rotates
    /// through its A/AAAA record set rather than caching one IP for
    /// the lifetime of the connection pool. Use this in front of
    /// any K8s `Service`, ECS Cloud Map endpoint, Nomad service, or
    /// any backend whose IPs scale up / down independently of the
    /// proxy's reload cycle.
    #[serde(default)]
    pub service_discovery: Option<ServiceDiscoveryConfig>,
    /// Override the SNI server name sent during the upstream TLS
    /// handshake. By default the proxy sends the upstream URL's
    /// hostname so the cert chain validates against the same name.
    /// Set this when the upstream presents a cert for a *different*
    /// hostname than the URL host (typical SaaS-fronting pattern:
    /// connect to `tenant.cdn.provider.net` but the cert is for
    /// `*.provider.net`). The behaviour mirrors `curl --resolve`
    /// followed by Host-header rewriting at the TLS layer.
    #[serde(default)]
    pub sni_override: Option<String>,
    /// Pin upstream connections to a specific IP address (and
    /// optional port), bypassing DNS resolution for the URL host.
    /// Equivalent to `curl --connect-to`. Use cases:
    ///
    /// - Front a SaaS where the public DNS resolves to a CDN edge
    ///   you don't want to traverse.
    /// - Hard-pin to a regional endpoint without polluting the
    ///   system resolver.
    /// - Test against a staging IP while keeping the public hostname
    ///   in the request line.
    ///
    /// Examples:
    /// - `"203.0.113.7"`: connect to that IPv4 on the URL's port.
    /// - `"203.0.113.7:443"`: pin both IP and port.
    /// - `"[2001:db8::1]:8443"`: IPv6 form.
    ///
    /// `sni_override` and `host_override` stay independent: pin the
    /// connect address here, send a different SNI via `sni_override`,
    /// and rewrite the upstream `Host` header via `host_override`.
    #[serde(default)]
    pub resolve_override: Option<String>,
}

/// DNS-based service discovery for an upstream hostname.
///
/// When attached to a `proxy` action, the proxy resolves the URL's
/// hostname every `refresh_secs` and serves requests against the
/// freshest A/AAAA set rather than caching one IP for the lifetime
/// of the connection pool.
#[derive(Debug, Deserialize, Clone)]
pub struct ServiceDiscoveryConfig {
    /// Master switch. Default `true`, since the presence of the block
    /// usually means the user wants it on; set `false` to keep the
    /// config without enabling.
    #[serde(default = "default_sd_enabled")]
    pub enabled: bool,
    /// How often to re-resolve the upstream hostname, in seconds.
    /// Default `30`. Setting this below the upstream record's actual
    /// TTL has no effect (the system resolver still applies its own
    /// caching) but the proxy will at least notice changes within
    /// `refresh_secs` of the upstream-side update.
    #[serde(default = "default_sd_refresh_secs")]
    pub refresh_secs: u64,
    /// Whether to honour AAAA records (IPv6). Default `true`.
    #[serde(default = "default_sd_ipv6")]
    pub ipv6: bool,
}

impl Default for ServiceDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: default_sd_enabled(),
            refresh_secs: default_sd_refresh_secs(),
            ipv6: default_sd_ipv6(),
        }
    }
}

fn default_sd_enabled() -> bool {
    true
}

fn default_sd_refresh_secs() -> u64 {
    30
}

fn default_sd_ipv6() -> bool {
    true
}

/// Upstream retry policy attached to a proxy or load_balancer action.
///
/// When `max_attempts > 0`, the proxy retries the request on a
/// retryable failure (connect error, idempotent timeout) up to
/// `max_attempts` total attempts. Retries on response status codes are
/// out of scope for this initial cut because they require buffering
/// the upstream response.
#[derive(Debug, Deserialize, Clone)]
pub struct RetryConfig {
    /// Maximum total request attempts (including the original). A
    /// value of `0` or `1` disables retries. Default: 1 (no retry).
    #[serde(default = "default_retry_attempts")]
    pub max_attempts: u32,
    /// Conditions under which to retry. Recognized values:
    ///   * `"connect_error"`: TCP connect failure
    ///   * `"timeout"`: connect or idle timeout
    ///
    /// Status-code retries (e.g. `502`, `503`) are accepted but not
    /// yet implemented in this cut.
    #[serde(default = "default_retry_on")]
    pub retry_on: Vec<String>,
    /// Base backoff in milliseconds before the next attempt. Doubled
    /// on each retry (capped at 5s) to avoid thundering herds against
    /// a struggling upstream. Default `100`.
    #[serde(default = "default_retry_backoff_ms")]
    pub backoff_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_retry_attempts(),
            retry_on: default_retry_on(),
            backoff_ms: default_retry_backoff_ms(),
        }
    }
}

fn default_retry_attempts() -> u32 {
    1
}

fn default_retry_on() -> Vec<String> {
    vec!["connect_error".into(), "timeout".into()]
}

fn default_retry_backoff_ms() -> u64 {
    100
}

impl RetryConfig {
    /// Returns true when retries are actually enabled (more than one
    /// attempt allowed).
    pub fn enabled(&self) -> bool {
        self.max_attempts > 1
    }

    /// Returns true when the configured `retry_on` includes the given
    /// condition string (case-insensitive).
    pub fn allows(&self, cond: &str) -> bool {
        self.retry_on.iter().any(|s| s.eq_ignore_ascii_case(cond))
    }

    /// Backoff delay in milliseconds for the given attempt number
    /// (zero-based). Doubles with each attempt and caps at 5s.
    pub fn backoff_for_attempt(&self, attempt: u32) -> u64 {
        let scaled = self.backoff_ms.saturating_mul(1u64 << attempt.min(5));
        scaled.min(5_000)
    }
}

/// Per-action opt-out flags for the standard proxy forwarding headers.
///
/// All fields default to `false`, meaning the proxy will set the header.
/// Setting a field to `true` suppresses that header on the upstream
/// request for this action.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ForwardingHeaderControls {
    /// When true, suppress the `X-Forwarded-Host` header that the proxy
    /// would otherwise set to the client's original `Host` whenever the
    /// upstream `Host` is rewritten.
    #[serde(default)]
    pub disable_forwarded_host_header: bool,
    /// When true, suppress the `X-Forwarded-For` header that the proxy
    /// would otherwise append the client IP to.
    #[serde(default)]
    pub disable_forwarded_for_header: bool,
    /// When true, suppress the `X-Real-IP` header.
    #[serde(default)]
    pub disable_real_ip_header: bool,
    /// When true, suppress the `X-Forwarded-Proto` header (`http`/`https`).
    #[serde(default)]
    pub disable_forwarded_proto_header: bool,
    /// When true, suppress the `X-Forwarded-Port` header (the listener port).
    #[serde(default)]
    pub disable_forwarded_port_header: bool,
    /// When true, suppress the RFC 7239 `Forwarded` header.
    #[serde(default)]
    pub disable_forwarded_header: bool,
    /// When true, suppress the `Via` header that the proxy would otherwise
    /// append to identify itself as an HTTP intermediary.
    #[serde(default)]
    pub disable_via_header: bool,
}

impl ProxyAction {
    /// Build a ProxyAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Parse the URL into (host, port, tls) for Pingora upstream peer.
    pub fn parse_upstream(&self) -> anyhow::Result<(String, u16, bool)> {
        let parsed = url::Url::parse(&self.url)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("missing host in proxy URL"))?
            .to_string();
        let tls = parsed.scheme() == "https";
        let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
        Ok((host, port, tls))
    }
}

// --- RedirectAction ---

fn default_redirect_status() -> u16 {
    302
}

/// One row in a bulk-redirect table. CSV columns: `from,to,status`.
#[derive(Debug, Clone)]
pub struct BulkRedirectRow {
    /// Destination URL or path the request rewrites to.
    pub to: String,
    /// HTTP status code returned (defaults to the action's `status`).
    pub status: u16,
    /// Whether to forward the original query string. Defaults to the action's `preserve_query`.
    pub preserve_query: bool,
}

/// Where to load a bulk-redirect list from. Each origin may declare
/// its own source; lists are scoped per origin and never shared across
/// hostnames.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BulkListSource {
    /// CSV or YAML on the local filesystem. Loaded at config compile;
    /// reload picks up changes on the next config swap.
    File {
        /// Filesystem path. CSV is detected by the `.csv` extension;
        /// everything else parses as YAML.
        path: String,
    },
    /// HTTPS URL fetched at startup. The proxy refuses HTTP for safety
    /// since list contents drive 30x responses.
    Url {
        /// HTTPS URL of a CSV or YAML document.
        url: String,
        /// Force the document parser when the URL has no extension.
        /// `csv` or `yaml`.
        #[serde(default)]
        format: Option<String>,
    },
    /// Inline list embedded directly in the YAML config.
    Inline {
        /// One row per redirect.
        rows: Vec<BulkRedirectRowConfig>,
    },
}

/// Wire shape of a single row in `BulkListSource::Inline`.
#[derive(Debug, Clone, Deserialize)]
pub struct BulkRedirectRowConfig {
    /// Source path that triggers the redirect (exact match).
    pub from: String,
    /// Destination URL or path.
    pub to: String,
    /// Optional per-row status override.
    #[serde(default)]
    pub status: Option<u16>,
    /// Optional per-row query-preservation override.
    #[serde(default)]
    pub preserve_query: Option<bool>,
}

/// Compiled bulk-redirect lookup table. Construction parses the list
/// once; runtime is an `O(1)` `HashMap` lookup keyed on the request
/// path.
#[derive(Debug, Clone, Default)]
pub struct BulkRedirectTable {
    rows: std::collections::HashMap<String, BulkRedirectRow>,
}

impl BulkRedirectTable {
    /// Look up a row by exact path match.
    pub fn lookup(&self, path: &str) -> Option<&BulkRedirectRow> {
        self.rows.get(path)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// True when the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Build a table from a CSV body. Lines starting with `#` and blank
    /// lines are ignored. Header row (`from,to[,status]`) is detected
    /// when the first column is the literal string `from`.
    pub fn from_csv(body: &str, default_status: u16, default_preserve_query: bool) -> Self {
        let mut rows = std::collections::HashMap::new();
        for (lineno, raw) in body.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(',').map(|p| p.trim()).collect();
            // Skip the header row when present.
            if lineno == 0 && parts.first().map(|p| *p == "from").unwrap_or(false) {
                continue;
            }
            if parts.len() < 2 {
                tracing::warn!(line = lineno + 1, "skipping malformed bulk-redirect row");
                continue;
            }
            let from = parts[0].to_string();
            let to = parts[1].to_string();
            let status = parts
                .get(2)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(default_status);
            if from.is_empty() || to.is_empty() {
                continue;
            }
            rows.insert(
                from,
                BulkRedirectRow {
                    to,
                    status,
                    preserve_query: default_preserve_query,
                },
            );
        }
        Self { rows }
    }

    /// Build a table from a list of inline rows.
    pub fn from_inline(
        inline: &[BulkRedirectRowConfig],
        default_status: u16,
        default_preserve_query: bool,
    ) -> Self {
        let mut rows = std::collections::HashMap::with_capacity(inline.len());
        for row in inline {
            if row.from.is_empty() || row.to.is_empty() {
                continue;
            }
            rows.insert(
                row.from.clone(),
                BulkRedirectRow {
                    to: row.to.clone(),
                    status: row.status.unwrap_or(default_status),
                    preserve_query: row.preserve_query.unwrap_or(default_preserve_query),
                },
            );
        }
        Self { rows }
    }

    /// Build a table from a YAML body that decodes as `Vec<BulkRedirectRowConfig>`.
    pub fn from_yaml(
        body: &str,
        default_status: u16,
        default_preserve_query: bool,
    ) -> anyhow::Result<Self> {
        let rows: Vec<BulkRedirectRowConfig> = serde_yaml::from_str(body)?;
        Ok(Self::from_inline(
            &rows,
            default_status,
            default_preserve_query,
        ))
    }
}

/// Redirect action config - sends an HTTP redirect response.
///
/// Supports both single-target redirects (`url:`) and bulk redirects
/// (`bulk_list:`). When a bulk list is configured, an exact match on
/// the request path takes precedence; otherwise the action falls
/// through to the single-target `url:` (or skips when `url:` is
/// empty).
#[derive(Debug, Deserialize)]
pub struct RedirectAction {
    /// Destination URL of the redirect. Required when `bulk_list` is
    /// unset; optional fallback when `bulk_list` is set.
    #[serde(default)]
    pub url: String,
    /// Go configs use `status_code` instead of `status`.
    #[serde(default = "default_redirect_status", alias = "status_code")]
    pub status: u16,
    /// Go compat: preserve query string parameters during redirect.
    #[serde(default)]
    pub preserve_query: bool,
    /// Optional bulk-redirect source. Each origin owns its own list.
    #[serde(default)]
    pub bulk_list: Option<BulkListSource>,
    /// Compiled lookup table built once at config-load time. `None`
    /// when `bulk_list` is unset or load failed (in which case the
    /// action behaves like a plain single-target redirect).
    #[serde(skip)]
    pub table: Option<BulkRedirectTable>,
}

impl RedirectAction {
    /// Build a RedirectAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut action: Self = serde_json::from_value(value)?;
        if action.url.is_empty() && action.bulk_list.is_none() {
            anyhow::bail!("redirect action requires either `url` or `bulk_list`");
        }
        action.table = match action.bulk_list.as_ref() {
            None => None,
            Some(source) => match Self::load_table(source, action.status, action.preserve_query) {
                Ok(table) => Some(table),
                Err(e) => {
                    tracing::warn!(error = %e, "bulk_list failed to load; redirect action will fall back to url:");
                    None
                }
            },
        };
        Ok(action)
    }

    fn load_table(
        source: &BulkListSource,
        default_status: u16,
        default_preserve_query: bool,
    ) -> anyhow::Result<BulkRedirectTable> {
        match source {
            BulkListSource::Inline { rows } => Ok(BulkRedirectTable::from_inline(
                rows,
                default_status,
                default_preserve_query,
            )),
            BulkListSource::File { path } => {
                let body = std::fs::read_to_string(path)?;
                if path.ends_with(".csv") {
                    Ok(BulkRedirectTable::from_csv(
                        &body,
                        default_status,
                        default_preserve_query,
                    ))
                } else {
                    BulkRedirectTable::from_yaml(&body, default_status, default_preserve_query)
                }
            }
            BulkListSource::Url { url, format } => {
                if !url.starts_with("https://") {
                    anyhow::bail!(
                        "bulk_list url must use https (got {}); list contents drive 30x responses",
                        url
                    );
                }
                let body = reqwest::blocking::get(url)?.error_for_status()?.text()?;
                let kind = format
                    .as_deref()
                    .or_else(|| {
                        if url.ends_with(".csv") {
                            Some("csv")
                        } else if url.ends_with(".yaml") || url.ends_with(".yml") {
                            Some("yaml")
                        } else {
                            None
                        }
                    })
                    .unwrap_or("yaml");
                match kind {
                    "csv" => Ok(BulkRedirectTable::from_csv(
                        &body,
                        default_status,
                        default_preserve_query,
                    )),
                    _ => {
                        BulkRedirectTable::from_yaml(&body, default_status, default_preserve_query)
                    }
                }
            }
        }
    }
}

// --- StaticAction ---

fn default_static_status() -> u16 {
    200
}

/// Static action config - serves a fixed response body.
#[derive(Debug, Deserialize)]
pub struct StaticAction {
    /// Go configs use `status_code` instead of `status`.
    #[serde(default = "default_static_status", alias = "status_code")]
    pub status: u16,
    /// Go configs may use `text_body` instead of `body`.
    #[serde(default, alias = "text_body")]
    pub body: String,
    /// Optional `Content-Type` header for the response.
    #[serde(default)]
    pub content_type: Option<String>,
    /// Extra response headers to send.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Go configs use `json_body` to provide an inline JSON object that gets
    /// serialized as the response body. When present, overrides `body` and
    /// defaults `content_type` to `application/json`.
    #[serde(default)]
    pub json_body: Option<serde_json::Value>,
}

impl StaticAction {
    /// Build a StaticAction from a generic JSON config value.
    ///
    /// When `json_body` is present, it is serialized into the `body` field
    /// and `content_type` defaults to `application/json` if not already set.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let mut action: Self = serde_json::from_value(value)?;
        if let Some(json_val) = action.json_body.take() {
            action.body = serde_json::to_string(&json_val)?;
            if action.content_type.is_none() {
                action.content_type = Some("application/json".to_string());
            }
        }
        Ok(action)
    }
}

// --- EchoAction ---

/// Echo action config - returns request details as JSON.
#[derive(Debug, Deserialize, Default)]
pub struct EchoAction {}

impl EchoAction {
    /// Build an EchoAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }
}

// --- MockAction ---

fn default_mock_status() -> u16 {
    200
}

/// Mock action config - returns a fixed JSON response for API mocking.
#[derive(Debug, Deserialize)]
pub struct MockAction {
    /// HTTP status code returned to the client.
    #[serde(default = "default_mock_status")]
    pub status: u16,
    /// JSON body returned in the response.
    #[serde(default)]
    pub body: serde_json::Value,
    /// Extra response headers to send.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Optional artificial delay in milliseconds before responding.
    #[serde(default)]
    pub delay_ms: Option<u64>,
}

impl MockAction {
    /// Build a MockAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }
}

// --- BeaconAction ---

/// Beacon action config - returns a 1x1 transparent GIF pixel.
#[derive(Debug, Deserialize, Default)]
pub struct BeaconAction {}

impl BeaconAction {
    /// Build a BeaconAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }
}

impl Action {
    /// Get the type name for this action.
    pub fn action_type(&self) -> &str {
        match self {
            Self::Proxy(_) => "proxy",
            Self::Redirect(_) => "redirect",
            Self::Static(_) => "static",
            Self::Echo(_) => "echo",
            Self::Mock(_) => "mock",
            Self::Beacon(_) => "beacon",
            Self::LoadBalancer(_) => "load_balancer",
            Self::AiProxy(_) => "ai_proxy",
            Self::WebSocket(_) => "websocket",
            Self::Grpc(_) => "grpc",
            Self::GraphQL(_) => "graphql",
            Self::Storage(_) => "storage",
            Self::A2a(_) => "a2a",
            Self::Mcp(_) => "mcp",
            Self::Noop => "noop",
            Self::Plugin(p) => p.handler_type(),
        }
    }
}

impl std::fmt::Debug for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proxy(p) => f.debug_tuple("Proxy").field(p).finish(),
            Self::Redirect(r) => f.debug_tuple("Redirect").field(r).finish(),
            Self::Static(s) => f.debug_tuple("Static").field(s).finish(),
            Self::Echo(e) => f.debug_tuple("Echo").field(e).finish(),
            Self::Mock(m) => f.debug_tuple("Mock").field(m).finish(),
            Self::Beacon(b) => f.debug_tuple("Beacon").field(b).finish(),
            Self::LoadBalancer(lb) => f.debug_tuple("LoadBalancer").field(lb).finish(),
            Self::AiProxy(ai) => f.debug_tuple("AiProxy").field(ai).finish(),
            Self::WebSocket(ws) => f.debug_tuple("WebSocket").field(ws).finish(),
            Self::Grpc(g) => f.debug_tuple("Grpc").field(g).finish(),
            Self::GraphQL(gql) => f.debug_tuple("GraphQL").field(gql).finish(),
            Self::Storage(st) => f.debug_tuple("Storage").field(st).finish(),
            Self::A2a(a) => f.debug_tuple("A2a").field(a).finish(),
            Self::Mcp(m) => f.debug_tuple("Mcp").field(m).finish(),
            Self::Noop => write!(f, "Noop"),
            Self::Plugin(_) => write!(f, "Plugin(...)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_action_type() {
        let action = Action::Proxy(ProxyAction {
            url: "http://localhost:8080".to_string(),
            strip_base_path: true,
            preserve_query: true,
            host_override: None,
            forwarding: Default::default(),
            retry: None,
            service_discovery: None,
            sni_override: None,
            resolve_override: None,
        });
        assert_eq!(action.action_type(), "proxy");
    }

    #[test]
    fn noop_action_type() {
        let action = Action::Noop;
        assert_eq!(action.action_type(), "noop");
    }

    #[test]
    fn action_debug_proxy() {
        let action = Action::Proxy(ProxyAction {
            url: "http://example.com".to_string(),
            strip_base_path: false,
            preserve_query: true,
            host_override: None,
            forwarding: Default::default(),
            retry: None,
            service_discovery: None,
            sni_override: None,
            resolve_override: None,
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("Proxy"));
        assert!(debug.contains("example.com"));
    }

    #[test]
    fn action_debug_noop() {
        let action = Action::Noop;
        assert_eq!(format!("{:?}", action), "Noop");
    }

    // --- ProxyAction deserialization tests ---

    #[test]
    fn proxy_action_from_config() {
        let json = serde_json::json!({
            "type": "proxy",
            "url": "https://api.example.com:9443",
            "strip_base_path": true,
            "preserve_query": false
        });
        let action = ProxyAction::from_config(json).unwrap();
        assert_eq!(action.url, "https://api.example.com:9443");
        assert!(action.strip_base_path);
        assert!(!action.preserve_query);
    }

    #[test]
    fn proxy_action_from_config_defaults() {
        let json = serde_json::json!({
            "type": "proxy",
            "url": "http://localhost:3000"
        });
        let action = ProxyAction::from_config(json).unwrap();
        assert!(!action.strip_base_path);
        assert!(!action.preserve_query);
    }

    #[test]
    fn proxy_action_from_config_missing_url() {
        let json = serde_json::json!({"type": "proxy"});
        assert!(ProxyAction::from_config(json).is_err());
    }

    // --- parse_upstream tests ---

    #[test]
    fn parse_upstream_http() {
        let action = ProxyAction {
            url: "http://backend:8080".to_string(),
            strip_base_path: false,
            preserve_query: false,
            host_override: None,
            forwarding: Default::default(),
            retry: None,
            service_discovery: None,
            sni_override: None,
            resolve_override: None,
        };
        let (host, port, tls) = action.parse_upstream().unwrap();
        assert_eq!(host, "backend");
        assert_eq!(port, 8080);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_https_default_port() {
        let action = ProxyAction {
            url: "https://api.example.com".to_string(),
            strip_base_path: false,
            preserve_query: false,
            host_override: None,
            forwarding: Default::default(),
            retry: None,
            service_discovery: None,
            sni_override: None,
            resolve_override: None,
        };
        let (host, port, tls) = action.parse_upstream().unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_http_default_port() {
        let action = ProxyAction {
            url: "http://localhost".to_string(),
            strip_base_path: false,
            preserve_query: false,
            host_override: None,
            forwarding: Default::default(),
            retry: None,
            service_discovery: None,
            sni_override: None,
            resolve_override: None,
        };
        let (host, port, tls) = action.parse_upstream().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 80);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_https_custom_port() {
        let action = ProxyAction {
            url: "https://backend:9443".to_string(),
            strip_base_path: false,
            preserve_query: false,
            host_override: None,
            forwarding: Default::default(),
            retry: None,
            service_discovery: None,
            sni_override: None,
            resolve_override: None,
        };
        let (host, port, tls) = action.parse_upstream().unwrap();
        assert_eq!(host, "backend");
        assert_eq!(port, 9443);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_invalid_url() {
        let action = ProxyAction {
            url: "not a valid url".to_string(),
            strip_base_path: false,
            preserve_query: false,
            host_override: None,
            forwarding: Default::default(),
            retry: None,
            service_discovery: None,
            sni_override: None,
            resolve_override: None,
        };
        assert!(action.parse_upstream().is_err());
    }

    // --- RedirectAction tests ---

    #[test]
    fn redirect_action_type() {
        let action = Action::Redirect(RedirectAction {
            url: "https://example.com".to_string(),
            status: 301,
            preserve_query: false,
            bulk_list: None,
            table: None,
        });
        assert_eq!(action.action_type(), "redirect");
    }

    #[test]
    fn redirect_action_from_config() {
        let json = serde_json::json!({
            "type": "redirect",
            "url": "https://new-site.com/path",
            "status": 301
        });
        let action = RedirectAction::from_config(json).unwrap();
        assert_eq!(action.url, "https://new-site.com/path");
        assert_eq!(action.status, 301);
    }

    #[test]
    fn redirect_action_from_config_defaults() {
        let json = serde_json::json!({
            "type": "redirect",
            "url": "https://example.com"
        });
        let action = RedirectAction::from_config(json).unwrap();
        assert_eq!(action.status, 302);
    }

    #[test]
    fn redirect_action_from_config_missing_url() {
        let json = serde_json::json!({"type": "redirect"});
        assert!(RedirectAction::from_config(json).is_err());
    }

    #[test]
    fn redirect_action_debug() {
        let action = Action::Redirect(RedirectAction {
            url: "https://example.com".to_string(),
            status: 307,
            preserve_query: false,
            bulk_list: None,
            table: None,
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("Redirect"));
        assert!(debug.contains("example.com"));
    }

    // --- BulkRedirectTable tests ---

    #[test]
    fn bulk_csv_loads_rows_and_skips_blanks_and_comments() {
        let csv = "from,to,status\n# comment line\n\n/old/about,/about,301\n/old/help,/help\n,/empty-from,302\n/empty-to,,302\n";
        let table = BulkRedirectTable::from_csv(csv, 302, false);
        assert_eq!(
            table.len(),
            2,
            "blank rows + comment + empty fields are skipped"
        );
        let row = table.lookup("/old/about").unwrap();
        assert_eq!(row.to, "/about");
        assert_eq!(row.status, 301);
        let row = table.lookup("/old/help").unwrap();
        assert_eq!(
            row.status, 302,
            "default status applies when column omitted"
        );
    }

    #[test]
    fn bulk_csv_lookup_misses_unknown_paths() {
        let csv = "/a,/b,301\n";
        let table = BulkRedirectTable::from_csv(csv, 302, false);
        assert!(table.lookup("/unknown").is_none());
    }

    #[test]
    fn bulk_inline_loads_with_per_row_overrides() {
        let rows = vec![
            BulkRedirectRowConfig {
                from: "/old".to_string(),
                to: "/new".to_string(),
                status: Some(308),
                preserve_query: Some(true),
            },
            BulkRedirectRowConfig {
                from: "/x".to_string(),
                to: "/y".to_string(),
                status: None,
                preserve_query: None,
            },
        ];
        let table = BulkRedirectTable::from_inline(&rows, 302, false);
        assert_eq!(table.len(), 2);
        let row = table.lookup("/old").unwrap();
        assert_eq!(row.status, 308);
        assert!(row.preserve_query);
        let row = table.lookup("/x").unwrap();
        assert_eq!(row.status, 302);
        assert!(!row.preserve_query);
    }

    #[test]
    fn redirect_action_inline_bulk_list_compiles() {
        let json = serde_json::json!({
            "type": "redirect",
            "status_code": 301,
            "bulk_list": {
                "type": "inline",
                "rows": [
                    {"from": "/foo", "to": "/bar"},
                    {"from": "/baz", "to": "/qux", "status": 308}
                ]
            }
        });
        let action = RedirectAction::from_config(json).unwrap();
        let table = action.table.expect("table compiled");
        assert_eq!(table.len(), 2);
        assert_eq!(table.lookup("/foo").unwrap().status, 301);
        assert_eq!(table.lookup("/baz").unwrap().status, 308);
    }

    #[test]
    fn redirect_action_requires_url_or_bulk_list() {
        let json = serde_json::json!({"type": "redirect"});
        assert!(RedirectAction::from_config(json).is_err());
    }

    #[test]
    fn bulk_url_must_be_https() {
        let json = serde_json::json!({
            "type": "redirect",
            "url": "/fallback",
            "bulk_list": {"type": "url", "url": "http://example.com/list.csv"}
        });
        // The action should still construct (loader logs and skips on
        // failure) but the table should be None because the loader
        // refused the http url.
        let action = RedirectAction::from_config(json).unwrap();
        assert!(action.table.is_none(), "http url must not produce a table");
    }

    // --- StaticAction tests ---

    #[test]
    fn static_action_type() {
        let action = Action::Static(StaticAction {
            status: 200,
            body: "hello".to_string(),
            content_type: None,
            headers: HashMap::new(),
            json_body: None,
        });
        assert_eq!(action.action_type(), "static");
    }

    #[test]
    fn static_action_from_config() {
        let json = serde_json::json!({
            "type": "static",
            "status": 404,
            "body": "<h1>Not Found</h1>",
            "content_type": "text/html",
            "headers": {"X-Custom": "value"}
        });
        let action = StaticAction::from_config(json).unwrap();
        assert_eq!(action.status, 404);
        assert_eq!(action.body, "<h1>Not Found</h1>");
        assert_eq!(action.content_type.as_deref(), Some("text/html"));
        assert_eq!(action.headers.get("X-Custom").unwrap(), "value");
    }

    #[test]
    fn static_action_from_config_defaults() {
        let json = serde_json::json!({"type": "static"});
        let action = StaticAction::from_config(json).unwrap();
        assert_eq!(action.status, 200);
        assert_eq!(action.body, "");
        assert!(action.content_type.is_none());
        assert!(action.headers.is_empty());
    }

    #[test]
    fn static_action_debug() {
        let action = Action::Static(StaticAction {
            status: 503,
            body: "maintenance".to_string(),
            content_type: Some("text/plain".to_string()),
            headers: HashMap::new(),
            json_body: None,
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("Static"));
        assert!(debug.contains("maintenance"));
    }

    // --- EchoAction tests ---

    #[test]
    fn echo_action_type() {
        let action = Action::Echo(EchoAction {});
        assert_eq!(action.action_type(), "echo");
    }

    #[test]
    fn echo_action_from_config() {
        let json = serde_json::json!({"type": "echo"});
        let action = EchoAction::from_config(json).unwrap();
        // EchoAction has no fields; just verify it deserializes.
        let _ = action;
    }

    #[test]
    fn echo_action_debug() {
        let action = Action::Echo(EchoAction {});
        let debug = format!("{:?}", action);
        assert!(debug.contains("Echo"));
    }

    // --- MockAction tests ---

    #[test]
    fn mock_action_type() {
        let action = Action::Mock(MockAction {
            status: 200,
            body: serde_json::json!({"ok": true}),
            headers: HashMap::new(),
            delay_ms: None,
        });
        assert_eq!(action.action_type(), "mock");
    }

    #[test]
    fn mock_action_from_config() {
        let json = serde_json::json!({
            "type": "mock",
            "status": 201,
            "body": {"id": 42, "name": "test"},
            "headers": {"X-Request-Id": "abc123"},
            "delay_ms": 150
        });
        let action = MockAction::from_config(json).unwrap();
        assert_eq!(action.status, 201);
        assert_eq!(action.body["id"], 42);
        assert_eq!(action.body["name"], "test");
        assert_eq!(action.headers.get("X-Request-Id").unwrap(), "abc123");
        assert_eq!(action.delay_ms, Some(150));
    }

    #[test]
    fn mock_action_from_config_defaults() {
        let json = serde_json::json!({"type": "mock"});
        let action = MockAction::from_config(json).unwrap();
        assert_eq!(action.status, 200);
        assert!(action.body.is_null());
        assert!(action.headers.is_empty());
        assert!(action.delay_ms.is_none());
    }

    #[test]
    fn mock_action_debug() {
        let action = Action::Mock(MockAction {
            status: 200,
            body: serde_json::json!(null),
            headers: HashMap::new(),
            delay_ms: Some(50),
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("Mock"));
    }

    // --- BeaconAction tests ---

    #[test]
    fn beacon_action_type() {
        let action = Action::Beacon(BeaconAction {});
        assert_eq!(action.action_type(), "beacon");
    }

    #[test]
    fn beacon_action_from_config() {
        let json = serde_json::json!({"type": "beacon"});
        let action = BeaconAction::from_config(json).unwrap();
        let _ = action;
    }

    #[test]
    fn beacon_action_debug() {
        let action = Action::Beacon(BeaconAction {});
        let debug = format!("{:?}", action);
        assert!(debug.contains("Beacon"));
    }

    // --- WebSocketAction tests ---

    #[test]
    fn websocket_action_type() {
        let action = Action::WebSocket(WebSocketAction {
            url: "ws://localhost:8080".to_string(),
            subprotocols: vec![],
            max_message_size: 10 * 1024 * 1024,
            host_override: None,
            forwarding: Default::default(),
        });
        assert_eq!(action.action_type(), "websocket");
    }

    #[test]
    fn websocket_action_debug() {
        let action = Action::WebSocket(WebSocketAction {
            url: "wss://echo.example.com".to_string(),
            subprotocols: vec!["graphql-ws".to_string()],
            max_message_size: 1024,
            host_override: None,
            forwarding: Default::default(),
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("WebSocket"));
        assert!(debug.contains("echo.example.com"));
    }

    // --- GrpcAction tests ---

    #[test]
    fn grpc_action_type() {
        let action = Action::Grpc(GrpcAction {
            url: "grpc://localhost:50051".to_string(),
            tls: false,
            authority: None,
            timeout_secs: 30,
            forwarding: Default::default(),
        });
        assert_eq!(action.action_type(), "grpc");
    }

    #[test]
    fn grpc_action_debug() {
        let action = Action::Grpc(GrpcAction {
            url: "grpcs://api.example.com:50051".to_string(),
            tls: true,
            authority: Some("api.example.com".to_string()),
            timeout_secs: 60,
            forwarding: Default::default(),
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("Grpc"));
        assert!(debug.contains("api.example.com"));
    }

    // --- GraphQLAction tests ---

    #[test]
    fn graphql_action_type() {
        let action = Action::GraphQL(GraphQLAction {
            url: "https://api.example.com/graphql".to_string(),
            max_depth: 10,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        });
        assert_eq!(action.action_type(), "graphql");
    }

    #[test]
    fn graphql_action_debug() {
        let action = Action::GraphQL(GraphQLAction {
            url: "http://localhost:4000/graphql".to_string(),
            max_depth: 5,
            allow_introspection: false,
            validate_queries: true,
            host_override: None,
            forwarding: Default::default(),
        });
        let debug = format!("{:?}", action);
        assert!(debug.contains("GraphQL"));
        assert!(debug.contains("localhost"));
    }
}
