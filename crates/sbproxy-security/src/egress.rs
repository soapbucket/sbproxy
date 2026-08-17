//! Deterministic, purpose-scoped egress authorization.
//!
//! Default-deny allowlists per [`EgressPurpose`], DNS-pinned
//! [`AuthorizedDestination`]s, and a [`GovernedHttpClient`] contract that
//! never auto-follows redirects. Call sites adopt these primitives per
//! purpose; dial paths close the resolve-to-connect window through
//! [`EgressAuthorizer::verify_dial_addrs`] immediately before connect.
//!
//! [`evaluate_hop`] is the per-hop half of that contract for consumers
//! that let their HTTP client follow redirects. A host allowlist checked
//! once covers hop one and nothing after it, so a chain that starts at an
//! approved host and ends somewhere else was never actually gated. Every
//! consumer disables its client's own redirect following and runs each
//! `Location` back through [`evaluate_hop`], bounded by
//! [`MAX_REDIRECT_HOPS`]. Refusals are counted through
//! [`record_egress_refused`].

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use url::Url;

use crate::ssrf::is_private_ip;

/// Why an outbound destination was rejected.
///
/// Closed set only: never embeds secrets, allowlist text, or matched
/// host/path fragments that could leak configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDenied {
    /// No allowlist entry exists for this purpose at all.
    UnlistedPurpose,
    /// Host is not on the purpose allowlist.
    UnlistedHost,
    /// Scheme is not permitted for the purpose.
    DisallowedScheme,
    /// Port is not permitted for the purpose.
    DisallowedPort,
    /// Dial address is not among the addresses pinned at authorize time.
    DnsPinMismatch,
    /// Redirect `Location` host is not on the purpose allowlist.
    RedirectToUnlistedHost,
    /// Injected resolver could not produce addresses for the host.
    DnsResolutionFailed,
    /// URL had no host component.
    MissingHost,
    /// URL failed to parse.
    InvalidUrl,
    /// Resolved address is private/internal and not explicitly allowed.
    PrivateAddress,
    /// The redirect chain exceeded [`MAX_REDIRECT_HOPS`].
    TooManyRedirects,
}

impl EgressDenied {
    /// Stable, bounded label for metrics and structured logs.
    ///
    /// Closed set by construction: the returned strings are the same
    /// vocabulary as the variants, so a counter labelled with them
    /// cannot grow cardinality with traffic and cannot leak a host,
    /// allowlist entry, or secret.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::UnlistedPurpose => "unlisted_purpose",
            Self::UnlistedHost => "unlisted_host",
            Self::DisallowedScheme => "disallowed_scheme",
            Self::DisallowedPort => "disallowed_port",
            Self::DnsPinMismatch => "dns_pin_mismatch",
            Self::RedirectToUnlistedHost => "redirect_to_unlisted_host",
            Self::DnsResolutionFailed => "dns_resolution_failed",
            Self::MissingHost => "missing_host",
            Self::InvalidUrl => "invalid_url",
            Self::PrivateAddress => "private_address",
            Self::TooManyRedirects => "too_many_redirects",
        }
    }
}

/// Logical purpose for an outbound connection.
///
/// Each purpose has an independent host/scheme/port allowlist under
/// the sketched `proxy.egress` config shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EgressPurpose {
    /// Upstream AI provider (OpenAI, Anthropic, …).
    AiProvider,
    /// AI judge / evaluation endpoint.
    AiJudge,
    /// Federated MCP upstream.
    McpUpstream,
    /// OpenAPI tool HTTP call.
    OpenApiTool,
    /// OAuth/OIDC token exchange.
    TokenExchange,
    /// Outbound webhook delivery.
    Webhook,
    /// Usage / telemetry sink.
    UsageSink,
    /// Model artifact download.
    ModelArtifact,
    /// Engine artifact download.
    EngineArtifact,
    /// Extension bundle hook outbound call (`net:outbound` grant).
    BundleHook,
}

impl EgressPurpose {
    /// Stable, bounded label for metrics and structured logs.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::AiProvider => "ai_provider",
            Self::AiJudge => "ai_judge",
            Self::McpUpstream => "mcp_upstream",
            Self::OpenApiTool => "openapi_tool",
            Self::TokenExchange => "token_exchange",
            Self::Webhook => "webhook",
            Self::UsageSink => "usage_sink",
            Self::ModelArtifact => "model_artifact",
            Self::EngineArtifact => "engine_artifact",
            Self::BundleHook => "bundle_hook",
        }
    }
}

/// Per-purpose allowlist entry under the sketched `proxy.egress` shape.
#[derive(Debug, Clone, Default)]
pub struct PurposeAllowlist {
    /// Exact hostnames (or IP literals) permitted for this purpose.
    pub hosts: HashSet<String>,
    /// Permitted URL schemes (e.g. `https`). Empty means deny all schemes.
    pub schemes: HashSet<String>,
    /// Permitted ports. Empty means deny all ports.
    pub ports: HashSet<u16>,
    /// When true, resolved private/link-local addresses are permitted
    /// for hosts on this allowlist (operator opt-in).
    pub allow_private: bool,
}

/// Sketched top-level egress config (`proxy.egress`).
///
/// Not wired to any config loader in this lane; callers construct it
/// in tests or later adoption lanes.
#[derive(Debug, Clone, Default)]
pub struct EgressConfig {
    /// Allowlists keyed by purpose. Missing purpose => default deny.
    pub purposes: HashMap<EgressPurpose, PurposeAllowlist>,
}

/// Injected host resolver so unit tests never touch the network.
pub trait HostResolver: Send + Sync {
    /// Resolve `host:port` to socket addresses.
    ///
    /// Failures collapse to `()` because callers map any miss to
    /// [`EgressDenied::DnsResolutionFailed`] and must not surface
    /// resolver diagnostics (which can leak infra detail).
    #[allow(clippy::result_unit_err)] // deliberate: opaque fail -> EgressDenied
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ()>;
}

/// Destination that passed purpose/host/scheme/port checks with DNS
/// addresses pinned for the subsequent connect.
#[derive(Debug, Clone)]
pub struct AuthorizedDestination {
    /// Parsed destination URL (may still carry credentials until a
    /// cross-origin redirect strips them).
    pub url: Url,
    /// Socket addresses resolved at authorize time. Connectors must
    /// dial one of these rather than re-resolving (DNS-rebind defense).
    pub pinned_addrs: Vec<SocketAddr>,
    /// Purpose that authorized this destination.
    pub purpose: EgressPurpose,
}

impl AuthorizedDestination {
    /// True when `addr` is among the pinned addresses.
    pub fn pins(&self, addr: &SocketAddr) -> bool {
        self.pinned_addrs.contains(addr)
    }
}

/// Authorizer that decides whether a destination is allowed for a purpose.
#[derive(Debug, Clone)]
pub struct EgressAuthorizer {
    config: EgressConfig,
}

impl EgressAuthorizer {
    /// Build an authorizer from sketched `proxy.egress` config.
    pub fn new(config: EgressConfig) -> Self {
        Self { config }
    }

    /// Authorize `url` for `purpose`, pinning resolved addresses via `resolver`.
    ///
    /// Default deny: unlisted purpose or host is rejected.
    pub fn authorize(
        &self,
        purpose: EgressPurpose,
        url: &str,
        resolver: &dyn HostResolver,
    ) -> Result<AuthorizedDestination, EgressDenied> {
        self.authorize_inner(purpose, url, resolver, false)
    }

    /// Re-authorize a redirect `Location` before any second connect.
    ///
    /// Returns the new destination and whether credentials must be
    /// stripped (cross-origin redirect). Never follows the redirect.
    pub fn authorize_redirect(
        &self,
        from: &AuthorizedDestination,
        location: &str,
        resolver: &dyn HostResolver,
    ) -> Result<(AuthorizedDestination, bool), EgressDenied> {
        let absolute = resolve_redirect_url(&from.url, location)?;
        let dest = self
            .authorize_inner(from.purpose, absolute.as_str(), resolver, true)
            .map_err(|e| match e {
                EgressDenied::UnlistedHost => EgressDenied::RedirectToUnlistedHost,
                other => other,
            })?;
        let strip = is_cross_origin(&from.url, &dest.url);
        let dest = if strip {
            strip_url_credentials(dest)
        } else {
            dest
        };
        Ok((dest, strip))
    }

    /// Confirm a dial address matches the pin set (DNS-rebind defense).
    ///
    /// Runs at dial time, immediately before a connector is handed an
    /// address for `destination`. [`Self::verify_dial_addrs`] is the
    /// usual entry point: it re-resolves the host and pushes every
    /// candidate address through this check, so an answer that changed
    /// between authorization and connect is refused with
    /// [`EgressDenied::DnsPinMismatch`] instead of being dialled
    /// (WOR-2080).
    pub fn verify_pinned(
        &self,
        destination: &AuthorizedDestination,
        dial: &SocketAddr,
    ) -> Result<(), EgressDenied> {
        if destination.pins(dial) {
            Ok(())
        } else {
            Err(EgressDenied::DnsPinMismatch)
        }
    }

    /// Verify the dial addresses for `destination` immediately before
    /// connect (DNS-rebind defense, WOR-2080).
    ///
    /// Re-resolves the destination host through `resolver` and checks
    /// every returned address against the pin set recorded at authorize
    /// time via [`Self::verify_pinned`]. All addresses must be pinned:
    /// a connector may pick any address it is handed, so one unpinned
    /// address in the answer refuses the whole dial rather than
    /// trusting the connector's choice. On success the verified
    /// addresses are returned so the caller can hand them, and only
    /// them, to its connector (resolve-override) instead of letting the
    /// HTTP stack re-resolve on its own.
    pub fn verify_dial_addrs(
        &self,
        destination: &AuthorizedDestination,
        resolver: &dyn HostResolver,
    ) -> Result<Vec<SocketAddr>, EgressDenied> {
        let url = &destination.url;
        let host = url.host_str().ok_or(EgressDenied::MissingHost)?;
        let port = url
            .port_or_known_default()
            .ok_or(EgressDenied::DisallowedPort)?;
        let addrs = resolver
            .resolve(host, port)
            .map_err(|_| EgressDenied::DnsResolutionFailed)?;
        if addrs.is_empty() {
            return Err(EgressDenied::DnsResolutionFailed);
        }
        for addr in &addrs {
            self.verify_pinned(destination, addr)?;
        }
        Ok(addrs)
    }

    fn authorize_inner(
        &self,
        purpose: EgressPurpose,
        url: &str,
        resolver: &dyn HostResolver,
        _is_redirect: bool,
    ) -> Result<AuthorizedDestination, EgressDenied> {
        let allow = self
            .config
            .purposes
            .get(&purpose)
            .ok_or(EgressDenied::UnlistedPurpose)?;

        let parsed = Url::parse(url).map_err(|_| EgressDenied::InvalidUrl)?;
        let scheme = parsed.scheme();
        if !allow.schemes.contains(scheme) {
            return Err(EgressDenied::DisallowedScheme);
        }

        let host = parsed
            .host_str()
            .ok_or(EgressDenied::MissingHost)?
            .to_string();
        if !allow.hosts.contains(&host) {
            return Err(EgressDenied::UnlistedHost);
        }

        let port = parsed
            .port_or_known_default()
            .ok_or(EgressDenied::DisallowedPort)?;
        if !allow.ports.contains(&port) {
            return Err(EgressDenied::DisallowedPort);
        }

        let addrs = resolver
            .resolve(&host, port)
            .map_err(|_| EgressDenied::DnsResolutionFailed)?;
        if addrs.is_empty() {
            return Err(EgressDenied::DnsResolutionFailed);
        }

        if !allow.allow_private {
            for addr in &addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(EgressDenied::PrivateAddress);
                }
            }
        }

        Ok(AuthorizedDestination {
            url: parsed,
            pinned_addrs: addrs,
            purpose,
        })
    }
}

fn resolve_redirect_url(base: &Url, location: &str) -> Result<Url, EgressDenied> {
    Url::parse(location)
        .or_else(|_| base.join(location))
        .map_err(|_| EgressDenied::InvalidUrl)
}

fn is_cross_origin(from: &Url, to: &Url) -> bool {
    let from_host = from.host_str().unwrap_or("");
    let to_host = to.host_str().unwrap_or("");
    let from_port = from.port_or_known_default();
    let to_port = to.port_or_known_default();
    from.scheme() != to.scheme() || from_host != to_host || from_port != to_port
}

fn strip_url_credentials(mut dest: AuthorizedDestination) -> AuthorizedDestination {
    let _ = dest.url.set_username("");
    let _ = dest.url.set_password(None);
    dest
}

/// Decision returned when evaluating a redirect under the governed client contract.
#[derive(Debug, Clone)]
pub struct RedirectDecision {
    /// Re-authorized destination for the next connect.
    pub destination: AuthorizedDestination,
    /// True when credentials must be stripped before the next request.
    pub strip_credentials: bool,
}

/// Contract for a governed HTTP client.
///
/// Implementors must:
/// - never auto-follow redirects;
/// - re-authorize every redirect target via [`EgressAuthorizer`] before
///   a second connect;
/// - strip credentials on cross-origin redirects;
/// - return only closed [`EgressDenied`] reasons (no secrets / matched text).
pub trait GovernedHttpClient {
    /// Issue one request to an already-authorized destination.
    ///
    /// Must not follow redirects. On a redirect status, return the
    /// response with `redirect_location` populated so the caller can
    /// re-authorize before a second connect.
    fn request(
        &self,
        destination: &AuthorizedDestination,
        method: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<GovernedHttpResponse, EgressDenied>;
}

/// Single-hop response from a [`GovernedHttpClient`].
#[derive(Debug, Clone)]
pub struct GovernedHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers (name, value).
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// `Location` value when this is a redirect; not followed.
    pub redirect_location: Option<String>,
}

/// Pure-library seam that applies the redirect re-authorization contract
/// against an [`EgressAuthorizer`]. Concrete HTTP clients in later lanes
/// call this instead of following redirects themselves.
pub struct GovernedRedirectSeam;

impl GovernedRedirectSeam {
    /// Evaluate a redirect `Location` under the governed-client rules.
    pub fn evaluate(
        authorizer: &EgressAuthorizer,
        from: &AuthorizedDestination,
        location: &str,
        resolver: &dyn HostResolver,
    ) -> Result<RedirectDecision, EgressDenied> {
        let (destination, strip_credentials) =
            authorizer.authorize_redirect(from, location, resolver)?;
        Ok(RedirectDecision {
            destination,
            strip_credentials,
        })
    }
}

/// Live system DNS resolver for production egress checks.
///
/// This is the resolver a production dial path must pass. Passing a
/// fixture resolver instead makes the authorization a self-consistent
/// statement about the fixture rather than about the address the HTTP
/// stack is going to dial, which is worse than no check at all because
/// it reads as coverage. Unit tests inject a map resolver; production
/// call sites inject this.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemHostResolver;

impl HostResolver for SystemHostResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ()> {
        use std::net::ToSocketAddrs;
        (host, port)
            .to_socket_addrs()
            .map(|iter| iter.collect())
            .map_err(|_| ())
    }
}

/// Process-wide TTL for [`CachedSystemResolver`] answers.
const RESOLVER_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);
/// Entry ceiling for [`CachedSystemResolver`]. Reaching it clears the
/// map rather than evicting one entry, so a resolver cache can never
/// become an unbounded allocation under hostile input.
const RESOLVER_CACHE_MAX_ENTRIES: usize = 1024;

type ResolverCache =
    std::collections::HashMap<(String, u16), (std::time::Instant, Vec<SocketAddr>)>;

fn resolver_cache() -> &'static std::sync::Mutex<ResolverCache> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<ResolverCache>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// [`SystemHostResolver`] behind a short process-wide TTL cache.
///
/// This is the resolver a per-request gate should use.
/// [`EgressAuthorizer::authorize`] resolves on every call, and the
/// authorize-then-verify contract resolves twice; run uncached on a hot
/// dial path and that is two blocking `getaddrinfo` calls per request,
/// which is a latency regression rather than a security gain. It also
/// makes the pin check flaky by construction: a host behind a rotating
/// CDN answer can legitimately return a different address set between
/// the two calls, and the strict all-addresses-pinned rule would refuse
/// a request that nothing attacked.
///
/// Caching for a fixed 30-second TTL fixes both. DNS work drops to one
/// lookup per host per TTL, and authorize and verify read the same
/// answer, so a mismatch means the answer actually changed rather than
/// that two queries raced. The residual window is the TTL itself: an
/// answer that rebinds inside it is still dialled. That is the correct
/// trade because the pinned answer is what the connector is handed, so
/// a rebind mid-TTL cannot redirect a dial that has already been
/// pinned; it only delays noticing a legitimate DNS change.
#[derive(Debug, Default, Clone, Copy)]
pub struct CachedSystemResolver;

impl HostResolver for CachedSystemResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ()> {
        let key = (host.to_string(), port);
        if let Ok(cache) = resolver_cache().lock() {
            if let Some((at, addrs)) = cache.get(&key) {
                if at.elapsed() < RESOLVER_CACHE_TTL {
                    return Ok(addrs.clone());
                }
            }
        }
        let addrs = SystemHostResolver.resolve(host, port)?;
        if let Ok(mut cache) = resolver_cache().lock() {
            if cache.len() >= RESOLVER_CACHE_MAX_ENTRIES {
                cache.clear();
            }
            cache.insert(key, (std::time::Instant::now(), addrs.clone()));
        }
        Ok(addrs)
    }
}

/// Maximum redirect hops any governed egress path will follow.
///
/// Matches the bound the OpenAPI-backed MCP tool-call loop already
/// enforces (WOR-2080), so every consumer that adopts the per-hop
/// contract agrees on the same ceiling.
pub const MAX_REDIRECT_HOPS: usize = 10;

/// What a governed dial path does with a cross-origin redirect when no
/// [`EgressAuthorizer`] is attached.
///
/// With an authorizer attached the allowlist is the authority and this
/// rule does not apply: a hop to another allowlisted host is permitted,
/// a hop off the allowlist is refused. The rule only decides what
/// "allowlist" means when the operator has configured none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectRule {
    /// Refuse any hop that changes scheme, host, or port.
    ///
    /// The correct default for a request carrying a credential the HTTP
    /// client will not strip on its own (a provider API key in
    /// `x-api-key`, a `DD-API-KEY` header, an OAuth subject token in a
    /// form body). With no allowlist configured, the only host the
    /// operator has approved is the one they wrote down, so that is the
    /// only host the chain may reach.
    SameOriginOnly,
    /// Follow a cross-origin hop, reporting that credentials must be
    /// stripped before the next request.
    ///
    /// For paths where a cross-origin redirect is load bearing rather
    /// than anomalous: object-storage and CDN handoffs on artifact
    /// downloads redirect off the origin host by design, so refusing
    /// them would break the feature rather than harden it.
    CrossOriginAllowed,
}

/// One re-authorized redirect hop.
#[derive(Debug, Clone)]
pub struct RedirectHop {
    /// Absolute URL for the next request.
    pub url: Url,
    /// Addresses pinned for this hop, empty when the hop was evaluated
    /// without an authorizer (nothing resolved, so nothing to pin).
    pub pinned_addrs: Vec<SocketAddr>,
    /// True when the hop crosses origin and credentials must not ride
    /// along. Callers strip their own credential headers; they must not
    /// rely on the HTTP client, which strips `Authorization` but leaves
    /// provider-specific header names and request bodies alone.
    pub strip_credentials: bool,
}

/// Re-authorize one redirect hop before any second connect.
///
/// `hop_index` is 1 for the first redirect, so a chain is refused with
/// [`EgressDenied::TooManyRedirects`] once it passes
/// [`MAX_REDIRECT_HOPS`]. `from` is the URL that produced the redirect
/// and `location` is its raw `Location` value, which may be relative.
///
/// With an authorizer, the hop is authorized from scratch for `purpose`
/// (host, scheme, port, private-address, and fresh DNS pins), and an
/// off-allowlist host is reported as
/// [`EgressDenied::RedirectToUnlistedHost`] rather than
/// [`EgressDenied::UnlistedHost`] so refusals on hop one and hop two
/// stay distinguishable in metrics. Without one, `rule` decides.
pub fn evaluate_hop(
    authorizer: Option<&EgressAuthorizer>,
    purpose: EgressPurpose,
    from: &Url,
    location: &str,
    hop_index: usize,
    rule: RedirectRule,
    resolver: &dyn HostResolver,
) -> Result<RedirectHop, EgressDenied> {
    if hop_index > MAX_REDIRECT_HOPS {
        return Err(EgressDenied::TooManyRedirects);
    }
    let next = resolve_redirect_url(from, location)?;
    if next.host_str().is_none() {
        return Err(EgressDenied::MissingHost);
    }
    let strip_credentials = is_cross_origin(from, &next);
    match authorizer {
        Some(auth) => {
            let dest = auth
                .authorize(purpose, next.as_str(), resolver)
                .map_err(|e| match e {
                    EgressDenied::UnlistedHost => EgressDenied::RedirectToUnlistedHost,
                    other => other,
                })?;
            Ok(RedirectHop {
                url: dest.url,
                pinned_addrs: dest.pinned_addrs,
                strip_credentials,
            })
        }
        None if strip_credentials && rule == RedirectRule::SameOriginOnly => {
            Err(EgressDenied::RedirectToUnlistedHost)
        }
        None => Ok(RedirectHop {
            url: next,
            pinned_addrs: Vec::new(),
            strip_credentials,
        }),
    }
}

/// Count and log one refused outbound dial.
///
/// Emits `sbproxy_egress_refused_total{purpose, reason, tenant, origin}`.
/// Every label is bounded: `purpose` and `reason` are closed enums, and
/// callers pass a tenant id and a configuration-scoped `origin` (an
/// origin id, provider name, or sink name), never a request-scoped
/// value such as a URL, request id, or trace id. Pass `"unset"` for a
/// dimension the surrounding code genuinely does not carry, so an
/// absent attribution is visible in the series rather than silently
/// merged into another tenant's.
pub fn record_egress_refused(
    purpose: EgressPurpose,
    reason: EgressDenied,
    tenant: &str,
    origin: &str,
) {
    use prometheus::{register_int_counter_vec, IntCounterVec};
    use std::sync::OnceLock;
    static C: OnceLock<IntCounterVec> = OnceLock::new();
    let counter = C.get_or_init(|| {
        register_int_counter_vec!(
            "sbproxy_egress_refused_total",
            "Outbound dials refused by purpose-scoped egress authorization, by purpose, closed reason, tenant, and origin",
            &["purpose", "reason", "tenant", "origin"],
        )
        .expect("egress refusal counter registers")
    });
    let tenant = if tenant.is_empty() { "unset" } else { tenant };
    let origin = if origin.is_empty() { "unset" } else { origin };
    counter
        .with_label_values(&[purpose.as_label(), reason.as_label(), tenant, origin])
        .inc();
    tracing::warn!(
        target: "sbproxy::egress",
        purpose = purpose.as_label(),
        reason = reason.as_label(),
        tenant = tenant,
        origin = origin,
        "outbound dial refused by egress authorization"
    );
    if let Some(hook) = EGRESS_REFUSED_HOOK.get() {
        hook(purpose, reason, tenant, origin);
    }
}

/// A bridge a higher layer installs so a refusal also reaches a typed
/// event feed (WOR-2486).
///
/// `sbproxy-security` is a leaf crate deliberately kept off
/// `sbproxy-observe` (see the dependency note on this module's
/// `Cargo.toml`: `sbproxy-observe` depends on `sbproxy-security`, not
/// the other way, or the workspace would not build). A function pointer
/// installed once at boot is the whole bridge: this crate never learns
/// what `sbproxy_observe::EventType::EgressRefused` is, only that
/// something wants to know when [`record_egress_refused`] fires.
pub type EgressRefusedHook =
    fn(purpose: EgressPurpose, reason: EgressDenied, tenant: &str, origin: &str);

static EGRESS_REFUSED_HOOK: std::sync::OnceLock<EgressRefusedHook> = std::sync::OnceLock::new();

/// Install the bridge. Startup-only and set-once, like the process-wide
/// event egress it typically feeds: returns `Err` if one is already
/// registered, so a second boot path finds out rather than silently
/// replacing the first.
pub fn install_egress_refused_hook(hook: EgressRefusedHook) -> Result<(), &'static str> {
    EGRESS_REFUSED_HOOK
        .set(hook)
        .map_err(|_| "egress refused hook already registered")
}

/// Outcome recorded for one observed egress destination.
///
/// [`Self::Ungated`] covers a purpose reached with no [`EgressAuthorizer`]
/// gating it (or authorization skipped); a later [`Self::Allowed`] or
/// [`Self::Denied`] sighting for the same `(purpose, host, port)`, once
/// an authorizer is configured, overwrites the status recorded here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressSightingStatus {
    /// A configured [`EgressAuthorizer`] allowed this destination.
    Allowed,
    /// A configured [`EgressAuthorizer`] denied this destination.
    Denied,
    /// No authorizer gated this destination for this purpose.
    Ungated,
}

impl EgressSightingStatus {
    fn as_label(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Ungated => "ungated",
        }
    }
}

/// One process-lifetime-bounded inventory entry: an upstream destination
/// the gateway reached (or attempted to reach) for a given purpose.
///
/// Fields are deliberately narrow: `host`/`port`/`scheme` are the only
/// URL-derived data ever stored. The parsed [`Url`] itself (which can
/// carry userinfo and a query string) never enters this struct or the
/// inventory behind it, matching the label discipline in
/// [`record_egress_refused`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct EgressSighting {
    /// Purpose label (see [`EgressPurpose::as_label`]).
    pub purpose: &'static str,
    /// Destination host, or `"unparseable"` when the recorded URL failed
    /// to parse or carried no host component.
    pub host: String,
    /// Destination port, or `0` when the recorded URL failed to parse.
    pub port: u16,
    /// Destination scheme, or `"unparseable"` when the recorded URL
    /// failed to parse.
    pub scheme: String,
    /// Most recent status recorded for this destination.
    pub status: &'static str,
    /// Most recent denial reason, set when the most recent sighting was
    /// [`EgressSightingStatus::Denied`].
    pub last_reason: Option<&'static str>,
    /// Caller-supplied, configuration-scoped attribution (an origin id,
    /// provider name, or sink name), never a request-scoped value.
    pub origin: String,
    /// Unix milliseconds of the first sighting of this destination.
    pub first_seen_unix_ms: u64,
    /// Unix milliseconds of the most recent sighting of this destination.
    pub last_seen_unix_ms: u64,
    /// Count of sightings recorded as [`EgressSightingStatus::Allowed`]
    /// or [`EgressSightingStatus::Ungated`].
    pub allowed_count: u64,
    /// Count of sightings recorded as [`EgressSightingStatus::Denied`].
    pub denied_count: u64,
}

/// Mutable inventory state for one `(purpose, host, port)` key. Kept
/// separate from [`EgressSighting`] so the key's own fields are not
/// duplicated inside the map's values.
#[derive(Debug, Clone)]
struct EgressSightingInner {
    scheme: String,
    status: &'static str,
    last_reason: Option<&'static str>,
    origin: String,
    first_seen_unix_ms: u64,
    last_seen_unix_ms: u64,
    allowed_count: u64,
    denied_count: u64,
}

/// Entry ceiling for the egress sightings inventory.
///
/// Unlike [`RESOLVER_CACHE_MAX_ENTRIES`], reaching this cap does not
/// clear the map: the inventory exists to answer "what has this process
/// ever reached", so wiping it on saturation would erase the exact
/// history an operator is trying to audit. Instead a new key is dropped
/// once the map is full, a `saturated` warning fires once per process,
/// and every already-tracked destination keeps updating normally.
const EGRESS_INVENTORY_MAX_ENTRIES: usize = 1024;

type EgressInventory = HashMap<(EgressPurpose, String, u16), EgressSightingInner>;

fn egress_inventory() -> &'static std::sync::Mutex<EgressInventory> {
    static INVENTORY: std::sync::OnceLock<std::sync::Mutex<EgressInventory>> =
        std::sync::OnceLock::new();
    INVENTORY.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Latches true the first time the inventory refuses a new key, so the
/// saturation warning logs once per process rather than once per call.
fn egress_inventory_saturated() -> &'static std::sync::atomic::AtomicBool {
    static SATURATED: std::sync::OnceLock<std::sync::atomic::AtomicBool> =
        std::sync::OnceLock::new();
    SATURATED.get_or_init(|| std::sync::atomic::AtomicBool::new(false))
}

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Record one observed egress destination in the process-wide inventory.
///
/// `url` is parsed only for its `host`/`port`/`scheme`; the parsed
/// [`Url`] is never stored, so a URL carrying userinfo or a query string
/// leaves neither in the inventory. A `url` that fails to parse, or
/// parses without a host, is recorded under host `"unparseable"` and
/// port `0` rather than dropped, so a malformed destination still shows
/// up as a signal instead of disappearing silently.
///
/// `status` sets the sighting's status on this call, so the latest call
/// always wins: a later [`EgressSightingStatus::Allowed`] or
/// [`EgressSightingStatus::Denied`] from a configured
/// [`EgressAuthorizer`] overwrites a prior
/// [`EgressSightingStatus::Ungated`] sighting for the same destination.
/// [`EgressSightingStatus::Allowed`] and [`EgressSightingStatus::Ungated`]
/// both increment `allowed_count`; [`EgressSightingStatus::Denied`]
/// increments `denied_count` and stores `reason`'s label. The map is
/// capped at 1024 entries; once full, a new `(purpose, host, port)` key
/// is dropped rather than recorded, and a `saturated` warning is logged
/// once per process.
pub fn record_egress_seen(
    purpose: EgressPurpose,
    url: &str,
    origin: &str,
    status: EgressSightingStatus,
    reason: Option<EgressDenied>,
) {
    let (host, port, scheme) = match Url::parse(url) {
        Ok(parsed) => {
            let host = parsed.host_str().unwrap_or("unparseable").to_string();
            let port = parsed.port_or_known_default().unwrap_or(0);
            (host, port, parsed.scheme().to_string())
        }
        Err(_) => ("unparseable".to_string(), 0u16, "unparseable".to_string()),
    };
    let now_ms = now_unix_ms();
    let status_label = status.as_label();
    let reason_label = reason.map(EgressDenied::as_label);
    let origin = origin.to_string();
    let key = (purpose, host, port);

    let mut inventory = match egress_inventory().lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    if !inventory.contains_key(&key) && inventory.len() >= EGRESS_INVENTORY_MAX_ENTRIES {
        if !egress_inventory_saturated().swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                target: "sbproxy::egress",
                max_entries = EGRESS_INVENTORY_MAX_ENTRIES,
                "egress sightings inventory is full; new destinations are no longer recorded"
            );
        }
        return;
    }

    let entry = inventory.entry(key).or_insert_with(|| EgressSightingInner {
        scheme: String::new(),
        status: status_label,
        last_reason: None,
        origin: String::new(),
        first_seen_unix_ms: now_ms,
        last_seen_unix_ms: now_ms,
        allowed_count: 0,
        denied_count: 0,
    });

    entry.scheme = scheme;
    entry.status = status_label;
    entry.last_reason = reason_label;
    entry.origin = origin;
    entry.last_seen_unix_ms = now_ms;
    match status {
        EgressSightingStatus::Allowed | EgressSightingStatus::Ungated => {
            entry.allowed_count += 1;
        }
        EgressSightingStatus::Denied => {
            entry.denied_count += 1;
        }
    }
}

/// Snapshot the process-wide egress sightings inventory.
///
/// Sorted by `(purpose, host, port)` so repeated calls against an
/// unchanged inventory return the same order.
pub fn egress_inventory_snapshot() -> Vec<EgressSighting> {
    let inventory = match egress_inventory().lock() {
        Ok(guard) => guard,
        Err(_) => return Vec::new(),
    };
    let mut sightings: Vec<EgressSighting> = inventory
        .iter()
        .map(|((purpose, host, port), inner)| EgressSighting {
            purpose: purpose.as_label(),
            host: host.clone(),
            port: *port,
            scheme: inner.scheme.clone(),
            status: inner.status,
            last_reason: inner.last_reason,
            origin: inner.origin.clone(),
            first_seen_unix_ms: inner.first_seen_unix_ms,
            last_seen_unix_ms: inner.last_seen_unix_ms,
            allowed_count: inner.allowed_count,
            denied_count: inner.denied_count,
        })
        .collect();
    sightings.sort_by(|a, b| {
        (a.purpose, a.host.as_str(), a.port).cmp(&(b.purpose, b.host.as_str(), b.port))
    });
    sightings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Serializes every test below that touches the process-global
    /// egress sightings inventory, so they behave deterministically
    /// whether the runner isolates each test in its own process
    /// (nextest) or shares one process across threads (`cargo test`).
    fn test_state_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// Clears the global inventory and saturation latch. Callers must
    /// hold [`test_state_lock`] first.
    fn reset_egress_inventory() {
        if let Ok(mut inventory) = egress_inventory().lock() {
            inventory.clear();
        }
        egress_inventory_saturated().store(false, std::sync::atomic::Ordering::Relaxed);
    }

    struct MapResolver {
        map: HashMap<String, Vec<SocketAddr>>,
    }

    impl MapResolver {
        fn new(entries: Vec<(&str, Vec<SocketAddr>)>) -> Self {
            Self {
                map: entries
                    .into_iter()
                    .map(|(h, a)| (h.to_string(), a))
                    .collect(),
            }
        }
    }

    impl HostResolver for MapResolver {
        fn resolve(&self, host: &str, _port: u16) -> Result<Vec<SocketAddr>, ()> {
            self.map.get(host).cloned().ok_or(())
        }
    }

    /// Resolver that hands out one answer per call, in order, so a test
    /// can change the DNS answer between authorization and dial.
    struct SequenceResolver {
        answers: std::sync::Mutex<std::collections::VecDeque<Vec<SocketAddr>>>,
    }

    impl SequenceResolver {
        fn new(answers: Vec<Vec<SocketAddr>>) -> Self {
            Self {
                answers: std::sync::Mutex::new(answers.into_iter().collect()),
            }
        }
    }

    impl HostResolver for SequenceResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, ()> {
            self.answers
                .lock()
                .expect("test lock")
                .pop_front()
                .ok_or(())
        }
    }

    fn addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port)
    }

    fn ai_provider_https_443(hosts: &[&str]) -> EgressConfig {
        let mut allow = PurposeAllowlist::default();
        for h in hosts {
            allow.hosts.insert((*h).to_string());
        }
        allow.schemes.insert("https".to_string());
        allow.ports.insert(443);
        let mut purposes = HashMap::new();
        purposes.insert(EgressPurpose::AiProvider, allow);
        EgressConfig { purposes }
    }

    /// WOR-2486: `record_egress_refused` bridges to a typed event feed
    /// through a boot-installed hook, because `sbproxy-security` cannot
    /// depend on `sbproxy-observe` (see the doc on
    /// `install_egress_refused_hook`). This is the only test in the
    /// crate that installs the hook: it is set-once, like the process
    /// egress it typically feeds.
    #[test]
    fn record_egress_refused_calls_the_installed_hook() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        static SEEN: std::sync::Mutex<Vec<(&'static str, &'static str, String, String)>> =
            std::sync::Mutex::new(Vec::new());

        fn hook(purpose: EgressPurpose, reason: EgressDenied, tenant: &str, origin: &str) {
            CALLS.fetch_add(1, Ordering::SeqCst);
            SEEN.lock().expect("test lock").push((
                purpose.as_label(),
                reason.as_label(),
                tenant.to_owned(),
                origin.to_owned(),
            ));
        }

        let _ = install_egress_refused_hook(hook);

        record_egress_refused(
            EgressPurpose::TokenExchange,
            EgressDenied::UnlistedHost,
            "acme",
            "mcp-upstream",
        );

        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "the hook must fire exactly once per refusal"
        );
        let seen = SEEN.lock().expect("test lock");
        assert_eq!(
            seen.last(),
            Some(&(
                "token_exchange",
                "unlisted_host",
                "acme".to_string(),
                "mcp-upstream".to_string()
            ))
        );
    }

    /// A deployment that never called `install_egress_refused_hook` at
    /// all (the OSS default, or any process that boots before
    /// `sbproxy-core`'s registration line runs) must not panic on a
    /// refusal. This is the sibling of the test above and deliberately
    /// does not install a hook itself; nextest gives it its own
    /// process, so `EGRESS_REFUSED_HOOK` starts unset here regardless
    /// of what any other test in this file does.
    #[test]
    fn record_egress_refused_is_a_no_op_with_no_hook_installed() {
        record_egress_refused(
            EgressPurpose::AiProvider,
            EgressDenied::PrivateAddress,
            "acme",
            "openai",
        );
    }

    #[test]
    fn deny_by_default_rejects_unlisted_purpose_host() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        let resolver =
            MapResolver::new(vec![("evil.example", vec![addr([93, 184, 216, 34], 443)])]);

        let err = auth
            .authorize(
                EgressPurpose::AiProvider,
                "https://evil.example/v1",
                &resolver,
            )
            .expect_err("unlisted host must be denied");
        assert_eq!(err, EgressDenied::UnlistedHost);

        let err = auth
            .authorize(
                EgressPurpose::Webhook,
                "https://api.openai.com/v1",
                &resolver,
            )
            .expect_err("unlisted purpose must be denied");
        assert_eq!(err, EgressDenied::UnlistedPurpose);
    }

    #[test]
    fn authorized_destination_pins_resolved_addresses() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        let pinned = vec![addr([104, 18, 1, 1], 443), addr([104, 18, 1, 2], 443)];
        let resolver = MapResolver::new(vec![("api.openai.com", pinned.clone())]);

        let dest = auth
            .authorize(
                EgressPurpose::AiProvider,
                "https://api.openai.com/v1/chat",
                &resolver,
            )
            .expect("listed host must authorize");
        assert_eq!(dest.pinned_addrs, pinned);
        assert!(dest.pins(&pinned[0]));
        assert!(!dest.pins(&addr([1, 2, 3, 4], 443)));
        auth.verify_pinned(&dest, &pinned[1])
            .expect("pinned addr must verify");
        assert_eq!(
            auth.verify_pinned(&dest, &addr([8, 8, 8, 8], 443)),
            Err(EgressDenied::DnsPinMismatch)
        );
    }

    #[test]
    fn dial_time_verification_accepts_a_stable_dns_answer() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        let pinned = vec![addr([104, 18, 1, 1], 443), addr([104, 18, 1, 2], 443)];
        let resolver = SequenceResolver::new(vec![pinned.clone(), pinned.clone()]);

        let dest = auth
            .authorize(
                EgressPurpose::AiProvider,
                "https://api.openai.com/v1/chat",
                &resolver,
            )
            .expect("listed host must authorize");
        let dial = auth
            .verify_dial_addrs(&dest, &resolver)
            .expect("unchanged answer must verify");
        assert_eq!(dial, pinned, "verified dial set must equal the pin set");
    }

    #[test]
    fn dial_time_rebind_is_refused_with_dns_pin_mismatch() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        // Authorize sees the public answer; the dial-time answer has
        // been rebound to an internal address.
        let resolver = SequenceResolver::new(vec![
            vec![addr([104, 18, 1, 1], 443)],
            vec![addr([10, 0, 0, 5], 443)],
        ]);

        let dest = auth
            .authorize(
                EgressPurpose::AiProvider,
                "https://api.openai.com/v1/chat",
                &resolver,
            )
            .expect("listed host must authorize");
        assert_eq!(
            auth.verify_dial_addrs(&dest, &resolver),
            Err(EgressDenied::DnsPinMismatch),
            "a rebound answer must refuse, not dial"
        );
    }

    #[test]
    fn dial_time_partially_rebound_answer_is_refused() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        let pinned = addr([104, 18, 1, 1], 443);
        // One address is still pinned, one is new. The connector could
        // pick either, so the whole dial must be refused.
        let resolver =
            SequenceResolver::new(vec![vec![pinned], vec![pinned, addr([10, 0, 0, 5], 443)]]);

        let dest = auth
            .authorize(
                EgressPurpose::AiProvider,
                "https://api.openai.com/v1/chat",
                &resolver,
            )
            .expect("listed host must authorize");
        assert_eq!(
            auth.verify_dial_addrs(&dest, &resolver),
            Err(EgressDenied::DnsPinMismatch),
            "one unpinned address must refuse the whole dial"
        );
    }

    #[test]
    fn dial_time_resolution_failure_is_refused() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        // Only the authorize-time answer exists; the dial-time
        // resolution fails outright.
        let resolver = SequenceResolver::new(vec![vec![addr([104, 18, 1, 1], 443)]]);

        let dest = auth
            .authorize(
                EgressPurpose::AiProvider,
                "https://api.openai.com/v1/chat",
                &resolver,
            )
            .expect("listed host must authorize");
        assert_eq!(
            auth.verify_dial_addrs(&dest, &resolver),
            Err(EgressDenied::DnsResolutionFailed),
            "a failed dial-time resolution must refuse"
        );
    }

    #[test]
    fn redirect_to_unlisted_host_is_denied_before_second_connect() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        let resolver = MapResolver::new(vec![
            ("api.openai.com", vec![addr([104, 18, 1, 1], 443)]),
            ("evil.example", vec![addr([93, 184, 216, 34], 443)]),
        ]);

        let from = auth
            .authorize(
                EgressPurpose::AiProvider,
                "https://api.openai.com/v1",
                &resolver,
            )
            .expect("initial host allowed");

        // Seam must deny before any second connect would occur.
        let err =
            GovernedRedirectSeam::evaluate(&auth, &from, "https://evil.example/steal", &resolver)
                .expect_err("redirect to unlisted host must be denied");
        assert_eq!(err, EgressDenied::RedirectToUnlistedHost);
    }

    #[test]
    fn disallowed_scheme_is_denied() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        let resolver = MapResolver::new(vec![("api.openai.com", vec![addr([104, 18, 1, 1], 80)])]);

        let err = auth
            .authorize(
                EgressPurpose::AiProvider,
                "http://api.openai.com/v1",
                &resolver,
            )
            .expect_err("http must be denied when only https listed");
        assert_eq!(err, EgressDenied::DisallowedScheme);
    }

    #[test]
    fn disallowed_port_is_denied() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        let resolver =
            MapResolver::new(vec![("api.openai.com", vec![addr([104, 18, 1, 1], 8443)])]);

        let err = auth
            .authorize(
                EgressPurpose::AiProvider,
                "https://api.openai.com:8443/v1",
                &resolver,
            )
            .expect_err("non-allowlisted port must be denied");
        assert_eq!(err, EgressDenied::DisallowedPort);
    }

    #[test]
    fn cross_origin_redirect_strips_credentials() {
        let cfg = ai_provider_https_443(&["api.openai.com", "cdn.openai.com"]);
        let auth = EgressAuthorizer::new(cfg);
        let resolver = MapResolver::new(vec![
            ("api.openai.com", vec![addr([104, 18, 1, 1], 443)]),
            ("cdn.openai.com", vec![addr([104, 18, 2, 2], 443)]),
        ]);

        let from = auth
            .authorize(
                EgressPurpose::AiProvider,
                "https://user:secret@api.openai.com/v1",
                &resolver,
            )
            .expect("initial authorize");

        let decision =
            GovernedRedirectSeam::evaluate(&auth, &from, "https://cdn.openai.com/file", &resolver)
                .expect("same-purpose listed host redirect allowed");
        assert!(decision.strip_credentials);
        assert!(decision.destination.url.username().is_empty());
        assert_eq!(decision.destination.url.password(), None);
    }

    #[test]
    fn hop_without_an_authorizer_refuses_a_cross_origin_redirect() {
        let resolver = MapResolver::new(vec![]);
        let from = Url::parse("https://api.openai.com/v1/chat").expect("test url");
        let err = evaluate_hop(
            None,
            EgressPurpose::AiProvider,
            &from,
            "https://evil.example/steal",
            1,
            RedirectRule::SameOriginOnly,
            &resolver,
        )
        .expect_err("an unconfigured path must not leave the host it was told to call");
        assert_eq!(err, EgressDenied::RedirectToUnlistedHost);
    }

    #[test]
    fn hop_without_an_authorizer_follows_same_origin_and_keeps_credentials() {
        let resolver = MapResolver::new(vec![]);
        let from = Url::parse("https://api.openai.com/v1/chat").expect("test url");
        let hop = evaluate_hop(
            None,
            EgressPurpose::AiProvider,
            &from,
            "/v1/chat/completions",
            1,
            RedirectRule::SameOriginOnly,
            &resolver,
        )
        .expect("a same-origin hop is the one redirect an unconfigured path may follow");
        assert_eq!(
            hop.url.as_str(),
            "https://api.openai.com/v1/chat/completions"
        );
        assert!(!hop.strip_credentials);
        assert!(hop.pinned_addrs.is_empty(), "no authorizer means no pins");
    }

    #[test]
    fn cross_origin_allowed_rule_follows_but_reports_a_credential_strip() {
        let resolver = MapResolver::new(vec![]);
        let from = Url::parse("https://huggingface.co/model/resolve/main/f.bin").expect("test url");
        let hop = evaluate_hop(
            None,
            EgressPurpose::ModelArtifact,
            &from,
            "https://cdn.example/blob/abc",
            1,
            RedirectRule::CrossOriginAllowed,
            &resolver,
        )
        .expect("artifact downloads redirect to object storage by design");
        assert_eq!(hop.url.as_str(), "https://cdn.example/blob/abc");
        assert!(
            hop.strip_credentials,
            "the source credential must not follow the hop off-origin"
        );
    }

    #[test]
    fn hop_with_an_authorizer_refuses_an_off_allowlist_host_distinguishably() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        let resolver =
            MapResolver::new(vec![("evil.example", vec![addr([93, 184, 216, 34], 443)])]);
        let from = Url::parse("https://api.openai.com/v1/chat").expect("test url");
        let err = evaluate_hop(
            Some(&auth),
            EgressPurpose::AiProvider,
            &from,
            "https://evil.example/steal",
            1,
            RedirectRule::SameOriginOnly,
            &resolver,
        )
        .expect_err("an off-allowlist hop must be refused");
        assert_eq!(
            err,
            EgressDenied::RedirectToUnlistedHost,
            "hop-two refusals stay distinguishable from hop-one UnlistedHost"
        );
    }

    #[test]
    fn hop_with_an_authorizer_pins_the_redirect_target() {
        let auth =
            EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com", "cdn.openai.com"]));
        let pinned = vec![addr([104, 18, 2, 2], 443)];
        let resolver = MapResolver::new(vec![
            ("api.openai.com", vec![addr([104, 18, 1, 1], 443)]),
            ("cdn.openai.com", pinned.clone()),
        ]);
        let from = Url::parse("https://api.openai.com/v1/chat").expect("test url");
        let hop = evaluate_hop(
            Some(&auth),
            EgressPurpose::AiProvider,
            &from,
            "https://cdn.openai.com/file",
            1,
            RedirectRule::SameOriginOnly,
            &resolver,
        )
        .expect("an allowlisted hop authorizes");
        assert_eq!(hop.pinned_addrs, pinned);
        assert!(hop.strip_credentials, "the hop crosses origin");
    }

    #[test]
    fn hop_beyond_the_ceiling_is_refused_before_any_resolution() {
        // No resolver entries at all: reaching resolution would fail
        // with DnsResolutionFailed, so TooManyRedirects proves the hop
        // cap fires first.
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        let resolver = MapResolver::new(vec![]);
        let from = Url::parse("https://api.openai.com/v1/chat").expect("test url");
        // Matched rather than compared: `RedirectHop` is deliberately
        // not `PartialEq`, and deriving it to make one test read
        // slightly better would widen a public type's contract for the
        // convenience of an assertion.
        let outcome = evaluate_hop(
            Some(&auth),
            EgressPurpose::AiProvider,
            &from,
            "https://api.openai.com/again",
            MAX_REDIRECT_HOPS + 1,
            RedirectRule::SameOriginOnly,
            &resolver,
        );
        assert!(
            matches!(outcome, Err(EgressDenied::TooManyRedirects)),
            "the hop cap must fire before resolution is attempted"
        );
    }

    #[test]
    fn denial_and_purpose_labels_are_closed_and_leak_nothing() {
        for reason in [
            EgressDenied::UnlistedPurpose,
            EgressDenied::UnlistedHost,
            EgressDenied::DisallowedScheme,
            EgressDenied::DisallowedPort,
            EgressDenied::DnsPinMismatch,
            EgressDenied::RedirectToUnlistedHost,
            EgressDenied::DnsResolutionFailed,
            EgressDenied::MissingHost,
            EgressDenied::InvalidUrl,
            EgressDenied::PrivateAddress,
            EgressDenied::TooManyRedirects,
        ] {
            let label = reason.as_label();
            assert!(!label.is_empty());
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "label must be a bounded identifier, got {label}"
            );
        }
        assert_eq!(EgressPurpose::AiProvider.as_label(), "ai_provider");
        assert_eq!(EgressPurpose::ModelArtifact.as_label(), "model_artifact");
    }

    #[test]
    fn private_resolved_address_denied_by_default() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["internal.svc"]));
        let resolver = MapResolver::new(vec![("internal.svc", vec![addr([10, 0, 0, 5], 443)])]);

        let err = auth
            .authorize(
                EgressPurpose::AiProvider,
                "https://internal.svc/health",
                &resolver,
            )
            .expect_err("private IP must be denied unless allow_private");
        assert_eq!(err, EgressDenied::PrivateAddress);
    }

    #[test]
    fn egress_seen_records_a_single_sighting_with_counts() {
        let _guard = test_state_lock().lock().unwrap_or_else(|e| e.into_inner());
        reset_egress_inventory();

        record_egress_seen(
            EgressPurpose::AiProvider,
            "https://api.openai.com/v1/chat",
            "openai",
            EgressSightingStatus::Allowed,
            None,
        );

        let snapshot = egress_inventory_snapshot();
        assert_eq!(snapshot.len(), 1);
        let sighting = &snapshot[0];
        assert_eq!(sighting.purpose, EgressPurpose::AiProvider.as_label());
        assert_eq!(sighting.host, "api.openai.com");
        assert_eq!(sighting.port, 443);
        assert_eq!(sighting.scheme, "https");
        assert_eq!(sighting.status, "allowed");
        assert_eq!(sighting.last_reason, None);
        assert_eq!(sighting.origin, "openai");
        assert_eq!(sighting.allowed_count, 1);
        assert_eq!(sighting.denied_count, 0);
        assert!(sighting.first_seen_unix_ms > 0);
        assert_eq!(sighting.first_seen_unix_ms, sighting.last_seen_unix_ms);
    }

    #[test]
    fn ungated_then_denied_flips_status_and_keeps_counts() {
        let _guard = test_state_lock().lock().unwrap_or_else(|e| e.into_inner());
        reset_egress_inventory();

        record_egress_seen(
            EgressPurpose::McpUpstream,
            "https://mcp.example/tool",
            "mcp",
            EgressSightingStatus::Ungated,
            None,
        );
        record_egress_seen(
            EgressPurpose::McpUpstream,
            "https://mcp.example/tool",
            "mcp",
            EgressSightingStatus::Denied,
            Some(EgressDenied::UnlistedHost),
        );

        let snapshot = egress_inventory_snapshot();
        assert_eq!(snapshot.len(), 1);
        let sighting = &snapshot[0];
        assert_eq!(sighting.status, "denied", "the latest call's status wins");
        assert_eq!(
            sighting.last_reason,
            Some(EgressDenied::UnlistedHost.as_label())
        );
        assert_eq!(
            sighting.allowed_count, 1,
            "the earlier ungated sighting's count is kept"
        );
        assert_eq!(sighting.denied_count, 1);
    }

    #[test]
    fn cap_refuses_a_new_key_once_full_without_panicking() {
        let _guard = test_state_lock().lock().unwrap_or_else(|e| e.into_inner());
        reset_egress_inventory();

        for i in 0..EGRESS_INVENTORY_MAX_ENTRIES {
            let url = format!("https://host-{i}.example/");
            record_egress_seen(
                EgressPurpose::Webhook,
                &url,
                "cap-test",
                EgressSightingStatus::Allowed,
                None,
            );
        }
        assert_eq!(
            egress_inventory_snapshot().len(),
            EGRESS_INVENTORY_MAX_ENTRIES
        );

        // A new key past the cap must be dropped, not panic.
        record_egress_seen(
            EgressPurpose::Webhook,
            "https://host-overflow.example/",
            "cap-test",
            EgressSightingStatus::Allowed,
            None,
        );
        let snapshot = egress_inventory_snapshot();
        assert_eq!(
            snapshot.len(),
            EGRESS_INVENTORY_MAX_ENTRIES,
            "a new key past the cap must be dropped, not inserted"
        );
        assert!(
            !snapshot.iter().any(|s| s.host == "host-overflow.example"),
            "the dropped key must not appear in the snapshot"
        );

        // An already-tracked key must still update past the cap.
        record_egress_seen(
            EgressPurpose::Webhook,
            "https://host-0.example/",
            "cap-test",
            EgressSightingStatus::Allowed,
            None,
        );
        let updated = egress_inventory_snapshot()
            .into_iter()
            .find(|s| s.host == "host-0.example")
            .expect("existing key must still be present");
        assert_eq!(
            updated.allowed_count, 2,
            "an existing key keeps updating past the cap"
        );
    }

    #[test]
    fn snapshot_is_sorted_by_purpose_host_port() {
        let _guard = test_state_lock().lock().unwrap_or_else(|e| e.into_inner());
        reset_egress_inventory();

        record_egress_seen(
            EgressPurpose::Webhook,
            "https://b.example/",
            "order-test",
            EgressSightingStatus::Allowed,
            None,
        );
        record_egress_seen(
            EgressPurpose::Webhook,
            "https://a.example/",
            "order-test",
            EgressSightingStatus::Allowed,
            None,
        );
        record_egress_seen(
            EgressPurpose::AiProvider,
            "https://z.example/",
            "order-test",
            EgressSightingStatus::Allowed,
            None,
        );

        let snapshot = egress_inventory_snapshot();
        assert_eq!(snapshot.len(), 3);
        assert_eq!(snapshot[0].purpose, "ai_provider");
        assert_eq!(snapshot[0].host, "z.example");
        assert_eq!(snapshot[1].purpose, "webhook");
        assert_eq!(snapshot[1].host, "a.example");
        assert_eq!(snapshot[2].purpose, "webhook");
        assert_eq!(snapshot[2].host, "b.example");
    }

    #[test]
    fn unparseable_url_is_recorded_under_a_fixed_placeholder_host() {
        let _guard = test_state_lock().lock().unwrap_or_else(|e| e.into_inner());
        reset_egress_inventory();

        record_egress_seen(
            EgressPurpose::AiJudge,
            "not a url",
            "judge",
            EgressSightingStatus::Ungated,
            None,
        );

        let snapshot = egress_inventory_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].host, "unparseable");
        assert_eq!(snapshot[0].port, 0);
        assert_eq!(snapshot[0].scheme, "unparseable");
    }

    #[test]
    fn serialized_sighting_never_carries_userinfo_or_query() {
        let _guard = test_state_lock().lock().unwrap_or_else(|e| e.into_inner());
        reset_egress_inventory();

        record_egress_seen(
            EgressPurpose::TokenExchange,
            "https://svc-user:s3cr3t-token@auth.example:8443/oauth/token?client_secret=topsecret&scope=all",
            "token-exchange",
            EgressSightingStatus::Allowed,
            None,
        );

        let snapshot = egress_inventory_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].host, "auth.example");
        assert_eq!(snapshot[0].port, 8443);
        assert_eq!(snapshot[0].scheme, "https");

        let serialized = serde_json::to_string(&snapshot[0]).expect("sighting serializes");
        assert!(
            !serialized.contains("s3cr3t-token"),
            "no credential: {serialized}"
        );
        assert!(
            !serialized.contains("svc-user"),
            "no credential: {serialized}"
        );
        assert!(
            !serialized.contains("client_secret"),
            "no query: {serialized}"
        );
        assert!(!serialized.contains("topsecret"), "no query: {serialized}");
        assert!(!serialized.contains("scope=all"), "no query: {serialized}");
        assert!(
            !serialized.contains("/oauth/token"),
            "no full URL: {serialized}"
        );
    }
}
