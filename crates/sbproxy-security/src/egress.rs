//! Deterministic, purpose-scoped egress authorization.
//!
//! Default-deny allowlists per [`EgressPurpose`], DNS-pinned
//! [`AuthorizedDestination`]s, and a [`GovernedHttpClient`] contract that
//! never auto-follows redirects. Later lanes (G2/GS) adopt call sites;
//! this module ships pure library primitives only.

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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

    #[test]
    fn deny_by_default_rejects_unlisted_purpose_host() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["api.openai.com"]));
        let resolver = MapResolver::new(vec![(
            "evil.example",
            vec![addr([93, 184, 216, 34], 443)],
        )]);

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
        let err = GovernedRedirectSeam::evaluate(
            &auth,
            &from,
            "https://evil.example/steal",
            &resolver,
        )
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

        let decision = GovernedRedirectSeam::evaluate(
            &auth,
            &from,
            "https://cdn.openai.com/file",
            &resolver,
        )
        .expect("same-purpose listed host redirect allowed");
        assert!(decision.strip_credentials);
        assert!(decision.destination.url.username().is_empty());
        assert_eq!(decision.destination.url.password(), None);
    }

    #[test]
    fn private_resolved_address_denied_by_default() {
        let auth = EgressAuthorizer::new(ai_provider_https_443(&["internal.svc"]));
        let resolver =
            MapResolver::new(vec![("internal.svc", vec![addr([10, 0, 0, 5], 443)])]);

        let err = auth
            .authorize(
                EgressPurpose::AiProvider,
                "https://internal.svc/health",
                &resolver,
            )
            .expect_err("private IP must be denied unless allow_private");
        assert_eq!(err, EgressDenied::PrivateAddress);
    }
}
