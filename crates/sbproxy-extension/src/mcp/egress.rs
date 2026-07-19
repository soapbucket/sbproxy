//! Deterministic egress policy for gateway-originated MCP traffic.
//!
//! Thin-wraps [`sbproxy_security::egress`]: legacy `allow_by_default`
//! (omitted / default config) preserves pre-WOR-1791 behaviour, while
//! `deny_by_default` / `enforce` fail closed through the GF authorizer
//! and share its closed [`EgressDenied`] vocabulary.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use reqwest::Url;
use serde::Deserialize;
use sbproxy_security::egress::{
    AuthorizedDestination, EgressAuthorizer, EgressConfig, EgressPurpose, HostResolver,
    PurposeAllowlist,
};

/// Closed denial vocabulary from the GF egress foundation.
pub use sbproxy_security::egress::EgressDenied;

/// Egress behavior when a destination host does not match any rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    /// Only explicitly listed hosts or suffixes may be contacted.
    /// Delegates to the GF authorizer (fail closed).
    DenyByDefault,
    /// Alias of [`Self::DenyByDefault`]: fail closed via GF.
    Enforce,
    /// All hosts may be contacted except malformed URLs.
    /// Legacy default when egress config is omitted.
    #[default]
    AllowByDefault,
}

impl EgressMode {
    /// True when this mode fails closed through the GF authorizer.
    pub fn is_enforce(&self) -> bool {
        matches!(self, Self::DenyByDefault | Self::Enforce)
    }
}

/// Exact-host and suffix-based egress policy.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EgressPolicy {
    /// Default behavior for hosts that do not match an allow rule.
    #[serde(default)]
    pub mode: EgressMode,
    /// Exact hostnames, compared case-insensitively.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// DNS suffixes, compared on dot boundaries. Entries may be
    /// written as `example.com` or `.example.com`.
    #[serde(default)]
    pub suffixes: Vec<String>,
    /// When true, resolved private/link-local addresses are permitted
    /// for hosts on this allowlist (operator opt-in; mirrors GF).
    #[serde(default)]
    pub allow_private: bool,
    /// Name used in denial diagnostics, e.g. `action` or
    /// `server:github`. Retained for config compatibility; denials
    /// never embed this string (closed [`EgressDenied`] only).
    #[serde(default)]
    pub scope: String,
}

impl EgressPolicy {
    /// Return an allow-all policy with a diagnostic scope.
    pub fn allow_all(scope: impl Into<String>) -> Self {
        Self {
            mode: EgressMode::AllowByDefault,
            hosts: Vec::new(),
            suffixes: Vec::new(),
            allow_private: false,
            scope: scope.into(),
        }
    }

    /// Return a copy of this policy with a diagnostic scope attached.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = scope.into();
        self
    }

    /// Enforce this policy against a destination URL (OpenAPI tool purpose).
    ///
    /// When `mode` is [`EgressMode::AllowByDefault`], returns `Ok(())`
    /// without contacting the network (legacy compatible). When enforce /
    /// deny-by-default, delegates to the GF authorizer and fails closed.
    pub fn check_url(&self, url: &Url) -> Result<(), EgressDenied> {
        self.authorize(
            EgressPurpose::OpenApiTool,
            url.as_str(),
            &PermissiveTestResolver,
        )
        .map(|_| ())
    }

    /// Authorize `url` for `purpose` under this policy.
    ///
    /// `AllowByDefault` short-circuits to a synthetic authorized
    /// destination (no DNS). Enforce modes build a purpose allowlist from
    /// the configured hosts (plus the concrete host when a suffix matches)
    /// and call [`EgressAuthorizer::authorize`].
    pub fn authorize(
        &self,
        purpose: EgressPurpose,
        url: &str,
        resolver: &dyn HostResolver,
    ) -> Result<AuthorizedDestination, EgressDenied> {
        if !self.mode.is_enforce() {
            return legacy_passthrough(purpose, url);
        }
        let parsed = Url::parse(url).map_err(|_| EgressDenied::InvalidUrl)?;
        let host = parsed
            .host_str()
            .ok_or(EgressDenied::MissingHost)
            .map(normalize_host)?;
        if !self.host_permitted(&host) {
            return Err(EgressDenied::UnlistedHost);
        }
        let authorizer = self.authorizer_for(purpose, &host, &parsed)?;
        authorizer.authorize(purpose, url, resolver)
    }

    /// Re-authorize a redirect `Location` before any second connect.
    pub fn authorize_redirect(
        &self,
        from: &AuthorizedDestination,
        location: &str,
        resolver: &dyn HostResolver,
    ) -> Result<(AuthorizedDestination, bool), EgressDenied> {
        let absolute = from
            .url
            .join(location)
            .or_else(|_| Url::parse(location))
            .map_err(|_| EgressDenied::InvalidUrl)?;
        if !self.mode.is_enforce() {
            return legacy_passthrough(from.purpose, absolute.as_str()).map(|d| (d, false));
        }
        let host = absolute
            .host_str()
            .ok_or(EgressDenied::MissingHost)
            .map(normalize_host)?;
        // Fail closed on redirect escape before any second connect.
        if !self.host_permitted(&host) {
            return Err(EgressDenied::RedirectToUnlistedHost);
        }
        // Rebuild the purpose allowlist around the redirect host so
        // suffix-matched destinations still pin through GF.
        let authorizer = self.authorizer_for(from.purpose, &host, &absolute)?;
        authorizer.authorize_redirect(from, location, resolver)
    }

    fn host_permitted(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| normalize_host(h) == host)
            || self.suffixes.iter().any(|s| suffix_matches(host, s))
    }

    fn authorizer_for(
        &self,
        purpose: EgressPurpose,
        concrete_host: &str,
        parsed: &Url,
    ) -> Result<EgressAuthorizer, EgressDenied> {
        let scheme = parsed.scheme().to_string();
        let port = parsed
            .port_or_known_default()
            .ok_or(EgressDenied::DisallowedPort)?;
        let mut hosts: HashSet<String> = self.hosts.iter().map(|h| normalize_host(h)).collect();
        hosts.insert(concrete_host.to_string());
        let mut allow = PurposeAllowlist {
            hosts,
            schemes: HashSet::from([scheme, "https".to_string(), "http".to_string()]),
            ports: HashSet::from([port, 443, 80]),
            allow_private: self.allow_private,
        };
        // Permit the concrete port even when it is non-default.
        allow.ports.insert(port);
        let mut purposes = HashMap::new();
        purposes.insert(purpose, allow);
        Ok(EgressAuthorizer::new(EgressConfig { purposes }))
    }

}

/// System DNS resolver for production OpenAPI / MCP egress checks.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemHostResolver;

impl HostResolver for SystemHostResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ()> {
        use std::net::ToSocketAddrs;
        (host, port).to_socket_addrs().map(|i| i.collect()).map_err(|_| ())
    }
}

/// Resolver used by [`EgressPolicy::check_url`] when no caller-injected
/// resolver is available. Returns a fixed public address so host/scheme/
/// port checks still run without touching the network. Enforce paths that
/// need real DNS pins should pass [`SystemHostResolver`] (or a test map).
struct PermissiveTestResolver;

impl HostResolver for PermissiveTestResolver {
    fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, ()> {
        Ok(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            port,
        )])
    }
}

fn legacy_passthrough(
    purpose: EgressPurpose,
    url: &str,
) -> Result<AuthorizedDestination, EgressDenied> {
    let parsed = Url::parse(url).map_err(|_| EgressDenied::InvalidUrl)?;
    if parsed.host_str().is_none() {
        return Err(EgressDenied::MissingHost);
    }
    Ok(AuthorizedDestination {
        url: parsed,
        pinned_addrs: Vec::new(),
        purpose,
    })
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .trim_matches(['[', ']'])
        .to_ascii_lowercase()
}

fn suffix_matches(host: &str, suffix: &str) -> bool {
    let suffix = normalize_host(suffix.trim_start_matches('.'));
    host == suffix
        || host
            .strip_suffix(&suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
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

    fn url(raw: &str) -> Url {
        Url::parse(raw).expect("test url")
    }

    #[test]
    fn exact_host_allows_case_insensitively() {
        let policy = EgressPolicy {
            mode: EgressMode::DenyByDefault,
            hosts: vec!["API.EXAMPLE.COM".to_string()],
            suffixes: vec![],
            allow_private: false,
            scope: "server:api".to_string(),
        };
        let resolver = MapResolver::new(vec![("api.example.com", vec![addr([93, 184, 216, 34], 443)])]);

        policy
            .authorize(
                EgressPurpose::OpenApiTool,
                "https://api.example.com/v1",
                &resolver,
            )
            .expect("listed host must authorize");
    }

    #[test]
    fn suffix_matches_on_dot_boundary_only() {
        let policy = EgressPolicy {
            mode: EgressMode::DenyByDefault,
            hosts: vec![],
            suffixes: vec!["example.com".to_string()],
            allow_private: false,
            scope: "action".to_string(),
        };
        let resolver = MapResolver::new(vec![
            ("api.example.com", vec![addr([93, 184, 216, 34], 443)]),
            ("example.com", vec![addr([93, 184, 216, 34], 443)]),
            ("badexample.com", vec![addr([93, 184, 216, 34], 443)]),
        ]);

        assert!(policy
            .authorize(
                EgressPurpose::OpenApiTool,
                "https://api.example.com/v1",
                &resolver,
            )
            .is_ok());
        assert!(policy
            .authorize(
                EgressPurpose::OpenApiTool,
                "https://example.com/v1",
                &resolver,
            )
            .is_ok());
        assert_eq!(
            policy
                .authorize(
                    EgressPurpose::OpenApiTool,
                    "https://badexample.com/v1",
                    &resolver,
                )
                .unwrap_err(),
            EgressDenied::UnlistedHost
        );
    }

    #[test]
    fn enforce_mode_rejects_unlisted_host_with_closed_denial() {
        let policy = EgressPolicy {
            mode: EgressMode::Enforce,
            hosts: vec!["api.example.com".to_string()],
            suffixes: vec![],
            allow_private: false,
            scope: "server:api".to_string(),
        };
        let resolver = MapResolver::new(vec![(
            "attacker.test",
            vec![addr([93, 184, 216, 34], 443)],
        )]);

        let err = policy
            .authorize(
                EgressPurpose::OpenApiTool,
                "https://attacker.test/steal",
                &resolver,
            )
            .expect_err("unlisted host must be denied");
        assert_eq!(err, EgressDenied::UnlistedHost);
        // Closed vocabulary: Debug must not embed the host or scope.
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("attacker.test"),
            "denial must not embed host, got: {rendered}"
        );
        assert!(
            !rendered.contains("server:api"),
            "denial must not embed scope, got: {rendered}"
        );
    }

    #[test]
    fn deny_by_default_rejects_unlisted_host_with_closed_denial() {
        let policy = EgressPolicy {
            mode: EgressMode::DenyByDefault,
            hosts: vec!["api.example.com".to_string()],
            suffixes: vec![],
            allow_private: false,
            scope: "server:api".to_string(),
        };
        let resolver =
            MapResolver::new(vec![("attacker.test", vec![addr([93, 184, 216, 34], 443)])]);

        assert_eq!(
            policy
                .authorize(
                    EgressPurpose::OpenApiTool,
                    "https://attacker.test/steal",
                    &resolver,
                )
                .unwrap_err(),
            EgressDenied::UnlistedHost
        );
    }

    #[test]
    fn omitted_allow_by_default_preserves_legacy_compatibility() {
        let policy = EgressPolicy::allow_all("action");
        let resolver =
            MapResolver::new(vec![("attacker.test", vec![addr([93, 184, 216, 34], 443)])]);

        policy
            .authorize(
                EgressPurpose::OpenApiTool,
                "https://attacker.test/ok",
                &resolver,
            )
            .expect("legacy allow-by-default must not deny");
        assert!(policy.check_url(&url("https://attacker.test/ok")).is_ok());
    }

    #[test]
    fn redirect_to_unlisted_host_denied_before_second_connect() {
        let policy = EgressPolicy {
            mode: EgressMode::Enforce,
            hosts: vec!["api.example.com".to_string()],
            suffixes: vec![],
            allow_private: false,
            scope: "server:api".to_string(),
        };
        let resolver = MapResolver::new(vec![
            ("api.example.com", vec![addr([104, 18, 1, 1], 443)]),
            ("evil.example", vec![addr([93, 184, 216, 34], 443)]),
        ]);

        let from = policy
            .authorize(
                EgressPurpose::OpenApiTool,
                "https://api.example.com/v1",
                &resolver,
            )
            .expect("initial host allowed");

        let err = policy
            .authorize_redirect(&from, "https://evil.example/steal", &resolver)
            .expect_err("redirect escape must be denied");
        assert_eq!(err, EgressDenied::RedirectToUnlistedHost);
    }

    #[test]
    fn check_url_unlisted_host_uses_shared_egress_denied() {
        let policy = EgressPolicy {
            mode: EgressMode::DenyByDefault,
            hosts: vec!["other.example.com".to_string()],
            suffixes: vec![],
            allow_private: false,
            scope: "server:api".to_string(),
        };
        let err = policy
            .check_url(&url("https://api.example.com/pets/123"))
            .expect_err("unlisted host");
        assert_eq!(err, EgressDenied::UnlistedHost);
    }
}
