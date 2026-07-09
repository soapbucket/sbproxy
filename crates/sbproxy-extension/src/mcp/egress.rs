//! Deterministic egress policy for gateway-originated MCP traffic.
//!
//! The policy is intentionally small: exact hostnames and DNS suffixes.
//! It is evaluated on a parsed URL so callers enforce it immediately
//! before opening an outbound connection and again on redirect targets.

use reqwest::Url;
use serde::Deserialize;

/// Egress behavior when a destination host does not match any rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    /// Only explicitly listed hosts or suffixes may be contacted.
    DenyByDefault,
    /// All hosts may be contacted except malformed URLs.
    #[default]
    AllowByDefault,
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
    /// Name used in denial diagnostics, e.g. `action` or
    /// `server:github`.
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
            scope: scope.into(),
        }
    }

    /// Return a copy of this policy with a diagnostic scope attached.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = scope.into();
        self
    }

    /// Enforce this policy against a destination URL.
    pub fn check_url(&self, url: &Url) -> Result<(), EgressDenied> {
        let Some(host) = url.host_str() else {
            return Err(EgressDenied {
                scope: self.scope.clone(),
                host: "<missing>".to_string(),
                reason: "url has no host".to_string(),
            });
        };
        let host = normalize_host(host);
        if self.hosts.iter().any(|h| normalize_host(h) == host)
            || self.suffixes.iter().any(|s| suffix_matches(&host, s))
        {
            return Ok(());
        }
        match self.mode {
            EgressMode::AllowByDefault => Ok(()),
            EgressMode::DenyByDefault => Err(EgressDenied {
                scope: self.scope.clone(),
                host,
                reason: "host is not in the egress allowlist".to_string(),
            }),
        }
    }
}

/// A deterministic egress denial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDenied {
    /// Policy scope that denied the URL.
    pub scope: String,
    /// Normalized destination host.
    pub host: String,
    /// Human-readable reason.
    pub reason: String,
}

impl std::fmt::Display for EgressDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "egress denied by {} policy for host {}: {}",
            if self.scope.is_empty() {
                "unnamed"
            } else {
                &self.scope
            },
            self.host,
            self.reason
        )
    }
}

impl std::error::Error for EgressDenied {}

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

    fn url(raw: &str) -> Url {
        Url::parse(raw).expect("test url")
    }

    #[test]
    fn exact_host_allows_case_insensitively() {
        let policy = EgressPolicy {
            mode: EgressMode::DenyByDefault,
            hosts: vec!["API.EXAMPLE.COM".to_string()],
            suffixes: vec![],
            scope: "server:api".to_string(),
        };

        assert!(policy.check_url(&url("https://api.example.com/v1")).is_ok());
    }

    #[test]
    fn suffix_matches_on_dot_boundary_only() {
        let policy = EgressPolicy {
            mode: EgressMode::DenyByDefault,
            hosts: vec![],
            suffixes: vec!["example.com".to_string()],
            scope: "action".to_string(),
        };

        assert!(policy.check_url(&url("https://api.example.com/v1")).is_ok());
        assert!(policy.check_url(&url("https://example.com/v1")).is_ok());
        assert!(policy.check_url(&url("https://badexample.com/v1")).is_err());
    }

    #[test]
    fn deny_by_default_rejects_unlisted_host_with_scope() {
        let policy = EgressPolicy {
            mode: EgressMode::DenyByDefault,
            hosts: vec!["api.example.com".to_string()],
            suffixes: vec![],
            scope: "server:api".to_string(),
        };

        let err = policy
            .check_url(&url("https://attacker.test/steal"))
            .expect_err("unlisted host should be denied");
        assert_eq!(err.scope, "server:api");
        assert_eq!(err.host, "attacker.test");
    }

    #[test]
    fn allow_by_default_allows_unlisted_host() {
        let policy = EgressPolicy::allow_all("action");

        assert!(policy.check_url(&url("https://attacker.test/ok")).is_ok());
    }
}
