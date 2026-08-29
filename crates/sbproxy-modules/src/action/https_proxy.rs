//! Guarded HTTPS reverse-proxy action - allow-listed relay to the
//! requested host.
//!
//! Ported from `sbproxy-enterprise-modules::action::https_proxy`
//! (WOR-2671). The source modeled an HTTP `CONNECT` tunnel: a client
//! asks to reach an arbitrary host, and the action either tunnels the
//! connection (host allow-listed) or refuses it. OSS's Pingora pipeline
//! has no `CONNECT`/raw-tunnel support (it is a message-based HTTP
//! reverse proxy, not a byte-tunneling forward proxy), so this action
//! is not a literal port of the tunnel mechanics.
//!
//! What ports directly is the decision the source action makes: given
//! the host a client is trying to reach, is it on the allow-list? OSS
//! already resolves "the host a client is trying to reach" for every
//! request, as `RequestContext::hostname` (the inbound `Host` header
//! used to route to an origin). This action reuses that resolution:
//! when the origin's `Host` is allow-listed, the request is relayed
//! onward unchanged (same host, same TLS, no config-time upstream URL,
//! matching the source's "tunnel to whatever was asked for" shape);
//! when it is not, the request is refused with `403` (the source's
//! `ActionOutcome::Responded` deny path). This makes the most sense on
//! a wildcard origin (`"*.internal.io"`) that wants to relay only a
//! named subset of the hosts the wildcard would otherwise match.
use serde::Deserialize;

/// Configuration for the guarded HTTPS reverse-proxy action.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpsProxyAction {
    /// Hosts that clients are allowed to reach through this action.
    /// Supports exact matches and `*.suffix` wildcard patterns.
    pub allowed_hosts: Vec<String>,
    /// Upstream connect timeout, applied to the relayed connection.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// When true, the relay requires a prior successful authentication
    /// decision on the request (the origin must also configure an
    /// `authentication:` provider). A request that reaches this action
    /// with no recorded `Allow` decision is refused with `401`,
    /// regardless of `allowed_hosts`.
    #[serde(default)]
    pub require_auth: bool,
}

fn default_connect_timeout_ms() -> u64 {
    5000
}

impl HttpsProxyAction {
    /// Build an HttpsProxyAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let action: Self = serde_json::from_value(value)?;
        if action.allowed_hosts.is_empty() {
            anyhow::bail!("https_proxy action requires at least one entry in `allowed_hosts`");
        }
        Ok(action)
    }

    /// Check whether a host is in the allow-list.
    ///
    /// Supports exact matches and wildcard prefix patterns (e.g. `*.example.com`).
    pub fn is_host_allowed(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();
        for pattern in &self.allowed_hosts {
            let p = pattern.to_lowercase();
            if p == host_lower {
                return true;
            }
            if let Some(suffix) = p.strip_prefix("*.") {
                if host_lower.ends_with(suffix)
                    && host_lower.len() > suffix.len()
                    && host_lower.as_bytes()[host_lower.len() - suffix.len() - 1] == b'.'
                {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> HttpsProxyAction {
        HttpsProxyAction::from_config(serde_json::json!({
            "type": "https_proxy",
            "allowed_hosts": ["api.example.com", "*.internal.io"],
            "connect_timeout_ms": 3000
        }))
        .unwrap()
    }

    #[test]
    fn deserialize_config() {
        let action = sample_config();
        assert_eq!(action.allowed_hosts.len(), 2);
        assert_eq!(action.connect_timeout_ms, 3000);
        assert!(!action.require_auth);
    }

    #[test]
    fn exact_host_allowed() {
        let action = sample_config();
        assert!(action.is_host_allowed("api.example.com"));
        assert!(action.is_host_allowed("API.EXAMPLE.COM"));
    }

    #[test]
    fn wildcard_host_allowed() {
        let action = sample_config();
        assert!(action.is_host_allowed("svc.internal.io"));
        assert!(!action.is_host_allowed("internal.io")); // bare domain does not match *.
    }

    #[test]
    fn unknown_host_denied() {
        let action = sample_config();
        assert!(!action.is_host_allowed("evil.example.org"));
    }

    #[test]
    fn default_timeout() {
        let action = HttpsProxyAction::from_config(serde_json::json!({
            "type": "https_proxy",
            "allowed_hosts": ["example.com"]
        }))
        .unwrap();
        assert_eq!(action.connect_timeout_ms, 5000);
    }

    #[test]
    fn empty_allowed_hosts_rejected_at_config_load() {
        let err = HttpsProxyAction::from_config(serde_json::json!({
            "type": "https_proxy",
            "allowed_hosts": []
        }))
        .expect_err("empty allowed_hosts must be rejected");
        assert!(err.to_string().contains("allowed_hosts"));
    }

    #[test]
    fn require_auth_defaults_false_and_parses_true() {
        let action = HttpsProxyAction::from_config(serde_json::json!({
            "type": "https_proxy",
            "allowed_hosts": ["example.com"],
            "require_auth": true
        }))
        .unwrap();
        assert!(action.require_auth);
    }
}
