//! A2A (Agent-to-Agent) action - proxies requests to an A2A agent endpoint.
//!
//! Implements the A2A protocol by forwarding requests to an upstream
//! agent URL. A configured agent card is served by the gateway at the
//! A2A discovery paths (see the serving handler in `sbproxy-core`).

use serde::Deserialize;

use super::ForwardingHeaderControls;

/// A2A action config - proxies requests to an A2A agent endpoint.
#[derive(Debug, Deserialize)]
pub struct A2aAction {
    /// Upstream agent URL to proxy requests to.
    pub url: String,
    /// Optional agent card served by the gateway at the A2A discovery
    /// paths. Stored verbatim so the served body matches what the
    /// operator authored; validated through the typed
    /// [`super::a2a_card::AgentCard`] at config compile so a malformed
    /// card is a boot error rather than a runtime surprise.
    #[serde(default)]
    pub agent_card: Option<serde_json::Value>,
    /// Override the `Host` header sent to the upstream agent. Defaults to
    /// the upstream URL's hostname.
    #[serde(default)]
    pub host_override: Option<String>,
    /// Per-action opt-out flags for the standard proxy forwarding headers.
    #[serde(flatten, default)]
    pub forwarding: ForwardingHeaderControls,
}

impl A2aAction {
    /// Build an A2aAction from a generic JSON config value.
    ///
    /// A configured `agent_card` is parsed through the typed
    /// [`super::a2a_card::AgentCard`] here so a card whose typed
    /// fields are the wrong shape (a `capabilities` list instead of
    /// an object, a non-string `url`, a non-object card) refuses the
    /// config at compile time. Unknown fields still round-trip via
    /// the card's `extensions`, so a full spec card keeps compiling.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        let action: Self = serde_json::from_value(value)?;
        if let Some(card) = action.agent_card.as_ref() {
            super::a2a_card::AgentCard::from_json(card.clone())
                .map_err(|e| anyhow::anyhow!("invalid a2a agent_card: {e}"))?;
        }
        Ok(action)
    }

    /// Parse the URL into (host, port, tls) for Pingora upstream peer.
    pub fn parse_upstream(&self) -> anyhow::Result<(String, u16, bool)> {
        super::memoized_upstream(&self.url, || {
            let parsed = url::Url::parse(&self.url)?;
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing host in A2A URL"))?
                .to_string();
            let tls = parsed.scheme() == "https";
            let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
            Ok((host, port, tls))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a2a_action_from_config() {
        let json = serde_json::json!({
            "type": "a2a",
            "url": "https://agent.example.com/a2a"
        });
        let action = A2aAction::from_config(json).unwrap();
        assert_eq!(action.url, "https://agent.example.com/a2a");
        assert!(action.agent_card.is_none());
    }

    #[test]
    fn a2a_action_with_agent_card() {
        let json = serde_json::json!({
            "type": "a2a",
            "url": "http://localhost:9000/a2a",
            "agent_card": {
                "name": "TestAgent",
                "version": "1.0",
                "capabilities": {"streaming": true},
                "defaultInputModes": ["text/plain"]
            }
        });
        let action = A2aAction::from_config(json).unwrap();
        assert_eq!(action.url, "http://localhost:9000/a2a");
        let card = action.agent_card.unwrap();
        assert_eq!(card["name"], "TestAgent");
        assert_eq!(card["version"], "1.0");
    }

    /// A card whose typed fields are the wrong shape is a config
    /// compile error, not a runtime surprise. `capabilities` is a
    /// list here where the A2A card schema wants an object.
    #[test]
    fn a2a_action_rejects_malformed_agent_card() {
        let json = serde_json::json!({
            "type": "a2a",
            "url": "http://localhost:9000/a2a",
            "agent_card": {
                "name": "TestAgent",
                "capabilities": ["text"]
            }
        });
        let err = A2aAction::from_config(json).unwrap_err();
        assert!(
            err.to_string().contains("invalid a2a agent_card"),
            "error should name the agent_card: {err}"
        );
    }

    /// A non-object card body (the operator pasted a string) is
    /// refused for the same reason.
    #[test]
    fn a2a_action_rejects_non_object_agent_card() {
        let json = serde_json::json!({
            "type": "a2a",
            "url": "http://localhost:9000/a2a",
            "agent_card": "not a card"
        });
        assert!(A2aAction::from_config(json).is_err());
    }

    /// Unknown card fields land on the typed card's `extensions`, so
    /// a full spec card (provider, authentication, etc.) still
    /// compiles and round-trips verbatim.
    #[test]
    fn a2a_action_accepts_card_with_unknown_fields() {
        let json = serde_json::json!({
            "type": "a2a",
            "url": "http://localhost:9000/a2a",
            "agent_card": {
                "name": "TestAgent",
                "provider": {"organization": "Example"},
                "supportsAuthenticatedExtendedCard": false
            }
        });
        let action = A2aAction::from_config(json).unwrap();
        let card = action.agent_card.unwrap();
        assert_eq!(card["provider"]["organization"], "Example");
    }

    #[test]
    fn a2a_action_missing_url() {
        let json = serde_json::json!({"type": "a2a"});
        assert!(A2aAction::from_config(json).is_err());
    }

    #[test]
    fn a2a_parse_upstream_https() {
        let action = A2aAction {
            url: "https://agent.example.com:9443/a2a".to_string(),
            agent_card: None,
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = action.parse_upstream().unwrap();
        assert_eq!(host, "agent.example.com");
        assert_eq!(port, 9443);
        assert!(tls);
    }

    #[test]
    fn a2a_parse_upstream_http_default_port() {
        let action = A2aAction {
            url: "http://localhost/a2a".to_string(),
            agent_card: None,
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = action.parse_upstream().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 80);
        assert!(!tls);
    }

    #[test]
    fn a2a_parse_upstream_https_default_port() {
        let action = A2aAction {
            url: "https://agent.example.com/a2a".to_string(),
            agent_card: None,
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = action.parse_upstream().unwrap();
        assert_eq!(host, "agent.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn a2a_parse_upstream_invalid_url() {
        let action = A2aAction {
            url: "not a url".to_string(),
            agent_card: None,
            host_override: None,
            forwarding: Default::default(),
        };
        assert!(action.parse_upstream().is_err());
    }
}
