//! WebSocket action handler.
//!
//! Proxies incoming HTTP requests to an upstream WebSocket server.
//! Supports ws:// and wss:// URL schemes, optional subprotocol
//! negotiation, and configurable max message size.

use serde::Deserialize;

use super::ForwardingHeaderControls;

fn default_max_message_size() -> usize {
    10 * 1024 * 1024 // 10 MB
}

/// WebSocket action config - proxies requests to an upstream WebSocket server.
#[derive(Debug, Deserialize)]
pub struct WebSocketAction {
    /// Backend WebSocket URL (ws:// or wss://).
    pub url: String,
    /// Supported subprotocols for negotiation.
    #[serde(default)]
    pub subprotocols: Vec<String>,
    /// Maximum message payload size in bytes (default: 10 MB).
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    /// Override the `Host` header sent on the upgrade request. Defaults to
    /// the upstream URL's hostname, which is what most vhost-based servers
    /// expect. Set this if the upstream needs a different Host.
    #[serde(default)]
    pub host_override: Option<String>,
    /// Per-action opt-out flags for the standard proxy forwarding headers.
    #[serde(flatten, default)]
    pub forwarding: ForwardingHeaderControls,
}

impl WebSocketAction {
    /// Build a WebSocketAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Parse the WebSocket URL into (host, port, tls) for upstream peer.
    ///
    /// Converts ws:// to http:// and wss:// to https:// before parsing
    /// so that the standard URL parser can extract host and port.
    pub fn parse_upstream(&self) -> anyhow::Result<(String, u16, bool)> {
        let normalized = if self.url.starts_with("wss://") {
            self.url.replacen("wss://", "https://", 1)
        } else if self.url.starts_with("ws://") {
            self.url.replacen("ws://", "http://", 1)
        } else {
            self.url.clone()
        };

        let parsed = url::Url::parse(&normalized)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("missing host in websocket URL"))?
            .to_string();
        let tls = parsed.scheme() == "https";
        let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
        Ok((host, port, tls))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_from_config_full() {
        let json = serde_json::json!({
            "type": "websocket",
            "url": "wss://echo.example.com/ws",
            "subprotocols": ["graphql-ws", "graphql-transport-ws"],
            "max_message_size": 5242880
        });
        let ws = WebSocketAction::from_config(json).unwrap();
        assert_eq!(ws.url, "wss://echo.example.com/ws");
        assert_eq!(ws.subprotocols, vec!["graphql-ws", "graphql-transport-ws"]);
        assert_eq!(ws.max_message_size, 5_242_880);
    }

    #[test]
    fn websocket_from_config_defaults() {
        let json = serde_json::json!({
            "type": "websocket",
            "url": "ws://localhost:8080"
        });
        let ws = WebSocketAction::from_config(json).unwrap();
        assert!(ws.subprotocols.is_empty());
        assert_eq!(ws.max_message_size, 10 * 1024 * 1024);
    }

    #[test]
    fn websocket_from_config_missing_url() {
        let json = serde_json::json!({"type": "websocket"});
        assert!(WebSocketAction::from_config(json).is_err());
    }

    #[test]
    fn parse_upstream_ws() {
        let ws = WebSocketAction {
            url: "ws://backend:9090/ws".to_string(),
            subprotocols: vec![],
            max_message_size: default_max_message_size(),
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = ws.parse_upstream().unwrap();
        assert_eq!(host, "backend");
        assert_eq!(port, 9090);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_wss_default_port() {
        let ws = WebSocketAction {
            url: "wss://secure.example.com/stream".to_string(),
            subprotocols: vec![],
            max_message_size: default_max_message_size(),
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = ws.parse_upstream().unwrap();
        assert_eq!(host, "secure.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_ws_default_port() {
        let ws = WebSocketAction {
            url: "ws://localhost".to_string(),
            subprotocols: vec![],
            max_message_size: default_max_message_size(),
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = ws.parse_upstream().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 80);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_http_url() {
        let ws = WebSocketAction {
            url: "http://fallback:3000".to_string(),
            subprotocols: vec![],
            max_message_size: default_max_message_size(),
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = ws.parse_upstream().unwrap();
        assert_eq!(host, "fallback");
        assert_eq!(port, 3000);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_invalid_url() {
        let ws = WebSocketAction {
            url: "not a valid url".to_string(),
            subprotocols: vec![],
            max_message_size: default_max_message_size(),
            host_override: None,
            forwarding: Default::default(),
        };
        assert!(ws.parse_upstream().is_err());
    }
}
