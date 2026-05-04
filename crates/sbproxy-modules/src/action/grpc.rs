//! gRPC action handler.
//!
//! Proxies incoming requests to an upstream gRPC server. Supports
//! grpc://, grpcs://, http://, and https:// URL schemes with
//! optional authority override and configurable timeout.

use serde::Deserialize;

use super::ForwardingHeaderControls;

fn default_timeout_secs() -> u64 {
    30
}

/// gRPC action config - proxies requests to an upstream gRPC server.
#[derive(Debug, Deserialize)]
pub struct GrpcAction {
    /// Backend gRPC URL (grpc://, grpcs://, http://, or https://).
    pub url: String,
    /// Whether the upstream connection requires TLS.
    #[serde(default)]
    pub tls: bool,
    /// Optional :authority override for the HTTP/2 connection.
    #[serde(default)]
    pub authority: Option<String>,
    /// Request timeout in seconds (default: 30).
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Per-action opt-out flags for the standard proxy forwarding headers.
    #[serde(flatten, default)]
    pub forwarding: ForwardingHeaderControls,
}

impl GrpcAction {
    /// Build a GrpcAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Parse the gRPC URL into (host, port, tls) for upstream peer.
    ///
    /// Converts grpc:// to http:// and grpcs:// to https:// before parsing.
    /// The `tls` field in the config can override scheme-based TLS detection.
    pub fn parse_upstream(&self) -> anyhow::Result<(String, u16, bool)> {
        let normalized = if self.url.starts_with("grpcs://") {
            self.url.replacen("grpcs://", "https://", 1)
        } else if self.url.starts_with("grpc://") {
            self.url.replacen("grpc://", "http://", 1)
        } else {
            self.url.clone()
        };

        let parsed = url::Url::parse(&normalized)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("missing host in gRPC URL"))?
            .to_string();
        let tls = self.tls || parsed.scheme() == "https";
        let port = parsed.port().unwrap_or(if tls { 443 } else { 80 });
        Ok((host, port, tls))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_from_config_full() {
        let json = serde_json::json!({
            "type": "grpc",
            "url": "grpcs://grpc.example.com:50051",
            "tls": true,
            "authority": "grpc.example.com",
            "timeout_secs": 60
        });
        let grpc = GrpcAction::from_config(json).unwrap();
        assert_eq!(grpc.url, "grpcs://grpc.example.com:50051");
        assert!(grpc.tls);
        assert_eq!(grpc.authority.as_deref(), Some("grpc.example.com"));
        assert_eq!(grpc.timeout_secs, 60);
    }

    #[test]
    fn grpc_from_config_defaults() {
        let json = serde_json::json!({
            "type": "grpc",
            "url": "grpc://localhost:50051"
        });
        let grpc = GrpcAction::from_config(json).unwrap();
        assert!(!grpc.tls);
        assert!(grpc.authority.is_none());
        assert_eq!(grpc.timeout_secs, 30);
    }

    #[test]
    fn grpc_from_config_missing_url() {
        let json = serde_json::json!({"type": "grpc"});
        assert!(GrpcAction::from_config(json).is_err());
    }

    #[test]
    fn parse_upstream_grpc() {
        let grpc = GrpcAction {
            url: "grpc://backend:50051".to_string(),
            tls: false,
            authority: None,
            timeout_secs: 30,
            forwarding: Default::default(),
        };
        let (host, port, tls) = grpc.parse_upstream().unwrap();
        assert_eq!(host, "backend");
        assert_eq!(port, 50051);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_grpcs() {
        let grpc = GrpcAction {
            url: "grpcs://api.example.com".to_string(),
            tls: false,
            authority: None,
            timeout_secs: 30,
            forwarding: Default::default(),
        };
        let (host, port, tls) = grpc.parse_upstream().unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_tls_override() {
        let grpc = GrpcAction {
            url: "grpc://secure-backend:50051".to_string(),
            tls: true,
            authority: None,
            timeout_secs: 30,
            forwarding: Default::default(),
        };
        let (host, port, tls) = grpc.parse_upstream().unwrap();
        assert_eq!(host, "secure-backend");
        assert_eq!(port, 50051);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_http_url() {
        let grpc = GrpcAction {
            url: "http://localhost:9090".to_string(),
            tls: false,
            authority: None,
            timeout_secs: 30,
            forwarding: Default::default(),
        };
        let (host, port, tls) = grpc.parse_upstream().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 9090);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_https_url() {
        let grpc = GrpcAction {
            url: "https://grpc.example.com".to_string(),
            tls: false,
            authority: None,
            timeout_secs: 30,
            forwarding: Default::default(),
        };
        let (host, port, tls) = grpc.parse_upstream().unwrap();
        assert_eq!(host, "grpc.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_invalid_url() {
        let grpc = GrpcAction {
            url: "not valid".to_string(),
            tls: false,
            authority: None,
            timeout_secs: 30,
            forwarding: Default::default(),
        };
        assert!(grpc.parse_upstream().is_err());
    }
}
