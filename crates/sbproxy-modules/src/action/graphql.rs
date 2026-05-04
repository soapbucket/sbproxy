//! GraphQL action handler.
//!
//! Proxies incoming GraphQL requests to an upstream HTTP endpoint.
//! Supports optional query depth limiting, introspection control,
//! and query validation settings.

use serde::Deserialize;

use super::ForwardingHeaderControls;

fn default_allow_introspection() -> bool {
    true
}

/// GraphQL action config - proxies GraphQL requests to an upstream HTTP server.
#[derive(Debug, Deserialize)]
pub struct GraphQLAction {
    /// Backend GraphQL endpoint URL (http:// or https://).
    pub url: String,
    /// Maximum allowed query nesting depth (0 = unlimited).
    #[serde(default)]
    pub max_depth: usize,
    /// Whether to allow introspection queries (default: true).
    #[serde(default = "default_allow_introspection")]
    pub allow_introspection: bool,
    /// Whether to validate incoming GraphQL queries (default: false).
    #[serde(default)]
    pub validate_queries: bool,
    /// Override the `Host` header sent to the upstream GraphQL server.
    /// Defaults to the upstream URL's hostname.
    #[serde(default)]
    pub host_override: Option<String>,
    /// Per-action opt-out flags for the standard proxy forwarding headers.
    #[serde(flatten, default)]
    pub forwarding: ForwardingHeaderControls,
}

impl GraphQLAction {
    /// Build a GraphQLAction from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }

    /// Parse the GraphQL URL into (host, port, tls) for upstream peer.
    pub fn parse_upstream(&self) -> anyhow::Result<(String, u16, bool)> {
        let parsed = url::Url::parse(&self.url)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("missing host in GraphQL URL"))?
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
    fn graphql_from_config_full() {
        let json = serde_json::json!({
            "type": "graphql",
            "url": "https://api.example.com/graphql",
            "max_depth": 10,
            "allow_introspection": false,
            "validate_queries": true
        });
        let gql = GraphQLAction::from_config(json).unwrap();
        assert_eq!(gql.url, "https://api.example.com/graphql");
        assert_eq!(gql.max_depth, 10);
        assert!(!gql.allow_introspection);
        assert!(gql.validate_queries);
    }

    #[test]
    fn graphql_from_config_defaults() {
        let json = serde_json::json!({
            "type": "graphql",
            "url": "http://localhost:4000/graphql"
        });
        let gql = GraphQLAction::from_config(json).unwrap();
        assert_eq!(gql.max_depth, 0);
        assert!(gql.allow_introspection);
        assert!(!gql.validate_queries);
    }

    #[test]
    fn graphql_from_config_missing_url() {
        let json = serde_json::json!({"type": "graphql"});
        assert!(GraphQLAction::from_config(json).is_err());
    }

    #[test]
    fn parse_upstream_https() {
        let gql = GraphQLAction {
            url: "https://api.example.com/graphql".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = gql.parse_upstream().unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_upstream_http_custom_port() {
        let gql = GraphQLAction {
            url: "http://localhost:4000/graphql".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = gql.parse_upstream().unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 4000);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_http_default_port() {
        let gql = GraphQLAction {
            url: "http://graphql-server".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };
        let (host, port, tls) = gql.parse_upstream().unwrap();
        assert_eq!(host, "graphql-server");
        assert_eq!(port, 80);
        assert!(!tls);
    }

    #[test]
    fn parse_upstream_invalid_url() {
        let gql = GraphQLAction {
            url: "not a url".to_string(),
            max_depth: 0,
            allow_introspection: true,
            validate_queries: false,
            host_override: None,
            forwarding: Default::default(),
        };
        assert!(gql.parse_upstream().is_err());
    }
}
