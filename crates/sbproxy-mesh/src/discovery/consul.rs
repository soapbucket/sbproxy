//! Consul service-catalog-based peer discovery.

use super::Discovery;

/// Discovers mesh peers via the Consul health API.
pub struct ConsulDiscovery {
    /// Consul HTTP API address (e.g. http://consul:8500).
    pub addr: String,
    /// Consul service name to query.
    pub service: String,
    /// Optional Consul datacenter. Uses Consul's local DC when None.
    pub datacenter: Option<String>,
    /// Optional Consul ACL token for authenticated clusters.
    pub token: Option<String>,
}

impl ConsulDiscovery {
    /// Create a new ConsulDiscovery with no datacenter or token.
    pub fn new(addr: &str, service: &str) -> Self {
        Self {
            addr: addr.to_string(),
            service: service.to_string(),
            datacenter: None,
            token: None,
        }
    }

    /// Build the Consul health API URL, optionally filtering by datacenter.
    pub fn health_url(&self) -> String {
        let mut url = format!(
            "{}/v1/health/service/{}?passing=true",
            self.addr, self.service
        );
        if let Some(dc) = &self.datacenter {
            url.push_str(&format!("&dc={dc}"));
        }
        url
    }
}

impl Discovery for ConsulDiscovery {
    /// Discover peers via the Consul health API.
    ///
    /// In production this would GET self.health_url() (with X-Consul-Token header
    /// if a token is set), parse the JSON response array, and return
    /// `Service.Address:Service.Port` for each passing instance.
    fn discover(&self) -> anyhow::Result<Vec<String>> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_defaults() {
        let cd = ConsulDiscovery::new("http://consul:8500", "sbproxy-mesh");
        assert_eq!(cd.addr, "http://consul:8500");
        assert_eq!(cd.service, "sbproxy-mesh");
        assert!(cd.datacenter.is_none());
        assert!(cd.token.is_none());
    }

    #[test]
    fn health_url_without_datacenter() {
        let cd = ConsulDiscovery::new("http://consul:8500", "sbproxy-mesh");
        assert_eq!(
            cd.health_url(),
            "http://consul:8500/v1/health/service/sbproxy-mesh?passing=true"
        );
    }

    #[test]
    fn health_url_with_datacenter() {
        let mut cd = ConsulDiscovery::new("http://consul:8500", "sbproxy-mesh");
        cd.datacenter = Some("us-east-1".to_string());
        assert_eq!(
            cd.health_url(),
            "http://consul:8500/v1/health/service/sbproxy-mesh?passing=true&dc=us-east-1"
        );
    }

    #[test]
    fn health_url_custom_addr() {
        let cd = ConsulDiscovery::new("https://vault.internal:8501", "proxy");
        assert!(cd.health_url().starts_with("https://vault.internal:8501"));
    }

    #[test]
    fn discover_returns_empty_without_consul() {
        let cd = ConsulDiscovery::new("http://consul:8500", "sbproxy-mesh");
        let peers = cd.discover().expect("discover should not error");
        assert!(peers.is_empty());
    }

    #[test]
    fn token_can_be_set() {
        let mut cd = ConsulDiscovery::new("http://consul:8500", "sbproxy-mesh");
        cd.token = Some("my-acl-token".to_string());
        assert_eq!(cd.token.as_deref(), Some("my-acl-token"));
    }

    #[test]
    fn is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ConsulDiscovery>();
    }
}
