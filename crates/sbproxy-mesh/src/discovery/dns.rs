//! DNS-based peer discovery (works with K8s headless services).

use super::Discovery;
use std::net::ToSocketAddrs;

/// Discovery backend that resolves a DNS hostname to peer addresses.
///
/// Works naturally with Kubernetes headless services, where DNS returns
/// one A record per pod in the StatefulSet.
pub struct DnsDiscovery {
    hostname: String,
    port: u16,
}

impl DnsDiscovery {
    /// Create a new DNS-based discovery for the given hostname and port.
    pub fn new(hostname: String, port: u16) -> Self {
        Self { hostname, port }
    }
}

impl Discovery for DnsDiscovery {
    fn discover(&self) -> anyhow::Result<Vec<String>> {
        let addr = format!("{}:{}", self.hostname, self.port);
        let addrs: Vec<String> = addr
            .to_socket_addrs()
            .map(|iter| iter.map(|a| a.to_string()).collect())
            .unwrap_or_default();
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::Discovery;

    #[test]
    fn returns_empty_on_unresolvable_hostname() {
        let discovery = DnsDiscovery::new(
            "this-hostname-definitely-does-not-exist.invalid".to_string(),
            7946,
        );
        let result = discovery.discover().expect("discover should not error");
        // unwrap_or_default means unresolvable returns empty, not error
        assert!(result.is_empty());
    }

    #[test]
    fn resolves_localhost() {
        let discovery = DnsDiscovery::new("localhost".to_string(), 7946);
        let result = discovery.discover().expect("discover");
        // localhost should resolve to at least one address
        assert!(!result.is_empty());
        // All results should contain the port
        for addr in &result {
            assert!(addr.contains("7946"), "address should include port: {addr}");
        }
    }

    #[test]
    fn port_is_included_in_results() {
        let discovery = DnsDiscovery::new("localhost".to_string(), 1234);
        let result = discovery.discover().expect("discover");
        for addr in &result {
            assert!(
                addr.contains("1234"),
                "address should include port 1234: {addr}"
            );
        }
    }
}
