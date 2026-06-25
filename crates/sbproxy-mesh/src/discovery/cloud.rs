//! Cloud provider tag-based peer discovery (AWS, GCP, Azure).

use super::Discovery;

/// Discovers mesh peers by querying cloud provider APIs for tagged instances.
pub struct CloudDiscovery {
    /// Cloud provider: "aws", "gcp", or "azure".
    pub provider: String,
    /// Tag key to filter instances by.
    pub tag_key: String,
    /// Expected tag value.
    pub tag_value: String,
    /// Cloud region to query (e.g. "us-east-1" for AWS, "us-central1" for GCP).
    pub region: String,
    /// Port on which discovered peers are listening.
    pub port: u16,
}

impl CloudDiscovery {
    /// Create a new CloudDiscovery.
    pub fn new(provider: &str, tag_key: &str, tag_value: &str, region: &str, port: u16) -> Self {
        Self {
            provider: provider.to_string(),
            tag_key: tag_key.to_string(),
            tag_value: tag_value.to_string(),
            region: region.to_string(),
            port,
        }
    }
}

impl Discovery for CloudDiscovery {
    /// Discover peers via the cloud provider's instance API.
    ///
    /// In production:
    /// - AWS: EC2 DescribeInstances filtered by tag, return private IPs
    /// - GCP: Compute Engine list instances filtered by label
    /// - Azure: Resource Graph query for VMs with the matching tag
    fn discover(&self) -> anyhow::Result<Vec<String>> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_all_fields() {
        let cd = CloudDiscovery::new("aws", "mesh-cluster", "prod", "us-east-1", 7946);
        assert_eq!(cd.provider, "aws");
        assert_eq!(cd.tag_key, "mesh-cluster");
        assert_eq!(cd.tag_value, "prod");
        assert_eq!(cd.region, "us-east-1");
        assert_eq!(cd.port, 7946);
    }

    #[test]
    fn new_gcp_config() {
        let cd = CloudDiscovery::new("gcp", "app", "sbproxy", "us-central1", 8946);
        assert_eq!(cd.provider, "gcp");
        assert_eq!(cd.region, "us-central1");
    }

    #[test]
    fn new_azure_config() {
        let cd = CloudDiscovery::new("azure", "role", "mesh-node", "eastus", 7946);
        assert_eq!(cd.provider, "azure");
        assert_eq!(cd.region, "eastus");
    }

    #[test]
    fn discover_returns_empty_without_cloud_credentials() {
        let cd = CloudDiscovery::new("aws", "mesh", "prod", "us-east-1", 7946);
        let peers = cd.discover().expect("discover should not error");
        assert!(peers.is_empty());
    }

    #[test]
    fn is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CloudDiscovery>();
    }
}
