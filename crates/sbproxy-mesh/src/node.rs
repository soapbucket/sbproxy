//! Node identity for mesh membership.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a mesh node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    /// Generate a stable node ID from hostname + port.
    pub fn auto_generate(port: u16) -> Self {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        Self(format!("{hostname}:{port}"))
    }

    /// Create from explicit string.
    pub fn new(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::str::FromStr for NodeId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Full information about a mesh node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Stable identifier for this node.
    pub id: NodeId,
    /// Address this node advertises to peers.
    pub advertise_addr: String,
    /// UDP port for the SWIM gossip protocol.
    pub gossip_port: u16,
    /// TCP port for the cache RPC transport.
    pub transport_port: u16,
    /// When the node joined, as an ISO 8601 timestamp string.
    pub joined_at: String,
    /// Free-form key/value labels attached to the node.
    pub metadata: HashMap<String, String>,
}

impl NodeInfo {
    /// Create a new NodeInfo with no metadata.
    pub fn new(
        id: NodeId,
        advertise_addr: String,
        gossip_port: u16,
        transport_port: u16,
        joined_at: String,
    ) -> Self {
        Self {
            id,
            advertise_addr,
            gossip_port,
            transport_port,
            joined_at,
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_generate_produces_stable_id() {
        let id1 = NodeId::auto_generate(8080);
        let id2 = NodeId::auto_generate(8080);
        assert_eq!(id1, id2, "same port should produce same node ID");
    }

    #[test]
    fn auto_generate_differs_by_port() {
        let id1 = NodeId::auto_generate(8080);
        let id2 = NodeId::auto_generate(9090);
        assert_ne!(
            id1, id2,
            "different ports should produce different node IDs"
        );
    }

    #[test]
    fn auto_generate_contains_port() {
        let id = NodeId::auto_generate(1234);
        assert!(id.0.contains("1234"), "node ID should contain the port");
    }

    #[test]
    fn from_str_works() {
        let id = NodeId::new("my-node:8080");
        assert_eq!(id.0, "my-node:8080");
    }

    #[test]
    fn display_formats_correctly() {
        let id = NodeId::new("host:1234");
        assert_eq!(format!("{id}"), "host:1234");
    }

    #[test]
    fn node_info_new() {
        let id = NodeId::new("host:8080");
        let info = NodeInfo::new(
            id.clone(),
            "10.0.0.1:8080".to_string(),
            7946,
            8946,
            "2026-01-01T00:00:00Z".to_string(),
        );
        assert_eq!(info.id, id);
        assert_eq!(info.gossip_port, 7946);
        assert_eq!(info.transport_port, 8946);
        assert!(info.metadata.is_empty());
    }

    #[test]
    fn node_info_serializes() {
        let id = NodeId::new("host:8080");
        let info = NodeInfo::new(
            id,
            "10.0.0.1:8080".to_string(),
            7946,
            8946,
            "2026-01-01T00:00:00Z".to_string(),
        );
        let json = serde_json::to_string(&info).expect("serialize");
        let back: NodeInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.gossip_port, 7946);
    }
}
