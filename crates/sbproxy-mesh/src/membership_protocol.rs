//! Graceful cluster join and leave protocol.
//!
//! When a node joins, it sends a JoinRequest containing its identity and
//! optionally a CRDT state snapshot so the cluster can merge state immediately.
//! When a node leaves gracefully, it broadcasts a LeaveRequest so peers can
//! update membership without waiting for failure detection timeouts.

use crate::node::NodeInfo;

/// Sent by a joining node to introduce itself to the cluster.
#[derive(Debug, Clone)]
pub struct JoinRequest {
    /// Full identity and address information for the joining node.
    pub node_info: NodeInfo,
    /// Optional serialized CRDT state snapshot for fast state transfer.
    ///
    /// When present, the receiving node should merge this snapshot into its
    /// local state so the new node quickly reaches consistency.
    pub state_snapshot: Option<Vec<u8>>,
}

/// Sent by a departing node to gracefully leave the cluster.
#[derive(Debug, Clone)]
pub struct LeaveRequest {
    /// ID of the node that is leaving.
    pub node_id: String,
    /// Human-readable reason for leaving (e.g. "shutdown", "maintenance").
    pub reason: String,
}

/// Build a JoinRequest for the given node with no state snapshot.
///
/// A state snapshot can be attached afterwards if the node has local CRDT
/// state to share with the cluster.
pub fn build_join_request(info: &NodeInfo) -> JoinRequest {
    JoinRequest {
        node_info: info.clone(),
        state_snapshot: None,
    }
}

/// Build a LeaveRequest for the given node ID and reason string.
pub fn build_leave_request(node_id: &str, reason: &str) -> LeaveRequest {
    LeaveRequest {
        node_id: node_id.to_string(),
        reason: reason.to_string(),
    }
}

/// Validate that a JoinRequest is well-formed.
///
/// Returns an error string if the request is invalid.
pub fn validate_join_request(req: &JoinRequest) -> Result<(), String> {
    if req.node_info.advertise_addr.is_empty() {
        return Err("JoinRequest missing advertise_addr".to_string());
    }
    if req.node_info.gossip_port == 0 {
        return Err("JoinRequest has invalid gossip_port (0)".to_string());
    }
    Ok(())
}

/// Validate that a LeaveRequest is well-formed.
pub fn validate_leave_request(req: &LeaveRequest) -> Result<(), String> {
    if req.node_id.is_empty() {
        return Err("LeaveRequest missing node_id".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{NodeId, NodeInfo};

    fn make_node(name: &str) -> NodeInfo {
        NodeInfo::new(
            NodeId::new(name),
            "10.0.0.1:8080".to_string(),
            7946,
            8946,
            "2026-01-01T00:00:00Z".to_string(),
        )
    }

    #[test]
    fn build_join_request_carries_node_info() {
        let info = make_node("joiner-1");
        let req = build_join_request(&info);
        assert_eq!(req.node_info.id, NodeId::new("joiner-1"));
        assert!(req.state_snapshot.is_none());
    }

    #[test]
    fn build_join_request_does_not_mutate_original() {
        let info = make_node("node-a");
        let req = build_join_request(&info);
        // Original info should still be accessible and unchanged
        assert_eq!(info.gossip_port, req.node_info.gossip_port);
    }

    #[test]
    fn join_request_can_carry_snapshot() {
        let info = make_node("node-b");
        let mut req = build_join_request(&info);
        req.state_snapshot = Some(vec![1, 2, 3, 4]);
        assert_eq!(req.state_snapshot, Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn build_leave_request_sets_fields() {
        let req = build_leave_request("node-c", "planned maintenance");
        assert_eq!(req.node_id, "node-c");
        assert_eq!(req.reason, "planned maintenance");
    }

    #[test]
    fn build_leave_request_shutdown_reason() {
        let req = build_leave_request("node-d", "shutdown");
        assert_eq!(req.reason, "shutdown");
    }

    #[test]
    fn validate_join_request_valid() {
        let info = make_node("valid-node");
        let req = build_join_request(&info);
        assert!(validate_join_request(&req).is_ok());
    }

    #[test]
    fn validate_join_request_missing_addr() {
        let mut info = make_node("bad-node");
        info.advertise_addr = String::new();
        let req = build_join_request(&info);
        let result = validate_join_request(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("advertise_addr"));
    }

    #[test]
    fn validate_join_request_zero_gossip_port() {
        let info = NodeInfo::new(
            NodeId::new("node-e"),
            "10.0.0.1:8080".to_string(),
            0,
            8946,
            "2026-01-01T00:00:00Z".to_string(),
        );
        let req = build_join_request(&info);
        let result = validate_join_request(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("gossip_port"));
    }

    #[test]
    fn validate_leave_request_valid() {
        let req = build_leave_request("node-f", "restart");
        assert!(validate_leave_request(&req).is_ok());
    }

    #[test]
    fn validate_leave_request_empty_id() {
        let req = build_leave_request("", "shutdown");
        let result = validate_leave_request(&req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("node_id"));
    }
}
