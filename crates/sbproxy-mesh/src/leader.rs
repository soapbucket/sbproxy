//! Simple gossip-based leader election.
//!
//! The node with the lexicographically smallest ID becomes leader. This is a
//! deterministic, coordination-free algorithm: every node independently applies
//! the same rule and converges on the same leader as gossip propagates the full
//! member list.

use crate::node::NodeId;
use std::sync::Mutex;

/// Tracks the known cluster membership and derives the current leader.
pub struct LeaderElection {
    local_id: NodeId,
    known_nodes: Mutex<Vec<NodeId>>,
}

impl LeaderElection {
    /// Create a new election state with only the local node known.
    pub fn new(local_id: NodeId) -> Self {
        let initial = vec![local_id.clone()];
        Self {
            local_id,
            known_nodes: Mutex::new(initial),
        }
    }

    /// Replace the known node list with an updated view from gossip.
    ///
    /// The local node is always included even if not present in `nodes`.
    pub fn update_nodes(&self, mut nodes: Vec<NodeId>) {
        // Ensure the local node is always in the list.
        if !nodes.contains(&self.local_id) {
            nodes.push(self.local_id.clone());
        }
        let mut guard = self.known_nodes.lock().expect("mutex poisoned");
        *guard = nodes;
    }

    /// Return the current leader (node with lexicographically smallest ID), or
    /// `None` if the node list is somehow empty.
    pub fn current_leader(&self) -> Option<NodeId> {
        let guard = self.known_nodes.lock().expect("mutex poisoned");
        guard.iter().min_by_key(|n| &n.0).cloned()
    }

    /// Returns `true` if this node is the current leader.
    pub fn is_leader(&self) -> bool {
        self.current_leader()
            .map(|leader| leader == self.local_id)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_node_is_leader() {
        let id = NodeId::new("node-a");
        let election = LeaderElection::new(id.clone());

        assert_eq!(election.current_leader(), Some(id));
        assert!(election.is_leader());
    }

    #[test]
    fn smallest_id_wins() {
        let id_c = NodeId::new("node-c");
        let election = LeaderElection::new(id_c.clone());

        election.update_nodes(vec![
            NodeId::new("node-c"),
            NodeId::new("node-a"), // smallest
            NodeId::new("node-b"),
        ]);

        assert_eq!(election.current_leader(), Some(NodeId::new("node-a")));
        assert!(!election.is_leader(), "node-c should not be leader");
    }

    #[test]
    fn update_changes_leader() {
        let id_b = NodeId::new("node-b");
        let election = LeaderElection::new(id_b.clone());

        // Initially node-b is the only node, so it leads.
        assert!(election.is_leader());

        // A new node with a smaller ID joins.
        election.update_nodes(vec![NodeId::new("node-b"), NodeId::new("node-a")]);

        assert_eq!(election.current_leader(), Some(NodeId::new("node-a")));
        assert!(!election.is_leader());
    }

    #[test]
    fn local_node_always_included() {
        let id_a = NodeId::new("node-a");
        let election = LeaderElection::new(id_a.clone());

        // Update without including the local node.
        election.update_nodes(vec![NodeId::new("node-b")]);

        // local node should be present and still eligible.
        let leader = election.current_leader().expect("should have leader");
        // node-a < node-b lexicographically.
        assert_eq!(leader, id_a);
        assert!(election.is_leader());
    }

    #[test]
    fn is_leader_when_smallest() {
        let id_a = NodeId::new("aaa");
        let election = LeaderElection::new(id_a);

        election.update_nodes(vec![
            NodeId::new("aaa"),
            NodeId::new("bbb"),
            NodeId::new("ccc"),
        ]);

        assert!(election.is_leader());
    }

    #[test]
    fn is_not_leader_when_not_smallest() {
        let id_z = NodeId::new("zzz");
        let election = LeaderElection::new(id_z);

        election.update_nodes(vec![
            NodeId::new("aaa"),
            NodeId::new("mmm"),
            NodeId::new("zzz"),
        ]);

        assert!(!election.is_leader());
        assert_eq!(election.current_leader(), Some(NodeId::new("aaa")));
    }
}
