//! Guardrail state propagation across mesh via OR-Set CRDT.
//!
//! Blocked IPs and user IDs are represented as OR-Sets so that concurrent
//! block/unblock operations from different nodes converge correctly across the
//! mesh without central coordination.

use crate::state::set::ORSet;

/// Cluster-wide guardrail state.
///
/// Uses two OR-Sets so that blocks made on any node propagate to all peers
/// through normal gossip rounds.
pub struct GuardrailState {
    /// Blocked IP addresses (propagated across mesh).
    blocked_ips: ORSet,
    /// Blocked user IDs.
    blocked_users: ORSet,
}

impl GuardrailState {
    /// Create an empty guardrail state.
    pub fn new() -> Self {
        Self {
            blocked_ips: ORSet::new(),
            blocked_users: ORSet::new(),
        }
    }

    /// Block an IP address, tagging the operation with `node_id`.
    pub fn block_ip(&mut self, ip: &str, node_id: &str) {
        self.blocked_ips.add(ip, node_id);
    }

    /// Unblock an IP address by tombstoning all current tags.
    pub fn unblock_ip(&mut self, ip: &str) {
        self.blocked_ips.remove(ip);
    }

    /// Returns `true` if the IP is currently blocked.
    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        self.blocked_ips.contains(ip)
    }

    /// Block a user ID, tagging the operation with `node_id`.
    pub fn block_user(&mut self, user_id: &str, node_id: &str) {
        self.blocked_users.add(user_id, node_id);
    }

    /// Unblock a user ID by tombstoning all current tags.
    pub fn unblock_user(&mut self, user_id: &str) {
        self.blocked_users.remove(user_id);
    }

    /// Returns `true` if the user is currently blocked.
    pub fn is_user_blocked(&self, user_id: &str) -> bool {
        self.blocked_users.contains(user_id)
    }

    /// Merge another node's guardrail state into this one (CRDT union).
    pub fn merge(&mut self, other: &GuardrailState) {
        self.blocked_ips.merge(&other.blocked_ips);
        self.blocked_users.merge(&other.blocked_users);
    }

    /// Return all currently blocked IP addresses.
    pub fn blocked_ips(&self) -> Vec<String> {
        self.blocked_ips.elements()
    }

    /// Return all currently blocked user IDs.
    pub fn blocked_users(&self) -> Vec<String> {
        self.blocked_users.elements()
    }
}

impl Default for GuardrailState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- IP blocking ---

    #[test]
    fn block_ip() {
        let mut state = GuardrailState::new();
        state.block_ip("192.168.1.1", "node-a");
        assert!(state.is_ip_blocked("192.168.1.1"));
    }

    #[test]
    fn unblock_ip() {
        let mut state = GuardrailState::new();
        state.block_ip("192.168.1.1", "node-a");
        state.unblock_ip("192.168.1.1");
        assert!(!state.is_ip_blocked("192.168.1.1"));
    }

    #[test]
    fn unblock_nonexistent_ip_is_safe() {
        let mut state = GuardrailState::new();
        state.unblock_ip("10.0.0.1");
        assert!(!state.is_ip_blocked("10.0.0.1"));
    }

    // --- User blocking ---

    #[test]
    fn block_user() {
        let mut state = GuardrailState::new();
        state.block_user("user-123", "node-a");
        assert!(state.is_user_blocked("user-123"));
    }

    #[test]
    fn unblock_user() {
        let mut state = GuardrailState::new();
        state.block_user("user-123", "node-a");
        state.unblock_user("user-123");
        assert!(!state.is_user_blocked("user-123"));
    }

    #[test]
    fn unblock_nonexistent_user_is_safe() {
        let mut state = GuardrailState::new();
        state.unblock_user("ghost-user");
        assert!(!state.is_user_blocked("ghost-user"));
    }

    // --- Merge ---

    #[test]
    fn merge_propagates_ip_blocks() {
        let mut node_a = GuardrailState::new();
        node_a.block_ip("1.2.3.4", "node-a");

        let mut node_b = GuardrailState::new();
        node_b.block_ip("5.6.7.8", "node-b");

        node_a.merge(&node_b);

        assert!(node_a.is_ip_blocked("1.2.3.4"), "local block preserved");
        assert!(node_a.is_ip_blocked("5.6.7.8"), "remote block propagated");
    }

    #[test]
    fn merge_propagates_user_blocks() {
        let mut node_a = GuardrailState::new();
        node_a.block_user("alice", "node-a");

        let mut node_b = GuardrailState::new();
        node_b.block_user("bob", "node-b");

        node_a.merge(&node_b);

        assert!(node_a.is_user_blocked("alice"));
        assert!(node_a.is_user_blocked("bob"));
    }

    #[test]
    fn merge_is_idempotent() {
        let mut state = GuardrailState::new();
        state.block_ip("10.0.0.1", "node-a");

        let snapshot = GuardrailState {
            blocked_ips: state.blocked_ips.clone(),
            blocked_users: state.blocked_users.clone(),
        };

        state.merge(&snapshot);
        state.merge(&snapshot);

        let ips = state.blocked_ips();
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn concurrent_unblock_block_merge() {
        // node-a blocks then unblocks; node-b concurrently blocks with a different tag.
        // After merge the element should still be present (node-b's add survives).
        let mut node_a = GuardrailState::new();
        node_a.block_ip("10.0.0.5", "node-a");
        node_a.unblock_ip("10.0.0.5");

        let mut node_b = GuardrailState::new();
        node_b.block_ip("10.0.0.5", "node-b");

        node_a.merge(&node_b);
        assert!(
            node_a.is_ip_blocked("10.0.0.5"),
            "concurrent add from node-b survives"
        );
    }

    #[test]
    fn blocked_ips_returns_all() {
        let mut state = GuardrailState::new();
        state.block_ip("1.1.1.1", "node-a");
        state.block_ip("2.2.2.2", "node-a");
        state.block_ip("3.3.3.3", "node-a");
        state.unblock_ip("2.2.2.2");

        let mut ips = state.blocked_ips();
        ips.sort();
        assert_eq!(ips, vec!["1.1.1.1", "3.3.3.3"]);
    }

    #[test]
    fn blocked_users_returns_all() {
        let mut state = GuardrailState::new();
        state.block_user("alice", "node-a");
        state.block_user("bob", "node-a");
        state.unblock_user("alice");

        let users = state.blocked_users();
        assert_eq!(users, vec!["bob"]);
    }
}
