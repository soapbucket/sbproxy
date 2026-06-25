//! Simplified SWIM gossip protocol for membership management.
//!
//! Not using the foca crate yet - this is a minimal implementation
//! that can be swapped for foca later if needed.

use crate::node::{NodeId, NodeInfo};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Membership state for a node in the cluster.
#[derive(Debug, Clone, PartialEq)]
pub enum MemberState {
    /// Node is actively participating.
    Alive,
    /// Node has not responded; pending confirmation.
    Suspect,
    /// Node has been confirmed unreachable.
    Dead,
}

/// A single member tracked by the membership list.
#[derive(Debug, Clone)]
pub struct Member {
    /// Node identity and addressing for this member.
    pub info: NodeInfo,
    /// Current membership state (alive, suspect, or dead).
    pub state: MemberState,
    /// When this member was last heard from.
    pub last_seen: Instant,
}

/// Tracks cluster membership using a SWIM-style gossip protocol.
pub struct MembershipList {
    members: Mutex<HashMap<NodeId, Member>>,
    local_id: NodeId,
    local_info: Mutex<NodeInfo>,
}

impl MembershipList {
    /// Create a new membership list seeded with the local node.
    pub fn new(local: NodeInfo) -> Self {
        let local_id = local.id.clone();
        let mut members = HashMap::new();
        members.insert(
            local_id.clone(),
            Member {
                info: local.clone(),
                state: MemberState::Alive,
                last_seen: Instant::now(),
            },
        );
        Self {
            members: Mutex::new(members),
            local_id,
            local_info: Mutex::new(local),
        }
    }

    /// Add or update a member. Resets state to Alive and refreshes last_seen.
    pub fn upsert(&self, info: NodeInfo) {
        let mut members = self.members.lock().unwrap();
        let id = info.id.clone();
        members.insert(
            id,
            Member {
                info,
                state: MemberState::Alive,
                last_seen: Instant::now(),
            },
        );
    }

    /// Mark a member as suspect (may be down; awaiting confirmation).
    pub fn suspect(&self, id: &NodeId) {
        let mut members = self.members.lock().unwrap();
        if let Some(member) = members.get_mut(id) {
            if member.state == MemberState::Alive {
                member.state = MemberState::Suspect;
            }
        }
    }

    /// Mark a member as dead and remove it from the list.
    pub fn dead(&self, id: &NodeId) {
        let mut members = self.members.lock().unwrap();
        members.remove(id);
    }

    /// Get all alive members (excludes suspect and dead).
    pub fn alive_members(&self) -> Vec<NodeInfo> {
        let members = self.members.lock().unwrap();
        members
            .values()
            .filter(|m| m.state == MemberState::Alive)
            .map(|m| m.info.clone())
            .collect()
    }

    /// Get the count of alive members (excludes suspect and dead).
    pub fn alive_count(&self) -> usize {
        let members = self.members.lock().unwrap();
        members
            .values()
            .filter(|m| m.state == MemberState::Alive)
            .count()
    }

    /// Check for members that haven't been seen recently and mark them suspect.
    ///
    /// Returns the list of NodeIds that were newly marked suspect.
    pub fn check_timeouts(&self, timeout_secs: u64) -> Vec<NodeId> {
        let threshold = Duration::from_secs(timeout_secs);
        let mut members = self.members.lock().unwrap();
        let local_id = self.local_id.clone();
        let mut newly_suspect = Vec::new();

        for (id, member) in members.iter_mut() {
            // Never suspect ourselves.
            if id == &local_id {
                continue;
            }
            if member.state == MemberState::Alive && member.last_seen.elapsed() > threshold {
                member.state = MemberState::Suspect;
                newly_suspect.push(id.clone());
            }
        }

        newly_suspect
    }

    /// Get a snapshot of the local node's info.
    pub fn local(&self) -> NodeInfo {
        self.local_info.lock().unwrap().clone()
    }

    /// Get all current members regardless of state (for diagnostics).
    pub fn all_members(&self) -> Vec<(NodeId, MemberState)> {
        let members = self.members.lock().unwrap();
        members
            .values()
            .map(|m| (m.info.id.clone(), m.state.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{NodeId, NodeInfo};

    fn make_node(name: &str) -> NodeInfo {
        NodeInfo::new(
            NodeId::new(name),
            format!("{name}:8080"),
            7946,
            8946,
            "2026-01-01T00:00:00Z".to_string(),
        )
    }

    #[test]
    fn local_node_starts_alive() {
        let local = make_node("local");
        let list = MembershipList::new(local.clone());
        assert_eq!(list.alive_count(), 1);
        let alive = list.alive_members();
        assert_eq!(alive.len(), 1);
        assert_eq!(alive[0].id, NodeId::new("local"));
    }

    #[test]
    fn add_member_increases_count() {
        let local = make_node("local");
        let list = MembershipList::new(local);

        list.upsert(make_node("peer1"));
        list.upsert(make_node("peer2"));

        assert_eq!(list.alive_count(), 3);
    }

    #[test]
    fn upsert_existing_member_resets_to_alive() {
        let local = make_node("local");
        let list = MembershipList::new(local);

        list.upsert(make_node("peer1"));
        list.suspect(&NodeId::new("peer1"));
        assert_eq!(list.alive_count(), 1); // only local

        // Re-upsert resets to alive
        list.upsert(make_node("peer1"));
        assert_eq!(list.alive_count(), 2);
    }

    #[test]
    fn suspect_member_excluded_from_alive() {
        let local = make_node("local");
        let list = MembershipList::new(local);

        list.upsert(make_node("peer1"));
        assert_eq!(list.alive_count(), 2);

        list.suspect(&NodeId::new("peer1"));
        assert_eq!(list.alive_count(), 1);

        let alive = list.alive_members();
        assert_eq!(alive.len(), 1);
        assert_eq!(alive[0].id, NodeId::new("local"));
    }

    #[test]
    fn dead_member_removes_from_list() {
        let local = make_node("local");
        let list = MembershipList::new(local);

        list.upsert(make_node("peer1"));
        assert_eq!(list.alive_count(), 2);

        list.dead(&NodeId::new("peer1"));
        assert_eq!(list.alive_count(), 1);

        // Verify it's completely gone
        let all = list.all_members();
        assert!(!all.iter().any(|(id, _)| id == &NodeId::new("peer1")));
    }

    #[test]
    fn suspect_nonexistent_node_is_noop() {
        let local = make_node("local");
        let list = MembershipList::new(local);

        // Should not panic
        list.suspect(&NodeId::new("ghost"));
        assert_eq!(list.alive_count(), 1);
    }

    #[test]
    fn dead_nonexistent_node_is_noop() {
        let local = make_node("local");
        let list = MembershipList::new(local);

        // Should not panic
        list.dead(&NodeId::new("ghost"));
        assert_eq!(list.alive_count(), 1);
    }

    #[test]
    fn local_node_never_becomes_suspect_from_timeout() {
        let local = make_node("local");
        let list = MembershipList::new(local);

        // Use 0-second timeout to force everything to time out
        let newly_suspect = list.check_timeouts(0);

        // Local should never be marked suspect
        assert!(!newly_suspect.contains(&NodeId::new("local")));
        assert_eq!(list.alive_count(), 1); // local still alive
    }

    #[test]
    fn timeout_detection_marks_stale_peers_suspect() {
        let local = make_node("local");
        let list = MembershipList::new(local);

        list.upsert(make_node("peer1"));
        list.upsert(make_node("peer2"));
        assert_eq!(list.alive_count(), 3);

        // 0-second timeout forces immediate timeout detection
        let newly_suspect = list.check_timeouts(0);

        // Both peers should be newly suspect (local is excluded)
        assert_eq!(newly_suspect.len(), 2);
        assert_eq!(list.alive_count(), 1); // only local remains alive
    }

    #[test]
    fn alive_count_accuracy_with_mixed_states() {
        let local = make_node("local");
        let list = MembershipList::new(local);

        list.upsert(make_node("a"));
        list.upsert(make_node("b"));
        list.upsert(make_node("c"));

        list.suspect(&NodeId::new("a"));
        list.dead(&NodeId::new("b"));

        // local + c = 2
        assert_eq!(list.alive_count(), 2);
    }

    #[test]
    fn local_returns_correct_info() {
        let local = make_node("my-local-node");
        let list = MembershipList::new(local.clone());
        let info = list.local();
        assert_eq!(info.id, local.id);
        assert_eq!(info.gossip_port, local.gossip_port);
    }
}
