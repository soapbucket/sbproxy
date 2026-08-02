//! Last-Writer-Wins Register CRDT.
//!
//! The value with the highest timestamp wins. Used for session data.

use serde::{Deserialize, Serialize};

/// A last-writer-wins register for a single string value.
///
/// Concurrent writes from different nodes are resolved by taking the
/// one with the highest timestamp. Ties are broken lexicographically
/// by node_id to ensure a consistent total order.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LWWRegister {
    value: Option<String>,
    timestamp: u64, // milliseconds since epoch
    node_id: String,
}

impl LWWRegister {
    /// Create a new empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the register value with a timestamp (ms since epoch) and the writing node's ID.
    pub fn set(&mut self, value: String, node_id: &str) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // Only update if this write is newer (or tied with a higher node_id).
        if now_ms > self.timestamp || (now_ms == self.timestamp && node_id > self.node_id.as_str())
        {
            self.value = Some(value);
            self.timestamp = now_ms;
            self.node_id = node_id.to_string();
        }
    }

    /// Set the register value with an explicit timestamp (for testing and replication).
    pub fn set_at(&mut self, value: String, node_id: &str, timestamp_ms: u64) {
        if timestamp_ms > self.timestamp
            || (timestamp_ms == self.timestamp && node_id > self.node_id.as_str())
        {
            self.value = Some(value);
            self.timestamp = timestamp_ms;
            self.node_id = node_id.to_string();
        }
    }

    /// Get the current value, if any.
    pub fn get(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Merge with another register, keeping the one with the higher timestamp.
    ///
    /// Ties are broken lexicographically by node_id.
    pub fn merge(&mut self, other: &LWWRegister) {
        if other.timestamp > self.timestamp
            || (other.timestamp == self.timestamp && other.node_id > self.node_id)
        {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
            self.node_id = other.node_id.clone();
        }
    }

    /// Get the timestamp (ms since epoch) of the current value.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

/// Result of merging one versioned LWW candidate into the current value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionedLwwMergeOutcome {
    /// The candidate was identical to the current value.
    Unchanged,
    /// A newer candidate replaced the current value.
    Replaced,
    /// A lower logical version was rejected.
    StaleRejected,
    /// A competing update lost the deterministic LWW comparison.
    ConflictRetained,
    /// A competing update won the deterministic LWW comparison.
    ConflictReplaced,
    /// A retained tombstone rejected a live candidate during its horizon.
    TombstoneRetained,
}

/// Version-aware LWW register used by bounded mesh application state.
///
/// Logical versions prevent a newer wall clock from reviving stale history.
/// Equal-version updates use timestamp, node ID, and value as a stable total
/// order. A tombstone rejects every live update until the mesh TTL removes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedLwwRegister {
    value: String,
    logical_version: u64,
    parent_logical_version: Option<u64>,
    timestamp_ms: u64,
    node_id: String,
    tombstone: bool,
    conflict_detected: bool,
}

impl VersionedLwwRegister {
    /// Construct a live versioned value using an explicit deterministic clock.
    pub fn live(
        value: String,
        node_id: &str,
        timestamp_ms: u64,
        logical_version: u64,
        parent_logical_version: Option<u64>,
    ) -> Self {
        Self::new(
            value,
            node_id,
            timestamp_ms,
            logical_version,
            parent_logical_version,
            false,
        )
    }

    /// Construct a deletion marker using an explicit deterministic clock.
    pub fn tombstone(
        value: String,
        node_id: &str,
        timestamp_ms: u64,
        logical_version: u64,
        parent_logical_version: Option<u64>,
    ) -> Self {
        Self::new(
            value,
            node_id,
            timestamp_ms,
            logical_version,
            parent_logical_version,
            true,
        )
    }

    fn new(
        value: String,
        node_id: &str,
        timestamp_ms: u64,
        logical_version: u64,
        parent_logical_version: Option<u64>,
        tombstone: bool,
    ) -> Self {
        Self {
            value,
            logical_version,
            parent_logical_version,
            timestamp_ms,
            node_id: node_id.to_string(),
            tombstone,
            conflict_detected: false,
        }
    }

    /// Borrow the encoded application value.
    pub fn value(&self) -> Option<&str> {
        Some(&self.value)
    }

    /// Monotonic application logical version.
    pub const fn logical_version(&self) -> u64 {
        self.logical_version
    }

    /// Logical version extended by this value.
    pub const fn parent_logical_version(&self) -> Option<u64> {
        self.parent_logical_version
    }

    /// Explicit Unix timestamp used for the LWW comparison.
    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// Stable writer node used to break timestamp ties.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Whether this value prevents stale live resurrection until expiry.
    pub const fn is_tombstone(&self) -> bool {
        self.tombstone
    }

    /// Whether equal-version competing updates were observed.
    pub const fn conflict_detected(&self) -> bool {
        self.conflict_detected
    }

    /// Merge a candidate using logical-version fencing and deterministic LWW.
    pub fn merge(&mut self, candidate: &Self) -> VersionedLwwMergeOutcome {
        if self.tombstone && !candidate.tombstone {
            return VersionedLwwMergeOutcome::TombstoneRetained;
        }
        self.merge_after_tombstone_fence(candidate)
    }

    /// Merge a candidate with the logical version as the primary fence.
    ///
    /// Unlike [`Self::merge`], a live candidate carrying a strictly higher
    /// logical version replaces a tombstone. The replicated substrate needs
    /// this: a coordinator that read the tombstone (proving causality) must
    /// be able to re-create the key, while a stale live copy at a lower or
    /// equal version is still fenced out. [`Self::merge`] keeps the
    /// tombstone-blocks-all-live behavior the typed cluster state relies on.
    pub fn merge_causal(&mut self, candidate: &Self) -> VersionedLwwMergeOutcome {
        if self.tombstone
            && !candidate.tombstone
            && candidate.logical_version <= self.logical_version
        {
            return VersionedLwwMergeOutcome::TombstoneRetained;
        }
        self.merge_after_tombstone_fence(candidate)
    }

    fn merge_after_tombstone_fence(&mut self, candidate: &Self) -> VersionedLwwMergeOutcome {
        if candidate.logical_version < self.logical_version {
            return VersionedLwwMergeOutcome::StaleRejected;
        }
        if candidate.logical_version > self.logical_version {
            *self = candidate.clone();
            return VersionedLwwMergeOutcome::Replaced;
        }

        let identical = self.value == candidate.value
            && self.parent_logical_version == candidate.parent_logical_version
            && self.timestamp_ms == candidate.timestamp_ms
            && self.node_id == candidate.node_id
            && self.tombstone == candidate.tombstone;
        if identical {
            self.conflict_detected |= candidate.conflict_detected;
            return VersionedLwwMergeOutcome::Unchanged;
        }

        let candidate_wins = (
            candidate.tombstone,
            candidate.timestamp_ms,
            candidate.node_id.as_str(),
            candidate.parent_logical_version,
            candidate.value.as_str(),
        ) > (
            self.tombstone,
            self.timestamp_ms,
            self.node_id.as_str(),
            self.parent_logical_version,
            self.value.as_str(),
        );
        let conflict_detected = self.conflict_detected || candidate.conflict_detected || !identical;
        if candidate_wins {
            *self = candidate.clone();
            self.conflict_detected = conflict_detected;
            VersionedLwwMergeOutcome::ConflictReplaced
        } else {
            self.conflict_detected = conflict_detected;
            VersionedLwwMergeOutcome::ConflictRetained
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versioned_live(
        value: &str,
        node_id: &str,
        timestamp_ms: u64,
        logical_version: u64,
        parent_logical_version: Option<u64>,
    ) -> VersionedLwwRegister {
        VersionedLwwRegister::live(
            value.to_string(),
            node_id,
            timestamp_ms,
            logical_version,
            parent_logical_version,
        )
    }

    #[test]
    fn new_register_is_empty() {
        let r = LWWRegister::new();
        assert_eq!(r.get(), None);
        assert_eq!(r.timestamp(), 0);
    }

    #[test]
    fn set_and_get() {
        let mut r = LWWRegister::new();
        r.set("session-data".to_string(), "node-a");
        assert_eq!(r.get(), Some("session-data"));
    }

    #[test]
    fn higher_timestamp_wins_in_merge() {
        let mut old = LWWRegister::new();
        old.set_at("old-value".to_string(), "node-a", 100);

        let mut new_reg = LWWRegister::new();
        new_reg.set_at("new-value".to_string(), "node-b", 200);

        old.merge(&new_reg);
        assert_eq!(old.get(), Some("new-value"));
        assert_eq!(old.timestamp(), 200);
    }

    #[test]
    fn lower_timestamp_loses_in_merge() {
        let mut current = LWWRegister::new();
        current.set_at("current-value".to_string(), "node-a", 500);

        let mut stale = LWWRegister::new();
        stale.set_at("stale-value".to_string(), "node-b", 100);

        current.merge(&stale);
        assert_eq!(current.get(), Some("current-value"));
        assert_eq!(current.timestamp(), 500);
    }

    #[test]
    fn same_timestamp_higher_node_id_wins() {
        let mut a = LWWRegister::new();
        a.set_at("value-from-a".to_string(), "node-a", 1000);

        let mut b = LWWRegister::new();
        b.set_at("value-from-z".to_string(), "node-z", 1000);

        a.merge(&b);
        // "node-z" > "node-a" lexicographically
        assert_eq!(a.get(), Some("value-from-z"));
    }

    #[test]
    fn same_timestamp_lower_node_id_loses() {
        let mut z = LWWRegister::new();
        z.set_at("value-from-z".to_string(), "node-z", 1000);

        let mut a = LWWRegister::new();
        a.set_at("value-from-a".to_string(), "node-a", 1000);

        z.merge(&a);
        // "node-z" > "node-a", so z's value should stay
        assert_eq!(z.get(), Some("value-from-z"));
    }

    #[test]
    fn merge_is_idempotent() {
        let mut r = LWWRegister::new();
        r.set_at("val".to_string(), "node-a", 100);

        let snapshot = r.clone();
        r.merge(&snapshot);
        r.merge(&snapshot);
        assert_eq!(r.get(), Some("val"));
        assert_eq!(r.timestamp(), 100);
    }

    #[test]
    fn merge_with_empty_register() {
        let mut r = LWWRegister::new();
        r.set_at("val".to_string(), "node-a", 100);

        let empty = LWWRegister::new();
        r.merge(&empty);
        assert_eq!(r.get(), Some("val")); // empty should not overwrite
    }

    #[test]
    fn timestamp_returned_correctly() {
        let mut r = LWWRegister::new();
        r.set_at("x".to_string(), "n", 12345);
        assert_eq!(r.timestamp(), 12345);
    }

    #[test]
    fn serializes_and_deserializes() {
        let mut r = LWWRegister::new();
        r.set_at("session-abc".to_string(), "node-1", 9999);
        let json = serde_json::to_string(&r).expect("serialize");
        let back: LWWRegister = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.get(), Some("session-abc"));
        assert_eq!(back.timestamp(), 9999);
    }

    #[test]
    fn versioned_register_rejects_stale_logical_version_even_with_newer_clock() {
        let mut current = versioned_live("version-3", "node-a", 100, 3, Some(2));
        let stale = versioned_live("version-2", "node-z", 10_000, 2, Some(1));

        assert_eq!(
            current.merge(&stale),
            VersionedLwwMergeOutcome::StaleRejected
        );
        assert_eq!(current.value(), Some("version-3"));
        assert_eq!(current.logical_version(), 3);
    }

    #[test]
    fn versioned_register_uses_fixed_clock_then_node_id_for_same_version() {
        let mut current = versioned_live("from-a", "node-a", 500, 4, Some(3));
        let newer = versioned_live("from-b", "node-b", 600, 4, Some(3));

        assert_eq!(
            current.merge(&newer),
            VersionedLwwMergeOutcome::ConflictReplaced
        );
        assert_eq!(current.value(), Some("from-b"));
        assert!(current.conflict_detected());

        let tied_lower_node = versioned_live("from-aa", "node-aa", 600, 4, Some(3));
        assert_eq!(
            current.merge(&tied_lower_node),
            VersionedLwwMergeOutcome::ConflictRetained
        );
        assert_eq!(current.value(), Some("from-b"));
        assert!(current.conflict_detected());
    }

    #[test]
    fn competing_children_converge_to_same_conflicted_winner_in_any_order() {
        let left = versioned_live("left", "node-a", 700, 8, Some(7));
        let right = versioned_live("right", "node-z", 700, 8, Some(7));

        let mut left_then_right = left.clone();
        left_then_right.merge(&right);
        let mut right_then_left = right;
        right_then_left.merge(&left);

        assert_eq!(left_then_right, right_then_left);
        assert_eq!(left_then_right.value(), Some("right"));
        assert!(left_then_right.conflict_detected());
    }

    #[test]
    fn tombstone_blocks_live_resurrection_inside_retention_horizon() {
        let mut tombstone =
            VersionedLwwRegister::tombstone("deleted".to_string(), "node-a", 1_000, 6, Some(5));
        let stale_replica = versioned_live("sensitive", "node-z", 2_000, 7, Some(6));

        assert_eq!(
            tombstone.merge(&stale_replica),
            VersionedLwwMergeOutcome::TombstoneRetained
        );
        assert!(tombstone.is_tombstone());
        assert_eq!(tombstone.value(), Some("deleted"));
    }

    #[test]
    fn newer_tombstone_replaces_live_state_deterministically() {
        let mut live = versioned_live("sensitive", "node-a", 1_000, 5, Some(4));
        let tombstone =
            VersionedLwwRegister::tombstone("deleted".to_string(), "node-b", 900, 6, Some(5));

        assert_eq!(live.merge(&tombstone), VersionedLwwMergeOutcome::Replaced);
        assert!(live.is_tombstone());
        assert_eq!(live.logical_version(), 6);
    }

    #[test]
    fn causal_merge_lets_a_higher_version_live_write_recreate_a_deleted_key() {
        let mut tombstone =
            VersionedLwwRegister::tombstone("deleted".to_string(), "node-a", 1_000, 6, Some(5));
        let recreate = versioned_live("fresh", "node-b", 2_000, 7, Some(6));

        assert_eq!(
            tombstone.merge_causal(&recreate),
            VersionedLwwMergeOutcome::Replaced
        );
        assert!(!tombstone.is_tombstone());
        assert_eq!(tombstone.value(), Some("fresh"));
        assert_eq!(tombstone.logical_version(), 7);
    }

    #[test]
    fn causal_merge_still_fences_stale_and_equal_version_live_writes() {
        let mut tombstone =
            VersionedLwwRegister::tombstone("deleted".to_string(), "node-a", 1_000, 6, Some(5));

        let stale = versioned_live("sensitive", "node-z", 2_000, 5, Some(4));
        assert_eq!(
            tombstone.merge_causal(&stale),
            VersionedLwwMergeOutcome::TombstoneRetained
        );

        let concurrent = versioned_live("sensitive", "node-z", 2_000, 6, Some(5));
        assert_eq!(
            tombstone.merge_causal(&concurrent),
            VersionedLwwMergeOutcome::TombstoneRetained
        );
        assert!(tombstone.is_tombstone());
    }

    #[test]
    fn causal_merge_matches_merge_for_live_on_live_updates() {
        let mut a = versioned_live("v1", "node-a", 1_000, 5, Some(4));
        let newer = versioned_live("v2", "node-b", 1_500, 6, Some(5));
        assert_eq!(a.merge_causal(&newer), VersionedLwwMergeOutcome::Replaced);

        let mut b = versioned_live("v2", "node-b", 1_500, 6, Some(5));
        let stale = versioned_live("v1", "node-a", 9_999, 5, Some(4));
        assert_eq!(
            b.merge_causal(&stale),
            VersionedLwwMergeOutcome::StaleRejected
        );
    }

    #[test]
    fn versioned_register_round_trip_preserves_merge_metadata() {
        let mut register = versioned_live("right", "node-z", 700, 8, Some(7));
        register.merge(&versioned_live("left", "node-a", 700, 8, Some(7)));

        let encoded = serde_json::to_vec(&register).unwrap();
        let decoded: VersionedLwwRegister = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded, register);
        assert!(decoded.conflict_detected());
        assert_eq!(decoded.parent_logical_version(), Some(7));
    }
}
