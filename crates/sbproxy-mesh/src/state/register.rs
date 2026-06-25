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

#[cfg(test)]
mod tests {
    use super::*;

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
}
