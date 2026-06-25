//! Config version tracking and broadcast via version vector.
//!
//! Tracks which config version each node has seen. Nodes compare their local
//! version against gossip-received remote versions and pull newer configs when
//! the remote version is higher.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Identifies a specific version of the proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigVersion {
    /// Monotonically increasing version counter.
    pub version: u64,
    /// SHA-256 of config content for integrity verification.
    pub hash: String,
    /// Node ID that made the change.
    pub updated_by: String,
    /// Unix timestamp (seconds) when the change was made.
    pub timestamp: u64,
}

/// Tracks and broadcasts the current config version across the mesh.
pub struct ConfigBroadcaster {
    current: Mutex<ConfigVersion>,
}

impl ConfigBroadcaster {
    /// Create a new broadcaster with version 0 (no config yet).
    pub fn new() -> Self {
        Self {
            current: Mutex::new(ConfigVersion {
                version: 0,
                hash: String::new(),
                updated_by: String::new(),
                timestamp: 0,
            }),
        }
    }

    /// Record a local config update, incrementing the version.
    ///
    /// Returns the new `ConfigVersion` that should be gossiped to peers.
    pub fn update(&self, hash: &str, node_id: &str) -> ConfigVersion {
        let mut guard = self.current.lock().expect("mutex poisoned");
        guard.version += 1;
        guard.hash = hash.to_string();
        guard.updated_by = node_id.to_string();
        guard.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        guard.clone()
    }

    /// Return the current config version.
    pub fn current(&self) -> ConfigVersion {
        self.current.lock().expect("mutex poisoned").clone()
    }

    /// Returns `true` if `remote` is newer than the local version and we should
    /// fetch the remote config.
    pub fn should_update(&self, remote: &ConfigVersion) -> bool {
        let guard = self.current.lock().expect("mutex poisoned");
        remote.version > guard.version
    }
}

impl Default for ConfigBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_increments_version() {
        let broadcaster = ConfigBroadcaster::new();
        assert_eq!(broadcaster.current().version, 0);

        let v1 = broadcaster.update("hash-abc", "node-a");
        assert_eq!(v1.version, 1);
        assert_eq!(v1.hash, "hash-abc");
        assert_eq!(v1.updated_by, "node-a");

        let v2 = broadcaster.update("hash-def", "node-b");
        assert_eq!(v2.version, 2);
        assert_eq!(v2.hash, "hash-def");
        assert_eq!(v2.updated_by, "node-b");
    }

    #[test]
    fn current_reflects_latest_update() {
        let broadcaster = ConfigBroadcaster::new();
        broadcaster.update("hash-1", "node-a");
        broadcaster.update("hash-2", "node-b");

        let cur = broadcaster.current();
        assert_eq!(cur.version, 2);
        assert_eq!(cur.hash, "hash-2");
    }

    #[test]
    fn should_update_with_newer_version() {
        let broadcaster = ConfigBroadcaster::new();
        broadcaster.update("hash-1", "node-a");

        let remote = ConfigVersion {
            version: 5,
            hash: "hash-newer".to_string(),
            updated_by: "node-b".to_string(),
            timestamp: 12345,
        };

        assert!(broadcaster.should_update(&remote));
    }

    #[test]
    fn same_version_no_update() {
        let broadcaster = ConfigBroadcaster::new();
        let v = broadcaster.update("hash-1", "node-a");

        // Remote has the same version - no update needed.
        let remote = ConfigVersion {
            version: v.version,
            hash: v.hash.clone(),
            updated_by: "node-b".to_string(),
            timestamp: 9999,
        };

        assert!(!broadcaster.should_update(&remote));
    }

    #[test]
    fn older_remote_no_update() {
        let broadcaster = ConfigBroadcaster::new();
        broadcaster.update("hash-1", "node-a");
        broadcaster.update("hash-2", "node-a");

        let old_remote = ConfigVersion {
            version: 1,
            hash: "hash-1".to_string(),
            updated_by: "node-a".to_string(),
            timestamp: 0,
        };

        assert!(!broadcaster.should_update(&old_remote));
    }

    #[test]
    fn config_version_serializes() {
        let cv = ConfigVersion {
            version: 3,
            hash: "abc123".to_string(),
            updated_by: "node-x".to_string(),
            timestamp: 1000,
        };
        let json = serde_json::to_string(&cv).expect("serialize");
        let back: ConfigVersion = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cv, back);
    }

    #[test]
    fn update_sets_nonzero_timestamp() {
        let broadcaster = ConfigBroadcaster::new();
        let v = broadcaster.update("hash-1", "node-a");
        // Timestamp should be set (non-zero in any reasonable test environment).
        assert!(v.timestamp > 0);
    }
}
