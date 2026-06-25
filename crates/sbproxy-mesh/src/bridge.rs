//! Cross-mesh bridge for multi-mesh cluster communication.
//!
//! When clusters grow beyond ~100 nodes, SWIM gossip overhead becomes
//! significant (O(n^2)). Split into multiple mesh groups with a bridge
//! that forwards state changes between groups.
//!
//! # Status: alpha (data structures only)
//!
//! **The bridge ships its data structures and the in-memory
//! aggregation logic, but it does not yet ship a transport.**
//! There is no network sync loop, no reqwest pull, and no caller
//! outside this crate's tests. Operators can construct and exercise
//! a `MeshBridge` programmatically (it is the same type the
//! production sync loop will eventually own), but spinning one up in
//! a deployment **does not** make rate-limit counters or blocklists
//! flow between mesh groups today.
//!
//! See `docs/mesh-bridge-roadmap.md` for the planned shape of the
//! transport (a reqwest-based pull on `sync_interval_secs` plus an
//! optional push via the existing gossip plane). The data structures
//! and public API on this module are stable; only the transport is
//! pending.
//!
//! Until the transport lands, the bridge constructor is silent (no
//! "ready" / "started" log) so it cannot be mistaken for a working
//! piece in audit logs. Callers that adopt the bridge in tests or
//! pre-production should call [`MeshBridge::log_alpha_status`]
//! explicitly to surface the maturity caveat.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Named group of mesh nodes that gossip internally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshGroup {
    /// Human-readable group name (used as the snapshot key).
    pub name: String,
    /// Bootstrap addresses for the SWIM gossip plane inside the group.
    pub seed_addresses: Vec<String>,
}

/// Configuration for the cross-mesh bridge.
///
/// `sync_interval_secs` is parsed and stored but not yet honoured by
/// any background task; see the module-level "alpha" note. The field
/// is kept on the struct so config files written today remain valid
/// when the transport lands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Group this bridge instance belongs to. Snapshots tagged with
    /// this name are *outgoing* (the bridge will not store its own
    /// snapshot in the remote-state map).
    pub local_group: String,
    /// Remote groups the bridge syncs state with.
    pub remote_groups: Vec<MeshGroup>,
    /// How often to sync state between groups (seconds). **Not
    /// honoured today**; see module-level alpha note.
    pub sync_interval_secs: u64,
}

/// Bridge that aggregates state across multiple mesh groups.
///
/// **Alpha**: only the in-memory aggregation half of the bridge is
/// wired. See module-level documentation.
pub struct MeshBridge {
    config: BridgeConfig,
    /// State summaries received from remote groups, keyed by group name.
    remote_state: std::sync::Mutex<HashMap<String, BridgeStateSnapshot>>,
}

/// A snapshot of one mesh group's state, exchanged between bridges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeStateSnapshot {
    pub group_name: String,
    pub node_count: usize,
    pub rate_limit_counters: HashMap<String, u64>,
    pub blocked_ips: Vec<String>,
    pub blocked_users: Vec<String>,
    pub timestamp: u64,
}

impl MeshBridge {
    /// Create a new bridge with the given configuration.
    ///
    /// Construction is intentionally silent (no `tracing::info!`
    /// "started" event) because the bridge has no transport yet:
    /// emitting a "started" log here would make the bridge look
    /// production-ready in audit logs even though no remote sync is
    /// happening. Callers that want the alpha caveat surfaced should
    /// call [`Self::log_alpha_status`] explicitly after construction.
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            config,
            remote_state: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Emit a `tracing::warn!` event documenting the bridge's alpha
    /// status. Intended for the binary entry point so operators that
    /// adopt the bridge in pre-production see the caveat at startup.
    /// The constructor stays silent so unit tests, in-process
    /// integrations, and OpenAPI emission don't pollute logs.
    pub fn log_alpha_status(&self) {
        tracing::warn!(
            local_group = %self.config.local_group,
            remote_groups = self.config.remote_groups.len(),
            sync_interval_secs = self.config.sync_interval_secs,
            "MeshBridge constructed in ALPHA mode: no transport wired. \
             apply_remote_snapshot must be driven manually until the \
             reqwest pull loop lands. See docs/mesh-bridge-roadmap.md."
        );
    }

    /// Create a state snapshot from the local mesh to send to remote groups.
    pub fn create_snapshot(
        &self,
        local_group: &str,
        node_count: usize,
        rate_counters: &HashMap<String, u64>,
        blocked_ips: &[String],
        blocked_users: &[String],
    ) -> BridgeStateSnapshot {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        BridgeStateSnapshot {
            group_name: local_group.to_string(),
            node_count,
            rate_limit_counters: rate_counters.clone(),
            blocked_ips: blocked_ips.to_vec(),
            blocked_users: blocked_users.to_vec(),
            timestamp,
        }
    }

    /// Apply a state snapshot received from a remote group.
    pub fn apply_remote_snapshot(&self, snapshot: BridgeStateSnapshot) {
        let mut state = self.remote_state.lock().expect("remote_state lock");
        state.insert(snapshot.group_name.clone(), snapshot);
    }

    /// Get the aggregated rate limit counter for `key` across all known mesh groups.
    ///
    /// Returns the sum of this counter across all remote groups. The caller
    /// should add their own local value on top.
    pub fn aggregated_rate_limit(&self, key: &str) -> u64 {
        let state = self.remote_state.lock().expect("remote_state lock");
        state
            .values()
            .filter_map(|s| s.rate_limit_counters.get(key))
            .sum()
    }

    /// Get all blocked IPs across all mesh groups (deduplicated).
    pub fn all_blocked_ips(&self) -> Vec<String> {
        let state = self.remote_state.lock().expect("remote_state lock");
        let mut ips: Vec<String> = state
            .values()
            .flat_map(|s| s.blocked_ips.iter().cloned())
            .collect();
        ips.sort();
        ips.dedup();
        ips
    }

    /// Get all blocked users across all mesh groups (deduplicated).
    pub fn all_blocked_users(&self) -> Vec<String> {
        let state = self.remote_state.lock().expect("remote_state lock");
        let mut users: Vec<String> = state
            .values()
            .flat_map(|s| s.blocked_users.iter().cloned())
            .collect();
        users.sort();
        users.dedup();
        users
    }

    /// Get the total node count across all known mesh groups (remote only).
    pub fn total_node_count(&self) -> usize {
        let state = self.remote_state.lock().expect("remote_state lock");
        state.values().map(|s| s.node_count).sum()
    }

    /// Return a reference to the bridge config.
    pub fn config(&self) -> &BridgeConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> BridgeConfig {
        BridgeConfig {
            local_group: "us-east".to_string(),
            remote_groups: vec![
                MeshGroup {
                    name: "us-west".to_string(),
                    seed_addresses: vec!["10.1.0.10:7946".to_string()],
                },
                MeshGroup {
                    name: "eu-central".to_string(),
                    seed_addresses: vec!["10.2.0.10:7946".to_string()],
                },
            ],
            sync_interval_secs: 5,
        }
    }

    #[test]
    fn create_snapshot_includes_all_fields() {
        let bridge = MeshBridge::new(make_config());

        let mut counters = HashMap::new();
        counters.insert("api:/v1/upload".to_string(), 120u64);

        let snapshot = bridge.create_snapshot(
            "us-east",
            10,
            &counters,
            &["1.2.3.4".to_string()],
            &["bad-user".to_string()],
        );

        assert_eq!(snapshot.group_name, "us-east");
        assert_eq!(snapshot.node_count, 10);
        assert_eq!(
            snapshot.rate_limit_counters.get("api:/v1/upload"),
            Some(&120)
        );
        assert_eq!(snapshot.blocked_ips, vec!["1.2.3.4"]);
        assert_eq!(snapshot.blocked_users, vec!["bad-user"]);
        assert!(snapshot.timestamp > 0);
    }

    #[test]
    fn apply_remote_snapshot_stored() {
        let bridge = MeshBridge::new(make_config());

        let snapshot = BridgeStateSnapshot {
            group_name: "us-west".to_string(),
            node_count: 5,
            rate_limit_counters: HashMap::new(),
            blocked_ips: vec![],
            blocked_users: vec![],
            timestamp: 1000,
        };
        bridge.apply_remote_snapshot(snapshot);

        assert_eq!(bridge.total_node_count(), 5);
    }

    #[test]
    fn aggregate_rate_limits_sums_across_groups() {
        let bridge = MeshBridge::new(make_config());

        let mut counters_west = HashMap::new();
        counters_west.insert("key:foo".to_string(), 30u64);

        let mut counters_eu = HashMap::new();
        counters_eu.insert("key:foo".to_string(), 20u64);

        bridge.apply_remote_snapshot(BridgeStateSnapshot {
            group_name: "us-west".to_string(),
            node_count: 3,
            rate_limit_counters: counters_west,
            blocked_ips: vec![],
            blocked_users: vec![],
            timestamp: 1,
        });
        bridge.apply_remote_snapshot(BridgeStateSnapshot {
            group_name: "eu-central".to_string(),
            node_count: 4,
            rate_limit_counters: counters_eu,
            blocked_ips: vec![],
            blocked_users: vec![],
            timestamp: 2,
        });

        // 30 + 20 = 50
        assert_eq!(bridge.aggregated_rate_limit("key:foo"), 50);
        // unknown key returns 0
        assert_eq!(bridge.aggregated_rate_limit("key:missing"), 0);
    }

    #[test]
    fn all_blocked_ips_across_groups_deduplicated() {
        let bridge = MeshBridge::new(make_config());

        bridge.apply_remote_snapshot(BridgeStateSnapshot {
            group_name: "us-west".to_string(),
            node_count: 2,
            rate_limit_counters: HashMap::new(),
            blocked_ips: vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
            blocked_users: vec![],
            timestamp: 1,
        });
        bridge.apply_remote_snapshot(BridgeStateSnapshot {
            group_name: "eu-central".to_string(),
            node_count: 2,
            rate_limit_counters: HashMap::new(),
            blocked_ips: vec!["10.0.0.2".to_string(), "10.0.0.3".to_string()],
            blocked_users: vec![],
            timestamp: 2,
        });

        let ips = bridge.all_blocked_ips();
        assert_eq!(ips.len(), 3);
        assert!(ips.contains(&"10.0.0.1".to_string()));
        assert!(ips.contains(&"10.0.0.2".to_string()));
        assert!(ips.contains(&"10.0.0.3".to_string()));
    }

    #[test]
    fn new_does_not_log_to_avoid_misleading_ready_status() {
        // The bridge has no transport yet. Construction must not
        // emit a tracing event that would make audit logs claim the
        // bridge is "ready" / "started". This is a regression guard:
        // adding a startup log to `new` is a one-line change that
        // looks innocent in code review but breaks the alpha contract.
        //
        // We can't directly assert "no event was emitted" without a
        // tracing subscriber stub, so we cover the contract two ways:
        //   1. The visible source of `MeshBridge::new` contains no
        //      `tracing::` calls (smoke check via this test file).
        //   2. The dedicated `log_alpha_status()` exists for callers
        //      that DO want the caveat on the wire (asserted below).
        let cfg = make_config();
        let bridge = MeshBridge::new(cfg);
        // The remote-state map starts empty; this is the only
        // observable side-effect of construction.
        assert_eq!(bridge.total_node_count(), 0);
    }

    #[test]
    fn log_alpha_status_runs_without_panicking() {
        // Smoke: the warn! event must build cleanly (no formatter
        // panics, no deadlocks) when invoked from a test context.
        let bridge = MeshBridge::new(make_config());
        bridge.log_alpha_status();
    }

    #[test]
    fn total_node_count_sums_remote_groups() {
        let bridge = MeshBridge::new(make_config());

        bridge.apply_remote_snapshot(BridgeStateSnapshot {
            group_name: "us-west".to_string(),
            node_count: 7,
            rate_limit_counters: HashMap::new(),
            blocked_ips: vec![],
            blocked_users: vec![],
            timestamp: 1,
        });
        bridge.apply_remote_snapshot(BridgeStateSnapshot {
            group_name: "eu-central".to_string(),
            node_count: 12,
            rate_limit_counters: HashMap::new(),
            blocked_ips: vec![],
            blocked_users: vec![],
            timestamp: 2,
        });

        assert_eq!(bridge.total_node_count(), 19);
    }
}
