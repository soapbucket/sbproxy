//! Convergence machinery for the replicated substrate: ownership handoff,
//! anti-entropy with read-repair semantics, and acknowledgement-aware
//! tombstone garbage collection.
//!
//! One [`ReplicatedStore::maintenance_round`] runs three bounded phases:
//!
//! 1. **Handoff**: records this node holds but no longer replicates (the
//!    ring changed) are pushed to every current replica; the local copy is
//!    dropped only after every push acknowledged, so a rebalance can move
//!    data but never silently lose it (WOR-1947 AC3).
//! 2. **Anti-entropy**: for each peer, exchange bounded digest pages and
//!    reconcile both directions with the causal merge. This is what
//!    converges live records and tombstones after a partition heals
//!    (WOR-1947 AC4).
//! 3. **Tombstone GC**: a tombstone is physically collected only when it
//!    is older than the grace period AND every current replica of the key
//!    confirms it (or holds a causally newer record). Combined with the
//!    long-absence quarantine in [`super::shard`], this is the
//!    no-resurrection argument documented in `docs/mesh-replication.md`
//!    (WOR-1947 AC5).
//!
//! Every phase pages through bounded windows so a large shard cannot pin
//! CPU or flood the transport in one tick.

use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::metrics::{
    ANTI_ENTROPY_DIRECTION_PULL, ANTI_ENTROPY_DIRECTION_PUSH, GC_OUTCOME_COLLECTED,
    GC_OUTCOME_DEFERRED, HANDOFF_OUTCOME_MOVED, HANDOFF_OUTCOME_RETAINED, MESH_ANTI_ENTROPY_KEYS,
    MESH_ANTI_ENTROPY_ROUNDS, MESH_HANDOFF_KEYS, MESH_REPLICA_SHARD_ENTRIES, MESH_TOMBSTONE_GC,
};
use crate::state::register::VersionedLwwRegister;
use crate::transport::frame::KeyDigest;

use super::shard::MAX_DIGEST_PAGE_ENTRIES;
use super::ReplicatedStore;

/// Records examined per maintenance phase per round.
const MAX_KEYS_PER_ROUND: usize = 2_048;
/// Digest pages pulled per peer per anti-entropy round.
const MAX_SYNC_PAGES_PER_PEER: usize = 8;
/// Entries per requested digest page.
const SYNC_PAGE_LIMIT: usize = 512;

/// What one maintenance round did. Returned for tests and diagnostics;
/// the numbers are also exported through `mesh_*` metrics.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MaintenanceReport {
    /// Records pulled from peers into the local shard.
    pub pulled: usize,
    /// Records pushed to peers that were missing or stale.
    pub pushed: usize,
    /// Records handed off to their new replica set and dropped locally.
    pub handoff_moved: usize,
    /// Records that failed handoff and remain local for the next round.
    pub handoff_retained: usize,
    /// Tombstones physically collected after full confirmation.
    pub gc_collected: usize,
    /// Tombstones past grace that still lack replica confirmation.
    pub gc_deferred: usize,
    /// True when a peer digest scan hit the per-round page budget, so the
    /// push phase for that peer was skipped this round.
    pub truncated: bool,
}

impl ReplicatedStore {
    /// Run one bounded maintenance round: handoff, anti-entropy, GC.
    pub async fn maintenance_round(&self) -> MaintenanceReport {
        let mut report = MaintenanceReport::default();
        // Liveness watermark first: a node that keeps completing rounds is
        // by definition inside the quarantine grace window.
        if let Err(error) = self.shard.heartbeat() {
            tracing::warn!(%error, "replicated maintenance: heartbeat persist failed");
        }
        self.handoff_round(&mut report).await;
        self.anti_entropy_round(&mut report).await;
        self.gc_round(&mut report).await;
        MESH_ANTI_ENTROPY_ROUNDS.inc();
        MESH_REPLICA_SHARD_ENTRIES.set(self.shard.len() as i64);
        report
    }

    /// Phase 1: push records this node no longer replicates to their
    /// current replica set, dropping the local copy only after every
    /// replica acknowledged.
    async fn handoff_round(&self, report: &mut MaintenanceReport) {
        let mut after: Option<String> = None;
        let mut scanned = 0usize;
        loop {
            let page = self.shard.records_page(after.as_deref(), SYNC_PAGE_LIMIT);
            if page.is_empty() {
                break;
            }
            after = page.last().map(|(key, _)| key.clone());
            for (key, record) in page {
                scanned += 1;
                if scanned > MAX_KEYS_PER_ROUND {
                    return;
                }
                let replicas = self.replica_set(&key);
                if replicas.is_empty() || replicas.iter().any(|n| n == self.local_node_id()) {
                    continue;
                }
                let mut all_acked = true;
                for node in &replicas {
                    if self
                        .apply_on(
                            node,
                            &key,
                            &record.register,
                            record.remaining_ttl_secs((self.clock)()),
                        )
                        .await
                        .is_err()
                    {
                        all_acked = false;
                    }
                }
                if all_acked {
                    match self.shard.remove_exact(&key, &record.register) {
                        Ok(true) => {
                            report.handoff_moved += 1;
                            MESH_HANDOFF_KEYS
                                .with_label_values(&[HANDOFF_OUTCOME_MOVED])
                                .inc();
                        }
                        // The record changed while we were pushing; the
                        // next round hands off the newer version.
                        _ => {
                            report.handoff_retained += 1;
                            MESH_HANDOFF_KEYS
                                .with_label_values(&[HANDOFF_OUTCOME_RETAINED])
                                .inc();
                        }
                    }
                } else {
                    report.handoff_retained += 1;
                    MESH_HANDOFF_KEYS
                        .with_label_values(&[HANDOFF_OUTCOME_RETAINED])
                        .inc();
                }
            }
        }
    }

    /// Phase 2: reconcile with each peer through bounded digest exchange.
    async fn anti_entropy_round(&self, report: &mut MaintenanceReport) {
        let peers: Vec<String> = self
            .cache
            .member_nodes()
            .into_iter()
            .filter(|n| n != self.local_node_id())
            .collect();
        for peer in peers {
            self.sync_with_peer(&peer, report).await;
        }
    }

    async fn sync_with_peer(&self, peer: &str, report: &mut MaintenanceReport) {
        let Some(client) = self.client_for(peer) else {
            return;
        };

        // --- Pull phase: walk the peer's digest ---
        let mut peer_digest: Vec<KeyDigest> = Vec::new();
        let mut page_token: Option<String> = None;
        let mut complete = false;
        for _ in 0..MAX_SYNC_PAGES_PER_PEER {
            let page = match tokio::time::timeout(
                Duration::from_secs(2),
                client.sync_digest(String::new(), page_token.clone(), SYNC_PAGE_LIMIT as u32),
            )
            .await
            {
                Ok(Ok(page)) => page,
                _ => return,
            };
            peer_digest.extend(page.entries);
            match page.next_page_token {
                Some(token) => page_token = Some(token),
                None => {
                    complete = true;
                    break;
                }
            }
        }
        if !complete {
            report.truncated = true;
        }

        for entry in &peer_digest {
            if !self
                .replica_set(&entry.key)
                .iter()
                .any(|n| n == self.local_node_id())
            {
                continue;
            }
            let local = self.shard.fetch(&entry.key);
            if !peer_side_is_newer(entry, local.as_ref()) {
                continue;
            }
            // Fetch the full record and causally merge it in. StaleRejected
            // is fine here: it means the local side advanced concurrently.
            if let Ok(Some(record)) = self.fetch_record_from(peer, &entry.key).await {
                let ttl = record.remaining_ttl_secs((self.clock)());
                if self.shard.apply(&entry.key, &record.register, ttl).is_ok() {
                    report.pulled += 1;
                    MESH_ANTI_ENTROPY_KEYS
                        .with_label_values(&[ANTI_ENTROPY_DIRECTION_PULL])
                        .inc();
                }
            }
        }

        // --- Push phase: only sound against a complete peer digest ---
        if !complete {
            return;
        }
        let peer_versions: std::collections::HashMap<&str, &KeyDigest> = peer_digest
            .iter()
            .map(|entry| (entry.key.as_str(), entry))
            .collect();
        let mut after: Option<String> = None;
        let mut scanned = 0usize;
        loop {
            let page = self.shard.records_page(after.as_deref(), SYNC_PAGE_LIMIT);
            if page.is_empty() {
                break;
            }
            after = page.last().map(|(key, _)| key.clone());
            for (key, record) in page {
                scanned += 1;
                if scanned > MAX_KEYS_PER_ROUND {
                    return;
                }
                if !self.replica_set(&key).iter().any(|n| n == peer) {
                    continue;
                }
                let peer_has_newer = peer_versions
                    .get(key.as_str())
                    .is_some_and(|entry| !local_side_is_newer(&record.register, entry));
                if peer_has_newer {
                    continue;
                }
                if self
                    .apply_on(
                        peer,
                        &key,
                        &record.register,
                        record.remaining_ttl_secs((self.clock)()),
                    )
                    .await
                    .is_ok()
                {
                    report.pushed += 1;
                    MESH_ANTI_ENTROPY_KEYS
                        .with_label_values(&[ANTI_ENTROPY_DIRECTION_PUSH])
                        .inc();
                }
            }
        }
    }

    /// Phase 3: acknowledgement-aware tombstone collection.
    async fn gc_round(&self, report: &mut MaintenanceReport) {
        let grace_ms = self.settings.tombstone_gc_grace_secs.saturating_mul(1_000);
        if grace_ms == 0 {
            // Grace zero disables GC entirely rather than collecting
            // tombstones that were never disseminated.
            return;
        }
        let now = (self.clock)();
        let mut after: Option<String> = None;
        let mut scanned = 0usize;
        loop {
            let page = self.shard.records_page(after.as_deref(), SYNC_PAGE_LIMIT);
            if page.is_empty() {
                break;
            }
            after = page.last().map(|(key, _)| key.clone());
            for (key, record) in page {
                scanned += 1;
                if scanned > MAX_KEYS_PER_ROUND {
                    return;
                }
                if !record.register.is_tombstone() {
                    continue;
                }
                if now.saturating_sub(record.register.timestamp_ms()) <= grace_ms {
                    continue;
                }
                let replicas = self.replica_set(&key);
                // A tombstone this node no longer replicates is handed off
                // by phase 1; collecting it here would skip the push.
                if !replicas.iter().any(|n| n == self.local_node_id()) {
                    continue;
                }
                let mut all_confirmed = true;
                for node in &replicas {
                    if node == self.local_node_id() {
                        continue;
                    }
                    match self.fetch_from(node, &key).await {
                        Ok(response) => {
                            if !replica_confirms_tombstone(&record.register, response.as_ref()) {
                                all_confirmed = false;
                            }
                        }
                        // Unreachable replica: defer to a later round.
                        Err(_) => all_confirmed = false,
                    }
                }
                if all_confirmed {
                    match self.shard.remove_exact(&key, &record.register) {
                        Ok(true) => {
                            report.gc_collected += 1;
                            MESH_TOMBSTONE_GC
                                .with_label_values(&[GC_OUTCOME_COLLECTED])
                                .inc();
                        }
                        _ => {
                            report.gc_deferred += 1;
                            MESH_TOMBSTONE_GC
                                .with_label_values(&[GC_OUTCOME_DEFERRED])
                                .inc();
                        }
                    }
                } else {
                    report.gc_deferred += 1;
                    MESH_TOMBSTONE_GC
                        .with_label_values(&[GC_OUTCOME_DEFERRED])
                        .inc();
                }
            }
        }
    }

    /// Spawn the periodic maintenance loop. Holds a [`Weak`] reference so
    /// dropping the store stops the loop; no-op without a tokio runtime
    /// (mirrors `DistributedCache::start_sweeper`).
    pub fn spawn_maintenance(store: &Arc<Self>) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let weak: Weak<Self> = Arc::downgrade(store);
        let period = Duration::from_secs(store.settings.anti_entropy_interval_secs.max(1));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.tick().await;
            loop {
                tick.tick().await;
                match Weak::upgrade(&weak) {
                    Some(state) => {
                        let report = state.maintenance_round().await;
                        if report != MaintenanceReport::default() {
                            tracing::debug!(?report, "replicated maintenance round");
                        }
                    }
                    None => break,
                }
            }
        });
    }
}

/// Whether a peer digest entry is causally ahead of the local register.
fn peer_side_is_newer(entry: &KeyDigest, local: Option<&VersionedLwwRegister>) -> bool {
    let Some(local) = local else {
        return true;
    };
    if entry.logical_version != local.logical_version() {
        return entry.logical_version > local.logical_version();
    }
    // Same version: fetch when the replicas visibly differ, so the
    // deterministic merge can settle the conflict on both sides.
    entry.tombstone != local.is_tombstone()
        || entry.timestamp_ms != local.timestamp_ms()
        || entry.node_id != local.node_id()
}

/// Whether the local register is causally ahead of a peer digest entry.
fn local_side_is_newer(local: &VersionedLwwRegister, entry: &KeyDigest) -> bool {
    if local.logical_version() != entry.logical_version {
        return local.logical_version() > entry.logical_version;
    }
    entry.tombstone != local.is_tombstone()
        || entry.timestamp_ms != local.timestamp_ms()
        || entry.node_id != local.node_id()
}

/// Whether a replica's response proves the tombstone cannot resurrect
/// from it: it either holds the tombstone (or a newer one), has moved on
/// to a causally newer record, or holds nothing at all. `None` after the
/// grace period means the replica either collected the tombstone itself
/// or was repopulated after its own quarantine; in both cases it holds no
/// stale live record to resurrect.
fn replica_confirms_tombstone(
    tombstone: &VersionedLwwRegister,
    response: Option<&VersionedLwwRegister>,
) -> bool {
    match response {
        None => true,
        Some(register) => {
            register.logical_version() > tombstone.logical_version()
                || (register.is_tombstone()
                    && register.logical_version() >= tombstone.logical_version())
        }
    }
}

// Keep the compile-time association with the page bound the shard exports;
// digest requests larger than this are clamped server-side anyway.
const _: () = assert!(SYNC_PAGE_LIMIT <= MAX_DIGEST_PAGE_ENTRIES);

#[cfg(test)]
mod tests {
    use super::*;

    fn live(node: &str, ts: u64, version: u64) -> VersionedLwwRegister {
        VersionedLwwRegister::live("dg".to_string(), node, ts, version, version.checked_sub(1))
    }

    fn tombstone(node: &str, ts: u64, version: u64) -> VersionedLwwRegister {
        VersionedLwwRegister::tombstone(String::new(), node, ts, version, version.checked_sub(1))
    }

    fn digest_of(register: &VersionedLwwRegister, key: &str) -> KeyDigest {
        KeyDigest {
            key: key.to_string(),
            logical_version: register.logical_version(),
            timestamp_ms: register.timestamp_ms(),
            node_id: register.node_id().to_string(),
            tombstone: register.is_tombstone(),
        }
    }

    #[test]
    fn peer_newer_when_local_missing_or_version_behind() {
        let remote = live("node-b", 2_000, 5);
        let entry = digest_of(&remote, "k");
        assert!(peer_side_is_newer(&entry, None));
        assert!(peer_side_is_newer(&entry, Some(&live("node-a", 1_000, 4))));
        assert!(!peer_side_is_newer(&entry, Some(&live("node-a", 1_000, 6))));
        assert!(!peer_side_is_newer(&entry, Some(&remote)));
    }

    #[test]
    fn equal_version_divergence_triggers_sync_both_ways() {
        let local = live("node-a", 1_000, 5);
        let remote = live("node-b", 1_000, 5);
        let entry = digest_of(&remote, "k");
        assert!(peer_side_is_newer(&entry, Some(&local)));
        assert!(local_side_is_newer(&local, &entry));
    }

    #[test]
    fn tombstone_confirmation_covers_all_safe_shapes() {
        let stone = tombstone("node-a", 1_000, 6);
        // The replica holds the tombstone itself.
        assert!(replica_confirms_tombstone(&stone, Some(&stone)));
        // The replica holds a newer tombstone.
        assert!(replica_confirms_tombstone(
            &stone,
            Some(&tombstone("node-b", 2_000, 7))
        ));
        // The key was legitimately re-created at a higher version.
        assert!(replica_confirms_tombstone(
            &stone,
            Some(&live("node-b", 2_000, 7))
        ));
        // The replica already collected it.
        assert!(replica_confirms_tombstone(&stone, None));
        // A stale live record blocks collection.
        assert!(!replica_confirms_tombstone(
            &stone,
            Some(&live("node-b", 500, 5))
        ));
        // An older tombstone blocks collection too: the replica has not
        // yet seen this deletion.
        assert!(!replica_confirms_tombstone(
            &stone,
            Some(&tombstone("node-b", 500, 5))
        ));
    }
}
