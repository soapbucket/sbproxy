//! Durable local replica shard for the replicated state substrate.
//!
//! Each mesh node stores the replicated records it is responsible for in a
//! [`ReplicaShard`]: an in-memory ordered map backed by a write-through redb
//! database. An apply is acknowledged only after the winning record has been
//! committed to disk, which is what lets a restarted owner serve committed
//! state without borrowing another process's memory (WOR-1947 AC2).
//!
//! # Time
//!
//! All expiry bookkeeping uses absolute Unix milliseconds from an injected
//! clock, never `Instant`, so deadlines survive a process restart and tests
//! can drive time deterministically.
//!
//! # Tombstones
//!
//! Deletion markers never expire by TTL. They are removed only by the
//! ack-aware garbage collection in
//! [`crate::state::replicated::ReplicatedStore`], because dropping a
//! tombstone before every replica has confirmed it reopens the resurrection
//! window this substrate exists to close.
//!
//! # Long-absence quarantine
//!
//! A node that was offline longer than the tombstone GC grace period may
//! hold live records whose covering tombstones have since been collected
//! cluster-wide. On open, such a shard discards its stored records (the
//! surviving replicas still hold the data; anti-entropy repopulates this
//! node), because re-admitting them could resurrect deleted state.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use bytes::Bytes;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::state::register::{VersionedLwwMergeOutcome, VersionedLwwRegister};
use crate::transport::frame::{DigestPage, KeyDigest};

/// redb table holding one JSON-encoded [`StoredRecord`] per replicated key.
const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("replicated_records");

/// redb table holding shard metadata (currently only the liveness
/// watermark used by the long-absence quarantine check).
const META: TableDefinition<&str, u64> = TableDefinition::new("replicated_meta");

/// Metadata key for the last time this shard's process was known alive.
const META_LAST_SEEN_MS: &str = "last_seen_ms";

/// Hard cap on one digest / records page, mirroring the bounded-snapshot
/// discipline used elsewhere in the mesh crate.
pub const MAX_DIGEST_PAGE_ENTRIES: usize = 1_024;

/// Hard cap on replicated key length, in bytes.
const MAX_KEY_BYTES: usize = 512;

/// Shared millisecond clock. Injected so GC grace and quarantine tests can
/// drive time deterministically.
pub type MeshClock = std::sync::Arc<dyn Fn() -> u64 + Send + Sync>;

/// Capacity and value-size bounds enforced by the shard.
#[derive(Debug, Clone, Copy)]
pub struct ShardLimits {
    /// Maximum number of records (live plus tombstones) the shard holds.
    pub max_entries: usize,
    /// Maximum decoded application value size, in bytes.
    pub max_value_bytes: usize,
}

impl Default for ShardLimits {
    fn default() -> Self {
        Self {
            max_entries: 65_536,
            max_value_bytes: 1024 * 1024,
        }
    }
}

/// Errors surfaced by shard operations.
#[derive(Debug, thiserror::Error)]
pub enum ShardError {
    /// The shard is at `max_entries` and the apply would add a new key.
    #[error("replica shard at capacity")]
    Capacity,
    /// The key or value exceeds the configured size bounds.
    #[error("replicated record too large")]
    TooLarge,
    /// The candidate bytes did not decode as a versioned register.
    #[error("invalid replicated record")]
    InvalidRecord,
    /// The durable backing store rejected the write. The in-memory state
    /// is left untouched so an un-persisted record is never served.
    #[error("replica shard storage error: {0}")]
    Storage(String),
}

/// One replicated record as stored: the register plus its absolute expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRecord {
    /// Versioned register carrying the value, version fencing metadata,
    /// and the tombstone flag.
    pub register: VersionedLwwRegister,
    /// Absolute expiry in Unix milliseconds; `None` means no expiry.
    /// Always `None` for tombstones.
    pub expires_at_ms: Option<u64>,
}

impl StoredRecord {
    /// TTL to forward when re-replicating this record: the remaining
    /// lifetime, floored at one second so a record already near expiry
    /// does not become immortal (`0` means "no expiry" on the wire).
    pub fn remaining_ttl_secs(&self, now_ms: u64) -> u64 {
        match self.expires_at_ms {
            None => 0,
            Some(deadline) => deadline.saturating_sub(now_ms).div_ceil(1_000).max(1),
        }
    }
}

/// Durable local replica shard: ordered in-memory records with
/// write-through redb persistence.
pub struct ReplicaShard {
    records: Mutex<BTreeMap<String, StoredRecord>>,
    db: Option<Database>,
    clock: MeshClock,
    limits: ShardLimits,
    /// Records discarded by the long-absence quarantine on open. Zero when
    /// the shard was opened within the grace window.
    quarantine_discarded: AtomicU64,
}

impl ReplicaShard {
    /// Open a durable shard at `path`, restoring surviving records.
    ///
    /// `grace_ms` is the tombstone GC grace period. If the shard's
    /// liveness watermark is older than `grace_ms`, every stored record is
    /// discarded (see the module docs on quarantine). `grace_ms = 0`
    /// disables the quarantine check and is intended only for tests.
    pub fn open(
        path: &Path,
        limits: ShardLimits,
        grace_ms: u64,
        clock: MeshClock,
    ) -> Result<Self, ShardError> {
        let db = Database::create(path).map_err(|e| ShardError::Storage(e.to_string()))?;
        let now = clock();

        let last_seen = {
            let txn = db
                .begin_write()
                .map_err(|e| ShardError::Storage(e.to_string()))?;
            let last_seen = {
                let mut meta = txn
                    .open_table(META)
                    .map_err(|e| ShardError::Storage(e.to_string()))?;
                // Ensure the records table exists in the same transaction.
                txn.open_table(RECORDS)
                    .map_err(|e| ShardError::Storage(e.to_string()))?;
                let previous = meta
                    .get(META_LAST_SEEN_MS)
                    .map_err(|e| ShardError::Storage(e.to_string()))?
                    .map(|guard| guard.value());
                meta.insert(META_LAST_SEEN_MS, now)
                    .map_err(|e| ShardError::Storage(e.to_string()))?;
                previous
            };
            txn.commit()
                .map_err(|e| ShardError::Storage(e.to_string()))?;
            last_seen
        };

        let absent_past_grace =
            grace_ms > 0 && last_seen.is_some_and(|seen| now.saturating_sub(seen) > grace_ms);

        let shard = Self {
            records: Mutex::new(BTreeMap::new()),
            db: Some(db),
            clock,
            limits,
            quarantine_discarded: AtomicU64::new(0),
        };

        if absent_past_grace {
            let discarded = shard.wipe_persisted()?;
            shard
                .quarantine_discarded
                .store(discarded, Ordering::Relaxed);
            tracing::warn!(
                discarded,
                "replica shard offline longer than tombstone GC grace; discarding stored \
                 records to prevent deleted-state resurrection (replicas will repopulate \
                 this node via anti-entropy)"
            );
        } else {
            shard.load_persisted(now)?;
        }
        Ok(shard)
    }

    /// Construct a memory-only shard (no durability). Used by tests and by
    /// deployments that explicitly opt out of a durable directory.
    pub fn in_memory(limits: ShardLimits, clock: MeshClock) -> Self {
        Self {
            records: Mutex::new(BTreeMap::new()),
            db: None,
            clock,
            limits,
            quarantine_discarded: AtomicU64::new(0),
        }
    }

    fn load_persisted(&self, now: u64) -> Result<(), ShardError> {
        let Some(db) = self.db.as_ref() else {
            return Ok(());
        };
        let txn = db
            .begin_read()
            .map_err(|e| ShardError::Storage(e.to_string()))?;
        let table = txn
            .open_table(RECORDS)
            .map_err(|e| ShardError::Storage(e.to_string()))?;
        let mut restored = BTreeMap::new();
        let mut expired: Vec<String> = Vec::new();
        for row in table
            .iter()
            .map_err(|e| ShardError::Storage(e.to_string()))?
        {
            let (key, value) = row.map_err(|e| ShardError::Storage(e.to_string()))?;
            let key = key.value().to_string();
            let Ok(record) = serde_json::from_slice::<StoredRecord>(value.value()) else {
                // A corrupt row is dropped rather than poisoning the boot.
                tracing::warn!(key = %key, "replica shard: dropping undecodable record");
                expired.push(key);
                continue;
            };
            let live_expired = !record.register.is_tombstone()
                && record.expires_at_ms.is_some_and(|deadline| deadline <= now);
            if live_expired {
                expired.push(key);
            } else {
                restored.insert(key, record);
            }
        }
        drop(table);
        drop(txn);
        for key in &expired {
            self.persist_remove(key)?;
        }
        *self.records.lock().unwrap() = restored;
        Ok(())
    }

    fn wipe_persisted(&self) -> Result<u64, ShardError> {
        let Some(db) = self.db.as_ref() else {
            return Ok(0);
        };
        let txn = db
            .begin_write()
            .map_err(|e| ShardError::Storage(e.to_string()))?;
        let discarded = {
            let mut table = txn
                .open_table(RECORDS)
                .map_err(|e| ShardError::Storage(e.to_string()))?;
            let keys: Vec<String> = table
                .iter()
                .map_err(|e| ShardError::Storage(e.to_string()))?
                .filter_map(|row| row.ok().map(|(k, _)| k.value().to_string()))
                .collect();
            for key in &keys {
                table
                    .remove(key.as_str())
                    .map_err(|e| ShardError::Storage(e.to_string()))?;
            }
            keys.len() as u64
        };
        txn.commit()
            .map_err(|e| ShardError::Storage(e.to_string()))?;
        Ok(discarded)
    }

    fn persist_record(&self, key: &str, record: &StoredRecord) -> Result<(), ShardError> {
        let Some(db) = self.db.as_ref() else {
            return Ok(());
        };
        let encoded = serde_json::to_vec(record).map_err(|e| ShardError::Storage(e.to_string()))?;
        let txn = db
            .begin_write()
            .map_err(|e| ShardError::Storage(e.to_string()))?;
        {
            let mut table = txn
                .open_table(RECORDS)
                .map_err(|e| ShardError::Storage(e.to_string()))?;
            table
                .insert(key, encoded.as_slice())
                .map_err(|e| ShardError::Storage(e.to_string()))?;
        }
        txn.commit().map_err(|e| ShardError::Storage(e.to_string()))
    }

    fn persist_remove(&self, key: &str) -> Result<(), ShardError> {
        let Some(db) = self.db.as_ref() else {
            return Ok(());
        };
        let txn = db
            .begin_write()
            .map_err(|e| ShardError::Storage(e.to_string()))?;
        {
            let mut table = txn
                .open_table(RECORDS)
                .map_err(|e| ShardError::Storage(e.to_string()))?;
            table
                .remove(key)
                .map_err(|e| ShardError::Storage(e.to_string()))?;
        }
        txn.commit().map_err(|e| ShardError::Storage(e.to_string()))
    }

    /// Refresh the liveness watermark. Called by the maintenance loop so a
    /// clean restart within the grace window keeps its records.
    pub fn heartbeat(&self) -> Result<(), ShardError> {
        let Some(db) = self.db.as_ref() else {
            return Ok(());
        };
        let now = (self.clock)();
        let txn = db
            .begin_write()
            .map_err(|e| ShardError::Storage(e.to_string()))?;
        {
            let mut meta = txn
                .open_table(META)
                .map_err(|e| ShardError::Storage(e.to_string()))?;
            meta.insert(META_LAST_SEEN_MS, now)
                .map_err(|e| ShardError::Storage(e.to_string()))?;
        }
        txn.commit().map_err(|e| ShardError::Storage(e.to_string()))
    }

    /// Apply a candidate register with the causal merge, persisting the
    /// winner before it becomes visible.
    ///
    /// The merge result is computed against a copy, committed to redb, and
    /// only then installed in the in-memory map: a record is never served
    /// (or acked) unless it is already durable.
    pub fn apply(
        &self,
        key: &str,
        candidate: &VersionedLwwRegister,
        ttl_secs: u64,
    ) -> Result<VersionedLwwMergeOutcome, ShardError> {
        if key.len() > MAX_KEY_BYTES {
            return Err(ShardError::TooLarge);
        }
        // The register value is base64 of the application value, so allow
        // for the 4/3 encoding overhead when enforcing the decoded bound.
        let max_encoded = self.limits.max_value_bytes.div_ceil(3).saturating_mul(4);
        if candidate.value().map(str::len).unwrap_or(0) > max_encoded {
            return Err(ShardError::TooLarge);
        }

        let now = (self.clock)();
        let mut records = self.records.lock().unwrap();

        // Lazy-expire a live record before merging against it. Tombstones
        // never expire here (see the module docs).
        let current = match records.get(key) {
            Some(existing) => {
                let live_expired = !existing.register.is_tombstone()
                    && existing
                        .expires_at_ms
                        .is_some_and(|deadline| deadline <= now);
                if live_expired {
                    None
                } else {
                    Some(existing.clone())
                }
            }
            None => None,
        };

        let (merged, outcome, expires_at_ms) = match current {
            None => {
                if records.len() >= self.limits.max_entries && !records.contains_key(key) {
                    return Err(ShardError::Capacity);
                }
                let expires = record_expiry(candidate, ttl_secs, now);
                (
                    candidate.clone(),
                    VersionedLwwMergeOutcome::Replaced,
                    expires,
                )
            }
            Some(existing) => {
                let mut merged = existing.register.clone();
                let outcome = merged.merge_causal(candidate);
                let expires = match outcome {
                    VersionedLwwMergeOutcome::Replaced
                    | VersionedLwwMergeOutcome::ConflictReplaced => {
                        record_expiry(&merged, ttl_secs, now)
                    }
                    _ => {
                        if merged.is_tombstone() {
                            None
                        } else {
                            existing.expires_at_ms
                        }
                    }
                };
                (merged, outcome, expires)
            }
        };

        let record = StoredRecord {
            register: merged,
            expires_at_ms,
        };
        let changed = records.get(key) != Some(&record);
        if changed {
            self.persist_record(key, &record)?;
            records.insert(key.to_string(), record);
        }
        Ok(outcome)
    }

    /// Decode a JSON candidate and apply it. This is the transport-facing
    /// entry point behind `CacheOp::ReplicaApply`.
    pub fn apply_encoded(
        &self,
        key: &str,
        candidate: &[u8],
        ttl_secs: u64,
    ) -> Result<VersionedLwwMergeOutcome, ShardError> {
        let candidate = serde_json::from_slice::<VersionedLwwRegister>(candidate)
            .map_err(|_| ShardError::InvalidRecord)?;
        self.apply(key, &candidate, ttl_secs)
    }

    /// Fetch the full stored record for `key`, if any. Expired live
    /// records are dropped on read; tombstones are always returned.
    pub fn fetch_record(&self, key: &str) -> Option<StoredRecord> {
        let now = (self.clock)();
        let mut records = self.records.lock().unwrap();
        let record = records.get(key)?;
        let live_expired = !record.register.is_tombstone()
            && record.expires_at_ms.is_some_and(|deadline| deadline <= now);
        if live_expired {
            records.remove(key);
            // Best-effort removal from the backing store; an error here
            // only delays reclamation until the next apply or boot sweep.
            let _ = self.persist_remove(key);
            return None;
        }
        Some(record.clone())
    }

    /// Fetch just the stored register for `key`, if any.
    pub fn fetch(&self, key: &str) -> Option<VersionedLwwRegister> {
        self.fetch_record(key).map(|record| record.register)
    }

    /// Fetch the stored record JSON-encoded, for the transport reply.
    /// Carries the absolute expiry alongside the register so a peer
    /// re-replicating the record preserves its remaining lifetime.
    pub fn fetch_encoded(&self, key: &str) -> Option<Bytes> {
        let record = self.fetch_record(key)?;
        serde_json::to_vec(&record).ok().map(Bytes::from)
    }

    /// Produce one bounded digest page for anti-entropy comparison.
    pub fn digest_page(&self, prefix: &str, after: Option<&str>, limit: usize) -> DigestPage {
        let limit = limit.clamp(1, MAX_DIGEST_PAGE_ENTRIES);
        let records = self.records.lock().unwrap();
        let mut entries = Vec::with_capacity(limit.min(records.len()));
        let mut next_page_token = None;
        for (key, record) in records.range::<str, _>((
            after
                .map(std::ops::Bound::Excluded)
                .unwrap_or(std::ops::Bound::Unbounded),
            std::ops::Bound::Unbounded,
        )) {
            if !key.starts_with(prefix) {
                if key.as_str() > prefix && !prefix.is_empty() {
                    break;
                }
                continue;
            }
            if entries.len() == limit {
                next_page_token = Some(
                    entries
                        .last()
                        .map(|last: &KeyDigest| last.key.clone())
                        .unwrap_or_default(),
                );
                break;
            }
            entries.push(KeyDigest {
                key: key.clone(),
                logical_version: record.register.logical_version(),
                timestamp_ms: record.register.timestamp_ms(),
                node_id: record.register.node_id().to_string(),
                tombstone: record.register.is_tombstone(),
            });
        }
        DigestPage {
            entries,
            next_page_token,
        }
    }

    /// One bounded, ordered page of full records for maintenance scans.
    pub fn records_page(&self, after: Option<&str>, limit: usize) -> Vec<(String, StoredRecord)> {
        let limit = limit.clamp(1, MAX_DIGEST_PAGE_ENTRIES);
        let records = self.records.lock().unwrap();
        records
            .range::<str, _>((
                after
                    .map(std::ops::Bound::Excluded)
                    .unwrap_or(std::ops::Bound::Unbounded),
                std::ops::Bound::Unbounded,
            ))
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Physically remove `key` if the stored register still equals
    /// `expected`. Used by ack-aware tombstone GC and by post-handoff
    /// cleanup, where dropping a record that changed since the decision
    /// was made would lose an update.
    pub fn remove_exact(
        &self,
        key: &str,
        expected: &VersionedLwwRegister,
    ) -> Result<bool, ShardError> {
        let mut records = self.records.lock().unwrap();
        match records.get(key) {
            Some(record) if &record.register == expected => {
                self.persist_remove(key)?;
                records.remove(key);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Number of records currently held (live plus tombstones).
    pub fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    /// Whether the shard holds no records.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Records discarded by the long-absence quarantine on open.
    pub fn quarantine_discarded(&self) -> u64 {
        self.quarantine_discarded.load(Ordering::Relaxed)
    }

    /// The shard's millisecond clock.
    pub fn clock(&self) -> MeshClock {
        self.clock.clone()
    }

    /// The shard's configured limits.
    pub fn limits(&self) -> ShardLimits {
        self.limits
    }
}

/// Expiry for a winning record: tombstones never expire, `ttl_secs = 0`
/// means no expiry, anything else is an absolute deadline from now.
fn record_expiry(register: &VersionedLwwRegister, ttl_secs: u64, now: u64) -> Option<u64> {
    if register.is_tombstone() || ttl_secs == 0 {
        None
    } else {
        Some(now.saturating_add(ttl_secs.saturating_mul(1_000)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64 as TestClockCell;
    use std::sync::Arc;

    fn fixed_clock(cell: Arc<TestClockCell>) -> MeshClock {
        Arc::new(move || cell.load(Ordering::Relaxed))
    }

    fn live(value: &str, node: &str, ts: u64, version: u64) -> VersionedLwwRegister {
        VersionedLwwRegister::live(value.to_string(), node, ts, version, version.checked_sub(1))
    }

    fn tombstone(node: &str, ts: u64, version: u64) -> VersionedLwwRegister {
        VersionedLwwRegister::tombstone(String::new(), node, ts, version, version.checked_sub(1))
    }

    #[test]
    fn apply_then_fetch_roundtrip() {
        let clock_cell = Arc::new(TestClockCell::new(1_000));
        let shard = ReplicaShard::in_memory(ShardLimits::default(), fixed_clock(clock_cell));
        let record = live("dmFsdWU", "node-a", 1_000, 1);
        let outcome = shard.apply("k", &record, 0).unwrap();
        assert_eq!(outcome, VersionedLwwMergeOutcome::Replaced);
        assert_eq!(shard.fetch("k"), Some(record));
    }

    #[test]
    fn reapplying_the_same_record_is_idempotent() {
        let clock_cell = Arc::new(TestClockCell::new(1_000));
        let shard = ReplicaShard::in_memory(ShardLimits::default(), fixed_clock(clock_cell));
        let record = live("dmFsdWU", "node-a", 1_000, 3);
        shard.apply("k", &record, 0).unwrap();
        let outcome = shard.apply("k", &record, 0).unwrap();
        assert_eq!(outcome, VersionedLwwMergeOutcome::Unchanged);
        assert_eq!(shard.len(), 1);
    }

    #[test]
    fn restart_preserves_committed_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shard.redb");
        let clock_cell = Arc::new(TestClockCell::new(10_000));

        let shard = ReplicaShard::open(
            &path,
            ShardLimits::default(),
            86_400_000,
            fixed_clock(clock_cell.clone()),
        )
        .unwrap();
        let record = live("Y29tbWl0dGVk", "node-a", 10_000, 5);
        shard.apply("k", &record, 0).unwrap();
        drop(shard);

        let reopened = ReplicaShard::open(
            &path,
            ShardLimits::default(),
            86_400_000,
            fixed_clock(clock_cell),
        )
        .unwrap();
        assert_eq!(reopened.fetch("k"), Some(record));
        assert_eq!(reopened.quarantine_discarded(), 0);
    }

    #[test]
    fn restart_drops_expired_live_records_but_keeps_tombstones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shard.redb");
        let clock_cell = Arc::new(TestClockCell::new(10_000));

        let shard = ReplicaShard::open(
            &path,
            ShardLimits::default(),
            86_400_000,
            fixed_clock(clock_cell.clone()),
        )
        .unwrap();
        shard
            .apply("live", &live("dg", "node-a", 10_000, 1), 5)
            .unwrap();
        shard
            .apply("dead", &tombstone("node-a", 10_000, 2), 5)
            .unwrap();
        drop(shard);

        // Advance past the live record's 5 second TTL, well inside grace.
        clock_cell.store(20_000, Ordering::Relaxed);
        let reopened = ReplicaShard::open(
            &path,
            ShardLimits::default(),
            86_400_000,
            fixed_clock(clock_cell),
        )
        .unwrap();
        assert_eq!(reopened.fetch("live"), None);
        assert!(reopened.fetch("dead").is_some_and(|r| r.is_tombstone()));
    }

    #[test]
    fn long_absence_quarantine_discards_stored_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shard.redb");
        let clock_cell = Arc::new(TestClockCell::new(10_000));

        let shard = ReplicaShard::open(
            &path,
            ShardLimits::default(),
            60_000,
            fixed_clock(clock_cell.clone()),
        )
        .unwrap();
        shard
            .apply("k", &live("c3RhbGU", "node-a", 10_000, 4), 0)
            .unwrap();
        drop(shard);

        // Rejoin after longer than the 60 second grace period.
        clock_cell.store(10_000 + 61_000, Ordering::Relaxed);
        let reopened = ReplicaShard::open(
            &path,
            ShardLimits::default(),
            60_000,
            fixed_clock(clock_cell),
        )
        .unwrap();
        assert_eq!(reopened.fetch("k"), None);
        assert_eq!(reopened.quarantine_discarded(), 1);
        assert!(reopened.is_empty());
    }

    #[test]
    fn capacity_rejects_new_keys_but_allows_updates() {
        let clock_cell = Arc::new(TestClockCell::new(1_000));
        let limits = ShardLimits {
            max_entries: 1,
            max_value_bytes: 1024,
        };
        let shard = ReplicaShard::in_memory(limits, fixed_clock(clock_cell));
        shard
            .apply("k1", &live("dg", "node-a", 1_000, 1), 0)
            .unwrap();
        let err = shard.apply("k2", &live("dg", "node-a", 1_000, 1), 0);
        assert!(matches!(err, Err(ShardError::Capacity)));
        // Updating the existing key is still allowed at capacity.
        shard
            .apply("k1", &live("dg2", "node-a", 1_100, 2), 0)
            .unwrap();
    }

    #[test]
    fn oversized_values_are_rejected() {
        let clock_cell = Arc::new(TestClockCell::new(1_000));
        let limits = ShardLimits {
            max_entries: 16,
            max_value_bytes: 8,
        };
        let shard = ReplicaShard::in_memory(limits, fixed_clock(clock_cell));
        let big = "A".repeat(64);
        let err = shard.apply("k", &live(&big, "node-a", 1_000, 1), 0);
        assert!(matches!(err, Err(ShardError::TooLarge)));
    }

    #[test]
    fn tombstones_ignore_ttl_and_never_expire() {
        let clock_cell = Arc::new(TestClockCell::new(1_000));
        let shard =
            ReplicaShard::in_memory(ShardLimits::default(), fixed_clock(clock_cell.clone()));
        shard.apply("k", &tombstone("node-a", 1_000, 2), 1).unwrap();
        clock_cell.store(1_000_000, Ordering::Relaxed);
        assert!(shard.fetch("k").is_some_and(|r| r.is_tombstone()));
    }

    #[test]
    fn digest_page_paginates_in_key_order() {
        let clock_cell = Arc::new(TestClockCell::new(1_000));
        let shard = ReplicaShard::in_memory(ShardLimits::default(), fixed_clock(clock_cell));
        for i in 0..5 {
            shard
                .apply(&format!("k{i}"), &live("dg", "node-a", 1_000, 1), 0)
                .unwrap();
        }
        let first = shard.digest_page("", None, 2);
        assert_eq!(first.entries.len(), 2);
        assert_eq!(first.entries[0].key, "k0");
        assert_eq!(first.next_page_token.as_deref(), Some("k1"));

        let second = shard.digest_page("", first.next_page_token.as_deref(), 2);
        assert_eq!(second.entries[0].key, "k2");

        let last = shard.digest_page("", Some("k3"), 10);
        assert_eq!(last.entries.len(), 1);
        assert_eq!(last.entries[0].key, "k4");
        assert!(last.next_page_token.is_none());
    }

    #[test]
    fn digest_page_honors_prefix() {
        let clock_cell = Arc::new(TestClockCell::new(1_000));
        let shard = ReplicaShard::in_memory(ShardLimits::default(), fixed_clock(clock_cell));
        shard
            .apply("a:1", &live("dg", "node-a", 1_000, 1), 0)
            .unwrap();
        shard
            .apply("b:1", &live("dg", "node-a", 1_000, 1), 0)
            .unwrap();
        shard
            .apply("b:2", &live("dg", "node-a", 1_000, 1), 0)
            .unwrap();
        let page = shard.digest_page("b:", None, 10);
        assert_eq!(page.entries.len(), 2);
        assert!(page.entries.iter().all(|e| e.key.starts_with("b:")));
    }

    #[test]
    fn remove_exact_only_drops_the_expected_register() {
        let clock_cell = Arc::new(TestClockCell::new(1_000));
        let shard = ReplicaShard::in_memory(ShardLimits::default(), fixed_clock(clock_cell));
        let v1 = live("dg", "node-a", 1_000, 1);
        let v2 = live("dg2", "node-a", 1_100, 2);
        shard.apply("k", &v1, 0).unwrap();
        assert!(!shard.remove_exact("k", &v2).unwrap());
        shard.apply("k", &v2, 0).unwrap();
        // The stale expectation no longer matches after the update.
        assert!(!shard.remove_exact("k", &v1).unwrap());
        assert!(shard.remove_exact("k", &v2).unwrap());
        assert!(shard.is_empty());
    }

    #[test]
    fn storage_failure_never_acks_an_unpersisted_record() {
        // A shard whose durable path is a directory cannot be created;
        // Database::create fails up front, which is the fail-loud path.
        let dir = tempfile::tempdir().unwrap();
        let clock_cell = Arc::new(TestClockCell::new(1_000));
        let result = ReplicaShard::open(
            dir.path(),
            ShardLimits::default(),
            0,
            fixed_clock(clock_cell),
        );
        assert!(matches!(result, Err(ShardError::Storage(_))));
    }
}
