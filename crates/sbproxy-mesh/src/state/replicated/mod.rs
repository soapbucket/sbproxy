//! Replicated, durable state substrate for the mesh (WOR-1947).
//!
//! The legacy [`crate::state::distributed_cache::DistributedCache`] routes
//! every key to exactly one owner and keeps everything in memory: an owner
//! restart loses data, a delete reaches only the current owner, and there
//! is no repair after a partition. This module adds the guarantees that
//! make shared mesh state safe for canonical, sensitive records:
//!
//! * A configurable replication factor with explicit read/write
//!   consistency levels ([`Consistency`]).
//! * A durable local shard per node ([`shard::ReplicaShard`]), so an
//!   acknowledged write survives the owner's restart.
//! * Idempotent write receipts ([`WriteReceipt`]): retrying an ambiguous
//!   write re-sends the identical versioned record, which the causal merge
//!   collapses to a no-op.
//! * Anti-entropy, read repair, ownership handoff, and acknowledgement-aware
//!   tombstone GC (see [`maintenance`]).
//!
//! The write and read paths fan out across the key's ring preference list
//! (see `ConsistentHashRing::get_nodes`) and count acknowledgements against
//! the configured consistency level. Reads reconcile divergent replicas
//! with the causal merge and repair stale ones in-line.
//!
//! The AI compression session store selects this substrate through
//! `compression.state.backend: mesh`; that adapter builds conditional
//! writes from [`ReplicatedStore::get_versioned`] and
//! [`ReplicatedStore::put_versioned`] and documents its consistency
//! contract in `docs/ai-context-compression.md`.

pub mod admin;
pub mod maintenance;
pub mod shard;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::state::distributed_cache::DistributedCache;
use crate::state::register::{VersionedLwwMergeOutcome, VersionedLwwRegister};
use crate::transport::TransportClientPool;

pub use shard::{MeshClock, ReplicaShard, ShardError, ShardLimits};

/// Per-operation transport timeout for replica fan-out calls. The client
/// pool has no deadline of its own, so the coordinator bounds every remote
/// apply/fetch to keep a wedged peer from stalling a quorum decision.
const REPLICA_OP_TIMEOUT: Duration = Duration::from_secs(2);

/// How many acknowledgements an operation needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Consistency {
    /// One replica (the coordinator's own shard counts).
    One,
    /// A majority of the key's effective replica set.
    Quorum,
    /// Every replica in the key's effective replica set.
    All,
}

impl Consistency {
    /// Acknowledgements required against an effective replica count.
    pub fn required(self, replicas: usize) -> usize {
        match self {
            Consistency::One => 1,
            Consistency::Quorum => replicas / 2 + 1,
            Consistency::All => replicas.max(1),
        }
    }
}

/// Tunables for the replicated substrate.
#[derive(Debug, Clone)]
pub struct ReplicationSettings {
    /// Desired copies per key. Clamped to cluster size at placement time;
    /// a smaller cluster runs degraded rather than unavailable.
    pub replication_factor: usize,
    /// Acknowledgements required before a write reports success.
    pub write_consistency: Consistency,
    /// Replicas consulted before a read reports its winner.
    pub read_consistency: Consistency,
    /// Cadence of the maintenance loop (anti-entropy, handoff, GC).
    pub anti_entropy_interval_secs: u64,
    /// Age a tombstone must reach, with every replica confirming, before
    /// it is physically collected. Also the long-absence quarantine bound.
    pub tombstone_gc_grace_secs: u64,
}

impl Default for ReplicationSettings {
    fn default() -> Self {
        Self {
            replication_factor: 2,
            write_consistency: Consistency::Quorum,
            read_consistency: Consistency::Quorum,
            anti_entropy_interval_secs: 30,
            tombstone_gc_grace_secs: 86_400,
        }
    }
}

/// Errors surfaced by replicated reads and writes.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// This node is currently isolated from the mesh; state operations
    /// fail fast instead of pretending a quorum is reachable.
    #[error("node is isolated from the mesh")]
    Isolated,
    /// Fewer replicas acknowledged than the consistency level requires.
    /// The write may have been applied on some replicas; retry with the
    /// receipt for an idempotent outcome.
    #[error("replication quorum failed: {acked}/{required} acks")]
    QuorumFailed {
        /// Replicas that acknowledged.
        acked: usize,
        /// Acknowledgements the consistency level required.
        required: usize,
    },
    /// The local shard rejected the record (capacity, size, storage).
    #[error(transparent)]
    Shard(#[from] ShardError),
    /// The ring has no members, so there is nowhere to place the record.
    #[error("no mesh members available for placement")]
    NoMembers,
    /// The stored register could not be decoded.
    #[error("invalid replicated record encoding")]
    InvalidRecord,
}

/// The full identity of an applied write. Serializable so a caller whose
/// response was lost can retry the exact same record: replicas collapse
/// the duplicate to `Unchanged` (WOR-1947 AC6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteReceipt {
    /// Replicated record key.
    pub key: String,
    /// The exact versioned register that was fanned out.
    pub register: VersionedLwwRegister,
    /// TTL the write carried.
    pub ttl_secs: u64,
    /// Replicas that acknowledged during the original attempt.
    pub acked: usize,
}

/// Outcome of a replicated read: the winning value plus how many replicas
/// answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOutcome {
    /// Decoded application value; `None` for missing or deleted keys.
    pub value: Option<Bytes>,
    /// Replicas that answered the read.
    pub responses: usize,
    /// Stale replicas repaired in-line by this read.
    pub repaired: usize,
}

/// Outcome of a replicated read that also surfaces the winning register's
/// metadata (logical version, writer, tombstone and conflict flags).
/// Adapters that build conditional writes on top of the causal merge need
/// this to establish the version they are extending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedReadOutcome {
    /// The reconciled winning register; `None` when no replica holds the
    /// key at all.
    pub register: Option<VersionedLwwRegister>,
    /// Decoded application value; `None` for missing or deleted keys.
    pub value: Option<Bytes>,
    /// Replicas that answered the read.
    pub responses: usize,
    /// Stale replicas repaired in-line by this read.
    pub repaired: usize,
}

/// Callback resolving a node ID to its transport address.
pub type PeerAddrFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;
/// Callback reporting whether this node is currently isolated.
pub type IsolationFn = Arc<dyn Fn() -> bool + Send + Sync>;

/// Coordinator for replicated reads, writes, deletes, and maintenance.
///
/// Shares the consistent-hash ring with the legacy cache (via
/// [`DistributedCache`]) so replica placement always agrees with the
/// membership view the gossip loop maintains.
pub struct ReplicatedStore {
    pub(crate) shard: Arc<ReplicaShard>,
    pub(crate) cache: Arc<DistributedCache<Bytes>>,
    pub(crate) pool: Arc<TransportClientPool>,
    pub(crate) peer_addr: PeerAddrFn,
    pub(crate) is_isolated: IsolationFn,
    pub(crate) settings: ReplicationSettings,
    pub(crate) clock: MeshClock,
    local_node_id: String,
}

impl ReplicatedStore {
    /// Build a store around an existing shard, ring view, and client pool.
    pub fn new(
        shard: Arc<ReplicaShard>,
        cache: Arc<DistributedCache<Bytes>>,
        pool: Arc<TransportClientPool>,
        peer_addr: PeerAddrFn,
        is_isolated: IsolationFn,
        settings: ReplicationSettings,
    ) -> Self {
        let clock = shard.clock();
        let local_node_id = cache.local_node_id().to_string();
        Self {
            shard,
            cache,
            pool,
            peer_addr,
            is_isolated,
            settings,
            clock,
            local_node_id,
        }
    }

    /// The local durable shard (transport dispatch applies records here).
    pub fn shard(&self) -> Arc<ReplicaShard> {
        self.shard.clone()
    }

    /// This node's stable identifier.
    pub fn local_node_id(&self) -> &str {
        &self.local_node_id
    }

    /// The effective settings.
    pub fn settings(&self) -> &ReplicationSettings {
        &self.settings
    }

    /// The key's current replica set: the first `replication_factor`
    /// distinct ring members. Shorter than the factor when the cluster is
    /// smaller; empty only when the ring is empty.
    pub fn replica_set(&self, key: &str) -> Vec<String> {
        self.cache
            .preference_nodes(key, self.settings.replication_factor.max(1))
    }

    /// Write `value` under `key`, replicated and durable.
    ///
    /// Reads the current version from reachable replicas first so the new
    /// record extends the key's causal history, then fans the record out
    /// and waits for the configured write consistency.
    pub async fn put(
        &self,
        key: &str,
        value: &[u8],
        ttl_secs: u64,
    ) -> Result<WriteReceipt, StateError> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(value);
        self.write_register(key, encoded, ttl_secs, false).await
    }

    /// Delete `key` by replicating a tombstone through the same quorum
    /// path as writes. The tombstone is collected only by ack-aware GC.
    pub async fn delete(&self, key: &str) -> Result<WriteReceipt, StateError> {
        self.write_register(key, String::new(), 0, true).await
    }

    /// Retry a write whose response was lost, by re-sending the identical
    /// record from its receipt. Safe to call any number of times.
    pub async fn apply_receipt(&self, receipt: &WriteReceipt) -> Result<WriteReceipt, StateError> {
        self.fan_out(&receipt.key, receipt.register.clone(), receipt.ttl_secs)
            .await
    }

    /// Write `value` under `key` at an explicit logical version, extending
    /// a version the caller has already observed through
    /// [`Self::get_versioned`]. This is the conditional-write building
    /// block for adapters that need compare-and-set semantics on top of
    /// the causal merge: a replica already holding a higher version fences
    /// the record out, and a concurrent writer claiming the same version
    /// resolves through the deterministic LWW order, which the loser
    /// detects by reading back. The fan-out itself acknowledges applies,
    /// not victories, so callers verify the winner with a follow-up
    /// [`Self::get_versioned`].
    pub async fn put_versioned(
        &self,
        key: &str,
        value: &[u8],
        ttl_secs: u64,
        logical_version: u64,
        parent_logical_version: Option<u64>,
    ) -> Result<WriteReceipt, StateError> {
        if (self.is_isolated)() && self.settings.write_consistency != Consistency::One {
            return Err(StateError::Isolated);
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(value);
        let register = VersionedLwwRegister::live(
            encoded,
            &self.local_node_id,
            (self.clock)(),
            logical_version,
            parent_logical_version,
        );
        self.fan_out(key, register, ttl_secs).await
    }

    /// Read `key` at the configured read consistency, reconciling replica
    /// divergence with the causal merge and repairing stale replicas.
    pub async fn get(&self, key: &str) -> Result<ReadOutcome, StateError> {
        let outcome = self.get_versioned(key).await?;
        Ok(ReadOutcome {
            value: outcome.value,
            responses: outcome.responses,
            repaired: outcome.repaired,
        })
    }

    /// [`Self::get`] with the winning register's metadata attached, for
    /// adapters that need the version and writer of the reconciled record
    /// rather than just its value.
    pub async fn get_versioned(&self, key: &str) -> Result<VersionedReadOutcome, StateError> {
        if (self.is_isolated)() && self.settings.read_consistency != Consistency::One {
            return Err(StateError::Isolated);
        }
        let replicas = self.replica_set(key);
        if replicas.is_empty() {
            return Err(StateError::NoMembers);
        }
        let required = self.settings.read_consistency.required(replicas.len());

        // Collect records from every replica (local shard answers
        // directly). Bounded fan-out: the replica set is at most the
        // replication factor.
        let mut responses: Vec<(String, Option<shard::StoredRecord>)> = Vec::new();
        for node in &replicas {
            match self.fetch_record_from(node, key).await {
                Ok(record) => responses.push((node.clone(), record)),
                Err(_) => continue,
            }
        }
        if responses.len() < required {
            return Err(StateError::QuorumFailed {
                acked: responses.len(),
                required,
            });
        }

        // Reconcile: causally merge every response into a winner, keeping
        // the winning record's expiry so repair preserves lifetimes.
        let mut winner: Option<VersionedLwwRegister> = None;
        for (_, record) in responses.iter() {
            match (winner.as_mut(), record) {
                (None, Some(r)) => winner = Some(r.register.clone()),
                (Some(w), Some(r)) => {
                    w.merge_causal(&r.register);
                }
                _ => {}
            }
        }
        let now = (self.clock)();
        let winner_ttl_secs = winner
            .as_ref()
            .and_then(|w| {
                responses.iter().find_map(|(_, record)| {
                    record
                        .as_ref()
                        .filter(|r| &r.register == w)
                        .map(|r| r.remaining_ttl_secs(now))
                })
            })
            .unwrap_or(0);

        // Read repair: push the winner back to any replica that answered
        // with an older register or no record at all.
        let mut repaired = 0usize;
        if let Some(w) = winner.as_ref() {
            for (node, record) in responses.iter() {
                let stale = match record {
                    None => true,
                    Some(r) => &r.register != w,
                };
                if stale && self.apply_on(node, key, w, winner_ttl_secs).await.is_ok() {
                    repaired += 1;
                    crate::metrics::MESH_REPLICATION_READ_REPAIRS.inc();
                }
            }
        }

        let value = match winner.as_ref() {
            Some(w) if !w.is_tombstone() => {
                let encoded = w.value().unwrap_or_default();
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| StateError::InvalidRecord)?;
                Some(Bytes::from(decoded))
            }
            _ => None,
        };
        Ok(VersionedReadOutcome {
            register: winner,
            value,
            responses: responses.len(),
            repaired,
        })
    }

    // --- Internals shared by put/delete/receipt retries ---

    async fn write_register(
        &self,
        key: &str,
        encoded_value: String,
        ttl_secs: u64,
        tombstone: bool,
    ) -> Result<WriteReceipt, StateError> {
        if (self.is_isolated)() && self.settings.write_consistency != Consistency::One {
            return Err(StateError::Isolated);
        }
        let replicas = self.replica_set(key);
        if replicas.is_empty() {
            return Err(StateError::NoMembers);
        }

        // Establish the causal parent: the highest version any reachable
        // replica currently holds. Best effort by design; two coordinators
        // racing to the same version resolve through the deterministic
        // LWW order and flag the conflict on the surviving record.
        let mut current_version: Option<u64> = None;
        for node in &replicas {
            if let Ok(Some(register)) = self.fetch_from(node, key).await {
                current_version =
                    Some(current_version.unwrap_or(0).max(register.logical_version()));
            }
        }
        let next_version = current_version.unwrap_or(0) + 1;
        let now = (self.clock)();
        let register = if tombstone {
            VersionedLwwRegister::tombstone(
                String::new(),
                &self.local_node_id,
                now,
                next_version,
                current_version,
            )
        } else {
            VersionedLwwRegister::live(
                encoded_value,
                &self.local_node_id,
                now,
                next_version,
                current_version,
            )
        };
        self.fan_out(key, register, ttl_secs).await
    }

    async fn fan_out(
        &self,
        key: &str,
        register: VersionedLwwRegister,
        ttl_secs: u64,
    ) -> Result<WriteReceipt, StateError> {
        let replicas = self.replica_set(key);
        if replicas.is_empty() {
            return Err(StateError::NoMembers);
        }
        let required = self.settings.write_consistency.required(replicas.len());

        let mut acked = 0usize;
        let mut local_error: Option<StateError> = None;
        for node in &replicas {
            match self.apply_on(node, key, &register, ttl_secs).await {
                Ok(_) => acked += 1,
                Err(err) => {
                    // A local shard rejection (capacity, size) is a hard
                    // failure the caller must see even if remote replicas
                    // would have acked.
                    if node == &self.local_node_id {
                        local_error = Some(err);
                    }
                }
            }
        }
        if let Some(err) = local_error {
            if matches!(
                err,
                StateError::Shard(ShardError::Capacity | ShardError::TooLarge)
            ) {
                return Err(err);
            }
        }
        if acked < required {
            crate::metrics::MESH_REPLICATION_WRITES
                .with_label_values(&[crate::metrics::REPLICATION_OUTCOME_QUORUM_FAILED])
                .inc();
            return Err(StateError::QuorumFailed { acked, required });
        }
        crate::metrics::MESH_REPLICATION_WRITES
            .with_label_values(&[crate::metrics::REPLICATION_OUTCOME_ACKED])
            .inc();
        Ok(WriteReceipt {
            key: key.to_string(),
            register,
            ttl_secs,
            acked,
        })
    }

    /// Apply a register on one replica (local shard or remote peer).
    pub(crate) async fn apply_on(
        &self,
        node: &str,
        key: &str,
        register: &VersionedLwwRegister,
        ttl_secs: u64,
    ) -> Result<VersionedLwwMergeOutcome, StateError> {
        if node == self.local_node_id {
            return Ok(self.shard.apply(key, register, ttl_secs)?);
        }
        let encoded = serde_json::to_vec(register).map_err(|_| StateError::InvalidRecord)?;
        let client = self.client_for(node).ok_or(StateError::QuorumFailed {
            acked: 0,
            required: 1,
        })?;
        let result = tokio::time::timeout(
            REPLICA_OP_TIMEOUT,
            client.replica_apply(key.to_string(), Bytes::from(encoded), ttl_secs),
        )
        .await;
        match result {
            Ok(Ok(outcome)) => Ok(outcome),
            _ => Err(StateError::QuorumFailed {
                acked: 0,
                required: 1,
            }),
        }
    }

    /// Fetch the full stored record (register plus expiry) from one
    /// replica.
    pub(crate) async fn fetch_record_from(
        &self,
        node: &str,
        key: &str,
    ) -> Result<Option<shard::StoredRecord>, StateError> {
        if node == self.local_node_id {
            return Ok(self.shard.fetch_record(key));
        }
        let client = self.client_for(node).ok_or(StateError::QuorumFailed {
            acked: 0,
            required: 1,
        })?;
        let result =
            tokio::time::timeout(REPLICA_OP_TIMEOUT, client.replica_fetch(key.to_string())).await;
        match result {
            Ok(Ok(Some(bytes))) => serde_json::from_slice::<shard::StoredRecord>(&bytes)
                .map(Some)
                .map_err(|_| StateError::InvalidRecord),
            Ok(Ok(None)) => Ok(None),
            _ => Err(StateError::QuorumFailed {
                acked: 0,
                required: 1,
            }),
        }
    }

    /// Fetch just the stored register from one replica.
    pub(crate) async fn fetch_from(
        &self,
        node: &str,
        key: &str,
    ) -> Result<Option<VersionedLwwRegister>, StateError> {
        Ok(self
            .fetch_record_from(node, key)
            .await?
            .map(|record| record.register))
    }

    pub(crate) fn client_for(&self, node: &str) -> Option<Arc<crate::transport::PeerClient>> {
        let addr = (self.peer_addr)(node)?;
        self.pool.try_client_for_node(node, &addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistency_required_counts() {
        assert_eq!(Consistency::One.required(3), 1);
        assert_eq!(Consistency::Quorum.required(1), 1);
        assert_eq!(Consistency::Quorum.required(2), 2);
        assert_eq!(Consistency::Quorum.required(3), 2);
        assert_eq!(Consistency::All.required(3), 3);
        // Degenerate cluster sizes never require zero acks.
        assert_eq!(Consistency::One.required(0), 1);
        assert_eq!(Consistency::All.required(0), 1);
    }

    #[test]
    fn write_receipt_round_trips_through_serde() {
        let receipt = WriteReceipt {
            key: "k".to_string(),
            register: VersionedLwwRegister::live("dg".to_string(), "node-a", 1_000, 3, Some(2)),
            ttl_secs: 60,
            acked: 2,
        };
        let encoded = serde_json::to_vec(&receipt).unwrap();
        let decoded: WriteReceipt = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, receipt);
    }
}
