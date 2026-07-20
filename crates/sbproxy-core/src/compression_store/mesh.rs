//! Replicated mesh compression session store over `ReplicatedStore`.
//!
//! Selected by `compression.state.backend: mesh`. Every session record is a
//! replicated, durable key on the cluster replication substrate
//! (`proxy.cluster.replication`): quorum writes, quorum reads with read
//! repair, anti-entropy after partitions, ownership handoff on rebalance,
//! and acknowledgement-aware tombstone GC.
//!
//! # Consistency contract, relative to Redis
//!
//! The Redis adapter serializes writers with a distributed lease, a
//! monotonic fence, and an atomic compare-and-set executed inside one Lua
//! script. The mesh substrate has no distributed lock, so this adapter
//! keeps the same trait shape with three documented differences:
//!
//! * **Leases are worker-local.** `acquire_update` serializes writers
//!   inside one process only. Writers on different nodes are not blocked
//!   by each other's permits; they are serialized by the version check
//!   below.
//! * **Compare-and-set is conditional-put plus read-back.** `commit`
//!   reads the current replicated version, rejects a stale expectation,
//!   writes the record at exactly `expected + 1`, then reads the key back
//!   at the configured read consistency. If the read-back winner is not
//!   the record that was written, the commit reports
//!   `CommitError::StaleVersion`. Two nodes that race the same parent
//!   version resolve through the deterministic causal LWW merge: exactly
//!   one record survives on every replica, the survivor carries
//!   `conflict_detected`, and the losing writer sees `StaleVersion`. The
//!   check window between read and write is real and is closed by the
//!   read-back verification, not by a lock.
//! * **Deletes are replicated tombstones.** A delete fences stale live
//!   copies on every replica and is physically collected only by the
//!   substrate's ack-aware GC, so deleted sessions do not resurrect after
//!   partitions or restarts. A later commit that has read the tombstone
//!   (so its version extends the tombstone's) legitimately re-creates the
//!   session.
//!
//! Admin listing and purge enumerate the fleet through the replicated
//! substrate's topology-safe fleet pagination (`fleet_state_page`), not a
//! bespoke scan: every record any current member still holds is visible,
//! pages are bounded, and a page token never wedges on a departed node. A
//! key replicated on several holders is deduplicated within one call; one
//! key may still appear in more than one page across calls, exactly like
//! a Redis `SCAN`, and callers collapse by record ID.

use crate::compression_metrics::{
    record_compression_state_operation, record_mesh_compression_coordination,
    CompressionStateOperation, CompressionStateOutcome, MeshCompressionCoordinationEvent,
};
use async_trait::async_trait;
use base64::Engine;
use parking_lot::Mutex;
use rand::RngCore;
use sbproxy_ai::compression::identity::normalize_origin;
use sbproxy_ai::compression::{
    CommitError, CompressionBackend, CompressionConsistency, CompressionRecordId,
    CompressionRecordMetadata, CompressionSessionRecord, CompressionSessionStore, DeleteResult,
    ListPage, ListRequest, MessageDigest, PurgePage, PurgeRequest, RecordKind, StoreError,
    UpdatePermit, RECORD_SCHEMA_VERSION,
};
use sbproxy_mesh::state::register::VersionedLwwRegister;
use sbproxy_mesh::state::replicated::{ReplicatedStore, StateError as MeshStateError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_ADMIN_PAGE_SIZE: u16 = 500;
const MAX_CURSOR_BYTES: usize = 64 * 1024;
const MAX_LOCAL_LOCK_CAPACITY: usize = 65_536;
const MAX_MESH_STATE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Fleet pages examined by one bounded admin list call before it returns
/// a continuation cursor.
const MAX_LIST_ROUNDS: u16 = 8;

/// Bounded mesh adapter settings independent of compression content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshCompressionStoreConfig {
    /// Key prefix inside the shared replicated-state key space.
    pub key_prefix: String,
    /// Maximum number of worker-local coordination entries.
    pub local_lock_capacity: usize,
}

impl Default for MeshCompressionStoreConfig {
    fn default() -> Self {
        Self {
            key_prefix: "compression:v1:".to_string(),
            local_lock_capacity: 4_096,
        }
    }
}

#[derive(Debug, Clone)]
struct RegistryPermit {
    record_id: CompressionRecordId,
    owner: Vec<u8>,
    fence: u64,
}

#[derive(Debug)]
struct LockEntry {
    owner: Option<Vec<u8>>,
    fence: u64,
    expires_at: Option<Instant>,
    last_used: u64,
}

#[derive(Debug, Default)]
struct LockRegistryState {
    entries: HashMap<CompressionRecordId, LockEntry>,
    sequence: u64,
}

/// Worker-local writer serialization. Not a distributed lock: it bounds
/// duplicate summarizer work inside one process, while cross-node writers
/// are serialized by the replicated version check in `commit`.
#[derive(Debug)]
struct LocalLockRegistry {
    capacity: usize,
    state: Mutex<LockRegistryState>,
}

impl LocalLockRegistry {
    fn new(capacity: usize) -> Result<Self, StoreError> {
        if !(1..=MAX_LOCAL_LOCK_CAPACITY).contains(&capacity) {
            return Err(StoreError::InvalidRequest);
        }
        Ok(Self {
            capacity,
            state: Mutex::new(LockRegistryState::default()),
        })
    }

    fn acquire(&self, record_id: CompressionRecordId, ttl: Duration) -> Option<RegistryPermit> {
        if ttl.is_zero() {
            return None;
        }
        let now = Instant::now();
        let mut state = self.state.lock();
        state.sequence = state.sequence.saturating_add(1);
        let sequence = state.sequence;
        if let Some(entry) = state.entries.get_mut(&record_id) {
            if entry.expires_at.is_some_and(|expires_at| expires_at <= now) {
                entry.owner = None;
                entry.expires_at = None;
            }
            if entry.owner.is_some() {
                entry.last_used = sequence;
                return None;
            }
        } else if state.entries.len() == self.capacity {
            let evict = state
                .entries
                .iter()
                .filter(|(_, entry)| entry.owner.is_none())
                .min_by_key(|(id, entry)| (entry.last_used, **id))
                .map(|(id, _)| *id)?;
            state.entries.remove(&evict);
        }

        let entry = state.entries.entry(record_id).or_insert(LockEntry {
            owner: None,
            fence: 0,
            expires_at: None,
            last_used: sequence,
        });
        let mut owner = vec![0_u8; 32];
        rand::thread_rng().fill_bytes(&mut owner);
        entry.fence = entry.fence.saturating_add(1).max(1);
        entry.owner = Some(owner.clone());
        entry.expires_at = now.checked_add(ttl);
        entry.last_used = sequence;
        Some(RegistryPermit {
            record_id,
            owner,
            fence: entry.fence,
        })
    }

    fn release(&self, permit: &RegistryPermit) -> Result<(), StoreError> {
        let mut state = self.state.lock();
        state.sequence = state.sequence.saturating_add(1);
        let sequence = state.sequence;
        let Some(entry) = state.entries.get_mut(&permit.record_id) else {
            return Ok(());
        };
        if entry.fence == permit.fence && entry.owner.as_deref() == Some(permit.owner.as_slice()) {
            entry.owner = None;
            entry.expires_at = None;
            entry.last_used = sequence;
        }
        Ok(())
    }

    fn validate(
        &self,
        record_id: CompressionRecordId,
        owner: &[u8],
        fence: u64,
    ) -> Result<(), CommitError> {
        let now = Instant::now();
        let mut state = self.state.lock();
        let Some(entry) = state.entries.get_mut(&record_id) else {
            return Err(CommitError::LeaseLost);
        };
        if entry.fence != fence {
            return Err(CommitError::FenceRejected);
        }
        if entry.expires_at.is_some_and(|expires_at| expires_at <= now) {
            entry.owner = None;
            entry.expires_at = None;
            return Err(CommitError::LeaseLost);
        }
        if entry.owner.as_deref() != Some(owner) {
            return Err(CommitError::LeaseLost);
        }
        Ok(())
    }

    fn invalidate(&self, record_id: CompressionRecordId) {
        let mut state = self.state.lock();
        state.sequence = state.sequence.saturating_add(1);
        let sequence = state.sequence;
        if let Some(entry) = state.entries.get_mut(&record_id) {
            entry.owner = None;
            entry.expires_at = None;
            entry.fence = entry.fence.saturating_add(1).max(1);
            entry.last_used = sequence;
        }
    }

    #[cfg(test)]
    fn contains(&self, record_id: CompressionRecordId) -> bool {
        self.state.lock().entries.contains_key(&record_id)
    }
}

/// Replicated mesh compression state bound to the WOR-1947 substrate.
#[derive(Clone)]
pub struct MeshCompressionStore {
    replicated: Arc<ReplicatedStore>,
    config: MeshCompressionStoreConfig,
    locks: Arc<LocalLockRegistry>,
}

impl MeshCompressionStore {
    /// Bind compression state to the process-wide replicated substrate.
    pub fn new(
        replicated: Arc<ReplicatedStore>,
        config: MeshCompressionStoreConfig,
    ) -> Result<Self, StoreError> {
        validate_config(&config)?;
        let locks = Arc::new(LocalLockRegistry::new(config.local_lock_capacity)?);
        Ok(Self {
            replicated,
            config,
            locks,
        })
    }

    fn state_key(&self, id: CompressionRecordId) -> String {
        format!("{}{id}", self.config.key_prefix)
    }

    fn record_id_from_key(&self, key: &str) -> Option<CompressionRecordId> {
        key.strip_prefix(&self.config.key_prefix)?.parse().ok()
    }

    /// Quorum-read one record, reconciling replicas and mapping tombstones
    /// to synthesized deletion markers so callers observe the version they
    /// must extend to re-create the session.
    async fn read_state(
        &self,
        id: CompressionRecordId,
    ) -> Result<Option<CompressionSessionRecord>, StoreError> {
        let outcome = self
            .replicated
            .get_versioned(&self.state_key(id))
            .await
            .map_err(read_error)?;
        let Some(register) = outcome.register else {
            return Ok(None);
        };
        if register.is_tombstone() {
            return Ok(Some(tombstone_record(&register)));
        }
        let bytes = outcome.value.ok_or(StoreError::CorruptRecord)?;
        let mut record = serde_json::from_slice::<CompressionSessionRecord>(&bytes)
            .map_err(|_| StoreError::CorruptRecord)?;
        if record.schema_version != RECORD_SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema);
        }
        if record.logical_version != register.logical_version() || record.kind != RecordKind::Live {
            return Err(StoreError::CorruptRecord);
        }
        record.conflict_detected |= register.conflict_detected();
        Ok(Some(record))
    }

    async fn list_page(&self, request: &ListRequest) -> Result<ListPage, StoreError> {
        validate_list_request(request)?;
        let mut fleet_token = request.cursor.as_deref().map(decode_cursor).transpose()?;
        let wanted_origin = request.origin.as_deref().map(normalize_origin);
        let limit = usize::from(request.limit);
        let mut records = Vec::with_capacity(limit);
        let mut seen: BTreeSet<CompressionRecordId> = BTreeSet::new();
        let mut rounds = 0_u16;

        loop {
            // Request at most as many holder entries as records still fit:
            // dedup and filtering only shrink a page, so the record budget
            // can never be exceeded mid-page and the substrate's page token
            // remains a lossless resume point.
            let remaining = limit.saturating_sub(records.len()).max(1);
            let page = self
                .replicated
                .fleet_state_page(&self.config.key_prefix, fleet_token.as_deref(), remaining)
                .await;
            if !page.unreachable.is_empty() {
                // A member that cannot be queried makes completeness
                // unverifiable; fail loud instead of returning a silently
                // partial page.
                return Err(StoreError::Unavailable);
            }
            for entry in &page.entries {
                let Some(id) = self.record_id_from_key(&entry.key) else {
                    continue;
                };
                if !seen.insert(id) {
                    continue;
                }
                let Some(record) = self.read_state(id).await? else {
                    continue;
                };
                if request
                    .tenant_id
                    .as_ref()
                    .is_some_and(|tenant_id| record.tenant_id != *tenant_id)
                    || wanted_origin
                        .as_ref()
                        .is_some_and(|origin| record.origin != *origin)
                    || request.expired.is_some_and(|expired| {
                        (record.expires_at_unix_ms <= request.expiration_cutoff_unix_ms) != expired
                    })
                    || request
                        .conflict
                        .is_some_and(|conflict| record.conflict_detected != conflict)
                {
                    continue;
                }
                records.push(CompressionRecordMetadata::from_record(
                    id,
                    CompressionBackend::Mesh,
                    CompressionConsistency::EventualLww,
                    &record,
                ));
            }
            match page.next_page_token {
                None => {
                    return Ok(ListPage {
                        records,
                        next_cursor: None,
                    });
                }
                Some(token) => {
                    fleet_token = Some(token);
                    rounds += 1;
                    if records.len() >= limit || rounds >= MAX_LIST_ROUNDS {
                        let next_cursor = fleet_token.as_deref().map(encode_cursor).transpose()?;
                        return Ok(ListPage {
                            records,
                            next_cursor,
                        });
                    }
                }
            }
        }
    }
}

#[async_trait]
impl CompressionSessionStore for MeshCompressionStore {
    fn backend(&self) -> CompressionBackend {
        CompressionBackend::Mesh
    }

    fn consistency(&self) -> CompressionConsistency {
        CompressionConsistency::EventualLww
    }

    async fn load(
        &self,
        id: &CompressionRecordId,
    ) -> Result<Option<CompressionSessionRecord>, StoreError> {
        let started = Instant::now();
        let result = self.read_state(*id).await;
        let outcome = match &result {
            Ok(Some(_)) => CompressionStateOutcome::Ok,
            Ok(None) => CompressionStateOutcome::Missing,
            Err(_) => CompressionStateOutcome::Error,
        };
        record_compression_state_operation(
            CompressionBackend::Mesh,
            CompressionStateOperation::Get,
            outcome,
            started.elapsed(),
        );
        result
    }

    async fn acquire_update(
        &self,
        id: &CompressionRecordId,
        lease_ttl: Duration,
    ) -> Result<Option<UpdatePermit>, StoreError> {
        if lease_ttl.is_zero() || lease_ttl > MAX_MESH_STATE_TTL {
            return Err(StoreError::InvalidRequest);
        }
        let permit = self.locks.acquire(*id, lease_ttl).map(|permit| {
            UpdatePermit::new(
                permit.record_id,
                CompressionBackend::Mesh,
                permit.owner,
                permit.fence,
            )
        });
        if permit.is_none() {
            record_mesh_compression_coordination(MeshCompressionCoordinationEvent::Contention);
        }
        Ok(permit)
    }

    async fn commit(
        &self,
        permit: &UpdatePermit,
        expected_logical_version: Option<u64>,
        record: &CompressionSessionRecord,
        ttl: Duration,
    ) -> Result<(), CommitError> {
        let started = Instant::now();
        let result = async {
            if permit.backend() != CompressionBackend::Mesh
                || record.schema_version != RECORD_SCHEMA_VERSION
                || record.kind != RecordKind::Live
                || record.logical_version
                    != expected_logical_version
                        .unwrap_or(0)
                        .checked_add(1)
                        .ok_or(CommitError::Serialization)?
                || record.parent_logical_version != expected_logical_version
            {
                return Err(CommitError::Serialization);
            }
            let ttl_secs = state_ttl_secs(ttl).ok_or(CommitError::Serialization)?;
            if let Err(error) =
                self.locks
                    .validate(permit.record_id(), permit.ownership_token(), permit.fence())
            {
                record_mesh_compression_coordination(match error {
                    CommitError::FenceRejected => MeshCompressionCoordinationEvent::FenceRejection,
                    _ => MeshCompressionCoordinationEvent::LeaseExpiry,
                });
                return Err(error);
            }

            // Conditional-put step 1: the current replicated version must
            // still be the one the caller extended.
            let current = self
                .read_state(permit.record_id())
                .await
                .map_err(commit_read_error)?;
            if current.as_ref().map(|record| record.logical_version) != expected_logical_version {
                record_mesh_compression_coordination(
                    MeshCompressionCoordinationEvent::StaleVersion,
                );
                return Err(CommitError::StaleVersion);
            }

            // Step 2: write the record at exactly `expected + 1`. Replicas
            // holding a newer version fence it out via the causal merge.
            let payload = serde_json::to_vec(record).map_err(|_| CommitError::Serialization)?;
            let key = self.state_key(permit.record_id());
            let receipt = self
                .replicated
                .put_versioned(
                    &key,
                    &payload,
                    ttl_secs,
                    record.logical_version,
                    expected_logical_version,
                )
                .await
                .map_err(|_| CommitError::Unavailable)?;

            // Step 3: read back and require this exact write to be the
            // reconciled winner. A concurrent equal-version writer loses
            // here deterministically; the surviving record carries the
            // conflict flag.
            let verified = self
                .replicated
                .get_versioned(&key)
                .await
                .map_err(|_| CommitError::Unavailable)?;
            let winner = verified.register.ok_or(CommitError::Unavailable)?;
            let ours = &receipt.register;
            let won = !winner.is_tombstone()
                && winner.logical_version() == ours.logical_version()
                && winner.node_id() == ours.node_id()
                && winner.timestamp_ms() == ours.timestamp_ms()
                && winner.value() == ours.value();
            if !won {
                record_mesh_compression_coordination(
                    MeshCompressionCoordinationEvent::StaleVersion,
                );
                return Err(CommitError::StaleVersion);
            }
            Ok(())
        }
        .await;
        record_compression_state_operation(
            CompressionBackend::Mesh,
            CompressionStateOperation::Commit,
            if result.is_ok() {
                CompressionStateOutcome::Ok
            } else {
                CompressionStateOutcome::Error
            },
            started.elapsed(),
        );
        result
    }

    async fn release(&self, permit: UpdatePermit) -> Result<(), StoreError> {
        if permit.backend() != CompressionBackend::Mesh {
            return Err(StoreError::InvalidRequest);
        }
        self.locks.release(&RegistryPermit {
            record_id: permit.record_id(),
            owner: permit.ownership_token().to_vec(),
            fence: permit.fence(),
        })
    }

    async fn list(&self, request: &ListRequest) -> Result<ListPage, StoreError> {
        let started = Instant::now();
        let result = self.list_page(request).await;
        record_compression_state_operation(
            CompressionBackend::Mesh,
            CompressionStateOperation::List,
            if result.is_ok() {
                CompressionStateOutcome::Ok
            } else {
                CompressionStateOutcome::Error
            },
            started.elapsed(),
        );
        result
    }

    async fn delete(&self, id: &CompressionRecordId) -> Result<DeleteResult, StoreError> {
        let started = Instant::now();
        let result = async {
            // Fence local in-flight writers first, so a worker holding a
            // permit cannot commit past the delete from this process.
            self.locks.invalidate(*id);
            let current = self.read_state(*id).await?;
            if let Some(existing) = current
                .as_ref()
                .filter(|record| record.kind == RecordKind::Tombstone)
            {
                return Ok(DeleteResult {
                    deleted: false,
                    logical_version: Some(existing.logical_version),
                });
            }
            let deleted = current.is_some();
            let receipt = self
                .replicated
                .delete(&self.state_key(*id))
                .await
                .map_err(|_| StoreError::Unavailable)?;
            Ok(DeleteResult {
                deleted,
                logical_version: Some(receipt.register.logical_version()),
            })
        }
        .await;
        let outcome = match &result {
            Ok(result) if result.deleted => CompressionStateOutcome::Ok,
            Ok(_) => CompressionStateOutcome::Missing,
            Err(_) => CompressionStateOutcome::Error,
        };
        record_compression_state_operation(
            CompressionBackend::Mesh,
            CompressionStateOperation::Delete,
            outcome,
            started.elapsed(),
        );
        result
    }

    async fn purge(&self, request: &PurgeRequest) -> Result<PurgePage, StoreError> {
        let started = Instant::now();
        let result = async {
            let page = self
                .list_page(&ListRequest {
                    tenant_id: request.tenant_id.clone(),
                    origin: request.origin.clone(),
                    expired: request.expired_before_unix_ms.map(|_| true),
                    expiration_cutoff_unix_ms: request.expired_before_unix_ms.unwrap_or(0),
                    conflict: request.conflict,
                    cursor: request.cursor.clone(),
                    limit: request.limit,
                })
                .await?;
            let mut deleted = 0_u64;
            for record in page.records {
                if self.delete(&record.id).await?.deleted {
                    deleted += 1;
                }
            }
            Ok(PurgePage {
                deleted,
                next_cursor: page.next_cursor,
            })
        }
        .await;
        record_compression_state_operation(
            CompressionBackend::Mesh,
            CompressionStateOperation::Purge,
            if result.is_ok() {
                CompressionStateOutcome::Ok
            } else {
                CompressionStateOutcome::Error
            },
            started.elapsed(),
        );
        result
    }
}

/// A synthesized deletion marker for a replicated tombstone. Content
/// fields are empty by construction: the substrate stores no value for a
/// tombstone, and the marker exists so callers observe `kind` and the
/// logical version a re-creating write must extend.
fn tombstone_record(register: &VersionedLwwRegister) -> CompressionSessionRecord {
    CompressionSessionRecord {
        schema_version: RECORD_SCHEMA_VERSION,
        logical_version: register.logical_version(),
        tenant_id: String::new(),
        origin: String::new(),
        summary: String::new(),
        protected_prefix_count: 0,
        protected_prefix_digest: MessageDigest::for_messages(&[]),
        covered_history_count: 0,
        covered_history_digest: MessageDigest::for_messages(&[]),
        covered_input_tokens: 0,
        summary_tokens: 0,
        summarizer_provider: String::new(),
        summarizer_model: String::new(),
        writer_node: register.node_id().to_string(),
        parent_logical_version: register.parent_logical_version(),
        conflict_detected: register.conflict_detected(),
        created_at_unix_ms: register.timestamp_ms(),
        updated_at_unix_ms: register.timestamp_ms(),
        expires_at_unix_ms: register.timestamp_ms(),
        kind: RecordKind::Tombstone,
    }
}

fn read_error(error: MeshStateError) -> StoreError {
    match error {
        MeshStateError::InvalidRecord => StoreError::CorruptRecord,
        _ => StoreError::Unavailable,
    }
}

fn commit_read_error(error: StoreError) -> CommitError {
    match error {
        StoreError::CorruptRecord | StoreError::UnsupportedSchema => CommitError::Serialization,
        _ => CommitError::Unavailable,
    }
}

fn state_ttl_secs(ttl: Duration) -> Option<u64> {
    if ttl.is_zero() || ttl > MAX_MESH_STATE_TTL {
        return None;
    }
    // Round up so a sub-second TTL is a one-second replicated lifetime
    // instead of the substrate's "no expiry" sentinel of zero.
    Some(u64::try_from(ttl.as_millis()).ok()?.div_ceil(1_000).max(1))
}

fn validate_config(config: &MeshCompressionStoreConfig) -> Result<(), StoreError> {
    if config.key_prefix.is_empty()
        || config.key_prefix.len() > 128
        || !config
            .key_prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":-_.".contains(&byte))
        || !(1..=MAX_LOCAL_LOCK_CAPACITY).contains(&config.local_lock_capacity)
    {
        return Err(StoreError::InvalidRequest);
    }
    Ok(())
}

fn validate_list_request(request: &ListRequest) -> Result<(), StoreError> {
    if request
        .tenant_id
        .as_ref()
        .is_some_and(|tenant_id| tenant_id.trim().is_empty())
        || request
            .origin
            .as_ref()
            .is_some_and(|origin| origin.trim().is_empty())
        || (request.expired.is_some() && request.expiration_cutoff_unix_ms == 0)
        || !(1..=MAX_ADMIN_PAGE_SIZE).contains(&request.limit)
    {
        return Err(StoreError::InvalidRequest);
    }
    Ok(())
}

/// Opaque adapter cursor wrapping the substrate's fleet page token, so an
/// undecodable cursor is a client error instead of a silent walk restart.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeshListCursor {
    fleet_token: String,
}

fn encode_cursor(fleet_token: &str) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(&MeshListCursor {
        fleet_token: fleet_token.to_string(),
    })
    .map_err(|_| StoreError::InvalidCursor)?;
    if encoded.len() > MAX_CURSOR_BYTES {
        return Err(StoreError::InvalidCursor);
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded))
}

fn decode_cursor(encoded: &str) -> Result<String, StoreError> {
    if encoded.len() > MAX_CURSOR_BYTES.saturating_mul(2) {
        return Err(StoreError::InvalidCursor);
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| StoreError::InvalidCursor)?;
    if bytes.len() > MAX_CURSOR_BYTES {
        return Err(StoreError::InvalidCursor);
    }
    let cursor =
        serde_json::from_slice::<MeshListCursor>(&bytes).map_err(|_| StoreError::InvalidCursor)?;
    if cursor.fleet_token.is_empty() {
        return Err(StoreError::InvalidCursor);
    }
    Ok(cursor.fleet_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sbproxy_ai::compression::{
        CommitError, CompressionRecordId, CompressionSessionRecord, CompressionSessionStore,
        ListRequest, MessageDigest, RecordKind, RECORD_SCHEMA_VERSION,
    };
    use sbproxy_mesh::state::distributed_cache::DistributedCache;
    use sbproxy_mesh::state::replicated::{
        Consistency, MeshClock, ReplicaShard, ReplicatedStore, ReplicationSettings, ShardLimits,
    };
    use sbproxy_mesh::transport::TransportClientPool;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::Duration;

    /// Single-node replicated substrate: the local shard is the whole
    /// replica set, so trait semantics are exercised without transport.
    fn substrate(node: &str) -> Arc<ReplicatedStore> {
        let clock: MeshClock = Arc::new(|| 1_000_000);
        let shard = Arc::new(ReplicaShard::in_memory(ShardLimits::default(), 0, clock));
        let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new(node, 128));
        Arc::new(ReplicatedStore::new(
            shard,
            cache,
            Arc::new(TransportClientPool::new()),
            Arc::new(|_| None),
            Arc::new(|| false),
            ReplicationSettings {
                replication_factor: 1,
                write_consistency: Consistency::One,
                read_consistency: Consistency::One,
                anti_entropy_interval_secs: 3_600,
                tombstone_gc_grace_secs: 0,
            },
        ))
    }

    fn store_over(substrate: Arc<ReplicatedStore>, capacity: usize) -> MeshCompressionStore {
        MeshCompressionStore::new(
            substrate,
            MeshCompressionStoreConfig {
                key_prefix: "compression:v1:".to_string(),
                local_lock_capacity: capacity,
            },
        )
        .unwrap()
    }

    fn store(capacity: usize) -> MeshCompressionStore {
        store_over(substrate("node-a"), capacity)
    }

    fn id(seed: u8) -> CompressionRecordId {
        CompressionRecordId::derive("tenant-a", "api.example.com", [seed; 16])
    }

    fn record(version: u64, value: &str) -> CompressionSessionRecord {
        CompressionSessionRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            logical_version: version,
            tenant_id: "tenant-a".to_string(),
            origin: "api.example.com".to_string(),
            summary: value.to_string(),
            protected_prefix_count: 1,
            protected_prefix_digest: MessageDigest::for_messages(&[json!({
                "role": "system",
                "content": "protected"
            })]),
            covered_history_count: 2,
            covered_history_digest: MessageDigest::for_messages(&[json!({
                "role": "user",
                "content": "covered"
            })]),
            covered_input_tokens: 200,
            summary_tokens: 20,
            summarizer_provider: "provider-a".to_string(),
            summarizer_model: "model-a".to_string(),
            writer_node: "node-a".to_string(),
            parent_logical_version: (version > 1).then_some(version - 1),
            conflict_detected: false,
            created_at_unix_ms: 1_000,
            updated_at_unix_ms: 2_000 + version,
            expires_at_unix_ms: 60_000,
            kind: RecordKind::Live,
        }
    }

    async fn commit_record(
        store: &MeshCompressionStore,
        record_id: CompressionRecordId,
        expected: Option<u64>,
        candidate: &CompressionSessionRecord,
    ) {
        let permit = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        store
            .commit(&permit, expected, candidate, Duration::from_secs(30))
            .await
            .unwrap();
        store.release(permit).await.unwrap();
    }

    #[test]
    fn admin_page_limit_accepts_five_hundred_and_rejects_more() {
        let request = ListRequest {
            tenant_id: None,
            origin: None,
            expired: None,
            expiration_cutoff_unix_ms: 0,
            conflict: None,
            cursor: None,
            limit: 500,
        };

        assert_eq!(validate_list_request(&request), Ok(()));
        assert_eq!(
            validate_list_request(&ListRequest {
                limit: 501,
                ..request
            }),
            Err(StoreError::InvalidRequest)
        );
    }

    #[tokio::test]
    async fn local_registry_serializes_same_record_and_releases_by_owner() {
        let store = store(2);
        let record_id = id(1);
        let first = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        assert!(store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .is_none());

        store.release(first).await.unwrap();
        assert!(store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .is_some());
    }

    #[test]
    fn lock_registry_evicts_idle_lru_but_never_active_entries() {
        let registry = LocalLockRegistry::new(2).unwrap();
        let first = registry.acquire(id(1), Duration::from_secs(5)).unwrap();
        registry.release(&first).unwrap();
        let second = registry.acquire(id(2), Duration::from_secs(5)).unwrap();
        registry.release(&second).unwrap();

        let third = registry.acquire(id(3), Duration::from_secs(5)).unwrap();
        assert!(!registry.contains(id(1)));
        assert!(registry.contains(id(2)));
        assert!(registry.contains(id(3)));

        let active = registry.acquire(id(2), Duration::from_secs(5)).unwrap();
        assert!(registry.acquire(id(4), Duration::from_secs(5)).is_none());
        registry.release(&active).unwrap();
        registry.release(&third).unwrap();
    }

    #[tokio::test]
    async fn update_permits_reject_unbounded_lease_durations() {
        let store = store(2);
        assert!(store
            .acquire_update(&id(1), Duration::from_secs(8 * 24 * 60 * 60))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn commit_load_delete_and_recreate_follow_the_causal_contract() {
        let store = store(4);
        let record_id = id(1);

        commit_record(&store, record_id, None, &record(1, "first")).await;
        assert_eq!(
            store.load(&record_id).await.unwrap().unwrap().summary,
            "first"
        );

        commit_record(&store, record_id, Some(1), &record(2, "second")).await;

        // A writer that read version 1 but commits after version 2 landed
        // is rejected by the conditional put, not silently merged.
        let stale = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store
                .commit(
                    &stale,
                    Some(1),
                    &record(2, "stale"),
                    Duration::from_secs(30)
                )
                .await,
            Err(CommitError::StaleVersion)
        );
        store.release(stale).await.unwrap();

        // Delete writes a replicated tombstone one version past the live
        // record; the tombstone is observable so a later writer knows the
        // version it must extend.
        let deleted = store.delete(&record_id).await.unwrap();
        assert!(deleted.deleted);
        assert_eq!(deleted.logical_version, Some(3));
        let tombstone = store.load(&record_id).await.unwrap().unwrap();
        assert_eq!(tombstone.kind, RecordKind::Tombstone);
        assert!(tombstone.summary.is_empty());

        // Deleting again is a no-op against the retained tombstone.
        let repeated = store.delete(&record_id).await.unwrap();
        assert!(!repeated.deleted);
        assert_eq!(repeated.logical_version, Some(3));

        // A commit that read the tombstone legitimately re-creates the
        // session at the next version.
        commit_record(&store, record_id, Some(3), &record(4, "recreated")).await;
        let recreated = store.load(&record_id).await.unwrap().unwrap();
        assert_eq!(recreated.kind, RecordKind::Live);
        assert_eq!(recreated.summary, "recreated");
    }

    #[tokio::test]
    async fn delete_invalidates_an_active_local_writer() {
        let store = store(2);
        let record_id = id(1);
        let permit = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();

        assert!(!store.delete(&record_id).await.unwrap().deleted);
        assert_eq!(
            store
                .commit(&permit, None, &record(1, "late"), Duration::from_secs(30))
                .await,
            Err(CommitError::FenceRejected)
        );
    }

    #[tokio::test]
    async fn cross_worker_writers_are_serialized_by_version_not_by_lease() {
        // Two adapters over one substrate model two proxy workers: local
        // leases do not extend across processes, so both writers hold a
        // permit, and the conditional put decides the winner.
        let shared = substrate("node-a");
        let left = store_over(shared.clone(), 4);
        let right = store_over(shared, 4);
        let record_id = id(9);
        commit_record(&left, record_id, None, &record(1, "base")).await;

        let left_permit = left
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        let right_permit = right
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();

        left.commit(
            &left_permit,
            Some(1),
            &record(2, "left wins"),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        assert_eq!(
            right
                .commit(
                    &right_permit,
                    Some(1),
                    &record(2, "right loses"),
                    Duration::from_secs(30),
                )
                .await,
            Err(CommitError::StaleVersion)
        );
        assert_eq!(
            right.load(&record_id).await.unwrap().unwrap().summary,
            "left wins"
        );
    }

    #[tokio::test]
    async fn listing_is_bounded_content_free_and_cursor_driven() {
        let store = store(8);
        for seed in 1..=3 {
            commit_record(
                &store,
                id(seed),
                None,
                &record(1, &format!("secret-{seed}")),
            )
            .await;
        }

        let first = store
            .list(&ListRequest {
                tenant_id: Some("tenant-a".to_string()),
                origin: None,
                expired: None,
                expiration_cutoff_unix_ms: 0,
                conflict: None,
                cursor: None,
                limit: 2,
            })
            .await
            .unwrap();
        assert_eq!(first.records.len(), 2);
        assert!(first.next_cursor.is_some());
        assert!(!serde_json::to_string(&first.records)
            .unwrap()
            .contains("secret-"));

        let second = store
            .list(&ListRequest {
                tenant_id: Some("tenant-a".to_string()),
                origin: None,
                expired: None,
                expiration_cutoff_unix_ms: 0,
                conflict: None,
                cursor: first.next_cursor,
                limit: 2,
            })
            .await
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert!(second.next_cursor.is_none());
    }

    #[tokio::test]
    async fn listing_supports_unscoped_expiry_and_conflict_filters() {
        let store = store(8);
        let expired_id = id(40);
        let active_id = id(41);
        for (record_id, expires_at_unix_ms) in [(expired_id, 50_000), (active_id, 70_000)] {
            let mut candidate = record(1, "sensitive");
            candidate.conflict_detected = true;
            candidate.expires_at_unix_ms = expires_at_unix_ms;
            commit_record(&store, record_id, None, &candidate).await;
        }

        let page = store
            .list(&ListRequest {
                tenant_id: None,
                origin: None,
                expired: Some(true),
                expiration_cutoff_unix_ms: 60_000,
                conflict: Some(true),
                cursor: None,
                limit: 10,
            })
            .await
            .unwrap();

        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].id, expired_id);
    }

    #[tokio::test]
    async fn invalid_cursors_are_rejected_not_treated_as_a_fresh_walk() {
        let store = store(2);
        for cursor in ["not-a-cursor", "", "AAAA"] {
            let result = store
                .list(&ListRequest {
                    tenant_id: None,
                    origin: None,
                    expired: None,
                    expiration_cutoff_unix_ms: 0,
                    conflict: None,
                    cursor: Some(cursor.to_string()),
                    limit: 10,
                })
                .await;
            assert_eq!(result, Err(StoreError::InvalidCursor), "cursor {cursor:?}");
        }
    }

    #[tokio::test]
    async fn purge_deletes_only_the_selected_tenant_scope() {
        let store = store(8);
        commit_record(&store, id(1), None, &record(1, "keep-me")).await;
        let mut other = record(1, "purge-me");
        other.tenant_id = "tenant-b".to_string();
        commit_record(&store, id(2), None, &other).await;

        let page = store
            .purge(&PurgeRequest {
                tenant_id: Some("tenant-b".to_string()),
                origin: None,
                expired_before_unix_ms: None,
                conflict: None,
                cursor: None,
                limit: 10,
            })
            .await
            .unwrap();
        assert_eq!(page.deleted, 1);
        assert!(page.next_cursor.is_none());
        assert_eq!(
            store.load(&id(2)).await.unwrap().unwrap().kind,
            RecordKind::Tombstone
        );
        assert_eq!(
            store.load(&id(1)).await.unwrap().unwrap().summary,
            "keep-me"
        );
    }

    #[test]
    fn state_ttl_rounds_up_and_rejects_zero_or_unbounded_lifetimes() {
        assert_eq!(state_ttl_secs(Duration::from_millis(1)), Some(1));
        assert_eq!(state_ttl_secs(Duration::from_secs(30)), Some(30));
        assert_eq!(state_ttl_secs(Duration::from_millis(1_500)), Some(2));
        assert_eq!(state_ttl_secs(Duration::ZERO), None);
        assert_eq!(state_ttl_secs(Duration::from_secs(8 * 24 * 60 * 60)), None);
    }
}
