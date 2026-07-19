//! Experimental LWW compression session state over the shared process mesh.
//!
//! This adapter is retained for mesh hardening work. It is not selectable from
//! SBproxy's public compression configuration because the current mesh cannot
//! guarantee replicated durability, ownership handoff, or tombstone propagation.

use crate::compression_metrics::{
    record_compression_state_operation, CompressionStateOperation, CompressionStateOutcome,
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
use sbproxy_mesh::{
    ClusterHandle, ClusterVersionedStateKind, ClusterVersionedStateRead, VersionedLwwMergeOutcome,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_ADMIN_PAGE_SIZE: u16 = 500;
const MAX_CURSOR_BYTES: usize = 512 * 1024;
const MAX_LOCAL_LOCK_CAPACITY: usize = 65_536;
const MAX_LOCAL_SNAPSHOT_CAPACITY: usize = 4_096;
const MAX_MESH_STATE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Bounded mesh adapter settings independent of compression content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshCompressionStoreConfig {
    /// Dedicated key namespace inside the shared cluster state substrate.
    pub namespace: String,
    /// Retention horizon for deletion tombstones.
    pub tombstone_ttl: Duration,
    /// Maximum number of worker-local coordination entries.
    pub local_lock_capacity: usize,
    /// Maximum number of locally owned keys retained by an admin snapshot.
    pub local_snapshot_capacity: usize,
}

impl Default for MeshCompressionStoreConfig {
    fn default() -> Self {
        Self {
            namespace: "compression_sessions".to_string(),
            tombstone_ttl: Duration::from_secs(24 * 60 * 60),
            local_lock_capacity: 4_096,
            local_snapshot_capacity: 4_096,
        }
    }
}

/// Closed convergence events emitted at the mesh adapter boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshCompressionEvent {
    /// This writer won an equal-version conflict.
    ConflictWinner,
    /// This writer lost an equal-version conflict.
    ConflictLoser,
    /// A higher-version deletion marker was published.
    TombstoneWritten,
    /// A retained deletion marker rejected a live write.
    TombstoneRetained,
    /// A candidate advanced the converged register.
    ConvergenceReplaced,
    /// A lower logical version was rejected.
    StaleWriteRejected,
}

impl MeshCompressionEvent {
    /// Stable low-cardinality label used by logs and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConflictWinner => "conflict_winner",
            Self::ConflictLoser => "conflict_loser",
            Self::TombstoneWritten => "tombstone_written",
            Self::TombstoneRetained => "tombstone_retained",
            Self::ConvergenceReplaced => "convergence_replaced",
            Self::StaleWriteRejected => "stale_write_rejected",
        }
    }
}

/// Sink for closed mesh convergence events.
pub trait MeshCompressionEventSink: Send + Sync {
    /// Record one content-free convergence event.
    fn record(&self, event: MeshCompressionEvent);
}

#[derive(Debug)]
struct NoopEventSink;

impl MeshCompressionEventSink for NoopEventSink {
    fn record(&self, _event: MeshCompressionEvent) {}
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

/// Mesh-backed eventual compression state with bounded local coordination.
#[derive(Clone)]
pub struct MeshCompressionStore {
    cluster: ClusterHandle,
    config: MeshCompressionStoreConfig,
    locks: Arc<LocalLockRegistry>,
    events: Arc<dyn MeshCompressionEventSink>,
}

impl MeshCompressionStore {
    /// Bind compression state to the existing process-wide cluster handle.
    pub fn new(
        cluster: ClusterHandle,
        config: MeshCompressionStoreConfig,
    ) -> Result<Self, StoreError> {
        validate_config(&config)?;
        let locks = Arc::new(LocalLockRegistry::new(config.local_lock_capacity)?);
        Ok(Self {
            cluster,
            config,
            locks,
            events: Arc::new(NoopEventSink),
        })
    }

    /// Replace the no-op convergence observer with an operational sink.
    pub fn with_event_sink(mut self, events: Arc<dyn MeshCompressionEventSink>) -> Self {
        self.events = events;
        self
    }

    async fn load_record(
        &self,
        id: CompressionRecordId,
    ) -> Result<Option<CompressionSessionRecord>, StoreError> {
        match self
            .cluster
            .read_versioned_state::<CompressionSessionRecord>(
                &self.config.namespace,
                &id.to_string(),
                u32::from(RECORD_SCHEMA_VERSION),
            )
            .await
        {
            ClusterVersionedStateRead::Present(outer) => {
                let mut record = outer.payload;
                let expected_kind = match outer.kind {
                    ClusterVersionedStateKind::Live => RecordKind::Live,
                    ClusterVersionedStateKind::Tombstone => RecordKind::Tombstone,
                };
                if record.schema_version != RECORD_SCHEMA_VERSION
                    || record.logical_version != outer.logical_version
                    || record.parent_logical_version != outer.parent_logical_version
                    || record.writer_node != outer.publisher_node_id
                    || record.kind != expected_kind
                    || (record.kind == RecordKind::Tombstone && !record.summary.is_empty())
                {
                    return Err(StoreError::CorruptRecord);
                }
                record.conflict_detected |= outer.conflict_detected;
                Ok(Some(record))
            }
            ClusterVersionedStateRead::Missing | ClusterVersionedStateRead::Expired { .. } => {
                Ok(None)
            }
            ClusterVersionedStateRead::IncompatibleSchema { .. } => {
                Err(StoreError::UnsupportedSchema)
            }
            ClusterVersionedStateRead::Unreachable { .. } => Err(StoreError::Unavailable),
            ClusterVersionedStateRead::Malformed { .. } => Err(StoreError::CorruptRecord),
        }
    }

    async fn merge_record(
        &self,
        record_id: CompressionRecordId,
        record: &CompressionSessionRecord,
        ttl: Duration,
    ) -> Result<VersionedLwwMergeOutcome, StoreError> {
        let kind = match record.kind {
            RecordKind::Live => ClusterVersionedStateKind::Live,
            RecordKind::Tombstone => ClusterVersionedStateKind::Tombstone,
        };
        self.cluster
            .merge_versioned_state(
                &self.config.namespace,
                &record_id.to_string(),
                u32::from(record.schema_version),
                record.logical_version,
                record.parent_logical_version,
                kind,
                ttl,
                record,
            )
            .await
            .map_err(|_| StoreError::Unavailable)
    }

    fn observe_merge(&self, outcome: VersionedLwwMergeOutcome) {
        let event = match outcome {
            VersionedLwwMergeOutcome::Replaced => MeshCompressionEvent::ConvergenceReplaced,
            VersionedLwwMergeOutcome::StaleRejected => MeshCompressionEvent::StaleWriteRejected,
            VersionedLwwMergeOutcome::ConflictRetained => MeshCompressionEvent::ConflictLoser,
            VersionedLwwMergeOutcome::ConflictReplaced => MeshCompressionEvent::ConflictWinner,
            VersionedLwwMergeOutcome::TombstoneRetained => MeshCompressionEvent::TombstoneRetained,
            VersionedLwwMergeOutcome::Unchanged => return,
        };
        self.events.record(event);
    }

    async fn list_page(&self, request: &ListRequest) -> Result<ListPage, StoreError> {
        validate_list_request(request)?;
        let mut cursor = match request.cursor.as_deref() {
            Some(cursor) => decode_cursor(cursor, self.config.local_snapshot_capacity)?,
            None => {
                let snapshot = self
                    .cluster
                    .local_state_key_snapshot(
                        &self.config.namespace,
                        self.config.local_snapshot_capacity,
                    )
                    .map_err(|_| StoreError::Unavailable)?;
                if snapshot.truncated {
                    return Err(StoreError::Unavailable);
                }
                MeshListCursor {
                    pending: snapshot.keys.into(),
                }
            }
        };
        let wanted_origin = request.origin.as_deref().map(normalize_origin);
        let mut records = Vec::with_capacity(usize::from(request.limit));
        while records.len() < usize::from(request.limit) {
            let Some(key) = cursor.pending.pop_front() else {
                break;
            };
            let id = key
                .parse::<CompressionRecordId>()
                .map_err(|_| StoreError::CorruptRecord)?;
            let Some(record) = self.load_record(id).await? else {
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
        let next_cursor = (!cursor.pending.is_empty())
            .then(|| encode_cursor(&cursor))
            .transpose()?;
        Ok(ListPage {
            records,
            next_cursor,
        })
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
        let result = self.load_record(*id).await;
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
        Ok(self.locks.acquire(*id, lease_ttl).map(|permit| {
            UpdatePermit::new(
                permit.record_id,
                CompressionBackend::Mesh,
                permit.owner,
                permit.fence,
            )
        }))
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
                || record.writer_node != self.cluster.identity().node_id
                || record.logical_version
                    != expected_logical_version
                        .unwrap_or(0)
                        .checked_add(1)
                        .ok_or(CommitError::Serialization)?
                || record.parent_logical_version != expected_logical_version
                || ttl.is_zero()
                || ttl > MAX_MESH_STATE_TTL
            {
                return Err(CommitError::Serialization);
            }
            self.locks
                .validate(permit.record_id(), permit.ownership_token(), permit.fence())?;
            let outcome = self
                .merge_record(permit.record_id(), record, ttl)
                .await
                .map_err(|error| match error {
                    StoreError::Unavailable => CommitError::Unavailable,
                    _ => CommitError::Serialization,
                })?;
            self.observe_merge(outcome);
            match outcome {
                VersionedLwwMergeOutcome::Replaced
                | VersionedLwwMergeOutcome::ConflictReplaced
                | VersionedLwwMergeOutcome::Unchanged => Ok(()),
                VersionedLwwMergeOutcome::StaleRejected
                | VersionedLwwMergeOutcome::ConflictRetained
                | VersionedLwwMergeOutcome::TombstoneRetained => Err(CommitError::StaleVersion),
            }
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
            self.locks.invalidate(*id);
            for _ in 0..3 {
                let current = self.load_record(*id).await?;
                if let Some(current) = current.as_ref() {
                    if current.kind == RecordKind::Tombstone {
                        return Ok(DeleteResult {
                            deleted: false,
                            logical_version: Some(current.logical_version),
                        });
                    }
                }
                let now = unix_time_ms().ok_or(StoreError::Unavailable)?;
                let ttl_ms = u64::try_from(self.config.tombstone_ttl.as_millis())
                    .map_err(|_| StoreError::InvalidRequest)?;
                let logical_version = current
                    .as_ref()
                    .map_or(0, |record| record.logical_version)
                    .checked_add(1)
                    .ok_or(StoreError::CorruptRecord)?;
                let deleted = current.is_some();
                let mut tombstone = current.unwrap_or_else(|| CompressionSessionRecord {
                    schema_version: RECORD_SCHEMA_VERSION,
                    logical_version,
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
                    writer_node: self.cluster.identity().node_id.clone(),
                    parent_logical_version: None,
                    conflict_detected: false,
                    created_at_unix_ms: now,
                    updated_at_unix_ms: now,
                    expires_at_unix_ms: now.saturating_add(ttl_ms),
                    kind: RecordKind::Tombstone,
                });
                tombstone.logical_version = logical_version;
                tombstone.summary.clear();
                tombstone.writer_node = self.cluster.identity().node_id.clone();
                tombstone.parent_logical_version =
                    (logical_version > 1).then_some(logical_version - 1);
                tombstone.conflict_detected = false;
                tombstone.updated_at_unix_ms = now;
                tombstone.expires_at_unix_ms = now.saturating_add(ttl_ms);
                tombstone.kind = RecordKind::Tombstone;
                let outcome = self
                    .merge_record(*id, &tombstone, self.config.tombstone_ttl)
                    .await?;
                self.observe_merge(outcome);
                match outcome {
                    VersionedLwwMergeOutcome::Replaced
                    | VersionedLwwMergeOutcome::ConflictReplaced
                    | VersionedLwwMergeOutcome::Unchanged => {
                        self.events.record(MeshCompressionEvent::TombstoneWritten);
                        return Ok(DeleteResult {
                            deleted,
                            logical_version: Some(logical_version),
                        });
                    }
                    VersionedLwwMergeOutcome::TombstoneRetained => {
                        return Ok(DeleteResult {
                            deleted: false,
                            logical_version: Some(logical_version),
                        });
                    }
                    VersionedLwwMergeOutcome::StaleRejected
                    | VersionedLwwMergeOutcome::ConflictRetained => continue,
                }
            }
            Err(StoreError::Unavailable)
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

fn validate_config(config: &MeshCompressionStoreConfig) -> Result<(), StoreError> {
    if config.namespace.is_empty()
        || config.namespace.len() > 128
        || !config
            .namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        || config.tombstone_ttl.is_zero()
        || config.tombstone_ttl > MAX_MESH_STATE_TTL
        || !(1..=MAX_LOCAL_LOCK_CAPACITY).contains(&config.local_lock_capacity)
        || !(1..=MAX_LOCAL_SNAPSHOT_CAPACITY).contains(&config.local_snapshot_capacity)
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

fn unix_time_ms() -> Option<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    u64::try_from(millis).ok()
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeshListCursor {
    pending: VecDeque<String>,
}

fn encode_cursor(cursor: &MeshListCursor) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(cursor).map_err(|_| StoreError::InvalidCursor)?;
    if encoded.len() > MAX_CURSOR_BYTES {
        return Err(StoreError::InvalidCursor);
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded))
}

fn decode_cursor(encoded: &str, capacity: usize) -> Result<MeshListCursor, StoreError> {
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
    if cursor.pending.len() > capacity
        || cursor
            .pending
            .iter()
            .any(|key| key.parse::<CompressionRecordId>().is_err())
    {
        return Err(StoreError::InvalidCursor);
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_ai::compression::{
        CommitError, CompressionRecordId, CompressionSessionRecord, CompressionSessionStore,
        ListRequest, MessageDigest, RecordKind, RECORD_SCHEMA_VERSION,
    };
    use sbproxy_mesh::{ClusterHandle, ClusterIdentity, ClusterNodeRole};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Default)]
    struct RecordingEvents(std::sync::Mutex<Vec<MeshCompressionEvent>>);

    impl MeshCompressionEventSink for RecordingEvents {
        fn record(&self, event: MeshCompressionEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    fn handle() -> ClusterHandle {
        ClusterHandle::local(ClusterIdentity {
            cluster_id: "cluster-a".to_string(),
            node_id: "node-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Gateway]),
            labels: BTreeMap::new(),
            peer_address: None,
            model_endpoint: None,
        })
        .unwrap()
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

    fn config(capacity: usize) -> MeshCompressionStoreConfig {
        MeshCompressionStoreConfig {
            namespace: "compression_sessions".to_string(),
            tombstone_ttl: Duration::from_secs(1),
            local_lock_capacity: capacity,
            local_snapshot_capacity: 64,
        }
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
        let store = MeshCompressionStore::new(handle(), config(2)).unwrap();
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
    async fn commit_load_conflict_and_delete_follow_eventual_lww_contract() {
        let store = MeshCompressionStore::new(handle(), config(4)).unwrap();
        let record_id = id(1);
        let permit = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        store
            .commit(&permit, None, &record(1, "first"), Duration::from_secs(30))
            .await
            .unwrap();
        store.release(permit).await.unwrap();
        assert_eq!(
            store.load(&record_id).await.unwrap().unwrap().summary,
            "first"
        );

        let left = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        store
            .commit(
                &left,
                Some(1),
                &record(2, "competing"),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
        store.release(left).await.unwrap();

        let competing = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        store
            .commit(
                &competing,
                Some(1),
                &record(2, "other child"),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
        store.release(competing).await.unwrap();
        assert!(
            store
                .load(&record_id)
                .await
                .unwrap()
                .unwrap()
                .conflict_detected
        );

        let stale = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store
                .commit(&stale, None, &record(1, "stale"), Duration::from_secs(30))
                .await,
            Err(CommitError::StaleVersion)
        );
        store.release(stale).await.unwrap();

        let deleted = store.delete(&record_id).await.unwrap();
        assert!(deleted.deleted);
        assert_eq!(deleted.logical_version, Some(3));
        let tombstone = store.load(&record_id).await.unwrap().unwrap();
        assert_eq!(tombstone.kind, RecordKind::Tombstone);
        assert!(tombstone.summary.is_empty());
    }

    #[tokio::test]
    async fn delete_invalidates_an_active_local_writer() {
        let store = MeshCompressionStore::new(handle(), config(2)).unwrap();
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
    async fn deleting_a_missing_id_tombstones_a_late_writer_from_another_node_registry() {
        let cluster = handle();
        let deleting_store = MeshCompressionStore::new(cluster.clone(), config(2)).unwrap();
        let writing_store = MeshCompressionStore::new(cluster, config(2)).unwrap();
        let record_id = id(1);
        let remote_permit = writing_store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();

        let deleted = deleting_store.delete(&record_id).await.unwrap();
        assert!(!deleted.deleted);
        assert_eq!(deleted.logical_version, Some(1));
        assert_eq!(
            writing_store
                .commit(
                    &remote_permit,
                    None,
                    &record(1, "late remote write"),
                    Duration::from_secs(30),
                )
                .await,
            Err(CommitError::StaleVersion)
        );
    }

    #[tokio::test]
    async fn update_permits_reject_unbounded_lease_durations() {
        let store = MeshCompressionStore::new(handle(), config(2)).unwrap();
        assert!(store
            .acquire_update(&id(1), Duration::from_secs(8 * 24 * 60 * 60))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn local_snapshot_cursor_is_stable_tenant_scoped_and_content_free() {
        let store = MeshCompressionStore::new(handle(), config(4)).unwrap();
        for seed in 1..=3 {
            let record_id = id(seed);
            let permit = store
                .acquire_update(&record_id, Duration::from_secs(5))
                .await
                .unwrap()
                .unwrap();
            store
                .commit(
                    &permit,
                    None,
                    &record(1, &format!("secret-{seed}")),
                    Duration::from_secs(30),
                )
                .await
                .unwrap();
            store.release(permit).await.unwrap();
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
    async fn local_snapshot_supports_unscoped_expiry_and_conflict_filters() {
        let store = MeshCompressionStore::new(handle(), config(4)).unwrap();
        let expired_id = id(40);
        let active_id = id(41);
        for (record_id, expires_at_unix_ms) in [(expired_id, 50_000), (active_id, 70_000)] {
            let permit = store
                .acquire_update(&record_id, Duration::from_secs(5))
                .await
                .unwrap()
                .unwrap();
            let mut candidate = record(1, "sensitive");
            candidate.conflict_detected = true;
            candidate.expires_at_unix_ms = expires_at_unix_ms;
            store
                .commit(&permit, None, &candidate, Duration::from_secs(30))
                .await
                .unwrap();
            store.release(permit).await.unwrap();
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

    #[test]
    fn mesh_event_vocabulary_is_closed_and_stable() {
        assert_eq!(
            MeshCompressionEvent::ConflictWinner.as_str(),
            "conflict_winner"
        );
        assert_eq!(
            MeshCompressionEvent::ConflictLoser.as_str(),
            "conflict_loser"
        );
        assert_eq!(
            MeshCompressionEvent::TombstoneWritten.as_str(),
            "tombstone_written"
        );
        assert_eq!(
            MeshCompressionEvent::TombstoneRetained.as_str(),
            "tombstone_retained"
        );
        assert_eq!(
            MeshCompressionEvent::ConvergenceReplaced.as_str(),
            "convergence_replaced"
        );
        assert_eq!(
            MeshCompressionEvent::StaleWriteRejected.as_str(),
            "stale_write_rejected"
        );
    }

    #[tokio::test]
    async fn adapter_emits_only_closed_content_free_convergence_events() {
        let events = Arc::new(RecordingEvents::default());
        let store = MeshCompressionStore::new(handle(), config(2))
            .unwrap()
            .with_event_sink(events.clone());
        let record_id = id(1);
        let permit = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        store
            .commit(&permit, None, &record(1, "secret"), Duration::from_secs(30))
            .await
            .unwrap();
        store.release(permit).await.unwrap();
        store.delete(&record_id).await.unwrap();

        let captured = events.0.lock().unwrap().clone();
        assert_eq!(
            captured,
            vec![
                MeshCompressionEvent::ConvergenceReplaced,
                MeshCompressionEvent::ConvergenceReplaced,
                MeshCompressionEvent::TombstoneWritten,
            ]
        );
        let encoded = serde_json::to_string(&captured).unwrap();
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains(&record_id.to_string()));
    }
}
