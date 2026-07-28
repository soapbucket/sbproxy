//! Durable lease-serialized Local compression state over redb.

use crate::compression_metrics::{
    record_compression_state_operation, CompressionStateOperation, CompressionStateOutcome,
};
use async_trait::async_trait;
use base64::Engine;
use rand::RngCore;
use redb::{Database, ReadableTable, TableDefinition};
use sbproxy_ai::compression::identity::normalize_origin;
use sbproxy_ai::compression::{
    CommitError, CompressionBackend, CompressionConsistency, CompressionRecordId,
    CompressionRecordMetadata, CompressionSessionRecord, CompressionSessionStore, DeleteResult,
    ListPage, ListRequest, PurgePage, PurgeRequest, RecordKind, StoreError, UpdatePermit,
    RECORD_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Bound::{Excluded, Unbounded};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RECORDS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("compression_records_v1");
const LEASES: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("compression_leases_v1");
const EXPIRATIONS: TableDefinition<&[u8; 41], ()> =
    TableDefinition::new("compression_expirations_v1");
const META: TableDefinition<&str, u64> = TableDefinition::new("compression_meta_v1");

const STORE_SCHEMA_VERSION: u16 = 1;
const STORE_SCHEMA_KEY: &str = "store_schema_version";
const NEXT_FENCE_KEY: &str = "next_fence";
const LAST_CLOCK_MS_KEY: &str = "last_clock_ms";
const RECORD_EXPIRATION_KIND: u8 = 0;
const LEASE_EXPIRATION_KIND: u8 = 1;
const MAX_ADMIN_PAGE_SIZE: u16 = 500;
const MAX_CURSOR_BYTES: usize = 128;
const MAX_GC_BATCH: usize = 256;
const MAX_SCAN_ROWS: usize = 1_024;

static DATABASE_HANDLES: LazyLock<Mutex<HashMap<PathBuf, Weak<Database>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

trait LocalClock: Send + Sync {
    fn now_unix_ms(&self) -> u64;
}

#[derive(Debug)]
struct SystemClock;

impl LocalClock for SystemClock {
    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    store_schema_version: u16,
    backend_expires_at_unix_ms: u64,
    record: CompressionSessionRecord,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLease {
    store_schema_version: u16,
    owner: [u8; 32],
    fence: u64,
    expires_at_unix_ms: u64,
}

/// Durable single-process compression state.
///
/// Clones share one canonical-path database handle. All synchronous redb work,
/// including open and initialization, runs on Tokio's blocking pool.
#[derive(Clone)]
pub struct LocalCompressionStore {
    database: Arc<Database>,
    canonical_path: Arc<PathBuf>,
    clock: Arc<dyn LocalClock>,
}

impl LocalCompressionStore {
    /// Open or create a Local store at an absolute database path.
    pub async fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::open_with_clock(path.as_ref().to_path_buf(), Arc::new(SystemClock)).await
    }

    /// Open from a synchronous pipeline-construction call while keeping redb
    /// work on Tokio's blocking pool.
    pub(crate) fn open_from_sync_context(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let opened = if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            handle.spawn_blocking(move || {
                let _ = sender.send(open_shared_database(path));
            });
            receiver.recv().map_err(|error| {
                anyhow::anyhow!("Local compression state open task failed: {error}")
            })?
        } else {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    anyhow::anyhow!("build Local compression state startup runtime: {error}")
                })?
                .block_on(async move {
                    tokio::task::spawn_blocking(move || open_shared_database(path))
                        .await
                        .map_err(|error| {
                            anyhow::anyhow!("Local compression state open task failed: {error}")
                        })?
                })
        }?;
        Ok(Self {
            database: opened.0,
            canonical_path: Arc::new(opened.1),
            clock: Arc::new(SystemClock),
        })
    }

    async fn open_with_clock(path: PathBuf, clock: Arc<dyn LocalClock>) -> anyhow::Result<Self> {
        let (database, canonical_path) =
            tokio::task::spawn_blocking(move || open_shared_database(path))
                .await
                .map_err(|error| {
                    anyhow::anyhow!("Local compression state open task failed: {error}")
                })??;
        Ok(Self {
            database,
            canonical_path: Arc::new(canonical_path),
            clock,
        })
    }

    /// Canonical database path used by this process.
    pub fn path(&self) -> &Path {
        self.canonical_path.as_path()
    }

    #[cfg(test)]
    fn shares_database_handle_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.database, &other.database)
    }

    #[cfg(test)]
    async fn set_next_fence_for_test(&self, fence: u64) -> Result<(), StoreError> {
        let database = self.database.clone();
        run_store_blocking(move || {
            let write = database
                .begin_write()
                .map_err(|_| StoreError::Unavailable)?;
            {
                let mut meta = write
                    .open_table(META)
                    .map_err(|_| StoreError::Unavailable)?;
                meta.insert(NEXT_FENCE_KEY, fence)
                    .map_err(|_| StoreError::Unavailable)?;
            }
            write.commit().map_err(|_| StoreError::Unavailable)
        })
        .await
    }

    #[cfg(test)]
    async fn insert_record_expirations_for_test(
        &self,
        rows: Vec<(u64, CompressionRecordId)>,
    ) -> Result<(), StoreError> {
        let database = self.database.clone();
        run_store_blocking(move || {
            let write = database
                .begin_write()
                .map_err(|_| StoreError::Unavailable)?;
            for (deadline, id) in rows {
                insert_expiration(&write, deadline, RECORD_EXPIRATION_KIND, id)?;
            }
            write.commit().map_err(|_| StoreError::Unavailable)
        })
        .await
    }

    #[cfg(test)]
    async fn expiration_count_for_test(&self) -> Result<usize, StoreError> {
        let database = self.database.clone();
        run_store_blocking(move || {
            let read = database.begin_read().map_err(|_| StoreError::Unavailable)?;
            let table = read
                .open_table(EXPIRATIONS)
                .map_err(|_| StoreError::Unavailable)?;
            let mut count = 0_usize;
            for entry in table.iter().map_err(|_| StoreError::Unavailable)? {
                entry.map_err(|_| StoreError::Unavailable)?;
                count = count.saturating_add(1);
            }
            Ok(count)
        })
        .await
    }

    #[cfg(test)]
    async fn insert_records_for_test(
        &self,
        rows: Vec<(CompressionRecordId, CompressionSessionRecord, u64)>,
    ) -> Result<(), StoreError> {
        let database = self.database.clone();
        run_store_blocking(move || {
            let write = database
                .begin_write()
                .map_err(|_| StoreError::Unavailable)?;
            for (id, mut record, expires_at) in rows {
                record.expires_at_unix_ms = expires_at;
                let stored = StoredRecord {
                    store_schema_version: STORE_SCHEMA_VERSION,
                    backend_expires_at_unix_ms: expires_at,
                    record,
                };
                let encoded = serde_json::to_vec(&stored).map_err(|_| StoreError::CorruptRecord)?;
                {
                    let mut records = write
                        .open_table(RECORDS)
                        .map_err(|_| StoreError::Unavailable)?;
                    records
                        .insert(id.as_bytes(), encoded.as_slice())
                        .map_err(|_| StoreError::Unavailable)?;
                }
                insert_expiration(&write, expires_at, RECORD_EXPIRATION_KIND, id)?;
            }
            write.commit().map_err(|_| StoreError::Unavailable)
        })
        .await
    }

    #[cfg(test)]
    async fn corrupt_record_for_test(&self, id: CompressionRecordId) -> Result<(), StoreError> {
        let database = self.database.clone();
        run_store_blocking(move || {
            let write = database
                .begin_write()
                .map_err(|_| StoreError::Unavailable)?;
            {
                let mut records = write
                    .open_table(RECORDS)
                    .map_err(|_| StoreError::Unavailable)?;
                records
                    .insert(id.as_bytes(), b"not-json".as_slice())
                    .map_err(|_| StoreError::Unavailable)?;
            }
            write.commit().map_err(|_| StoreError::Unavailable)
        })
        .await
    }
}

#[async_trait]
impl CompressionSessionStore for LocalCompressionStore {
    fn backend(&self) -> CompressionBackend {
        CompressionBackend::Local
    }

    fn consistency(&self) -> CompressionConsistency {
        CompressionConsistency::Serialized
    }

    async fn load(
        &self,
        id: &CompressionRecordId,
    ) -> Result<Option<CompressionSessionRecord>, StoreError> {
        let started = Instant::now();
        let database = self.database.clone();
        let id = *id;
        let raw_now = self.clock.now_unix_ms();
        let result = run_store_blocking(move || {
            let write = database
                .begin_write()
                .map_err(|_| StoreError::Unavailable)?;
            let now = prepare_transaction(&write, raw_now)?;
            let encoded = {
                let records = write
                    .open_table(RECORDS)
                    .map_err(|_| StoreError::Unavailable)?;
                let value = records
                    .get(id.as_bytes())
                    .map_err(|_| StoreError::Unavailable)?;
                value.map(|value| value.value().to_vec())
            };
            let result = match encoded {
                None => None,
                Some(encoded) => {
                    let stored = decode_record(&encoded)?;
                    if stored.backend_expires_at_unix_ms <= now {
                        remove_record(&write, id, Some(stored.backend_expires_at_unix_ms))?;
                        None
                    } else {
                        Some(record_with_backend_expiration(stored))
                    }
                }
            };
            write.commit().map_err(|_| StoreError::Unavailable)?;
            Ok(result)
        })
        .await;
        record_compression_state_operation(
            CompressionBackend::Local,
            CompressionStateOperation::Get,
            match &result {
                Ok(Some(_)) => CompressionStateOutcome::Ok,
                Ok(None) => CompressionStateOutcome::Missing,
                Err(_) => CompressionStateOutcome::Error,
            },
            started.elapsed(),
        );
        result
    }

    async fn acquire_update(
        &self,
        id: &CompressionRecordId,
        lease_ttl: Duration,
    ) -> Result<Option<UpdatePermit>, StoreError> {
        let lease_ttl_ms = duration_millis(lease_ttl).ok_or(StoreError::InvalidRequest)?;
        let database = self.database.clone();
        let id = *id;
        let raw_now = self.clock.now_unix_ms();
        let mut owner = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut owner);
        run_store_blocking(move || {
            let write = database
                .begin_write()
                .map_err(|_| StoreError::Unavailable)?;
            let now = prepare_transaction(&write, raw_now)?;
            let expires_at = now
                .checked_add(lease_ttl_ms)
                .ok_or(StoreError::InvalidRequest)?;
            let current = {
                let leases = write
                    .open_table(LEASES)
                    .map_err(|_| StoreError::Unavailable)?;
                let value = leases
                    .get(id.as_bytes())
                    .map_err(|_| StoreError::Unavailable)?;
                value.map(|value| value.value().to_vec())
            };
            if let Some(current) = current {
                let current = decode_lease(&current)?;
                if current.expires_at_unix_ms > now {
                    write.commit().map_err(|_| StoreError::Unavailable)?;
                    return Ok(None);
                }
                remove_lease(&write, id, Some(&current))?;
            }

            let fence = {
                let mut meta = write
                    .open_table(META)
                    .map_err(|_| StoreError::Unavailable)?;
                let previous = meta
                    .get(NEXT_FENCE_KEY)
                    .map_err(|_| StoreError::Unavailable)?
                    .map(|value| value.value())
                    .unwrap_or(0);
                let fence = previous.checked_add(1).ok_or(StoreError::Unavailable)?;
                meta.insert(NEXT_FENCE_KEY, fence)
                    .map_err(|_| StoreError::Unavailable)?;
                fence
            };
            let stored = StoredLease {
                store_schema_version: STORE_SCHEMA_VERSION,
                owner,
                fence,
                expires_at_unix_ms: expires_at,
            };
            let encoded = serde_json::to_vec(&stored).map_err(|_| StoreError::Unavailable)?;
            {
                let mut leases = write
                    .open_table(LEASES)
                    .map_err(|_| StoreError::Unavailable)?;
                leases
                    .insert(id.as_bytes(), encoded.as_slice())
                    .map_err(|_| StoreError::Unavailable)?;
            }
            insert_expiration(&write, expires_at, LEASE_EXPIRATION_KIND, id)?;
            write.commit().map_err(|_| StoreError::Unavailable)?;
            Ok(Some(UpdatePermit::new(
                id,
                CompressionBackend::Local,
                owner.to_vec(),
                fence,
            )))
        })
        .await
    }

    async fn commit(
        &self,
        permit: &UpdatePermit,
        expected_logical_version: Option<u64>,
        record: &CompressionSessionRecord,
        ttl: Duration,
    ) -> Result<(), CommitError> {
        let started = Instant::now();
        let ttl_ms = duration_millis(ttl).ok_or(CommitError::Serialization);
        let next_version = expected_logical_version
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(CommitError::Serialization);
        let preflight = match (ttl_ms, next_version) {
            (Ok(ttl_ms), Ok(next_version))
                if permit.backend() == CompressionBackend::Local
                    && permit.ownership_token().len() == 32
                    && record.schema_version == RECORD_SCHEMA_VERSION
                    && record.kind == RecordKind::Live
                    && record.logical_version == next_version
                    && record.parent_logical_version == expected_logical_version =>
            {
                Ok(ttl_ms)
            }
            _ => Err(CommitError::Serialization),
        };
        let result = match preflight {
            Err(error) => Err(error),
            Ok(ttl_ms) => {
                let database = self.database.clone();
                let raw_now = self.clock.now_unix_ms();
                let id = permit.record_id();
                let fence = permit.fence();
                let owner: [u8; 32] = permit
                    .ownership_token()
                    .try_into()
                    .map_err(|_| CommitError::Serialization)?;
                let mut candidate = record.clone();
                run_commit_blocking(move || {
                    let write = database
                        .begin_write()
                        .map_err(|_| CommitError::Unavailable)?;
                    let now =
                        prepare_transaction(&write, raw_now).map_err(store_to_commit_error)?;
                    let expires_at = now.checked_add(ttl_ms).ok_or(CommitError::Serialization)?;
                    let encoded_lease = {
                        let leases = write
                            .open_table(LEASES)
                            .map_err(|_| CommitError::Unavailable)?;
                        let value = leases
                            .get(id.as_bytes())
                            .map_err(|_| CommitError::Unavailable)?;
                        value.map(|value| value.value().to_vec())
                    };
                    let lease = encoded_lease
                        .as_deref()
                        .ok_or(CommitError::LeaseLost)
                        .and_then(|encoded| decode_lease(encoded).map_err(store_to_commit_error))?;
                    if lease.fence != fence {
                        return Err(CommitError::FenceRejected);
                    }
                    if lease.owner != owner || lease.expires_at_unix_ms <= now {
                        return Err(CommitError::LeaseLost);
                    }

                    let encoded_current = {
                        let records = write
                            .open_table(RECORDS)
                            .map_err(|_| CommitError::Unavailable)?;
                        let value = records
                            .get(id.as_bytes())
                            .map_err(|_| CommitError::Unavailable)?;
                        value.map(|value| value.value().to_vec())
                    };
                    let current = encoded_current
                        .as_deref()
                        .map(decode_record)
                        .transpose()
                        .map_err(store_to_commit_error)?;
                    let current_version = current
                        .as_ref()
                        .filter(|stored| stored.backend_expires_at_unix_ms > now)
                        .map(|stored| stored.record.logical_version);
                    if current_version != expected_logical_version {
                        return Err(CommitError::StaleVersion);
                    }
                    if let Some(current) = current.as_ref() {
                        remove_record(&write, id, Some(current.backend_expires_at_unix_ms))
                            .map_err(store_to_commit_error)?;
                    }

                    candidate.expires_at_unix_ms = expires_at;
                    let stored = StoredRecord {
                        store_schema_version: STORE_SCHEMA_VERSION,
                        backend_expires_at_unix_ms: expires_at,
                        record: candidate,
                    };
                    let encoded =
                        serde_json::to_vec(&stored).map_err(|_| CommitError::Serialization)?;
                    {
                        let mut records = write
                            .open_table(RECORDS)
                            .map_err(|_| CommitError::Unavailable)?;
                        records
                            .insert(id.as_bytes(), encoded.as_slice())
                            .map_err(|_| CommitError::Unavailable)?;
                    }
                    insert_expiration(&write, expires_at, RECORD_EXPIRATION_KIND, id)
                        .map_err(store_to_commit_error)?;
                    write.commit().map_err(|_| CommitError::Unavailable)
                })
                .await
            }
        };
        record_compression_state_operation(
            CompressionBackend::Local,
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
        if permit.backend() != CompressionBackend::Local || permit.ownership_token().len() != 32 {
            return Err(StoreError::InvalidRequest);
        }
        let owner: [u8; 32] = permit
            .ownership_token()
            .try_into()
            .map_err(|_| StoreError::InvalidRequest)?;
        let database = self.database.clone();
        let raw_now = self.clock.now_unix_ms();
        let id = permit.record_id();
        let fence = permit.fence();
        run_store_blocking(move || {
            let write = database
                .begin_write()
                .map_err(|_| StoreError::Unavailable)?;
            let now = prepare_transaction(&write, raw_now)?;
            let encoded = {
                let leases = write
                    .open_table(LEASES)
                    .map_err(|_| StoreError::Unavailable)?;
                let value = leases
                    .get(id.as_bytes())
                    .map_err(|_| StoreError::Unavailable)?;
                value.map(|value| value.value().to_vec())
            };
            if let Some(encoded) = encoded {
                let lease = decode_lease(&encoded)?;
                if lease.expires_at_unix_ms <= now || (lease.fence == fence && lease.owner == owner)
                {
                    remove_lease(&write, id, Some(&lease))?;
                }
            }
            write.commit().map_err(|_| StoreError::Unavailable)
        })
        .await
    }

    async fn list(&self, request: &ListRequest) -> Result<ListPage, StoreError> {
        let started = Instant::now();
        let result = validate_list_request(request).and_then(|()| {
            request
                .cursor
                .as_deref()
                .map(decode_cursor)
                .transpose()
                .map(|cursor| (cursor, request.clone()))
        });
        let result = match result {
            Err(error) => Err(error),
            Ok((cursor, request)) => {
                let database = self.database.clone();
                let raw_now = self.clock.now_unix_ms();
                run_store_blocking(move || {
                    let write = database
                        .begin_write()
                        .map_err(|_| StoreError::Unavailable)?;
                    prepare_transaction(&write, raw_now)?;
                    let wanted_origin = request.origin.as_deref().map(normalize_origin);
                    let mut records = Vec::with_capacity(usize::from(request.limit));
                    let mut scanned = 0_usize;
                    let mut last_scanned = None;
                    let mut stopped_early = false;
                    {
                        let table = write
                            .open_table(RECORDS)
                            .map_err(|_| StoreError::Unavailable)?;
                        let range = match cursor.as_ref() {
                            Some(cursor) => table.range::<&[u8; 32]>((Excluded(cursor), Unbounded)),
                            None => table.range::<&[u8; 32]>(..),
                        }
                        .map_err(|_| StoreError::Unavailable)?;
                        for entry in range {
                            if scanned == MAX_SCAN_ROWS {
                                stopped_early = true;
                                break;
                            }
                            let (key, value) = entry.map_err(|_| StoreError::Unavailable)?;
                            let id = record_id_from_bytes(*key.value())?;
                            let stored = decode_record(value.value())?;
                            scanned += 1;
                            last_scanned = Some(id);
                            let expired = stored.backend_expires_at_unix_ms
                                <= request.expiration_cutoff_unix_ms;
                            if request
                                .tenant_id
                                .as_ref()
                                .is_some_and(|tenant| stored.record.tenant_id != *tenant)
                                || wanted_origin
                                    .as_ref()
                                    .is_some_and(|origin| stored.record.origin != *origin)
                                || request.expired.is_some_and(|wanted| expired != wanted)
                                || request
                                    .conflict
                                    .is_some_and(|wanted| stored.record.conflict_detected != wanted)
                            {
                                continue;
                            }
                            let record = record_with_backend_expiration(stored);
                            records.push(CompressionRecordMetadata::from_record(
                                id,
                                CompressionBackend::Local,
                                CompressionConsistency::Serialized,
                                &record,
                            ));
                            if records.len() == usize::from(request.limit) {
                                stopped_early = true;
                                break;
                            }
                        }
                    }
                    write.commit().map_err(|_| StoreError::Unavailable)?;
                    let next_cursor = if stopped_early {
                        last_scanned.map(encode_cursor).transpose()?
                    } else {
                        None
                    };
                    Ok(ListPage {
                        records,
                        next_cursor,
                    })
                })
                .await
            }
        };
        record_compression_state_operation(
            CompressionBackend::Local,
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
        let database = self.database.clone();
        let raw_now = self.clock.now_unix_ms();
        let id = *id;
        let result = run_store_blocking(move || {
            let write = database
                .begin_write()
                .map_err(|_| StoreError::Unavailable)?;
            prepare_transaction(&write, raw_now)?;
            let encoded_record = {
                let records = write
                    .open_table(RECORDS)
                    .map_err(|_| StoreError::Unavailable)?;
                let value = records
                    .get(id.as_bytes())
                    .map_err(|_| StoreError::Unavailable)?;
                value.map(|value| value.value().to_vec())
            };
            let decoded_record = encoded_record
                .as_deref()
                .and_then(|encoded| decode_record(encoded).ok());
            remove_record(
                &write,
                id,
                decoded_record
                    .as_ref()
                    .map(|stored| stored.backend_expires_at_unix_ms),
            )?;

            let encoded_lease = {
                let leases = write
                    .open_table(LEASES)
                    .map_err(|_| StoreError::Unavailable)?;
                let value = leases
                    .get(id.as_bytes())
                    .map_err(|_| StoreError::Unavailable)?;
                value.map(|value| value.value().to_vec())
            };
            let decoded_lease = encoded_lease
                .as_deref()
                .and_then(|encoded| decode_lease(encoded).ok());
            remove_lease(&write, id, decoded_lease.as_ref())?;
            write.commit().map_err(|_| StoreError::Unavailable)?;
            Ok(DeleteResult {
                deleted: encoded_record.is_some(),
                logical_version: None,
            })
        })
        .await;
        record_compression_state_operation(
            CompressionBackend::Local,
            CompressionStateOperation::Delete,
            match &result {
                Ok(result) if result.deleted => CompressionStateOutcome::Ok,
                Ok(_) => CompressionStateOutcome::Missing,
                Err(_) => CompressionStateOutcome::Error,
            },
            started.elapsed(),
        );
        result
    }

    async fn purge(&self, request: &PurgeRequest) -> Result<PurgePage, StoreError> {
        let started = Instant::now();
        let validated = validate_purge_request(request).and_then(|()| {
            request
                .cursor
                .as_deref()
                .map(decode_cursor)
                .transpose()
                .map(|cursor| (cursor, request.clone()))
        });
        let result = match validated {
            Err(error) => Err(error),
            Ok((cursor, request)) => {
                let database = self.database.clone();
                let raw_now = self.clock.now_unix_ms();
                run_store_blocking(move || {
                    let write = database
                        .begin_write()
                        .map_err(|_| StoreError::Unavailable)?;
                    prepare_transaction(&write, raw_now)?;
                    let wanted_origin = request.origin.as_deref().map(normalize_origin);
                    let mut candidates = Vec::with_capacity(usize::from(request.limit));
                    let mut scanned = 0_usize;
                    let mut last_scanned = None;
                    let mut stopped_early = false;
                    {
                        let table = write
                            .open_table(RECORDS)
                            .map_err(|_| StoreError::Unavailable)?;
                        let range = match cursor.as_ref() {
                            Some(cursor) => table.range::<&[u8; 32]>((Excluded(cursor), Unbounded)),
                            None => table.range::<&[u8; 32]>(..),
                        }
                        .map_err(|_| StoreError::Unavailable)?;
                        for entry in range {
                            if scanned == MAX_SCAN_ROWS {
                                stopped_early = true;
                                break;
                            }
                            let (key, value) = entry.map_err(|_| StoreError::Unavailable)?;
                            let id = record_id_from_bytes(*key.value())?;
                            let stored = decode_record(value.value())?;
                            scanned += 1;
                            last_scanned = Some(id);
                            if request
                                .tenant_id
                                .as_ref()
                                .is_some_and(|tenant| stored.record.tenant_id != *tenant)
                                || wanted_origin
                                    .as_ref()
                                    .is_some_and(|origin| stored.record.origin != *origin)
                                || request.expired_before_unix_ms.is_some_and(|cutoff| {
                                    stored.backend_expires_at_unix_ms >= cutoff
                                })
                                || request
                                    .conflict
                                    .is_some_and(|wanted| stored.record.conflict_detected != wanted)
                            {
                                continue;
                            }
                            candidates.push((id, stored.backend_expires_at_unix_ms));
                            if candidates.len() == usize::from(request.limit) {
                                stopped_early = true;
                                break;
                            }
                        }
                    }
                    for (id, expires_at) in &candidates {
                        remove_record(&write, *id, Some(*expires_at))?;
                        let encoded_lease = {
                            let leases = write
                                .open_table(LEASES)
                                .map_err(|_| StoreError::Unavailable)?;
                            let value = leases
                                .get(id.as_bytes())
                                .map_err(|_| StoreError::Unavailable)?;
                            value.map(|value| value.value().to_vec())
                        };
                        let lease = encoded_lease
                            .as_deref()
                            .and_then(|encoded| decode_lease(encoded).ok());
                        remove_lease(&write, *id, lease.as_ref())?;
                    }
                    write.commit().map_err(|_| StoreError::Unavailable)?;
                    let next_cursor = if stopped_early {
                        last_scanned.map(encode_cursor).transpose()?
                    } else {
                        None
                    };
                    Ok(PurgePage {
                        deleted: candidates.len() as u64,
                        next_cursor,
                    })
                })
                .await
            }
        };
        record_compression_state_operation(
            CompressionBackend::Local,
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

fn open_shared_database(path: PathBuf) -> anyhow::Result<(Arc<Database>, PathBuf)> {
    anyhow::ensure!(
        path.is_absolute(),
        "Local compression state path must be absolute"
    );
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Local compression state path must name a file"))?
        .to_owned();
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Local compression state path must have a parent"))?;
    create_owner_only_directory(parent).map_err(|error| {
        anyhow::anyhow!(
            "create Local compression state directory {}: {error}",
            parent.display()
        )
    })?;
    enforce_owner_only_directory(parent).map_err(|error| {
        anyhow::anyhow!(
            "secure Local compression state directory {}: {error}",
            parent.display()
        )
    })?;
    let canonical_path = if path.exists() {
        std::fs::canonicalize(&path)
    } else {
        std::fs::canonicalize(parent).map(|parent| parent.join(file_name))
    }
    .map_err(|error| {
        anyhow::anyhow!(
            "resolve Local compression state path {}: {error}",
            path.display()
        )
    })?;
    enforce_owner_only_database_file(&canonical_path).map_err(|error| {
        anyhow::anyhow!(
            "secure Local compression state database {}: {error}",
            canonical_path.display()
        )
    })?;

    let mut handles = DATABASE_HANDLES
        .lock()
        .map_err(|_| anyhow::anyhow!("Local compression database handle cache poisoned"))?;
    handles.retain(|_, handle| handle.strong_count() > 0);
    if let Some(database) = handles.get(&canonical_path).and_then(Weak::upgrade) {
        return Ok((database, canonical_path));
    }

    let database = Arc::new(Database::create(&canonical_path).map_err(|error| {
        anyhow::anyhow!(
            "open Local compression state database {}: {error}",
            canonical_path.display()
        )
    })?);
    let write = database
        .begin_write()
        .map_err(|error| anyhow::anyhow!("initialize Local compression state: {error}"))?;
    write
        .open_table(RECORDS)
        .map_err(|error| anyhow::anyhow!("initialize Local record table: {error}"))?;
    write
        .open_table(LEASES)
        .map_err(|error| anyhow::anyhow!("initialize Local lease table: {error}"))?;
    write
        .open_table(EXPIRATIONS)
        .map_err(|error| anyhow::anyhow!("initialize Local expiration table: {error}"))?;
    {
        let mut meta = write
            .open_table(META)
            .map_err(|error| anyhow::anyhow!("initialize Local metadata table: {error}"))?;
        let configured_schema = meta
            .get(STORE_SCHEMA_KEY)
            .map_err(|error| anyhow::anyhow!("read Local store schema: {error}"))?
            .map(|value| value.value());
        match configured_schema {
            Some(version) if version != u64::from(STORE_SCHEMA_VERSION) => {
                anyhow::bail!("unsupported Local compression state store schema {version}");
            }
            Some(_) => {}
            None => {
                meta.insert(STORE_SCHEMA_KEY, u64::from(STORE_SCHEMA_VERSION))
                    .map_err(|error| anyhow::anyhow!("write Local store schema: {error}"))?;
                meta.insert(NEXT_FENCE_KEY, 0)
                    .map_err(|error| anyhow::anyhow!("initialize Local fence: {error}"))?;
                meta.insert(LAST_CLOCK_MS_KEY, 0)
                    .map_err(|error| anyhow::anyhow!("initialize Local clock: {error}"))?;
            }
        }
    }
    write.commit().map_err(|error| {
        anyhow::anyhow!("commit Local compression state initialization: {error}")
    })?;
    handles.insert(canonical_path.clone(), Arc::downgrade(&database));
    Ok((database, canonical_path))
}

#[cfg(unix)]
fn create_owner_only_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_owner_only_directory(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

#[cfg(unix)]
fn enforce_owner_only_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn enforce_owner_only_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn enforce_owner_only_database_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn enforce_owner_only_database_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

async fn run_store_blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| StoreError::Unavailable)?
}

async fn run_commit_blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, CommitError> + Send + 'static,
) -> Result<T, CommitError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| CommitError::Unavailable)?
}

fn prepare_transaction(write: &redb::WriteTransaction, raw_now: u64) -> Result<u64, StoreError> {
    let now = {
        let mut meta = write
            .open_table(META)
            .map_err(|_| StoreError::Unavailable)?;
        let previous = meta
            .get(LAST_CLOCK_MS_KEY)
            .map_err(|_| StoreError::Unavailable)?
            .map(|value| value.value())
            .unwrap_or(0);
        let now = previous.max(raw_now);
        if now != previous {
            meta.insert(LAST_CLOCK_MS_KEY, now)
                .map_err(|_| StoreError::Unavailable)?;
        }
        now
    };
    collect_expired(write, now)?;
    Ok(now)
}

fn collect_expired(write: &redb::WriteTransaction, now: u64) -> Result<(), StoreError> {
    let expired_keys = {
        let expirations = write
            .open_table(EXPIRATIONS)
            .map_err(|_| StoreError::Unavailable)?;
        let mut keys = Vec::with_capacity(MAX_GC_BATCH);
        for entry in expirations.iter().map_err(|_| StoreError::Unavailable)? {
            let (key, _) = entry.map_err(|_| StoreError::Unavailable)?;
            let key = *key.value();
            if expiration_deadline(&key) > now {
                break;
            }
            keys.push(key);
            if keys.len() == MAX_GC_BATCH {
                break;
            }
        }
        keys
    };

    for key in &expired_keys {
        let (deadline, kind, id) = decode_expiration_key(key)?;
        match kind {
            RECORD_EXPIRATION_KIND => {
                let encoded = {
                    let records = write
                        .open_table(RECORDS)
                        .map_err(|_| StoreError::Unavailable)?;
                    let value = records
                        .get(id.as_bytes())
                        .map_err(|_| StoreError::Unavailable)?;
                    value.map(|value| value.value().to_vec())
                };
                let remove = encoded.as_deref().is_some_and(|encoded| {
                    decode_record(encoded)
                        .map(|record| record.backend_expires_at_unix_ms == deadline)
                        .unwrap_or(true)
                });
                if remove {
                    let mut records = write
                        .open_table(RECORDS)
                        .map_err(|_| StoreError::Unavailable)?;
                    records
                        .remove(id.as_bytes())
                        .map_err(|_| StoreError::Unavailable)?;
                }
            }
            LEASE_EXPIRATION_KIND => {
                let encoded = {
                    let leases = write
                        .open_table(LEASES)
                        .map_err(|_| StoreError::Unavailable)?;
                    let value = leases
                        .get(id.as_bytes())
                        .map_err(|_| StoreError::Unavailable)?;
                    value.map(|value| value.value().to_vec())
                };
                let remove = encoded.as_deref().is_some_and(|encoded| {
                    decode_lease(encoded)
                        .map(|lease| lease.expires_at_unix_ms == deadline)
                        .unwrap_or(true)
                });
                if remove {
                    let mut leases = write
                        .open_table(LEASES)
                        .map_err(|_| StoreError::Unavailable)?;
                    leases
                        .remove(id.as_bytes())
                        .map_err(|_| StoreError::Unavailable)?;
                }
            }
            _ => return Err(StoreError::CorruptRecord),
        }
    }
    if !expired_keys.is_empty() {
        let mut expirations = write
            .open_table(EXPIRATIONS)
            .map_err(|_| StoreError::Unavailable)?;
        for key in expired_keys {
            expirations
                .remove(&key)
                .map_err(|_| StoreError::Unavailable)?;
        }
    }
    Ok(())
}

fn insert_expiration(
    write: &redb::WriteTransaction,
    deadline: u64,
    kind: u8,
    id: CompressionRecordId,
) -> Result<(), StoreError> {
    let key = expiration_key(deadline, kind, id);
    let mut expirations = write
        .open_table(EXPIRATIONS)
        .map_err(|_| StoreError::Unavailable)?;
    expirations
        .insert(&key, ())
        .map_err(|_| StoreError::Unavailable)?;
    Ok(())
}

fn remove_expiration(
    write: &redb::WriteTransaction,
    deadline: u64,
    kind: u8,
    id: CompressionRecordId,
) -> Result<(), StoreError> {
    let key = expiration_key(deadline, kind, id);
    let mut expirations = write
        .open_table(EXPIRATIONS)
        .map_err(|_| StoreError::Unavailable)?;
    expirations
        .remove(&key)
        .map_err(|_| StoreError::Unavailable)?;
    Ok(())
}

fn remove_record(
    write: &redb::WriteTransaction,
    id: CompressionRecordId,
    expires_at: Option<u64>,
) -> Result<(), StoreError> {
    {
        let mut records = write
            .open_table(RECORDS)
            .map_err(|_| StoreError::Unavailable)?;
        records
            .remove(id.as_bytes())
            .map_err(|_| StoreError::Unavailable)?;
    }
    if let Some(expires_at) = expires_at {
        remove_expiration(write, expires_at, RECORD_EXPIRATION_KIND, id)?;
    }
    Ok(())
}

fn remove_lease(
    write: &redb::WriteTransaction,
    id: CompressionRecordId,
    stored: Option<&StoredLease>,
) -> Result<(), StoreError> {
    {
        let mut leases = write
            .open_table(LEASES)
            .map_err(|_| StoreError::Unavailable)?;
        leases
            .remove(id.as_bytes())
            .map_err(|_| StoreError::Unavailable)?;
    }
    if let Some(stored) = stored {
        remove_expiration(write, stored.expires_at_unix_ms, LEASE_EXPIRATION_KIND, id)?;
    }
    Ok(())
}

fn decode_record(encoded: &[u8]) -> Result<StoredRecord, StoreError> {
    let stored =
        serde_json::from_slice::<StoredRecord>(encoded).map_err(|_| StoreError::CorruptRecord)?;
    if stored.store_schema_version != STORE_SCHEMA_VERSION
        || stored.record.schema_version != RECORD_SCHEMA_VERSION
    {
        return Err(StoreError::UnsupportedSchema);
    }
    Ok(stored)
}

fn decode_lease(encoded: &[u8]) -> Result<StoredLease, StoreError> {
    let stored =
        serde_json::from_slice::<StoredLease>(encoded).map_err(|_| StoreError::CorruptRecord)?;
    if stored.store_schema_version != STORE_SCHEMA_VERSION || stored.fence == 0 {
        return Err(StoreError::UnsupportedSchema);
    }
    Ok(stored)
}

fn record_with_backend_expiration(mut stored: StoredRecord) -> CompressionSessionRecord {
    stored.record.expires_at_unix_ms = stored.backend_expires_at_unix_ms;
    stored.record
}

fn duration_millis(duration: Duration) -> Option<u64> {
    let millis = u64::try_from(duration.as_millis()).ok()?;
    (millis > 0).then_some(millis)
}

fn expiration_key(deadline: u64, kind: u8, id: CompressionRecordId) -> [u8; 41] {
    let mut key = [0_u8; 41];
    key[..8].copy_from_slice(&deadline.to_be_bytes());
    key[8] = kind;
    key[9..].copy_from_slice(id.as_bytes());
    key
}

fn expiration_deadline(key: &[u8; 41]) -> u64 {
    u64::from_be_bytes(key[..8].try_into().expect("fixed-width expiration key"))
}

fn decode_expiration_key(key: &[u8; 41]) -> Result<(u64, u8, CompressionRecordId), StoreError> {
    let deadline = expiration_deadline(key);
    let kind = key[8];
    let id = record_id_from_bytes(key[9..].try_into().map_err(|_| StoreError::CorruptRecord)?)?;
    Ok((deadline, kind, id))
}

fn record_id_from_bytes(bytes: [u8; 32]) -> Result<CompressionRecordId, StoreError> {
    hex::encode(bytes)
        .parse()
        .map_err(|_| StoreError::CorruptRecord)
}

fn encode_cursor(id: CompressionRecordId) -> Result<String, StoreError> {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_bytes());
    if encoded.len() > MAX_CURSOR_BYTES {
        return Err(StoreError::InvalidCursor);
    }
    Ok(encoded)
}

fn decode_cursor(encoded: &str) -> Result<[u8; 32], StoreError> {
    if encoded.len() > MAX_CURSOR_BYTES {
        return Err(StoreError::InvalidCursor);
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| StoreError::InvalidCursor)?;
    decoded.try_into().map_err(|_| StoreError::InvalidCursor)
}

fn validate_list_request(request: &ListRequest) -> Result<(), StoreError> {
    if request
        .tenant_id
        .as_ref()
        .is_some_and(|tenant| tenant.trim().is_empty())
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

fn validate_purge_request(request: &PurgeRequest) -> Result<(), StoreError> {
    if request
        .tenant_id
        .as_ref()
        .is_some_and(|tenant| tenant.trim().is_empty())
        || request
            .origin
            .as_ref()
            .is_some_and(|origin| origin.trim().is_empty())
        || request.expired_before_unix_ms == Some(0)
        || !(1..=MAX_ADMIN_PAGE_SIZE).contains(&request.limit)
    {
        return Err(StoreError::InvalidRequest);
    }
    Ok(())
}

fn store_to_commit_error(error: StoreError) -> CommitError {
    match error {
        StoreError::Unavailable => CommitError::Unavailable,
        StoreError::CorruptRecord
        | StoreError::InvalidCursor
        | StoreError::InvalidRequest
        | StoreError::UnsupportedSchema => CommitError::Serialization,
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalClock, LocalCompressionStore};
    use base64::Engine;
    use sbproxy_ai::compression::{
        CommitError, CompressionBackend, CompressionConsistency, CompressionRecordId,
        CompressionSessionRecord, CompressionSessionStore, ListRequest, MessageDigest,
        PurgeRequest, RecordKind, StoreError, UpdatePermit, RECORD_SCHEMA_VERSION,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Debug)]
    struct TestClock(AtomicU64);

    impl TestClock {
        fn new(now: u64) -> Self {
            Self(AtomicU64::new(now))
        }

        fn set(&self, now: u64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl LocalClock for TestClock {
        fn now_unix_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn id(seed: u8) -> CompressionRecordId {
        CompressionRecordId::derive("tenant-a", "api.example.com", [seed; 16])
    }

    fn record(version: u64) -> CompressionSessionRecord {
        CompressionSessionRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            logical_version: version,
            tenant_id: "tenant-a".to_string(),
            origin: "api.example.com".to_string(),
            summary: "sensitive summary".to_string(),
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
            updated_at_unix_ms: 2_000,
            expires_at_unix_ms: 60_000,
            kind: RecordKind::Live,
        }
    }

    async fn store() -> (tempfile::TempDir, LocalCompressionStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalCompressionStore::open(dir.path().join("compression.redb"))
            .await
            .expect("open Local store");
        (dir, store)
    }

    async fn store_with_clock(
        now: u64,
    ) -> (tempfile::TempDir, Arc<TestClock>, LocalCompressionStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = Arc::new(TestClock::new(now));
        let store = LocalCompressionStore::open_with_clock(
            dir.path().join("compression.redb"),
            clock.clone(),
        )
        .await
        .expect("open Local store");
        (dir, clock, store)
    }

    async fn put(
        store: &LocalCompressionStore,
        id: CompressionRecordId,
        expected: Option<u64>,
        record: &CompressionSessionRecord,
        ttl: Duration,
    ) {
        let permit = store
            .acquire_update(&id, Duration::from_secs(5))
            .await
            .unwrap()
            .expect("writer permit");
        store.commit(&permit, expected, record, ttl).await.unwrap();
        store.release(permit).await.unwrap();
    }

    #[tokio::test]
    async fn reports_local_serialized_identity_and_reuses_one_database_handle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("compression.redb");
        let first = LocalCompressionStore::open(&path).await.unwrap();
        let second = LocalCompressionStore::open(&path).await.unwrap();

        assert_eq!(first.backend(), CompressionBackend::Local);
        assert_eq!(first.consistency(), CompressionConsistency::Serialized);
        assert!(first.shares_database_handle_with(&second));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn creates_and_tightens_owner_only_database_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("state");
        let path = parent.join("compression.redb");
        let store = LocalCompressionStore::open(&path).await.unwrap();
        drop(store);

        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let reopened = LocalCompressionStore::open(&path).await.unwrap();
        drop(reopened);

        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn rejects_invalid_lease_ttl_and_serializes_writers() {
        let (_dir, store) = store().await;
        let record_id = id(1);

        assert!(matches!(
            store.acquire_update(&record_id, Duration::ZERO).await,
            Err(StoreError::InvalidRequest)
        ));
        let first = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .expect("first writer");
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

    #[tokio::test]
    async fn commit_requires_matching_permit_version_and_parent() {
        let (_dir, store) = store().await;
        let record_id = id(2);
        let permit = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();

        let wrong_backend = UpdatePermit::new(
            record_id,
            CompressionBackend::Redis,
            permit.ownership_token().to_vec(),
            permit.fence(),
        );
        assert_eq!(
            store
                .commit(&wrong_backend, None, &record(1), Duration::from_secs(60))
                .await,
            Err(CommitError::Serialization)
        );

        let mut wrong_parent = record(1);
        wrong_parent.parent_logical_version = Some(9);
        assert_eq!(
            store
                .commit(&permit, None, &wrong_parent, Duration::from_secs(60))
                .await,
            Err(CommitError::Serialization)
        );
        store
            .commit(&permit, None, &record(1), Duration::from_secs(60))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stale_cas_delete_invalidation_and_fences_are_monotonic() {
        let (_dir, store) = store().await;
        let record_id = id(3);
        let first = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        store
            .commit(&first, None, &record(1), Duration::from_secs(60))
            .await
            .unwrap();
        store.release(first).await.unwrap();

        let stale = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store
                .commit(&stale, None, &record(1), Duration::from_secs(60))
                .await,
            Err(CommitError::StaleVersion)
        );
        let stale_fence = stale.fence();
        assert!(store.delete(&record_id).await.unwrap().deleted);
        assert_eq!(
            store
                .commit(&stale, Some(1), &record(2), Duration::from_secs(60))
                .await,
            Err(CommitError::LeaseLost)
        );
        let next = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        assert!(next.fence() > stale_fence);
    }

    #[tokio::test]
    async fn fence_and_version_overflow_fail_closed() {
        let (_dir, store) = store().await;
        store.set_next_fence_for_test(u64::MAX).await.unwrap();
        assert!(matches!(
            store.acquire_update(&id(4), Duration::from_secs(5)).await,
            Err(StoreError::Unavailable)
        ));

        let forged = UpdatePermit::new(id(5), CompressionBackend::Local, vec![7; 32], 1);
        assert_eq!(
            store
                .commit(
                    &forged,
                    Some(u64::MAX),
                    &record(u64::MAX),
                    Duration::from_secs(60)
                )
                .await,
            Err(CommitError::Serialization)
        );
    }

    #[tokio::test]
    async fn record_and_crash_held_lease_ttls_survive_reopen() {
        let (dir, clock, store) = store_with_clock(10_000).await;
        let path = dir.path().join("compression.redb");
        let record_id = id(10);
        let permit = store
            .acquire_update(&record_id, Duration::from_millis(100))
            .await
            .unwrap()
            .unwrap();
        store
            .commit(&permit, None, &record(1), Duration::from_millis(200))
            .await
            .unwrap();
        drop(permit);
        drop(store);

        let reopened = LocalCompressionStore::open_with_clock(path, clock.clone())
            .await
            .unwrap();
        assert!(reopened.load(&record_id).await.unwrap().is_some());
        assert!(reopened
            .acquire_update(&record_id, Duration::from_millis(100))
            .await
            .unwrap()
            .is_none());

        clock.set(10_100);
        assert!(reopened
            .acquire_update(&record_id, Duration::from_millis(100))
            .await
            .unwrap()
            .is_some());
        clock.set(10_200);
        assert!(reopened.load(&record_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn persisted_clock_prevents_backward_time_from_reviving_ttls() {
        let (dir, clock, store) = store_with_clock(50_000).await;
        let path = dir.path().join("compression.redb");
        let record_id = id(11);
        let _crash_held = store
            .acquire_update(&record_id, Duration::from_millis(100))
            .await
            .unwrap()
            .unwrap();
        drop(store);

        clock.set(40_000);
        let reopened = LocalCompressionStore::open_with_clock(path, clock.clone())
            .await
            .unwrap();
        assert!(reopened
            .acquire_update(&record_id, Duration::from_millis(100))
            .await
            .unwrap()
            .is_none());
        clock.set(50_100);
        assert!(reopened
            .acquire_update(&record_id, Duration::from_millis(100))
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn expiration_gc_is_bounded_and_update_churn_replaces_old_index_rows() {
        let (_dir, _clock, store) = store_with_clock(1_000).await;
        let expirations = (0..300_u16)
            .map(|seed| {
                let mut session = [0_u8; 16];
                session[..2].copy_from_slice(&seed.to_be_bytes());
                (
                    999,
                    CompressionRecordId::derive("tenant-gc", "api.example.com", session),
                )
            })
            .collect();
        store
            .insert_record_expirations_for_test(expirations)
            .await
            .unwrap();
        assert_eq!(store.expiration_count_for_test().await.unwrap(), 300);

        store.load(&id(12)).await.unwrap();
        assert_eq!(
            store.expiration_count_for_test().await.unwrap(),
            44,
            "one operation collects no more than the 256-row batch"
        );
        store.load(&id(12)).await.unwrap();
        assert_eq!(store.expiration_count_for_test().await.unwrap(), 0);

        let record_id = id(13);
        for version in 1..=25 {
            put(
                &store,
                record_id,
                (version > 1).then_some(version - 1),
                &record(version),
                Duration::from_secs(60 + version),
            )
            .await;
        }
        assert_eq!(
            store.expiration_count_for_test().await.unwrap(),
            1,
            "record and released-lease churn leaves only the live record index"
        );
    }

    #[tokio::test]
    async fn list_is_metadata_only_exclusive_and_capped_at_one_thousand_twenty_four_scans() {
        let (_dir, _clock, store) = store_with_clock(1_000).await;
        put(&store, id(20), None, &record(1), Duration::from_secs(60)).await;
        put(&store, id(21), None, &record(1), Duration::from_secs(60)).await;
        let request = ListRequest {
            tenant_id: Some("tenant-a".to_string()),
            origin: Some("API.EXAMPLE.COM.".to_string()),
            expired: Some(false),
            expiration_cutoff_unix_ms: 1_000,
            conflict: Some(false),
            cursor: None,
            limit: 1,
        };
        let first = store.list(&request).await.unwrap();
        assert_eq!(first.records.len(), 1);
        let encoded = serde_json::to_string(&first.records).unwrap();
        assert!(!encoded.contains("sensitive summary"));
        let second = store
            .list(&ListRequest {
                cursor: first.next_cursor,
                ..request
            })
            .await
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert_ne!(first.records[0].id, second.records[0].id);

        let future_cutoff = store
            .list(&ListRequest {
                tenant_id: Some("tenant-a".to_string()),
                origin: None,
                expired: Some(true),
                expiration_cutoff_unix_ms: 100_000,
                conflict: None,
                cursor: None,
                limit: 10,
            })
            .await
            .unwrap();
        assert_eq!(
            future_cutoff.records.len(),
            2,
            "expiration classification uses the requested cutoff, not wall clock"
        );

        let rows = (0..1_025_u16)
            .map(|seed| {
                let mut session = [0_u8; 16];
                session[..2].copy_from_slice(&seed.to_be_bytes());
                let id = CompressionRecordId::derive("tenant-scan", "scan.example.com", session);
                let mut record = record(1);
                record.tenant_id = "tenant-scan".to_string();
                record.origin = "scan.example.com".to_string();
                (id, record, 100_000)
            })
            .collect();
        store.insert_records_for_test(rows).await.unwrap();
        let capped_request = ListRequest {
            tenant_id: Some("does-not-match".to_string()),
            origin: None,
            expired: None,
            expiration_cutoff_unix_ms: 0,
            conflict: None,
            cursor: None,
            limit: 500,
        };
        let capped = store.list(&capped_request).await.unwrap();
        assert!(capped.records.is_empty());
        assert!(
            capped.next_cursor.is_some(),
            "the 1024-row work cap returns a lossless continuation"
        );
        let final_page = store
            .list(&ListRequest {
                cursor: capped.next_cursor,
                ..capped_request
            })
            .await
            .unwrap();
        assert!(final_page.records.is_empty());
        assert!(final_page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn admin_bounds_and_fixed_width_cursor_fail_closed() {
        let (_dir, _clock, store) = store_with_clock(1_000).await;
        let base = ListRequest {
            tenant_id: None,
            origin: None,
            expired: None,
            expiration_cutoff_unix_ms: 0,
            conflict: None,
            cursor: None,
            limit: 500,
        };
        assert_eq!(
            store
                .list(&ListRequest {
                    limit: 501,
                    ..base.clone()
                })
                .await,
            Err(StoreError::InvalidRequest)
        );
        assert_eq!(
            store
                .list(&ListRequest {
                    cursor: Some("a".repeat(129)),
                    ..base.clone()
                })
                .await,
            Err(StoreError::InvalidCursor)
        );
        let short_cursor = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0_u8; 31]);
        assert_eq!(
            store
                .list(&ListRequest {
                    cursor: Some(short_cursor),
                    ..base
                })
                .await,
            Err(StoreError::InvalidCursor)
        );
    }

    #[tokio::test]
    async fn scoped_purge_preserves_other_tenants_and_corrupt_bytes_remain_deletable() {
        let (_dir, _clock, store) = store_with_clock(1_000).await;
        let tenant_a = id(30);
        let tenant_b = id(31);
        put(&store, tenant_a, None, &record(1), Duration::from_secs(60)).await;
        let mut other = record(1);
        other.tenant_id = "tenant-b".to_string();
        put(&store, tenant_b, None, &other, Duration::from_secs(60)).await;
        let purged = store
            .purge(&PurgeRequest {
                tenant_id: Some("tenant-a".to_string()),
                origin: None,
                expired_before_unix_ms: None,
                conflict: None,
                cursor: None,
                limit: 500,
            })
            .await
            .unwrap();
        assert_eq!(purged.deleted, 1);
        assert!(store.load(&tenant_a).await.unwrap().is_none());
        assert!(store.load(&tenant_b).await.unwrap().is_some());

        let corrupt = id(32);
        store.corrupt_record_for_test(corrupt).await.unwrap();
        assert_eq!(store.load(&corrupt).await, Err(StoreError::CorruptRecord));
        assert!(store.delete(&corrupt).await.unwrap().deleted);
        assert!(store.load(&corrupt).await.unwrap().is_none());
    }
}
