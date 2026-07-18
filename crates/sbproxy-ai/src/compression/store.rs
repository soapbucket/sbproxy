//! Backend-neutral external summary-state contract.

use crate::compression::{
    CompressionBackend, CompressionRecordId, CompressionSessionRecord, RecordKind,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// Concurrency semantics exposed by an external state adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionConsistency {
    /// Updates are lease-serialized and compare-and-set by logical version.
    Serialized,
    /// Replicas converge through deterministic last-writer-wins merging.
    EventualLww,
}

/// Bounded ownership proof returned by a state adapter.
pub struct UpdatePermit {
    record_id: CompressionRecordId,
    backend: CompressionBackend,
    ownership_token: Vec<u8>,
    fence: u64,
}

impl UpdatePermit {
    /// Construct an adapter-owned permit with an opaque ownership token.
    pub fn new(
        record_id: CompressionRecordId,
        backend: CompressionBackend,
        ownership_token: Vec<u8>,
        fence: u64,
    ) -> Self {
        Self {
            record_id,
            backend,
            ownership_token,
            fence,
        }
    }

    /// Opaque record protected by this permit.
    pub const fn record_id(&self) -> CompressionRecordId {
        self.record_id
    }

    /// Backend that issued this permit.
    pub const fn backend(&self) -> CompressionBackend {
        self.backend
    }

    /// Adapter-private ownership proof used for release and commit scripts.
    pub fn ownership_token(&self) -> &[u8] {
        &self.ownership_token
    }

    /// Monotonic fencing value, or zero for adapters without fencing.
    pub const fn fence(&self) -> u64 {
        self.fence
    }
}

impl fmt::Debug for UpdatePermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdatePermit")
            .field("record_id", &"<opaque>")
            .field("backend", &self.backend)
            .field("ownership_token", &"<redacted>")
            .field("fence", &self.fence)
            .finish()
    }
}

/// Content-free projection returned by administrative listing APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionRecordMetadata {
    /// Opaque externally safe record identifier.
    pub id: CompressionRecordId,
    /// Adapter that currently holds the record.
    pub backend: CompressionBackend,
    /// Adapter concurrency model.
    pub consistency: CompressionConsistency,
    /// External record serialization schema.
    pub schema_version: u16,
    /// Tenant boundary used for authorization and filtering.
    pub tenant_id: String,
    /// Normalized AI handler hostname.
    pub origin: String,
    /// Monotonic record version.
    pub logical_version: u64,
    /// Number of leading messages protected verbatim.
    pub protected_prefix_count: usize,
    /// Number of original history messages represented by the record.
    pub covered_history_count: usize,
    /// Target-model tokens represented by the covered history.
    pub covered_input_tokens: u64,
    /// Bounded generated output token count, without generated content.
    pub summary_tokens: u64,
    /// Configured internal provider name.
    pub summarizer_provider: String,
    /// Configured internal model name.
    pub summarizer_model: String,
    /// Stable writer identity.
    pub writer_node: String,
    /// Whether an eventual merge observed competing children.
    pub conflict_detected: bool,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_unix_ms: u64,
    /// Last update timestamp in Unix milliseconds.
    pub updated_at_unix_ms: u64,
    /// Backend expiration timestamp in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Live state or deletion tombstone.
    pub kind: RecordKind,
}

impl CompressionRecordMetadata {
    /// Project a content-bearing record into a safe administrative shape.
    pub fn from_record(
        id: CompressionRecordId,
        backend: CompressionBackend,
        consistency: CompressionConsistency,
        record: &CompressionSessionRecord,
    ) -> Self {
        Self {
            id,
            backend,
            consistency,
            schema_version: record.schema_version,
            tenant_id: record.tenant_id.clone(),
            origin: record.origin.clone(),
            logical_version: record.logical_version,
            protected_prefix_count: record.protected_prefix_count,
            covered_history_count: record.covered_history_count,
            covered_input_tokens: record.covered_input_tokens,
            summary_tokens: record.summary_tokens,
            summarizer_provider: record.summarizer_provider.clone(),
            summarizer_model: record.summarizer_model.clone(),
            writer_node: record.writer_node.clone(),
            conflict_detected: record.conflict_detected,
            created_at_unix_ms: record.created_at_unix_ms,
            updated_at_unix_ms: record.updated_at_unix_ms,
            expires_at_unix_ms: record.expires_at_unix_ms,
            kind: record.kind,
        }
    }
}

/// Bounded metadata scan request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRequest {
    /// Optional tenant boundary.
    pub tenant_id: Option<String>,
    /// Optional normalized-origin filter.
    pub origin: Option<String>,
    /// Optional expired (`true`) or active (`false`) filter.
    pub expired: Option<bool>,
    /// Timestamp used by [`Self::expired`], in Unix milliseconds.
    pub expiration_cutoff_unix_ms: u64,
    /// Optional eventual-convergence conflict filter.
    pub conflict: Option<bool>,
    /// Adapter-issued opaque cursor.
    pub cursor: Option<String>,
    /// Maximum records returned in one page.
    pub limit: u16,
}

/// One bounded metadata page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPage {
    /// Content-free records.
    pub records: Vec<CompressionRecordMetadata>,
    /// Opaque continuation cursor.
    pub next_cursor: Option<String>,
}

/// Bounded explicitly scoped purge request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeRequest {
    /// Optional tenant boundary.
    pub tenant_id: Option<String>,
    /// Optional normalized-origin filter.
    pub origin: Option<String>,
    /// Optional exclusive upper expiration timestamp in Unix milliseconds.
    pub expired_before_unix_ms: Option<u64>,
    /// Optional eventual-convergence conflict filter.
    pub conflict: Option<bool>,
    /// Adapter-issued opaque cursor.
    pub cursor: Option<String>,
    /// Maximum records deleted in one call.
    pub limit: u16,
}

/// One bounded purge result page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgePage {
    /// Records deleted or tombstoned in this page.
    pub deleted: u64,
    /// Opaque continuation cursor.
    pub next_cursor: Option<String>,
}

/// Result of deleting one opaque record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteResult {
    /// Whether live state existed and was removed or tombstoned.
    pub deleted: bool,
    /// Logical version written by a tombstone-capable adapter.
    pub logical_version: Option<u64>,
}

/// Sanitized state read, coordination, or administration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The configured external state dependency is unavailable.
    #[error("compression state unavailable")]
    Unavailable,
    /// Stored bytes are invalid or fail integrity checks.
    #[error("invalid compression state record")]
    CorruptRecord,
    /// A pagination cursor is invalid or expired.
    #[error("invalid compression state cursor")]
    InvalidCursor,
    /// Stored data uses an unsupported schema version.
    #[error("unsupported compression state schema")]
    UnsupportedSchema,
    /// A bounded administrative request is invalid.
    #[error("invalid compression state request")]
    InvalidRequest,
}

/// Sanitized conditional-write failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CommitError {
    /// The configured external state dependency is unavailable.
    #[error("compression state unavailable")]
    Unavailable,
    /// Permit ownership expired or changed before the write.
    #[error("compression state lease lost")]
    LeaseLost,
    /// The expected logical version is no longer current.
    #[error("compression state version changed")]
    StaleVersion,
    /// A stale writer was rejected by the backend fence.
    #[error("compression state fence rejected")]
    FenceRejected,
    /// The record could not be serialized safely.
    #[error("compression state serialization failed")]
    Serialization,
}

/// External canonical summary-state operations used by request and admin paths.
#[async_trait]
pub trait CompressionSessionStore: Send + Sync {
    /// Stable backend label.
    fn backend(&self) -> CompressionBackend;

    /// Concurrency and convergence semantics.
    fn consistency(&self) -> CompressionConsistency;

    /// Load the current live record or tombstone.
    async fn load(
        &self,
        id: &CompressionRecordId,
    ) -> Result<Option<CompressionSessionRecord>, StoreError>;

    /// Acquire a bounded update permit without waiting indefinitely.
    async fn acquire_update(
        &self,
        id: &CompressionRecordId,
        lease_ttl: Duration,
    ) -> Result<Option<UpdatePermit>, StoreError>;

    /// Conditionally commit a record and its backend TTL.
    async fn commit(
        &self,
        permit: &UpdatePermit,
        expected_logical_version: Option<u64>,
        record: &CompressionSessionRecord,
        ttl: Duration,
    ) -> Result<(), CommitError>;

    /// Best-effort release of a permit after every request path.
    async fn release(&self, permit: UpdatePermit) -> Result<(), StoreError>;

    /// List a bounded tenant-scoped page without returning summary content.
    async fn list(&self, request: &ListRequest) -> Result<ListPage, StoreError>;

    /// Delete or tombstone one opaque record.
    async fn delete(&self, id: &CompressionRecordId) -> Result<DeleteResult, StoreError>;

    /// Delete or tombstone one bounded tenant-scoped page.
    async fn purge(&self, request: &PurgeRequest) -> Result<PurgePage, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::{CompressionRecordMetadata, UpdatePermit};
    use crate::compression::{
        CompressionBackend, CompressionRecordId, CompressionSessionRecord, MessageDigest,
        RecordKind, RECORD_SCHEMA_VERSION,
    };
    use serde_json::json;

    fn record() -> CompressionSessionRecord {
        CompressionSessionRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            logical_version: 4,
            tenant_id: "tenant-a".to_string(),
            origin: "api.example.com".to_string(),
            summary: "sensitive historical summary".to_string(),
            protected_prefix_count: 1,
            protected_prefix_digest: MessageDigest::for_messages(&[
                json!({"role": "system", "content": "protected"}),
            ]),
            covered_history_count: 6,
            covered_history_digest: MessageDigest::for_messages(&[
                json!({"role": "user", "content": "history"}),
            ]),
            covered_input_tokens: 300,
            summary_tokens: 40,
            summarizer_provider: "anthropic".to_string(),
            summarizer_model: "summary-model".to_string(),
            writer_node: "node-a".to_string(),
            parent_logical_version: Some(3),
            conflict_detected: false,
            created_at_unix_ms: 1_000,
            updated_at_unix_ms: 2_000,
            expires_at_unix_ms: 3_000,
            kind: RecordKind::Live,
        }
    }

    #[test]
    fn metadata_projection_never_contains_summary_content() {
        let id = CompressionRecordId::derive("tenant-a", "api.example.com", [9; 16]);
        let metadata = CompressionRecordMetadata::from_record(
            id,
            CompressionBackend::Redis,
            super::CompressionConsistency::Serialized,
            &record(),
        );

        let encoded = serde_json::to_string(&metadata).unwrap();
        assert!(!encoded.contains("sensitive historical summary"));
        assert!(!encoded.contains("summary\""));
        assert!(!encoded.contains("session_id"));
        assert_eq!(metadata.id, id);
        assert_eq!(metadata.schema_version, RECORD_SCHEMA_VERSION);
        assert_eq!(metadata.logical_version, 4);
        assert_eq!(metadata.covered_history_count, 6);
    }

    #[test]
    fn update_permit_debug_redacts_ownership_token() {
        let id = CompressionRecordId::derive("tenant-a", "api.example.com", [9; 16]);
        let permit = UpdatePermit::new(id, CompressionBackend::Redis, b"lease-secret".to_vec(), 7);
        let rendered = format!("{permit:?}");

        assert!(!rendered.contains("lease-secret"));
        assert!(!rendered.contains(&id.to_string()));
        assert!(rendered.contains("Redis"));
        assert_eq!(permit.fence(), 7);
    }
}
