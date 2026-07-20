//! Ordered AI context-compression policies and execution.

/// Deterministic compact serialization of marked JSON chunks.
pub mod compact_serialization;
/// Typed compression policy configuration.
pub mod config;
/// Opaque domain-separated session record identity.
pub mod identity;
mod marked_context;
/// Closed compression outcomes and accounting records.
pub mod outcome;
/// Retrieval-aware selection for explicitly marked context.
pub mod rag_select;
/// Versioned external summary-state records and canonical message digests.
pub mod record;
/// Sequential asynchronous compression execution.
pub mod runner;
/// Backend-neutral external summary-state contract.
pub mod store;
/// Stateful running-summary compression lever.
pub mod summary_buffer;
/// Stable behavior identity for summary-buffer state lineages.
mod summary_policy;
/// Compatibility adapter for deterministic model-window fitting.
pub mod window_fit;

pub use compact_serialization::CompactSerializationLever;
pub use config::{
    CompactSerializationConfig, CompressionBackend, CompressionLeverConfig, CompressionPolicy,
    CompressionProfile, CompressionSelector, CompressionStateBackend, CompressionStateConfig,
    PositionReorderConfig, RagSelectConfig, RetrievalRanking, SummarizerConfig,
    SummaryBufferConfig, TabularSerializationConfig, WindowFitConfig,
};
pub use identity::CompressionRecordId;
pub use marked_context::table::{decode_sbproxy_table_v1, TableDecodeError};
pub use marked_context::{
    inspect_marked_context, MarkedContextError, MarkedContextSnapshot, RetrievalBlockSnapshot,
    RetrievalChunkSnapshot,
};
pub use outcome::{
    FailureReason, LeverKind, LeverOutcome, LeverResult, RequestOutcome, SkipReason,
};
pub use rag_select::RagSelectLever;
pub use record::{CompressionSessionRecord, MessageDigest, RecordKind, RECORD_SCHEMA_VERSION};
pub use runner::{
    CompressionCommitRule, CompressionDecision, CompressionLever, CompressionRequest,
    CompressionRequestControls, CompressionRun, CompressionRunner, ModelTokenCounter, TokenCounter,
};
pub use store::{
    CommitError, CompressionConsistency, CompressionRecordMetadata, CompressionSessionStore,
    DeleteResult, ListPage, ListRequest, PurgePage, PurgeRequest, StoreError, UpdatePermit,
};
pub use summary_buffer::{
    InternalSummarizer, SummarizationOutput, SummarizationRequest, SummarizerError,
    SummaryBufferLever,
};
pub use summary_policy::SummaryPolicyFingerprint;
pub use window_fit::WindowFitLever;
