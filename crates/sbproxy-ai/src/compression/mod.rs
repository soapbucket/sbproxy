//! Ordered AI context-compression policies and execution.

/// Typed compression policy configuration.
pub mod config;
/// Opaque domain-separated session record identity.
pub mod identity;
/// Closed compression outcomes and accounting records.
pub mod outcome;
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

pub use config::{
    CompressionBackend, CompressionLeverConfig, CompressionPolicy, CompressionStateBackend,
    CompressionStateConfig, SummarizerConfig, SummaryBufferConfig, WindowFitConfig,
};
pub use identity::CompressionRecordId;
pub use outcome::{
    FailureReason, LeverKind, LeverOutcome, LeverResult, RequestOutcome, SkipReason,
};
pub use record::{CompressionSessionRecord, MessageDigest, RecordKind, RECORD_SCHEMA_VERSION};
pub use runner::{
    CompressionDecision, CompressionLever, CompressionRequest, CompressionRequestControls,
    CompressionRun, CompressionRunner, ModelTokenCounter, TokenCounter,
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
