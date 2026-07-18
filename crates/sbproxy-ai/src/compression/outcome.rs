//! Closed compression outcomes and token-accounting records.

use crate::compression::CompressionBackend;
use std::time::Duration;

/// Stable identifier for a compression lever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeverKind {
    /// Stateful running-summary compaction.
    SummaryBuffer,
    /// Deterministic target-window fitting.
    WindowFit,
}

impl LeverKind {
    /// Closed metric and log label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SummaryBuffer => "summary_buffer",
            Self::WindowFit => "window_fit",
        }
    }
}

/// Non-error reason that a lever left the working messages unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// A candidate did not strictly reduce the target-model token estimate.
    NoSavings,
    /// The request is outside this lever's supported eligibility rules.
    NotEligible,
    /// The request already satisfies the lever's target.
    NotNeeded,
    /// The target model has no known context-window size.
    UnknownModelWindow,
    /// No captured session identifier is available.
    MissingSession,
    /// The request is not a supported chat message array.
    UnsupportedRequest,
    /// The request is below the configured summary threshold.
    BelowThreshold,
    /// No eligible history remains after protecting the recent tail.
    InsufficientHistory,
    /// Structured tool, schema, or multimodal material prevents summarization.
    StructuredRequest,
    /// Stored history digests do not match the incoming branch.
    BranchMismatch,
    /// No additional eligible history needs summarization.
    NoNewHistory,
    /// Prior summary plus new source exceeds the summarizer input window.
    SummarizerInputTooLarge,
    /// Internal summarizer budget admission was denied.
    BudgetDenied,
    /// Credential governance disallows the configured summarizer destination.
    PolicyDenied,
    /// A bounded coordination permit was unavailable.
    LockContended,
}

impl SkipReason {
    /// Closed metric and log label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoSavings => "no_savings",
            Self::NotEligible => "not_eligible",
            Self::NotNeeded => "not_needed",
            Self::UnknownModelWindow => "unknown_model_window",
            Self::MissingSession => "missing_session",
            Self::UnsupportedRequest => "unsupported_request",
            Self::BelowThreshold => "below_threshold",
            Self::InsufficientHistory => "insufficient_history",
            Self::StructuredRequest => "structured_request",
            Self::BranchMismatch => "branch_mismatch",
            Self::NoNewHistory => "no_new_history",
            Self::SummarizerInputTooLarge => "summarizer_input_too_large",
            Self::BudgetDenied => "budget_denied",
            Self::PolicyDenied => "policy_denied",
            Self::LockContended => "lock_contended",
        }
    }
}

/// Sanitized runtime failure classification for a lever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// External canonical state could not be read or written.
    StateUnavailable,
    /// A Redis lease expired or ownership changed before commit.
    LeaseLost,
    /// The expected logical version was no longer current.
    StaleVersion,
    /// The internal summarizer exceeded its bounded deadline.
    SummarizerTimeout,
    /// The selected summarizer provider returned an error.
    SummarizerProvider,
    /// The summarizer response was empty, oversized, or malformed.
    InvalidSummary,
    /// A record or message could not be serialized safely.
    Serialization,
    /// A bounded internal invariant failed without exposing raw details.
    Internal,
}

impl FailureReason {
    /// Closed metric and log label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StateUnavailable => "state_unavailable",
            Self::LeaseLost => "lease_lost",
            Self::StaleVersion => "stale_version",
            Self::SummarizerTimeout => "summarizer_timeout",
            Self::SummarizerProvider => "summarizer_provider",
            Self::InvalidSummary => "invalid_summary",
            Self::Serialization => "serialization",
            Self::Internal => "internal",
        }
    }
}

/// Result category for one lever invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeverOutcome {
    /// A strictly token-reducing replacement was committed.
    Applied,
    /// The lever did not need or could not safely attempt a replacement.
    Skipped {
        /// Closed reason for the skip.
        reason: SkipReason,
    },
    /// A runtime dependency or validation step failed open.
    Failed {
        /// Closed sanitized failure classification.
        reason: FailureReason,
    },
}

/// Accounting record for one completed lever invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeverResult {
    /// Lever that ran.
    pub lever: LeverKind,
    /// Stateful backend, or `None` for stateless levers.
    pub backend: Option<CompressionBackend>,
    /// Applied, skipped, or failed classification.
    pub outcome: LeverOutcome,
    /// Target-model tokens in the committed working list before the lever.
    pub before_tokens: u64,
    /// Target-model tokens in the committed working list after the lever.
    pub after_tokens: u64,
    /// Exact committed reduction, always zero for skips and failures.
    pub tokens_saved: u64,
    /// Wall-clock time added by the lever invocation.
    pub duration: Duration,
}

/// Failure-first result for the completed request pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOutcome {
    /// At least one lever applied and no lever failed.
    Applied,
    /// Every lever skipped, or the pipeline was explicitly empty.
    Skipped,
    /// At least one lever failed, even if a later fallback applied.
    Failed,
}

impl RequestOutcome {
    /// Closed metric and log label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}
