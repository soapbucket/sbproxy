//! Ordered AI context-compression policies and execution.

/// Typed compression policy configuration.
pub mod config;
/// Closed compression outcomes and accounting records.
pub mod outcome;
/// Sequential asynchronous compression execution.
pub mod runner;
/// Compatibility adapter for deterministic model-window fitting.
pub mod window_fit;

pub use config::{
    CompressionBackend, CompressionLeverConfig, CompressionPolicy, CompressionStateConfig,
    SummarizerConfig, SummaryBufferConfig, WindowFitConfig,
};
pub use outcome::{
    FailureReason, LeverKind, LeverOutcome, LeverResult, RequestOutcome, SkipReason,
};
pub use runner::{
    CompressionDecision, CompressionLever, CompressionRequest, CompressionRun, CompressionRunner,
    ModelTokenCounter, TokenCounter,
};
pub use window_fit::WindowFitLever;
