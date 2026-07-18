//! Ordered AI context-compression policies and execution.

/// Typed compression policy configuration.
pub mod config;

pub use config::{
    CompressionBackend, CompressionLeverConfig, CompressionPolicy, CompressionStateConfig,
    SummarizerConfig, SummaryBufferConfig, WindowFitConfig,
};
