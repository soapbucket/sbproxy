//! Error type returned by the dynamic-dispatch plugin traits.

use thiserror::Error;

/// Error returned by the [`crate::traits`] plugin trait methods.
///
/// Replaces the previous `anyhow::Result` so callers (the dispatcher in
/// `sbproxy-core`, and third-party plugin authors) can pattern-match the
/// failure category instead of inspecting `.to_string()`. Marked
/// `#[non_exhaustive]` so adding variants later is not a breaking change.
///
/// Existing `?`-on-`anyhow` bodies keep compiling because of the
/// [`From<anyhow::Error>`] impl, which folds any uncategorised failure into
/// [`PluginError::Internal`] while preserving the original error chain.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PluginError {
    /// The operation exceeded its time budget.
    #[error("plugin operation timed out")]
    Timeout,
    /// An upstream dependency returned an error status.
    #[error("upstream returned status {status}")]
    Upstream {
        /// The upstream HTTP status code.
        status: u16,
    },
    /// Authentication or authorization failed.
    #[error("authentication failed: {0}")]
    Auth(String),
    /// The plugin was misconfigured.
    #[error("plugin configuration error: {0}")]
    Config(String),
    /// Any other failure. Carries the original error chain so callers that
    /// only log keep full context, and `?`-on-`anyhow` bodies convert
    /// automatically via [`From<anyhow::Error>`].
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Convenience alias used by the plugin trait method signatures.
pub type PluginResult<T> = Result<T, PluginError>;
