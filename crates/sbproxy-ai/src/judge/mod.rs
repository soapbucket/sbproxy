//! LLM-as-judge backend (single-provider, BYOK).
//!
//! Implements the OSS slice of the judge surface defined in
//! `docs/adr-judge-trait.md`. The host function `judge::semantic`
//! takes a prompt template plus a JSON payload and returns a
//! [`PolicyDecision`](sbproxy_plugin::PolicyDecision). The OSS
//! backend is a single configurable provider; the enterprise router
//! (multi-provider failover, Redis cache, calibration tracker) lives
//! outside this crate.
//!
//! Public surface:
//!
//! - [`JudgeConfig`] - endpoint, API key env var, timeout, cache and
//!   budget caps. Configured once at startup.
//! - [`JudgeClient`] - holds an HTTP client, the cache, and the
//!   budget tracker. Exposes [`JudgeClient::semantic`] as the host
//!   function callable from any authoring surface.
//! - [`JudgeError`] - failure modes the caller must convert into
//!   `PolicyDecision::Deny` (or surface to telemetry).
//! - [`JudgeCache`] - LRU keyed on `(prompt_hash, payload_hash)`,
//!   exposed publicly so the enterprise crate can wrap it with a
//!   Redis layer without re-implementing the LRU.
//!
//! The cache key is a pair of `u128` values, each the leading 128
//! bits of `SHA-256(text)`. Cache hits skip the model call entirely
//! and the cost-per-decision metric records zero.
//!
//! Budget enforcement is hard-fail: when [`BudgetTracker::charge`]
//! returns `BudgetExhausted`, [`JudgeClient::semantic`] surfaces
//! [`JudgeError::BudgetExhausted`]. Callers convert this to
//! `PolicyDecision::Deny`. The judge backend itself does NOT silently
//! return `Allow` when out of budget; that would defeat the security
//! purpose of calling the judge in the first place.

pub mod budget;
pub mod cache;
pub mod client;
pub mod compat_judge;
pub mod telemetry;

pub use budget::{BudgetExhausted, BudgetTracker};
pub use cache::JudgeCache;
pub use client::JudgeClient;
pub use compat_judge::{CompatJudge, CompatJudgeConfig};

/// Configuration for the single-provider judge backend.
///
/// Fields match the public surface in `adr-judge-trait.md`. The
/// endpoint is the upstream chat-completions URL the judge will
/// `POST` to; `api_key_env` names the environment variable that
/// holds the bearer token (BYOK; the proxy itself does not store the
/// key in config). `timeout_ms` bounds the round-trip wall-clock per
/// call. `cache_capacity` sizes the in-memory LRU; `budget_tokens`
/// sizes the per-process token budget enforced by [`BudgetTracker`].
#[derive(Debug, Clone)]
pub struct JudgeConfig {
    /// Upstream chat-completions endpoint to POST to.
    pub endpoint: url::Url,
    /// Name of the environment variable holding the bearer API key.
    pub api_key_env: String,
    /// Per-call timeout in milliseconds.
    pub timeout_ms: u32,
    /// Maximum entries in the in-memory LRU cache.
    pub cache_capacity: usize,
    /// Total token-equivalent budget before the tracker hard-fails.
    pub budget_tokens: u64,
}

impl JudgeConfig {
    /// Sensible default capacity for the LRU when callers do not
    /// override it. Matches the ADR-published default of 10k entries.
    pub const DEFAULT_CACHE_CAPACITY: usize = 10_000;

    /// Default per-call timeout (2 seconds, matching the hosted
    /// frontier judge p95 SLO from the ADR).
    pub const DEFAULT_TIMEOUT_MS: u32 = 2_000;
}

/// Failure modes the judge backend can surface to a caller.
///
/// These are deliberately coarse: callers are expected to map any
/// `Err(JudgeError::*)` to `PolicyDecision::Deny` so the proxy's
/// fast path stays on a single shape. The variants exist so
/// telemetry and structured logs can disambiguate the failure
/// without re-parsing strings.
#[derive(Debug, thiserror::Error)]
pub enum JudgeError {
    /// The configured token-equivalent budget has been exhausted.
    /// Callers convert to `PolicyDecision::Deny { status: 429,
    /// message: "judge_budget_exhausted" }`.
    #[error("judge budget exhausted")]
    BudgetExhausted,
    /// The upstream provider returned a non-success status or a
    /// transport-level failure occurred. The inner string is
    /// suitable for logging but not for returning verbatim to
    /// untrusted clients.
    #[error("judge provider error: {0}")]
    ProviderError(String),
    /// The per-call timeout elapsed before the upstream responded.
    #[error("judge call timed out")]
    Timeout,
    /// The upstream returned 2xx but the body could not be parsed
    /// into a recognisable verdict shape.
    #[error("judge response malformed: {0}")]
    MalformedResponse(String),
}
