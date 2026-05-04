//! sbproxy-transport: Custom HTTP transport features.
//!
//! Provides retry, request coalescing, hedged requests, upstream
//! rate limiting, self-tuning connection pools, and request deduplication
//! for the proxy transport layer.

#![warn(missing_docs)]

pub mod auto_pool;
pub mod coalescing;
pub mod dedup;
pub mod hedging;
pub mod mirroring;
pub mod ratelimit;
pub mod retry;

pub use coalescing::{CoalescedResponse, RequestCoalescer};
pub use dedup::DedupCache;
pub use hedging::HedgingConfig;
pub use mirroring::{mirror_request, MirrorConfig};
pub use ratelimit::UpstreamRateLimiter;
pub use retry::{RetryBudget, RetryConfig};
