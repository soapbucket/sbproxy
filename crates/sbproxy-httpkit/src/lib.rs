//! Shared HTTP primitives for sbproxy.
//!
//! The crate is the public-API entrypoint for plugin authors who need
//! to recycle response-body buffers without paying repeated heap
//! allocation. It also exposes bounded outbound clients that give
//! integrations consistent timeout, connection-pool, redirect, and
//! user-agent settings.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bufferpool;
pub mod outbound;

pub use outbound::{
    default_outbound, request_error_summary, token_bearing_outbound, OutboundClientBuilder,
};
