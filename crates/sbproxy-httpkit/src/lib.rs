//! sbproxy-httpkit: shared `BytesMut` buffer pool for response body
//! buffering on the proxy hot path.
//!
//! The crate is the public-API entrypoint for plugin authors who need
//! to recycle response-body buffers without paying repeated heap
//! allocation, and is intentionally narrow: today it exposes only
//! [`bufferpool::BufferPool`]. Broader HTTP request/response helpers
//! (header parsing, body limits, compression) live in `sbproxy-core`,
//! `sbproxy-middleware`, and `sbproxy-transport`; they are not
//! re-exported here to keep the public surface stable.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bufferpool;
