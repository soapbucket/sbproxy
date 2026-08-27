//! Consolidated streaming end-to-end suite (WOR-2066).
//!
//! The five files below were five separately linked integration
//! binaries. Every one of them links the whole `sbproxy-e2e` support
//! crate and its dependency graph, so five binaries paid that link cost
//! five times to run twenty-odd tests. They are modules of one binary
//! now, and every case keeps its own name, its own fixture, and its own
//! proxy harness: nothing is shared between them but the link.
//!
//! Run one module with a filter rather than a separate target, for
//! example `cargo nextest run -p sbproxy-e2e --test streaming -E
//! 'test(ai_streaming_usage::)'`.

mod ai_streaming;
mod ai_streaming_native_inbound;
mod ai_streaming_translation;
mod ai_streaming_usage;
mod grpc_web_streaming;
