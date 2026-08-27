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
//!
//! # What a module in here may not do
//!
//! The e2e lane runs `cargo test -p sbproxy-e2e -- --test-threads=1`,
//! which is one process per binary rather than one per case, so the
//! process boundary that used to separate these five is gone. Anything
//! a case leaves behind now survives into the next one. Three
//! properties make that safe, and all three were checked before the
//! files moved:
//!
//! * Every fixture binds `http_bind_port: 0`, so no case can collide
//!   with a listener another case leaked.
//! * `ProxyHarness` and `MockUpstream` both reclaim their child process
//!   and their listener in `Drop`, so cleanup does not depend on the
//!   process exiting.
//! * No module touches `std::env`, a `OnceLock`, or a process-global
//!   subscriber.
//!
//! The third one is the load-bearing rule and the reason the five
//! `otlp_*` suites are deliberately **not** consolidated the same way:
//! `assert_complete_ai_span_exports` calls
//! `LoggingConfig::init_with_resolved_filter_and_telemetry`, the
//! process-global tracing subscriber and OTel tracer provider, inside
//! the test process. Two transports in one binary would initialize it
//! twice and the second collector would receive nothing. A new module
//! added here owes the same three checks.

mod ai_streaming;
mod ai_streaming_native_inbound;
mod ai_streaming_translation;
mod ai_streaming_usage;
mod grpc_web_streaming;
