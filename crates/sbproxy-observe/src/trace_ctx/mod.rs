//! Distributed tracing: W3C Trace Context propagation and pipeline phase spans.
//!
//! Uses the module name `trace_ctx` to avoid collision with the `tracing` crate.

pub mod auto_inject;
pub mod b3;
pub mod baggage;
pub mod events;
pub mod w3c;
