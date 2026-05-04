//! Export targets for metrics, events, and alerts.
//!
//! Provides fire-and-forget delivery of structured payloads to external
//! systems. Each exporter spawns background Tokio tasks so callers are
//! never blocked waiting for network I/O.

pub mod otlp_grpc;
pub mod webhook;

pub use webhook::{WebhookConfig, WebhookExporter};
