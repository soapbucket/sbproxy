//! Message passing for inter-component communication.
//!
//! Provides a trait-based messenger system for publishing events (config changes,
//! health updates, etc.) to subscribers.  Includes a bounded in-memory
//! implementation, a Redis Streams backend, an AWS SQS backend, and a GCP
//! Pub/Sub backend.

pub mod aws_sqs;
pub mod gcp_pubsub;
mod memory;
pub mod redis;

pub use aws_sqs::SqsMessenger;
pub use gcp_pubsub::GcpPubSubMessenger;
pub use memory::MemoryMessenger;
pub use redis::RedisMessenger;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A message that can be sent between components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Topic/channel the message belongs to (e.g. "config.updated", "health.changed").
    pub topic: String,
    /// Arbitrary JSON payload.
    pub payload: serde_json::Value,
    /// Unix timestamp in milliseconds when the message was created.
    pub timestamp: u64,
}

/// Message delivery trait for inter-component communication.
///
/// Implementations must be thread-safe. Subscribers receive only messages published
/// after they subscribe, and only on topics they subscribed to.
pub trait Messenger: Send + Sync + 'static {
    /// Publish a message to all subscribers of the message's topic.
    fn publish(&self, msg: &Message) -> Result<()>;

    /// Subscribe to a topic. Returns an iterator that yields messages as they arrive.
    ///
    /// The iterator blocks when no messages are available and terminates when the
    /// messenger is dropped or the internal channel is closed.
    fn subscribe(&self, topic: &str) -> Result<Box<dyn Iterator<Item = Message> + Send>>;
}
