//! External state adapters for AI compression sessions.

/// Strict lease-serialized Redis adapter.
pub mod redis;

pub use redis::{RedisCompressionStore, RedisCompressionStoreConfig};
