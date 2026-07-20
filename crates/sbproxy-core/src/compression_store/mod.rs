//! External state adapters for AI compression sessions.

/// Replicated mesh adapter over the cluster replication substrate.
pub mod mesh;
/// Strict lease-serialized Redis adapter.
pub mod redis;

pub use mesh::{MeshCompressionStore, MeshCompressionStoreConfig};
pub use redis::{RedisCompressionStore, RedisCompressionStoreConfig};
