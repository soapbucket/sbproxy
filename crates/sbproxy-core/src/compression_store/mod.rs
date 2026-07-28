//! External state adapters for AI compression sessions.

/// Durable single-process adapter over an embedded redb database.
pub mod local;
/// Replicated mesh adapter over the cluster replication substrate.
pub mod mesh;
/// Strict lease-serialized Redis adapter.
pub mod redis;

pub use local::LocalCompressionStore;
pub use mesh::{MeshCompressionStore, MeshCompressionStoreConfig};
pub use redis::{RedisCompressionStore, RedisCompressionStoreConfig};
