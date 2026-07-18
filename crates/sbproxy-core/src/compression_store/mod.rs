//! External state adapters for AI compression sessions.

/// Eventual LWW adapter over the shared process mesh.
pub mod mesh;
/// Strict lease-serialized Redis adapter.
pub mod redis;

pub use mesh::{
    MeshCompressionEvent, MeshCompressionEventSink, MeshCompressionStore,
    MeshCompressionStoreConfig,
};
pub use redis::{RedisCompressionStore, RedisCompressionStoreConfig};
