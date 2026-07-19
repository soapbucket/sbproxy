//! External state adapters for AI compression sessions.

/// Experimental mesh adapter retained for hardening work; not public-config selectable.
pub mod mesh;
/// Strict lease-serialized Redis adapter.
pub mod redis;

pub use mesh::{
    MeshCompressionEvent, MeshCompressionEventSink, MeshCompressionStore,
    MeshCompressionStoreConfig,
};
pub use redis::{RedisCompressionStore, RedisCompressionStoreConfig};
