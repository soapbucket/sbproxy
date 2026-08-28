//! sbproxy-cache: Response cache and object cache management.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod at_rest;
pub mod cache_event;
pub mod reserve;
pub mod response;
pub mod store;

pub use at_rest::{AtRestPosture, CacheDurability};
pub use reserve::{
    CacheReserveBackend, FsReserve, MemoryReserve, ObjectStoreReserve, RedisReserve,
    ReserveCacheStore, ReserveConfig, ReserveMetadata, ReserveStats,
};
pub use response::{
    caller_identity, canonicalize_query, compute_cache_key, evaluate_cached_preconditions,
    headers_for_not_modified, is_mutation_method, negotiated_encoding_bucket,
    path_invalidation_prefix, vary_fingerprint, CachedPrecondition, QueryMode, ResponseCacheConfig,
};
pub use store::{
    cache_key_ring, new_cache_generation, CacheKeyDirectory, CacheStore, CachedResponse,
    EncryptedCacheStore, FileCacheConfig, FileCacheStore, MemcachedConfig, MemcachedStore,
    MemoryCacheStore, RedisCacheStore,
};
