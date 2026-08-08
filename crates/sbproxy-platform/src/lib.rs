//! sbproxy-platform: Storage, circuit breaker, DNS, health checks, and
//! network protocol utilities.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adaptive_breaker;
pub mod circuitbreaker;
pub mod dns;
pub mod health;
pub mod outlier;
pub mod proxy_protocol;
pub mod storage;

pub use adaptive_breaker::AdaptiveBreaker;
pub use circuitbreaker::{CircuitBreaker, CircuitState};
pub use dns::{DnsCache, RefreshingResolver};
pub use health::{HealthState, HealthTracker};
pub use proxy_protocol::{parse_proxy_protocol_v1, ProxyProtocolHeader};
pub use storage::{KVStore, MemoryKVStore};
