// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! # sbproxy-storage
//!
//! A small storage abstraction shared by the OSS mesh and the key plane.
//!
//! ## The trait shapes
//!
//! * [`EphemeralKv`] : TTL-bounded key/value (sessions, short-lived counters).
//! * [`PersistentKv`] : durable key/value with prefix listing.
//! * [`PubSub`] : fan-out broadcast channels (invalidation, notifications).
//! * [`HashKv`] : Redis-Hash-shaped per-field map under a parent key.
//! * [`SetKv`] : Redis-Set-shaped unordered unique-member tracking (mesh
//!   membership).
//! * [`StreamKv`] : Redis-Stream-shaped append-only log.
//!
//! Trait objects keep call sites backend-agnostic: a downstream crate stores
//! `Box<dyn EphemeralKv>` (or `Arc` when shared across tasks) and is injected
//! with whichever backend the deployment picked. The `redis` feature (on by
//! default) provides [`RedisStore`]; the `mock` feature provides in-memory test
//! doubles.
//!
//! Every method returns [`StorageError`]. Backends validate keys against
//! [`MAX_KEY_BYTES`] and values against [`MAX_VALUE_BYTES`] via
//! [`error::check_key`] and [`error::check_value`]. [`metrics::observe_op`]
//! wraps a backend call with the `storage_op_duration_seconds` histogram and the
//! `storage_op_errors_total` counter.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod error;
pub mod metrics;
pub mod traits;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

#[cfg(feature = "redis")]
pub mod redis_backend;

pub use error::{check_key, check_value, StorageError, MAX_KEY_BYTES, MAX_VALUE_BYTES};
pub use metrics::{observe_op, STORAGE_OP_DURATION_SECONDS, STORAGE_OP_ERRORS_TOTAL};
pub use traits::{
    EphemeralKv, HashKv, PersistentKv, PubSub, SetKv, StreamEntry, StreamKv, Subscription,
};

#[cfg(feature = "redis")]
pub use redis_backend::{RedisStore, RedisSubscription, MAX_LIST_PREFIX_KEYS};
