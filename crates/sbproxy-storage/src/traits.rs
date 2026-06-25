// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Trait definitions for the storage shapes the OSS workspace
//! consumes.
//!
//! * [`EphemeralKv`] is the TTL-bounded key/value surface used by
//!   semantic cache entries, OAuth state, MCP gateway sessions, and
//!   short-lived rate-limit counters. It exposes `take` for atomic
//!   GETDEL semantics so OAuth nonces and PKCE verifiers can be
//!   consumed exactly once.
//! * [`PersistentKv`] is the durable key/value surface used by
//!   entitlement snapshots, RAG vector index metadata, WAF rule
//!   checkpoints, and other state that must survive a restart.
//! * [`PubSub`] is the broadcast surface used by the WAF feed
//!   distribution path, the entitlement invalidation channel, and the
//!   mesh peer-state notification stream. Subscribers receive a
//!   [`Subscription`] handle they poll for new messages.
//! * [`HashKv`] is the Redis-Hash-shaped surface (a map of fields under
//!   a parent key). The entitlements source uses it for per-tenant
//!   state hashes (`HGETALL`).
//! * [`SetKv`] is the Redis-Set-shaped surface (unordered unique
//!   members). The mesh backend uses it for membership tracking
//!   (`SADD` / `SREM` / `SMEMBERS`).
//! * [`StreamKv`] is the Redis-Stream-shaped append-only log with
//!   multi-field entries. The WAF feed publisher uses it for `XADD`
//!   (version + bundle + signature) and the entitlements change-stream
//!   uses it for `XREAD` with consumer groups.
//!
//! Every method returns [`StorageError`] so callers get a single
//! retryable / fatal taxonomy. Backends are expected to enforce key
//! and value size limits with [`crate::error::check_key`] and
//! [`crate::error::check_value`] before issuing the underlying I/O.

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::StorageError;

/// TTL-bounded key/value storage.
///
/// Implementations MUST evict entries on or before the supplied TTL
/// elapses; callers rely on that for OAuth state expiry and rate-limit
/// window resets. Reads of expired keys return `Ok(None)`.
#[async_trait]
pub trait EphemeralKv: Send + Sync {
    /// Fetch the value for `key`, or `Ok(None)` if absent / expired.
    async fn get(&self, key: &str) -> Result<Option<Bytes>, StorageError>;

    /// Store `value` under `key` with the given TTL.
    ///
    /// Implementations should treat `ttl == Duration::ZERO` as
    /// "evict immediately"; backends without that primitive may
    /// reject it with [`StorageError::InvalidConfig`].
    async fn put(&self, key: &str, value: Bytes, ttl: Duration) -> Result<(), StorageError>;

    /// Atomically read and delete `key` (Redis GETDEL semantics).
    ///
    /// Used by single-use credentials (PKCE verifiers, OAuth state
    /// tokens). Returns `Ok(None)` if the key was already absent.
    async fn take(&self, key: &str) -> Result<Option<Bytes>, StorageError>;

    /// Remove `key` if present. Idempotent: removing a missing key
    /// returns `Ok(())`.
    async fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// Test whether `key` exists and has not yet expired. Backends
    /// SHOULD answer without materialising the value (Redis `EXISTS`,
    /// in-memory `HashMap::contains_key`). Returns `Ok(false)` for
    /// expired or absent keys.
    ///
    /// The default implementation routes through [`Self::get`] so
    /// existing backends keep compiling without changes; production
    /// backends on the hot path (Redis, in-memory, Postgres, the test
    /// mock) override it to skip the value materialisation.
    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self.get(key).await?.is_some())
    }
}

/// Durable key/value storage with prefix listing.
///
/// Implementations MUST persist values across process restarts.
/// `list_prefix` returns the keys (not values) currently present
/// under the supplied prefix; callers iterate and `get` individually
/// when they need values, which keeps the trait surface compatible
/// with backends that page results internally.
#[async_trait]
pub trait PersistentKv: Send + Sync {
    /// Fetch the value for `key`, or `Ok(None)` if absent.
    async fn get(&self, key: &str) -> Result<Option<Bytes>, StorageError>;

    /// Store `value` under `key`. Overwrites any existing value.
    async fn put(&self, key: &str, value: Bytes) -> Result<(), StorageError>;

    /// Remove `key` if present. Idempotent.
    async fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// Return every key whose name begins with `prefix`. Order is
    /// implementation-defined; callers that need ordering must sort.
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError>;
}

/// Broadcast / pub-sub channel for fan-out notifications.
///
/// Implementations MUST deliver a published message to every
/// subscriber that was active at publish time. Late subscribers do
/// not receive historical messages; callers that need replay should
/// pair pub/sub with a [`PersistentKv`] checkpoint.
#[async_trait]
pub trait PubSub: Send + Sync {
    /// Publish `message` on `channel`. Returns once the backend has
    /// accepted the message (not necessarily delivered).
    async fn publish(&self, channel: &str, message: Bytes) -> Result<(), StorageError>;

    /// Subscribe to `channel` and return a handle the caller polls
    /// for messages. Dropping the handle unsubscribes.
    async fn subscribe(&self, channel: &str) -> Result<Box<dyn Subscription + Send>, StorageError>;
}

/// Active subscription handle returned by [`PubSub::subscribe`].
///
/// Callers `next` in a loop until they receive `Ok(None)`, which
/// signals the channel was closed by the backend (e.g. the connection
/// dropped). Errors are typically [`StorageError::Disconnected`] and
/// require the caller to re-subscribe.
#[async_trait]
pub trait Subscription: Send {
    /// Wait for the next message. `Ok(None)` indicates the channel
    /// was closed cleanly.
    async fn next(&mut self) -> Result<Option<Bytes>, StorageError>;
}

// --- HashKv ---

/// Redis-Hash-shaped key/value: a map of fields under a parent key.
///
/// Used by the entitlements source for per-tenant state hashes, where a
/// single parent key (e.g. `entitlements:tenant:acme`) holds many named
/// fields (`plan`, `seats`, `expires_at`, ...). Backends MUST treat the
/// parent key + field as a composite primary key; two distinct parents
/// MUST NOT see each other's fields.
#[async_trait]
pub trait HashKv: Send + Sync {
    /// Fetch the value of `field` under `key`, or `Ok(None)` if either
    /// the parent key or the named field is absent.
    async fn hget(&self, key: &str, field: &str) -> Result<Option<Bytes>, StorageError>;

    /// Set a single `field` under `key` to `value`. Overwrites any
    /// existing value for that field; other fields are untouched.
    async fn hset(&self, key: &str, field: &str, value: Bytes) -> Result<(), StorageError>;

    /// Set multiple `fields` under `key` in one call. Implementations
    /// SHOULD batch these into a single round trip where the backend
    /// supports it (Redis `HSET` accepts multiple field/value pairs in
    /// 4.0+).
    async fn hset_multi(&self, key: &str, fields: &[(&str, Bytes)]) -> Result<(), StorageError>;

    /// Return every `(field, value)` pair under `key`. Order is
    /// implementation-defined. Returns an empty `Vec` if the parent key
    /// is absent.
    async fn hgetall(&self, key: &str) -> Result<Vec<(String, Bytes)>, StorageError>;

    /// Remove `field` from `key`. Idempotent: removing a missing field
    /// (or operating on a missing parent key) returns `Ok(())`.
    async fn hdel(&self, key: &str, field: &str) -> Result<(), StorageError>;

    /// Test whether `field` exists under `key`. Returns `Ok(false)` if
    /// the parent key itself is absent.
    async fn hexists(&self, key: &str, field: &str) -> Result<bool, StorageError>;
}

// --- SetKv ---

/// Redis-Set-shaped: unordered unique-member tracking.
///
/// Used by the mesh backend for membership tracking. Implementations
/// MUST deduplicate members within a single `key`; adding a member that
/// already exists is a no-op (and not counted in the returned
/// "new-additions" tally).
#[async_trait]
pub trait SetKv: Send + Sync {
    /// Add `members` to the set under `key`. Returns the number of
    /// members that were NEW to the set (i.e. excludes duplicates).
    async fn sadd(&self, key: &str, members: &[Bytes]) -> Result<u64, StorageError>;

    /// Remove `members` from the set under `key`. Returns the number of
    /// members that were actually present (and therefore removed).
    async fn srem(&self, key: &str, members: &[Bytes]) -> Result<u64, StorageError>;

    /// Return every member currently in the set under `key`. Order is
    /// implementation-defined. Returns an empty `Vec` if the parent key
    /// is absent.
    async fn smembers(&self, key: &str) -> Result<Vec<Bytes>, StorageError>;

    /// Return the cardinality of the set under `key`. `Ok(0)` if the
    /// parent key is absent.
    async fn scard(&self, key: &str) -> Result<u64, StorageError>;

    /// Test whether `member` is in the set under `key`.
    async fn sismember(&self, key: &str, member: &Bytes) -> Result<bool, StorageError>;
}

// --- StreamKv ---

/// Redis-Stream-shaped: append-only log with multi-field entries.
///
/// Used by the WAF feed publisher (`XADD` with `version` + `bundle` +
/// `signature` fields per entry) and the entitlements change-stream
/// (`XREAD` with consumer groups). Implementations MUST assign every
/// entry a monotonically-increasing ID that callers can use as a
/// resume cursor.
///
/// Consumer groups (`XGROUP`, `XACK`) are deliberately out of scope for
/// the trait surface: backends without that primitive (Postgres, in-
/// memory) would have to fake them poorly. Callers that need consumer
/// groups today still use Redis directly via the underlying
/// `redis::Client` until a future wave promotes them.
#[async_trait]
pub trait StreamKv: Send + Sync {
    /// Append an entry to `stream`. Returns the assigned ID, e.g.
    /// `"1234567890-0"` (Redis-style: ms-timestamp dash sequence).
    async fn xadd(&self, stream: &str, entry: &[(&str, Bytes)]) -> Result<String, StorageError>;

    /// Read up to `count` entries from `stream` since `since_id`.
    ///
    /// `since_id` semantics:
    /// * `"0"` (or any ID) reads from after that ID inclusive of newer
    ///   entries.
    /// * `"$"` reads only NEW entries appended after the call. Backends
    ///   that lack a blocking-read primitive (in-memory, Postgres) treat
    ///   `"$"` as "return nothing right now"; callers should poll.
    async fn xread(
        &self,
        stream: &str,
        since_id: &str,
        count: usize,
    ) -> Result<Vec<StreamEntry>, StorageError>;

    /// Trim `stream` to at most `max_len` entries (drops the oldest).
    /// Returns the number of entries actually removed.
    async fn xtrim(&self, stream: &str, max_len: usize) -> Result<u64, StorageError>;
}

/// One entry in a [`StreamKv`] stream. The `id` is the backend-assigned
/// monotonic identifier; `fields` is the multi-field payload the caller
/// pushed via [`StreamKv::xadd`], preserving insertion order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEntry {
    /// Monotonic identifier the backend assigned at `xadd` time.
    pub id: String,
    /// Field/value pairs in original insertion order.
    pub fields: Vec<(String, Bytes)>,
}
