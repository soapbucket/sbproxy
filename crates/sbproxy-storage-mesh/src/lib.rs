// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Mesh-backed storage adapter.
//!
//! [`MeshStore`] implements [`EphemeralKv`] and [`PubSub`] on top of the
//! primitives the mesh node exposes:
//!
//! * Ephemeral KV is served by `sbproxy_mesh::state::distributed_cache::DistributedCache`.
//!   Entries replicate across the cluster via gossip, expire on a TTL,
//!   and are swept by the mesh's background sweeper. The adapter wraps
//!   the local-shard accessors (`put_local_with_ttl`, `get_local`,
//!   `delete_local`); routed reads/writes through the consistent hash
//!   ring are a deployment-wiring concern handled by the mesh
//!   `MeshNode` itself, which is why this adapter accepts an
//!   `Arc<DistributedCache<Bytes>>` directly.
//! * Pub/sub uses an in-process `tokio::sync::broadcast` channel
//!   registry. The mesh crate does not currently expose a generic
//!   broadcast primitive on its public surface (federation pushes to
//!   Redis, gossip dissemination is encapsulated inside the SWIM
//!   loop), so cross-node fan-out for pub/sub is out of scope for
//!   the initial OSS adapter. Callers that need cluster-wide notifications should
//!   keep using `RedisStore` (the Redis backend) for now; this in-process
//!   broadcaster is enough for the workspace-local use cases that
//!   share a single mesh node (PKCE state replay-set notifications
//!   inside one workspace replica, AS metadata cache invalidation
//!   inside one process).
//!
//! # Why this crate exists
//!
//! Wave 6G originally placed the adapter inside
//! `sbproxy-storage`, but that pulled
//! `sbproxy-mesh` into the storage crate as an optional
//! prod dep, which formed a package cycle once the mesh crate
//! started consuming `RedisStore` from storage. The dep was demoted
//! to dev-only, leaving the adapter compiling only under `cargo test`.
//! Lifting the adapter into its own crate breaks the cycle without
//! sacrificing production availability: this crate depends on both
//! sides as regular prod deps, and the storage crate no longer needs
//! to know about the mesh.
//!
//! # Lossy vs. durable trade-off
//!
//! `MeshStore` is **eventually consistent and ephemeral**. Use it for
//! short-lived state that survives partial replica failure:
//!
//! * PKCE state and OAuth nonces (single-use, TTL bounded to a few
//!   minutes).
//! * DPoP `jti` replay sets (TTL bounded to the access-token lifetime).
//! * Authorization-server metadata caches (TTL bounded to the cache
//!   refresh interval).
//!
//! Do **NOT** use it for:
//!
//! * Long-lived secrets (rotate via `PostgresStore`, Wave 6E).
//! * Billing records or audit logs (durability requirement).
//! * Anything where a missed read after a node crash would silently
//!   corrupt state. The mesh distributed cache replicates via gossip
//!   but does not promise read-after-write across all replicas, and
//!   the in-process pub/sub does not survive a process restart at
//!   all.
//!
//! `MeshStore` deliberately does **not** implement [`PersistentKv`];
//! attempting to use it for durable state should fail at compile time
//! rather than at 03:00.
//!
//! # No HashKv / SetKv / StreamKv on the mesh
//!
//! Wave 6FGH adds three Redis-shaped trait surfaces (`HashKv`, `SetKv`,
//! `StreamKv`) for the entitlements / mesh / WAF feed call sites. The
//! mesh backend deliberately does **not** implement any of them:
//!
//! * Hash semantics need atomic per-(parent, field) updates. The mesh
//!   distributed cache only addresses whole values, so emulating
//!   `HSET` would race on every field write under gossip.
//! * Set semantics need exact `SADD` / `SREM` deltas across replicas.
//!   Gossip is eventually consistent and replicas can resurrect a
//!   removed member after a partition heals; that is the wrong
//!   behaviour for "exactly once" membership tracking.
//! * Stream semantics need a monotonic, durable, append-only log with
//!   a globally-agreed ID order. Gossip cannot promise that without a
//!   raft / paxos quorum we do not have here.
//!
//! Consumers that need any of these shapes must wire the Redis or
//! Postgres backend (the Redis backend / 6E). The intent of those backends is
//! captured in the `BackendConfig` enum so YAML can route per-tenant.
//!
//! # Test coverage
//!
//! The unit tests in this module construct `DistributedCache` directly
//! (single-node ring, no gossip loop, no transport server) so they
//! exercise the adapter wiring without bringing up a multi-node mesh.
//! Tests that would require a multi-node fixture (cross-node TTL
//! propagation, cluster-wide pub/sub fan-out) are intentionally
//! out-of-scope for the initial OSS adapter: the mesh's own integration tests already
//! cover the underlying primitives, and re-running them here would
//! duplicate work and slow the storage crate's CI.
//!
//! [`PersistentKv`]: sbproxy_storage::PersistentKv

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use sbproxy_mesh::state::distributed_cache::DistributedCache;
use sbproxy_mesh::MeshNode;
use sbproxy_storage::error::{check_key, check_value, StorageError};
use sbproxy_storage::metrics::observe_op;
use sbproxy_storage::traits::{EphemeralKv, PubSub, Subscription};
use tokio::sync::{broadcast, Mutex};

/// Backend label used by the metrics layer.
const BACKEND: &str = "mesh";
/// Trait-shape label used by the metrics layer for the ephemeral path.
const KIND_EPHEMERAL: &str = "ephemeral";
/// Trait-shape label used by the metrics layer for the pubsub path.
const KIND_PUBSUB: &str = "pubsub";
/// Default capacity for in-process pub/sub channels. Picked so that a
/// slow subscriber lags no more than a few seconds of typical traffic
/// (entitlement invalidations, AS metadata refreshes) before the
/// `RecvError::Lagged` arm prunes it.
const PUBSUB_CHANNEL_CAPACITY: usize = 1024;

// --- MeshStore ---

/// Storage adapter backed by the mesh node.
///
/// Constructed once from a shared [`MeshNode`] handle (or directly from
/// an `Arc<DistributedCache<Bytes>>` for tests) and shared across every
/// trait-using site in a workspace.
///
/// Keys are namespaced with `key_prefix` so different storage clients
/// (PKCE state, jti replay, AS metadata) can share one mesh cluster
/// without colliding on key names.
pub struct MeshStore {
    /// Local-shard accessor for the mesh's distributed cache. Cluster
    /// routing (consistent hash ring + transport pool) is handled by
    /// the mesh node itself; this adapter speaks to the local shard
    /// because that is the contract the underlying `DistributedCache`
    /// API exposes for raw `Bytes` values.
    cache: Arc<DistributedCache<Bytes>>,
    /// Per-store key namespace. Joined with the caller-supplied key as
    /// `"{key_prefix}:{key}"` so two stores wired to the same mesh node
    /// cannot read each other's traffic. Empty string means "no
    /// prefix" (used by the unit tests).
    key_prefix: String,
    /// In-process broadcast registry: one `broadcast::Sender` per
    /// channel name. Subscribers each hold their own
    /// `broadcast::Receiver`. Stored behind a `Mutex` because
    /// `subscribe` and `publish` both need write access to insert /
    /// look up the per-channel sender, and the lock is held only for
    /// the lookup, not for the send itself.
    channels: Arc<Mutex<HashMap<String, broadcast::Sender<Bytes>>>>,
}

impl MeshStore {
    /// Construct a new adapter from a [`MeshNode`] handle.
    ///
    /// The `MeshNode` is expected to live for the duration of the
    /// process; the adapter only needs its `DistributedCache` handle,
    /// which is cloned out and held internally.
    pub fn new(mesh: Arc<MeshNode>, key_prefix: impl Into<String>) -> Self {
        Self::from_cache(mesh.distributed_cache(), key_prefix)
    }

    /// Construct directly from a `DistributedCache` handle. Intended
    /// for tests and for embedding inside larger composite stores
    /// (e.g. the workspace bootstrap wires one of these per workspace).
    pub fn from_cache(cache: Arc<DistributedCache<Bytes>>, key_prefix: impl Into<String>) -> Self {
        Self {
            cache,
            key_prefix: key_prefix.into(),
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Join the per-store prefix with the caller-supplied key. Empty
    /// prefix returns the key untouched so unit tests can address
    /// keys directly.
    fn full_key(&self, key: &str) -> String {
        if self.key_prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}:{}", self.key_prefix, key)
        }
    }
}

#[async_trait]
impl EphemeralKv for MeshStore {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        check_key(key)?;
        let full = self.full_key(key);
        observe_op("get", BACKEND, KIND_EPHEMERAL, async {
            // `get_local` already honors the per-entry expires_at
            // recorded by `put_local_with_ttl`, so no extra TTL check
            // is needed here. A miss returns Ok(None).
            Ok(self.cache.get_local(&full))
        })
        .await
    }

    async fn put(&self, key: &str, value: Bytes, ttl: Duration) -> Result<(), StorageError> {
        check_key(key)?;
        check_value(&value)?;
        let full = self.full_key(key);
        observe_op("put", BACKEND, KIND_EPHEMERAL, async {
            // `DistributedCache::put_local_with_ttl` takes whole
            // seconds. Round up so any non-zero sub-second TTL is
            // honored as at least one second of liveness; rounding
            // down to zero would silently mean "no expiry" per the
            // mesh's TTL convention.
            let ttl_secs = ttl_to_secs_round_up(ttl);
            self.cache.put_local_with_ttl(&full, value, ttl_secs);
            Ok(())
        })
        .await
    }

    async fn take(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        check_key(key)?;
        let full = self.full_key(key);
        observe_op("take", BACKEND, KIND_EPHEMERAL, async {
            // `DistributedCache` exposes get + delete but not an
            // atomic GETDEL. Two-step is safe for our use case
            // (single-use credentials) because the local shard is
            // single-writer per node and the mesh's gossip
            // replication is best-effort: a racing reader on another
            // node would also be reading stale state, which is the
            // accepted ephemeral-cache trade-off.
            let value = self.cache.get_local(&full);
            if value.is_some() {
                self.cache.delete_local(&full);
            }
            Ok(value)
        })
        .await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        check_key(key)?;
        let full = self.full_key(key);
        observe_op("delete", BACKEND, KIND_EPHEMERAL, async {
            // `delete_local` returns true on hit, false on miss. The
            // trait contract is "idempotent: removing a missing key
            // returns `Ok(())`", so we discard the bool.
            let _ = self.cache.delete_local(&full);
            Ok(())
        })
        .await
    }
}

#[async_trait]
impl PubSub for MeshStore {
    async fn publish(&self, channel: &str, message: Bytes) -> Result<(), StorageError> {
        check_key(channel)?;
        check_value(&message)?;
        let full = self.full_key(channel);
        observe_op("publish", BACKEND, KIND_PUBSUB, async {
            // Look up the sender for this channel. If nobody has
            // subscribed yet, the channel does not exist and the
            // publish is a silent no-op (mirrors Redis pub/sub
            // semantics: messages are not buffered for late
            // subscribers).
            let guard = self.channels.lock().await;
            if let Some(tx) = guard.get(&full) {
                // `broadcast::Sender::send` returns `Err` only when
                // every receiver has been dropped. That is not a
                // backend error in our model; subscribers come and
                // go. Treat it as a successful no-op publish so
                // callers do not have to reason about timing.
                let _ = tx.send(message);
            }
            Ok(())
        })
        .await
    }

    async fn subscribe(&self, channel: &str) -> Result<Box<dyn Subscription + Send>, StorageError> {
        check_key(channel)?;
        let full = self.full_key(channel);
        observe_op("subscribe", BACKEND, KIND_PUBSUB, async {
            let mut guard = self.channels.lock().await;
            let tx = guard
                .entry(full)
                .or_insert_with(|| broadcast::channel(PUBSUB_CHANNEL_CAPACITY).0)
                .clone();
            let rx = tx.subscribe();
            Ok(Box::new(MeshSubscription { rx }) as Box<dyn Subscription + Send>)
        })
        .await
    }
}

/// Subscription handle returned by [`MeshStore::subscribe`].
///
/// Wraps a `broadcast::Receiver`. `next` resolves on every message
/// the matching publisher emits; `Ok(None)` is returned once the
/// underlying sender is dropped (channel closed). A `Lagged` error
/// is converted to a backend error so the caller can decide whether
/// to re-subscribe.
pub struct MeshSubscription {
    rx: broadcast::Receiver<Bytes>,
}

#[async_trait]
impl Subscription for MeshSubscription {
    async fn next(&mut self) -> Result<Option<Bytes>, StorageError> {
        match self.rx.recv().await {
            Ok(msg) => Ok(Some(msg)),
            Err(broadcast::error::RecvError::Closed) => Ok(None),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                // The subscriber fell behind by `skipped` messages.
                // Surface as a retryable backend error so the caller
                // can re-subscribe (or accept the gap and call `next`
                // again to keep draining).
                tracing::warn!(
                    skipped = skipped,
                    "mesh storage pub/sub subscriber lagged; messages dropped"
                );
                Err(StorageError::Backend(format!(
                    "subscriber lagged by {skipped} messages"
                )))
            }
        }
    }
}

/// Convert a `Duration` TTL to whole seconds, rounding up so any
/// non-zero TTL stays non-zero. Zero in is zero out (the mesh
/// convention for "no expiry"); anything else is at least one
/// second.
fn ttl_to_secs_round_up(ttl: Duration) -> u64 {
    if ttl.is_zero() {
        return 0;
    }
    let secs = ttl.as_secs();
    if ttl.subsec_nanos() > 0 {
        secs.saturating_add(1)
    } else {
        secs.max(1)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a single-node `DistributedCache`. Sufficient for adapter
    /// wiring tests because the local node owns every key.
    fn cache() -> Arc<DistributedCache<Bytes>> {
        Arc::new(DistributedCache::<Bytes>::new("mesh-store-test", 16))
    }

    fn store() -> MeshStore {
        MeshStore::from_cache(cache(), "")
    }

    // --- EphemeralKv coverage ---

    #[tokio::test]
    async fn ephemeral_round_trip() {
        let s = store();
        s.put("k", Bytes::from_static(b"v"), Duration::from_secs(60))
            .await
            .unwrap();
        let got = s.get("k").await.unwrap();
        assert_eq!(got.as_deref(), Some(&b"v"[..]));
    }

    #[tokio::test]
    async fn ephemeral_take_returns_and_removes() {
        let s = store();
        s.put("nonce", Bytes::from_static(b"abc"), Duration::from_secs(60))
            .await
            .unwrap();
        let first = s.take("nonce").await.unwrap();
        assert_eq!(first.as_deref(), Some(&b"abc"[..]));
        let second = s.take("nonce").await.unwrap();
        assert!(second.is_none(), "second take must miss");
    }

    #[tokio::test]
    async fn ephemeral_delete_is_idempotent() {
        let s = store();
        s.delete("never-put").await.unwrap();
        s.put("k", Bytes::from_static(b"v"), Duration::from_secs(60))
            .await
            .unwrap();
        s.delete("k").await.unwrap();
        assert!(s.get("k").await.unwrap().is_none());
        s.delete("k").await.unwrap();
    }

    #[tokio::test]
    async fn ephemeral_ttl_evicts_entry() {
        // 1 second is the smallest whole-second TTL the underlying
        // `DistributedCache::put_local_with_ttl` honors. We sleep a
        // little past that to avoid racing the expiry check.
        let s = store();
        s.put("temp", Bytes::from_static(b"x"), Duration::from_secs(1))
            .await
            .unwrap();
        assert!(s.get("temp").await.unwrap().is_some());
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(s.get("temp").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn key_prefix_isolates_two_stores() {
        // Two stores sharing one mesh cache but with distinct
        // prefixes must not see each other's writes.
        let cache = cache();
        let a = MeshStore::from_cache(cache.clone(), "tenant-a");
        let b = MeshStore::from_cache(cache, "tenant-b");
        a.put("k", Bytes::from_static(b"a-val"), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(
            a.get("k").await.unwrap().as_deref(),
            Some(&b"a-val"[..]),
            "store A must read its own write"
        );
        assert!(
            b.get("k").await.unwrap().is_none(),
            "store B must not see store A's namespace"
        );
    }

    // --- PubSub coverage ---

    #[tokio::test]
    async fn pubsub_publish_then_subscribe_misses_message() {
        // Trait contract: late subscribers do not receive historical
        // messages. The first publish before any subscriber is set up
        // is dropped on the floor.
        let s = store();
        s.publish("ch", Bytes::from_static(b"early")).await.unwrap();
        let mut sub = s.subscribe("ch").await.unwrap();
        s.publish("ch", Bytes::from_static(b"late")).await.unwrap();
        let got = sub.next().await.unwrap();
        assert_eq!(got.as_deref(), Some(&b"late"[..]));
    }

    #[tokio::test]
    async fn pubsub_fan_out_to_two_subscribers() {
        let s = store();
        let mut sub_a = s.subscribe("invalidate").await.unwrap();
        let mut sub_b = s.subscribe("invalidate").await.unwrap();
        s.publish("invalidate", Bytes::from_static(b"go"))
            .await
            .unwrap();
        let a = sub_a.next().await.unwrap();
        let b = sub_b.next().await.unwrap();
        assert_eq!(a.as_deref(), Some(&b"go"[..]));
        assert_eq!(b.as_deref(), Some(&b"go"[..]));
    }

    #[tokio::test]
    async fn ttl_round_up_preserves_sub_second_liveness() {
        // 500ms must round up to >= 1s so the entry is readable
        // immediately after put (a naive `as_secs` truncation would
        // hand 0 to the cache, which means "no expiry" - readable
        // forever - which is the wrong direction but a different
        // bug). Either way, the entry should be present right after
        // we write it.
        let s = store();
        s.put("k", Bytes::from_static(b"v"), Duration::from_millis(500))
            .await
            .unwrap();
        assert!(s.get("k").await.unwrap().is_some());
    }

    #[test]
    fn ttl_to_secs_round_up_zero_is_zero() {
        assert_eq!(ttl_to_secs_round_up(Duration::ZERO), 0);
    }

    #[test]
    fn ttl_to_secs_round_up_whole_seconds_unchanged() {
        assert_eq!(ttl_to_secs_round_up(Duration::from_secs(5)), 5);
    }

    #[test]
    fn ttl_to_secs_round_up_subsecond_rounds_up() {
        assert_eq!(ttl_to_secs_round_up(Duration::from_millis(1)), 1);
        assert_eq!(ttl_to_secs_round_up(Duration::from_millis(1500)), 2);
    }
}
