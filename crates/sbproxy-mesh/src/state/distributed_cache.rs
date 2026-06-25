//! Distributed response cache using consistent hashing.
//!
//! Routes cache keys to responsible nodes using a consistent hash ring with
//! virtual nodes (vnodes) to improve load distribution when nodes are added
//! or removed.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::transport::TransportClientPool;

/// Default sweeper period (seconds) used by
/// [`DistributedCache::start_sweeper`] when the caller does not pin a
/// custom interval. Picked to be small enough that expired entries do not
/// linger long after the TTL elapses, but large enough that a 64k-entry
/// cache does not spend noticeable CPU on sweeps.
pub const DEFAULT_SWEEP_INTERVAL_SECS: u64 = 10;

/// A consistent hash ring that maps keys to node IDs using virtual nodes.
pub struct ConsistentHashRing {
    /// Sorted list of (hash, node_id) pairs representing virtual node positions.
    ring: Vec<(u64, String)>,
    /// Number of virtual nodes per real node.
    vnodes: usize,
}

fn hash_key(key: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

impl ConsistentHashRing {
    /// Create a new empty consistent hash ring with the specified virtual node count.
    pub fn new(vnodes: usize) -> Self {
        Self {
            ring: Vec::new(),
            vnodes: vnodes.max(1),
        }
    }

    /// Add a node to the ring, distributing it across `vnodes` positions.
    pub fn add_node(&mut self, node_id: &str) {
        for i in 0..self.vnodes {
            let vnode_key = format!("{node_id}#{i}");
            let h = hash_key(&vnode_key);
            self.ring.push((h, node_id.to_string()));
        }
        self.ring.sort_by_key(|(h, _)| *h);
    }

    /// Remove a node from the ring (removes all its virtual nodes).
    pub fn remove_node(&mut self, node_id: &str) {
        self.ring.retain(|(_, id)| id != node_id);
    }

    /// Find the responsible node for a given key using clockwise ring lookup.
    ///
    /// Returns None if the ring is empty.
    pub fn get_node(&self, key: &str) -> Option<&str> {
        if self.ring.is_empty() {
            return None;
        }
        let h = hash_key(key);
        // Find the first vnode at or after h; wrap around to the first if none.
        let idx = self.ring.partition_point(|(ring_hash, _)| *ring_hash < h);
        let idx = if idx >= self.ring.len() { 0 } else { idx };
        Some(&self.ring[idx].1)
    }

    /// Return the number of distinct real nodes currently in the ring.
    pub fn node_count(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        for (_, id) in &self.ring {
            seen.insert(id.as_str());
        }
        seen.len()
    }
}

// --- Entry ---

/// Wrapper around a cached value with an optional absolute expiration.
///
/// `expires_at = None` means the entry lives until explicit delete or
/// process restart (the pre-K1 default). `Some(deadline)` means the entry
/// is treated as absent once `Instant::now() >= deadline` and is dropped
/// either lazily (on `get_local`) or eagerly (by the background sweeper,
/// see [`DistributedCache::start_sweeper`]).
struct Entry<V> {
    value: V,
    expires_at: Option<Instant>,
}

/// A distributed cache that stores entries locally and uses a consistent hash
/// ring to determine which node owns each key.
///
/// Generic over the value type `V` so different consumers (semantic cache uses
/// serialized `Bytes`, future consumers may use arbitrary types) can share the
/// same routing + local-storage skeleton.
pub struct DistributedCache<V: Clone + Send + Sync + 'static> {
    local_cache: Mutex<HashMap<String, Entry<V>>>,
    ring: Mutex<ConsistentHashRing>,
    local_node_id: String,
}

impl<V: Clone + Send + Sync + 'static> DistributedCache<V> {
    /// Create a new distributed cache for the given local node.
    ///
    /// No background sweeper task is spawned by `new`; entries with TTLs
    /// will still expire lazily on `get_local`, but will linger in the
    /// underlying `HashMap` until read. Callers that want a periodic
    /// eviction sweep should wrap the result in an `Arc` and call
    /// [`DistributedCache::start_sweeper`] (or use
    /// [`DistributedCache::new_with_sweeper`] for the common case).
    pub fn new(local_node_id: &str, vnodes: usize) -> Self {
        let mut ring = ConsistentHashRing::new(vnodes);
        ring.add_node(local_node_id);
        Self {
            local_cache: Mutex::new(HashMap::new()),
            ring: Mutex::new(ring),
            local_node_id: local_node_id.to_string(),
        }
    }

    /// Construct an `Arc<Self>` and spawn the sweeper task in one call.
    ///
    /// `interval_secs = 0` disables the sweeper and is equivalent to
    /// `Arc::new(Self::new(...))`.
    pub fn new_with_sweeper(local_node_id: &str, vnodes: usize, interval_secs: u64) -> Arc<Self> {
        let this = Arc::new(Self::new(local_node_id, vnodes));
        if interval_secs > 0 {
            Self::start_sweeper(&this, interval_secs);
        }
        this
    }

    /// Spawn a background task that periodically evicts expired entries.
    ///
    /// The task holds a [`Weak`] reference to the cache, so when the last
    /// strong `Arc` is dropped the sweeper upgrades to `None` on the next
    /// tick and exits cleanly. There is no handle stored on `self`
    /// because spawning the task only requires an `Arc<Self>`, and a
    /// `JoinHandle` field would complicate the public type.
    ///
    /// `interval_secs` must be non-zero; the caller is expected to have
    /// already guarded against the "no sweeper" case (see
    /// [`Self::new_with_sweeper`]).
    ///
    /// No-op if there is no current tokio runtime handle available. This
    /// keeps synchronous tests that build a `MeshNode` without a runtime
    /// from panicking; production callers always live inside tokio.
    pub fn start_sweeper(this: &Arc<Self>, interval_secs: u64) {
        if tokio::runtime::Handle::try_current().is_err() {
            // No reactor; eviction falls back to the lazy `get_local`
            // path. This branch is only hit from `#[test] fn foo()` unit
            // tests (sync) that do not exercise sweeping.
            return;
        }
        let weak = Arc::downgrade(this);
        let period = Duration::from_secs(interval_secs.max(1));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            // First tick fires immediately; skip it so the sweeper doesn't
            // evict within microseconds of construction.
            tick.tick().await;
            loop {
                tick.tick().await;
                match Weak::upgrade(&weak) {
                    Some(cache) => cache.sweep_expired(),
                    // Last strong Arc has dropped; exit cleanly.
                    None => break,
                }
            }
        });
    }

    /// Scan all entries and drop any whose `expires_at` has elapsed.
    ///
    /// Called periodically by the sweeper task. Exposed `pub` so tests can
    /// drive it deterministically without waiting for a wall-clock tick.
    pub fn sweep_expired(&self) {
        let now = Instant::now();
        let mut cache = self.local_cache.lock().unwrap();
        cache.retain(|_, entry| match entry.expires_at {
            Some(deadline) => deadline > now,
            None => true,
        });
    }

    /// Returns true if the local node is responsible for the given key.
    pub fn is_local(&self, key: &str) -> bool {
        let ring = self.ring.lock().unwrap();
        ring.get_node(key)
            .map(|n| n == self.local_node_id)
            .unwrap_or(true)
    }

    /// Get a cached value from local storage.
    ///
    /// Expired entries are dropped on read: if the entry has an
    /// `expires_at` in the past we remove it and return `None`. This keeps
    /// callers from seeing stale data even if the background sweeper has
    /// not yet run.
    pub fn get_local(&self, key: &str) -> Option<V> {
        let mut cache = self.local_cache.lock().unwrap();
        match cache.get(key) {
            Some(entry) => {
                if let Some(deadline) = entry.expires_at {
                    if deadline <= Instant::now() {
                        cache.remove(key);
                        return None;
                    }
                }
                Some(entry.value.clone())
            }
            None => None,
        }
    }

    /// Store a value in local storage with no expiry.
    ///
    /// Retained for backwards compatibility and callers that intentionally
    /// want a no-TTL entry. New code that needs bounded lifetimes should
    /// use [`Self::put_local_with_ttl`].
    pub fn put_local(&self, key: &str, value: V) {
        let mut cache = self.local_cache.lock().unwrap();
        cache.insert(
            key.to_string(),
            Entry {
                value,
                expires_at: None,
            },
        );
    }

    /// Store a value in local storage with a TTL in seconds.
    ///
    /// `ttl_secs = 0` is treated as "no expiry" and is equivalent to
    /// [`Self::put_local`]; any positive value sets an absolute deadline
    /// `Instant::now() + Duration::from_secs(ttl_secs)`.
    pub fn put_local_with_ttl(&self, key: &str, value: V, ttl_secs: u64) {
        let expires_at = if ttl_secs == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl_secs))
        };
        let mut cache = self.local_cache.lock().unwrap();
        cache.insert(key.to_string(), Entry { value, expires_at });
    }

    /// Remove a value from local storage. Returns true if the key was present
    /// (regardless of whether it was expired).
    ///
    /// Network-level delete that gossips the removal to peer nodes is not yet
    /// implemented; this only evicts the local copy. Callers that need full
    /// cluster-wide eviction should track a follow-up in the mesh crate.
    pub fn delete_local(&self, key: &str) -> bool {
        let mut cache = self.local_cache.lock().unwrap();
        cache.remove(key).is_some()
    }

    /// Delete every local entry whose key starts with `prefix`. Returns the
    /// number of entries removed.
    ///
    /// Scans the entire local shard, so callers should use a precise prefix
    /// (e.g. `semcache:v1:{origin}:`) rather than a broad one. Entries whose
    /// TTL has already elapsed but have not yet been swept are still counted
    /// if they match the prefix, matching the semantics callers expect for
    /// a purge-by-prefix operation (they want the key gone, period).
    ///
    /// This method only touches the local shard. Cluster-wide prefix purges
    /// fan out via the `CacheOp::PurgePrefix` RPC (see
    /// [`crate::transport::frame::CacheOp`]) and sum the per-node counts.
    pub fn purge_prefix_local(&self, prefix: &str) -> usize {
        let mut cache = self.local_cache.lock().unwrap();
        let before = cache.len();
        cache.retain(|k, _| !k.starts_with(prefix));
        before - cache.len()
    }

    /// Delete every local entry. Returns the number of entries removed.
    ///
    /// This is a hard clear of the local shard. As with
    /// [`Self::purge_prefix_local`], cluster-wide purges are driven by the
    /// `CacheOp::PurgePrefix` RPC (with an empty `prefix` meaning "all") and
    /// sum the per-node counts returned from each peer.
    pub fn purge_all_local(&self) -> usize {
        let mut cache = self.local_cache.lock().unwrap();
        let n = cache.len();
        cache.clear();
        n
    }

    /// Number of entries currently in the local shard (including expired
    /// entries that have not yet been swept). Test / diagnostics only.
    #[cfg(test)]
    pub(crate) fn local_len(&self) -> usize {
        self.local_cache.lock().unwrap().len()
    }

    /// Add a node to the consistent hash ring.
    pub fn add_node(&self, node_id: &str) {
        let mut ring = self.ring.lock().unwrap();
        ring.add_node(node_id);
    }

    /// Remove a node from the consistent hash ring.
    pub fn remove_node(&self, node_id: &str) {
        let mut ring = self.ring.lock().unwrap();
        ring.remove_node(node_id);
    }

    /// Return the responsible node ID for a key, or None if the ring is empty.
    pub fn responsible_node(&self, key: &str) -> Option<String> {
        let ring = self.ring.lock().unwrap();
        ring.get_node(key).map(|s| s.to_string())
    }

    /// Local node identifier this cache was constructed with.
    pub fn local_node_id(&self) -> &str {
        &self.local_node_id
    }
}

// --- Cross-node routing (J2) ---
//
// The routing methods are specialised to `DistributedCache<Bytes>` because
// that is what the semantic-cache (and every other mesh consumer we expect
// to add near-term) actually uses, and the RPC wire format in
// `crate::transport::frame` is already fixed to `Bytes`. Keeping the
// generic parameter intact for `get_local`/`put_local` preserves the
// existing API while avoiding the serialization gymnastics a fully
// generic routed API would require.

impl DistributedCache<Bytes> {
    /// Fetch `key` via the consistent hash ring.
    ///
    /// If the local node owns the key, serves from the local shard. Otherwise
    /// routes through `pool` to the peer returned by `peer_addr_for_node`.
    ///
    /// Fail-open: any transport error (connection refused, read timeout,
    /// missing peer mapping) returns `None` rather than `Err`. Semantic cache
    /// callers treat a `None` as a cache miss, which is the desired graceful
    /// degradation path. Callers that need to distinguish transport failure
    /// from a clean miss can inspect the `tracing` output.
    pub async fn get_routed(
        &self,
        key: &str,
        pool: &TransportClientPool,
        peer_addr_for_node: impl Fn(&str) -> Option<String>,
    ) -> Option<Bytes> {
        // --- Owner resolution ---
        let owner = match self.responsible_node(key) {
            Some(id) => id,
            // Empty ring: fall back to local (matches `is_local` semantics).
            None => return self.get_local(key),
        };
        if owner == self.local_node_id {
            return self.get_local(key);
        }

        // --- Remote fetch ---
        let Some(addr) = peer_addr_for_node(&owner) else {
            tracing::debug!(
                owner = %owner,
                key = %key,
                "get_routed: no transport address for owner, returning local-miss"
            );
            return None;
        };
        let client = pool.client_for(&addr);
        match client.get(key.to_string()).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(
                    owner = %owner,
                    addr = %addr,
                    error = %e,
                    "get_routed: peer fetch failed, returning miss"
                );
                None
            }
        }
    }

    /// Store `key` -> `value` via the consistent hash ring with no expiry.
    ///
    /// Convenience wrapper around [`Self::put_routed_with_ttl`] with `ttl_secs =
    /// 0` (no expiry). Preserved for back-compat with callers that do not
    /// need TTL semantics.
    pub async fn put_routed(
        &self,
        key: &str,
        value: Bytes,
        pool: &TransportClientPool,
        peer_addr_for_node: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<()> {
        self.put_routed_with_ttl(key, value, 0, pool, peer_addr_for_node)
            .await
    }

    /// Store `key` -> `value` via the consistent hash ring with an optional TTL.
    ///
    /// If the local node owns the key, writes to the local shard (honoring
    /// `ttl_secs` via [`Self::put_local_with_ttl`]). Otherwise routes through
    /// `pool` to the peer returned by `peer_addr_for_node`; the remote
    /// peer applies the TTL to its local shard.
    ///
    /// `ttl_secs = 0` is treated as "no expiry" and matches the pre-K1
    /// `put_routed` semantics.
    ///
    /// Unlike [`Self::get_routed`], transport failures are returned to the caller
    /// as `Err` so they can decide whether to fall back (e.g. write-through
    /// to Redis) or simply log. The current semantic-cache adapter logs.
    pub async fn put_routed_with_ttl(
        &self,
        key: &str,
        value: Bytes,
        ttl_secs: u64,
        pool: &TransportClientPool,
        peer_addr_for_node: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<()> {
        let owner = match self.responsible_node(key) {
            Some(id) => id,
            None => {
                self.put_local_with_ttl(key, value, ttl_secs);
                return Ok(());
            }
        };
        if owner == self.local_node_id {
            self.put_local_with_ttl(key, value, ttl_secs);
            return Ok(());
        }
        let addr = peer_addr_for_node(&owner).ok_or_else(|| {
            anyhow::anyhow!("put_routed: no transport address configured for owner node '{owner}'")
        })?;
        let client = pool.client_for(&addr);
        client.put_with_ttl(key.to_string(), value, ttl_secs).await
    }

    /// Delete `key` via the consistent hash ring.
    ///
    /// Routing mirrors [`Self::put_routed`]. Transport failures propagate as
    /// `Err` so callers can surface them; semantic cache treats a failed
    /// delete as a cache-miss on the next lookup (the entry will continue
    /// living on the remote peer until a subsequent successful delete or
    /// TTL-driven eviction).
    pub async fn delete_routed(
        &self,
        key: &str,
        pool: &TransportClientPool,
        peer_addr_for_node: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<()> {
        let owner = match self.responsible_node(key) {
            Some(id) => id,
            None => {
                self.delete_local(key);
                return Ok(());
            }
        };
        if owner == self.local_node_id {
            self.delete_local(key);
            return Ok(());
        }
        let addr = peer_addr_for_node(&owner).ok_or_else(|| {
            anyhow::anyhow!(
                "delete_routed: no transport address configured for owner node '{owner}'"
            )
        })?;
        let client = pool.client_for(&addr);
        client.delete(key.to_string()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ConsistentHashRing tests ---

    #[test]
    fn empty_ring_returns_none() {
        let ring = ConsistentHashRing::new(10);
        assert_eq!(ring.get_node("any-key"), None);
        assert_eq!(ring.node_count(), 0);
    }

    #[test]
    fn single_node_always_owns_all_keys() {
        let mut ring = ConsistentHashRing::new(10);
        ring.add_node("node-a");
        assert_eq!(ring.get_node("key-1"), Some("node-a"));
        assert_eq!(ring.get_node("key-2"), Some("node-a"));
        assert_eq!(ring.get_node("anything"), Some("node-a"));
    }

    #[test]
    fn add_multiple_nodes_splits_ownership() {
        let mut ring = ConsistentHashRing::new(100);
        ring.add_node("node-a");
        ring.add_node("node-b");
        ring.add_node("node-c");
        assert_eq!(ring.node_count(), 3);

        // With 100 vnodes each, keys should distribute across nodes
        let keys: Vec<String> = (0..50).map(|i| format!("key-{i}")).collect();
        let mut owners: std::collections::HashSet<String> = std::collections::HashSet::new();
        for key in &keys {
            if let Some(owner) = ring.get_node(key) {
                owners.insert(owner.to_string());
            }
        }
        // With 50 keys and 3 nodes + 100 vnodes, all nodes should own at least one key
        assert!(!owners.is_empty());
    }

    #[test]
    fn remove_node_leaves_remaining_nodes() {
        let mut ring = ConsistentHashRing::new(10);
        ring.add_node("node-a");
        ring.add_node("node-b");
        ring.remove_node("node-b");
        assert_eq!(ring.node_count(), 1);
        // node-a still handles all keys
        assert_eq!(ring.get_node("any"), Some("node-a"));
    }

    #[test]
    fn remove_all_nodes_leaves_empty_ring() {
        let mut ring = ConsistentHashRing::new(10);
        ring.add_node("node-a");
        ring.remove_node("node-a");
        assert_eq!(ring.node_count(), 0);
        assert_eq!(ring.get_node("key"), None);
    }

    #[test]
    fn same_key_always_maps_to_same_node() {
        let mut ring = ConsistentHashRing::new(50);
        ring.add_node("n1");
        ring.add_node("n2");
        ring.add_node("n3");
        let first = ring.get_node("stable-key").unwrap().to_string();
        for _ in 0..10 {
            assert_eq!(ring.get_node("stable-key"), Some(first.as_str()));
        }
    }

    // --- DistributedCache tests ---

    #[test]
    fn new_cache_has_local_node_in_ring() {
        let cache: DistributedCache<String> = DistributedCache::new("local-node", 10);
        assert_eq!(
            cache.responsible_node("any-key"),
            Some("local-node".to_string())
        );
    }

    #[test]
    fn put_and_get_local_string() {
        let cache: DistributedCache<String> = DistributedCache::new("local-node", 10);
        cache.put_local("my-key", "my-value".to_string());
        assert_eq!(cache.get_local("my-key"), Some("my-value".to_string()));
    }

    #[test]
    fn put_and_get_local_bytes() {
        use bytes::Bytes;
        let cache: DistributedCache<Bytes> = DistributedCache::new("local-node", 10);
        cache.put_local("my-key", Bytes::from_static(b"payload"));
        assert_eq!(
            cache.get_local("my-key"),
            Some(Bytes::from_static(b"payload"))
        );
    }

    #[test]
    fn get_missing_key_returns_none() {
        let cache: DistributedCache<String> = DistributedCache::new("local-node", 10);
        assert_eq!(cache.get_local("missing"), None);
    }

    #[test]
    fn is_local_with_only_local_node() {
        let cache: DistributedCache<String> = DistributedCache::new("local", 10);
        assert!(cache.is_local("any-key"), "single node owns all keys");
    }

    #[test]
    fn add_and_remove_node_from_cache() {
        let cache: DistributedCache<String> = DistributedCache::new("local", 10);
        cache.add_node("remote-1");
        cache.add_node("remote-2");
        cache.remove_node("remote-1");
        // Should not panic and ring should still work
        let owner = cache.responsible_node("test-key");
        assert!(owner.is_some());
    }

    #[test]
    fn overwrite_value_in_local_cache() {
        let cache: DistributedCache<String> = DistributedCache::new("local", 10);
        cache.put_local("k", "v1".to_string());
        cache.put_local("k", "v2".to_string());
        assert_eq!(cache.get_local("k"), Some("v2".to_string()));
    }

    #[test]
    fn local_node_id_accessor() {
        let cache: DistributedCache<String> = DistributedCache::new("node-xyz", 4);
        assert_eq!(cache.local_node_id(), "node-xyz");
    }

    #[test]
    fn delete_local_removes_entry() {
        let cache: DistributedCache<String> = DistributedCache::new("local", 10);
        cache.put_local("k", "v".to_string());
        assert!(cache.delete_local("k"), "delete_local returns true on hit");
        assert_eq!(cache.get_local("k"), None);
        assert!(
            !cache.delete_local("k"),
            "delete_local returns false on miss"
        );
    }

    // --- K2: prefix / all local purge ---

    #[test]
    fn purge_prefix_local_removes_only_matching_keys() {
        // Prefix scan must match the exact byte prefix and leave non-matching
        // entries untouched. This is the local half of the K2 cluster-wide
        // purge fan-out; the RPC dispatcher calls straight into this method.
        let cache: DistributedCache<String> = DistributedCache::new("local", 10);
        cache.put_local("foo:1", "a".to_string());
        cache.put_local("foo:2", "b".to_string());
        cache.put_local("bar:1", "c".to_string());

        let removed = cache.purge_prefix_local("foo:");
        assert_eq!(removed, 2, "both 'foo:*' entries must be purged");
        assert_eq!(cache.get_local("foo:1"), None);
        assert_eq!(cache.get_local("foo:2"), None);
        assert_eq!(
            cache.get_local("bar:1"),
            Some("c".to_string()),
            "non-matching entry must survive a prefix purge"
        );
    }

    #[test]
    fn purge_prefix_local_returns_zero_on_no_match() {
        let cache: DistributedCache<String> = DistributedCache::new("local", 10);
        cache.put_local("foo:1", "a".to_string());
        let removed = cache.purge_prefix_local("baz:");
        assert_eq!(removed, 0, "no keys match => nothing removed");
        assert_eq!(cache.get_local("foo:1"), Some("a".to_string()));
    }

    #[test]
    fn purge_prefix_local_empty_prefix_matches_everything() {
        // The K2 wire protocol encodes "purge all" as `PurgePrefix { prefix:
        // "" }`, so an empty prefix must match every key. The server-side
        // dispatcher short-circuits to `purge_all_local` in practice, but we
        // keep this property here too so callers who hit the method
        // directly get the same shape.
        let cache: DistributedCache<String> = DistributedCache::new("local", 10);
        cache.put_local("a", "1".to_string());
        cache.put_local("b", "2".to_string());
        let removed = cache.purge_prefix_local("");
        assert_eq!(removed, 2);
        assert_eq!(cache.local_len(), 0);
    }

    #[test]
    fn purge_all_local_removes_everything() {
        let cache: DistributedCache<String> = DistributedCache::new("local", 10);
        cache.put_local("a", "1".to_string());
        cache.put_local("b", "2".to_string());
        cache.put_local("c", "3".to_string());
        let removed = cache.purge_all_local();
        assert_eq!(removed, 3);
        assert_eq!(cache.local_len(), 0);
    }

    #[test]
    fn purge_all_local_on_empty_returns_zero() {
        let cache: DistributedCache<String> = DistributedCache::new("local", 10);
        assert_eq!(cache.purge_all_local(), 0);
    }

    // --- J2: Routing tests ---

    use crate::transport::{TransportClientPool, TransportServer};
    use std::sync::Arc;

    /// Pick a key from a set that is owned by a specific peer, given a ring
    /// that contains `local_id` and `remote_id`. Returns the key string.
    /// Panics if no suitable key is found in a reasonable search range - in
    /// practice the first few keys are always enough with 128 vnodes.
    fn find_key_owned_by(cache: &DistributedCache<Bytes>, remote_id: &str) -> String {
        for i in 0..2_000u32 {
            let k = format!("probe-{i}");
            if cache.responsible_node(&k).as_deref() == Some(remote_id) {
                return k;
            }
        }
        panic!("could not find a key owned by {remote_id} in first 2000 probes");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_nodes_share_cache_via_tcp() {
        // --- Node B: remote peer ---
        //
        // Stand up a DistributedCache<Bytes> and a TransportServer so
        // node A can reach it over TCP.
        let cache_b: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("node-B", 128));
        let server_b = TransportServer::start(0, cache_b.clone())
            .await
            .expect("server B bind");
        let port_b = server_b.local_port();

        // --- Node A: local side driving the test ---
        //
        // Node A's cache owns its own keys + B's keys (it knows B via the
        // consistent-hash ring).
        let cache_a: DistributedCache<Bytes> = DistributedCache::new("node-A", 128);
        cache_a.add_node("node-B");

        // --- Peer-address lookup ---
        //
        // A single mapping entry: the remote node id -> its transport port
        // on localhost. Real deployments source this from gossip; tests
        // short-circuit to a fixed map.
        let peer_addr_map: std::collections::HashMap<String, String> = {
            let mut m = std::collections::HashMap::new();
            m.insert("node-B".to_string(), format!("127.0.0.1:{port_b}"));
            m
        };
        let lookup = |node_id: &str| peer_addr_map.get(node_id).cloned();
        let pool = TransportClientPool::new();

        // --- Pick a key owned by B ---
        let key = find_key_owned_by(&cache_a, "node-B");
        assert_eq!(cache_a.responsible_node(&key).as_deref(), Some("node-B"));

        // --- Route a put from A: must land on B ---
        cache_a
            .put_routed(&key, Bytes::from_static(b"hello"), &pool, &lookup)
            .await
            .expect("put_routed ok");
        // Sanity: A's local shard is still empty for this key.
        assert_eq!(
            cache_a.get_local(&key),
            None,
            "routed put should NOT touch A's local shard"
        );
        // B's local shard now has it.
        assert_eq!(cache_b.get_local(&key), Some(Bytes::from_static(b"hello")));

        // --- Route a get from A: must return B's value ---
        let got = cache_a.get_routed(&key, &pool, &lookup).await;
        assert_eq!(got, Some(Bytes::from_static(b"hello")));

        // --- Route a delete from A: must evict on B ---
        cache_a
            .delete_routed(&key, &pool, &lookup)
            .await
            .expect("delete_routed ok");
        assert_eq!(cache_b.get_local(&key), None);
        assert_eq!(
            cache_a.get_routed(&key, &pool, &lookup).await,
            None,
            "get after routed delete should miss"
        );

        // --- Cleanup ---
        server_b.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_routed_fails_open_when_peer_unreachable() {
        let cache_a: DistributedCache<Bytes> = DistributedCache::new("node-A", 128);
        cache_a.add_node("node-B");

        // Map B to a port with nothing listening.
        let lookup = |node_id: &str| -> Option<String> {
            if node_id == "node-B" {
                Some("127.0.0.1:1".to_string())
            } else {
                None
            }
        };
        let pool = TransportClientPool::new();

        let key = find_key_owned_by(&cache_a, "node-B");
        // get_routed must return None rather than Err / panic / block.
        let got = cache_a.get_routed(&key, &pool, &lookup).await;
        assert_eq!(got, None);

        // A subsequent call must also complete (no deadlock).
        let got2 = cache_a.get_routed(&key, &pool, &lookup).await;
        assert_eq!(got2, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn put_routed_returns_err_when_peer_unreachable() {
        let cache_a: DistributedCache<Bytes> = DistributedCache::new("node-A", 128);
        cache_a.add_node("node-B");

        let lookup = |node_id: &str| -> Option<String> {
            if node_id == "node-B" {
                Some("127.0.0.1:1".to_string())
            } else {
                None
            }
        };
        let pool = TransportClientPool::new();

        let key = find_key_owned_by(&cache_a, "node-B");
        let err = cache_a
            .put_routed(&key, Bytes::from_static(b"x"), &pool, &lookup)
            .await
            .expect_err("put should fail when peer is down");
        let msg = err.to_string();
        assert!(msg.contains("connect") || msg.contains("127.0.0.1:1"));
    }

    #[tokio::test]
    async fn get_routed_serves_locally_when_local_owner() {
        // Only the local node is in the ring, so every key is owned
        // locally and get_routed should never touch the pool.
        let cache: DistributedCache<Bytes> = DistributedCache::new("solo", 128);
        cache.put_local("k", Bytes::from_static(b"v"));
        let pool = TransportClientPool::new();
        let lookup = |_: &str| -> Option<String> { None };
        let got = cache.get_routed("k", &pool, lookup).await;
        assert_eq!(got, Some(Bytes::from_static(b"v")));
        assert!(
            pool.is_empty(),
            "pool should not be touched for local owner"
        );
    }

    // --- K1: TTL tests ---

    #[tokio::test(flavor = "multi_thread")]
    async fn entries_without_ttl_do_not_expire() {
        // Sanity: `put_local` preserves the no-expiry default and entries
        // remain readable across an arbitrary sleep.
        let cache: DistributedCache<Bytes> = DistributedCache::new("a", 10);
        cache.put_local("k", Bytes::from_static(b"v"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(cache.get_local("k"), Some(Bytes::from_static(b"v")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn entries_with_ttl_zero_do_not_expire() {
        // `ttl_secs = 0` is the "no expiry" convention matching the pre-K1
        // `put_local` semantics.
        let cache: DistributedCache<Bytes> = DistributedCache::new("a", 10);
        cache.put_local_with_ttl("k", Bytes::from_static(b"v"), 0);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(cache.get_local("k"), Some(Bytes::from_static(b"v")));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn entries_with_ttl_expire_on_read() {
        // Lazy expiry: `get_local` must drop entries whose deadline has
        // elapsed, independent of the background sweeper.
        let cache: DistributedCache<Bytes> = DistributedCache::new("a", 10);
        cache.put_local_with_ttl("k", Bytes::from_static(b"v"), 1);
        assert_eq!(cache.get_local("k"), Some(Bytes::from_static(b"v")));
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert_eq!(cache.get_local("k"), None);
        // The expired entry must also be removed from the underlying map,
        // not just hidden behind a `None` return.
        assert_eq!(cache.local_len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sweep_expired_removes_entries_without_read() {
        // Explicit sweep: simulates the background task firing without
        // relying on wall-clock interval ticks.
        let cache: DistributedCache<Bytes> = DistributedCache::new("a", 10);
        cache.put_local_with_ttl("k", Bytes::from_static(b"v"), 1);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert_eq!(
            cache.local_len(),
            1,
            "expired entry sits in the map until swept or read"
        );
        cache.sweep_expired();
        assert_eq!(cache.local_len(), 0, "sweeper must evict expired entries");
        assert_eq!(cache.get_local("k"), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sweep_expired_leaves_live_entries() {
        // Mixed bag: a no-expiry entry plus an already-expired entry.
        // Sweeper must remove the expired one and leave the other alone.
        let cache: DistributedCache<Bytes> = DistributedCache::new("a", 10);
        cache.put_local("stays", Bytes::from_static(b"forever"));
        cache.put_local_with_ttl("goes", Bytes::from_static(b"soon"), 1);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        cache.sweep_expired();
        assert_eq!(
            cache.get_local("stays"),
            Some(Bytes::from_static(b"forever"))
        );
        assert_eq!(cache.get_local("goes"), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sweeper_task_runs_and_evicts_on_interval() {
        // End-to-end: spawn the sweeper with a 1s cadence and verify that
        // an expired entry is evicted without any read in between. We
        // wait a little more than two intervals because `start_sweeper`
        // skips the first immediate tick (see its impl note).
        let cache = DistributedCache::<Bytes>::new_with_sweeper("a", 10, 1);
        cache.put_local_with_ttl("k", Bytes::from_static(b"v"), 1);
        assert_eq!(cache.local_len(), 1);
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert_eq!(
            cache.local_len(),
            0,
            "background sweeper must evict the expired entry without a read"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sweeper_task_exits_when_last_arc_drops() {
        // Weak-ref design: dropping the last strong `Arc<DistributedCache>`
        // must let the sweeper task exit on its next tick. We cannot
        // observe the JoinHandle directly (it is owned by the tokio
        // runtime), so we verify the indirect signal: the `Weak::upgrade`
        // inside the sweeper returns `None` and the task breaks out of
        // its loop without panicking when the interval fires after the
        // drop.
        let cache = DistributedCache::<Bytes>::new_with_sweeper("a", 10, 1);
        drop(cache);
        // Give the sweeper enough time to tick past the drop. If the task
        // panicked or held a strong reference, the runtime would
        // eventually surface an error during teardown.
        tokio::time::sleep(Duration::from_millis(2_000)).await;
    }

    #[tokio::test]
    async fn put_routed_with_ttl_local_owner_honors_ttl() {
        // Routed put with TTL, single-node ring: the local node owns every
        // key, so `put_routed_with_ttl` writes directly to the local
        // shard and the TTL applies to `get_local`.
        let cache: DistributedCache<Bytes> = DistributedCache::new("solo", 128);
        let pool = TransportClientPool::new();
        let lookup = |_: &str| -> Option<String> { None };
        cache
            .put_routed_with_ttl("k", Bytes::from_static(b"v"), 1, &pool, lookup)
            .await
            .expect("put_routed_with_ttl ok");
        assert_eq!(cache.get_local("k"), Some(Bytes::from_static(b"v")));
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert_eq!(cache.get_local("k"), None);
    }

    #[tokio::test]
    async fn put_routed_missing_peer_address_returns_err() {
        let cache_a: DistributedCache<Bytes> = DistributedCache::new("node-A", 128);
        cache_a.add_node("node-B");
        // Lookup returns None for every node, simulating a stale peer
        // table that knows of node-B but cannot resolve its transport
        // address.
        let lookup = |_: &str| -> Option<String> { None };
        let pool = TransportClientPool::new();
        let key = find_key_owned_by(&cache_a, "node-B");
        let err = cache_a
            .put_routed(&key, Bytes::from_static(b"x"), &pool, &lookup)
            .await
            .expect_err("put_routed should fail without a peer mapping");
        assert!(err.to_string().contains("no transport address"));
    }
}
