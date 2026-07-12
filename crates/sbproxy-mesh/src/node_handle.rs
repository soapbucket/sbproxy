//! Live handle returned by [`crate::bootstrap::bootstrap`].
//!
//! Bundles the cluster-wide distributed cache with the local node identity and
//! the snapshot of peers discovered at bootstrap time. Enterprise consumers
//! (semantic cache, rate-limit, etc.) clone the `Arc<DistributedCache<_>>` to
//! route reads/writes through the mesh without depending on the bootstrap
//! call site.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use bytes::Bytes;

use crate::gossip_loop::{GossipLoop, PeerTable};
use crate::isolation::IsolationObserver;
use crate::peer_eviction::PeerEvictor;
use crate::state::distributed_cache::DistributedCache;
use crate::transport::{TransportClientPool, TransportServer};

/// Live handle to a bootstrapped mesh node. Owns the distributed cache and a
/// snapshot of the membership view; dropped when the node leaves the cluster.
///
/// The `distributed_cache` is wrapped in an `Arc` so downstream consumers can
/// cheaply clone a reference and share the hash ring + local storage across
/// the request path.
pub struct MeshNode {
    /// Locally assigned node identifier (matches `MeshConfig::node_id`).
    pub node_id: String,

    /// Snapshot of peer addresses discovered during bootstrap. Live updates are
    /// available via the gossip protocol's subscribers; this field is the
    /// point-in-time view used to seed the consistent hash ring.
    pub peers: Vec<String>,

    /// Cluster-wide distributed cache, keyed by `String`, value `Bytes`.
    /// Enterprise consumers (e.g. `MeshSemanticCacheStore`) clone this `Arc`
    /// to dispatch reads/writes through the mesh.
    pub distributed_cache: Arc<DistributedCache<Bytes>>,

    /// Running gossip loop. `None` when the UDP socket could not be bound at
    /// bootstrap time; the rest of the handle is still fully usable but this
    /// node will not observe peer liveness until it can re-bind.
    gossip_loop: Option<GossipLoop>,

    /// Shared peer table consumed by the gossip loop. Kept alive on the
    /// handle so it is dropped only when the mesh node itself is dropped.
    /// Exposed for diagnostics via [`MeshNode::peer_table`].
    peer_table: Option<Arc<RwLock<PeerTable>>>,

    /// Shared eviction tracker consumed by the gossip loop. Exposed for
    /// diagnostics via [`MeshNode::peer_evictor`].
    peer_evictor: Option<Arc<PeerEvictor>>,

    /// Shared isolation observer consumed by the gossip loop. Exposed for
    /// diagnostics / mesh-aware consumers via
    /// [`MeshNode::isolation_observer`].
    isolation_observer: Option<Arc<IsolationObserver>>,

    /// Running cross-node cache RPC server (J2). `None` when the TCP bind
    /// failed at bootstrap time; the rest of the handle continues to
    /// function but remote peers will not be able to reach this node's
    /// cache shard. Cleanly shut down when the handle is dropped.
    transport_server: Option<TransportServer>,

    /// Pool of outbound [`crate::transport::PeerClient`] instances keyed
    /// by `host:port`. Shared with `DistributedCache::*_routed` callers
    /// (typically `MeshSemanticCacheStore`) so they reuse the same
    /// persistent connection per peer.
    transport_pool: Arc<TransportClientPool>,

    /// Enrolled identity proof issuer/verifier for canonical mTLS state.
    identity_authenticator: Option<Arc<crate::peer_identity::PeerIdentityAuthenticator>>,

    /// `node_id -> host:port` mapping used by routed cache ops to resolve
    /// the consistent-hash owner into a transport address. Populated from
    /// config (seed peers) at bootstrap; gossip-driven updates would
    /// rewrite this map in a future phase. Exposed via
    /// [`MeshNode::peer_addr_map`] so consumers can inspect / refresh it.
    peer_addr_map: Arc<RwLock<HashMap<String, String>>>,

    /// Optional periodic snapshot task (Phase 2 of the hybrid Redis
    /// design). Dropped on `MeshNode::drop` which signals the task to
    /// stop; the task performs a final flush on shutdown. `None` when
    /// persistence is disabled or the backend could not be constructed.
    persistence_task: Option<crate::persistence::SnapshotTaskHandle>,

    /// Optional federation loop (Phases 4-5 of the hybrid Redis
    /// design). Drops on `MeshNode::drop` which signals shutdown. `None`
    /// when federation is disabled or mesh config has no federation block.
    federation_task: Option<crate::federation::FederationTaskHandle>,
}

impl MeshNode {
    /// Construct a new handle. `peers` is the bootstrap-time snapshot of
    /// discovered peer addresses (each is added to the cache's hash ring).
    ///
    /// The distributed cache is wrapped in an `Arc` before the sweeper
    /// task is spawned so the sweeper can hold a `Weak` reference and
    /// exit cleanly when the last handle is dropped. The sweeper uses
    /// the crate-default period (see
    /// [`crate::state::distributed_cache::DEFAULT_SWEEP_INTERVAL_SECS`]);
    /// call sites that need a custom interval can construct the cache
    /// themselves and inject it here in a future refactor.
    pub fn new(node_id: String, peers: Vec<String>, vnodes: usize) -> Self {
        use crate::state::distributed_cache::DEFAULT_SWEEP_INTERVAL_SECS;
        let cache = DistributedCache::<Bytes>::new_with_sweeper(
            &node_id,
            vnodes,
            DEFAULT_SWEEP_INTERVAL_SECS,
        );
        // Seed the consistent hash ring with every discovered peer so routing
        // decisions reflect the bootstrap-time membership view. Gossip-driven
        // membership updates will call `add_node`/`remove_node` on the shared
        // `Arc` as the cluster evolves.
        for peer in &peers {
            cache.add_node(peer);
        }
        Self {
            node_id,
            peers,
            distributed_cache: cache,
            gossip_loop: None,
            peer_table: None,
            peer_evictor: None,
            isolation_observer: None,
            transport_server: None,
            transport_pool: Arc::new(TransportClientPool::new()),
            identity_authenticator: None,
            peer_addr_map: Arc::new(RwLock::new(HashMap::new())),
            persistence_task: None,
            federation_task: None,
        }
    }

    /// Attach a running [`GossipLoop`] and its shared primitives to this
    /// handle. Consumes `self` and returns it so `bootstrap()` can chain the
    /// construction.
    ///
    /// The loop is shut down when the returned handle is dropped.
    pub fn with_gossip_loop(
        mut self,
        gossip_loop: GossipLoop,
        peer_table: Arc<RwLock<PeerTable>>,
        peer_evictor: Arc<PeerEvictor>,
        isolation_observer: Arc<IsolationObserver>,
    ) -> Self {
        self.gossip_loop = Some(gossip_loop);
        self.peer_table = Some(peer_table);
        self.peer_evictor = Some(peer_evictor);
        self.isolation_observer = Some(isolation_observer);
        self
    }

    /// Attach the cross-node cache RPC transport (J2). Consumes `self` so
    /// `bootstrap()` can chain the construction in a single expression.
    ///
    /// `transport_server` is the running TCP listener; pass `None` when
    /// the bind failed at bootstrap and the handle should continue without
    /// inbound routing. `peer_addr_map` is a shared `node_id -> host:port`
    /// table that routed cache ops consult to resolve a consistent-hash
    /// owner to a reachable transport address.
    pub fn with_transport(
        mut self,
        transport_server: Option<TransportServer>,
        transport_pool: Arc<TransportClientPool>,
        peer_addr_map: Arc<RwLock<HashMap<String, String>>>,
    ) -> Self {
        self.transport_server = transport_server;
        self.transport_pool = transport_pool;
        self.peer_addr_map = peer_addr_map;
        self
    }

    /// Attach the enrolled identity proof issuer used by typed cluster state.
    pub fn with_identity_authenticator(
        mut self,
        authenticator: Option<Arc<crate::peer_identity::PeerIdentityAuthenticator>>,
    ) -> Self {
        self.identity_authenticator = authenticator;
        self
    }

    /// Returns a cheap `Arc` clone of the distributed cache suitable for
    /// passing to consumer crates (semantic cache, rate-limit, etc).
    pub fn distributed_cache(&self) -> Arc<DistributedCache<Bytes>> {
        self.distributed_cache.clone()
    }

    /// Locally assigned node identifier.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Snapshot of peer addresses captured during bootstrap.
    pub fn peers(&self) -> &[String] {
        &self.peers
    }

    /// Optional shared peer table used by the gossip loop. `None` if the
    /// loop did not start (e.g. UDP bind failure).
    pub fn peer_table(&self) -> Option<Arc<RwLock<PeerTable>>> {
        self.peer_table.clone()
    }

    /// Optional peer evictor driven by the gossip loop.
    pub fn peer_evictor(&self) -> Option<Arc<PeerEvictor>> {
        self.peer_evictor.clone()
    }

    /// Optional isolation observer driven by the gossip loop. Consumers can
    /// short-circuit mesh reads while `is_isolated()` returns `true`.
    pub fn isolation_observer(&self) -> Option<Arc<IsolationObserver>> {
        self.isolation_observer.clone()
    }

    /// Shared transport client pool. Callers route cross-node cache ops
    /// through this pool so every outbound RPC reuses the same persistent
    /// TCP connection per peer.
    pub fn transport_pool(&self) -> Arc<TransportClientPool> {
        self.transport_pool.clone()
    }

    /// Enrolled identity proof issuer/verifier for canonical mTLS state.
    pub fn identity_authenticator(
        &self,
    ) -> Option<Arc<crate::peer_identity::PeerIdentityAuthenticator>> {
        self.identity_authenticator.clone()
    }

    /// Attach a periodic Redis-backed snapshot task. Called by the
    /// enterprise startup hook after bootstrap when `MeshConfig.persistence`
    /// is enabled. The task is shut down and flushed when the `MeshNode`
    /// is dropped.
    ///
    /// Takes ownership of the handle. Calling this more than once replaces
    /// the prior task (the prior task's graceful shutdown runs on the
    /// replaced handle's Drop).
    pub fn with_persistence(mut self, handle: crate::persistence::SnapshotTaskHandle) -> Self {
        self.persistence_task = Some(handle);
        self
    }

    /// Returns `true` when a periodic snapshot task is running.
    pub fn has_persistence(&self) -> bool {
        self.persistence_task.is_some()
    }

    /// Attach a running federation loop. Called by the enterprise startup
    /// hook after persistence is wired when `MeshConfig.federation` is
    /// enabled. Task is shut down when the `MeshNode` is dropped.
    pub fn with_federation(mut self, handle: crate::federation::FederationTaskHandle) -> Self {
        self.federation_task = Some(handle);
        self
    }

    /// Returns `true` when a federation loop is running.
    pub fn has_federation(&self) -> bool {
        self.federation_task.is_some()
    }

    /// Returns the current leader node id, computed deterministically as
    /// the lexicographically smallest node_id among this node + live
    /// peers. Every node in the cluster sees the same ordering because
    /// each node sees the same SWIM membership view after gossip
    /// convergence. Returns `Some(self.node_id)` when no peer table is
    /// attached (solo node).
    ///
    /// This is a simple deterministic leader election suitable for
    /// low-frequency coordination tasks like federation push (one
    /// pusher per cluster). It is NOT a strong consensus primitive.
    pub fn current_leader(&self) -> Option<String> {
        let Some(table) = self.peer_table.as_ref() else {
            return Some(self.node_id.clone());
        };
        let guard = match table.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut ids: Vec<String> = vec![self.node_id.clone()];
        for peer in guard.iter() {
            if matches!(peer.state, crate::gossip_loop::PeerState::Alive) {
                ids.push(peer.node_id.clone());
            }
        }
        ids.sort();
        ids.into_iter().next()
    }

    /// Build a cheap, cloneable leader-check closure.
    ///
    /// The returned closure holds a weak view of the peer table (via an
    /// `Arc`), so it keeps returning up-to-date answers as gossip runs
    /// without re-taking the `MeshNode`. Wires directly into
    /// [`crate::federation::spawn_federation_loop`]'s `is_leader`
    /// parameter.
    pub fn is_leader_fn(&self) -> impl Fn() -> bool + Send + Sync + 'static {
        let peer_table = self.peer_table.clone();
        let my_id = self.node_id.clone();
        move || {
            let Some(table) = peer_table.as_ref() else {
                return true;
            };
            let guard = match table.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let mut ids: Vec<String> = vec![my_id.clone()];
            for peer in guard.iter() {
                if matches!(peer.state, crate::gossip_loop::PeerState::Alive) {
                    ids.push(peer.node_id.clone());
                }
            }
            ids.sort();
            ids.into_iter().next().map(|s| s == my_id).unwrap_or(true)
        }
    }

    /// Returns `true` when the inbound cross-node cache RPC server bound
    /// successfully at bootstrap. When this is `false`, peers cannot reach
    /// this node's cache shard over TCP; enabling cross-node routing on the
    /// semantic cache in that state would only produce asymmetric traffic
    /// (we can read/write to peers, but they cannot reach us). Callers use
    /// this to decide whether to fall back to local-only storage.
    pub fn has_transport(&self) -> bool {
        self.transport_server.is_some()
    }

    /// Shared `node_id -> host:port` table consulted by routed cache ops
    /// to resolve the consistent-hash owner of a key into a reachable
    /// transport address. The returned `Arc` is the same one used inside
    /// the closure returned by [`Self::peer_addr_lookup`]; mutating it is
    /// visible to subsequent routed calls without any extra wiring.
    pub fn peer_addr_map(&self) -> Arc<RwLock<HashMap<String, String>>> {
        self.peer_addr_map.clone()
    }

    /// Build a `Fn(&str) -> Option<String>` closure over a cheap `Arc`
    /// clone of the peer-address map. Pass the result to
    /// [`DistributedCache::get_routed`](crate::state::distributed_cache::DistributedCache::get_routed)
    /// / `put_routed` / `delete_routed`.
    ///
    /// The closure holds an `Arc` clone so it outlives the `MeshNode` - a
    /// `MeshSemanticCacheStore` can cache the resolver and keep routing
    /// even if the original `MeshNode` handle is passed around by value.
    pub fn peer_addr_lookup(&self) -> impl Fn(&str) -> Option<String> + Send + Sync + 'static {
        let map = self.peer_addr_map.clone();
        move |node_id: &str| {
            let guard = match map.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.get(node_id).cloned()
        }
    }

    /// Build a `Fn() -> Vec<String>` closure that returns the current set
    /// of known peer transport addresses (every `host:port` the peer-addr
    /// map knows about, excluding this node's own address).
    ///
    /// Used by the K2 cluster-wide purge fan-out to enumerate every peer
    /// a purge RPC should be sent to. Like [`Self::peer_addr_lookup`],
    /// the closure holds an `Arc` clone of the peer-address map, so
    /// gossip-driven updates to the map are visible without rewiring the
    /// store that owns the closure.
    pub fn peer_addresses_fn(&self) -> impl Fn() -> Vec<String> + Send + Sync + 'static {
        let map = self.peer_addr_map.clone();
        move || {
            let guard = match map.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.values().cloned().collect()
        }
    }
}

impl Drop for MeshNode {
    fn drop(&mut self) {
        // Signal the gossip loop to stop. Both the send/sweep and the recv
        // task terminate after this returns, so the socket + backing tasks
        // are released deterministically.
        if let Some(loop_handle) = self.gossip_loop.take() {
            loop_handle.shutdown();
        }
        // Tear down the cross-node cache RPC server so the bound TCP port
        // is released before the test harness moves on.
        if let Some(server) = self.transport_server.take() {
            server.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distributed_cache_returns_clonable_arc() {
        let node = MeshNode::new("n1".to_string(), vec![], 16);
        let cache_a = node.distributed_cache();
        let cache_b = node.distributed_cache();
        // Both clones must point at the same allocation.
        assert!(Arc::ptr_eq(&cache_a, &cache_b));
        // And the original handle still holds its own strong reference.
        assert!(Arc::strong_count(&node.distributed_cache) >= 3);
    }

    #[test]
    fn node_id_and_peers_accessors_return_snapshot() {
        let node = MeshNode::new(
            "node-abc".to_string(),
            vec!["10.0.0.2:7946".to_string(), "10.0.0.3:7946".to_string()],
            8,
        );
        assert_eq!(node.node_id(), "node-abc");
        assert_eq!(
            node.peers(),
            &["10.0.0.2:7946".to_string(), "10.0.0.3:7946".to_string()]
        );
    }

    #[test]
    fn distributed_cache_seeded_with_peers() {
        let node = MeshNode::new(
            "local".to_string(),
            vec!["remote-1".to_string(), "remote-2".to_string()],
            32,
        );
        // Adding the local node + two peers means at least one key should
        // resolve to a non-local owner (with 32 vnodes the ring is well
        // populated).
        let cache = node.distributed_cache();
        let mut owners = std::collections::HashSet::new();
        for i in 0..200 {
            if let Some(owner) = cache.responsible_node(&format!("key-{i}")) {
                owners.insert(owner);
            }
        }
        // All three entries (local + two peers) should show up across a
        // reasonably large key sample.
        assert!(owners.contains("local"));
        assert!(owners.len() >= 2, "expected routing to spread across peers");
    }

    #[test]
    fn distributed_cache_put_get_bytes() {
        let node = MeshNode::new("n1".to_string(), vec![], 16);
        let cache = node.distributed_cache();
        cache.put_local("entry", Bytes::from_static(b"payload"));
        assert_eq!(
            cache.get_local("entry"),
            Some(Bytes::from_static(b"payload"))
        );
    }
}
