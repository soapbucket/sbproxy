//! First-node bootstrap for single-node cluster startup.
//!
//! Attempts peer discovery using all configured backends. If no peers are found
//! within the configured timeout, the node starts as a single-node cluster and
//! waits for others to join.
//!
//! The returned [`MeshNode`] is a live handle that bundles the local node id,
//! the bootstrap-time peer snapshot, and the cluster-wide `DistributedCache`.
//! Enterprise consumers (semantic cache, rate-limit, etc.) clone the cache
//! `Arc` off the handle rather than reconstructing it from the raw peer list.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::Result;

use crate::crypto::Cipher;
use crate::discovery::Discovery;
use crate::gossip_loop::{GossipLoop, GossipLoopConfig, PeerEntry, PeerTable};
use crate::isolation::IsolationObserver;
use crate::node_handle::MeshNode;
use crate::peer_eviction::{PeerEvictor, DEFAULT_MAX_CONSECUTIVE_FAILURES};
use crate::transport::{TransportClientPool, TransportServer};

/// Number of virtual nodes per real node on the consistent hash ring backing
/// [`MeshNode::distributed_cache`]. 128 is a standard default that provides
/// good key distribution without ballooning the ring's memory footprint.
const DEFAULT_CACHE_VNODES: usize = 128;

/// Default minimum peer count before [`IsolationObserver`] flips the node into
/// quarantine. Single-peer clusters should not trip the quarantine unless the
/// one peer goes away, so the floor is `1`.
const DEFAULT_MIN_PEERS_FOR_QUORUM: usize = 1;

/// Configuration for the bootstrap process.
pub struct BootstrapConfig {
    /// How long to wait for peers before starting solo (seconds).
    pub wait_for_peers_secs: u64,

    /// UDP port to bind for the gossip loop.
    pub gossip_port: u16,

    /// TCP port to bind for the cross-node cache RPC transport (J2). `0`
    /// requests an OS-assigned ephemeral port (handy for tests). A bind
    /// failure is logged and the node continues without inbound routing.
    pub transport_port: u16,

    /// Gossip address announced in join messages. Canonical callers secure
    /// those messages with the configured cluster cipher. When absent,
    /// receivers use the observed UDP source address.
    pub gossip_advertise_addr: Option<String>,

    /// Typed-state transport address announced in join messages.
    /// When absent and `transport_port` is nonzero, receivers combine the
    /// observed peer IP with that port.
    pub transport_advertise_addr: Option<String>,

    /// How often this node emits heartbeats to every known peer (seconds).
    pub heartbeat_interval_secs: u64,

    /// How often the failure-check sweep runs (seconds).
    pub failure_check_interval_secs: u64,

    /// Time after which a peer with no heartbeats is considered failed
    /// (seconds). Must be larger than `heartbeat_interval_secs`.
    pub failure_timeout_secs: u64,

    /// K3: optional cluster-wide shared secret. When `Some(non-empty)`,
    /// the bootstrap derives an AES-256-GCM [`Cipher`] from this string
    /// and threads a single clone through both the gossip loop and the
    /// transport (server + client pool). When `None` or empty, both
    /// wire protocols stay plaintext (pre-K3 behavior).
    ///
    /// Callers typically populate this from
    /// `MeshConfig.encryption.shared_key` after resolving any
    /// `${ENV}` placeholders.
    pub shared_key: Option<String>,

    // --- K4: SWIM timing knobs ---
    /// SWIM protocol period in milliseconds. One random Alive peer is
    /// probed per tick.
    pub swim_protocol_period_ms: u64,
    /// Deadline on a direct PING waiting for its ACK; on elapsed, fall
    /// back to indirect probes.
    pub swim_ping_timeout_ms: u64,
    /// K, the number of indirect probe witnesses a direct-timeout node
    /// fans PING-REQ out to. Clamped to `min(K, alive_peers - 1)` at
    /// runtime.
    pub swim_indirect_probes: usize,
    /// How long a peer stays in `Suspect` before being marked `Dead`.
    pub swim_suspect_timeout_secs: u64,

    // --- L2: dead-peer GC ---
    /// How long a peer stays in `Dead` before the L2 sweeper removes
    /// the entry from the peer table. Defaults to 300s (5 minutes).
    pub dead_peer_gc_secs: u64,

    /// Optional peer mTLS for the transport. When `Some`, the transport
    /// server requires and verifies a CA-signed client certificate on every
    /// inbound connection, and the client pool presents this node's
    /// certificate and verifies peers' on every outbound connection. `None`
    /// keeps the plaintext transport (the pre-mTLS behavior).
    pub peer_tls: Option<PeerTlsParams>,

    /// WOR-1947: optional replicated durable state substrate. When set,
    /// bootstrap opens the durable replica shard, installs it behind the
    /// transport's replica ops, and spawns the maintenance loop. `None`
    /// leaves the substrate off (single-owner cache semantics only).
    pub replication: Option<ReplicationBootstrapConfig>,
}

/// Peer-mTLS material for the mesh transport, already resolved to PEM by the
/// caller (for example by reading the configured cert/key/CA files).
#[derive(Debug, Clone)]
pub struct PeerTlsParams {
    /// This node's certificate, private key, and the shared CA (PEM).
    pub tls: crate::transport::tls::MeshTlsConfig,
    /// Cluster server-name SAN installed by the authority. Compatibility mTLS
    /// verifies this shared name; enrolled canonical transport verifies the
    /// target node-ID SAN instead.
    pub server_name: String,
    /// Enrolled identity proof issuer for canonical clusters. Compatibility
    /// mTLS may omit this and retain shared-SAN behavior.
    pub identity_authenticator: Option<Arc<crate::peer_identity::PeerIdentityAuthenticator>>,
}

/// Replicated-substrate wiring consumed by [`bootstrap`].
#[derive(Debug, Clone)]
pub struct ReplicationBootstrapConfig {
    /// Replication factor, consistency levels, cadence, GC grace.
    pub settings: crate::state::replicated::ReplicationSettings,
    /// Shard capacity and value-size bounds.
    pub limits: crate::state::replicated::ShardLimits,
    /// Durable shard file. `None` runs the shard memory-only, which
    /// keeps replication but gives up restart durability; canonical
    /// cluster config always supplies a path via `state_dir`.
    pub durable_path: Option<std::path::PathBuf>,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            wait_for_peers_secs: 5,
            gossip_port: 7946,
            transport_port: 8946,
            gossip_advertise_addr: None,
            transport_advertise_addr: None,
            heartbeat_interval_secs: 1,
            failure_check_interval_secs: 2,
            failure_timeout_secs: 5,
            shared_key: None,
            peer_tls: None,
            // K4 SWIM defaults mirror the paper's small-cluster profile.
            swim_protocol_period_ms: 1000,
            swim_ping_timeout_ms: 300,
            swim_indirect_probes: 3,
            swim_suspect_timeout_secs: 5,
            // L2: 5 minutes is long enough to absorb transient partitions
            // without letting the Dead row leak forever.
            dead_peer_gc_secs: 300,
            replication: None,
        }
    }
}

/// Attempt to discover peers and assemble a [`MeshNode`] handle.
///
/// Iterates all discovery backends in order and takes the first non-empty peer
/// list. If every backend returns empty (or the overall discovery window
/// elapses), the node bootstraps as a single-node cluster with an empty peer
/// list. In both cases the returned handle owns a freshly constructed
/// [`DistributedCache`](crate::state::distributed_cache::DistributedCache)
/// seeded with the discovered membership view.
///
/// Returns `Result` so future phases (transport bind, gossip start) can
/// propagate fatal errors without changing this function's signature. Today
/// the `Ok(...)` branch is always taken: discovery failures are logged and
/// the bootstrap falls through to single-node startup.
pub async fn bootstrap(
    discoveries: &[Box<dyn Discovery>],
    config: &BootstrapConfig,
    node_id: String,
) -> Result<MeshNode> {
    let timeout = tokio::time::Duration::from_secs(config.wait_for_peers_secs);

    // --- Discover peers ---
    //
    // Walk the configured backends in order and short-circuit on the first
    // non-empty result. A backend that errors is logged and skipped so a
    // broken cloud API cannot prevent seed peers from being tried.
    let discover = async {
        for discovery in discoveries {
            match discovery.discover() {
                Ok(peers) if !peers.is_empty() => return peers,
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("discovery backend failed: {e}");
                }
            }
        }
        vec![]
    };

    let peers = match tokio::time::timeout(timeout, discover).await {
        Ok(peers) if !peers.is_empty() => {
            tracing::info!("discovered {} peer(s) during bootstrap", peers.len());
            peers
        }
        Ok(_) | Err(_) => {
            tracing::info!("no peers found, starting as single-node cluster");
            vec![]
        }
    };

    // A symmetric seed list (every node ships the same seeds, which is the
    // natural shape for static fleet config and the Kubernetes operator)
    // includes this node's own advertised address. Keep it out of the peer
    // set: otherwise the node enters its own ring twice, once under its
    // node ID and once as an address alias no join message ever replaces,
    // and consistent-hash placement (including the WOR-1947 replica sets)
    // can count one physical node as two members.
    let peers: Vec<String> = peers
        .into_iter()
        .filter(|peer| Some(peer.as_str()) != config.gossip_advertise_addr.as_deref())
        .collect();

    // --- K3: derive the cluster cipher (if configured) ---
    //
    // A single `Cipher` is derived once here and shared by both the
    // gossip loop and the transport. Empty strings are treated as
    // "unset" so an operator who leaves `shared_key: ""` in their
    // sb.yml gets plaintext behavior rather than a silently-diverged
    // cluster key. A real secret should be at least 16 bytes of
    // entropy; enforcement is the config layer's job.
    let cipher: Option<Cipher> = match config
        .shared_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(key) => {
            tracing::info!(
                node_id = %node_id,
                "mesh: AES-256-GCM encryption enabled on gossip + transport"
            );
            Some(Cipher::from_shared_key(key))
        }
        None => {
            tracing::info!(
                node_id = %node_id,
                "mesh: encryption disabled (no shared_key configured); \
                 gossip + transport run in plaintext"
            );
            None
        }
    };

    // --- Assemble the handle ---
    //
    // Construct a `MeshNode` that owns the distributed cache. The handle's
    // `new` seeds the consistent hash ring with `node_id` + every peer so
    // routing decisions immediately reflect the discovered membership.
    let mut node = MeshNode::new(node_id.clone(), peers.clone(), DEFAULT_CACHE_VNODES);

    // --- Build the shared peer address map ---
    //
    // Seeded from the bootstrap-time gossip snapshot under temporary address
    // identities, with each route lowered to the configured TCP port. Join
    // messages replace those aliases with stable node IDs. Constructed BEFORE
    // the gossip loop so the same `Arc` can be handed to both the loop
    // (which writes gossip-learned mappings into it, L3) and the handle
    // (which exposes it via `peer_addr_lookup` for transport routing).
    let peer_addr_map_init: HashMap<String, String> = node
        .peers()
        .iter()
        .map(|peer| {
            (
                peer.clone(),
                replace_port(peer, config.transport_port).unwrap_or_else(|| peer.clone()),
            )
        })
        .collect();
    let peer_addr_map = Arc::new(RwLock::new(peer_addr_map_init));

    // --- Spawn the gossip loop ---
    //
    // Build a shared peer table keyed by discovered addresses. `node_id` is
    // unknown until we receive our first heartbeat from the peer, so the
    // initial entries hold an empty string. `last_heartbeat` starts at "now"
    // so peers get a full `failure_timeout_secs` grace period to respond.
    let now = Instant::now();
    let peer_entries: Vec<PeerEntry> = peers
        .into_iter()
        .map(|addr| PeerEntry::new(String::new(), addr, now))
        .collect();
    let peers_arc = Arc::new(RwLock::new(PeerTable::from_entries(peer_entries)));

    let evictor = Arc::new(PeerEvictor::for_distributed_cache(
        DEFAULT_MAX_CONSECUTIVE_FAILURES,
        node.distributed_cache(),
    ));
    let isolation = Arc::new(IsolationObserver::new(
        node_id.clone(),
        DEFAULT_MIN_PEERS_FOR_QUORUM,
    ));

    let gossip_cfg = GossipLoopConfig {
        node_id: node_id.clone(),
        gossip_port: config.gossip_port,
        gossip_advertise_addr: config.gossip_advertise_addr.clone(),
        transport_advertise_addr: config
            .transport_advertise_addr
            .clone()
            .or_else(|| {
                config
                    .gossip_advertise_addr
                    .as_deref()
                    .and_then(|address| replace_port(address, config.transport_port))
            })
            .or_else(|| {
                (config.transport_port > 0).then(|| format!("0.0.0.0:{}", config.transport_port))
            }),
        heartbeat_interval_secs: config.heartbeat_interval_secs.max(1),
        failure_check_interval_secs: config.failure_check_interval_secs.max(1),
        failure_timeout_secs: config.failure_timeout_secs.max(1),
        // K3: same cipher for gossip and transport. `clone` here is
        // cheap because `Cipher` wraps an `Arc<Aes256Gcm>`.
        cipher: cipher.clone(),
        // K4 SWIM knobs. `max(1)` keeps pathological zero values from
        // producing a tight-loop timer; K (indirect probes) of 0 is
        // tolerated (the fallback just short-circuits).
        swim_protocol_period_ms: config.swim_protocol_period_ms.max(1),
        swim_ping_timeout_ms: config.swim_ping_timeout_ms.max(1),
        swim_indirect_probes: config.swim_indirect_probes,
        swim_suspect_timeout_secs: config.swim_suspect_timeout_secs.max(1),
        // L2: tunable dead-peer GC timeout. `0` is tolerated as "GC on
        // the next sweep tick" so tests can exercise the path without
        // waiting several seconds.
        dead_peer_gc_secs: config.dead_peer_gc_secs,
        identity_authenticator: config
            .peer_tls
            .as_ref()
            .and_then(|params| params.identity_authenticator.clone()),
    };

    match GossipLoop::start(
        gossip_cfg,
        peers_arc.clone(),
        evictor.clone(),
        isolation.clone(),
        // L3: the gossip loop writes gossip-learned (node_id, addr)
        // mappings into this same `Arc`; the transport layer reads them
        // via `MeshNode::peer_addr_lookup` for routed cache RPCs.
        peer_addr_map.clone(),
        Some(node.distributed_cache()),
    )
    .await
    {
        Ok(loop_handle) => {
            node = node.with_gossip_loop(loop_handle, peers_arc, evictor, isolation);
        }
        Err(e) => {
            // Fail-warn: UDP bind failures log and leave `MeshNode.gossip_loop`
            // unset. The rest of the enterprise stack still functions; the
            // mesh just will not observe peer liveness.
            tracing::warn!(
                error = %e,
                port = config.gossip_port,
                "gossip loop failed to start; mesh continues without live peer monitoring"
            );
        }
    }

    // --- Spawn the cross-node cache RPC transport (J2) ---
    //
    // The transport server is the inbound side: a TCP listener that
    // answers Get/Put/Delete on this node's shard. The client pool is the
    // outbound side; we build it even when the server fails to bind so
    // this node can still act as a pure client (read and write to peers).
    //
    // L3: `peer_addr_map` was already constructed (and handed to the
    // gossip loop) above. It is seeded from the bootstrap-time peer
    // snapshot under temporary address identities and live-updated by the
    // gossip loop as stable node IDs and typed-state addresses are learned.
    // K3: the pool gets the same cipher as the gossip loop so every
    // outbound `PeerClient` speaks the same AEAD-wrapped protocol as
    // the server on the other end.
    // Peer mTLS: build the rustls acceptor (inbound) and connector (outbound)
    // once, from the resolved cert/key/CA. A misconfigured cert fails the
    // bootstrap rather than silently downgrading the cluster to plaintext.
    let (tls_acceptor, tls_client) = match &config.peer_tls {
        Some(p) => {
            let acceptor = crate::transport::tls::build_acceptor(&p.tls)
                .map_err(|e| anyhow::anyhow!("mesh peer-mTLS acceptor: {e}"))?;
            let connector = crate::transport::tls::build_connector(&p.tls)
                .map_err(|e| anyhow::anyhow!("mesh peer-mTLS connector: {e}"))?;
            let server_name = rustls::pki_types::ServerName::try_from(p.server_name.clone())
                .map_err(|e| {
                    anyhow::anyhow!("mesh peer-mTLS server_name '{}': {e}", p.server_name)
                })?;
            (
                Some(acceptor),
                Some(crate::transport::client::MeshTlsClient {
                    connector,
                    server_name,
                    verify_node_id: p.identity_authenticator.is_some(),
                }),
            )
        }
        None => (None, None),
    };

    let transport_pool = Arc::new(TransportClientPool::with_security(
        cipher.clone(),
        tls_client,
    ));

    let transport_server = match TransportServer::start_with_security(
        config.transport_port,
        node.distributed_cache(),
        cipher.clone(),
        tls_acceptor,
    )
    .await
    {
        Ok(server) => {
            tracing::info!(port = server.local_port(), "transport server bound");
            Some(server)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                port = config.transport_port,
                "transport server failed to bind; mesh continues without inbound cache routing"
            );
            None
        }
    };

    // --- WOR-1947: replicated durable state substrate ---
    //
    // Constructed before the transport server moves into the handle so the
    // shard can be installed behind the ReplicaApply/ReplicaFetch/SyncDigest
    // ops. Unlike the fail-warn paths above, a durable shard that cannot
    // open FAILS the bootstrap: silently continuing without durability
    // would violate the substrate's restart guarantee.
    let replica_shard = match &config.replication {
        Some(replication) => {
            let clock: crate::state::replicated::MeshClock = Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_millis() as u64)
                    .unwrap_or_default()
            });
            let grace_ms = replication
                .settings
                .tombstone_gc_grace_secs
                .saturating_mul(1_000);
            let shard = match &replication.durable_path {
                Some(path) => crate::state::replicated::ReplicaShard::open(
                    path,
                    replication.limits,
                    grace_ms,
                    clock,
                )
                .map_err(|e| anyhow::anyhow!("open replicated state shard: {e}"))?,
                None => crate::state::replicated::ReplicaShard::in_memory(
                    replication.limits,
                    grace_ms,
                    clock,
                ),
            };
            let shard = Arc::new(shard);
            if let Some(server) = transport_server.as_ref() {
                server.install_replica_shard(shard.clone());
            }
            Some(shard)
        }
        None => None,
    };

    node = node
        .with_transport(transport_server, transport_pool, peer_addr_map)
        .with_identity_authenticator(
            config
                .peer_tls
                .as_ref()
                .and_then(|params| params.identity_authenticator.clone()),
        );

    if let (Some(shard), Some(replication)) = (replica_shard, &config.replication) {
        let lookup = node.peer_addr_lookup();
        let is_isolated: crate::state::replicated::IsolationFn = match node.isolation_observer() {
            Some(observer) => Arc::new(move || observer.is_isolated()),
            None => Arc::new(|| false),
        };
        let store = Arc::new(crate::state::replicated::ReplicatedStore::new(
            shard,
            node.distributed_cache(),
            node.transport_pool(),
            Arc::new(lookup),
            is_isolated,
            replication.settings.clone(),
        ));
        crate::state::replicated::ReplicatedStore::spawn_maintenance(&store);
        tracing::info!(
            factor = replication.settings.replication_factor,
            "replicated state substrate enabled"
        );
        node = node.with_replicated_store(store);
    }

    Ok(node)
}

fn replace_port(address: &str, port: u16) -> Option<String> {
    if port == 0 {
        return None;
    }
    let (host, _) = address.rsplit_once(':')?;
    (!host.is_empty()).then(|| format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticDiscovery(Vec<String>);

    impl Discovery for StaticDiscovery {
        fn discover(&self) -> Result<Vec<String>> {
            Ok(self.0.clone())
        }
    }

    struct FailingDiscovery;

    impl Discovery for FailingDiscovery {
        fn discover(&self) -> Result<Vec<String>> {
            Err(anyhow::anyhow!("discovery failure"))
        }
    }

    /// Build a `BootstrapConfig` safe for unit tests. Uses port `0` so each
    /// invocation binds an ephemeral UDP port and tests can run in parallel
    /// without port-reuse flakiness.
    fn test_bootstrap_config() -> BootstrapConfig {
        BootstrapConfig {
            wait_for_peers_secs: 1,
            gossip_port: 0,
            // Ephemeral TCP port so parallel test runs do not collide on
            // the default 8946.
            transport_port: 0,
            gossip_advertise_addr: None,
            transport_advertise_addr: None,
            heartbeat_interval_secs: 1,
            failure_check_interval_secs: 2,
            failure_timeout_secs: 5,
            shared_key: None,
            // Fast SWIM cadence for the bootstrap suite so tests don't
            // wait a full real-world protocol period.
            swim_protocol_period_ms: 200,
            swim_ping_timeout_ms: 50,
            swim_indirect_probes: 3,
            swim_suspect_timeout_secs: 1,
            // Tests tolerate a generous GC timeout; none of the
            // bootstrap-suite tests exercise the GC path, which has
            // its own coverage in `gossip_loop::tests`.
            dead_peer_gc_secs: 60,
            peer_tls: None,
            replication: None,
        }
    }

    #[tokio::test]
    async fn returns_peers_when_found() {
        let peers = vec!["10.0.0.1:7946".to_string(), "10.0.0.2:7946".to_string()];
        let discovery: Vec<Box<dyn Discovery>> = vec![Box::new(StaticDiscovery(peers.clone()))];
        let config = test_bootstrap_config();

        let node = bootstrap(&discovery, &config, "n1".to_string())
            .await
            .expect("bootstrap ok");
        assert_eq!(node.peers(), peers.as_slice());
        assert_eq!(node.node_id(), "n1");
    }

    #[tokio::test]
    async fn symmetric_seed_list_filters_own_advertised_address() {
        // Every node in a static fleet ships the same seed list, so this
        // node's own address arrives via discovery. It must not become a
        // ring member: that alias is never replaced by a join and would
        // let placement count one physical node twice.
        let peers = vec![
            "10.0.0.1:7946".to_string(),
            "10.0.0.2:7946".to_string(),
            "10.0.0.3:7946".to_string(),
        ];
        let discovery: Vec<Box<dyn Discovery>> = vec![Box::new(StaticDiscovery(peers))];
        let mut config = test_bootstrap_config();
        config.gossip_advertise_addr = Some("10.0.0.1:7946".to_string());

        let node = bootstrap(&discovery, &config, "n1".to_string())
            .await
            .expect("bootstrap ok");
        assert_eq!(
            node.peers(),
            ["10.0.0.2:7946".to_string(), "10.0.0.3:7946".to_string()].as_slice()
        );
        assert!(!node
            .distributed_cache()
            .member_nodes()
            .iter()
            .any(|member| member == "10.0.0.1:7946"));
    }

    #[tokio::test]
    async fn returns_empty_when_no_peers() {
        let discovery: Vec<Box<dyn Discovery>> = vec![Box::new(StaticDiscovery(vec![]))];
        let config = test_bootstrap_config();

        let node = bootstrap(&discovery, &config, "n1".to_string())
            .await
            .expect("bootstrap ok");
        assert!(node.peers().is_empty());
    }

    #[tokio::test]
    async fn returns_empty_when_all_backends_fail() {
        let discovery: Vec<Box<dyn Discovery>> = vec![Box::new(FailingDiscovery)];
        let config = test_bootstrap_config();

        let node = bootstrap(&discovery, &config, "n1".to_string())
            .await
            .expect("bootstrap ok");
        assert!(node.peers().is_empty());
    }

    #[tokio::test]
    async fn returns_empty_with_no_backends() {
        let discovery: Vec<Box<dyn Discovery>> = vec![];
        let config = test_bootstrap_config();

        let node = bootstrap(&discovery, &config, "n1".to_string())
            .await
            .expect("bootstrap ok");
        assert!(node.peers().is_empty());
    }

    #[tokio::test]
    async fn uses_first_non_empty_backend() {
        // First backend is empty, second has peers.
        let peers = vec!["10.0.0.3:7946".to_string()];
        let discovery: Vec<Box<dyn Discovery>> = vec![
            Box::new(StaticDiscovery(vec![])),
            Box::new(StaticDiscovery(peers.clone())),
        ];
        let config = test_bootstrap_config();

        let node = bootstrap(&discovery, &config, "n1".to_string())
            .await
            .expect("bootstrap ok");
        assert_eq!(node.peers(), peers.as_slice());
    }

    #[tokio::test]
    async fn skips_failing_backends_to_find_peers() {
        let peers = vec!["10.0.0.4:7946".to_string()];
        let discovery: Vec<Box<dyn Discovery>> = vec![
            Box::new(FailingDiscovery),
            Box::new(StaticDiscovery(peers.clone())),
        ];
        let config = test_bootstrap_config();

        let node = bootstrap(&discovery, &config, "n1".to_string())
            .await
            .expect("bootstrap ok");
        assert_eq!(node.peers(), peers.as_slice());
    }

    #[tokio::test]
    async fn single_node_config_works() {
        let config = test_bootstrap_config();
        let discovery: Vec<Box<dyn Discovery>> = vec![Box::new(StaticDiscovery(vec![]))];

        let node = bootstrap(&discovery, &config, "solo".to_string())
            .await
            .expect("bootstrap ok");
        assert!(node.peers().is_empty());
        assert_eq!(node.node_id(), "solo");
    }

    #[tokio::test]
    async fn single_seed_peer_produces_expected_mesh_node() {
        // Regression guard: a single seed peer must show up in the returned
        // MeshNode's peers list and be reachable through the distributed
        // cache Arc clone.
        let peers = vec!["10.0.0.9:7946".to_string()];
        let discovery: Vec<Box<dyn Discovery>> = vec![Box::new(StaticDiscovery(peers.clone()))];
        let config = test_bootstrap_config();

        let node = bootstrap(&discovery, &config, "local".to_string())
            .await
            .expect("bootstrap ok");
        assert_eq!(node.peers(), peers.as_slice());

        let cache = node.distributed_cache();
        // With local + one peer in the ring, some keys should route to the
        // peer and some to local. We only verify the routing never returns
        // None and that the local node id is preserved on the cache itself.
        assert_eq!(cache.local_node_id(), "local");
        assert!(cache.responsible_node("any-key").is_some());
    }
}
