//! Mesh configuration parsed from the opaque `proxy.extensions["mesh"]` block
//! in sb.yml.
//!
//! The types in this module mirror the shape expected by [`crate::bootstrap`]
//! and the discovery backends in [`crate::discovery`]. G1 only defines the
//! schema; wiring it into the request pipeline happens in G2/G3.

use serde::{Deserialize, Serialize};

use crate::bootstrap::BootstrapConfig;

// --- Defaults ---

fn default_gossip_port() -> u16 {
    7946
}

fn default_transport_port() -> u16 {
    8946
}

fn default_cipher() -> String {
    "aes256gcm".to_string()
}

fn default_bootstrap_timeout_secs() -> u64 {
    5
}

fn default_heartbeat_interval() -> u64 {
    1
}

fn default_failure_check_interval() -> u64 {
    2
}

fn default_failure_timeout() -> u64 {
    5
}

// --- SWIM defaults (K4) ---

fn default_swim_protocol_period_ms() -> u64 {
    1000
}

fn default_swim_ping_timeout_ms() -> u64 {
    300
}

fn default_swim_indirect_probes() -> usize {
    3
}

fn default_swim_suspect_timeout_secs() -> u64 {
    5
}

// --- L2 defaults ---

/// Default dead-peer GC timeout. After a peer has been in the Dead state
/// for this long, the L2 sweeper removes it from the local peer table so
/// its memory + `peer_count{state=dead}` label are reclaimed.
fn default_dead_gc_secs() -> u64 {
    300
}

// --- MeshConfig ---

/// Top-level mesh configuration parsed from `proxy.extensions["mesh"]`.
///
/// Fields intentionally mirror the arguments of the existing mesh building
/// blocks (`NodeInfo`, `BootstrapConfig`, the discovery backends) so G2/G3
/// can convert this struct into the concrete runtime objects without any
/// lossy translation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeshConfig {
    /// Stable node identifier. If omitted at the config layer, callers
    /// should fall back to `NodeId::auto_generate(gossip_port)`.
    pub node_id: String,

    /// Address other nodes should use to reach this one. Host or host:port.
    pub advertise_addr: String,

    /// UDP gossip port.
    #[serde(default = "default_gossip_port")]
    pub gossip_port: u16,

    /// TCP transport port for CRDT sync and request forwarding.
    #[serde(default = "default_transport_port")]
    pub transport_port: u16,

    /// Static seed peers (`host:port`). Used by the `SeedDiscovery` backend.
    #[serde(default)]
    pub seed_peers: Vec<String>,

    /// Optional peer discovery backends (Kubernetes, DNS, cloud, Consul).
    #[serde(default)]
    pub discovery: DiscoveryConfig,

    /// Optional symmetric encryption for gossip traffic.
    #[serde(default)]
    pub encryption: Option<EncryptionConfig>,

    /// How long to wait for discovery to find peers before bootstrapping
    /// as a single-node cluster. Defaults to 5 seconds.
    #[serde(default)]
    pub bootstrap_timeout_secs: Option<u64>,

    /// Interval between outbound heartbeats, in seconds. Defaults to 1s.
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,

    /// Interval between failure-check sweeps, in seconds. Defaults to 2s.
    #[serde(default = "default_failure_check_interval")]
    pub failure_check_interval_secs: u64,

    /// Time after which a peer with no heartbeats is considered failed,
    /// in seconds. Defaults to 5s.
    #[serde(default = "default_failure_timeout")]
    pub failure_timeout_secs: u64,

    // --- SWIM timing knobs (K4) ---
    //
    // These control the direct-probe + indirect-probe failure detector.
    // The MVP gossip loop ignored these; K4 wires them through
    // `BootstrapConfig` into `GossipLoopConfig`.
    /// SWIM protocol period in milliseconds. Each period, the node picks
    /// a single random Alive peer and sends a `PING` to it. Defaults to
    /// 1000ms per the SWIM paper recommendation for a small cluster.
    #[serde(default = "default_swim_protocol_period_ms")]
    pub swim_protocol_period_ms: u64,

    /// Timeout on a direct `PING` waiting for its matching `ACK`. If no
    /// ACK arrives within this window the node falls back to indirect
    /// probes (PING-REQ). Defaults to 300ms.
    #[serde(default = "default_swim_ping_timeout_ms")]
    pub swim_ping_timeout_ms: u64,

    /// K, the number of indirect-probe witnesses a node fans PING-REQ
    /// out to when a direct probe times out. Clamped at runtime to
    /// `min(K, alive_peers - 1)`. Defaults to 3.
    #[serde(default = "default_swim_indirect_probes")]
    pub swim_indirect_probes: usize,

    /// Time a peer is kept in the Suspect state before being marked
    /// Dead, in seconds. Any ACK (direct or indirect) during this
    /// window refutes suspicion and restores the peer to Alive. Defaults
    /// to 5s.
    #[serde(default = "default_swim_suspect_timeout_secs")]
    pub swim_suspect_timeout_secs: u64,

    // --- L2: dead-peer garbage collection ---
    /// How long a peer stays in the `Dead` state before the L2 sweeper
    /// removes it from the peer table entirely. Dead is otherwise
    /// terminal, so without this knob the peer would linger in memory
    /// (and in `peer_count{state=dead}`) until process restart. A peer
    /// that resurrects after GC is re-added as a fresh Alive entry via
    /// the normal discovery / dissemination path. Defaults to 300s
    /// (5 minutes).
    #[serde(default = "default_dead_gc_secs")]
    pub dead_peer_gc_secs: u64,

    // --- Hybrid Redis integration (design doc 2026-04-23-mesh-redis-hybrid) ---
    /// Optional Redis-backed persistence layer. When enabled, the mesh
    /// leader periodically snapshots CRDT state to Redis; new nodes
    /// warm up from Redis on cold start before/instead of pure gossip
    /// convergence.
    ///
    /// Completely optional: absence keeps the proxy in pure-gossip mode.
    #[serde(default)]
    pub persistence: Option<MeshPersistenceConfig>,

    /// Optional cross-cluster federation via a shared Redis bridge.
    /// When enabled, this cluster publishes summaries of selected CRDTs
    /// to a shared Redis and pulls summaries from named peer clusters.
    ///
    /// Requires `persistence` to also be enabled (federation reuses the
    /// persistence Redis connection unless `federation.redis` overrides).
    #[serde(default)]
    pub federation: Option<MeshFederationConfig>,
}

// --- Persistence (b) ---

/// Configuration for the Redis-backed persistence layer.
///
/// See `2026-04-23-mesh-redis-hybrid-design.md` §3 for the design.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeshPersistenceConfig {
    /// Master on/off switch.
    #[serde(default = "default_enabled_true")]
    pub enabled: bool,

    /// Backend driver. Currently only `"redis"` is implemented.
    #[serde(default = "default_persistence_driver")]
    pub driver: String,

    /// Driver params. For `driver=redis`, expected keys: `dsn`,
    /// optional `key_prefix` (defaults to `sbproxy:mesh:`).
    #[serde(default)]
    pub params: std::collections::HashMap<String, String>,

    /// Snapshot cadence in seconds. `0` = snapshot on graceful
    /// shutdown only. Defaults to 60.
    #[serde(default = "default_snapshot_interval")]
    pub snapshot_interval_secs: u64,

    /// Whitelist of CRDT class names to persist. Empty = all.
    /// Example: `["rate_limit", "response_cache"]`.
    #[serde(default)]
    pub include: Vec<String>,

    /// How old a Redis-stored snapshot can be before a cold-starting
    /// node refuses to load it (seconds). Defaults to 3600 (1 hour).
    #[serde(default = "default_max_staleness")]
    pub max_staleness_secs: u64,

    /// Posture when Redis is unreachable at bootstrap time.
    /// `"open"` (default) = start with empty state; `"close"` = refuse
    /// to start.
    #[serde(default = "default_startup_fail")]
    pub startup_fail: String,
}

fn default_enabled_true() -> bool {
    true
}
fn default_persistence_driver() -> String {
    "redis".into()
}
fn default_snapshot_interval() -> u64 {
    60
}
fn default_max_staleness() -> u64 {
    3600
}
fn default_startup_fail() -> String {
    "open".into()
}

// --- Federation (c) ---

/// Configuration for cross-cluster federation via Redis bridge.
///
/// See `2026-04-23-mesh-redis-hybrid-design.md` §5 for the design.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeshFederationConfig {
    /// Master on/off switch.
    #[serde(default = "default_enabled_true")]
    pub enabled: bool,

    /// Human-readable cluster identifier. Must be unique across all
    /// clusters in the federation. Included in Redis keys so two
    /// clusters don't overwrite each other.
    pub cluster_id: String,

    /// If true (default), federation reuses the Redis connection from
    /// `persistence.params`. If false, specify `redis` below.
    #[serde(default = "default_enabled_true")]
    pub share_redis_with_persistence: bool,

    /// Alternate Redis config, used when `share_redis_with_persistence`
    /// is false.
    #[serde(default)]
    pub redis: Option<std::collections::HashMap<String, String>>,

    /// Named peer cluster ids whose summaries this cluster pulls.
    /// The cluster's own `cluster_id` must not appear here.
    #[serde(default)]
    pub peers: Vec<String>,

    /// How often to push local summary + pull peer summaries (seconds).
    /// Defaults to 10.
    #[serde(default = "default_federation_sync_interval")]
    pub sync_interval_secs: u64,

    /// Whitelist of CRDT class names to federate. Often a subset of
    /// `persistence.include`; empty = all.
    #[serde(default)]
    pub include: Vec<String>,

    /// Merge strategy on pull.
    /// `"auto"` (default) uses the CRDT's native merge algebra.
    /// `"union"` and `"peer_wins"` are overrides for special cases.
    #[serde(default = "default_merge_strategy")]
    pub merge: String,

    /// Read-only mode: pull peer summaries but do not push our own.
    /// Useful for observer-only clusters.
    #[serde(default)]
    pub read_only: bool,
}

fn default_federation_sync_interval() -> u64 {
    10
}
fn default_merge_strategy() -> String {
    "auto".into()
}

impl Default for MeshFederationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cluster_id: String::new(),
            share_redis_with_persistence: true,
            redis: None,
            peers: Vec::new(),
            sync_interval_secs: default_federation_sync_interval(),
            include: Vec::new(),
            merge: default_merge_strategy(),
            read_only: false,
        }
    }
}

// --- DiscoveryConfig ---

/// Union of all supported discovery backends. All fields are optional; any
/// combination may be configured and will be tried in order by the bootstrap
/// routine.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DiscoveryConfig {
    /// Kubernetes API-based peer discovery, when configured.
    #[serde(default)]
    pub kubernetes: Option<KubernetesDiscoveryConfig>,

    /// DNS-based peer discovery, when configured.
    #[serde(default)]
    pub dns: Option<DnsDiscoveryConfig>,

    /// Cloud-provider tag-based peer discovery, when configured.
    #[serde(default)]
    pub cloud: Option<CloudDiscoveryConfig>,

    /// Consul service-catalog-based peer discovery, when configured.
    #[serde(default)]
    pub consul: Option<ConsulDiscoveryConfig>,
}

/// Kubernetes API-based peer discovery. Mirrors
/// [`crate::discovery::kubernetes::KubernetesDiscovery`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KubernetesDiscoveryConfig {
    /// Namespace to search for peer pods.
    pub namespace: String,
    /// Label selector matching the peer pods.
    pub label_selector: String,
    /// Gossip port to contact discovered peers on.
    #[serde(default = "default_gossip_port")]
    pub port: u16,
}

/// DNS-based peer discovery (works with K8s headless services). Mirrors
/// [`crate::discovery::dns::DnsDiscovery`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsDiscoveryConfig {
    /// DNS name to resolve for peer addresses (e.g. a headless service).
    pub hostname: String,
    /// Gossip port to contact resolved peers on.
    #[serde(default = "default_gossip_port")]
    pub port: u16,
}

/// Cloud-provider tag-based peer discovery. Mirrors
/// [`crate::discovery::cloud::CloudDiscovery`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloudDiscoveryConfig {
    /// `"aws"`, `"gcp"`, or `"azure"`.
    pub provider: String,
    /// Instance tag key to match when listing peers.
    pub tag_key: String,
    /// Instance tag value to match when listing peers.
    pub tag_value: String,
    /// Cloud region to query.
    pub region: String,
    /// Gossip port to contact discovered peers on.
    #[serde(default = "default_gossip_port")]
    pub port: u16,
}

/// Consul service-catalog-based peer discovery. Mirrors
/// [`crate::discovery::consul::ConsulDiscovery`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConsulDiscoveryConfig {
    /// Consul HTTP API address.
    pub addr: String,
    /// Service name to look up in the catalog.
    pub service: String,
    /// Consul datacenter to query. Defaults to the agent's when unset.
    #[serde(default)]
    pub datacenter: Option<String>,
    /// ACL token for the Consul API, if the cluster requires one.
    #[serde(default)]
    pub token: Option<String>,
}

// --- EncryptionConfig ---

/// Symmetric encryption settings for gossip traffic.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EncryptionConfig {
    /// Cipher identifier. Currently only `"aes256gcm"` is honored by
    /// [`crate::encryption::GossipEncryption`]; retained as a string so
    /// future ciphers can be added without breaking config.
    #[serde(default = "default_cipher")]
    pub cipher: String,

    /// Shared cluster secret. May be a literal value or an env-var
    /// placeholder such as `"${SB_MESH_KEY}"`; resolution is the caller's
    /// responsibility (G2/G3).
    pub shared_key: Option<String>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            advertise_addr: String::new(),
            gossip_port: default_gossip_port(),
            transport_port: default_transport_port(),
            seed_peers: Vec::new(),
            discovery: DiscoveryConfig::default(),
            encryption: None,
            bootstrap_timeout_secs: None,
            heartbeat_interval_secs: default_heartbeat_interval(),
            failure_check_interval_secs: default_failure_check_interval(),
            failure_timeout_secs: default_failure_timeout(),
            swim_protocol_period_ms: default_swim_protocol_period_ms(),
            swim_ping_timeout_ms: default_swim_ping_timeout_ms(),
            swim_indirect_probes: default_swim_indirect_probes(),
            swim_suspect_timeout_secs: default_swim_suspect_timeout_secs(),
            dead_peer_gc_secs: default_dead_gc_secs(),
            persistence: None,
            federation: None,
        }
    }
}

// --- Extension parsing / bootstrap adaptation ---

impl MeshConfig {
    /// Parse from the opaque extensions map, returning `None` if the
    /// `"mesh"` key is absent and `Err` if present but malformed.
    pub fn from_extensions(
        extensions: &std::collections::HashMap<String, serde_yaml::Value>,
    ) -> anyhow::Result<Option<Self>> {
        match extensions.get("mesh") {
            None => Ok(None),
            Some(v) => {
                let cfg: Self = serde_yaml::from_value(v.clone())?;
                Ok(Some(cfg))
            }
        }
    }

    /// Adapter to the shape expected by [`crate::bootstrap::bootstrap`].
    ///
    /// Kept as an explicit method (rather than a `From` impl) because
    /// `BootstrapConfig` is not `Deserialize` and may grow fields that do
    /// not map cleanly from `MeshConfig`.
    ///
    /// K3: forwards `encryption.shared_key` into `BootstrapConfig.shared_key`
    /// so the bootstrap can derive a cluster `Cipher` when the operator
    /// configured one. `${ENV}` placeholder resolution is the caller's
    /// responsibility (see the module-level doc on [`EncryptionConfig`]).
    pub fn into_bootstrap_config(&self) -> BootstrapConfig {
        BootstrapConfig {
            wait_for_peers_secs: self
                .bootstrap_timeout_secs
                .unwrap_or_else(default_bootstrap_timeout_secs),
            gossip_port: self.gossip_port,
            transport_port: self.transport_port,
            gossip_advertise_addr: (!self.advertise_addr.is_empty())
                .then(|| self.advertise_addr.clone()),
            transport_advertise_addr: self
                .advertise_addr
                .rsplit_once(':')
                .filter(|(host, _)| !host.is_empty() && self.transport_port > 0)
                .map(|(host, _)| format!("{host}:{}", self.transport_port)),
            heartbeat_interval_secs: self.heartbeat_interval_secs,
            failure_check_interval_secs: self.failure_check_interval_secs,
            failure_timeout_secs: self.failure_timeout_secs,
            shared_key: self.encryption.as_ref().and_then(|e| e.shared_key.clone()),
            // K4: forward SWIM knobs to the bootstrap so the gossip loop
            // picks them up. The SWIM defaults mirror the paper's
            // small-cluster recommendation.
            swim_protocol_period_ms: self.swim_protocol_period_ms,
            swim_ping_timeout_ms: self.swim_ping_timeout_ms,
            swim_indirect_probes: self.swim_indirect_probes,
            swim_suspect_timeout_secs: self.swim_suspect_timeout_secs,
            // L2: forward the dead-peer GC knob so the gossip loop's
            // sweeper removes terminal entries after the timeout.
            dead_peer_gc_secs: self.dead_peer_gc_secs,
            // Peer mTLS is supplied by the embedding host (the key plane reads
            // the configured cert/key/CA); the standalone `MeshConfig` path
            // stays plaintext unless a caller sets it after conversion.
            peer_tls: None,
            // The replicated substrate is wired only through the canonical
            // `proxy.cluster` path; the legacy extensions block cannot
            // enable it.
            replication: None,
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_yaml() {
        let yaml = r#"
node_id: "node-01"
advertise_addr: "10.0.0.1"
"#;
        let cfg: MeshConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.node_id, "node-01");
        assert_eq!(cfg.advertise_addr, "10.0.0.1");
        assert_eq!(cfg.gossip_port, 7946);
        assert_eq!(cfg.transport_port, 8946);
        assert!(cfg.seed_peers.is_empty());
        assert!(cfg.encryption.is_none());
        assert!(cfg.bootstrap_timeout_secs.is_none());
        assert!(cfg.discovery.kubernetes.is_none());
        assert!(cfg.discovery.dns.is_none());
        assert!(cfg.discovery.cloud.is_none());
        assert!(cfg.discovery.consul.is_none());
    }

    #[test]
    fn parses_full_yaml_with_seeds_and_encryption() {
        let yaml = r#"
node_id: "node-02"
advertise_addr: "10.0.0.2"
gossip_port: 17946
transport_port: 18946
seed_peers:
  - "10.0.0.1:7946"
  - "10.0.0.3:7946"
encryption:
  cipher: "aes256gcm"
  shared_key: "test-key"
bootstrap_timeout_secs: 15
"#;
        let cfg: MeshConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.seed_peers.len(), 2);
        assert_eq!(cfg.gossip_port, 17946);
        assert_eq!(cfg.transport_port, 18946);
        assert!(cfg.encryption.is_some());
        let enc = cfg.encryption.as_ref().unwrap();
        assert_eq!(enc.cipher, "aes256gcm");
        assert_eq!(enc.shared_key.as_deref(), Some("test-key"));
        assert_eq!(cfg.bootstrap_timeout_secs, Some(15));
    }

    #[test]
    fn parses_kubernetes_discovery() {
        let yaml = r#"
node_id: "n1"
advertise_addr: "10.0.0.1"
discovery:
  kubernetes:
    namespace: "production"
    label_selector: "app=sbproxy,tier=mesh"
    port: 7946
"#;
        let cfg: MeshConfig = serde_yaml::from_str(yaml).expect("parse");
        let k = cfg.discovery.kubernetes.expect("kubernetes present");
        assert_eq!(k.namespace, "production");
        assert_eq!(k.label_selector, "app=sbproxy,tier=mesh");
        assert_eq!(k.port, 7946);
    }

    #[test]
    fn parses_dns_discovery() {
        let yaml = r#"
node_id: "n1"
advertise_addr: "10.0.0.1"
discovery:
  dns:
    hostname: "sbproxy-headless.default.svc.cluster.local"
"#;
        let cfg: MeshConfig = serde_yaml::from_str(yaml).expect("parse");
        let d = cfg.discovery.dns.expect("dns present");
        assert_eq!(d.hostname, "sbproxy-headless.default.svc.cluster.local");
        // gossip_port default falls through to the discovery port default.
        assert_eq!(d.port, 7946);
    }

    #[test]
    fn parses_cloud_and_consul_discovery() {
        let yaml = r#"
node_id: "n1"
advertise_addr: "10.0.0.1"
discovery:
  cloud:
    provider: "aws"
    tag_key: "mesh-cluster"
    tag_value: "prod"
    region: "us-east-1"
  consul:
    addr: "http://consul:8500"
    service: "sbproxy-mesh"
    datacenter: "dc1"
    token: "tok"
"#;
        let cfg: MeshConfig = serde_yaml::from_str(yaml).expect("parse");
        let c = cfg.discovery.cloud.expect("cloud present");
        assert_eq!(c.provider, "aws");
        assert_eq!(c.region, "us-east-1");
        assert_eq!(c.port, 7946);
        let co = cfg.discovery.consul.expect("consul present");
        assert_eq!(co.addr, "http://consul:8500");
        assert_eq!(co.service, "sbproxy-mesh");
        assert_eq!(co.datacenter.as_deref(), Some("dc1"));
        assert_eq!(co.token.as_deref(), Some("tok"));
    }

    #[test]
    fn extracts_from_extensions_map() {
        let mut m = std::collections::HashMap::new();
        m.insert(
            "mesh".to_string(),
            serde_yaml::from_str("node_id: n1\nadvertise_addr: 127.0.0.1").unwrap(),
        );
        let parsed = MeshConfig::from_extensions(&m).unwrap();
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap().node_id, "n1");
    }

    #[test]
    fn returns_none_when_absent() {
        let m = std::collections::HashMap::new();
        let parsed = MeshConfig::from_extensions(&m).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn malformed_yaml_returns_err() {
        let mut m = std::collections::HashMap::new();
        // `node_id` must be a string; passing a map triggers a deserialize error.
        m.insert(
            "mesh".to_string(),
            serde_yaml::from_str("node_id:\n  nested: true\nadvertise_addr: 127.0.0.1").unwrap(),
        );
        assert!(MeshConfig::from_extensions(&m).is_err());
    }

    #[test]
    fn into_bootstrap_config_uses_configured_timeout() {
        let cfg = MeshConfig {
            node_id: "n1".to_string(),
            advertise_addr: "10.0.0.1".to_string(),
            gossip_port: default_gossip_port(),
            transport_port: default_transport_port(),
            seed_peers: vec![],
            discovery: DiscoveryConfig::default(),
            encryption: None,
            bootstrap_timeout_secs: Some(42),
            heartbeat_interval_secs: default_heartbeat_interval(),
            failure_check_interval_secs: default_failure_check_interval(),
            failure_timeout_secs: default_failure_timeout(),
            swim_protocol_period_ms: default_swim_protocol_period_ms(),
            swim_ping_timeout_ms: default_swim_ping_timeout_ms(),
            swim_indirect_probes: default_swim_indirect_probes(),
            swim_suspect_timeout_secs: default_swim_suspect_timeout_secs(),
            dead_peer_gc_secs: default_dead_gc_secs(),
            persistence: None,
            federation: None,
        };
        let bc = cfg.into_bootstrap_config();
        assert_eq!(bc.wait_for_peers_secs, 42);
    }

    #[test]
    fn into_bootstrap_config_falls_back_to_default() {
        let cfg = MeshConfig {
            node_id: "n1".to_string(),
            advertise_addr: "10.0.0.1".to_string(),
            gossip_port: default_gossip_port(),
            transport_port: default_transport_port(),
            seed_peers: vec![],
            discovery: DiscoveryConfig::default(),
            encryption: None,
            bootstrap_timeout_secs: None,
            heartbeat_interval_secs: default_heartbeat_interval(),
            failure_check_interval_secs: default_failure_check_interval(),
            failure_timeout_secs: default_failure_timeout(),
            swim_protocol_period_ms: default_swim_protocol_period_ms(),
            swim_ping_timeout_ms: default_swim_ping_timeout_ms(),
            swim_indirect_probes: default_swim_indirect_probes(),
            swim_suspect_timeout_secs: default_swim_suspect_timeout_secs(),
            dead_peer_gc_secs: default_dead_gc_secs(),
            persistence: None,
            federation: None,
        };
        let bc = cfg.into_bootstrap_config();
        assert_eq!(bc.wait_for_peers_secs, default_bootstrap_timeout_secs());
    }

    #[test]
    fn swim_defaults_match_paper_recommendations() {
        // Unit-safe sanity: a minimal YAML block without any `swim_*`
        // keys falls through to the SWIM defaults.
        let yaml = r#"
node_id: "n-swim-defaults"
advertise_addr: "10.0.0.1"
"#;
        let cfg: MeshConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.swim_protocol_period_ms, 1000);
        assert_eq!(cfg.swim_ping_timeout_ms, 300);
        assert_eq!(cfg.swim_indirect_probes, 3);
        assert_eq!(cfg.swim_suspect_timeout_secs, 5);
        // L2: dead-peer GC default is 5 minutes.
        assert_eq!(cfg.dead_peer_gc_secs, 300);
    }

    #[test]
    fn dead_peer_gc_override_parses_and_forwards() {
        let yaml = r#"
node_id: "n-gc"
advertise_addr: "10.0.0.1"
dead_peer_gc_secs: 42
"#;
        let cfg: MeshConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.dead_peer_gc_secs, 42);
        let bc = cfg.into_bootstrap_config();
        assert_eq!(bc.dead_peer_gc_secs, 42);
    }

    #[test]
    fn swim_knobs_override_parses() {
        let yaml = r#"
node_id: "n-swim-override"
advertise_addr: "10.0.0.1"
swim_protocol_period_ms: 200
swim_ping_timeout_ms: 50
swim_indirect_probes: 4
swim_suspect_timeout_secs: 2
"#;
        let cfg: MeshConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.swim_protocol_period_ms, 200);
        assert_eq!(cfg.swim_ping_timeout_ms, 50);
        assert_eq!(cfg.swim_indirect_probes, 4);
        assert_eq!(cfg.swim_suspect_timeout_secs, 2);
    }
}
