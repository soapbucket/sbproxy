//! Multi-node tests for the WOR-2064 mesh keystore backend.
//!
//! Follows the harness pattern of `sbproxy-mesh/tests/replication.rs`:
//! each test stands up real `TransportServer`s on ephemeral localhost
//! ports with durable `ReplicaShard`s, pins membership directly (no
//! SWIM), and drives `MeshKeyStore` adapters over per-node
//! `ReplicatedStore` coordinators. Partitions are simulated by pointing
//! a peer's address at a dead port; time is an injected shared clock.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use sbproxy_core::mesh_keystore::MeshKeyStore;
use sbproxy_keystore::record::{KeyRecord, RecordStatus};
use sbproxy_keystore::{KeyPolicyCasResult, KeyStore};
use sbproxy_mesh::state::distributed_cache::DistributedCache;
use sbproxy_mesh::state::replicated::{
    Consistency, MeshClock, ReplicaShard, ReplicatedStore, ReplicationSettings, ShardLimits,
};
use sbproxy_mesh::transport::{TransportClientPool, TransportServer};
use tempfile::TempDir;

fn shared_clock(cell: &Arc<AtomicU64>) -> MeshClock {
    let cell = cell.clone();
    Arc::new(move || cell.load(Ordering::Relaxed))
}

struct TestNode {
    id: String,
    cache: Arc<DistributedCache<Bytes>>,
    shard: Arc<ReplicaShard>,
    server: TransportServer,
    // Kept alive so the durable directory survives for restart scenarios.
    dir: TempDir,
}

impl TestNode {
    async fn start(id: &str, members: &[&str], clock: MeshClock, grace_ms: u64) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let shard = Arc::new(
            ReplicaShard::open(
                &dir.path().join("shard.redb"),
                ShardLimits::default(),
                grace_ms,
                clock,
            )
            .expect("open shard"),
        );
        let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new(id, 128));
        for member in members {
            if member != &id {
                cache.add_node(member);
            }
        }
        let server = TransportServer::start(0, cache.clone())
            .await
            .expect("server bind");
        server.install_replica_shard(shard.clone());
        Self {
            id: id.to_string(),
            cache,
            shard,
            server,
            dir,
        }
    }

    fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.server.local_port())
    }
}

/// The cluster's replication block, as `proxy.cluster.replication` would
/// lower it. The keystore pins its own consistency on top, so the levels
/// here are deliberately the operator-flavored ones.
fn cluster_settings(grace_secs: u64) -> ReplicationSettings {
    ReplicationSettings {
        replication_factor: 2,
        write_consistency: Consistency::Quorum,
        read_consistency: Consistency::Quorum,
        anti_entropy_interval_secs: 3_600,
        tombstone_gc_grace_secs: grace_secs,
    }
}

fn substrate_for(
    node: &TestNode,
    addrs: &HashMap<String, String>,
    settings: ReplicationSettings,
) -> Arc<ReplicatedStore> {
    let addrs = addrs.clone();
    Arc::new(ReplicatedStore::new(
        node.shard.clone(),
        node.cache.clone(),
        Arc::new(TransportClientPool::new()),
        Arc::new(move |node_id: &str| addrs.get(node_id).cloned()),
        Arc::new(|| false),
        settings,
    ))
}

fn addr_map(nodes: &[&TestNode]) -> HashMap<String, String> {
    nodes.iter().map(|n| (n.id.clone(), n.addr())).collect()
}

fn dead_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn ts() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

fn key_record(id: &str) -> KeyRecord {
    KeyRecord::new(id, "hash", ts())
}

fn credential_fixture(id: &str) -> sbproxy_keystore::record::CredentialRecord {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "name": id,
        "material": {"kind": "vault_ref", "reference": "vault://upstream"},
        "created_at": "2023-11-14T22:13:20Z",
        "updated_at": "2023-11-14T22:13:20Z"
    }))
    .expect("credential fixture")
}

#[tokio::test]
async fn a_key_minted_on_one_node_resolves_on_its_peers() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    let mesh_a = MeshKeyStore::new(substrate_for(&a, &addrs, cluster_settings(0)));
    let mesh_b = MeshKeyStore::new(substrate_for(&b, &addrs, cluster_settings(0)));

    // Mint on A: a key record and a vault-referenced credential. No
    // Redis, no secrets manager, nothing but the two nodes.
    let mut minted = key_record("ci-runner");
    minted.name = Some("ci".into());
    mesh_a.put_key(minted).await.expect("mint on A");
    mesh_a
        .put_credential(credential_fixture("upstream-cred"))
        .await
        .expect("mint credential on A");

    // B resolves both, and its fleet listing sees them.
    let resolved = mesh_b
        .get_key("ci-runner")
        .await
        .expect("resolve on B")
        .expect("record visible on B");
    assert_eq!(resolved.name.as_deref(), Some("ci"));
    assert_eq!(resolved.status, RecordStatus::Active);
    assert!(mesh_b
        .get_credential("upstream-cred")
        .await
        .expect("credential resolve on B")
        .is_some());
    let listed = mesh_b.list_keys().await.expect("fleet listing on B");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].key_id, "ci-runner");
}

#[tokio::test]
async fn revoke_on_one_node_denies_on_the_peer() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    let mesh_a = MeshKeyStore::new(substrate_for(&a, &addrs, cluster_settings(0)));
    let mesh_b = MeshKeyStore::new(substrate_for(&b, &addrs, cluster_settings(0)));

    mesh_a.put_key(key_record("shared")).await.expect("mint");
    assert_eq!(
        mesh_b
            .get_key("shared")
            .await
            .expect("resolve")
            .expect("present")
            .status,
        RecordStatus::Active
    );

    let mut revoked = mesh_a
        .get_key("shared")
        .await
        .expect("read")
        .expect("present");
    revoked.status = RecordStatus::Revoked;
    assert_eq!(
        mesh_a
            .put_key_if_revision(revoked, 1)
            .await
            .expect("revoke on A"),
        KeyPolicyCasResult::Applied { policy_revision: 2 }
    );

    // The one-ack revocation fans out to every reachable replica, so a
    // healthy peer denies without waiting for the maintenance loop.
    let on_b = mesh_b
        .get_key("shared")
        .await
        .expect("resolve on B")
        .expect("record still resolvable");
    assert_eq!(on_b.status, RecordStatus::Revoked);
    assert!(!on_b.is_usable(Utc::now()));
}

#[tokio::test]
async fn a_minority_partition_can_still_revoke_and_peers_deny_after_heal() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    let substrate_a = substrate_for(&a, &addrs, cluster_settings(0));
    let mesh_a = MeshKeyStore::new(substrate_a.clone());
    let mesh_b = MeshKeyStore::new(substrate_for(&b, &addrs, cluster_settings(0)));

    mesh_a.put_key(key_record("compromised")).await.expect("mint");
    let before_partition = mesh_a
        .get_key("compromised")
        .await
        .expect("read")
        .expect("present");

    // Partition: A is the minority of two and cannot reach B.
    let mut cut = addrs.clone();
    cut.insert("node-b".to_string(), format!("127.0.0.1:{}", dead_port()));
    let mesh_a_cut = MeshKeyStore::new(substrate_for(&a, &cut, cluster_settings(0)));

    // A quorum-pinned mint on the minority fails, and the failure says
    // what an operator must assume about it: nothing.
    let error = mesh_a_cut
        .put_key(key_record("minority-mint"))
        .await
        .expect_err("a partitioned minority cannot mint");
    assert!(
        format!("{error:#}").contains("reconcile by listing"),
        "the failed mint names the reconciliation rule: {error:#}"
    );

    // Revocation is written at one ack: the minority can still revoke.
    let mut revoked = before_partition;
    revoked.status = RecordStatus::Revoked;
    assert_eq!(
        mesh_a_cut
            .put_key_if_revision(revoked, 1)
            .await
            .expect("minority revoke"),
        KeyPolicyCasResult::Applied { policy_revision: 2 }
    );

    // The revoking node denies immediately: its quorum read fails
    // closed rather than serving anything during the partition, and the
    // one-ack view it owns is already terminal.
    assert!(
        mesh_a_cut.get_key("compromised").await.is_err(),
        "the partitioned minority must not serve an allow"
    );

    // The majority still serves the stale record until the heal; that
    // is the documented eventual bound, not a bug.
    assert_eq!(
        mesh_b
            .get_key("compromised")
            .await
            .expect("resolve on B")
            .expect("present")
            .status,
        RecordStatus::Active
    );

    // Heal: one anti-entropy round on A pushes the revocation out.
    substrate_a.maintenance_round().await;
    for (name, store) in [("A", &mesh_a), ("B", &mesh_b)] {
        let resolved = store
            .get_key("compromised")
            .await
            .expect("resolve after heal")
            .expect("present after heal");
        assert_eq!(
            resolved.status,
            RecordStatus::Revoked,
            "node {name} must deny after the heal"
        );
        assert!(!resolved.is_usable(Utc::now()));
    }
}

#[tokio::test]
async fn a_quarantined_rejoin_holds_authentication_until_its_first_complete_round() {
    let clock_cell = Arc::new(AtomicU64::new(10_000));
    let members = ["node-a", "node-b"];
    // 60 second tombstone GC grace, which is also the quarantine bound.
    let grace_ms = 60_000;
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), grace_ms).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), grace_ms).await;
    let addrs = addr_map(&[&a, &b]);
    let substrate_a = substrate_for(&a, &addrs, cluster_settings(60));
    let mesh_a = MeshKeyStore::new(substrate_a.clone());

    mesh_a.put_key(key_record("durable")).await.expect("mint");
    assert!(b.shard.fetch("keystore:v1:key:durable").is_some());

    // B crashes. Drop every handle that keeps its redb lock alive: the
    // server, the shard, and A's coordinator whose pooled connection
    // pins B's per-connection handler task.
    let TestNode {
        server: server_b,
        shard: shard_b,
        dir: dir_b,
        ..
    } = b;
    drop(mesh_a);
    drop(substrate_a);
    server_b.shutdown();
    drop(shard_b);

    // Rejoin after longer than the grace period: the shard quarantines.
    clock_cell.fetch_add(grace_ms + 1_000, Ordering::Relaxed);
    let reopened = {
        let mut attempt = 0;
        loop {
            match ReplicaShard::open(
                &dir_b.path().join("shard.redb"),
                ShardLimits::default(),
                grace_ms,
                shared_clock(&clock_cell),
            ) {
                Ok(shard) => break shard,
                Err(_) if attempt < 40 => {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(e) => panic!("reopen shard: {e}"),
            }
        }
    };
    assert!(reopened.quarantined());
    let cache_b2: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("node-b", 128));
    cache_b2.add_node("node-a");
    let substrate_b2 = Arc::new(ReplicatedStore::new(
        Arc::new(reopened),
        cache_b2,
        Arc::new(TransportClientPool::new()),
        {
            let addrs = addrs.clone();
            Arc::new(move |node_id: &str| addrs.get(node_id).cloned())
        },
        Arc::new(|| false),
        cluster_settings(60),
    ));
    let mesh_b2 = MeshKeyStore::new(substrate_b2.clone());

    // Unready: the wiped shard must not serve authentication.
    assert!(!mesh_b2.readiness().ready());
    let error = mesh_b2
        .get_key("durable")
        .await
        .expect_err("a quarantined shard must hold authentication");
    assert!(
        format!("{error:#}").contains("not ready"),
        "unexpected refusal: {error:#}"
    );

    // One complete anti-entropy round against the surviving replica
    // repopulates the shard and opens the gate.
    let report = substrate_b2.maintenance_round().await;
    assert!(report.pulled >= 1, "the round must repopulate the key");
    assert!(mesh_b2.readiness().ready());
    let resolved = mesh_b2
        .get_key("durable")
        .await
        .expect("resolve after catch-up")
        .expect("record restored from the surviving replica");
    assert_eq!(resolved.key_id, "durable");
}
