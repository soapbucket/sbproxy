//! Multi-node tests for the mesh compression session store over the
//! replicated cluster substrate.
//!
//! Each test stands up real `TransportServer`s on ephemeral localhost
//! ports with durable `ReplicaShard`s, drives `ReplicatedStore`
//! coordinators against them, and exercises the compression session
//! semantics through `MeshCompressionStore`, the adapter selected by
//! `compression.state.backend: mesh`. Membership is pinned directly (no
//! SWIM) and time is an injected shared clock, so every scenario is
//! deterministic.
//!
//! Coverage: sessions survive an owner restart from disk; sessions move
//! with the ring on rebalance without loss; a partition heals without
//! invisible loss or tombstone resurrection; competing writers resolve
//! deterministically with the loser observing a stale-version commit
//! failure; and Admin list, delete, and purge are cluster-complete and
//! bounded while topology changes underneath the page cursor.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use sbproxy_ai::compression::{
    CommitError, CompressionRecordId, CompressionSessionRecord, CompressionSessionStore,
    ListRequest, MessageDigest, PurgeRequest, RecordKind, RECORD_SCHEMA_VERSION,
};
use sbproxy_core::compression_store::{MeshCompressionStore, MeshCompressionStoreConfig};
use sbproxy_mesh::state::distributed_cache::DistributedCache;
use sbproxy_mesh::state::replicated::{
    Consistency, MeshClock, ReplicaShard, ReplicatedStore, ReplicationSettings, ShardLimits,
};
use sbproxy_mesh::transport::{TransportClientPool, TransportServer};
use serde_json::json;
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

fn replicated_for(
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

fn settings(
    factor: usize,
    write: Consistency,
    read: Consistency,
    grace_secs: u64,
) -> ReplicationSettings {
    ReplicationSettings {
        replication_factor: factor,
        write_consistency: write,
        read_consistency: read,
        anti_entropy_interval_secs: 3_600,
        tombstone_gc_grace_secs: grace_secs,
    }
}

fn session_store(replicated: Arc<ReplicatedStore>) -> MeshCompressionStore {
    MeshCompressionStore::new(replicated, MeshCompressionStoreConfig::default())
        .expect("mesh compression store")
}

fn id(seed: u8) -> CompressionRecordId {
    CompressionRecordId::derive("tenant-a", "api.example.com", [seed; 16])
}

fn record(version: u64, tenant: &str, summary: &str) -> CompressionSessionRecord {
    CompressionSessionRecord {
        schema_version: RECORD_SCHEMA_VERSION,
        logical_version: version,
        tenant_id: tenant.to_string(),
        origin: "api.example.com".to_string(),
        summary: summary.to_string(),
        protected_prefix_count: 1,
        protected_prefix_digest: MessageDigest::for_messages(&[json!({
            "role": "system",
            "content": "protected"
        })]),
        covered_history_count: 2,
        covered_history_digest: MessageDigest::for_messages(&[json!({
            "role": "user",
            "content": "covered"
        })]),
        covered_input_tokens: 200,
        summary_tokens: 20,
        summarizer_provider: "provider-a".to_string(),
        summarizer_model: "model-a".to_string(),
        writer_node: "writer".to_string(),
        parent_logical_version: (version > 1).then_some(version - 1),
        conflict_detected: false,
        created_at_unix_ms: 1_000,
        updated_at_unix_ms: 2_000 + version,
        expires_at_unix_ms: 60_000,
        kind: RecordKind::Live,
    }
}

async fn commit_session(
    store: &MeshCompressionStore,
    record_id: CompressionRecordId,
    expected: Option<u64>,
    candidate: &CompressionSessionRecord,
) -> Result<(), CommitError> {
    let permit = store
        .acquire_update(&record_id, Duration::from_secs(5))
        .await
        .expect("acquire permit")
        .expect("uncontended local permit");
    let result = store
        .commit(&permit, expected, candidate, Duration::from_secs(600))
        .await;
    store.release(permit).await.expect("release permit");
    result
}

// --- Restart: an acknowledged session survives a replica's crash ---

#[tokio::test]
async fn compression_sessions_survive_owner_restart() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    let store_a = session_store(replicated_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    ));

    let record_id = id(1);
    commit_session(&store_a, record_id, None, &record(1, "tenant-a", "durable"))
        .await
        .expect("replicated commit");
    // The session is on both durable shards, not in one owner's memory.
    let key = format!("compression:v1:{record_id}");
    assert!(a.shard.fetch(&key).is_some());
    assert!(b.shard.fetch(&key).is_some());

    // Crash node B: tear down its server and drop every in-memory
    // reference, keeping only the disk directory. The coordinator goes
    // too, so its pooled connection releases B's shard lock.
    let TestNode {
        shard: shard_b,
        server: server_b,
        dir: dir_b,
        ..
    } = b;
    drop(store_a);
    server_b.shutdown();
    drop(shard_b);

    let reopened = {
        let mut attempt = 0;
        loop {
            match ReplicaShard::open(
                &dir_b.path().join("shard.redb"),
                ShardLimits::default(),
                0,
                shared_clock(&clock_cell),
            ) {
                Ok(shard) => break Arc::new(shard),
                Err(_) if attempt < 40 => {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("reopen shard: {e}"),
            }
        }
    };

    // A restarted node serves the committed session from its own disk:
    // bind a coordinator whose replica set is just the reopened shard.
    let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("node-b", 128));
    let solo = Arc::new(ReplicatedStore::new(
        reopened,
        cache,
        Arc::new(TransportClientPool::new()),
        Arc::new(|_| None),
        Arc::new(|| false),
        settings(1, Consistency::One, Consistency::One, 0),
    ));
    let restarted = session_store(solo);
    let loaded = restarted
        .load(&record_id)
        .await
        .expect("post-restart load")
        .expect("session survives restart");
    assert_eq!(loaded.summary, "durable");
    assert_eq!(loaded.logical_version, 1);
}

// --- Rebalance: sessions move with the ring, none are lost ---

#[tokio::test]
async fn compression_sessions_rebalance_without_loss() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let bootstrap_members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &bootstrap_members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &bootstrap_members, shared_clock(&clock_cell), 0).await;
    let c = TestNode::start("node-c", &["node-c"], shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b, &c]);

    // RF=1 makes ownership moves unambiguous.
    let replicated_a = replicated_for(
        &a,
        &addrs,
        settings(1, Consistency::All, Consistency::One, 0),
    );
    let replicated_b = replicated_for(
        &b,
        &addrs,
        settings(1, Consistency::All, Consistency::One, 0),
    );
    let store_a = session_store(replicated_a.clone());

    let seeds: Vec<u8> = (1..=32).collect();
    for seed in &seeds {
        commit_session(
            &store_a,
            id(*seed),
            None,
            &record(1, "tenant-a", &format!("summary-{seed}")),
        )
        .await
        .expect("seed session");
    }
    assert_eq!(a.shard.len() + b.shard.len(), 32);

    // Node C joins: every ring learns about it.
    for node in [&a, &b, &c] {
        for member in ["node-a", "node-b", "node-c"] {
            if member != node.id {
                node.cache.add_node(member);
            }
        }
    }
    let report_a = replicated_a.maintenance_round().await;
    let report_b = replicated_b.maintenance_round().await;
    let moved = report_a.handoff_moved + report_b.handoff_moved;
    assert!(moved > 0, "some sessions must move to node C");
    assert_eq!(
        report_a.handoff_retained + report_b.handoff_retained,
        0,
        "all handoffs must ack against a healthy target"
    );
    assert_eq!(
        a.shard.len() + b.shard.len() + c.shard.len(),
        32,
        "rebalance must move, never lose, sessions"
    );

    // Every session still loads with its exact summary after the move.
    let store_b = session_store(replicated_b);
    for seed in &seeds {
        let loaded = store_b
            .load(&id(*seed))
            .await
            .expect("post-rebalance load")
            .unwrap_or_else(|| panic!("session {seed} lost after rebalance"));
        assert_eq!(loaded.summary, format!("summary-{seed}"));
    }
}

// --- Partition heal: convergence without loss or resurrection ---

#[tokio::test]
async fn partition_heal_converges_sessions_and_deletes_do_not_resurrect() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    let replicated_a = replicated_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 60),
    );
    let replicated_b = replicated_for(
        &b,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 60),
    );
    let store_a = session_store(replicated_a.clone());
    let store_b = session_store(replicated_b.clone());

    let live_id = id(1);
    let doomed_id = id(2);
    commit_session(&store_a, live_id, None, &record(1, "tenant-a", "v1"))
        .await
        .expect("seed live");
    commit_session(
        &store_a,
        doomed_id,
        None,
        &record(1, "tenant-a", "sensitive"),
    )
    .await
    .expect("seed doomed");

    // Partition: a newer summary lands only on A; the delete lands only
    // on B (One-consistency coordinators cut off from their peer).
    let solo_a = session_store(replicated_for(
        &a,
        &HashMap::new(),
        settings(2, Consistency::One, Consistency::One, 60),
    ));
    solo_a
        .commit(
            &solo_a
                .acquire_update(&live_id, Duration::from_secs(5))
                .await
                .unwrap()
                .unwrap(),
            Some(1),
            &record(2, "tenant-a", "v2"),
            Duration::from_secs(600),
        )
        .await
        .expect("partitioned update");
    let solo_b = session_store(replicated_for(
        &b,
        &HashMap::new(),
        settings(2, Consistency::One, Consistency::One, 60),
    ));
    assert!(
        solo_b
            .delete(&doomed_id)
            .await
            .expect("solo delete")
            .deleted
    );

    // Divergence is real before the heal.
    let live_key = format!("compression:v1:{live_id}");
    let doomed_key = format!("compression:v1:{doomed_id}");
    assert_ne!(a.shard.fetch(&live_key), b.shard.fetch(&live_key));
    assert!(a
        .shard
        .fetch(&doomed_key)
        .is_some_and(|r| !r.is_tombstone()));
    assert!(b.shard.fetch(&doomed_key).is_some_and(|r| r.is_tombstone()));

    // Heal.
    replicated_a.maintenance_round().await;
    replicated_b.maintenance_round().await;

    assert_eq!(a.shard.fetch(&live_key), b.shard.fetch(&live_key));
    let healed = store_b
        .load(&live_id)
        .await
        .expect("healed load")
        .expect("live session present");
    assert_eq!(healed.summary, "v2");

    // The delete won on both replicas and is visible as a tombstone.
    for store in [&store_a, &store_b] {
        let marker = store
            .load(&doomed_id)
            .await
            .expect("tombstone load")
            .expect("tombstone visible");
        assert_eq!(marker.kind, RecordKind::Tombstone);
        assert!(marker.summary.is_empty());
    }

    // A stale writer that still believes version 1 cannot resurrect the
    // deleted session or regress the live one.
    assert_eq!(
        commit_session(
            &store_a,
            doomed_id,
            Some(1),
            &record(2, "tenant-a", "resurrect")
        )
        .await,
        Err(CommitError::StaleVersion)
    );
    assert_eq!(
        commit_session(&store_b, live_id, Some(1), &record(2, "tenant-a", "stale")).await,
        Err(CommitError::StaleVersion)
    );

    // A writer that observed the tombstone legitimately re-creates the
    // session at the next version, on both replicas.
    let tombstone_version = store_a
        .load(&doomed_id)
        .await
        .unwrap()
        .unwrap()
        .logical_version;
    commit_session(
        &store_a,
        doomed_id,
        Some(tombstone_version),
        &record(tombstone_version + 1, "tenant-a", "recreated"),
    )
    .await
    .expect("re-create after observed delete");
    assert_eq!(
        store_b.load(&doomed_id).await.unwrap().unwrap().summary,
        "recreated"
    );
}

// --- Competing writers: deterministic winner, loser sees StaleVersion ---

#[tokio::test]
async fn competing_writers_resolve_deterministically_and_flag_conflicts() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    let replicated_a = replicated_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    );
    let replicated_b = replicated_for(
        &b,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    );
    let store_a = session_store(replicated_a.clone());
    let store_b = session_store(replicated_b.clone());

    let record_id = id(7);
    commit_session(&store_a, record_id, None, &record(1, "tenant-a", "base"))
        .await
        .expect("seed");

    // Connected case: the second writer extending the same parent loses
    // at the conditional put, before any replicated write happens.
    commit_session(
        &store_a,
        record_id,
        Some(1),
        &record(2, "tenant-a", "winner"),
    )
    .await
    .expect("first update");
    assert_eq!(
        commit_session(
            &store_b,
            record_id,
            Some(1),
            &record(2, "tenant-a", "loser")
        )
        .await,
        Err(CommitError::StaleVersion)
    );
    assert_eq!(
        store_b.load(&record_id).await.unwrap().unwrap().summary,
        "winner"
    );

    // Partitioned case: both sides accept an equal-version child at One
    // consistency. After the heal the causal LWW merge settles one
    // deterministic winner on every replica and flags the conflict.
    let solo_a = session_store(replicated_for(
        &a,
        &HashMap::new(),
        settings(2, Consistency::One, Consistency::One, 0),
    ));
    let solo_b = session_store(replicated_for(
        &b,
        &HashMap::new(),
        settings(2, Consistency::One, Consistency::One, 0),
    ));
    commit_session(
        &solo_a,
        record_id,
        Some(2),
        &record(3, "tenant-a", "child-a"),
    )
    .await
    .expect("partitioned child A");
    commit_session(
        &solo_b,
        record_id,
        Some(2),
        &record(3, "tenant-a", "child-b"),
    )
    .await
    .expect("partitioned child B");

    replicated_a.maintenance_round().await;
    replicated_b.maintenance_round().await;

    let from_a = store_a.load(&record_id).await.unwrap().unwrap();
    let from_b = store_b.load(&record_id).await.unwrap().unwrap();
    assert_eq!(from_a.summary, from_b.summary, "replicas converge");
    assert_eq!(from_a.logical_version, 3);
    assert!(
        from_a.conflict_detected && from_b.conflict_detected,
        "the surviving record must carry the conflict flag"
    );
}

// --- Admin lifecycle: cluster-complete, bounded, topology-safe ---

#[tokio::test]
async fn admin_list_delete_and_purge_are_cluster_complete_and_bounded() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b", "node-c"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let c = TestNode::start("node-c", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b, &c]);
    let replicated_a = replicated_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    );
    let replicated_c = replicated_for(
        &c,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    );
    let store_a = session_store(replicated_a);
    let store_c = session_store(replicated_c);

    // Sessions written through different coordinators, two tenants.
    let mut expected_ids: BTreeSet<CompressionRecordId> = BTreeSet::new();
    for seed in 1..=8 {
        commit_session(
            &store_a,
            id(seed),
            None,
            &record(1, "tenant-a", "content-a"),
        )
        .await
        .expect("seed tenant-a");
        expected_ids.insert(id(seed));
    }
    for seed in 9..=12 {
        commit_session(
            &store_c,
            id(seed),
            None,
            &record(1, "tenant-b", "content-b"),
        )
        .await
        .expect("seed tenant-b");
        expected_ids.insert(id(seed));
    }

    // Bounded pagination to completion: every session written anywhere in
    // the fleet is listed; pages never exceed their limit; duplicates
    // across holders collapse by record ID.
    let mut seen: BTreeSet<CompressionRecordId> = BTreeSet::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = store_c
            .list(&ListRequest {
                tenant_id: None,
                origin: None,
                expired: None,
                expiration_cutoff_unix_ms: 0,
                conflict: None,
                cursor: cursor.take(),
                limit: 3,
            })
            .await
            .expect("bounded list page");
        assert!(page.records.len() <= 3, "page exceeded its bound");
        for metadata in &page.records {
            assert!(!format!("{metadata:?}").contains("content-"));
            seen.insert(metadata.id);
        }
        pages += 1;
        assert!(pages < 60, "pagination must terminate");
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, expected_ids, "listing is cluster-complete");

    // Topology-safe pagination: stop mid-walk, then lose a member. The
    // stale cursor resumes at a surviving node and terminates.
    let first = store_c
        .list(&ListRequest {
            tenant_id: None,
            origin: None,
            expired: None,
            expiration_cutoff_unix_ms: 0,
            conflict: None,
            cursor: None,
            limit: 2,
        })
        .await
        .expect("first page");
    let stale_cursor = first.next_cursor.expect("mid-walk cursor");
    for node in [&a, &b, &c] {
        node.cache.remove_node("node-b");
    }
    let mut cursor = Some(stale_cursor);
    let mut resumed_pages = 0;
    while let Some(current) = cursor.take() {
        let page = store_c
            .list(&ListRequest {
                tenant_id: None,
                origin: None,
                expired: None,
                expiration_cutoff_unix_ms: 0,
                conflict: None,
                cursor: Some(current),
                limit: 100,
            })
            .await
            .expect("stale-cursor page");
        resumed_pages += 1;
        assert!(resumed_pages < 10, "stale-cursor walk must terminate");
        cursor = page.next_cursor;
    }
    for node in [&a, &b, &c] {
        for member in ["node-a", "node-b", "node-c"] {
            if member != node.id {
                node.cache.add_node(member);
            }
        }
    }

    // Replicated single delete through one coordinator is visible from
    // every other coordinator.
    let deleted = store_c.delete(&id(1)).await.expect("replicated delete");
    assert!(deleted.deleted);
    assert_eq!(
        store_a.load(&id(1)).await.unwrap().unwrap().kind,
        RecordKind::Tombstone
    );

    // Bounded tenant-scoped purge deletes exactly that tenant's live
    // sessions fleet-wide and leaves the rest alone.
    let purge = store_a
        .purge(&PurgeRequest {
            tenant_id: Some("tenant-b".to_string()),
            origin: None,
            expired_before_unix_ms: None,
            conflict: None,
            cursor: None,
            limit: 100,
        })
        .await
        .expect("bounded purge");
    assert_eq!(purge.deleted, 4);
    for seed in 9..=12 {
        assert_eq!(
            store_c.load(&id(seed)).await.unwrap().unwrap().kind,
            RecordKind::Tombstone,
            "tenant-b session {seed} must be tombstoned"
        );
    }
    for seed in 2..=8 {
        assert_eq!(
            store_c.load(&id(seed)).await.unwrap().unwrap().kind,
            RecordKind::Live,
            "tenant-a session {seed} must survive the scoped purge"
        );
    }
}
