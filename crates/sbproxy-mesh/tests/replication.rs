//! Multi-node tests for the WOR-1947 replicated state substrate.
//!
//! Each test stands up real `TransportServer`s on ephemeral localhost
//! ports with durable `ReplicaShard`s and drives `ReplicatedStore`
//! coordinators against them. Placement uses the same consistent-hash
//! ring as production; membership is pinned directly (no SWIM) so every
//! scenario is deterministic. Time is an injected shared clock.
//!
//! The tests map onto the ticket's acceptance criteria:
//! replication-not-routing (AC1), durable restart (AC2), ring-change
//! handoff without loss (AC3), partition heal convergence for live
//! records and tombstones (AC4), no resurrection of deleted state (AC5),
//! and idempotent ambiguous-write retries (AC6).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use sbproxy_mesh::state::distributed_cache::DistributedCache;
use sbproxy_mesh::state::replicated::{
    Consistency, MeshClock, ReplicaShard, ReplicatedStore, ReplicationSettings, ShardLimits,
    StateError,
};
use sbproxy_mesh::transport::{TransportClientPool, TransportServer};
use tempfile::TempDir;

/// Shared deterministic clock: all nodes see the same milliseconds value,
/// and tests advance it explicitly.
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

fn store_for(
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

/// Probe for a key whose replica set (at the given factor) is exactly
/// `want`, in any order.
fn key_with_replicas(store: &ReplicatedStore, want: &[&str]) -> String {
    for i in 0..10_000 {
        let key = format!("probe-key-{i}");
        let mut replicas = store.replica_set(&key);
        replicas.sort();
        let mut expected: Vec<String> = want.iter().map(|s| s.to_string()).collect();
        expected.sort();
        if replicas == expected {
            return key;
        }
    }
    panic!("no key found with replica set {want:?}");
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
        anti_entropy_interval_secs: 3600,
        tombstone_gc_grace_secs: grace_secs,
    }
}

// --- AC1: replication, not remote-owner routing ---

#[tokio::test]
async fn writes_land_on_every_replica_not_just_the_owner() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b", "node-c"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let c = TestNode::start("node-c", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b, &c]);
    let store_a = store_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    );

    let key = key_with_replicas(&store_a, &["node-b", "node-c"]);
    store_a
        .put(&key, b"replicated-value", 0)
        .await
        .expect("replicated put");

    // Both replicas hold the record in their own durable shards; the
    // coordinator (not in the replica set) holds nothing. This is
    // replication: no single owner's memory is load-bearing.
    assert!(
        b.shard.fetch(&key).is_some(),
        "replica B must hold the record"
    );
    assert!(
        c.shard.fetch(&key).is_some(),
        "replica C must hold the record"
    );
    assert!(
        a.shard.fetch(&key).is_none(),
        "non-replica A must not hold it"
    );

    // Reads reconcile across replicas and decode the original value.
    let read = store_a.get(&key).await.expect("replicated read");
    assert_eq!(read.value, Some(Bytes::from_static(b"replicated-value")));
    assert_eq!(read.responses, 2);
}

#[tokio::test]
async fn quorum_write_fails_closed_when_replicas_unreachable() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let mut addrs = addr_map(&[&a, &b]);

    // Make node B unreachable by pointing its address at a dead port.
    let dead_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    addrs.insert("node-b".to_string(), format!("127.0.0.1:{dead_port}"));

    let store_a = store_for(
        &a,
        &addrs,
        settings(2, Consistency::Quorum, Consistency::One, 0),
    );
    let key = key_with_replicas(&store_a, &["node-a", "node-b"]);

    // Quorum of 2 requires both replicas; only A can ack.
    let err = store_a
        .put(&key, b"v", 0)
        .await
        .expect_err("quorum must fail");
    assert!(matches!(
        err,
        StateError::QuorumFailed {
            acked: 1,
            required: 2
        }
    ));

    // Consistency::One succeeds against the reachable local replica.
    let store_relaxed = store_for(
        &a,
        &addrs,
        settings(2, Consistency::One, Consistency::One, 0),
    );
    store_relaxed
        .put(&key, b"v", 0)
        .await
        .expect("one-ack write");
}

// --- AC2: owner restart preserves committed state ---

#[tokio::test]
async fn replica_restart_serves_committed_state_from_disk() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    let store_a = store_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::One, 0),
    );

    let key = key_with_replicas(&store_a, &["node-a", "node-b"]);
    store_a.put(&key, b"durable-value", 0).await.expect("put");

    // Simulate node B crashing: tear down its server and drop every
    // in-memory reference to its shard, keeping only the disk directory.
    // The coordinator must go too: its pooled connection keeps B's
    // per-connection handler task (and thus the shard's redb lock) alive.
    let TestNode {
        shard: shard_b,
        server: server_b,
        dir: dir_b,
        ..
    } = b;
    let record_before = shard_b.fetch(&key).expect("present before restart");
    drop(store_a);
    server_b.shutdown();
    drop(shard_b);

    // Restart: reopen the shard from disk with a fresh process's state.
    // Poll briefly; the handler task releases the database lock as soon
    // as it observes the closed connection.
    let reopened = {
        let mut attempt = 0;
        loop {
            match ReplicaShard::open(
                &dir_b.path().join("shard.redb"),
                ShardLimits::default(),
                0,
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
    let record_after = reopened
        .fetch(&key)
        .expect("committed state must survive restart");
    assert_eq!(record_before, record_after);
    assert_eq!(reopened.quarantine_discarded(), 0);
}

// --- AC3: ring changes hand off records without invisible loss ---

#[tokio::test]
async fn ring_change_hands_off_records_and_drops_only_after_ack() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    // Start with A and B only; C joins later.
    let bootstrap_members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &bootstrap_members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &bootstrap_members, shared_clock(&clock_cell), 0).await;
    let c = TestNode::start("node-c", &["node-c"], shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b, &c]);

    // RF=1 makes ownership moves unambiguous.
    let store_a = store_for(
        &a,
        &addrs,
        settings(1, Consistency::All, Consistency::One, 0),
    );
    let store_b = store_for(
        &b,
        &addrs,
        settings(1, Consistency::All, Consistency::One, 0),
    );

    // Write a batch through A so both nodes hold some records.
    for i in 0..32 {
        store_a
            .put(
                &format!("handoff-key-{i}"),
                format!("value-{i}").as_bytes(),
                0,
            )
            .await
            .expect("seed write");
    }
    let before_total = a.shard.len() + b.shard.len();
    assert_eq!(before_total, 32);

    // Node C joins: every ring learns about it (what gossip record_join
    // does in production).
    for node in [&a, &b, &c] {
        for member in ["node-a", "node-b", "node-c"] {
            if member != node.id {
                node.cache.add_node(member);
            }
        }
    }

    // Run handoff on the shedding nodes.
    let report_a = store_a.maintenance_round().await;
    let report_b = store_b.maintenance_round().await;
    let moved = report_a.handoff_moved + report_b.handoff_moved;
    assert!(moved > 0, "some keys must move to node C");
    assert_eq!(
        report_a.handoff_retained + report_b.handoff_retained,
        0,
        "all handoffs must ack against a healthy target"
    );

    // No invisible loss: every record is still readable at its current
    // owner, and totals balance.
    let after_total = a.shard.len() + b.shard.len() + c.shard.len();
    assert_eq!(after_total, 32, "handoff must move, never lose, records");
    assert_eq!(c.shard.len(), moved);
    for i in 0..32 {
        let key = format!("handoff-key-{i}");
        let read = store_b.get(&key).await.expect("read after rebalance");
        assert_eq!(
            read.value,
            Some(Bytes::from(format!("value-{i}").into_bytes())),
            "key {key} lost after handoff"
        );
    }
}

// --- AC4: partition heal converges live records and tombstones ---

#[tokio::test]
async fn anti_entropy_converges_divergent_replicas_after_heal() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    let store_a = store_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    );
    let store_b = store_for(
        &b,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    );

    let live_key = key_with_replicas(&store_a, &["node-a", "node-b"]);
    let deleted_key = format!("{live_key}-deleted");

    // Healthy cluster: both keys replicated everywhere.
    store_a.put(&live_key, b"v1", 0).await.expect("seed live");
    store_a
        .put(&deleted_key, b"sensitive", 0)
        .await
        .expect("seed doomed");

    // Partition: writes reach only one side (applied directly to one
    // shard, which is exactly what a coordinator cut off from its peer
    // produces at Consistency::One).
    let receipt_v2 = {
        // Newer live update lands only on A.
        let store_a_solo = store_for(
            &a,
            &HashMap::new(),
            settings(2, Consistency::One, Consistency::One, 0),
        );
        store_a_solo
            .put(&live_key, b"v2", 0)
            .await
            .expect("partitioned write")
    };
    {
        // The delete lands only on B.
        let store_b_solo = store_for(
            &b,
            &HashMap::new(),
            settings(2, Consistency::One, Consistency::One, 0),
        );
        store_b_solo
            .delete(&deleted_key)
            .await
            .expect("partitioned delete");
    }
    // Divergence is real before the heal.
    assert_ne!(a.shard.fetch(&live_key), b.shard.fetch(&live_key));
    assert!(a
        .shard
        .fetch(&deleted_key)
        .is_some_and(|r| !r.is_tombstone()));
    assert!(b
        .shard
        .fetch(&deleted_key)
        .is_some_and(|r| r.is_tombstone()));

    // Heal: run anti-entropy on both sides.
    store_a.maintenance_round().await;
    store_b.maintenance_round().await;

    // Both replicas converge: the newer live write wins its key, the
    // tombstone wins the deleted key, on BOTH nodes.
    assert_eq!(a.shard.fetch(&live_key), b.shard.fetch(&live_key));
    assert_eq!(
        a.shard.fetch(&live_key).map(|r| r.logical_version()),
        Some(receipt_v2.register.logical_version())
    );
    assert!(a
        .shard
        .fetch(&deleted_key)
        .is_some_and(|r| r.is_tombstone()));
    assert!(b
        .shard
        .fetch(&deleted_key)
        .is_some_and(|r| r.is_tombstone()));

    // The healed read surfaces the winner and hides the deleted key.
    let healed = store_b.get(&live_key).await.expect("healed read");
    assert_eq!(healed.value, Some(Bytes::from_static(b"v2")));
    let deleted = store_a.get(&deleted_key).await.expect("deleted read");
    assert_eq!(deleted.value, None);
}

// --- AC5: deleted state cannot resurrect ---

#[tokio::test]
async fn stale_replica_cannot_resurrect_a_deleted_record() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    let store_a = store_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    );
    let store_b = store_for(
        &b,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    );

    let key = key_with_replicas(&store_a, &["node-a", "node-b"]);
    let stale_receipt = store_a.put(&key, b"sensitive", 0).await.expect("write");
    store_a.delete(&key).await.expect("delete");

    // A stale holder replays the old live record at both replicas (a
    // former owner pushing its memory back, or a delayed retry).
    for store in [&store_a, &store_b] {
        let outcome = store.apply_receipt(&stale_receipt).await;
        // The fan-out acks (merge ran) but every replica retained the
        // tombstone; nothing came back to life.
        assert!(outcome.is_ok());
    }
    assert!(a.shard.fetch(&key).is_some_and(|r| r.is_tombstone()));
    assert!(b.shard.fetch(&key).is_some_and(|r| r.is_tombstone()));
    assert_eq!(store_b.get(&key).await.expect("read").value, None);

    // A causally NEWER write (which read the tombstone) is a legitimate
    // re-create and must succeed.
    store_a.put(&key, b"recreated", 0).await.expect("recreate");
    assert_eq!(
        store_b.get(&key).await.expect("read").value,
        Some(Bytes::from_static(b"recreated"))
    );
}

#[tokio::test]
async fn tombstone_gc_waits_for_every_replica_to_confirm() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    // Grace of 60 seconds; the shared clock advances explicitly.
    let store_a = store_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 60),
    );
    let store_b = store_for(
        &b,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 60),
    );

    let key = key_with_replicas(&store_a, &["node-a", "node-b"]);
    store_a.put(&key, b"sensitive", 0).await.expect("write");

    // Partition-shaped divergence: the delete lands only on A, while B
    // still holds the stale live record.
    let store_a_solo = store_for(
        &a,
        &HashMap::new(),
        settings(2, Consistency::One, Consistency::One, 60),
    );
    store_a_solo.delete(&key).await.expect("solo delete");
    assert!(b.shard.fetch(&key).is_some_and(|r| !r.is_tombstone()));

    // Advance past grace while B is unreachable (the partition is still
    // up for A's view of B). GC must defer: no confirmation from B.
    clock_cell.fetch_add(61_000, Ordering::Relaxed);
    let report = store_a_solo.maintenance_round().await;
    assert_eq!(
        report.gc_collected, 0,
        "GC must defer while B is unconfirmed"
    );
    assert!(report.gc_deferred >= 1);
    assert!(a.shard.fetch(&key).is_some_and(|r| r.is_tombstone()));
    assert!(b.shard.fetch(&key).is_some_and(|r| !r.is_tombstone()));

    // Heal. The same maintenance round first pushes the tombstone to B
    // (anti-entropy) and only then finds every replica confirming, so
    // collection on A is safe within one round.
    let report_a = store_a.maintenance_round().await;
    assert!(b.shard.fetch(&key).is_some_and(|r| r.is_tombstone()));
    assert_eq!(report_a.gc_collected, 1, "A collects after B confirms");
    assert!(a.shard.fetch(&key).is_none());

    // B in turn observes A holding nothing (already collected), which
    // also confirms, and collects its own tombstone.
    let report_b = store_b.maintenance_round().await;
    assert_eq!(report_b.gc_collected, 1, "B collects after A confirms");
    assert!(b.shard.fetch(&key).is_none());

    // Collection must TERMINATE: further rounds on either side must not
    // re-learn the collected tombstone from the other's digest (the
    // ping-pong hazard found during live GCP validation) nor re-push it.
    for _ in 0..3 {
        store_a.maintenance_round().await;
        store_b.maintenance_round().await;
    }
    assert!(
        a.shard.fetch(&key).is_none() && b.shard.fetch(&key).is_none(),
        "collected tombstone must stay collected on both replicas"
    );

    // Nothing resurrects after collection: reads agree the key is gone.
    assert_eq!(store_b.get(&key).await.expect("read").value, None);
}

// --- AC6: ambiguous applied-write retries are idempotent ---

#[tokio::test]
async fn retrying_a_write_receipt_is_idempotent() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    let store_a = store_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    );

    let key = key_with_replicas(&store_a, &["node-a", "node-b"]);
    let receipt = store_a.put(&key, b"exactly-once", 0).await.expect("write");
    let stored_after_first = b.shard.fetch(&key).expect("stored");

    // The caller's response was lost; it retries the same receipt twice.
    for _ in 0..2 {
        let retry = store_a.apply_receipt(&receipt).await.expect("retry");
        assert_eq!(retry.acked, 2);
    }

    // The stored record is byte-identical: same version, no duplicate
    // effects, no version inflation.
    assert_eq!(b.shard.fetch(&key), Some(stored_after_first.clone()));
    assert_eq!(a.shard.fetch(&key), Some(stored_after_first));
    assert_eq!(
        store_a.get(&key).await.expect("read").value,
        Some(Bytes::from_static(b"exactly-once"))
    );
}

// --- AC7: fleet-complete admin list, delete, purge ---

#[tokio::test]
async fn fleet_admin_list_delete_and_purge_are_complete_and_bounded() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b", "node-c"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let c = TestNode::start("node-c", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b, &c]);
    let store_a = store_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::One, 0),
    );

    for i in 0..10 {
        store_a
            .put(&format!("admin:key-{i}"), b"v", 0)
            .await
            .expect("seed");
    }
    store_a.put("other:key", b"v", 0).await.expect("seed other");

    // Bounded pagination: pages never exceed the limit, tokens chain to
    // completion, and the union covers every key on every holder.
    let mut seen_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut holders_per_key: HashMap<String, usize> = HashMap::new();
    let mut token: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = store_a
            .fleet_state_page("admin:", token.as_deref(), 4)
            .await;
        assert!(page.entries.len() <= 4, "page exceeded its bound");
        assert!(page.unreachable.is_empty(), "all members reachable");
        for entry in &page.entries {
            assert!(entry.key.starts_with("admin:"));
            seen_keys.insert(entry.key.clone());
            *holders_per_key.entry(entry.key.clone()).or_default() += 1;
        }
        pages += 1;
        assert!(pages < 50, "pagination must terminate");
        match page.next_page_token {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    assert_eq!(seen_keys.len(), 10, "every replicated key is listed");
    // RF=2: every key is reported by exactly its two holders.
    assert!(holders_per_key.values().all(|holders| *holders == 2));

    // Topology-safe pagination: stop mid-walk, then lose a member. The
    // stale token resumes at the next surviving node without wedging.
    let first_page = store_a.fleet_state_page("admin:", None, 3).await;
    let stale_token = first_page.next_page_token.expect("mid-walk token");
    for node in [&a, &b, &c] {
        node.cache.remove_node("node-b");
    }
    let mut token = Some(stale_token);
    let mut resumed_pages = 0;
    while let Some(current) = token.take() {
        let page = store_a
            .fleet_state_page("admin:", Some(&current), 100)
            .await;
        resumed_pages += 1;
        assert!(resumed_pages < 10, "stale-token walk must terminate");
        token = page.next_page_token;
    }
    for node in [&a, &b, &c] {
        for member in ["node-a", "node-b", "node-c"] {
            if member != node.id {
                node.cache.add_node(member);
            }
        }
    }

    // Replicated purge: bounded, prefix-scoped, and terminal. Every
    // purged key reads as deleted afterwards; other prefixes survive.
    let outcome = store_a.fleet_purge("admin:", 100).await;
    assert_eq!(outcome.deleted, 10);
    assert_eq!(outcome.failed, 0);
    assert!(!outcome.truncated);
    for i in 0..10 {
        let read = store_a
            .get(&format!("admin:key-{i}"))
            .await
            .expect("post-purge read");
        assert_eq!(read.value, None, "purged key must read as deleted");
    }
    assert_eq!(
        store_a.get("other:key").await.expect("read").value,
        Some(Bytes::from_static(b"v")),
        "purge must not cross its prefix"
    );

    // Purge budget: a max of 1 truncates and reports it.
    store_a.put("budget:k1", b"v", 0).await.expect("seed");
    store_a.put("budget:k2", b"v", 0).await.expect("seed");
    let bounded = store_a.fleet_purge("budget:", 1).await;
    assert_eq!(bounded.deleted, 1);
    assert!(bounded.truncated);
}

// --- Read repair ---

#[tokio::test]
async fn quorum_reads_repair_stale_replicas_inline() {
    let clock_cell = Arc::new(AtomicU64::new(1_000_000));
    let members = ["node-a", "node-b"];
    let a = TestNode::start("node-a", &members, shared_clock(&clock_cell), 0).await;
    let b = TestNode::start("node-b", &members, shared_clock(&clock_cell), 0).await;
    let addrs = addr_map(&[&a, &b]);
    let store_a = store_for(
        &a,
        &addrs,
        settings(2, Consistency::All, Consistency::Quorum, 0),
    );

    let key = key_with_replicas(&store_a, &["node-a", "node-b"]);
    store_a.put(&key, b"v1", 0).await.expect("seed");

    // Divergence: a newer write reaches only A.
    let store_a_solo = store_for(
        &a,
        &HashMap::new(),
        settings(2, Consistency::One, Consistency::One, 0),
    );
    store_a_solo.put(&key, b"v2", 0).await.expect("solo write");
    assert_ne!(a.shard.fetch(&key), b.shard.fetch(&key));

    // A quorum read reconciles to v2 and repairs B in-line.
    let read = store_a.get(&key).await.expect("read");
    assert_eq!(read.value, Some(Bytes::from_static(b"v2")));
    assert_eq!(read.repaired, 1);
    assert_eq!(a.shard.fetch(&key), b.shard.fetch(&key));
}
