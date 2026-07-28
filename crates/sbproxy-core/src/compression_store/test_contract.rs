//! Shared behavioral contract for durable compression-state adapters.

use super::{LocalCompressionStore, MeshCompressionStore, MeshCompressionStoreConfig};
use bytes::Bytes;
use sbproxy_ai::compression::{
    CommitError, CompressionBackend, CompressionRecordId, CompressionSessionRecord,
    CompressionSessionStore, ListRequest, MessageDigest, RecordKind, RECORD_SCHEMA_VERSION,
};
use sbproxy_mesh::state::distributed_cache::DistributedCache;
use sbproxy_mesh::state::replicated::{
    Consistency, MeshClock, ReplicaShard, ReplicatedStore, ReplicationSettings, ShardLimits,
};
use sbproxy_mesh::transport::TransportClientPool;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy)]
enum DeleteRepresentation {
    Missing,
    Tombstone,
}

fn id(seed: u8) -> CompressionRecordId {
    CompressionRecordId::derive("contract-tenant", "contract.example.com", [seed; 16])
}

fn record(version: u64, summary: &str) -> CompressionSessionRecord {
    CompressionSessionRecord {
        schema_version: RECORD_SCHEMA_VERSION,
        logical_version: version,
        tenant_id: "contract-tenant".to_string(),
        origin: "contract.example.com".to_string(),
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
        writer_node: "node-a".to_string(),
        parent_logical_version: (version > 1).then_some(version - 1),
        conflict_detected: false,
        created_at_unix_ms: 1_000,
        updated_at_unix_ms: 2_000 + version,
        expires_at_unix_ms: u64::MAX,
        kind: RecordKind::Live,
    }
}

async fn assert_store_contract(
    store: Arc<dyn CompressionSessionStore>,
    delete_representation: DeleteRepresentation,
) {
    let record_id = id(91);
    assert!(
        store.load(&record_id).await.unwrap().is_none(),
        "an unknown record must be absent"
    );

    let initial = store
        .acquire_update(&record_id, Duration::from_secs(5))
        .await
        .unwrap()
        .expect("first writer acquires the lease");
    assert!(
        store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .is_none(),
        "a concurrent writer must observe contention"
    );
    store
        .commit(&initial, None, &record(1, "first"), Duration::from_secs(60))
        .await
        .unwrap();
    store.release(initial).await.unwrap();

    let loaded = store.load(&record_id).await.unwrap().unwrap();
    assert_eq!(loaded.logical_version, 1);
    assert_eq!(loaded.summary, "first");
    assert_eq!(loaded.kind, RecordKind::Live);

    let stale = store
        .acquire_update(&record_id, Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    let mut stale_candidate = record(1, "stale");
    stale_candidate.parent_logical_version = Some(0);
    assert_eq!(
        store
            .commit(&stale, Some(0), &stale_candidate, Duration::from_secs(60),)
            .await,
        Err(CommitError::StaleVersion)
    );
    store.release(stale).await.unwrap();

    let update = store
        .acquire_update(&record_id, Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    store
        .commit(
            &update,
            Some(1),
            &record(2, "second"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    store.release(update).await.unwrap();
    assert_eq!(
        store.load(&record_id).await.unwrap().unwrap().summary,
        "second"
    );

    let page = store
        .list(&ListRequest {
            tenant_id: Some("contract-tenant".to_string()),
            origin: Some("contract.example.com".to_string()),
            expired: Some(false),
            expiration_cutoff_unix_ms: 1_000_000,
            conflict: Some(false),
            cursor: None,
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].id, record_id);
    assert_eq!(page.records[0].logical_version, 2);
    assert_eq!(page.records[0].kind, RecordKind::Live);
    assert!(page.next_cursor.is_none());

    let deleted = store.delete(&record_id).await.unwrap();
    assert!(deleted.deleted);
    let after_delete = store.load(&record_id).await.unwrap();
    match delete_representation {
        DeleteRepresentation::Missing => assert!(after_delete.is_none()),
        DeleteRepresentation::Tombstone => {
            let tombstone = after_delete.expect("Mesh retains a tombstone");
            assert_eq!(tombstone.kind, RecordKind::Tombstone);
            assert!(tombstone.summary.is_empty());
        }
    }
    assert!(
        !after_delete_is_live(store.load(&record_id).await.unwrap()),
        "delete must leave no live record"
    );
}

fn after_delete_is_live(record: Option<CompressionSessionRecord>) -> bool {
    record.is_some_and(|record| record.kind == RecordKind::Live)
}

fn mesh_substrate() -> Arc<ReplicatedStore> {
    let clock: MeshClock = Arc::new(|| 1_000_000);
    let shard = Arc::new(ReplicaShard::in_memory(ShardLimits::default(), 0, clock));
    let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("contract-node", 128));
    Arc::new(ReplicatedStore::new(
        shard,
        cache,
        Arc::new(TransportClientPool::new()),
        Arc::new(|_| None),
        Arc::new(|| false),
        ReplicationSettings {
            replication_factor: 1,
            write_consistency: Consistency::One,
            read_consistency: Consistency::One,
            anti_entropy_interval_secs: 3_600,
            tombstone_gc_grace_secs: 0,
        },
    ))
}

#[tokio::test]
async fn local_obeys_the_shared_compression_store_contract() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        LocalCompressionStore::open(directory.path().join("contract.redb"))
            .await
            .unwrap(),
    );
    assert_eq!(store.backend(), CompressionBackend::Local);
    assert_store_contract(store, DeleteRepresentation::Missing).await;
}

#[tokio::test]
async fn mesh_obeys_the_shared_compression_store_contract() {
    let store = Arc::new(
        MeshCompressionStore::new(
            mesh_substrate(),
            MeshCompressionStoreConfig {
                key_prefix: "compression:contract:v1:".to_string(),
                local_lock_capacity: 16,
            },
        )
        .unwrap(),
    );
    assert_eq!(store.backend(), CompressionBackend::Mesh);
    assert_store_contract(store, DeleteRepresentation::Tombstone).await;
}
