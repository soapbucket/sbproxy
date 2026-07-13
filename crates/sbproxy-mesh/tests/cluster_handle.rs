use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use sbproxy_mesh::{
    ClusterHandle, ClusterIdentity, ClusterMemberState, ClusterMode, ClusterNodeRole,
    ClusterStateError, ClusterStateRead, MeshNode,
};
use serde::{Deserialize, Serialize};

fn identity(node_id: &str) -> ClusterIdentity {
    ClusterIdentity {
        cluster_id: "cluster-a".to_string(),
        node_id: node_id.to_string(),
        roles: BTreeSet::from([ClusterNodeRole::Gateway, ClusterNodeRole::Worker]),
        labels: BTreeMap::from([("zone".to_string(), "a".to_string())]),
        peer_address: Some("127.0.0.1:7946".to_string()),
        model_endpoint: Some("https://127.0.0.1:9443".to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Payload {
    value: String,
}

#[test]
fn local_handle_has_one_live_member_and_no_network_node() {
    let handle = ClusterHandle::local(identity("local-a")).expect("local handle");

    assert_eq!(handle.mode(), ClusterMode::Local);
    assert_eq!(handle.identity().node_id, "local-a");
    assert!(handle.mesh_node().is_none());
    assert!(!handle.has_peer_transport());
    assert!(handle.isolation_observer().is_none());

    let members = handle.membership();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].node_id, "local-a");
    assert_eq!(members[0].state, ClusterMemberState::Alive);
    assert!(members[0].last_ack_age.is_zero());
}

#[test]
fn distributed_handle_wraps_one_mesh_node_and_clones_one_inner() {
    let mesh = Arc::new(MeshNode::new("worker-a".to_string(), Vec::new(), 32));
    let handle = ClusterHandle::distributed(identity("worker-a"), Arc::clone(&mesh))
        .expect("distributed handle");
    let clone = handle.clone();

    assert_eq!(handle.mode(), ClusterMode::Distributed);
    assert!(ClusterHandle::ptr_eq(&handle, &clone));
    assert!(Arc::ptr_eq(&handle.mesh_node().expect("mesh node"), &mesh));
    assert_eq!(handle.membership()[0].state, ClusterMemberState::Alive);
}

#[test]
fn distributed_handle_rejects_mesh_identity_mismatch() {
    let mesh = Arc::new(MeshNode::new("worker-b".to_string(), Vec::new(), 32));
    let error =
        ClusterHandle::distributed(identity("worker-a"), mesh).expect_err("identity mismatch");
    assert!(matches!(error, ClusterStateError::InvalidIdentity(_)));
}

#[tokio::test]
async fn typed_state_round_trips_generation_publisher_and_payload() {
    let handle = ClusterHandle::local(identity("local-a")).expect("local handle");
    handle
        .publish_state(
            "model-snapshots",
            "local-a",
            1,
            7,
            Duration::from_secs(30),
            &Payload {
                value: "ready".to_string(),
            },
        )
        .await
        .expect("publish state");

    let read = handle
        .read_state::<Payload>("model-snapshots", "local-a", 1)
        .await;
    let ClusterStateRead::Present(record) = read else {
        panic!("expected present state, got {read:?}");
    };
    assert_eq!(record.publisher_node_id, "local-a");
    assert_eq!(record.generation, 7);
    assert_eq!(record.schema_version, 1);
    assert_eq!(record.payload.value, "ready");
    assert!(record.expires_at_unix_ms > record.published_at_unix_ms);
}

#[tokio::test]
async fn distributed_state_routes_to_the_remote_hash_owner() {
    use sbproxy_mesh::transport::{TransportClientPool, TransportServer};

    let node_a = MeshNode::new("worker-a".to_string(), vec!["worker-b".to_string()], 32);
    let node_b = MeshNode::new("worker-b".to_string(), vec!["worker-a".to_string()], 32);
    let cache_a = node_a.distributed_cache();
    let cache_b = node_b.distributed_cache();
    let server_a = TransportServer::start(0, Arc::clone(&cache_a))
        .await
        .expect("server a");
    let server_b = TransportServer::start(0, Arc::clone(&cache_b))
        .await
        .expect("server b");
    let port_a = server_a.local_port();
    let port_b = server_b.local_port();
    let map_a = Arc::new(RwLock::new(HashMap::from([
        ("worker-a".to_string(), format!("127.0.0.1:{port_a}")),
        ("worker-b".to_string(), format!("127.0.0.1:{port_b}")),
    ])));
    let map_b = Arc::new(RwLock::new(HashMap::from([
        ("worker-a".to_string(), format!("127.0.0.1:{port_a}")),
        ("worker-b".to_string(), format!("127.0.0.1:{port_b}")),
    ])));
    let node_a = node_a.with_transport(Some(server_a), Arc::new(TransportClientPool::new()), map_a);
    let _node_b = Arc::new(node_b.with_transport(
        Some(server_b),
        Arc::new(TransportClientPool::new()),
        map_b,
    ));
    let handle = ClusterHandle::distributed(identity("worker-a"), Arc::new(node_a))
        .expect("distributed handle");

    let key = (0..10_000)
        .map(|index| format!("worker-a-{index}"))
        .find(|key| {
            cache_a.responsible_node(&format!("sbproxy:cluster-state:v1:model-snapshots:{key}"))
                == Some("worker-b".to_string())
        })
        .expect("key owned by worker b");
    handle
        .publish_state(
            "model-snapshots",
            &key,
            1,
            4,
            Duration::from_secs(30),
            &Payload {
                value: "remote".to_string(),
            },
        )
        .await
        .expect("remote publish");

    assert!(cache_b
        .get_local(&format!("sbproxy:cluster-state:v1:model-snapshots:{key}"))
        .is_some());
    let ClusterStateRead::Present(record) = handle
        .read_state::<Payload>("model-snapshots", &key, 1)
        .await
    else {
        panic!("remote state should be readable");
    };
    assert_eq!(record.payload.value, "remote");
}

#[tokio::test]
async fn typed_state_distinguishes_missing_incompatible_and_expired() {
    let handle = ClusterHandle::local(identity("local-a")).expect("local handle");
    assert!(matches!(
        handle
            .read_state::<Payload>("model-snapshots", "missing", 1)
            .await,
        ClusterStateRead::Missing
    ));

    handle
        .publish_state(
            "model-snapshots",
            "local-a",
            2,
            1,
            Duration::from_millis(20),
            &Payload {
                value: "brief".to_string(),
            },
        )
        .await
        .expect("publish state");
    assert!(matches!(
        handle
            .read_state::<Payload>("model-snapshots", "local-a", 1)
            .await,
        ClusterStateRead::IncompatibleSchema {
            expected: 1,
            actual: 2,
            generation: 1,
        }
    ));

    let ClusterStateRead::Present(versioned) =
        handle.read_state_value("model-snapshots", "local-a").await
    else {
        panic!("raw versioned state should remain readable");
    };
    assert_eq!(versioned.schema_version, 2);
    assert_eq!(versioned.payload["value"], "brief");

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(matches!(
        handle
            .read_state::<Payload>("model-snapshots", "local-a", 2)
            .await,
        ClusterStateRead::Expired { generation: 1, .. }
    ));
}

#[tokio::test]
async fn stale_generation_cannot_replace_newer_state() {
    let handle = ClusterHandle::local(identity("local-a")).expect("local handle");
    handle
        .publish_state(
            "model-snapshots",
            "local-a",
            1,
            9,
            Duration::from_secs(30),
            &Payload {
                value: "new".to_string(),
            },
        )
        .await
        .expect("publish newer");
    let error = handle
        .publish_state(
            "model-snapshots",
            "local-a",
            1,
            8,
            Duration::from_secs(30),
            &Payload {
                value: "old".to_string(),
            },
        )
        .await
        .expect_err("stale publish rejected");
    assert!(matches!(
        error,
        ClusterStateError::StaleGeneration {
            current: 9,
            attempted: 8,
        }
    ));

    let ClusterStateRead::Present(record) = handle
        .read_state::<Payload>("model-snapshots", "local-a", 1)
        .await
    else {
        panic!("newer state remains present");
    };
    assert_eq!(record.payload.value, "new");
}

#[tokio::test]
async fn one_generation_cannot_be_reused_for_different_contents() {
    let handle = ClusterHandle::local(identity("local-a")).expect("local handle");
    handle
        .publish_state(
            "model-snapshots",
            "local-a",
            1,
            9,
            Duration::from_secs(30),
            &Payload {
                value: "first".to_string(),
            },
        )
        .await
        .expect("publish first");
    let error = handle
        .publish_state(
            "model-snapshots",
            "local-a",
            1,
            9,
            Duration::from_secs(30),
            &Payload {
                value: "different".to_string(),
            },
        )
        .await
        .expect_err("generation is immutable");
    assert!(matches!(
        error,
        ClusterStateError::GenerationConflict { generation: 9 }
    ));
}

#[tokio::test]
async fn state_keys_and_payloads_are_bounded() {
    let handle = ClusterHandle::local(identity("local-a")).expect("local handle");
    let error = handle
        .publish_state(
            "bad namespace",
            "key",
            1,
            1,
            Duration::from_secs(1),
            &Payload {
                value: "x".to_string(),
            },
        )
        .await
        .expect_err("invalid namespace");
    assert!(matches!(error, ClusterStateError::InvalidKey(_)));

    let oversized = Payload {
        value: "x".repeat(1_048_577),
    };
    let error = handle
        .publish_state(
            "model-snapshots",
            "local-a",
            1,
            1,
            Duration::from_secs(1),
            &oversized,
        )
        .await
        .expect_err("oversized payload");
    assert!(matches!(error, ClusterStateError::PayloadTooLarge { .. }));
}
