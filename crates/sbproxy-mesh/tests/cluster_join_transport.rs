use std::collections::{BTreeMap, BTreeSet};
use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use sbproxy_mesh::bootstrap::{bootstrap, BootstrapConfig};
use sbproxy_mesh::discovery::{seeds::SeedDiscovery, Discovery};
use sbproxy_mesh::{ClusterHandle, ClusterIdentity, ClusterNodeRole, ClusterStateRead};

fn reserve_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("reserve UDP port")
        .local_addr()
        .expect("UDP address")
        .port()
}

fn reserve_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve TCP port")
        .local_addr()
        .expect("TCP address")
        .port()
}

fn config(gossip_port: u16, transport_port: u16) -> BootstrapConfig {
    BootstrapConfig {
        wait_for_peers_secs: 0,
        gossip_port,
        transport_port,
        gossip_advertise_addr: Some(format!("127.0.0.1:{gossip_port}")),
        transport_advertise_addr: Some(format!("127.0.0.1:{transport_port}")),
        shared_key: Some("cluster-join-test-secret".to_string()),
        swim_protocol_period_ms: 25,
        swim_ping_timeout_ms: 20,
        swim_suspect_timeout_secs: 2,
        ..Default::default()
    }
}

fn identity(node_id: &str, gossip_port: u16) -> ClusterIdentity {
    ClusterIdentity {
        cluster_id: "integration".to_string(),
        node_id: node_id.to_string(),
        roles: BTreeSet::from([ClusterNodeRole::Worker]),
        labels: BTreeMap::new(),
        peer_address: Some(format!("127.0.0.1:{gossip_port}")),
        model_endpoint: None,
    }
}

async fn wait_for_route(handle: &ClusterHandle, peer_id: &str, expected: &str) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let routed = handle.mesh_node().and_then(|mesh| {
                mesh.peer_addr_map()
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(peer_id)
                    .cloned()
            });
            let in_ring = handle.mesh_node().is_some_and(|mesh| {
                let cache = mesh.distributed_cache();
                (0..1024).any(|index| {
                    cache.responsible_node(&format!("probe-{index}")).as_deref() == Some(peer_id)
                })
            });
            if routed.as_deref() == Some(expected) && in_ring {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("peer route learned");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joining_nodes_exchange_stable_ids_and_typed_state_over_transport() {
    let gossip_a = reserve_udp_port();
    let gossip_b = reserve_udp_port();
    let transport_a = reserve_tcp_port();
    let transport_b = reserve_tcp_port();

    let none: Vec<Box<dyn Discovery>> = Vec::new();
    let node_a = bootstrap(&none, &config(gossip_a, transport_a), "node-a".to_string())
        .await
        .expect("bootstrap node A");
    let seeds: Vec<Box<dyn Discovery>> = vec![Box::new(SeedDiscovery::new(vec![format!(
        "127.0.0.1:{gossip_a}"
    )]))];
    let node_b = bootstrap(&seeds, &config(gossip_b, transport_b), "node-b".to_string())
        .await
        .expect("bootstrap node B");

    let handle_a = ClusterHandle::distributed(identity("node-a", gossip_a), Arc::new(node_a))
        .expect("handle A");
    let handle_b = ClusterHandle::distributed(identity("node-b", gossip_b), Arc::new(node_b))
        .expect("handle B");

    wait_for_route(&handle_a, "node-b", &format!("127.0.0.1:{transport_b}")).await;
    wait_for_route(&handle_b, "node-a", &format!("127.0.0.1:{transport_a}")).await;

    handle_a
        .publish_state(
            "join-test",
            "shared",
            1,
            1,
            Duration::from_secs(10),
            &BTreeMap::from([("ready".to_string(), true)]),
        )
        .await
        .expect("publish typed state");

    match handle_b
        .read_state::<BTreeMap<String, bool>>("join-test", "shared", 1)
        .await
    {
        ClusterStateRead::Present(record) => {
            assert_eq!(record.publisher_node_id, "node-a");
            assert_eq!(record.payload.get("ready"), Some(&true));
        }
        other => panic!("expected state from node A, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn seed_join_flood_converges_three_nodes_on_one_stable_ring() {
    let gossip_a = reserve_udp_port();
    let gossip_b = reserve_udp_port();
    let gossip_c = reserve_udp_port();
    let transport_a = reserve_tcp_port();
    let transport_b = reserve_tcp_port();
    let transport_c = reserve_tcp_port();

    let none: Vec<Box<dyn Discovery>> = Vec::new();
    let node_a = bootstrap(&none, &config(gossip_a, transport_a), "node-a".to_string())
        .await
        .expect("bootstrap node A");
    let seed_a = || -> Vec<Box<dyn Discovery>> {
        vec![Box::new(SeedDiscovery::new(vec![format!(
            "127.0.0.1:{gossip_a}"
        )]))]
    };
    let node_b = bootstrap(
        &seed_a(),
        &config(gossip_b, transport_b),
        "node-b".to_string(),
    )
    .await
    .expect("bootstrap node B");
    let node_c = bootstrap(
        &seed_a(),
        &config(gossip_c, transport_c),
        "node-c".to_string(),
    )
    .await
    .expect("bootstrap node C");

    let handle_a = ClusterHandle::distributed(identity("node-a", gossip_a), Arc::new(node_a))
        .expect("handle A");
    let handle_b = ClusterHandle::distributed(identity("node-b", gossip_b), Arc::new(node_b))
        .expect("handle B");
    let handle_c = ClusterHandle::distributed(identity("node-c", gossip_c), Arc::new(node_c))
        .expect("handle C");

    let expected = [
        ("node-a", format!("127.0.0.1:{transport_a}")),
        ("node-b", format!("127.0.0.1:{transport_b}")),
        ("node-c", format!("127.0.0.1:{transport_c}")),
    ];
    for handle in [&handle_a, &handle_b, &handle_c] {
        for (peer_id, address) in &expected {
            if peer_id != &handle.identity().node_id {
                wait_for_route(handle, peer_id, address).await;
            }
        }
        assert_eq!(handle.membership().len(), 3);
    }
}
