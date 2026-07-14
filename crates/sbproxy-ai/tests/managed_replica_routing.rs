use std::collections::BTreeMap;

use sbproxy_ai::managed_replica::{ManagedReplicaInput, ManagedReplicaRouter, ManagedRouteClass};
use sbproxy_ai::model_directory::{ModelDirectoryReplica, ModelDirectoryView};
use sbproxy_model_host::node_snapshot::ModelPlaneHealth;
use sbproxy_model_host::{DeploymentGenerationFence, DeploymentRuntimeState};

fn replica(
    node_id: &str,
    state: DeploymentRuntimeState,
    compute_utilization_millis: Option<u16>,
    queue_depth: u64,
) -> ModelDirectoryReplica {
    ModelDirectoryReplica {
        node_id: node_id.to_string(),
        deployment: "coder".to_string(),
        deployment_generation: 7,
        model: "qwen2.5-coder".to_string(),
        variant: Some("fp8".to_string()),
        endpoint: Some(format!("https://{node_id}.internal:9443")),
        state,
        active_requests: 1,
        queue_depth,
        adapters: vec!["sql".to_string()],
        node_labels: BTreeMap::from([("region".to_string(), "us-central1".to_string())]),
        compute_utilization_millis,
        memory_occupancy_millis: Some(500),
        model_plane_health: ModelPlaneHealth::Ready,
    }
}

fn view(replicas: Vec<ModelDirectoryReplica>) -> ModelDirectoryView {
    let mut view = ModelDirectoryView::default();
    view.candidate_replicas
        .insert("coder".to_string(), replicas);
    view.deployment_generation_fences.insert(
        "coder".to_string(),
        DeploymentGenerationFence {
            deployment_generation: 7,
            desired_revision_digest: None,
        },
    );
    view
}

fn input<'a>(
    local_node_id: &'a str,
    requested_adapter: Option<&'a str>,
    preferred_region: Option<&'a str>,
    allow_cold: bool,
) -> ManagedReplicaInput<'a> {
    ManagedReplicaInput {
        local_node_id,
        requested_adapter,
        preferred_region,
        prefix_key: b"tenant-a:prefix-a",
        allow_cold,
    }
}

#[test]
fn ready_adapter_region_and_queue_precede_remote_ties() {
    let mut no_adapter = replica(
        "worker-no-adapter",
        DeploymentRuntimeState::Ready,
        Some(100),
        0,
    );
    no_adapter.adapters.clear();
    let mut other_region = replica(
        "worker-other-region",
        DeploymentRuntimeState::Ready,
        Some(100),
        0,
    );
    other_region
        .node_labels
        .insert("region".to_string(), "europe-west1".to_string());
    let low_queue = replica(
        "worker-low-queue",
        DeploymentRuntimeState::Ready,
        Some(300),
        1,
    );
    let high_queue = replica(
        "worker-high-queue",
        DeploymentRuntimeState::Ready,
        Some(100),
        4,
    );
    let selection = ManagedReplicaRouter::ordered_candidates(
        &view(vec![no_adapter, other_region, high_queue, low_queue]),
        "coder",
        input("gateway-a", Some("sql"), Some("us-central1"), false),
    );

    assert_eq!(selection.candidates[0].replica.node_id, "worker-low-queue");
    assert_eq!(selection.trace.excluded_adapter, 1);
    assert_eq!(selection.trace.selected_reason, Some("ready_low_queue"));
}

#[test]
fn unknown_compute_is_not_scored_as_idle() {
    let selection = ManagedReplicaRouter::ordered_candidates(
        &view(vec![
            replica("unknown", DeploymentRuntimeState::Ready, None, 0),
            replica("known", DeploymentRuntimeState::Ready, Some(500), 0),
        ]),
        "coder",
        input("gateway-a", None, None, false),
    );
    assert_eq!(selection.candidates[0].replica.node_id, "known");
}

#[test]
fn equivalent_local_replica_wins_without_a_peer_hop() {
    let selection = ManagedReplicaRouter::ordered_candidates(
        &view(vec![
            replica("worker-remote", DeploymentRuntimeState::Ready, Some(500), 0),
            replica("worker-local", DeploymentRuntimeState::Ready, Some(500), 0),
        ]),
        "coder",
        input("worker-local", None, None, false),
    );
    assert_eq!(selection.candidates[0].replica.node_id, "worker-local");
    assert_eq!(
        selection.candidates[0].route_class,
        ManagedRouteClass::Local
    );
    assert_eq!(selection.trace.selected_reason, Some("local_fast_path"));
}

#[test]
fn cold_and_unavailable_candidates_follow_explicit_policy() {
    let cold = replica(
        "worker-cold",
        DeploymentRuntimeState::Preparing,
        Some(100),
        0,
    );
    let mut unavailable = replica(
        "worker-unavailable",
        DeploymentRuntimeState::Ready,
        Some(0),
        0,
    );
    unavailable.model_plane_health = ModelPlaneHealth::Unavailable;
    let view = view(vec![cold, unavailable]);

    let ready_only = ManagedReplicaRouter::ordered_candidates(
        &view,
        "coder",
        input("gateway-a", None, None, false),
    );
    assert!(ready_only.candidates.is_empty());
    assert_eq!(ready_only.trace.excluded_state, 1);
    assert_eq!(ready_only.trace.excluded_health, 1);

    let with_cold = ManagedReplicaRouter::ordered_candidates(
        &view,
        "coder",
        input("gateway-a", None, None, true),
    );
    assert_eq!(with_cold.candidates.len(), 1);
    assert_eq!(with_cold.candidates[0].replica.node_id, "worker-cold");
    assert_eq!(with_cold.trace.selected_reason, Some("cold_start"));
}
