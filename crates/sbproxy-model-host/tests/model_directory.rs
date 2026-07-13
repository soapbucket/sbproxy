use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use sbproxy_ai::model_directory::{
    DirectoryAuthenticatedIdentity, DirectoryMember, DirectoryMemberState,
    DirectorySnapshotEnvelope, DirectorySnapshotRead, ModelDirectory,
    ModelDirectoryExclusionReason, ModelDirectoryHealth,
};
use sbproxy_model_host::node_snapshot::{
    ModelPlaneHealth, NodeArtifactSnapshot, NodeEngineSnapshot, NodeHealthSnapshot,
    NodeHealthState, NodeIdentitySnapshot, NodeModelSnapshot, NodeReplicaSnapshot, NodeRole,
    NodeSnapshotGeneration, RuntimeReplicaIdentity, NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
};
use sbproxy_model_host::{
    AcceleratorKind, ArtifactCacheState, ArtifactFormat, DeploymentRuntimeState,
    DeploymentRuntimeStatus, EngineAvailability, EngineCapabilities, EngineDetection, EngineKind,
    GpuDescriptor, MemoryEstimate,
};

fn fixture() -> NodeModelSnapshot {
    NodeModelSnapshot {
        schema_version: NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
        node: NodeIdentitySnapshot {
            node_id: "worker-a".to_string(),
            roles: BTreeSet::from([NodeRole::Worker]),
            labels: BTreeMap::from([
                ("zone".to_string(), "us-central1-a".to_string()),
                ("accelerator".to_string(), "l4".to_string()),
            ]),
            model_endpoint: Some("https://10.0.0.12:9443".to_string()),
        },
        health: NodeHealthSnapshot {
            state: NodeHealthState::Ready,
            reason_codes: Vec::new(),
            model_plane: ModelPlaneHealth::Ready,
        },
        engines: vec![NodeEngineSnapshot {
            engine: EngineKind::Vllm,
            availability: EngineAvailability::Available,
            version: Some("0.10.0".to_string()),
            artifact_formats: vec![ArtifactFormat::Safetensors],
            accelerators: BTreeSet::from([AcceleratorKind::Cuda]),
            supports_container: true,
            supports_uv: true,
            reason_code: None,
        }],
        devices: vec![GpuDescriptor::l4().try_into().expect("device snapshot")],
        artifacts: vec![NodeArtifactSnapshot {
            artifact_digest: "a".repeat(64),
            model: "qwen2.5-coder".to_string(),
            variant: "fp8-l4".to_string(),
            state: sbproxy_model_host::node_snapshot::NodeArtifactState::Ready,
            completed_bytes: 8_000_000_000,
            total_bytes: Some(8_000_000_000),
            last_accessed_unix_ms: Some(1_700_000_000_000),
            reason_code: None,
        }],
        replicas: vec![NodeReplicaSnapshot {
            deployment: "coder".to_string(),
            deployment_generation: 9,
            model: "qwen2.5-coder".to_string(),
            variant: Some("fp8-l4".to_string()),
            engine: Some(EngineKind::Vllm),
            state: DeploymentRuntimeState::Ready,
            endpoint: Some("https://10.0.0.12:9443".to_string()),
            artifact_digest: Some("a".repeat(64)),
            selected_devices: vec![0],
            reserved_memory_bytes: Some(9_000_000_000),
            active_requests: 3,
            queue_depth: 2,
            adapters: vec!["sql".to_string()],
            reason_code: None,
        }],
        placement_weight: 24_000,
        active_deployment_digest: Some("b".repeat(64)),
        generation: 11,
        published_at_unix_ms: 1_700_000_000_000,
        expires_at_unix_ms: 1_700_000_030_000,
    }
}

#[test]
fn snapshot_schema_v2_round_trips_every_operational_field() {
    let snapshot = fixture();
    snapshot.validate().expect("valid snapshot");
    let encoded = snapshot.to_json().expect("encode snapshot");
    let decoded = NodeModelSnapshot::from_json(&encoded).expect("decode snapshot");
    assert_eq!(decoded, snapshot);
    assert_eq!(decoded.replicas[0].active_requests, 3);
    assert_eq!(decoded.replicas[0].queue_depth, 2);
    assert_eq!(
        decoded.devices[0].available_memory_bytes,
        23 * 1024 * 1024 * 1024
    );
    assert_eq!(decoded.artifacts[0].state.as_str(), "ready");
    assert_eq!(decoded.health.model_plane, ModelPlaneHealth::Ready);
    assert_eq!(decoded.devices[0].compute_utilization_millis, None);
    assert_eq!(decoded.devices[0].memory_occupancy_millis, Some(42));
}

#[test]
fn strict_decode_and_validation_reject_unknown_unbounded_or_unsafe_state() {
    let snapshot = fixture();
    let mut value: serde_json::Value =
        serde_json::from_slice(&snapshot.to_json().expect("JSON")).expect("value");
    value["node"]["private_key"] = serde_json::Value::String("secret".to_string());
    let unknown = serde_json::to_vec(&value).expect("unknown JSON");
    assert!(NodeModelSnapshot::from_json(&unknown)
        .expect_err("unknown nested field")
        .to_string()
        .contains("decode"));

    let mut invalid = snapshot.clone();
    invalid
        .node
        .labels
        .insert("x".repeat(129), "bad".to_string());
    assert!(invalid.validate().is_err());

    let mut invalid = snapshot.clone();
    invalid.replicas[0].reason_code = Some("raw error: /var/lib/private/key".to_string());
    assert!(invalid.validate().is_err());

    let mut invalid = snapshot.clone();
    invalid.expires_at_unix_ms = invalid.published_at_unix_ms;
    assert!(invalid.validate().is_err());

    assert!(NodeModelSnapshot::from_json(&vec![b' '; 512 * 1024 + 1]).is_err());
}

#[test]
fn runtime_converters_keep_exact_state_but_drop_paths_and_raw_errors() {
    let detection = EngineDetection {
        kind: EngineKind::Vllm,
        availability: EngineAvailability::Available,
        version: Some("0.10.0".to_string()),
        reason: "installed at /private/engine".to_string(),
        remediation: None,
    };
    let capabilities = EngineCapabilities {
        artifact_formats: vec![ArtifactFormat::Safetensors],
        accelerators: vec![AcceleratorKind::Cuda],
        supports_container: true,
        supports_uv: true,
    };
    let engine =
        NodeEngineSnapshot::from_runtime(&detection, &capabilities, None).expect("engine snapshot");
    assert_eq!(engine.availability, EngineAvailability::Available);

    let artifact = NodeArtifactSnapshot::from_cache(
        &"c".repeat(64),
        "qwen2.5-coder",
        "fp8-l4",
        &ArtifactCacheState::Ready {
            snapshot_path: PathBuf::from("/private/model/snapshot"),
            total_size_bytes: 10_000,
            last_accessed_ms: 55,
        },
    )
    .expect("artifact snapshot");
    assert_eq!(artifact.total_bytes, Some(10_000));

    let runtime = DeploymentRuntimeStatus {
        deployment: "coder".to_string(),
        generation: 7,
        state: DeploymentRuntimeState::Failed,
        active_requests: 4,
        queued_requests: 5,
        engine: Some(EngineKind::Vllm),
        driver_availability: Some(EngineAvailability::Available),
        artifact_digest: Some("c".repeat(64)),
        selected_devices: vec![0],
        memory: Some(MemoryEstimate::from_total(0, 10_000)),
        port: None,
        reason_code: Some("engine_launch_failed".to_string()),
        job_id: Some("job-secret-context".to_string()),
        last_error: Some("failed to open /private/model/snapshot with token=secret".to_string()),
    };
    let replica = NodeReplicaSnapshot::from_runtime(
        &runtime,
        RuntimeReplicaIdentity {
            model: "qwen2.5-coder",
            variant: Some("fp8-l4"),
            endpoint: Some("https://10.0.0.12:9443"),
            adapters: &["sql".to_string()],
        },
    )
    .expect("replica snapshot");
    assert_eq!(replica.active_requests, 4);
    assert_eq!(replica.queue_depth, 5);
    assert_eq!(replica.reason_code.as_deref(), Some("engine_launch_failed"));

    let serialized = serde_json::to_string(&(engine, artifact, replica)).expect("serialize");
    assert!(!serialized.contains("/private"));
    assert!(!serialized.contains("token=secret"));
    assert!(!serialized.contains("job-secret-context"));
}

#[test]
fn snapshot_generation_survives_reopen_and_is_unique_across_writers() {
    let temp = tempfile::tempdir().expect("temp dir");
    let first = NodeSnapshotGeneration::open(temp.path()).expect("first counter");
    assert_eq!(first.next().expect("generation 1"), 1);
    assert_eq!(first.next().expect("generation 2"), 2);
    drop(first);
    assert_eq!(
        NodeSnapshotGeneration::open(temp.path())
            .expect("reopened counter")
            .next()
            .expect("generation 3"),
        3
    );

    let counter = Arc::new(NodeSnapshotGeneration::open(temp.path()).expect("shared counter"));
    let barrier = Arc::new(Barrier::new(9));
    let writers = (0..8)
        .map(|_| {
            let counter = Arc::clone(&counter);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                counter.next().expect("concurrent generation")
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let generations = writers
        .into_iter()
        .map(|writer| writer.join().expect("writer"))
        .collect::<BTreeSet<_>>();
    assert_eq!(generations, BTreeSet::from_iter(4..=11));
}

fn member(node_id: &str, state: DirectoryMemberState) -> DirectoryMember {
    DirectoryMember {
        node_id: node_id.to_string(),
        address: Some(format!("10.0.0.{}:7946", node_id.len())),
        state,
        last_ack_age_ms: 250,
        incarnation: 4,
    }
}

fn observed(snapshot: &NodeModelSnapshot) -> DirectorySnapshotRead {
    DirectorySnapshotRead::Present(DirectorySnapshotEnvelope {
        publisher_node_id: snapshot.node.node_id.clone(),
        schema_version: snapshot.schema_version,
        generation: snapshot.generation,
        published_at_unix_ms: snapshot.published_at_unix_ms,
        expires_at_unix_ms: snapshot.expires_at_unix_ms,
        authenticated_identity: None,
        payload: serde_json::to_value(snapshot).expect("snapshot value"),
    })
}

fn snapshot_for(node_id: &str, generation: u64) -> NodeModelSnapshot {
    let mut snapshot = fixture();
    snapshot.node.node_id = node_id.to_string();
    snapshot.node.model_endpoint = Some(format!("https://{node_id}.internal:9443"));
    snapshot.replicas[0].endpoint = snapshot.node.model_endpoint.clone();
    snapshot.generation = generation;
    snapshot.validate().expect("directory snapshot fixture");
    snapshot
}

#[test]
fn directory_joins_every_member_and_calls_out_unhealthy_nodes() {
    let directory = ModelDirectory::new();
    let worker_a = snapshot_for("worker-a", 10);
    let worker_b = snapshot_for("worker-b", 8);
    let view = directory
        .refresh(
            worker_a.published_at_unix_ms + 1_000,
            vec![
                member("worker-a", DirectoryMemberState::Alive),
                member("worker-b", DirectoryMemberState::Suspect),
                member("worker-c", DirectoryMemberState::Dead),
                member("worker-d", DirectoryMemberState::Unreachable),
            ],
            BTreeMap::from([
                ("worker-a".to_string(), observed(&worker_a)),
                ("worker-b".to_string(), observed(&worker_b)),
                (
                    "worker-c".to_string(),
                    DirectorySnapshotRead::Expired {
                        generation: 7,
                        expires_at_unix_ms: worker_a.published_at_unix_ms - 1,
                    },
                ),
                ("worker-d".to_string(), DirectorySnapshotRead::Unreachable),
            ]),
        )
        .expect("directory refresh");

    assert_eq!(view.nodes.len(), 4);
    assert_eq!(view.summary.total_nodes, 4);
    assert_eq!(view.summary.healthy_nodes, 1);
    assert_eq!(view.summary.unhealthy_nodes, 3);
    assert_eq!(view.unhealthy_nodes().len(), 3);
    assert_eq!(
        view.node("worker-b").expect("worker b").exclusion_reason,
        Some(ModelDirectoryExclusionReason::MembershipSuspect)
    );
    assert_eq!(
        view.node("worker-c").expect("worker c").exclusion_reason,
        Some(ModelDirectoryExclusionReason::MembershipDead)
    );
    assert_eq!(
        view.node("worker-d").expect("worker d").exclusion_reason,
        Some(ModelDirectoryExclusionReason::MembershipUnreachable)
    );
    assert_eq!(view.eligible_replicas["coder"].len(), 1);
}

#[test]
fn directory_keeps_current_generation_cold_candidates_and_device_utilization() {
    let directory = ModelDirectory::new();
    let mut snapshot = snapshot_for("worker-a", 10);
    snapshot.replicas[0].state = DeploymentRuntimeState::Preparing;
    snapshot.devices[0].compute_utilization_millis = Some(720);
    snapshot.devices[0].memory_occupancy_millis = Some(640);
    let view = directory
        .refresh(
            snapshot.published_at_unix_ms + 1_000,
            vec![member("worker-a", DirectoryMemberState::Alive)],
            BTreeMap::from([("worker-a".to_string(), observed(&snapshot))]),
        )
        .expect("directory refresh");

    assert!(!view.eligible_replicas.contains_key("coder"));
    let replica = &view.candidate_replicas["coder"][0];
    assert_eq!(replica.state, DeploymentRuntimeState::Preparing);
    assert_eq!(replica.compute_utilization_millis, Some(720));
    assert_eq!(replica.memory_occupancy_millis, Some(640));
    assert_eq!(replica.model_plane_health, ModelPlaneHealth::Ready);
    assert_eq!(replica.adapters, vec!["sql".to_string()]);
}

#[test]
fn directory_reports_snapshot_failure_classes_without_raw_details() {
    let directory = ModelDirectory::new();
    let now = fixture().published_at_unix_ms + 1_000;
    let view = directory
        .refresh(
            now,
            vec![
                member("missing", DirectoryMemberState::Alive),
                member("malformed", DirectoryMemberState::Alive),
                member("future", DirectoryMemberState::Alive),
            ],
            BTreeMap::from([
                ("missing".to_string(), DirectorySnapshotRead::Missing),
                ("malformed".to_string(), DirectorySnapshotRead::Malformed),
                (
                    "future".to_string(),
                    DirectorySnapshotRead::IncompatibleSchema {
                        schema_version: 99,
                        generation: 2,
                    },
                ),
            ]),
        )
        .expect("failure view");

    assert_eq!(
        view.node("missing").expect("missing").exclusion_reason,
        Some(ModelDirectoryExclusionReason::SnapshotMissing)
    );
    assert_eq!(
        view.node("malformed").expect("malformed").exclusion_reason,
        Some(ModelDirectoryExclusionReason::SnapshotMalformed)
    );
    assert_eq!(
        view.node("future").expect("future").exclusion_reason,
        Some(ModelDirectoryExclusionReason::SchemaIncompatible)
    );
    let json = serde_json::to_string(&*view).expect("admin-safe JSON");
    assert!(!json.contains("raw"));
    assert!(!json.contains("private"));
}

#[test]
fn directory_rejects_snapshot_roles_or_labels_outside_enrolled_claims() {
    let directory = ModelDirectory::new();
    let snapshot = snapshot_for("worker-a", 10);
    let mut read = observed(&snapshot);
    let DirectorySnapshotRead::Present(envelope) = &mut read else {
        unreachable!();
    };
    envelope.authenticated_identity = Some(DirectoryAuthenticatedIdentity {
        node_id: "worker-a".to_string(),
        roles: BTreeSet::from([NodeRole::Gateway]),
        labels: snapshot.node.labels.clone(),
    });
    let view = directory
        .refresh(
            snapshot.published_at_unix_ms + 100,
            vec![member("worker-a", DirectoryMemberState::Alive)],
            BTreeMap::from([("worker-a".to_string(), read)]),
        )
        .expect("identity mismatch view");
    let node = view.node("worker-a").unwrap();
    assert_eq!(
        node.exclusion_reason,
        Some(ModelDirectoryExclusionReason::IdentityMismatch)
    );
    assert_eq!(node.health, ModelDirectoryHealth::Unhealthy);
    assert!(!node.model_eligible);
}

#[test]
fn older_snapshot_generation_never_replaces_last_observed_truth() {
    let directory = ModelDirectory::new();
    let newer = snapshot_for("worker-a", 12);
    let first = directory
        .refresh(
            newer.published_at_unix_ms + 100,
            vec![member("worker-a", DirectoryMemberState::Alive)],
            BTreeMap::from([("worker-a".to_string(), observed(&newer))]),
        )
        .expect("newer refresh");
    assert_eq!(
        first.node("worker-a").unwrap().snapshot_generation,
        Some(12)
    );

    let older = snapshot_for("worker-a", 11);
    let second = directory
        .refresh(
            older.published_at_unix_ms + 200,
            vec![member("worker-a", DirectoryMemberState::Alive)],
            BTreeMap::from([("worker-a".to_string(), observed(&older))]),
        )
        .expect("older refresh");
    let node = second.node("worker-a").expect("worker a");
    assert_eq!(node.snapshot_generation, Some(12));
    assert_eq!(
        node.exclusion_reason,
        Some(ModelDirectoryExclusionReason::OldSnapshotGeneration)
    );
    assert_eq!(node.health, ModelDirectoryHealth::Unhealthy);
}

#[test]
fn schema_zero_normalizes_and_readers_hold_immutable_views() {
    let directory = ModelDirectory::new();
    let snapshot = snapshot_for("worker-a", 5);
    let mut payload = serde_json::to_value(&snapshot).expect("snapshot value");
    payload["schema_version"] = serde_json::json!(0);
    payload.as_object_mut().unwrap().remove("health");
    payload
        .as_object_mut()
        .unwrap()
        .remove("active_deployment_digest");
    for device in payload["devices"].as_array_mut().unwrap() {
        device
            .as_object_mut()
            .unwrap()
            .remove("compute_utilization_millis");
        device
            .as_object_mut()
            .unwrap()
            .remove("memory_occupancy_millis");
    }
    let old = directory.load();
    let current = directory
        .refresh(
            snapshot.published_at_unix_ms + 100,
            vec![member("worker-a", DirectoryMemberState::Alive)],
            BTreeMap::from([(
                "worker-a".to_string(),
                DirectorySnapshotRead::Present(DirectorySnapshotEnvelope {
                    publisher_node_id: "worker-a".to_string(),
                    schema_version: 0,
                    generation: snapshot.generation,
                    published_at_unix_ms: snapshot.published_at_unix_ms,
                    expires_at_unix_ms: snapshot.expires_at_unix_ms,
                    authenticated_identity: None,
                    payload,
                }),
            )]),
        )
        .expect("v0 refresh");

    assert!(old.nodes.is_empty());
    assert_eq!(current.nodes.len(), 1);
    assert!(!Arc::ptr_eq(&old, &current));
    assert_eq!(
        current.node("worker-a").unwrap().normalized_schema_version,
        Some(NODE_MODEL_SNAPSHOT_SCHEMA_VERSION)
    );
}

#[test]
fn schema_one_normalizes_without_claiming_model_plane_readiness() {
    let directory = ModelDirectory::new();
    let snapshot = snapshot_for("worker-a", 6);
    let mut payload = serde_json::to_value(&snapshot).expect("snapshot value");
    payload["schema_version"] = serde_json::json!(1);
    payload["health"]
        .as_object_mut()
        .unwrap()
        .remove("model_plane");
    for device in payload["devices"].as_array_mut().unwrap() {
        device
            .as_object_mut()
            .unwrap()
            .remove("compute_utilization_millis");
        device
            .as_object_mut()
            .unwrap()
            .remove("memory_occupancy_millis");
    }

    let current = directory
        .refresh(
            snapshot.published_at_unix_ms + 100,
            vec![member("worker-a", DirectoryMemberState::Alive)],
            BTreeMap::from([(
                "worker-a".to_string(),
                DirectorySnapshotRead::Present(DirectorySnapshotEnvelope {
                    publisher_node_id: "worker-a".to_string(),
                    schema_version: 1,
                    generation: snapshot.generation,
                    published_at_unix_ms: snapshot.published_at_unix_ms,
                    expires_at_unix_ms: snapshot.expires_at_unix_ms,
                    authenticated_identity: None,
                    payload,
                }),
            )]),
        )
        .expect("v1 refresh");

    let node = current.node("worker-a").expect("normalized worker");
    assert_eq!(node.observed_schema_version, Some(1));
    assert_eq!(
        node.normalized_schema_version,
        Some(NODE_MODEL_SNAPSHOT_SCHEMA_VERSION)
    );
    assert_eq!(
        node.reported_health.as_ref().unwrap().model_plane,
        ModelPlaneHealth::Unavailable
    );
    assert_eq!(node.health, ModelDirectoryHealth::Degraded);
    assert!(node.model_eligible);
    assert!(!current.eligible_replicas.contains_key("coder"));
    assert_eq!(
        current.candidate_replicas["coder"][0].model_plane_health,
        ModelPlaneHealth::Unavailable
    );
}

#[test]
fn directory_fences_old_replica_generations_and_deployment_digest_drift() {
    let directory = ModelDirectory::new();
    let mut worker_a = snapshot_for("worker-a", 10);
    worker_a.replicas[0].deployment_generation = 20;
    let mut worker_b = snapshot_for("worker-b", 10);
    worker_b.replicas[0].deployment_generation = 19;
    let mut unrelated = worker_b.replicas[0].clone();
    unrelated.deployment = "embed".to_string();
    unrelated.deployment_generation = 3;
    unrelated.model = "embedding-model".to_string();
    worker_b.replicas.push(unrelated);
    let now = worker_a.published_at_unix_ms + 100;
    let view = directory
        .refresh(
            now,
            vec![
                member("worker-a", DirectoryMemberState::Alive),
                member("worker-b", DirectoryMemberState::Alive),
            ],
            BTreeMap::from([
                ("worker-a".to_string(), observed(&worker_a)),
                ("worker-b".to_string(), observed(&worker_b)),
            ]),
        )
        .expect("generation view");
    assert_eq!(view.eligible_replicas["coder"].len(), 1);
    assert_eq!(view.eligible_replicas["coder"][0].node_id, "worker-a");
    assert_eq!(view.eligible_replicas["embed"].len(), 1);
    let worker_b_view = view.node("worker-b").unwrap();
    assert!(worker_b_view.model_eligible);
    assert_eq!(worker_b_view.exclusion_reason, None);
    assert_eq!(worker_b_view.health, ModelDirectoryHealth::Degraded);
    assert!(worker_b_view
        .unhealthy_reasons
        .iter()
        .any(|reason| reason == "behind_active_generation"));

    worker_b.generation = 11;
    worker_b.active_deployment_digest = Some("d".repeat(64));
    let drift = directory
        .refresh(
            now + 1,
            vec![
                member("worker-a", DirectoryMemberState::Alive),
                member("worker-b", DirectoryMemberState::Alive),
            ],
            BTreeMap::from([
                ("worker-a".to_string(), observed(&worker_a)),
                ("worker-b".to_string(), observed(&worker_b)),
            ]),
        )
        .expect("digest drift view");
    assert!(drift.summary.deployment_digest_mismatch);
    assert!(drift.eligible_replicas.is_empty());
    assert!(drift.nodes.iter().all(|node| node.exclusion_reason
        == Some(ModelDirectoryExclusionReason::DeploymentDigestMismatch)));

    let recovered = directory
        .refresh(
            now + 2,
            vec![
                member("worker-a", DirectoryMemberState::Alive),
                member("worker-b", DirectoryMemberState::Alive),
            ],
            BTreeMap::from([
                ("worker-a".to_string(), observed(&worker_a)),
                ("worker-b".to_string(), DirectorySnapshotRead::Missing),
            ]),
        )
        .expect("digest recovery view");
    assert!(!recovered.summary.deployment_digest_mismatch);
    assert!(recovered.node("worker-a").unwrap().model_eligible);
    assert_eq!(
        recovered.node("worker-b").unwrap().exclusion_reason,
        Some(ModelDirectoryExclusionReason::SnapshotMissing)
    );
}

#[test]
fn directory_never_regresses_when_the_newest_replica_becomes_unreachable() {
    let directory = ModelDirectory::new();
    let mut newest = snapshot_for("worker-a", 10);
    newest.replicas[0].deployment_generation = 20;
    let mut older = snapshot_for("worker-b", 10);
    older.replicas[0].deployment_generation = 19;
    let now = newest.published_at_unix_ms + 100;

    directory
        .refresh(
            now,
            vec![
                member("worker-a", DirectoryMemberState::Alive),
                member("worker-b", DirectoryMemberState::Alive),
            ],
            BTreeMap::from([
                ("worker-a".to_string(), observed(&newest)),
                ("worker-b".to_string(), observed(&older)),
            ]),
        )
        .expect("observe generation 20");

    let after_failure = directory
        .refresh(
            now + 1,
            vec![
                member("worker-a", DirectoryMemberState::Unreachable),
                member("worker-b", DirectoryMemberState::Alive),
            ],
            BTreeMap::from([
                ("worker-a".to_string(), DirectorySnapshotRead::Unreachable),
                ("worker-b".to_string(), observed(&older)),
            ]),
        )
        .expect("retain generation fence");

    assert!(
        after_failure
            .eligible_replicas
            .get("coder")
            .is_none_or(Vec::is_empty),
        "generation 19 must not become routable again after generation 20 disappears"
    );
    let older = after_failure.node("worker-b").expect("older worker");
    assert_eq!(older.health, ModelDirectoryHealth::Degraded);
    assert!(older
        .unhealthy_reasons
        .iter()
        .any(|reason| reason == "behind_active_generation"));
}

#[test]
fn directory_retains_a_dead_tombstone_after_routing_membership_gc() {
    let directory = ModelDirectory::new();
    let snapshot = snapshot_for("worker-a", 12);
    let first = directory
        .refresh(
            snapshot.published_at_unix_ms + 100,
            vec![member("worker-a", DirectoryMemberState::Alive)],
            BTreeMap::from([("worker-a".to_string(), observed(&snapshot))]),
        )
        .expect("initial roster");
    assert_eq!(first.summary.total_nodes, 1);

    let after_mesh_gc = directory
        .refresh(
            snapshot.published_at_unix_ms + 6 * 60 * 1_000,
            Vec::new(),
            BTreeMap::new(),
        )
        .expect("roster after routing GC");
    let tombstone = after_mesh_gc
        .node("worker-a")
        .expect("known worker remains in operator roster");

    assert_eq!(after_mesh_gc.summary.total_nodes, 1);
    assert_eq!(tombstone.membership_state, DirectoryMemberState::Dead);
    assert_eq!(tombstone.health, ModelDirectoryHealth::Unhealthy);
    assert!(!tombstone.model_eligible);
    assert!(tombstone
        .unhealthy_reasons
        .iter()
        .any(|reason| reason == "membership_dead"));
}
