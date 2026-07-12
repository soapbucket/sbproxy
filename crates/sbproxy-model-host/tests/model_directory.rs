use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use sbproxy_model_host::node_snapshot::{
    NodeArtifactSnapshot, NodeEngineSnapshot, NodeHealthSnapshot, NodeHealthState,
    NodeIdentitySnapshot, NodeModelSnapshot, NodeReplicaSnapshot, NodeRole, NodeSnapshotGeneration,
    RuntimeReplicaIdentity, NODE_MODEL_SNAPSHOT_SCHEMA_VERSION,
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
fn snapshot_schema_v1_round_trips_every_operational_field() {
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
