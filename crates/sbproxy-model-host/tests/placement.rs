use std::collections::{BTreeMap, BTreeSet};

use sbproxy_model_host::node_snapshot::{
    NodeArtifactSnapshot, NodeArtifactState, NodeComputeCapability, NodeDeviceSnapshot,
    NodeEngineSnapshot, NodeHealthState, NodeRole,
};
use sbproxy_model_host::placement::{
    plan_placement, PlacementNode, PlacementRejectionReason, PlacementRequest,
};
use sbproxy_model_host::{
    AcceleratorKind, ArtifactFormat, Catalog, EngineAvailability, EngineChoice, EngineKind,
    GpuVendor, ModelDeployment, PullPolicy, RolloutPolicy,
};

fn catalog() -> Catalog {
    Catalog::from_yaml(
        r#"
schema_version: 2
catalog_revision: placement-fixture-v1
models:
  coder:
    params: 7B
    license: apache-2.0
    family: qwen
    context_length: 32768
    variants:
      - id: cuda-fp8
        format: safetensors
        quant: FP8
        engines: [vllm]
        source: hf:Org/Coder
        revision: cccccccccccccccccccccccccccccccccccccccc
        files:
          - path: model.safetensors
            sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            size_bytes: 8000000000
        requirements:
          accelerators: [cuda]
          min_compute_capability: {major: 8, minor: 9}
          min_memory_bytes: 10000000000
        stability: stable
        certification: fixture-cuda
      - id: cpu-q4
        format: gguf
        quant: Q4_K_M
        engines: [llama_cpp]
        source: hf:Org/Coder-GGUF
        revision: dddddddddddddddddddddddddddddddddddddddd
        files:
          - path: model.gguf
            sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            size_bytes: 4000000000
        requirements:
          accelerators: [cpu, metal]
          min_memory_bytes: 6000000000
        stability: stable
        certification: fixture-cpu
"#,
    )
    .expect("placement catalog")
}

fn deployment(replicas: u32) -> ModelDeployment {
    ModelDeployment {
        model: "coder".to_string(),
        variant: None,
        heterogeneous_variants: replicas > 1,
        replicas,
        required_labels: BTreeMap::new(),
        spread_by: Vec::new(),
        pull: PullPolicy::OnDemand,
        warm: false,
        keep_alive_secs: None,
        max_concurrency: Some(8),
        max_queue_depth: 128,
        queue_timeout_ms: 30_000,
        engine: EngineChoice::Auto,
        rollout: RolloutPolicy::Rolling,
    }
}

fn cuda_node(node_id: &str, zone: &str, memory: u64) -> PlacementNode {
    PlacementNode {
        node_id: node_id.to_string(),
        roles: BTreeSet::from([NodeRole::Worker]),
        health: NodeHealthState::Ready,
        labels: BTreeMap::from([
            ("zone".to_string(), zone.to_string()),
            ("pool".to_string(), "gpu".to_string()),
        ]),
        model_endpoint: Some(format!("https://{node_id}.internal:9443")),
        placement_weight: u32::try_from(memory / (1024 * 1024)).unwrap_or(u32::MAX),
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
        devices: vec![NodeDeviceSnapshot {
            index: 0,
            vendor: GpuVendor::Nvidia,
            accelerator: Some(AcceleratorKind::Cuda),
            name: "NVIDIA L4".to_string(),
            total_memory_bytes: memory,
            available_memory_bytes: memory,
            compute_capability: Some(NodeComputeCapability { major: 8, minor: 9 }),
            supports_fp8: true,
        }],
        artifacts: Vec::new(),
    }
}

fn cpu_node(node_id: &str, zone: &str, memory: u64) -> PlacementNode {
    PlacementNode {
        node_id: node_id.to_string(),
        roles: BTreeSet::from([NodeRole::Worker]),
        health: NodeHealthState::Ready,
        labels: BTreeMap::from([
            ("zone".to_string(), zone.to_string()),
            ("pool".to_string(), "cpu".to_string()),
        ]),
        model_endpoint: Some(format!("https://{node_id}.internal:9443")),
        placement_weight: u32::try_from(memory / (1024 * 1024)).unwrap_or(u32::MAX),
        engines: vec![NodeEngineSnapshot {
            engine: EngineKind::LlamaCpp,
            availability: EngineAvailability::Available,
            version: Some("b9905".to_string()),
            artifact_formats: vec![ArtifactFormat::Gguf],
            accelerators: BTreeSet::from([AcceleratorKind::Cpu]),
            supports_container: false,
            supports_uv: false,
            reason_code: None,
        }],
        devices: vec![NodeDeviceSnapshot {
            index: 0,
            vendor: GpuVendor::Cpu,
            accelerator: Some(AcceleratorKind::Cpu),
            name: "host RAM".to_string(),
            total_memory_bytes: memory,
            available_memory_bytes: memory,
            compute_capability: None,
            supports_fp8: false,
        }],
        artifacts: Vec::new(),
    }
}

fn request(deployment: ModelDeployment, nodes: Vec<PlacementNode>) -> PlacementRequest {
    PlacementRequest {
        deployment_id: "coder".to_string(),
        deployment_generation: 7,
        deployment,
        nodes,
    }
}

#[test]
fn planner_filters_labels_engine_accelerator_memory_and_endpoint() {
    let mut desired = deployment(1);
    desired.variant = Some("cuda-fp8".to_string());
    desired.heterogeneous_variants = false;
    desired
        .required_labels
        .insert("pool".to_string(), "gpu".to_string());
    let mut wrong_label = cuda_node("wrong-label", "b", 24_000_000_000);
    wrong_label
        .labels
        .insert("pool".to_string(), "other".to_string());
    let mut no_endpoint = cuda_node("no-endpoint", "c", 24_000_000_000);
    no_endpoint.model_endpoint = None;
    let mut no_engine = cuda_node("no-engine", "d", 24_000_000_000);
    no_engine.engines[0].availability = EngineAvailability::Blocked;
    no_engine.engines[0].reason_code = Some("engine_blocked".to_string());
    let mut not_worker = cuda_node("not-worker", "g", 24_000_000_000);
    not_worker.roles = BTreeSet::from([NodeRole::Gateway]);
    let mut wrong_accelerator = cpu_node("wrong-accelerator", "f", 64_000_000_000);
    wrong_accelerator
        .labels
        .insert("pool".to_string(), "gpu".to_string());
    let plan = plan_placement(
        &catalog(),
        request(
            desired,
            vec![
                cuda_node("eligible", "a", 24_000_000_000),
                wrong_label,
                no_endpoint,
                no_engine,
                not_worker,
                cuda_node("too-small", "e", 9_000_000_000),
                wrong_accelerator,
            ],
        ),
    )
    .expect("placement plan");

    assert_eq!(plan.assignments.len(), 1);
    assert_eq!(plan.assignments[0].node_id, "eligible");
    assert_eq!(
        plan.rejections["wrong-label"],
        PlacementRejectionReason::RequiredLabels
    );
    assert_eq!(
        plan.rejections["no-endpoint"],
        PlacementRejectionReason::MissingEndpoint
    );
    assert_eq!(
        plan.rejections["no-engine"],
        PlacementRejectionReason::EngineUnavailable
    );
    assert_eq!(
        plan.rejections["not-worker"],
        PlacementRejectionReason::NotWorker
    );
    assert_eq!(
        plan.rejections["too-small"],
        PlacementRejectionReason::InsufficientMemory
    );
    assert_eq!(
        plan.rejections["wrong-accelerator"],
        PlacementRejectionReason::AcceleratorIncompatible
    );
}

#[test]
fn one_node_plan_and_input_order_are_deterministic() {
    let one = plan_placement(
        &catalog(),
        request(deployment(1), vec![cuda_node("only", "a", 24_000_000_000)]),
    )
    .expect("one node");
    assert_eq!(one.assignments.len(), 1);
    assert_eq!(one.assignments[0].node_id, "only");

    let nodes = vec![
        cuda_node("a", "a", 24_000_000_000),
        cpu_node("b", "b", 64_000_000_000),
        cuda_node("c", "c", 24_000_000_000),
    ];
    let mut reverse = nodes.clone();
    reverse.reverse();
    let first = plan_placement(&catalog(), request(deployment(2), nodes)).expect("first");
    let second = plan_placement(&catalog(), request(deployment(2), reverse)).expect("second");
    assert_eq!(first, second);
}

#[test]
fn rendezvous_addition_moves_only_an_assignment_displaced_by_the_new_node() {
    let original = vec![
        cuda_node("a", "same", 24_000_000_000),
        cuda_node("b", "same", 24_000_000_000),
        cuda_node("c", "same", 24_000_000_000),
    ];
    let before = plan_placement(&catalog(), request(deployment(2), original.clone())).unwrap();
    let mut expanded = original;
    expanded.push(cuda_node("new", "same", 24_000_000_000));
    let after = plan_placement(&catalog(), request(deployment(2), expanded)).unwrap();
    let before_nodes = before
        .assignments
        .iter()
        .map(|assignment| assignment.node_id.as_str())
        .collect::<BTreeSet<_>>();
    let after_nodes = after
        .assignments
        .iter()
        .map(|assignment| assignment.node_id.as_str())
        .collect::<BTreeSet<_>>();
    assert!(before_nodes.difference(&after_nodes).count() <= 1);
    assert!(after_nodes
        .difference(&before_nodes)
        .all(|node| *node == "new"));
}

#[test]
fn rendezvous_capacity_weight_changes_rank_without_score_saturation() {
    let mut light = cuda_node("a-light", "same", 24_000_000_000);
    light.placement_weight = 2;
    let mut heavy = cuda_node("z-heavy", "same", 24_000_000_000);
    heavy.placement_weight = 1_000_000;
    let plan = plan_placement(&catalog(), request(deployment(1), vec![light, heavy])).unwrap();

    assert_eq!(plan.assignments[0].node_id, "z-heavy");
}

#[test]
fn spread_prefers_new_failure_domains_before_reusing_one() {
    let mut desired = deployment(3);
    desired.variant = Some("cuda-fp8".to_string());
    desired.heterogeneous_variants = false;
    desired.spread_by = vec!["zone".to_string()];
    let plan = plan_placement(
        &catalog(),
        request(
            desired,
            vec![
                cuda_node("a1", "a", 24_000_000_000),
                cuda_node("a2", "a", 24_000_000_000),
                cuda_node("b1", "b", 24_000_000_000),
                cuda_node("c1", "c", 24_000_000_000),
            ],
        ),
    )
    .unwrap();
    let zones = plan
        .assignments
        .iter()
        .map(|assignment| assignment.failure_domains["zone"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(zones, BTreeSet::from(["a", "b", "c"]));
}

#[test]
fn pinned_and_heterogeneous_variant_policies_are_explicit() {
    let mut pinned = deployment(2);
    pinned.variant = Some("cuda-fp8".to_string());
    pinned.heterogeneous_variants = false;
    let pinned = plan_placement(
        &catalog(),
        request(
            pinned,
            vec![
                cuda_node("cuda-a", "a", 24_000_000_000),
                cuda_node("cuda-b", "b", 24_000_000_000),
            ],
        ),
    )
    .unwrap();
    assert!(pinned
        .assignments
        .iter()
        .all(|assignment| assignment.variant_id == "cuda-fp8"));

    let heterogeneous = plan_placement(
        &catalog(),
        request(
            deployment(2),
            vec![
                cuda_node("cuda", "a", 24_000_000_000),
                cpu_node("cpu", "b", 64_000_000_000),
            ],
        ),
    )
    .unwrap();
    assert_eq!(heterogeneous.assignments.len(), 2);
    assert_eq!(
        heterogeneous
            .assignments
            .iter()
            .map(|assignment| assignment.variant_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["cpu-q4", "cuda-fp8"])
    );
}

#[test]
fn manual_pull_requires_a_ready_local_artifact_and_partitions_stay_local() {
    let mut desired = deployment(1);
    desired.variant = Some("cuda-fp8".to_string());
    desired.heterogeneous_variants = false;
    desired.pull = PullPolicy::Manual;
    let uncached = cuda_node("uncached", "a", 24_000_000_000);
    let uncached_plan =
        plan_placement(&catalog(), request(desired.clone(), vec![uncached])).unwrap();
    assert!(uncached_plan.assignments.is_empty());
    assert_eq!(
        uncached_plan.rejections["uncached"],
        PlacementRejectionReason::ArtifactNotReady
    );

    let mut cached = cuda_node("left", "a", 24_000_000_000);
    let digest = plan_placement(
        &catalog(),
        request(
            {
                let mut on_demand = desired.clone();
                on_demand.pull = PullPolicy::OnDemand;
                on_demand
            },
            vec![cached.clone()],
        ),
    )
    .unwrap()
    .assignments[0]
        .artifact_digest
        .clone();
    cached.artifacts.push(NodeArtifactSnapshot {
        artifact_digest: digest,
        model: "coder".to_string(),
        variant: "cuda-fp8".to_string(),
        state: NodeArtifactState::Ready,
        completed_bytes: 8_000_000_000,
        total_bytes: Some(8_000_000_000),
        last_accessed_unix_ms: Some(1),
        reason_code: None,
    });
    let left = plan_placement(&catalog(), request(desired.clone(), vec![cached])).unwrap();
    let right = plan_placement(
        &catalog(),
        request(desired, vec![cuda_node("right", "b", 24_000_000_000)]),
    )
    .unwrap();
    assert_eq!(left.assignments[0].node_id, "left");
    assert!(right.assignments.is_empty());
    assert!(left
        .assignments
        .iter()
        .all(|assignment| assignment.node_id != "right"));
}

#[test]
fn partitioned_directories_never_assign_an_unreachable_peer() {
    let left = plan_placement(
        &catalog(),
        request(deployment(1), vec![cuda_node("left", "a", 24_000_000_000)]),
    )
    .unwrap();
    let right = plan_placement(
        &catalog(),
        request(deployment(1), vec![cuda_node("right", "b", 24_000_000_000)]),
    )
    .unwrap();

    assert_eq!(left.assignments[0].node_id, "left");
    assert_eq!(right.assignments[0].node_id, "right");
}
