use std::collections::{BTreeMap, BTreeSet};

use sbproxy_model_host::node_snapshot::{
    NodeArtifactSnapshot, NodeArtifactState, NodeComputeCapability, NodeDeviceSnapshot,
    NodeEngineSnapshot, NodeHealthState, NodeRole,
};
use sbproxy_model_host::placement::{
    plan_placement, PlacementAssignment, PlacementNode, PlacementPlan, PlacementRejectionReason,
    PlacementRequest,
};
use sbproxy_model_host::rollout::{
    filter_desired_state_for_assignments, plan_rollout, AssignedModelDeployment, RolloutPhase,
    RolloutReplicaObservation, RolloutRequest,
};
use sbproxy_model_host::{
    compile_desired_state, reconcile_cluster_placement, AcceleratorKind, ArtifactFormat, Catalog,
    DeploymentGenerationFences, DeploymentRuntimeState, EngineAvailability, EngineChoice,
    EngineKind, FileDeploymentGenerationStore, GpuVendor, ManagedProviderInput, ModelDeployment,
    PullPolicy, RolloutPolicy, RuntimeDesiredInput,
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

fn rollout_assignment(node_id: &str, variant_id: &str) -> PlacementAssignment {
    PlacementAssignment {
        node_id: node_id.to_string(),
        model_endpoint: format!("https://{node_id}.internal:9443"),
        variant_id: variant_id.to_string(),
        artifact_digest: if variant_id == "cuda-fp8" {
            "a".repeat(64)
        } else {
            "b".repeat(64)
        },
        engine: if variant_id == "cuda-fp8" {
            EngineKind::Vllm
        } else {
            EngineKind::LlamaCpp
        },
        accelerator: if variant_id == "cuda-fp8" {
            AcceleratorKind::Cuda
        } else {
            AcceleratorKind::Cpu
        },
        device_index: 0,
        required_memory_bytes: 1,
        available_memory_bytes: 2,
        artifact_cached: true,
        failure_domains: BTreeMap::new(),
    }
}

fn rollout_plan(generation: u64, nodes: &[&str]) -> PlacementPlan {
    PlacementPlan {
        deployment_id: "coder".to_string(),
        deployment_generation: generation,
        desired_replicas: u32::try_from(nodes.len()).unwrap(),
        assignments: nodes
            .iter()
            .map(|node| rollout_assignment(node, "cuda-fp8"))
            .collect(),
        unplaced_replicas: 0,
        rejections: BTreeMap::new(),
    }
}

fn ready(node_id: &str, generation: u64) -> RolloutReplicaObservation {
    RolloutReplicaObservation {
        node_id: node_id.to_string(),
        deployment_generation: generation,
        variant_id: Some("cuda-fp8".to_string()),
        artifact_digest: Some("a".repeat(64)),
        state: DeploymentRuntimeState::Ready,
    }
}

#[test]
fn rollout_rolling_starts_replacements_before_readiness_and_then_drains_losers() {
    let target = rollout_plan(2, &["b", "c"]);
    let previous = rollout_plan(1, &["a", "b"]);
    let waiting = plan_rollout(RolloutRequest {
        policy: RolloutPolicy::Rolling,
        target: target.clone(),
        previous: Some(previous.clone()),
        observations: vec![ready("b", 2)],
        prior_drain_issued: false,
        now_unix_ms: 1_000,
        handoff_deadline_unix_ms: 2_000,
    })
    .unwrap();
    assert_eq!(waiting.phase, RolloutPhase::WaitingForReadiness);
    assert_eq!(
        waiting
            .start
            .iter()
            .map(|assignment| assignment.assignment.node_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["b", "c"])
    );
    assert_eq!(waiting.retain[0].assignment.node_id, "a");
    assert!(waiting.drain.is_empty());

    let ready = plan_rollout(RolloutRequest {
        policy: RolloutPolicy::Rolling,
        target,
        previous: Some(previous),
        observations: vec![ready("b", 2), ready("c", 2)],
        prior_drain_issued: false,
        now_unix_ms: 1_500,
        handoff_deadline_unix_ms: 2_000,
    })
    .unwrap();
    assert_eq!(ready.phase, RolloutPhase::Stable);
    assert!(ready.retain.is_empty());
    assert_eq!(ready.drain[0].assignment.node_id, "a");
}

#[test]
fn rollout_rolling_deadline_bounds_unready_retention() {
    let decision = plan_rollout(RolloutRequest {
        policy: RolloutPolicy::Rolling,
        target: rollout_plan(2, &["b"]),
        previous: Some(rollout_plan(1, &["a"])),
        observations: Vec::new(),
        prior_drain_issued: false,
        now_unix_ms: 2_000,
        handoff_deadline_unix_ms: 2_000,
    })
    .unwrap();

    assert_eq!(decision.phase, RolloutPhase::TimedOut);
    assert!(decision.timed_out);
    assert!(decision.retain.is_empty());
    assert_eq!(decision.drain[0].assignment.node_id, "a");
}

#[test]
fn rollout_recreate_drains_the_prior_generation_before_starting_target() {
    let target = rollout_plan(2, &["b"]);
    let previous = rollout_plan(1, &["a"]);
    let draining = plan_rollout(RolloutRequest {
        policy: RolloutPolicy::Recreate,
        target: target.clone(),
        previous: Some(previous.clone()),
        observations: vec![ready("a", 1)],
        prior_drain_issued: false,
        now_unix_ms: 1_000,
        handoff_deadline_unix_ms: 2_000,
    })
    .unwrap();
    assert_eq!(draining.phase, RolloutPhase::DrainingPrior);
    assert!(draining.start.is_empty());
    assert_eq!(draining.drain[0].assignment.node_id, "a");

    let starting = plan_rollout(RolloutRequest {
        policy: RolloutPolicy::Recreate,
        target,
        previous: Some(previous),
        observations: Vec::new(),
        prior_drain_issued: true,
        now_unix_ms: 1_500,
        handoff_deadline_unix_ms: 2_000,
    })
    .unwrap();
    assert_eq!(starting.phase, RolloutPhase::Starting);
    assert_eq!(starting.start[0].assignment.node_id, "b");
}

#[test]
fn rollout_assignment_filter_pins_one_warm_local_replica_and_drops_remote_routes() {
    let host = serde_yaml::from_str(
        r#"
deployments:
  coder:
    model: coder
    heterogeneous_variants: true
    replicas: 2
  spare:
    model: coder
    variant: cpu-q4
"#,
    )
    .unwrap();
    let global = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "cluster-revision-1".to_string(),
            canonical: Some(host),
            managed_providers: vec![
                ManagedProviderInput {
                    origin: "api".to_string(),
                    provider: "local".to_string(),
                    deployment: "coder".to_string(),
                    models: vec!["coder".to_string()],
                },
                ManagedProviderInput {
                    origin: "api".to_string(),
                    provider: "spare".to_string(),
                    deployment: "spare".to_string(),
                    models: vec!["spare".to_string()],
                },
            ],
            legacy_providers: Vec::new(),
        },
        &catalog(),
    )
    .unwrap();
    let assignments = BTreeMap::from([(
        "coder".to_string(),
        AssignedModelDeployment {
            deployment_generation: 9,
            assignment: rollout_assignment("worker-a", "cuda-fp8"),
            deployment: global.deployments["coder"].clone(),
        },
    )]);

    let local = filter_desired_state_for_assignments(&global, &assignments).unwrap();

    assert_eq!(local.deployments.keys().collect::<Vec<_>>(), ["coder"]);
    assert_eq!(
        local.revision.deployments.keys().collect::<Vec<_>>(),
        ["coder"]
    );
    assert_eq!(local.routes.len(), 1);
    assert_eq!(local.routes[0].deployment, "coder");
    let coder = &local.deployments["coder"].desired;
    assert_eq!(coder.variant.as_deref(), Some("cuda-fp8"));
    assert!(!coder.heterogeneous_variants);
    assert_eq!(coder.replicas, 1);
    assert!(coder.warm);
    assert_eq!(coder.engine, EngineChoice::Vllm);
}

#[test]
fn rollout_cluster_state_retains_a_loser_then_removes_it_after_replacement_readiness() {
    let host = serde_yaml::from_str(
        r#"
handoff_timeout_ms: 1000
deployments:
  coder:
    model: coder
    variant: cuda-fp8
    replicas: 1
"#,
    )
    .unwrap();
    let global = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "cluster-state-1".to_string(),
            canonical: Some(host),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog(),
    )
    .unwrap();
    let initial = reconcile_cluster_placement(
        &catalog(),
        None,
        global.clone(),
        vec![
            cuda_node("worker-a", "a", 24_000_000_000),
            cuda_node("worker-b", "b", 24_000_000_000),
        ],
        &BTreeMap::new(),
        &DeploymentGenerationFences::default(),
        1_000,
    )
    .unwrap();
    let initial_placement = &initial.deployments()["coder"];
    let old = initial_placement.target.assignments[0].clone();
    let replacement_node = if old.node_id == "worker-a" {
        "worker-b"
    } else {
        "worker-a"
    };
    let old_ready = RolloutReplicaObservation {
        node_id: old.node_id.clone(),
        deployment_generation: initial_placement.target.deployment_generation,
        variant_id: Some(old.variant_id.clone()),
        artifact_digest: Some(old.artifact_digest.clone()),
        state: DeploymentRuntimeState::Ready,
    };
    let moving = reconcile_cluster_placement(
        &catalog(),
        Some(&initial),
        global,
        vec![cuda_node(replacement_node, "b", 24_000_000_000)],
        &BTreeMap::from([("coder".to_string(), vec![old_ready.clone()])]),
        &DeploymentGenerationFences::default(),
        1_100,
    )
    .unwrap();
    let moving_placement = &moving.deployments()["coder"];
    assert_eq!(
        moving_placement.target.deployment_generation,
        initial_placement.target.deployment_generation
    );
    assert_eq!(
        moving_placement.rollout.phase,
        RolloutPhase::WaitingForReadiness
    );
    assert!(moving
        .local_desired(&old.node_id)
        .unwrap()
        .deployments
        .contains_key("coder"));
    assert!(moving
        .local_desired(replacement_node)
        .unwrap()
        .deployments
        .contains_key("coder"));

    let replacement = moving_placement.target.assignments[0].clone();
    let replacement_ready = RolloutReplicaObservation {
        node_id: replacement.node_id.clone(),
        deployment_generation: moving_placement.target.deployment_generation,
        variant_id: Some(replacement.variant_id.clone()),
        artifact_digest: Some(replacement.artifact_digest.clone()),
        state: DeploymentRuntimeState::Ready,
    };
    let draining = reconcile_cluster_placement(
        &catalog(),
        Some(&moving),
        moving.global().clone(),
        vec![cuda_node(replacement_node, "b", 24_000_000_000)],
        &BTreeMap::from([("coder".to_string(), vec![old_ready, replacement_ready])]),
        &DeploymentGenerationFences::default(),
        1_200,
    )
    .unwrap();
    assert_eq!(
        draining.deployments()["coder"].rollout.phase,
        RolloutPhase::Stable
    );
    assert!(!draining
        .local_desired(&old.node_id)
        .unwrap()
        .deployments
        .contains_key("coder"));
    assert!(draining
        .local_desired(replacement_node)
        .unwrap()
        .deployments
        .contains_key("coder"));
}

#[test]
fn restarted_controller_reuses_the_generation_of_the_same_observed_desired_state() {
    let host = serde_yaml::from_str(
        r#"
deployments:
  coder:
    model: coder
    variant: cuda-fp8
    replicas: 1
"#,
    )
    .unwrap();
    let global = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "controller-restart".to_string(),
            canonical: Some(host),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog(),
    )
    .unwrap();
    let observed = RolloutReplicaObservation {
        node_id: "worker-a".to_string(),
        deployment_generation: 9,
        variant_id: Some("cuda-fp8".to_string()),
        artifact_digest: Some("a".repeat(64)),
        state: DeploymentRuntimeState::Ready,
    };

    let desired_digest = global.revision_digest().expect("desired digest");
    let restarted = reconcile_cluster_placement(
        &catalog(),
        None,
        global,
        vec![cuda_node("worker-a", "a", 24_000_000_000)],
        &BTreeMap::from([("coder".to_string(), vec![observed])]),
        &DeploymentGenerationFences::observed(BTreeMap::from([(
            "coder".to_string(),
            sbproxy_model_host::DeploymentGenerationFence {
                deployment_generation: 9,
                desired_revision_digest: Some(desired_digest.clone()),
            },
        )])),
        10_000,
    )
    .unwrap();

    assert_eq!(
        restarted.deployments()["coder"]
            .target
            .deployment_generation,
        9,
        "a restarted controller must converge with live controllers on the same desired state"
    );

    let changed_host = serde_yaml::from_str(
        r#"
deployments:
  coder:
    model: coder
    variant: cuda-fp8
    replicas: 1
    max_concurrency: 16
"#,
    )
    .unwrap();
    let changed = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "controller-restart".to_string(),
            canonical: Some(changed_host),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog(),
    )
    .unwrap();
    let changed_digest = changed.revision_digest().expect("changed desired digest");
    let advanced = reconcile_cluster_placement(
        &catalog(),
        None,
        changed.clone(),
        vec![cuda_node("worker-a", "a", 24_000_000_000)],
        &BTreeMap::new(),
        &DeploymentGenerationFences::observed(BTreeMap::from([(
            "coder".to_string(),
            sbproxy_model_host::DeploymentGenerationFence {
                deployment_generation: 9,
                desired_revision_digest: Some(desired_digest),
            },
        )])),
        10_100,
    )
    .unwrap();
    assert_eq!(
        advanced.deployments()["coder"].target.deployment_generation,
        10
    );

    let converged = reconcile_cluster_placement(
        &catalog(),
        None,
        changed,
        vec![cuda_node("worker-a", "a", 24_000_000_000)],
        &BTreeMap::new(),
        &DeploymentGenerationFences::observed(BTreeMap::from([(
            "coder".to_string(),
            sbproxy_model_host::DeploymentGenerationFence {
                deployment_generation: 10,
                desired_revision_digest: Some(changed_digest),
            },
        )])),
        10_200,
    )
    .unwrap();
    assert_eq!(
        converged.deployments()["coder"]
            .target
            .deployment_generation,
        10,
        "controllers joining an in-progress desired revision must not increment it again"
    );
}

#[test]
fn global_revision_changes_advance_every_deployment_generation() {
    let initial_host = serde_yaml::from_str(
        r#"
deployments:
  coder:
    model: coder
    variant: cuda-fp8
  spare:
    model: coder
    variant: cuda-fp8
"#,
    )
    .unwrap();
    let initial_global = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "global-1".to_string(),
            canonical: Some(initial_host),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog(),
    )
    .unwrap();
    let initial = reconcile_cluster_placement(
        &catalog(),
        None,
        initial_global,
        vec![cuda_node("worker-a", "a", 24_000_000_000)],
        &BTreeMap::new(),
        &DeploymentGenerationFences::default(),
        1_000,
    )
    .unwrap();

    let changed_host = serde_yaml::from_str(
        r#"
deployments:
  coder:
    model: coder
    variant: cuda-fp8
  spare:
    model: coder
    variant: cuda-fp8
    max_concurrency: 16
"#,
    )
    .unwrap();
    let changed_global = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "global-2".to_string(),
            canonical: Some(changed_host),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog(),
    )
    .unwrap();
    let changed = reconcile_cluster_placement(
        &catalog(),
        Some(&initial),
        changed_global,
        vec![cuda_node("worker-a", "a", 24_000_000_000)],
        &BTreeMap::new(),
        &DeploymentGenerationFences::default(),
        1_100,
    )
    .unwrap();

    assert_eq!(
        changed.deployments()["coder"].target.deployment_generation,
        2
    );
    assert_eq!(
        changed.deployments()["spare"].target.deployment_generation,
        2
    );
}

#[test]
fn durable_generation_store_survives_restart_without_replica_observations() {
    let host = serde_yaml::from_str(
        r#"
deployments:
  coder:
    model: coder
    variant: cuda-fp8
"#,
    )
    .unwrap();
    let global = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "durable-unplaced".to_string(),
            canonical: Some(host),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog(),
    )
    .unwrap();
    let initial = reconcile_cluster_placement(
        &catalog(),
        None,
        global.clone(),
        Vec::new(),
        &BTreeMap::new(),
        &DeploymentGenerationFences::default(),
        1_000,
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = FileDeploymentGenerationStore::open(temp.path()).unwrap();
    store.persist(&initial).unwrap();

    let restarted = reconcile_cluster_placement(
        &catalog(),
        None,
        global,
        Vec::new(),
        &BTreeMap::new(),
        &DeploymentGenerationFences::local(store.load().unwrap()),
        2_000,
    )
    .unwrap();
    assert_eq!(
        restarted.deployments()["coder"]
            .target
            .deployment_generation,
        1
    );
}

#[test]
fn failed_generation_reservation_allows_last_good_config_to_return() {
    let host_a = serde_yaml::from_str(
        r#"
deployments:
  coder:
    model: coder
    variant: cuda-fp8
    max_concurrency: 4
"#,
    )
    .unwrap();
    let global_a = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "rollback-a".to_string(),
            canonical: Some(host_a),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog(),
    )
    .unwrap();
    let active = reconcile_cluster_placement(
        &catalog(),
        None,
        global_a.clone(),
        Vec::new(),
        &BTreeMap::new(),
        &DeploymentGenerationFences::default(),
        1_000,
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = FileDeploymentGenerationStore::open(temp.path()).unwrap();
    store.persist(&active).unwrap();

    let host_b = serde_yaml::from_str(
        r#"
deployments:
  coder:
    model: coder
    variant: cuda-fp8
    max_concurrency: 8
"#,
    )
    .unwrap();
    let global_b = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "rollback-b".to_string(),
            canonical: Some(host_b),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog(),
    )
    .unwrap();
    let failed_candidate = reconcile_cluster_placement(
        &catalog(),
        Some(&active),
        global_b,
        Vec::new(),
        &BTreeMap::new(),
        &DeploymentGenerationFences::local(store.load().unwrap()),
        1_100,
    )
    .unwrap();
    assert_eq!(
        failed_candidate.deployments()["coder"]
            .target
            .deployment_generation,
        2
    );
    store.persist(&failed_candidate).unwrap();

    let reverted = reconcile_cluster_placement(
        &catalog(),
        Some(&active),
        global_a,
        Vec::new(),
        &BTreeMap::new(),
        &DeploymentGenerationFences::local(store.load().unwrap()),
        1_200,
    )
    .unwrap();
    assert_eq!(
        reverted.deployments()["coder"].target.deployment_generation,
        3,
        "reverting after a failed reserved revision must skip the consumed generation"
    );
    store.persist(&reverted).unwrap();
}

#[test]
fn remote_mismatched_revision_does_not_advance_unchanged_local_state() {
    let host_a = serde_yaml::from_str(
        r#"
deployments:
  coder:
    model: coder
    variant: cuda-fp8
    max_concurrency: 4
"#,
    )
    .unwrap();
    let global_a = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "rolling-a".to_string(),
            canonical: Some(host_a),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog(),
    )
    .unwrap();
    let active = reconcile_cluster_placement(
        &catalog(),
        None,
        global_a.clone(),
        Vec::new(),
        &BTreeMap::new(),
        &DeploymentGenerationFences::default(),
        1_000,
    )
    .unwrap();

    let host_b = serde_yaml::from_str(
        r#"
deployments:
  coder:
    model: coder
    variant: cuda-fp8
    max_concurrency: 8
"#,
    )
    .unwrap();
    let global_b = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "rolling-b".to_string(),
            canonical: Some(host_b),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog(),
    )
    .unwrap();
    let remote_digest = global_b.revision_digest().unwrap();
    let stable = reconcile_cluster_placement(
        &catalog(),
        Some(&active),
        global_a,
        Vec::new(),
        &BTreeMap::new(),
        &DeploymentGenerationFences::observed(BTreeMap::from([(
            "coder".to_string(),
            sbproxy_model_host::DeploymentGenerationFence {
                deployment_generation: 2,
                desired_revision_digest: Some(remote_digest),
            },
        )])),
        1_100,
    )
    .unwrap();

    assert_eq!(
        stable.deployments()["coder"].target.deployment_generation,
        1,
        "a remote rolling-update fence must not consume a local generation"
    );
}
