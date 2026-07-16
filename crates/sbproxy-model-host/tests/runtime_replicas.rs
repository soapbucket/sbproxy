//! WOR-1904: N replicas of one deployment on one node, each on its own
//! device set. These exercise the reconcile path end to end with a fake
//! preparer that honors the node-level device plan, so the assertions are
//! about slot fan-out, disjoint devices, legible over-subscription, and
//! per-replica lifecycle rather than a real engine.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sbproxy_config::{ManagedDeploymentConfig, ModelHostControlConfig};
use sbproxy_model_host::{
    compile_desired_state, AcceleratorKind, Catalog, DeploymentPrepareRequest, DeploymentPreparer,
    EngineDriverError, EngineKind, EngineProcess, FitPlan, MemoryEstimate, ModelRuntimeManager,
    OperationJob, PreparedDeploymentRuntime, PullIntent, Quant, RunningEngine, RuntimeDesiredInput,
    RuntimeDesiredState, RuntimeManagerError,
};

#[derive(Debug, Default)]
struct FakeProcess {
    stopped: AtomicBool,
}

#[async_trait]
impl EngineProcess for FakeProcess {
    fn id(&self) -> Option<u32> {
        Some(1)
    }

    async fn has_exited(&self) -> Result<bool, EngineDriverError> {
        Ok(self.stopped.load(Ordering::SeqCst))
    }

    async fn shutdown(&self, _grace: Duration) -> Result<(), EngineDriverError> {
        self.stopped.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn stderr_tail(&self) -> String {
        String::new()
    }
}

fn zero_memory(devices: Vec<u32>) -> MemoryEstimate {
    MemoryEstimate {
        device_indexes: devices,
        weight_bytes: 0,
        kv_bytes: 0,
        runtime_overhead_bytes: 0,
        safety_margin_bytes: 0,
        total_bytes: 0,
    }
}

fn fit_plan(devices: Vec<u32>) -> FitPlan {
    FitPlan {
        quant_name: "Q4_K_M".to_string(),
        quant: Quant::Int4,
        estimated_vram_bytes: 0,
        gpu_indexes: devices.clone(),
        seq_len: 4096,
        memory: zero_memory(devices),
        moe: None,
        throughput: None,
    }
}

/// One faked replica: it records its start/stop and reports the device set the
/// node-level plan pinned to it.
struct ReplicaRuntime {
    id: String,
    generation: u64,
    devices: Vec<u32>,
    events: Arc<Mutex<Vec<String>>>,
    next_port: Arc<AtomicU16>,
}

#[async_trait]
impl PreparedDeploymentRuntime for ReplicaRuntime {
    async fn memory_estimate(
        &self,
        _intent: PullIntent,
    ) -> Result<MemoryEstimate, RuntimeManagerError> {
        Ok(zero_memory(self.devices.clone()))
    }

    async fn start(&self, _intent: PullIntent) -> Result<RunningEngine, RuntimeManagerError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("start:{}:{}", self.id, self.generation));
        Ok(RunningEngine {
            deployment: self.id.clone(),
            generation: self.generation,
            kind: EngineKind::LlamaCpp,
            port: self.next_port.fetch_add(1, Ordering::SeqCst),
            accelerator: AcceleratorKind::Cuda,
            selected_devices: self.devices.clone(),
            started_at_ms: 1,
            artifact_digest: "a".repeat(64),
            engine_version: None,
            memory: zero_memory(self.devices.clone()),
            process: Arc::new(FakeProcess::default()),
        })
    }

    async fn stop(&self, _grace: Duration) -> Result<(), RuntimeManagerError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("stop:{}:{}", self.id, self.generation));
        Ok(())
    }

    async fn reset(&self) -> Result<Option<OperationJob>, RuntimeManagerError> {
        Ok(None)
    }
}

/// A preparer that packs replicas onto disjoint device sets by count: replica
/// `k` at tensor-parallel degree `t` claims devices `[k*t, (k+1)*t)`, and asks
/// for more than the node has fail legibly.
struct ReplicaPreparer {
    device_count: u32,
    events: Arc<Mutex<Vec<String>>>,
    next_port: Arc<AtomicU16>,
}

impl ReplicaPreparer {
    fn new(device_count: u32) -> Arc<Self> {
        Arc::new(Self {
            device_count,
            events: Arc::new(Mutex::new(Vec::new())),
            next_port: Arc::new(AtomicU16::new(20_000)),
        })
    }
}

#[async_trait]
impl DeploymentPreparer for ReplicaPreparer {
    async fn prepare(
        &self,
        request: DeploymentPrepareRequest,
    ) -> Result<Arc<dyn PreparedDeploymentRuntime>, RuntimeManagerError> {
        let devices = request
            .pinned_fit
            .map(|fit| fit.gpu_indexes)
            .unwrap_or_else(|| vec![0]);
        Ok(Arc::new(ReplicaRuntime {
            id: request.deployment_id,
            generation: request.generation,
            devices,
            events: self.events.clone(),
            next_port: self.next_port.clone(),
        }))
    }

    async fn plan_replica_devices(
        &self,
        request: &DeploymentPrepareRequest,
    ) -> Result<Vec<FitPlan>, RuntimeManagerError> {
        let replicas = request.desired.desired.replicas.max(1);
        let degree = request.desired.desired.tensor_parallel.unwrap_or(1).max(1);
        let needed = replicas * degree;
        if needed > self.device_count {
            return Err(RuntimeManagerError::Prepare(format!(
                "cannot place {replicas} replicas at tensor_parallel {degree}: needs {needed} devices, {} available",
                self.device_count
            )));
        }
        Ok((0..replicas)
            .map(|replica| {
                let base = replica * degree;
                fit_plan((base..base + degree).collect())
            })
            .collect())
    }
}

fn replica_desired(
    source: &str,
    id: &str,
    replicas: u32,
    tensor_parallel: Option<u32>,
) -> RuntimeDesiredState {
    let mut host = ModelHostControlConfig::default();
    host.deployments.insert(
        id.to_string(),
        ManagedDeploymentConfig {
            model: "qwen2.5-0.5b-instruct".to_string(),
            variant: Some("q4_k_m".to_string()),
            replicas,
            tensor_parallel,
            ..serde_yaml::from_str("model: qwen2.5-0.5b-instruct").unwrap()
        },
    );
    compile_desired_state(
        RuntimeDesiredInput {
            source_revision: source.to_string(),
            canonical: Some(host),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &Catalog::builtin(),
    )
    .unwrap()
}

fn manager(preparer: Arc<ReplicaPreparer>, device_count: u32) -> Arc<ModelRuntimeManager> {
    let capacities = (0..device_count).map(|index| (index, 1_u64)).collect();
    Arc::new(
        ModelRuntimeManager::new_with_device_capacities(
            Catalog::builtin().catalog_revision,
            preparer,
            capacities,
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn reconcile_starts_each_replica_on_its_own_device() {
    let preparer = ReplicaPreparer::new(4);
    let manager = manager(preparer.clone(), 4);
    manager
        .reconcile(replica_desired("r1", "coder", 4, Some(1)))
        .await
        .expect("four single-device replicas fit a four-GPU node");

    let mut statuses = manager.statuses().await;
    assert_eq!(statuses.len(), 4, "one status per replica");
    statuses.sort_by_key(|status| status.replica);

    let replica_indexes: Vec<u32> = statuses.iter().map(|status| status.replica).collect();
    assert_eq!(replica_indexes, vec![0, 1, 2, 3]);

    let generations: BTreeSet<u64> = statuses.iter().map(|status| status.generation).collect();
    assert_eq!(generations.len(), 4, "each replica has its own generation");

    for status in &statuses {
        assert_eq!(status.deployment, "coder");
    }

    // Every replica is ready on its own single device, and no device is shared.
    let mut devices = BTreeSet::new();
    for status in &statuses {
        let running = manager
            .ensure_ready_for_generation(
                "coder",
                status.generation,
                0,
                sbproxy_model_host::PriorityClass::Standard,
            )
            .await
            .expect("each replica reaches ready");
        assert_eq!(running.selected_devices.len(), 1);
        assert!(
            devices.insert(running.selected_devices[0]),
            "replicas must not share a device"
        );
    }
    assert_eq!(devices, BTreeSet::from([0, 1, 2, 3]));
}

#[tokio::test]
async fn tensor_parallel_replicas_claim_disjoint_device_groups() {
    let preparer = ReplicaPreparer::new(4);
    let manager = manager(preparer.clone(), 4);
    manager
        .reconcile(replica_desired("r-tp", "coder", 2, Some(2)))
        .await
        .expect("two tp=2 replicas fit a four-GPU node");

    let statuses = manager.statuses().await;
    assert_eq!(statuses.len(), 2);

    let mut groups = Vec::new();
    for status in &statuses {
        let running = manager
            .ensure_ready_for_generation(
                "coder",
                status.generation,
                0,
                sbproxy_model_host::PriorityClass::Standard,
            )
            .await
            .expect("each replica reaches ready");
        let mut group = running.selected_devices.clone();
        group.sort_unstable();
        groups.push(group);
    }
    groups.sort();
    assert_eq!(groups, vec![vec![0, 1], vec![2, 3]]);
}

#[tokio::test]
async fn oversubscribed_replicas_fail_with_a_legible_reason() {
    let preparer = ReplicaPreparer::new(4);
    let manager = manager(preparer.clone(), 4);
    let error = manager
        .reconcile(replica_desired("over", "coder", 8, Some(1)))
        .await
        .expect_err("eight replicas cannot fit a four-GPU node");
    let message = error.to_string();
    assert!(
        message.contains("cannot place") && message.contains("8"),
        "over-subscription must name the shortfall, got: {message}"
    );
    // The failed reconcile leaves no partial state behind.
    assert!(manager.statuses().await.is_empty());
}

#[tokio::test]
async fn draining_a_multi_replica_deployment_stops_every_replica() {
    let preparer = ReplicaPreparer::new(4);
    let manager = manager(preparer.clone(), 4);
    manager
        .reconcile(replica_desired("drain", "coder", 3, Some(1)))
        .await
        .expect("three replicas fit");

    for status in manager.statuses().await {
        manager
            .ensure_ready_for_generation(
                "coder",
                status.generation,
                0,
                sbproxy_model_host::PriorityClass::Standard,
            )
            .await
            .expect("replica ready");
    }

    manager.drain("coder").await.expect("drain the deployment");

    let stops = preparer
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.starts_with("stop:coder:"))
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        stops.len(),
        3,
        "every replica generation stops exactly once"
    );
}

#[tokio::test]
async fn admission_spreads_across_local_replicas() {
    // Each held permit raises a replica's in-flight count, so the next
    // admission lands on a less-loaded replica: three concurrent admissions
    // reach three distinct replicas.
    let preparer = ReplicaPreparer::new(3);
    let manager = manager(preparer.clone(), 3);
    manager
        .reconcile(replica_desired("bal", "coder", 3, Some(1)))
        .await
        .expect("three replicas fit");

    let mut generations = BTreeSet::new();
    let mut held = Vec::new();
    for _ in 0..3 {
        let permit = manager
            .admit("coder", sbproxy_model_host::PriorityClass::Standard)
            .await
            .expect("admission succeeds");
        generations.insert(permit.generation());
        held.push(permit);
    }
    assert_eq!(
        generations.len(),
        3,
        "three concurrent admissions spread across the three replicas"
    );
}

#[tokio::test]
async fn a_single_replica_deployment_needs_no_device_plan() {
    // replicas = 1 keeps the lazy path: plan_replica_devices is never called,
    // so a preparer that would reject it still serves one replica.
    let preparer = ReplicaPreparer::new(1);
    let manager = manager(preparer.clone(), 1);
    manager
        .reconcile(replica_desired("solo", "coder", 1, None))
        .await
        .expect("one replica reconciles without a node-level plan");
    assert_eq!(manager.statuses().await.len(), 1);
}
