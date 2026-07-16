use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sbproxy_config::{
    ManagedDeploymentConfig, ManagedEngineChoice, ManagedPullPolicy, ManagedRolloutPolicy,
    ModelHostAuthority, ModelHostControlConfig,
};
use sbproxy_model_host::{
    compile_desired_state, ArtifactFormat, ArtifactManager, Catalog, DeploymentPrepareRequest,
    DeploymentPreparer, DeploymentSourceMode, DesiredStateError, EngineAvailability,
    EngineCapabilities, EngineDetection, EngineDriver, EngineDriverError, EngineFailureReason,
    EngineHealth, EngineKind, EngineProcess, EngineProvisioning, EvictionPolicy,
    FileDeploymentRevisionStore, GpuDescriptor, GpuVendor, LegacyServeInput, ManagedProviderInput,
    ModelHostConfig, ModelHostObserver, ModelMetadata, ModelMetadataProvider, ModelRuntimeManager,
    NetworkPolicy, OperationJob, PreparedDeploymentRuntime, ProductionDeploymentPreparer,
    ProvisionRequest, ProvisionedEngine, PullIntent, RunningEngine, RuntimeDesiredInput,
    RuntimeManagerError, StaticGpuProbe, UnavailableArtifactTransport, WorkerProfile,
};
use sha2::{Digest, Sha256};

fn canonical_host() -> ModelHostControlConfig {
    ModelHostControlConfig {
        authority: ModelHostAuthority::FileManaged,
        deployments: BTreeMap::from([(
            "coder".to_string(),
            ManagedDeploymentConfig {
                model: "qwen2.5-0.5b-instruct".to_string(),
                variant: Some("q4_k_m".to_string()),
                warm: true,
                max_concurrency: Some(4),
                ..serde_yaml::from_str("model: qwen2.5-0.5b-instruct").expect("deployment defaults")
            },
        )]),
        ..ModelHostControlConfig::default()
    }
}

fn managed(origin: &str, provider: &str, deployment: &str) -> ManagedProviderInput {
    ManagedProviderInput {
        origin: origin.to_string(),
        provider: provider.to_string(),
        deployment: deployment.to_string(),
        models: vec!["coder".to_string()],
    }
}

fn legacy(origin: &str, provider: &str, model: &str) -> LegacyServeInput {
    let config: ModelHostConfig = serde_yaml::from_str(&format!(
        r#"
models:
  - model: {model}
    name: coder
"#
    ))
    .expect("legacy serve config");
    LegacyServeInput {
        origin: origin.to_string(),
        provider: provider.to_string(),
        config,
    }
}

fn input(
    canonical: Option<ModelHostControlConfig>,
    managed_providers: Vec<ManagedProviderInput>,
    legacy_providers: Vec<LegacyServeInput>,
) -> RuntimeDesiredInput {
    RuntimeDesiredInput {
        source_revision: "test-config-sha".to_string(),
        canonical,
        managed_providers,
        legacy_providers,
    }
}

#[test]
fn desired_canonical_deployments_validate_managed_routes_from_all_origins() {
    let state = compile_desired_state(
        input(
            Some(canonical_host()),
            vec![
                managed("origin-a", "local", "coder"),
                managed("origin-b", "local", "coder"),
            ],
            Vec::new(),
        ),
        &Catalog::builtin(),
    )
    .expect("complete desired state");

    assert_eq!(state.revision.deployments.len(), 1);
    assert_eq!(state.routes.len(), 2, "both origins remain routable");
    assert_eq!(
        state
            .route_for("origin-a", "local", "coder")
            .expect("origin-a route")
            .deployment,
        "coder"
    );
    assert_eq!(state.revision.deployments["coder"].max_concurrency, Some(4));
}

#[test]
fn desired_rejects_a_managed_provider_for_an_undeclared_deployment() {
    let error = compile_desired_state(
        input(
            Some(canonical_host()),
            vec![managed("origin-a", "local", "missing")],
            Vec::new(),
        ),
        &Catalog::builtin(),
    )
    .expect_err("undeclared reference must fail the whole revision");

    assert!(matches!(
        error,
        DesiredStateError::UndeclaredDeployment { ref deployment, .. }
            if deployment == "missing"
    ));
}

#[test]
fn desired_legacy_ids_are_stable_and_equivalent_origins_deduplicate() {
    let first = compile_desired_state(
        input(
            None,
            Vec::new(),
            vec![
                legacy("origin-a", "local", "qwen3-8b"),
                legacy("origin-b", "local", "qwen3-8b"),
            ],
        ),
        &Catalog::builtin(),
    )
    .expect("equivalent legacy providers");
    let again = compile_desired_state(
        input(
            None,
            Vec::new(),
            vec![legacy("origin-a", "local", "qwen3-8b")],
        ),
        &Catalog::builtin(),
    )
    .expect("same legacy provider");

    let first_ids = first.revision.deployments.keys().collect::<Vec<_>>();
    let again_ids = again.revision.deployments.keys().collect::<Vec<_>>();
    assert_eq!(first_ids, again_ids);
    assert_eq!(first.routes.len(), 2);
    assert!(first_ids[0].starts_with("legacy-local-coder-"));
}

#[test]
fn desired_rejects_conflicting_legacy_routes_instead_of_picking_an_origin() {
    let error = compile_desired_state(
        input(
            None,
            Vec::new(),
            vec![
                legacy("origin-a", "local", "qwen3-8b"),
                legacy("origin-b", "local", "qwen3-14b"),
            ],
        ),
        &Catalog::builtin(),
    )
    .expect_err("one public route cannot select two deployments");

    assert!(matches!(
        error,
        DesiredStateError::Conflict { ref field, .. } if field == "route local/coder"
    ));
}

#[test]
fn desired_rejects_conflicting_legacy_host_policies() {
    let mut first = legacy("origin-a", "local-a", "qwen3-8b");
    first.config.cache_dir = Some("/cache/a".to_string());
    let mut second = legacy("origin-b", "local-b", "qwen3-14b");
    second.config.cache_dir = Some("/cache/b".to_string());

    let error = compile_desired_state(
        input(None, Vec::new(), vec![first, second]),
        &Catalog::builtin(),
    )
    .expect_err("host policy must be merged explicitly");

    assert!(matches!(
        error,
        DesiredStateError::Conflict { ref field, .. } if field == "legacy host policy"
    ));
}

#[test]
fn desired_rejects_legacy_fields_the_managed_driver_cannot_honor() {
    let config: ModelHostConfig = serde_yaml::from_str(
        r#"
models:
  - model: qwen3-14b
    speculative: {}
"#,
    )
    .unwrap();
    let error = compile_desired_state(
        input(
            None,
            Vec::new(),
            vec![LegacyServeInput {
                origin: "origin-a".to_string(),
                provider: "local".to_string(),
                config,
            }],
        ),
        &Catalog::builtin(),
    )
    .expect_err("validate and boot must reject unsupported legacy fields equally");

    assert!(matches!(
        error,
        DesiredStateError::Invalid(ref message) if message.contains("speculative")
    ));
}

fn manager_desired(
    source_revision: &str,
    deployments: &[(&str, bool, u64)],
    max_parallel_prepares: usize,
) -> sbproxy_model_host::RuntimeDesiredState {
    let mut host = ModelHostControlConfig {
        max_parallel_prepares,
        ..ModelHostControlConfig::default()
    };
    for (id, warm, keep_alive_secs) in deployments {
        host.deployments.insert(
            (*id).to_string(),
            ManagedDeploymentConfig {
                model: "qwen2.5-0.5b-instruct".to_string(),
                variant: Some("q4_k_m".to_string()),
                warm: *warm,
                keep_alive_secs: Some(*keep_alive_secs),
                ..serde_yaml::from_str("model: qwen2.5-0.5b-instruct").unwrap()
            },
        );
    }
    compile_desired_state(
        RuntimeDesiredInput {
            source_revision: source_revision.to_string(),
            canonical: Some(host),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &Catalog::builtin(),
    )
    .unwrap()
}

fn rollout_desired(
    source_revision: &str,
    rollout: ManagedRolloutPolicy,
    max_concurrency: u32,
) -> sbproxy_model_host::RuntimeDesiredState {
    let mut host = ModelHostControlConfig::default();
    host.deployments.insert(
        "a".to_string(),
        ManagedDeploymentConfig {
            model: "qwen2.5-0.5b-instruct".to_string(),
            variant: Some("q4_k_m".to_string()),
            warm: true,
            max_concurrency: Some(max_concurrency),
            rollout,
            ..serde_yaml::from_str("model: qwen2.5-0.5b-instruct").unwrap()
        },
    );
    compile_desired_state(
        RuntimeDesiredInput {
            source_revision: source_revision.to_string(),
            canonical: Some(host),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &Catalog::builtin(),
    )
    .unwrap()
}

#[derive(Debug)]
struct ManagerFixtureProcess {
    stopped: AtomicBool,
}

#[async_trait]
impl EngineProcess for ManagerFixtureProcess {
    fn id(&self) -> Option<u32> {
        Some(77)
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

#[derive(Default)]
struct FixtureRuntimeFacts {
    estimates: Mutex<BTreeMap<String, usize>>,
    starts: Mutex<BTreeMap<String, usize>>,
    stops: Mutex<BTreeMap<String, usize>>,
    processes: Mutex<BTreeMap<String, Arc<ManagerFixtureProcess>>>,
    active_starts: AtomicUsize,
    max_active_starts: AtomicUsize,
    fail_start: Mutex<BTreeSet<String>>,
    fail_start_once: Mutex<BTreeSet<String>>,
    fail_stop: Mutex<BTreeSet<String>>,
    fail_health: Mutex<BTreeSet<String>>,
    events: Mutex<Vec<String>>,
    next_port: AtomicU16,
    block_memory: AtomicBool,
    memory_entered: tokio::sync::Notify,
    memory_release: tokio::sync::Notify,
    block_start: AtomicBool,
    start_entered: tokio::sync::Notify,
    start_release: tokio::sync::Notify,
    block_stop: AtomicBool,
    stop_entered: tokio::sync::Notify,
    stop_release: tokio::sync::Notify,
    block_reset: AtomicBool,
    reset_entered: tokio::sync::Notify,
    reset_release: tokio::sync::Notify,
}

#[derive(Default)]
struct ManagerTelemetryObserver {
    states: Mutex<Vec<(String, sbproxy_model_host::DeploymentRuntimeState)>>,
    requests: Mutex<Vec<(String, usize, usize)>>,
    rejections: Mutex<
        Vec<(
            String,
            sbproxy_model_host::PriorityClass,
            sbproxy_model_host::AdmissionReason,
        )>,
    >,
}

impl ModelHostObserver for ManagerTelemetryObserver {
    fn set_deployment_requests(&self, deployment: &str, active: usize, queued: usize) {
        self.requests
            .lock()
            .unwrap()
            .push((deployment.to_string(), active, queued));
    }

    fn set_deployment_state(
        &self,
        deployment: &str,
        _engine: Option<EngineKind>,
        state: sbproxy_model_host::DeploymentRuntimeState,
    ) {
        self.states
            .lock()
            .unwrap()
            .push((deployment.to_string(), state));
    }

    fn on_admission_rejected(
        &self,
        deployment: &str,
        priority: sbproxy_model_host::PriorityClass,
        reason: sbproxy_model_host::AdmissionReason,
    ) {
        self.rejections
            .lock()
            .unwrap()
            .push((deployment.to_string(), priority, reason));
    }
}

struct FixturePreparedRuntime {
    id: String,
    generation: u64,
    facts: Arc<FixtureRuntimeFacts>,
    delay: Duration,
}

#[async_trait]
impl PreparedDeploymentRuntime for FixturePreparedRuntime {
    async fn memory_estimate(
        &self,
        _intent: PullIntent,
    ) -> Result<sbproxy_model_host::MemoryEstimate, RuntimeManagerError> {
        *self
            .facts
            .estimates
            .lock()
            .unwrap()
            .entry(self.id.clone())
            .or_default() += 1;
        if self.facts.block_memory.load(Ordering::SeqCst) {
            self.facts.memory_entered.notify_one();
            self.facts.memory_release.notified().await;
        }
        Ok(sbproxy_model_host::MemoryEstimate::from_total(0, 1))
    }

    async fn start(&self, _intent: PullIntent) -> Result<RunningEngine, RuntimeManagerError> {
        {
            let mut starts = self.facts.starts.lock().unwrap();
            *starts.entry(self.id.clone()).or_default() += 1;
        }
        self.facts
            .events
            .lock()
            .unwrap()
            .push(format!("start:{}:{}", self.id, self.generation));
        let active = self.facts.active_starts.fetch_add(1, Ordering::SeqCst) + 1;
        record_max(&self.facts.max_active_starts, active);
        if self.facts.block_start.load(Ordering::SeqCst) {
            self.facts.start_entered.notify_one();
            self.facts.start_release.notified().await;
        }
        tokio::time::sleep(self.delay).await;
        self.facts.active_starts.fetch_sub(1, Ordering::SeqCst);
        let fail_once = self.facts.fail_start_once.lock().unwrap().remove(&self.id);
        if fail_once || self.facts.fail_start.lock().unwrap().contains(&self.id) {
            return Err(RuntimeManagerError::Engine(EngineDriverError::new(
                EngineFailureReason::EngineEarlyExit,
                format!("fixture deployment {} failed to start", self.id),
                "repair the fixture and reset it",
                true,
            )));
        }
        let port = self
            .facts
            .next_port
            .fetch_add(1, Ordering::SeqCst)
            .max(20_000);
        let process = Arc::new(ManagerFixtureProcess {
            stopped: AtomicBool::new(false),
        });
        self.facts
            .processes
            .lock()
            .unwrap()
            .insert(self.id.clone(), process.clone());
        Ok(RunningEngine {
            deployment: self.id.clone(),
            generation: self.generation,
            kind: EngineKind::LlamaCpp,
            port,
            accelerator: sbproxy_model_host::AcceleratorKind::Cpu,
            selected_devices: Vec::new(),
            started_at_ms: 1,
            artifact_digest: "a".repeat(64),
            engine_version: None,
            memory: sbproxy_model_host::MemoryEstimate::from_total(0, 1),
            process,
        })
    }

    async fn stop(&self, _grace: Duration) -> Result<(), RuntimeManagerError> {
        self.facts
            .events
            .lock()
            .unwrap()
            .push(format!("stop:{}:{}", self.id, self.generation));
        if self.facts.block_stop.load(Ordering::SeqCst) {
            self.facts.stop_entered.notify_one();
            self.facts.stop_release.notified().await;
        }
        if self.facts.fail_stop.lock().unwrap().contains(&self.id) {
            return Err(RuntimeManagerError::Engine(EngineDriverError::new(
                EngineFailureReason::EngineInternal,
                format!("fixture deployment {} failed to stop", self.id),
                "repair the fixture shutdown boundary",
                true,
            )));
        }
        let mut stops = self.facts.stops.lock().unwrap();
        *stops.entry(self.id.clone()).or_default() += 1;
        Ok(())
    }

    async fn health(&self, running: &RunningEngine) -> Result<EngineHealth, RuntimeManagerError> {
        if self.facts.fail_health.lock().unwrap().contains(&self.id) {
            return Err(RuntimeManagerError::Engine(EngineDriverError::new(
                EngineFailureReason::EngineHealthFailed,
                format!("fixture deployment {} failed its health check", self.id),
                "repair the fixture health boundary",
                true,
            )));
        }
        if running.process.has_exited().await? {
            Ok(EngineHealth::Stopped)
        } else {
            Ok(EngineHealth::Ready)
        }
    }

    async fn reset(&self) -> Result<Option<OperationJob>, RuntimeManagerError> {
        if self.facts.block_reset.load(Ordering::SeqCst) {
            self.facts.reset_entered.notify_one();
            self.facts.reset_release.notified().await;
        }
        self.facts.fail_start.lock().unwrap().remove(&self.id);
        Ok(None)
    }
}

struct FixturePreparer {
    facts: Arc<FixtureRuntimeFacts>,
    prepares: Mutex<BTreeMap<String, usize>>,
    fail_prepare: Mutex<BTreeSet<String>>,
    active_prepares: AtomicUsize,
    max_active_prepares: AtomicUsize,
    delay: Duration,
}

impl FixturePreparer {
    fn new(delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            facts: Arc::new(FixtureRuntimeFacts {
                next_port: AtomicU16::new(20_000),
                ..FixtureRuntimeFacts::default()
            }),
            prepares: Mutex::new(BTreeMap::new()),
            fail_prepare: Mutex::new(BTreeSet::new()),
            active_prepares: AtomicUsize::new(0),
            max_active_prepares: AtomicUsize::new(0),
            delay,
        })
    }
}

#[async_trait]
impl DeploymentPreparer for FixturePreparer {
    async fn prepare(
        &self,
        request: DeploymentPrepareRequest,
    ) -> Result<Arc<dyn PreparedDeploymentRuntime>, RuntimeManagerError> {
        {
            let mut prepares = self.prepares.lock().unwrap();
            *prepares.entry(request.deployment_id.clone()).or_default() += 1;
        }
        let active = self.active_prepares.fetch_add(1, Ordering::SeqCst) + 1;
        record_max(&self.max_active_prepares, active);
        tokio::time::sleep(self.delay).await;
        self.active_prepares.fetch_sub(1, Ordering::SeqCst);
        if self
            .fail_prepare
            .lock()
            .unwrap()
            .contains(&request.deployment_id)
        {
            return Err(RuntimeManagerError::Prepare(format!(
                "fixture preparation failed for {}",
                request.deployment_id
            )));
        }
        Ok(Arc::new(FixturePreparedRuntime {
            id: request.deployment_id,
            generation: request.generation,
            facts: self.facts.clone(),
            delay: self.delay,
        }))
    }
}

fn record_max(maximum: &AtomicUsize, candidate: usize) {
    let mut current = maximum.load(Ordering::SeqCst);
    while candidate > current {
        match maximum.compare_exchange(current, candidate, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

fn manager(preparer: Arc<FixturePreparer>) -> Arc<ModelRuntimeManager> {
    Arc::new(
        ModelRuntimeManager::new(Catalog::builtin().catalog_revision, preparer)
            .expect("empty manager"),
    )
}

#[tokio::test]
async fn manager_starts_empty_and_swaps_only_after_complete_preparation() {
    let preparer = FixturePreparer::new(Duration::from_millis(20));
    let manager = manager(preparer.clone());
    assert_eq!(manager.current_revision(), 0);
    assert!(manager.current_desired().deployments.is_empty());

    let candidate = manager_desired("revision-one", &[("a", true, 30)], 2);
    let task_manager = manager.clone();
    let reconcile = tokio::spawn(async move { task_manager.reconcile(candidate).await });
    tokio::time::sleep(Duration::from_millis(2)).await;
    assert_eq!(manager.current_revision(), 0);
    assert!(manager.current_desired().deployments.is_empty());

    let report = reconcile.await.unwrap().unwrap();
    assert_eq!(report.revision, 1);
    let running = manager.ensure_ready("a").await.unwrap();
    assert_eq!(running.generation, 1);

    preparer
        .fail_prepare
        .lock()
        .unwrap()
        .insert("broken".to_string());
    let broken = manager_desired(
        "revision-broken",
        &[("a", true, 30), ("broken", false, 30)],
        2,
    );
    assert!(manager.reconcile(broken).await.is_err());
    assert_eq!(manager.current_revision(), 1);
    assert_eq!(
        manager.current_desired().revision.source_revision,
        "revision-one"
    );
    assert_eq!(manager.ensure_ready("a").await.unwrap().port, running.port);
}

#[tokio::test]
async fn manager_telemetry_observes_committed_lifecycle_and_request_counts() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let observer = Arc::new(ManagerTelemetryObserver::default());
    let manager = Arc::new(
        ModelRuntimeManager::new(Catalog::builtin().catalog_revision, preparer)
            .unwrap()
            .with_observer(observer.clone()),
    );
    manager
        .reconcile(manager_desired("telemetry", &[("a", false, 30)], 2))
        .await
        .unwrap();
    let permit = manager
        .admit("a", sbproxy_model_host::PriorityClass::Standard)
        .await
        .unwrap();
    manager.ensure_ready("a").await.unwrap();
    assert_eq!(manager.residency_reservations().await.len(), 1);
    drop(permit);
    manager.drain("a").await.unwrap();
    manager.cache("a").await.unwrap();
    assert_eq!(
        manager.status("a").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Stopped
    );
    let resumed = manager
        .admit("a", sbproxy_model_host::PriorityClass::Standard)
        .await
        .expect("a stopped cached deployment can be started again");
    drop(resumed);

    let states = observer.states.lock().unwrap();
    for expected in [
        sbproxy_model_host::DeploymentRuntimeState::Configured,
        sbproxy_model_host::DeploymentRuntimeState::Preparing,
        sbproxy_model_host::DeploymentRuntimeState::Ready,
        sbproxy_model_host::DeploymentRuntimeState::Draining,
        sbproxy_model_host::DeploymentRuntimeState::Stopped,
    ] {
        assert!(
            states
                .iter()
                .any(|(deployment, state)| deployment == "a" && *state == expected),
            "missing lifecycle transition {expected:?}"
        );
    }
    let requests = observer.requests.lock().unwrap();
    assert!(requests.contains(&("a".to_string(), 1, 0)));
    assert_eq!(requests.last(), Some(&("a".to_string(), 0, 0)));
}

#[tokio::test]
async fn manager_preserves_unchanged_generations_and_stops_only_retired_slots() {
    let preparer = FixturePreparer::new(Duration::from_millis(2));
    let manager = manager(preparer.clone());
    manager
        .reconcile(manager_desired(
            "first",
            &[("a", true, 30), ("b", true, 30)],
            2,
        ))
        .await
        .unwrap();
    let a = manager.ensure_ready("a").await.unwrap();

    let report = manager
        .reconcile(manager_desired(
            "second",
            &[("a", true, 30), ("b", true, 60), ("c", false, 30)],
            2,
        ))
        .await
        .unwrap();
    assert_eq!(report.plan.preserved, vec!["a"]);
    assert_eq!(report.plan.changed, vec!["b"]);
    assert_eq!(report.plan.added, vec!["c"]);
    let after = manager.ensure_ready("a").await.unwrap();
    assert_eq!((after.generation, after.port), (a.generation, a.port));
    assert_eq!(
        preparer.facts.stops.lock().unwrap().get("b").copied(),
        Some(1)
    );

    let removed = manager
        .reconcile(manager_desired("third", &[("a", true, 30)], 2))
        .await
        .unwrap();
    assert_eq!(removed.plan.removed, vec!["b", "c"]);
    assert!(manager.ensure_ready("b").await.is_err());
    assert_eq!(manager.ensure_ready("a").await.unwrap().port, a.port);
}

#[tokio::test]
async fn engine_or_cache_policy_changes_replace_the_affected_generation() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer);
    manager
        .reconcile(manager_desired("first", &[("a", false, 30)], 2))
        .await
        .unwrap();
    let first = manager.ensure_ready("a").await.unwrap();
    let mut changed = manager_desired("second", &[("a", false, 30)], 2);
    changed.control.cache.directory = Some("/different/model-cache".to_string());

    let report = manager.reconcile(changed).await.unwrap();
    assert_eq!(report.plan.changed, vec!["a"]);
    let second = manager.ensure_ready("a").await.unwrap();
    assert_ne!(second.generation, first.generation);
}

#[tokio::test]
async fn manager_shares_one_cold_start_and_prepares_different_deployments_concurrently() {
    let preparer = FixturePreparer::new(Duration::from_millis(20));
    let manager = manager(preparer.clone());
    manager
        .reconcile(manager_desired(
            "cold",
            &[("a", false, 30), ("b", false, 30), ("c", false, 30)],
            2,
        ))
        .await
        .unwrap();
    assert_eq!(preparer.max_active_prepares.load(Ordering::SeqCst), 2);

    let (first, second) = tokio::join!(manager.ensure_ready("a"), manager.ensure_ready("a"));
    assert_eq!(first.unwrap().port, second.unwrap().port);
    assert_eq!(
        preparer.facts.starts.lock().unwrap().get("a").copied(),
        Some(1)
    );

    preparer.facts.max_active_starts.store(0, Ordering::SeqCst);
    let (b, c) = tokio::join!(manager.ensure_ready("b"), manager.ensure_ready("c"));
    b.unwrap();
    c.unwrap();
    assert_eq!(preparer.facts.max_active_starts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn ready_generation_detects_a_process_that_exited_after_readiness() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    manager
        .reconcile(manager_desired("health", &[("a", false, 30)], 1))
        .await
        .unwrap();
    manager.ensure_ready("a").await.unwrap();
    assert_eq!(manager.residency_reservations().await.len(), 1);
    preparer.facts.processes.lock().unwrap()["a"]
        .stopped
        .store(true, Ordering::SeqCst);

    let error = manager
        .ensure_ready("a")
        .await
        .expect_err("an exited ready process must not remain routable");
    assert_eq!(error.reason_code(), "engine_health_failed");
    let status = manager.status("a").await.unwrap();
    assert_eq!(
        status.state,
        sbproxy_model_host::DeploymentRuntimeState::Failed
    );
    assert!(status.port.is_none());
    assert!(manager.residency_reservations().await.is_empty());
}

#[tokio::test]
async fn failed_health_cleanup_retains_process_ownership_and_residency() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    manager
        .reconcile(manager_desired(
            "health-stop-failure",
            &[("a", false, 30)],
            1,
        ))
        .await
        .unwrap();
    manager.ensure_ready("a").await.unwrap();
    preparer
        .facts
        .fail_health
        .lock()
        .unwrap()
        .insert("a".to_string());
    preparer
        .facts
        .fail_stop
        .lock()
        .unwrap()
        .insert("a".to_string());

    manager.maintenance_tick(tokio::time::Instant::now()).await;

    let status = manager.status("a").await.unwrap();
    assert_eq!(
        status.state,
        sbproxy_model_host::DeploymentRuntimeState::Failed
    );
    assert!(
        status.port.is_some(),
        "the possibly-live process stays owned"
    );
    assert_eq!(manager.residency_reservations().await.len(), 1);
    assert!(
        manager.reset("a").await.is_err(),
        "reset cannot discard a process whose shutdown failed"
    );

    preparer.facts.fail_stop.lock().unwrap().remove("a");
    manager.stop("a").await.unwrap();
    assert!(manager.residency_reservations().await.is_empty());
}

#[tokio::test]
async fn failed_retirement_is_retained_and_retried_until_shutdown_succeeds() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    manager
        .reconcile(manager_desired("retirement-owner", &[("a", true, 30)], 1))
        .await
        .unwrap();
    let generation = manager.status("a").await.unwrap().generation;
    preparer
        .facts
        .fail_stop
        .lock()
        .unwrap()
        .insert("a".to_string());

    let report = manager
        .reconcile(manager_desired("retired", &[], 1))
        .await
        .unwrap();
    assert!(report.retire_failures.contains_key("a"));
    assert!(manager.status("a").await.is_none());
    let reservations = manager.residency_reservations().await;
    assert_eq!(reservations.len(), 1);
    assert_eq!(reservations[0].generation, generation);
    assert!(reservations[0].protection.draining);

    manager.maintenance_tick(tokio::time::Instant::now()).await;
    assert_eq!(
        manager.residency_reservations().await.len(),
        1,
        "maintenance must retain capacity while retired shutdown still fails"
    );

    preparer.facts.fail_stop.lock().unwrap().remove("a");
    manager.maintenance_tick(tokio::time::Instant::now()).await;
    assert!(manager.residency_reservations().await.is_empty());
    assert_eq!(
        preparer.facts.stops.lock().unwrap().get("a").copied(),
        Some(1)
    );
    let stop_events = preparer
        .facts
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.starts_with("stop:a:"))
        .count();
    manager.maintenance_tick(tokio::time::Instant::now()).await;
    assert_eq!(
        preparer
            .facts
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.starts_with("stop:a:"))
            .count(),
        stop_events,
        "a successfully retired generation must leave the retry registry"
    );
}

#[tokio::test]
async fn explicit_stop_invalidates_a_cold_request_waiting_for_placement() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    let mut desired = manager_desired("stop-race", &[("a", false, 30)], 1);
    desired.control.shutdown_deadline_ms = 20;
    manager.reconcile(desired).await.unwrap();
    preparer.facts.block_memory.store(true, Ordering::SeqCst);

    let request_manager = manager.clone();
    let permit = request_manager
        .admit("a", sbproxy_model_host::PriorityClass::Standard)
        .await
        .unwrap();
    let request = tokio::spawn(async move {
        let generation = permit.generation();
        let start_epoch = permit.start_epoch();
        let _permit = permit;
        request_manager
            .ensure_ready_for_generation(
                "a",
                generation,
                start_epoch,
                sbproxy_model_host::PriorityClass::Standard,
            )
            .await
    });
    preparer.facts.memory_entered.notified().await;

    tokio::time::timeout(Duration::from_millis(200), manager.stop("a"))
        .await
        .expect("stop remains bounded")
        .unwrap();
    preparer.facts.memory_release.notify_one();
    assert!(matches!(
        request.await.unwrap(),
        Err(RuntimeManagerError::Draining(_))
    ));
    assert_eq!(
        preparer.facts.starts.lock().unwrap().get("a").copied(),
        None,
        "a permit issued before stop must not restart the stopped engine"
    );
}

#[tokio::test]
async fn explicit_stop_invalidates_a_permit_issued_while_stopped() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    let mut desired = manager_desired("stopped-permit-race", &[("a", false, 30)], 1);
    desired.control.shutdown_deadline_ms = 20;
    manager.reconcile(desired).await.unwrap();
    manager.stop("a").await.unwrap();

    let permit = manager
        .admit("a", sbproxy_model_host::PriorityClass::Standard)
        .await
        .unwrap();
    manager.stop("a").await.unwrap();
    let result = manager
        .ensure_ready_for_generation(
            "a",
            permit.generation(),
            permit.start_epoch(),
            sbproxy_model_host::PriorityClass::Standard,
        )
        .await;
    drop(permit);

    assert!(matches!(result, Err(RuntimeManagerError::Draining(_))));
    assert_eq!(
        preparer.facts.starts.lock().unwrap().get("a").copied(),
        None,
        "a stop after stopped-slot admission must invalidate that permit"
    );
}

#[tokio::test]
async fn stop_releases_a_reservation_created_by_an_inflight_activation() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    manager
        .reconcile(manager_desired(
            "activation-reservation-stop",
            &[("a", false, 30)],
            1,
        ))
        .await
        .unwrap();
    preparer.facts.block_start.store(true, Ordering::SeqCst);

    let request_manager = manager.clone();
    let request = tokio::spawn(async move { request_manager.ensure_ready("a").await });
    preparer.facts.start_entered.notified().await;
    assert_eq!(manager.residency_reservations().await.len(), 1);

    let stop_manager = manager.clone();
    let stop = tokio::spawn(async move { stop_manager.stop("a").await });
    tokio::task::yield_now().await;
    preparer.facts.start_release.notify_one();

    stop.await.unwrap().unwrap();
    assert!(matches!(
        request.await.unwrap(),
        Err(RuntimeManagerError::Draining(_))
    ));
    assert!(manager.residency_reservations().await.is_empty());
    assert_eq!(
        manager.status("a").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Stopped
    );
}

#[tokio::test]
async fn stopped_slot_ignores_a_stale_memory_estimate_completion() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    manager
        .reconcile(manager_desired("stale-memory-stop", &[("a", false, 30)], 1))
        .await
        .unwrap();
    preparer.facts.block_memory.store(true, Ordering::SeqCst);

    let cache_manager = manager.clone();
    let cache = tokio::spawn(async move { cache_manager.cache("a").await });
    preparer.facts.memory_entered.notified().await;
    manager.stop("a").await.unwrap();
    assert_eq!(
        manager.status("a").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Stopped
    );

    preparer.facts.memory_release.notify_one();
    assert!(matches!(
        cache.await.unwrap(),
        Err(RuntimeManagerError::Draining(_))
    ));
    assert_eq!(
        manager.status("a").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Stopped,
        "a stale estimate must not overwrite the stop lifecycle"
    );
}

#[tokio::test]
async fn ready_slot_ignores_a_stale_memory_estimate_completion() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    manager
        .reconcile(manager_desired(
            "stale-memory-ready",
            &[("a", false, 30)],
            2,
        ))
        .await
        .unwrap();
    preparer.facts.block_memory.store(true, Ordering::SeqCst);

    let cache_manager = manager.clone();
    let cache = tokio::spawn(async move { cache_manager.cache("a").await });
    preparer.facts.memory_entered.notified().await;
    preparer.facts.block_memory.store(false, Ordering::SeqCst);
    let running = manager.ensure_ready("a").await.unwrap();
    assert_eq!(
        manager.status("a").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Ready
    );

    preparer.facts.memory_release.notify_one();
    cache.await.unwrap().unwrap();
    let status = manager.status("a").await.unwrap();
    assert_eq!(
        status.state,
        sbproxy_model_host::DeploymentRuntimeState::Ready,
        "an older estimate must not overwrite newer readiness"
    );
    assert_eq!(status.port, Some(running.port));
}

#[tokio::test]
async fn explicit_stop_supersedes_a_blocked_reset_completion() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    preparer
        .facts
        .fail_start_once
        .lock()
        .unwrap()
        .insert("a".to_string());
    manager
        .reconcile(manager_desired("stale-reset-stop", &[("a", false, 30)], 1))
        .await
        .unwrap();
    manager
        .ensure_ready("a")
        .await
        .expect_err("the fixture must retain a resettable failure");
    preparer.facts.block_reset.store(true, Ordering::SeqCst);

    let reset_manager = manager.clone();
    let reset = tokio::spawn(async move { reset_manager.reset("a").await });
    preparer.facts.reset_entered.notified().await;
    manager.stop("a").await.unwrap();
    assert_eq!(
        manager.status("a").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Stopped
    );

    preparer.facts.reset_release.notify_one();
    assert!(matches!(
        reset.await.unwrap(),
        Err(RuntimeManagerError::Draining(_))
    ));
    assert_eq!(
        manager.status("a").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Stopped,
        "a stale reset must not overwrite an explicit stop"
    );
}

#[tokio::test]
async fn explicit_stop_supersedes_recreate_rollback() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    manager
        .reconcile(rollout_desired(
            "recreate-stop-old",
            ManagedRolloutPolicy::Rolling,
            1,
        ))
        .await
        .unwrap();
    assert_eq!(
        preparer.facts.starts.lock().unwrap().get("a").copied(),
        Some(1)
    );
    preparer
        .facts
        .fail_start_once
        .lock()
        .unwrap()
        .insert("a".to_string());
    preparer.facts.block_stop.store(true, Ordering::SeqCst);

    let reconcile_manager = manager.clone();
    let replacement = rollout_desired("recreate-stop-new", ManagedRolloutPolicy::Recreate, 2);
    let reconcile = tokio::spawn(async move { reconcile_manager.reconcile(replacement).await });
    preparer.facts.stop_entered.notified().await;

    let stop_manager = manager.clone();
    let stop = tokio::spawn(async move { stop_manager.stop("a").await });
    preparer.facts.stop_entered.notified().await;
    preparer.facts.block_stop.store(false, Ordering::SeqCst);
    preparer.facts.stop_release.notify_waiters();

    stop.await.unwrap().unwrap();
    assert!(matches!(
        reconcile.await.unwrap(),
        Err(RuntimeManagerError::Draining(_))
    ));
    assert_eq!(
        manager.status("a").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Stopped
    );
    assert_eq!(
        preparer.facts.starts.lock().unwrap().get("a").copied(),
        Some(1),
        "a superseded recreate must neither launch nor roll back over explicit stop"
    );
}

#[tokio::test]
async fn recreate_releases_placement_while_rejecting_a_cold_request() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    let mut initial = rollout_desired("recreate-race-old", ManagedRolloutPolicy::Rolling, 1);
    initial.control.shutdown_deadline_ms = 1_000;
    initial.deployments.get_mut("a").unwrap().desired.warm = false;
    initial.revision.deployments.get_mut("a").unwrap().warm = false;
    manager.reconcile(initial).await.unwrap();
    preparer.facts.block_memory.store(true, Ordering::SeqCst);

    let request_manager = manager.clone();
    let permit = request_manager
        .admit("a", sbproxy_model_host::PriorityClass::Standard)
        .await
        .unwrap();
    let request = tokio::spawn(async move {
        let generation = permit.generation();
        let start_epoch = permit.start_epoch();
        let _permit = permit;
        request_manager
            .ensure_ready_for_generation(
                "a",
                generation,
                start_epoch,
                sbproxy_model_host::PriorityClass::Standard,
            )
            .await
    });
    preparer.facts.memory_entered.notified().await;

    let reconcile_manager = manager.clone();
    let mut replacement = rollout_desired("recreate-race-new", ManagedRolloutPolicy::Recreate, 2);
    replacement.control.shutdown_deadline_ms = 1_000;
    replacement.deployments.get_mut("a").unwrap().desired.warm = false;
    replacement.revision.deployments.get_mut("a").unwrap().warm = false;
    let reconcile = tokio::spawn(async move { reconcile_manager.reconcile(replacement).await });
    while manager.status("a").await.unwrap().state
        != sbproxy_model_host::DeploymentRuntimeState::Draining
    {
        tokio::task::yield_now().await;
    }
    preparer.facts.memory_release.notify_one();

    assert!(matches!(
        tokio::time::timeout(Duration::from_millis(200), request)
            .await
            .expect("stale request must acquire placement and reject promptly")
            .unwrap(),
        Err(RuntimeManagerError::Draining(_))
    ));
    tokio::time::timeout(Duration::from_millis(200), reconcile)
        .await
        .expect("recreate must not wait for its full drain deadline")
        .unwrap()
        .unwrap();
    assert_eq!(manager.current_revision(), 2);
    assert_eq!(
        preparer.facts.starts.lock().unwrap().get("a").copied(),
        None
    );
}

#[tokio::test]
async fn reload_cannot_resurrect_a_cold_generation_removed_while_it_waits_for_placement() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    let mut initial = manager_desired("initial", &[("a", false, 30)], 1);
    initial.control.shutdown_deadline_ms = 1_000;
    manager.reconcile(initial).await.unwrap();
    preparer.facts.block_memory.store(true, Ordering::SeqCst);

    let request_manager = manager.clone();
    let permit = request_manager
        .admit("a", sbproxy_model_host::PriorityClass::Standard)
        .await
        .unwrap();
    let request = tokio::spawn(async move {
        let _permit = permit;
        request_manager.ensure_ready("a").await
    });
    preparer.facts.memory_entered.notified().await;

    let reconcile_manager = manager.clone();
    let mut removed = manager_desired("removed", &[], 1);
    removed.control.shutdown_deadline_ms = 1_000;
    let reconcile = tokio::spawn(async move { reconcile_manager.reconcile(removed).await });
    while manager.current_revision() == 1 {
        tokio::task::yield_now().await;
    }
    preparer.facts.memory_release.notify_one();

    let request_result = tokio::time::timeout(Duration::from_millis(200), request)
        .await
        .expect("stale request must not wait for the retirement deadline")
        .unwrap();
    assert!(matches!(
        request_result,
        Err(RuntimeManagerError::Draining(_))
    ));
    tokio::time::timeout(Duration::from_millis(200), reconcile)
        .await
        .expect("reconcile must finish after the stale permit is released")
        .unwrap()
        .unwrap();
    assert!(!manager.current_desired().deployments.contains_key("a"));
    assert_eq!(
        preparer.facts.starts.lock().unwrap().get("a").copied(),
        None,
        "the retired cold slot must never start"
    );
}

#[tokio::test]
async fn admission_and_readiness_are_bound_to_the_same_generation() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer);
    let mut initial = manager_desired("initial", &[("a", false, 30)], 1);
    initial.control.shutdown_deadline_ms = 1_000;
    manager.reconcile(initial).await.unwrap();
    let permit = manager
        .admit("a", sbproxy_model_host::PriorityClass::Standard)
        .await
        .unwrap();
    assert_eq!(permit.generation(), 1);

    let reconcile_manager = manager.clone();
    let mut changed = manager_desired("changed", &[("a", false, 60)], 1);
    changed.control.shutdown_deadline_ms = 1_000;
    let reconcile = tokio::spawn(async move { reconcile_manager.reconcile(changed).await });
    while manager.current_revision() == 1 {
        tokio::task::yield_now().await;
    }

    let error = manager
        .ensure_ready_for_generation(
            "a",
            permit.generation(),
            permit.start_epoch(),
            sbproxy_model_host::PriorityClass::Standard,
        )
        .await
        .expect_err("an old admission permit cannot start the replacement generation");
    assert!(matches!(error, RuntimeManagerError::Draining(_)));
    drop(permit);
    tokio::time::timeout(Duration::from_millis(200), reconcile)
        .await
        .expect("replacement reconcile must finish when the old permit is released")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cancelling_the_only_cold_start_waiter_does_not_strand_activation() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    manager
        .reconcile(manager_desired("cancel", &[("a", false, 30)], 1))
        .await
        .unwrap();
    preparer.facts.block_start.store(true, Ordering::SeqCst);

    let request_manager = manager.clone();
    let request = tokio::spawn(async move { request_manager.ensure_ready("a").await });
    preparer.facts.start_entered.notified().await;
    request.abort();
    let _ = request.await;
    preparer.facts.start_release.notify_one();

    tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            if manager.status("a").await.is_some_and(|status| {
                status.state == sbproxy_model_host::DeploymentRuntimeState::Ready
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("manager-owned activation must complete without a request poller");
    manager.ensure_ready("a").await.unwrap();
    assert_eq!(
        preparer.facts.starts.lock().unwrap().get("a").copied(),
        Some(1)
    );
}

#[tokio::test]
async fn non_warm_on_boot_deployment_is_acquired_during_reconciliation() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    let mut host = ModelHostControlConfig::default();
    host.deployments.insert(
        "a".to_string(),
        ManagedDeploymentConfig {
            model: "qwen2.5-0.5b-instruct".to_string(),
            variant: Some("q4_k_m".to_string()),
            pull: ManagedPullPolicy::OnBoot,
            warm: false,
            ..serde_yaml::from_str("model: qwen2.5-0.5b-instruct").unwrap()
        },
    );
    let desired = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "on-boot".to_string(),
            canonical: Some(host),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &Catalog::builtin(),
    )
    .unwrap();

    manager.reconcile(desired).await.unwrap();

    assert_eq!(
        preparer.facts.estimates.lock().unwrap().get("a").copied(),
        Some(1)
    );
    assert_eq!(
        preparer.facts.starts.lock().unwrap().get("a").copied(),
        None
    );
}

#[tokio::test]
async fn reset_rejects_a_healthy_ready_generation_without_hiding_it() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer);
    manager
        .reconcile(manager_desired("ready-reset", &[("a", true, 30)], 1))
        .await
        .unwrap();
    let before = manager.status("a").await.unwrap();
    assert_eq!(
        before.state,
        sbproxy_model_host::DeploymentRuntimeState::Ready
    );

    manager
        .reset("a")
        .await
        .expect_err("reset is only valid for a retained failure");

    let after = manager.status("a").await.unwrap();
    assert_eq!(after.state, before.state);
    assert_eq!(after.port, before.port);
}

#[tokio::test]
async fn warm_failure_rolls_back_and_preserves_the_unaffected_running_slot() {
    let preparer = FixturePreparer::new(Duration::from_millis(2));
    let manager = manager(preparer.clone());
    manager
        .reconcile(manager_desired("good", &[("a", true, 30)], 2))
        .await
        .unwrap();
    let a = manager.ensure_ready("a").await.unwrap();
    preparer
        .facts
        .fail_start
        .lock()
        .unwrap()
        .insert("bad".to_string());

    let error = manager
        .reconcile(manager_desired(
            "bad",
            &[("a", true, 30), ("bad", true, 30)],
            2,
        ))
        .await
        .expect_err("warm failure must roll back");
    assert!(matches!(error, RuntimeManagerError::Engine(_)));
    assert_eq!(manager.current_desired().revision.source_revision, "good");
    assert_eq!(manager.ensure_ready("a").await.unwrap().port, a.port);
}

#[tokio::test]
async fn stale_prepared_revision_is_rejected_and_its_staged_runtime_is_stopped() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());
    let first = manager
        .prepare_revision(manager_desired("first", &[("a", false, 30)], 2))
        .await
        .unwrap();
    let stale = manager
        .prepare_revision(manager_desired("stale", &[("b", false, 30)], 2))
        .await
        .unwrap();
    manager.commit_revision(first).await.unwrap();

    assert!(matches!(
        manager.commit_revision(stale).await,
        Err(RuntimeManagerError::StalePrepared {
            based_on: 0,
            current: 1
        })
    ));
    assert_eq!(manager.current_desired().revision.source_revision, "first");
    assert_eq!(
        preparer.facts.stops.lock().unwrap().get("b").copied(),
        Some(1)
    );
}

#[tokio::test]
async fn admin_managed_reconciliation_loads_the_store_and_invalid_updates_preserve_live_state() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = directory.path().join("deployments.json");
    let store = FileDeploymentRevisionStore::open(&store_path).unwrap();
    let mut stored = manager_desired("stored-source", &[("stored", false, 30)], 2).revision;
    stored.source_mode = DeploymentSourceMode::AdminManaged;
    store.compare_and_swap(None, stored).unwrap();

    let host = ModelHostControlConfig {
        authority: ModelHostAuthority::AdminManaged,
        store_path: Some(store_path.display().to_string()),
        ..ModelHostControlConfig::default()
    };
    let candidate = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "file-wrapper".to_string(),
            canonical: Some(host.clone()),
            managed_providers: vec![managed("origin", "local", "stored")],
            legacy_providers: Vec::new(),
        },
        &Catalog::builtin(),
    )
    .unwrap();
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer);
    manager.reconcile(candidate).await.unwrap();
    assert!(manager.current_desired().deployments.contains_key("stored"));
    assert_eq!(
        manager
            .route_for("origin", "local", "coder")
            .unwrap()
            .deployment,
        "stored"
    );
    assert!(manager
        .current_desired()
        .revision
        .source_revision
        .starts_with("stored-source#1"));

    std::fs::write(&store_path, b"{ invalid JSON").unwrap();
    let invalid = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "invalid-wrapper".to_string(),
            canonical: Some(host),
            managed_providers: vec![managed("origin", "local", "stored")],
            legacy_providers: Vec::new(),
        },
        &Catalog::builtin(),
    )
    .unwrap();
    assert!(matches!(
        manager.reconcile(invalid).await,
        Err(RuntimeManagerError::Store(_))
    ));
    assert_eq!(manager.current_revision(), 1);
    assert!(manager.current_desired().deployments.contains_key("stored"));
}

#[tokio::test]
async fn drained_admin_store_adopts_a_new_catalog_revision_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = directory.path().join("deployments.json");
    let store = FileDeploymentRevisionStore::open(&store_path).unwrap();
    let mut initial = manager_desired("catalog-v1", &[("old", false, 30)], 2).revision;
    initial.source_mode = DeploymentSourceMode::AdminManaged;
    store.compare_and_swap(None, initial).unwrap();
    let mut drained = manager_desired("catalog-v1-drained", &[], 2).revision;
    drained.source_mode = DeploymentSourceMode::AdminManaged;
    store.compare_and_swap(Some(1), drained).unwrap();

    let mut next_catalog = Catalog::builtin();
    next_catalog.catalog_revision = "catalog-v2".to_string();
    let candidate = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "catalog-v2-wrapper".to_string(),
            canonical: Some(ModelHostControlConfig {
                authority: ModelHostAuthority::AdminManaged,
                store_path: Some(store_path.display().to_string()),
                ..ModelHostControlConfig::default()
            }),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &next_catalog,
    )
    .unwrap();
    let manager = Arc::new(
        ModelRuntimeManager::new(
            next_catalog.catalog_revision.clone(),
            FixturePreparer::new(Duration::from_millis(1)),
        )
        .unwrap(),
    );

    manager
        .reconcile(candidate)
        .await
        .expect("empty durable state can rebase to the active catalog");

    let rebased = store.load().unwrap().expect("rebased durable revision");
    assert_eq!(rebased.revision, 3);
    assert_eq!(rebased.catalog_revision, "catalog-v2");
    assert!(rebased.deployments.is_empty());
}

#[tokio::test]
async fn nonempty_admin_store_refuses_a_new_catalog_revision() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = directory.path().join("deployments.json");
    let store = FileDeploymentRevisionStore::open(&store_path).unwrap();
    let mut initial = manager_desired("catalog-v1", &[("old", false, 30)], 2).revision;
    initial.source_mode = DeploymentSourceMode::AdminManaged;
    store.compare_and_swap(None, initial).unwrap();

    let mut next_catalog = Catalog::builtin();
    next_catalog.catalog_revision = "catalog-v2".to_string();
    let candidate = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "catalog-v2-wrapper".to_string(),
            canonical: Some(ModelHostControlConfig {
                authority: ModelHostAuthority::AdminManaged,
                store_path: Some(store_path.display().to_string()),
                ..ModelHostControlConfig::default()
            }),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &next_catalog,
    )
    .unwrap();
    let manager = Arc::new(
        ModelRuntimeManager::new(
            next_catalog.catalog_revision.clone(),
            FixturePreparer::new(Duration::from_millis(1)),
        )
        .unwrap(),
    );

    let error = manager
        .reconcile(candidate)
        .await
        .expect_err("configured durable state remains catalog fenced");

    assert!(matches!(error, RuntimeManagerError::Store(_)));
    let unchanged = store.load().unwrap().expect("original durable revision");
    assert_eq!(unchanged.revision, 1);
    assert_ne!(unchanged.catalog_revision, "catalog-v2");
    assert!(unchanged.deployments.contains_key("old"));
}

#[tokio::test]
async fn admin_revision_preparation_uses_the_supplied_revision_without_changing_store_normalization(
) {
    let directory = tempfile::tempdir().unwrap();
    let store_path = directory.path().join("deployments.json");
    let store = FileDeploymentRevisionStore::open(&store_path).unwrap();
    let mut stored = manager_desired("stored-source", &[("stored", false, 30)], 2).revision;
    stored.source_mode = DeploymentSourceMode::AdminManaged;
    store.compare_and_swap(None, stored).unwrap();

    let template = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "admin-template".to_string(),
            canonical: Some(ModelHostControlConfig {
                authority: ModelHostAuthority::AdminManaged,
                store_path: Some(store_path.display().to_string()),
                ..ModelHostControlConfig::default()
            }),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &Catalog::builtin(),
    )
    .unwrap();
    let mut supplied = manager_desired("supplied-source", &[("supplied", false, 30)], 2).revision;
    supplied.source_mode = DeploymentSourceMode::AdminManaged;
    let supplied = supplied.into_revision(2).unwrap();
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer.clone());

    let prepared = manager
        .prepare_admin_revision(template.clone(), supplied)
        .await
        .expect("supplied durable revision prepares");
    manager.abort_prepared(prepared).await;
    assert_eq!(
        preparer.prepares.lock().unwrap().get("supplied").copied(),
        Some(1)
    );
    assert_eq!(
        preparer.prepares.lock().unwrap().get("stored").copied(),
        None
    );

    let prepared = manager
        .prepare_revision(template)
        .await
        .expect("ordinary preparation normalizes from the durable store");
    manager.abort_prepared(prepared).await;
    assert_eq!(
        preparer.prepares.lock().unwrap().get("stored").copied(),
        Some(1)
    );
}

struct ProductionFixtureMetadata;

impl ModelMetadataProvider for ProductionFixtureMetadata {
    fn metadata(&self, _model: &sbproxy_model_host::ModelRef) -> Option<ModelMetadata> {
        Some(ModelMetadata {
            params: 1_000,
            layers: 2,
            kv_heads: 2,
            head_dim: 8,
            max_context: 128,
        })
    }
}

#[tokio::test]
async fn production_preparer_classifies_artifact_ensure_io_as_infrastructure() {
    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path().join("cache");
    let artifacts =
        Arc::new(ArtifactManager::new(&cache, Arc::new(UnavailableArtifactTransport)).unwrap());
    let catalog = Arc::new(Catalog::builtin());
    let probe = Arc::new(StaticGpuProbe::new(vec![GpuDescriptor {
        index: 0,
        vendor: GpuVendor::Cpu,
        name: "fixture CPU".to_string(),
        total_vram_bytes: 8 * 1024 * 1024 * 1024,
        free_vram_bytes: 8 * 1024 * 1024 * 1024,
        compute_utilization: None,
        memory_occupancy: Some(0.0),
        compute_capability: None,
        supports_fp8: false,
        mem_bandwidth_gbps: None,
    }]));
    let preparer = ProductionDeploymentPreparer::new(
        Arc::clone(&catalog),
        artifacts,
        probe,
        Arc::new(ProductionFixtureMetadata),
        NetworkPolicy::Denied,
    );
    let mut control = ModelHostControlConfig::default();
    control.cache.directory = Some(cache.display().to_string());
    control.deployments.insert(
        "fixture".to_string(),
        ManagedDeploymentConfig {
            model: "qwen2.5-0.5b-instruct".to_string(),
            variant: Some("q4_k_m".to_string()),
            pull: ManagedPullPolicy::OnBoot,
            warm: true,
            engine: ManagedEngineChoice::LlamaCpp,
            ..serde_yaml::from_str("model: qwen2.5-0.5b-instruct").unwrap()
        },
    );
    let desired = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "artifact-io-fixture".to_string(),
            canonical: Some(control),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog,
    )
    .unwrap();
    let prepared = preparer
        .prepare(DeploymentPrepareRequest {
            deployment_id: "fixture".to_string(),
            replica_idx: 0,
            generation: 1,
            desired: desired.deployments["fixture"].clone(),
            pinned_fit: None,
            control: desired.control.clone(),
            legacy_host_policy: desired.legacy_host_policy.clone(),
        })
        .await
        .expect("initial artifact lease succeeds");
    let digest = std::fs::read_dir(cache.join("locks"))
        .unwrap()
        .find_map(|entry| {
            entry
                .ok()?
                .file_name()
                .to_str()?
                .strip_prefix("lease-")?
                .strip_suffix(".lock")
                .map(str::to_string)
        })
        .expect("prepared deployment holds an artifact lease");
    std::fs::create_dir(cache.join("locks").join(format!("{digest}.lock"))).unwrap();

    let error = prepared
        .memory_estimate(PullIntent::Startup)
        .await
        .expect_err("artifact cache lock I/O rejects preparation");

    assert!(matches!(
        error,
        RuntimeManagerError::PrepareInfrastructure(_)
    ));
}

struct ProductionFixtureDriver {
    launches: Arc<Mutex<Vec<(String, std::path::PathBuf, String)>>>,
}

#[async_trait]
impl EngineDriver for ProductionFixtureDriver {
    fn kind(&self) -> EngineKind {
        EngineKind::Vllm
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            artifact_formats: vec![ArtifactFormat::Safetensors],
            accelerators: vec![sbproxy_model_host::AcceleratorKind::Cpu],
            supports_container: false,
            supports_uv: false,
        }
    }

    fn detect(
        &self,
        _worker: &WorkerProfile,
        _provisioning: &EngineProvisioning,
    ) -> EngineDetection {
        EngineDetection {
            kind: EngineKind::Vllm,
            availability: EngineAvailability::Available,
            version: Some("fixture".to_string()),
            reason: "fixture driver is ready".to_string(),
            remediation: None,
        }
    }

    async fn provision(
        &self,
        request: &ProvisionRequest,
    ) -> Result<ProvisionedEngine, EngineDriverError> {
        Ok(ProvisionedEngine {
            kind: EngineKind::Vllm,
            executable: "/fixture/vllm".into(),
            version: Some("fixture".to_string()),
            fingerprint: request.artifact.artifact_digest.clone(),
            provisioning: request.provisioning.clone(),
        })
    }

    async fn launch(
        &self,
        provisioned: &ProvisionedEngine,
        request: &sbproxy_model_host::LaunchRequest,
    ) -> Result<RunningEngine, EngineDriverError> {
        request.validate(EngineKind::Vllm)?;
        self.launches.lock().unwrap().push((
            request.deployment.clone(),
            request.artifact.snapshot_path.clone(),
            request.artifact.metadata.trust.clone(),
        ));
        Ok(RunningEngine {
            deployment: request.deployment.clone(),
            generation: request.generation,
            kind: provisioned.kind,
            port: request.port,
            accelerator: request.accelerator,
            selected_devices: request.selected_devices.clone(),
            started_at_ms: 1,
            artifact_digest: request.artifact.artifact_digest.clone(),
            engine_version: provisioned.version.clone(),
            memory: request.fit.memory.clone(),
            process: Arc::new(ManagerFixtureProcess {
                stopped: AtomicBool::new(false),
            }),
        })
    }

    async fn health(&self, _running: &RunningEngine) -> Result<EngineHealth, EngineDriverError> {
        Ok(EngineHealth::Ready)
    }

    async fn shutdown(
        &self,
        running: RunningEngine,
        grace: Duration,
    ) -> Result<(), EngineDriverError> {
        running.process.shutdown(grace).await
    }
}

#[tokio::test]
async fn production_preparer_launches_only_a_verified_local_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    std::fs::create_dir_all(&source).unwrap();
    let config = br#"{"hidden_size":16,"num_hidden_layers":2,"num_attention_heads":2,"num_key_value_heads":2,"max_position_embeddings":128}"#;
    let weights = b"fixture safe tensor bytes";
    std::fs::write(source.join("config.json"), config).unwrap();
    std::fs::write(source.join("model.safetensors"), weights).unwrap();
    let digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    let catalog = Catalog::from_yaml(&format!(
        r#"
schema_version: 2
catalog_revision: fixture-runtime-v2
models:
  fixture-model:
    params: 1K
    license: apache-2.0
    family: fixture
    context_length: 128
    variants:
      - id: safe
        format: safetensors
        quant: bf16
        engines: [vllm]
        source: "file:{}"
        revision: 1111111111111111111111111111111111111111
        files:
          - path: config.json
            sha256: {}
            size_bytes: {}
          - path: model.safetensors
            sha256: {}
            size_bytes: {}
        requirements:
          accelerators: [cpu]
          min_memory_bytes: 1
        stability: preview
        certification: fixture
"#,
        source.display(),
        digest(config),
        config.len(),
        digest(weights),
        weights.len(),
    ))
    .unwrap();
    let cache = directory.path().join("cache");
    let artifacts =
        Arc::new(ArtifactManager::new(&cache, Arc::new(UnavailableArtifactTransport)).unwrap());
    let probe = Arc::new(StaticGpuProbe::new(vec![GpuDescriptor {
        index: 0,
        vendor: GpuVendor::Cpu,
        name: "fixture CPU".to_string(),
        total_vram_bytes: 8 * 1024 * 1024 * 1024,
        free_vram_bytes: 8 * 1024 * 1024 * 1024,
        compute_utilization: None,
        memory_occupancy: Some(0.0),
        compute_capability: None,
        supports_fp8: false,
        mem_bandwidth_gbps: None,
    }]));
    let launches = Arc::new(Mutex::new(Vec::new()));
    let drivers = BTreeMap::from([(
        EngineKind::Vllm,
        Arc::new(ProductionFixtureDriver {
            launches: launches.clone(),
        }) as Arc<dyn EngineDriver>,
    )]);
    let preparer = Arc::new(
        ProductionDeploymentPreparer::new(
            Arc::new(catalog.clone()),
            artifacts,
            probe,
            Arc::new(ProductionFixtureMetadata),
            NetworkPolicy::Denied,
        )
        .with_drivers(drivers),
    );
    let manager = ModelRuntimeManager::new(catalog.catalog_revision.clone(), preparer).unwrap();
    let mut host = ModelHostControlConfig::default();
    host.cache.directory = Some(cache.display().to_string());
    host.deployments.insert(
        "fixture".to_string(),
        ManagedDeploymentConfig {
            model: "fixture-model".to_string(),
            variant: Some("safe".to_string()),
            warm: false,
            engine: ManagedEngineChoice::Vllm,
            ..serde_yaml::from_str("model: fixture-model").unwrap()
        },
    );
    let desired = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "fixture-config".to_string(),
            canonical: Some(host),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog,
    )
    .unwrap();

    manager.reconcile(desired).await.unwrap();
    let assigned = manager.status("fixture").await.unwrap();
    assert_eq!(
        assigned.state,
        sbproxy_model_host::DeploymentRuntimeState::Assigned
    );
    assert_eq!(assigned.engine, Some(EngineKind::Vllm));
    assert_eq!(
        assigned.driver_availability,
        Some(EngineAvailability::Available)
    );
    assert_eq!(assigned.active_requests, 0);
    assert_eq!(assigned.queued_requests, 0);
    assert_eq!(assigned.selected_devices, Vec::<u32>::new());
    assert!(assigned.artifact_digest.is_some());
    assert!(assigned.job_id.is_none());

    manager.cache("fixture").await.unwrap();
    let cached = manager.status("fixture").await.unwrap();
    assert_eq!(
        cached.state,
        sbproxy_model_host::DeploymentRuntimeState::Cached
    );
    assert!(cached.memory.is_some());
    assert!(cached.job_id.is_some());

    let running = manager.ensure_ready("fixture").await.unwrap();
    assert_eq!(running.kind, EngineKind::Vllm);
    let ready = manager.status("fixture").await.unwrap();
    assert_eq!(
        ready.state,
        sbproxy_model_host::DeploymentRuntimeState::Ready
    );
    assert_eq!(ready.artifact_digest, Some(running.artifact_digest.clone()));
    assert_eq!(ready.memory, Some(running.memory.clone()));
    assert!(ready.reason_code.is_none());
    let launches = launches.lock().unwrap();
    assert_eq!(launches.len(), 1);
    assert_eq!(launches[0].0, "fixture");
    assert_eq!(launches[0].2, "verified");
    assert!(launches[0].1.starts_with(cache.join("snapshots")));
}

#[tokio::test]
async fn manager_admission_drains_queued_work_and_waits_for_the_active_permit() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer);
    let mut desired = manager_desired("admission", &[("a", false, 30)], 2);
    desired
        .deployments
        .get_mut("a")
        .unwrap()
        .desired
        .max_concurrency = Some(1);
    desired
        .deployments
        .get_mut("a")
        .unwrap()
        .desired
        .max_queue_depth = 1;
    desired
        .revision
        .deployments
        .get_mut("a")
        .unwrap()
        .max_concurrency = Some(1);
    desired
        .revision
        .deployments
        .get_mut("a")
        .unwrap()
        .max_queue_depth = 1;
    manager.reconcile(desired).await.unwrap();

    let active = manager
        .admit("a", sbproxy_model_host::PriorityClass::Standard)
        .await
        .unwrap();
    manager.ensure_ready("a").await.unwrap();
    let active_status = manager.status("a").await.unwrap();
    assert_eq!(active_status.active_requests, 1);
    assert_eq!(active_status.queued_requests, 0);
    let queued_manager = manager.clone();
    let queued = tokio::spawn(async move {
        queued_manager
            .admit("a", sbproxy_model_host::PriorityClass::Interactive)
            .await
    });
    tokio::task::yield_now().await;
    let queued_status = manager.status("a").await.unwrap();
    assert_eq!(queued_status.active_requests, 1);
    assert_eq!(queued_status.queued_requests, 1);
    let drain_manager = manager.clone();
    let drain = tokio::spawn(async move { drain_manager.drain("a").await });
    tokio::task::yield_now().await;
    assert_eq!(
        queued.await.unwrap().unwrap_err().reason,
        sbproxy_model_host::AdmissionReason::Draining
    );
    assert!(!drain.is_finished());
    let draining_status = manager.status("a").await.unwrap();
    assert_eq!(
        draining_status.state,
        sbproxy_model_host::DeploymentRuntimeState::Draining
    );
    assert_eq!(draining_status.active_requests, 1);
    assert_eq!(draining_status.queued_requests, 0);
    drop(active);
    let report = drain.await.unwrap().unwrap();
    assert_eq!(report.cancelled_queued, 1);
    assert_eq!(report.remaining_active, 0);
    assert_eq!(
        manager.status("a").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Stopped
    );
}

#[tokio::test]
async fn manager_capacity_evicts_only_after_active_protection_is_released() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let observer = Arc::new(ManagerTelemetryObserver::default());
    let manager = Arc::new(
        ModelRuntimeManager::new_with_device_capacities(
            Catalog::builtin().catalog_revision,
            preparer.clone(),
            BTreeMap::from([(0, 1)]),
        )
        .unwrap()
        .with_observer(observer.clone()),
    );
    manager
        .reconcile(manager_desired(
            "capacity",
            &[("a", false, 30), ("b", false, 30)],
            2,
        ))
        .await
        .unwrap();
    let active = manager
        .admit("a", sbproxy_model_host::PriorityClass::Standard)
        .await
        .unwrap();
    manager.ensure_ready("a").await.unwrap();
    assert!(matches!(
        manager
            .ensure_ready_for("b", sbproxy_model_host::PriorityClass::Interactive)
            .await,
        Err(RuntimeManagerError::Admission(ref rejection))
            if rejection.reason == sbproxy_model_host::AdmissionReason::InsufficientCapacity
    ));
    assert_ne!(
        manager.status("b").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Preparing,
        "a rejected placement must not leave a phantom preparation"
    );
    assert_eq!(
        observer.rejections.lock().unwrap().as_slice(),
        &[(
            "b".to_string(),
            sbproxy_model_host::PriorityClass::Interactive,
            sbproxy_model_host::AdmissionReason::InsufficientCapacity,
        )]
    );
    drop(active);

    manager.ensure_ready("b").await.unwrap();
    assert_eq!(
        preparer.facts.stops.lock().unwrap().get("a").copied(),
        Some(1)
    );
}

#[tokio::test]
async fn manager_enforces_the_canonical_global_resident_limit() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = ModelRuntimeManager::new_with_device_capacities(
        Catalog::builtin().catalog_revision,
        preparer.clone(),
        BTreeMap::from([(0, 2)]),
    )
    .unwrap();
    let mut desired = manager_desired("resident-limit", &[("a", false, 30), ("b", false, 30)], 2);
    desired.control.cache.max_resident_models = Some(1);
    manager.reconcile(desired).await.unwrap();

    manager.ensure_ready("a").await.unwrap();
    manager.ensure_ready("b").await.unwrap();

    assert_eq!(manager.residency_reservations().await.len(), 1);
    assert_eq!(
        preparer.facts.stops.lock().unwrap().get("a").copied(),
        Some(1)
    );
}

#[tokio::test]
async fn lowering_the_resident_limit_evicts_idle_preserved_slots() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = ModelRuntimeManager::new_with_device_capacities(
        Catalog::builtin().catalog_revision,
        preparer.clone(),
        BTreeMap::from([(0, 2)]),
    )
    .unwrap();
    manager
        .reconcile(manager_desired(
            "resident-limit-unbounded",
            &[("a", false, 30), ("b", false, 30)],
            2,
        ))
        .await
        .unwrap();
    manager.ensure_ready("a").await.unwrap();
    manager.ensure_ready("b").await.unwrap();
    assert_eq!(manager.residency_reservations().await.len(), 2);

    let mut limited = manager_desired(
        "resident-limit-one",
        &[("a", false, 30), ("b", false, 30)],
        2,
    );
    limited.control.cache.max_resident_models = Some(1);
    let report = manager.reconcile(limited).await.unwrap();

    assert_eq!(
        report.plan.preserved,
        vec!["a".to_string(), "b".to_string()]
    );
    assert_eq!(manager.residency_reservations().await.len(), 1);
    assert_eq!(
        preparer.facts.stops.lock().unwrap().get("a").copied(),
        Some(1)
    );
}

#[tokio::test]
async fn policy_eviction_owns_the_idle_generation_before_shutdown() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = Arc::new(
        ModelRuntimeManager::new_with_device_capacities(
            Catalog::builtin().catalog_revision,
            preparer.clone(),
            BTreeMap::from([(0, 2)]),
        )
        .unwrap(),
    );
    manager
        .reconcile(manager_desired(
            "policy-owner",
            &[("a", false, 30), ("b", false, 30)],
            2,
        ))
        .await
        .unwrap();
    manager.ensure_ready("a").await.unwrap();
    manager.ensure_ready("b").await.unwrap();
    preparer.facts.block_stop.store(true, Ordering::SeqCst);

    let mut limited = manager_desired(
        "policy-owner-limited",
        &[("a", false, 30), ("b", false, 30)],
        2,
    );
    limited.control.cache.max_resident_models = Some(1);
    let reconcile_manager = manager.clone();
    let reconcile = tokio::spawn(async move { reconcile_manager.reconcile(limited).await });
    preparer.facts.stop_entered.notified().await;

    assert_eq!(
        manager.status("a").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Draining
    );
    assert!(matches!(
        manager
            .admit("a", sbproxy_model_host::PriorityClass::Standard)
            .await,
        Err(ref rejection)
            if rejection.reason == sbproxy_model_host::AdmissionReason::Draining
    ));
    preparer.facts.stop_release.notify_one();
    reconcile.await.unwrap().unwrap();
    assert_eq!(manager.residency_reservations().await.len(), 1);
}

#[tokio::test]
async fn failed_limit_eviction_keeps_the_physical_generation_accounted() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = ModelRuntimeManager::new_with_device_capacities(
        Catalog::builtin().catalog_revision,
        preparer.clone(),
        BTreeMap::from([(0, 2)]),
    )
    .unwrap();
    manager
        .reconcile(manager_desired(
            "resident-limit-failure",
            &[("a", false, 30), ("b", false, 30)],
            2,
        ))
        .await
        .unwrap();
    let a_generation = manager.ensure_ready("a").await.unwrap().generation;
    manager.ensure_ready("b").await.unwrap();
    preparer
        .facts
        .fail_stop
        .lock()
        .unwrap()
        .insert("a".to_string());

    let mut limited = manager_desired(
        "resident-limit-failure-retained",
        &[("a", false, 30), ("b", false, 30)],
        2,
    );
    limited.control.cache.max_resident_models = Some(1);
    let report = manager.reconcile(limited).await.unwrap();
    assert!(report.retire_failures.contains_key("a"));
    let reservations = manager.residency_reservations().await;
    assert_eq!(
        reservations.len(),
        2,
        "accounting must retain a process that failed its policy eviction"
    );
    assert!(reservations.iter().any(|reservation| {
        reservation.deployment == "a"
            && reservation.generation == a_generation
            && reservation.protection.draining
    }));

    preparer.facts.fail_stop.lock().unwrap().remove("a");
    manager.maintenance_tick(tokio::time::Instant::now()).await;
    let reservations = manager.residency_reservations().await;
    assert_eq!(reservations.len(), 1);
    assert_eq!(reservations[0].deployment, "b");
}

#[tokio::test]
async fn operator_stop_clears_a_failed_policy_retirement_before_restart() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = ModelRuntimeManager::new_with_device_capacities(
        Catalog::builtin().catalog_revision,
        preparer.clone(),
        BTreeMap::from([(0, 2)]),
    )
    .unwrap();
    manager
        .reconcile(manager_desired(
            "operator-retirement-owner",
            &[("a", false, 30), ("b", false, 30)],
            2,
        ))
        .await
        .unwrap();
    manager.ensure_ready("a").await.unwrap();
    manager.ensure_ready("b").await.unwrap();
    preparer
        .facts
        .fail_stop
        .lock()
        .unwrap()
        .insert("a".to_string());

    let mut limited = manager_desired(
        "operator-retirement-failed",
        &[("a", false, 30), ("b", false, 30)],
        2,
    );
    limited.control.cache.max_resident_models = Some(1);
    let report = manager.reconcile(limited).await.unwrap();
    assert!(report.retire_failures.contains_key("a"));

    preparer.facts.fail_stop.lock().unwrap().remove("a");
    manager.stop("a").await.unwrap();
    let restarted = manager.ensure_ready("a").await.unwrap();
    manager.maintenance_tick(tokio::time::Instant::now()).await;
    let status = manager.status("a").await.unwrap();
    assert_eq!(
        status.state,
        sbproxy_model_host::DeploymentRuntimeState::Ready,
        "maintenance must not act on a retiree registration cleared by operator stop"
    );
    assert_eq!(status.port, Some(restarted.port));
}

#[tokio::test]
async fn manager_honors_legacy_never_eviction_policy() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = ModelRuntimeManager::new_with_device_capacities(
        Catalog::builtin().catalog_revision,
        preparer.clone(),
        BTreeMap::from([(0, 1)]),
    )
    .unwrap();
    let mut config: ModelHostConfig = serde_yaml::from_str(
        r#"
eviction: never
models:
  - model: qwen3-8b
    name: first
  - model: qwen3-14b
    name: second
"#,
    )
    .unwrap();
    config.eviction = EvictionPolicy::Never;
    let desired = compile_desired_state(
        input(
            None,
            Vec::new(),
            vec![LegacyServeInput {
                origin: "origin-a".to_string(),
                provider: "local".to_string(),
                config,
            }],
        ),
        &Catalog::builtin(),
    )
    .unwrap();
    let first = desired
        .route_for("origin-a", "local", "first")
        .unwrap()
        .deployment
        .clone();
    let second = desired
        .route_for("origin-a", "local", "second")
        .unwrap()
        .deployment
        .clone();
    manager.reconcile(desired).await.unwrap();

    manager.ensure_ready(&first).await.unwrap();
    let blocked = manager.ensure_ready(&second).await.unwrap_err();

    assert!(matches!(
        blocked,
        RuntimeManagerError::Admission(ref rejection)
            if rejection.reason == sbproxy_model_host::AdmissionReason::InsufficientCapacity
                && rejection.detail.contains("eviction policy is never")
    ));
    assert!(preparer.facts.stops.lock().unwrap().get(&first).is_none());
}

#[tokio::test]
async fn failed_eviction_shutdown_restores_the_previous_capacity_owner() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = ModelRuntimeManager::new_with_device_capacities(
        Catalog::builtin().catalog_revision,
        preparer.clone(),
        BTreeMap::from([(0, 1)]),
    )
    .unwrap();
    manager
        .reconcile(manager_desired(
            "eviction-rollback",
            &[("a", false, 30), ("b", false, 30)],
            2,
        ))
        .await
        .unwrap();
    manager.ensure_ready("a").await.unwrap();
    preparer
        .facts
        .fail_stop
        .lock()
        .unwrap()
        .insert("a".to_string());

    assert!(matches!(
        manager.ensure_ready("b").await,
        Err(RuntimeManagerError::Engine(ref error))
            if error.reason() == EngineFailureReason::EngineInternal
    ));
    assert_eq!(
        manager.status("a").await.unwrap().state,
        sbproxy_model_host::DeploymentRuntimeState::Failed
    );
    assert!(matches!(
        manager.ensure_ready("b").await,
        Err(RuntimeManagerError::Admission(ref rejection))
            if rejection.reason == sbproxy_model_host::AdmissionReason::InsufficientCapacity
    ));
    assert!(preparer.facts.starts.lock().unwrap().get("b").is_none());
}

#[tokio::test]
async fn warm_revision_that_cannot_fit_atomically_preserves_the_prior_revision() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = ModelRuntimeManager::new_with_device_capacities(
        Catalog::builtin().catalog_revision,
        preparer.clone(),
        BTreeMap::from([(0, 1)]),
    )
    .unwrap();
    let error = manager
        .reconcile(manager_desired(
            "too-large",
            &[("a", true, 30), ("b", true, 30)],
            2,
        ))
        .await
        .expect_err("both warm generations cannot share one byte");
    assert!(matches!(
        error,
        RuntimeManagerError::Admission(ref rejection)
            if rejection.reason == sbproxy_model_host::AdmissionReason::InsufficientCapacity
    ));
    assert_eq!(manager.current_revision(), 0);
    assert!(manager.current_desired().deployments.is_empty());
    assert!(
        preparer.facts.starts.lock().unwrap().is_empty(),
        "capacity must be proven before any staged warm engine starts"
    );
}

#[tokio::test]
async fn rolling_warm_replacement_requires_capacity_for_both_generations() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = ModelRuntimeManager::new_with_device_capacities(
        Catalog::builtin().catalog_revision,
        preparer.clone(),
        BTreeMap::from([(0, 1)]),
    )
    .unwrap();
    manager
        .reconcile(rollout_desired(
            "rolling-old",
            ManagedRolloutPolicy::Rolling,
            1,
        ))
        .await
        .unwrap();
    let old = manager.ensure_ready("a").await.unwrap();

    let error = manager
        .reconcile(rollout_desired(
            "rolling-new",
            ManagedRolloutPolicy::Rolling,
            2,
        ))
        .await
        .expect_err("rolling replacement cannot displace its old generation");

    assert!(matches!(
        error,
        RuntimeManagerError::Admission(ref rejection)
            if rejection.reason == sbproxy_model_host::AdmissionReason::InsufficientCapacity
    ));
    assert_eq!(manager.current_revision(), 1);
    assert_eq!(manager.ensure_ready("a").await.unwrap().port, old.port);
    assert_eq!(
        preparer.facts.starts.lock().unwrap().get("a").copied(),
        Some(1),
        "failed capacity preflight must not start the replacement"
    );
}

#[tokio::test]
async fn recreate_warm_replacement_stops_old_before_starting_new() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = ModelRuntimeManager::new_with_device_capacities(
        Catalog::builtin().catalog_revision,
        preparer.clone(),
        BTreeMap::from([(0, 1)]),
    )
    .unwrap();
    manager
        .reconcile(rollout_desired(
            "recreate-old",
            ManagedRolloutPolicy::Rolling,
            1,
        ))
        .await
        .unwrap();
    let old = manager.ensure_ready("a").await.unwrap();

    manager
        .reconcile(rollout_desired(
            "recreate-new",
            ManagedRolloutPolicy::Recreate,
            2,
        ))
        .await
        .unwrap();
    let new = manager.ensure_ready("a").await.unwrap();

    assert_ne!(new.generation, old.generation);
    let events = preparer.facts.events.lock().unwrap();
    let old_stop = events
        .iter()
        .position(|event| event == "stop:a:1")
        .expect("old generation stop");
    let new_start = events
        .iter()
        .position(|event| event == "start:a:2")
        .expect("new generation start");
    assert!(
        old_stop < new_start,
        "recreate must stop before replacement launch"
    );
}

#[tokio::test]
async fn failed_recreate_warm_replacement_restarts_the_old_generation() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = ModelRuntimeManager::new_with_device_capacities(
        Catalog::builtin().catalog_revision,
        preparer.clone(),
        BTreeMap::from([(0, 1)]),
    )
    .unwrap();
    manager
        .reconcile(rollout_desired(
            "rollback-old",
            ManagedRolloutPolicy::Rolling,
            1,
        ))
        .await
        .unwrap();
    let old_generation = manager.ensure_ready("a").await.unwrap().generation;
    preparer
        .facts
        .fail_start_once
        .lock()
        .unwrap()
        .insert("a".to_string());

    manager
        .reconcile(rollout_desired(
            "rollback-new",
            ManagedRolloutPolicy::Recreate,
            2,
        ))
        .await
        .expect_err("replacement launch fails");

    assert_eq!(manager.current_revision(), 1);
    let restored = manager.ensure_ready("a").await.unwrap();
    assert_eq!(restored.generation, old_generation);
    assert_eq!(
        preparer.facts.starts.lock().unwrap().get("a").copied(),
        Some(3),
        "initial start, failed replacement, and rollback restart"
    );
}

#[tokio::test(start_paused = true)]
async fn manager_keep_alive_starts_after_the_last_permit_completes() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    let manager = manager(preparer);
    manager
        .reconcile(manager_desired("keep-alive", &[("a", false, 30)], 2))
        .await
        .unwrap();
    let permit = manager
        .admit("a", sbproxy_model_host::PriorityClass::Standard)
        .await
        .unwrap();
    manager.ensure_ready("a").await.unwrap();
    tokio::time::advance(Duration::from_secs(100)).await;
    assert!(manager
        .maintenance_tick(tokio::time::Instant::now())
        .await
        .is_empty());
    drop(permit);
    tokio::time::advance(Duration::from_secs(29)).await;
    assert!(manager
        .maintenance_tick(tokio::time::Instant::now())
        .await
        .is_empty());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        manager.maintenance_tick(tokio::time::Instant::now()).await,
        vec!["a"]
    );
}

#[tokio::test(start_paused = true)]
async fn manager_keep_alive_never_reaps_a_failed_generation() {
    let preparer = FixturePreparer::new(Duration::from_millis(1));
    preparer
        .facts
        .fail_start
        .lock()
        .unwrap()
        .insert("a".to_string());
    let manager = manager(preparer);
    manager
        .reconcile(manager_desired("failed-keep-alive", &[("a", false, 30)], 2))
        .await
        .unwrap();
    let permit = manager
        .admit("a", sbproxy_model_host::PriorityClass::Standard)
        .await
        .unwrap();
    assert!(manager.ensure_ready("a").await.is_err());
    drop(permit);
    tokio::time::advance(Duration::from_secs(30)).await;

    assert!(manager
        .maintenance_tick(tokio::time::Instant::now())
        .await
        .is_empty());
    let failed = manager.status("a").await.unwrap();
    assert_eq!(
        failed.state,
        sbproxy_model_host::DeploymentRuntimeState::Failed
    );
    assert_eq!(failed.reason_code.as_deref(), Some("engine_early_exit"));
    assert!(failed
        .last_error
        .as_ref()
        .is_some_and(|error| error.len() <= 512));
}
