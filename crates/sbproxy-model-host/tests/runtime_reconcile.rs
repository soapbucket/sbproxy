use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sbproxy_config::{
    ManagedDeploymentConfig, ManagedEngineChoice, ModelHostAuthority, ModelHostControlConfig,
};
use sbproxy_model_host::{
    compile_desired_state, ArtifactFormat, ArtifactManager, Catalog, DeploymentPrepareRequest,
    DeploymentPreparer, DeploymentSourceMode, DesiredStateError, EngineAvailability,
    EngineCapabilities, EngineDetection, EngineDriver, EngineDriverError, EngineFailureReason,
    EngineHealth, EngineKind, EngineProcess, EngineProvisioning, FileDeploymentRevisionStore,
    GpuDescriptor, GpuVendor, LegacyServeInput, ManagedProviderInput, ModelHostConfig,
    ModelMetadata, ModelMetadataProvider, ModelRuntimeManager, NetworkPolicy, OperationJob,
    PreparedDeploymentRuntime, ProductionDeploymentPreparer, ProvisionRequest, ProvisionedEngine,
    PullIntent, RunningEngine, RuntimeDesiredInput, RuntimeManagerError, StaticGpuProbe,
    UnavailableArtifactTransport, WorkerProfile,
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
    starts: Mutex<BTreeMap<String, usize>>,
    stops: Mutex<BTreeMap<String, usize>>,
    active_starts: AtomicUsize,
    max_active_starts: AtomicUsize,
    fail_start: Mutex<BTreeSet<String>>,
    next_port: AtomicU16,
}

struct FixturePreparedRuntime {
    id: String,
    generation: u64,
    facts: Arc<FixtureRuntimeFacts>,
    delay: Duration,
}

#[async_trait]
impl PreparedDeploymentRuntime for FixturePreparedRuntime {
    async fn start(&self, _intent: PullIntent) -> Result<RunningEngine, RuntimeManagerError> {
        {
            let mut starts = self.facts.starts.lock().unwrap();
            *starts.entry(self.id.clone()).or_default() += 1;
        }
        let active = self.facts.active_starts.fetch_add(1, Ordering::SeqCst) + 1;
        record_max(&self.facts.max_active_starts, active);
        tokio::time::sleep(self.delay).await;
        self.facts.active_starts.fetch_sub(1, Ordering::SeqCst);
        if self.facts.fail_start.lock().unwrap().contains(&self.id) {
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
        Ok(RunningEngine {
            deployment: self.id.clone(),
            generation: self.generation,
            kind: EngineKind::LlamaCpp,
            port,
            selected_devices: vec![0],
            started_at_ms: 1,
            artifact_digest: "a".repeat(64),
            process: Arc::new(ManagerFixtureProcess {
                stopped: AtomicBool::new(false),
            }),
        })
    }

    async fn stop(&self, _grace: Duration) -> Result<(), RuntimeManagerError> {
        let mut stops = self.facts.stops.lock().unwrap();
        *stops.entry(self.id.clone()).or_default() += 1;
        Ok(())
    }

    async fn reset(&self) -> Result<Option<OperationJob>, RuntimeManagerError> {
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
            selected_devices: request.selected_devices.clone(),
            started_at_ms: 1,
            artifact_digest: request.artifact.artifact_digest.clone(),
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
            warm: true,
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
    let running = manager.ensure_ready("fixture").await.unwrap();
    assert_eq!(running.kind, EngineKind::Vllm);
    let launches = launches.lock().unwrap();
    assert_eq!(launches.len(), 1);
    assert_eq!(launches[0].0, "fixture");
    assert_eq!(launches[0].2, "verified");
    assert!(launches[0].1.starts_with(cache.join("snapshots")));
}
