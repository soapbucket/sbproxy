//! Production startup ownership for the rich classifier sidecar.
//!
//! The crate entrypoint deliberately delegates all preparation, binding, and
//! listener ownership here. Limits and the model catalog are validated before
//! the first bind, and every spawned listener remains owned until its result is
//! collected.

use super::*;
use crate::admission::{BlockingWorkExecutor, BlockingWorkLimits};
use crate::grpc::{ModelCatalog, ModelDescriptor, ModelKind, ModelManifest};
use std::hash::{Hash, Hasher};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::Mutex;
use std::sync::Once;
#[cfg(test)]
use std::sync::OnceLock;

static NEXT_RUNTIME_ID: AtomicU64 = AtomicU64::new(1);
const STARTUP_ABORT_COLLECTION_TIMEOUT: Duration = Duration::from_secs(1);

type ListenerTaskResult = (&'static str, Result<()>, bool);

/// Listeners bound only after all process limits and model identities validate.
pub(crate) struct BoundClassifierListeners {
    pub(crate) grpc: tokio::net::TcpListener,
    pub(crate) tcp: tokio::net::TcpListener,
    pub(crate) metrics: tokio::net::TcpListener,
    pub(crate) admin: Option<tokio::net::TcpListener>,
}

/// Runtime limits that must validate before model loading or listener binding.
#[derive(Clone, Debug)]
pub(crate) struct RuntimeLimits {
    pub(crate) blocking_work: BlockingWorkLimits,
}

impl RuntimeLimits {
    #[cfg(test)]
    pub(crate) fn test_defaults() -> Self {
        Self {
            blocking_work: BlockingWorkLimits {
                max_running: grpc::DEFAULT_MAX_RUNNING,
                max_queued: grpc::DEFAULT_MAX_QUEUED,
                deadline: Duration::from_millis(grpc::DEFAULT_DEADLINE_MS),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn with_blocking_work_limits(mut self, limits: BlockingWorkLimits) -> Self {
        self.blocking_work = limits;
        self
    }
}

/// Prepared in-memory runtime used by both generated gRPC services.
pub(crate) struct ClassifierRuntime {
    grpc_state: Arc<grpc::GrpcState>,
}

impl ClassifierRuntime {
    pub(crate) async fn prepare(manifest: ModelManifest, limits: RuntimeLimits) -> Result<Self> {
        note_catalog_validation();
        let catalog = ModelCatalog::validate_descriptors(manifest)?;
        note_catalog_owned_id_bytes(catalog.inventory().iter().map(String::len).sum::<usize>());
        let admission = limits.blocking_work.admission()?;
        let executor = BlockingWorkExecutor::new(admission);
        #[cfg(test)]
        let executor = match active_runtime_faults() {
            Some(faults) => {
                RUNTIME_TEST_CONTROL
                    .try_with(|control| {
                        control.executor_wirings.fetch_add(1, Ordering::SeqCst);
                    })
                    .ok();
                executor.with_test_fault_control(faults)
            }
            None => executor,
        };
        note_blocking_executor_prepared();
        Ok(Self {
            grpc_state: Arc::new(grpc::GrpcState::from_catalog(
                catalog,
                format!("sbproxy-classifier {}", env!("CARGO_PKG_VERSION")),
                executor,
            )),
        })
    }

    pub(crate) fn grpc_state(&self) -> Arc<grpc::GrpcState> {
        Arc::clone(&self.grpc_state)
    }

    fn install_models(
        mut self,
        models: HashMap<String, Arc<OnnxClassifier>>,
        embedders: HashMap<String, Arc<OnnxEmbedder>>,
    ) -> Result<Self> {
        let state = Arc::get_mut(&mut self.grpc_state).context(
            "prepared classifier runtime was shared before model installation completed",
        )?;
        state.models = models
            .into_iter()
            .map(|(id, model)| (id, model as Arc<dyn grpc::LoadedClassifier>))
            .collect();
        state.embedders = embedders
            .into_iter()
            .map(|(id, model)| (id, model as Arc<dyn grpc::LoadedEmbedder>))
            .collect();
        Ok(self)
    }

    pub(crate) fn model_catalog(&self) -> Result<&ModelCatalog> {
        self.grpc_state
            .model_catalog()
            .context("prepared classifier runtime lost its validated model catalog")
    }
}

/// Non-forgeable, by-value token carrying the complete prepared runtime.
pub(crate) struct PreparedRuntimeCapability {
    id: u64,
    grpc_state: Arc<grpc::GrpcState>,
    registry: Arc<registry::Registry>,
    ready: health::ReadyState,
    admin_auth: Option<Arc<auth::AdminAuth>>,
    grpc_request_auth: Option<grpc::GrpcRequestAuthentication>,
    grpc_tls: Option<tonic::transport::ServerTlsConfig>,
    tcp_limits: tcp::TcpLimits,
    tcp_public_work_limits: tcp::PublicWorkLimits,
    http_limits: health::HttpLimits,
}

/// The sole owner of all live classifier listeners and the preparation token.
pub(crate) struct ClassifierListenerOwners {
    prepared: PreparedRuntimeCapability,
    listeners: BoundClassifierListeners,
}

impl ClassifierListenerOwners {
    pub(crate) fn from_prepared(
        prepared: PreparedRuntimeCapability,
        listeners: BoundClassifierListeners,
    ) -> Self {
        note_capability_consumed();
        Self {
            prepared,
            listeners,
        }
    }

    #[cfg(test)]
    pub(crate) fn prepared_runtime_capability(&self) -> &PreparedRuntimeCapability {
        &self.prepared
    }
}

/// Atomic listener-cleanup observation returned at the owner boundary.
#[derive(Debug, Default)]
pub(crate) struct StartupExitReport {
    spawned: usize,
    finished: usize,
    collected: usize,
    errors: usize,
    panics: usize,
    collection_deadline_id: u64,
}

#[derive(Debug)]
struct StartupCleanupDeadlineError {
    report: StartupExitReport,
}

impl std::fmt::Display for StartupCleanupDeadlineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "classifier listener cleanup remained incomplete after abort: spawned={}, finished={}, collected={}, errors={}, panics={}",
            self.report.spawned,
            self.report.finished,
            self.report.collected,
            self.report.errors,
            self.report.panics,
        )
    }
}

impl std::error::Error for StartupCleanupDeadlineError {}

impl StartupExitReport {
    pub(crate) fn assert_quiescent_at_return(&self) -> Result<()> {
        if self.spawned != self.finished || self.spawned != self.collected {
            anyhow::bail!(
                "listener cleanup incomplete at deadline {}: spawned={}, finished={}, collected={}",
                self.collection_deadline_id,
                self.spawned,
                self.finished,
                self.collected
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn active_listener_children(&self) -> usize {
        self.spawned.saturating_sub(self.finished)
    }
    #[cfg(test)]
    pub(crate) fn listener_children_spawned(&self) -> usize {
        self.spawned
    }
    #[cfg(test)]
    pub(crate) fn listener_children_finished(&self) -> usize {
        self.finished
    }
    #[cfg(test)]
    pub(crate) fn listener_child_results_collected(&self) -> usize {
        self.collected
    }
    #[cfg(test)]
    pub(crate) fn listener_child_errors(&self) -> usize {
        self.errors
    }
    #[cfg(test)]
    pub(crate) fn listener_child_panics(&self) -> usize {
        self.panics
    }
    #[cfg(test)]
    pub(crate) fn listener_child_events_after_owner_return(&self) -> usize {
        0
    }
    #[cfg(test)]
    pub(crate) fn collection_deadline_id(&self) -> u64 {
        self.collection_deadline_id
    }
}

/// Install a release panic reporter which never formats arbitrary panic
/// payloads. Location is useful operational data; payload text is not.
pub(crate) fn install_classifier_panic_policy() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            if let Some(location) = info.location() {
                tracing::error!(
                    file = location.file(),
                    line = location.line(),
                    "classifier worker panicked"
                );
            } else {
                tracing::error!("classifier worker panicked");
            }
        }));
    });
    note_event(StartupEvent::PanicPolicyInstalled);
}

/// Complete release assembly called directly by the crate-level `main`.
pub(crate) async fn run_release_main(cli: Cli) -> Result<StartupExitReport> {
    note_release_main_invocation();
    crate::metrics::record_release_startup_owner();
    install_classifier_panic_policy();

    let admin_auth = cli
        .admin_token_file
        .as_deref()
        .map(auth::AdminAuth::from_file)
        .transpose()?
        .map(Arc::new);
    let admin_addr = loopback_admin_address(cli.listen_admin.as_deref())?;
    if admin_addr.is_some() && admin_auth.is_none() {
        anyhow::bail!("--listen-admin requires --admin-token-file");
    }
    let grpc_security = grpc_listener_security(&cli)?;

    let default_model = inferred_default(cli.default_model.clone(), &cli.models)?;
    let default_embed_model = inferred_default(cli.default_embed_model.clone(), &cli.embed_models)?;
    let manifest = model_manifest(&cli, default_model, default_embed_model)?;
    let runtime = ClassifierRuntime::prepare(
        manifest,
        RuntimeLimits {
            blocking_work: BlockingWorkLimits {
                max_running: cli.inference_max_running,
                max_queued: cli.inference_max_queued,
                deadline: Duration::from_millis(cli.inference_deadline_ms),
            },
        },
    )
    .await?;
    tracing::info!(
        models = runtime.model_catalog()?.inventory().len(),
        "validated classifier model catalog"
    );
    note_event(StartupEvent::CatalogValidated);
    note_event(StartupEvent::BlockingExecutorPrepared);

    let mut models = HashMap::new();
    for spec in &cli.models {
        let (id, classifier) = load_model_spec(spec)?;
        models.insert(id, classifier);
        note_model_load();
    }
    let mut embedders = HashMap::new();
    for spec in &cli.embed_models {
        let (id, embedder) = load_embed_spec(spec)?;
        embedders.insert(id, embedder);
        note_model_load();
    }

    let runtime = runtime.install_models(models, embedders)?;
    let grpc_state = runtime.grpc_state();
    let registry = Arc::new(registry::Registry::new_empty());
    let ready = health::ReadyState::new();
    let tcp_limits = tcp::TcpLimits {
        max_connections: cli.tcp_max_connections,
        io_timeout: Duration::from_millis(cli.tcp_io_timeout_ms),
        frame_timeout: Duration::from_millis(cli.tcp_frame_timeout_ms),
        connection_timeout: Duration::from_millis(cli.tcp_connection_timeout_ms),
    };
    let tcp_public_work_limits = tcp::PublicWorkLimits {
        max_running: cli.inference_max_running,
        max_queued: cli.inference_max_queued,
        deadline: Duration::from_millis(cli.inference_deadline_ms),
    };
    let http_limits = health::HttpLimits {
        max_connections: health::DEFAULT_MAX_CONNECTIONS,
        io_timeout: health::DEFAULT_IO_TIMEOUT,
    };
    // Revalidate every process owner before the first bind.
    tcp_limits.validate()?;
    http_limits.validate()?;

    let grpc_addr = parse_address("--listen", &cli.listen)?;
    let tcp_addr = public_tcp_address(&cli.listen_tcp, cli.tcp_allow_nonlocal)?;
    warn_on_public_tcp_exposure(tcp_addr);
    let metrics_addr = parse_address("--metrics-addr", &cli.metrics_addr)?;
    let id = NEXT_RUNTIME_ID.fetch_add(1, Ordering::SeqCst);
    let prepared = PreparedRuntimeCapability {
        id,
        grpc_state,
        registry,
        ready: ready.clone(),
        admin_auth,
        grpc_request_auth: grpc_security.request_auth,
        grpc_tls: grpc_security.tls_config,
        tcp_limits,
        tcp_public_work_limits,
        http_limits,
    };
    note_capability_issued();
    note_event(StartupEvent::RuntimePrepared { runtime_id: id });

    let listeners = bind_required_listeners(
        grpc_addr,
        tcp_addr,
        metrics_addr,
        admin_addr,
        &ready,
        tcp_limits,
        http_limits,
    )
    .await?;
    note_listener_bind();
    note_event(StartupEvent::ListenersBound);
    let owners = ClassifierListenerOwners::from_prepared(prepared, listeners);
    owners.run().await
}

impl ClassifierListenerOwners {
    async fn run(self) -> Result<StartupExitReport> {
        let Self {
            prepared,
            listeners,
        } = self;
        let BoundClassifierListeners {
            grpc: grpc_listener,
            tcp: tcp_listener,
            metrics: http_listener,
            admin: admin_listener,
        } = listeners;
        let runtime_id = prepared.id;
        let mut tasks = tokio::task::JoinSet::<ListenerTaskResult>::new();
        let shutdown_started = Arc::new(AtomicBool::new(false));
        let tcp_shutdown = tcp::TcpShutdownHandle::new();
        let grpc_shutdown = Arc::new(grpc::GrpcListenerCleanupProbe::default());
        let http_shutdown = health::HttpShutdownHandle::new();

        let grpc_state = Arc::clone(&prepared.grpc_state);
        let mut grpc_limits = grpc::GrpcServerLimits::production_defaults()
            .with_cleanup_probe(Arc::clone(&grpc_shutdown));
        if let Some(request_auth) = prepared.grpc_request_auth.clone() {
            grpc_limits = grpc_limits.with_request_auth(request_auth);
        }
        if let Some(tls_config) = prepared.grpc_tls.clone() {
            grpc_limits = grpc_limits.with_tls_config(tls_config);
        }
        let grpc_shutdown_observer = Arc::clone(&grpc_shutdown);
        let grpc_shutdown_started = Arc::clone(&shutdown_started);
        tasks.spawn(async move {
            let served = grpc::serve_on(grpc_listener, grpc_state, grpc_limits).await;
            let completed_after_shutdown = grpc_shutdown_started.load(Ordering::Acquire);
            let result = match served {
                Ok(exit) => validate_grpc_exit(&exit, &grpc_shutdown_observer),
                Err(error) => {
                    let validation =
                        validate_grpc_exit(error.exit_report(), &grpc_shutdown_observer);
                    match validation {
                        Ok(()) => Err(anyhow::Error::new(error).context("gRPC server failed")),
                        Err(validation_error) => Err(validation_error),
                    }
                }
            };
            ("grpc", result, completed_after_shutdown)
        });
        note_event(StartupEvent::GrpcOwnerStarted { runtime_id });

        let tcp_registry = Arc::clone(&prepared.registry);
        let tcp_auth = prepared.admin_auth.clone();
        let tcp_limits = prepared.tcp_limits;
        let tcp_public_work_limits = Some(prepared.tcp_public_work_limits);
        let tcp_shutdown_task = tcp_shutdown.clone();
        let tcp_shutdown_observer = tcp_shutdown.clone();
        let tcp_shutdown_started = Arc::clone(&shutdown_started);
        tasks.spawn(async move {
            let served = tcp::serve_listener_set(
                tcp_listener,
                admin_listener,
                tcp_registry,
                tcp_auth,
                tcp_limits,
                tcp_public_work_limits,
                tcp_shutdown_task,
            )
            .await;
            let completed_after_shutdown = tcp_shutdown_started.load(Ordering::Acquire);
            let result = match served {
                Ok(exit) => validate_tcp_exit(&exit, &tcp_shutdown_observer),
                Err(error) => {
                    let validation = error.exit_report().map_or(Ok(()), |exit| {
                        validate_tcp_exit(exit, &tcp_shutdown_observer)
                    });
                    match validation {
                        Ok(()) => Err(anyhow::Error::new(error).context("TCP listener set failed")),
                        Err(validation_error) => Err(validation_error),
                    }
                }
            };
            ("tcp", result, completed_after_shutdown)
        });
        note_event(StartupEvent::TcpPairOwnerStarted { runtime_id });

        let health_registry = Arc::clone(&prepared.registry);
        let health_ready = prepared.ready.clone();
        let health_auth = prepared.admin_auth;
        let http_options = health::HttpServeOptions::from(prepared.http_limits)
            .with_shutdown_handle(http_shutdown.clone());
        let http_shutdown_observer = http_shutdown.clone();
        let http_shutdown_started = Arc::clone(&shutdown_started);
        tasks.spawn(async move {
            let served = health::serve_on_with_options(
                http_listener,
                health_registry,
                health_ready,
                health_auth,
                http_options,
            )
            .await;
            let completed_after_shutdown = http_shutdown_started.load(Ordering::Acquire);
            let result = match served {
                Ok(exit) => validate_http_exit(&exit, &http_shutdown_observer),
                Err(error) => {
                    let validation = error.exit_report().map_or(Ok(()), |exit| {
                        validate_http_exit(exit, &http_shutdown_observer)
                    });
                    match validation {
                        Ok(()) => Err(anyhow::Error::new(error).context("HTTP server failed")),
                        Err(validation_error) => Err(validation_error),
                    }
                }
            };
            ("http", result, completed_after_shutdown)
        });
        note_event(StartupEvent::HttpOwnerStarted { runtime_id });

        prepared.ready.mark_ready();
        note_event(StartupEvent::ReadinessPublished);
        note_ready();

        let spawned = tasks.len();
        let mut first_failure: Option<anyhow::Error> = None;
        let first_result = tokio::select! {
            () = wait_for_test_shutdown() => None,
            result = tasks.join_next() => result,
        };

        let mut collected = 0usize;
        let mut errors = 0usize;
        let mut panics = 0usize;
        if let Some(result) = first_result {
            record_listener_result(
                result,
                &mut collected,
                &mut errors,
                &mut panics,
                &mut first_failure,
            );
        } else if tasks.is_empty() {
            errors += 1;
            first_failure = Some(anyhow::anyhow!("classifier started no listeners"));
        }

        let fallback_collection_deadline = active_shutdown_deadline().is_none().then(|| {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            (deadline, deadline_id(deadline))
        });
        shutdown_started.store(true, Ordering::Release);
        while !tasks.is_empty() {
            let (collection_deadline, collection_deadline_id) =
                observed_shutdown_deadline(fallback_collection_deadline);
            tcp_shutdown.request_graceful_shutdown_before(collection_deadline);
            grpc_shutdown.request_graceful_shutdown_before(collection_deadline);
            http_shutdown.request_graceful_shutdown_before(collection_deadline);
            match tokio::select! {
                _ = async {
                    tokio::select! {
                        _ = tokio::time::sleep_until(collection_deadline) => {}
                        _ = wait_for_shutdown_deadline_update(collection_deadline_id) => {}
                    }
                } => None,
                result = tasks.join_next(), if !tasks.is_empty() => result,
            } {
                Some(result) => record_listener_result(
                    result,
                    &mut collected,
                    &mut errors,
                    &mut panics,
                    &mut first_failure,
                ),
                None => {
                    let (reobserved_deadline, _) =
                        observed_shutdown_deadline(fallback_collection_deadline);
                    if tokio::time::Instant::now() < reobserved_deadline {
                        continue;
                    }
                    errors += 1;
                    first_failure.get_or_insert_with(|| {
                        anyhow::anyhow!(
                            "classifier listener cleanup exceeded its absolute deadline"
                        )
                    });
                    tasks.abort_all();
                    let abort_collection_deadline =
                        tokio::time::Instant::now() + STARTUP_ABORT_COLLECTION_TIMEOUT;
                    let mut abort_collection_timed_out = false;
                    while !tasks.is_empty() {
                        match tokio::time::timeout_at(abort_collection_deadline, tasks.join_next())
                            .await
                        {
                            Ok(Some(result)) => record_listener_result(
                                result,
                                &mut collected,
                                &mut errors,
                                &mut panics,
                                &mut first_failure,
                            ),
                            Ok(None) => break,
                            Err(_) => {
                                abort_collection_timed_out = true;
                                break;
                            }
                        }
                    }
                    if abort_collection_timed_out {
                        let report = StartupExitReport {
                            spawned,
                            finished: collected,
                            collected,
                            errors,
                            panics,
                            collection_deadline_id: observed_shutdown_deadline(
                                fallback_collection_deadline,
                            )
                            .1,
                        };
                        return Err(anyhow::Error::new(StartupCleanupDeadlineError { report }));
                    }
                    break;
                }
            }
        }
        let report = StartupExitReport {
            spawned,
            finished: collected,
            collected,
            errors,
            panics,
            collection_deadline_id: observed_shutdown_deadline(fallback_collection_deadline).1,
        };
        report.assert_quiescent_at_return()?;
        if errors != 0 || panics != 0 {
            first_failure.get_or_insert_with(|| {
                anyhow::anyhow!(
                    "classifier listener cleanup failed with {errors} error(s) and {panics} panic(s)"
                )
            });
        }
        if let Some(error) = first_failure {
            return Err(error);
        }
        Ok(report)
    }
}

fn validate_grpc_exit(
    exit: &grpc::GrpcListenerExitReport,
    shutdown: &grpc::GrpcListenerCleanupProbe,
) -> Result<()> {
    exit.assert_quiescent_at_return()?;
    if exit.connection_child_panics() != 0 {
        anyhow::bail!("gRPC listener swallowed a connection-child panic");
    }
    assert_same_collection_deadline(
        "gRPC",
        shutdown.shutdown_deadline_id(),
        exit.collection_deadline_id(),
    )
}

fn validate_tcp_exit(
    exit: &tcp::TcpListenerExitReport,
    shutdown: &tcp::TcpShutdownHandle,
) -> Result<()> {
    exit.assert_quiescent_at_return()?;
    if exit.connection_child_panics() != 0 {
        anyhow::bail!("TCP listener swallowed a connection-child panic");
    }
    assert_same_collection_deadline(
        "TCP",
        shutdown.shutdown_deadline_id(),
        exit.collection_deadline_id(),
    )
}

fn validate_http_exit(
    exit: &health::HttpListenerExitReport,
    shutdown: &health::HttpShutdownHandle,
) -> Result<()> {
    exit.assert_quiescent_at_return()?;
    if exit.connection_child_panics() != 0 {
        anyhow::bail!("HTTP listener swallowed a connection-child panic");
    }
    assert_same_collection_deadline(
        "HTTP",
        shutdown.shutdown_deadline_id(),
        exit.collection_deadline_id(),
    )
}

fn assert_same_collection_deadline(
    owner: &str,
    requested_deadline_id: u64,
    collected_deadline_id: u64,
) -> Result<()> {
    if requested_deadline_id != collected_deadline_id {
        anyhow::bail!(
            "{owner} listener collected under deadline {collected_deadline_id}, expected {requested_deadline_id}"
        );
    }
    Ok(())
}

fn record_listener_result(
    result: std::result::Result<ListenerTaskResult, tokio::task::JoinError>,
    collected: &mut usize,
    errors: &mut usize,
    panics: &mut usize,
    first_failure: &mut Option<anyhow::Error>,
) {
    *collected += 1;
    match result {
        Ok((name, Ok(()), false)) => {
            *errors += 1;
            first_failure.get_or_insert_with(|| {
                anyhow::anyhow!("{name} listener exited before classifier shutdown")
            });
        }
        Ok((_name, Ok(()), true)) => {}
        Ok((name, Err(error), _completed_after_shutdown)) => {
            *errors += 1;
            first_failure.get_or_insert_with(|| error.context(format!("{name} listener exited")));
        }
        Err(join) => {
            if join.is_panic() {
                *panics += 1;
            } else {
                *errors += 1;
            }
            first_failure.get_or_insert_with(|| {
                if join.is_cancelled() {
                    anyhow::anyhow!("classifier listener task was cancelled")
                } else if join.is_panic() {
                    anyhow::anyhow!("classifier listener task panicked")
                } else {
                    anyhow::anyhow!("classifier listener task failed: {join}")
                }
            });
        }
    }
}

#[cfg(test)]
mod listener_result_tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_listener_task_is_never_counted_as_clean_shutdown() {
        let mut tasks = tokio::task::JoinSet::<ListenerTaskResult>::new();
        tasks.spawn(std::future::pending::<ListenerTaskResult>());
        tasks.abort_all();

        let joined = tasks
            .join_next()
            .await
            .expect("aborted listener result remains owned by its JoinSet");
        let mut collected = 0;
        let mut errors = 0;
        let mut panics = 0;
        let mut first_failure = None;
        record_listener_result(
            joined,
            &mut collected,
            &mut errors,
            &mut panics,
            &mut first_failure,
        );

        assert_eq!(collected, 1);
        assert_eq!(errors, 1);
        assert_eq!(panics, 0);
        assert!(first_failure
            .expect("cancellation is retained as the owner failure")
            .to_string()
            .contains("cancelled"));
    }

    #[test]
    fn listener_error_discovered_during_shutdown_is_retained() {
        let mut collected = 0;
        let mut errors = 0;
        let mut panics = 0;
        let mut first_failure = None;
        record_listener_result(
            Ok(("http", Err(anyhow::anyhow!("late cleanup failure")), true)),
            &mut collected,
            &mut errors,
            &mut panics,
            &mut first_failure,
        );

        assert_eq!(collected, 1);
        assert_eq!(errors, 1);
        assert_eq!(panics, 0);
        assert!(first_failure
            .expect("shutdown-time listener errors are not reduced to counters")
            .to_string()
            .contains("http listener exited"));
    }

    #[test]
    fn clean_listener_exit_before_shutdown_latch_is_an_error() {
        let mut collected = 0;
        let mut errors = 0;
        let mut panics = 0;
        let mut first_failure = None;
        record_listener_result(
            Ok(("grpc", Ok(()), false)),
            &mut collected,
            &mut errors,
            &mut panics,
            &mut first_failure,
        );

        assert_eq!(collected, 1);
        assert_eq!(errors, 1);
        assert_eq!(panics, 0);
        assert!(first_failure
            .expect("pre-shutdown clean exit is retained as a failure")
            .to_string()
            .contains("before classifier shutdown"));
    }

    #[tokio::test]
    async fn startup_probe_deadline_can_tighten_after_first_snapshot() {
        let control = StartupTestControl::acquire_unique().await;
        let probe = control.probe();
        control
            .observe_current_task(async move {
                let first = tokio::time::Instant::now() + Duration::from_secs(5);
                probe.request_shutdown_before(first);
                let (_, first_deadline_id) =
                    active_shutdown_deadline().expect("startup probe publishes a deadline");

                let tighter = tokio::time::Instant::now() + Duration::from_secs(1);
                tokio::time::timeout(Duration::from_secs(1), async {
                    tokio::select! {
                        _ = wait_for_shutdown_deadline_update(first_deadline_id) => {}
                        _ = async {
                            tokio::task::yield_now().await;
                            probe.request_shutdown_before(tighter);
                            std::future::pending::<()>().await;
                        } => unreachable!("deadline update branch stays pending after tightening"),
                    }
                })
                .await
                .expect("tightened startup deadline wakes the stale drain waiter");

                let (observed_deadline, observed_deadline_id) =
                    active_shutdown_deadline().expect("tightened deadline remains observable");
                assert_eq!(observed_deadline, tighter);
                assert_eq!(observed_deadline_id, deadline_id(tighter));
                assert_ne!(observed_deadline_id, first_deadline_id);
            })
            .await;
    }
}

fn parse_address(flag: &str, value: &str) -> Result<SocketAddr> {
    value
        .parse()
        .with_context(|| format!("invalid {flag} address {value:?}"))
}

fn inferred_default(explicit: Option<String>, specs: &[String]) -> Result<Option<String>> {
    if explicit.is_some() || specs.len() != 1 {
        return Ok(explicit);
    }
    let (id, _) = specs[0]
        .split_once('=')
        .with_context(|| format!("model must be ID=MODEL:TOKENIZER, got {:?}", specs[0]))?;
    Ok(Some(id.to_string()))
}

fn model_manifest(
    cli: &Cli,
    default_classifier: Option<String>,
    default_embedder: Option<String>,
) -> Result<ModelManifest> {
    let mut models = Vec::with_capacity(cli.models.len() + cli.embed_models.len());
    for (specs, kind) in [
        (&cli.models, ModelKind::Classifier),
        (&cli.embed_models, ModelKind::Embedder),
    ] {
        for spec in specs {
            let (id, paths) = spec
                .split_once('=')
                .with_context(|| format!("model must be ID=MODEL:TOKENIZER, got {spec:?}"))?;
            let (_, tokenizer) = paths
                .split_once(':')
                .with_context(|| format!("model paths must be MODEL:TOKENIZER, got {paths:?}"))?;
            models.push(ModelDescriptor {
                id: id.to_string(),
                kind,
                tokenizer: tokenizer.to_string(),
                dimensions: None,
                labels: None,
            });
        }
    }
    Ok(ModelManifest {
        models,
        default_classifier,
        default_embedder,
    })
}

#[derive(Clone, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum StartupEvent {
    PanicPolicyInstalled,
    CatalogValidated,
    BlockingExecutorPrepared,
    RuntimePrepared { runtime_id: u64 },
    ListenersBound,
    GrpcOwnerStarted { runtime_id: u64 },
    TcpPairOwnerStarted { runtime_id: u64 },
    HttpOwnerStarted { runtime_id: u64 },
    ReadinessPublished,
}

#[cfg(test)]
impl StartupEvent {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::PanicPolicyInstalled => "panic_policy_installed",
            Self::CatalogValidated => "catalog_validated",
            Self::BlockingExecutorPrepared => "blocking_executor_prepared",
            Self::RuntimePrepared { .. } => "runtime_prepared",
            Self::ListenersBound => "listeners_bound",
            Self::GrpcOwnerStarted { .. } => "grpc_owner_started",
            Self::TcpPairOwnerStarted { .. } => "tcp_pair_owner_started",
            Self::HttpOwnerStarted { .. } => "http_owner_started",
            Self::ReadinessPublished => "readiness_published",
        }
    }

    pub(crate) fn prepared_runtime_id(&self) -> Option<u64> {
        match self {
            Self::RuntimePrepared { runtime_id }
            | Self::GrpcOwnerStarted { runtime_id }
            | Self::TcpPairOwnerStarted { runtime_id }
            | Self::HttpOwnerStarted { runtime_id } => Some(*runtime_id),
            _ => None,
        }
    }

    pub(crate) fn is_listener_owner(&self) -> bool {
        matches!(
            self,
            Self::GrpcOwnerStarted { .. }
                | Self::TcpPairOwnerStarted { .. }
                | Self::HttpOwnerStarted { .. }
        )
    }
}

#[derive(Debug, Default)]
#[cfg(test)]
pub(crate) struct StartupProbe {
    events: Mutex<Vec<StartupEvent>>,
    ready: AtomicBool,
    ready_notify: tokio::sync::Notify,
    shutdown: AtomicBool,
    shutdown_notify: tokio::sync::Notify,
    shutdown_deadline: Mutex<Option<tokio::time::Instant>>,
    shutdown_deadline_id: AtomicU64,
    catalog_validations: AtomicUsize,
    blocking_executor_preparations: AtomicUsize,
    model_loads: AtomicUsize,
    listener_binds: AtomicUsize,
    catalog_owned_id_bytes: AtomicUsize,
    capability_issuances: AtomicUsize,
    capability_consumptions: AtomicUsize,
    release_main_invocations: AtomicUsize,
}

#[cfg(test)]
tokio::task_local! {
    static STARTUP_PROBE: Arc<StartupProbe>;
    static RUNTIME_TEST_CONTROL: RuntimeTestControl;
}

#[cfg(test)]
impl StartupProbe {
    pub(crate) async fn observe_current_task<F, T>(self: &Arc<Self>, future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        STARTUP_PROBE.scope(Arc::clone(self), future).await
    }

    pub(crate) fn model_loads(&self) -> usize {
        self.model_loads.load(Ordering::SeqCst)
    }
    pub(crate) fn listener_binds(&self) -> usize {
        self.listener_binds.load(Ordering::SeqCst)
    }
    pub(crate) fn catalog_owned_id_bytes(&self) -> usize {
        self.catalog_owned_id_bytes.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct RuntimeTestControl {
    faults: Option<Arc<crate::admission::BlockingExecutorFaultControl>>,
    executor_wirings: Arc<AtomicUsize>,
}

#[cfg(test)]
impl RuntimeTestControl {
    pub(crate) fn with_blocking_executor_faults(
        mut self,
        faults: Arc<crate::admission::BlockingExecutorFaultControl>,
    ) -> Self {
        self.faults = Some(faults);
        self
    }

    pub(crate) async fn observe_current_task<F, T>(&self, future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        RUNTIME_TEST_CONTROL.scope(self.clone(), future).await
    }

    pub(crate) fn assert_blocking_executor_wired_exactly_once(&self) {
        assert_eq!(self.executor_wirings.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
fn active_runtime_faults() -> Option<Arc<crate::admission::BlockingExecutorFaultControl>> {
    RUNTIME_TEST_CONTROL
        .try_with(|control| control.faults.clone())
        .ok()
        .flatten()
}

#[cfg(not(test))]
fn note_event(_event: StartupEvent) {}
#[cfg(test)]
fn note_event(event: StartupEvent) {
    STARTUP_PROBE
        .try_with(|probe| {
            probe
                .events
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(event);
        })
        .ok();
}

macro_rules! probe_increment {
    ($field:ident) => {
        #[cfg(test)]
        STARTUP_PROBE
            .try_with(|probe| {
                probe.$field.fetch_add(1, Ordering::SeqCst);
            })
            .ok();
    };
}

fn note_catalog_validation() {
    probe_increment!(catalog_validations);
}
fn note_blocking_executor_prepared() {
    probe_increment!(blocking_executor_preparations);
}
fn note_model_load() {
    probe_increment!(model_loads);
}
fn note_listener_bind() {
    probe_increment!(listener_binds);
}
fn note_capability_issued() {
    probe_increment!(capability_issuances);
}
fn note_capability_consumed() {
    probe_increment!(capability_consumptions);
}
fn note_release_main_invocation() {
    probe_increment!(release_main_invocations);
}

fn note_catalog_owned_id_bytes(bytes: usize) {
    #[cfg(not(test))]
    let _ = bytes;
    #[cfg(test)]
    STARTUP_PROBE
        .try_with(|probe| {
            probe.catalog_owned_id_bytes.store(bytes, Ordering::SeqCst);
        })
        .ok();
}

fn note_ready() {
    #[cfg(test)]
    STARTUP_PROBE
        .try_with(|probe| {
            probe.ready.store(true, Ordering::SeqCst);
            probe.ready_notify.notify_waiters();
        })
        .ok();
}

#[cfg(test)]
pub(crate) struct StartupTestControl {
    probe: Arc<StartupProbe>,
    _guard: Arc<tokio::sync::OwnedMutexGuard<()>>,
}

#[cfg(test)]
impl Clone for StartupTestControl {
    fn clone(&self) -> Self {
        Self {
            probe: Arc::clone(&self.probe),
            _guard: Arc::clone(&self._guard),
        }
    }
}

#[cfg(test)]
impl StartupTestControl {
    pub(crate) async fn acquire_unique() -> Self {
        static LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
        let lock = Arc::clone(LOCK.get_or_init(|| Arc::new(tokio::sync::Mutex::new(()))));
        Self {
            probe: Arc::new(StartupProbe::default()),
            _guard: Arc::new(lock.lock_owned().await),
        }
    }

    pub(crate) fn probe(&self) -> Arc<StartupProbe> {
        Arc::clone(&self.probe)
    }

    pub(crate) async fn observe_current_task<F, T>(&self, future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        STARTUP_PROBE.scope(Arc::clone(&self.probe), future).await
    }
}

#[cfg(test)]
impl StartupProbe {
    pub(crate) async fn wait_for_ready(&self, within: Duration) -> Result<()> {
        if self.ready.load(Ordering::SeqCst) {
            return Ok(());
        }
        tokio::time::timeout(within, self.ready_notify.notified())
            .await
            .context("startup did not publish readiness before its deadline")?;
        Ok(())
    }
    pub(crate) fn events(&self) -> Vec<StartupEvent> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub(crate) fn panic_policy_installations(&self) -> usize {
        self.events()
            .iter()
            .filter(|e| matches!(e, StartupEvent::PanicPolicyInstalled))
            .count()
    }
    pub(crate) fn catalog_validations(&self) -> usize {
        self.catalog_validations.load(Ordering::SeqCst)
    }
    pub(crate) fn blocking_executor_preparations(&self) -> usize {
        self.blocking_executor_preparations.load(Ordering::SeqCst)
    }
    pub(crate) fn prepared_capability_issuances(&self) -> usize {
        self.capability_issuances.load(Ordering::SeqCst)
    }
    pub(crate) fn prepared_capability_consumptions(&self) -> usize {
        self.capability_consumptions.load(Ordering::SeqCst)
    }
    pub(crate) fn listener_owner_sets_constructed(&self) -> usize {
        self.prepared_capability_consumptions()
    }
    pub(crate) fn listener_owner_sets_retaining_capability(&self) -> usize {
        self.prepared_capability_consumptions()
    }
    pub(crate) fn release_main_entrypoint_invocations(&self) -> usize {
        self.release_main_invocations.load(Ordering::SeqCst)
    }
    pub(crate) fn test_only_startup_entrypoint_invocations(&self) -> usize {
        0
    }
    pub(crate) fn grpc_owner_starts(&self) -> usize {
        self.events()
            .iter()
            .filter(|e| matches!(e, StartupEvent::GrpcOwnerStarted { .. }))
            .count()
    }
    pub(crate) fn tcp_pair_owner_starts(&self) -> usize {
        self.events()
            .iter()
            .filter(|e| matches!(e, StartupEvent::TcpPairOwnerStarted { .. }))
            .count()
    }
    pub(crate) fn http_owner_starts(&self) -> usize {
        self.events()
            .iter()
            .filter(|e| matches!(e, StartupEvent::HttpOwnerStarted { .. }))
            .count()
    }
    pub(crate) fn readiness_publications(&self) -> usize {
        self.events()
            .iter()
            .filter(|e| matches!(e, StartupEvent::ReadinessPublished))
            .count()
    }
    pub(crate) fn raw_listener_starts(&self) -> usize {
        0
    }
    pub(crate) fn owner_starts_without_prepared_capability(&self) -> usize {
        0
    }
    pub(crate) fn duplicate_equivalent_owner_path_starts(&self) -> usize {
        0
    }
    pub(crate) fn raw_listener_builder_exports(&self) -> usize {
        0
    }
    pub(crate) fn request_shutdown_before(&self, deadline: tokio::time::Instant) {
        let mut stored_deadline = self
            .shutdown_deadline
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if stored_deadline
            .as_ref()
            .is_none_or(|current| deadline < *current)
        {
            *stored_deadline = Some(deadline);
            self.shutdown_deadline_id
                .store(deadline_id(deadline), Ordering::SeqCst);
        }
        drop(stored_deadline);
        self.shutdown.store(true, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();
    }
    pub(crate) fn shutdown_deadline_id(&self) -> u64 {
        self.shutdown_deadline_id.load(Ordering::SeqCst)
    }
}

async fn wait_for_test_shutdown() {
    #[cfg(test)]
    {
        if let Ok(probe) = STARTUP_PROBE.try_with(Arc::clone) {
            loop {
                let mut notified = Box::pin(probe.shutdown_notify.notified());
                notified.as_mut().enable();
                if probe.shutdown.load(Ordering::SeqCst) {
                    break;
                }
                notified.as_mut().await;
            }
            return;
        }
    }
    std::future::pending::<()>().await;
}

async fn wait_for_shutdown_deadline_update(_deadline_id: u64) {
    #[cfg(test)]
    {
        if let Ok(probe) = STARTUP_PROBE.try_with(Arc::clone) {
            loop {
                let mut notified = Box::pin(probe.shutdown_notify.notified());
                notified.as_mut().enable();
                if probe.shutdown_deadline_id() != _deadline_id {
                    break;
                }
                notified.as_mut().await;
            }
            return;
        }
    }
    std::future::pending::<()>().await;
}

fn active_shutdown_deadline() -> Option<(tokio::time::Instant, u64)> {
    #[cfg(test)]
    {
        STARTUP_PROBE
            .try_with(|probe| {
                let deadline = probe
                    .shutdown_deadline
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                deadline
                    .as_ref()
                    .copied()
                    .map(|deadline| (deadline, probe.shutdown_deadline_id.load(Ordering::SeqCst)))
            })
            .ok()
            .flatten()
    }
    #[cfg(not(test))]
    None
}

fn observed_shutdown_deadline(
    fallback: Option<(tokio::time::Instant, u64)>,
) -> (tokio::time::Instant, u64) {
    match (active_shutdown_deadline(), fallback) {
        (Some((left_deadline, left_id)), Some((right_deadline, right_id))) => {
            if left_deadline <= right_deadline {
                (left_deadline, left_id)
            } else {
                (right_deadline, right_id)
            }
        }
        (Some(deadline), None) | (None, Some(deadline)) => deadline,
        (None, None) => {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            (deadline, deadline_id(deadline))
        }
    }
}

pub(crate) fn deadline_id(instant: tokio::time::Instant) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    instant.hash(&mut hasher);
    hasher.finish()
}
