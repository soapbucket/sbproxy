//! `sbproxy-k8s-operator` binary.
//!
//! Watches `SBProxy` and `SBProxyConfig` resources and reconciles them into
//! Deployment / Service / ConfigMap triples in the configured namespace (or
//! cluster-wide when `--all-namespaces` is set). When an `SBProxy` enables
//! `spec.clustering`, the Deployment is swapped for a StatefulSet plus a
//! headless Service and a shared-key Secret so the replicas form a mesh.
//!
//! See `docs/kubernetes.md` for end-user instructions.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use futures::StreamExt;
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::core::v1::{ConfigMap, Pod, Secret, Service};
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Client, CustomResourceExt};
use sbproxy_k8s_operator::crd::{AdminAuthSecretRef, SBProxy, SBProxyConfig};
use sbproxy_k8s_operator::leader::{
    acquire_lease, build_identity, discover_namespace_default, renew_loop, LeaderConfig, WriteGate,
};
use sbproxy_k8s_operator::reconcile;

/// Lease name used for operator leader election. A constant so two operator
/// Deployments in the same namespace would deliberately fight for the same
/// lock (only one should be installed). Changing this is a breaking config
/// change.
const LEADER_LEASE_NAME: &str = "sbproxy-operator-leader";

/// Field manager string used for server-side-apply patches. Pinning this lets
/// kubectl `--field-manager` filtering distinguish operator-owned fields from
/// human edits.
const FIELD_MANAGER: &str = "sbproxy-k8s-operator";

/// Default graceful-shutdown drain budget when no env var is set.
/// Matches the binary's default and Kubernetes' default
/// `terminationGracePeriodSeconds` so the kubelet's pod-termination
/// grace window aligns with our drain budget.
const DEFAULT_SHUTDOWN_GRACE_MS: u64 = 30_000;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "sbproxy-k8s-operator",
    about = "OSS Kubernetes operator for sbproxy. Reconciles SBProxy + SBProxyConfig CRDs.",
    version
)]
struct Cli {
    /// Optional subcommand. If omitted, the operator runs the reconcile loop.
    #[command(subcommand)]
    command: Option<Command>,

    /// Namespace to watch. If omitted, watches all namespaces.
    #[arg(long, env = "SBPROXY_NAMESPACE")]
    namespace: Option<String>,

    /// Log level. Falls back to `RUST_LOG` if unset.
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,

    /// Disable leader election. Useful for `cargo run` against a kind cluster
    /// or for single-replica installs where the lock is overhead. Defaults
    /// to OFF (i.e. leader election is ON by default).
    #[arg(long)]
    no_leader_election: bool,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    /// Print the generated CRD YAML to stdout. Useful for embedding in Helm
    /// charts or for `kubectl apply -f -`.
    PrintCrds,
}

/// Per-controller context. Cloned into each reconcile invocation by kube-runtime.
struct Ctx {
    client: Client,

    /// Closed the moment this replica stops being able to prove it holds the
    /// leader Lease. Every reconcile checks it before its first write, so a
    /// deposed leader stops applying rather than relying on its controller
    /// task being aborted (a task is only cancelled at its next await point,
    /// and a request already dispatched to the apiserver still lands).
    /// [`WriteGate::always`] under `--no-leader-election`.
    write_gate: WriteGate,
}

#[tokio::main]
async fn main() {
    // rustls 0.23 requires the process to select a CryptoProvider before any
    // TLS machinery initialises, and the kube client speaks TLS to the API
    // server. Install ring to match the rest of the workspace; without this
    // the first reconcile panics and the operator manages nothing.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Init tracing once, regardless of subcommand.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Some(Command::PrintCrds) = cli.command {
        match print_crds() {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                tracing::error!(error = %e, "failed to print CRDs");
                std::process::exit(1);
            }
        }
    }

    // WOR-636: race the reconcile loop against SIGINT/SIGTERM so a
    // kubelet pod-eviction or `docker stop` produces a clean exit
    // with a structured shutdown log instead of an OS kill at
    // `terminationGracePeriodSeconds`.
    let grace = resolve_shutdown_grace_ms();
    let mut run_handle = tokio::spawn(run(cli));
    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    let exit_code = tokio::select! {
        biased;
        // The signal arm runs first under `biased`; if a signal
        // arrives concurrently with the controller exiting, we
        // prefer the signal path so the operator log makes the
        // shutdown cause unambiguous.
        signal_name = &mut shutdown => {
            tracing::info!(
                event = "shutdown_signal_received",
                signal = %signal_name,
                grace_ms = grace,
                "shutdown signal received; stopping reconcile loop"
            );
            // Race the controller's clean-exit path against the
            // grace budget. We do not abort the task on entry: the
            // controller's own cancellation path (loss of leader
            // lease, watcher stream drop) is the canonical
            // shutdown trigger, so we give it the grace window to
            // finish in flight. After the budget expires we abort
            // and exit 1 so the orchestrator sees an unclean
            // shutdown and can surface an alert.
            match tokio::time::timeout(
                std::time::Duration::from_millis(grace),
                &mut run_handle,
            )
            .await
            {
                Ok(Ok(Ok(()))) => {
                    tracing::info!(
                        event = "shutdown_complete",
                        signal = %signal_name,
                        "operator stopped cleanly"
                    );
                    0
                }
                Ok(Ok(Err(e))) => {
                    tracing::error!(
                        error = %e,
                        event = "shutdown_complete_with_error",
                        signal = %signal_name,
                        "operator stopped with error"
                    );
                    1
                }
                Ok(Err(join_err)) => {
                    tracing::error!(
                        error = %join_err,
                        event = "shutdown_complete_with_error",
                        signal = %signal_name,
                        "operator task join error"
                    );
                    1
                }
                Err(_) => {
                    run_handle.abort();
                    tracing::warn!(
                        event = "shutdown_grace_exceeded",
                        signal = %signal_name,
                        grace_ms = grace,
                        "grace period exceeded; forcing exit"
                    );
                    1
                }
            }
        }
        res = &mut run_handle => {
            match res {
                Ok(Ok(())) => 0,
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "operator exited with error");
                    1
                }
                Err(join_err) => {
                    tracing::error!(error = %join_err, "operator task join error");
                    1
                }
            }
        }
    };

    std::process::exit(exit_code);
}

/// Resolve `SBPROXY_SHUTDOWN_GRACE_MS`, falling back to
/// [`DEFAULT_SHUTDOWN_GRACE_MS`] when the env var is unset or
/// malformed. WOR-636.
fn resolve_shutdown_grace_ms() -> u64 {
    match std::env::var("SBPROXY_SHUTDOWN_GRACE_MS") {
        Ok(v) => match v.parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(
                    value = %v,
                    "SBPROXY_SHUTDOWN_GRACE_MS is not a non-negative integer; using default"
                );
                DEFAULT_SHUTDOWN_GRACE_MS
            }
        },
        Err(_) => DEFAULT_SHUTDOWN_GRACE_MS,
    }
}

/// Block until SIGINT or SIGTERM arrives, returning a static label
/// the caller can include in structured logs. WOR-636.
///
/// On non-Unix targets we fall back to `ctrl_c` only because
/// `SignalKind::terminate()` is Unix-only; Windows operators get
/// SIGINT-equivalent behaviour through Ctrl+C and the orchestrator
/// (Service Manager, container runtime) handles the analogue of
/// SIGTERM.
#[cfg(unix)]
async fn wait_for_shutdown_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};
    // Failing to install either handler is fatal in the same way
    // Pingora treats it: we cannot guarantee a clean shutdown
    // without the signal path, so propagate the panic upward and
    // let the orchestrator restart the pod.
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => "SIGINT",
        _ = sigterm.recv() => "SIGTERM",
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "ctrl_c"
}

/// Emit both CRDs as a single multi-document YAML stream.
fn print_crds() -> Result<()> {
    let sbproxy_crd = serde_yaml::to_string(&SBProxy::crd())?;
    let sbproxyconfig_crd = serde_yaml::to_string(&SBProxyConfig::crd())?;
    println!("---\n{sbproxy_crd}---\n{sbproxyconfig_crd}");
    Ok(())
}

/// Build a kube-runtime Controller that watches SBProxy primaries and the
/// owned Deployment / Service / ConfigMap children, plus SBProxyConfig as a
/// secondary trigger so config edits cascade to the proxy.
///
/// Leader election. When `--no-leader-election` is unset (the default) the
/// operator first acquires a `coordination.k8s.io/v1.Lease` named
/// [`LEADER_LEASE_NAME`] in the namespace returned by
/// `leader::discover_namespace_default`. While the lease is held the
/// controller runs; if the lease is lost (network partition, theft, an
/// apiserver that stops answering) the `WriteGate` shared with the renew
/// loop closes, the controller is cancelled, and the function returns
/// `Ok(())` so the binary exits with code 0. The pod is then restarted by the
/// Deployment and re-races for the lock. This matches the client-go pattern
/// used by kube-controller-manager / kubelet.
///
/// The gate, not the cancellation, is the fence. Aborting a task only takes
/// effect at its next await point, and an apply already dispatched to the
/// apiserver lands regardless, so a deposed leader that relied on the abort
/// alone kept writing for as long as its in-flight work took.
async fn run(cli: Cli) -> Result<()> {
    let client = Client::try_default().await.context(
        "failed to construct Kubernetes client; is KUBECONFIG / in-cluster auth wired up?",
    )?;

    if cli.no_leader_election {
        tracing::info!("leader election disabled (--no-leader-election)");
        // No election means no fence to enforce: a single replica is always
        // allowed to write.
        return run_controller(client, &cli, WriteGate::always()).await;
    }

    let lease_namespace = discover_namespace_default().await;
    let hostname = std::env::var("K8S_POD_NAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "sbproxy-operator".to_string());
    let identity = build_identity(&hostname);
    let leader_cfg = LeaderConfig {
        lease_name: LEADER_LEASE_NAME.to_string(),
        namespace: lease_namespace,
        identity,
    };

    tracing::info!(
        lease = %leader_cfg.lease_name,
        namespace = %leader_cfg.namespace,
        identity = %leader_cfg.identity,
        "racing for leader lease"
    );
    // Starts closed and is opened by the acquire below, so a reconcile can
    // never observe a leader that has not yet won the Lease.
    let write_gate = WriteGate::for_election();
    acquire_lease(&client, &leader_cfg, &write_gate).await;

    // Run the controller and the renew loop concurrently. The first task to
    // exit wins; we cancel the other and surface a step-down log.
    let controller_client = client.clone();
    let cli_clone = cli.clone();
    let controller_gate = write_gate.clone();
    let mut controller_handle = tokio::spawn(async move {
        run_controller(controller_client, &cli_clone, controller_gate).await
    });
    let mut renew_handle = tokio::spawn(renew_loop(client, leader_cfg, write_gate));

    tokio::select! {
        res = &mut controller_handle => {
            renew_handle.abort();
            match res {
                Ok(inner) => inner,
                Err(join_err) => Err(anyhow::anyhow!("controller task join error: {join_err}")),
            }
        }
        res = &mut renew_handle => {
            // Leadership ended. The renew loop already closed the write gate
            // before returning, so the controller is refusing applies by the
            // time we get here; the abort below only stops it re-queueing.
            // Exit 0 so the Deployment restarts the pod as a standby.
            controller_handle.abort();
            if let Err(join_err) = res {
                tracing::warn!(error = %join_err, "renew task join error");
            }
            tracing::info!("lost leader lease; stepping down");
            Ok(())
        }
    }
}

/// Run the kube-runtime `Controller` until it exits (which only happens when
/// the watcher's stream is dropped, e.g. via `controller_handle.abort()` from
/// the leader-election step-down path).
async fn run_controller(client: Client, cli: &Cli, write_gate: WriteGate) -> Result<()> {
    let sbproxy_api: Api<SBProxy> = match &cli.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let sbproxyconfig_api: Api<SBProxyConfig> = match &cli.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let deployments: Api<Deployment> = match &cli.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let statefulsets: Api<StatefulSet> = match &cli.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let services: Api<Service> = match &cli.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let configmaps: Api<ConfigMap> = match &cli.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    tracing::info!(
        namespace = cli.namespace.as_deref().unwrap_or("<all>"),
        "starting sbproxy operator reconciler"
    );

    Controller::new(sbproxy_api, WatcherConfig::default())
        .owns(deployments, WatcherConfig::default())
        .owns(statefulsets, WatcherConfig::default())
        .owns(services, WatcherConfig::default())
        .owns(configmaps, WatcherConfig::default())
        // Re-reconcile every SBProxy when any SBProxyConfig changes. Cheap to
        // keep simple: the controller queue dedupes anyway.
        .watches(sbproxyconfig_api, WatcherConfig::default(), |_cfg| {
            std::iter::empty::<kube::runtime::reflector::ObjectRef<SBProxy>>()
        })
        .run(
            reconcile_one,
            error_policy,
            Arc::new(Ctx { client, write_gate }),
        )
        .for_each(|res| async move {
            match res {
                Ok((obj_ref, _)) => {
                    tracing::debug!(?obj_ref, "reconciled");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "reconcile error");
                }
            }
        })
        .await;

    Ok(())
}

/// Reconcile a single SBProxy.
///
/// Steps:
/// 1. Resolve the referenced `SBProxyConfig` in the same namespace.
/// 2. Render the pod-facing `sb.yml` (verbatim, or with the injected
///    `proxy.cluster` block when clustering is enabled) and compute its
///    content hash.
/// 3. Server-side-apply the desired ConfigMap and Service.
/// 4. Reconcile the workload: a Deployment by default, or a StatefulSet
///    plus headless Service plus shared-key Secret when
///    `spec.clustering.enabled` is true. Flipping clustering deletes the
///    other workload kind before applying the new one.
/// 5. Decide between **hot-reload** and **rollout-restart**:
///    - Hot-reload (`POST /admin/reload`) when only `spec.config`
///      changed and `spec.adminAuthSecretRef` is set.
///    - Rollout-restart (apply the workload with a bumped config-hash
///      annotation) otherwise, or when hot-reload fails.
///
/// Hot-reload preserves pod identity and connection state. The
/// proxy serialises the reload via an internal single-flight guard
/// so simultaneous reloads (e.g. file-watcher + admin route) never
/// race.
async fn reconcile_one(sbproxy: Arc<SBProxy>, ctx: Arc<Ctx>) -> Result<Action, ReconcileError> {
    let start = std::time::Instant::now();
    let outcome = reconcile_one_inner(sbproxy, ctx).await;
    let elapsed = start.elapsed().as_secs_f64();
    let result_label = match &outcome {
        Ok(_) => "ok",
        Err(ReconcileError::Fenced) => "fenced",
        Err(ReconcileError::SuspendedOnFallback { .. }) => "suspended_on_fallback",
        Err(ReconcileError::MissingNamespace) | Err(ReconcileError::MissingName) => "crd_invalid",
        Err(ReconcileError::ConfigFetch { source, .. }) => match source {
            kube::Error::Api(e) if e.code == 409 => "conflict",
            _ => "backend_error",
        },
        Err(_) => "backend_error",
    };
    sbproxy_observe::metrics::record_operator_reconcile("sbproxy", result_label, elapsed);
    outcome
}

async fn reconcile_one_inner(
    sbproxy: Arc<SBProxy>,
    ctx: Arc<Ctx>,
) -> Result<Action, ReconcileError> {
    let ns = sbproxy
        .metadata
        .namespace
        .clone()
        .ok_or(ReconcileError::MissingNamespace)?;
    let name = sbproxy
        .metadata
        .name
        .clone()
        .ok_or(ReconcileError::MissingName)?;

    tracing::info!(name = %name, namespace = %ns, "reconciling SBProxy");

    // --- Resolve referenced SBProxyConfig ---
    let sbproxyconfig_api: Api<SBProxyConfig> = Api::namespaced(ctx.client.clone(), &ns);
    let cfg = sbproxyconfig_api
        .get(&sbproxy.spec.config_ref)
        .await
        .map_err(|e| ReconcileError::ConfigFetch {
            name: sbproxy.spec.config_ref.clone(),
            source: e,
        })?;

    // --- Preview-validate the referenced config ---
    // A malformed config must not roll out to every replica. Validate it here;
    // on failure record the error in status and requeue without touching the
    // Deployment, so operators see the problem on the CRD instead of a
    // crash-looping fleet.
    if let Err(msg) = reconcile::validate_config_yaml(&cfg.spec.config) {
        tracing::warn!(
            name = %name,
            namespace = %ns,
            error = %msg,
            "referenced SBProxyConfig failed validation; not rolling out"
        );
        patch_status(
            &ctx,
            &ns,
            &name,
            serde_json::json!({ "status": { "lastError": msg } }),
        )
        .await;
        sbproxy_observe::metrics::record_operator_config_delivery("refused_invalid_config");
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    // --- Refuse node-side auto-revert while this operator owns the config ---
    // A node that reverts its own configuration loses the race with the
    // next reconcile, which reapplies the ConfigMap it just reverted away
    // from. Accepting the key and losing that race, or refusing it
    // quietly, are both worse than saying so at validation time
    // (WOR-2467).
    // Recorded now and acted on *after* the condition block below. This
    // refusal is permanent until somebody edits the config, so returning
    // here left whatever `ConfigFallbackActive` an earlier pass wrote
    // frozen on the CR for the whole time: a node that had since cleared
    // its pin still read `True`, forever, with nothing to move it.
    let auto_revert_refusal =
        reconcile::check_auto_revert_under_operator_ownership(&cfg.spec.config).err();
    if let Some(msg) = auto_revert_refusal.as_deref() {
        tracing::warn!(
            name = %name,
            namespace = %ns,
            error = %msg,
            "referenced SBProxyConfig arms node-side auto_revert under operator ownership; not \
             rolling out"
        );
        patch_status(
            &ctx,
            &ns,
            &name,
            serde_json::json!({ "status": { "lastError": msg } }),
        )
        .await;
    }

    // --- Suspend config delivery while a pod is on its boot fallback ---
    // Boot fallback is local recovery, not drift. A node that could not
    // compile its configuration and came up on its last good one has not
    // diverged on purpose, and reapplying the document it could not
    // compile restarts it into the same crash loop. So the pin suspends
    // config delivery for this SBProxy and the condition says so; the
    // resume is `DELETE /admin/config/fallback` on the node, and the next
    // loop picks it up (WOR-2467).
    //
    // Behind the write gate: the probe sends this operator's admin
    // credential to each pod, and a replica that can no longer prove it
    // holds the lease has no business making that call. Its successor
    // will.
    require_write_gate(&ctx, &ns, &name)?;
    let fallbacks = read_fallback_reports(&ctx.client, &sbproxy, &ns).await;
    let suspension = reconcile::fallback_suspension(&fallbacks).cloned();
    let previous_condition = reconcile::current_fallback_condition(&sbproxy).cloned();
    let condition = reconcile::fallback_condition(
        &fallbacks,
        sbproxy.metadata.generation,
        &now_rfc3339(),
        previous_condition.as_ref(),
    );
    // Written only when it actually changed. An identical patch still
    // bumps `resourceVersion`, which this operator's own watch reads as
    // a change, so an unconditional write made every SBProxy re-enqueue
    // itself forever, and each self-triggered pass re-ran the
    // credentialed pod fan-out and a full server-side apply.
    if let Some(patch) =
        reconcile::fallback_condition_patch(&condition, previous_condition.as_ref())
    {
        patch_status(&ctx, &ns, &name, patch).await;
    }
    if let Some(pinned) = suspension.as_ref() {
        tracing::warn!(
            name = %name,
            namespace = %ns,
            pod = %pinned.pod,
            revision = pinned.report.revision,
            condition = reconcile::FALLBACK_CONDITION_TYPE,
            "SBProxy has a pod on a fallback configuration; suspending config delivery until \
             the pin is cleared"
        );
    }

    // Now the refusal acts, with the condition already refreshed above.
    // Counted, because the pass itself completes cleanly and
    // `sbproxy_operator_reconcile_total{result}` reads `ok` for it, so
    // without this series an SBProxy whose image bumps are all being
    // dropped looks healthy in operator metrics.
    if auto_revert_refusal.is_some() {
        sbproxy_observe::metrics::record_operator_config_delivery("refused_auto_revert");
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    // --- Refuse a fleet that drives ACME from a pod-local cert store ---
    // Config validation cannot catch this pairing: the replica count is on
    // the SBProxy, not in the sb.yml, so the operator is the only component
    // that sees both. Record it on the CR and requeue without rolling out,
    // the same way a malformed config is handled, so `kubectl describe`
    // shows why nothing moved instead of leaving a fleet to burn through
    // the CA's duplicate-certificate rate limit.
    if let Err(msg) = reconcile::check_acme_storage_for_replicas(&sbproxy, &cfg.spec.config) {
        tracing::warn!(
            name = %name,
            namespace = %ns,
            error = %msg,
            "multi-replica SBProxy drives ACME from a pod-local cert store; not rolling out"
        );
        patch_status(
            &ctx,
            &ns,
            &name,
            serde_json::json!({ "status": { "lastError": msg } }),
        )
        .await;
        sbproxy_observe::metrics::record_operator_config_delivery("refused_acme");
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    // --- Render the pod-facing sb.yml body ---
    // Non-clustered: the user document verbatim. Clustered: the user
    // document with the operator-owned `proxy.cluster` block injected.
    // The rollout hash covers the rendered body, so topology changes
    // (replica count changing the seed list, port changes) roll pods
    // even when the user document is untouched.
    let clustered = reconcile::clustering_enabled(&sbproxy);
    let body = if clustered {
        match reconcile::render_clustered_config(&sbproxy, &cfg.spec.config) {
            Ok(rendered) => rendered,
            Err(msg) => {
                tracing::warn!(
                    name = %name,
                    namespace = %ns,
                    error = %msg,
                    "failed to render clustered config; not rolling out"
                );
                patch_status(
                    &ctx,
                    &ns,
                    &name,
                    serde_json::json!({ "status": { "lastError": msg } }),
                )
                .await;
                sbproxy_observe::metrics::record_operator_config_delivery("refused_invalid_config");
                return Ok(Action::requeue(Duration::from_secs(60)));
            }
        }
    } else {
        cfg.spec.config.clone()
    };
    let hash = reconcile::config_hash(&body);

    // The config parsed and passed the guards, which is all this says. It
    // deliberately does not touch `configHash` or clear `lastError`: both of
    // those are documented as end-of-rollout signals, and nothing has been
    // applied yet. Stamping them here made a 403 on the ConfigMap patch read
    // as a completed rollout on the CR while every pod kept running the old
    // config.
    patch_status(&ctx, &ns, &name, reconcile::observed_status_patch(&hash)).await;

    // --- Apply the Service, which carries no configuration ---
    // Ahead of the suspension return on purpose. A Service is a name
    // and a port selector; recreating a deleted one cannot put a
    // document on a pod, and leaving it unreconciled while a single pod
    // sits pinned would turn a config incident into an outage.
    require_write_gate(&ctx, &ns, &name)?;
    let pp = PatchParams::apply(FIELD_MANAGER).force();
    let desired_svc = reconcile::desired_service(&sbproxy);
    let svc_api: Api<Service> = Api::namespaced(ctx.client.clone(), &ns);
    svc_api
        .patch(
            desired_svc
                .metadata
                .name
                .as_deref()
                .ok_or(ReconcileError::MissingName)?,
            &pp,
            &Patch::Apply(&desired_svc),
        )
        .await
        .map_err(ReconcileError::Apply)?;

    // --- Everything below this line puts configuration on a pod ---
    //
    // The ConfigMap is the document itself. The workload is how a pod
    // comes to read it: applying it rolls pods, and a rolled pod
    // re-reads the ConfigMap this operator is not allowed to update, so
    // it restarts into the very document that pinned it. So an image
    // bump and a replica change wait too, and `docs/kubernetes.md` says
    // so rather than promising only the ConfigMap is held.
    if suspension.is_some() {
        sbproxy_observe::metrics::record_operator_config_delivery("suspended_on_fallback");
        // The ordinary cadence rather than a back-off: the resume is an
        // operator clearing the pin on the node, and the condition has
        // to follow within one loop interval.
        return Ok(Action::requeue(Duration::from_secs(30)));
    }
    require_config_push_allowed(suspension.as_ref(), &ns, &name)?;
    let desired_cm = reconcile::desired_configmap_with_body(&sbproxy, &body);
    let cm_api: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &ns);
    cm_api
        .patch(
            desired_cm
                .metadata
                .name
                .as_deref()
                .ok_or(ReconcileError::MissingName)?,
            &pp,
            &Patch::Apply(&desired_cm),
        )
        .await
        .map_err(ReconcileError::Apply)?;

    // Bound rather than inlined so both calls stay on one line: the
    // write-order guard in this file's tests greps for
    // `reconcile_deployment_workload(&ctx,` and would stop seeing a
    // wrapped call.
    let pinned = suspension.as_ref();
    let pass = if clustered {
        reconcile_clustered_workload(&ctx, &sbproxy, &ns, &name, &hash, &pp, pinned).await?
    } else {
        reconcile_deployment_workload(&ctx, &sbproxy, &ns, &name, &hash, &pp, pinned).await?
    };

    // Everything landed. Only now is `configHash` the hash the pods are
    // actually running, which is what the CRD documents it as, and only now
    // is clearing `lastError` a true statement. Both writes are after the
    // `?`s above, so any failed apply leaves the previous values in place and
    // `observedConfigHash` ahead of `configHash` shows the rollout is stuck.
    patch_status(&ctx, &ns, &name, reconcile::rolled_out_status_patch(&hash)).await;
    // One count per pass, here and nowhere else. This line has counted
    // every delivery since the metric was added, including the ones the
    // hot-reload arms return early from, because those returns unwind
    // into the `?` above rather than out of this function. Recording a
    // second time down there made a clean hot reload count twice.
    sbproxy_observe::metrics::record_operator_config_delivery(if pass.unowned_skipped == 0 {
        "delivered"
    } else {
        "delivered_unowned_skipped"
    });

    Ok(pass.action)
}

/// Non-clustered workload path: the original Deployment flow, plus
/// garbage collection of clustered children left behind when a user
/// flips `spec.clustering.enabled` off. The StatefulSet is deleted
/// before the Deployment is applied so the two workloads never run
/// pods side by side under the same labels.
async fn reconcile_deployment_workload(
    ctx: &Ctx,
    sbproxy: &SBProxy,
    ns: &str,
    name: &str,
    hash: &str,
    pp: &PatchParams,
    suspension: Option<&reconcile::PodFallback>,
) -> Result<WorkloadPass, ReconcileError> {
    // The deletes below are the most destructive writes in the operator, so
    // the fence is re-checked here rather than trusted from the caller.
    require_write_gate(ctx, ns, name)?;
    require_config_push_allowed(suspension, ns, name)?;

    // --- GC clustered children on the clustering-off transition ---
    let sts_api: Api<StatefulSet> = Api::namespaced(ctx.client.clone(), ns);
    let sts_name = reconcile::statefulset_name(sbproxy);
    if sts_api.get_opt(&sts_name).await.unwrap_or(None).is_some() {
        tracing::info!(
            name = %name,
            namespace = %ns,
            statefulset = %sts_name,
            "clustering disabled; deleting StatefulSet before applying Deployment"
        );
        delete_ignoring_missing(sts_api.delete(&sts_name, &DeleteParams::default()).await)?;
    }
    let headless_api: Api<Service> = Api::namespaced(ctx.client.clone(), ns);
    let headless_name = reconcile::headless_service_name(sbproxy);
    if headless_api
        .get_opt(&headless_name)
        .await
        .unwrap_or(None)
        .is_some()
    {
        delete_ignoring_missing(
            headless_api
                .delete(&headless_name, &DeleteParams::default())
                .await,
        )?;
    }
    // The shared-key Secret is deliberately retained: re-enabling
    // clustering later reuses the same key, and the owner reference
    // still cascades it on SBProxy deletion.

    // --- Decide hot-reload vs rollout-restart ---
    let deploy_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), ns);
    let existing_deploy = deploy_api
        .get_opt(&reconcile::deployment_name(sbproxy))
        .await
        .unwrap_or(None);
    let template_hash = existing_deploy
        .as_ref()
        .and_then(reconcile::previous_config_hash);
    // What the pods are serving, which after a hot reload is ahead of what
    // their template says they were started with.
    let running_hash = reconcile::running_config_hash(sbproxy);

    // The pod template only moves when the pods have to. Building the
    // desired Deployment around that hash rather than around `hash` is what
    // keeps the pass after a hot reload from rolling the fleet for a config
    // it is already running.
    let desired_deploy = reconcile::desired_deployment(
        sbproxy,
        reconcile::rollout_config_hash(template_hash.as_deref(), running_hash, hash),
    );
    let deploy_name = desired_deploy
        .metadata
        .name
        .as_deref()
        .ok_or(ReconcileError::MissingName)?;

    let hot_reload_eligible = reconcile::should_hot_reload(
        sbproxy,
        existing_deploy.as_ref(),
        &desired_deploy,
        running_hash,
        hash,
    );

    // Re-checked after the reads above: a hot reload fans an authenticated
    // POST out to every proxy pod, and the apply below rolls them. Both
    // put configuration on a node, so the fallback pin gates them too.
    require_write_gate(ctx, ns, name)?;
    require_config_push_allowed(suspension, ns, name)?;

    if hot_reload_eligible {
        // Best-effort hot-reload across every proxy pod this operator's
        // workload created. If any of them fails, we fall through to the
        // rollout-restart path so the workload is never left in a
        // half-reloaded state.
        //
        // A pod carrying the instance label that this workload did not
        // create is skipped rather than failed, and that is deliberate.
        // Erroring would fall through to the rollout restart, which
        // patches the workload's own pod template and therefore cannot
        // reach the very pod that was skipped; it would restart every
        // healthy owned pod on every config change, forever, and leave
        // the unowned one exactly as stale as before. So the owned fleet
        // is what `Ok` claims, the skipped pods are counted rather than
        // silently absorbed, and an operator who orphaned pods on
        // purpose owns them from that point on.
        match try_hot_reload(&ctx.client, sbproxy, ns).await {
            Ok(outcome) => {
                tracing::info!(
                    name = %name,
                    namespace = %ns,
                    config_revision = %hash,
                    unowned_skipped = outcome.unowned_skipped,
                    "hot-reloaded every proxy pod this workload created via /admin/reload"
                );

                // Skip the Deployment patch entirely: the pod template's
                // config-hash annotation is the rolling-restart trigger, so
                // advancing it here would restart the pods a reload just
                // spared. `status.configHash`, stamped by the caller once
                // this returns Ok, is what records the delivery, and it is
                // what gate 4 above reads on the next pass. The ConfigMap is
                // already up to date for any pod that restarts for unrelated
                // reasons.
                return Ok(WorkloadPass {
                    action: Action::requeue(Duration::from_secs(300)),
                    unowned_skipped: outcome.unowned_skipped,
                });
            }
            // `hot_reload_error`, not `e`: `HotReloadError::Request`
            // wraps a `reqwest::Error`, whose Display ends with the pod
            // URL it dialled. `try_hot_reload` strips that URL before
            // wrapping, and the name is what says so here (WOR-2629).
            Err(hot_reload_error) => {
                tracing::warn!(
                    error = %hot_reload_error,
                    name = %name,
                    namespace = %ns,
                    "hot-reload failed; falling back to rollout-restart"
                );
            }
        }
    }

    // --- Apply Deployment (rollout-restart on annotation change) ---
    deploy_api
        .patch(deploy_name, pp, &Patch::Apply(&desired_deploy))
        .await
        .map_err(ReconcileError::Apply)?;

    // Requeue periodically as a belt-and-braces against missed watch events.
    Ok(WorkloadPass {
        action: Action::requeue(Duration::from_secs(300)),
        unowned_skipped: 0,
    })
}

/// Clustered workload path: shared-key Secret, headless Service, and
/// StatefulSet, with garbage collection of the Deployment left behind
/// when a user flips `spec.clustering.enabled` on. The Deployment is
/// deleted before the StatefulSet is applied so the two workloads never
/// run pods side by side under the same labels; the flip is therefore a
/// full (brief) restart of the fleet, which a mesh-topology change
/// requires anyway.
async fn reconcile_clustered_workload(
    ctx: &Ctx,
    sbproxy: &SBProxy,
    ns: &str,
    name: &str,
    hash: &str,
    pp: &PatchParams,
    suspension: Option<&reconcile::PodFallback>,
) -> Result<WorkloadPass, ReconcileError> {
    require_write_gate(ctx, ns, name)?;
    require_config_push_allowed(suspension, ns, name)?;

    // --- Ensure the shared cluster key exists ---
    // Create-if-absent, never overwrite: existing key material is what
    // lets a rescheduled pod rejoin the mesh, so it must survive every
    // reconcile. A user-referenced Secret is never created or touched.
    let secrets_api: Api<Secret> = Api::namespaced(ctx.client.clone(), ns);
    let secret_name = reconcile::cluster_secret_name(sbproxy);
    let existing_secret = secrets_api
        .get_opt(&secret_name)
        .await
        .map_err(ReconcileError::ClusterSecret)?;
    if reconcile::needs_generated_cluster_secret(sbproxy, existing_secret.as_ref()) {
        let secret = reconcile::desired_cluster_secret(sbproxy, &reconcile::generate_cluster_key());
        match secrets_api.create(&PostParams::default(), &secret).await {
            Ok(_) => {
                tracing::info!(
                    name = %name,
                    namespace = %ns,
                    secret = %secret_name,
                    "generated shared cluster key Secret"
                );
            }
            // Lost a create race with a concurrent reconcile: the
            // winner's key is the cluster key; use it as-is.
            Err(kube::Error::Api(e)) if e.code == 409 => {}
            Err(e) => return Err(ReconcileError::ClusterSecret(e)),
        }
    }

    // --- Apply the headless Service for stable per-pod DNS ---
    let headless = reconcile::desired_headless_service(sbproxy);
    let headless_api: Api<Service> = Api::namespaced(ctx.client.clone(), ns);
    headless_api
        .patch(
            headless
                .metadata
                .name
                .as_deref()
                .ok_or(ReconcileError::MissingName)?,
            pp,
            &Patch::Apply(&headless),
        )
        .await
        .map_err(ReconcileError::Apply)?;

    // --- GC the Deployment on the clustering-on transition ---
    let deploy_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), ns);
    let deploy_name = reconcile::deployment_name(sbproxy);
    if deploy_api
        .get_opt(&deploy_name)
        .await
        .unwrap_or(None)
        .is_some()
    {
        tracing::info!(
            name = %name,
            namespace = %ns,
            deployment = %deploy_name,
            "clustering enabled; deleting Deployment before applying StatefulSet"
        );
        delete_ignoring_missing(
            deploy_api
                .delete(&deploy_name, &DeleteParams::default())
                .await,
        )?;
    }

    // --- Decide hot-reload vs rollout-restart, then apply ---
    let sts_api: Api<StatefulSet> = Api::namespaced(ctx.client.clone(), ns);
    let existing_sts = sts_api
        .get_opt(&reconcile::statefulset_name(sbproxy))
        .await
        .unwrap_or(None);
    let template_hash = existing_sts
        .as_ref()
        .and_then(reconcile::previous_config_hash_statefulset);
    let running_hash = reconcile::running_config_hash(sbproxy);

    // Same reasoning as the Deployment path: the template hash is the roll
    // trigger, so it holds still while the pods already run the config.
    let desired_sts = reconcile::desired_statefulset(
        sbproxy,
        reconcile::rollout_config_hash(template_hash.as_deref(), running_hash, hash),
    );
    let sts_name = desired_sts
        .metadata
        .name
        .as_deref()
        .ok_or(ReconcileError::MissingName)?;

    let hot_reload_eligible = reconcile::should_hot_reload_statefulset(
        sbproxy,
        existing_sts.as_ref(),
        &desired_sts,
        running_hash,
        hash,
    );

    // Same re-check as the Deployment path, for the same reason.
    require_write_gate(ctx, ns, name)?;
    require_config_push_allowed(suspension, ns, name)?;

    if hot_reload_eligible {
        match try_hot_reload(&ctx.client, sbproxy, ns).await {
            Ok(outcome) => {
                tracing::info!(
                    name = %name,
                    namespace = %ns,
                    config_revision = %hash,
                    unowned_skipped = outcome.unowned_skipped,
                    "hot-reloaded every clustered proxy pod this workload created via \
                     /admin/reload"
                );

                return Ok(WorkloadPass {
                    action: Action::requeue(Duration::from_secs(300)),
                    unowned_skipped: outcome.unowned_skipped,
                });
            }
            // `hot_reload_error`, not `e`: `HotReloadError::Request`
            // wraps a `reqwest::Error`, whose Display ends with the pod
            // URL it dialled. `try_hot_reload` strips that URL before
            // wrapping, and the name is what says so here (WOR-2629).
            Err(hot_reload_error) => {
                tracing::warn!(
                    error = %hot_reload_error,
                    name = %name,
                    namespace = %ns,
                    "hot-reload failed; falling back to rollout-restart"
                );
            }
        }
    }

    sts_api
        .patch(sts_name, pp, &Patch::Apply(&desired_sts))
        .await
        .map_err(ReconcileError::Apply)?;

    Ok(WorkloadPass {
        action: Action::requeue(Duration::from_secs(300)),
        unowned_skipped: 0,
    })
}

/// The current time as an RFC 3339 timestamp, for a status condition.
///
/// Seconds resolution and a `Z` suffix, which is how Kubernetes renders
/// `metav1.Time` in a condition. `chrono` is already a dependency here
/// for the Lease timestamps.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Collapse a delete result so a concurrent deletion (404) is not an
/// error: the object being gone is exactly the desired outcome. Generic
/// over the success payload (`Either<K, Status>`) so no direct
/// dependency on the `either` crate is needed.
fn delete_ignoring_missing<T>(result: Result<T, kube::Error>) -> Result<(), ReconcileError> {
    match result {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(ReconcileError::Cleanup(e)),
    }
}

/// Refuse to continue when this replica can no longer prove it holds the
/// leader Lease.
///
/// Called immediately before each group of writes rather than once at the
/// top of the pass. A single entry check would leave the whole rest of the
/// pass, which includes several apiserver round-trips and an HTTP fan-out to
/// every proxy pod, running on a leadership claim that may have expired
/// mid-flight.
///
/// What this cannot see: a request already handed to `reqwest` or to the
/// kube client when the gate closes. Nothing in-process can recall those.
/// The gate bounds how many further writes a deposed leader issues, and the
/// Lease arithmetic in `leader` is what keeps the gate closing before a
/// successor may legally start.
fn require_write_gate(ctx: &Ctx, ns: &str, name: &str) -> Result<(), ReconcileError> {
    if ctx.write_gate.allows() {
        return Ok(());
    }
    tracing::warn!(
        name = %name,
        namespace = %ns,
        "leader lease is no longer provable; abandoning this reconcile without writing"
    );
    Err(ReconcileError::Fenced)
}

/// Patch the `SBProxy` `status` subresource with a JSON merge patch.
///
/// Best-effort: a status write failure is logged and swallowed so it never
/// fails the reconcile (status is observability, not correctness). Used by
/// the config preview-validation path to surface a bad config on
/// the CRD and to clear the error once the config validates again.
///
/// Takes the whole context rather than the client so the leader fence is
/// applied by construction: a deposed replica must not keep stamping status
/// onto an object its successor now owns.
async fn patch_status(ctx: &Ctx, ns: &str, name: &str, body: serde_json::Value) {
    if !ctx.write_gate.allows() {
        tracing::warn!(
            name = %name,
            namespace = %ns,
            "leader lease is no longer provable; skipping status write"
        );
        return;
    }
    let client = &ctx.client;
    let api: Api<SBProxy> = Api::namespaced(client.clone(), ns);
    if let Err(e) = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(&body))
        .await
    {
        tracing::warn!(
            name = %name,
            namespace = %ns,
            error = %e,
            "failed to patch SBProxy status"
        );
    }
}

/// Best-effort `POST /admin/reload` against every running proxy
/// pod for the given `SBProxy`.
///
/// Returns `Ok` only when every pod this operator's workload created
/// returned 200. Any pod that returns a non-200 (or fails to dial)
/// propagates as `Err`, which triggers the rollout-restart fallback in
/// `reconcile_one`.
///
/// The `Ok` value counts the pods that carried this SBProxy's instance
/// label and were skipped because its workload did not create them, so
/// the caller can say which kind of success this was.
async fn try_hot_reload(
    client: &Client,
    sbproxy: &SBProxy,
    namespace: &str,
) -> Result<HotReloadOutcome, HotReloadError> {
    let secret_ref = sbproxy
        .spec
        .admin_auth_secret_ref
        .as_ref()
        .ok_or(HotReloadError::NoAdminAuthSecretRef)?;

    let auth_header = read_admin_auth(client, namespace, secret_ref).await?;

    // Select by the standard instance label, then keep only the pods
    // this operator's own workload created.
    //
    // The label alone is a value anyone with `pods/create` in the
    // namespace can type, and this loop posts the admin Basic credential
    // in cleartext to every pod it keeps. That is the same disclosure
    // the fallback probe was fixed for; this is the second path carrying
    // it, and a fix on one of two paths is not the fix the release note
    // describes.
    //
    // What over-filtering costs depends on how much of the list it
    // takes, and the two cases are not the same.
    //
    // Filter everything and this returns `NoPodsFound`; every
    // `HotReloadError` falls back to a rollout restart, which reloads
    // by replacing the pods, so the cost is a restart.
    //
    // Filter some and this returns `Ok`, the caller skips the workload
    // patch on purpose, and the pods that were filtered keep the old
    // configuration. That is deliberate rather than overlooked: a pod
    // that fails this check was not created by the workload whose pod
    // template a rollout would patch, so restarting cannot reach it,
    // and erroring would restart every healthy owned pod on every
    // config change while leaving that one exactly as stale. The count
    // travels back on `HotReloadOutcome` so the pass is recorded as
    // `delivered_unowned_skipped` rather than passing silently. The
    // caller's comment at the `Ok` arm carries the same reasoning; if
    // you change one, change both.
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let sbp_name = sbproxy
        .metadata
        .name
        .as_deref()
        .ok_or(HotReloadError::MissingPodSelector)?;
    let lp = ListParams::default().labels(&format!("app.kubernetes.io/instance={sbp_name}"));
    let pods = pods_api.list(&lp).await.map_err(HotReloadError::ListPods)?;

    let deployment = reconcile::deployment_name(sbproxy);
    let statefulset = reconcile::statefulset_name(sbproxy);
    let owned: Vec<&Pod> = pods
        .items
        .iter()
        .filter(|pod| {
            let owned = reconcile::pod_is_operator_owned(pod, &deployment, &statefulset);
            if !owned {
                tracing::warn!(
                    pod = %pod.metadata.name.as_deref().unwrap_or("?"),
                    namespace = %namespace,
                    "a pod carries this SBProxy's instance label but was not created by its \
                     workload; not reloading it and not sending it the admin credential",
                );
            }
            owned
        })
        .collect();

    if owned.is_empty() {
        return Err(HotReloadError::NoPodsFound);
    }
    let unowned_skipped = pods.items.len() - owned.len();

    let admin_port = sbproxy.spec.admin_port;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(HotReloadError::HttpClient)?;

    for pod in owned {
        let pod_ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.as_deref())
            .ok_or(HotReloadError::PodHasNoIp)?;
        // A bare IPv6 literal has to be bracketed or the URL does not
        // parse, and the whole fleet would fall back to a rollout
        // restart on every config change. The probe sibling carries the
        // same bracketing.
        let authority = if pod_ip.contains(':') {
            format!("[{pod_ip}]")
        } else {
            pod_ip.to_string()
        };
        let url = format!("http://{authority}:{admin_port}/admin/reload");
        let resp = http
            .post(&url)
            .header("authorization", &auth_header)
            .send()
            .await
            // The URL is a pod IP and the fixed `/admin/reload` path, so
            // the leak is small, but the rule is that no reqwest Display
            // reaches a log line with its URL attached (WOR-2629).
            .map_err(|error| HotReloadError::Request(error.without_url()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(HotReloadError::ProxyRejected(status.as_u16()));
        }
    }

    Ok(HotReloadOutcome { unowned_skipped })
}

/// What a successful hot reload actually covered.
///
/// A bare `Ok(())` could not distinguish "every labeled pod reloaded"
/// from "every pod I own reloaded, and some sharing the label did not",
/// and the caller skips the workload patch on both. That is the right
/// call and it should not be silent, so the count travels with the
/// success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HotReloadOutcome {
    /// Pods carrying the instance label that this operator's workload
    /// did not create. Never reloaded and never sent the credential.
    unowned_skipped: usize,
}

/// What one workload pass did, for the caller that records it.
///
/// `reconcile_one` counts the delivery exactly once, after the workload
/// function returns, and it has counted it there since the metric was
/// added. The label is the only thing the workload path knows and the
/// caller does not, so it travels up rather than being recorded a second
/// time down here: two call sites meant a clean hot reload counted
/// `delivered` twice and a partial one counted both labels, so the
/// series stopped counting passes.
struct WorkloadPass {
    /// What to tell the controller to do next.
    action: Action,
    /// Pods this pass could not reload because this operator's workload
    /// did not create them. Zero on every path but a partial hot reload.
    unowned_skipped: usize,
}

/// Most pods one pass probes before it gives up and applies.
///
/// A count bound alone is not enough, and setting it at fifty was
/// setting it at exactly the failure case: fifty pods behind a
/// NetworkPolicy, each costing the full per-request timeout, is over
/// four minutes in which the SBProxy's ConfigMap and workload are not
/// applied, because both happen after this. [`FALLBACK_PROBE_BUDGET`]
/// is the bound that actually holds; this one stays as a second limit
/// for a large fleet whose pods all answer instantly.
const MAX_FALLBACK_PROBES: usize = 50;

/// Largest fallback answer this operator will read off a pod.
///
/// The pod is the untrusted end of this call. `reqwest` caps nothing,
/// so `resp.json()` would buffer whatever arrives before any bound this
/// operator applies could look at it: `FallbackReport::bounded` fixes
/// what reaches the CR, not what reaches the heap. A real answer is a
/// few hundred bytes; 64 KiB is generous for one and small enough that
/// a hostile pod cannot make it matter.
const MAX_FALLBACK_BODY_BYTES: usize = 64 * 1024;

/// Wall clock one pass spends probing before it gives up and applies.
///
/// The overall budget the count bound could not provide. Giving up is
/// safe and is the posture already documented: a pod that does not
/// answer contributes no report and does not suspend anything, so the
/// worst case of an exhausted budget is one pass that fails open on a
/// pod it never asked, counted as `budget_exhausted`, and a pin that is
/// noticed on the next loop 30 seconds later.
///
/// Fifteen seconds is three unreachable pods at the 5s per-request
/// timeout. The check runs before each request rather than cancelling
/// one in flight, so a pass can overshoot by a single timeout; the real
/// ceiling is 20 seconds.
///
/// Deliberately still serial. Concurrency would need a `Semaphore` to
/// avoid a thundering herd against a large fleet, and serial issuance
/// is what keeps exactly one response body in the operator's heap at a
/// time, which is the other half of bounding an untrusted pod's answer.
const FALLBACK_PROBE_BUDGET: Duration = Duration::from_secs(15);

/// Ask every running proxy pod whether it is serving a configuration
/// its boot fallback restored (WOR-2467).
///
/// Best effort by design. A pod that cannot be reached, has no IP yet,
/// or answers something this build cannot parse contributes **no**
/// report, which means it does not suspend reconciliation. Suspending
/// on a failure to ask would let one unreachable pod freeze config
/// delivery for the whole `SBProxy`, which is a worse failure than the
/// one this is here to prevent. The suspension is keyed on a node
/// actually saying "I am on a fallback", never on silence.
///
/// Needs `spec.adminAuthSecretRef`, the same credential the hot-reload
/// path uses. Without it there is no way to ask, so the answer is an
/// empty list and the operator reconciles as it always did.
async fn read_fallback_reports(
    client: &Client,
    sbproxy: &SBProxy,
    namespace: &str,
) -> Vec<reconcile::PodFallback> {
    let Some(secret_ref) = sbproxy.spec.admin_auth_secret_ref.as_ref() else {
        return Vec::new();
    };
    let Ok(auth_header) = read_admin_auth(client, namespace, secret_ref).await else {
        return Vec::new();
    };
    let Some(sbp_name) = sbproxy.metadata.name.as_deref() else {
        return Vec::new();
    };
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default().labels(&format!("app.kubernetes.io/instance={sbp_name}"));
    let Ok(pods) = pods_api.list(&lp).await else {
        return Vec::new();
    };
    let deployment = reconcile::deployment_name(sbproxy);
    let statefulset = reconcile::statefulset_name(sbproxy);
    let admin_port = sbproxy.spec.admin_port;
    let Ok(http) = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    else {
        return Vec::new();
    };
    let mut reports = Vec::new();
    let mut probed = 0usize;
    let deadline = std::time::Instant::now() + FALLBACK_PROBE_BUDGET;
    for pod in &pods.items {
        let name = pod.metadata.name.clone().unwrap_or_else(|| "?".to_string());
        // The credential goes only to a pod this operator's own
        // workload created. The instance label alone is a value anyone
        // with pod-create in the namespace can type, and this request
        // carries the admin Basic credential in cleartext.
        if !reconcile::pod_is_operator_owned(pod, &deployment, &statefulset) {
            tracing::warn!(
                pod = %name,
                namespace = %namespace,
                "a pod carries this SBProxy's instance label but was not created by its \
                 workload; not probing it and not sending it the admin credential",
            );
            sbproxy_observe::metrics::record_operator_fallback_probe("unowned");
            continue;
        }
        // A bounded fan-out. Each request costs up to the 5s client
        // timeout, so an unreachable fleet would otherwise pin a
        // reconcile worker for `replicas * 5s` before anything is
        // applied.
        if probed >= MAX_FALLBACK_PROBES || std::time::Instant::now() >= deadline {
            tracing::warn!(
                namespace = %namespace,
                probed,
                "reached the per-pass fallback probe budget; the remaining pods are treated \
                 as not pinned this pass and are asked again on the next loop",
            );
            sbproxy_observe::metrics::record_operator_fallback_probe("budget_exhausted");
            break;
        }
        let Some(pod_ip) = pod.status.as_ref().and_then(|s| s.pod_ip.as_deref()) else {
            continue;
        };
        probed += 1;
        // A bare IPv6 literal has to be bracketed or the URL does not
        // parse, and every pod on an IPv6 cluster would take the error
        // arm and read as "not pinned" for the whole fleet.
        let authority = if pod_ip.contains(':') {
            format!("[{pod_ip}]")
        } else {
            pod_ip.to_string()
        };
        let url = format!("http://{authority}:{admin_port}/admin/config/fallback");
        // `without_url` on every error path: the rule is that no reqwest
        // Display reaches a log line with its URL attached (WOR-2629).
        let resp = match http
            .get(&url)
            .header("authorization", &auth_header)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(error) => {
                // Counted, not only logged: `debug!` is compiled out in
                // release, so without this the documented fail-open
                // ("it does not suspend when it cannot ask") would be
                // invisible in production.
                sbproxy_observe::metrics::record_operator_fallback_probe("unreachable");
                tracing::debug!(
                    pod = %name,
                    error = %error.without_url(),
                    "could not read the config fallback status from a proxy pod; treating it \
                     as not pinned",
                );
                continue;
            }
        };
        if !resp.status().is_success() {
            sbproxy_observe::metrics::record_operator_fallback_probe("refused");
            continue;
        }
        let body = match read_capped_body(resp, MAX_FALLBACK_BODY_BYTES).await {
            Ok(body) => body,
            Err(reason) => {
                sbproxy_observe::metrics::record_operator_fallback_probe("unreadable");
                tracing::debug!(
                    pod = %name,
                    reason,
                    "a proxy pod's fallback answer was refused before it was parsed; treating \
                     it as not pinned",
                );
                continue;
            }
        };
        match serde_json::from_slice::<reconcile::FallbackReport>(&body) {
            Ok(report) => {
                sbproxy_observe::metrics::record_operator_fallback_probe(if report.active {
                    "pinned"
                } else {
                    "running_configured"
                });
                reports.push(reconcile::PodFallback {
                    pod: name,
                    // The node bounds its own reason; this operator
                    // re-bounds what a pod hands it, because the pod is
                    // the untrusted end of this call and the value goes
                    // straight into a Kubernetes condition message.
                    report: report.bounded(),
                });
            }
            Err(error) => {
                sbproxy_observe::metrics::record_operator_fallback_probe("unreadable");
                // Serde's classification, not its message. `invalid
                // type` and friends quote the offending value, so
                // `%error` would put pod-supplied bytes on this line.
                // The pod is the untrusted end of this call and the
                // reason it hands back is already re-bounded below;
                // this is the same rule applied to the parse failure.
                tracing::debug!(
                    pod = %name,
                    error_line = error.line(),
                    error_column = error.column(),
                    error_class = %match error.classify() {
                        serde_json::error::Category::Io => "io",
                        serde_json::error::Category::Syntax => "syntax",
                        serde_json::error::Category::Data => "data",
                        serde_json::error::Category::Eof => "eof",
                    },
                    "a proxy pod answered the fallback route with a body this operator cannot \
                     read; treating it as not pinned",
                );
            }
        }
    }
    reports
}

/// Read at most `cap` bytes of a response body, refusing a larger one
/// rather than buffering it.
///
/// Streamed chunk by chunk, because `Content-Length` is absent on a
/// chunked response and is attacker-supplied on any other: the only
/// bound that holds is the one applied while reading.
async fn read_capped_body(
    response: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut response = response;
    let mut body = Vec::new();
    loop {
        // `without_url` on the error path: no reqwest Display reaches a
        // log line with its URL attached (WOR-2629). The caller logs the
        // `&'static str` this returns instead.
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > cap {
                    return Err("the answer is larger than this operator will read");
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(body),
            Err(_) => return Err("the answer could not be read to the end"),
        }
    }
}

/// Refuse to push configuration to an `SBProxy` whose pods rescued
/// themselves onto a fallback configuration (WOR-2467).
///
/// Called immediately before each group of config writes rather than
/// once at the top of the pass, for the same reason
/// [`require_write_gate`] is: a single entry check would leave the rest
/// of the pass, which includes several apiserver round-trips, running on
/// a decision taken before them. The early return in
/// `reconcile_one_inner` is the ordinary path; these calls are what stop
/// a future write path from being added without deciding about the pin.
fn require_config_push_allowed(
    suspension: Option<&reconcile::PodFallback>,
    ns: &str,
    name: &str,
) -> Result<(), ReconcileError> {
    let Some(pinned) = suspension else {
        return Ok(());
    };
    tracing::warn!(
        name = %name,
        namespace = %ns,
        pod = %pinned.pod,
        revision = pinned.report.revision,
        condition = reconcile::FALLBACK_CONDITION_TYPE,
        "a pod is serving a configuration its boot fallback restored; not pushing config to \
         this SBProxy until the pin is cleared",
    );
    Err(ReconcileError::SuspendedOnFallback {
        pod: pinned.pod.clone(),
    })
}

/// Fetch the basic-auth header from the Secret named in
/// `SBProxy.spec.adminAuthSecretRef`. Cross-namespace refs are
/// rejected at the API surface (the Secret is looked up in the
/// SBProxy's own namespace), so a malicious manifest cannot read
/// secrets from arbitrary namespaces.
async fn read_admin_auth(
    client: &Client,
    namespace: &str,
    secret_ref: &AdminAuthSecretRef,
) -> Result<String, HotReloadError> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secret = secrets
        .get(&secret_ref.name)
        .await
        .map_err(HotReloadError::SecretFetch)?;
    let data = secret.data.unwrap_or_default();
    let raw = data
        .get(&secret_ref.key)
        .ok_or_else(|| HotReloadError::SecretKeyMissing(secret_ref.key.clone()))?;
    let s = std::str::from_utf8(&raw.0).map_err(|_| HotReloadError::SecretNotUtf8)?;
    Ok(s.to_string())
}

/// Error policy for the controller. Retry quickly on transient errors; this
/// is the standard kube-runtime shape.
fn error_policy(_obj: Arc<SBProxy>, err: &ReconcileError, _ctx: Arc<Ctx>) -> Action {
    tracing::warn!(error = %err, "reconcile failed; requeueing");
    Action::requeue(Duration::from_secs(15))
}

/// Errors surfaced by the reconciler.
#[derive(Debug, thiserror::Error)]
enum ReconcileError {
    /// The reconciled `SBProxy` had no namespace. Should be impossible for a
    /// namespaced CRD but typed for completeness.
    #[error("SBProxy is missing .metadata.namespace")]
    MissingNamespace,

    /// The reconciled object had no name. Same caveat as `MissingNamespace`.
    #[error("object is missing .metadata.name")]
    MissingName,

    /// Failed to fetch the referenced `SBProxyConfig`.
    #[error("failed to fetch referenced SBProxyConfig {name:?}: {source}")]
    ConfigFetch {
        /// The referenced config name.
        name: String,
        /// Underlying API error.
        #[source]
        source: kube::Error,
    },

    /// This replica can no longer prove it holds the leader Lease, so it
    /// refuses to write. Not a failure of the object under reconcile: the
    /// successor will do the pass.
    #[error("this replica no longer holds the leader lease; refusing to write")]
    Fenced,

    /// A pod owned by this `SBProxy` is serving a configuration its boot
    /// fallback restored, so config delivery is suspended (WOR-2467).
    ///
    /// Not a failure of the object under reconcile and not an error to
    /// alert on: the `ConfigFallbackActive` condition on the CR is the
    /// signal, and this exists so a write path added later cannot get
    /// past the suspension by not knowing about it.
    #[error(
        "pod {pod} is serving a configuration its boot fallback restored; config delivery is \
         suspended for this SBProxy until the pin is cleared"
    )]
    SuspendedOnFallback {
        /// The pod that reported the pin.
        pod: String,
    },

    /// Server-side-apply patch failed.
    #[error("failed to apply child object: {0}")]
    Apply(#[source] kube::Error),

    /// Reading or creating the shared cluster key Secret failed.
    #[error("failed to ensure cluster key Secret: {0}")]
    ClusterSecret(#[source] kube::Error),

    /// Deleting a stale child object (Deployment or StatefulSet left
    /// behind by a clustering on/off flip) failed.
    #[error("failed to delete stale child object: {0}")]
    Cleanup(#[source] kube::Error),
}

/// Errors specific to the hot-reload code path. These are
/// **soft** errors: the caller logs them and falls back to the
/// rollout-restart path so a failed hot-reload never leaves the
/// cluster in an inconsistent state.
#[derive(Debug, thiserror::Error)]
enum HotReloadError {
    /// `should_hot_reload` was a false positive: no auth secret to
    /// read. Defensive; the gate already rejects this case.
    #[error("SBProxy has no spec.adminAuthSecretRef set")]
    NoAdminAuthSecretRef,

    /// Pod selector requires `metadata.name`; the SBProxy CRD
    /// requires it but the kube types make it optional.
    #[error("SBProxy is missing .metadata.name; cannot select pods")]
    MissingPodSelector,

    /// Listing pods failed. Usually a transient API error.
    #[error("failed to list pods: {0}")]
    ListPods(#[source] kube::Error),

    /// No pods matched the selector. May happen between
    /// Deployment creation and pod scheduling; we fall back to
    /// rollout-restart so the operator's job is still done.
    #[error("no proxy pods found for SBProxy")]
    NoPodsFound,

    /// A matched pod has no IP allocated yet. Same fallback.
    #[error("pod has no .status.podIP")]
    PodHasNoIp,

    /// Could not construct the reqwest client (rare).
    #[error("failed to build HTTP client: {0}")]
    HttpClient(#[source] reqwest::Error),

    /// The reload request itself failed (timeout, connection
    /// refused, etc.).
    #[error("admin /reload request failed: {0}")]
    Request(#[source] reqwest::Error),

    /// The proxy returned a non-2xx response (e.g. 401 if the
    /// Secret is wrong, 503 if admin is misconfigured, 409 if
    /// another reload is in flight).
    #[error("proxy /admin/reload returned status {0}")]
    ProxyRejected(u16),

    /// Failed to fetch the auth Secret.
    #[error("failed to fetch admin auth Secret: {0}")]
    SecretFetch(#[source] kube::Error),

    /// The configured key is missing from the Secret.
    #[error("admin auth Secret has no key {0:?}")]
    SecretKeyMissing(String),

    /// The Secret value is not valid UTF-8 (the auth header is
    /// always ASCII).
    #[error("admin auth Secret value is not valid UTF-8")]
    SecretNotUtf8,
}

#[cfg(test)]
mod test_env;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::EnvVarGuard;
    use clap::Parser;

    /// Helper that strips the env-var bridge so `RUST_LOG` from the host
    /// shell does not leak into the parsed `Cli` and surprise the asserts.
    fn parse_cli(args: &[&str]) -> Cli {
        // We cannot rely on the host env: clap reads `RUST_LOG` and
        // `SBPROXY_NAMESPACE`. Parse with both cleared; the guard
        // serializes the mutation against the other env tests in this
        // binary and restores the host values on return (WOR-646).
        let _env = EnvVarGuard::set(&[("RUST_LOG", None), ("SBPROXY_NAMESPACE", None)]);
        Cli::try_parse_from(args).expect("parse Cli")
    }

    #[test]
    fn cli_default_keeps_leader_election_on() {
        let cli = parse_cli(&["sbproxy-k8s-operator"]);
        assert!(
            !cli.no_leader_election,
            "leader election must default to ON"
        );
    }

    #[test]
    fn cli_no_leader_election_flag_flips_off() {
        let cli = parse_cli(&["sbproxy-k8s-operator", "--no-leader-election"]);
        assert!(
            cli.no_leader_election,
            "--no-leader-election must disable the lock"
        );
    }

    #[test]
    fn cli_namespace_flag_threads_through() {
        let cli = parse_cli(&["sbproxy-k8s-operator", "--namespace", "my-ns"]);
        assert_eq!(cli.namespace.as_deref(), Some("my-ns"));
    }

    #[test]
    fn cli_log_level_default_is_info() {
        let cli = parse_cli(&["sbproxy-k8s-operator"]);
        assert_eq!(cli.log_level, "info");
    }

    /// The constant must match the documented Lease name in `docs/kubernetes.md`
    /// and the RBAC verb list shipped in the Helm chart. Any change here is a
    /// breaking config change.
    #[test]
    fn leader_lease_name_is_pinned() {
        assert_eq!(LEADER_LEASE_NAME, "sbproxy-operator-leader");
    }

    // --- WOR-636: SIGINT/SIGTERM grace-period parser ---

    /// The 30s default tracks Kubernetes' default
    /// `terminationGracePeriodSeconds`; a change here is a behaviour
    /// change for the kubelet drain window.
    #[test]
    fn shutdown_grace_default_is_30_seconds() {
        assert_eq!(DEFAULT_SHUTDOWN_GRACE_MS, 30_000);
    }

    /// `SBPROXY_SHUTDOWN_GRACE_MS` overrides the default when set to
    /// a non-negative integer.
    #[test]
    fn shutdown_grace_env_overrides_default() {
        let _env = EnvVarGuard::set(&[("SBPROXY_SHUTDOWN_GRACE_MS", Some("12345"))]);
        let got = resolve_shutdown_grace_ms();
        assert_eq!(got, 12_345);
    }

    /// A malformed `SBPROXY_SHUTDOWN_GRACE_MS` falls back to the
    /// default rather than panicking; a misconfigured pod still
    /// drains in the documented 30s window.
    #[test]
    fn shutdown_grace_malformed_env_falls_back_to_default() {
        let _env = EnvVarGuard::set(&[("SBPROXY_SHUTDOWN_GRACE_MS", Some("thirty-seconds"))]);
        let got = resolve_shutdown_grace_ms();
        assert_eq!(got, DEFAULT_SHUTDOWN_GRACE_MS);
    }

    /// An unset `SBPROXY_SHUTDOWN_GRACE_MS` resolves to the
    /// documented default.
    #[test]
    fn shutdown_grace_unset_env_returns_default() {
        let _env = EnvVarGuard::set(&[("SBPROXY_SHUTDOWN_GRACE_MS", None)]);
        assert_eq!(resolve_shutdown_grace_ms(), DEFAULT_SHUTDOWN_GRACE_MS);
    }

    // --- Status ordering ---

    /// This binary's own source, so the ordering below is checked against the
    /// code that ships rather than against a paraphrase of it.
    const MAIN_RS: &str = include_str!("main.rs");

    /// Everything above this file's own `#[cfg(test)]` block: the code that
    /// actually runs in the operator. Searching the whole file instead would
    /// match this module's own assertions and count them as call sites.
    fn production_source() -> &'static str {
        let (production, _tests) = MAIN_RS
            .split_once("#[cfg(test)]")
            .expect("main.rs carries a test module");
        production
    }

    /// `configHash` and the `lastError` clear are documented as end-of-pass
    /// signals, and `reconcile_one_inner` used to write them right after
    /// validation. A ConfigMap apply that then 403'd left the CR reading
    /// `configHash: H1, lastError: ""` while every pod still ran H0.
    ///
    /// A live apiserver is the only thing that can observe the write order
    /// directly, and the operator's reconcile takes one. So this pins the
    /// order in the source instead, which is narrow in a specific way worth
    /// naming: it proves the rolled-out patch is dispatched after the
    /// workload calls in `reconcile_one_inner`, and it cannot see a write
    /// issued from anywhere else. What keeps that from mattering is
    /// `rolled_out_status_patch` being the only producer of `configHash` in
    /// the crate, which the companion test below pins.
    #[test]
    fn the_rolled_out_status_patch_is_dispatched_after_the_workload_apply() {
        let src = production_source();
        let observed = src
            .find("reconcile::observed_status_patch")
            .expect("the pre-apply pass records observedConfigHash");
        let deployment_apply = src
            .find("reconcile_deployment_workload(&ctx,")
            .expect("the Deployment workload is reconciled from reconcile_one_inner");
        let clustered_apply = src
            .find("reconcile_clustered_workload(&ctx,")
            .expect("the clustered workload is reconciled from reconcile_one_inner");
        let rolled_out = src
            .find("reconcile::rolled_out_status_patch")
            .expect("configHash is stamped once the rollout lands");

        assert!(
            observed < clustered_apply && observed < deployment_apply,
            "observedConfigHash is the pre-apply signal and must be written first"
        );
        assert!(
            rolled_out > deployment_apply && rolled_out > clustered_apply,
            "configHash must not be stamped until both workload paths have \
             had their chance to fail"
        );
    }

    /// The other half of the claim above: nothing else in the operator can
    /// produce a `configHash` status write, so pinning one call site's
    /// position pins the behavior.
    #[test]
    fn config_hash_status_is_written_from_exactly_one_place() {
        assert_eq!(
            production_source()
                .matches("rolled_out_status_patch")
                .count(),
            1,
            "a second configHash writer would escape the ordering guard above"
        );
        assert!(
            !production_source().contains("\"configHash\""),
            "configHash belongs in reconcile::rolled_out_status_patch, not in an \
             inline json! at some other point in the pass"
        );
    }

    // --- WOR-2467: a pinned pod suspends config delivery ---
    //
    // These drive the real `reconcile_one_inner` against a `kube::Client`
    // built over a recording `tower` service, plus a loopback HTTP server
    // standing in for the proxy's admin port. That is the only shape that
    // can assert "no write was issued": a pure decision function proves
    // the decision and not the enforcement, and this operator has three
    // separate config write sites.

    use std::sync::Mutex as StdMutex;

    /// Every apiserver request one reconcile issued, as `METHOD path`.
    type Recorded = Arc<StdMutex<Vec<String>>>;

    /// A loopback server answering `GET /admin/config/fallback` with
    /// `body`, standing in for one proxy pod's admin port.
    struct FallbackStub {
        port: u16,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
        /// How many requests this stub actually answered, so a test can
        /// assert the operator never dialed it at all.
        served: Arc<std::sync::atomic::AtomicUsize>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl FallbackStub {
        fn requests(&self) -> usize {
            self.served.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl FallbackStub {
        fn start(body: &'static str) -> Self {
            use std::io::{Read as _, Write as _};
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind the fallback stub");
            let port = listener.local_addr().expect("addr").port();
            listener
                .set_nonblocking(true)
                .expect("non-blocking so the loop can notice shutdown");
            let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let stop = Arc::clone(&shutdown);
            let counted = Arc::clone(&served);
            let handle = std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            // This counts accepts, not requests, which
                            // is only the same number because of the
                            // `connection: close` below. reqwest pools
                            // by default, so without that header two
                            // requests to the same pod IP would ride one
                            // connection and arrive as a single accept.
                            // `a_partial_owner_filter_reloads_only_the_owned_pod_and_reports_the_rest`
                            // discriminates on exactly that difference,
                            // one reload against two, so removing the
                            // header would leave that test green while
                            // it stopped testing anything. Load bearing.
                            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let mut buf = [0u8; 2048];
                            socket.set_nonblocking(false).ok();
                            let _ = socket.read(&mut buf);
                            let response = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                                body.len(),
                            );
                            let _ = socket.write_all(response.as_bytes());
                            let _ = socket.flush();
                        }
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                port,
                shutdown,
                served,
                handle: Some(handle),
            }
        }
    }

    impl Drop for FallbackStub {
        fn drop(&mut self) {
            self.shutdown
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn json_response(
        value: &serde_json::Value,
    ) -> http::Response<http_body_util::Full<bytes::Bytes>> {
        http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(
                value.to_string(),
            )))
            .expect("build a response")
    }

    /// The `SBProxy` under reconcile, and the `SBProxyConfig` it names.
    fn suspension_fixtures(admin_port: i32, config: &str) -> (SBProxy, serde_json::Value) {
        let mut sbp: SBProxy = serde_json::from_value(serde_json::json!({
            "apiVersion": "sbproxy.dev/v1alpha1",
            "kind": "SBProxy",
            "metadata": { "name": "edge", "namespace": "sbproxy", "generation": 3 },
            "spec": {
                "image": "ghcr.io/soapbucket/sbproxy:v1",
                "configRef": "edge-config",
                "replicas": 1,
                "adminPort": admin_port,
                "adminAuthSecretRef": { "name": "admin-auth" },
            },
        }))
        .expect("SBProxy fixture");
        sbp.metadata.generation = Some(3);
        let cfg = serde_json::json!({
            "apiVersion": "sbproxy.dev/v1alpha1",
            "kind": "SBProxyConfig",
            "metadata": { "name": "edge-config", "namespace": "sbproxy" },
            "spec": { "config": config },
        });
        (sbp, cfg)
    }

    /// Run one reconcile against a recording apiserver, with the pod's
    /// admin port pointed at `stub_port`. Returns every request issued.
    async fn drive_one_reconcile(stub_port: u16) -> Vec<String> {
        drive_one_reconcile_with(stub_port, "proxy:\n  http_bind_port: 8080\n").await
    }

    async fn drive_one_reconcile_with(stub_port: u16, config: &str) -> Vec<String> {
        drive_one_reconcile_full(stub_port, config, OWNED_POD_OWNER).await
    }

    /// The controller reference a pod created by this operator's own
    /// Deployment carries: `deployment_name` is `<sbproxy>-proxy`, and
    /// Kubernetes appends the pod-template hash to name its ReplicaSet.
    const OWNED_POD_OWNER: Option<(&str, &str)> = Some(("ReplicaSet", "edge-proxy-7d9f8c"));

    async fn drive_one_reconcile_full(
        stub_port: u16,
        config: &str,
        pod_owner: Option<(&str, &str)>,
    ) -> Vec<String> {
        use tower::ServiceExt as _;

        let (sbp, cfg) = suspension_fixtures(i32::from(stub_port), config);
        let recorded: Recorded = Arc::new(StdMutex::new(Vec::new()));
        let seen = Arc::clone(&recorded);
        let cfg_body = cfg.clone();
        let sbp_body = serde_json::to_value(&sbp).expect("serialize the SBProxy");

        let owner_refs = match pod_owner {
            Some((kind, name)) => serde_json::json!([{
                "apiVersion": "apps/v1",
                "kind": kind,
                "name": name,
                "uid": "owner-uid",
                "controller": true,
            }]),
            // A bare `kubectl run` with the right label and nothing else.
            None => serde_json::json!([]),
        };
        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let seen = Arc::clone(&seen);
            let owner_refs = owner_refs.clone();
            let cfg_body = cfg_body.clone();
            let sbp_body = sbp_body.clone();
            async move {
                let method = request.method().clone();
                let path = request.uri().path().to_string();
                seen.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(format!("{method} {path}"));
                let answer = if path.ends_with("/sbproxyconfigs/edge-config") {
                    cfg_body
                } else if path.ends_with("/secrets/admin-auth") {
                    // `authorization` is the default key, and the value is
                    // the whole header. Base64 of "admin:pw".
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": { "name": "admin-auth", "namespace": "sbproxy" },
                        "data": { "authorization": "QmFzaWMgWVdSdGFXNDZjSGM9" },
                    })
                } else if path.ends_with("/pods") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "PodList",
                        "metadata": {},
                        "items": [{
                            "apiVersion": "v1",
                            "kind": "Pod",
                            "metadata": {
                                "name": "edge-0",
                                "namespace": "sbproxy",
                                "ownerReferences": owner_refs,
                            },
                            "status": { "podIP": "127.0.0.1" },
                        }],
                    })
                } else if path.contains("/sbproxies/") {
                    sbp_body
                } else {
                    // A server-side apply answers with the object it
                    // stored, and `kube` deserializes it into the typed
                    // resource. Echoing the SBProxy back for a Service
                    // or a ConfigMap apply fails that decode and the
                    // reconcile aborts there, which silently truncated
                    // this test the moment the Service moved ahead of
                    // the ConfigMap.
                    serde_json::json!({
                        "metadata": { "name": "applied", "namespace": "sbproxy" },
                    })
                };
                Ok::<_, std::convert::Infallible>(json_response(&answer))
            }
        });

        let client = Client::new(service.boxed_clone(), "sbproxy");
        let ctx = Arc::new(Ctx {
            client,
            write_gate: WriteGate::always(),
        });
        let _ = reconcile_one_inner(Arc::new(sbp), ctx).await;
        let requests = recorded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        requests
    }

    /// The acceptance criterion, driven rather than reasoned about: a
    /// reconcile against an SBProxy whose pod is on a fallback config
    /// issues no ConfigMap, Service, Deployment, or StatefulSet write.
    #[tokio::test]
    async fn a_reconcile_writes_no_config_while_a_pod_is_on_its_boot_fallback() {
        let stub = FallbackStub::start(
            r#"{"active":true,"revision":7,"digest":"sha256:abc","reason":"unknown action type: statik","suspended":["file_watcher"]}"#,
        );
        let requests = drive_one_reconcile(stub.port).await;

        for kind in ["configmaps", "deployments", "statefulsets"] {
            assert!(
                !requests.iter().any(|request| request.contains(kind)),
                "a pinned SBProxy must not have config pushed to it; saw {kind} in \
                 {requests:?}",
            );
        }
        // The Service is deliberately still reconciled: it is a name and
        // a port selector, it cannot put a document on a pod, and
        // leaving a deleted one unrecreated would turn a config incident
        // into an outage.
        assert!(
            requests
                .iter()
                .any(|request| request.starts_with("PATCH") && request.contains("services")),
            "the Service carries no configuration and must still be applied: {requests:?}",
        );
        // It did do the reads, so the absence above is a decision rather
        // than a reconcile that never started.
        assert!(
            requests
                .iter()
                .any(|request| request.contains("sbproxyconfigs")),
            "{requests:?}",
        );
        assert!(
            requests.iter().any(|request| request.contains("/pods")),
            "the pin is read from the pods themselves: {requests:?}",
        );
        // And it wrote the condition, which is the operator-visible
        // signal an alert fires on.
        assert!(
            requests
                .iter()
                .any(|request| request.starts_with("PATCH") && request.contains("/status")),
            "the condition is a status write: {requests:?}",
        );
    }

    /// The other half: the same reconcile, the same fixtures, a pod that
    /// reports no pin. Without this the test above would pass on a build
    /// that never reconciles anything.
    #[tokio::test]
    async fn clearing_the_pin_resumes_config_delivery_on_the_next_loop() {
        let stub = FallbackStub::start(
            r#"{"active":false,"revision":null,"digest":null,"reason":null,"suspended":[]}"#,
        );
        let requests = drive_one_reconcile(stub.port).await;

        assert!(
            requests
                .iter()
                .any(|request| request.starts_with("PATCH") && request.contains("configmaps")),
            "a node that is not pinned gets its config pushed: {requests:?}",
        );
    }

    /// The `auto_revert` refusal is an enforcement, not just a
    /// function. Driven through the same reconcile so a call site that
    /// was never wired would show up here rather than pass on the pure
    /// function alone.
    #[tokio::test]
    async fn a_config_arming_auto_revert_is_never_rolled_out_under_the_operator() {
        let stub = FallbackStub::start(r#"{"active":false}"#);
        let requests = drive_one_reconcile_with(
            stub.port,
            "proxy:\n  config_history:\n    enabled: true\n    soak:\n      auto_revert: true\n",
        )
        .await;
        for kind in ["configmaps", "services", "deployments", "statefulsets"] {
            assert!(
                !requests.iter().any(|request| request.contains(kind)),
                "an auto_revert config must not roll out; saw {kind} in {requests:?}",
            );
        }
        assert!(
            requests
                .iter()
                .any(|request| request.starts_with("PATCH") && request.contains("/status")),
            "and the refusal reaches the CR as lastError: {requests:?}",
        );
    }

    /// One delivery count per pass, pinned where it can be checked
    /// without a metrics registry.
    ///
    /// `reconcile_one` has counted every pass at its single site since
    /// the metric was added, including the hot-reload arms, whose early
    /// `return` unwinds into the `?` there rather than out of the
    /// function. A round that believed otherwise added a second call in
    /// each workload function: a clean hot reload then counted
    /// `delivered` twice and a partial one counted both labels, so the
    /// series stopped counting passes. Nothing failed, because nothing
    /// asserted a count.
    ///
    /// What this cannot see, and what covers each. Whether the one call
    /// site is reachable: the driven reconcile tests. **Which of the two
    /// delivered labels it records**, because this counts call sites and
    /// not their arguments, so hardcoding `unowned_skipped: 0` in either
    /// workload `Ok` arm would make `delivered_unowned_skipped`
    /// unreachable and leave this green. There are two such arms and
    /// each has its own witness, because covering one and claiming both
    /// is how that gap survived a round:
    /// `the_workload_pass_carries_the_count_that_picks_the_delivery_label`
    /// drives `reconcile_deployment_workload` and
    /// `the_clustered_workload_pass_carries_the_count_that_picks_the_delivery_label`
    /// drives `reconcile_clustered_workload`, each asserting the count
    /// survives the trip on its own arm. And a second call added inside a helper the workload
    /// functions call rather than in their own bodies: the total
    /// assertion below still catches that, because it counts the whole
    /// production half of this file, but the per-function assertion does
    /// not.
    #[test]
    fn the_delivery_metric_is_recorded_once_per_pass() {
        let src = production_source();
        assert_eq!(
            src.matches("record_operator_config_delivery(").count(),
            6,
            "five refusal or suspension states plus the one success at the end of \
             reconcile_one; a seventh call site needs a line here saying which pass it counts",
        );
        for name in [
            "async fn reconcile_deployment_workload",
            "async fn reconcile_clustered_workload",
        ] {
            let start = src
                .find(name)
                .expect("the workload function is in this file");
            let rest = &src[start + name.len()..];
            let end = rest.find("\nasync fn ").unwrap_or(rest.len());
            assert_eq!(
                rest[..end]
                    .matches("record_operator_config_delivery(")
                    .count(),
                0,
                "{name} must not record a delivery: its caller already counts the pass, and \
                 a call here is a second increment rather than a first",
            );
        }
    }

    /// Drive `try_hot_reload` itself against a pod the operator did
    /// not create, and assert the credential never leaves.
    ///
    /// The source counter proves the ownership call exists in the file.
    /// It cannot prove the call *gates* the send: inverting the filter,
    /// or iterating `pods.items` again after computing `owned`, leaves
    /// both counts at two. This is the backstop the counter's own
    /// disclosure names, for the path that did not have one.
    #[tokio::test]
    async fn the_reload_credential_never_reaches_a_pod_the_operator_did_not_create() {
        use tower::ServiceExt as _;

        // A stub on a real port, so a request that escapes the filter is
        // counted rather than merely rejected somewhere downstream.
        let stub = FallbackStub::start(r#"{"reloaded":true}"#);
        let (sbp, _cfg) =
            suspension_fixtures(i32::from(stub.port), "proxy:\n  http_bind_port: 8080\n");
        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let path = request.uri().path().to_string();
            async move {
                let answer = if path.ends_with("/secrets/admin-auth") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": { "name": "admin-auth", "namespace": "sbproxy" },
                        "data": { "authorization": "QmFzaWMgWVdSdGFXNDZjSGM9" },
                    })
                } else if path.ends_with("/pods") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "PodList",
                        "metadata": {},
                        // Carries the instance label the selector asks
                        // for, and no controller owner reference: a bare
                        // `kubectl run` by anyone with pods/create.
                        "items": [{
                            "apiVersion": "v1",
                            "kind": "Pod",
                            "metadata": {
                                "name": "impostor-0",
                                "namespace": "sbproxy",
                                "ownerReferences": [],
                            },
                            "status": { "podIP": "127.0.0.1" },
                        }],
                    })
                } else {
                    serde_json::json!({
                        "metadata": { "name": "applied", "namespace": "sbproxy" },
                    })
                };
                Ok::<_, std::convert::Infallible>(json_response(&answer))
            }
        });
        let client = Client::new(service.boxed_clone(), "sbproxy");

        let outcome = try_hot_reload(&client, &sbp, "sbproxy").await;

        assert!(
            matches!(outcome, Err(HotReloadError::NoPodsFound)),
            "every labeled pod was unowned, so there is nothing this operator may reload, and \
             the caller must fall through to the rollout restart: {outcome:?}",
        );
        assert_eq!(
            stub.requests(),
            0,
            "the admin credential must not be sent to a pod this operator did not create",
        );
    }

    /// The mixed case, which the all-unowned test cannot reach: `owned`
    /// is non-empty, so the loop actually runs and the filter has to
    /// hold inside it.
    ///
    /// This is what catches iterating `pods.items` again after computing
    /// `owned`, which the all-unowned fixture cannot see because it
    /// returns `NoPodsFound` before the client is built. It is also the
    /// only test of `unowned_skipped`, which is what picks the delivery
    /// label.
    #[tokio::test]
    async fn a_partial_owner_filter_reloads_only_the_owned_pod_and_reports_the_rest() {
        use tower::ServiceExt as _;

        let stub = FallbackStub::start(r#"{"reloaded":true}"#);
        let (sbp, _cfg) =
            suspension_fixtures(i32::from(stub.port), "proxy:\n  http_bind_port: 8080\n");
        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let path = request.uri().path().to_string();
            async move {
                let answer = if path.ends_with("/secrets/admin-auth") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": { "name": "admin-auth", "namespace": "sbproxy" },
                        "data": { "authorization": "QmFzaWMgWVdSdGFXNDZjSGM9" },
                    })
                } else if path.ends_with("/pods") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "PodList",
                        "metadata": {},
                        "items": [
                            {
                                "apiVersion": "v1",
                                "kind": "Pod",
                                "metadata": {
                                    "name": "edge-proxy-abc123-0",
                                    "namespace": "sbproxy",
                                    "ownerReferences": [{
                                        "apiVersion": "apps/v1",
                                        "kind": "ReplicaSet",
                                        "name": "edge-proxy-abc123",
                                        "uid": "rs-uid",
                                        "controller": true,
                                    }],
                                },
                                "status": { "podIP": "127.0.0.1" },
                            },
                            {
                                "apiVersion": "v1",
                                "kind": "Pod",
                                "metadata": {
                                    "name": "impostor-0",
                                    "namespace": "sbproxy",
                                    "ownerReferences": [],
                                },
                                "status": { "podIP": "127.0.0.1" },
                            },
                        ],
                    })
                } else {
                    serde_json::json!({
                        "metadata": { "name": "applied", "namespace": "sbproxy" },
                    })
                };
                Ok::<_, std::convert::Infallible>(json_response(&answer))
            }
        });
        let client = Client::new(service.boxed_clone(), "sbproxy");

        let outcome = try_hot_reload(&client, &sbp, "sbproxy")
            .await
            .expect("the owned pod reloads, so this is a success");

        assert_eq!(
            outcome.unowned_skipped, 1,
            "the impostor is reported so the caller can pick the delivery label",
        );
        assert_eq!(
            stub.requests(),
            1,
            "exactly the owned pod was reloaded: iterating the unfiltered list would make \
             this two, and that is the mutation the source counter cannot see",
        );
    }

    /// Which label the pass records, not merely that one is
    /// recorded.
    ///
    /// `the_delivery_metric_is_recorded_once_per_pass` counts call
    /// sites, so it cannot see the argument. Hardcoding
    /// `unowned_skipped: 0` in either workload `Ok` arm makes
    /// `delivered_unowned_skipped` unreachable and leaves that test, and
    /// every other, green.
    ///
    /// **This one covers the Deployment arm.** The clustered arm is
    /// covered by
    /// `the_clustered_workload_pass_carries_the_count_that_picks_the_delivery_label`,
    /// and the two are siblings because the first version of this test
    /// covered one arm while its own doc claimed both.
    ///
    /// It drives the real workload function down the hot-reload path
    /// with one owned pod and one impostor and asserts the count that
    /// picks the label survives the trip, which is the whole wiring
    /// between `try_hot_reload` and the recording site.
    ///
    /// Self-discriminating in both directions: the rollout path
    /// hardcodes `unowned_skipped: 0`, so a fixture that failed to enter
    /// the hot-reload path would fail this assertion rather than pass
    /// it.
    #[tokio::test]
    async fn the_workload_pass_carries_the_count_that_picks_the_delivery_label() {
        use tower::ServiceExt as _;

        let stub = FallbackStub::start(r#"{"reloaded":true}"#);
        let (mut sbp, _cfg) =
            suspension_fixtures(i32::from(stub.port), "proxy:\n  http_bind_port: 8080\n");
        // Gate 4 of `should_hot_reload`: the pods are running an older
        // config than the one this pass is delivering.
        // `delivered_config_hash` returns `None` unless both are set,
        // so both are, or gate 4 reads "no hash recorded yet" instead of
        // "the config changed" and the test would pass for a reason it
        // is not testing.
        sbp.status = Some(sbproxy_k8s_operator::crd::SBProxyStatus {
            config_hash: "old-hash".to_string(),
            observed_config_hash: "old-hash".to_string(),
            ..Default::default()
        });
        // Gate 2 and 3: an existing Deployment whose operator-owned spec
        // matches the desired one. Built with the same builder the
        // operator uses, so a change to the template cannot silently
        // drop this test onto the rollout path.
        let existing = serde_json::to_value(reconcile::desired_deployment(&sbp, "old-hash"))
            .expect("serialize the existing Deployment");

        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let path = request.uri().path().to_string();
            let existing = existing.clone();
            async move {
                let answer = if path.ends_with("/secrets/admin-auth") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": { "name": "admin-auth", "namespace": "sbproxy" },
                        "data": { "authorization": "QmFzaWMgWVdSdGFXNDZjSGM9" },
                    })
                } else if path.ends_with("/pods") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "PodList",
                        "metadata": {},
                        "items": [
                            {
                                "apiVersion": "v1",
                                "kind": "Pod",
                                "metadata": {
                                    "name": "edge-proxy-abc123-0",
                                    "namespace": "sbproxy",
                                    "ownerReferences": [{
                                        "apiVersion": "apps/v1",
                                        "kind": "ReplicaSet",
                                        "name": "edge-proxy-abc123",
                                        "uid": "rs-uid",
                                        "controller": true,
                                    }],
                                },
                                "status": { "podIP": "127.0.0.1" },
                            },
                            {
                                "apiVersion": "v1",
                                "kind": "Pod",
                                "metadata": {
                                    "name": "impostor-0",
                                    "namespace": "sbproxy",
                                    "ownerReferences": [],
                                },
                                "status": { "podIP": "127.0.0.1" },
                            },
                        ],
                    })
                } else if path.contains("/deployments/") {
                    existing
                } else {
                    serde_json::json!({
                        "metadata": { "name": "applied", "namespace": "sbproxy" },
                    })
                };
                Ok::<_, std::convert::Infallible>(json_response(&answer))
            }
        });
        let ctx = Ctx {
            client: Client::new(service.boxed_clone(), "sbproxy"),
            write_gate: WriteGate::always(),
        };

        let pass = reconcile_deployment_workload(
            &ctx,
            &sbp,
            "sbproxy",
            "edge",
            "new-hash",
            &PatchParams::apply(FIELD_MANAGER).force(),
            None,
        )
        .await
        .expect("the owned pod reloads, so the pass succeeds");

        assert_eq!(
            pass.unowned_skipped, 1,
            "the impostor has to reach the recording site: at zero the label is `delivered` \
             and `delivered_unowned_skipped` is unreachable on every path",
        );
        assert_eq!(
            stub.requests(),
            1,
            "and it really went down the hot-reload path, reloading only the owned pod",
        );
    }

    /// The clustered arm of the same wiring.
    ///
    /// `reconcile_clustered_workload` carries an identical
    /// `unowned_skipped: outcome.unowned_skipped`, and until this test
    /// existed nothing drove it at all: hardcoding `0` there left every
    /// test green and made `delivered_unowned_skipped` unreachable for
    /// every clustered `SBProxy`. That is the one-of-two-arms shape this
    /// branch has now hit four times, most recently inside the fix for
    /// the third, so the two tests are siblings on purpose and each
    /// names its arm.
    #[tokio::test]
    async fn the_clustered_workload_pass_carries_the_count_that_picks_the_delivery_label() {
        use tower::ServiceExt as _;

        let stub = FallbackStub::start(r#"{"reloaded":true}"#);
        let (mut sbp, _cfg) =
            suspension_fixtures(i32::from(stub.port), "proxy:\n  http_bind_port: 8080\n");
        // Gate 4 of `should_hot_reload_statefulset`, and the same
        // `delivered_config_hash` requirement its Deployment sibling
        // documents: both fields have to be set or the gate reads "no
        // hash recorded yet" rather than "the config changed", and the
        // test would pass for a reason it is not testing.
        sbp.status = Some(sbproxy_k8s_operator::crd::SBProxyStatus {
            config_hash: "old-hash".to_string(),
            observed_config_hash: "old-hash".to_string(),
            ..Default::default()
        });
        // Gates 2 and 3: an existing StatefulSet whose operator-owned
        // spec matches the desired one, built with the same builder the
        // operator uses so a template change cannot silently drop this
        // test onto the rollout path.
        //
        // `spec.clustering` is deliberately absent, which is worth
        // saying because the real clustered path always has it. It
        // makes `clustering_enabled` false, so the shared-key block
        // above the workload apply does not generate a Secret. That is
        // upstream of the arm under test and cannot reach
        // `unowned_skipped`; leaving it out keeps the fixture to the
        // one decision this test is about. The `get_opt` on that Secret
        // still runs and is answered by the generic arm below.
        let existing = serde_json::to_value(reconcile::desired_statefulset(&sbp, "old-hash"))
            .expect("serialize the existing StatefulSet");

        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let path = request.uri().path().to_string();
            let existing = existing.clone();
            async move {
                // No Deployment to garbage collect. A 404 rather than a
                // decode failure, so the absence is the fixture saying
                // so rather than an accident of deserialization.
                if path.contains("/deployments/") {
                    return Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(404)
                            .header("content-type", "application/json")
                            .body(http_body_util::Full::new(bytes::Bytes::from(
                                serde_json::json!({"kind": "Status", "code": 404}).to_string(),
                            )))
                            .expect("build a 404"),
                    );
                }
                let answer = if path.ends_with("/secrets/admin-auth") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": { "name": "admin-auth", "namespace": "sbproxy" },
                        "data": { "authorization": "QmFzaWMgWVdSdGFXNDZjSGM9" },
                    })
                } else if path.ends_with("/pods") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "PodList",
                        "metadata": {},
                        "items": [
                            {
                                "apiVersion": "v1",
                                "kind": "Pod",
                                "metadata": {
                                    "name": "edge-proxy-0",
                                    "namespace": "sbproxy",
                                    // A StatefulSet owns its pods by
                                    // exact name, which is the other
                                    // half of `pod_is_operator_owned`.
                                    "ownerReferences": [{
                                        "apiVersion": "apps/v1",
                                        "kind": "StatefulSet",
                                        "name": "edge-proxy",
                                        "uid": "sts-uid",
                                        "controller": true,
                                    }],
                                },
                                "status": { "podIP": "127.0.0.1" },
                            },
                            {
                                "apiVersion": "v1",
                                "kind": "Pod",
                                "metadata": {
                                    "name": "impostor-0",
                                    "namespace": "sbproxy",
                                    "ownerReferences": [],
                                },
                                "status": { "podIP": "127.0.0.1" },
                            },
                        ],
                    })
                } else if path.contains("/statefulsets/") {
                    existing
                } else {
                    serde_json::json!({
                        "metadata": { "name": "applied", "namespace": "sbproxy" },
                    })
                };
                Ok::<_, std::convert::Infallible>(json_response(&answer))
            }
        });
        let ctx = Ctx {
            client: Client::new(service.boxed_clone(), "sbproxy"),
            write_gate: WriteGate::always(),
        };

        let pass = reconcile_clustered_workload(
            &ctx,
            &sbp,
            "sbproxy",
            "edge",
            "new-hash",
            &PatchParams::apply(FIELD_MANAGER).force(),
            None,
        )
        .await
        .expect("the owned pod reloads, so the pass succeeds");

        assert_eq!(
            pass.unowned_skipped, 1,
            "the clustered arm has to carry the count too: at zero the label is `delivered` \
             and `delivered_unowned_skipped` is unreachable for every clustered SBProxy",
        );
        assert_eq!(
            stub.requests(),
            1,
            "and it really went down the hot-reload path, reloading only the owned pod",
        );
    }

    /// A Blocker from the WOR-2467 review. A pod is selected for the
    /// probe by label, and a label is a value anyone with pod-create in
    /// the namespace can type. Before the owner gate, any pod answering
    /// `{"active":true}` halted config delivery for the whole SBProxy
    /// and was handed the operator's admin Basic credential in
    /// cleartext, on every pass.
    #[tokio::test]
    async fn a_labeled_pod_the_operator_did_not_create_is_neither_probed_nor_obeyed() {
        let stub = FallbackStub::start(
            r#"{"active":true,"revision":7,"digest":"sha256:abc","reason":"trust me"}"#,
        );
        let requests = drive_one_reconcile_full(
            stub.port,
            "proxy:\n  http_bind_port: 8080\n",
            // No controller reference: this pod was not created by the
            // operator's Deployment or StatefulSet.
            None,
        )
        .await;

        // It did not get to stop the rollout.
        assert!(
            requests
                .iter()
                .any(|request| request.starts_with("PATCH") && request.contains("configmaps")),
            "an unowned pod claiming a pin must not suspend config delivery: {requests:?}",
        );
        // And the credential never left the operator: the stub counts
        // every request it answered, and it answered none.
        assert_eq!(
            stub.requests(),
            0,
            "the admin credential must not be sent to a pod this operator did not create",
        );
    }

    /// The refusal is permanent until somebody edits
    /// the config, so returning before the condition block left a
    /// `ConfigFallbackActive` from an earlier pass frozen on the CR with
    /// nothing able to move it. The condition is refreshed first now.
    #[tokio::test]
    async fn an_auto_revert_refusal_still_refreshes_the_fallback_condition() {
        let stub = FallbackStub::start(r#"{"active":false}"#);
        let requests = drive_one_reconcile_with(
            stub.port,
            "proxy:\n  config_history:\n    enabled: true\n    soak:\n      auto_revert: true\n",
        )
        .await;
        // The pods were still asked, which is what refreshes the
        // condition, and the refusal still stopped the rollout.
        assert!(
            requests.iter().any(|request| request.contains("/pods")),
            "the condition cannot be refreshed without asking: {requests:?}",
        );
        for kind in ["configmaps", "deployments", "statefulsets"] {
            assert!(
                !requests.iter().any(|request| request.contains(kind)),
                "an auto_revert config must not roll out; saw {kind} in {requests:?}",
            );
        }
    }

    /// The guard every config write site calls. The early return in
    /// `reconcile_one_inner` is the ordinary path; this is what stops a
    /// write path added later from getting past the suspension by not
    /// knowing about it.
    #[test]
    fn the_config_push_guard_refuses_while_a_pod_is_pinned() {
        assert!(require_config_push_allowed(None, "ns", "edge").is_ok());
        let pinned = reconcile::PodFallback {
            pod: "edge-0".to_string(),
            report: reconcile::FallbackReport {
                active: true,
                revision: Some(7),
                digest: None,
                reason: None,
            },
        };
        let error = require_config_push_allowed(Some(&pinned), "ns", "edge")
            .expect_err("a pinned pod refuses the write");
        assert!(matches!(
            error,
            ReconcileError::SuspendedOnFallback { ref pod } if pod == "edge-0"
        ));
        assert!(error.to_string().contains("edge-0"), "{error}");
    }

    /// Every config write site consults the guard. Narrow in the way the
    /// write-order guard above is narrow, and for the same reason: this
    /// reads the source rather than a live apiserver. What it buys is
    /// that a fourth write path cannot be added without deciding about
    /// the pin, which is the failure mode a decision-function-only test
    /// would miss.
    #[test]
    fn every_config_write_site_consults_the_fallback_guard() {
        let src = production_source();
        assert_eq!(
            src.matches("require_config_push_allowed(").count(),
            // The definition, the pre-apply call, and two per workload
            // path: the entry check and the re-check before the apply.
            6,
            "a config write site that does not call the guard would push config to a pinned node",
        );
        // The write gate is deliberately *wider* than the config guard:
        // it also covers the credentialed pod probe and the Service
        // apply, neither of which puts configuration on a pod. Pinned as
        // an exact count rather than an inequality so adding a site to
        // either one has to be a deliberate edit here.
        assert_eq!(
            src.matches("require_write_gate(").count(),
            7,
            "the leader fence guards the five config write sites plus the credentialed pod \
             probe, plus its own definition",
        );
    }

    /// The detector has to be as wide as the thing it protects.
    ///
    /// The round-one Blocker was that the operator sent its admin
    /// credential to any pod carrying the instance label. The fix added
    /// `pod_is_operator_owned` to the fallback probe and stopped there,
    /// while `try_hot_reload` went on posting the same credential to the
    /// same unfiltered list. One of two paths fixed reads as fixed to
    /// anyone checking the path the finding cited, which is how it
    /// survived two rounds.
    ///
    /// So this counts the credential sends rather than the check: every
    /// place that puts `authorization` on a request to a pod must have
    /// an ownership filter, and adding a third sender without one moves
    /// these two numbers apart.
    ///
    /// What it cannot see, stated rather than implied. It matches the
    /// literal `header("authorization"`, so `.basic_auth(...)`,
    /// `.bearer_auth(...)` and `.header(AUTHORIZATION, ...)` are all
    /// invisible to it; none exists in this crate today, and this
    /// assertion is what makes adding one a deliberate edit here. It
    /// also cannot see whether a counted check actually *gates* its
    /// send, because it counts occurrences and not control flow. Three
    /// tests cover that half, and the split follows the two paths'
    /// different shapes rather than being symmetric.
    ///
    /// The **probe** gates inside its loop: it iterates `&pods.items`
    /// and `continue`s on an unowned pod, so there is no filter step to
    /// empty and the loop is always entered.
    /// `a_labeled_pod_the_operator_did_not_create_is_neither_probed_nor_obeyed`
    /// therefore exercises the in-loop gate directly with a single
    /// unowned pod, and asserting the stub was asked nothing is proof
    /// the gate holds.
    ///
    /// The **hot reload** filters first and returns `NoPodsFound` when
    /// nothing survives, so an all-unowned fixture returns before the
    /// request loop:
    /// `the_reload_credential_never_reaches_a_pod_the_operator_did_not_create`
    /// covers that early return, and
    /// `a_partial_owner_filter_reloads_only_the_owned_pod_and_reports_the_rest`
    /// is the one that reaches the loop, with one owned pod and one
    /// impostor, and catches iterating the unfiltered list after
    /// computing `owned`. All three drive the real code against a stub
    /// that counts what it was asked.
    #[test]
    fn every_credentialed_pod_request_is_filtered_by_ownership() {
        let src = production_source();
        let senders = src.matches("header(\"authorization\"").count();
        let checks = src.matches("pod_is_operator_owned(").count();
        assert_eq!(
            senders, 2,
            "the credentialed pod requests are the fallback probe and the hot reload; a third \
             needs an ownership filter and a line here saying so",
        );
        assert_eq!(
            checks, senders,
            "every path that sends a pod the admin credential must first check the pod is one \
             this operator's own workload created",
        );
    }
}
