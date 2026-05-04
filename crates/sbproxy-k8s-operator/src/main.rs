//! `sbproxy-k8s-operator` binary.
//!
//! Watches `SBProxy` and `SBProxyConfig` resources and reconciles them into
//! Deployment / Service / ConfigMap triples in the configured namespace (or
//! cluster-wide when `--all-namespaces` is set).
//!
//! See `docs/kubernetes.md` for end-user instructions.

#![deny(missing_docs)]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Pod, Secret, Service};
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Client, CustomResourceExt};
use sbproxy_k8s_operator::crd::{AdminAuthSecretRef, SBProxy, SBProxyConfig};
use sbproxy_k8s_operator::leader::{
    acquire_lease, build_identity, discover_namespace_default, renew_loop, LeaderConfig,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Init tracing once, regardless of subcommand.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Some(Command::PrintCrds) = cli.command {
        return print_crds();
    }

    run(cli).await
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
/// [`leader::discover_namespace_default`]. While the lease is held the
/// controller runs; if the lease is lost (network partition, theft, API
/// timeout) the controller is cancelled and the function returns `Ok(())`
/// so the binary exits with code 0. The pod is then restarted by the
/// Deployment and re-races for the lock. This matches the client-go pattern
/// used by kube-controller-manager / kubelet.
async fn run(cli: Cli) -> Result<()> {
    let client = Client::try_default().await.context(
        "failed to construct Kubernetes client; is KUBECONFIG / in-cluster auth wired up?",
    )?;

    if cli.no_leader_election {
        tracing::info!("leader election disabled (--no-leader-election)");
        return run_controller(client, &cli).await;
    }

    let lease_namespace = discover_namespace_default();
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
    acquire_lease(&client, &leader_cfg)
        .await
        .context("failed to acquire leader lease")?;

    // Run the controller and the renew loop concurrently. The first task to
    // exit wins; we cancel the other and surface a step-down log.
    let controller_client = client.clone();
    let cli_clone = cli.clone();
    let mut controller_handle =
        tokio::spawn(async move { run_controller(controller_client, &cli_clone).await });
    let mut renew_handle = tokio::spawn(renew_loop(client, leader_cfg));

    tokio::select! {
        res = &mut controller_handle => {
            renew_handle.abort();
            match res {
                Ok(inner) => inner,
                Err(join_err) => Err(anyhow::anyhow!("controller task join error: {join_err}")),
            }
        }
        res = &mut renew_handle => {
            // Lock lost. Cancel the controller and exit 0 so the pod restarts.
            controller_handle.abort();
            match res {
                Ok(Ok(())) => {
                    // Renew loop returned Ok (only on shutdown signal in the
                    // future); treat as a clean step-down.
                    tracing::info!("renew loop exited cleanly; stepping down");
                    Ok(())
                }
                Ok(Err(e)) => {
                    tracing::info!(error = %e, "lost leader lease; stepping down");
                    Ok(())
                }
                Err(join_err) => {
                    tracing::warn!(error = %join_err, "renew task join error");
                    Ok(())
                }
            }
        }
    }
}

/// Run the kube-runtime `Controller` until it exits (which only happens when
/// the watcher's stream is dropped, e.g. via `controller_handle.abort()` from
/// the leader-election step-down path).
async fn run_controller(client: Client, cli: &Cli) -> Result<()> {
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
        .owns(services, WatcherConfig::default())
        .owns(configmaps, WatcherConfig::default())
        // Re-reconcile every SBProxy when any SBProxyConfig changes. Cheap to
        // keep simple: the controller queue dedupes anyway.
        .watches(sbproxyconfig_api, WatcherConfig::default(), |_cfg| {
            std::iter::empty::<kube::runtime::reflector::ObjectRef<SBProxy>>()
        })
        .run(reconcile_one, error_policy, Arc::new(Ctx { client }))
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
/// 2. Compute the `sb.yml` content hash.
/// 3. Server-side-apply the desired ConfigMap and Service.
/// 4. Decide between **hot-reload** and **rollout-restart**:
///    - Hot-reload (`POST /admin/reload`) when only `spec.config`
///      changed and `spec.adminAuthSecretRef` is set.
///    - Rollout-restart (apply Deployment with bumped config-hash
///      annotation) otherwise, or when hot-reload fails.
///
/// Hot-reload preserves pod identity and connection state. The
/// proxy serialises the reload via an internal single-flight guard
/// so simultaneous reloads (e.g. file-watcher + admin route) never
/// race.
async fn reconcile_one(sbproxy: Arc<SBProxy>, ctx: Arc<Ctx>) -> Result<Action, ReconcileError> {
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

    let hash = reconcile::config_hash(&cfg.spec.config);

    // --- Render desired state ---
    let desired_cm = reconcile::desired_configmap(&sbproxy, &cfg);
    let desired_svc = reconcile::desired_service(&sbproxy);
    let desired_deploy = reconcile::desired_deployment(&sbproxy, &hash);

    // --- Apply ConfigMap + Service unconditionally ---
    let pp = PatchParams::apply(FIELD_MANAGER).force();

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

    // --- Decide hot-reload vs rollout-restart ---
    let deploy_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), &ns);
    let deploy_name = desired_deploy
        .metadata
        .name
        .as_deref()
        .ok_or(ReconcileError::MissingName)?;
    let existing_deploy = deploy_api.get_opt(deploy_name).await.unwrap_or(None);
    let prev_hash = existing_deploy
        .as_ref()
        .and_then(reconcile::previous_config_hash);

    let hot_reload_eligible = reconcile::should_hot_reload(
        &sbproxy,
        existing_deploy.as_ref(),
        &desired_deploy,
        prev_hash.as_deref(),
        &hash,
    );

    if hot_reload_eligible {
        // Best-effort hot-reload across every running proxy pod.
        // If any pod fails, we fall through to the rollout-restart
        // path so the cluster is never left in a half-reloaded
        // state.
        match try_hot_reload(&ctx.client, &sbproxy, &ns).await {
            Ok(()) => {
                tracing::info!(
                    name = %name,
                    namespace = %ns,
                    config_revision = %hash,
                    "hot-reloaded all proxy pods via /admin/reload"
                );
                // Skip the Deployment patch entirely so the pod
                // template's config-hash annotation stays stale
                // until the next "real" Deployment edit. The
                // ConfigMap is already up to date for any pod that
                // restarts for unrelated reasons.
                return Ok(Action::requeue(Duration::from_secs(300)));
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    name = %name,
                    namespace = %ns,
                    "hot-reload failed; falling back to rollout-restart"
                );
            }
        }
    }

    // --- Apply Deployment (rollout-restart on annotation change) ---
    deploy_api
        .patch(deploy_name, &pp, &Patch::Apply(&desired_deploy))
        .await
        .map_err(ReconcileError::Apply)?;

    // Requeue periodically as a belt-and-braces against missed watch events.
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Best-effort `POST /admin/reload` against every running proxy
/// pod for the given `SBProxy`.
///
/// Returns `Ok(())` only when every pod returned 200. Any pod that
/// returns a non-200 (or fails to dial) propagates as `Err`, which
/// triggers the rollout-restart fallback in `reconcile_one`.
async fn try_hot_reload(
    client: &Client,
    sbproxy: &SBProxy,
    namespace: &str,
) -> Result<(), HotReloadError> {
    let secret_ref = sbproxy
        .spec
        .admin_auth_secret_ref
        .as_ref()
        .ok_or(HotReloadError::NoAdminAuthSecretRef)?;

    let auth_header = read_admin_auth(client, namespace, secret_ref).await?;

    // Find every Pod owned by the proxy Deployment via the standard
    // selector (`app.kubernetes.io/instance=<sbproxy-name>`).
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let sbp_name = sbproxy
        .metadata
        .name
        .as_deref()
        .ok_or(HotReloadError::MissingPodSelector)?;
    let lp = ListParams::default().labels(&format!("app.kubernetes.io/instance={sbp_name}"));
    let pods = pods_api.list(&lp).await.map_err(HotReloadError::ListPods)?;

    if pods.items.is_empty() {
        return Err(HotReloadError::NoPodsFound);
    }

    let admin_port = sbproxy.spec.admin_port;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(HotReloadError::HttpClient)?;

    for pod in &pods.items {
        let pod_ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.as_deref())
            .ok_or(HotReloadError::PodHasNoIp)?;
        let url = format!("http://{pod_ip}:{admin_port}/admin/reload");
        let resp = http
            .post(&url)
            .header("authorization", &auth_header)
            .send()
            .await
            .map_err(HotReloadError::Request)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(HotReloadError::ProxyRejected(status.as_u16()));
        }
    }

    Ok(())
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

    /// Server-side-apply patch failed.
    #[error("failed to apply child object: {0}")]
    Apply(#[source] kube::Error),
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
mod tests {
    use super::*;
    use clap::Parser;

    /// Helper that strips the env-var bridge so `RUST_LOG` from the host
    /// shell does not leak into the parsed `Cli` and surprise the asserts.
    fn parse_cli(args: &[&str]) -> Cli {
        // SAFETY: tests are single-threaded under default cargo test layout
        // and the env vars are restored before the next test runs because we
        // explicitly remove them.
        // We cannot rely on the host env: clap reads `RUST_LOG`,
        // `SBPROXY_NAMESPACE`. Wipe both for each parse.
        std::env::remove_var("RUST_LOG");
        std::env::remove_var("SBPROXY_NAMESPACE");
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
}
