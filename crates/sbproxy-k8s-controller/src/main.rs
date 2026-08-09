// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! `sbproxy-k8s-controller` entry point.
//!
//! Wires the Gateway API watchers to the reconciler, serves `/healthz`,
//! `/readyz`, and `/metrics`, and exits cleanly on SIGTERM. Everything
//! worth testing lives in the library; this file is argument parsing and
//! process lifecycle.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use kube::Client;

use sbproxy_k8s_controller::{
    config_writer::{WriterOptions, DEFAULT_CLUSTER_DOMAIN, DEFAULT_TLS_MOUNT_DIR},
    controller::{self, ControllerHandle, KIND_PERIODIC},
    health, metrics,
    reconciler::ReconcilerConfig,
    shutdown, CONTROLLER_NAME,
};

#[derive(Parser, Debug)]
#[command(
    name = "sbproxy-k8s-controller",
    about = "Kubernetes Gateway API controller for sbproxy",
    long_about = "Watches gateway.networking.k8s.io/v1 GatewayClass, Gateway, HTTPRoute, and \
                  GRPCRoute resources and renders them into an sb.yml the sbproxy data plane \
                  reads. Implements a subset of Gateway API v1; it is not conformance tested.",
    version
)]
struct Args {
    /// Path the controller writes the rendered sb.yml to. The data plane
    /// pod should mount this path read-only.
    #[arg(
        long,
        env = "SBPROXY_CONFIG_OUT",
        default_value = "/etc/sbproxy/sb.yml"
    )]
    config_out: PathBuf,

    /// Narrow this replica to a single GatewayClass name. By default
    /// every GatewayClass naming this controller is served.
    #[arg(long, env = "SBPROXY_GATEWAY_CLASS")]
    gateway_class: Option<String>,

    /// Restrict the Gateway and route watches to one namespace. Default
    /// is cluster-wide. GatewayClass is cluster scoped and is never
    /// narrowed.
    #[arg(long, env = "SBPROXY_WATCH_NAMESPACE")]
    watch_namespace: Option<String>,

    /// Directory the Gateway TLS Secrets are mounted under, one
    /// subdirectory per Secret name.
    #[arg(long, env = "SBPROXY_TLS_MOUNT_DIR", default_value = DEFAULT_TLS_MOUNT_DIR)]
    tls_mount_dir: String,

    /// Cluster DNS domain used to build Service addresses.
    #[arg(long, env = "SBPROXY_CLUSTER_DOMAIN", default_value = DEFAULT_CLUSTER_DOMAIN)]
    cluster_domain: String,

    /// Address for the health and metrics HTTP server.
    #[arg(long, env = "SBPROXY_HEALTH_ADDR", default_value = "0.0.0.0:8081")]
    health_addr: String,

    /// Run a full reconcile every N seconds even with no watch event, as
    /// a defense against a missed one.
    #[arg(long, env = "SBPROXY_RECONCILE_INTERVAL_SECS", default_value_t = 300)]
    reconcile_interval_secs: u64,

    /// Verify the Gateway API CRDs are installed before starting the
    /// watchers. Without this a missing CRD looks like an empty cluster.
    #[arg(long, env = "SBPROXY_VERIFY_CRDS", default_value_t = true)]
    verify_crds: bool,

    /// Acquire a Lease before reconciling, so only one replica writes.
    /// Off by default, which is correct for a single replica.
    #[arg(long, env = "SBPROXY_LEADER_ELECTION", default_value_t = false)]
    leader_election: bool,

    /// Lease name for leader election.
    #[arg(
        long,
        env = "SBPROXY_LEASE_NAME",
        default_value = "sbproxy-gateway-controller"
    )]
    lease_name: String,

    /// Lease namespace for leader election.
    #[arg(
        long,
        env = "SBPROXY_LEASE_NAMESPACE",
        default_value = "sbproxy-system"
    )]
    lease_namespace: String,

    /// Log level. Falls back to `RUST_LOG` when that is set.
    #[arg(long, env = "SBPROXY_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 requires the process to pick a CryptoProvider before
    // any TLS handshake, and the kube client speaks TLS to the API
    // server. An Err here means one is already installed, which is fine.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("a rustls crypto provider was already installed; continuing with it");
    }

    let args = Args::parse();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    metrics::init();

    tracing::info!(
        target: "k8s_audit",
        controller_name = CONTROLLER_NAME,
        gateway_class = ?args.gateway_class,
        config_out = %args.config_out.display(),
        watch_namespace = ?args.watch_namespace,
        health_addr = %args.health_addr,
        leader_election = args.leader_election,
        "sbproxy-k8s-controller starting"
    );

    let (shutdown_sig, shutdown_trig) = shutdown::channel();

    let health_addr: SocketAddr = args
        .health_addr
        .parse()
        .with_context(|| format!("invalid --health-addr {}", args.health_addr))?;
    let health_shutdown = shutdown_sig.clone();
    let health_task = tokio::spawn(async move {
        if let Err(e) = serve_health(health_addr, health_shutdown).await {
            tracing::error!(target: "k8s_audit", error = %e, "health server exited");
        }
    });

    let signal_task = tokio::spawn(shutdown::install_signal_handler(shutdown_trig.clone()));

    let client = Client::try_default()
        .await
        .context("build a kube Client; is in-cluster auth or KUBECONFIG wired up?")?;

    let crd_check = if args.verify_crds {
        controller::verify_crds_installed(&client).await
    } else {
        Ok(())
    };
    if let Err(e) = crd_check {
        tracing::error!(
            target: "k8s_audit",
            error = %e,
            "Gateway API CRD discovery failed; install the gateway-api CRDs and restart"
        );
        shutdown_trig.trigger();
        let _ = signal_task.await;
        let _ = health_task.await;
        return Err(e);
    }

    if args.leader_election {
        tracing::info!(
            target: "k8s_audit",
            lease = %args.lease_name,
            namespace = %args.lease_namespace,
            "acquiring the leader-election Lease before starting watchers"
        );
        match acquire_leader_lease(
            &client,
            &args.lease_namespace,
            &args.lease_name,
            shutdown_sig.clone(),
        )
        .await
        {
            Ok(true) => tracing::info!(target: "k8s_audit", "leader lease acquired"),
            Ok(false) => {
                tracing::info!(target: "k8s_audit", "shutdown arrived before the lease was won");
                let _ = signal_task.await;
                let _ = health_task.await;
                return Ok(());
            }
            Err(e) => {
                tracing::error!(target: "k8s_audit", error = %e, "leader election failed");
                shutdown_trig.trigger();
                let _ = signal_task.await;
                let _ = health_task.await;
                return Err(e);
            }
        }
    }

    let handle = Arc::new(ControllerHandle::with_client(
        ReconcilerConfig {
            output_path: args.config_out.clone(),
            gateway_class: args.gateway_class.clone(),
            writer: WriterOptions {
                tls_mount_dir: args.tls_mount_dir.clone(),
                cluster_domain: args.cluster_domain.clone(),
            },
        },
        client.clone(),
    ));

    // Periodic full resync, as a safety net for a watch event that never
    // arrived. Floored at 10s so a misconfigured interval cannot turn
    // into a hot loop against the API server.
    let resync_handle = handle.clone();
    let resync_shutdown = shutdown_sig.clone();
    let interval = Duration::from_secs(args.reconcile_interval_secs.max(10));
    let resync_task = tokio::spawn(async move {
        let scheduler = resync_handle.scheduler();
        loop {
            tokio::select! {
                _ = resync_shutdown.wait() => return,
                _ = tokio::time::sleep(interval) => {
                    let _ = scheduler.try_send(KIND_PERIODIC);
                }
            }
        }
    });

    let run_result = controller::run(
        client,
        handle,
        args.watch_namespace.as_deref(),
        shutdown_sig.clone(),
    )
    .await;

    if let Err(e) = run_result {
        tracing::error!(target: "k8s_audit", error = %e, "controller exited with an error");
    }

    let _ = resync_task.await;
    let _ = signal_task.await;
    let _ = health_task.await;
    Ok(())
}

// --- Health, readiness, metrics -----------------------------------------

async fn serve_health(addr: SocketAddr, shutdown: shutdown::ShutdownSignal) -> anyhow::Result<()> {
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    tracing::info!(target: "k8s_audit", %addr, "health server listening");

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                tracing::info!(target: "k8s_audit", "health server stopping");
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(target: "k8s_audit", error = %e, "health accept error");
                        continue;
                    }
                };
                let io = TokioIo::new(stream);
                tokio::task::spawn(async move {
                    let svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                        let (status, body, content_type) = match req.uri().path() {
                            "/healthz" => {
                                let (s, b) = health::health_check();
                                (s, b.to_string(), "application/json")
                            }
                            "/readyz" => {
                                let (s, b) = health::readiness_check();
                                (s, b.to_string(), "application/json")
                            }
                            "/metrics" => (
                                200,
                                metrics::gather_text(),
                                "text/plain; version=0.0.4",
                            ),
                            _ => (404, r#"{"error":"not found"}"#.to_string(), "application/json"),
                        };
                        let response = Response::builder()
                            .status(status)
                            .header("content-type", content_type)
                            .body(Full::new(Bytes::from(body)))
                            .unwrap_or_else(|_| {
                                Response::new(Full::new(Bytes::from_static(b"error")))
                            });
                        Ok::<_, std::convert::Infallible>(response)
                    });
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await
                    {
                        tracing::debug!(target: "k8s_audit", error = %e, "health connection closed");
                    }
                });
            }
        }
    }
}

// --- Leader election -----------------------------------------------------

/// Acquire a `coordination.k8s.io/v1` Lease. `Ok(true)` once held,
/// `Ok(false)` when shutdown arrived first.
///
/// Poll-create-then-apply with a fixed retry period, the same shape
/// client-go uses, so no extra dependency is needed. Only relevant with
/// more than one replica: two controllers writing the same `sb.yml` would
/// fight over the file.
async fn acquire_leader_lease(
    client: &Client,
    namespace: &str,
    name: &str,
    shutdown: shutdown::ShutdownSignal,
) -> anyhow::Result<bool> {
    use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
    use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};

    let identity = format!("{}-{}", hostname_or_default(), std::process::id());
    let api: Api<Lease> = Api::namespaced(client.clone(), namespace);

    let lease_duration_secs = 15i32;
    let retry_period = Duration::from_secs(5);

    loop {
        let now = MicroTime(chrono::Utc::now());
        match api.get_opt(name).await.context("read the leader Lease")? {
            None => {
                let body = Lease {
                    metadata: ObjectMeta {
                        name: Some(name.to_string()),
                        namespace: Some(namespace.to_string()),
                        ..Default::default()
                    },
                    spec: Some(LeaseSpec {
                        holder_identity: Some(identity.clone()),
                        lease_duration_seconds: Some(lease_duration_secs),
                        acquire_time: Some(now.clone()),
                        renew_time: Some(now),
                        ..Default::default()
                    }),
                };
                match api.create(&PostParams::default(), &body).await {
                    Ok(_) => return Ok(true),
                    // Someone else created it between the read and the
                    // write. Fall through and try the takeover path.
                    Err(kube::Error::Api(e)) if e.code == 409 => {}
                    Err(e) => return Err(anyhow::anyhow!("create the leader Lease: {e}")),
                }
            }
            Some(lease) => {
                let spec = lease.spec.unwrap_or_default();
                let we_hold = spec.holder_identity.as_deref() == Some(identity.as_str());
                if we_hold || is_lease_expired(&spec, lease_duration_secs) {
                    let stamp =
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
                    let patch = serde_json::json!({
                        "apiVersion": "coordination.k8s.io/v1",
                        "kind": "Lease",
                        "metadata": { "name": name },
                        "spec": {
                            "holderIdentity": identity,
                            "leaseDurationSeconds": lease_duration_secs,
                            "renewTime": stamp,
                            "acquireTime": stamp,
                        }
                    });
                    let pp = PatchParams::apply("sbproxy-gateway-controller").force();
                    if api.patch(name, &pp, &Patch::Apply(&patch)).await.is_ok() {
                        return Ok(true);
                    }
                }
            }
        }

        tokio::select! {
            _ = shutdown.wait() => return Ok(false),
            _ = tokio::time::sleep(retry_period) => {}
        }
    }
}

fn hostname_or_default() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "controller".to_string())
}

fn is_lease_expired(
    spec: &k8s_openapi::api::coordination::v1::LeaseSpec,
    lease_duration_secs: i32,
) -> bool {
    let Some(renew) = spec.renew_time.as_ref() else {
        // Never renewed, so nobody is holding it.
        return true;
    };
    chrono::Utc::now()
        .signed_duration_since(renew.0)
        .num_seconds()
        > i64::from(lease_duration_secs)
}
