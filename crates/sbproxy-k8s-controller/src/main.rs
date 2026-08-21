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
    health, leader, metrics,
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

    // WOR-2614: with leader election on, writes are fenced by a gate that
    // only leadership opens, and leadership is a lifecycle (acquire, renew,
    // fence on loss) rather than a one-shot boolean.
    let write_gate = if args.leader_election {
        leader::WriteGate::for_election()
    } else {
        leader::WriteGate::always()
    };

    let mut leader_task = None;
    if args.leader_election {
        let identity = leader::build_identity();
        tracing::info!(
            target: "k8s_audit",
            lease = %args.lease_name,
            namespace = %args.lease_namespace,
            identity = %identity,
            "acquiring the leader-election Lease before starting watchers"
        );
        if !leader::acquire(
            &client,
            &args.lease_namespace,
            &args.lease_name,
            &identity,
            &write_gate,
            &shutdown_sig,
        )
        .await
        {
            tracing::info!(target: "k8s_audit", "shutdown arrived before the lease was won");
            let _ = signal_task.await;
            let _ = health_task.await;
            return Ok(());
        }
        tracing::info!(
            target: "k8s_audit",
            renew_period_secs = leader::RENEW_PERIOD.as_secs(),
            lease_duration_secs = leader::LEASE_DURATION.as_secs(),
            "leader lease acquired; renewing continuously"
        );

        // Renew for as long as we reconcile. On loss the gate is already
        // closed by the time `hold` returns; readiness drops and shutdown
        // cancels the watchers, so the pod exits cleanly and restarts as a
        // standby that re-races for the Lease.
        let hold_client = client.clone();
        let hold_gate = write_gate.clone();
        let hold_shutdown = shutdown_sig.clone();
        let hold_trigger = shutdown_trig.clone();
        let lease_namespace = args.lease_namespace.clone();
        let lease_name = args.lease_name.clone();
        leader_task = Some(tokio::spawn(async move {
            let end = leader::hold(
                hold_client,
                lease_namespace,
                lease_name,
                identity,
                hold_gate,
                hold_shutdown,
            )
            .await;
            if end == leader::LeadershipEnd::Lost {
                health::set_ready(false);
                tracing::warn!(
                    target: "k8s_audit",
                    "leadership lost; writes are fenced, readiness is down, and the \
                     controller is shutting down to restart as a standby"
                );
                hold_trigger.trigger();
            }
        }));
    }

    let handle = Arc::new(ControllerHandle::with_client(
        ReconcilerConfig {
            output_path: args.config_out.clone(),
            gateway_class: args.gateway_class.clone(),
            writer: WriterOptions {
                tls_mount_dir: args.tls_mount_dir.clone(),
                cluster_domain: args.cluster_domain.clone(),
            },
            write_gate: write_gate.clone(),
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
    if let Some(task) = leader_task {
        let _ = task.await;
    }
    // The signal task completes only when an OS signal arrives. A shutdown
    // that started elsewhere (a lost leader Lease fencing itself, WOR-2614)
    // must not wait for a signal that may never come.
    signal_task.abort();
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

// Leader election lives in `sbproxy_k8s_controller::leader` (WOR-2614):
// acquisition, continuous renewal, and the write fence are one lifecycle
// there, tested against an in-memory Lease with the API server's
// conditional-write semantics.
