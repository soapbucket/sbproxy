//! `sbproxy-classifier`: the rich multi-tenant prompt-classification
//! sidecar (WOR-2665).
//!
//! Ported from `sbproxy-enterprise/crates/sbproxy-classifier` (41 files,
//! 16,108 lines), cut down to the capabilities named in the ticket: heuristic
//! multi-tenant classification, quality scoring, text normalization / PII
//! redaction, ONNX embedding, intent / content-type detection, and per-token
//! streaming safety checks. See `docs/classifier-sidecar.md` for the full
//! scope note, including what was deliberately not ported (LLM-judge
//! backends, license-leak detection, the Wave 5 agent-classifier ML path,
//! Ed25519 model-signing, OpenTelemetry).
//!
//! Serves three listeners:
//!
//! - gRPC on `--listen` (default `127.0.0.1:9500`): the shared
//!   `InferenceService` contract (ONNX-backed, optional) plus the
//!   rich-only `ClassifierService` (`Quality`, `StreamSafety`).
//! - TCP + length-prefixed MessagePack on `--listen-tcp` (default
//!   `127.0.0.1:9400`): multi-tenant heuristic classify, quality scoring,
//!   intent / content-type detection, and tenant admin
//!   (register/delete/list).
//! - HTTP on `--metrics-addr` (default `127.0.0.1:9402`): `/healthz`,
//!   `/readyz`, `/metrics` (Prometheus text), `/tenants`.
//!
//! ## Optional-degrade architecture (the epic's hard requirement)
//!
//! This binary is a sidecar process a deployment must run and keep running
//! to use it. Per WOR-2661's no-external-store rule (extended to sidecar
//! processes), nothing in this OSS workspace may depend on it being up.
//! **This binary itself has no fallback story** because a sidecar cannot
//! degrade itself; the fallback lives one layer up, in the client:
//! `sbproxy-classifier-client`'s `FallbackClassifier` degrades to the
//! existing in-process `sbproxy_classifiers::OnnxClassifier` whenever this
//! process is not deployed or not reachable, so an operator who never runs
//! this binary still gets full classification via that in-process path. See
//! `crates/sbproxy-classifier-client/src/fallback.rs` and
//! `crates/sbproxy-classifier-client/examples/fallback.rs`.

mod admission;
mod auth;
mod config;
mod grpc;
mod health;
mod heuristic;
mod metrics;
mod normalize;
mod protocol;
mod quality;
mod registry;
mod tcp;

use anyhow::{Context, Result};
use clap::Parser;
use sbproxy_classifier_proto::{ClassifierServiceServer, InferenceServiceServer};
use sbproxy_classifiers::{OnnxClassifier, OnnxEmbedder};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Server;

/// CLI for the rich classifier sidecar.
#[derive(Parser)]
#[command(
    about = "Rich multi-tenant prompt-classification sidecar: gRPC + TCP/MessagePack (WOR-2665)."
)]
struct Cli {
    /// gRPC listen address: `InferenceService` (ONNX, optional) and
    /// `ClassifierService` (`Quality`, `StreamSafety`).
    #[arg(long, default_value = "127.0.0.1:9500")]
    listen: String,
    /// TCP + MessagePack listen address: multi-tenant heuristic classify,
    /// quality scoring, intent / content-type detection, tenant admin.
    #[arg(long = "listen-tcp", default_value = "127.0.0.1:9400")]
    listen_tcp: String,
    /// Optional, separate TCP + MessagePack listener for tenant administration.
    /// This listener is loopback-only and requires `--admin-token-file`.
    #[arg(long = "listen-admin")]
    listen_admin: Option<String>,
    /// Mode-0600 JSON file containing scoped admin bearer-token grants.
    /// Also protects `GET /tenants` on the HTTP listener.
    #[arg(long = "admin-token-file")]
    admin_token_file: Option<PathBuf>,
    /// HTTP listen address for `/healthz`, `/readyz`, `/metrics`, `/tenants`.
    #[arg(long = "metrics-addr", default_value = "127.0.0.1:9402")]
    metrics_addr: String,
    /// ONNX classifier to load for gRPC `Classify`, as
    /// `id=<model.onnx>:<tokenizer.json>`. Repeatable. Optional: the
    /// heuristic multi-tenant path over TCP works with zero models loaded.
    #[arg(long = "model", value_name = "ID=MODEL:TOKENIZER")]
    models: Vec<String>,
    /// Classifier model id used when a gRPC `Classify` request leaves
    /// `model` empty. Defaults to the single loaded model when exactly one
    /// is configured.
    #[arg(long)]
    default_model: Option<String>,
    /// ONNX embedding model to load for gRPC `Embed`, as
    /// `id=<model.onnx>:<tokenizer.json>`. Repeatable.
    #[arg(long = "embed-model", value_name = "ID=MODEL:TOKENIZER")]
    embed_models: Vec<String>,
    /// Embedding model id used when a gRPC `Embed` request leaves `model`
    /// empty. Defaults to the single loaded embedder when exactly one is
    /// configured.
    #[arg(long)]
    default_embed_model: Option<String>,
    /// Maximum CPU-bound gRPC requests running concurrently.
    #[arg(long, default_value_t = grpc::DEFAULT_MAX_RUNNING)]
    inference_max_running: usize,
    /// Maximum CPU-bound gRPC requests queued behind running work.
    #[arg(long, default_value_t = grpc::DEFAULT_MAX_QUEUED)]
    inference_max_queued: usize,
    /// End-to-end gRPC admission/execution deadline in milliseconds.
    #[arg(long, default_value_t = grpc::DEFAULT_DEADLINE_MS)]
    inference_deadline_ms: u64,
    /// Maximum simultaneous connections on each TCP listener.
    #[arg(long, default_value_t = tcp::DEFAULT_MAX_CONNECTIONS)]
    tcp_max_connections: usize,
    /// Per-frame TCP read/write deadline in milliseconds.
    #[arg(long, default_value_t = 5_000)]
    tcp_io_timeout_ms: u64,
}

struct BoundListeners {
    grpc: tokio::net::TcpListener,
    tcp: tokio::net::TcpListener,
    metrics: tokio::net::TcpListener,
    admin: Option<tokio::net::TcpListener>,
}

async fn bind_required_listeners(
    grpc: SocketAddr,
    tcp: SocketAddr,
    metrics: SocketAddr,
    admin: Option<SocketAddr>,
    ready: &health::ReadyState,
) -> Result<BoundListeners> {
    let grpc = tokio::net::TcpListener::bind(grpc)
        .await
        .context("binding gRPC listener")?;
    let tcp = tokio::net::TcpListener::bind(tcp)
        .await
        .context("binding public TCP listener")?;
    let metrics = tokio::net::TcpListener::bind(metrics)
        .await
        .context("binding HTTP listener")?;
    let admin = match admin {
        Some(address) => Some(
            tokio::net::TcpListener::bind(address)
                .await
                .context("binding admin TCP listener")?,
        ),
        None => None,
    };
    ready.mark_ready();
    Ok(BoundListeners {
        grpc,
        tcp,
        metrics,
        admin,
    })
}

fn loopback_admin_address(value: Option<&str>) -> Result<Option<SocketAddr>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let address: SocketAddr = value
        .parse()
        .with_context(|| format!("invalid --listen-admin address {value:?}"))?;
    if !address.ip().is_loopback() {
        anyhow::bail!(
            "--listen-admin must use a loopback address; remote administration requires a secure transport not provided by this binary"
        );
    }
    Ok(Some(address))
}

fn load_model_spec(spec: &str) -> Result<(String, Arc<OnnxClassifier>)> {
    let (id, paths) = spec
        .split_once('=')
        .with_context(|| format!("--model must be ID=MODEL:TOKENIZER, got {spec:?}"))?;
    let (model_path, tokenizer_path) = paths
        .split_once(':')
        .with_context(|| format!("--model paths must be MODEL:TOKENIZER, got {paths:?}"))?;
    let classifier = OnnxClassifier::load(Path::new(model_path), Path::new(tokenizer_path))
        .with_context(|| format!("loading model {id:?}"))?;
    Ok((id.to_string(), Arc::new(classifier)))
}

fn load_embed_spec(spec: &str) -> Result<(String, Arc<OnnxEmbedder>)> {
    let (id, paths) = spec
        .split_once('=')
        .with_context(|| format!("--embed-model must be ID=MODEL:TOKENIZER, got {spec:?}"))?;
    let (model_path, tokenizer_path) = paths
        .split_once(':')
        .with_context(|| format!("--embed-model paths must be MODEL:TOKENIZER, got {paths:?}"))?;
    let embedder = OnnxEmbedder::load(Path::new(model_path), Path::new(tokenizer_path))
        .with_context(|| format!("loading embed model {id:?}"))?;
    Ok((id.to_string(), Arc::new(embedder)))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();
    let admin_auth = cli
        .admin_token_file
        .as_deref()
        .map(auth::AdminAuth::from_file)
        .transpose()?;
    let admin_addr = loopback_admin_address(cli.listen_admin.as_deref())?;
    if admin_addr.is_some() && admin_auth.is_none() {
        anyhow::bail!("--listen-admin requires --admin-token-file");
    }

    let mut models = HashMap::new();
    for spec in &cli.models {
        let (id, classifier) = load_model_spec(spec)?;
        models.insert(id, classifier);
    }
    let default_model = cli.default_model.or_else(|| {
        (models.len() == 1)
            .then(|| models.keys().next().cloned())
            .flatten()
    });

    let mut embedders = HashMap::new();
    for spec in &cli.embed_models {
        let (id, embedder) = load_embed_spec(spec)?;
        embedders.insert(id, embedder);
    }
    let default_embed_model = cli.default_embed_model.or_else(|| {
        (embedders.len() == 1)
            .then(|| embedders.keys().next().cloned())
            .flatten()
    });

    let registry = Arc::new(registry::Registry::new_empty());
    let ready = health::ReadyState::new();

    let grpc_state = Arc::new(grpc::GrpcState {
        models,
        embedders,
        default_model,
        default_embed_model,
        version: format!("sbproxy-classifier {}", env!("CARGO_PKG_VERSION")),
        admission: admission::Admission::new(
            cli.inference_max_running,
            cli.inference_max_queued,
            Duration::from_millis(cli.inference_deadline_ms),
        )?,
    });

    let grpc_addr: SocketAddr = cli
        .listen
        .parse()
        .with_context(|| format!("invalid --listen address {:?}", cli.listen))?;
    let tcp_addr: SocketAddr = cli
        .listen_tcp
        .parse()
        .with_context(|| format!("invalid --listen-tcp address {:?}", cli.listen_tcp))?;
    let metrics_addr: SocketAddr = cli
        .metrics_addr
        .parse()
        .with_context(|| format!("invalid --metrics-addr address {:?}", cli.metrics_addr))?;
    let tcp_limits = tcp::TcpLimits {
        max_connections: cli.tcp_max_connections,
        io_timeout: Duration::from_millis(cli.tcp_io_timeout_ms),
    };
    let listeners =
        bind_required_listeners(grpc_addr, tcp_addr, metrics_addr, admin_addr, &ready).await?;

    tracing::info!(
        grpc_addr = %grpc_addr,
        tcp_addr = %cli.listen_tcp,
        metrics_addr = %cli.metrics_addr,
        models = grpc_state.models.len(),
        embedders = grpc_state.embedders.len(),
        "sbproxy-classifier starting",
    );

    let grpc_task = {
        let state = Arc::clone(&grpc_state);
        tokio::spawn(async move {
            // Both services share the same `Arc<GrpcState>` (loaded ONNX
            // models, the tenant registry), wrapped in the thin newtypes
            // `grpc::InferenceHandler` / `grpc::ClassifierHandler` that
            // Rust's orphan rules require (see their doc comments in
            // `grpc.rs`). Cloning the `Arc` is a refcount bump, not a copy
            // of the loaded models.
            Server::builder()
                .add_service(InferenceServiceServer::new(grpc::InferenceHandler(
                    Arc::clone(&state),
                )))
                .add_service(ClassifierServiceServer::new(grpc::ClassifierHandler(state)))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(
                    listeners.grpc,
                ))
                .await
        })
    };

    let tcp_task = {
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            tcp::serve_on(
                listeners.tcp,
                registry,
                tcp::TransportMode::Public,
                None,
                tcp_limits,
            )
            .await
        })
    };

    let admin_task = {
        let registry = Arc::clone(&registry);
        let auth = admin_auth.clone();
        tokio::spawn(async move {
            match (listeners.admin, auth) {
                (Some(listener), Some(auth)) => {
                    tcp::serve_on(
                        listener,
                        registry,
                        tcp::TransportMode::Admin,
                        Some(Arc::new(auth)),
                        tcp_limits,
                    )
                    .await
                }
                _ => std::future::pending().await,
            }
        })
    };

    let health_task = {
        let registry = Arc::clone(&registry);
        let ready = ready.clone();
        let auth = admin_auth.map(Arc::new);
        tokio::spawn(
            async move { health::serve_on(listeners.metrics, registry, ready, auth).await },
        )
    };

    tokio::select! {
        res = grpc_task => {
            res.context("gRPC server task panicked")?
                .context("gRPC server failed")?;
        }
        res = tcp_task => {
            res.context("TCP server task panicked")?
                .map_err(|e| anyhow::anyhow!("TCP server failed: {e}"))?;
        }
        res = health_task => {
            res.context("health server task panicked")?
                .map_err(|e| anyhow::anyhow!("health server failed: {e}"))?;
        }
        res = admin_task => {
            res.context("admin TCP server task panicked")?
                .map_err(|e| anyhow::anyhow!("admin TCP server failed: {e}"))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_bind_conflict_cannot_publish_readiness() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ready = health::ReadyState::new();
        let result = bind_required_listeners(
            occupied.local_addr().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            &ready,
        )
        .await;

        assert!(result.is_err());
        assert!(!ready.is_ready());
    }

    #[test]
    fn remote_admin_bind_is_rejected_even_with_a_bearer_transport() {
        let error = loopback_admin_address(Some("0.0.0.0:9401")).unwrap_err();
        assert!(error.to_string().contains("loopback"));
    }
}
