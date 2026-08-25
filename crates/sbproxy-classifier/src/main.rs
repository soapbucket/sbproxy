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
mod startup;
mod tcp;

// The Group B frame-allocation regression observes the allocator itself, not
// a counter adjacent to `Vec` construction. This remains test-only, but it is
// installed at crate root so allocations hidden inside an admission lease are
// visible too.
#[cfg(test)]
#[global_allocator]
static GROUP_B_FRAME_ALLOCATOR: tcp::FrameTrackingAllocator<std::alloc::System> =
    tcp::FrameTrackingAllocator::new(std::alloc::System);

use anyhow::{Context, Result};
use clap::Parser;
use sbproxy_classifiers::{OnnxClassifier, OnnxEmbedder};
use std::collections::HashMap;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

const MAX_LISTENER_TLS_PEM_BYTES: u64 = 256 * 1024;

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
    /// Mode-0600 JSON file containing bearer tokens accepted by the gRPC
    /// inference listener. When present, requests must send
    /// `authorization: Bearer <token>`.
    #[arg(long = "inference-token-file")]
    inference_token_file: Option<PathBuf>,
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
    /// PEM certificate chain for TLS on the gRPC listener.
    #[arg(long = "listen-tls-cert-file")]
    listen_tls_cert_file: Option<PathBuf>,
    /// PEM private key for TLS on the gRPC listener. Must be a mode-0600
    /// regular file.
    #[arg(long = "listen-tls-key-file")]
    listen_tls_key_file: Option<PathBuf>,
    /// Optional PEM CA bundle used to verify gRPC client certificates.
    #[arg(long = "listen-tls-client-ca-file")]
    listen_tls_client_ca_file: Option<PathBuf>,
    /// If set with `--listen-tls-client-ca-file`, verify client certificates
    /// when present but do not require one on every connection.
    #[arg(long = "listen-tls-client-auth-optional")]
    listen_tls_client_auth_optional: bool,
}

struct GrpcListenerSecurity {
    request_auth: Option<grpc::GrpcRequestAuthentication>,
    tls_config: Option<ServerTlsConfig>,
}

impl std::fmt::Debug for GrpcListenerSecurity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrpcListenerSecurity")
            .field("request_auth", &self.request_auth)
            .field(
                "tls_config",
                &self.tls_config.as_ref().map(|_| "<configured>"),
            )
            .finish()
    }
}

async fn bind_required_listeners(
    grpc: SocketAddr,
    tcp: SocketAddr,
    metrics: SocketAddr,
    admin: Option<SocketAddr>,
    _ready: &health::ReadyState,
    tcp_limits: tcp::TcpLimits,
    http_limits: health::HttpLimits,
) -> Result<startup::BoundClassifierListeners> {
    tcp_limits.validate()?;
    http_limits.validate()?;
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
    Ok(startup::BoundClassifierListeners {
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

fn read_bounded_listener_file(
    path: &Path,
    label: &str,
    require_private_permissions: bool,
) -> Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("opening {label} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("reading {label} metadata {}", path.display()))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("{label} {} must be a regular file", path.display());
    }
    #[cfg(unix)]
    if require_private_permissions {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{label} {} must not be readable or writable by group/other",
                path.display()
            );
        }
    }
    if metadata.len() > MAX_LISTENER_TLS_PEM_BYTES {
        anyhow::bail!(
            "{label} {} exceeds {} byte limit",
            path.display(),
            MAX_LISTENER_TLS_PEM_BYTES
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_LISTENER_TLS_PEM_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} {}", path.display()))?;
    if bytes.len() as u64 > MAX_LISTENER_TLS_PEM_BYTES {
        anyhow::bail!(
            "{label} {} exceeds {} byte limit",
            path.display(),
            MAX_LISTENER_TLS_PEM_BYTES
        );
    }
    Ok(bytes)
}

fn grpc_listener_security(cli: &Cli) -> Result<GrpcListenerSecurity> {
    let request_auth = cli
        .inference_token_file
        .as_deref()
        .map(auth::InferenceAuth::from_file)
        .transpose()?
        .map(Arc::new)
        .map(|auth| {
            grpc::GrpcRequestAuthentication::bearer(
                tonic::codegen::http::header::AUTHORIZATION,
                "Bearer",
                auth,
            )
        });

    let tls_cert = cli.listen_tls_cert_file.as_deref();
    let tls_key = cli.listen_tls_key_file.as_deref();
    let tls_client_ca = cli.listen_tls_client_ca_file.as_deref();
    if tls_cert.is_some() != tls_key.is_some() {
        anyhow::bail!("--listen-tls-cert-file and --listen-tls-key-file must be provided together");
    }
    if tls_client_ca.is_some() && tls_cert.is_none() {
        anyhow::bail!(
            "--listen-tls-client-ca-file requires --listen-tls-cert-file and --listen-tls-key-file"
        );
    }
    if cli.listen_tls_client_auth_optional && tls_client_ca.is_none() {
        anyhow::bail!("--listen-tls-client-auth-optional requires --listen-tls-client-ca-file");
    }

    let tls_config = match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let cert_pem =
                read_bounded_listener_file(cert_path, "gRPC listener TLS certificate file", false)?;
            let key_pem = read_bounded_listener_file(key_path, "gRPC listener TLS key file", true)?;
            let mut tls_config =
                ServerTlsConfig::new().identity(Identity::from_pem(cert_pem, key_pem));
            if let Some(ca_path) = tls_client_ca {
                let ca_pem =
                    read_bounded_listener_file(ca_path, "gRPC listener TLS client CA file", false)?;
                tls_config = tls_config.client_ca_root(Certificate::from_pem(ca_pem));
                if cli.listen_tls_client_auth_optional {
                    tls_config = tls_config.client_auth_optional(true);
                }
            }
            let _ = tonic::transport::Server::builder()
                .tls_config(tls_config.clone())
                .context("validating gRPC listener TLS settings")?;
            Some(tls_config)
        }
        (None, None) => None,
        _ => unreachable!("validated TLS identity completeness above"),
    };

    Ok(GrpcListenerSecurity {
        request_auth,
        tls_config,
    })
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
    startup::run_release_main(Cli::parse()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    trait AmbiguousIfClone<Marker> {
        fn assert_not_clone() {}
    }

    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfDefault<Marker> {
        fn assert_not_default() {}
    }

    impl<T: ?Sized> AmbiguousIfDefault<()> for T {}
    impl<T: ?Sized + Default> AmbiguousIfDefault<u8> for T {}

    #[tokio::test]
    async fn production_entrypoint_orders_preparation_and_listener_owners_before_readiness() {
        use crate::startup::{
            BoundClassifierListeners, ClassifierListenerOwners, PreparedRuntimeCapability,
            StartupEvent, StartupTestControl,
        };

        // These are type contracts, not event-name assertions: production
        // can construct the complete listener owner set only by consuming the
        // opaque capability emitted by successful runtime preparation.  The
        // returned owner set must retain that same capability for its entire
        // lifetime.  Because the capability is neither Clone nor Default, the
        // by-value factory cannot be called a second time with an equivalent
        // token or reused through a borrowed reference.
        type PreparedOwnerFactory =
            fn(PreparedRuntimeCapability, BoundClassifierListeners) -> ClassifierListenerOwners;
        type RetainedCapabilityAccessor = for<'owners> fn(
            &'owners ClassifierListenerOwners,
        )
            -> &'owners PreparedRuntimeCapability;
        let _prepared_owner_factory: PreparedOwnerFactory = ClassifierListenerOwners::from_prepared;
        let _retained_capability_accessor: RetainedCapabilityAccessor =
            ClassifierListenerOwners::prepared_runtime_capability;
        let _ = <PreparedRuntimeCapability as AmbiguousIfClone<_>>::assert_not_clone;
        let _ = <PreparedRuntimeCapability as AmbiguousIfDefault<_>>::assert_not_default;

        // Prove the shipped crate entrypoint itself remains a deliberately tiny
        // delegator. This structural assertion is independent of runtime probe
        // counters and fails if listener builders are reintroduced beside the
        // capability-owning production assembly.
        let source = include_str!("main.rs");
        let main_start = source
            .find("#[tokio::main]\nasync fn main")
            .expect("crate-level async main remains present");
        let tests_start = source[main_start..]
            .find("\n#[cfg(test)]")
            .map(|offset| main_start + offset)
            .expect("test module follows the crate entrypoint");
        let shipped_main = &source[main_start..tests_start];
        assert_eq!(
            shipped_main.matches("startup::run_release_main").count(),
            1,
            "the shipped entrypoint delegates exactly once to the production startup owner"
        );
        for bypass in ["Server::builder", "serve_on(", "bind_required_listeners("] {
            assert!(
                !shipped_main.contains(bypass),
                "the shipped entrypoint bypasses startup ownership via {bypass}"
            );
        }

        let control = StartupTestControl::acquire_unique().await;
        let probe = control.probe();
        let cli = Cli {
            listen: "127.0.0.1:0".to_string(),
            listen_tcp: "127.0.0.1:0".to_string(),
            listen_admin: None,
            admin_token_file: None,
            inference_token_file: None,
            metrics_addr: "127.0.0.1:0".to_string(),
            models: Vec::new(),
            default_model: None,
            embed_models: Vec::new(),
            default_embed_model: None,
            inference_max_running: grpc::DEFAULT_MAX_RUNNING,
            inference_max_queued: grpc::DEFAULT_MAX_QUEUED,
            inference_deadline_ms: grpc::DEFAULT_DEADLINE_MS,
            tcp_max_connections: tcp::DEFAULT_MAX_CONNECTIONS,
            tcp_io_timeout_ms: 5_000,
            listen_tls_cert_file: None,
            listen_tls_key_file: None,
            listen_tls_client_ca_file: None,
            listen_tls_client_auth_optional: false,
        };
        let scoped_control = control.clone();
        let mut startup =
            Box::pin(scoped_control.observe_current_task(crate::startup::run_release_main(cli)));
        tokio::select! {
            result = &mut startup => {
                panic!("production startup exited before readiness: {result:?}");
            }
            ready = probe.wait_for_ready(std::time::Duration::from_secs(3)) => {
                ready.expect(
                    "production startup publishes readiness before its bounded probe deadline",
                );
            }
        }

        let events = probe.events();
        assert_eq!(
            events.iter().map(StartupEvent::kind).collect::<Vec<_>>(),
            vec![
                "panic_policy_installed",
                "catalog_validated",
                "blocking_executor_prepared",
                "runtime_prepared",
                "listeners_bound",
                "grpc_owner_started",
                "tcp_pair_owner_started",
                "http_owner_started",
                "readiness_published",
            ],
            "the observed events come from the one production startup state machine",
        );
        let prepared_runtime = events
            .iter()
            .find_map(StartupEvent::prepared_runtime_id)
            .expect("startup emits one typed prepared-runtime identity");
        for event in events.iter().filter(|event| event.is_listener_owner()) {
            assert_eq!(
                event.prepared_runtime_id(),
                Some(prepared_runtime),
                "no listener owner can be constructed without the prepared runtime token"
            );
        }
        assert_eq!(probe.panic_policy_installations(), 1);
        assert_eq!(probe.catalog_validations(), 1);
        assert_eq!(probe.blocking_executor_preparations(), 1);
        assert_eq!(
            probe.prepared_capability_issuances(),
            1,
            "preparation emits exactly one unforgeable listener capability"
        );
        assert_eq!(
            probe.prepared_capability_consumptions(),
            1,
            "the one listener-owner set consumes the one prepared capability"
        );
        assert_eq!(probe.listener_owner_sets_constructed(), 1);
        assert_eq!(
            probe.listener_owner_sets_retaining_capability(),
            1,
            "the consumed capability remains owned by the live listener set"
        );
        assert_eq!(
            probe.release_main_entrypoint_invocations(),
            1,
            "the test enters the same non-test startup assembly called by release main"
        );
        assert_eq!(
            probe.test_only_startup_entrypoint_invocations(),
            0,
            "a cfg(test) mirror is not an acceptable listener assembly"
        );
        assert_eq!(probe.grpc_owner_starts(), 1);
        assert_eq!(probe.tcp_pair_owner_starts(), 1);
        assert_eq!(probe.http_owner_starts(), 1);
        assert_eq!(probe.readiness_publications(), 1);
        assert_eq!(
            probe.raw_listener_starts(),
            0,
            "startup may not bypass the typed owners with the old inline builders"
        );
        assert_eq!(
            probe.owner_starts_without_prepared_capability(),
            0,
            "no listener constructor is reachable without the prepared capability"
        );
        assert_eq!(
            probe.duplicate_equivalent_owner_path_starts(),
            0,
            "a parallel owner assembly beside the capability-gated path is forbidden"
        );
        assert_eq!(
            probe.raw_listener_builder_exports(),
            0,
            "raw listener builders stay private to the one production startup owner module"
        );

        let shutdown_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        probe.request_shutdown_before(shutdown_deadline);
        let exit = tokio::time::timeout_at(shutdown_deadline, &mut startup)
            .await
            .expect("production startup joins before its cleanup deadline")
            .expect("production startup shuts down cleanly");
        exit.assert_quiescent_at_return()
            .expect("production startup returns only with every listener child joined");
        assert_eq!(exit.active_listener_children(), 0);
        assert_eq!(
            exit.listener_children_spawned(),
            exit.listener_children_finished(),
            "the typed startup owner set cannot detach a listener child"
        );
        assert_eq!(
            exit.listener_child_results_collected(),
            exit.listener_children_spawned(),
            "release startup returns only after inspecting every listener result"
        );
        assert_eq!(exit.listener_child_errors(), 0);
        assert_eq!(exit.listener_child_panics(), 0);
        assert_eq!(
            exit.listener_child_events_after_owner_return(),
            0,
            "startup cannot report success before a detached listener reaper catches up"
        );
        assert_eq!(exit.collection_deadline_id(), probe.shutdown_deadline_id());
    }

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
            tcp::TcpLimits::default(),
            health::HttpLimits {
                max_connections: health::DEFAULT_MAX_CONNECTIONS,
                io_timeout: health::DEFAULT_IO_TIMEOUT,
            },
        )
        .await;

        assert!(result.is_err());
        assert!(!ready.is_ready());
    }

    #[tokio::test]
    async fn invalid_http_limits_cannot_publish_readiness() {
        let ready = health::ReadyState::new();
        let invalid_http_limits = health::HttpLimits {
            max_connections: 0,
            io_timeout: health::DEFAULT_IO_TIMEOUT,
        };
        assert!(invalid_http_limits.validate().is_err());

        let result = bind_required_listeners(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            None,
            &ready,
            tcp::TcpLimits::default(),
            invalid_http_limits,
        )
        .await;

        assert!(result.is_err());
        assert!(
            !ready.is_ready(),
            "HTTP limits must be validated before listener binding can publish readiness"
        );
    }

    #[tokio::test]
    async fn invalid_tcp_limits_cannot_publish_readiness() {
        let mut observed = Vec::new();
        for max_connections in [0, tcp::DEFAULT_MAX_CONNECTIONS + 1] {
            let ready = health::ReadyState::new();
            let result = bind_required_listeners(
                "127.0.0.1:0".parse().unwrap(),
                "127.0.0.1:0".parse().unwrap(),
                "127.0.0.1:0".parse().unwrap(),
                None,
                &ready,
                tcp::TcpLimits {
                    max_connections,
                    io_timeout: Duration::from_millis(100),
                },
                health::HttpLimits {
                    max_connections: health::DEFAULT_MAX_CONNECTIONS,
                    io_timeout: health::DEFAULT_IO_TIMEOUT,
                },
            )
            .await;
            observed.push((max_connections, result.is_err(), ready.is_ready()));
        }
        assert_eq!(
            observed,
            vec![
                (0, true, false),
                (tcp::DEFAULT_MAX_CONNECTIONS + 1, true, false),
            ],
            "zero and ceiling-plus-one TCP limits must both fail before readiness"
        );
    }

    #[test]
    fn remote_admin_bind_is_rejected_even_with_a_bearer_transport() {
        let error = loopback_admin_address(Some("0.0.0.0:9401")).unwrap_err();
        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn grpc_listener_security_requires_complete_tls_identity() {
        let cli = Cli {
            listen: "127.0.0.1:9500".to_string(),
            listen_tcp: "127.0.0.1:9400".to_string(),
            listen_admin: None,
            admin_token_file: None,
            inference_token_file: None,
            metrics_addr: "127.0.0.1:9402".to_string(),
            models: Vec::new(),
            default_model: None,
            embed_models: Vec::new(),
            default_embed_model: None,
            inference_max_running: grpc::DEFAULT_MAX_RUNNING,
            inference_max_queued: grpc::DEFAULT_MAX_QUEUED,
            inference_deadline_ms: grpc::DEFAULT_DEADLINE_MS,
            tcp_max_connections: tcp::DEFAULT_MAX_CONNECTIONS,
            tcp_io_timeout_ms: 5_000,
            listen_tls_cert_file: Some(PathBuf::from("server.pem")),
            listen_tls_key_file: None,
            listen_tls_client_ca_file: None,
            listen_tls_client_auth_optional: false,
        };
        let error = grpc_listener_security(&cli).unwrap_err();
        assert!(error.to_string().contains("provided together"));
    }

    #[test]
    fn grpc_listener_security_requires_client_ca_for_optional_client_auth() {
        let cli = Cli {
            listen: "127.0.0.1:9500".to_string(),
            listen_tcp: "127.0.0.1:9400".to_string(),
            listen_admin: None,
            admin_token_file: None,
            inference_token_file: None,
            metrics_addr: "127.0.0.1:9402".to_string(),
            models: Vec::new(),
            default_model: None,
            embed_models: Vec::new(),
            default_embed_model: None,
            inference_max_running: grpc::DEFAULT_MAX_RUNNING,
            inference_max_queued: grpc::DEFAULT_MAX_QUEUED,
            inference_deadline_ms: grpc::DEFAULT_DEADLINE_MS,
            tcp_max_connections: tcp::DEFAULT_MAX_CONNECTIONS,
            tcp_io_timeout_ms: 5_000,
            listen_tls_cert_file: None,
            listen_tls_key_file: None,
            listen_tls_client_ca_file: None,
            listen_tls_client_auth_optional: true,
        };
        let error = grpc_listener_security(&cli).unwrap_err();
        assert!(error
            .to_string()
            .contains("requires --listen-tls-client-ca-file"));
    }

    #[test]
    fn grpc_listener_security_loads_request_auth_from_file() {
        let directory = tempfile::tempdir().expect("tempdir");
        let token_file = directory.path().join("inference-auth.json");
        std::fs::write(&token_file, br#"{"tokens":["secret-token"]}"#).expect("token fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut permissions = std::fs::metadata(&token_file).unwrap().permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&token_file, permissions).unwrap();
        }

        let cli = Cli {
            listen: "127.0.0.1:9500".to_string(),
            listen_tcp: "127.0.0.1:9400".to_string(),
            listen_admin: None,
            admin_token_file: None,
            inference_token_file: Some(token_file),
            metrics_addr: "127.0.0.1:9402".to_string(),
            models: Vec::new(),
            default_model: None,
            embed_models: Vec::new(),
            default_embed_model: None,
            inference_max_running: grpc::DEFAULT_MAX_RUNNING,
            inference_max_queued: grpc::DEFAULT_MAX_QUEUED,
            inference_deadline_ms: grpc::DEFAULT_DEADLINE_MS,
            tcp_max_connections: tcp::DEFAULT_MAX_CONNECTIONS,
            tcp_io_timeout_ms: 5_000,
            listen_tls_cert_file: None,
            listen_tls_key_file: None,
            listen_tls_client_ca_file: None,
            listen_tls_client_auth_optional: false,
        };

        let security = grpc_listener_security(&cli).expect("request auth must load");
        assert!(security.request_auth.is_some());
        assert!(security.tls_config.is_none());
    }

    #[test]
    fn grpc_listener_security_rejects_invalid_pem_before_bind() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cert_path = directory.path().join("server.pem");
        let key_path = directory.path().join("server.key");
        std::fs::write(&cert_path, b"not a certificate").unwrap();
        std::fs::write(&key_path, b"not a key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut permissions = std::fs::metadata(&key_path).unwrap().permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&key_path, permissions).unwrap();
        }

        let cli = Cli {
            listen: "127.0.0.1:9500".to_string(),
            listen_tcp: "127.0.0.1:9400".to_string(),
            listen_admin: None,
            admin_token_file: None,
            inference_token_file: None,
            metrics_addr: "127.0.0.1:9402".to_string(),
            models: Vec::new(),
            default_model: None,
            embed_models: Vec::new(),
            default_embed_model: None,
            inference_max_running: grpc::DEFAULT_MAX_RUNNING,
            inference_max_queued: grpc::DEFAULT_MAX_QUEUED,
            inference_deadline_ms: grpc::DEFAULT_DEADLINE_MS,
            tcp_max_connections: tcp::DEFAULT_MAX_CONNECTIONS,
            tcp_io_timeout_ms: 5_000,
            listen_tls_cert_file: Some(cert_path),
            listen_tls_key_file: Some(key_path),
            listen_tls_client_ca_file: None,
            listen_tls_client_auth_optional: false,
        };

        let error = grpc_listener_security(&cli).unwrap_err();
        assert!(error
            .to_string()
            .contains("validating gRPC listener TLS settings"));
    }
}
