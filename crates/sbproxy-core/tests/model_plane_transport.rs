use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::future::join_all;
use futures::StreamExt;
use sbproxy_core::model_plane::{
    body_sha256_hex, DispatchEnvelope, DispatchSigner, ModelPlaneClient, ModelPlaneClientSecurity,
    ModelPlaneServer, ModelPlaneServerConfig, ModelPlaneServerSecurity, SignedDispatchEnvelope,
    WorkerModelExecution, DISPATCH_ENVELOPE_SCHEMA_VERSION,
};
use sbproxy_mesh::enrollment::{
    install_worker_enrollment, AuthorityInit, EnrollmentAuthority, EnrollmentTokenConstraints,
    WorkerEnrollment,
};
use sbproxy_mesh::peer_identity::PeerIdentityAuthenticator;
use sbproxy_mesh::transport::tls::MeshTlsConfig;
use sbproxy_mesh::{ClusterHandle, ClusterNodeRole, MeshNode};
use sbproxy_model_host::{
    AcceleratorKind, Catalog, DeploymentPrepareRequest, DeploymentPreparer, EngineDriverError,
    EngineKind, EngineProcess, MemoryEstimate, ModelRuntimeManager, OperationJob,
    PreparedDeploymentRuntime, PriorityClass, PullIntent, RunningEngine, RuntimeDesiredInput,
    RuntimeManagerError,
};

#[derive(Debug)]
struct FixtureProcess;

#[async_trait::async_trait]
impl EngineProcess for FixtureProcess {
    fn id(&self) -> Option<u32> {
        Some(41)
    }

    async fn has_exited(&self) -> Result<bool, EngineDriverError> {
        Ok(false)
    }

    async fn shutdown(&self, _grace: Duration) -> Result<(), EngineDriverError> {
        Ok(())
    }

    fn stderr_tail(&self) -> String {
        String::new()
    }
}

struct FixtureRuntime {
    deployment: String,
    generation: u64,
    starts: Arc<AtomicUsize>,
    port: u16,
}

#[async_trait::async_trait]
impl PreparedDeploymentRuntime for FixtureRuntime {
    async fn memory_estimate(
        &self,
        _intent: PullIntent,
    ) -> Result<MemoryEstimate, RuntimeManagerError> {
        Ok(MemoryEstimate::from_total(0, 1))
    }

    async fn start(&self, _intent: PullIntent) -> Result<RunningEngine, RuntimeManagerError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(25)).await;
        Ok(RunningEngine {
            deployment: self.deployment.clone(),
            generation: self.generation,
            kind: EngineKind::LlamaCpp,
            port: self.port,
            selected_devices: vec![0],
            accelerator: AcceleratorKind::Cpu,
            started_at_ms: 1,
            artifact_digest: "a".repeat(64),
            memory: MemoryEstimate::from_total(0, 1),
            process: Arc::new(FixtureProcess),
        })
    }

    async fn stop(&self, _grace: Duration) -> Result<(), RuntimeManagerError> {
        Ok(())
    }

    async fn reset(&self) -> Result<Option<OperationJob>, RuntimeManagerError> {
        Ok(None)
    }
}

struct FixturePreparer {
    starts: Arc<AtomicUsize>,
    port: u16,
}

#[async_trait::async_trait]
impl DeploymentPreparer for FixturePreparer {
    async fn prepare(
        &self,
        request: DeploymentPrepareRequest,
    ) -> Result<Arc<dyn PreparedDeploymentRuntime>, RuntimeManagerError> {
        Ok(Arc::new(FixtureRuntime {
            deployment: request.deployment_id,
            generation: request.generation,
            starts: Arc::clone(&self.starts),
            port: self.port,
        }))
    }
}

async fn execution_fixture(port: u16) -> (WorkerModelExecution, Arc<AtomicUsize>) {
    let starts = Arc::new(AtomicUsize::new(0));
    let catalog = Catalog::builtin();
    let manager = Arc::new(
        ModelRuntimeManager::new(
            catalog.catalog_revision.clone(),
            Arc::new(FixturePreparer {
                starts: Arc::clone(&starts),
                port,
            }),
        )
        .expect("runtime manager"),
    );
    let desired = sbproxy_model_host::compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "model-plane-fixture".to_string(),
            canonical: Some(
                serde_yaml::from_str(
                    r#"
deployments:
  coder:
    model: qwen2.5-0.5b-instruct
    variant: q4_k_m
    pull: on_demand
    max_concurrency: 32
    max_queue_depth: 32
"#,
                )
                .expect("model host config"),
            ),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &catalog,
    )
    .expect("desired state");
    let prepared = manager
        .prepare_revision(desired)
        .await
        .expect("prepare desired state");
    manager
        .commit_revision(prepared)
        .await
        .expect("commit desired state");
    (
        WorkerModelExecution::from_manager(manager, BTreeMap::from([("coder".to_string(), 7)])),
        starts,
    )
}

#[tokio::test]
async fn worker_rejects_a_stale_generation_before_engine_dispatch() {
    let (service, starts) = execution_fixture(20_041).await;
    let error = service
        .prepare("coder", 6, PriorityClass::Standard)
        .await
        .expect_err("stale generation");
    assert_eq!(error.code(), "stale_deployment_generation");
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn concurrent_cold_requests_share_one_runtime_prepare() {
    let (service, starts) = execution_fixture(20_041).await;
    let results = join_all((0..16).map(|_| {
        let service = service.clone();
        async move { service.prepare("coder", 7, PriorityClass::Standard).await }
    }))
    .await;
    assert!(results.iter().all(Result::is_ok));
    assert_eq!(starts.load(Ordering::SeqCst), 1);
}

const DEVELOPMENT_KEY: &[u8] = b"development-model-plane-key-32b";
const REQUEST_BODY: &[u8] = br#"{"model":"logical/coder","messages":[]}"#;
const RESPONSE_BODY: &[u8] = b"data: first\n\ndata: second\n\n";

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_millis() as u64
}

fn dispatch_envelope(nonce: &str) -> DispatchEnvelope {
    let now = now_unix_ms();
    DispatchEnvelope {
        schema_version: DISPATCH_ENVELOPE_SCHEMA_VERSION,
        issuer_node_id: "gateway-a".to_string(),
        audience_node_id: "worker-a".to_string(),
        request_id: "req_model_plane_transport".to_string(),
        nonce: nonce.to_string(),
        issued_at_unix_ms: now.saturating_sub(100),
        expires_at_unix_ms: now + 10_000,
        hop_count: 1,
        tenant_id: "tenant-a".to_string(),
        governed_key_id: "key-a".to_string(),
        policy_revision: "policy-7".to_string(),
        deployment: "coder".to_string(),
        deployment_generation: 7,
        logical_model: "logical/coder".to_string(),
        priority: PriorityClass::Standard,
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        content_type: Some("application/json".to_string()),
        body_sha256: body_sha256_hex(REQUEST_BODY),
    }
}

async fn spawn_engine_upstream() -> (
    u16,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<Vec<u8>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("engine listener");
    let port = listener.local_addr().expect("engine address").port();
    let (body_tx, body_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("engine accept");
        let mut received = Vec::new();
        let header_end = loop {
            let mut chunk = [0u8; 4096];
            let count = stream.read(&mut chunk).await.expect("engine read");
            assert!(count > 0, "request closed before headers");
            received.extend_from_slice(&chunk[..count]);
            if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers = String::from_utf8_lossy(&received[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(str::trim)
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .expect("engine content length");
        while received.len() - header_end < content_length {
            let mut chunk = [0u8; 4096];
            let count = stream.read(&mut chunk).await.expect("engine body read");
            assert!(count > 0, "request closed before body");
            received.extend_from_slice(&chunk[..count]);
        }
        body_tx
            .send(received[header_end..header_end + content_length].to_vec())
            .expect("capture engine body");

        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    RESPONSE_BODY.len()
                )
                .as_bytes(),
            )
            .await
            .expect("engine response headers");
        let split = RESPONSE_BODY.len() / 2;
        stream
            .write_all(&RESPONSE_BODY[..split])
            .await
            .expect("first response frame");
        stream.flush().await.expect("first response flush");
        tokio::time::sleep(Duration::from_millis(20)).await;
        stream
            .write_all(&RESPONSE_BODY[split..])
            .await
            .expect("second response frame");
    });
    (port, task, body_rx)
}

async fn collect_response(
    mut response: sbproxy_core::model_plane::ModelPlaneResponse,
) -> (http::Version, Vec<Bytes>) {
    let version = response.http_version();
    let mut frames = Vec::new();
    while let Some(frame) = response.body.next().await {
        frames.push(frame.expect("response frame"));
    }
    (version, frames)
}

struct EnrolledPair {
    _temp: tempfile::TempDir,
    gateway_handle: ClusterHandle,
    worker_handle: ClusterHandle,
    gateway_tls: MeshTlsConfig,
    worker_tls: MeshTlsConfig,
}

fn enrolled_pair() -> EnrolledPair {
    let temp = tempfile::tempdir().expect("identity directory");
    let gateway_dir = temp.path().join("gateway");
    let authority = EnrollmentAuthority::initialize(
        &gateway_dir,
        AuthorityInit {
            cluster_id: "cluster-a".to_string(),
            node_id: "gateway-a".to_string(),
            roles: BTreeSet::from([ClusterNodeRole::Authority, ClusterNodeRole::Gateway]),
            labels: BTreeMap::new(),
            server_name: "sbproxy-mesh".to_string(),
        },
    )
    .expect("initialize authority");
    let constraints = EnrollmentTokenConstraints {
        allowed_roles: BTreeSet::from([ClusterNodeRole::Worker]),
        labels: BTreeMap::new(),
    };
    let token = authority
        .create_token(constraints.clone(), Duration::from_secs(60))
        .expect("worker token");
    let worker =
        WorkerEnrollment::generate("worker-a", "sbproxy-mesh").expect("worker enrollment key");
    let response = authority
        .enroll(worker.request(
            token.into_token(),
            BTreeSet::from([ClusterNodeRole::Worker]),
            constraints.labels,
        ))
        .expect("enroll worker");
    let worker_dir = temp.path().join("worker");
    let installed =
        install_worker_enrollment(&worker_dir, worker, response).expect("install worker identity");

    let tls_from = |directory: &std::path::Path| MeshTlsConfig {
        cert_pem: std::fs::read_to_string(directory.join("node.pem")).expect("certificate"),
        key_pem: std::fs::read_to_string(directory.join("node-key.pem")).expect("private key"),
        ca_pem: std::fs::read_to_string(directory.join("ca.pem")).expect("CA"),
    };
    let gateway_tls = tls_from(&gateway_dir);
    let worker_tls = tls_from(&worker_dir);
    let gateway_identity = authority
        .identity()
        .document
        .to_cluster_identity()
        .expect("gateway identity");
    let gateway_auth = PeerIdentityAuthenticator::load_installed(
        &gateway_dir,
        &gateway_identity,
        "sbproxy-mesh",
        &gateway_tls,
    )
    .expect("gateway authenticator");
    let worker_auth = PeerIdentityAuthenticator::load_installed(
        &worker_dir,
        &installed.identity,
        "sbproxy-mesh",
        &worker_tls,
    )
    .expect("worker authenticator");
    let gateway_mesh = MeshNode::new("gateway-a".to_string(), Vec::new(), 8)
        .with_identity_authenticator(Some(Arc::new(gateway_auth)));
    let worker_mesh = MeshNode::new("worker-a".to_string(), Vec::new(), 8)
        .with_identity_authenticator(Some(Arc::new(worker_auth)));

    EnrolledPair {
        _temp: temp,
        gateway_handle: ClusterHandle::distributed(gateway_identity, Arc::new(gateway_mesh))
            .expect("gateway handle"),
        worker_handle: ClusterHandle::distributed(installed.identity, Arc::new(worker_mesh))
            .expect("worker handle"),
        gateway_tls,
        worker_tls,
    }
}

#[tokio::test]
async fn mtls_h2_streams_and_binds_proof_to_tls_peer() {
    let identities = enrolled_pair();
    let (engine_port, engine, engine_body) = spawn_engine_upstream().await;
    let (execution, _) = execution_fixture(engine_port).await;
    let server = ModelPlaneServer::start(
        ModelPlaneServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            "worker-a",
            1024 * 1024,
        ),
        ModelPlaneServerSecurity::Mtls {
            tls: identities.worker_tls.clone(),
            cluster: identities.worker_handle.clone(),
        },
        execution,
    )
    .await
    .expect("start mTLS model plane");
    let signed = dispatch_envelope("nonce_mtls_transport_0001")
        .sign(DispatchSigner::PeerIdentity(&identities.gateway_handle))
        .expect("sign peer dispatch");
    let client = ModelPlaneClient::new(ModelPlaneClientSecurity::Mtls {
        tls: identities.gateway_tls.clone(),
        server_name: "sbproxy-mesh".to_string(),
    });
    let response = client
        .dispatch(
            &format!("https://{}", server.local_addr()),
            &signed,
            Bytes::from_static(REQUEST_BODY),
        )
        .await
        .expect("mTLS dispatch");
    let response = reqwest::Response::from(response);
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.version(), http::Version::HTTP_2);
    let frames = response
        .bytes_stream()
        .map(|frame| frame.expect("response frame"))
        .collect::<Vec<_>>()
        .await;
    assert_eq!(frames.concat(), RESPONSE_BODY);
    assert!(frames.len() >= 2, "delayed engine writes should stream");
    let forwarded: serde_json::Value =
        serde_json::from_slice(&engine_body.await.expect("engine body")).expect("forwarded JSON");
    assert_eq!(forwarded["model"], "coder");
    engine.await.expect("engine task");

    let mismatched_tls_client = ModelPlaneClient::new(ModelPlaneClientSecurity::Mtls {
        tls: identities.worker_tls.clone(),
        server_name: "sbproxy-mesh".to_string(),
    });
    let mismatched = dispatch_envelope("nonce_mtls_transport_0002")
        .sign(DispatchSigner::PeerIdentity(&identities.gateway_handle))
        .expect("sign mismatched dispatch");
    let error = mismatched_tls_client
        .dispatch(
            &format!("https://{}", server.local_addr()),
            &mismatched,
            Bytes::from_static(REQUEST_BODY),
        )
        .await
        .expect_err("proof must match TLS leaf");
    assert_eq!(error.code(), "peer_authentication_failed");
    assert!(!error.retryable());
    server.shutdown().await.expect("server shutdown");
}

#[tokio::test]
async fn replay_and_auth_errors_are_not_retryable_capacity_errors() {
    let (engine_port, engine, _engine_body) = spawn_engine_upstream().await;
    let (execution, _) = execution_fixture(engine_port).await;
    let server = ModelPlaneServer::start(
        ModelPlaneServerConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            "worker-a",
            1024 * 1024,
        ),
        ModelPlaneServerSecurity::DevelopmentSharedKey {
            key: Arc::from(DEVELOPMENT_KEY),
        },
        execution,
    )
    .await
    .expect("start development model plane");
    let signed: SignedDispatchEnvelope = dispatch_envelope("nonce_replay_transport_0001")
        .sign(DispatchSigner::DevelopmentSharedKey(DEVELOPMENT_KEY))
        .expect("sign development dispatch");
    let client = ModelPlaneClient::new(ModelPlaneClientSecurity::DevelopmentSharedKey {
        key: Arc::from(DEVELOPMENT_KEY),
    });
    let endpoint = format!("http://{}", server.local_addr());
    let first = client
        .dispatch(&endpoint, &signed, Bytes::from_static(REQUEST_BODY))
        .await
        .expect("first dispatch");
    assert_eq!(first.status, http::StatusCode::OK);
    let (_, frames) = collect_response(first).await;
    assert_eq!(frames.concat(), RESPONSE_BODY);

    let replay = client
        .dispatch(&endpoint, &signed, Bytes::from_static(REQUEST_BODY))
        .await
        .expect_err("replay rejected");
    assert_eq!(replay.code(), "replay_detected");
    assert!(!replay.retryable());

    let wrong_auth = dispatch_envelope("nonce_replay_transport_0002")
        .sign(DispatchSigner::DevelopmentSharedKey(
            b"different-development-model-key",
        ))
        .expect("sign wrong-key dispatch");
    let auth_error = client
        .dispatch(&endpoint, &wrong_auth, Bytes::from_static(REQUEST_BODY))
        .await
        .expect_err("wrong HMAC rejected");
    assert_eq!(auth_error.code(), "peer_authentication_failed");
    assert!(!auth_error.retryable());
    engine.await.expect("engine task");
    server.shutdown().await.expect("server shutdown");
}
