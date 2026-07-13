# Distributed Data Plane Implementation Plan

> **Execution:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route governed managed-model requests to the best current local or remote replica over an authenticated private HTTP/2 model plane, with safe pre-output failover, coordinated cold starts, and an OpenRouter-compatible logical model surface.

**Architecture:** The public gateway evaluates caller policy and provider eligibility once, then expands a managed provider from an immutable `ModelDirectoryView`. A pure selector orders current-generation replicas. Local winners call the worker execution service directly; remote winners use the same service through a bounded, signed dispatch envelope over mTLS HTTP/2 in production or explicitly authenticated h2c in development. The worker performs final generation-fenced admission and engine readiness, while the ingress gateway remains the only usage-accounting and policy authority.

**Tech Stack:** Rust 2021, Tokio, Hyper 1 HTTP/2, rustls 0.23, reqwest 0.12 response streaming, Ed25519/X.509 peer identity proofs, HMAC-SHA256 development authentication, ArcSwap model-directory snapshots, Pingora downstream streaming, Schemas/JsonSchema, Rust integration and multi-process E2E tests.

## Global Constraints

- Production remote dispatch requires canonical cluster mTLS and an authenticated gateway or worker peer identity.
- Development shared-key dispatch must remain explicit and must never be reported as production peer identity.
- The public bearer key, provider secret, prompt, private worker endpoint, engine port, certificate, artifact path, and raw low-level error must not enter logs, metrics, traces, status JSON, or client-visible route metadata.
- A request may cross at most one peer hop. Workers never forward to another worker.
- Failover is permitted only before downstream response headers or tokens. Mid-stream failure is surfaced and recorded without replay.
- Worker-local generation, admission, queue, fit, lifecycle, and engine health remain authoritative.
- GCP live validation, VM provisioning, GPU images, governance leases, and strict distributed budget closure are excluded from this PR.
- All production behavior is developed red-green-refactor. Run only focused checks for files changed in each task, then the final proportional gate.

---

### Task 1: Model-plane configuration and reusable cluster authentication

**Files:**
- Modify: `crates/sbproxy-config/src/cluster.rs`
- Modify: `crates/sbproxy-config/tests/cluster_config.rs`
- Modify: `crates/sbproxy-mesh/src/cluster_handle.rs`
- Modify: `crates/sbproxy-mesh/src/lib.rs`
- Modify: `crates/sbproxy-mesh/src/transport/tls.rs`
- Modify: `crates/sbproxy-core/src/cluster.rs`

**Interfaces:**
- Produces: `EffectiveClusterConfig::model_bind: Option<String>` and the matching restart fingerprint.
- Produces: `ClusterHandle::sign_peer_payload(context, payload)` and `verify_peer_payload(context, payload, expected_node_id, proof)`.
- Produces: crate-private `ModelPlaneSecurity::{Mtls, DevelopmentSharedKey}` from the installed process cluster.
- Produces: `build_http2_acceptor` and `build_http2_connector` with ALPN restricted to `h2`.

- [x] **Step 1: Write failing configuration tests**

```rust,no_run
#[test]
fn model_bind_is_restart_owned_and_requires_a_worker_endpoint() {
    let cfg = parse(canonical_with("model_bind: 0.0.0.0:9443"));
    let effective = resolve_effective_cluster(&cfg).unwrap().unwrap();
    assert_eq!(effective.model_bind.as_deref(), Some("0.0.0.0:9443"));
    assert_eq!(effective.restart_fingerprint().model_bind, effective.model_bind);
}

#[test]
fn production_model_plane_requires_mtls() {
    let error = parse_invalid(shared_key_cluster_with_model_bind());
    assert!(error.to_string().contains("development: true"));
}
```

- [x] **Step 2: Run the configuration tests and verify RED**

Run: `cargo test -p sbproxy-config --test cluster_config model_bind -- --nocapture`

Expected: FAIL because `model_bind` is not part of `ClusterConfig` or the restart fingerprint.

- [x] **Step 3: Add the bounded bind contract**

```rust,no_run
pub struct ClusterConfig {
    pub model_endpoint: Option<String>,
    pub model_bind: Option<String>,
}

fn validate_model_bind(bind: &str) -> Result<(), ClusterConfigError> {
    let address: std::net::SocketAddr = bind.parse().map_err(|_| {
        ClusterConfigError::invalid("model_bind must be an IP:port socket address")
    })?;
    if address.port() == 0 {
        return Err(ClusterConfigError::invalid("model_bind port must be non-zero"));
    }
    Ok(())
}
```

Validation rules: `model_bind` requires the worker role and `model_endpoint`; canonical mTLS may bind HTTPS, while shared-key mode requires `development: true` and an HTTP endpoint. Add the field to lowering and restart comparison.

- [x] **Step 4: Write failing peer-proof and ALPN tests**

```rust,no_run
#[test]
fn handle_signs_and_verifies_a_domain_separated_peer_payload() {
    let (gateway, worker) = authenticated_handles();
    let proof = gateway.sign_peer_payload("sbproxy.model-dispatch.v1", b"payload").unwrap();
    let identity = worker
        .verify_peer_payload("sbproxy.model-dispatch.v1", b"payload", Some("gateway-a"), &proof)
        .unwrap();
    assert!(identity.roles.contains(&ClusterNodeRole::Gateway));
}

#[tokio::test]
async fn model_plane_tls_negotiates_h2_only() {
    let negotiated = complete_test_handshake(
        build_http2_acceptor(&test_tls()).unwrap(),
        build_http2_connector(&test_tls()).unwrap(),
    ).await;
    assert_eq!(negotiated.as_deref(), Some(b"h2".as_slice()));
}
```

- [x] **Step 5: Run peer-proof tests and verify RED**

Run: `cargo test -p sbproxy-mesh cluster_handle::tests::handle_signs_and_verifies_a_domain_separated_peer_payload -- --nocapture`

Run: `cargo test -p sbproxy-mesh transport::tls::tests::model_plane_tls_negotiates_h2_only -- --nocapture`

Expected: FAIL because the public wrapper methods and HTTP/2 acceptor do not exist.

- [x] **Step 6: Expose bounded peer authentication and installed security**

```rust,no_run
pub fn sign_peer_payload(&self, context: &str, payload: &[u8]) -> Result<PeerIdentityProof, ClusterStateError>;

pub fn verify_peer_payload(
    &self,
    context: &str,
    payload: &[u8],
    expected_node_id: Option<&str>,
    proof: &PeerIdentityProof,
) -> Result<AuthenticatedPeerIdentity, ClusterStateError>;

pub(crate) enum ModelPlaneSecurity {
    Mtls { tls: MeshTlsConfig, server_name: String },
    DevelopmentSharedKey { key: ModelPlaneSharedKey },
}
```

`ModelPlaneSharedKey` is a crate-private, cloneable byte wrapper with a redacted `Debug` implementation. The wrappers must return a typed `AuthenticationUnavailable` error on local or unauthenticated handles. `ClusterOwner` reads PEM material once from the effective configuration and stores a cloneable model-plane profile without exposing it through admin state.

- [x] **Step 7: Run focused tests and commit**

Run: `cargo test -p sbproxy-config --test cluster_config`

Run: `cargo test -p sbproxy-mesh cluster_handle::tests`

Run: `cargo test -p sbproxy-mesh transport::tls::tests`

Run: `cargo test -p sbproxy-core cluster::tests`

Expected: PASS.

Commit: `git commit -m "WOR-1847: define model plane security"`

---

### Task 2: Strict dispatch envelope and replay fence

**Files:**
- Create: `crates/sbproxy-core/src/model_plane/mod.rs`
- Create: `crates/sbproxy-core/src/model_plane/envelope.rs`
- Create: `crates/sbproxy-core/src/model_plane/replay.rs`
- Modify: `crates/sbproxy-core/src/lib.rs`
- Create: `crates/sbproxy-core/tests/model_plane_envelope.rs`

**Interfaces:**
- Produces: `DispatchEnvelope`, `SignedDispatchEnvelope`, `DispatchAuthProof`, `DispatchEnvelopeError`.
- Produces: `DispatchReplayFence::check_and_record(issuer, nonce, expires_at_unix_ms, now_unix_ms)`.
- Consumes: Task 1 peer-proof and development shared-key authentication.

- [x] **Step 1: Write failing strict-envelope tests**

```rust,no_run
#[test]
fn envelope_rejects_wrong_audience_expiry_hop_and_body_digest() {
    let signed = signed_fixture();
    assert_code(verify(signed.clone(), "worker-b", NOW, BODY), "audience_mismatch");
    assert_code(verify(signed.clone(), "worker-a", EXPIRED, BODY), "dispatch_expired");
    assert_code(verify(with_hop(signed.clone(), 2), "worker-a", NOW, BODY), "hop_limit_exceeded");
    assert_code(verify(signed, "worker-a", NOW, b"changed"), "request_digest_mismatch");
}

#[test]
fn envelope_denies_unknown_fields_and_oversize_values() {
    assert_code(parse_json(with_unknown_field()), "invalid_envelope");
    assert_code(parse_json(with_oversize_request_id()), "invalid_envelope");
}
```

- [x] **Step 2: Run and verify RED**

Run: `cargo test -p sbproxy-core --test model_plane_envelope envelope_ -- --nocapture`

Expected: compile failure because the envelope module is absent.

- [x] **Step 3: Implement the canonical signed envelope**

```rust,no_run
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchEnvelope {
    pub schema_version: u32,
    pub issuer_node_id: String,
    pub audience_node_id: String,
    pub request_id: String,
    pub nonce: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub hop_count: u8,
    pub tenant_id: String,
    pub governed_key_id: String,
    pub policy_revision: String,
    pub deployment: String,
    pub deployment_generation: u64,
    pub logical_model: String,
    pub priority: sbproxy_model_host::PriorityClass,
    pub method: String,
    pub path: String,
    pub content_type: Option<String>,
    pub body_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DispatchAuthProof {
    PeerIdentity { proof: sbproxy_mesh::peer_identity::PeerIdentityProof },
    DevelopmentHmac { signature: String },
}
```

Canonical signing bytes exclude `auth`. Validate exact schema version, bounded ASCII identifiers, `hop_count == 1`, maximum lifetime 30 seconds, clock skew 5 seconds, worker audience, generation greater than zero, allowlisted HTTP methods and AI paths, SHA-256 body binding, gateway role, and certificate fingerprint equality with the TLS peer when mTLS is used.

- [x] **Step 4: Write failing replay tests**

```rust,no_run
#[test]
fn concurrent_duplicate_nonce_has_exactly_one_winner() {
    let fence = Arc::new(DispatchReplayFence::new(1024));
    let accepted = race(32, || fence.check_and_record("gateway-a", NONCE, EXPIRY, NOW));
    assert_eq!(accepted, 1);
}

#[test]
fn full_replay_fence_fails_closed_without_evicting_live_entries() {
    let fence = DispatchReplayFence::new(1);
    fence.check_and_record("a", "one", EXPIRY, NOW).unwrap();
    assert_code(fence.check_and_record("a", "two", EXPIRY, NOW), "replay_fence_full");
}
```

- [x] **Step 5: Run replay tests and verify RED**

Run: `cargo test -p sbproxy-core --test model_plane_envelope replay -- --nocapture`

Expected: FAIL because `DispatchReplayFence` is absent.

- [x] **Step 6: Implement a bounded expiry-aware replay fence**

```rust,no_run
pub struct DispatchReplayFence {
    capacity: usize,
    entries: parking_lot::Mutex<BTreeMap<(String, String), u64>>,
}

pub fn check_and_record(
    &self,
    issuer: &str,
    nonce: &str,
    expires_at_unix_ms: u64,
    now_unix_ms: u64,
) -> Result<(), DispatchEnvelopeError>;
```

Prune expired entries under the same lock, reject an existing live key as `replay_detected`, and fail closed when the remaining live set is at capacity.

- [x] **Step 7: Run focused tests and commit**

Run: `cargo test -p sbproxy-core --test model_plane_envelope`

Expected: PASS.

Commit: `git commit -m "WOR-1847: authenticate dispatch envelopes"`

---

### Task 3: Directory telemetry and pure replica routing

**Files:**
- Modify: `crates/sbproxy-model-host/src/node_snapshot.rs`
- Modify: `crates/sbproxy-model-host/src/capabilities.rs`
- Modify: `crates/sbproxy-ai/src/model_directory.rs`
- Create: `crates/sbproxy-ai/src/managed_replica.rs`
- Modify: `crates/sbproxy-ai/src/lib.rs`
- Modify: `crates/sbproxy-model-host/tests/model_directory.rs`
- Create: `crates/sbproxy-ai/tests/managed_replica_routing.rs`

**Interfaces:**
- Produces: `ModelPlaneHealth::{Ready, Degraded, Unavailable}` independent of SWIM state.
- Produces: current-generation `candidate_replicas` including ready and cold assigned replicas.
- Produces: `ManagedReplicaRouter::ordered_candidates(view, deployment, input)` and `ReplicaSelectionTrace`.

- [x] **Step 1: Write failing directory projection tests**

```rust,no_run
#[test]
fn directory_keeps_current_generation_cold_candidates_and_device_utilization() {
    let view = collect(snapshot_with_preparing_replica_and_utilization(0.72));
    let replica = &view.candidate_replicas["qwen"][0];
    assert_eq!(replica.state, DeploymentRuntimeState::Preparing);
    assert_eq!(replica.compute_utilization_millis, Some(720));
    assert_eq!(replica.model_plane_health, ModelPlaneHealth::Ready);
}
```

- [x] **Step 2: Run and verify RED**

Run: `cargo test -p sbproxy-model-host --test model_directory directory_keeps_current_generation_cold_candidates -- --nocapture`

Expected: FAIL because the snapshot and directory omit those fields/indexes.

- [x] **Step 3: Extend bounded snapshot truth and normalization**

```rust,no_run
pub struct NodeDeviceSnapshot {
    // existing fields
    pub compute_utilization_millis: Option<u16>,
    pub memory_occupancy_millis: Option<u16>,
}

pub struct NodeHealthSnapshot {
    pub state: NodeHealthState,
    pub reason_codes: Vec<String>,
    pub model_plane: ModelPlaneHealth,
}
```

Represent ratios as integer thousandths so equality, schema, and JavaScript safety remain exact. Bump the node snapshot schema and normalize the prior schema by treating missing utilization as unknown and the prior advertised endpoint as model-plane `Unavailable` until a listener reports ready.

- [x] **Step 4: Write failing router tests**

```rust,no_run
#[test]
fn ready_adapter_region_and_queue_precede_remote_ties() {
    let ordered = route(candidates(), input("gateway-a", Some("finance"), Some("us-central1")));
    assert_eq!(ordered[0].node_id, "worker-ready-adapter-low-queue");
}

#[test]
fn unknown_compute_is_not_scored_as_idle() {
    let ordered = route(vec![candidate("unknown", None), candidate("known", Some(500))], input_default());
    assert_eq!(ordered[0].node_id, "known");
}

#[test]
fn equivalent_local_replica_wins_without_peer_hop() {
    let ordered = route(equivalent_local_and_remote(), input("node-a", None, None));
    assert_eq!(ordered[0].route_class, ManagedRouteClass::Local);
}
```

- [x] **Step 5: Run router tests and verify RED**

Run: `cargo test -p sbproxy-ai --test managed_replica_routing -- --nocapture`

Expected: compile failure because the router module does not exist.

- [x] **Step 6: Implement deterministic ordered selection**

```rust,no_run
pub struct ManagedReplicaInput<'a> {
    pub local_node_id: &'a str,
    pub requested_adapter: Option<&'a str>,
    pub preferred_region: Option<&'a str>,
    pub prefix_key: &'a [u8],
    pub allow_cold: bool,
}

pub struct ReplicaSelectionTrace {
    pub total_candidates: usize,
    pub excluded_generation: usize,
    pub excluded_health: usize,
    pub excluded_endpoint: usize,
    pub selected_reason: &'static str,
}
```

Filter generation, health, endpoint, lifecycle, and adapter requirements before scoring. Rank readiness, model-plane health, region match, queue depth, active requests, known compute and memory utilization, local equivalence, prefix rendezvous score, then stable node ID. Unknown utilization receives the maximum utilization penalty, never zero. Return all distinct eligible candidates in retry order plus bounded exclusion counts.

- [x] **Step 7: Run focused tests and commit**

Run: `cargo test -p sbproxy-model-host --test model_directory && cargo test -p sbproxy-ai --test managed_replica_routing`

Expected: PASS.

Commit: `git commit -m "WOR-1850: route current managed replicas"`

---

### Task 4: Worker execution service and private HTTP/2 transport

**Files:**
- Create: `crates/sbproxy-core/src/model_plane/execution.rs`
- Create: `crates/sbproxy-core/src/model_plane/server.rs`
- Create: `crates/sbproxy-core/src/model_plane/client.rs`
- Modify: `crates/sbproxy-core/src/model_plane/mod.rs`
- Modify: `crates/sbproxy-core/src/server/model_host.rs`
- Modify: `crates/sbproxy-core/src/server/lifecycle.rs`
- Modify: `crates/sbproxy-core/Cargo.toml`
- Modify: `Cargo.toml`
- Create: `crates/sbproxy-core/tests/model_plane_transport.rs`

**Interfaces:**
- Produces: `WorkerModelExecution::prepare(deployment, generation, priority)` shared by local and peer paths.
- Produces: `ModelPlaneServer::start(config, security, cluster, execution)` and graceful `ModelPlaneServerHandle::shutdown()`.
- Produces: `ModelPlaneClient::dispatch(candidate, signed, body)` returning status, allowlisted headers, and a backpressured byte stream.

- [x] **Step 1: Write failing worker-execution tests**

```rust,no_run
#[tokio::test]
async fn worker_rejects_a_stale_generation_before_engine_dispatch() {
    let service = execution_with_generation(7);
    let error = service.prepare("qwen", 6, PriorityClass::Standard).await.unwrap_err();
    assert_eq!(error.code(), "stale_deployment_generation");
}

#[tokio::test]
async fn concurrent_cold_requests_share_one_runtime_prepare() {
    let service = counting_cold_execution();
    join_all((0..16).map(|_| service.prepare("qwen", 1, PriorityClass::Standard))).await;
    assert_eq!(service.launch_count(), 1);
}
```

- [x] **Step 2: Run and verify RED**

Run: `cargo test -p sbproxy-core --test model_plane_transport worker_ -- --nocapture`

Expected: compile failure because the execution service is absent.

- [x] **Step 3: Extract a generation-fenced worker service**

```rust,no_run
pub struct PreparedWorkerExecution {
    pub base_url: String,
    pub engine_model: String,
    pub permit: ManagedModelPermit,
}

impl WorkerModelExecution {
    pub async fn prepare(
        &self,
        deployment: &str,
        deployment_generation: u64,
        priority: PriorityClass,
    ) -> Result<PreparedWorkerExecution, ModelPlaneError>;
}
```

It must verify the active cluster assignment and generation before admission, use the existing bounded queue, call `ensure_ready_for_generation`, and hold the permit until the returned response stream is dropped.

- [x] **Step 4: Write failing transport tests**

```rust,no_run
#[tokio::test]
async fn mtls_h2_streams_and_binds_proof_to_tls_peer() {
    let fixture = ModelPlaneFixture::mtls().await;
    let response = fixture.dispatch_streaming().await.unwrap();
    assert_eq!(response.http_version(), http::Version::HTTP_2);
    assert_eq!(collect_frames(response).await, fixture.expected_frames());
}

#[tokio::test]
async fn replay_and_auth_errors_are_not_retryable_capacity_errors() {
    let fixture = ModelPlaneFixture::development().await;
    let first = fixture.dispatch_once().await.unwrap();
    assert!(first.status().is_success());
    let replay = fixture.dispatch_same_envelope().await.unwrap_err();
    assert_eq!(replay.code(), "replay_detected");
    assert!(!replay.retryable());
}
```

- [x] **Step 5: Run and verify RED**

Run: `cargo test -p sbproxy-core --test model_plane_transport mtls_h2_streams_and_binds_proof_to_tls_peer -- --nocapture`

Run: `cargo test -p sbproxy-core --test model_plane_transport replay_and_auth_errors_are_not_retryable_capacity_errors -- --nocapture`

Expected: FAIL because no listener or client exists.

- [x] **Step 6: Implement the listener, client, and response stream**

```rust,no_run
pub const MODEL_PLANE_PATH_PREFIX: &str = "/_sbproxy/model-plane/v1";

pub struct ModelPlaneResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: Pin<Box<dyn Stream<Item = Result<bytes::Bytes, ModelPlaneError>> + Send>>,
}
```

Use Hyper HTTP/2 for the separate listener. Production accepts only mTLS with `h2` ALPN and binds the verified request proof to the TLS leaf fingerprint. Explicit development mode uses h2c plus HMAC. The server accepts only the internal prefix, bounds headers and body by the configured AI body limit, validates the envelope and replay fence before local admission, strips all public authorization headers, rewrites only the engine model field, and forwards to `127.0.0.1:<engine-port>`. Dropping either side of the stream drops the upstream request and permit.

- [x] **Step 7: Add lifecycle ownership and health publication**

Start the server after the model runtime is installed and before the public pipeline is loaded. Publish `Degraded` while starting, `Ready` after bind, or `Unavailable` after failure and shutdown through process state consumed by node snapshots. On shutdown, stop accepting, cancel active peer requests within the model shutdown deadline, then drain engines.

- [x] **Step 8: Run focused tests and commit**

Run: `cargo test -p sbproxy-core --test model_plane_transport && cargo test -p sbproxy-core server::model_host::tests`

Expected: PASS.

Commit: `git commit -m "WOR-1847: stream over the private model plane"`

---

### Task 5: Managed replica dispatch, safe failover, and route traces

**Files:**
- Modify: `crates/sbproxy-core/src/server/model_host.rs`
- Modify: `crates/sbproxy-core/src/server/ai_dispatch.rs`
- Modify: `crates/sbproxy-core/src/context.rs`
- Modify: `crates/sbproxy-core/src/server/ai_support.rs`
- Modify: `crates/sbproxy-observe/src/metrics.rs`
- Create: `crates/sbproxy-core/tests/managed_replica_dispatch.rs`

**Interfaces:**
- Produces: `ManagedAttempt::{Local, Peer}` and `ManagedDispatchOutcome` with logical model, route class, selected node ID for internal tracing only, and request-lifetime permit/stream ownership.
- Produces: stable `ModelPlaneError::retry_class()` distinguishing security, capacity, readiness, transport, and terminal stream failures.
- Consumes: Task 3 ordered candidates and Task 4 transport.

- [x] **Step 1: Write failing local/peer/fallback tests**

```rust,no_run
#[tokio::test]
async fn equivalent_local_candidate_uses_direct_engine_path() {
    let outcome = dispatch_fixture().with_local_and_remote().send().await.unwrap();
    assert_eq!(outcome.route_class, ManagedRouteClass::Local);
    assert_eq!(outcome.peer_requests, 0);
}

#[tokio::test]
async fn pre_output_worker_failure_tries_a_distinct_replica_then_succeeds() {
    let outcome = dispatch_fixture().first_worker_unavailable().send().await.unwrap();
    assert_eq!(outcome.replica_attempts, 2);
    assert_eq!(outcome.pre_output_failovers, 1);
}

#[tokio::test]
async fn security_rejection_does_not_try_another_replica() {
    let error = dispatch_fixture().invalid_peer_proof().send().await.unwrap_err();
    assert_eq!(error.replica_attempts, 1);
    assert_eq!(error.code(), "peer_authentication_failed");
}
```

- [x] **Step 2: Run and verify RED**

Run: `cargo test -p sbproxy-core --test managed_replica_dispatch -- --nocapture`

Expected: compile failure because managed providers still resolve only local runtime state.

- [x] **Step 3: Implement managed attempt resolution**

```rust,no_run
pub enum ManagedAttempt {
    Local { execution: PreparedWorkerExecution },
    Peer { replica: ModelDirectoryReplica, envelope: SignedDispatchEnvelope },
}

pub async fn managed_attempts(
    origin: &str,
    provider: &ProviderConfig,
    requested_model: Option<&str>,
    request: ManagedRequestContext<'_>,
) -> Result<Vec<ManagedAttempt>, ManagedDispatchError>;
```

Evaluate provider and logical-model eligibility before this call. Snapshot the directory once per provider attempt. Verify every candidate matches the active deployment generation. Build a new nonce per peer attempt, but preserve one public request ID. Do not include the bearer key.

- [x] **Step 4: Integrate all existing forwarding shapes**

Route JSON, method-aware JSON, native byte bypass, and raw multipart bodies through a shared `send_provider_attempt` adapter. External providers keep the existing `AiClient` path. Managed candidates use local execution or `ModelPlaneClient`. Provider fallback begins only after the managed candidate list returns a retryable pre-output exhaustion.

- [x] **Step 5: Write failing mid-stream and trace tests**

```rust,no_run
#[tokio::test]
async fn mid_stream_failure_is_partial_and_never_replayed() {
    let result = dispatch_fixture().fail_after_first_sse_frame().relay().await;
    assert!(result.is_err());
    assert_eq!(result.replica_attempts, 1);
    assert_eq!(result.stream_outcome, "partial_failure");
}

#[test]
fn route_trace_is_bounded_and_contains_no_endpoint() {
    let trace = trace_fixture();
    assert_eq!(trace.selected_reason, "ready_low_queue");
    assert!(!serde_json::to_string(&trace).unwrap().contains("10.0.0."));
}
```

- [x] **Step 6: Run and verify RED**

Run: `cargo test -p sbproxy-core --test managed_replica_dispatch mid_stream_failure_is_partial_and_never_replayed -- --nocapture`

Run: `cargo test -p sbproxy-core --test managed_replica_dispatch route_trace_is_bounded_and_contains_no_endpoint -- --nocapture`

Expected: FAIL because replica-level stream outcomes and traces do not exist.

- [x] **Step 7: Add bounded metrics and tracing**

Register counters/histograms for route class, replica attempts, pre-output failover, cancellation, auth/replay rejection, queue refusal, and peer latency. Labels are allowlisted enums plus bounded provider/deployment identifiers already used by the model host. Trace candidate counts and selected reason, never the endpoint or node certificate.

- [x] **Step 8: Run focused tests and commit**

Run: `cargo test -p sbproxy-core --test managed_replica_dispatch && cargo test -p sbproxy-core server::ai_dispatch::tests`

Expected: PASS.

Commit: `git commit -m "WOR-1850: dispatch managed replica pools"`

---

### Task 6: Cold-start policy and OpenRouter-compatible logical surface

**Files:**
- Modify: `crates/sbproxy-model-host/src/deployment.rs`
- Modify: `crates/sbproxy-model-host/src/desired.rs`
- Modify: `crates/sbproxy-model-host/src/cluster_authority.rs`
- Modify: `crates/sbproxy-config/src/model_host.rs`
- Modify: `crates/sbproxy-core/src/admin_model_host.rs`
- Modify: `crates/sbproxy-core/src/server/ai_dispatch.rs`
- Modify: `crates/sbproxy-core/src/server/ai_support.rs`
- Modify: related Rust tests beside each file

**Interfaces:**
- Produces: `ColdStartPolicy::{Wait, Reject, Fallback}` on every compiled deployment.
- Produces: managed `/v1/models` aggregate availability without topology.
- Produces: stable OpenAI-style error body with `type`, `code`, `request_id`, `retryable`, and `sbproxy_reason`.
- Produces: `x-sbproxy-logical-model` and `x-sbproxy-route-class` allowlisted response headers.

- [x] **Step 1: Write failing cold-start policy tests**

```rust,no_run
#[test]
fn development_defaults_to_wait_and_production_defaults_to_fallback() {
    assert_eq!(compile_deployment(dev_cluster(), no_policy()).cold_start, ColdStartPolicy::Wait);
    assert_eq!(compile_deployment(mtls_cluster(), no_policy()).cold_start, ColdStartPolicy::Fallback);
}

#[tokio::test]
async fn reject_returns_retry_after_without_starting_the_engine() {
    let response = dispatch_cold(ColdStartPolicy::Reject).await;
    assert_eq!(response.status(), 503);
    assert!(response.headers().contains_key("retry-after"));
    assert_eq!(engine_launch_count(), 0);
}
```

- [x] **Step 2: Run and verify RED**

Run: `cargo test -p sbproxy-model-host cold_start && cargo test -p sbproxy-core --test managed_replica_dispatch cold_start -- --nocapture`

Expected: FAIL because deployments have no cold-start policy.

- [x] **Step 3: Add explicit policy to every desired-state surface**

```rust,no_run
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ColdStartPolicy { Wait, Reject, Fallback }
```

Config carries `Option<ColdStartPolicy>` until compilation can apply the security-profile default. Signed bundles and the durable admin store carry the concrete value. This PR preserves the merged admin UI and API compatibility; UI selection of the new policy remains outside this data-plane batch. `Wait` selects assigned cold candidates and attaches to the existing job; `Reject` returns a stable retryable refusal; `Fallback` skips cold candidates and advances the provider chain.

- [x] **Step 4: Write failing logical model and safe-header tests**

```rust,no_run
#[tokio::test]
async fn managed_models_listing_contains_availability_but_no_topology() {
    let response = get_models(managed_and_cloud_config()).await;
    assert_eq!(response["data"][0]["id"], "qwen");
    assert!(response["data"][0].get("availability").is_some());
    assert!(!response.to_string().contains("model_endpoint"));
}

#[tokio::test]
async fn route_headers_are_logical_and_allowlisted() {
    let response = completion_through_peer().await;
    assert_eq!(response.header("x-sbproxy-logical-model"), "qwen");
    assert_eq!(response.header("x-sbproxy-route-class"), "peer");
    assert!(response.header("x-sbproxy-worker").is_none());
}
```

- [x] **Step 5: Run and verify RED**

Run: `cargo test -p sbproxy-core --test managed_replica_dispatch managed_models_listing_contains_availability_but_no_topology -- --nocapture`

Run: `cargo test -p sbproxy-core --test managed_replica_dispatch route_headers_are_logical_and_allowlisted -- --nocapture`

Expected: FAIL because canonical managed providers are not synthesized by `/v1/models` and route headers do not exist.

- [x] **Step 6: Implement logical discovery, stable errors, and safe headers**

Aggregate configured public model names after the caller's provider/model policy filter. Availability is `ready`, `cold`, or `unavailable` with ready/desired counts, capabilities, and no worker identity. Use one error renderer:

```json
{
  "error": {
    "message": "managed model is temporarily unavailable",
    "type": "managed_model_error",
    "code": "no_ready_replica",
    "request_id": "req_...",
    "retryable": true,
    "sbproxy_reason": "no_ready_replica"
  }
}
```

Add only `local`, `peer`, or `external` route class and the logical model header after selection. Key introspection remains gated on the governance batch and must not be claimed stable here.

- [x] **Step 7: Run focused Rust tests and commit**

Run: `cargo test -p sbproxy-model-host deployment`

Run: `cargo test -p sbproxy-model-host cluster_authority`

Run: `cargo test -p sbproxy-core --test managed_replica_dispatch`

Expected: PASS.

Commit: `git commit -m "WOR-1854: govern cold starts and model discovery"`

---

### Task 7: Multi-process streaming, cancellation, and failure drills

**Files:**
- Modify: `e2e/src/bin/fake_model_engine.rs`
- Create: `e2e/tests/model_cluster_dispatch.rs`
- Modify: `e2e/Cargo.toml`
- Modify: `examples/model-cluster-split/gateway.yml`
- Modify: `examples/model-cluster-split/worker-a.yml`
- Modify: `examples/model-cluster-split/worker-b.yml`
- Modify: `examples/model-cluster-split/README.md`
- Modify: `examples/model-cluster-symmetric/sb.yml`
- Modify: `examples/model-cluster-symmetric/README.md`

**Interfaces:**
- Produces: fake-engine control modes for unary, SSE, delayed headers, pre-output error, mid-stream error, and cancellation observation.
- Produces: a three-process cluster fixture with explicit development authentication and managed providers.

- [ ] **Step 1: Write a failing fake-engine behavior test**

```rust,no_run
#[tokio::test]
async fn fake_engine_streams_usage_and_observes_disconnect() {
    let engine = FakeEngine::start(FaultMode::StreamUntilCancelled).await;
    let response = engine.chat(true).await;
    assert_eq!(first_frame(response).await, "data: {\"choices\":[");
    drop(response);
    assert!(engine.wait_for_cancellation(Duration::from_secs(2)).await);
}
```

- [ ] **Step 2: Run and verify RED**

Run: `cargo test -p sbproxy-e2e --bin fake_model_engine -- --nocapture`

Expected: FAIL because the fake engine implements readiness only.

- [ ] **Step 3: Add deterministic engine fixtures**

Keep `/health` unchanged. Add `/v1/chat/completions`, `/v1/models`, and a test-only loopback control endpoint. The completion handler echoes a fixed model and usage object, supports SSE, and records active/cancelled request counts without logging authorization headers or request bodies.

- [ ] **Step 4: Write the failing three-node E2E scenarios**

```rust,no_run
#[test]
fn remote_stream_failover_and_cancel_are_safe() {
    let cluster = ThreeNodeCluster::start();
    cluster.assert_models_lists_logical_qwen_only();
    cluster.assert_remote_unary_completion();
    cluster.assert_remote_sse_usage();
    cluster.assert_concurrent_cold_start_launches_once();
    cluster.assert_pre_output_worker_failure_fails_over();
    cluster.assert_mid_stream_failure_does_not_replay();
    cluster.assert_client_cancel_reaches_engine_and_releases_permit();
    cluster.assert_raw_public_key_absent_from_worker_logs();
}
```

- [ ] **Step 5: Run and verify RED**

Run: `SBPROXY_E2E_BIN=$(pwd)/target/debug/sbproxy cargo test -p sbproxy-e2e --test model_cluster_dispatch -- --nocapture`

Expected: FAIL on the first remote completion before data-plane integration is complete.

- [ ] **Step 6: Complete fixtures and example configuration**

Use loopback-only engine ports, distinct gateway/worker model-plane ports, explicit shared development secret, finite snapshot intervals, bounded waits, and process-group cleanup. The examples must include a managed provider at the gateway and a curl that proves the selected worker without exposing its address in the public response.

- [ ] **Step 7: Run E2E and commit**

Run: `cargo build -p sbproxy && SBPROXY_E2E_BIN=$(pwd)/target/debug/sbproxy cargo test -p sbproxy-e2e --test model_cluster_dispatch -- --nocapture`

Expected: PASS with all child processes reaped.

Commit: `git commit -m "WOR-1850: prove three node model dispatch"`

---

### Task 8: Documentation, capability evidence, and final verification

**Files:**
- Modify: `docs/model-host.md`
- Modify: `docs/security-model-host.md`
- Modify: `docs/ai-gateway.md`
- Modify: `docs/configuration.md`
- Modify: `docs/troubleshooting.md`
- Modify: `docs/model-host-certification.md`
- Modify: `docs/model-host-capabilities.md` through its generator
- Modify: `docs/self-hosted-openrouter-delivery-design.md`
- Modify: `docs/llms-full.txt` through its generator
- Modify: `schemas/sb-config.schema.json` through its generator
- Modify: `schemas/ai-proxy-provider.schema.json` through its generator
- Modify: `crates/sbproxy-model-host/src/capabilities.rs`
- Modify: `docs/metrics-stability.md`

**Interfaces:**
- Produces: executable evidence for remote dispatch, streaming, cancellation, pre-output failover, cold-start policy, and logical model discovery.
- Preserves: the current admin model-management capability state; only remote data-plane fields advance in this batch.

- [ ] **Step 1: Update operator and security documentation**

Document the exact request flow, `model_bind` versus `model_endpoint`, mTLS and explicit development mode, certificate/node-name requirements, envelope fields, replay bounds, one-hop rule, queue/cold-start behavior, Retry-After, failover boundary, cancellation, stable errors, safe route headers, metrics, and troubleshooting commands. Remove statements that remote dispatch is absent.

- [ ] **Step 2: Update executable capability evidence**

Add evidence IDs backed by the focused unit and three-node E2E tests. Promote only the verified remote data-plane fields. Keep GCP, NVIDIA multi-node, strict distributed budgets, and full SH-16 key introspection as Preview or Unsupported according to current truth.

- [ ] **Step 3: Regenerate machine-derived artifacts**

Run: `cargo run -q -p sbproxy-config --bin generate-schema > schemas/sb-config.schema.json`

Run: `cargo run -q -p sbproxy-ai --bin generate-ai-provider-schema > schemas/ai-proxy-provider.schema.json`

Run: `cargo run -q -p sbproxy-model-host --bin generate-model-host-capabilities > docs/model-host-capabilities.md`

Run: `LC_ALL=C ./scripts/regen-llms-full.sh`

Expected: schema, capability matrix, and `llms-full.txt` change only as explained by this PR.

- [ ] **Step 4: Run focused final verification**

Run: `cargo fmt --all -- --check`

Run: `cargo test -p sbproxy-config --test cluster_config`

Run: `cargo test -p sbproxy-mesh cluster_handle::tests`

Run: `cargo test -p sbproxy-mesh transport::tls::tests`

Run: `cargo test -p sbproxy-model-host --test model_directory`

Run: `cargo test -p sbproxy-model-host deployment`

Run: `cargo test -p sbproxy-model-host cluster_authority`

Run: `cargo test -p sbproxy-ai --test managed_replica_routing`

Run: `cargo test -p sbproxy-core --test model_plane_envelope --test model_plane_transport --test managed_replica_dispatch`

Run: `cargo build -p sbproxy && SBPROXY_E2E_BIN=$(pwd)/target/debug/sbproxy cargo test -p sbproxy-e2e --test model_cluster_dispatch -- --nocapture`

Run: `cargo clippy -p sbproxy-config -p sbproxy-mesh -p sbproxy-model-host -p sbproxy-ai -p sbproxy-core -p sbproxy-e2e --all-targets -- -D warnings`

Run: `LC_ALL=C ./scripts/regen-llms-full.sh --check && git diff --check`

Expected: every command exits 0. Do not run GCP certification in this batch.

- [ ] **Step 5: Review scope and secrets before publishing**

Inspect the diff for private endpoints, PEM material, secrets, raw bearer values, prompts, tracker placeholders, em dashes, unbounded metric labels, unsafe JSON integers, and claims not backed by executable evidence. Verify every SH-11/12/13 acceptance criterion and the implemented SH-16 subset has a test or explicit documented deferral.

- [ ] **Step 6: Commit documentation and generated artifacts**

Commit: `git commit -m "WOR-1835: document distributed model serving"`
