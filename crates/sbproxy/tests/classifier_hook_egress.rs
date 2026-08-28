// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Process-boundary coverage for stock classifier-hook egress.
//!
//! The hook is intentionally exercised through the shipped `sbproxy` binary,
//! a real AI POST, and real loopback listeners. A construction-only test would
//! miss the current last-callsite bypass in `LazyClassifierClient::classify`,
//! where the stock hook creates an ungated client immediately before dialing.

use std::io::{self, Read, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sbproxy_classifier_proto::{
    ClassifierService, ClassifierServiceServer, ClassifyRequest, ClassifyResponse, CompressRequest,
    CompressResponse, EmbedRequest, EmbedResponse, InferenceService, InferenceServiceServer, Label,
    ModelInfoRequest, ModelInfoResponse, QualityRequest, QualityResponse, SafetyToken,
    SafetyVerdict, VersionRequest, VersionResponse,
};
use tokio_stream::StreamExt as _;
use tonic::{Request, Response, Status, Streaming};

const PROMPT_MARKER: &str = "classifier-egress-private-prompt-c0";
const INTENT_MODEL: &str = "intent-v1";
const QUALITY_MODEL: &str = "quality-local-openai-v1";
const QUALITY_LABEL: &str = "preferred";
const HOOK_TIMEOUT: Duration = Duration::from_millis(250);
const DENIAL_QUIET_WINDOW: Duration = Duration::from_millis(500);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const FIXTURE_STARTUP_TIMEOUT: Duration = Duration::from_secs(2);
const FIXTURE_IO_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_FIXTURE_REQUEST_BYTES: usize = 64 * 1024;
const MAX_HTTP_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_RECORDED_CLASSIFY_CALLS: usize = 8;
const MAX_CAPTURED_CHILD_OUTPUT_BYTES: usize = 32 * 1024;
const CHILD_OUTPUT_READ_BYTES: usize = 4096;
// Readiness needs only the status line and response headers. Refuse a peer
// that cannot frame them within this fixed in-memory ceiling.
const MAX_READINESS_RESPONSE_BYTES: usize = 16 * 1024;
const PORT_ATTEMPTS: usize = 4;
const FIXTURE_PROVIDER_KEY: &str = "fixture-key";
const ADDRESS_IN_USE_MARKERS: &[&[u8]] = &[b"address already in use", b"address in use"];
const CLASSIFIER_CONFIG_MARKER: &[u8] = b"classifier_hooks";
const UNKNOWN_FIELD_MARKER: &[u8] = b"unknown field";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sbproxy")
}

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new(label: &str) -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sbproxy-classifier-hook-egress-{label}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassifyCall {
    model: String,
    top_k: u32,
    exact_prompt: bool,
}

#[derive(Default)]
struct ClassifierObservation {
    accepts: AtomicUsize,
    classify_total: AtomicUsize,
    classify_calls: Mutex<Vec<ClassifyCall>>,
    quality_total: AtomicUsize,
    other_rpc_total: AtomicUsize,
    exact_prompt_rpcs: AtomicUsize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassifierSnapshot {
    accepts: usize,
    classify_total: usize,
    classify_calls: Vec<ClassifyCall>,
    quality_total: usize,
    other_rpc_total: usize,
    exact_prompt_rpcs: usize,
}

impl ClassifierSnapshot {
    fn is_quiet(&self) -> bool {
        self.accepts == 0
            && self.classify_total == 0
            && self.classify_calls.is_empty()
            && self.quality_total == 0
            && self.other_rpc_total == 0
            && self.exact_prompt_rpcs == 0
    }
}

#[derive(Clone)]
struct ClassifierGrpcService {
    observation: Arc<ClassifierObservation>,
    prompt_marker: Arc<str>,
}

#[tonic::async_trait]
impl InferenceService for ClassifierGrpcService {
    async fn classify(
        &self,
        request: Request<ClassifyRequest>,
    ) -> Result<Response<ClassifyResponse>, Status> {
        let request = request.into_inner();
        let exact_prompt = request.text == self.prompt_marker.as_ref();
        if exact_prompt {
            self.observation
                .exact_prompt_rpcs
                .fetch_add(1, Ordering::AcqRel);
        }
        let call = ClassifyCall {
            model: request.model.clone(),
            top_k: request.top_k,
            exact_prompt,
        };
        let mut calls = self
            .observation
            .classify_calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if calls.len() < MAX_RECORDED_CLASSIFY_CALLS {
            calls.push(call);
        }
        drop(calls);
        // Publish completion only after the privacy-safe call record is
        // visible, so the bounded observer cannot return a partial snapshot.
        self.observation
            .classify_total
            .fetch_add(1, Ordering::AcqRel);

        let labels = match request.model.as_str() {
            INTENT_MODEL => vec![Label {
                name: "coding".to_string(),
                score: 0.99,
            }],
            QUALITY_MODEL => vec![
                Label {
                    name: QUALITY_LABEL.to_string(),
                    score: 0.95,
                },
                Label {
                    name: "other".to_string(),
                    score: 0.05,
                },
            ],
            _ => return Err(Status::invalid_argument("unexpected classifier model")),
        };
        Ok(Response::new(ClassifyResponse {
            labels,
            latency_us: 1,
        }))
    }

    async fn embed(
        &self,
        _request: Request<EmbedRequest>,
    ) -> Result<Response<EmbedResponse>, Status> {
        self.observation
            .other_rpc_total
            .fetch_add(1, Ordering::AcqRel);
        Err(Status::unimplemented("embed is outside this fixture"))
    }

    async fn compress(
        &self,
        _request: Request<CompressRequest>,
    ) -> Result<Response<CompressResponse>, Status> {
        self.observation
            .other_rpc_total
            .fetch_add(1, Ordering::AcqRel);
        Err(Status::unimplemented("compress is outside this fixture"))
    }

    async fn model_info(
        &self,
        _request: Request<ModelInfoRequest>,
    ) -> Result<Response<ModelInfoResponse>, Status> {
        self.observation
            .other_rpc_total
            .fetch_add(1, Ordering::AcqRel);
        Err(Status::unimplemented("model_info is outside this fixture"))
    }

    async fn version(
        &self,
        _request: Request<VersionRequest>,
    ) -> Result<Response<VersionResponse>, Status> {
        self.observation
            .other_rpc_total
            .fetch_add(1, Ordering::AcqRel);
        Err(Status::unimplemented("version is outside this fixture"))
    }
}

#[tonic::async_trait]
impl ClassifierService for ClassifierGrpcService {
    async fn quality(
        &self,
        request: Request<QualityRequest>,
    ) -> Result<Response<QualityResponse>, Status> {
        let request = request.into_inner();
        self.observation
            .quality_total
            .fetch_add(1, Ordering::AcqRel);
        if request.text == self.prompt_marker.as_ref() {
            self.observation
                .exact_prompt_rpcs
                .fetch_add(1, Ordering::AcqRel);
        }
        Ok(Response::new(QualityResponse {
            score: 0.95,
            signals: std::collections::HashMap::new(),
        }))
    }

    type StreamSafetyStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<SafetyVerdict, Status>> + Send>>;

    async fn stream_safety(
        &self,
        _request: Request<Streaming<SafetyToken>>,
    ) -> Result<Response<Self::StreamSafetyStream>, Status> {
        self.observation
            .other_rpc_total
            .fetch_add(1, Ordering::AcqRel);
        Err(Status::unimplemented(
            "stream_safety is outside this fixture",
        ))
    }
}

/// Real bounded gRPC server for both classifier services the shared stock
/// client carries. Observations retain model ids and prompt equality only;
/// request text never leaves the RPC handler or appears in failures.
struct ClassifierFixture {
    address: SocketAddr,
    observation: Arc<ClassifierObservation>,
    server_failure: Arc<Mutex<Option<String>>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl ClassifierFixture {
    fn start(prompt_marker: &str) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|error| format!("bind classifier fixture: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("configure classifier fixture listener: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("read classifier fixture address: {error}"))?;
        let observation = Arc::new(ClassifierObservation::default());
        let server_failure = Arc::new(Mutex::new(None));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread_observation = Arc::clone(&observation);
        let thread_failure = Arc::clone(&server_failure);
        let service = ClassifierGrpcService {
            observation: Arc::clone(&observation),
            prompt_marker: Arc::from(prompt_marker),
        };
        let join = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ =
                        ready_tx.send(Err(format!("build classifier fixture runtime: {error}")));
                    return;
                }
            };
            let result = runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .map_err(|error| format!("adopt classifier fixture listener: {error}"))?;
                let incoming =
                    tokio_stream::wrappers::TcpListenerStream::new(listener).map(move |result| {
                        if result.is_ok() {
                            thread_observation.accepts.fetch_add(1, Ordering::AcqRel);
                        }
                        result
                    });
                ready_tx
                    .send(Ok(()))
                    .map_err(|_| "classifier fixture ready receiver dropped".to_string())?;
                tonic::transport::Server::builder()
                    .add_service(InferenceServiceServer::new(service.clone()))
                    .add_service(ClassifierServiceServer::new(service))
                    .serve_with_incoming_shutdown(incoming, async move {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .map_err(|error| format!("serve classifier fixture: {error}"))
            });
            if let Err(error) = result {
                let mut failure = thread_failure
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *failure = Some(error);
            }
        });
        match ready_rx.recv_timeout(FIXTURE_STARTUP_TIMEOUT) {
            Ok(Ok(())) => Ok(Self {
                address,
                observation,
                server_failure,
                shutdown: Some(shutdown_tx),
                join: Some(join),
            }),
            Ok(Err(error)) => {
                let _ = join.join();
                Err(error)
            }
            Err(_) => {
                let _ = shutdown_tx.send(());
                let _ = join.join();
                Err("classifier fixture did not become ready before its bounded deadline".into())
            }
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn snapshot(&self) -> ClassifierSnapshot {
        let calls = self
            .observation
            .classify_calls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        ClassifierSnapshot {
            accepts: self.observation.accepts.load(Ordering::Acquire),
            classify_total: self.observation.classify_total.load(Ordering::Acquire),
            classify_calls: calls,
            quality_total: self.observation.quality_total.load(Ordering::Acquire),
            other_rpc_total: self.observation.other_rpc_total.load(Ordering::Acquire),
            exact_prompt_rpcs: self.observation.exact_prompt_rpcs.load(Ordering::Acquire),
        }
    }

    fn server_failure(&self) -> Option<String> {
        self.server_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn assert_quiet_now(&self, context: &str) {
        assert!(
            self.server_failure().is_none(),
            "{context}: classifier fixture server failed"
        );
        let snapshot = self.snapshot();
        assert!(snapshot.is_quiet(), "{context}: {snapshot:?}");
    }

    fn require_quiet_window(&self, window: Duration) -> Result<(), String> {
        let deadline = Instant::now() + window;
        loop {
            if self.server_failure().is_some() {
                return Err("classifier fixture server failed during quiet window".into());
            }
            let snapshot = self.snapshot();
            if !snapshot.is_quiet() {
                return Err(format!(
                    "classifier activity appeared inside denial quiet window: {snapshot:?}"
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(5).min(remaining));
        }
    }

    fn wait_for_classify_total(
        &self,
        expected: usize,
        timeout: Duration,
    ) -> Result<ClassifierSnapshot, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.server_failure().is_some() {
                return Err("classifier fixture server failed while awaiting RPCs".into());
            }
            let snapshot = self.snapshot();
            if snapshot.classify_total >= expected
                || snapshot.quality_total > 0
                || snapshot.other_rpc_total > 0
            {
                return Ok(snapshot);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "classifier RPC deadline elapsed with privacy-safe observation {snapshot:?}"
                ));
            }
            std::thread::sleep(Duration::from_millis(5).min(remaining));
        }
    }
}

impl Drop for ClassifierFixture {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Default)]
struct UpstreamObservation {
    requests: AtomicUsize,
    prompt_seen: AtomicBool,
}

/// Minimal OpenAI-compatible HTTP fixture. Only booleans and counts escape
/// the listener thread, so a failing assertion cannot print the request body.
struct OpenAiFixture {
    address: SocketAddr,
    observation: Arc<UpstreamObservation>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl OpenAiFixture {
    fn start(prompt_marker: &str) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let observation = Arc::new(UpstreamObservation::default());
        let stop = Arc::new(AtomicBool::new(false));
        let thread_observation = Arc::clone(&observation);
        let thread_stop = Arc::clone(&stop);
        let marker = prompt_marker.as_bytes().to_vec();
        let join = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // The listener is non-blocking, and on BSD and macOS an accepted
                        // socket inherits that flag, which makes the read timeout
                        // below a no-op: `read` returns `WouldBlock` at once and the
                        // reader gives up on a partial request. Clear it, the way
                        // every other non-blocking-listener fixture in this
                        // workspace does.
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(FIXTURE_IO_TIMEOUT));
                        let request = read_bounded_http_request(&mut stream).unwrap_or_default();
                        thread_observation.requests.fetch_add(1, Ordering::AcqRel);
                        if contains_bytes(&request, &marker) {
                            thread_observation
                                .prompt_seen
                                .store(true, Ordering::Release);
                        }
                        let _ = write_openai_response(&mut stream);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            observation,
            stop,
            join: Some(join),
        })
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn requests(&self) -> usize {
        self.observation.requests.load(Ordering::Acquire)
    }

    fn prompt_seen(&self) -> bool {
        self.observation.prompt_seen.load(Ordering::Acquire)
    }
}

impl Drop for OpenAiFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn read_bounded_http_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 4096];
    while request.len() < MAX_FIXTURE_REQUEST_BYTES {
        let remaining = MAX_FIXTURE_REQUEST_BYTES - request.len();
        let read_limit = remaining.min(chunk.len());
        match stream.read(&mut chunk[..read_limit]) {
            Ok(0) => break,
            Ok(read) => {
                request.extend_from_slice(&chunk[..read]);
                if http_request_is_complete(&request) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(request)
}

fn http_request_is_complete(request: &[u8]) -> bool {
    let Some(header_end) = find_bytes(request, b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    });
    content_length.is_some_and(|length| {
        header_end
            .checked_add(4)
            .and_then(|body_start| body_start.checked_add(length))
            .is_some_and(|expected| request.len() >= expected)
    })
}

fn write_openai_response(stream: &mut TcpStream) -> io::Result<()> {
    const BODY: &str = r#"{"id":"chatcmpl-c0","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    )?;
    stream.flush()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        None
    } else {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}

#[derive(Clone, Copy)]
enum HookEgressPolicy {
    DenyAll,
    AllowLoopback,
}

impl HookEgressPolicy {
    fn yaml(self, classifier_port: u16) -> String {
        match self {
            Self::DenyAll => format!(
                "  classifier_hooks:\n    mode: deny_by_default\n    hosts: []\n    ports: [{classifier_port}]"
            ),
            Self::AllowLoopback => format!(
                "  classifier_hooks:\n    mode: deny_by_default\n    hosts: [\"127.0.0.1\"]\n    allow_private: true\n    ports: [{classifier_port}]"
            ),
        }
    }
}

fn proxy_yaml(
    proxy_port: u16,
    classifier: &ClassifierFixture,
    upstream: &OpenAiFixture,
    policy: HookEgressPolicy,
) -> String {
    // Correct-child mutation guard: readiness deliberately uses Echo rather
    // than Static. Echo returns 200 through the generated-response arm that
    // stamps this child's harness token; Static does not stamp that token.
    format!(
        r#"proxy:
  http_bind_port: {proxy_port}
  bind_address: 127.0.0.1
  classifier_hooks:
    endpoint: {classifier_endpoint}
    timeout_ms: {hook_timeout_ms}
    intent:
      model: {intent_model}
    quality:
      minimum_score: 0.8
      provider_models:
        local-openai:
          model: {quality_model}
          label: {quality_label}
egress:
{egress_policy}
origins:
  "ready.localhost":
    action:
      type: echo
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: local-openai
          provider_type: openai
          api_key: {provider_key}
          base_url: {upstream_url}
          allow_private_base_url: true
          models: [gpt-4o]
"#,
        classifier_endpoint = classifier.endpoint(),
        hook_timeout_ms = HOOK_TIMEOUT.as_millis(),
        egress_policy = policy.yaml(classifier.port()),
        intent_model = INTENT_MODEL,
        quality_model = QUALITY_MODEL,
        quality_label = QUALITY_LABEL,
        provider_key = FIXTURE_PROVIDER_KEY,
        upstream_url = upstream.base_url(),
    )
}

#[derive(Default)]
struct BoundedOutputState {
    retained: Vec<u8>,
    total_bytes: u64,
    overflowed: bool,
    private_marker_detected: bool,
    address_in_use: bool,
    classifier_config_marker: bool,
    unknown_field_marker: bool,
}

#[derive(Debug)]
struct BoundedOutputSummary {
    retained_bytes: usize,
    total_bytes: u64,
    overflowed: bool,
    private_marker_detected: bool,
    address_in_use: bool,
    classifier_config_marker: bool,
    unknown_field_marker: bool,
    drain_failed: bool,
}

impl BoundedOutputSummary {
    fn validate_complete_scan(&self) -> Result<(), String> {
        if self.drain_failed {
            return Err("child output could not be scanned to EOF".to_string());
        }
        if self.private_marker_detected {
            return Err("child output contained a private test marker".to_string());
        }
        if self.retained_bytes > MAX_CAPTURED_CHILD_OUTPUT_BYTES {
            return Err("child output exceeded the in-memory diagnostic ceiling".to_string());
        }
        let ceiling = u64::try_from(MAX_CAPTURED_CHILD_OUTPUT_BYTES)
            .expect("the fixed diagnostic ceiling fits in u64");
        if self.overflowed != (self.total_bytes > ceiling)
            || u64::try_from(self.retained_bytes).unwrap_or(u64::MAX)
                != self.total_bytes.min(ceiling)
        {
            return Err("child output accounting was internally inconsistent".to_string());
        }
        Ok(())
    }

    fn is_unknown_classifier_config(&self) -> bool {
        self.classifier_config_marker && self.unknown_field_marker
    }
}

struct BoundedChildOutput {
    state: Arc<Mutex<BoundedOutputState>>,
    drains: Vec<JoinHandle<io::Result<()>>>,
}

impl BoundedChildOutput {
    fn from_child(child: &mut Child, harness_token: &str) -> Result<Self, String> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "shipped child stdout pipe was not available".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "shipped child stderr pipe was not available".to_string())?;
        Ok(Self::from_readers(
            stdout,
            stderr,
            vec![
                PROMPT_MARKER.as_bytes().to_vec(),
                FIXTURE_PROVIDER_KEY.as_bytes().to_vec(),
                harness_token.as_bytes().to_vec(),
            ],
        ))
    }

    fn from_readers<Stdout, Stderr>(
        stdout: Stdout,
        stderr: Stderr,
        private_markers: Vec<Vec<u8>>,
    ) -> Self
    where
        Stdout: Read + Send + 'static,
        Stderr: Read + Send + 'static,
    {
        let state = Arc::new(Mutex::new(BoundedOutputState::default()));
        let private_markers = Arc::new(private_markers);
        let stdout_state = Arc::clone(&state);
        let stderr_state = Arc::clone(&state);
        let stdout_markers = Arc::clone(&private_markers);
        let stderr_markers = Arc::clone(&private_markers);
        let drains = vec![
            std::thread::spawn(move || drain_child_output(stdout, stdout_state, stdout_markers)),
            std::thread::spawn(move || drain_child_output(stderr, stderr_state, stderr_markers)),
        ];
        Self { state, drains }
    }

    fn finish(self) -> BoundedOutputSummary {
        let Self { state, drains } = self;
        let mut drain_failed = false;
        for drain in drains {
            match drain.join() {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => drain_failed = true,
            }
        }
        drain_failed |= state.is_poisoned();
        let state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        BoundedOutputSummary {
            retained_bytes: state.retained.len(),
            total_bytes: state.total_bytes,
            overflowed: state.overflowed,
            private_marker_detected: state.private_marker_detected,
            address_in_use: state.address_in_use,
            classifier_config_marker: state.classifier_config_marker,
            unknown_field_marker: state.unknown_field_marker,
            drain_failed,
        }
    }
}

fn drain_child_output<Reader>(
    mut reader: Reader,
    state: Arc<Mutex<BoundedOutputState>>,
    private_markers: Arc<Vec<Vec<u8>>>,
) -> io::Result<()>
where
    Reader: Read,
{
    let overlap = max_scanner_marker_bytes(private_markers.as_slice()).saturating_sub(1);
    let mut scanner_tail = Vec::with_capacity(overlap);
    let mut chunk = [0_u8; CHILD_OUTPUT_READ_BYTES];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(read) => scan_child_output_chunk(
                &state,
                &mut scanner_tail,
                &chunk[..read],
                private_markers.as_slice(),
                overlap,
            ),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn scan_child_output_chunk(
    state: &Arc<Mutex<BoundedOutputState>>,
    scanner_tail: &mut Vec<u8>,
    chunk: &[u8],
    private_markers: &[Vec<u8>],
    overlap: usize,
) {
    let mut searchable = Vec::with_capacity(scanner_tail.len() + chunk.len());
    searchable.extend_from_slice(scanner_tail);
    searchable.extend_from_slice(chunk);

    let private_marker_detected = private_markers
        .iter()
        .any(|marker| contains_bytes(&searchable, marker));
    let address_in_use = ADDRESS_IN_USE_MARKERS
        .iter()
        .any(|marker| contains_ascii_case_insensitive(&searchable, marker));
    let classifier_config_marker = contains_bytes(&searchable, CLASSIFIER_CONFIG_MARKER);
    let unknown_field_marker = contains_bytes(&searchable, UNKNOWN_FIELD_MARKER);

    let tail_start = searchable.len().saturating_sub(overlap);
    scanner_tail.clear();
    scanner_tail.extend_from_slice(&searchable[tail_start..]);

    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.total_bytes = state
        .total_bytes
        .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
    let remaining = MAX_CAPTURED_CHILD_OUTPUT_BYTES.saturating_sub(state.retained.len());
    let retained_from_chunk = remaining.min(chunk.len());
    state
        .retained
        .extend_from_slice(&chunk[..retained_from_chunk]);
    state.overflowed |= retained_from_chunk < chunk.len();
    state.private_marker_detected |= private_marker_detected;
    state.address_in_use |= address_in_use;
    state.classifier_config_marker |= classifier_config_marker;
    state.unknown_field_marker |= unknown_field_marker;
}

fn max_scanner_marker_bytes(private_markers: &[Vec<u8>]) -> usize {
    private_markers
        .iter()
        .map(Vec::len)
        .chain(ADDRESS_IN_USE_MARKERS.iter().map(|marker| marker.len()))
        .chain([CLASSIFIER_CONFIG_MARKER.len(), UNKNOWN_FIELD_MARKER.len()])
        .max()
        .unwrap_or(1)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle.iter())
                .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundedReadEnd {
    Delimiter,
    Eof,
    LimitExceeded,
}

#[derive(Debug, PartialEq, Eq)]
struct BoundedReadFrame {
    retained: Vec<u8>,
    observed_bytes: usize,
    end: BoundedReadEnd,
}

/// Reads through EOF, a delimiter, or the first byte beyond `max_bytes`.
/// Retention is independently capped, so readiness can keep its frame while
/// AI response bodies are counted and drained without being stored.
fn read_bounded_frame<Reader>(
    reader: &mut Reader,
    max_bytes: usize,
    retention_limit: usize,
    delimiter: Option<&[u8]>,
) -> io::Result<BoundedReadFrame>
where
    Reader: Read,
{
    if retention_limit > max_bytes
        || delimiter.is_some_and(|_| retention_limit != max_bytes)
        || max_bytes == usize::MAX
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid bounded-read limits",
        ));
    }

    let mut retained = Vec::with_capacity(retention_limit);
    let mut observed_bytes = 0_usize;
    let mut chunk = [0_u8; 4096];
    loop {
        let read_limit = if observed_bytes == max_bytes {
            1
        } else {
            (max_bytes - observed_bytes).min(chunk.len())
        };
        let read = match reader.read(&mut chunk[..read_limit]) {
            Ok(0) => {
                return Ok(BoundedReadFrame {
                    retained,
                    observed_bytes,
                    end: BoundedReadEnd::Eof,
                });
            }
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        observed_bytes = observed_bytes
            .checked_add(read)
            .ok_or_else(|| io::Error::other("bounded-read byte count overflowed"))?;
        let retained_remaining = retention_limit.saturating_sub(retained.len());
        let retain = retained_remaining.min(read);
        retained.extend_from_slice(&chunk[..retain]);

        if delimiter.is_some_and(|delimiter| find_bytes(&retained, delimiter).is_some()) {
            return Ok(BoundedReadFrame {
                retained,
                observed_bytes,
                end: BoundedReadEnd::Delimiter,
            });
        }
        if observed_bytes > max_bytes {
            return Ok(BoundedReadFrame {
                retained,
                observed_bytes,
                end: BoundedReadEnd::LimitExceeded,
            });
        }
    }
}

struct FragmentedReader {
    chunks: std::collections::VecDeque<Vec<u8>>,
    offset: usize,
}

impl FragmentedReader {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            chunks: chunks.into(),
            offset: 0,
        }
    }
}

impl Read for FragmentedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let Some(chunk) = self.chunks.front() else {
                return Ok(0);
            };
            if self.offset == chunk.len() {
                self.chunks.pop_front();
                self.offset = 0;
                continue;
            }
            let read = buffer.len().min(chunk.len() - self.offset);
            buffer[..read].copy_from_slice(&chunk[self.offset..self.offset + read]);
            self.offset += read;
            return Ok(read);
        }
    }
}

struct RecordingReader {
    remaining_bytes: usize,
    consumed_bytes: usize,
    requested_bytes: Vec<usize>,
}

impl RecordingReader {
    fn new(available_bytes: usize) -> Self {
        Self {
            remaining_bytes: available_bytes,
            consumed_bytes: 0,
            requested_bytes: Vec::new(),
        }
    }

    fn consumed_bytes(&self) -> usize {
        self.consumed_bytes
    }

    fn remaining_bytes(&self) -> usize {
        self.remaining_bytes
    }

    fn last_requested_bytes(&self) -> Option<usize> {
        self.requested_bytes.last().copied()
    }
}

impl Read for RecordingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.requested_bytes.push(buffer.len());
        let read = buffer.len().min(self.remaining_bytes);
        buffer[..read].fill(b'x');
        self.remaining_bytes -= read;
        self.consumed_bytes += read;
        Ok(read)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AiPostError {
    ClientBuild,
    RequestFailed,
    ResponseRead,
    ResponseLimitExceeded {
        limit_bytes: usize,
        observed_bytes: usize,
        retained_bytes: usize,
    },
}

impl std::fmt::Display for AiPostError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientBuild => formatter.write_str("build local test client"),
            Self::RequestFailed => formatter.write_str("send local AI request"),
            Self::ResponseRead => formatter.write_str("read local AI response"),
            Self::ResponseLimitExceeded {
                limit_bytes,
                observed_bytes,
                ..
            } => write!(
                formatter,
                "local AI response exceeded the {limit_bytes}-byte ceiling after observing {observed_bytes} bytes"
            ),
        }
    }
}

impl std::error::Error for AiPostError {}

/// Sole owner of the AI POST path used by both real child-process cases and
/// the adversarial oversized-response fixture.
#[derive(Debug, Clone, Copy)]
struct ProxyEndpoint {
    port: u16,
}

impl ProxyEndpoint {
    fn post_ai(&self, prompt: &str) -> Result<u16, AiPostError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .build()
            .map_err(|_| AiPostError::ClientBuild)?;
        let mut response = client
            .post(format!(
                "http://127.0.0.1:{}/v1/chat/completions",
                self.port
            ))
            .header("host", "ai.localhost")
            .json(&serde_json::json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": prompt}]
            }))
            .send()
            .map_err(|_| AiPostError::RequestFailed)?;
        let status = response.status().as_u16();
        let response_frame = read_bounded_frame(&mut response, MAX_HTTP_RESPONSE_BYTES, 0, None)
            .map_err(|_| AiPostError::ResponseRead)?;
        if response_frame.end == BoundedReadEnd::LimitExceeded {
            return Err(AiPostError::ResponseLimitExceeded {
                limit_bytes: MAX_HTTP_RESPONSE_BYTES,
                observed_bytes: response_frame.observed_bytes,
                retained_bytes: response_frame.retained.len(),
            });
        }
        Ok(status)
    }
}

struct ProxyChild {
    child: Child,
    endpoint: ProxyEndpoint,
    output: Option<BoundedChildOutput>,
}

impl ProxyChild {
    fn start(
        root: &TestRoot,
        classifier: &ClassifierFixture,
        upstream: &OpenAiFixture,
        policy: HookEgressPolicy,
    ) -> Result<Self, String> {
        let token = harness_token();
        for attempt in 0..PORT_ATTEMPTS {
            let reservation = TcpListener::bind("127.0.0.1:0")
                .map_err(|error| format!("reserve proxy listener: {error}"))?;
            let port = reservation
                .local_addr()
                .map_err(|error| format!("read proxy listener address: {error}"))?
                .port();
            let config_path = root.path().join(format!("sb-{attempt}.yml"));
            std::fs::write(&config_path, proxy_yaml(port, classifier, upstream, policy))
                .map_err(|error| format!("write proxy config: {error}"))?;
            let mut command = Command::new(binary());
            command
                .arg("serve")
                .arg(&config_path)
                .arg("--shutdown-grace-ms")
                .arg("0")
                .arg("--log-level")
                .arg("error")
                .env_remove("SB_CONFIG_FILE")
                .env("SBPROXY_E2E_HARNESS_TOKEN", &token)
                .env(
                    "SBPROXY_ENGINE_OWNERSHIP_DIR",
                    root.path().join(format!("ownership-{attempt}")),
                )
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            // Keep the reservation until every fallible setup step is done,
            // then make the unavoidable handoff window as small as possible.
            drop(reservation);
            let mut child = command
                .spawn()
                .map_err(|error| format!("spawn sbproxy: {error}"))?;
            let output = match BoundedChildOutput::from_child(&mut child, &token) {
                Ok(output) => output,
                Err(error) => {
                    let _ = stop_and_reap_child(&mut child);
                    return Err(error);
                }
            };
            match wait_for_ready(&mut child, port, &token, STARTUP_TIMEOUT) {
                Ok(()) => {
                    return Ok(Self {
                        child,
                        endpoint: ProxyEndpoint { port },
                        output: Some(output),
                    });
                }
                Err(StartFailure::EarlyExit(status)) => {
                    let stop_result = stop_and_reap_child(&mut child);
                    let summary = output.finish();
                    summary.validate_complete_scan()?;
                    stop_result?;
                    if summary.address_in_use {
                        continue;
                    }
                    if summary.is_unknown_classifier_config() {
                        return Err(
                            "stock `egress.classifier_hooks` is rejected before the process can reach readiness"
                                .to_string(),
                        );
                    }
                    return Err(format!(
                        "sbproxy exited before readiness with {status}; retained_output_bytes={}; total_output_bytes={}; output_truncated={}",
                        summary.retained_bytes, summary.total_bytes, summary.overflowed
                    ));
                }
                Err(StartFailure::Timeout) => {
                    let stop_result = stop_and_reap_child(&mut child);
                    let summary = output.finish();
                    summary.validate_complete_scan()?;
                    stop_result?;
                    if summary.address_in_use {
                        continue;
                    }
                    return Err(format!(
                        "sbproxy did not reach the bounded readiness deadline; retained_output_bytes={}; total_output_bytes={}; output_truncated={}",
                        summary.retained_bytes, summary.total_bytes, summary.overflowed
                    ));
                }
            }
        }
        Err("could not hand an ephemeral loopback port to sbproxy after bounded retries".into())
    }

    fn shutdown(mut self) -> Result<BoundedOutputSummary, String> {
        let stop_result = stop_and_reap_child(&mut self.child);
        let Some(output) = self.output.take() else {
            return Err("child output scanner was already finished".to_string());
        };
        let summary = output.finish();
        let scan_result = summary.validate_complete_scan();
        stop_result?;
        scan_result?;
        Ok(summary)
    }
}

impl Drop for ProxyChild {
    fn drop(&mut self) {
        let _ = stop_and_reap_child(&mut self.child);
        if let Some(output) = self.output.take() {
            let _ = output.finish();
        }
    }
}

fn stop_and_reap_child(child: &mut Child) -> Result<(), String> {
    let mut first_error = None;
    match child.try_wait() {
        Ok(Some(_)) => {}
        Ok(None) => {
            if let Err(error) = child.kill() {
                first_error = Some(format!("stop shipped child: {error}"));
            }
        }
        Err(error) => {
            first_error = Some(format!("inspect shipped child status: {error}"));
            let _ = child.kill();
        }
    }
    if let Err(error) = child.wait() {
        if first_error.is_none() {
            first_error = Some(format!("reap shipped child: {error}"));
        }
    }
    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(())
    }
}

enum StartFailure {
    EarlyExit(std::process::ExitStatus),
    Timeout,
}

fn wait_for_ready(
    child: &mut Child,
    port: u16,
    token: &str,
    timeout: Duration,
) -> Result<(), StartFailure> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(StartFailure::Timeout);
        }
        if readiness_probe(port, token, deadline) {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(StartFailure::EarlyExit(status));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(StartFailure::Timeout);
        }
        std::thread::sleep(Duration::from_millis(25).min(remaining));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessProbeOutcome {
    Ready,
    Rejected,
    LimitExceeded {
        retained_bytes: usize,
        observed_bytes: usize,
    },
}

fn readiness_probe(port: u16, token: &str, deadline: Instant) -> bool {
    readiness_probe_outcome(port, token, deadline) == ReadinessProbeOutcome::Ready
}

fn readiness_probe_outcome(port: u16, token: &str, deadline: Instant) -> ReadinessProbeOutcome {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let connect_timeout = Duration::from_millis(500).min(remaining);
    if connect_timeout.is_zero() {
        return ReadinessProbeOutcome::Rejected;
    }
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, connect_timeout) else {
        return ReadinessProbeOutcome::Rejected;
    };
    if !write_before_deadline(
        &mut stream,
        b"GET / HTTP/1.1\r\nHost: ready.localhost\r\nConnection: close\r\n\r\n",
        deadline,
    ) {
        return ReadinessProbeOutcome::Rejected;
    }
    read_readiness_headers_before_deadline(&mut stream, token, deadline)
}

fn write_before_deadline(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> bool {
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let write_timeout = FIXTURE_IO_TIMEOUT.min(remaining);
        if write_timeout.is_zero() || stream.set_write_timeout(Some(write_timeout)).is_err() {
            return false;
        }
        match stream.write(bytes) {
            Ok(0) => return false,
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    Instant::now() < deadline
}

fn read_readiness_headers_before_deadline(
    stream: &mut TcpStream,
    token: &str,
    deadline: Instant,
) -> ReadinessProbeOutcome {
    struct DeadlineReader<'a> {
        stream: &'a mut TcpStream,
        deadline: Instant,
    }

    impl Read for DeadlineReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            let read_timeout = FIXTURE_IO_TIMEOUT.min(remaining);
            if read_timeout.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "readiness deadline elapsed",
                ));
            }
            self.stream.set_read_timeout(Some(read_timeout))?;
            self.stream.read(buffer)
        }
    }

    let mut reader = DeadlineReader { stream, deadline };
    let Ok(frame) = read_bounded_frame(
        &mut reader,
        MAX_READINESS_RESPONSE_BYTES,
        MAX_READINESS_RESPONSE_BYTES,
        Some(b"\r\n\r\n"),
    ) else {
        return ReadinessProbeOutcome::Rejected;
    };
    match frame.end {
        BoundedReadEnd::Delimiter
            if Instant::now() < deadline && readiness_headers_match(&frame.retained, token) =>
        {
            ReadinessProbeOutcome::Ready
        }
        BoundedReadEnd::LimitExceeded => ReadinessProbeOutcome::LimitExceeded {
            retained_bytes: frame.retained.len(),
            observed_bytes: frame.observed_bytes,
        },
        BoundedReadEnd::Delimiter | BoundedReadEnd::Eof => ReadinessProbeOutcome::Rejected,
    }
}

fn readiness_headers_match(response: &[u8], token: &str) -> bool {
    let Some(header_end) = find_bytes(response, b"\r\n\r\n") else {
        return false;
    };
    let Ok(headers) = std::str::from_utf8(&response[..header_end]) else {
        return false;
    };
    let mut lines = headers.split("\r\n");
    if !lines
        .next()
        .is_some_and(|status| status.starts_with("HTTP/1.1 200"))
    {
        return false;
    }
    lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim()
                .eq_ignore_ascii_case("x-sbproxy-e2e-harness-token")
                && value.trim() == token
        })
    })
}

fn harness_token() -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("c0-{}-{nonce}", std::process::id())
}

#[test]
fn c0_harness_bounds_child_output_readiness_and_real_ai_post_response() {
    let private_token = b"c0-private-output-token".to_vec();
    let stdout_chunks = vec![
        vec![b'x'; MAX_CAPTURED_CHILD_OUTPUT_BYTES],
        b"classifier_".to_vec(),
        b"hooks: unknown ".to_vec(),
        b"field; classifier-egress-private-".to_vec(),
        b"prompt-c0; c0-private-".to_vec(),
        b"output-token; fixture-".to_vec(),
        b"key".to_vec(),
    ];
    let stderr_chunks = vec![b"ADDRESS ".to_vec(), b"IN USE".to_vec()];
    let expected_total = stdout_chunks
        .iter()
        .chain(stderr_chunks.iter())
        .map(Vec::len)
        .sum::<usize>();
    let summary = BoundedChildOutput::from_readers(
        FragmentedReader::new(stdout_chunks),
        FragmentedReader::new(stderr_chunks),
        vec![
            PROMPT_MARKER.as_bytes().to_vec(),
            FIXTURE_PROVIDER_KEY.as_bytes().to_vec(),
            private_token.clone(),
        ],
    )
    .finish();

    assert_eq!(
        summary.retained_bytes, MAX_CAPTURED_CHILD_OUTPUT_BYTES,
        "diagnostic retention must stop at the fixed ceiling"
    );
    assert_eq!(
        summary.total_bytes,
        u64::try_from(expected_total).expect("small fixture byte total"),
        "the drains must account for both complete streams"
    );
    assert!(summary.overflowed);
    assert!(summary.private_marker_detected);
    assert!(summary.address_in_use);
    assert!(summary.is_unknown_classifier_config());
    assert!(!summary.drain_failed);
    let failure = summary
        .validate_complete_scan()
        .expect_err("a private marker beyond retention must fail the complete scan");
    assert!(!failure.contains(PROMPT_MARKER));
    assert!(!failure.contains(FIXTURE_PROVIDER_KEY));
    assert!(!contains_bytes(failure.as_bytes(), &private_token));

    let readiness_token = "bounded-readiness-token";
    let valid =
        format!("HTTP/1.1 200 OK\r\nx-sbproxy-e2e-harness-token: {readiness_token}\r\n\r\n");
    assert!(readiness_headers_match(valid.as_bytes(), readiness_token));
    let newline_free = vec![b'x'; MAX_READINESS_RESPONSE_BYTES];
    assert!(!readiness_headers_match(&newline_free, readiness_token));

    // Production mutation this catches: widening the shared helper's single
    // overflow probe. This reader always satisfies the requested buffer, so
    // an oversized probe deterministically consumes protected trailing data.
    const UNTOUCHED_TRAILING_BYTES: usize = 8 * 1024;
    let mut recording_reader =
        RecordingReader::new(MAX_HTTP_RESPONSE_BYTES + 1 + UNTOUCHED_TRAILING_BYTES);
    let recorded_frame =
        read_bounded_frame(&mut recording_reader, MAX_HTTP_RESPONSE_BYTES, 0, None)
            .expect("read deterministic first-over-limit fixture");
    assert_eq!(recorded_frame.end, BoundedReadEnd::LimitExceeded);
    assert_eq!(recorded_frame.observed_bytes, MAX_HTTP_RESPONSE_BYTES + 1);
    assert_eq!(
        recording_reader.consumed_bytes(),
        MAX_HTTP_RESPONSE_BYTES + 1
    );
    assert_eq!(
        recording_reader.remaining_bytes(),
        UNTOUCHED_TRAILING_BYTES,
        "the overflow probe must leave every trailing source byte untouched"
    );
    assert_eq!(
        recording_reader.last_requested_bytes(),
        Some(1),
        "the overflow probe must request exactly one source byte"
    );

    // Production mutation this catches: replacing the exact AI POST method
    // used by the process tests with an unbounded whole-body collection.
    let oversized_listener =
        TcpListener::bind("127.0.0.1:0").expect("bind oversized AI response fixture");
    oversized_listener
        .set_nonblocking(true)
        .expect("make oversized AI response fixture bounded");
    let oversized_port = oversized_listener
        .local_addr()
        .expect("read oversized AI response fixture port")
        .port();
    let oversized_server = std::thread::spawn(move || -> Result<(), String> {
        const TRAILING_BODY_MARKER: &[u8] = b"c0-private-oversized-response-body-marker";
        let accept_deadline = Instant::now() + Duration::from_secs(1);
        let mut stream = loop {
            match oversized_listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= accept_deadline {
                        return Err("oversized AI response fixture accept deadline elapsed".into());
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => {
                    return Err(format!("accept oversized AI response fixture: {error}"));
                }
            }
        };
        // An accepted socket inherits the listener's non-blocking flag on
        // BSD and macOS, which turns the read timeout below into a no-op and
        // makes the completeness check fail on a request that was merely slow.
        stream
            .set_nonblocking(false)
            .map_err(|error| format!("clear oversized fixture non-blocking: {error}"))?;
        stream
            .set_read_timeout(Some(FIXTURE_IO_TIMEOUT))
            .map_err(|error| format!("bound oversized fixture request read: {error}"))?;
        let request = read_bounded_http_request(&mut stream)
            .map_err(|error| format!("read oversized fixture request: {error}"))?;
        if !http_request_is_complete(&request) {
            return Err("oversized fixture received an incomplete bounded request".into());
        }

        let write_deadline = Instant::now() + Duration::from_secs(2);
        let response_headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_HTTP_RESPONSE_BYTES + TRAILING_BODY_MARKER.len() + 2
        );
        if !write_before_deadline(&mut stream, response_headers.as_bytes(), write_deadline)
            || !write_before_deadline(&mut stream, b"\"", write_deadline)
        {
            return Err("write oversized AI response framing before deadline".into());
        }
        let response_chunk = [b'x'; 4096];
        let mut remaining_string_bytes = MAX_HTTP_RESPONSE_BYTES;
        while remaining_string_bytes > response_chunk.len() {
            if !write_before_deadline(&mut stream, &response_chunk, write_deadline) {
                return Err("write oversized AI response body before deadline".into());
            }
            remaining_string_bytes -= response_chunk.len();
        }
        let mut final_fragment = Vec::with_capacity(
            remaining_string_bytes
                .saturating_add(TRAILING_BODY_MARKER.len())
                .saturating_add(1),
        );
        final_fragment.extend_from_slice(&response_chunk[..remaining_string_bytes]);
        final_fragment.extend_from_slice(TRAILING_BODY_MARKER);
        final_fragment.push(b'"');
        if !write_before_deadline(&mut stream, &final_fragment, write_deadline) {
            return Err("finish oversized AI response body before deadline".into());
        }
        Ok(())
    });
    let oversized_prompt = "c0-private-oversized-response-prompt";
    let oversized_result = ProxyEndpoint {
        port: oversized_port,
    }
    .post_ai(oversized_prompt);
    let oversized_server_result = oversized_server
        .join()
        .expect("join bounded oversized AI response fixture");
    oversized_server_result.expect("serve fragmented valid oversized AI response");
    let oversized_error = oversized_result
        .expect_err("the real AI POST method must reject a response body over its ceiling");
    assert_eq!(
        oversized_error,
        AiPostError::ResponseLimitExceeded {
            limit_bytes: MAX_HTTP_RESPONSE_BYTES,
            observed_bytes: MAX_HTTP_RESPONSE_BYTES + 1,
            retained_bytes: 0,
        }
    );
    let oversized_diagnostic = oversized_error.to_string();
    assert_eq!(
        oversized_diagnostic,
        "local AI response exceeded the 262144-byte ceiling after observing 262145 bytes"
    );
    assert!(!oversized_diagnostic.contains(oversized_prompt));
    assert!(!oversized_diagnostic.contains("c0-private-oversized-response-body-marker"));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind malformed readiness fixture");
    listener
        .set_nonblocking(true)
        .expect("make malformed readiness fixture bounded");
    let port = listener
        .local_addr()
        .expect("read malformed readiness fixture port")
        .port();
    let (release_tx, release_rx) = mpsc::channel();
    let readiness_accepted = Arc::new(AtomicBool::new(false));
    let server_accepted = Arc::clone(&readiness_accepted);
    let malformed_server = std::thread::spawn(move || {
        let accept_deadline = Instant::now() + Duration::from_secs(1);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break Some(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= accept_deadline {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break None,
            }
        };
        if let Some(stream) = stream.as_mut() {
            server_accepted.store(true, Ordering::Release);
            // Same inherited non-blocking flag as the two fixtures above.
            let _ = stream.set_nonblocking(false);
            let _ = stream.set_read_timeout(Some(FIXTURE_IO_TIMEOUT));
            let mut request = [0_u8; 256];
            let _ = stream.read(&mut request);
            let newline_free = vec![b'x'; MAX_READINESS_RESPONSE_BYTES];
            let _ = stream.write_all(&newline_free);
            let _ = stream.write_all(b"x");
            let _ = release_rx.recv_timeout(Duration::from_secs(1));
        }
    });
    let probe_started = Instant::now();
    let probe_deadline = probe_started + Duration::from_millis(200);
    let probe_outcome = readiness_probe_outcome(port, readiness_token, probe_deadline);
    let probe_elapsed = probe_started.elapsed();
    let _ = release_tx.send(());
    malformed_server
        .join()
        .expect("join malformed readiness fixture");
    assert_eq!(
        probe_outcome,
        ReadinessProbeOutcome::LimitExceeded {
            retained_bytes: MAX_READINESS_RESPONSE_BYTES,
            observed_bytes: MAX_READINESS_RESPONSE_BYTES + 1,
        },
        "a newline-free peer must exhaust the framing cap, not merely time out"
    );
    assert!(
        readiness_accepted.load(Ordering::Acquire),
        "the malformed fixture must own the connection the probe rejected"
    );
    assert!(
        probe_elapsed < Duration::from_millis(400),
        "newline-free readiness framing exceeded its absolute deadline: {probe_elapsed:?}"
    );
}

#[test]
fn denied_stock_intent_and_quality_get_no_connection_rpc_or_prompt_bytes() {
    // Production mutation this catches: constructing the stock hook with
    // `ClassifierClient::connect_lazy` instead of the governed connector.
    // Config parsing is the first current-tree RED. Once that surface lands,
    // the same test advances to the real dial and remains RED at the live
    // zero-side-effect assertion until both hook callsites are governed.
    let root = TestRoot::new("denied").expect("create isolated test root");
    let classifier =
        ClassifierFixture::start(PROMPT_MARKER).expect("start bounded classifier gRPC fixture");
    let upstream = OpenAiFixture::start(PROMPT_MARKER).expect("start local AI upstream");
    let proxy = ProxyChild::start(&root, &classifier, &upstream, HookEgressPolicy::DenyAll)
        .expect("a stock classifier-hook egress policy must compile and reach the live proxy");
    classifier.assert_quiet_now(
        "proxy startup must not probe or dial the lazily constructed stock classifier client",
    );

    assert_eq!(
        proxy
            .endpoint
            .post_ai(PROMPT_MARKER)
            .expect("drive one real AI POST through the child process"),
        200,
        "classifier refusal must preserve the hook's fail-open AI request posture"
    );
    assert_eq!(
        upstream.requests(),
        1,
        "the local AI provider must serve once"
    );
    assert!(
        upstream.prompt_seen(),
        "the real AI request body must reach the configured provider"
    );

    // Poll the real destination throughout two complete configured hook
    // deadlines. Any raw intent or quality connector fails immediately on
    // the first accepted socket/RPC/prompt observation; a correct denial
    // earns the quiet window without relying on a scheduler-sensitive sleep.
    classifier
        .require_quiet_window(DENIAL_QUIET_WINDOW)
        .expect("denied intent and quality hooks must stay silent for two full hook deadlines");
    proxy
        .shutdown()
        .expect("reap the child and validate its complete bounded output scan");
}

#[test]
fn authorized_stock_intent_and_quality_share_one_live_classifier_connection() {
    // Positive control for the denial. Both stock hooks must call the real
    // generated InferenceService contract after, and only after, the AI POST.
    // One accepted HTTP/2 connection proves they share one lazy client.
    let root = TestRoot::new("authorized").expect("create isolated test root");
    let classifier =
        ClassifierFixture::start(PROMPT_MARKER).expect("start bounded classifier gRPC fixture");
    let upstream = OpenAiFixture::start(PROMPT_MARKER).expect("start local AI upstream");
    let proxy = ProxyChild::start(
        &root,
        &classifier,
        &upstream,
        HookEgressPolicy::AllowLoopback,
    )
    .expect("an explicitly authorized stock classifier-hook destination must compile");
    classifier.assert_quiet_now(
        "proxy startup must not satisfy the test with a classifier readiness probe",
    );

    assert_eq!(
        proxy
            .endpoint
            .post_ai(PROMPT_MARKER)
            .expect("drive one real AI POST through the child process"),
        200,
        "successful stock intent and quality RPCs must preserve provider dispatch"
    );
    assert_eq!(
        upstream.requests(),
        1,
        "the local AI provider must serve once"
    );
    assert!(
        upstream.prompt_seen(),
        "the local AI provider must receive the real prompt-bearing POST"
    );

    let snapshot = classifier
        .wait_for_classify_total(2, DENIAL_QUIET_WINDOW)
        .expect("both live stock hook RPCs must reach the classifier fixture");
    assert_eq!(
        snapshot.accepts, 1,
        "intent and provider-quality must share one governed client connection: {snapshot:?}"
    );
    assert_eq!(
        snapshot.classify_total, 2,
        "one intent and one provider-quality Classify RPC are required: {snapshot:?}"
    );
    assert_eq!(
        snapshot.classify_calls.as_slice(),
        &[
            ClassifyCall {
                model: INTENT_MODEL.to_string(),
                top_k: 0,
                exact_prompt: true,
            },
            ClassifyCall {
                model: QUALITY_MODEL.to_string(),
                top_k: 0,
                exact_prompt: true,
            },
        ],
        "the stock child must send the exact intent and quality-provider requests"
    );
    assert_eq!(
        snapshot.quality_total, 0,
        "prompt-aware provider quality uses InferenceService/Classify, not the generated-response ClassifierService/Quality RPC"
    );
    assert_eq!(
        snapshot.other_rpc_total, 0,
        "the live stock hooks must issue no generated RPC except the two required Classify calls"
    );
    assert_eq!(
        snapshot.exact_prompt_rpcs, 2,
        "both stock hook RPCs must carry the request prompt without printing it"
    );
    proxy
        .shutdown()
        .expect("reap the child and validate its complete bounded output scan");
}
