//! Minimal OSS classifier sidecar (WOR-704 PR 2).
//!
//! Serves the shared `InferenceService` gRPC contract backed by the
//! `sbproxy-classifiers` tract ONNX engine. Running classification in this
//! separate process is what isolates the model runtime from the proxy: a
//! malicious or oversized model OOMs the sidecar (which the proxy's
//! supervisor restarts), never the proxy itself.
//!
//! Transports:
//!
//! * `--listen 127.0.0.1:9440` (default) for the externally-deployed
//!   case where the proxy reaches the sidecar over loopback or a
//!   container network.
//! * `--listen-uds /run/sbproxy/classifier.sock` (WOR-705) for the
//!   co-located case where the sidecar is supervised next to the
//!   proxy: skips the loopback TCP round trip and stays bounded to
//!   the proxy's filesystem namespace. `--listen-uds` is mutually
//!   exclusive with `--listen`.
//!
//! `Classify`, `Embed`, and `Compress` run local operator-supplied ONNX
//! artifacts. The proxy-side child supervisor owns restart behavior.

use std::collections::HashMap;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use prost::Message as _;
use sbproxy_classifier_proto::{
    compress_request, ClassifyRequest, ClassifyResponse, CompressRequest, CompressResponse,
    EmbedRequest, EmbedResponse, Embedding, InferenceService, InferenceServiceServer, Label,
    ModelInfoRequest, ModelInfoResponse, VersionRequest, VersionResponse,
};
use sbproxy_classifiers::{
    ClassificationOutput, EmbeddingOutput, LoadOptions, OnnxClassifier, OnnxEmbedder,
    OnnxTokenClassifier, TokenCompressionLimitError, TokenCompressionLimits,
    TokenCompressionOutput, TokenCompressionTarget, MAX_MODEL_BYTES_DEFAULT,
};
use serde::Deserialize;
use subtle::ConstantTimeEq as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::codegen::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

const MAX_TOKEN_MODEL_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const DEFAULT_TOKEN_MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_TOKEN_MAX_REQUEST_TOKENS: usize = 131_072;
const MAX_TOKEN_REQUEST_TOKENS: usize = 1_000_000;
const DEFAULT_TOKEN_MAX_WINDOWS: usize = 256;
const MAX_TOKEN_WINDOWS: usize = 4_096;
const DEFAULT_TOKEN_MAX_MODEL_WINDOW: usize = 512;
const MAX_TOKEN_MODEL_WINDOW: usize = 4_096;
const DEFAULT_TOKEN_MAX_CONCURRENT: usize = 2;
const MAX_TOKEN_CONCURRENT: usize = 64;
const DEFAULT_TOKEN_MAX_QUEUED: usize = 8;
const MAX_TOKEN_QUEUED: usize = 1_024;
const DEFAULT_INFERENCE_MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_INFERENCE_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_INFERENCE_MAX_ITEMS: usize = 64;
const MAX_INFERENCE_ITEMS: usize = 4_096;
const MAX_INFERENCE_CONCURRENT: usize = 64;
const MAX_INFERENCE_QUEUED: usize = 1_024;
const MAX_INFERENCE_TIMEOUT_MS: u64 = 600_000;
const MAX_MODEL_ID_BYTES: usize = 256;
const DEFAULT_GRPC_DECODING_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_AUTH_FILE_BYTES: u64 = 256 * 1024;
const MAX_LISTENER_TLS_PEM_BYTES: u64 = 256 * 1024;

/// Smallest running set the derived concurrency default will produce.
///
/// Also the value used when the host will not report its parallelism.
const INFERENCE_CONCURRENT_FLOOR: usize = 4;

/// Queue slots the derived queue default gives each running slot.
const INFERENCE_QUEUE_DEPTH_PER_SLOT: usize = 8;

/// Deadline for one `Classify`, `Embed`, or `Compress`, covering the wait
/// for a running slot as well as the inference behind it.
///
/// This is not the caller's deadline and cannot usefully be. Callers set
/// their own and theirs are far shorter: the `prompt_injection_v2` sidecar
/// detector gives up after 250 ms, and `ClassifierClient` wraps every RPC
/// in `tokio::time::timeout`, so a caller that gives up drops the stream
/// and this handler's future is cancelled wherever it is parked. That, not
/// this number, is what returns capacity in the normal case.
///
/// What is left for the sidecar to bound is the caller that sets no
/// deadline of its own, and the request parked behind a model that has
/// stopped returning. For that the value has to clear the slowest
/// inference the sidecar will legitimately accept, which is a `Compress`
/// over `--token-max-windows` windows: hundreds of forward passes, so
/// seconds rather than milliseconds. 30 s clears that with room and is
/// still a long way short of forever.
///
/// Cutting it to something in the detector's range would not make
/// `Classify` answer sooner, because `Classify` is already bounded by the
/// 250 ms the detector waits. It would only truncate `Compress`.
const DEFAULT_INFERENCE_TIMEOUT_MS: u64 = 30_000;

/// The `Classify` and `Embed` concurrency default, derived from the host.
///
/// A classification is CPU-bound: one forward pass occupies one thread
/// until it returns. How many of them a host can genuinely run at once is
/// its parallelism, so any fixed literal is wrong on every box except the
/// one it was picked on.
///
/// Which direction it is wrong in decides whether it is a bug. Before this
/// bound existed the only ceiling on `Classify` was the blocking pool and
/// the core count, so a 16-core host answered roughly 16 classifications
/// at a time. A literal default under that sheds load on upgrade at a rate
/// the same hardware used to serve, and the caller does not experience the
/// shed as a queued wait it can measure: the detector gives up at 250 ms
/// and treats a refusal exactly like a sidecar that is down, so the shed
/// becomes a `failure_posture` decision on live traffic. Tracking
/// `available_parallelism` is what keeps the ceiling at what the machine
/// can do instead of at what one machine could do once.
///
/// The clamps mark where tracking the host stops helping:
///
/// * `INFERENCE_CONCURRENT_FLOOR` keeps a one- or two-core host from
///   serializing harder than a flat default would have, so deriving the
///   value can only ever widen it.
/// * `MAX_INFERENCE_CONCURRENT` is the same ceiling the flag validates
///   against. Past it the running set has stopped being a bound, and on
///   compute-bound work more runners buy queueing latency, not throughput.
///
/// `--inference-max-concurrent` replaces the whole calculation.
fn derive_inference_max_concurrent(available_parallelism: Option<usize>) -> usize {
    available_parallelism
        .unwrap_or(INFERENCE_CONCURRENT_FLOOR)
        .clamp(INFERENCE_CONCURRENT_FLOOR, MAX_INFERENCE_CONCURRENT)
}

/// `derive_inference_max_concurrent` against the running host.
fn default_inference_max_concurrent() -> usize {
    derive_inference_max_concurrent(std::thread::available_parallelism().ok().map(|n| n.get()))
}

/// The `Classify` and `Embed` queue-depth default, derived from the
/// running set rather than fixed.
///
/// What decides whether a queue slot is worth having is how long the
/// request in it waits, not how many requests are waiting: a request `n`
/// deep behind a full running set starts after roughly `n / max_concurrent`
/// service times. A flat count is therefore a different wait on every box,
/// and it is the small box that draws the long one. Scaling depth with the
/// running slots holds the wait at about
/// `INFERENCE_QUEUE_DEPTH_PER_SLOT` service times on any host.
///
/// At floor concurrency this reproduces a 4-running, 32-queued pair, so no
/// host ends up with a shallower queue than a flat default would have
/// given it.
///
/// `--inference-max-queued` replaces it, and `0` disables waiting.
fn derive_inference_max_queued(max_concurrent: usize) -> usize {
    max_concurrent
        .saturating_mul(INFERENCE_QUEUE_DEPTH_PER_SLOT)
        .min(MAX_INFERENCE_QUEUED)
}

/// `derive_inference_max_queued` against the derived running set.
fn default_inference_max_queued() -> usize {
    derive_inference_max_queued(default_inference_max_concurrent())
}

// RPC names. Each is both the `rpc` log field and the subject of the
// refusal messages that RPC returns.
const RPC_CLASSIFY: &str = "classify";
const RPC_EMBED: &str = "embed";
const RPC_COMPRESS: &str = "compress";

/// Emit one refusal warning per this many refusals of the same reason.
///
/// A refusal storm is the exact shape of the attack these bounds exist to
/// stop, so a line per refusal would hand the caller a log amplifier. The
/// first refusal of a reason speaks immediately, because an operator needs
/// to see the onset, and every hundredth after that carries the running
/// total. The count itself is exact either way.
const REFUSAL_LOG_INTERVAL: u64 = 100;

fn grpc_decoding_message_limit(max_request_bytes: usize) -> usize {
    DEFAULT_GRPC_DECODING_MESSAGE_BYTES.max(max_request_bytes)
}

fn validate_model_id(model: &str) -> std::result::Result<(), &'static str> {
    if model.len() > MAX_MODEL_ID_BYTES {
        return Err("model id exceeds the 256-byte limit");
    }
    Ok(())
}

#[derive(Clone)]
struct InferenceAuth {
    tokens: Arc<Vec<String>>,
}

#[derive(Deserialize)]
struct InferenceAuthFile {
    tokens: Vec<String>,
}

impl std::fmt::Debug for InferenceAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InferenceAuth")
            .field("tokens", &self.tokens.len())
            .finish()
    }
}

impl InferenceAuth {
    fn from_file(path: &Path) -> Result<Self> {
        let bytes = read_bounded_file(path, "inference token file", MAX_AUTH_FILE_BYTES, true)?;
        Self::from_json(&bytes)
            .with_context(|| format!("parsing inference token file {}", path.display()))
    }

    fn from_json(bytes: &[u8]) -> Result<Self> {
        let auth: InferenceAuthFile = serde_json::from_slice(bytes).context("invalid JSON")?;
        if auth.tokens.is_empty() {
            anyhow::bail!("inference token file must contain at least one token");
        }
        if auth.tokens.len() > 1024 {
            anyhow::bail!("inference token file exceeds 1024 token limit");
        }
        let mut seen = std::collections::HashSet::new();
        for token in &auth.tokens {
            if token.is_empty() {
                anyhow::bail!("inference token must not be empty");
            }
            if token.len() > 256 {
                anyhow::bail!("inference token exceeds 256 byte limit");
            }
            if !seen.insert(token.as_str()) {
                anyhow::bail!("inference token file contains a duplicate token");
            }
        }
        Ok(Self {
            tokens: Arc::new(auth.tokens),
        })
    }

    fn authenticated(&self, presented: Option<&str>) -> bool {
        let Some(presented) = presented else {
            return false;
        };
        let mut matched = false;
        for token in self.tokens.iter() {
            let equal = token.len() == presented.len()
                && bool::from(token.as_bytes().ct_eq(presented.as_bytes()));
            if equal {
                matched = true;
            }
        }
        matched
    }
}

#[derive(Clone, Debug)]
struct RequestAuthentication {
    policy: Arc<InferenceAuth>,
}

impl RequestAuthentication {
    fn bearer(policy: Arc<InferenceAuth>) -> Self {
        Self { policy }
    }

    fn authorize(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
        let presented = metadata
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_bearer_authorization);
        if self.policy.authenticated(presented) {
            Ok(())
        } else {
            Err(Status::unauthenticated("gRPC request unauthenticated"))
        }
    }
}

fn parse_bearer_authorization(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

#[derive(Clone, Debug)]
struct SidecarAuthInterceptor {
    request_auth: Option<RequestAuthentication>,
}

impl Interceptor for SidecarAuthInterceptor {
    fn call(&mut self, request: Request<()>) -> std::result::Result<Request<()>, Status> {
        if let Some(request_auth) = &self.request_auth {
            request_auth.authorize(request.metadata())?;
        }
        Ok(request)
    }
}

fn read_bounded_file(
    path: &Path,
    label: &str,
    max_bytes: u64,
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
    if metadata.len() > max_bytes {
        anyhow::bail!("{label} {} exceeds {max_bytes} byte limit", path.display());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("{label} {} exceeds {max_bytes} byte limit", path.display());
    }
    Ok(bytes)
}

fn build_server_tls_config(
    cert_file: Option<&Path>,
    key_file: Option<&Path>,
    client_ca_file: Option<&Path>,
    client_auth_optional: bool,
) -> Result<Option<ServerTlsConfig>> {
    if cert_file.is_some() != key_file.is_some() {
        anyhow::bail!("--listen-tls-cert-file and --listen-tls-key-file must be provided together");
    }
    if client_ca_file.is_some() && cert_file.is_none() {
        anyhow::bail!(
            "--listen-tls-client-ca-file requires --listen-tls-cert-file and --listen-tls-key-file"
        );
    }
    if client_auth_optional && client_ca_file.is_none() {
        anyhow::bail!("--listen-tls-client-auth-optional requires --listen-tls-client-ca-file");
    }
    let Some(cert_file) = cert_file else {
        return Ok(None);
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_pem = read_bounded_file(
        cert_file,
        "gRPC listener TLS certificate file",
        MAX_LISTENER_TLS_PEM_BYTES,
        false,
    )?;
    let key_pem = read_bounded_file(
        key_file.expect("TLS key presence validated above"),
        "gRPC listener TLS key file",
        MAX_LISTENER_TLS_PEM_BYTES,
        true,
    )?;
    let mut tls_config = ServerTlsConfig::new().identity(Identity::from_pem(cert_pem, key_pem));
    if let Some(client_ca_file) = client_ca_file {
        let ca_pem = read_bounded_file(
            client_ca_file,
            "gRPC listener TLS client CA file",
            MAX_LISTENER_TLS_PEM_BYTES,
            false,
        )?;
        tls_config = tls_config.client_ca_root(Certificate::from_pem(ca_pem));
        if client_auth_optional {
            tls_config = tls_config.client_auth_optional(true);
        }
    }
    let _ = Server::builder()
        .tls_config(tls_config.clone())
        .context("validating gRPC listener TLS settings")?;
    Ok(Some(tls_config))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TokenCompressionRuntimeLimits {
    max_model_bytes: u64,
    max_request_bytes: usize,
    max_request_tokens: usize,
    max_windows: usize,
    max_model_window: usize,
    max_concurrent: usize,
    max_queued: usize,
}

impl Default for TokenCompressionRuntimeLimits {
    fn default() -> Self {
        Self {
            max_model_bytes: MAX_MODEL_BYTES_DEFAULT,
            max_request_bytes: DEFAULT_TOKEN_MAX_REQUEST_BYTES,
            max_request_tokens: DEFAULT_TOKEN_MAX_REQUEST_TOKENS,
            max_windows: DEFAULT_TOKEN_MAX_WINDOWS,
            max_model_window: DEFAULT_TOKEN_MAX_MODEL_WINDOW,
            max_concurrent: DEFAULT_TOKEN_MAX_CONCURRENT,
            max_queued: DEFAULT_TOKEN_MAX_QUEUED,
        }
    }
}

/// Operator-configured bounds on `Classify` and `Embed` work.
///
/// `TokenCompressionRuntimeLimits` bounds the heavy `Compress` path. This is
/// the same shape for the two fast-path RPCs, which had no bound of their
/// own before: an unbounded `spawn_blocking` is a thread-pool exhaustion
/// primitive, because the blocking pool has a fixed ceiling and every task
/// queued past it stalls every other blocking caller in the process.
///
/// Every field has a finite default, and the two that decide how much of
/// the machine the sidecar uses are derived from the machine rather than
/// written down as literals. A bound an operator has to discover and
/// configure is not a bound for the operator who never read the flag, and
/// a bound picked on somebody else's hardware is not a bound that fits
/// theirs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InferenceRuntimeLimits {
    max_request_bytes: usize,
    max_items: usize,
    max_concurrent: usize,
    max_queued: usize,
    timeout: Duration,
}

impl Default for InferenceRuntimeLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: DEFAULT_INFERENCE_MAX_REQUEST_BYTES,
            max_items: DEFAULT_INFERENCE_MAX_ITEMS,
            max_concurrent: default_inference_max_concurrent(),
            max_queued: default_inference_max_queued(),
            timeout: Duration::from_millis(DEFAULT_INFERENCE_TIMEOUT_MS),
        }
    }
}

/// Running and queued capacity for one class of inference work.
///
/// Each RPC owns its own instance, so a burst of one cannot consume the
/// slots another RPC needs.
struct InferenceAdmission {
    running: Arc<Semaphore>,
    admitted: Arc<Semaphore>,
}

impl InferenceAdmission {
    fn new(max_concurrent: usize, max_queued: usize) -> Self {
        Self {
            running: Arc::new(Semaphore::new(max_concurrent)),
            admitted: Arc::new(Semaphore::new(max_concurrent + max_queued)),
        }
    }

    async fn acquire(&self) -> std::result::Result<InferencePermits, AdmissionError> {
        let admitted = Arc::clone(&self.admitted)
            .try_acquire_owned()
            .map_err(|_| AdmissionError::QueueFull)?;
        let running = Arc::clone(&self.running)
            .acquire_owned()
            .await
            .map_err(|_| AdmissionError::Unavailable)?;
        Ok(InferencePermits {
            _admitted: admitted,
            _running: running,
        })
    }
}

/// Why an inference request was not admitted.
///
/// `acquire` knows the two ways admission can fail and nothing about what
/// the wire should say, so it hands back this instead of a `tonic::Status`.
/// `SidecarService::admit` is the single place that turns one into a status,
/// and it is also where the refusal is counted, so the message an operator
/// reads and the number they alert on cannot drift apart.
enum AdmissionError {
    /// Admission queue was already full.
    QueueFull,
    /// The running semaphore was closed.
    Unavailable,
}

struct InferencePermits {
    _admitted: OwnedSemaphorePermit,
    _running: OwnedSemaphorePermit,
}

/// Why the sidecar refused a request, as a dimension an operator alerts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusalReason {
    /// Encoded request exceeded the RPC's configured byte budget.
    RequestBytes,
    /// Batch carried more items than the configured budget.
    BatchItems,
    /// Running and queued capacity were both already full.
    QueueFull,
    /// Admission was closed, which happens on shutdown.
    AdmissionUnavailable,
    /// Inference did not finish inside the configured deadline.
    DeadlineExceeded,
    /// The blocking task ended without a result: a contained panic, or
    /// cancellation while the runtime was shutting down.
    TaskFailed,
}

impl RefusalReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::RequestBytes => "request_bytes",
            Self::BatchItems => "batch_items",
            Self::QueueFull => "queue_full",
            Self::AdmissionUnavailable => "admission_unavailable",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::TaskFailed => "task_failed",
        }
    }
}

/// Exact per-reason refusal counts for the life of the process.
///
/// Counting is deliberately separate from logging. A refusal that exists
/// only in a log line is lossy and rotates away, and under the load these
/// bounds exist to shed the log is the first thing to become unreadable.
/// The counter stays exact while `REFUSAL_LOG_INTERVAL` keeps the log
/// quiet.
///
/// This process has no Prometheus exporter of its own yet, so these
/// counters are the whole operator-facing signal today. The follow-up that
/// gives the sidecar a scrape surface publishes them unchanged as
/// `sbproxy_classifier_sidecar_refusals_total`, labeled by `rpc` and
/// `reason`.
#[derive(Default)]
struct RefusalCounters {
    request_bytes: AtomicU64,
    batch_items: AtomicU64,
    queue_full: AtomicU64,
    admission_unavailable: AtomicU64,
    deadline_exceeded: AtomicU64,
    task_failed: AtomicU64,
}

impl RefusalCounters {
    fn counter(&self, reason: RefusalReason) -> &AtomicU64 {
        match reason {
            RefusalReason::RequestBytes => &self.request_bytes,
            RefusalReason::BatchItems => &self.batch_items,
            RefusalReason::QueueFull => &self.queue_full,
            RefusalReason::AdmissionUnavailable => &self.admission_unavailable,
            RefusalReason::DeadlineExceeded => &self.deadline_exceeded,
            RefusalReason::TaskFailed => &self.task_failed,
        }
    }

    /// Count one refusal and return the running total for its reason.
    fn record(&self, reason: RefusalReason) -> u64 {
        self.counter(reason)
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }
}

/// The `InferenceService` implementation, backed by a registry of loaded
/// tract ONNX classifiers keyed by logical model id.
struct SidecarService {
    models: HashMap<String, Arc<dyn TextClassifier>>,
    /// Embedding models keyed by logical id, paired with the embedding
    /// dimension learned at load time (for `ModelInfo`).
    embedders: HashMap<String, (Arc<dyn TextEmbedder>, u32)>,
    /// Token-classification models used by the `Compress` RPC.
    token_models: HashMap<String, Arc<dyn TokenCompressor>>,
    /// Classifier used when a `Classify` request leaves `model` empty.
    default_model: Option<String>,
    /// Embedder used when an `Embed` request leaves `model` empty.
    default_embed_model: Option<String>,
    /// Token classifier used when `CompressRequest.model` is empty.
    default_token_model: Option<String>,
    /// Operator-configured bounds for token-compression artifacts and work.
    token_limits: TokenCompressionRuntimeLimits,
    /// Operator-configured bounds for `Classify` and `Embed` work.
    inference_limits: InferenceRuntimeLimits,
    /// Bounds running `Classify` work and the requests waiting behind it.
    classify_admission: InferenceAdmission,
    /// The same bounds for `Embed`, on its own semaphores so a burst of one
    /// fast-path RPC cannot starve the other.
    embed_admission: InferenceAdmission,
    /// Bounds running `Compress` work and the requests waiting behind it.
    compression_admission: InferenceAdmission,
    /// Per-reason refusal counts, the operator-facing signal for load
    /// shedding.
    refusals: RefusalCounters,
    /// Reported by the `Version` RPC.
    version: String,
}

/// The classification seam.
///
/// `OnnxClassifier` is the only production implementation. The trait exists
/// so a test can hold inference open on a real request path without a real
/// ONNX artifact, which is the only way to prove the admission bound is
/// wired to the RPC rather than merely present.
trait TextClassifier: Send + Sync {
    fn classify(&self, text: &str) -> Result<ClassificationOutput>;
}

impl TextClassifier for OnnxClassifier {
    fn classify(&self, text: &str) -> Result<ClassificationOutput> {
        OnnxClassifier::classify(self, text)
    }
}

/// The embedding seam, for the same reason. `OnnxEmbedder` is the only
/// production implementation.
trait TextEmbedder: Send + Sync {
    fn embed(&self, text: &str) -> Result<EmbeddingOutput>;
}

impl TextEmbedder for OnnxEmbedder {
    fn embed(&self, text: &str) -> Result<EmbeddingOutput> {
        OnnxEmbedder::embed(self, text)
    }
}

trait TokenCompressor: Send + Sync {
    fn compress(
        &self,
        text: &str,
        target: TokenCompressionTarget,
        limits: TokenCompressionLimits,
    ) -> Result<TokenCompressionOutput>;
}

impl TokenCompressor for OnnxTokenClassifier {
    fn compress(
        &self,
        text: &str,
        target: TokenCompressionTarget,
        limits: TokenCompressionLimits,
    ) -> Result<TokenCompressionOutput> {
        OnnxTokenClassifier::compress_with_limits(self, text, target, limits)
    }
}

impl SidecarService {
    /// Resolve a request's `model` field (or the default) to a loaded model.
    fn resolve(&self, model: &str) -> Option<(String, Arc<dyn TextClassifier>)> {
        let id = if model.is_empty() {
            self.default_model.clone()?
        } else {
            model.to_string()
        };
        self.models.get(&id).map(|m| (id, Arc::clone(m)))
    }

    /// Resolve a request's `model` field (or the default) to a loaded
    /// embedder.
    fn resolve_embedder(&self, model: &str) -> Option<(String, Arc<dyn TextEmbedder>)> {
        let id = if model.is_empty() {
            self.default_embed_model.clone()?
        } else {
            model.to_string()
        };
        self.embedders.get(&id).map(|(e, _)| (id, Arc::clone(e)))
    }

    fn resolve_token_model(&self, model: &str) -> Option<(String, Arc<dyn TokenCompressor>)> {
        let id = if model.is_empty() {
            self.default_token_model.clone()?
        } else {
            model.to_string()
        };
        self.token_models
            .get(&id)
            .map(|token_model| (id, Arc::clone(token_model)))
    }

    /// Count one refusal, speak about it on a sampled schedule, and hand
    /// back the status the RPC returns.
    ///
    /// Every refusal path goes through here so that no bound can be added
    /// later that sheds load without the operator being able to see it.
    fn refuse(&self, rpc: &'static str, reason: RefusalReason, status: Status) -> Status {
        let total = self.refusals.record(reason);
        if total == 1 || total.is_multiple_of(REFUSAL_LOG_INTERVAL) {
            tracing::warn!(
                rpc,
                reason = reason.as_str(),
                total,
                "classifier sidecar refused a request"
            );
        }
        status
    }

    /// Refuse an encoded request larger than the RPC's configured budget.
    ///
    /// This runs before the model is resolved and before any text is handed
    /// to a tokenizer, so an oversized body never becomes a tensor.
    /// `max_decoding_message_size` bounds what the transport will decode at
    /// all; this is the per-RPC logical budget underneath it.
    ///
    /// `tonic::Status` is 176 bytes, over `result_large_err`'s threshold, and
    /// this helper and the three below it all carry one. Returning a small
    /// error instead would move the message and the refusal count back out to
    /// every RPC that calls them, which is the duplication `refuse` exists to
    /// prevent, and boxing a third-party type only to unbox it one frame up
    /// buys nothing. Each takes the allow rather than the reshape.
    #[allow(clippy::result_large_err)]
    fn check_request_bytes(
        &self,
        rpc: &'static str,
        encoded_len: usize,
        limit: usize,
    ) -> Result<(), Status> {
        if encoded_len > limit {
            return Err(self.refuse(
                rpc,
                RefusalReason::RequestBytes,
                Status::resource_exhausted(format!(
                    "{rpc} request exceeds its configured byte limit: {encoded_len} > {limit}"
                )),
            ));
        }
        Ok(())
    }

    /// Refuse a batch carrying more items than the configured budget.
    ///
    /// The per-item loop inside the blocking closure is the unbounded work:
    /// one admitted request with a million texts is a million inferences on
    /// a single running slot.
    #[allow(clippy::result_large_err)]
    fn check_batch_items(&self, rpc: &'static str, items: usize) -> Result<(), Status> {
        let limit = self.inference_limits.max_items;
        if items > limit {
            return Err(self.refuse(
                rpc,
                RefusalReason::BatchItems,
                Status::resource_exhausted(format!(
                    "{rpc} batch exceeds its configured item limit: {items} > {limit}"
                )),
            ));
        }
        Ok(())
    }

    /// Take a running slot for `rpc` before `deadline`, or refuse.
    ///
    /// The wait for a slot is the part of the handling an overloaded
    /// sidecar spends the most time in, so it runs under the same deadline
    /// as the inference behind it. Bounding only the inference would leave
    /// the queue wait unbounded, which is the half that actually grows,
    /// and would make the deadline a bound on nothing the caller feels.
    #[allow(clippy::result_large_err)]
    async fn admit(
        &self,
        rpc: &'static str,
        admission: &InferenceAdmission,
        deadline: tokio::time::Instant,
    ) -> Result<InferencePermits, Status> {
        match tokio::time::timeout_at(deadline, admission.acquire()).await {
            Ok(Ok(permits)) => Ok(permits),
            Ok(Err(AdmissionError::QueueFull)) => Err(self.refuse(
                rpc,
                RefusalReason::QueueFull,
                Status::resource_exhausted(format!("{rpc} queue is full")),
            )),
            Ok(Err(AdmissionError::Unavailable)) => Err(self.refuse(
                rpc,
                RefusalReason::AdmissionUnavailable,
                Status::unavailable(format!("{rpc} admission is unavailable")),
            )),
            Err(_) => Err(self.refuse(
                rpc,
                RefusalReason::DeadlineExceeded,
                Status::deadline_exceeded(format!(
                    "{rpc} waited for a running slot past the configured deadline"
                )),
            )),
        }
    }

    /// Await a blocking inference task under the configured deadline, and
    /// keep the ways it can end without a result distinct from a model that
    /// ran and failed.
    ///
    /// A panic inside `spawn_blocking` is contained by the runtime: it
    /// arrives here as a `JoinError` instead of ending the process, and the
    /// default panic hook has already written the payload and its location
    /// to stderr for the operator. That payload is derived from
    /// caller-supplied text, which is why this returns a fixed message
    /// rather than formatting the `JoinError` onto the wire.
    ///
    /// The deadline frees the caller, not the thread. `spawn_blocking` work
    /// cannot be cancelled, so the permit the closure owns stays held until
    /// the inference really finishes: a wedged model keeps occupying one of
    /// its RPC's running slots and the sidecar sheds load, rather than
    /// handing out a slot whose thread is still busy.
    ///
    /// `deadline` is the same absolute instant `Self::admit` waited
    /// against, not a fresh window, so the two halves of the handling share
    /// one budget instead of each getting the whole of it.
    #[allow(clippy::result_large_err)]
    async fn join_bounded<T>(
        &self,
        rpc: &'static str,
        task: tokio::task::JoinHandle<T>,
        deadline: tokio::time::Instant,
    ) -> Result<T, Status> {
        match tokio::time::timeout_at(deadline, task).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) if error.is_cancelled() => Err(self.refuse(
                rpc,
                RefusalReason::TaskFailed,
                Status::unavailable(format!("{rpc} inference was cancelled")),
            )),
            Ok(Err(_)) => Err(self.refuse(
                rpc,
                RefusalReason::TaskFailed,
                Status::internal(format!("{rpc} inference ended without a result")),
            )),
            Err(_) => Err(self.refuse(
                rpc,
                RefusalReason::DeadlineExceeded,
                Status::deadline_exceeded(format!(
                    "{rpc} inference exceeded the configured deadline"
                )),
            )),
        }
    }
}

#[tonic::async_trait]
impl InferenceService for SidecarService {
    async fn classify(
        &self,
        req: Request<ClassifyRequest>,
    ) -> Result<Response<ClassifyResponse>, Status> {
        let req = req.into_inner();
        // One budget for the whole handling, fixed here rather than at each
        // await, so queueing time and inference time cannot each spend it.
        let deadline = tokio::time::Instant::now() + self.inference_limits.timeout;
        validate_model_id(&req.model).map_err(Status::invalid_argument)?;
        self.check_request_bytes(
            RPC_CLASSIFY,
            req.encoded_len(),
            self.inference_limits.max_request_bytes,
        )?;
        let (_id, classifier) = self
            .resolve(&req.model)
            .ok_or_else(|| Status::not_found("unknown classifier model"))?;
        let text = req.text;
        let started = std::time::Instant::now();
        // tract inference is synchronous and CPU-bound: run it on the blocking
        // pool so it never stalls a gRPC async worker. The permit moves into
        // the closure rather than staying with this future, so a cancelled or
        // timed-out RPC never hands out a slot whose thread is still busy.
        let permits = self
            .admit(RPC_CLASSIFY, &self.classify_admission, deadline)
            .await?;
        let task = tokio::task::spawn_blocking(move || {
            let output = classifier.classify(&text);
            drop(permits);
            output
        });
        let output = self
            .join_bounded(RPC_CLASSIFY, task, deadline)
            .await?
            .map_err(|e| Status::internal(format!("classify failed: {e}")))?;
        let latency_us = started.elapsed().as_micros() as u64;
        Ok(Response::new(ClassifyResponse {
            labels: vec![Label {
                name: output.label,
                score: output.score as f64,
            }],
            latency_us,
        }))
    }

    async fn embed(&self, req: Request<EmbedRequest>) -> Result<Response<EmbedResponse>, Status> {
        let req = req.into_inner();
        let deadline = tokio::time::Instant::now() + self.inference_limits.timeout;
        validate_model_id(&req.model).map_err(Status::invalid_argument)?;
        self.check_request_bytes(
            RPC_EMBED,
            req.encoded_len(),
            self.inference_limits.max_request_bytes,
        )?;
        self.check_batch_items(RPC_EMBED, req.texts.len())?;
        let (_id, embedder) = self.resolve_embedder(&req.model).ok_or_else(|| {
            Status::failed_precondition(
                "no matching embedding model is loaded; start the sidecar with --embed-model",
            )
        })?;
        let texts = req.texts;
        let started = std::time::Instant::now();
        // An empty batch has no work to admit. Answering it here stops a
        // caller from spending a running slot and a blocking thread on
        // nothing at all.
        if texts.is_empty() {
            return Ok(Response::new(EmbedResponse {
                embeddings: Vec::new(),
                latency_us: started.elapsed().as_micros() as u64,
            }));
        }
        // tract inference is synchronous and CPU-bound: run it on the blocking
        // pool so it never stalls a gRPC async worker. The permit moves into
        // the closure rather than staying with this future, so a cancelled or
        // timed-out RPC never hands out a slot whose thread is still busy.
        let permits = self
            .admit(RPC_EMBED, &self.embed_admission, deadline)
            .await?;
        let task = tokio::task::spawn_blocking(move || {
            let vectors = texts
                .iter()
                .map(|t| embedder.embed(t))
                .collect::<anyhow::Result<Vec<_>>>();
            drop(permits);
            vectors
        });
        let vectors = self
            .join_bounded(RPC_EMBED, task, deadline)
            .await?
            .map_err(|e| Status::internal(format!("embed failed: {e}")))?;
        Ok(Response::new(EmbedResponse {
            embeddings: vectors
                .into_iter()
                .map(|v| Embedding { values: v.values })
                .collect(),
            latency_us: started.elapsed().as_micros() as u64,
        }))
    }

    async fn compress(
        &self,
        req: Request<CompressRequest>,
    ) -> Result<Response<CompressResponse>, Status> {
        let req = req.into_inner();
        let deadline = tokio::time::Instant::now() + self.inference_limits.timeout;
        validate_model_id(&req.model).map_err(Status::invalid_argument)?;
        self.check_request_bytes(
            RPC_COMPRESS,
            req.encoded_len(),
            self.token_limits.max_request_bytes,
        )?;
        if req.text.is_empty() {
            return Err(Status::invalid_argument("compression text is empty"));
        }
        let target = match req.target {
            Some(compress_request::Target::RetainRatio(ratio))
                if ratio.is_finite() && ratio > 0.0 && ratio <= 1.0 =>
            {
                TokenCompressionTarget::RetainRatio(ratio)
            }
            Some(compress_request::Target::TargetTokens(tokens)) if tokens > 0 => {
                TokenCompressionTarget::TargetTokens(tokens as usize)
            }
            Some(compress_request::Target::RetainRatio(_)) => {
                return Err(Status::invalid_argument(
                    "retain_ratio must be finite and in (0, 1]",
                ))
            }
            Some(compress_request::Target::TargetTokens(_)) => {
                return Err(Status::invalid_argument(
                    "target_tokens must be greater than zero",
                ))
            }
            None => return Err(Status::invalid_argument("compression target is required")),
        };
        let (_id, token_model) = self
            .resolve_token_model(&req.model)
            .ok_or_else(|| Status::not_found("unknown token model"))?;
        let source = req.text;
        let work_limits = TokenCompressionLimits {
            max_input_tokens: self.token_limits.max_request_tokens,
            max_windows: self.token_limits.max_windows,
        };
        let started = std::time::Instant::now();
        let permits = self
            .admit(RPC_COMPRESS, &self.compression_admission, deadline)
            .await?;
        let task = tokio::task::spawn_blocking(move || {
            let output = token_model.compress(&source, target, work_limits);
            drop(permits);
            (source, output)
        });
        let (source, output) = self.join_bounded(RPC_COMPRESS, task, deadline).await?;
        let output = output.map_err(|error| {
            if error.downcast_ref::<TokenCompressionLimitError>().is_some() {
                Status::resource_exhausted(format!("compress failed: {error}"))
            } else {
                Status::internal(format!("compress failed: {error}"))
            }
        })?;
        validate_compression_output(&source, &output).map_err(Status::internal)?;
        let original_tokens = u32::try_from(output.original_tokens)
            .map_err(|_| Status::internal("compression original token count exceeds u32"))?;
        let compressed_tokens = u32::try_from(output.compressed_tokens)
            .map_err(|_| Status::internal("compression result token count exceeds u32"))?;
        Ok(Response::new(CompressResponse {
            text: output.text,
            original_tokens,
            compressed_tokens,
            latency_us: started.elapsed().as_micros() as u64,
        }))
    }

    async fn model_info(
        &self,
        req: Request<ModelInfoRequest>,
    ) -> Result<Response<ModelInfoResponse>, Status> {
        let req = req.into_inner();
        validate_model_id(&req.model).map_err(Status::invalid_argument)?;
        // Classifiers first, then embedders, then token classifiers.
        let resp = if let Some((id, _)) = self.resolve(&req.model) {
            ModelInfoResponse {
                model: id,
                loaded: true,
                labels: Vec::new(),
                embedding_dim: 0,
            }
        } else {
            let embed_id = if req.model.is_empty() {
                self.default_embed_model.clone()
            } else {
                Some(req.model.clone())
            };
            match embed_id.and_then(|id| self.embedders.get(&id).map(|(_, dim)| (id, *dim))) {
                Some((id, dim)) => ModelInfoResponse {
                    model: id,
                    loaded: true,
                    labels: Vec::new(),
                    embedding_dim: dim,
                },
                None => {
                    let token_id = if req.model.is_empty() {
                        self.default_token_model.clone()
                    } else {
                        Some(req.model.clone())
                    };
                    match token_id.filter(|id| self.token_models.contains_key(id)) {
                        Some(id) => ModelInfoResponse {
                            model: id,
                            loaded: true,
                            labels: Vec::new(),
                            embedding_dim: 0,
                        },
                        None => ModelInfoResponse {
                            model: req.model,
                            loaded: false,
                            labels: Vec::new(),
                            embedding_dim: 0,
                        },
                    }
                }
            }
        };
        Ok(Response::new(resp))
    }

    async fn version(
        &self,
        _req: Request<VersionRequest>,
    ) -> Result<Response<VersionResponse>, Status> {
        let mut models: Vec<String> = self.models.keys().cloned().collect();
        models.extend(self.token_models.keys().cloned());
        models.sort();
        models.dedup();
        Ok(Response::new(VersionResponse {
            version: self.version.clone(),
            models,
        }))
    }
}

/// CLI for the sidecar.
#[derive(Parser)]
#[command(about = "Minimal OSS classifier sidecar serving the InferenceService gRPC contract.")]
struct Cli {
    /// TCP address to listen on. Mutually exclusive with
    /// `--listen-uds`; the default is used only when neither flag is
    /// set.
    #[arg(long, default_value = "127.0.0.1:9440", conflicts_with = "listen_uds")]
    listen: String,
    /// WOR-705: Unix domain socket path to listen on instead of TCP.
    /// The natural transport for a supervised co-located sidecar:
    /// removes the loopback TCP round trip and stays bounded to the
    /// proxy's filesystem namespace. The path's parent directory MUST
    /// exist; the sidecar creates the socket file on bind and removes
    /// any stale file at the same path before binding (so a crashed
    /// previous run does not block restart).
    #[arg(long = "listen-uds", value_name = "PATH", conflicts_with = "listen")]
    listen_uds: Option<std::path::PathBuf>,
    /// Model to load, as `id=<model.onnx>:<tokenizer.json>`. Repeatable.
    #[arg(long = "model", value_name = "ID=MODEL:TOKENIZER")]
    models: Vec<String>,
    /// Model id used when a request leaves `model` empty. Defaults to the
    /// single loaded model when exactly one is configured.
    #[arg(long)]
    default_model: Option<String>,
    /// Embedding model to load, as `id=<model.onnx>:<tokenizer.json>`.
    /// Repeatable. Enables the `Embed` RPC (used by the AI gateway semantic
    /// cache); without one, `Embed` returns FAILED_PRECONDITION.
    #[arg(long = "embed-model", value_name = "ID=MODEL:TOKENIZER")]
    embed_models: Vec<String>,
    /// Embedding model id used when an `Embed` request leaves `model` empty.
    /// Defaults to the single loaded embedder when exactly one is configured.
    #[arg(long)]
    default_embed_model: Option<String>,
    /// Token-classification model to load, as
    /// `id=<model.onnx>:<tokenizer.json>:<max-model-tokens>`. Repeatable.
    #[arg(long = "token-model", value_name = "ID=MODEL:TOKENIZER:MAX_TOKENS")]
    token_models: Vec<String>,
    /// Token model id used when a `Compress` request leaves `model` empty.
    /// Defaults to the single loaded token model.
    #[arg(long)]
    default_token_model: Option<String>,
    /// Maximum bytes accepted for each token-model ONNX artifact. The finite
    /// default matches other classifiers; loading the first-party mBERT
    /// LLMLingua-2 export requires an explicit larger value.
    #[arg(long, default_value_t = MAX_MODEL_BYTES_DEFAULT)]
    token_model_max_bytes: u64,
    /// Maximum encoded protobuf bytes accepted by one Compress request.
    #[arg(long, default_value_t = DEFAULT_TOKEN_MAX_REQUEST_BYTES)]
    token_max_request_bytes: usize,
    /// Maximum tokenizer tokens accepted by one Compress request.
    #[arg(long, default_value_t = DEFAULT_TOKEN_MAX_REQUEST_TOKENS)]
    token_max_request_tokens: usize,
    /// Maximum token-model inference windows evaluated by one Compress request.
    #[arg(long, default_value_t = DEFAULT_TOKEN_MAX_WINDOWS)]
    token_max_windows: usize,
    /// Maximum model-window value accepted in any --token-model specification.
    #[arg(long, default_value_t = DEFAULT_TOKEN_MAX_MODEL_WINDOW)]
    token_max_model_window: usize,
    /// Maximum token-compression inferences running simultaneously.
    #[arg(long, default_value_t = DEFAULT_TOKEN_MAX_CONCURRENT)]
    token_max_concurrent: usize,
    /// Maximum token-compression requests allowed to wait behind running work.
    #[arg(long, default_value_t = DEFAULT_TOKEN_MAX_QUEUED)]
    token_max_queued: usize,
    /// Maximum encoded protobuf bytes accepted by one Classify or Embed
    /// request.
    #[arg(long, default_value_t = DEFAULT_INFERENCE_MAX_REQUEST_BYTES)]
    inference_max_request_bytes: usize,
    /// Maximum texts accepted in one Embed batch.
    #[arg(long, default_value_t = DEFAULT_INFERENCE_MAX_ITEMS)]
    inference_max_items: usize,
    /// Maximum Classify inferences running simultaneously, and separately
    /// the same ceiling for Embed. Defaults to this host's available
    /// parallelism, clamped to between 4 and 64.
    #[arg(long, default_value_t = default_inference_max_concurrent())]
    inference_max_concurrent: usize,
    /// Maximum Classify requests allowed to wait behind running work, and
    /// separately the same ceiling for Embed. Defaults to eight per
    /// running slot, so the wait stays comparable across host sizes.
    #[arg(long, default_value_t = default_inference_max_queued())]
    inference_max_queued: usize,
    /// Deadline for one inference, in milliseconds, counted from the
    /// moment the request arrives so it covers the wait for a running slot
    /// as well. Applies to Classify, Embed, and Compress. A request past it
    /// gets DEADLINE_EXCEEDED; a blocking thread cannot be cancelled, so an
    /// inference that has already started keeps its running slot until the
    /// model returns.
    #[arg(long, default_value_t = DEFAULT_INFERENCE_TIMEOUT_MS)]
    inference_timeout_ms: u64,
    /// Mode-0600 JSON file containing bearer tokens accepted by the gRPC
    /// inference listener. When present, requests must send
    /// `authorization: Bearer <token>`.
    #[arg(long = "inference-token-file")]
    inference_token_file: Option<PathBuf>,
    /// PEM certificate chain for TLS on the TCP gRPC listener.
    #[arg(long = "listen-tls-cert-file")]
    listen_tls_cert_file: Option<PathBuf>,
    /// PEM private key for TLS on the TCP gRPC listener. Must be a mode-0600
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

impl Cli {
    fn validate_runtime_configuration(&self) -> Result<()> {
        // Parse every specification before any artifact is opened so malformed
        // or oversized operator-controlled IDs fail at startup without doing
        // partial model loading first.
        for spec in &self.token_models {
            parse_token_model_spec(spec)?;
        }
        if let Some(default_model) = self.default_token_model.as_deref() {
            if default_model.is_empty() {
                anyhow::bail!("--default-token-model must not be empty");
            }
            validate_model_id(default_model).map_err(anyhow::Error::msg)?;
        }
        Ok(())
    }

    fn request_auth(&self) -> Result<Option<RequestAuthentication>> {
        Ok(self
            .inference_token_file
            .as_deref()
            .map(InferenceAuth::from_file)
            .transpose()?
            .map(Arc::new)
            .map(RequestAuthentication::bearer))
    }

    fn listener_tls_config(&self) -> Result<Option<ServerTlsConfig>> {
        if self.listen_uds.is_some()
            && (self.listen_tls_cert_file.is_some()
                || self.listen_tls_key_file.is_some()
                || self.listen_tls_client_ca_file.is_some()
                || self.listen_tls_client_auth_optional)
        {
            anyhow::bail!("TLS flags are not supported with --listen-uds");
        }
        build_server_tls_config(
            self.listen_tls_cert_file.as_deref(),
            self.listen_tls_key_file.as_deref(),
            self.listen_tls_client_ca_file.as_deref(),
            self.listen_tls_client_auth_optional,
        )
    }

    fn token_compression_limits(&self) -> Result<TokenCompressionRuntimeLimits> {
        if self.token_model_max_bytes == 0 || self.token_model_max_bytes > MAX_TOKEN_MODEL_BYTES {
            anyhow::bail!("--token-model-max-bytes must be between 1 and {MAX_TOKEN_MODEL_BYTES}");
        }
        if self.token_max_request_bytes == 0
            || self.token_max_request_bytes > MAX_TOKEN_REQUEST_BYTES
        {
            anyhow::bail!(
                "--token-max-request-bytes must be between 1 and {MAX_TOKEN_REQUEST_BYTES}"
            );
        }
        if self.token_max_request_tokens == 0
            || self.token_max_request_tokens > MAX_TOKEN_REQUEST_TOKENS
        {
            anyhow::bail!(
                "--token-max-request-tokens must be between 1 and {MAX_TOKEN_REQUEST_TOKENS}"
            );
        }
        if self.token_max_windows == 0 || self.token_max_windows > MAX_TOKEN_WINDOWS {
            anyhow::bail!("--token-max-windows must be between 1 and {MAX_TOKEN_WINDOWS}");
        }
        if !(3..=MAX_TOKEN_MODEL_WINDOW).contains(&self.token_max_model_window) {
            anyhow::bail!(
                "--token-max-model-window must be between 3 and {MAX_TOKEN_MODEL_WINDOW}"
            );
        }
        if self.token_max_concurrent == 0 || self.token_max_concurrent > MAX_TOKEN_CONCURRENT {
            anyhow::bail!("--token-max-concurrent must be between 1 and {MAX_TOKEN_CONCURRENT}");
        }
        if self.token_max_queued > MAX_TOKEN_QUEUED {
            anyhow::bail!("--token-max-queued must not exceed {MAX_TOKEN_QUEUED}");
        }
        Ok(TokenCompressionRuntimeLimits {
            max_model_bytes: self.token_model_max_bytes,
            max_request_bytes: self.token_max_request_bytes,
            max_request_tokens: self.token_max_request_tokens,
            max_windows: self.token_max_windows,
            max_model_window: self.token_max_model_window,
            max_concurrent: self.token_max_concurrent,
            max_queued: self.token_max_queued,
        })
    }

    fn inference_limits(&self) -> Result<InferenceRuntimeLimits> {
        if self.inference_max_request_bytes == 0
            || self.inference_max_request_bytes > MAX_INFERENCE_REQUEST_BYTES
        {
            anyhow::bail!(
                "--inference-max-request-bytes must be between 1 and {MAX_INFERENCE_REQUEST_BYTES}"
            );
        }
        if self.inference_max_items == 0 || self.inference_max_items > MAX_INFERENCE_ITEMS {
            anyhow::bail!("--inference-max-items must be between 1 and {MAX_INFERENCE_ITEMS}");
        }
        if self.inference_max_concurrent == 0
            || self.inference_max_concurrent > MAX_INFERENCE_CONCURRENT
        {
            anyhow::bail!(
                "--inference-max-concurrent must be between 1 and {MAX_INFERENCE_CONCURRENT}"
            );
        }
        if self.inference_max_queued > MAX_INFERENCE_QUEUED {
            anyhow::bail!("--inference-max-queued must not exceed {MAX_INFERENCE_QUEUED}");
        }
        if self.inference_timeout_ms == 0 || self.inference_timeout_ms > MAX_INFERENCE_TIMEOUT_MS {
            anyhow::bail!(
                "--inference-timeout-ms must be between 1 and {MAX_INFERENCE_TIMEOUT_MS}"
            );
        }
        Ok(InferenceRuntimeLimits {
            max_request_bytes: self.inference_max_request_bytes,
            max_items: self.inference_max_items,
            max_concurrent: self.inference_max_concurrent,
            max_queued: self.inference_max_queued,
            timeout: Duration::from_millis(self.inference_timeout_ms),
        })
    }
}

/// Parse one `id=<model>:<tokenizer>` spec and load the classifier.
fn load_model_spec(spec: &str) -> Result<(String, Arc<dyn TextClassifier>)> {
    let (id, paths) = spec
        .split_once('=')
        .with_context(|| format!("--model must be ID=MODEL:TOKENIZER, got {spec:?}"))?;
    let (model_path, tokenizer_path) = paths
        .split_once(':')
        .with_context(|| format!("--model paths must be MODEL:TOKENIZER, got {paths:?}"))?;
    let classifier = OnnxClassifier::load(Path::new(model_path), Path::new(tokenizer_path))
        .with_context(|| format!("loading model {id:?}"))?;
    let classifier: Arc<dyn TextClassifier> = Arc::new(classifier);
    Ok((id.to_string(), classifier))
}

/// Parse one `id=<model>:<tokenizer>` spec and load the embedder, learning
/// its output dimension via a one-time warmup embed so `ModelInfo` can
/// report it.
fn load_embed_spec(spec: &str) -> Result<(String, Arc<dyn TextEmbedder>, u32)> {
    let (id, paths) = spec
        .split_once('=')
        .with_context(|| format!("--embed-model must be ID=MODEL:TOKENIZER, got {spec:?}"))?;
    let (model_path, tokenizer_path) = paths
        .split_once(':')
        .with_context(|| format!("--embed-model paths must be MODEL:TOKENIZER, got {paths:?}"))?;
    let embedder = OnnxEmbedder::load(Path::new(model_path), Path::new(tokenizer_path))
        .with_context(|| format!("loading embed model {id:?}"))?;
    let dim = embedder
        .embed("dimension probe")
        .map(|o| o.values.len() as u32)
        .unwrap_or(0);
    let embedder: Arc<dyn TextEmbedder> = Arc::new(embedder);
    Ok((id.to_string(), embedder, dim))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenModelSpec {
    id: String,
    model_path: PathBuf,
    tokenizer_path: PathBuf,
    max_model_tokens: usize,
}

fn parse_token_model_spec(spec: &str) -> Result<TokenModelSpec> {
    let (id, paths_and_window) = spec
        .split_once('=')
        .with_context(|| format!("--token-model must contain ID=..., got {spec:?}"))?;
    let (paths, max_model_tokens) = paths_and_window.rsplit_once(':').with_context(|| {
        format!("--token-model must end in :MAX_TOKENS, got {paths_and_window:?}")
    })?;
    let (model_path, tokenizer_path) = paths
        .split_once(':')
        .with_context(|| format!("--token-model paths must be MODEL:TOKENIZER, got {paths:?}"))?;
    if id.is_empty() || model_path.is_empty() || tokenizer_path.is_empty() {
        anyhow::bail!("--token-model id and paths must not be empty");
    }
    validate_model_id(id).map_err(anyhow::Error::msg)?;
    let max_model_tokens = max_model_tokens
        .parse::<usize>()
        .with_context(|| format!("invalid --token-model MAX_TOKENS {max_model_tokens:?}"))?;
    if max_model_tokens < 3 {
        anyhow::bail!("--token-model MAX_TOKENS must be at least 3");
    }
    Ok(TokenModelSpec {
        id: id.to_string(),
        model_path: PathBuf::from(model_path),
        tokenizer_path: PathBuf::from(tokenizer_path),
        max_model_tokens,
    })
}

fn load_token_model_spec(
    spec: &str,
    max_model_bytes: u64,
    max_model_window: usize,
) -> Result<(String, Arc<dyn TokenCompressor>)> {
    let spec = parse_token_model_spec(spec)?;
    if spec.max_model_tokens > max_model_window {
        anyhow::bail!(
            "token model {:?} window {} exceeds the configured maximum {}",
            spec.id,
            spec.max_model_tokens,
            max_model_window
        );
    }
    let options = LoadOptions::default().with_max_model_bytes(max_model_bytes);
    let token_model = OnnxTokenClassifier::load_with_options(
        &spec.model_path,
        &spec.tokenizer_path,
        spec.max_model_tokens,
        &options,
    )
    .with_context(|| format!("loading token model {:?}", spec.id))?;
    Ok((spec.id, Arc::new(token_model)))
}

fn validate_compression_output(
    source: &str,
    output: &TokenCompressionOutput,
) -> std::result::Result<(), &'static str> {
    if output.text.is_empty()
        || output.original_tokens == 0
        || output.compressed_tokens == 0
        || output.compressed_tokens > output.original_tokens
    {
        return Err("token model returned an invalid compression result");
    }
    let mut source_characters = source.chars();
    if !output
        .text
        .chars()
        .all(|wanted| source_characters.by_ref().any(|found| found == wanted))
    {
        return Err("token model returned non-extractive compression text");
    }
    Ok(())
}

fn inference_service(
    service: SidecarService,
    max_decoding_message_size: usize,
    request_auth: Option<RequestAuthentication>,
) -> InterceptedService<InferenceServiceServer<SidecarService>, SidecarAuthInterceptor> {
    InterceptedService::new(
        InferenceServiceServer::new(service).max_decoding_message_size(max_decoding_message_size),
        SidecarAuthInterceptor { request_auth },
    )
}

fn tonic_server_builder(tls_config: Option<ServerTlsConfig>) -> Result<Server> {
    match tls_config {
        Some(tls_config) => Server::builder()
            .tls_config(tls_config)
            .context("configuring gRPC listener TLS"),
        None => Ok(Server::builder()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();
    cli.validate_runtime_configuration()?;
    let request_auth = cli.request_auth()?;
    let tls_config = cli.listener_tls_config()?;
    let token_compression_limits = cli.token_compression_limits()?;
    let inference_limits = cli.inference_limits()?;
    // Tonic exposes one decoding cap for the entire service. Preserve its
    // historical 4 MiB behavior at the default per-RPC budgets; an explicit
    // larger budget on either side raises (never lowers) that shared
    // transport ceiling. Each RPC independently enforces its own exact
    // encoded-message budget in the handler.
    let max_decoding_message_size = grpc_decoding_message_limit(
        token_compression_limits
            .max_request_bytes
            .max(inference_limits.max_request_bytes),
    );

    let mut models = HashMap::new();
    for spec in &cli.models {
        let (id, classifier) = load_model_spec(spec)?;
        models.insert(id, classifier);
    }

    let default_model = cli.default_model.or_else(|| {
        if models.len() == 1 {
            models.keys().next().cloned()
        } else {
            None
        }
    });

    let mut embedders = HashMap::new();
    for spec in &cli.embed_models {
        let (id, embedder, dim) = load_embed_spec(spec)?;
        embedders.insert(id, (embedder, dim));
    }

    let default_embed_model = cli.default_embed_model.or_else(|| {
        if embedders.len() == 1 {
            embedders.keys().next().cloned()
        } else {
            None
        }
    });

    let mut token_models = HashMap::new();
    for spec in &cli.token_models {
        let (id, token_model) = load_token_model_spec(
            spec,
            token_compression_limits.max_model_bytes,
            token_compression_limits.max_model_window,
        )?;
        token_models.insert(id, token_model);
    }

    let default_token_model = cli.default_token_model.or_else(|| {
        if token_models.len() == 1 {
            token_models.keys().next().cloned()
        } else {
            None
        }
    });

    let service = SidecarService {
        version: format!("sbproxy-classifier-sidecar {}", env!("CARGO_PKG_VERSION")),
        default_model,
        default_embed_model,
        default_token_model,
        token_limits: token_compression_limits,
        inference_limits,
        classify_admission: InferenceAdmission::new(
            inference_limits.max_concurrent,
            inference_limits.max_queued,
        ),
        embed_admission: InferenceAdmission::new(
            inference_limits.max_concurrent,
            inference_limits.max_queued,
        ),
        compression_admission: InferenceAdmission::new(
            token_compression_limits.max_concurrent,
            token_compression_limits.max_queued,
        ),
        refusals: RefusalCounters::default(),
        models,
        embedders,
        token_models,
    };

    if let Some(uds_path) = cli.listen_uds.as_ref() {
        // WOR-705 UDS branch. Remove a stale socket file from a prior
        // crashed run so restart does not hit EADDRINUSE; the parent
        // directory is the operator's responsibility (a tmpfiles.d
        // entry or a Helm initContainer mkdir is typical).
        let _ = std::fs::remove_file(uds_path);
        let listener = tokio::net::UnixListener::bind(uds_path)
            .with_context(|| format!("bind UDS {uds_path:?}"))?;
        tracing::info!(
            uds_path = %uds_path.display(),
            models = service.models.len(),
            token_models = service.token_models.len(),
            inference_max_concurrent = inference_limits.max_concurrent,
            inference_max_queued = inference_limits.max_queued,
            inference_timeout = ?inference_limits.timeout,
            "classifier sidecar listening on Unix domain socket",
        );
        let stream = tokio_stream::wrappers::UnixListenerStream::new(listener);
        tonic_server_builder(tls_config)?
            .add_service(inference_service(
                service,
                max_decoding_message_size,
                request_auth,
            ))
            .serve_with_incoming(stream)
            .await
            .context("classifier sidecar server failed")?;
        return Ok(());
    }

    let addr: SocketAddr = cli
        .listen
        .parse()
        .with_context(|| format!("invalid --listen address {:?}", cli.listen))?;

    tracing::info!(
        %addr,
        models = service.models.len(),
        token_models = service.token_models.len(),
        inference_max_concurrent = inference_limits.max_concurrent,
        inference_max_queued = inference_limits.max_queued,
        inference_timeout = ?inference_limits.timeout,
        "classifier sidecar listening on TCP",
    );

    tonic_server_builder(tls_config)?
        .add_service(inference_service(
            service,
            max_decoding_message_size,
            request_auth,
        ))
        .serve(addr)
        .await
        .context("classifier sidecar server failed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_classifier_proto::{compress_request, CompressRequest, InferenceServiceClient};
    use sbproxy_classifiers::{
        TokenCompressionLimitError, TokenCompressionOutput, TokenCompressionTarget,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    struct StubTokenCompressor;

    impl TokenCompressor for StubTokenCompressor {
        fn compress(
            &self,
            text: &str,
            target: TokenCompressionTarget,
            _limits: TokenCompressionLimits,
        ) -> anyhow::Result<TokenCompressionOutput> {
            if text == "work limit fixture" {
                return Err(TokenCompressionLimitError::InputTokens {
                    actual: 101,
                    limit: 100,
                }
                .into());
            }
            if text == "invalid output fixture" {
                return Ok(TokenCompressionOutput {
                    text: "invented".to_string(),
                    original_tokens: 2,
                    compressed_tokens: 3,
                });
            }
            let (text, compressed_tokens) = match target {
                TokenCompressionTarget::RetainRatio(ratio)
                    if (ratio - 0.5).abs() < f64::EPSILON =>
                {
                    ("alpha gamma".to_string(), 2)
                }
                TokenCompressionTarget::TargetTokens(1) => ("alpha".to_string(), 1),
                other => anyhow::bail!("unexpected target {other:?} for {text:?}"),
            };
            Ok(TokenCompressionOutput {
                text,
                original_tokens: 3,
                compressed_tokens,
            })
        }
    }

    fn empty_service() -> SidecarService {
        let inference_limits = InferenceRuntimeLimits::default();
        SidecarService {
            models: HashMap::new(),
            embedders: HashMap::new(),
            token_models: HashMap::new(),
            default_model: None,
            default_embed_model: None,
            default_token_model: None,
            token_limits: TokenCompressionRuntimeLimits::default(),
            inference_limits,
            classify_admission: InferenceAdmission::new(
                inference_limits.max_concurrent,
                inference_limits.max_queued,
            ),
            embed_admission: InferenceAdmission::new(
                inference_limits.max_concurrent,
                inference_limits.max_queued,
            ),
            compression_admission: InferenceAdmission::new(
                DEFAULT_TOKEN_MAX_CONCURRENT,
                DEFAULT_TOKEN_MAX_QUEUED,
            ),
            refusals: RefusalCounters::default(),
            version: "sbproxy-classifier-sidecar test".to_string(),
        }
    }

    fn service_with_token_model() -> SidecarService {
        let mut service = empty_service();
        service
            .token_models
            .insert("llmlingua-2".to_string(), Arc::new(StubTokenCompressor));
        service.default_token_model = Some("llmlingua-2".to_string());
        service
    }

    #[tokio::test]
    async fn classify_unknown_model_is_not_found() {
        let svc = empty_service();
        let err = svc
            .classify(Request::new(ClassifyRequest {
                model: "nope".to_string(),
                text: "hello".to_string(),
                top_k: 1,
            }))
            .await
            .expect_err("unknown model must error");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn embed_without_model_is_failed_precondition() {
        let svc = empty_service();
        let err = svc
            .embed(Request::new(EmbedRequest {
                model: String::new(),
                texts: vec!["hi".to_string()],
            }))
            .await
            .expect_err("embed must fail when no embed model is loaded");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn embed_unknown_model_is_failed_precondition() {
        let svc = empty_service();
        let err = svc
            .embed(Request::new(EmbedRequest {
                model: "nope".to_string(),
                texts: vec!["hi".to_string()],
            }))
            .await
            .expect_err("unknown embed model must fail");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn compress_maps_ratio_and_absolute_targets() {
        let service = service_with_token_model();

        let ratio = service
            .compress(Request::new(CompressRequest {
                model: "llmlingua-2".to_string(),
                text: "alpha beta gamma".to_string(),
                target: Some(compress_request::Target::RetainRatio(0.5)),
            }))
            .await
            .expect("ratio compression")
            .into_inner();
        assert_eq!(ratio.text, "alpha gamma");
        assert_eq!(ratio.original_tokens, 3);
        assert_eq!(ratio.compressed_tokens, 2);

        let absolute = service
            .compress(Request::new(CompressRequest {
                model: String::new(),
                text: "alpha beta gamma".to_string(),
                target: Some(compress_request::Target::TargetTokens(1)),
            }))
            .await
            .expect("target-token compression")
            .into_inner();
        assert_eq!(absolute.text, "alpha");
        assert_eq!(absolute.compressed_tokens, 1);
    }

    #[tokio::test]
    async fn compress_rejects_missing_or_invalid_targets_before_model_lookup() {
        let service = empty_service();
        for target in [
            None,
            Some(compress_request::Target::RetainRatio(0.0)),
            Some(compress_request::Target::RetainRatio(f64::NAN)),
            Some(compress_request::Target::RetainRatio(1.1)),
            Some(compress_request::Target::TargetTokens(0)),
        ] {
            let error = service
                .compress(Request::new(CompressRequest {
                    model: "missing".to_string(),
                    text: "alpha beta".to_string(),
                    target,
                }))
                .await
                .expect_err("invalid target must fail");
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
    }

    #[tokio::test]
    async fn compress_unknown_token_model_is_not_found() {
        let error = empty_service()
            .compress(Request::new(CompressRequest {
                model: "missing".to_string(),
                text: "alpha beta".to_string(),
                target: Some(compress_request::Target::TargetTokens(1)),
            }))
            .await
            .expect_err("unknown token model must fail");

        assert_eq!(error.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn compress_rejects_invalid_model_output() {
        let error = service_with_token_model()
            .compress(Request::new(CompressRequest {
                model: String::new(),
                text: "invalid output fixture".to_string(),
                target: Some(compress_request::Target::TargetTokens(1)),
            }))
            .await
            .expect_err("invalid model output must fail");

        assert_eq!(error.code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn compress_rejects_requests_above_the_default_byte_limit() {
        let error = service_with_token_model()
            .compress(Request::new(CompressRequest {
                model: String::new(),
                text: "x".repeat(DEFAULT_TOKEN_MAX_REQUEST_BYTES + 1),
                target: Some(compress_request::Target::TargetTokens(1)),
            }))
            .await
            .expect_err("oversized request must fail before inference");

        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn compress_maps_classifier_work_limits_to_resource_exhausted() {
        let error = service_with_token_model()
            .compress(Request::new(CompressRequest {
                model: String::new(),
                text: "work limit fixture".to_string(),
                target: Some(compress_request::Target::TargetTokens(1)),
            }))
            .await
            .expect_err("classifier work limit must fail");

        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    }

    struct BlockingInferenceState {
        entered: AtomicUsize,
        released: Mutex<bool>,
        released_changed: Condvar,
    }

    impl BlockingInferenceState {
        fn new() -> Self {
            Self {
                entered: AtomicUsize::new(0),
                released: Mutex::new(false),
                released_changed: Condvar::new(),
            }
        }

        /// Record entry into inference and block until the test releases it,
        /// which is what holds a running slot open long enough to observe
        /// the admission bound.
        fn enter_and_wait(&self) {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let mut released = self.released.lock().expect("release lock poisoned");
            while !*released {
                released = self
                    .released_changed
                    .wait(released)
                    .expect("release lock poisoned");
            }
        }

        fn release(&self) {
            *self.released.lock().expect("release lock poisoned") = true;
            self.released_changed.notify_all();
        }
    }

    struct BlockingTokenCompressor {
        state: Arc<BlockingInferenceState>,
    }

    impl TokenCompressor for BlockingTokenCompressor {
        fn compress(
            &self,
            text: &str,
            _target: TokenCompressionTarget,
            _limits: TokenCompressionLimits,
        ) -> anyhow::Result<TokenCompressionOutput> {
            self.state.enter_and_wait();
            Ok(TokenCompressionOutput {
                text: text.to_string(),
                original_tokens: 1,
                compressed_tokens: 1,
            })
        }
    }

    struct BlockingClassifier {
        state: Arc<BlockingInferenceState>,
    }

    impl TextClassifier for BlockingClassifier {
        fn classify(&self, _text: &str) -> anyhow::Result<ClassificationOutput> {
            self.state.enter_and_wait();
            Ok(ClassificationOutput {
                label: "clean".to_string(),
                score: 0.25,
            })
        }
    }

    struct BlockingEmbedder {
        state: Arc<BlockingInferenceState>,
    }

    impl TextEmbedder for BlockingEmbedder {
        fn embed(&self, _text: &str) -> anyhow::Result<EmbeddingOutput> {
            self.state.enter_and_wait();
            Ok(EmbeddingOutput { values: vec![0.0] })
        }
    }

    /// Panics with the caller's text in the payload, so a test can prove the
    /// payload does not travel back to the caller.
    struct PanickingClassifier;

    impl TextClassifier for PanickingClassifier {
        fn classify(&self, text: &str) -> anyhow::Result<ClassificationOutput> {
            panic!("model exploded on {text}");
        }
    }

    struct ReleaseOnDrop(Arc<BlockingInferenceState>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    fn compression_request(text: &str) -> Request<CompressRequest> {
        Request::new(CompressRequest {
            model: String::new(),
            text: text.to_string(),
            target: Some(compress_request::Target::TargetTokens(1)),
        })
    }

    #[tokio::test]
    async fn compress_bounds_running_and_queued_work() {
        let state = Arc::new(BlockingInferenceState::new());
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&state));
        let mut service = empty_service();
        service.token_limits.max_concurrent = 1;
        service.token_limits.max_queued = 1;
        service.compression_admission = InferenceAdmission::new(1, 1);
        service.token_models.insert(
            "blocking".to_string(),
            Arc::new(BlockingTokenCompressor {
                state: Arc::clone(&state),
            }),
        );
        service.default_token_model = Some("blocking".to_string());
        let service = Arc::new(service);

        let first_service = Arc::clone(&service);
        let first =
            tokio::spawn(async move { first_service.compress(compression_request("first")).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.entered.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first request must enter inference");

        let second_service = Arc::clone(&service);
        let second =
            tokio::spawn(
                async move { second_service.compress(compression_request("second")).await },
            );
        tokio::time::timeout(Duration::from_secs(2), async {
            while service.compression_admission.admitted.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second request must occupy the queue");

        let error = service
            .compress(compression_request("third"))
            .await
            .expect_err("a request beyond running and queued capacity must fail");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);

        state.release();
        first
            .await
            .expect("first task must join")
            .expect("first request");
        second
            .await
            .expect("second task must join")
            .expect("second request");
        assert_eq!(state.entered.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancelling_an_rpc_does_not_release_a_running_blocking_slot() {
        let state = Arc::new(BlockingInferenceState::new());
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&state));
        let mut service = empty_service();
        service.token_limits.max_concurrent = 1;
        service.token_limits.max_queued = 0;
        service.compression_admission = InferenceAdmission::new(1, 0);
        service.token_models.insert(
            "blocking".to_string(),
            Arc::new(BlockingTokenCompressor {
                state: Arc::clone(&state),
            }),
        );
        service.default_token_model = Some("blocking".to_string());
        let service = Arc::new(service);

        let first_service = Arc::clone(&service);
        let first =
            tokio::spawn(async move { first_service.compress(compression_request("first")).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.entered.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first request must enter blocking inference");

        first.abort();
        assert!(first
            .await
            .expect_err("RPC task must be cancelled")
            .is_cancelled());
        assert_eq!(
            service.compression_admission.admitted.available_permits(),
            0,
            "the blocking closure must retain admission after RPC cancellation"
        );

        let error = service
            .compress(compression_request("second"))
            .await
            .expect_err("cancelled RPC must not free a still-running blocking slot");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert_eq!(state.entered.load(Ordering::SeqCst), 1);
        state.release();
    }

    fn classify_request(text: &str) -> Request<ClassifyRequest> {
        Request::new(ClassifyRequest {
            model: String::new(),
            text: text.to_string(),
            top_k: 1,
        })
    }

    fn blocking_classify_service(state: &Arc<BlockingInferenceState>) -> SidecarService {
        let mut service = empty_service();
        service.models.insert(
            "blocking".to_string(),
            Arc::new(BlockingClassifier {
                state: Arc::clone(state),
            }),
        );
        service.default_model = Some("blocking".to_string());
        service
    }

    #[tokio::test]
    async fn classify_bounds_running_and_queued_work() {
        let state = Arc::new(BlockingInferenceState::new());
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&state));
        let mut service = blocking_classify_service(&state);
        service.inference_limits.max_concurrent = 1;
        service.inference_limits.max_queued = 1;
        service.classify_admission = InferenceAdmission::new(1, 1);
        let service = Arc::new(service);

        let first_service = Arc::clone(&service);
        let first =
            tokio::spawn(async move { first_service.classify(classify_request("first")).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.entered.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first request must enter inference");

        let second_service = Arc::clone(&service);
        let second =
            tokio::spawn(async move { second_service.classify(classify_request("second")).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while service.classify_admission.admitted.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second request must occupy the queue");

        let error = tokio::time::timeout(
            Duration::from_secs(2),
            service.classify(classify_request("third")),
        )
        .await
        .expect("a request beyond capacity must be refused, not queued behind the others")
        .expect_err("a request beyond running and queued capacity must fail");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert_eq!(service.refusals.queue_full.load(Ordering::Relaxed), 1);

        state.release();
        first
            .await
            .expect("first task must join")
            .expect("first request");
        second
            .await
            .expect("second task must join")
            .expect("second request");
        assert_eq!(state.entered.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn embed_bounds_running_and_queued_work() {
        let state = Arc::new(BlockingInferenceState::new());
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&state));
        let mut service = empty_service();
        service.embed_admission = InferenceAdmission::new(1, 0);
        service.embedders.insert(
            "blocking".to_string(),
            (
                Arc::new(BlockingEmbedder {
                    state: Arc::clone(&state),
                }),
                1,
            ),
        );
        service.default_embed_model = Some("blocking".to_string());
        let service = Arc::new(service);

        let first_service = Arc::clone(&service);
        let first = tokio::spawn(async move {
            first_service
                .embed(Request::new(EmbedRequest {
                    model: String::new(),
                    texts: vec!["first".to_string()],
                }))
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.entered.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first request must enter inference");

        let error = tokio::time::timeout(
            Duration::from_secs(2),
            service.embed(Request::new(EmbedRequest {
                model: String::new(),
                texts: vec!["second".to_string()],
            })),
        )
        .await
        .expect("a request beyond capacity must be refused, not queued behind the first")
        .expect_err("a request beyond running capacity must fail");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert_eq!(service.refusals.queue_full.load(Ordering::Relaxed), 1);

        state.release();
        first
            .await
            .expect("first task must join")
            .expect("first request");
    }

    #[tokio::test]
    async fn classify_deadline_frees_the_caller_and_keeps_the_running_slot() {
        let state = Arc::new(BlockingInferenceState::new());
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&state));
        let mut service = blocking_classify_service(&state);
        service.inference_limits.timeout = Duration::from_millis(50);
        service.classify_admission = InferenceAdmission::new(1, 0);

        let error = tokio::time::timeout(
            Duration::from_secs(2),
            service.classify(classify_request("wedged")),
        )
        .await
        .expect("a wedged model must not hold the caller open")
        .expect_err("a wedged model must surface as an error");

        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert_eq!(
            service.refusals.deadline_exceeded.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            service.classify_admission.running.available_permits(),
            0,
            "a thread that is still running must keep its slot after the deadline"
        );
        state.release();
    }

    #[tokio::test]
    async fn classify_waiting_for_a_running_slot_is_bounded_by_the_deadline() {
        let state = Arc::new(BlockingInferenceState::new());
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&state));
        let mut service = blocking_classify_service(&state);
        service.inference_limits.timeout = Duration::from_millis(100);
        // One running slot and one queue slot behind it.
        service.classify_admission = InferenceAdmission::new(1, 1);

        // Hold the only running slot the way an inference in flight holds
        // it, without running one: a real first request would race this
        // test's own deadline, and what is under test is the wait, not the
        // inference.
        let held = Arc::clone(&service.classify_admission.running)
            .acquire_owned()
            .await
            .expect("the running semaphore is open");
        let queue_depth = service.classify_admission.admitted.available_permits();

        let queued = tokio::time::timeout(
            Duration::from_secs(2),
            service.classify(classify_request("queued")),
        )
        .await
        .expect("a queued request must not wait for a running slot without a bound")
        .expect_err("a queued request past the deadline must be refused");

        // A deadline that wraps only the inference never fires here,
        // because this request never reaches an inference to wrap.
        assert_eq!(queued.code(), tonic::Code::DeadlineExceeded);
        assert_eq!(
            service.refusals.deadline_exceeded.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            state.entered.load(Ordering::SeqCst),
            0,
            "a request refused while queued must never reach the model"
        );
        assert_eq!(
            service.classify_admission.admitted.available_permits(),
            queue_depth,
            "a request that gave up waiting must hand its queue slot back"
        );

        drop(held);
    }

    #[tokio::test]
    async fn classify_panic_is_contained_and_never_echoed_to_the_caller() {
        let mut service = empty_service();
        service
            .models
            .insert("boom".to_string(), Arc::new(PanickingClassifier));
        service.default_model = Some("boom".to_string());
        service.classify_admission = InferenceAdmission::new(1, 0);

        let error = service
            .classify(classify_request("secret prompt text"))
            .await
            .expect_err("a panicking model must surface as an error");

        assert_eq!(error.code(), tonic::Code::Internal);
        // The panic payload carries the caller's text. It reaches the
        // operator through the panic hook's stderr line and stops there.
        assert_eq!(error.message(), "classify inference ended without a result");
        assert_eq!(service.refusals.task_failed.load(Ordering::Relaxed), 1);
        assert_eq!(
            service.classify_admission.running.available_permits(),
            1,
            "a blocking task that unwinds must give its slot back"
        );
    }

    #[tokio::test]
    async fn classify_rejects_requests_above_the_default_byte_limit() {
        let service = empty_service();

        let error = service
            .classify(classify_request(
                &"x".repeat(DEFAULT_INFERENCE_MAX_REQUEST_BYTES + 1),
            ))
            .await
            .expect_err("oversized request must fail before inference");

        // An empty service answers NotFound once model lookup runs, so
        // ResourceExhausted is proof the bound ran first, on the default
        // configuration rather than an operator-supplied one.
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert_eq!(service.refusals.request_bytes.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn embed_rejects_batches_above_the_default_item_limit() {
        let service = empty_service();

        let error = service
            .embed(Request::new(EmbedRequest {
                model: String::new(),
                texts: vec!["hi".to_string(); DEFAULT_INFERENCE_MAX_ITEMS + 1],
            }))
            .await
            .expect_err("oversized batch must fail before inference");

        // An empty service answers FailedPrecondition once model lookup
        // runs, so ResourceExhausted is proof the bound ran first.
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert_eq!(service.refusals.batch_items.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn embed_with_no_texts_never_reaches_the_blocking_pool() {
        let state = Arc::new(BlockingInferenceState::new());
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&state));
        let mut service = empty_service();
        // Admission that refuses every request. An empty batch answering OK
        // is then proof the short-circuit ran: any path that reaches
        // `admit` gets RESOURCE_EXHAUSTED here, and a blocking pool that is
        // never entered cannot be distinguished from one entered zero times
        // by counting entries alone.
        service.embed_admission = InferenceAdmission::new(0, 0);
        service.embedders.insert(
            "blocking".to_string(),
            (
                Arc::new(BlockingEmbedder {
                    state: Arc::clone(&state),
                }),
                1,
            ),
        );
        service.default_embed_model = Some("blocking".to_string());

        let response = service
            .embed(Request::new(EmbedRequest {
                model: String::new(),
                texts: Vec::new(),
            }))
            .await
            .expect("an empty batch is not an error")
            .into_inner();

        assert!(response.embeddings.is_empty());
        assert_eq!(state.entered.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn every_refusal_is_counted_even_when_the_log_line_is_sampled() {
        let mut service = empty_service();
        service.inference_limits.max_request_bytes = 8;

        for _ in 0..3 {
            let error = service
                .classify(classify_request("longer than eight bytes"))
                .await
                .expect_err("oversized request must fail");
            assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        }

        assert_eq!(service.refusals.request_bytes.load(Ordering::Relaxed), 3);
        assert_eq!(service.refusals.queue_full.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn inference_limits_are_finite_without_any_configuration() {
        let cli = Cli::try_parse_from(["sbproxy-classifier-sidecar"]).expect("CLI syntax");

        let limits = cli.inference_limits().expect("default inference limits");

        assert_eq!(limits, InferenceRuntimeLimits::default());
        assert_eq!(
            limits.max_request_bytes,
            DEFAULT_INFERENCE_MAX_REQUEST_BYTES
        );
        assert_eq!(limits.max_items, DEFAULT_INFERENCE_MAX_ITEMS);
        assert!(limits.max_concurrent >= INFERENCE_CONCURRENT_FLOOR);
        assert!(limits.max_concurrent <= MAX_INFERENCE_CONCURRENT);
        assert!(limits.max_queued <= MAX_INFERENCE_QUEUED);
        assert_eq!(
            limits.timeout,
            Duration::from_millis(DEFAULT_INFERENCE_TIMEOUT_MS)
        );
    }

    #[test]
    fn inference_concurrency_default_tracks_the_host_between_its_clamps() {
        // A one- or two-core host is held at the floor rather than
        // serialized harder than a flat default would have serialized it.
        assert_eq!(derive_inference_max_concurrent(Some(1)), 4);
        assert_eq!(derive_inference_max_concurrent(Some(4)), 4);
        // Between the clamps the default is the host, not a literal. This
        // is the assertion a fixed `4` fails.
        assert_eq!(derive_inference_max_concurrent(Some(8)), 8);
        assert_eq!(derive_inference_max_concurrent(Some(16)), 16);
        assert_eq!(
            derive_inference_max_concurrent(Some(128)),
            MAX_INFERENCE_CONCURRENT
        );
        // A host that will not report its parallelism falls back to the
        // floor, never to something unbounded.
        assert_eq!(
            derive_inference_max_concurrent(None),
            INFERENCE_CONCURRENT_FLOOR
        );
    }

    #[test]
    fn inference_queue_default_scales_with_the_running_slots() {
        // Eight deep per running slot, so the wait a queued request faces
        // stays comparable instead of the count staying comparable.
        assert_eq!(derive_inference_max_queued(4), 32);
        assert_eq!(derive_inference_max_queued(16), 128);
        assert_eq!(derive_inference_max_queued(MAX_INFERENCE_CONCURRENT), 512);
        assert_eq!(
            derive_inference_max_queued(usize::MAX),
            MAX_INFERENCE_QUEUED
        );
    }

    #[test]
    fn the_flag_defaults_are_the_derived_values_and_not_a_second_opinion() {
        // Three declarations have to agree: the derivation, the struct's
        // Default, and the clap default the operator sees in --help. A
        // literal reintroduced in any one of them is the drift this pins.
        // On a host at or below the floor the derivation and a literal 4
        // coincide, which is what
        // `inference_concurrency_default_tracks_the_host_between_its_clamps`
        // covers instead.
        let host = std::thread::available_parallelism().ok().map(|n| n.get());
        let expected_concurrent = derive_inference_max_concurrent(host);
        let expected_queued = derive_inference_max_queued(expected_concurrent);

        let cli = Cli::try_parse_from(["sbproxy-classifier-sidecar"]).expect("CLI syntax");
        let from_flags = cli.inference_limits().expect("default inference limits");

        assert_eq!(from_flags.max_concurrent, expected_concurrent);
        assert_eq!(from_flags.max_queued, expected_queued);
        assert_eq!(
            InferenceRuntimeLimits::default().max_concurrent,
            expected_concurrent
        );
        assert_eq!(
            InferenceRuntimeLimits::default().max_queued,
            expected_queued
        );
    }

    #[test]
    fn inference_limit_cli_accepts_explicit_overrides() {
        let cli = Cli::try_parse_from([
            "sbproxy-classifier-sidecar",
            "--inference-max-request-bytes",
            "2097152",
            "--inference-max-items",
            "128",
            "--inference-max-concurrent",
            "8",
            "--inference-max-queued",
            "64",
            "--inference-timeout-ms",
            "1500",
        ])
        .expect("bounded inference override");

        let limits = cli.inference_limits().expect("bounded inference limits");

        assert_eq!(limits.max_request_bytes, 2_097_152);
        assert_eq!(limits.max_items, 128);
        assert_eq!(limits.max_concurrent, 8);
        assert_eq!(limits.max_queued, 64);
        assert_eq!(limits.timeout, Duration::from_millis(1_500));
    }

    #[test]
    fn inference_limit_cli_rejects_zero_and_excessive_values() {
        let cases = [
            ("--inference-max-request-bytes", "0"),
            ("--inference-max-request-bytes", "20000000"),
            ("--inference-max-items", "0"),
            ("--inference-max-items", "5000"),
            ("--inference-max-concurrent", "0"),
            ("--inference-max-concurrent", "65"),
            ("--inference-max-queued", "1025"),
            ("--inference-timeout-ms", "0"),
            ("--inference-timeout-ms", "600001"),
        ];

        for (option, value) in cases {
            let cli = Cli::try_parse_from(["sbproxy-classifier-sidecar", option, value])
                .expect("CLI syntax");
            assert!(
                cli.inference_limits().is_err(),
                "{option}={value} must be rejected"
            );
        }
    }

    #[test]
    fn inference_auth_debug_redacts_and_authenticates() {
        let auth = InferenceAuth::from_json(br#"{"tokens":["secret-a","secret-b"]}"#).unwrap();
        let debug = format!("{auth:?}");
        assert!(debug.contains("InferenceAuth"));
        assert!(debug.contains("2"));
        assert!(!debug.contains("secret-a"));
        assert!(!debug.contains("secret-b"));
        assert!(auth.authenticated(Some("secret-a")));
        assert!(!auth.authenticated(Some("missing")));
    }

    #[test]
    fn listener_tls_validation_rejects_uds_and_partial_identity_flags() {
        let uds_cli = Cli::try_parse_from([
            "sbproxy-classifier-sidecar",
            "--listen-uds",
            "/tmp/sbproxy.sock",
            "--listen-tls-cert-file",
            "server.pem",
            "--listen-tls-key-file",
            "server.key",
        ])
        .expect("CLI syntax");
        let uds_error = uds_cli.listener_tls_config().unwrap_err();
        assert!(uds_error.to_string().contains("--listen-uds"));

        let partial_cli = Cli::try_parse_from([
            "sbproxy-classifier-sidecar",
            "--listen-tls-cert-file",
            "server.pem",
        ])
        .expect("CLI syntax");
        let partial_error = partial_cli.listener_tls_config().unwrap_err();
        assert!(partial_error.to_string().contains("provided together"));
    }

    #[test]
    fn listener_tls_validation_rejects_invalid_pem_before_bind() {
        let directory = std::env::temp_dir().join(format!(
            "sbproxy-sidecar-tls-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&directory).expect("tempdir");
        let cert_path = directory.join("server.pem");
        let key_path = directory.join("server.key");
        std::fs::write(&cert_path, b"not a certificate").unwrap();
        std::fs::write(&key_path, b"not a key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut permissions = std::fs::metadata(&key_path).unwrap().permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&key_path, permissions).unwrap();
        }

        let cli = Cli::try_parse_from([
            "sbproxy-classifier-sidecar",
            "--listen-tls-cert-file",
            cert_path.to_str().unwrap(),
            "--listen-tls-key-file",
            key_path.to_str().unwrap(),
        ])
        .expect("CLI syntax");
        let error = cli.listener_tls_config().unwrap_err();
        assert!(error
            .to_string()
            .contains("validating gRPC listener TLS settings"));

        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn load_embed_spec_rejects_malformed() {
        assert!(load_embed_spec("no-equals").is_err());
        assert!(load_embed_spec("id=only-one-path").is_err());
    }

    #[test]
    fn token_model_spec_parses_paths_and_window_from_the_right() {
        let spec = parse_token_model_spec(
            "llmlingua-2=/models/compressor.onnx:/models/tokenizer.json:512",
        )
        .expect("valid token model spec");

        assert_eq!(spec.id, "llmlingua-2");
        assert_eq!(spec.model_path, Path::new("/models/compressor.onnx"));
        assert_eq!(spec.tokenizer_path, Path::new("/models/tokenizer.json"));
        assert_eq!(spec.max_model_tokens, 512);
    }

    #[test]
    fn token_model_spec_rejects_missing_parts_and_tiny_windows() {
        for spec in [
            "no-equals",
            "id=only-one-path",
            "id=model.onnx:tokenizer.json:not-a-number",
            "id=model.onnx:tokenizer.json:2",
        ] {
            assert!(
                parse_token_model_spec(spec).is_err(),
                "spec must fail: {spec}"
            );
        }
    }

    #[test]
    fn token_model_spec_rejects_ids_over_256_utf8_bytes() {
        let oversized_id = "é".repeat((MAX_MODEL_ID_BYTES / 2) + 1);
        let spec = format!("{oversized_id}=model.onnx:tokenizer.json:512");

        let error = parse_token_model_spec(&spec).expect_err("oversized model id must fail");

        assert!(error.to_string().contains("256-byte"), "{error:#}");
        assert!(!error.to_string().contains(&oversized_id), "{error:#}");
    }

    #[test]
    fn grpc_decoding_limit_tracks_the_configured_request_limit() {
        assert_eq!(
            grpc_decoding_message_limit(DEFAULT_TOKEN_MAX_REQUEST_BYTES),
            DEFAULT_GRPC_DECODING_MESSAGE_BYTES
        );
        assert_eq!(
            grpc_decoding_message_limit(8 * 1024 * 1024),
            8 * 1024 * 1024
        );
    }

    async fn spawn_wire_service(
        request_auth: Option<RequestAuthentication>,
    ) -> Option<InferenceServiceClient<tonic::transport::Channel>> {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping sidecar wire test: loopback bind denied: {error}");
                return None;
            }
            Err(error) => panic!("failed to bind sidecar wire test listener: {error}"),
        };
        let address = listener.local_addr().expect("listener address");
        let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tokio::spawn(async move {
            Server::builder()
                .add_service(inference_service(
                    empty_service(),
                    grpc_decoding_message_limit(DEFAULT_TOKEN_MAX_REQUEST_BYTES),
                    request_auth,
                ))
                .serve_with_incoming(stream)
                .await
                .expect("wire test server");
        });
        Some(
            InferenceServiceClient::connect(format!("http://{address}"))
                .await
                .expect("wire test client"),
        )
    }

    #[tokio::test]
    async fn wire_decoder_admits_four_mib_and_the_handler_bounds_it() {
        let Some(mut client) = spawn_wire_service(None).await else {
            return;
        };
        let error = client
            .classify(ClassifyRequest {
                model: "missing".to_string(),
                text: "x".repeat(2 * 1024 * 1024),
                top_k: 1,
            })
            .await
            .expect_err("request must reach the empty service");

        // The transport still decodes 2 MiB, so the request reaches the
        // handler at all; the handler's own budget is what refuses it. A
        // codec rejection could never produce this status.
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert!(
            error.message().contains("byte limit"),
            "unexpected message: {}",
            error.message()
        );
    }

    #[tokio::test]
    async fn wire_compress_enforces_the_exact_encoded_request_limit() {
        let Some(mut client) = spawn_wire_service(None).await else {
            return;
        };
        let request = CompressRequest {
            model: String::new(),
            text: "x".repeat(DEFAULT_TOKEN_MAX_REQUEST_BYTES),
            target: Some(compress_request::Target::TargetTokens(1)),
        };
        assert!(prost::Message::encoded_len(&request) > DEFAULT_TOKEN_MAX_REQUEST_BYTES);

        let error = client
            .compress(request)
            .await
            .expect_err("logical Compress cap must reject before model lookup");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn wire_bearer_auth_rejects_missing_metadata_and_allows_authorized_requests() {
        let auth = RequestAuthentication::bearer(Arc::new(
            InferenceAuth::from_json(br#"{"tokens":["secret-token"]}"#).unwrap(),
        ));
        let Some(mut client) = spawn_wire_service(Some(auth)).await else {
            return;
        };

        let missing = client
            .classify(ClassifyRequest {
                model: "missing".to_string(),
                text: "hello".to_string(),
                top_k: 1,
            })
            .await
            .expect_err("missing bearer token must be rejected");
        assert_eq!(missing.code(), tonic::Code::Unauthenticated);

        let mut request = Request::new(ClassifyRequest {
            model: "missing".to_string(),
            text: "hello".to_string(),
            top_k: 1,
        });
        request
            .metadata_mut()
            .insert("authorization", "Bearer secret-token".parse().unwrap());
        let authorized = client
            .classify(request)
            .await
            .expect_err("authorized request must reach the empty service");
        assert_eq!(authorized.code(), tonic::Code::NotFound);
    }

    #[test]
    fn bearer_authorization_parser_is_case_insensitive_and_rejects_empty_tokens() {
        assert_eq!(
            parse_bearer_authorization("Bearer secret-token"),
            Some("secret-token")
        );
        assert_eq!(
            parse_bearer_authorization("bearer   secret-token  "),
            Some("secret-token")
        );
        assert_eq!(
            parse_bearer_authorization("BEARER\tsecret-token"),
            Some("secret-token")
        );
        assert_eq!(parse_bearer_authorization("Basic secret-token"), None);
        assert_eq!(parse_bearer_authorization("Bearer "), None);
        assert_eq!(parse_bearer_authorization("Bearer\t  "), None);
        assert_eq!(parse_bearer_authorization("Bearer"), None);
    }

    #[tokio::test]
    async fn compress_bounds_and_does_not_echo_model_ids() {
        let oversized_id = "s".repeat(MAX_MODEL_ID_BYTES + 1);
        let oversized_error = empty_service()
            .compress(Request::new(CompressRequest {
                model: oversized_id.clone(),
                text: "alpha".to_string(),
                target: Some(compress_request::Target::TargetTokens(1)),
            }))
            .await
            .expect_err("oversized model id must fail before lookup");
        assert_eq!(oversized_error.code(), tonic::Code::InvalidArgument);
        assert!(!oversized_error.message().contains(&oversized_id));

        let untrusted_id = "customer-secret-model";
        let unknown_error = empty_service()
            .compress(Request::new(CompressRequest {
                model: untrusted_id.to_string(),
                text: "alpha".to_string(),
                target: Some(compress_request::Target::TargetTokens(1)),
            }))
            .await
            .expect_err("unknown model must fail");
        assert_eq!(unknown_error.code(), tonic::Code::NotFound);
        assert!(!unknown_error.message().contains(untrusted_id));
    }

    #[test]
    fn token_model_loader_enforces_operator_artifact_and_window_limits() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "sbproxy-token-model-limit-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("tempdir");
        let model_path = directory.join("model.onnx");
        let tokenizer_path = directory.join("tokenizer.json");
        std::fs::write(&model_path, [0_u8; 5]).expect("model fixture");
        let spec = format!(
            "llmlingua-2={}:{}:512",
            model_path.display(),
            tokenizer_path.display()
        );

        let size_error = load_token_model_spec(&spec, 4, 512)
            .err()
            .expect("artifact limit must reject");
        assert!(format!("{size_error:#}").contains("exceeds"));

        let parse_error = load_token_model_spec(&spec, 5, 512)
            .err()
            .expect("invalid fixture must not load");
        assert!(
            !format!("{parse_error:#}").contains("exceeds"),
            "larger explicit artifact limit must reach the next validation: {parse_error:#}"
        );

        let window_error = load_token_model_spec(&spec, 5, 256)
            .err()
            .expect("model window limit must reject");
        assert!(
            format!("{window_error:#}").contains("configured maximum 256"),
            "unexpected error: {window_error:#}"
        );
        std::fs::remove_dir_all(&directory).expect("remove fixture directory");
    }

    #[test]
    fn cli_accepts_repeatable_token_models_and_an_explicit_default() {
        let cli = Cli::try_parse_from([
            "sbproxy-classifier-sidecar",
            "--token-model",
            "small=small.onnx:small-tokenizer.json:512",
            "--token-model",
            "large=large.onnx:large-tokenizer.json:512",
            "--default-token-model",
            "small",
        ])
        .expect("valid token model CLI");

        assert_eq!(cli.token_models.len(), 2);
        assert_eq!(cli.default_token_model.as_deref(), Some("small"));
        cli.validate_runtime_configuration()
            .expect("valid token model IDs");
    }

    #[test]
    fn cli_rejects_an_oversized_explicit_default_token_model() {
        let oversized_id = "é".repeat((MAX_MODEL_ID_BYTES / 2) + 1);
        let cli = Cli::try_parse_from([
            "sbproxy-classifier-sidecar",
            "--default-token-model",
            oversized_id.as_str(),
        ])
        .expect("CLI syntax");

        let error = cli
            .validate_runtime_configuration()
            .expect_err("oversized default token model must fail");

        assert!(error.to_string().contains("256-byte"), "{error:#}");
        assert!(!error.to_string().contains(&oversized_id), "{error:#}");
    }

    #[test]
    fn token_limit_cli_accepts_an_explicit_mbert_artifact_override() {
        let cli = Cli::try_parse_from([
            "sbproxy-classifier-sidecar",
            "--token-model-max-bytes",
            "750000000",
            "--token-max-request-bytes",
            "2097152",
            "--token-max-request-tokens",
            "200000",
            "--token-max-windows",
            "400",
            "--token-max-model-window",
            "1024",
            "--token-max-concurrent",
            "3",
            "--token-max-queued",
            "7",
        ])
        .expect("bounded LLMLingua override");

        let limits = cli
            .token_compression_limits()
            .expect("bounded LLMLingua limits");

        assert_eq!(limits.max_model_bytes, 750_000_000);
        assert_eq!(limits.max_request_bytes, 2_097_152);
        assert_eq!(limits.max_request_tokens, 200_000);
        assert_eq!(limits.max_windows, 400);
        assert_eq!(limits.max_model_window, 1_024);
        assert_eq!(limits.max_concurrent, 3);
        assert_eq!(limits.max_queued, 7);
    }

    #[test]
    fn token_limit_cli_rejects_zero_and_excessive_values() {
        let cases = [
            ("--token-model-max-bytes", "0"),
            ("--token-model-max-bytes", "5000000000"),
            ("--token-max-request-bytes", "0"),
            ("--token-max-request-bytes", "20000000"),
            ("--token-max-request-tokens", "0"),
            ("--token-max-request-tokens", "2000000"),
            ("--token-max-windows", "0"),
            ("--token-max-windows", "5000"),
            ("--token-max-model-window", "2"),
            ("--token-max-model-window", "5000"),
            ("--token-max-concurrent", "0"),
            ("--token-max-concurrent", "65"),
            ("--token-max-queued", "1025"),
        ];

        for (option, value) in cases {
            let cli = Cli::try_parse_from(["sbproxy-classifier-sidecar", option, value])
                .expect("CLI syntax");
            assert!(
                cli.token_compression_limits().is_err(),
                "{option}={value} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn version_reports_models_sorted() {
        let svc = empty_service();
        let resp = svc
            .version(Request::new(VersionRequest {}))
            .await
            .expect("version ok")
            .into_inner();
        assert!(resp.version.contains("sbproxy-classifier-sidecar"));
        assert!(resp.models.is_empty());
    }

    #[test]
    fn load_model_spec_rejects_malformed() {
        assert!(load_model_spec("no-equals").is_err());
        assert!(load_model_spec("id=only-one-path").is_err());
    }
}
