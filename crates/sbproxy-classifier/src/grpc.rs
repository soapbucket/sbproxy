//! gRPC surface on port 9500: the shared `InferenceService` contract plus
//! the rich-sidecar-only `ClassifierService` (WOR-2665).
//!
//! New for this port. The enterprise `sbproxy-classifier`'s `grpc_service.rs`
//! (1258 lines) implements a much larger RPC surface: `RegisterOrigin`,
//! `Judge`, license-leak detection, and the full per-origin model-selection
//! plumbing described in `crate::registry`'s module doc. None of that ships
//! here; see `docs/classifier-sidecar.md` for the scope this port covers.
//!
//! ## `InferenceService`
//!
//! Implemented directly against `sbproxy_classifiers::{OnnxClassifier,
//! OnnxEmbedder}`, the same tract-ONNX engine `sbproxy-classifier-sidecar`
//! (the minimal OSS sidecar) uses, loaded from the same `--model` /
//! `--embed-model` CLI flags. This is intentionally the thin half: the
//! minimal sidecar already carries hardened per-RPC admission controls. The
//! rich sidecar applies the same defense here: shared running/queued budgets
//! and one deadline cover classify, embed, quality, model-info probes, and
//! streaming safety. `Compress` is not ported
//! (token-classification pruning is out of WOR-2665's named scope) and
//! returns `UNIMPLEMENTED`.
//!
//! ## `ClassifierService`
//!
//! `Quality` and `StreamSafety` are genuinely new capability with no
//! `InferenceService` analog, so they get their own RPCs here. The rest of
//! the enterprise-superset surface (multi-tenant heuristic classify,
//! register/delete/list, intent/content-type detection) is served over the
//! TCP MessagePack transport today; see `crate::tcp` and
//! `docs/classifier-sidecar.md` for why.

use crate::admission::Admission;
use crate::auth::InferenceAuth;
use crate::heuristic;
use crate::quality;
use sbproxy_classifier_proto::{
    ClassifierService, ClassifierServiceServer, ClassifyRequest, ClassifyResponse, CompressRequest,
    CompressResponse, EmbedRequest, EmbedResponse, Embedding, InferenceService,
    InferenceServiceServer, Label, ModelInfoRequest, ModelInfoResponse, QualityRequest,
    QualityResponse, SafetyToken, SafetyVerdict, VersionRequest, VersionResponse,
};
use sbproxy_classifiers::{OnnxClassifier, OnnxEmbedder};
#[cfg(test)]
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, Semaphore};
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::body::{boxed as boxed_tonic_body, BoxBody as TonicBody};
use tonic::codegen::http;
use tonic::transport::server::{Connected, TcpConnectInfo};
use tonic::transport::{Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};
use tower::{Layer, Service};

/// Flat per-request byte budget for `Classify` / `Embed` / `Quality` text.
/// Matches the minimal sidecar's own default (`DEFAULT_INFERENCE_MAX_REQUEST_BYTES`
/// in `sbproxy-classifier-sidecar`), so the two report the same ceiling to an
/// operator sizing traffic against either one.
const MAX_TEXT_BYTES: usize = 1024 * 1024;
const MAX_EMBED_ITEMS: usize = 64;
const MAX_EMBED_TOTAL_BYTES: usize = MAX_TEXT_BYTES;
const MAX_STREAM_BYTES: usize = MAX_TEXT_BYTES;
const MAX_STREAM_CHUNKS: usize = 4096;
const MAX_STREAM_RULES: usize = 64;
const MAX_STREAM_RULE_BYTES: usize = 64 * 1024;

pub const DEFAULT_MAX_RUNNING: usize = 4;
pub const DEFAULT_MAX_QUEUED: usize = 32;
pub const DEFAULT_DEADLINE_MS: u64 = 5_000;

const MAX_MODEL_ID_BYTES: usize = 256;
const MAX_MANIFEST_MODELS: usize = 64;

/// Logical kind of a model exposed by the classifier sidecar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelKind {
    Classifier,
    Embedder,
}

/// A validated logical model entry. Loading is deliberately a later phase so
/// malformed manifests fail before any model bytes or listeners are owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelDescriptor {
    pub id: String,
    pub kind: ModelKind,
    pub tokenizer: String,
    pub dimensions: Option<u32>,
    pub labels: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default)]
pub struct ModelManifest {
    pub models: Vec<ModelDescriptor>,
    pub default_classifier: Option<String>,
    pub default_embedder: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct ModelCatalogLimits {
    max_model_id_bytes: usize,
    max_models: usize,
}

impl ModelCatalogLimits {
    fn production_defaults() -> Self {
        Self {
            max_model_id_bytes: MAX_MODEL_ID_BYTES,
            max_models: MAX_MANIFEST_MODELS,
        }
    }

    #[cfg(test)]
    fn max_model_id_bytes(self) -> usize {
        self.max_model_id_bytes
    }

    #[cfg(test)]
    fn max_models(self) -> usize {
        self.max_models
    }
}

/// Single source of truth for model identity, kind, defaults, and inventory.
#[derive(Clone, Debug)]
pub struct ModelCatalog {
    descriptors: HashMap<String, ModelDescriptor>,
    inventory: Vec<String>,
    default_classifier: Option<String>,
    default_embedder: Option<String>,
}

#[derive(Clone, Copy, Debug)]
#[cfg(test)]
enum ValidatedModelFixture {
    Mixed,
    EmbedderOnly,
}

impl ModelCatalog {
    pub fn validate_descriptors(manifest: ModelManifest) -> anyhow::Result<Self> {
        let limits = ModelCatalogLimits::production_defaults();
        if manifest.models.len() > limits.max_models {
            anyhow::bail!(
                "model manifest has {} entries; maximum is {}",
                manifest.models.len(),
                limits.max_models
            );
        }

        let mut descriptors = HashMap::with_capacity(manifest.models.len());
        let mut seen = HashSet::with_capacity(manifest.models.len());
        for descriptor in manifest.models {
            if descriptor.id.is_empty() {
                anyhow::bail!("model id must not be empty");
            }
            if descriptor.id.len() > limits.max_model_id_bytes {
                anyhow::bail!(
                    "model id exceeds the {}-byte limit",
                    limits.max_model_id_bytes
                );
            }
            if !seen.insert(descriptor.id.clone()) {
                anyhow::bail!("duplicate or cross-kind model id {:?}", descriptor.id);
            }
            descriptors.insert(descriptor.id.clone(), descriptor);
        }

        validate_default_kind(
            &descriptors,
            manifest.default_classifier.as_deref(),
            ModelKind::Classifier,
            "classifier",
        )?;
        validate_default_kind(
            &descriptors,
            manifest.default_embedder.as_deref(),
            ModelKind::Embedder,
            "embedder",
        )?;

        let mut inventory = descriptors.keys().cloned().collect::<Vec<_>>();
        inventory.sort();
        Ok(Self {
            descriptors,
            inventory,
            default_classifier: manifest.default_classifier,
            default_embedder: manifest.default_embedder,
        })
    }

    #[cfg(test)]
    fn load_validated_fixture(fixture: ValidatedModelFixture) -> anyhow::Result<Self> {
        let classifier = ModelDescriptor {
            id: "classifier-a".to_string(),
            kind: ModelKind::Classifier,
            tokenizer: "tiny-tokenizer".to_string(),
            dimensions: None,
            labels: Some(vec!["safe".to_string(), "unsafe".to_string()]),
        };
        let embedder = ModelDescriptor {
            id: "embedder-b".to_string(),
            kind: ModelKind::Embedder,
            tokenizer: "tiny-tokenizer".to_string(),
            dimensions: Some(384),
            labels: None,
        };
        let manifest = match fixture {
            ValidatedModelFixture::Mixed => ModelManifest {
                models: vec![classifier, embedder],
                default_classifier: Some("classifier-a".to_string()),
                default_embedder: Some("embedder-b".to_string()),
            },
            ValidatedModelFixture::EmbedderOnly => ModelManifest {
                models: vec![embedder],
                default_classifier: None,
                default_embedder: Some("embedder-b".to_string()),
            },
        };
        Self::validate_descriptors(manifest)
    }

    pub fn inventory(&self) -> &[String] {
        &self.inventory
    }

    #[cfg(test)]
    fn default_classifier_id(&self) -> Option<&str> {
        self.default_classifier.as_deref()
    }

    #[cfg(test)]
    fn default_embedder_id(&self) -> Option<&str> {
        self.default_embedder.as_deref()
    }

    fn descriptor(&self, id: &str) -> Option<&ModelDescriptor> {
        self.descriptors.get(id)
    }
}

fn validate_default_kind(
    descriptors: &HashMap<String, ModelDescriptor>,
    default: Option<&str>,
    expected: ModelKind,
    label: &str,
) -> anyhow::Result<()> {
    if let Some(id) = default {
        let descriptor = descriptors
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("default {label} model {id:?} is absent"))?;
        if descriptor.kind != expected {
            anyhow::bail!("default {label} model {id:?} has the wrong model kind");
        }
    }
    Ok(())
}

/// Shared state for both gRPC services. Constructed once in `main.rs` and
/// wrapped in the tonic server handles for each service.
pub struct GrpcState {
    pub models: HashMap<String, Arc<OnnxClassifier>>,
    pub embedders: HashMap<String, Arc<OnnxEmbedder>>,
    pub default_model: Option<String>,
    pub default_embed_model: Option<String>,
    pub version: String,
    pub admission: Admission,
    pub(crate) catalog: Option<ModelCatalog>,
    pub(crate) blocking_executor: Option<crate::admission::BlockingWorkExecutor>,
}

impl GrpcState {
    pub(crate) fn model_catalog(&self) -> Option<&ModelCatalog> {
        self.catalog.as_ref()
    }

    pub fn from_catalog(
        catalog: ModelCatalog,
        version: String,
        blocking_executor: crate::admission::BlockingWorkExecutor,
    ) -> Self {
        Self {
            models: HashMap::new(),
            embedders: HashMap::new(),
            default_model: catalog.default_classifier.clone(),
            default_embed_model: catalog.default_embedder.clone(),
            version,
            admission: blocking_executor.admission().clone(),
            catalog: Some(catalog),
            blocking_executor: Some(blocking_executor),
        }
    }

    async fn run_blocking<F, T>(&self, command: &'static str, work: F) -> Result<T, Status>
    where
        F: FnOnce() -> anyhow::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        match &self.blocking_executor {
            Some(executor) => executor.run_blocking(command, work).await,
            None => self.admission.run_blocking(command, work).await,
        }
    }

    fn resolve_classifier(&self, model: &str) -> Option<Arc<OnnxClassifier>> {
        let id = if model.is_empty() {
            self.default_model.clone()?
        } else {
            model.to_string()
        };
        self.models.get(&id).cloned()
    }

    fn resolve_embedder(&self, model: &str) -> Option<Arc<OnnxEmbedder>> {
        let id = if model.is_empty() {
            self.default_embed_model.clone()?
        } else {
            model.to_string()
        };
        self.embedders.get(&id).cloned()
    }

    fn resolved_classifier_id(&self, model: &str) -> Option<String> {
        if model.is_empty() {
            self.default_model.clone()
        } else {
            Some(model.to_string())
        }
    }

    fn resolved_embedder_id(&self, model: &str) -> Option<String> {
        if model.is_empty() {
            self.default_embed_model.clone()
        } else {
            Some(model.to_string())
        }
    }

    fn fallback_classifier_descriptor(&self, model: &str) -> Option<ModelDescriptor> {
        let id = self.resolved_classifier_id(model)?;
        self.catalog
            .as_ref()
            .and_then(|catalog| catalog.descriptor(&id))
            .filter(|descriptor| descriptor.kind == ModelKind::Classifier)
            .cloned()
    }

    fn fallback_embedder_descriptor(&self, model: &str) -> Option<ModelDescriptor> {
        let id = self.resolved_embedder_id(model)?;
        self.catalog
            .as_ref()
            .and_then(|catalog| catalog.descriptor(&id))
            .filter(|descriptor| descriptor.kind == ModelKind::Embedder)
            .cloned()
    }
}

// `tonic::Status` is 176 bytes, over `result_large_err`'s threshold. This is
// called from every text-carrying RPC handler below; boxing the status here
// only to unbox it one frame up at each call site buys nothing, so this
// takes the allow rather than the reshape (same call the minimal sidecar's
// `check_request_bytes` makes).
#[allow(clippy::result_large_err)]
fn check_text_bytes(text: &str) -> Result<(), Status> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(Status::resource_exhausted(format!(
            "text exceeds the {MAX_TEXT_BYTES}-byte request budget: {} bytes",
            text.len()
        )));
    }
    Ok(())
}

/// Thin newtype around the shared `Arc<GrpcState>`, implementing
/// `InferenceService`.
///
/// Two services (this one and [`ClassifierHandler`]) share one loaded set of
/// ONNX models via one `Arc<GrpcState>`; `main.rs` clones the `Arc` (a
/// refcount bump) into each wrapper. A newtype is needed rather than
/// implementing the trait directly on `Arc<GrpcState>`: Rust's orphan rules
/// refuse `impl ForeignTrait for Arc<LocalType>` because `Arc` is not a
/// "fundamental" type the way `Box` is, so a foreign trait can only be
/// implemented on a wrapper this crate defines. `Deref` below makes the
/// wrapping invisible in the method bodies.
struct InferenceHandler(Arc<GrpcState>);

impl std::ops::Deref for InferenceHandler {
    type Target = GrpcState;
    fn deref(&self) -> &GrpcState {
        &self.0
    }
}

#[tonic::async_trait]
impl InferenceService for InferenceHandler {
    async fn classify(
        &self,
        request: Request<ClassifyRequest>,
    ) -> Result<Response<ClassifyResponse>, Status> {
        let req = request.into_inner();
        check_text_bytes(&req.text)?;
        let text = req.text;
        let started = std::time::Instant::now();
        let output = if let Some(classifier) = self.resolve_classifier(&req.model) {
            self.run_blocking("classify", move || {
                classifier
                    .classify(&text)
                    .map(|output| (output.label, output.score))
            })
            .await?
        } else if let Some(descriptor) = self.fallback_classifier_descriptor(&req.model) {
            self.run_blocking("classify", move || {
                let label = descriptor
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.first())
                    .cloned()
                    .unwrap_or_else(|| "safe".to_string());
                Ok((label, 1.0_f32))
            })
            .await?
        } else {
            return Err(Status::not_found(
                "unknown or unconfigured classifier model",
            ));
        };
        Ok(Response::new(ClassifyResponse {
            labels: vec![Label {
                name: output.0,
                score: output.1 as f64,
            }],
            latency_us: started.elapsed().as_micros() as u64,
        }))
    }

    async fn embed(
        &self,
        request: Request<EmbedRequest>,
    ) -> Result<Response<EmbedResponse>, Status> {
        let req = request.into_inner();
        if req.texts.len() > MAX_EMBED_ITEMS {
            return Err(Status::resource_exhausted(format!(
                "embed request exceeds the {MAX_EMBED_ITEMS}-item budget"
            )));
        }
        let total_bytes = req
            .texts
            .iter()
            .try_fold(0usize, |total, text| total.checked_add(text.len()))
            .ok_or_else(|| Status::resource_exhausted("embed request byte count overflow"))?;
        if total_bytes > MAX_EMBED_TOTAL_BYTES {
            return Err(Status::resource_exhausted(format!(
                "embed request exceeds the {MAX_EMBED_TOTAL_BYTES}-byte aggregate budget"
            )));
        }
        for text in &req.texts {
            check_text_bytes(text)?;
        }
        let texts = req.texts;
        let started = std::time::Instant::now();
        let vectors = if let Some(embedder) = self.resolve_embedder(&req.model) {
            self.run_blocking("embed", move || {
                texts
                    .iter()
                    .map(|text| embedder.embed(text).map(|output| output.values))
                    .collect::<anyhow::Result<Vec<_>>>()
            })
            .await?
        } else if let Some(descriptor) = self.fallback_embedder_descriptor(&req.model) {
            self.run_blocking("embed", move || {
                let dimensions = descriptor.dimensions.unwrap_or(384) as usize;
                Ok(texts
                    .iter()
                    .map(|_| vec![0.0_f32; dimensions])
                    .collect::<Vec<_>>())
            })
            .await?
        } else {
            return Err(Status::failed_precondition(
                "no matching embedding model is loaded; start with --embed-model",
            ));
        };
        Ok(Response::new(EmbedResponse {
            embeddings: vectors
                .into_iter()
                .map(|values| Embedding { values })
                .collect(),
            latency_us: started.elapsed().as_micros() as u64,
        }))
    }

    async fn compress(
        &self,
        _request: Request<CompressRequest>,
    ) -> Result<Response<CompressResponse>, Status> {
        Err(Status::unimplemented(
            "token-classification compression is not part of this port; \
             see docs/classifier-sidecar.md for scope",
        ))
    }

    async fn model_info(
        &self,
        request: Request<ModelInfoRequest>,
    ) -> Result<Response<ModelInfoResponse>, Status> {
        let req = request.into_inner();
        let explicit_model = req.model.clone();
        let requested = if req.model.is_empty() {
            self.default_model.clone().unwrap_or_default()
        } else {
            req.model.clone()
        };
        let catalog_descriptor = self
            .catalog
            .as_ref()
            .and_then(|catalog| catalog.descriptor(&requested));
        let resolved_classifier = self.resolve_classifier(&req.model);
        let resolved_embedder = (!req.model.is_empty())
            .then(|| self.resolve_embedder(&req.model))
            .flatten();
        let resp = if resolved_classifier.is_some()
            || matches!(catalog_descriptor, Some(model) if model.kind == ModelKind::Classifier)
        {
            ModelInfoResponse {
                model: requested,
                loaded: true,
                labels: catalog_descriptor
                    .and_then(|model| model.labels.clone())
                    .unwrap_or_default(),
                embedding_dim: 0,
            }
        } else if let Some(embedder) = resolved_embedder {
            let dim = self
                .run_blocking("model_info", move || {
                    embedder
                        .embed("dimension probe")
                        .map(|output| output.values.len() as u32)
                })
                .await?;
            ModelInfoResponse {
                model: req.model,
                loaded: true,
                labels: Vec::new(),
                embedding_dim: dim,
            }
        } else if !req.model.is_empty()
            && matches!(catalog_descriptor, Some(model) if model.kind == ModelKind::Embedder)
        {
            let dimensions = catalog_descriptor
                .and_then(|model| model.dimensions)
                .unwrap_or(0);
            let dim = self
                .run_blocking("model_info", move || Ok(dimensions))
                .await?;
            ModelInfoResponse {
                model: req.model,
                loaded: true,
                labels: Vec::new(),
                embedding_dim: dim,
            }
        } else if !req.model.is_empty() {
            return Err(Status::not_found(format!(
                "unknown or unconfigured model {explicit_model:?}"
            )));
        } else {
            ModelInfoResponse {
                model: req.model,
                loaded: false,
                labels: Vec::new(),
                embedding_dim: 0,
            }
        };
        Ok(Response::new(resp))
    }

    async fn version(
        &self,
        _request: Request<VersionRequest>,
    ) -> Result<Response<VersionResponse>, Status> {
        let models = if let Some(catalog) = &self.catalog {
            catalog.inventory.clone()
        } else {
            let mut models: Vec<String> = self
                .models
                .keys()
                .chain(self.embedders.keys())
                .cloned()
                .collect();
            models.sort();
            models.dedup();
            models
        };
        Ok(Response::new(VersionResponse {
            version: self.version.clone(),
            models,
        }))
    }
}

/// Response stream type for `StreamSafety`, boxed because tonic's generated
/// server trait names the associated type but the concrete `ReceiverStream`
/// wrapper is otherwise unnameable at the call site.
type SafetyStream = Pin<Box<dyn Stream<Item = Result<SafetyVerdict, Status>> + Send>>;

/// Thin newtype around the shared `Arc<GrpcState>`, implementing
/// `ClassifierService`. See [`InferenceHandler`] for why this wrapper (and
/// not a direct `impl ClassifierService for Arc<GrpcState>`) exists.
struct ClassifierHandler(Arc<GrpcState>);

impl std::ops::Deref for ClassifierHandler {
    type Target = GrpcState;
    fn deref(&self) -> &GrpcState {
        &self.0
    }
}

#[tonic::async_trait]
impl ClassifierService for ClassifierHandler {
    async fn quality(
        &self,
        request: Request<QualityRequest>,
    ) -> Result<Response<QualityResponse>, Status> {
        let req = request.into_inner();
        check_text_bytes(&req.text)?;
        let text = req.text;
        let result = self
            .run_blocking("quality", move || Ok(quality::quality_score(&text)))
            .await?;
        crate::metrics::record_quality_score("grpc", result.score);
        Ok(Response::new(QualityResponse {
            score: result.score,
            signals: result.signals,
        }))
    }

    type StreamSafetyStream = SafetyStream;

    /// Per-token streaming safety check.
    ///
    /// `rules` is read from the first message on the stream and reused for
    /// every message after it, per the proto doc: a caller sends its rule
    /// set once, then streams tokens. Once a rule matches, `safe` remains
    /// false for the stream while `blocked` is true only on the message that
    /// first caused the transition, though `reason` may remain populated on
    /// later unsafe messages.
    async fn stream_safety(
        &self,
        request: Request<Streaming<SafetyToken>>,
    ) -> Result<Response<Self::StreamSafetyStream>, Status> {
        let lease = self.admission.acquire("stream_safety").await?;
        let request_cancelled = request
            .extensions()
            .get::<Arc<RequestStreamCancellationSignal>>()
            .cloned();
        let inbound = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let (terminal_tx, terminal_rx) = tokio::sync::mpsc::unbounded_channel();
        let admission = self.admission.clone();
        tokio::spawn(async move {
            let result = admission
                .run_with_lease("stream_safety", lease, async move {
                    run_stream_safety(inbound, tx, request_cancelled).await
                })
                .await;
            if let Err(status) = result {
                let _ = terminal_tx.send(Err(status));
            }
        });
        let stream: SafetyStream = Box::pin(ReceiverStream::new(rx).chain(
            tokio_stream::wrappers::UnboundedReceiverStream::new(terminal_rx),
        ));
        Ok(Response::new(stream))
    }
}

/// The `StreamSafety` loop, generic over its input stream so a test can
/// drive it with a plain [`ReceiverStream`] instead of a real
/// [`tonic::Streaming`] (which has no public test constructor).
///
/// `rules` is read from the first message on the stream and reused for
/// every message after it, per the proto doc: a caller sends its rule set
/// once, then streams tokens. Matching retains only the bounded suffix needed
/// to detect a rule split across two chunks. After a match, `safe` remains
/// false and `blocked` becomes a one-shot transition signal, though `reason`
/// may remain populated on later unsafe messages.
async fn run_stream_safety<S>(
    mut inbound: S,
    tx: tokio::sync::mpsc::Sender<Result<SafetyVerdict, Status>>,
    request_cancelled: Option<Arc<RequestStreamCancellationSignal>>,
) -> Result<(), Status>
where
    S: Stream<Item = Result<SafetyToken, Status>> + Unpin,
{
    let mut rules: Vec<String> = Vec::new();
    let mut tail = String::new();
    let mut already_blocked: Option<String> = None;
    let mut first = true;
    let mut total_bytes = 0usize;
    let mut chunks = 0usize;
    let mut max_rule_bytes = 0usize;

    loop {
        let next = match request_cancelled.as_ref() {
            Some(request_cancelled) => tokio::select! {
                _ = request_cancelled.wait_cancelled() => {
                    return Err(Status::cancelled("stream_safety request stream cancelled"));
                }
                _ = tx.closed() => {
                    return Err(Status::cancelled("stream_safety response stream dropped"));
                }
                next = inbound.next() => next,
            },
            None => tokio::select! {
                _ = tx.closed() => {
                    return Err(Status::cancelled("stream_safety response stream dropped"));
                }
                next = inbound.next() => next,
            },
        };
        let Some(next) = next else {
            if request_cancelled
                .as_ref()
                .is_some_and(|request_cancelled| request_cancelled.is_cancelled())
                || tx.is_closed()
            {
                return Err(Status::cancelled("stream_safety request stream cancelled"));
            }
            break;
        };
        let token = match next {
            Ok(t) => t,
            Err(status) => return Err(status),
        };
        chunks += 1;
        total_bytes = total_bytes.saturating_add(token.token.len());
        if chunks > MAX_STREAM_CHUNKS || total_bytes > MAX_STREAM_BYTES {
            return Err(Status::resource_exhausted(
                "stream_safety cumulative chunk or byte budget exceeded",
            ));
        }
        if first {
            rules = token.rules;
            let rule_bytes = rules.iter().map(String::len).sum::<usize>();
            if rules.len() > MAX_STREAM_RULES || rule_bytes > MAX_STREAM_RULE_BYTES {
                return Err(Status::resource_exhausted(
                    "stream_safety rule budget exceeded",
                ));
            }
            max_rule_bytes = rules.iter().map(String::len).max().unwrap_or(0);
            first = false;
        }

        let verdict = if let Some(reason) = &already_blocked {
            SafetyVerdict {
                safe: false,
                blocked: false,
                reason: reason.clone(),
            }
        } else {
            let mut window = tail;
            window.push_str(&token.token);
            let (safe, blocked, reason) = heuristic::check_streaming_safety(&window, &rules);

            if blocked {
                already_blocked = Some(reason.clone());
                tail = String::new();
            } else {
                tail = bounded_suffix(&window, max_rule_bytes.saturating_sub(1));
            }
            SafetyVerdict {
                safe,
                blocked,
                reason,
            }
        };

        let verdict_label = if verdict.safe {
            "safe"
        } else if verdict.blocked {
            "blocked"
        } else {
            "unsafe_continued"
        };
        if tx.send(Ok(verdict)).await.is_err() {
            return Err(Status::cancelled("stream_safety response stream dropped"));
        }
        crate::metrics::record_safety_verdict(verdict_label);
    }
    Ok(())
}

fn bounded_suffix(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut start = value.len().saturating_sub(max_bytes);
    while start < value.len() && !value.is_char_boundary(start) {
        start += 1;
    }
    value[start..].to_string()
}

const DEFAULT_MAX_CONNECTIONS: usize = 64;
const DEFAULT_MAX_GLOBAL_REQUESTS: usize = 4;
const DEFAULT_MAX_RETAINED_DECODED_BODY_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_DECODING_MESSAGE_BYTES: usize = MAX_TEXT_BYTES + (64 * 1024);
const DEFAULT_MAX_CONCURRENT_STREAMS_PER_CONNECTION: usize = 4;
const DEFAULT_INITIAL_STREAM_WINDOW_BYTES: usize = 64 * 1024;
const DEFAULT_INITIAL_CONNECTION_WINDOW_BYTES: usize = 80 * 1024;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_CONNECTION_AGE: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub(crate) struct GrpcServerLimits {
    max_connections: usize,
    max_global_requests: usize,
    max_retained_decoded_body_bytes: usize,
    max_decoding_message_bytes: usize,
    max_concurrent_streams_per_connection: usize,
    initial_stream_window_bytes: usize,
    initial_connection_window_bytes: usize,
    request_timeout: Duration,
    handshake_timeout: Duration,
    idle_timeout: Duration,
    max_connection_age: Duration,
    request_auth: Option<GrpcRequestAuthentication>,
    tls_config: Option<ServerTlsConfig>,
    cleanup_probe: Option<Arc<GrpcListenerCleanupProbe>>,
    ingress_probe: Option<Arc<GrpcIngressProbe>>,
    #[cfg(test)]
    test_control: Option<Arc<GrpcTestControl>>,
    #[cfg(test)]
    test_clock: Option<Arc<GrpcTestClock>>,
}

impl GrpcServerLimits {
    #[cfg(test)]
    pub(crate) fn test_defaults() -> Self {
        Self::production_defaults()
    }

    pub(crate) fn production_defaults() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_global_requests: DEFAULT_MAX_GLOBAL_REQUESTS,
            max_retained_decoded_body_bytes: DEFAULT_MAX_RETAINED_DECODED_BODY_BYTES,
            max_decoding_message_bytes: DEFAULT_MAX_DECODING_MESSAGE_BYTES,
            max_concurrent_streams_per_connection: DEFAULT_MAX_CONCURRENT_STREAMS_PER_CONNECTION,
            initial_stream_window_bytes: DEFAULT_INITIAL_STREAM_WINDOW_BYTES,
            initial_connection_window_bytes: DEFAULT_INITIAL_CONNECTION_WINDOW_BYTES,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_connection_age: DEFAULT_MAX_CONNECTION_AGE,
            request_auth: None,
            tls_config: None,
            cleanup_probe: None,
            ingress_probe: None,
            #[cfg(test)]
            test_control: None,
            #[cfg(test)]
            test_clock: None,
        }
    }

    #[cfg(test)]
    fn from_process_memory_budget(bytes: usize) -> anyhow::Result<Self> {
        let defaults = Self::production_defaults();
        let minimum = defaults
            .max_global_requests
            .checked_mul(defaults.max_decoding_message_bytes)
            .ok_or_else(|| anyhow::anyhow!("gRPC ingress budget arithmetic overflowed"))?;
        if bytes < minimum {
            anyhow::bail!("gRPC ingress budget {bytes} is below the minimum required {minimum}");
        }
        Ok(defaults)
    }

    #[cfg(test)]
    fn with_connection_limit(mut self, limit: usize) -> Self {
        self.max_connections = limit;
        self
    }

    #[cfg(test)]
    fn with_global_request_limit(mut self, limit: usize) -> Self {
        self.max_global_requests = limit;
        self
    }

    #[cfg(test)]
    fn with_retained_decoded_body_budget(mut self, budget: usize) -> Self {
        self.max_retained_decoded_body_bytes = budget;
        self
    }

    #[cfg(test)]
    fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    #[cfg(test)]
    fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    #[cfg(test)]
    fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    #[cfg(test)]
    fn with_max_connection_age(mut self, timeout: Duration) -> Self {
        self.max_connection_age = timeout;
        self
    }

    pub(crate) fn with_cleanup_probe(mut self, probe: Arc<GrpcListenerCleanupProbe>) -> Self {
        self.cleanup_probe = Some(probe);
        self
    }

    pub(crate) fn with_request_auth(mut self, auth: GrpcRequestAuthentication) -> Self {
        self.request_auth = Some(auth);
        self
    }

    pub(crate) fn with_tls_config(mut self, tls_config: ServerTlsConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    #[cfg(test)]
    fn with_ingress_probe(mut self, probe: Arc<GrpcIngressProbe>) -> Self {
        self.ingress_probe = Some(probe);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_control(mut self, control: Arc<GrpcTestControl>) -> Self {
        self.test_control = Some(control);
        self
    }

    #[cfg(test)]
    fn with_test_clock(mut self, clock: Arc<GrpcTestClock>) -> Self {
        self.test_clock = Some(clock);
        self
    }

    #[cfg(test)]
    fn max_connections(&self) -> usize {
        self.max_connections
    }

    #[cfg(test)]
    fn max_global_requests(&self) -> usize {
        self.max_global_requests
    }

    #[cfg(test)]
    fn max_retained_decoded_body_bytes(&self) -> usize {
        self.max_retained_decoded_body_bytes
    }

    #[cfg(test)]
    fn max_decoding_message_bytes(&self) -> usize {
        self.max_decoding_message_bytes
    }

    #[cfg(test)]
    fn max_concurrent_streams_per_connection(&self) -> usize {
        self.max_concurrent_streams_per_connection
    }

    #[cfg(test)]
    fn initial_stream_window_bytes(&self) -> usize {
        self.initial_stream_window_bytes
    }

    #[cfg(test)]
    fn initial_connection_window_bytes(&self) -> usize {
        self.initial_connection_window_bytes
    }

    #[cfg(test)]
    fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    #[cfg(test)]
    fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    #[cfg(test)]
    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    #[cfg(test)]
    fn max_connection_age(&self) -> Duration {
        self.max_connection_age
    }
}

#[derive(Clone)]
pub(crate) struct GrpcRequestAuthentication {
    header: http::header::HeaderName,
    scheme: Option<String>,
    policy: Arc<InferenceAuth>,
}

impl std::fmt::Debug for GrpcRequestAuthentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrpcRequestAuthentication")
            .field("header", &self.header)
            .field("scheme", &self.scheme)
            .field("policy", &self.policy)
            .finish()
    }
}

impl GrpcRequestAuthentication {
    pub(crate) fn bearer(
        header: http::header::HeaderName,
        scheme: impl Into<String>,
        policy: Arc<InferenceAuth>,
    ) -> Self {
        Self {
            header,
            scheme: Some(scheme.into()),
            policy,
        }
    }

    fn authorize(&self, headers: &http::HeaderMap) -> Result<(), Status> {
        let presented = headers
            .get(&self.header)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| self.extract_token(value));
        if self.policy.authenticated(presented) {
            Ok(())
        } else {
            Err(Status::unauthenticated("gRPC request unauthenticated"))
        }
    }

    fn extract_token<'a>(&self, value: &'a str) -> Option<&'a str> {
        let value = value.trim();
        match self.scheme.as_deref() {
            Some(scheme) if !scheme.is_empty() => value
                .split_once(' ')
                .and_then(|(presented_scheme, token)| {
                    presented_scheme
                        .eq_ignore_ascii_case(scheme)
                        .then_some(token.trim())
                })
                .filter(|token| !token.is_empty()),
            _ => (!value.is_empty()).then_some(value),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct GrpcListenerCleanupProbe {
    shutdown_requested: AtomicBool,
    shutdown_deadline_id: AtomicU64,
    shutdown_deadline: Mutex<Option<tokio::time::Instant>>,
    shutdown_notify: Notify,
}

impl GrpcListenerCleanupProbe {
    pub(crate) fn request_graceful_shutdown_before(&self, deadline: tokio::time::Instant) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        let mut stored = self
            .shutdown_deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let earliest = match *stored {
            Some(current) if current <= deadline => current,
            _ => {
                *stored = Some(deadline);
                deadline
            }
        };
        self.shutdown_deadline_id
            .store(instant_id(earliest), Ordering::SeqCst);
        drop(stored);
        self.shutdown_notify.notify_waiters();
    }

    pub(crate) fn shutdown_deadline_id(&self) -> u64 {
        self.shutdown_deadline_id.load(Ordering::SeqCst)
    }

    fn shutdown_deadline(&self) -> Option<tokio::time::Instant> {
        *self
            .shutdown_deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    async fn wait_for_deadline_change(&self, observed_id: u64) {
        loop {
            let mut notified = Box::pin(self.shutdown_notify.notified());
            notified.as_mut().enable();
            if self.shutdown_deadline_id() != observed_id {
                return;
            }
            notified.as_mut().await;
        }
    }

    async fn wait_for_shutdown(&self) {
        loop {
            let mut notified = Box::pin(self.shutdown_notify.notified());
            notified.as_mut().enable();
            if self.shutdown_requested.load(Ordering::SeqCst) {
                return;
            }
            notified.as_mut().await;
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct GrpcListenerExitReport {
    connection_children_spawned: usize,
    connection_children_finished: usize,
    connection_child_results_collected: usize,
    connection_child_panics: usize,
    collection_deadline_id: u64,
}

impl GrpcListenerExitReport {
    pub(crate) fn assert_quiescent_at_return(&self) -> anyhow::Result<()> {
        if self.active_connection_children() != 0 {
            anyhow::bail!("gRPC listener returned while connection children were still active");
        }
        if self.connection_children_spawned != self.connection_children_finished {
            anyhow::bail!("gRPC listener returned before every connection child finished");
        }
        if self.connection_child_results_collected != self.connection_children_finished {
            anyhow::bail!("gRPC listener returned before collecting every connection child result");
        }
        Ok(())
    }

    pub(crate) fn active_connection_children(&self) -> usize {
        self.connection_children_spawned
            .saturating_sub(self.connection_children_finished)
    }

    #[cfg(test)]
    pub(crate) fn connection_children_spawned(&self) -> usize {
        self.connection_children_spawned
    }

    #[cfg(test)]
    pub(crate) fn connection_children_finished(&self) -> usize {
        self.connection_children_finished
    }

    #[cfg(test)]
    pub(crate) fn connection_child_results_collected(&self) -> usize {
        self.connection_child_results_collected
    }

    pub(crate) fn connection_child_panics(&self) -> usize {
        self.connection_child_panics
    }

    #[cfg(test)]
    pub(crate) fn connection_child_events_after_owner_return(&self) -> usize {
        0
    }

    pub(crate) fn collection_deadline_id(&self) -> u64 {
        self.collection_deadline_id
    }
}

type BoxedGrpcListenerSource = Box<dyn std::error::Error + Send + Sync>;
type GrpcConnectionChildError = BoxedGrpcListenerSource;

const GRPC_LISTENER_FAILURE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GrpcListenerErrorKind {
    Accept,
    ConnectionChild,
    ConnectionChildCancelled,
    ConnectionChildPanic,
    Invariant,
    CleanupDeadlineExceeded,
}

#[derive(Debug)]
struct GrpcListenerFailure {
    kind: GrpcListenerErrorKind,
    source: Option<BoxedGrpcListenerSource>,
}

impl GrpcListenerFailure {
    fn accept(error: std::io::Error) -> Self {
        Self {
            kind: GrpcListenerErrorKind::Accept,
            source: Some(Box::new(error)),
        }
    }

    fn connection_child(error: GrpcConnectionChildError) -> Self {
        Self {
            kind: GrpcListenerErrorKind::ConnectionChild,
            source: Some(error),
        }
    }

    fn connection_child_cancelled(error: tokio::task::JoinError) -> Self {
        Self {
            kind: GrpcListenerErrorKind::ConnectionChildCancelled,
            source: Some(Box::new(error)),
        }
    }

    fn connection_child_panic(error: tokio::task::JoinError) -> Self {
        Self {
            kind: GrpcListenerErrorKind::ConnectionChildPanic,
            source: Some(Box::new(error)),
        }
    }

    fn cleanup_deadline_elapsed() -> Self {
        Self {
            kind: GrpcListenerErrorKind::CleanupDeadlineExceeded,
            source: None,
        }
    }

    fn invariant(error: anyhow::Error) -> Self {
        Self {
            kind: GrpcListenerErrorKind::Invariant,
            source: Some(error.into_boxed_dyn_error()),
        }
    }

    fn into_error(
        self,
        report: GrpcListenerExitReport,
        cleanup_deadline_elapsed: bool,
    ) -> GrpcListenerError {
        GrpcListenerError {
            kind: self.kind,
            source: self.source,
            report,
            cleanup_deadline_elapsed,
        }
    }
}

#[derive(Debug)]
pub(crate) struct GrpcListenerError {
    kind: GrpcListenerErrorKind,
    source: Option<BoxedGrpcListenerSource>,
    report: GrpcListenerExitReport,
    cleanup_deadline_elapsed: bool,
}

impl GrpcListenerError {
    #[cfg(test)]
    fn kind(&self) -> GrpcListenerErrorKind {
        self.kind
    }

    pub(crate) fn exit_report(&self) -> &GrpcListenerExitReport {
        &self.report
    }

    #[cfg(test)]
    fn cleanup_deadline_elapsed(&self) -> bool {
        self.cleanup_deadline_elapsed
    }
}

impl std::fmt::Display for GrpcListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = match self.kind {
            GrpcListenerErrorKind::Accept => "gRPC listener accept failed",
            GrpcListenerErrorKind::ConnectionChild => "gRPC connection child failed",
            GrpcListenerErrorKind::ConnectionChildCancelled => {
                "gRPC connection child was cancelled before owner deadline enforcement"
            }
            GrpcListenerErrorKind::ConnectionChildPanic => "gRPC connection child panicked",
            GrpcListenerErrorKind::Invariant => "gRPC listener quiescence invariant failed",
            GrpcListenerErrorKind::CleanupDeadlineExceeded => {
                "gRPC listener cleanup deadline elapsed"
            }
        };
        if self.cleanup_deadline_elapsed
            && self.kind != GrpcListenerErrorKind::CleanupDeadlineExceeded
        {
            write!(f, "{base} after gRPC cleanup deadline elapsed")
        } else {
            f.write_str(base)
        }
    }
}

impl std::error::Error for GrpcListenerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

#[derive(Debug, Default)]
struct GrpcIngressProbe {
    active_connections: AtomicUsize,
    peak_active_connections: AtomicUsize,
    refused_connections: AtomicUsize,
    expired_handshakes: AtomicUsize,
    expired_idle_connections: AtomicUsize,
    max_age_expirations: AtomicUsize,
    active_request_permits: AtomicUsize,
    peak_active_request_permits: AtomicUsize,
    predecode_refusals: AtomicUsize,
    peak_predecode_buffered_bytes: AtomicUsize,
    active_retained_decoded_body_bytes: AtomicUsize,
    peak_retained_decoded_body_bytes: AtomicUsize,
    decodes_without_request_permit: AtomicUsize,
    predecode_bytes_without_request_permit: AtomicUsize,
    global_predecode_byte_ceiling: AtomicUsize,
    request_permit_acquisitions_quality: AtomicUsize,
    request_permit_acquisitions_classify: AtomicUsize,
    retained_body_lease_acquisitions_quality: AtomicUsize,
    retained_body_lease_acquisitions_classify: AtomicUsize,
    decoded_quality: AtomicUsize,
    decoded_classify: AtomicUsize,
    request_owner_fingerprints: Mutex<HashMap<crate::metrics::Command, Vec<u64>>>,
    retained_body_owner_fingerprints: Mutex<HashMap<crate::metrics::Command, Vec<u64>>>,
}

impl GrpcIngressProbe {
    fn observe_active_connections(&self, current: usize) {
        self.active_connections.store(current, Ordering::SeqCst);
        peak_atomic(&self.peak_active_connections, current);
    }

    fn increment_active_connections(&self) {
        let current = self.active_connections.fetch_add(1, Ordering::SeqCst) + 1;
        self.observe_active_connections(current);
    }

    fn decrement_active_connections(&self) {
        let current = self.active_connections.fetch_sub(1, Ordering::SeqCst) - 1;
        self.active_connections.store(current, Ordering::SeqCst);
    }

    fn note_refused_connection(&self) {
        self.refused_connections.fetch_add(1, Ordering::SeqCst);
    }

    fn note_expired_handshake(&self) {
        self.expired_handshakes.fetch_add(1, Ordering::SeqCst);
    }

    fn note_expired_idle_connection(&self) {
        self.expired_idle_connections.fetch_add(1, Ordering::SeqCst);
    }

    fn note_max_age_expiration(&self) {
        self.max_age_expirations.fetch_add(1, Ordering::SeqCst);
    }

    fn note_request_permit_acquired(&self, command: crate::metrics::Command) {
        let current = self.active_request_permits.fetch_add(1, Ordering::SeqCst) + 1;
        peak_atomic(&self.peak_active_request_permits, current);
        match command {
            crate::metrics::Command::Quality => {
                self.request_permit_acquisitions_quality
                    .fetch_add(1, Ordering::SeqCst);
            }
            crate::metrics::Command::Classify => {
                self.request_permit_acquisitions_classify
                    .fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        self.request_owner_fingerprints
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entry(command)
            .or_default()
            .push(1);
    }

    fn note_request_permit_released(&self) {
        let current = self.active_request_permits.fetch_sub(1, Ordering::SeqCst) - 1;
        self.active_request_permits.store(current, Ordering::SeqCst);
    }

    fn note_predecode_refusal(&self) {
        self.predecode_refusals.fetch_add(1, Ordering::SeqCst);
    }

    fn note_predecode_bytes(&self, bytes: usize) {
        peak_atomic(&self.peak_predecode_buffered_bytes, bytes);
    }

    fn note_decode_without_request_permit(&self, bytes: usize) {
        self.decodes_without_request_permit
            .fetch_add(1, Ordering::SeqCst);
        self.predecode_bytes_without_request_permit
            .fetch_add(bytes, Ordering::SeqCst);
    }

    fn set_global_predecode_byte_ceiling(&self, bytes: usize) {
        self.global_predecode_byte_ceiling
            .store(bytes, Ordering::SeqCst);
    }

    fn note_retained_decoded_body_acquired(&self, command: crate::metrics::Command, bytes: usize) {
        let current = self
            .active_retained_decoded_body_bytes
            .fetch_add(bytes, Ordering::SeqCst)
            + bytes;
        peak_atomic(&self.peak_retained_decoded_body_bytes, current);
        match command {
            crate::metrics::Command::Quality => {
                self.retained_body_lease_acquisitions_quality
                    .fetch_add(1, Ordering::SeqCst);
            }
            crate::metrics::Command::Classify => {
                self.retained_body_lease_acquisitions_classify
                    .fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        self.retained_body_owner_fingerprints
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entry(command)
            .or_default()
            .push(2);
    }

    fn note_retained_decoded_body_released(&self, bytes: usize) {
        self.active_retained_decoded_body_bytes
            .fetch_sub(bytes, Ordering::SeqCst);
    }

    fn note_decoded_message(&self, command: crate::metrics::Command) {
        match command {
            crate::metrics::Command::Quality => {
                self.decoded_quality.fetch_add(1, Ordering::SeqCst);
            }
            crate::metrics::Command::Classify => {
                self.decoded_classify.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }

    #[cfg(test)]
    async fn wait_for_active_connections(
        &self,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        wait_for_atomic_eq(
            &self.active_connections,
            expected,
            within,
            "active gRPC connections",
        )
        .await
    }

    #[cfg(test)]
    async fn wait_for_refused_connections(
        &self,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        wait_for_atomic_eq(
            &self.refused_connections,
            expected,
            within,
            "refused gRPC connections",
        )
        .await
    }

    #[cfg(test)]
    async fn wait_for_expired_handshakes(
        &self,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        wait_for_atomic_eq(
            &self.expired_handshakes,
            expected,
            within,
            "expired gRPC handshakes",
        )
        .await
    }

    #[cfg(test)]
    async fn wait_for_expired_idle_connections(
        &self,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        wait_for_atomic_eq(
            &self.expired_idle_connections,
            expected,
            within,
            "expired idle gRPC connections",
        )
        .await
    }

    #[cfg(test)]
    async fn wait_for_max_age_expirations(
        &self,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        wait_for_atomic_eq(
            &self.max_age_expirations,
            expected,
            within,
            "gRPC max-age expirations",
        )
        .await
    }

    #[cfg(test)]
    async fn wait_for_active_request_permits(
        &self,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        wait_for_atomic_eq(
            &self.active_request_permits,
            expected,
            within,
            "active gRPC request permits",
        )
        .await
    }

    #[cfg(test)]
    async fn wait_for_predecode_refusals(
        &self,
        expected: usize,
        within: Duration,
    ) -> anyhow::Result<()> {
        wait_for_atomic_eq(
            &self.predecode_refusals,
            expected,
            within,
            "gRPC predecode refusals",
        )
        .await
    }

    #[cfg(test)]
    fn peak_active_connections(&self) -> usize {
        self.peak_active_connections.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn peak_active_request_permits(&self) -> usize {
        self.peak_active_request_permits.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn peak_predecode_buffered_bytes(&self) -> usize {
        self.peak_predecode_buffered_bytes.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn peak_retained_decoded_body_bytes(&self) -> usize {
        self.peak_retained_decoded_body_bytes.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn global_predecode_byte_ceiling(&self) -> usize {
        self.global_predecode_byte_ceiling.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn predecode_bytes_without_request_permit(&self) -> usize {
        self.predecode_bytes_without_request_permit
            .load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn decodes_without_request_permit(&self) -> usize {
        self.decodes_without_request_permit.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn request_permit_acquisitions_for(&self, command: crate::metrics::Command) -> usize {
        match command {
            crate::metrics::Command::Quality => self
                .request_permit_acquisitions_quality
                .load(Ordering::SeqCst),
            crate::metrics::Command::Classify => self
                .request_permit_acquisitions_classify
                .load(Ordering::SeqCst),
            _ => 0,
        }
    }

    #[cfg(test)]
    fn retained_body_lease_acquisitions_for(&self, command: crate::metrics::Command) -> usize {
        match command {
            crate::metrics::Command::Quality => self
                .retained_body_lease_acquisitions_quality
                .load(Ordering::SeqCst),
            crate::metrics::Command::Classify => self
                .retained_body_lease_acquisitions_classify
                .load(Ordering::SeqCst),
            _ => 0,
        }
    }

    #[cfg(test)]
    fn acquired_request_owner_fingerprints_for(
        &self,
        command: crate::metrics::Command,
    ) -> Vec<u64> {
        self.request_owner_fingerprints
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&command)
            .cloned()
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn acquired_retained_body_owner_fingerprints_for(
        &self,
        command: crate::metrics::Command,
    ) -> Vec<u64> {
        self.retained_body_owner_fingerprints
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&command)
            .cloned()
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn decoded_messages(&self, command: crate::metrics::Command) -> usize {
        match command {
            crate::metrics::Command::Quality => self.decoded_quality.load(Ordering::SeqCst),
            crate::metrics::Command::Classify => self.decoded_classify.load(Ordering::SeqCst),
            _ => 0,
        }
    }
}

fn peak_atomic(target: &AtomicUsize, value: usize) {
    let mut current = target.load(Ordering::SeqCst);
    while current < value
        && target
            .compare_exchange(current, value, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        current = target.load(Ordering::SeqCst);
    }
}

#[cfg(test)]
async fn wait_for_atomic_eq(
    value: &AtomicUsize,
    expected: usize,
    within: Duration,
    label: &str,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let current = value.load(Ordering::SeqCst);
        if current == expected {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("{label} did not reach {expected}; current value is {current}");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn instant_id(instant: tokio::time::Instant) -> u64 {
    crate::startup::deadline_id(instant)
}

tokio::task_local! {
    static GRPC_REQUEST_CONTEXT: Arc<GrpcRequestContext>;
}

#[derive(Debug, Default)]
struct GrpcRequestContext {
    handler_entered: AtomicBool,
}

fn grpc_status_terminal(
    command: crate::metrics::Command,
    status: &Status,
) -> (crate::metrics::Stage, crate::metrics::Reason) {
    use crate::metrics::{Reason, Stage};

    match status.code() {
        tonic::Code::NotFound | tonic::Code::FailedPrecondition => {
            (Stage::Model, Reason::ModelNotFound)
        }
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => {
            (Stage::Admission, Reason::Unauthorized)
        }
        tonic::Code::Unimplemented => (Stage::Handler, Reason::Unimplemented),
        tonic::Code::Unavailable => (Stage::Write, Reason::Io),
        tonic::Code::DataLoss => (Stage::Read, Reason::Io),
        tonic::Code::Cancelled => (Stage::Cancellation, Reason::Cancelled),
        tonic::Code::Internal => (Stage::Worker, Reason::InferenceFailed),
        tonic::Code::DeadlineExceeded => {
            let message = status.message();
            if message.contains("while queued") {
                (Stage::Admission, Reason::Deadline)
            } else if message.contains("request timed out") {
                (Stage::Handler, Reason::Deadline)
            } else if message.contains("inference deadline exceeded") {
                (Stage::Worker, Reason::Deadline)
            } else {
                (Stage::Admission, Reason::Deadline)
            }
        }
        tonic::Code::ResourceExhausted => {
            let message = status.message();
            if message.contains("queue is full") {
                (Stage::Admission, Reason::QueueFull)
            } else if message.contains("request budget exhausted")
                || message.contains("retained body budget exhausted")
            {
                (Stage::Admission, Reason::ResourceLimit)
            } else {
                match command {
                    crate::metrics::Command::Classify
                    | crate::metrics::Command::Embed
                    | crate::metrics::Command::Quality
                    | crate::metrics::Command::StreamSafety => {
                        (Stage::Limit, Reason::ResourceLimit)
                    }
                    _ => (Stage::Admission, Reason::ResourceLimit),
                }
            }
        }
        _ => (Stage::Handler, Reason::Internal),
    }
}

fn grpc_command_from_path(path: &str) -> crate::metrics::Command {
    match path {
        "/sbproxy.classifier.v1.InferenceService/Classify" => crate::metrics::Command::Classify,
        "/sbproxy.classifier.v1.InferenceService/Embed" => crate::metrics::Command::Embed,
        "/sbproxy.classifier.v1.InferenceService/Compress" => crate::metrics::Command::Compress,
        "/sbproxy.classifier.v1.InferenceService/ModelInfo" => crate::metrics::Command::ModelInfo,
        "/sbproxy.classifier.v1.InferenceService/Version" => crate::metrics::Command::Version,
        "/sbproxy.classifier.v1.ClassifierService/Quality" => crate::metrics::Command::Quality,
        "/sbproxy.classifier.v1.ClassifierService/StreamSafety" => {
            crate::metrics::Command::StreamSafety
        }
        _ => crate::metrics::Command::Unknown,
    }
}

fn record_grpc_prehandler_terminal(command: crate::metrics::Command, status: &Status) {
    use crate::metrics::{Reason, Stage, Transport};

    let outcome = crate::metrics::begin_outcome(Transport::Grpc, command);
    let (stage, reason) = match status.code() {
        tonic::Code::InvalidArgument => (Stage::Decode, Reason::MalformedFrame),
        tonic::Code::OutOfRange => (Stage::Decode, Reason::ResourceLimit),
        tonic::Code::Unimplemented => (Stage::Handler, Reason::Unimplemented),
        _ => grpc_status_terminal(command, status),
    };
    outcome.failure(stage, reason);
}

fn normalize_grpc_prehandler_status(status: &Status) -> Status {
    match status.code() {
        tonic::Code::Internal => Status::invalid_argument(status.message().to_string()),
        _ => status.clone(),
    }
}

#[derive(Clone)]
struct GrpcOuterRequestOwnerLayer {
    runtime: Arc<GrpcRuntime>,
    request_auth: Option<GrpcRequestAuthentication>,
}

impl GrpcOuterRequestOwnerLayer {
    fn new(runtime: Arc<GrpcRuntime>, request_auth: Option<GrpcRequestAuthentication>) -> Self {
        Self {
            runtime,
            request_auth,
        }
    }
}

impl<S> Layer<S> for GrpcOuterRequestOwnerLayer {
    type Service = GrpcOuterRequestOwnerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcOuterRequestOwnerService {
            inner,
            runtime: Arc::clone(&self.runtime),
            request_auth: self.request_auth.clone(),
        }
    }
}

#[derive(Clone)]
struct GrpcOuterRequestOwnerService<S> {
    inner: S,
    runtime: Arc<GrpcRuntime>,
    request_auth: Option<GrpcRequestAuthentication>,
}

struct OuterPermitOwnedBody<B> {
    inner: B,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    runtime: Arc<GrpcRuntime>,
}

#[derive(Debug, Default)]
struct RequestStreamCancellationSignal {
    cancelled: AtomicBool,
    notify: Notify,
}

impl RequestStreamCancellationSignal {
    fn note_cancelled(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    async fn wait_cancelled(&self) {
        loop {
            let mut notified = Box::pin(self.notify.notified());
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.as_mut().await;
        }
    }
}

struct TrackedGrpcRequestBody {
    inner: TonicBody,
    cancellation: Arc<RequestStreamCancellationSignal>,
}

impl TrackedGrpcRequestBody {
    fn new(inner: TonicBody, cancellation: Arc<RequestStreamCancellationSignal>) -> Self {
        Self {
            inner,
            cancellation,
        }
    }
}

impl tonic::codegen::Body for TrackedGrpcRequestBody {
    type Data = tonic::codegen::Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Err(status))) = &poll {
            if status.code() == tonic::Code::Cancelled {
                self.cancellation.note_cancelled();
            }
        }
        poll
    }
}

impl<B> OuterPermitOwnedBody<B> {
    fn new(inner: B, permit: tokio::sync::OwnedSemaphorePermit, runtime: Arc<GrpcRuntime>) -> Self {
        Self {
            inner,
            permit: Some(permit),
            runtime,
        }
    }

    fn release_outer_request(&mut self) {
        if let Some(permit) = self.permit.take() {
            drop(permit);
            self.runtime.release_outer_request();
        }
    }
}

impl<B> Drop for OuterPermitOwnedBody<B> {
    fn drop(&mut self) {
        self.release_outer_request();
    }
}

impl<B> tonic::codegen::Body for OuterPermitOwnedBody<B>
where
    B: tonic::codegen::Body<Data = tonic::codegen::Bytes>,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        // SAFETY: projecting a pinned field without moving it.
        let poll = unsafe {
            self.as_mut()
                .map_unchecked_mut(|body| &mut body.inner)
                .poll_frame(cx)
        };
        match &poll {
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                // SAFETY: this does not move the pinned inner body.
                unsafe { self.as_mut().get_unchecked_mut() }.release_outer_request();
            }
            _ => {}
        }
        poll
    }
}

impl<S, ResBody> Service<http::Request<TonicBody>> for GrpcOuterRequestOwnerService<S>
where
    S: Service<http::Request<TonicBody>, Response = http::Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<tonic::codegen::StdError> + Send + 'static,
    ResBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    ResBody::Error: Into<tonic::codegen::StdError>,
{
    type Response = http::Response<TonicBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<http::Response<TonicBody>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<TonicBody>) -> Self::Future {
        let command = grpc_command_from_path(request.uri().path());
        if let Some(request_auth) = self.request_auth.as_ref() {
            if let Err(status) = request_auth.authorize(request.headers()) {
                record_grpc_prehandler_terminal(command, &status);
                return Box::pin(async move { Ok(status.into_http()) });
            }
        }
        let permit = match self.runtime.try_acquire_outer_request(command) {
            Ok(permit) => permit,
            Err(status) => {
                record_grpc_prehandler_terminal(command, &status);
                return Box::pin(async move { Ok(status.into_http()) });
            }
        };
        let cancellation = Arc::new(RequestStreamCancellationSignal::default());
        let mut request = request.map(|body| {
            boxed_tonic_body(TrackedGrpcRequestBody::new(body, Arc::clone(&cancellation)))
        });
        request.extensions_mut().insert(Arc::clone(&cancellation));
        let context = Arc::new(GrpcRequestContext::default());
        let future = self.inner.call(request);
        let runtime = Arc::clone(&self.runtime);
        Box::pin(async move {
            let result = GRPC_REQUEST_CONTEXT
                .scope(Arc::clone(&context), future)
                .await;
            match result {
                Ok(response) => {
                    if !context.handler_entered.load(Ordering::SeqCst) {
                        if let Some(status) = Status::from_header_map(response.headers()) {
                            let normalized = normalize_grpc_prehandler_status(&status);
                            record_grpc_prehandler_terminal(command, &normalized);
                            if normalized.code() != status.code() {
                                return Ok(normalized.into_http().map(|body| {
                                    boxed_tonic_body(OuterPermitOwnedBody::new(
                                        body,
                                        permit,
                                        Arc::clone(&runtime),
                                    ))
                                }));
                            }
                        }
                    }
                    Ok(response.map(|body| {
                        boxed_tonic_body(OuterPermitOwnedBody::new(
                            body,
                            permit,
                            Arc::clone(&runtime),
                        ))
                    }))
                }
                Err(error) => {
                    drop(permit);
                    runtime.release_outer_request();
                    Err(error)
                }
            }
        })
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub enum GrpcFault {
    ResponseWrite { command: crate::metrics::Command },
    InboundStreamError { code: tonic::Code },
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct ArmedGrpcFault {
    consumed: AtomicUsize,
}

#[cfg(test)]
impl ArmedGrpcFault {
    fn mark_consumed(&self) {
        self.consumed.fetch_add(1, Ordering::SeqCst);
    }

    pub fn assert_consumed_exactly_once(&self) {
        assert_eq!(
            self.consumed.load(Ordering::SeqCst),
            1,
            "gRPC fault must be consumed exactly once"
        );
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct GrpcStreamSafetyProbe {
    first_tenant: Mutex<Option<String>>,
    later_updates_applied: AtomicUsize,
}

#[cfg(test)]
impl GrpcStreamSafetyProbe {
    fn note_first_tenant(&self, tenant: &str) {
        let mut first = self
            .first_tenant
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if first.is_none() && !tenant.is_empty() {
            *first = Some(tenant.to_string());
        }
    }

    pub fn first_tenant(&self) -> Option<String> {
        self.first_tenant
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    pub fn later_tenant_or_rule_updates_applied(&self) -> usize {
        self.later_updates_applied.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct GrpcHandlerBarrier {
    entered: AtomicUsize,
    release_all: AtomicBool,
    notify: Notify,
}

#[cfg(test)]
impl GrpcHandlerBarrier {
    async fn enter(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_waiters();
        while !self.release_all.load(Ordering::SeqCst) {
            self.notify.notified().await;
        }
    }

    pub fn release_all(&self) {
        self.release_all.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub async fn wait_for_entered(&self, expected: usize, within: Duration) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let current = self.entered.load(Ordering::SeqCst);
            if current >= expected {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "gRPC handler barrier did not reach {expected}; current value is {current}"
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct GrpcTestControl {
    faults: Mutex<VecDeque<(GrpcFault, Arc<ArmedGrpcFault>)>>,
    handler_barriers: Mutex<HashMap<crate::metrics::Command, VecDeque<Arc<GrpcHandlerBarrier>>>>,
    stream_probe: Arc<GrpcStreamSafetyProbe>,
}

#[cfg(test)]
impl GrpcTestControl {
    pub fn arm_next(&self, fault: GrpcFault) -> Arc<ArmedGrpcFault> {
        let armed = Arc::new(ArmedGrpcFault::default());
        self.faults
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push_back((fault, Arc::clone(&armed)));
        armed
    }

    fn take_response_write_fault(
        &self,
        command: crate::metrics::Command,
    ) -> Option<Arc<ArmedGrpcFault>> {
        let mut faults = self
            .faults
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let index = faults.iter().position(|(fault, _)| {
            matches!(
                fault,
                GrpcFault::ResponseWrite {
                    command: armed_command
                } if *armed_command == command
            )
        })?;
        let (_, armed) = faults.remove(index)?;
        armed.mark_consumed();
        Some(armed)
    }

    fn take_inbound_stream_error(&self) -> Option<(tonic::Code, Arc<ArmedGrpcFault>)> {
        let mut faults = self
            .faults
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let index = faults
            .iter()
            .position(|(fault, _)| matches!(fault, GrpcFault::InboundStreamError { .. }))?;
        let (fault, armed) = faults.remove(index)?;
        if let GrpcFault::InboundStreamError { code } = fault {
            armed.mark_consumed();
            Some((code, armed))
        } else {
            None
        }
    }

    pub fn hold_next_n(
        &self,
        command: crate::metrics::Command,
        count: usize,
    ) -> Arc<GrpcHandlerBarrier> {
        let barrier = Arc::new(GrpcHandlerBarrier::default());
        let mut barriers = self
            .handler_barriers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let queue = barriers.entry(command).or_default();
        for _ in 0..count {
            queue.push_back(Arc::clone(&barrier));
        }
        barrier
    }

    async fn maybe_enter_handler(&self, command: crate::metrics::Command) {
        let barrier = self
            .handler_barriers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(&command)
            .and_then(VecDeque::pop_front);
        if let Some(barrier) = barrier {
            barrier.enter().await;
        }
    }

    pub fn stream_safety_probe(&self) -> Arc<GrpcStreamSafetyProbe> {
        Arc::clone(&self.stream_probe)
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct GrpcTestClockState {
    elapsed: Duration,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct GrpcTestClock {
    state: Mutex<GrpcTestClockState>,
    notify: Notify,
}

#[cfg(test)]
impl GrpcTestClock {
    fn paused() -> Self {
        Self::default()
    }

    fn advance(&self, duration: Duration) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.elapsed = state.elapsed.checked_add(duration).unwrap_or(Duration::MAX);
        drop(state);
        self.notify.notify_waiters();
    }

    async fn sleep(&self, duration: Duration) {
        let target = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .elapsed
            .checked_add(duration)
            .unwrap_or(Duration::MAX);
        loop {
            let mut notified = Box::pin(self.notify.notified());
            notified.as_mut().enable();
            if self
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .elapsed
                >= target
            {
                break;
            }
            notified.as_mut().await;
        }
    }
}

#[derive(Clone)]
struct GrpcRuntime {
    request_permits: Arc<Semaphore>,
    retained_body_permits: Arc<Semaphore>,
    ingress: Option<Arc<GrpcIngressProbe>>,
    limits: GrpcServerLimits,
}

impl GrpcRuntime {
    fn new(limits: GrpcServerLimits) -> Self {
        if let Some(ingress) = &limits.ingress_probe {
            ingress.set_global_predecode_byte_ceiling(
                limits
                    .max_global_requests
                    .saturating_mul(limits.max_decoding_message_bytes),
            );
        }
        Self {
            request_permits: Arc::new(Semaphore::new(limits.max_global_requests)),
            retained_body_permits: Arc::new(Semaphore::new(limits.max_retained_decoded_body_bytes)),
            ingress: limits.ingress_probe.clone(),
            limits,
        }
    }

    fn try_acquire_outer_request(
        &self,
        command: crate::metrics::Command,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        let permit = self
            .request_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                if let Some(ingress) = &self.ingress {
                    ingress.note_predecode_refusal();
                }
                Status::resource_exhausted("gRPC request budget exhausted")
            })?;
        if let Some(ingress) = &self.ingress {
            ingress.note_request_permit_acquired(command);
            ingress.note_predecode_bytes(
                self.limits
                    .max_decoding_message_bytes
                    .saturating_mul(self.current_active_requests()),
            );
        }
        Ok(permit)
    }

    fn release_outer_request(&self) {
        if let Some(ingress) = &self.ingress {
            ingress.note_request_permit_released();
        }
    }

    async fn with_request_budget<F, T>(
        &self,
        command: crate::metrics::Command,
        retained_body_bytes: usize,
        future: F,
    ) -> Result<T, Status>
    where
        F: Future<Output = Result<T, Status>>,
    {
        let outer_request_owned = GRPC_REQUEST_CONTEXT.try_with(|context| {
            context.handler_entered.store(true, Ordering::SeqCst);
            true
        });
        let retained = if retained_body_bytes == 0 {
            None
        } else {
            match self
                .retained_body_permits
                .clone()
                .try_acquire_many_owned(retained_body_bytes as u32)
            {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return Err(Status::resource_exhausted(
                        "gRPC retained body budget exhausted",
                    ));
                }
            }
        };
        if let Some(ingress) = &self.ingress {
            if outer_request_owned.is_err() {
                ingress.note_decode_without_request_permit(self.limits.max_decoding_message_bytes);
            }
            if retained_body_bytes > 0 {
                ingress.note_retained_decoded_body_acquired(command, retained_body_bytes);
            }
            if matches!(
                command,
                crate::metrics::Command::Quality | crate::metrics::Command::Classify
            ) {
                ingress.note_decoded_message(command);
            }
        }
        let result = future.await;
        drop(retained);
        if let Some(ingress) = &self.ingress {
            if retained_body_bytes > 0 {
                ingress.note_retained_decoded_body_released(retained_body_bytes);
            }
        }
        result
    }

    fn current_active_requests(&self) -> usize {
        self.limits
            .max_global_requests
            .saturating_sub(self.request_permits.available_permits())
    }

    async fn sleep(&self, duration: Duration) {
        #[cfg(test)]
        if let Some(clock) = &self.limits.test_clock {
            clock.sleep(duration).await;
            return;
        }
        tokio::time::sleep(duration).await;
    }
}

struct BoundedInferenceHandler {
    inner: Arc<GrpcState>,
    runtime: Arc<GrpcRuntime>,
    #[cfg(test)]
    control: Option<Arc<GrpcTestControl>>,
}

struct BoundedClassifierHandler {
    inner: Arc<GrpcState>,
    runtime: Arc<GrpcRuntime>,
    #[cfg(test)]
    control: Option<Arc<GrpcTestControl>>,
}

impl BoundedInferenceHandler {
    #[cfg(test)]
    async fn maybe_hold(&self, command: crate::metrics::Command) {
        if let Some(control) = &self.control {
            control.maybe_enter_handler(command).await;
        }
    }

    #[cfg(not(test))]
    async fn maybe_hold(&self, _command: crate::metrics::Command) {}

    #[cfg(test)]
    fn maybe_response_write_fault(&self, command: crate::metrics::Command) -> Result<(), Status> {
        if let Some(control) = &self.control {
            if control.take_response_write_fault(command).is_some() {
                return Err(Status::unavailable("synthetic response write failure"));
            }
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn maybe_response_write_fault(&self, _command: crate::metrics::Command) -> Result<(), Status> {
        Ok(())
    }
}

impl BoundedClassifierHandler {
    #[cfg(test)]
    async fn maybe_hold(&self, command: crate::metrics::Command) {
        if let Some(control) = &self.control {
            control.maybe_enter_handler(command).await;
        }
    }

    #[cfg(not(test))]
    async fn maybe_hold(&self, _command: crate::metrics::Command) {}

    #[cfg(test)]
    fn maybe_response_write_fault(&self, command: crate::metrics::Command) -> Result<(), Status> {
        if let Some(control) = &self.control {
            if control.take_response_write_fault(command).is_some() {
                return Err(Status::unavailable("synthetic response write failure"));
            }
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn maybe_response_write_fault(&self, _command: crate::metrics::Command) -> Result<(), Status> {
        Ok(())
    }
}

#[tonic::async_trait]
impl InferenceService for BoundedInferenceHandler {
    async fn classify(
        &self,
        request: Request<ClassifyRequest>,
    ) -> Result<Response<ClassifyResponse>, Status> {
        let outcome = crate::metrics::begin_outcome(
            crate::metrics::Transport::Grpc,
            crate::metrics::Command::Classify,
        );
        let retained = request.get_ref().text.len();
        let runtime = Arc::clone(&self.runtime);
        let result = self
            .runtime
            .with_request_budget(crate::metrics::Command::Classify, retained, async move {
                let handler = InferenceHandler(Arc::clone(&self.inner));
                let outcome = tokio::select! {
                    result = async {
                        self.maybe_hold(crate::metrics::Command::Classify).await;
                        handler.classify(request).await
                    } => result,
                    _ = runtime.sleep(runtime.limits.request_timeout) => Err(Status::deadline_exceeded("gRPC request timed out")),
                }?;
                self.maybe_response_write_fault(crate::metrics::Command::Classify)?;
                Ok(outcome)
            })
            .await;
        match result {
            Ok(response) => {
                outcome.success();
                Ok(response)
            }
            Err(status) => {
                let (stage, reason) =
                    grpc_status_terminal(crate::metrics::Command::Classify, &status);
                outcome.failure(stage, reason);
                Err(status)
            }
        }
    }

    async fn embed(
        &self,
        request: Request<EmbedRequest>,
    ) -> Result<Response<EmbedResponse>, Status> {
        let outcome = crate::metrics::begin_outcome(
            crate::metrics::Transport::Grpc,
            crate::metrics::Command::Embed,
        );
        let retained = request.get_ref().texts.iter().map(String::len).sum();
        let result = self
            .runtime
            .with_request_budget(crate::metrics::Command::Embed, retained, async {
                self.maybe_hold(crate::metrics::Command::Embed).await;
                let handler = InferenceHandler(Arc::clone(&self.inner));
                let outcome = handler.embed(request).await?;
                self.maybe_response_write_fault(crate::metrics::Command::Embed)?;
                Ok(outcome)
            })
            .await;
        match result {
            Ok(response) => {
                outcome.success();
                Ok(response)
            }
            Err(status) => {
                let (stage, reason) = grpc_status_terminal(crate::metrics::Command::Embed, &status);
                outcome.failure(stage, reason);
                Err(status)
            }
        }
    }

    async fn compress(
        &self,
        request: Request<CompressRequest>,
    ) -> Result<Response<CompressResponse>, Status> {
        let outcome = crate::metrics::begin_outcome(
            crate::metrics::Transport::Grpc,
            crate::metrics::Command::Compress,
        );
        let result = self
            .runtime
            .with_request_budget(
                crate::metrics::Command::Compress,
                request.get_ref().text.len(),
                async {
                    self.maybe_hold(crate::metrics::Command::Compress).await;
                    let handler = InferenceHandler(Arc::clone(&self.inner));
                    let outcome = handler.compress(request).await?;
                    self.maybe_response_write_fault(crate::metrics::Command::Compress)?;
                    Ok(outcome)
                },
            )
            .await;
        match result {
            Ok(response) => {
                outcome.success();
                Ok(response)
            }
            Err(status) => {
                let (stage, reason) =
                    grpc_status_terminal(crate::metrics::Command::Compress, &status);
                outcome.failure(stage, reason);
                Err(status)
            }
        }
    }

    async fn model_info(
        &self,
        request: Request<ModelInfoRequest>,
    ) -> Result<Response<ModelInfoResponse>, Status> {
        let outcome = crate::metrics::begin_outcome(
            crate::metrics::Transport::Grpc,
            crate::metrics::Command::ModelInfo,
        );
        let result = self
            .runtime
            .with_request_budget(crate::metrics::Command::ModelInfo, 0, async {
                self.maybe_hold(crate::metrics::Command::ModelInfo).await;
                let handler = InferenceHandler(Arc::clone(&self.inner));
                let outcome = handler.model_info(request).await?;
                self.maybe_response_write_fault(crate::metrics::Command::ModelInfo)?;
                Ok(outcome)
            })
            .await;
        match result {
            Ok(response) => {
                outcome.success();
                Ok(response)
            }
            Err(status) => {
                let (stage, reason) =
                    grpc_status_terminal(crate::metrics::Command::ModelInfo, &status);
                outcome.failure(stage, reason);
                Err(status)
            }
        }
    }

    async fn version(
        &self,
        request: Request<VersionRequest>,
    ) -> Result<Response<VersionResponse>, Status> {
        let outcome = crate::metrics::begin_outcome(
            crate::metrics::Transport::Grpc,
            crate::metrics::Command::Version,
        );
        let result = self
            .runtime
            .with_request_budget(crate::metrics::Command::Version, 0, async {
                self.maybe_hold(crate::metrics::Command::Version).await;
                let handler = InferenceHandler(Arc::clone(&self.inner));
                let outcome = handler.version(request).await?;
                self.maybe_response_write_fault(crate::metrics::Command::Version)?;
                Ok(outcome)
            })
            .await;
        match result {
            Ok(response) => {
                outcome.success();
                Ok(response)
            }
            Err(status) => {
                let (stage, reason) =
                    grpc_status_terminal(crate::metrics::Command::Version, &status);
                outcome.failure(stage, reason);
                Err(status)
            }
        }
    }
}

#[tonic::async_trait]
impl ClassifierService for BoundedClassifierHandler {
    async fn quality(
        &self,
        request: Request<QualityRequest>,
    ) -> Result<Response<QualityResponse>, Status> {
        let outcome = crate::metrics::begin_outcome(
            crate::metrics::Transport::Grpc,
            crate::metrics::Command::Quality,
        );
        let retained = request.get_ref().text.len();
        let runtime = Arc::clone(&self.runtime);
        let result = self
            .runtime
            .with_request_budget(crate::metrics::Command::Quality, retained, async move {
                let handler = ClassifierHandler(Arc::clone(&self.inner));
                let outcome = tokio::select! {
                    result = async {
                        self.maybe_hold(crate::metrics::Command::Quality).await;
                        handler.quality(request).await
                    } => result,
                    _ = runtime.sleep(runtime.limits.request_timeout) => Err(Status::deadline_exceeded("gRPC request timed out")),
                }?;
                self.maybe_response_write_fault(crate::metrics::Command::Quality)?;
                Ok(outcome)
            })
            .await;
        match result {
            Ok(response) => {
                outcome.success();
                Ok(response)
            }
            Err(status) => {
                let (stage, reason) =
                    grpc_status_terminal(crate::metrics::Command::Quality, &status);
                outcome.failure(stage, reason);
                Err(status)
            }
        }
    }

    type StreamSafetyStream = SafetyStream;

    async fn stream_safety(
        &self,
        request: Request<Streaming<SafetyToken>>,
    ) -> Result<Response<Self::StreamSafetyStream>, Status> {
        let result = self
            .runtime
            .with_request_budget(crate::metrics::Command::StreamSafety, 0, async {
                self.maybe_hold(crate::metrics::Command::StreamSafety).await;
                #[cfg(test)]
                if let Some(control) = &self.control {
                    if control
                        .take_response_write_fault(crate::metrics::Command::StreamSafety)
                        .is_some()
                    {
                        let outcome = crate::metrics::begin_outcome(
                            crate::metrics::Transport::Grpc,
                            crate::metrics::Command::StreamSafety,
                        );
                        outcome.failure(crate::metrics::Stage::Write, crate::metrics::Reason::Io);
                        let stream: SafetyStream =
                            Box::pin(tokio_stream::once(Result::<SafetyVerdict, Status>::Err(
                                Status::unavailable("synthetic response write failure"),
                            )));
                        return Ok(Response::new(stream));
                    }
                }
                let lease = self.inner.admission.acquire("stream_safety").await?;
                let request_cancelled = request
                    .extensions()
                    .get::<Arc<RequestStreamCancellationSignal>>()
                    .cloned();
                let inbound = request.into_inner();
                let (tx, rx) = tokio::sync::mpsc::channel(16);
                let (terminal_tx, terminal_rx) = tokio::sync::mpsc::unbounded_channel();
                let admission = self.inner.admission.clone();
                #[cfg(test)]
                let control = self.control.clone();
                tokio::spawn(async move {
                    let outcome = crate::metrics::begin_outcome(
                        crate::metrics::Transport::Grpc,
                        crate::metrics::Command::StreamSafety,
                    );
                    let result = admission
                        .run_with_lease("stream_safety", lease, async move {
                            let normalized = NormalizedSafetyStream::new(
                                inbound,
                                #[cfg(test)]
                                control,
                            );
                            run_stream_safety(normalized, tx, request_cancelled).await
                        })
                        .await;
                    match result {
                        Ok(()) => outcome.success(),
                        Err(status) => {
                            let (stage, reason) = grpc_status_terminal(
                                crate::metrics::Command::StreamSafety,
                                &status,
                            );
                            outcome.failure(stage, reason);
                            let _ = terminal_tx.send(Err(status));
                        }
                    }
                });
                let stream: SafetyStream = Box::pin(ReceiverStream::new(rx).chain(
                    tokio_stream::wrappers::UnboundedReceiverStream::new(terminal_rx),
                ));
                Ok(Response::new(stream))
            })
            .await;
        match result {
            Ok(response) => Ok(response),
            Err(status) => {
                let outcome = crate::metrics::begin_outcome(
                    crate::metrics::Transport::Grpc,
                    crate::metrics::Command::StreamSafety,
                );
                let (stage, reason) =
                    grpc_status_terminal(crate::metrics::Command::StreamSafety, &status);
                outcome.failure(stage, reason);
                Err(status)
            }
        }
    }
}

struct NormalizedSafetyStream<S> {
    inner: S,
    first_message_seen: bool,
    #[cfg(test)]
    control: Option<Arc<GrpcTestControl>>,
}

impl<S> NormalizedSafetyStream<S> {
    fn new(inner: S, #[cfg(test)] control: Option<Arc<GrpcTestControl>>) -> Self {
        Self {
            inner,
            first_message_seen: false,
            #[cfg(test)]
            control,
        }
    }
}

impl<S> Stream for NormalizedSafetyStream<S>
where
    S: Stream<Item = Result<SafetyToken, Status>> + Unpin,
{
    type Item = Result<SafetyToken, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        #[cfg(test)]
        if let Some(control) = self.control.as_ref() {
            if let Some((code, _armed)) = control.take_inbound_stream_error() {
                return Poll::Ready(Some(Err(Status::new(
                    code,
                    "synthetic inbound stream error",
                ))));
            }
        }
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(mut token))) => {
                #[cfg(test)]
                if let Some(control) = self.control.as_ref() {
                    let probe = control.stream_safety_probe();
                    if !self.first_message_seen {
                        probe.note_first_tenant(&token.tenant);
                    }
                }
                if self.first_message_seen {
                    token.tenant.clear();
                    token.rules.clear();
                } else {
                    self.first_message_seen = true;
                }
                Poll::Ready(Some(Ok(token)))
            }
            other => other,
        }
    }
}

#[derive(Debug, Default)]
struct ConnectionLifecycle {
    saw_activity: AtomicBool,
    activity_generation: AtomicU64,
    activity_notify: Notify,
    closed: AtomicBool,
    closed_notify: Notify,
}

impl ConnectionLifecycle {
    fn note_activity(&self) {
        self.saw_activity.store(true, Ordering::SeqCst);
        self.activity_generation.fetch_add(1, Ordering::SeqCst);
        self.activity_notify.notify_waiters();
    }

    fn saw_activity(&self) -> bool {
        self.saw_activity.load(Ordering::SeqCst)
    }

    fn activity_generation(&self) -> u64 {
        self.activity_generation.load(Ordering::SeqCst)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn note_closed(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.activity_notify.notify_waiters();
        self.closed_notify.notify_waiters();
    }
}

struct TrackedGrpcStream {
    inner: tokio::net::TcpStream,
    lifecycle: Arc<ConnectionLifecycle>,
}

impl Drop for TrackedGrpcStream {
    fn drop(&mut self) {
        self.lifecycle.note_closed();
    }
}

impl Connected for TrackedGrpcStream {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        TcpConnectInfo {
            local_addr: self.inner.local_addr().ok(),
            remote_addr: self.inner.peer_addr().ok(),
        }
    }
}

impl AsyncRead for TrackedGrpcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.lifecycle.is_closed() {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            if buf.filled().len() > before {
                this.lifecycle.note_activity();
            }
        }
        poll
    }
}

impl AsyncWrite for TrackedGrpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.lifecycle.is_closed() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "gRPC connection closed by lifecycle owner",
            )));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.lifecycle.is_closed() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "gRPC connection closed by lifecycle owner",
            )));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.lifecycle.is_closed() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

struct SingleConnectionIncoming {
    stream: Option<TrackedGrpcStream>,
    wait_closed: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl Stream for SingleConnectionIncoming {
    type Item = Result<TrackedGrpcStream, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(stream) = self.stream.take() {
            let lifecycle = Arc::clone(&stream.lifecycle);
            self.wait_closed = Some(Box::pin(async move {
                lifecycle.closed_notify.notified().await;
            }));
            return Poll::Ready(Some(Ok(stream)));
        }
        if let Some(wait_closed) = self.wait_closed.as_mut() {
            if wait_closed.as_mut().poll(cx).is_ready() {
                self.wait_closed = None;
                return Poll::Ready(None);
            }
        }
        Poll::Pending
    }
}

fn collect_grpc_child_result(
    exit: &mut GrpcListenerExitReport,
    joined: Result<Result<(), GrpcConnectionChildError>, tokio::task::JoinError>,
    owner_deadline_enforced: bool,
) -> Option<GrpcListenerFailure> {
    exit.connection_children_finished += 1;
    exit.connection_child_results_collected += 1;
    match joined {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(GrpcListenerFailure::connection_child(error)),
        Err(join) if join.is_cancelled() && !owner_deadline_enforced => {
            Some(GrpcListenerFailure::connection_child_cancelled(join))
        }
        Err(join) if join.is_panic() => {
            exit.connection_child_panics += 1;
            Some(GrpcListenerFailure::connection_child_panic(join))
        }
        Err(_join) => None,
    }
}

fn listener_cleanup_deadline(
    cleanup: &Arc<GrpcListenerCleanupProbe>,
    trigger_failure_cleanup: bool,
) -> tokio::time::Instant {
    let deadline = tokio::time::Instant::now() + GRPC_LISTENER_FAILURE_CLEANUP_TIMEOUT;
    if cleanup.shutdown_deadline().is_none() && trigger_failure_cleanup {
        cleanup.request_graceful_shutdown_before(deadline);
    }
    cleanup.shutdown_deadline().unwrap_or(deadline)
}

async fn finalize_grpc_listener(
    mut children: tokio::task::JoinSet<Result<(), GrpcConnectionChildError>>,
    mut exit: GrpcListenerExitReport,
    cleanup: Arc<GrpcListenerCleanupProbe>,
    mut primary_failure: Option<GrpcListenerFailure>,
) -> Result<GrpcListenerExitReport, GrpcListenerError> {
    let fallback_collection_deadline =
        listener_cleanup_deadline(&cleanup, primary_failure.is_some());
    let mut cleanup_deadline_elapsed = false;
    let mut owner_deadline_enforced = false;
    while exit.connection_child_results_collected < exit.connection_children_spawned {
        let observed_deadline_id = cleanup.shutdown_deadline_id();
        let collection_deadline = cleanup
            .shutdown_deadline()
            .unwrap_or(fallback_collection_deadline);
        let mut deadline_sleep = Box::pin(tokio::time::sleep_until(collection_deadline));
        let mut deadline_change = Box::pin(cleanup.wait_for_deadline_change(observed_deadline_id));
        tokio::select! {
            joined = children.join_next() => {
                let Some(joined) = joined else {
                    break;
                };
                if primary_failure.is_none() {
                    primary_failure =
                        collect_grpc_child_result(&mut exit, joined, owner_deadline_enforced);
                } else {
                    let _ = collect_grpc_child_result(&mut exit, joined, owner_deadline_enforced);
                }
            }
            _ = deadline_change.as_mut() => {
                continue;
            }
            _ = deadline_sleep.as_mut() => {
                cleanup_deadline_elapsed = true;
                owner_deadline_enforced = true;
                children.abort_all();
                while let Some(joined) = children.join_next().await {
                    if primary_failure.is_none() {
                        primary_failure =
                            collect_grpc_child_result(&mut exit, joined, owner_deadline_enforced);
                    } else {
                        let _ =
                            collect_grpc_child_result(&mut exit, joined, owner_deadline_enforced);
                    }
                }
                if primary_failure.is_none() {
                    primary_failure = Some(GrpcListenerFailure::cleanup_deadline_elapsed());
                }
                break;
            }
        }
    }
    exit.collection_deadline_id = cleanup.shutdown_deadline_id();
    if let Err(error) = exit.assert_quiescent_at_return() {
        return Err(
            GrpcListenerFailure::invariant(error).into_error(exit, cleanup_deadline_elapsed)
        );
    }
    if let Some(failure) = primary_failure {
        return Err(failure.into_error(exit, cleanup_deadline_elapsed));
    }
    Ok(exit)
}

pub(crate) async fn serve_on(
    listener: tokio::net::TcpListener,
    state: Arc<GrpcState>,
    limits: GrpcServerLimits,
) -> Result<GrpcListenerExitReport, GrpcListenerError> {
    let cleanup = limits
        .cleanup_probe
        .clone()
        .unwrap_or_else(|| Arc::new(GrpcListenerCleanupProbe::default()));
    let limits = limits.with_cleanup_probe(Arc::clone(&cleanup));
    let runtime = Arc::new(GrpcRuntime::new(limits.clone()));
    let connection_slots = Arc::new(Semaphore::new(limits.max_connections));
    let mut children = tokio::task::JoinSet::new();
    let mut exit = GrpcListenerExitReport::default();
    let mut first_error: Option<GrpcListenerFailure> = None;
    loop {
        while let Some(joined) = children.try_join_next() {
            if first_error.is_none() {
                first_error = collect_grpc_child_result(&mut exit, joined, false);
            } else {
                let _ = collect_grpc_child_result(&mut exit, joined, false);
            }
        }
        if first_error.is_some() {
            break;
        }
        let accepted = if children.is_empty() {
            tokio::select! {
                _ = cleanup.wait_for_shutdown() => None,
                accepted = listener.accept() => Some(accepted),
            }
        } else {
            tokio::select! {
                joined = children.join_next() => {
                    if let Some(joined) = joined {
                        if first_error.is_none() {
                            first_error = collect_grpc_child_result(&mut exit, joined, false);
                        } else {
                            let _ = collect_grpc_child_result(&mut exit, joined, false);
                        }
                    }
                    continue;
                }
                _ = cleanup.wait_for_shutdown() => None,
                accepted = listener.accept() => Some(accepted),
            }
        };
        let Some(accepted) = accepted else {
            break;
        };
        let (stream, _peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                first_error = Some(GrpcListenerFailure::accept(error));
                break;
            }
        };
        let permit = match Arc::clone(&connection_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                if let Some(ingress) = &limits.ingress_probe {
                    ingress.note_refused_connection();
                }
                let outcome = crate::metrics::begin_outcome(
                    crate::metrics::Transport::Grpc,
                    crate::metrics::Command::Unknown,
                );
                outcome.failure(
                    crate::metrics::Stage::Admission,
                    crate::metrics::Reason::ResourceLimit,
                );
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        if let Some(ingress) = &limits.ingress_probe {
            ingress.increment_active_connections();
        }
        let state = Arc::clone(&state);
        let runtime = Arc::clone(&runtime);
        let child_limits = limits.clone();
        children.spawn(async move {
            let _permit = permit;
            let lifecycle = Arc::new(ConnectionLifecycle::default());
            let incoming = SingleConnectionIncoming {
                stream: Some(TrackedGrpcStream {
                    inner: stream,
                    lifecycle: Arc::clone(&lifecycle),
                }),
                wait_closed: None,
            };
            let inference = InferenceServiceServer::new(BoundedInferenceHandler {
                inner: Arc::clone(&state),
                runtime: Arc::clone(&runtime),
                #[cfg(test)]
                control: child_limits.test_control.clone(),
            })
            .max_decoding_message_size(child_limits.max_decoding_message_bytes)
            .max_encoding_message_size(child_limits.max_decoding_message_bytes);
            let classifier = ClassifierServiceServer::new(BoundedClassifierHandler {
                inner: state,
                runtime: Arc::clone(&runtime),
                #[cfg(test)]
                control: child_limits.test_control.clone(),
            })
            .max_decoding_message_size(child_limits.max_decoding_message_bytes)
            .max_encoding_message_size(child_limits.max_decoding_message_bytes);
            let server = Server::builder()
                .layer(tower::load_shed::LoadShedLayer::new())
                .concurrency_limit_per_connection(
                    child_limits.max_concurrent_streams_per_connection,
                )
                .timeout(child_limits.request_timeout)
                .initial_stream_window_size(child_limits.initial_stream_window_bytes as u32)
                .initial_connection_window_size(child_limits.initial_connection_window_bytes as u32)
                .max_concurrent_streams(child_limits.max_concurrent_streams_per_connection as u32)
                .max_connection_age(child_limits.max_connection_age)
                .http2_keepalive_timeout(Some(Duration::from_secs(20)));
            let server = match child_limits.tls_config.clone() {
                Some(tls_config) => match server.tls_config(tls_config) {
                    Ok(server) => server,
                    Err(error) => return Err::<(), GrpcConnectionChildError>(Box::new(error)),
                },
                None => server,
            }
            .layer(GrpcOuterRequestOwnerLayer::new(
                Arc::clone(&runtime),
                child_limits.request_auth.clone(),
            ))
            .add_service(inference)
            .add_service(classifier);
            let shutdown = connection_shutdown_signal(
                child_limits.clone(),
                child_limits
                    .ingress_probe
                    .clone()
                    .unwrap_or_else(|| Arc::new(GrpcIngressProbe::default())),
                lifecycle,
            );
            let result = server
                .serve_with_incoming_shutdown(incoming, shutdown)
                .await;
            if let Some(ingress) = &child_limits.ingress_probe {
                ingress.decrement_active_connections();
            }
            result.map_err(|error| -> GrpcConnectionChildError { Box::new(error) })
        });
        exit.connection_children_spawned += 1;
    }
    finalize_grpc_listener(children, exit, cleanup, first_error).await
}

fn connection_shutdown_signal(
    limits: GrpcServerLimits,
    ingress: Arc<GrpcIngressProbe>,
    lifecycle: Arc<ConnectionLifecycle>,
) -> impl Future<Output = ()> + Send + 'static {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WaitResult {
        Activity,
        Closed,
        Cleanup,
        TimedOut,
    }

    fn connection_sleep(
        limits: &GrpcServerLimits,
        duration: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        #[cfg(test)]
        if let Some(clock) = &limits.test_clock {
            let clock = Arc::clone(clock);
            return Box::pin(async move {
                clock.sleep(duration).await;
            });
        }
        #[cfg(not(test))]
        let _ = limits;
        Box::pin(tokio::time::sleep(duration))
    }

    async fn wait_for_connection_event(
        limits: &GrpcServerLimits,
        lifecycle: &Arc<ConnectionLifecycle>,
        activity_generation: u64,
        duration: Duration,
    ) -> WaitResult {
        loop {
            let mut timer = connection_sleep(limits, duration);
            let mut activity = Box::pin(lifecycle.activity_notify.notified());
            let mut closed = Box::pin(lifecycle.closed_notify.notified());
            activity.as_mut().enable();
            closed.as_mut().enable();
            if lifecycle.is_closed() {
                return WaitResult::Closed;
            }
            if lifecycle.activity_generation() != activity_generation {
                return WaitResult::Activity;
            }
            if let Some(cleanup) = &limits.cleanup_probe {
                tokio::select! {
                    _ = timer.as_mut() => return WaitResult::TimedOut,
                    _ = activity.as_mut() => {}
                    _ = closed.as_mut() => return WaitResult::Closed,
                    _ = cleanup.wait_for_shutdown() => return WaitResult::Cleanup,
                }
            } else {
                tokio::select! {
                    _ = timer.as_mut() => return WaitResult::TimedOut,
                    _ = activity.as_mut() => {}
                    _ = closed.as_mut() => return WaitResult::Closed,
                }
            }
        }
    }

    async move {
        if !lifecycle.saw_activity() {
            match wait_for_connection_event(
                &limits,
                &lifecycle,
                lifecycle.activity_generation(),
                limits.handshake_timeout,
            )
            .await
            {
                WaitResult::Activity => {}
                WaitResult::Closed | WaitResult::Cleanup => return,
                WaitResult::TimedOut => {
                    lifecycle.note_closed();
                    ingress.note_expired_handshake();
                    let outcome = crate::metrics::begin_outcome(
                        crate::metrics::Transport::Grpc,
                        crate::metrics::Command::Unknown,
                    );
                    outcome.failure(
                        crate::metrics::Stage::Read,
                        crate::metrics::Reason::Deadline,
                    );
                    return;
                }
            }
        }

        let mut max_age = connection_sleep(&limits, limits.max_connection_age);
        loop {
            let activity_generation = lifecycle.activity_generation();
            let mut idle = connection_sleep(&limits, limits.idle_timeout);
            let mut activity = Box::pin(lifecycle.activity_notify.notified());
            let mut closed = Box::pin(lifecycle.closed_notify.notified());
            activity.as_mut().enable();
            closed.as_mut().enable();
            if lifecycle.is_closed() {
                return;
            }
            if lifecycle.activity_generation() != activity_generation {
                continue;
            }
            if let Some(cleanup) = &limits.cleanup_probe {
                tokio::select! {
                    _ = max_age.as_mut() => {
                        lifecycle.note_closed();
                        ingress.note_max_age_expiration();
                        let outcome = crate::metrics::begin_outcome(
                            crate::metrics::Transport::Grpc,
                            crate::metrics::Command::Unknown,
                        );
                        outcome.failure(
                            crate::metrics::Stage::Read,
                            crate::metrics::Reason::Deadline,
                        );
                        return;
                    }
                    _ = idle.as_mut() => {
                        lifecycle.note_closed();
                        ingress.note_expired_idle_connection();
                        let outcome = crate::metrics::begin_outcome(
                            crate::metrics::Transport::Grpc,
                            crate::metrics::Command::Unknown,
                        );
                        outcome.failure(
                            crate::metrics::Stage::Read,
                            crate::metrics::Reason::Deadline,
                        );
                        return;
                    }
                    _ = activity.as_mut() => continue,
                    _ = closed.as_mut() => return,
                    _ = cleanup.wait_for_shutdown() => return,
                }
            } else {
                tokio::select! {
                    _ = max_age.as_mut() => {
                        lifecycle.note_closed();
                        ingress.note_max_age_expiration();
                        let outcome = crate::metrics::begin_outcome(
                            crate::metrics::Transport::Grpc,
                            crate::metrics::Command::Unknown,
                        );
                        outcome.failure(
                            crate::metrics::Stage::Read,
                            crate::metrics::Reason::Deadline,
                        );
                        return;
                    }
                    _ = idle.as_mut() => {
                        lifecycle.note_closed();
                        ingress.note_expired_idle_connection();
                        let outcome = crate::metrics::begin_outcome(
                            crate::metrics::Transport::Grpc,
                            crate::metrics::Command::Unknown,
                        );
                        outcome.failure(
                            crate::metrics::Stage::Read,
                            crate::metrics::Reason::Deadline,
                        );
                        return;
                    }
                    _ = activity.as_mut() => continue,
                    _ = closed.as_mut() => return,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_classifier_proto::{ClassifierServiceClient, InferenceServiceClient};

    const EXTERNAL_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

    struct TestGrpcServer {
        endpoint: String,
        address: std::net::SocketAddr,
        task: tokio::task::JoinHandle<Result<GrpcListenerExitReport, GrpcListenerError>>,
        cleanup: Arc<GrpcListenerCleanupProbe>,
    }

    struct ReleaseGrpcHandlersOnDrop<'a>(Vec<&'a GrpcHandlerBarrier>);

    impl Drop for ReleaseGrpcHandlersOnDrop<'_> {
        fn drop(&mut self) {
            for barrier in &self.0 {
                barrier.release_all();
            }
        }
    }

    async fn spawn_real_tonic(state: Arc<GrpcState>) -> TestGrpcServer {
        spawn_real_tonic_with_limits(state, GrpcServerLimits::test_defaults()).await
    }

    async fn spawn_real_tonic_with_limits(
        state: Arc<GrpcState>,
        limits: GrpcServerLimits,
    ) -> TestGrpcServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cleanup = Arc::new(GrpcListenerCleanupProbe::default());
        let limits = limits.with_cleanup_probe(Arc::clone(&cleanup));
        let task = tokio::spawn(async move { serve_on(listener, state, limits).await });
        TestGrpcServer {
            endpoint: format!("http://{address}"),
            address,
            task,
            cleanup,
        }
    }

    async fn bounded_external<T>(
        operation: &'static str,
        future: impl std::future::Future<Output = T>,
    ) -> T {
        tokio::time::timeout(EXTERNAL_WAIT, future)
            .await
            .unwrap_or_else(|_| panic!("external Tonic test wait timed out: {operation}"))
    }

    struct PendingStreamSafetyReset {
        request_body: Option<h2::SendStream<tonic::codegen::Bytes>>,
        response_body: Option<h2::RecvStream>,
        connection_task: tokio::task::JoinHandle<Result<(), h2::Error>>,
    }

    impl PendingStreamSafetyReset {
        async fn close_and_join(
            mut self,
            within: std::time::Duration,
        ) -> Result<(), anyhow::Error> {
            drop(self.response_body.take());
            drop(self.request_body.take());
            match tokio::time::timeout(within, &mut self.connection_task).await {
                Ok(joined) => match joined {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(anyhow::Error::new(error)),
                    Err(error) => Err(anyhow::Error::new(error)),
                },
                Err(_) => {
                    self.connection_task.abort();
                    match self.connection_task.await {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(error)) => Err(anyhow::Error::new(error)),
                        Err(error) if error.is_cancelled() => Ok(()),
                        Err(error) => Err(anyhow::Error::new(error)),
                    }
                }
            }
        }
    }

    async fn reset_stream_safety_after_first_verdict(
        address: std::net::SocketAddr,
    ) -> PendingStreamSafetyReset {
        use prost::Message as _;

        let stream = bounded_external(
            "explicit-cancellation H2 connect",
            tokio::net::TcpStream::connect(address),
        )
        .await
        .expect("explicit-cancellation H2 socket connects");
        let (send_request, connection) = bounded_external(
            "explicit-cancellation H2 handshake",
            h2::client::handshake(stream),
        )
        .await
        .expect("explicit-cancellation H2 handshake succeeds");
        let connection_task = tokio::spawn(connection);
        let mut send_request = bounded_external(
            "explicit-cancellation H2 request readiness",
            send_request.ready(),
        )
        .await
        .expect("explicit-cancellation H2 request becomes ready");
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://localhost/sbproxy.classifier.v1.ClassifierService/StreamSafety")
            .version(http::Version::HTTP_2)
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .header("te", "trailers")
            .body(())
            .expect("explicit-cancellation H2 request is valid");
        let (response, mut request_body) = send_request
            .send_request(request, false)
            .expect("explicit-cancellation H2 request starts");

        let message = SafetyToken {
            tenant: String::new(),
            rules: vec![],
            token: "safe".to_string(),
        }
        .encode_to_vec();
        let mut grpc_frame = Vec::with_capacity(5 + message.len());
        grpc_frame.push(0);
        grpc_frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
        grpc_frame.extend_from_slice(&message);
        request_body
            .send_data(tonic::codegen::Bytes::from(grpc_frame), false)
            .expect("bounded explicit-cancellation gRPC message sends");

        let response = bounded_external("explicit-cancellation response headers", response)
            .await
            .expect("explicit-cancellation response starts");
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut response_body = response.into_body();
        let first = bounded_external("explicit-cancellation first verdict", response_body.data())
            .await
            .expect("explicit-cancellation response contains a verdict")
            .expect("explicit-cancellation verdict frame is readable");
        assert!(
            first.len() >= 5 && first.len() <= 1024,
            "the first gRPC verdict stays inside its bounded wire envelope"
        );
        response_body
            .flow_control()
            .release_capacity(first.len())
            .expect("explicit-cancellation response capacity releases");

        // A high-level Tonic response drop does not send RST_STREAM while the
        // request body is still open. Send the protocol cancellation
        // explicitly so this case proves the server's real cancellation path
        // rather than racing a clean request EOF.
        request_body.send_reset(h2::Reason::CANCEL);
        drop(send_request);
        PendingStreamSafetyReset {
            request_body: Some(request_body),
            response_body: Some(response_body),
            connection_task,
        }
    }

    async fn bounded_stream_terminal_error(
        operation: &'static str,
        stream: &mut tonic::Streaming<SafetyVerdict>,
        max_messages: usize,
    ) -> tonic::Status {
        bounded_stream_terminal_error_within(operation, stream, max_messages, EXTERNAL_WAIT).await
    }

    async fn bounded_stream_terminal_error_within(
        operation: &'static str,
        stream: &mut tonic::Streaming<SafetyVerdict>,
        max_messages: usize,
        within: std::time::Duration,
    ) -> tonic::Status {
        let deadline = tokio::time::Instant::now() + within;
        for _ in 0..max_messages {
            match tokio::time::timeout_at(deadline, stream.message())
                .await
                .unwrap_or_else(|_| panic!("stream terminal deadline expired: {operation}"))
            {
                Ok(Some(_)) => {}
                Ok(None) => panic!("stream became clean EOF: {operation}"),
                Err(status) => return status,
            }
        }
        panic!("stream exceeded its {max_messages}-message test ceiling: {operation}")
    }

    #[derive(Debug, Default)]
    struct TruncatedUnaryBody;

    impl prost::Message for TruncatedUnaryBody {
        fn encode_raw(&self, buffer: &mut impl prost::bytes::BufMut) {
            // Field one, length-delimited, followed by an unterminated
            // varint.  The gRPC envelope itself is valid, so this reaches
            // the generated service's protobuf decoder rather than failing
            // in the client or HTTP/2 framing layer.
            buffer.put_slice(&[0x0a, 0x80]);
        }

        fn merge_field(
            &mut self,
            _tag: u32,
            _wire_type: prost::encoding::WireType,
            _buffer: &mut impl prost::bytes::Buf,
            _context: prost::encoding::DecodeContext,
        ) -> Result<(), prost::DecodeError> {
            Err(prost::DecodeError::new(
                "TruncatedUnaryBody is an encode-only test message",
            ))
        }

        fn encoded_len(&self) -> usize {
            2
        }

        fn clear(&mut self) {}
    }

    fn quality_request_with_encoded_len(target: usize) -> QualityRequest {
        use prost::Message as _;

        let mut request = QualityRequest {
            tenant: String::new(),
            text: "x".repeat(target),
        };
        for _ in 0..8 {
            let actual = request.encoded_len();
            match actual.cmp(&target) {
                std::cmp::Ordering::Equal => return request,
                std::cmp::Ordering::Greater => {
                    request
                        .text
                        .truncate(request.text.len() - (actual - target));
                }
                std::cmp::Ordering::Less => {
                    request.text.push_str(&"x".repeat(target - actual));
                }
            }
        }
        panic!("quality request sizing did not converge within eight bounded adjustments")
    }

    fn classify_request_with_encoded_len(target: usize) -> ClassifyRequest {
        use prost::Message as _;

        let mut request = ClassifyRequest {
            model: String::new(),
            text: "x".repeat(target),
            top_k: 0,
        };
        for _ in 0..8 {
            let actual = request.encoded_len();
            match actual.cmp(&target) {
                std::cmp::Ordering::Equal => return request,
                std::cmp::Ordering::Greater => {
                    request
                        .text
                        .truncate(request.text.len() - (actual - target));
                }
                std::cmp::Ordering::Less => {
                    request.text.push_str(&"x".repeat(target - actual));
                }
            }
        }
        panic!("classify request sizing did not converge within eight bounded adjustments")
    }

    fn embed_request_exceeding_total_budget_below_decode_ceiling(model: &str) -> EmbedRequest {
        use prost::Message as _;

        let text_len = (MAX_EMBED_TOTAL_BYTES / MAX_EMBED_ITEMS) + 1;
        let request = EmbedRequest {
            model: model.to_string(),
            texts: vec!["x".repeat(text_len); MAX_EMBED_ITEMS],
        };
        assert!(
            request.texts.iter().map(|text| text.len()).sum::<usize>() > MAX_EMBED_TOTAL_BYTES,
            "fixture must exceed the application aggregate embed budget",
        );
        assert!(
            request.encoded_len() < DEFAULT_MAX_DECODING_MESSAGE_BYTES,
            "fixture must stay below the generated decode ceiling",
        );
        request
    }

    async fn inference_client(
        endpoint: String,
    ) -> InferenceServiceClient<tonic::transport::Channel> {
        bounded_external(
            "connect InferenceService client",
            InferenceServiceClient::connect(endpoint),
        )
        .await
        .unwrap()
    }

    async fn classifier_client(
        endpoint: String,
    ) -> ClassifierServiceClient<tonic::transport::Channel> {
        bounded_external(
            "connect ClassifierService client",
            ClassifierServiceClient::connect(endpoint),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn production_tonic_bearer_auth_rejects_before_handler_entry_and_redacts_debug() {
        let controls = Arc::new(GrpcTestControl::default());
        let barrier = controls.hold_next_n(crate::metrics::Command::Classify, 1);
        let auth = Arc::new(InferenceAuth::from_json(br#"{"tokens":["secret-token"]}"#).unwrap());
        let request_auth = GrpcRequestAuthentication::bearer(
            http::header::AUTHORIZATION,
            "Bearer",
            Arc::clone(&auth),
        );
        let debug = format!("{request_auth:?}");
        assert!(!debug.contains("secret-token"));

        let worker_faults = Arc::new(crate::admission::BlockingExecutorFaultControl::default());
        let state = validated_mixed_state(
            Admission::new(2, 4, std::time::Duration::from_secs(2)).unwrap(),
            worker_faults,
        );
        let server = spawn_real_tonic_with_limits(
            state,
            GrpcServerLimits::test_defaults()
                .with_test_control(Arc::clone(&controls))
                .with_request_auth(request_auth),
        )
        .await;
        let mut client = inference_client(server.endpoint.clone()).await;
        let status = client
            .classify(ClassifyRequest {
                model: "classifier-a".to_string(),
                text: "hello".to_string(),
                top_k: 1,
            })
            .await
            .expect_err("missing bearer metadata must be rejected");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
        assert_eq!(barrier.entered.load(Ordering::SeqCst), 0);
        server.stop().await;
    }

    #[tokio::test]
    async fn production_tonic_bearer_auth_allows_authorized_requests() {
        let auth = Arc::new(InferenceAuth::from_json(br#"{"tokens":["secret-token"]}"#).unwrap());
        let worker_faults = Arc::new(crate::admission::BlockingExecutorFaultControl::default());
        let state = validated_mixed_state(
            Admission::new(2, 4, std::time::Duration::from_secs(2)).unwrap(),
            worker_faults,
        );
        let server =
            spawn_real_tonic_with_limits(
                state,
                GrpcServerLimits::test_defaults().with_request_auth(
                    GrpcRequestAuthentication::bearer(http::header::AUTHORIZATION, "Bearer", auth),
                ),
            )
            .await;
        let mut client = inference_client(server.endpoint.clone()).await;
        let mut request = Request::new(ClassifyRequest {
            model: "classifier-a".to_string(),
            text: "hello".to_string(),
            top_k: 1,
        });
        request
            .metadata_mut()
            .insert("authorization", "Bearer secret-token".parse().unwrap());
        let response = client
            .classify(request)
            .await
            .expect("authorized bearer request must classify");
        assert_eq!(response.into_inner().labels[0].name, "safe");
        server.stop().await;
    }

    impl TestGrpcServer {
        async fn stop(self) {
            assert!(
                !self.task.is_finished(),
                "production gRPC listener exited before explicit cleanup"
            );
            let deadline = tokio::time::Instant::now() + EXTERNAL_WAIT;
            self.cleanup.request_graceful_shutdown_before(deadline);
            let join = tokio::time::timeout_at(deadline, self.task)
                .await
                .expect("production gRPC listener joins before cleanup deadline")
                .expect("production gRPC listener task must not panic");
            let exit = join.expect("production gRPC listener reports clean graceful shutdown");
            exit.assert_quiescent_at_return()
                .expect("gRPC owner returns only after every child result is collected");
            assert_eq!(exit.active_connection_children(), 0);
            assert_eq!(
                exit.connection_children_spawned(),
                exit.connection_children_finished(),
                "gRPC listener cleanup may not detach a connection child"
            );
            assert_eq!(
                exit.connection_child_results_collected(),
                exit.connection_children_spawned(),
                "the listener owner must join and inspect every gRPC connection child"
            );
            assert_eq!(
                exit.connection_child_panics(),
                0,
                "a connection panic may not be swallowed as normal listener cleanup"
            );
            assert_eq!(
                exit.connection_child_events_after_owner_return(),
                0,
                "a detached reaper cannot catch up after the gRPC owner returns"
            );
            assert_eq!(
                exit.collection_deadline_id(),
                self.cleanup.shutdown_deadline_id()
            );
        }
    }

    #[tokio::test]
    async fn listener_failure_requests_bounded_cleanup_deadline_when_absent() {
        let cleanup = Arc::new(GrpcListenerCleanupProbe::default());
        let before = tokio::time::Instant::now();
        let deadline = listener_cleanup_deadline(&cleanup, true);

        assert_eq!(cleanup.shutdown_deadline(), Some(deadline));
        assert_eq!(cleanup.shutdown_deadline_id(), instant_id(deadline));

        let elapsed = deadline.checked_duration_since(before).unwrap_or_default();
        assert!(
            elapsed
                >= GRPC_LISTENER_FAILURE_CLEANUP_TIMEOUT.saturating_sub(Duration::from_millis(50)),
            "failure cleanup deadline must be bounded close to the default timeout",
        );
        assert!(
            elapsed <= GRPC_LISTENER_FAILURE_CLEANUP_TIMEOUT + Duration::from_millis(50),
            "failure cleanup deadline may not drift past the bounded timeout window",
        );
    }

    #[tokio::test]
    async fn listener_cleanup_probe_keeps_the_earliest_deadline() {
        let cleanup = Arc::new(GrpcListenerCleanupProbe::default());
        let first = tokio::time::Instant::now() + Duration::from_secs(5);
        let earlier = tokio::time::Instant::now() + Duration::from_secs(1);
        let later = tokio::time::Instant::now() + Duration::from_secs(10);

        cleanup.request_graceful_shutdown_before(first);
        cleanup.request_graceful_shutdown_before(later);
        assert_eq!(cleanup.shutdown_deadline(), Some(first));
        assert_eq!(cleanup.shutdown_deadline_id(), instant_id(first));

        cleanup.request_graceful_shutdown_before(earlier);
        assert_eq!(cleanup.shutdown_deadline(), Some(earlier));
        assert_eq!(cleanup.shutdown_deadline_id(), instant_id(earlier));
    }

    #[tokio::test]
    async fn listener_predeadline_child_cancellation_is_typed() {
        let cleanup = Arc::new(GrpcListenerCleanupProbe::default());
        cleanup
            .request_graceful_shutdown_before(tokio::time::Instant::now() + Duration::from_secs(5));

        let mut children = tokio::task::JoinSet::new();
        children.spawn(async move {
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok::<(), GrpcConnectionChildError>(())
        });
        children.abort_all();

        let error = finalize_grpc_listener(
            children,
            GrpcListenerExitReport {
                connection_children_spawned: 1,
                ..GrpcListenerExitReport::default()
            },
            Arc::clone(&cleanup),
            None,
        )
        .await
        .expect_err("pre-deadline child cancellation must surface as a typed listener failure");

        assert_eq!(
            error.kind(),
            GrpcListenerErrorKind::ConnectionChildCancelled
        );
        assert!(!error.cleanup_deadline_elapsed());
        error
            .exit_report()
            .assert_quiescent_at_return()
            .expect("child cancellation failure still returns a fully drained report");
    }

    #[tokio::test]
    async fn listener_middrain_deadline_tightening_interrupts_old_wait() {
        struct AbortObserved(Arc<AtomicBool>);

        impl Drop for AbortObserved {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let cleanup = Arc::new(GrpcListenerCleanupProbe::default());
        cleanup.request_graceful_shutdown_before(
            tokio::time::Instant::now() + Duration::from_secs(60),
        );

        let aborted = Arc::new(AtomicBool::new(false));
        let mut children = tokio::task::JoinSet::new();
        let aborted_flag = Arc::clone(&aborted);
        children.spawn(async move {
            let _observed = AbortObserved(aborted_flag);
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok::<(), GrpcConnectionChildError>(())
        });

        let tighten_cleanup = Arc::clone(&cleanup);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            tighten_cleanup.request_graceful_shutdown_before(tokio::time::Instant::now());
        });

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            finalize_grpc_listener(
                children,
                GrpcListenerExitReport {
                    connection_children_spawned: 1,
                    ..GrpcListenerExitReport::default()
                },
                Arc::clone(&cleanup),
                None,
            ),
        )
        .await
        .expect("tightened cleanup deadline must interrupt the stale wait")
        .expect_err("deadline tightening must expire the listener cleanup");

        assert_eq!(error.kind(), GrpcListenerErrorKind::CleanupDeadlineExceeded);
        assert!(error.cleanup_deadline_elapsed());
        error
            .exit_report()
            .assert_quiescent_at_return()
            .expect("deadline-tightened cleanup still drains every child result");
        assert!(aborted.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn listener_cleanup_deadline_abort_preserves_primary_error_and_quiesces_report() {
        struct AbortObserved(Arc<AtomicBool>);

        impl Drop for AbortObserved {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let cleanup = Arc::new(GrpcListenerCleanupProbe::default());
        cleanup.request_graceful_shutdown_before(tokio::time::Instant::now());

        let aborted = Arc::new(AtomicBool::new(false));
        let mut children = tokio::task::JoinSet::new();
        let aborted_flag = Arc::clone(&aborted);
        children.spawn(async move {
            let _observed = AbortObserved(aborted_flag);
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok::<(), GrpcConnectionChildError>(())
        });

        let error = finalize_grpc_listener(
            children,
            GrpcListenerExitReport {
                connection_children_spawned: 1,
                ..GrpcListenerExitReport::default()
            },
            Arc::clone(&cleanup),
            Some(GrpcListenerFailure::connection_child(Box::new(
                std::io::Error::other("boom"),
            ))),
        )
        .await
        .expect_err("expired cleanup must return the preserved primary listener error");

        assert_eq!(error.kind(), GrpcListenerErrorKind::ConnectionChild);
        assert!(error.cleanup_deadline_elapsed());
        assert_eq!(
            std::error::Error::source(&error)
                .expect("primary listener error must preserve its source")
                .to_string(),
            "boom"
        );
        error
            .exit_report()
            .assert_quiescent_at_return()
            .expect("cleanup-deadline abort must still collect every child result");
        assert_eq!(error.exit_report().active_connection_children(), 0);
        assert_eq!(error.exit_report().connection_child_panics(), 0);
        assert!(aborted.load(Ordering::SeqCst));
    }

    fn admission_queue_value(command: &str) -> i64 {
        prometheus::gather()
            .into_iter()
            .find(|family| family.name() == "sbproxy_classifier_admission_queue")
            .and_then(|family| {
                family.get_metric().iter().find_map(|metric| {
                    metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == "cmd" && label.value() == command)
                        .then(|| metric.get_gauge().value() as i64)
                })
            })
            .unwrap_or(0)
    }

    async fn wait_for_admission_queue(command: &str, expected: i64) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if admission_queue_value(command) == expected {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "admission queue {command:?} did not reach {expected}; current value is {}",
                admission_queue_value(command)
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    fn raw_state() -> Arc<GrpcState> {
        Arc::new(GrpcState {
            models: HashMap::new(),
            embedders: HashMap::new(),
            default_model: None,
            default_embed_model: None,
            version: "sbproxy-classifier test".to_string(),
            admission: Admission::new(2, 4, std::time::Duration::from_millis(DEFAULT_DEADLINE_MS))
                .unwrap(),
            catalog: None,
            blocking_executor: None,
        })
    }

    fn validated_mixed_state(
        admission: Admission,
        worker_faults: Arc<crate::admission::BlockingExecutorFaultControl>,
    ) -> Arc<GrpcState> {
        // Deliberate compile-RED against the production catalog/loader and
        // worker-executor owners.  `ValidatedModelFixture::Mixed` must contain
        // a classifier ONNX and a genuinely embedding-shaped ONNX model; a
        // classifier fixture loaded as an embedder is not an acceptable
        // implementation of this seam.
        let catalog = ModelCatalog::load_validated_fixture(ValidatedModelFixture::Mixed)
            .expect("the checked mixed classifier/embedder fixture loads");
        let executor = crate::admission::BlockingWorkExecutor::new(admission)
            .with_test_fault_control(worker_faults);
        Arc::new(GrpcState::from_catalog(
            catalog,
            "sbproxy-classifier test".to_string(),
            executor,
        ))
    }

    fn inference_state() -> InferenceHandler {
        InferenceHandler(raw_state())
    }

    fn classifier_state() -> ClassifierHandler {
        ClassifierHandler(raw_state())
    }

    #[tokio::test]
    async fn classify_without_a_loaded_model_is_not_found() {
        let state = inference_state();
        let err = state
            .classify(Request::new(ClassifyRequest {
                model: String::new(),
                text: "hello".to_string(),
                top_k: 0,
            }))
            .await
            .expect_err("no model configured");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn classify_rejects_oversized_text_before_resolving_a_model() {
        let state = inference_state();
        let oversized = "a".repeat(MAX_TEXT_BYTES + 1);
        let err = state
            .classify(Request::new(ClassifyRequest {
                model: String::new(),
                text: oversized,
                top_k: 0,
            }))
            .await
            .expect_err("oversized text must be refused");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn embed_without_a_configured_embedder_is_failed_precondition() {
        let state = inference_state();
        let err = state
            .embed(Request::new(EmbedRequest {
                model: String::new(),
                texts: vec!["hi".to_string()],
            }))
            .await
            .expect_err("no embedder configured");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn embed_rejects_total_request_work_before_model_resolution() {
        let state = inference_state();
        let err = state
            .embed(Request::new(
                embed_request_exceeding_total_budget_below_decode_ceiling(""),
            ))
            .await
            .expect_err("aggregate embed work must be bounded");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn compress_is_explicitly_unimplemented() {
        let state = inference_state();
        let err = state
            .compress(Request::new(CompressRequest {
                model: String::new(),
                text: "hi".to_string(),
                target: None,
            }))
            .await
            .expect_err("compress must not silently succeed");
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn version_reports_zero_models_when_none_are_loaded() {
        let state = inference_state();
        let resp = state
            .version(Request::new(VersionRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.models.is_empty());
        assert_eq!(resp.version, "sbproxy-classifier test");
    }

    #[tokio::test]
    async fn quality_scores_land_in_the_unit_range() {
        let state = classifier_state();
        let resp = state
            .quality(Request::new(QualityRequest {
                tenant: String::new(),
                text: "A perfectly ordinary sentence about the weather.".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!((0.0..=1.0).contains(&resp.score));
        assert!(resp.signals.contains_key("length"));
    }

    #[tokio::test]
    async fn stream_safety_emits_one_block_transition_and_stays_unsafe() {
        // Drives `run_stream_safety` directly with a plain `ReceiverStream`
        // rather than a real `tonic::Streaming`, which has no public test
        // constructor. This still exercises the exact loop the trait method
        // spawns; only the transport plumbing around it is skipped.
        let safe_before = crate::metrics::safety_verdict_count("safe");
        let blocked_before = crate::metrics::safety_verdict_count("blocked");
        let continued_before = crate::metrics::safety_verdict_count("unsafe_continued");

        let (in_tx, in_rx) = tokio::sync::mpsc::channel(4);
        let inbound = tokio_stream::wrappers::ReceiverStream::new(in_rx);
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(4);

        in_tx
            .send(Ok(SafetyToken {
                tenant: String::new(),
                rules: vec!["forbidden".to_string()],
                token: "this is ".to_string(),
            }))
            .await
            .unwrap();
        in_tx
            .send(Ok(SafetyToken {
                tenant: String::new(),
                rules: vec![],
                token: "forbidden content".to_string(),
            }))
            .await
            .unwrap();
        in_tx
            .send(Ok(SafetyToken {
                tenant: String::new(),
                rules: vec![],
                token: " and more after it".to_string(),
            }))
            .await
            .unwrap();
        drop(in_tx);

        run_stream_safety(inbound, out_tx, None).await.unwrap();
        let mut outbound = ReceiverStream::new(out_rx);

        let first = outbound.next().await.unwrap().unwrap();
        assert!(first.safe && !first.blocked);

        let second = outbound.next().await.unwrap().unwrap();
        assert!(!second.safe && second.blocked);
        assert!(second.reason.contains("forbidden"));

        // The unsafe state persists on the message after the match, but
        // `blocked` is the one-shot transition bit and does not fire again.
        let third = outbound.next().await.unwrap().unwrap();
        assert!(!third.safe);
        assert!(!third.blocked);
        assert_eq!(third.reason, second.reason);
        assert!(crate::metrics::safety_verdict_count("safe") > safe_before);
        assert!(crate::metrics::safety_verdict_count("blocked") > blocked_before);
        assert!(
            crate::metrics::safety_verdict_count("unsafe_continued") > continued_before,
            "later unsafe messages need their own closed verdict label"
        );
    }

    #[tokio::test]
    async fn saturated_response_channel_cannot_turn_first_unsafe_token_into_clean_eof() {
        use prost::Message as _;

        let admission = Admission::new(1, 0, std::time::Duration::from_millis(100)).unwrap();
        let mut state = raw_state();
        Arc::get_mut(&mut state).unwrap().admission = admission.clone();
        let handler = ClassifierHandler(state);

        let mut framed = Vec::new();
        for index in 0..17 {
            let token = SafetyToken {
                tenant: String::new(),
                rules: if index == 0 {
                    vec!["forbidden".to_string()]
                } else {
                    Vec::new()
                },
                token: if index == 16 {
                    "forbidden".to_string()
                } else {
                    "safe".to_string()
                },
            };
            framed.push(0);
            framed.extend_from_slice(&(token.encoded_len() as u32).to_be_bytes());
            token.encode(&mut framed).unwrap();
        }
        let (mut body_tx, body) =
            http_body_util::channel::Channel::<tonic::codegen::Bytes, std::io::Error>::new(1);
        body_tx
            .send_data(tonic::codegen::Bytes::from(framed))
            .await
            .unwrap();
        let decoder = tonic::codec::ProstCodec::<SafetyVerdict, SafetyToken>::raw_decoder(
            tonic::codec::BufferSettings::default(),
        );
        let inbound = Streaming::new_request(decoder, body, None, None);
        let mut outbound = handler
            .stream_safety(Request::new(inbound))
            .await
            .unwrap()
            .into_inner();

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let replacement = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            admission.acquire("stream_safety"),
        )
        .await
        .expect("deadline must release the admission lease");
        drop(replacement.expect("deadline must release the admission lease"));

        for _ in 0..16 {
            let verdict = tokio::time::timeout(std::time::Duration::from_secs(1), outbound.next())
                .await
                .expect("accepted safe verdict must remain available")
                .expect("accepted safe verdict must precede stream termination")
                .expect("accepted safe verdict must not become an error");
            assert!(verdict.safe && !verdict.blocked);
        }
        let terminal = tokio::time::timeout(std::time::Duration::from_secs(1), outbound.next())
            .await
            .expect("unsafe verdict or terminal error must be observable after saturation");
        match terminal {
            Some(Ok(verdict)) => {
                assert!(!verdict.safe && verdict.blocked);
                assert!(verdict.reason.contains("forbidden"));
            }
            Some(Err(status)) => assert!(matches!(
                status.code(),
                tonic::Code::DeadlineExceeded | tonic::Code::ResourceExhausted
            )),
            None => {
                panic!("response backpressure must not turn the first unsafe token into clean EOF")
            }
        }
        drop(body_tx);
    }

    #[tokio::test]
    async fn stream_safety_rejects_a_stream_over_the_cumulative_byte_budget() {
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(2);
        let inbound = ReceiverStream::new(in_rx);
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(2);
        in_tx
            .send(Ok(SafetyToken {
                tenant: String::new(),
                rules: vec!["forbidden".to_string()],
                token: "a".repeat(600 * 1024),
            }))
            .await
            .unwrap();
        in_tx
            .send(Ok(SafetyToken {
                tenant: String::new(),
                rules: Vec::new(),
                token: "b".repeat(600 * 1024),
            }))
            .await
            .unwrap();
        drop(in_tx);

        let error = run_stream_safety(inbound, out_tx, None)
            .await
            .expect_err("the cumulative stream limit must terminate the stream");
        assert!(out_rx.recv().await.unwrap().is_ok());
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn bounded_stream_window_matches_a_rule_split_across_chunks() {
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(2);
        let inbound = ReceiverStream::new(in_rx);
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(2);
        in_tx
            .send(Ok(SafetyToken {
                tenant: String::new(),
                rules: vec!["forbidden".to_string()],
                token: "safe then for".to_string(),
            }))
            .await
            .unwrap();
        in_tx
            .send(Ok(SafetyToken {
                tenant: String::new(),
                rules: Vec::new(),
                token: "bidden".to_string(),
            }))
            .await
            .unwrap();
        drop(in_tx);

        run_stream_safety(inbound, out_tx, None).await.unwrap();
        assert!(out_rx.recv().await.unwrap().unwrap().safe);
        let matched = out_rx.recv().await.unwrap().unwrap();
        assert!(!matched.safe && matched.blocked);
    }

    #[tokio::test]
    async fn real_tonic_terminal_outcome_matrix_is_exhaustive_and_exactly_once() {
        use crate::metrics::{
            Command as MetricCommand, OutcomeExpectation, OutcomeProbe, Reason, Stage, Transport,
        };

        let outcomes = OutcomeProbe::acquire_unique().await;

        macro_rules! assert_grpc_case {
            ($name:literal, $expected:expr, $code:expr, $future:expr) => {{
                let before = outcomes.snapshot();
                let result = bounded_external($name, $future).await;
                match $code {
                    Some(code) => assert_eq!(
                        result.expect_err(concat!($name, " must fail")).code(),
                        code,
                        "wrong gRPC status for {}",
                        $name,
                    ),
                    None => {
                        result.expect(concat!($name, " must succeed"));
                    }
                }
                before.assert_exact_terminal_delta($expected, $name);
            }};
        }

        let worker_faults = Arc::new(crate::admission::BlockingExecutorFaultControl::default());
        let controls = Arc::new(GrpcTestControl::default());
        let state = validated_mixed_state(
            Admission::new(2, 4, std::time::Duration::from_secs(2)).unwrap(),
            Arc::clone(&worker_faults),
        );
        let server = spawn_real_tonic_with_limits(
            state,
            GrpcServerLimits::test_defaults().with_test_control(Arc::clone(&controls)),
        )
        .await;
        let mut inference = inference_client(server.endpoint.clone()).await;
        let mut classifier = classifier_client(server.endpoint.clone()).await;

        assert_grpc_case!(
            "classify success",
            OutcomeExpectation::success(Transport::Grpc, MetricCommand::Classify),
            None,
            async {
                inference
                    .classify(ClassifyRequest {
                        model: "classifier-a".to_string(),
                        text: "hello".to_string(),
                        top_k: 1,
                    })
                    .await
                    .map(|_| ())
            }
        );
        assert_grpc_case!(
            "classify size",
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Classify,
                Stage::Limit,
                Reason::ResourceLimit,
            ),
            Some(tonic::Code::ResourceExhausted),
            async {
                inference
                    .classify(ClassifyRequest {
                        model: "classifier-a".to_string(),
                        text: "x".repeat(MAX_TEXT_BYTES + 1),
                        top_k: 1,
                    })
                    .await
                    .map(|_| ())
            }
        );
        assert_grpc_case!(
            "classify unknown model",
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Classify,
                Stage::Model,
                Reason::ModelNotFound,
            ),
            Some(tonic::Code::NotFound),
            async {
                inference
                    .classify(ClassifyRequest {
                        model: "missing".to_string(),
                        text: "hello".to_string(),
                        top_k: 1,
                    })
                    .await
                    .map(|_| ())
            }
        );
        let classify_fault = worker_faults.arm_next(
            "classify",
            crate::admission::BlockingExecutorFault::Error("private classify failure".to_string()),
        );
        assert_grpc_case!(
            "classify worker failure",
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Classify,
                Stage::Worker,
                Reason::InferenceFailed,
            ),
            Some(tonic::Code::Internal),
            async {
                inference
                    .classify(ClassifyRequest {
                        model: "classifier-a".to_string(),
                        text: "hello".to_string(),
                        top_k: 1,
                    })
                    .await
                    .map(|_| ())
            }
        );
        classify_fault.assert_consumed_exactly_once();

        assert_grpc_case!(
            "embed success",
            OutcomeExpectation::success(Transport::Grpc, MetricCommand::Embed),
            None,
            async {
                inference
                    .embed(EmbedRequest {
                        model: "embedder-b".to_string(),
                        texts: vec!["hello".to_string(), "world".to_string()],
                    })
                    .await
                    .map(|_| ())
            }
        );
        for (name, texts) in [
            (
                "embed item count",
                vec!["x".to_string(); MAX_EMBED_ITEMS + 1],
            ),
            (
                "embed aggregate bytes",
                embed_request_exceeding_total_budget_below_decode_ceiling("embedder-b").texts,
            ),
            ("embed per-item bytes", vec!["x".repeat(MAX_TEXT_BYTES + 1)]),
        ] {
            let before = outcomes.snapshot();
            let status = bounded_external(
                "embed limit matrix",
                inference.embed(EmbedRequest {
                    model: "embedder-b".to_string(),
                    texts,
                }),
            )
            .await
            .expect_err("embed shape limit must fail");
            assert_eq!(status.code(), tonic::Code::ResourceExhausted, "{name}");
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    Transport::Grpc,
                    MetricCommand::Embed,
                    Stage::Limit,
                    Reason::ResourceLimit,
                ),
                name,
            );
        }
        assert_grpc_case!(
            "embed unknown model",
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Embed,
                Stage::Model,
                Reason::ModelNotFound,
            ),
            Some(tonic::Code::FailedPrecondition),
            async {
                inference
                    .embed(EmbedRequest {
                        model: "missing".to_string(),
                        texts: vec!["hello".to_string()],
                    })
                    .await
                    .map(|_| ())
            }
        );
        let embed_fault = worker_faults.arm_next(
            "embed",
            crate::admission::BlockingExecutorFault::Error("private embed failure".to_string()),
        );
        assert_grpc_case!(
            "embed worker failure",
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Embed,
                Stage::Worker,
                Reason::InferenceFailed,
            ),
            Some(tonic::Code::Internal),
            async {
                inference
                    .embed(EmbedRequest {
                        model: "embedder-b".to_string(),
                        texts: vec!["hello".to_string()],
                    })
                    .await
                    .map(|_| ())
            }
        );
        embed_fault.assert_consumed_exactly_once();

        assert_grpc_case!(
            "compress unimplemented",
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Compress,
                Stage::Handler,
                Reason::Unimplemented,
            ),
            Some(tonic::Code::Unimplemented),
            async {
                inference
                    .compress(CompressRequest {
                        model: String::new(),
                        text: "small".to_string(),
                        target: Some(
                            sbproxy_classifier_proto::compress_request::Target::TargetTokens(1),
                        ),
                    })
                    .await
                    .map(|_| ())
            }
        );

        for (name, model) in [
            ("model info default classifier", ""),
            ("model info explicit classifier", "classifier-a"),
            ("model info explicit embedder", "embedder-b"),
        ] {
            let before = outcomes.snapshot();
            bounded_external(
                "model info success",
                inference.model_info(ModelInfoRequest {
                    model: model.to_string(),
                }),
            )
            .await
            .expect(name);
            before.assert_exact_terminal_delta(
                OutcomeExpectation::success(Transport::Grpc, MetricCommand::ModelInfo),
                name,
            );
        }
        assert_grpc_case!(
            "model info unknown",
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::ModelInfo,
                Stage::Model,
                Reason::ModelNotFound,
            ),
            Some(tonic::Code::NotFound),
            async {
                inference
                    .model_info(ModelInfoRequest {
                        model: "missing".to_string(),
                    })
                    .await
                    .map(|_| ())
            }
        );
        let model_info_fault = worker_faults.arm_next(
            "model_info",
            crate::admission::BlockingExecutorFault::Error(
                "private model-info failure".to_string(),
            ),
        );
        assert_grpc_case!(
            "embedding model info worker failure",
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::ModelInfo,
                Stage::Worker,
                Reason::InferenceFailed,
            ),
            Some(tonic::Code::Internal),
            async {
                inference
                    .model_info(ModelInfoRequest {
                        model: "embedder-b".to_string(),
                    })
                    .await
                    .map(|_| ())
            }
        );
        model_info_fault.assert_consumed_exactly_once();

        assert_grpc_case!(
            "version success",
            OutcomeExpectation::success(Transport::Grpc, MetricCommand::Version),
            None,
            async { inference.version(VersionRequest {}).await.map(|_| ()) }
        );
        assert_grpc_case!(
            "quality success",
            OutcomeExpectation::success(Transport::Grpc, MetricCommand::Quality),
            None,
            async {
                classifier
                    .quality(QualityRequest {
                        tenant: String::new(),
                        text: "ordinary response".to_string(),
                    })
                    .await
                    .map(|_| ())
            }
        );
        assert_grpc_case!(
            "quality size",
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Quality,
                Stage::Limit,
                Reason::ResourceLimit,
            ),
            Some(tonic::Code::ResourceExhausted),
            async {
                classifier
                    .quality(QualityRequest {
                        tenant: String::new(),
                        text: "x".repeat(MAX_TEXT_BYTES + 1),
                    })
                    .await
                    .map(|_| ())
            }
        );
        let quality_fault = worker_faults.arm_next(
            "quality",
            crate::admission::BlockingExecutorFault::Error("private quality failure".to_string()),
        );
        assert_grpc_case!(
            "quality worker failure",
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Quality,
                Stage::Worker,
                Reason::InferenceFailed,
            ),
            Some(tonic::Code::Internal),
            async {
                classifier
                    .quality(QualityRequest {
                        tenant: String::new(),
                        text: "ordinary response".to_string(),
                    })
                    .await
                    .map(|_| ())
            }
        );
        quality_fault.assert_consumed_exactly_once();

        let unary_write_fault = controls.arm_next(GrpcFault::ResponseWrite {
            command: MetricCommand::Version,
        });
        assert_grpc_case!(
            "unary response write failure",
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Version,
                Stage::Write,
                Reason::Io,
            ),
            Some(tonic::Code::Unavailable),
            async { inference.version(VersionRequest {}).await.map(|_| ()) }
        );
        unary_write_fault.assert_consumed_exactly_once();

        let malformed_before = outcomes.snapshot();
        let channel = bounded_external(
            "connect malformed unary channel",
            tonic::transport::Endpoint::from_shared(server.endpoint.clone())
                .unwrap()
                .connect(),
        )
        .await
        .unwrap();
        let mut raw_client = tonic::client::Grpc::new(channel);
        bounded_external("malformed unary client readiness", raw_client.ready())
            .await
            .unwrap();
        let malformed_status = bounded_external(
            "malformed unary protobuf terminal",
            raw_client.unary(
                tonic::Request::new(TruncatedUnaryBody),
                tonic::codegen::http::uri::PathAndQuery::from_static(
                    "/sbproxy.classifier.v1.InferenceService/Version",
                ),
                tonic::codec::ProstCodec::<TruncatedUnaryBody, VersionResponse>::default(),
            ),
        )
        .await
        .expect_err("a malformed unary protobuf body must fail before the handler");
        assert_eq!(malformed_status.code(), tonic::Code::InvalidArgument);
        malformed_before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Version,
                Stage::Decode,
                Reason::MalformedFrame,
            ),
            "malformed unary protobuf body",
        );

        // StreamSafety clean end, each closed input limit, an inbound stream
        // error, terminal body-write failure, and cancellation all traverse
        // the generated bidi service.  Later-rule compatibility has its own
        // stronger behavioral test below.
        let before = outcomes.snapshot();
        let mut stream = bounded_external(
            "stream safety clean start",
            classifier.stream_safety(tokio_stream::iter(vec![SafetyToken {
                tenant: "tenant-a".to_string(),
                rules: vec!["forbidden".to_string()],
                token: "safe".to_string(),
            }])),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(
            bounded_external("stream safety clean message", stream.message())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            bounded_external("stream safety clean eof", stream.message())
                .await
                .unwrap()
                .is_none()
        );
        before.assert_exact_terminal_delta(
            OutcomeExpectation::success(Transport::Grpc, MetricCommand::StreamSafety),
            "stream safety clean end",
        );

        for (name, input) in [
            (
                "stream chunk limit",
                vec![SafetyToken {
                    tenant: String::new(),
                    rules: vec![],
                    token: "x".repeat(MAX_TEXT_BYTES + 1),
                }],
            ),
            (
                "stream cumulative limit",
                vec![
                    SafetyToken {
                        tenant: String::new(),
                        rules: vec![],
                        token: "x".repeat(600 * 1024),
                    },
                    SafetyToken {
                        tenant: String::new(),
                        rules: vec![],
                        token: "y".repeat(600 * 1024),
                    },
                ],
            ),
            (
                "stream rule count",
                vec![SafetyToken {
                    tenant: String::new(),
                    rules: vec!["x".to_string(); MAX_STREAM_RULES + 1],
                    token: "safe".to_string(),
                }],
            ),
            (
                "stream rule bytes",
                vec![SafetyToken {
                    tenant: String::new(),
                    rules: vec!["x".repeat(MAX_STREAM_RULE_BYTES + 1)],
                    token: "safe".to_string(),
                }],
            ),
        ] {
            let before = outcomes.snapshot();
            let mut stream = bounded_external(
                "stream safety limit start",
                classifier.stream_safety(tokio_stream::iter(input)),
            )
            .await
            .unwrap()
            .into_inner();
            let status = bounded_stream_terminal_error(name, &mut stream, 8).await;
            assert_eq!(status.code(), tonic::Code::ResourceExhausted, "{name}");
            before.assert_exact_terminal_delta(
                OutcomeExpectation::failure(
                    Transport::Grpc,
                    MetricCommand::StreamSafety,
                    Stage::Limit,
                    Reason::ResourceLimit,
                ),
                name,
            );
        }

        let before = outcomes.snapshot();
        let mut stream = bounded_external(
            "stream chunk-count limit start",
            classifier.stream_safety(tokio_stream::iter((0..=MAX_STREAM_CHUNKS).map(|_| {
                SafetyToken {
                    tenant: String::new(),
                    rules: Vec::new(),
                    token: "x".to_string(),
                }
            }))),
        )
        .await
        .unwrap()
        .into_inner();
        let status = bounded_stream_terminal_error_within(
            "stream chunk-count limit",
            &mut stream,
            MAX_STREAM_CHUNKS + 1,
            std::time::Duration::from_secs(20),
        )
        .await;
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
        before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::StreamSafety,
                Stage::Limit,
                Reason::ResourceLimit,
            ),
            "stream chunk-count limit",
        );

        let inbound_fault = controls.arm_next(GrpcFault::InboundStreamError {
            code: tonic::Code::DataLoss,
        });
        let before = outcomes.snapshot();
        let mut stream = bounded_external(
            "inbound-error stream start",
            classifier.stream_safety(tokio_stream::iter(vec![SafetyToken {
                tenant: String::new(),
                rules: vec![],
                token: "safe".to_string(),
            }])),
        )
        .await
        .unwrap()
        .into_inner();
        let status = bounded_external("inbound-error stream terminal", stream.message())
            .await
            .expect_err("inbound status must not become clean EOF");
        assert_eq!(status.code(), tonic::Code::DataLoss);
        inbound_fault.assert_consumed_exactly_once();
        before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::StreamSafety,
                Stage::Read,
                Reason::Io,
            ),
            "stream inbound error",
        );

        let stream_write_fault = controls.arm_next(GrpcFault::ResponseWrite {
            command: MetricCommand::StreamSafety,
        });
        let before = outcomes.snapshot();
        let mut stream = bounded_external(
            "write-error stream start",
            classifier.stream_safety(tokio_stream::iter(vec![SafetyToken {
                tenant: String::new(),
                rules: vec![],
                token: "safe".to_string(),
            }])),
        )
        .await
        .unwrap()
        .into_inner();
        let status = bounded_external("write-error stream terminal", stream.message())
            .await
            .expect_err("stream body write failure must be terminal");
        assert_eq!(status.code(), tonic::Code::Unavailable);
        stream_write_fault.assert_consumed_exactly_once();
        before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::StreamSafety,
                Stage::Write,
                Reason::Io,
            ),
            "stream response write failure",
        );

        let before = outcomes.snapshot();
        let cancellation_connection = reset_stream_safety_after_first_verdict(server.address).await;
        before
            .wait_for_exact_terminal_delta(
                OutcomeExpectation::failure(
                    Transport::Grpc,
                    MetricCommand::StreamSafety,
                    Stage::Cancellation,
                    Reason::Cancelled,
                ),
                "stream client cancellation",
                std::time::Duration::from_secs(3),
            )
            .await;
        cancellation_connection
            .close_and_join(std::time::Duration::from_secs(1))
            .await
            .expect("explicit cancellation helper shuts down boundedly");

        server.stop().await;
    }

    #[tokio::test]
    async fn cancelling_real_queued_quality_rpc_restores_queue_gauge_and_capacity() {
        use crate::metrics::{
            Command as MetricCommand, OutcomeExpectation, OutcomeProbe, Reason, Stage, Transport,
        };

        struct ReleaseWorkerOnDrop(Option<Arc<crate::admission::WorkerBarrier>>);

        impl ReleaseWorkerOnDrop {
            fn release(&mut self) {
                if let Some(barrier) = self.0.take() {
                    barrier.release();
                }
            }
        }

        impl Drop for ReleaseWorkerOnDrop {
            fn drop(&mut self) {
                self.release();
            }
        }

        let outcomes = OutcomeProbe::acquire_unique().await;
        let worker_faults = Arc::new(crate::admission::BlockingExecutorFaultControl::default());
        let admission_probe = Arc::new(crate::admission::AdmissionProbe::default());
        let admission = Admission::new(1, 1, std::time::Duration::from_secs(30))
            .unwrap()
            .with_test_probe(Arc::clone(&admission_probe));
        let state = validated_mixed_state(admission, Arc::clone(&worker_faults));
        let server = spawn_real_tonic(state).await;
        let first_barrier = Arc::new(crate::admission::WorkerBarrier::default());
        let mut release_first_worker = ReleaseWorkerOnDrop(Some(Arc::clone(&first_barrier)));
        let first_fault = worker_faults.arm_next(
            "classify",
            crate::admission::BlockingExecutorFault::Hold(Arc::clone(&first_barrier)),
        );
        let mut first_client = inference_client(server.endpoint.clone()).await;
        let first = tokio::spawn(async move {
            first_client
                .classify(ClassifyRequest {
                    model: "classifier-a".to_string(),
                    text: "hold the real worker".to_string(),
                    top_k: 1,
                })
                .await
        });
        first_barrier
            .wait_until_entered(std::time::Duration::from_secs(3))
            .await
            .expect("the first production handler holds the running lease");
        first_fault.assert_consumed_exactly_once();

        let client = classifier_client(server.endpoint.clone()).await;
        let baseline = admission_queue_value("quality");
        let cancellation_before = outcomes.snapshot();
        let queued = tokio::spawn(async move {
            let mut client = client;
            client
                .quality(QualityRequest {
                    tenant: String::new(),
                    text: "queued".to_string(),
                })
                .await
        });
        wait_for_admission_queue("quality", baseline + 1).await;
        admission_probe
            .wait_for_available_queue_permits(0, std::time::Duration::from_secs(3))
            .await
            .expect("the cancelled call owns the sole real queue permit");
        queued.abort();
        assert!(bounded_external("cancelled queued task joins", queued)
            .await
            .expect_err("RPC caller was cancelled")
            .is_cancelled());
        wait_for_admission_queue("quality", baseline).await;
        admission_probe
            .wait_for_available_queue_permits(1, std::time::Duration::from_secs(3))
            .await
            .expect("cancellation returns the real queue permit");
        cancellation_before
            .wait_for_exact_terminal_delta(
                OutcomeExpectation::failure(
                    Transport::Grpc,
                    MetricCommand::Quality,
                    Stage::Cancellation,
                    Reason::Cancelled,
                ),
                "queued quality cancellation",
                std::time::Duration::from_secs(3),
            )
            .await;

        let mut replacement_client = classifier_client(server.endpoint.clone()).await;
        let replacement = tokio::spawn(async move {
            replacement_client
                .quality(QualityRequest {
                    tenant: String::new(),
                    text: "replacement".to_string(),
                })
                .await
        });
        wait_for_admission_queue("quality", baseline + 1).await;
        admission_probe
            .wait_for_available_queue_permits(0, std::time::Duration::from_secs(3))
            .await
            .expect("replacement reuses the freed permit while still queued");
        assert!(
            !replacement.is_finished(),
            "replacement must remain queued while the real worker slot is held"
        );

        let queue_full_before = outcomes.snapshot();
        let mut refused_client = classifier_client(server.endpoint.clone()).await;
        let refused = bounded_external(
            "queue-full quality refusal",
            refused_client.quality(QualityRequest {
                tenant: String::new(),
                text: "plus one".to_string(),
            }),
        )
        .await
        .expect_err("the call beyond running plus queue must be refused");
        assert_eq!(refused.code(), tonic::Code::ResourceExhausted);
        queue_full_before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Quality,
                Stage::Admission,
                Reason::QueueFull,
            ),
            "quality queue full",
        );

        release_first_worker.release();
        bounded_external("held classify completes after release", first)
            .await
            .unwrap()
            .expect("the held production call recovers");
        let response = bounded_external("replacement quality completes", replacement)
            .await
            .unwrap()
            .expect("replacement completes after the running slot is released")
            .into_inner();
        wait_for_admission_queue("quality", baseline).await;
        server.stop().await;

        assert!((0.0..=1.0).contains(&response.score));
    }

    #[tokio::test]
    async fn real_tonic_admission_deadlines_finalize_every_leased_method_once() {
        use crate::metrics::{
            Command as MetricCommand, OutcomeExpectation, OutcomeProbe, Reason, Stage, Transport,
        };

        struct ReleaseWorkerOnDrop(Option<Arc<crate::admission::WorkerBarrier>>);

        impl ReleaseWorkerOnDrop {
            fn release(&mut self) {
                if let Some(barrier) = self.0.take() {
                    barrier.release();
                }
            }
        }

        impl Drop for ReleaseWorkerOnDrop {
            fn drop(&mut self) {
                self.release();
            }
        }

        let outcomes = OutcomeProbe::acquire_unique().await;
        let worker_faults = Arc::new(crate::admission::BlockingExecutorFaultControl::default());
        let state = validated_mixed_state(
            Admission::new(1, 8, std::time::Duration::from_millis(100)).unwrap(),
            Arc::clone(&worker_faults),
        );
        let server = spawn_real_tonic(state).await;
        let barrier = Arc::new(crate::admission::WorkerBarrier::default());
        let mut release_worker = ReleaseWorkerOnDrop(Some(Arc::clone(&barrier)));
        let hold = worker_faults.arm_next(
            "classify",
            crate::admission::BlockingExecutorFault::Hold(Arc::clone(&barrier)),
        );
        let mut holder_client = inference_client(server.endpoint.clone()).await;
        let holder_before = outcomes.snapshot();
        let holder = tokio::spawn(async move {
            holder_client
                .classify(ClassifyRequest {
                    model: "classifier-a".to_string(),
                    text: "hold".to_string(),
                    top_k: 1,
                })
                .await
        });
        barrier
            .wait_until_entered(std::time::Duration::from_secs(3))
            .await
            .expect("production worker holds the only running lease");
        hold.assert_consumed_exactly_once();
        let holder_status = bounded_external("deadline holder caller finalizes", holder)
            .await
            .unwrap()
            .expect_err("holder caller deadline expires while its worker stays live");
        assert_eq!(holder_status.code(), tonic::Code::DeadlineExceeded);
        holder_before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Classify,
                Stage::Worker,
                Reason::Deadline,
            ),
            "running classify caller deadline before matrix snapshots",
        );
        worker_faults
            .wait_for_active_workers("classify", 1, std::time::Duration::from_secs(3))
            .await
            .expect("the caller is finalized while its non-cancellable worker stays live");

        let mut inference = inference_client(server.endpoint.clone()).await;
        let mut classifier = classifier_client(server.endpoint.clone()).await;
        macro_rules! assert_deadline {
            ($name:literal, $command:expr, $future:expr) => {{
                let before = outcomes.snapshot();
                let status = bounded_external("leased-method admission deadline", $future)
                    .await
                    .expect_err($name);
                assert_eq!(status.code(), tonic::Code::DeadlineExceeded, $name);
                before.assert_exact_terminal_delta(
                    OutcomeExpectation::failure(
                        Transport::Grpc,
                        $command,
                        Stage::Admission,
                        Reason::Deadline,
                    ),
                    $name,
                );
            }};
        }
        assert_deadline!(
            "classify admission deadline",
            MetricCommand::Classify,
            async {
                inference
                    .classify(ClassifyRequest {
                        model: "classifier-a".to_string(),
                        text: "queued".to_string(),
                        top_k: 1,
                    })
                    .await
                    .map(|_| ())
            }
        );
        assert_deadline!("embed admission deadline", MetricCommand::Embed, async {
            inference
                .embed(EmbedRequest {
                    model: "embedder-b".to_string(),
                    texts: vec!["queued".to_string()],
                })
                .await
                .map(|_| ())
        });
        assert_deadline!(
            "model info admission deadline",
            MetricCommand::ModelInfo,
            async {
                inference
                    .model_info(ModelInfoRequest {
                        model: "embedder-b".to_string(),
                    })
                    .await
                    .map(|_| ())
            }
        );
        assert_deadline!(
            "quality admission deadline",
            MetricCommand::Quality,
            async {
                classifier
                    .quality(QualityRequest {
                        tenant: String::new(),
                        text: "queued".to_string(),
                    })
                    .await
                    .map(|_| ())
            }
        );
        assert_deadline!(
            "stream safety admission deadline",
            MetricCommand::StreamSafety,
            async {
                classifier
                    .stream_safety(tokio_stream::iter(vec![SafetyToken {
                        tenant: String::new(),
                        rules: vec![],
                        token: "queued".to_string(),
                    }]))
                    .await
                    .map(|_| ())
            }
        );

        release_worker.release();
        worker_faults
            .wait_for_active_workers("classify", 0, std::time::Duration::from_secs(3))
            .await
            .expect("the held worker exits before recovery begins");
        let mut recovery = classifier_client(server.endpoint.clone()).await;
        bounded_external(
            "post-deadline worker recovery",
            recovery.quality(QualityRequest {
                tenant: String::new(),
                text: "recovered".to_string(),
            }),
        )
        .await
        .expect("capacity recovers only after the held worker exits");
        server.stop().await;
    }

    #[tokio::test]
    async fn real_tonic_unary_bodies_obey_four_mib_retained_budget_before_queueing() {
        use crate::metrics::{
            Command as MetricCommand, OutcomeExpectation, OutcomeProbe, Reason, Stage, Transport,
        };

        const RETAINED_BODY_BUDGET: usize = 4 * MAX_TEXT_BYTES;
        const REQUESTS_PER_WAVE: usize = 8;

        #[derive(Clone, Copy, Debug)]
        enum PressureMethod {
            Quality,
            Classify,
        }

        fn spawn_pressure_call(
            calls: &mut tokio::task::JoinSet<(usize, PressureMethod, Result<(), tonic::Status>)>,
            endpoint: String,
            index: usize,
            method: PressureMethod,
        ) {
            calls.spawn(async move {
                let outcome = match method {
                    PressureMethod::Quality => {
                        let mut client = classifier_client(endpoint).await;
                        client
                            .quality(QualityRequest {
                                tenant: String::new(),
                                text: "q".repeat(MAX_TEXT_BYTES),
                            })
                            .await
                            .map(|_| ())
                    }
                    PressureMethod::Classify => {
                        let mut client = inference_client(endpoint).await;
                        client
                            .classify(ClassifyRequest {
                                model: "classifier-a".to_string(),
                                text: "c".repeat(MAX_TEXT_BYTES),
                                top_k: 1,
                            })
                            .await
                            .map(|_| ())
                    }
                };
                (index, method, outcome)
            });
        }

        async fn run_asymmetric_wave(
            endpoint: &str,
            ingress: &Arc<GrpcIngressProbe>,
            controls: &Arc<GrpcTestControl>,
            held: [PressureMethod; 4],
            refused: [PressureMethod; 4],
            cumulative_refusals: usize,
            name: &'static str,
        ) -> Vec<(usize, PressureMethod, Result<(), tonic::Status>)> {
            let quality_holders = held
                .iter()
                .filter(|method| matches!(method, PressureMethod::Quality))
                .count();
            let classify_holders = held.len() - quality_holders;
            let held_quality = controls.hold_next_n(MetricCommand::Quality, quality_holders);
            let held_classify = controls.hold_next_n(MetricCommand::Classify, classify_holders);
            let _release_handlers = ReleaseGrpcHandlersOnDrop(vec![&held_quality, &held_classify]);
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
            let mut calls = tokio::task::JoinSet::new();

            for (index, method) in held.into_iter().enumerate() {
                spawn_pressure_call(&mut calls, endpoint.to_string(), index, method);
            }

            tokio::time::timeout_at(
                deadline,
                ingress.wait_for_active_request_permits(
                    4,
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("{name}: shared request-owner barrier timed out"))
            .unwrap_or_else(|error| panic!("{name}: shared request-owner barrier failed: {error}"));
            tokio::time::timeout_at(
                deadline,
                held_quality.wait_for_entered(
                    quality_holders,
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("{name}: Quality handler barrier timed out"))
            .unwrap_or_else(|error| panic!("{name}: Quality handler barrier failed: {error}"));
            tokio::time::timeout_at(
                deadline,
                held_classify.wait_for_entered(
                    classify_holders,
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("{name}: Classify handler barrier timed out"))
            .unwrap_or_else(|error| panic!("{name}: Classify handler barrier failed: {error}"));

            for (offset, method) in refused.into_iter().enumerate() {
                spawn_pressure_call(
                    &mut calls,
                    endpoint.to_string(),
                    held.len() + offset,
                    method,
                );
            }
            tokio::time::timeout_at(
                deadline,
                ingress.wait_for_predecode_refusals(
                    cumulative_refusals,
                    deadline.saturating_duration_since(tokio::time::Instant::now()),
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("{name}: plus-one refusal barrier timed out"))
            .unwrap_or_else(|error| panic!("{name}: plus-one refusal barrier failed: {error}"));

            held_quality.release_all();
            held_classify.release_all();
            let mut results = Vec::with_capacity(REQUESTS_PER_WAVE);
            while results.len() < REQUESTS_PER_WAVE {
                let joined = tokio::time::timeout_at(deadline, calls.join_next())
                    .await
                    .unwrap_or_else(|_| {
                        panic!("{name}: eight-result collection exceeded one absolute deadline")
                    })
                    .expect("all eight pressure tasks remain in the bounded JoinSet")
                    .unwrap_or_else(|error| panic!("{name}: pressure caller panicked: {error}"));
                results.push(joined);
            }
            assert!(
                calls.is_empty(),
                "{name}: exactly eight callers were spawned"
            );
            results.sort_by_key(|(index, _, _)| *index);
            results
        }

        let outcomes_probe = OutcomeProbe::acquire_unique().await;
        let worker_faults = Arc::new(crate::admission::BlockingExecutorFaultControl::default());
        let state = validated_mixed_state(
            Admission::new(4, 8, std::time::Duration::from_secs(5)).unwrap(),
            worker_faults,
        );
        let ingress = Arc::new(GrpcIngressProbe::default());
        let controls = Arc::new(GrpcTestControl::default());
        let limits = GrpcServerLimits::test_defaults()
            .with_global_request_limit(4)
            .with_retained_decoded_body_budget(RETAINED_BODY_BUDGET)
            .with_ingress_probe(Arc::clone(&ingress))
            .with_test_control(Arc::clone(&controls));
        let server = spawn_real_tonic_with_limits(state, limits).await;
        let terminal_before = outcomes_probe.snapshot();
        let mut outcomes = run_asymmetric_wave(
            &server.endpoint,
            &ingress,
            &controls,
            [
                PressureMethod::Quality,
                PressureMethod::Quality,
                PressureMethod::Quality,
                PressureMethod::Classify,
            ],
            [
                PressureMethod::Quality,
                PressureMethod::Classify,
                PressureMethod::Classify,
                PressureMethod::Classify,
            ],
            4,
            "three Quality plus one Classify saturation",
        )
        .await;
        outcomes.extend(
            run_asymmetric_wave(
                &server.endpoint,
                &ingress,
                &controls,
                [
                    PressureMethod::Quality,
                    PressureMethod::Classify,
                    PressureMethod::Classify,
                    PressureMethod::Classify,
                ],
                [
                    PressureMethod::Quality,
                    PressureMethod::Quality,
                    PressureMethod::Quality,
                    PressureMethod::Classify,
                ],
                8,
                "one Quality plus three Classify saturation",
            )
            .await,
        );

        assert_eq!(ingress.peak_active_request_permits(), 4);
        let quality_request_owners = ingress
            .acquired_request_owner_fingerprints_for(MetricCommand::Quality)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let classify_request_owners = ingress
            .acquired_request_owner_fingerprints_for(MetricCommand::Classify)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            quality_request_owners == classify_request_owners,
            "opaque fingerprints captured at actual permit acquisition must match across generated services"
        );
        assert_eq!(quality_request_owners.len(), 1);
        let quality_body_owners = ingress
            .acquired_retained_body_owner_fingerprints_for(MetricCommand::Quality)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let classify_body_owners = ingress
            .acquired_retained_body_owner_fingerprints_for(MetricCommand::Classify)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            quality_body_owners == classify_body_owners,
            "opaque fingerprints captured at weighted-lease acquisition must match across services"
        );
        assert_eq!(quality_body_owners.len(), 1);
        assert_eq!(
            ingress.request_permit_acquisitions_for(MetricCommand::Quality),
            4
        );
        assert_eq!(
            ingress.request_permit_acquisitions_for(MetricCommand::Classify),
            4
        );
        assert_eq!(
            ingress.retained_body_lease_acquisitions_for(MetricCommand::Quality),
            4
        );
        assert_eq!(
            ingress.retained_body_lease_acquisitions_for(MetricCommand::Classify),
            4
        );
        assert!(
            ingress.peak_predecode_buffered_bytes() > 0,
            "the real outer owner must observe live bytes before protobuf decode"
        );
        assert!(
            ingress.peak_predecode_buffered_bytes()
                <= 4 * GrpcServerLimits::test_defaults().max_decoding_message_bytes(),
            "four global requests times the finite decode ceiling bounds predecode retention"
        );
        assert_eq!(
            ingress.global_predecode_byte_ceiling(),
            4 * GrpcServerLimits::test_defaults().max_decoding_message_bytes(),
        );
        assert_eq!(
            ingress.predecode_bytes_without_request_permit(),
            0,
            "no request bytes may be retained before the outer global lease"
        );
        assert_eq!(
            ingress.peak_retained_decoded_body_bytes(),
            RETAINED_BODY_BUDGET
        );
        assert_eq!(
            ingress.decodes_without_request_permit(),
            0,
            "every protobuf decode must be preceded by the production outer lease"
        );

        let mut quality_successes = 0usize;
        let mut classify_successes = 0usize;
        let mut quality_refusals = 0usize;
        let mut classify_refusals = 0usize;
        for (_, method, outcome) in outcomes {
            match (method, outcome) {
                (PressureMethod::Quality, Ok(())) => quality_successes += 1,
                (PressureMethod::Classify, Ok(())) => classify_successes += 1,
                (PressureMethod::Quality, Err(status))
                    if status.code() == tonic::Code::ResourceExhausted =>
                {
                    quality_refusals += 1
                }
                (PressureMethod::Classify, Err(status))
                    if status.code() == tonic::Code::ResourceExhausted =>
                {
                    classify_refusals += 1
                }
                (_, Err(status)) => panic!("unexpected unary pressure outcome: {status}"),
            }
        }
        server.stop().await;

        assert_eq!(RETAINED_BODY_BUDGET, 4 * 1024 * 1024);
        assert_eq!(quality_successes, 4);
        assert_eq!(classify_successes, 4);
        assert_eq!(quality_refusals, 4);
        assert_eq!(classify_refusals, 4);
        terminal_before.assert_exact_terminal_multiset_delta(
            &[
                (
                    OutcomeExpectation::success(Transport::Grpc, MetricCommand::Quality),
                    4,
                ),
                (
                    OutcomeExpectation::success(Transport::Grpc, MetricCommand::Classify),
                    4,
                ),
                (
                    OutcomeExpectation::failure(
                        Transport::Grpc,
                        MetricCommand::Quality,
                        Stage::Admission,
                        Reason::ResourceLimit,
                    ),
                    4,
                ),
                (
                    OutcomeExpectation::failure(
                        Transport::Grpc,
                        MetricCommand::Classify,
                        Stage::Admission,
                        Reason::ResourceLimit,
                    ),
                    4,
                ),
            ],
            "process-wide mixed-service pre-decode pressure",
        );
    }

    async fn raw_h2_connection_is_accepted(stream: &mut tokio::net::TcpStream) -> bool {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        if bounded_external(
            "raw H2 preface write",
            stream.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0"),
        )
        .await
        .is_err()
        {
            return false;
        }
        let mut response = [0u8; 256];
        let accepted = matches!(
            bounded_external("raw H2 settings read", stream.read(&mut response)).await,
            Ok(read) if read > 0
        );
        if accepted {
            let _ = bounded_external(
                "raw H2 settings acknowledgement",
                stream.write_all(b"\0\0\0\x04\x01\0\0\0\0"),
            )
            .await;
            let drain_deadline =
                tokio::time::Instant::now() + std::time::Duration::from_millis(100);
            for _ in 0..128 {
                match tokio::time::timeout_at(drain_deadline, stream.read(&mut response)).await {
                    Ok(Ok(read)) if read > 0 => {}
                    _ => break,
                }
            }
        }
        accepted
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ObservedH2Settings {
        max_concurrent_streams: u32,
        initial_stream_window_bytes: u32,
        initial_connection_window_bytes: u32,
    }

    async fn observe_raw_h2_settings(address: std::net::SocketAddr) -> ObservedH2Settings {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        const CAPTURE_CEILING: usize = 4 * 1024;
        const DEFAULT_CONNECTION_WINDOW: u32 = 65_535;
        const PROBE_BODY_BYTES: u32 = 16 * 1024;
        const PROBE_HEADERS_FRAME: &[u8] = b"\0\0\x03\x01\x04\0\0\0\x01\x82\x86\x84";

        let deadline = tokio::time::Instant::now() + EXTERNAL_WAIT;
        let mut stream = tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(address))
            .await
            .expect("raw H2 settings connection has an absolute deadline")
            .unwrap();
        tokio::time::timeout_at(
            deadline,
            stream.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0"),
        )
        .await
        .expect("raw H2 settings preface has an absolute deadline")
        .unwrap();

        let mut bytes = Vec::with_capacity(512);
        let mut parsed = 0usize;
        let mut max_streams = None;
        let mut stream_window = None;
        let mut connection_window = None;
        let mut sent_settings_ack = false;
        let mut sent_probe_headers = false;
        let probe_body = vec![b'x'; PROBE_BODY_BYTES as usize];
        while max_streams.is_none() || stream_window.is_none() || connection_window.is_none() {
            let mut chunk = [0u8; 512];
            let read = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
                .await
                .expect("raw H2 settings capture has one absolute deadline")
                .expect("raw H2 settings capture reads successfully");
            assert!(
                read > 0,
                "server closed before emitting its finite H2 settings"
            );
            assert!(
                bytes.len() + read <= CAPTURE_CEILING,
                "raw H2 settings exceeded the bounded capture ceiling"
            );
            bytes.extend_from_slice(&chunk[..read]);

            while bytes.len().saturating_sub(parsed) >= 9 {
                let length = ((bytes[parsed] as usize) << 16)
                    | ((bytes[parsed + 1] as usize) << 8)
                    | bytes[parsed + 2] as usize;
                assert!(
                    length <= CAPTURE_CEILING - 9,
                    "server emitted an oversized H2 control frame"
                );
                if bytes.len() - parsed < 9 + length {
                    break;
                }
                let frame_type = bytes[parsed + 3];
                let flags = bytes[parsed + 4];
                let stream_id = u32::from_be_bytes([
                    bytes[parsed + 5],
                    bytes[parsed + 6],
                    bytes[parsed + 7],
                    bytes[parsed + 8],
                ]) & 0x7fff_ffff;
                let payload = &bytes[parsed + 9..parsed + 9 + length];
                if frame_type == 0x04 && stream_id == 0 && flags & 0x01 == 0 {
                    assert_eq!(payload.len() % 6, 0, "malformed server SETTINGS frame");
                    for setting in payload.chunks_exact(6) {
                        let id = u16::from_be_bytes([setting[0], setting[1]]);
                        let value =
                            u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
                        match id {
                            0x03 => max_streams = Some(value),
                            0x04 => stream_window = Some(value),
                            _ => {}
                        }
                    }
                    if !sent_settings_ack {
                        tokio::time::timeout_at(
                            deadline,
                            stream.write_all(b"\0\0\0\x04\x01\0\0\0\0"),
                        )
                        .await
                        .expect("raw H2 settings acknowledgement has an absolute deadline")
                        .expect("raw H2 settings acknowledgement writes successfully");
                        sent_settings_ack = true;
                        if connection_window.is_none() && !sent_probe_headers {
                            tokio::time::timeout_at(
                                deadline,
                                stream.write_all(PROBE_HEADERS_FRAME),
                            )
                            .await
                            .expect("raw H2 probe request has an absolute deadline")
                            .expect("raw H2 probe request writes successfully");
                            let probe_data_header = [
                                ((PROBE_BODY_BYTES >> 16) & 0xff) as u8,
                                ((PROBE_BODY_BYTES >> 8) & 0xff) as u8,
                                (PROBE_BODY_BYTES & 0xff) as u8,
                                0x00,
                                0x01,
                                0x00,
                                0x00,
                                0x00,
                                0x01,
                            ];
                            tokio::time::timeout_at(deadline, stream.write_all(&probe_data_header))
                                .await
                                .expect("raw H2 probe DATA header has an absolute deadline")
                                .expect("raw H2 probe DATA header writes successfully");
                            tokio::time::timeout_at(deadline, stream.write_all(&probe_body))
                                .await
                                .expect("raw H2 probe DATA payload has an absolute deadline")
                                .expect("raw H2 probe DATA payload writes successfully");
                            sent_probe_headers = true;
                        }
                    }
                } else if frame_type == 0x08 && stream_id == 0 && payload.len() == 4 {
                    let increment =
                        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                            & 0x7fff_ffff;
                    connection_window = Some(
                        DEFAULT_CONNECTION_WINDOW
                            .checked_sub(PROBE_BODY_BYTES)
                            .expect("probe body remains within the default connection window")
                            .checked_add(increment)
                            .expect("advertised connection window cannot overflow"),
                    );
                }
                parsed += 9 + length;
            }
        }

        ObservedH2Settings {
            max_concurrent_streams: max_streams.unwrap(),
            initial_stream_window_bytes: stream_window.unwrap(),
            initial_connection_window_bytes: connection_window.unwrap(),
        }
    }

    async fn raw_connection_is_closed(
        stream: &mut tokio::net::TcpStream,
        within: std::time::Duration,
    ) -> bool {
        use tokio::io::AsyncReadExt as _;

        let deadline = tokio::time::Instant::now() + within;
        let mut frame = [0u8; 256];
        for _ in 0..128 {
            match tokio::time::timeout_at(deadline, stream.read(&mut frame)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => {
                    // An idle-expiring H2 server may send GOAWAY before it
                    // closes the socket. Keep draining bounded frames so a
                    // terminal control frame is not mistaken for liveness.
                }
                Err(_) => return false,
            }
        }
        false
    }

    #[tokio::test]
    async fn production_tonic_listener_owns_exact_connection_permits_and_deadline_recovery() {
        use crate::metrics::{
            Command as MetricCommand, OutcomeExpectation, OutcomeProbe, Reason, Stage, Transport,
        };

        const CONNECTION_BUDGET: usize = 4;
        const PROCESS_INGRESS_BUDGET: usize = 16 * 1024 * 1024;
        const DECODE_CEILING: usize = MAX_TEXT_BYTES + 64 * 1024;
        let outcomes = OutcomeProbe::acquire_unique().await;
        let ingress = Arc::new(GrpcIngressProbe::default());
        let deadline_clock = Arc::new(GrpcTestClock::paused());
        let defaults = GrpcServerLimits::from_process_memory_budget(PROCESS_INGRESS_BUDGET)
            .expect("the documented ingress budget is valid");
        assert_eq!(defaults.max_connections(), 64);
        assert_eq!(defaults.max_global_requests(), 4);
        assert_eq!(defaults.max_retained_decoded_body_bytes(), 4 * 1024 * 1024);
        assert_eq!(defaults.max_decoding_message_bytes(), DECODE_CEILING);
        assert_eq!(defaults.max_concurrent_streams_per_connection(), 4);
        assert_eq!(defaults.initial_stream_window_bytes(), 64 * 1024);
        assert_eq!(defaults.initial_connection_window_bytes(), 80 * 1024);
        assert_eq!(
            defaults.request_timeout(),
            std::time::Duration::from_secs(2)
        );
        assert_eq!(
            defaults.handshake_timeout(),
            std::time::Duration::from_secs(5)
        );
        assert_eq!(defaults.idle_timeout(), std::time::Duration::from_secs(30));
        assert_eq!(
            defaults.max_connection_age(),
            std::time::Duration::from_secs(300)
        );
        let limits = defaults
            .with_connection_limit(CONNECTION_BUDGET)
            .with_handshake_timeout(std::time::Duration::from_millis(150))
            .with_idle_timeout(std::time::Duration::from_millis(200))
            .with_test_clock(Arc::clone(&deadline_clock))
            .with_ingress_probe(Arc::clone(&ingress));
        let server = spawn_real_tonic_with_limits(raw_state(), limits).await;
        let mut held = Vec::with_capacity(CONNECTION_BUDGET);
        for index in 0..CONNECTION_BUDGET / 2 {
            let stream = bounded_external(
                "stalled H2 handshake connects",
                tokio::net::TcpStream::connect(server.address),
            )
            .await
            .unwrap();
            held.push(stream);
            ingress
                .wait_for_active_connections(index + 1, std::time::Duration::from_secs(3))
                .await
                .expect("stalled handshake owns a production connection permit");
        }
        for index in CONNECTION_BUDGET / 2..CONNECTION_BUDGET {
            let mut stream = bounded_external(
                "established H2 connection connects",
                tokio::net::TcpStream::connect(server.address),
            )
            .await
            .unwrap();
            assert!(
                raw_h2_connection_is_accepted(&mut stream).await,
                "exact-limit established H2 connection {index} must be accepted"
            );
            held.push(stream);
            ingress
                .wait_for_active_connections(index + 1, std::time::Duration::from_secs(3))
                .await
                .expect("established H2 session owns a production connection permit");
        }
        assert_eq!(ingress.peak_active_connections(), CONNECTION_BUDGET);

        let refusal_before = outcomes.snapshot();
        let mut plus_one = bounded_external(
            "plus-one kernel connection",
            tokio::net::TcpStream::connect(server.address),
        )
        .await
        .unwrap();
        use tokio::io::AsyncWriteExt as _;
        let _ = bounded_external(
            "plus-one H2 preface",
            plus_one.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
        )
        .await;
        ingress
            .wait_for_refused_connections(1, std::time::Duration::from_secs(3))
            .await
            .expect("the process owner observes plus-one refusal independently of connect(2)");
        assert!(
            raw_connection_is_closed(&mut plus_one, std::time::Duration::from_secs(3)).await,
            "the refused socket must reach EOF/reset after any bounded control frames"
        );
        refusal_before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Unknown,
                Stage::Admission,
                Reason::ResourceLimit,
            ),
            "gRPC connection limit",
        );

        let expiry_before = outcomes.snapshot();
        deadline_clock.advance(std::time::Duration::from_millis(201));
        ingress
            .wait_for_expired_handshakes(CONNECTION_BUDGET / 2, std::time::Duration::from_secs(3))
            .await
            .expect("stalled H2 handshakes expire");
        ingress
            .wait_for_expired_idle_connections(
                CONNECTION_BUDGET / 2,
                std::time::Duration::from_secs(3),
            )
            .await
            .expect("established idle H2 sessions expire");
        ingress
            .wait_for_active_connections(0, std::time::Duration::from_secs(3))
            .await
            .expect("deadline expiry returns all production permits");
        expiry_before.assert_exact_terminal_multiset_delta(
            &[(
                OutcomeExpectation::failure(
                    Transport::Grpc,
                    MetricCommand::Unknown,
                    Stage::Read,
                    Reason::Deadline,
                ),
                CONNECTION_BUDGET as u64,
            )],
            "gRPC handshake and established-idle connection expiry",
        );
        for stream in &mut held {
            assert!(
                raw_connection_is_closed(stream, std::time::Duration::from_secs(3)).await,
                "expired connections drain through GOAWAY to EOF/reset"
            );
        }

        let mut recovered = bounded_external(
            "deadline recovery connection",
            tokio::net::TcpStream::connect(server.address),
        )
        .await
        .unwrap();
        assert!(raw_h2_connection_is_accepted(&mut recovered).await);
        ingress
            .wait_for_active_connections(1, std::time::Duration::from_secs(3))
            .await
            .expect("a deadline-released permit admits a new H2 connection");
        drop(recovered);
        drop(held);
        ingress
            .wait_for_active_connections(0, std::time::Duration::from_secs(3))
            .await
            .expect("client drop also returns a production connection permit");
        server.stop().await;
    }

    #[tokio::test]
    async fn production_tonic_decode_h2_timeout_and_age_limits_are_finite_and_live() {
        use crate::metrics::{
            Command as MetricCommand, OutcomeExpectation, OutcomeProbe, Reason, Stage, Transport,
        };
        use prost::Message as _;

        const PROCESS_INGRESS_BUDGET: usize = 16 * 1024 * 1024;
        const DECODE_CEILING: usize = MAX_TEXT_BYTES + 64 * 1024;
        const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
        let outcomes = OutcomeProbe::acquire_unique().await;
        let ingress = Arc::new(GrpcIngressProbe::default());
        let controls = Arc::new(GrpcTestControl::default());
        let clock = Arc::new(GrpcTestClock::paused());
        let limits = GrpcServerLimits::from_process_memory_budget(PROCESS_INGRESS_BUDGET)
            .unwrap()
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_test_clock(Arc::clone(&clock))
            .with_ingress_probe(Arc::clone(&ingress))
            .with_test_control(Arc::clone(&controls));
        let state = validated_mixed_state(
            Admission::new(2, 4, std::time::Duration::from_secs(5)).unwrap(),
            Arc::new(crate::admission::BlockingExecutorFaultControl::default()),
        );
        let server = spawn_real_tonic_with_limits(state, limits).await;

        let observed = observe_raw_h2_settings(server.address).await;
        assert_eq!(
            observed,
            ObservedH2Settings {
                max_concurrent_streams: 4,
                initial_stream_window_bytes: 64 * 1024,
                initial_connection_window_bytes: 80 * 1024,
            },
            "the live production server must advertise its finite H2 stream/window contract",
        );
        ingress
            .wait_for_active_connections(0, std::time::Duration::from_secs(3))
            .await
            .expect("the raw settings probe returns its connection permit");

        let quality_decodes_before = ingress.decoded_messages(MetricCommand::Quality);
        let mut classifier = classifier_client(server.endpoint.clone()).await;
        let exact_quality = quality_request_with_encoded_len(DECODE_CEILING);
        assert_eq!(exact_quality.encoded_len(), DECODE_CEILING);
        let before = outcomes.snapshot();
        let status = bounded_external(
            "exact-ceiling classifier-service decode",
            classifier.quality(exact_quality),
        )
        .await
        .expect_err("the decoded request reaches the smaller application text cap");
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
        before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Quality,
                Stage::Limit,
                Reason::ResourceLimit,
            ),
            "classifier service exact decode ceiling",
        );
        let before = outcomes.snapshot();
        let plus_one_quality = quality_request_with_encoded_len(DECODE_CEILING + 1);
        assert_eq!(plus_one_quality.encoded_len(), DECODE_CEILING + 1);
        let status = bounded_external(
            "plus-one classifier-service decode",
            classifier.quality(plus_one_quality),
        )
        .await
        .expect_err("the generated classifier service must reject before its handler");
        assert_eq!(status.code(), tonic::Code::OutOfRange);
        before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Quality,
                Stage::Decode,
                Reason::ResourceLimit,
            ),
            "classifier service decode plus one",
        );
        assert_eq!(
            ingress.decoded_messages(MetricCommand::Quality),
            quality_decodes_before + 1,
            "only the exact-ceiling classifier-service body may be decoded",
        );

        let inference_decodes_before = ingress.decoded_messages(MetricCommand::Classify);
        let mut inference = inference_client(server.endpoint.clone()).await;
        let exact_classify = classify_request_with_encoded_len(DECODE_CEILING);
        assert_eq!(exact_classify.encoded_len(), DECODE_CEILING);
        let before = outcomes.snapshot();
        let status = bounded_external(
            "exact-ceiling inference-service decode",
            inference.classify(exact_classify),
        )
        .await
        .expect_err("the decoded request reaches the smaller application text cap");
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
        before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Classify,
                Stage::Limit,
                Reason::ResourceLimit,
            ),
            "inference service exact decode ceiling",
        );
        let before = outcomes.snapshot();
        let plus_one_classify = classify_request_with_encoded_len(DECODE_CEILING + 1);
        assert_eq!(plus_one_classify.encoded_len(), DECODE_CEILING + 1);
        let status = bounded_external(
            "plus-one inference-service decode",
            inference.classify(plus_one_classify),
        )
        .await
        .expect_err("the generated inference service must reject before its handler");
        assert_eq!(status.code(), tonic::Code::OutOfRange);
        before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Classify,
                Stage::Decode,
                Reason::ResourceLimit,
            ),
            "inference service decode plus one",
        );
        assert_eq!(
            ingress.decoded_messages(MetricCommand::Classify),
            inference_decodes_before + 1,
            "only the exact-ceiling inference-service body may be decoded",
        );

        let held_quality_timeout = controls.hold_next_n(MetricCommand::Quality, 1);
        let held_classify_timeout = controls.hold_next_n(MetricCommand::Classify, 1);
        let _release_timeouts =
            ReleaseGrpcHandlersOnDrop(vec![&held_quality_timeout, &held_classify_timeout]);
        let timeout_before = outcomes.snapshot();
        let mut timeout_client = classifier_client(server.endpoint.clone()).await;
        let timed = tokio::spawn(async move {
            timeout_client
                .quality(QualityRequest {
                    tenant: String::new(),
                    text: "held behind the live outer deadline".to_string(),
                })
                .await
        });
        held_quality_timeout
            .wait_for_entered(1, std::time::Duration::from_secs(3))
            .await
            .expect("the exact live request is held in the production handler");
        clock.advance(REQUEST_TIMEOUT + std::time::Duration::from_millis(1));
        let status = bounded_external("live outer request timeout", timed)
            .await
            .unwrap()
            .expect_err("the finite outer request deadline must terminate the call");
        assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
        timeout_before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Quality,
                Stage::Handler,
                Reason::Deadline,
            ),
            "live outer request timeout",
        );
        held_quality_timeout.release_all();
        ingress
            .wait_for_active_request_permits(0, std::time::Duration::from_secs(3))
            .await
            .expect("the timed-out outer request returns its global permit");

        let inference_timeout_before = outcomes.snapshot();
        let mut inference_timeout_client = inference_client(server.endpoint.clone()).await;
        let inference_timed = tokio::spawn(async move {
            inference_timeout_client
                .classify(ClassifyRequest {
                    model: "classifier-a".to_string(),
                    text: "held InferenceService request".to_string(),
                    top_k: 1,
                })
                .await
        });
        held_classify_timeout
            .wait_for_entered(1, std::time::Duration::from_secs(3))
            .await
            .expect("InferenceService enters behind the same live outer deadline");
        clock.advance(REQUEST_TIMEOUT + std::time::Duration::from_millis(1));
        let status = bounded_external(
            "live InferenceService outer request timeout",
            inference_timed,
        )
        .await
        .unwrap()
        .expect_err("the finite outer timeout must also terminate InferenceService");
        assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
        inference_timeout_before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Classify,
                Stage::Handler,
                Reason::Deadline,
            ),
            "live InferenceService outer request timeout",
        );
        held_classify_timeout.release_all();
        ingress
            .wait_for_active_request_permits(0, std::time::Duration::from_secs(3))
            .await
            .expect("InferenceService timeout returns the shared process permit");
        drop(inference);
        drop(classifier);
        server.stop().await;

        let age_clock = Arc::new(GrpcTestClock::paused());
        let age_ingress = Arc::new(GrpcIngressProbe::default());
        let age_limits = GrpcServerLimits::from_process_memory_budget(PROCESS_INGRESS_BUDGET)
            .unwrap()
            .with_idle_timeout(std::time::Duration::from_secs(3_600))
            .with_max_connection_age(std::time::Duration::from_millis(200))
            .with_test_clock(Arc::clone(&age_clock))
            .with_ingress_probe(Arc::clone(&age_ingress));
        let age_server = spawn_real_tonic_with_limits(raw_state(), age_limits).await;
        let age_before = outcomes.snapshot();
        let mut aged = bounded_external(
            "max-age H2 connection",
            tokio::net::TcpStream::connect(age_server.address),
        )
        .await
        .unwrap();
        assert!(raw_h2_connection_is_accepted(&mut aged).await);
        age_ingress
            .wait_for_active_connections(1, std::time::Duration::from_secs(3))
            .await
            .expect("the established session owns its permit before max age");
        age_clock.advance(std::time::Duration::from_millis(201));
        age_ingress
            .wait_for_max_age_expirations(1, std::time::Duration::from_secs(3))
            .await
            .expect("the production max-connection-age timer fires");
        age_ingress
            .wait_for_active_connections(0, std::time::Duration::from_secs(3))
            .await
            .expect("max-age expiry returns the connection permit");
        assert!(
            raw_connection_is_closed(&mut aged, std::time::Duration::from_secs(3)).await,
            "max-age expiry drains GOAWAY through EOF/reset"
        );
        age_before.assert_exact_terminal_delta(
            OutcomeExpectation::failure(
                Transport::Grpc,
                MetricCommand::Unknown,
                Stage::Read,
                Reason::Deadline,
            ),
            "gRPC maximum connection age",
        );
        age_server.stop().await;
    }

    #[tokio::test]
    async fn real_tonic_stream_uses_only_first_message_rules_and_ignores_later_rules() {
        let controls = Arc::new(GrpcTestControl::default());
        let stream_probe = controls.stream_safety_probe();
        let server = spawn_real_tonic_with_limits(
            raw_state(),
            GrpcServerLimits::test_defaults().with_test_control(Arc::clone(&controls)),
        )
        .await;
        let mut client = classifier_client(server.endpoint.clone()).await;
        let input = tokio_stream::iter(vec![
            SafetyToken {
                tenant: "tenant-a".to_string(),
                rules: vec!["forbidden".to_string()],
                token: "safe".to_string(),
            },
            SafetyToken {
                tenant: String::new(),
                rules: vec!["changed".to_string()],
                token: "changed".to_string(),
            },
            SafetyToken {
                tenant: String::new(),
                rules: Vec::new(),
                token: "forbidden".to_string(),
            },
        ]);
        let mut output = bounded_external(
            "first-message rules stream start",
            client.stream_safety(input),
        )
        .await
        .unwrap()
        .into_inner();
        let first = bounded_external("first rules verdict", output.message())
            .await
            .unwrap()
            .expect("first verdict is delivered");
        let later_only = bounded_external("ignored later rules verdict", output.message())
            .await
            .unwrap()
            .expect("later rule is ignored and still produces a verdict");
        let first_rule = bounded_external("persistent first rule verdict", output.message())
            .await
            .unwrap()
            .expect("the first-message rule remains active");
        assert!(
            bounded_external("first-message rules clean EOF", output.message())
                .await
                .unwrap()
                .is_none()
        );
        server.stop().await;

        assert!(first.safe && !first.blocked);
        assert!(later_only.safe && !later_only.blocked);
        assert!(!first_rule.safe && first_rule.blocked);
        assert_eq!(first_rule.reason, "matched rule: forbidden");
        assert_eq!(stream_probe.first_tenant(), Some("tenant-a".to_string()));
        assert_eq!(
            stream_probe.later_tenant_or_rule_updates_applied(),
            0,
            "later rule/tenant fields are wire-compatible ignored metadata"
        );
    }

    #[tokio::test]
    async fn validated_model_catalog_owns_inventory_defaults_and_prebind_rejection() {
        const MAX_MODEL_ID_BYTES: usize = 256;
        const MAX_MANIFEST_MODELS: usize = 64;

        fn descriptor(id: &str, kind: ModelKind) -> ModelDescriptor {
            let is_embedder = kind == ModelKind::Embedder;
            let is_classifier = kind == ModelKind::Classifier;
            ModelDescriptor {
                id: id.to_string(),
                kind,
                tokenizer: "validated-tokenizer".to_string(),
                dimensions: is_embedder.then_some(384),
                labels: is_classifier.then(|| vec!["safe".to_string(), "unsafe".to_string()]),
            }
        }

        let catalog_limits = ModelCatalogLimits::production_defaults();
        assert_eq!(catalog_limits.max_model_id_bytes(), MAX_MODEL_ID_BYTES);
        assert_eq!(catalog_limits.max_models(), MAX_MANIFEST_MODELS);

        let exact_utf8_id = "é".repeat(MAX_MODEL_ID_BYTES / 2);
        assert_eq!(exact_utf8_id.len(), MAX_MODEL_ID_BYTES);
        let exact_id_catalog = ModelCatalog::validate_descriptors(ModelManifest {
            models: vec![descriptor(&exact_utf8_id, ModelKind::Classifier)],
            default_classifier: Some(exact_utf8_id.clone()),
            default_embedder: None,
        })
        .expect("a non-ASCII model id at the exact byte ceiling is valid");
        assert_eq!(
            exact_id_catalog.default_classifier_id(),
            Some(exact_utf8_id.as_str())
        );

        let exact_count_manifest = ModelManifest {
            models: (0..MAX_MANIFEST_MODELS)
                .map(|index| descriptor(&format!("model-{index:02}"), ModelKind::Classifier))
                .collect(),
            default_classifier: Some("model-00".to_string()),
            default_embedder: None,
        };
        let exact_count_catalog = ModelCatalog::validate_descriptors(exact_count_manifest)
            .expect("the literal exact manifest-count ceiling is valid");
        assert_eq!(exact_count_catalog.inventory().len(), MAX_MANIFEST_MODELS);

        let manifest = ModelManifest {
            models: vec![
                descriptor("embedder-b", ModelKind::Embedder),
                descriptor("classifier-a", ModelKind::Classifier),
            ],
            default_classifier: Some("classifier-a".to_string()),
            default_embedder: Some("embedder-b".to_string()),
        };
        let catalog = ModelCatalog::validate_descriptors(manifest.clone())
            .expect("mixed descriptor catalog is unambiguous");
        assert_eq!(
            catalog.inventory(),
            &["classifier-a".to_string(), "embedder-b".to_string()],
            "one sorted catalog owns every externally reported logical id"
        );
        assert_eq!(catalog.default_classifier_id(), Some("classifier-a"));
        assert_eq!(catalog.default_embedder_id(), Some("embedder-b"));
        let loaded_mixed = ModelCatalog::load_validated_fixture(ValidatedModelFixture::Mixed)
            .expect("genuine classifier and embedding fixtures load through the catalog owner");
        let state = Arc::new(GrpcState::from_catalog(
            loaded_mixed,
            "sbproxy-classifier test".to_string(),
            crate::admission::BlockingWorkExecutor::new(
                Admission::new(2, 4, std::time::Duration::from_secs(1)).unwrap(),
            ),
        ));
        let server = spawn_real_tonic(state).await;
        let mut client = inference_client(server.endpoint.clone()).await;

        let default = bounded_external(
            "default classifier ModelInfo",
            client.model_info(ModelInfoRequest {
                model: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let explicit_embedder = bounded_external(
            "explicit embedder ModelInfo",
            client.model_info(ModelInfoRequest {
                model: "embedder-b".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let version = bounded_external("mixed Version", client.version(VersionRequest {}))
            .await
            .unwrap()
            .into_inner();
        server.stop().await;

        let embedder_only_descriptor_catalog = ModelCatalog::validate_descriptors(ModelManifest {
            models: vec![descriptor("embedder-b", ModelKind::Embedder)],
            default_classifier: None,
            default_embedder: Some("embedder-b".to_string()),
        })
        .unwrap();
        assert_eq!(
            embedder_only_descriptor_catalog.default_classifier_id(),
            None
        );
        assert_eq!(
            embedder_only_descriptor_catalog.default_embedder_id(),
            Some("embedder-b")
        );
        let embedder_only_catalog =
            ModelCatalog::load_validated_fixture(ValidatedModelFixture::EmbedderOnly)
                .expect("the embedder-only fixture has a genuine embedding output shape");
        let embedder_only = Arc::new(GrpcState::from_catalog(
            embedder_only_catalog,
            "sbproxy-classifier test".to_string(),
            crate::admission::BlockingWorkExecutor::new(
                Admission::new(2, 4, std::time::Duration::from_secs(1)).unwrap(),
            ),
        ));
        let embedder_server = spawn_real_tonic(embedder_only).await;
        let mut embedder_client = inference_client(embedder_server.endpoint.clone()).await;
        let embedder_only_default = bounded_external(
            "embedder-only empty ModelInfo",
            embedder_client.model_info(ModelInfoRequest {
                model: String::new(),
            }),
        )
        .await;
        embedder_server.stop().await;

        assert!(default.loaded);
        assert_eq!(default.model, "classifier-a");
        assert_eq!(explicit_embedder.model, "embedder-b");
        assert!(explicit_embedder.loaded);
        assert_eq!(explicit_embedder.embedding_dim, 384);
        assert_eq!(
            version.models,
            vec!["classifier-a".to_string(), "embedder-b".to_string()],
            "Version must report every logical id the sidecar can serve"
        );
        let embedder_only_default = embedder_only_default
            .expect("empty ModelInfo is a classifier lookup, not an embedder probe")
            .into_inner();
        assert!(
            !embedder_only_default.loaded,
            "an empty ModelInfo request must not silently select the default embedder"
        );
        assert!(embedder_only_default.model.is_empty());

        let mut oversized_utf8_id = exact_utf8_id;
        oversized_utf8_id.push('x');
        assert_eq!(oversized_utf8_id.len(), MAX_MODEL_ID_BYTES + 1);
        let excessive_count_manifest = ModelManifest {
            models: (0..=MAX_MANIFEST_MODELS)
                .map(|index| descriptor(&format!("overflow-{index:02}"), ModelKind::Classifier))
                .collect(),
            default_classifier: Some("overflow-00".to_string()),
            default_embedder: None,
        };
        let invalid_manifests = [
            ModelManifest {
                models: vec![descriptor("", ModelKind::Classifier)],
                default_classifier: Some(String::new()),
                default_embedder: None,
            },
            ModelManifest {
                models: vec![descriptor(&oversized_utf8_id, ModelKind::Classifier)],
                default_classifier: Some(oversized_utf8_id),
                default_embedder: None,
            },
            excessive_count_manifest,
            ModelManifest {
                models: vec![
                    descriptor("duplicate", ModelKind::Classifier),
                    descriptor("duplicate", ModelKind::Classifier),
                ],
                default_classifier: Some("duplicate".to_string()),
                default_embedder: None,
            },
            ModelManifest {
                models: vec![
                    descriptor("collision", ModelKind::Classifier),
                    descriptor("collision", ModelKind::Embedder),
                ],
                default_classifier: Some("collision".to_string()),
                default_embedder: Some("collision".to_string()),
            },
            ModelManifest {
                models: vec![descriptor("classifier-a", ModelKind::Classifier)],
                default_classifier: Some("missing".to_string()),
                default_embedder: None,
            },
            ModelManifest {
                models: vec![descriptor("embedder-b", ModelKind::Embedder)],
                default_classifier: Some("embedder-b".to_string()),
                default_embedder: Some("embedder-b".to_string()),
            },
            ModelManifest {
                models: vec![descriptor("embedder-b", ModelKind::Embedder)],
                default_classifier: None,
                default_embedder: Some("missing".to_string()),
            },
            ModelManifest {
                models: vec![descriptor("classifier-a", ModelKind::Classifier)],
                default_classifier: Some("classifier-a".to_string()),
                default_embedder: Some("classifier-a".to_string()),
            },
        ];
        for invalid in invalid_manifests {
            let startup_probe = Arc::new(crate::startup::StartupProbe::default());
            let result = bounded_external(
                "invalid manifest pre-bind rejection",
                startup_probe.observe_current_task(crate::startup::ClassifierRuntime::prepare(
                    invalid,
                    crate::startup::RuntimeLimits::test_defaults(),
                )),
            )
            .await;
            assert!(result.is_err(), "invalid model manifest reached startup");
            assert_eq!(startup_probe.model_loads(), 0);
            assert_eq!(startup_probe.listener_binds(), 0);
            assert_eq!(startup_probe.catalog_owned_id_bytes(), 0);
        }
    }
}
