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
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use prost::Message as _;
use sbproxy_classifier_proto::{
    compress_request, ClassifyRequest, ClassifyResponse, CompressRequest, CompressResponse,
    EmbedRequest, EmbedResponse, Embedding, InferenceService, InferenceServiceServer, Label,
    ModelInfoRequest, ModelInfoResponse, VersionRequest, VersionResponse,
};
use sbproxy_classifiers::{
    LoadOptions, OnnxClassifier, OnnxEmbedder, OnnxTokenClassifier, TokenCompressionLimitError,
    TokenCompressionLimits, TokenCompressionOutput, TokenCompressionTarget,
    MAX_MODEL_BYTES_DEFAULT,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::transport::Server;
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
const MAX_MODEL_ID_BYTES: usize = 256;
const DEFAULT_GRPC_DECODING_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

fn grpc_decoding_message_limit(max_request_bytes: usize) -> usize {
    DEFAULT_GRPC_DECODING_MESSAGE_BYTES.max(max_request_bytes)
}

fn validate_model_id(model: &str) -> std::result::Result<(), &'static str> {
    if model.len() > MAX_MODEL_ID_BYTES {
        return Err("model id exceeds the 256-byte limit");
    }
    Ok(())
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

struct CompressionAdmission {
    running: Arc<Semaphore>,
    admitted: Arc<Semaphore>,
}

impl CompressionAdmission {
    fn new(max_concurrent: usize, max_queued: usize) -> Self {
        Self {
            running: Arc::new(Semaphore::new(max_concurrent)),
            admitted: Arc::new(Semaphore::new(max_concurrent + max_queued)),
        }
    }

    async fn acquire(&self) -> std::result::Result<CompressionPermits, Status> {
        let admitted = Arc::clone(&self.admitted)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("token-compression queue is full"))?;
        let running = Arc::clone(&self.running)
            .acquire_owned()
            .await
            .map_err(|_| Status::unavailable("token-compression admission is unavailable"))?;
        Ok(CompressionPermits {
            _admitted: admitted,
            _running: running,
        })
    }
}

struct CompressionPermits {
    _admitted: OwnedSemaphorePermit,
    _running: OwnedSemaphorePermit,
}

/// The `InferenceService` implementation, backed by a registry of loaded
/// tract ONNX classifiers keyed by logical model id.
struct SidecarService {
    models: HashMap<String, Arc<OnnxClassifier>>,
    /// Embedding models keyed by logical id, paired with the embedding
    /// dimension learned at load time (for `ModelInfo`).
    embedders: HashMap<String, (Arc<OnnxEmbedder>, u32)>,
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
    /// Bounds blocking inference work and the requests waiting behind it.
    compression_admission: CompressionAdmission,
    /// Reported by the `Version` RPC.
    version: String,
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
    fn resolve(&self, model: &str) -> Option<(String, Arc<OnnxClassifier>)> {
        let id = if model.is_empty() {
            self.default_model.clone()?
        } else {
            model.to_string()
        };
        self.models.get(&id).map(|m| (id, Arc::clone(m)))
    }

    /// Resolve a request's `model` field (or the default) to a loaded
    /// embedder.
    fn resolve_embedder(&self, model: &str) -> Option<(String, Arc<OnnxEmbedder>)> {
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
}

#[tonic::async_trait]
impl InferenceService for SidecarService {
    async fn classify(
        &self,
        req: Request<ClassifyRequest>,
    ) -> Result<Response<ClassifyResponse>, Status> {
        let req = req.into_inner();
        validate_model_id(&req.model).map_err(Status::invalid_argument)?;
        let (_id, classifier) = self
            .resolve(&req.model)
            .ok_or_else(|| Status::not_found("unknown classifier model"))?;
        let text = req.text;
        let started = std::time::Instant::now();
        // tract inference is synchronous and CPU-bound: run it on the blocking
        // pool so it never stalls a gRPC async worker.
        let output = tokio::task::spawn_blocking(move || classifier.classify(&text))
            .await
            .map_err(|e| Status::internal(format!("classify task panicked: {e}")))?
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
        validate_model_id(&req.model).map_err(Status::invalid_argument)?;
        let (_id, embedder) = self.resolve_embedder(&req.model).ok_or_else(|| {
            Status::failed_precondition(
                "no matching embedding model is loaded; start the sidecar with --embed-model",
            )
        })?;
        let texts = req.texts;
        let started = std::time::Instant::now();
        // tract inference is synchronous and CPU-bound: run it on the blocking
        // pool so it never stalls a gRPC async worker.
        let vectors = tokio::task::spawn_blocking(move || {
            texts
                .iter()
                .map(|t| embedder.embed(t))
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .await
        .map_err(|e| Status::internal(format!("embed task panicked: {e}")))?
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
        validate_model_id(&req.model).map_err(Status::invalid_argument)?;
        let encoded_len = req.encoded_len();
        if encoded_len > self.token_limits.max_request_bytes {
            return Err(Status::resource_exhausted(format!(
                "encoded compression request exceeds the configured byte limit: {encoded_len} > {}",
                self.token_limits.max_request_bytes
            )));
        }
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
        let permits = self.compression_admission.acquire().await?;
        let (source, output) = tokio::task::spawn_blocking(move || {
            let output = token_model.compress(&source, target, work_limits);
            drop(permits);
            (source, output)
        })
        .await
        .map_err(|error| Status::internal(format!("compress task panicked: {error}")))?;
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
}

impl Cli {
    fn validate_token_model_configuration(&self) -> Result<()> {
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
}

/// Parse one `id=<model>:<tokenizer>` spec and load the classifier.
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

/// Parse one `id=<model>:<tokenizer>` spec and load the embedder, learning
/// its output dimension via a one-time warmup embed so `ModelInfo` can
/// report it.
fn load_embed_spec(spec: &str) -> Result<(String, Arc<OnnxEmbedder>, u32)> {
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
    Ok((id.to_string(), Arc::new(embedder), dim))
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();
    cli.validate_token_model_configuration()?;
    let token_compression_limits = cli.token_compression_limits()?;
    // Tonic exposes one decoding cap for the entire service. Preserve its
    // historical 4 MiB behavior for Classify/Embed at the default Compress
    // budget; an explicit larger Compress budget raises (never lowers) that
    // shared transport ceiling. Compress independently enforces its exact
    // encoded-message budget in the handler.
    let max_decoding_message_size =
        grpc_decoding_message_limit(token_compression_limits.max_request_bytes);

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
        compression_admission: CompressionAdmission::new(
            token_compression_limits.max_concurrent,
            token_compression_limits.max_queued,
        ),
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
            "classifier sidecar listening on Unix domain socket",
        );
        let stream = tokio_stream::wrappers::UnixListenerStream::new(listener);
        Server::builder()
            .add_service(
                InferenceServiceServer::new(service)
                    .max_decoding_message_size(max_decoding_message_size),
            )
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
        "classifier sidecar listening on TCP",
    );

    Server::builder()
        .add_service(
            InferenceServiceServer::new(service)
                .max_decoding_message_size(max_decoding_message_size),
        )
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
        SidecarService {
            models: HashMap::new(),
            embedders: HashMap::new(),
            token_models: HashMap::new(),
            default_model: None,
            default_embed_model: None,
            default_token_model: None,
            token_limits: TokenCompressionRuntimeLimits::default(),
            compression_admission: CompressionAdmission::new(
                DEFAULT_TOKEN_MAX_CONCURRENT,
                DEFAULT_TOKEN_MAX_QUEUED,
            ),
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

    struct BlockingCompressionState {
        entered: AtomicUsize,
        released: Mutex<bool>,
        released_changed: Condvar,
    }

    impl BlockingCompressionState {
        fn new() -> Self {
            Self {
                entered: AtomicUsize::new(0),
                released: Mutex::new(false),
                released_changed: Condvar::new(),
            }
        }

        fn release(&self) {
            *self.released.lock().expect("release lock poisoned") = true;
            self.released_changed.notify_all();
        }
    }

    struct BlockingTokenCompressor {
        state: Arc<BlockingCompressionState>,
    }

    impl TokenCompressor for BlockingTokenCompressor {
        fn compress(
            &self,
            text: &str,
            _target: TokenCompressionTarget,
            _limits: TokenCompressionLimits,
        ) -> anyhow::Result<TokenCompressionOutput> {
            self.state.entered.fetch_add(1, Ordering::SeqCst);
            let mut released = self.state.released.lock().expect("release lock poisoned");
            while !*released {
                released = self
                    .state
                    .released_changed
                    .wait(released)
                    .expect("release lock poisoned");
            }
            Ok(TokenCompressionOutput {
                text: text.to_string(),
                original_tokens: 1,
                compressed_tokens: 1,
            })
        }
    }

    struct ReleaseOnDrop(Arc<BlockingCompressionState>);

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
        let state = Arc::new(BlockingCompressionState::new());
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&state));
        let mut service = empty_service();
        service.token_limits.max_concurrent = 1;
        service.token_limits.max_queued = 1;
        service.compression_admission = CompressionAdmission::new(1, 1);
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
        let state = Arc::new(BlockingCompressionState::new());
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&state));
        let mut service = empty_service();
        service.token_limits.max_concurrent = 1;
        service.token_limits.max_queued = 0;
        service.compression_admission = CompressionAdmission::new(1, 0);
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

    async fn spawn_wire_service() -> Option<InferenceServiceClient<tonic::transport::Channel>> {
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
                .add_service(
                    InferenceServiceServer::new(empty_service()).max_decoding_message_size(
                        grpc_decoding_message_limit(DEFAULT_TOKEN_MAX_REQUEST_BYTES),
                    ),
                )
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
    async fn wire_decoder_keeps_existing_rpcs_at_the_four_mib_limit() {
        let Some(mut client) = spawn_wire_service().await else {
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

        assert_eq!(error.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn wire_compress_enforces_the_exact_encoded_request_limit() {
        let Some(mut client) = spawn_wire_service().await else {
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
        cli.validate_token_model_configuration()
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
            .validate_token_model_configuration()
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
