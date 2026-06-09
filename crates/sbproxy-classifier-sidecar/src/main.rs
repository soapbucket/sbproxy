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
//! `Classify` is implemented for real; `Embed` is unimplemented (the
//! OSS classifiers are label classifiers, not embedders). The
//! proxy-side child supervisor lands in a follow-up; the sidecar's
//! UDS option is the half of that story that ships here.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use sbproxy_classifier_proto::{
    ClassifyRequest, ClassifyResponse, EmbedRequest, EmbedResponse, Embedding, InferenceService,
    InferenceServiceServer, Label, ModelInfoRequest, ModelInfoResponse, VersionRequest,
    VersionResponse,
};
use sbproxy_classifiers::{OnnxClassifier, OnnxEmbedder};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

/// The `InferenceService` implementation, backed by a registry of loaded
/// tract ONNX classifiers keyed by logical model id.
struct SidecarService {
    models: HashMap<String, Arc<OnnxClassifier>>,
    /// Embedding models keyed by logical id, paired with the embedding
    /// dimension learned at load time (for `ModelInfo`).
    embedders: HashMap<String, (Arc<OnnxEmbedder>, u32)>,
    /// Classifier used when a `Classify` request leaves `model` empty.
    default_model: Option<String>,
    /// Embedder used when an `Embed` request leaves `model` empty.
    default_embed_model: Option<String>,
    /// Reported by the `Version` RPC.
    version: String,
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
}

#[tonic::async_trait]
impl InferenceService for SidecarService {
    async fn classify(
        &self,
        req: Request<ClassifyRequest>,
    ) -> Result<Response<ClassifyResponse>, Status> {
        let req = req.into_inner();
        let (_id, classifier) = self
            .resolve(&req.model)
            .ok_or_else(|| Status::not_found(format!("unknown model {:?}", req.model)))?;
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
        let (_id, embedder) = self.resolve_embedder(&req.model).ok_or_else(|| {
            Status::failed_precondition(format!(
                "no embedding model loaded for {:?}; start the sidecar with --embed-model",
                req.model
            ))
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

    async fn model_info(
        &self,
        req: Request<ModelInfoRequest>,
    ) -> Result<Response<ModelInfoResponse>, Status> {
        let req = req.into_inner();
        // Classifiers first, then embedders (which report their dimension).
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
                None => ModelInfoResponse {
                    model: req.model,
                    loaded: false,
                    labels: Vec::new(),
                    embedding_dim: 0,
                },
            }
        };
        Ok(Response::new(resp))
    }

    async fn version(
        &self,
        _req: Request<VersionRequest>,
    ) -> Result<Response<VersionResponse>, Status> {
        let mut models: Vec<String> = self.models.keys().cloned().collect();
        models.sort();
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

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

    let service = SidecarService {
        version: format!("sbproxy-classifier-sidecar {}", env!("CARGO_PKG_VERSION")),
        default_model,
        default_embed_model,
        models,
        embedders,
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
            "classifier sidecar listening on Unix domain socket",
        );
        let stream = tokio_stream::wrappers::UnixListenerStream::new(listener);
        Server::builder()
            .add_service(InferenceServiceServer::new(service))
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
        "classifier sidecar listening on TCP",
    );

    Server::builder()
        .add_service(InferenceServiceServer::new(service))
        .serve(addr)
        .await
        .context("classifier sidecar server failed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_service() -> SidecarService {
        SidecarService {
            models: HashMap::new(),
            embedders: HashMap::new(),
            default_model: None,
            default_embed_model: None,
            version: "sbproxy-classifier-sidecar test".to_string(),
        }
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

    #[test]
    fn load_embed_spec_rejects_malformed() {
        assert!(load_embed_spec("no-equals").is_err());
        assert!(load_embed_spec("id=only-one-path").is_err());
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
