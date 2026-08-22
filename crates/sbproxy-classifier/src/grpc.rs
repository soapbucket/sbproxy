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
//! minimal sidecar already carries a hardened, per-RPC admission-controlled
//! implementation of this exact contract (request-byte budgets, running/
//! queued semaphores, a bounded deadline covering both). Reimplementing that
//! bound-for-bound here would not add capability, only a second copy to keep
//! in sync, so an operator whose traffic needs that hardening runs the
//! minimal sidecar for ONNX classify/embed and this binary alongside it for
//! the genuinely new surface (`Classify` here still enforces a flat
//! `MAX_TEXT_BYTES` request-size guard; it just does not admission-control
//! concurrency the way the minimal sidecar does). `Compress` is not ported
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

use crate::heuristic;
use crate::quality;
use sbproxy_classifier_proto::{
    ClassifierService, ClassifyRequest, ClassifyResponse, CompressRequest, CompressResponse,
    EmbedRequest, EmbedResponse, Embedding, InferenceService, Label, ModelInfoRequest,
    ModelInfoResponse, QualityRequest, QualityResponse, SafetyToken, SafetyVerdict, VersionRequest,
    VersionResponse,
};
use sbproxy_classifiers::{OnnxClassifier, OnnxEmbedder};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

/// Flat per-request byte budget for `Classify` / `Embed` / `Quality` text.
/// Matches the minimal sidecar's own default (`DEFAULT_INFERENCE_MAX_REQUEST_BYTES`
/// in `sbproxy-classifier-sidecar`), so the two report the same ceiling to an
/// operator sizing traffic against either one.
const MAX_TEXT_BYTES: usize = 1024 * 1024;

/// Shared state for both gRPC services. Constructed once in `main.rs` and
/// wrapped in the tonic server handles for each service.
pub struct GrpcState {
    pub models: HashMap<String, Arc<OnnxClassifier>>,
    pub embedders: HashMap<String, Arc<OnnxEmbedder>>,
    pub default_model: Option<String>,
    pub default_embed_model: Option<String>,
    pub version: String,
}

impl GrpcState {
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
pub struct InferenceHandler(pub Arc<GrpcState>);

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
        crate::metrics::record_request("grpc", "classify");
        let classifier = self
            .resolve_classifier(&req.model)
            .ok_or_else(|| Status::not_found("unknown or unconfigured classifier model"))?;
        let text = req.text;
        let started = std::time::Instant::now();
        let output = tokio::task::spawn_blocking(move || classifier.classify(&text))
            .await
            .map_err(|e| Status::internal(format!("classify task panicked: {e}")))?
            .map_err(|e| {
                crate::metrics::record_error("grpc", "classify", "inference_failed");
                Status::internal(format!("classify failed: {e}"))
            })?;
        Ok(Response::new(ClassifyResponse {
            labels: vec![Label {
                name: output.label,
                score: output.score as f64,
            }],
            latency_us: started.elapsed().as_micros() as u64,
        }))
    }

    async fn embed(
        &self,
        request: Request<EmbedRequest>,
    ) -> Result<Response<EmbedResponse>, Status> {
        let req = request.into_inner();
        crate::metrics::record_request("grpc", "embed");
        let embedder = self.resolve_embedder(&req.model).ok_or_else(|| {
            Status::failed_precondition(
                "no matching embedding model is loaded; start with --embed-model",
            )
        })?;
        for text in &req.texts {
            check_text_bytes(text)?;
        }
        let texts = req.texts;
        let started = std::time::Instant::now();
        let vectors = tokio::task::spawn_blocking(move || {
            texts
                .iter()
                .map(|t| embedder.embed(t))
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .await
        .map_err(|e| Status::internal(format!("embed task panicked: {e}")))?
        .map_err(|e| {
            crate::metrics::record_error("grpc", "embed", "inference_failed");
            Status::internal(format!("embed failed: {e}"))
        })?;
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
        let resp = if let Some(_classifier) = self.resolve_classifier(&req.model) {
            ModelInfoResponse {
                model: if req.model.is_empty() {
                    self.default_model.clone().unwrap_or_default()
                } else {
                    req.model
                },
                loaded: true,
                labels: Vec::new(),
                embedding_dim: 0,
            }
        } else if let Some(embedder) = self.resolve_embedder(&req.model) {
            let dim = embedder
                .embed("dimension probe")
                .map(|o| o.values.len() as u32)
                .unwrap_or(0);
            ModelInfoResponse {
                model: if req.model.is_empty() {
                    self.default_embed_model.clone().unwrap_or_default()
                } else {
                    req.model
                },
                loaded: true,
                labels: Vec::new(),
                embedding_dim: dim,
            }
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
        let mut models: Vec<String> = self.models.keys().cloned().collect();
        models.sort();
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
pub struct ClassifierHandler(pub Arc<GrpcState>);

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
        crate::metrics::record_request("grpc", "quality");
        let result = quality::quality_score(&req.text);
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
    /// set once, then streams tokens. Once a rule matches, every subsequent
    /// verdict on the stream reports `blocked` again with the same reason
    /// and `safe: false`, rather than silently going back to evaluating
    /// only the latest token: the caller is expected to have stopped
    /// forwarding output at the first block, so this is a safety net for a
    /// caller that keeps streaming anyway, not new information.
    async fn stream_safety(
        &self,
        request: Request<Streaming<SafetyToken>>,
    ) -> Result<Response<Self::StreamSafetyStream>, Status> {
        crate::metrics::record_request("grpc", "stream_safety");
        let inbound = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(run_stream_safety(inbound, tx));
        let stream: SafetyStream = Box::pin(ReceiverStream::new(rx));
        Ok(Response::new(stream))
    }
}

/// The `StreamSafety` loop, generic over its input stream so a test can
/// drive it with a plain [`ReceiverStream`] instead of a real
/// [`tonic::Streaming`] (which has no public test constructor).
///
/// `rules` is read from the first message on the stream and reused for
/// every message after it, per the proto doc: a caller sends its rule set
/// once, then streams tokens. Once a rule matches, every subsequent verdict
/// reports `blocked` again with the same reason and `safe: false`, rather
/// than silently going back to evaluating only the latest token: the caller
/// is expected to have stopped forwarding output at the first block, so
/// this is a safety net for a caller that keeps streaming anyway, not new
/// information.
async fn run_stream_safety<S>(
    mut inbound: S,
    tx: tokio::sync::mpsc::Sender<Result<SafetyVerdict, Status>>,
) where
    S: Stream<Item = Result<SafetyToken, Status>> + Unpin,
{
    let mut rules: Vec<String> = Vec::new();
    let mut accumulated = String::new();
    let mut already_blocked: Option<String> = None;
    let mut first = true;

    while let Some(next) = inbound.next().await {
        let token = match next {
            Ok(t) => t,
            Err(status) => {
                let _ = tx.send(Err(status)).await;
                return;
            }
        };
        if first {
            rules = token.rules;
            first = false;
        }
        accumulated.push_str(&token.token);

        let verdict = if let Some(reason) = &already_blocked {
            SafetyVerdict {
                safe: false,
                blocked: false,
                reason: reason.clone(),
            }
        } else {
            let (safe, blocked, reason) = heuristic::check_streaming_safety(&accumulated, &rules);
            crate::metrics::record_safety_verdict(if safe { "safe" } else { "blocked" });
            if blocked {
                already_blocked = Some(reason.clone());
            }
            SafetyVerdict {
                safe,
                blocked,
                reason,
            }
        };

        if tx.send(Ok(verdict)).await.is_err() {
            // Caller dropped the response stream; stop reading input.
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_state() -> Arc<GrpcState> {
        Arc::new(GrpcState {
            models: HashMap::new(),
            embedders: HashMap::new(),
            default_model: None,
            default_embed_model: None,
            version: "sbproxy-classifier test".to_string(),
        })
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
    async fn stream_safety_blocks_once_a_rule_matches_and_stays_blocked() {
        // Drives `run_stream_safety` directly with a plain `ReceiverStream`
        // rather than a real `tonic::Streaming`, which has no public test
        // constructor. This still exercises the exact loop the trait method
        // spawns; only the transport plumbing around it is skipped.
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

        run_stream_safety(inbound, out_tx).await;
        let mut outbound = ReceiverStream::new(out_rx);

        let first = outbound.next().await.unwrap().unwrap();
        assert!(first.safe && !first.blocked);

        let second = outbound.next().await.unwrap().unwrap();
        assert!(!second.safe && second.blocked);
        assert!(second.reason.contains("forbidden"));

        // Stays blocked on the message after the match, even though this
        // chunk alone contains none of the rule text.
        let third = outbound.next().await.unwrap().unwrap();
        assert!(!third.safe);
        assert_eq!(third.reason, second.reason);
    }
}
