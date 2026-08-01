//! Resilient gRPC client for the classifier sidecar `InferenceService`.
//!
//! The proxy uses this one client to reach whichever sidecar is deployed:
//! the minimal OSS sidecar or the enterprise rich sidecar. Both implement
//! the shared proto. This crate owns the connection, a per-call timeout,
//! typed errors, and (WOR-705) two transports:
//!
//! * **TCP**: `http://host:port`. The default for a separately-deployed
//!   sidecar.
//! * **Unix domain socket**: a path on the local filesystem. The natural
//!   default for a supervised co-located child; saves the loopback TCP
//!   round trip and stays bounded to the proxy's own filesystem
//!   namespace.
//!
//! The transport is the only thing that differs between the two
//! constructors: once a channel is built the gRPC RPC surface and the
//! per-call timeout behaviour are identical, and the rest of the proxy
//! (the `SidecarDetector` request-path bridge) treats both alike.

use std::path::{Path, PathBuf};
use std::time::Duration;

use sbproxy_classifier_proto::{
    compress_request, ClassifyRequest, CompressRequest, CompressResponse, EmbedRequest,
    InferenceServiceClient, VersionRequest, VersionResponse,
};

/// Classification response types, re-exported so callers of
/// [`ClassifierClient::classify`] can name them without depending on the
/// proto crate directly.
pub use sbproxy_classifier_proto::{ClassifyResponse, Label};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

/// WOR-705 part 2: child supervisor that owns the lifecycle of a
/// co-located sidecar binary. Pairs with `connect_uds_lazy`: the
/// supervisor spawns the sidecar with `--listen-uds <path>` and
/// the lazy client over the same path races the bind exactly
/// once. The supervisor restarts the child on unexpected exit
/// and supports a SIGTERM-then-SIGKILL graceful shutdown.
pub mod supervisor;
pub use supervisor::{Supervisor, SupervisorConfig, SupervisorError, SupervisorState};

/// Error talking to the classifier sidecar.
///
/// The caller maps these to its fail policy: fail-open classifiers treat any
/// variant as "skip classification, allow"; fail-closed classifiers treat them
/// as a deny.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClassifierClientError {
    /// The endpoint string was not a valid URI, or the connection failed.
    #[error("connect to classifier sidecar failed: {0}")]
    Connect(String),
    /// The call exceeded the configured per-call timeout.
    #[error("classifier call timed out after {0:?}")]
    Timeout(Duration),
    /// The sidecar returned a gRPC error status.
    #[error("classifier rpc failed ({code:?}): {message}")]
    Rpc {
        /// Structured gRPC status code returned by the sidecar.
        code: tonic::Code,
        /// Status message returned by the sidecar.
        message: String,
    },
    /// The sidecar returned a structurally invalid response (see
    /// `validate_classify_response` / `validate_compress_response`).
    #[error("classifier protocol error: {0}")]
    Protocol(String),
    /// The caller supplied an invalid compression request.
    #[error("invalid classifier request: {0}")]
    InvalidRequest(String),
}

fn rpc_error(status: tonic::Status) -> ClassifierClientError {
    ClassifierClientError::Rpc {
        code: status.code(),
        message: status.message().to_string(),
    }
}

/// Target mode for extractive token compression.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionTarget {
    /// Retain this fraction of source tokens.
    RetainRatio(f64),
    /// Retain at most this many source tokens.
    TargetTokens(u32),
}

/// A connected, cheaply-cloneable client to a classifier sidecar.
///
/// `InferenceServiceClient<Channel>` clones share the underlying connection
/// pool, so cloning this is cheap and the clones can be used concurrently.
#[derive(Clone, Debug)]
pub struct ClassifierClient {
    inner: InferenceServiceClient<Channel>,
    timeout: Duration,
}

impl ClassifierClient {
    /// Connect to a sidecar at `endpoint` (e.g. `http://127.0.0.1:9440`),
    /// applying `connect_timeout` to the dial and `call_timeout` to each RPC.
    pub async fn connect(
        endpoint: &str,
        connect_timeout: Duration,
        call_timeout: Duration,
    ) -> Result<Self, ClassifierClientError> {
        let channel = Endpoint::from_shared(endpoint.to_string())
            .map_err(|e| ClassifierClientError::Connect(e.to_string()))?
            .connect_timeout(connect_timeout)
            .connect()
            .await
            .map_err(|e| ClassifierClientError::Connect(e.to_string()))?;
        Ok(Self {
            inner: InferenceServiceClient::new(channel),
            timeout: call_timeout,
        })
    }

    /// Validate an endpoint URI without building a channel.
    ///
    /// Channel construction, even the lazy kind, spawns onto the Tokio
    /// runtime and panics without one (WOR-1783). Config-load code calls
    /// this for eager URI validation and defers
    /// [`connect_lazy`](Self::connect_lazy) to the first call made on a
    /// runtime thread.
    pub fn validate_endpoint(endpoint: &str) -> Result<(), ClassifierClientError> {
        Endpoint::from_shared(endpoint.to_string())
            .map(|_| ())
            .map_err(|e| ClassifierClientError::Connect(e.to_string()))
    }

    /// Build a client that connects lazily on first use.
    ///
    /// Unlike [`connect`](Self::connect) this does not dial immediately: the
    /// connection (and any failure) surfaces on the first `classify`/`version`
    /// call, bounded by `call_timeout`. Only an invalid endpoint URI fails
    /// here. CALLER BEWARE: building the underlying channel still requires a
    /// live Tokio runtime; call this from runtime context (see
    /// [`validate_endpoint`](Self::validate_endpoint) for the config-load
    /// half).
    pub fn connect_lazy(
        endpoint: &str,
        call_timeout: Duration,
    ) -> Result<Self, ClassifierClientError> {
        let channel = Endpoint::from_shared(endpoint.to_string())
            .map_err(|e| ClassifierClientError::Connect(e.to_string()))?
            .connect_timeout(call_timeout)
            .connect_lazy();
        Ok(Self {
            inner: InferenceServiceClient::new(channel),
            timeout: call_timeout,
        })
    }

    /// Connect to a sidecar over a Unix domain socket.
    ///
    /// The natural transport for a co-located sidecar (the supervised
    /// child case): removes the loopback TCP round trip and stays
    /// bounded to the proxy's own filesystem namespace. The path MUST
    /// already exist; the connector dials it once with `connect_timeout`,
    /// then per-call dials reuse the same UNIX stream multiplexer.
    pub async fn connect_uds(
        socket_path: impl AsRef<Path>,
        connect_timeout: Duration,
        call_timeout: Duration,
    ) -> Result<Self, ClassifierClientError> {
        let path: PathBuf = socket_path.as_ref().to_path_buf();
        // The HTTP/2 authority on the placeholder URI is ignored by the
        // custom connector; `Endpoint::try_from` still validates URI
        // syntax, so passing `http://[::]:50051` keeps it happy.
        let endpoint = Endpoint::try_from("http://[::]:50051")
            .map_err(|e| ClassifierClientError::Connect(e.to_string()))?
            .connect_timeout(connect_timeout);
        let path_for_connector = path.clone();
        let channel = endpoint
            .connect_with_connector(service_fn(move |_| {
                let p = path_for_connector.clone();
                async move {
                    let stream = UnixStream::connect(&p).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await
            .map_err(|e| ClassifierClientError::Connect(format!("uds {path:?}: {e}")))?;
        Ok(Self {
            inner: InferenceServiceClient::new(channel),
            timeout: call_timeout,
        })
    }

    /// Build a UDS client that connects lazily on first use.
    ///
    /// Same shape as [`connect_lazy`](Self::connect_lazy) but over UDS.
    /// Use this from synchronous config-load code so a missing socket
    /// surfaces on the first call rather than at proxy boot. The
    /// supervised-child case typically pairs this with the supervisor
    /// (a separate follow-up): the supervisor spawns the sidecar with
    /// `--listen-uds <path>`, and the proxy holds a lazy client at the
    /// same path so the dial races the child's bind exactly once.
    pub fn connect_uds_lazy(
        socket_path: impl AsRef<Path>,
        call_timeout: Duration,
    ) -> Result<Self, ClassifierClientError> {
        let path: PathBuf = socket_path.as_ref().to_path_buf();
        let endpoint = Endpoint::try_from("http://[::]:50051")
            .map_err(|e| ClassifierClientError::Connect(e.to_string()))?
            .connect_timeout(call_timeout);
        let path_for_connector = path.clone();
        let channel = endpoint.connect_with_connector_lazy(service_fn(move |_| {
            let p = path_for_connector.clone();
            async move {
                let stream = UnixStream::connect(&p).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }));
        Ok(Self {
            inner: InferenceServiceClient::new(channel),
            timeout: call_timeout,
        })
    }

    /// Classify `text` with the named model (empty = the sidecar's default).
    ///
    /// The response is validated before it is returned: it carries at least
    /// one label, every label has a non-empty name unique within the
    /// response, and every score is finite and within `0.0..=1.0`. A
    /// response that fails any of these checks surfaces as
    /// [`ClassifierClientError::Protocol`], so a malformed sidecar verdict
    /// flows through the caller's fail policy instead of masquerading as a
    /// clean result. The returned labels are ordered highest score first
    /// regardless of the order the sidecar sent them in.
    pub async fn classify(
        &self,
        model: &str,
        text: &str,
    ) -> Result<ClassifyResponse, ClassifierClientError> {
        let request = ClassifyRequest {
            model: model.to_string(),
            text: text.to_string(),
            top_k: 0,
        };
        // Clone the inner client so this method takes `&self`: tonic clients
        // require `&mut self`, and the channel clone shares the connection.
        let mut client = self.inner.clone();
        let mut response = match tokio::time::timeout(self.timeout, client.classify(request)).await
        {
            Ok(Ok(resp)) => resp.into_inner(),
            Ok(Err(status)) => return Err(rpc_error(status)),
            Err(_) => return Err(ClassifierClientError::Timeout(self.timeout)),
        };
        validate_classify_response(&mut response)?;
        Ok(response)
    }

    /// Embed `inputs` with the named model (empty = the sidecar's default).
    ///
    /// Returns one L2-normalized vector per input, in request order. Used by
    /// the AI gateway semantic cache to vectorize prompts locally instead of
    /// via a paid embedding-provider API.
    pub async fn embed(
        &self,
        model: &str,
        inputs: &[String],
    ) -> Result<Vec<Vec<f32>>, ClassifierClientError> {
        let request = EmbedRequest {
            model: model.to_string(),
            texts: inputs.to_vec(),
        };
        let mut client = self.inner.clone();
        match tokio::time::timeout(self.timeout, client.embed(request)).await {
            Ok(Ok(resp)) => Ok(resp
                .into_inner()
                .embeddings
                .into_iter()
                .map(|e| e.values)
                .collect()),
            Ok(Err(status)) => Err(rpc_error(status)),
            Err(_) => Err(ClassifierClientError::Timeout(self.timeout)),
        }
    }

    /// Compress `text` extractively with the named token-classification model.
    pub async fn compress(
        &self,
        model: &str,
        text: &str,
        target: CompressionTarget,
    ) -> Result<CompressResponse, ClassifierClientError> {
        if text.is_empty() {
            return Err(ClassifierClientError::InvalidRequest(
                "compression text is empty".to_string(),
            ));
        }
        let target = match target {
            CompressionTarget::RetainRatio(ratio)
                if ratio.is_finite() && ratio > 0.0 && ratio <= 1.0 =>
            {
                compress_request::Target::RetainRatio(ratio)
            }
            CompressionTarget::RetainRatio(_) => {
                return Err(ClassifierClientError::InvalidRequest(
                    "retain ratio must be finite and in (0, 1]".to_string(),
                ))
            }
            CompressionTarget::TargetTokens(tokens) if tokens > 0 => {
                compress_request::Target::TargetTokens(tokens)
            }
            CompressionTarget::TargetTokens(_) => {
                return Err(ClassifierClientError::InvalidRequest(
                    "target token count must be greater than zero".to_string(),
                ))
            }
        };
        let request = CompressRequest {
            model: model.to_string(),
            text: text.to_string(),
            target: Some(target),
        };
        let mut client = self.inner.clone();
        let response = match tokio::time::timeout(self.timeout, client.compress(request)).await {
            Ok(Ok(response)) => response.into_inner(),
            Ok(Err(status)) => return Err(rpc_error(status)),
            Err(_) => return Err(ClassifierClientError::Timeout(self.timeout)),
        };
        validate_compress_response(text, &response)?;
        Ok(response)
    }

    /// Probe the sidecar's version + served model ids (startup capability check).
    pub async fn version(&self) -> Result<VersionResponse, ClassifierClientError> {
        let mut client = self.inner.clone();
        match tokio::time::timeout(self.timeout, client.version(VersionRequest {})).await {
            Ok(Ok(resp)) => Ok(resp.into_inner()),
            Ok(Err(status)) => Err(rpc_error(status)),
            Err(_) => Err(ClassifierClientError::Timeout(self.timeout)),
        }
    }
}

/// Validate (and normalize) a classification response before it reaches an
/// adapter (WOR-2161).
///
/// The proto cannot express these invariants, so the client enforces them
/// centrally, mirroring [`validate_compress_response`]:
///
/// * at least one label is present;
/// * every label name is non-empty;
/// * every score is finite and within `0.0..=1.0`.
///
/// Duplicates: two labels whose names collide ASCII-case-insensitively are
/// rejected. Adapters match label names case-insensitively (the sidecar
/// detector's `injection_label`), so a duplicate pair such as `Injection`
/// 0.9 / `INJECTION` 0.1 makes the verdict ambiguous; guessing which score
/// the sidecar meant is how a bypass hides, so the response fails loud
/// instead.
///
/// Ordering: the proto documents labels as "highest score first" but this
/// client does not trust the sidecar to honor that. After validation the
/// labels are re-sorted descending by score (stable, so equal scores keep
/// the sidecar's relative order), turning the documented ordering into an
/// enforced invariant callers may rely on.
fn validate_classify_response(
    response: &mut ClassifyResponse,
) -> Result<(), ClassifierClientError> {
    if response.labels.is_empty() {
        return Err(ClassifierClientError::Protocol(
            "classification response contains no labels".to_string(),
        ));
    }
    let mut seen = std::collections::HashSet::with_capacity(response.labels.len());
    for label in &response.labels {
        if label.name.is_empty() {
            return Err(ClassifierClientError::Protocol(
                "classification response contains a label with an empty name".to_string(),
            ));
        }
        if !label.score.is_finite() || !(0.0..=1.0).contains(&label.score) {
            return Err(ClassifierClientError::Protocol(format!(
                "classification response label {:?} has invalid score {}: \
                 must be finite and in [0.0, 1.0]",
                label.name, label.score
            )));
        }
        if !seen.insert(label.name.to_ascii_lowercase()) {
            return Err(ClassifierClientError::Protocol(format!(
                "classification response contains duplicate label {:?} \
                 (names are compared case-insensitively)",
                label.name
            )));
        }
    }
    // total_cmp is safe here: every score was just checked finite.
    response.labels.sort_by(|a, b| b.score.total_cmp(&a.score));
    Ok(())
}

fn validate_compress_response(
    source: &str,
    response: &CompressResponse,
) -> Result<(), ClassifierClientError> {
    if response.text.is_empty() {
        return Err(ClassifierClientError::Protocol(
            "compression response text is empty".to_string(),
        ));
    }
    if response.original_tokens == 0 {
        return Err(ClassifierClientError::Protocol(
            "compression response original_tokens is zero".to_string(),
        ));
    }
    if response.compressed_tokens == 0 || response.compressed_tokens > response.original_tokens {
        return Err(ClassifierClientError::Protocol(format!(
            "invalid compression token counts: original={}, compressed={}",
            response.original_tokens, response.compressed_tokens
        )));
    }
    if !is_char_subsequence(&response.text, source) {
        return Err(ClassifierClientError::Protocol(
            "compression response is not an extractive subsequence of the request".to_string(),
        ));
    }
    Ok(())
}

fn is_char_subsequence(candidate: &str, source: &str) -> bool {
    let mut source_chars = source.chars();
    candidate
        .chars()
        .all(|wanted| source_chars.by_ref().any(|found| found == wanted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_classifier_proto::{
        compress_request, ClassifyRequest, CompressRequest, CompressResponse, EmbedRequest,
        EmbedResponse, Embedding, InferenceService, InferenceServiceServer, Label,
        ModelInfoRequest, ModelInfoResponse,
    };
    use tonic::{Request, Response, Status};

    // Minimal stub sidecar: Classify echoes a fixed label, Version reports one
    // model. Lets us exercise the client end to end without a real ONNX model.
    struct StubService;

    #[tonic::async_trait]
    impl InferenceService for StubService {
        async fn classify(
            &self,
            req: Request<ClassifyRequest>,
        ) -> Result<Response<ClassifyResponse>, Status> {
            let model = req.into_inner().model;
            // Malformed-response fixtures keyed by model name, mirroring the
            // compress stubs below: each one is structurally valid protobuf
            // that the client must reject as a protocol error (WOR-2161).
            let labels = match model.as_str() {
                "empty-labels" => vec![],
                "empty-name" => vec![Label {
                    name: String::new(),
                    score: 0.5,
                }],
                "nan-score" => vec![Label {
                    name: "injection".to_string(),
                    score: f64::NAN,
                }],
                "inf-score" => vec![Label {
                    name: "injection".to_string(),
                    score: f64::INFINITY,
                }],
                "negative-score" => vec![Label {
                    name: "injection".to_string(),
                    score: -0.25,
                }],
                "overrange-score" => vec![Label {
                    name: "injection".to_string(),
                    score: 1.5,
                }],
                "duplicate-labels" => vec![
                    Label {
                        name: "Injection".to_string(),
                        score: 0.9,
                    },
                    Label {
                        name: "INJECTION".to_string(),
                        score: 0.1,
                    },
                ],
                "unsorted-labels" => vec![
                    Label {
                        name: "benign".to_string(),
                        score: 0.25,
                    },
                    Label {
                        name: "injection".to_string(),
                        score: 0.75,
                    },
                ],
                "boundary-scores" => vec![
                    Label {
                        name: "injection".to_string(),
                        score: 1.0,
                    },
                    Label {
                        name: "benign".to_string(),
                        score: 0.0,
                    },
                ],
                _ => vec![Label {
                    name: format!("stub:{model}"),
                    score: 0.99,
                }],
            };
            Ok(Response::new(ClassifyResponse {
                labels,
                latency_us: 1,
            }))
        }
        async fn embed(
            &self,
            req: Request<EmbedRequest>,
        ) -> Result<Response<EmbedResponse>, Status> {
            // Echo one fixed 2-dim vector per input so the client mapping is
            // exercised without a real ONNX model.
            let n = req.into_inner().texts.len();
            Ok(Response::new(EmbedResponse {
                embeddings: (0..n)
                    .map(|_| Embedding {
                        values: vec![1.0, 0.0],
                    })
                    .collect(),
                latency_us: 1,
            }))
        }
        async fn compress(
            &self,
            req: Request<CompressRequest>,
        ) -> Result<Response<CompressResponse>, Status> {
            let req = req.into_inner();
            if req.model == "resource-exhausted" {
                return Err(Status::resource_exhausted("compression queue is full"));
            }
            if req.model == "empty-result" {
                return Ok(Response::new(CompressResponse {
                    text: String::new(),
                    original_tokens: 3,
                    compressed_tokens: 0,
                    latency_us: 1,
                }));
            }
            if req.model == "invented-result" {
                return Ok(Response::new(CompressResponse {
                    text: "words not in source".to_string(),
                    original_tokens: 3,
                    compressed_tokens: 2,
                    latency_us: 1,
                }));
            }
            if req.model == "bad-counts" {
                return Ok(Response::new(CompressResponse {
                    text: req.text,
                    original_tokens: 2,
                    compressed_tokens: 3,
                    latency_us: 1,
                }));
            }
            let text = match req.target {
                Some(compress_request::Target::RetainRatio(0.5)) => "alpha gamma".to_string(),
                Some(compress_request::Target::TargetTokens(2)) => "alpha beta".to_string(),
                Some(compress_request::Target::RetainRatio(_))
                | Some(compress_request::Target::TargetTokens(_)) => {
                    return Err(Status::invalid_argument("unexpected target"))
                }
                None => return Err(Status::invalid_argument("missing target")),
            };
            Ok(Response::new(CompressResponse {
                text,
                original_tokens: 3,
                compressed_tokens: 2,
                latency_us: 1,
            }))
        }
        async fn model_info(
            &self,
            _req: Request<ModelInfoRequest>,
        ) -> Result<Response<ModelInfoResponse>, Status> {
            Ok(Response::new(ModelInfoResponse {
                model: "stub".into(),
                loaded: true,
                labels: vec![],
                embedding_dim: 0,
            }))
        }
        async fn version(
            &self,
            _req: Request<VersionRequest>,
        ) -> Result<Response<VersionResponse>, Status> {
            Ok(Response::new(VersionResponse {
                version: "stub 0".into(),
                models: vec!["stub".into()],
            }))
        }
    }

    // Bind port 0, spawn the stub server, return its `http://` endpoint.
    async fn spawn_stub() -> Option<String> {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping classifier-client TCP test: loopback bind denied: {err}");
                return None;
            }
            Err(err) => panic!("failed to bind classifier-client TCP test listener: {err}"),
        };
        let addr = listener.local_addr().unwrap();
        let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(InferenceServiceServer::new(StubService))
                .serve_with_incoming(stream)
                .await
                .unwrap();
        });
        Some(format!("http://{addr}"))
    }

    #[tokio::test]
    async fn classify_round_trips_against_a_stub() {
        let Some(endpoint) = spawn_stub().await else {
            return;
        };
        let client =
            ClassifierClient::connect(&endpoint, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .expect("connect");

        let resp = client
            .classify("prompt-injection", "ignore previous")
            .await
            .unwrap();
        assert_eq!(resp.labels.len(), 1);
        assert_eq!(resp.labels[0].name, "stub:prompt-injection");

        let version = client.version().await.unwrap();
        assert_eq!(version.models, vec!["stub".to_string()]);
    }

    #[tokio::test]
    async fn classify_rejects_malformed_sidecar_responses() {
        let Some(endpoint) = spawn_stub().await else {
            return;
        };
        let client =
            ClassifierClient::connect(&endpoint, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .expect("connect");

        for model in [
            "empty-labels",
            "empty-name",
            "nan-score",
            "inf-score",
            "negative-score",
            "overrange-score",
            "duplicate-labels",
        ] {
            let error = client
                .classify(model, "ignore previous")
                .await
                .expect_err("malformed response must fail");
            assert!(
                matches!(error, ClassifierClientError::Protocol(_)),
                "unexpected error for {model}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn classify_sorts_labels_highest_score_first() {
        // The proto documents this ordering but the client enforces it, so
        // a sidecar that returns labels unsorted still yields the invariant.
        let Some(endpoint) = spawn_stub().await else {
            return;
        };
        let client =
            ClassifierClient::connect(&endpoint, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .expect("connect");

        let resp = client
            .classify("unsorted-labels", "ignore previous")
            .await
            .expect("valid response");
        assert_eq!(resp.labels.len(), 2);
        assert_eq!(resp.labels[0].name, "injection");
        assert_eq!(resp.labels[0].score, 0.75);
        assert_eq!(resp.labels[1].name, "benign");
    }

    #[tokio::test]
    async fn classify_accepts_boundary_scores() {
        // 0.0 and 1.0 are valid scores; the range check is inclusive.
        let Some(endpoint) = spawn_stub().await else {
            return;
        };
        let client =
            ClassifierClient::connect(&endpoint, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .expect("connect");

        let resp = client
            .classify("boundary-scores", "ignore previous")
            .await
            .expect("boundary scores are valid");
        assert_eq!(resp.labels[0].score, 1.0);
        assert_eq!(resp.labels[1].score, 0.0);
    }

    #[tokio::test]
    async fn embed_round_trips_against_a_stub() {
        let Some(endpoint) = spawn_stub().await else {
            return;
        };
        let client =
            ClassifierClient::connect(&endpoint, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .expect("connect");
        let vecs = client
            .embed(
                "all-MiniLM-L6-v2",
                &["hello".to_string(), "world".to_string()],
            )
            .await
            .unwrap();
        assert_eq!(vecs.len(), 2);
        assert_eq!(vecs[0], vec![1.0, 0.0]);
    }

    #[tokio::test]
    async fn compress_ratio_round_trips_against_a_stub() {
        let Some(endpoint) = spawn_stub().await else {
            return;
        };
        let client =
            ClassifierClient::connect(&endpoint, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .expect("connect");

        let response = client
            .compress(
                "llmlingua-2",
                "alpha beta gamma",
                CompressionTarget::RetainRatio(0.5),
            )
            .await
            .expect("compress");

        assert_eq!(response.text, "alpha gamma");
        assert_eq!(response.original_tokens, 3);
        assert_eq!(response.compressed_tokens, 2);
    }

    #[tokio::test]
    async fn compress_target_tokens_round_trips_against_a_stub() {
        let Some(endpoint) = spawn_stub().await else {
            return;
        };
        let client =
            ClassifierClient::connect(&endpoint, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .expect("connect");

        let response = client
            .compress(
                "llmlingua-2",
                "alpha beta gamma",
                CompressionTarget::TargetTokens(2),
            )
            .await
            .expect("compress");

        assert_eq!(response.text, "alpha beta");
        assert_eq!(response.original_tokens, 3);
        assert_eq!(response.compressed_tokens, 2);
    }

    #[tokio::test]
    async fn compress_rejects_malformed_sidecar_responses() {
        let Some(endpoint) = spawn_stub().await else {
            return;
        };
        let client =
            ClassifierClient::connect(&endpoint, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .expect("connect");

        for model in ["empty-result", "invented-result", "bad-counts"] {
            let error = client
                .compress(
                    model,
                    "alpha beta gamma",
                    CompressionTarget::TargetTokens(2),
                )
                .await
                .expect_err("malformed response must fail");
            assert!(
                matches!(error, ClassifierClientError::Protocol(_)),
                "unexpected error for {model}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn compress_preserves_resource_exhausted_status_code() {
        let Some(endpoint) = spawn_stub().await else {
            return;
        };
        let client =
            ClassifierClient::connect(&endpoint, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .expect("connect");

        let error = client
            .compress(
                "resource-exhausted",
                "alpha beta gamma",
                CompressionTarget::TargetTokens(2),
            )
            .await
            .expect_err("stub exhaustion must reach the caller");

        let ClassifierClientError::Rpc { code, message } = error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(code, tonic::Code::ResourceExhausted);
        assert_eq!(message, "compression queue is full");
    }

    #[tokio::test]
    async fn compress_rejects_invalid_requests_before_the_rpc() {
        let Some(endpoint) = spawn_stub().await else {
            return;
        };
        let client =
            ClassifierClient::connect(&endpoint, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .expect("connect");

        for target in [
            CompressionTarget::RetainRatio(0.0),
            CompressionTarget::RetainRatio(f64::NAN),
            CompressionTarget::RetainRatio(1.1),
            CompressionTarget::TargetTokens(0),
        ] {
            let error = client
                .compress("llmlingua-2", "alpha beta", target)
                .await
                .expect_err("invalid request must fail");
            assert!(
                matches!(error, ClassifierClientError::InvalidRequest(_)),
                "unexpected error for {target:?}: {error:?}"
            );
        }

        let error = client
            .compress("llmlingua-2", "", CompressionTarget::TargetTokens(1))
            .await
            .expect_err("empty text must fail");
        assert!(matches!(error, ClassifierClientError::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn connect_to_dead_endpoint_errors() {
        // Port 1 refuses immediately; connect must surface a Connect error
        // rather than hang (bounded by connect_timeout).
        let err = ClassifierClient::connect(
            "http://127.0.0.1:1",
            Duration::from_millis(500),
            Duration::from_millis(500),
        )
        .await
        .expect_err("connect to a dead endpoint must fail");
        assert!(matches!(err, ClassifierClientError::Connect(_)));
    }

    // --- WOR-705 UDS transport ---

    /// Bind the stub server on a Unix domain socket in `dir` and return
    /// the socket path. Co-located with the TCP `spawn_stub` helper so
    /// both transports share the StubService implementation verbatim.
    async fn spawn_stub_uds(dir: &std::path::Path) -> Option<std::path::PathBuf> {
        let sock = dir.join("classifier.sock");
        let listener = match tokio::net::UnixListener::bind(&sock) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping classifier-client UDS test: socket bind denied: {err}");
                return None;
            }
            Err(err) => panic!("failed to bind classifier-client UDS test listener: {err}"),
        };
        let stream = tokio_stream::wrappers::UnixListenerStream::new(listener);
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(InferenceServiceServer::new(StubService))
                .serve_with_incoming(stream)
                .await
                .unwrap();
        });
        Some(sock)
    }

    #[tokio::test]
    async fn classify_round_trips_over_uds() {
        let dir = tempfile::tempdir().unwrap();
        let Some(sock) = spawn_stub_uds(dir.path()).await else {
            return;
        };
        let client =
            ClassifierClient::connect_uds(&sock, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .expect("connect_uds");

        let resp = client
            .classify("prompt-injection", "ignore previous")
            .await
            .unwrap();
        assert_eq!(resp.labels.len(), 1);
        assert_eq!(resp.labels[0].name, "stub:prompt-injection");

        let version = client.version().await.unwrap();
        assert_eq!(version.models, vec!["stub".to_string()]);
    }

    #[tokio::test]
    async fn connect_uds_to_missing_socket_errors() {
        // The path does not exist; connect_uds must surface a Connect
        // error rather than hang. The connect_timeout bounds the dial.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let err = ClassifierClient::connect_uds(
            &missing,
            Duration::from_millis(500),
            Duration::from_millis(500),
        )
        .await
        .expect_err("connect to a missing UDS path must fail");
        assert!(matches!(err, ClassifierClientError::Connect(_)));
    }

    #[tokio::test]
    async fn connect_uds_lazy_defers_dial_to_first_call() {
        // The path does not exist yet, but connect_uds_lazy must
        // succeed because it does not dial. The failure surfaces on the
        // first call, bounded by call_timeout.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-yet.sock");
        let client = ClassifierClient::connect_uds_lazy(&missing, Duration::from_millis(500))
            .expect("lazy build with non-existent socket must succeed");
        let err = client
            .version()
            .await
            .expect_err("version() must fail when the socket never appeared");
        // Either Timeout or Rpc(...) is acceptable; the lazy connector
        // surfaces tonic's underlying error wrapped as an Rpc status,
        // and the per-call timeout wraps that. We only need to confirm
        // the call did not succeed.
        assert!(
            matches!(
                err,
                ClassifierClientError::Timeout(_) | ClassifierClientError::Rpc { .. }
            ),
            "expected Timeout or Rpc, got {err:?}"
        );
    }
}
