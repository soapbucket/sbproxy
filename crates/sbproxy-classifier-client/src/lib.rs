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
    ClassifyRequest, ClassifyResponse, InferenceServiceClient, VersionRequest, VersionResponse,
};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

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
    #[error("classifier rpc failed: {0}")]
    Rpc(String),
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

    /// Build a client that connects lazily on first use.
    ///
    /// Unlike [`connect`](Self::connect) this does not dial immediately, so it
    /// is safe to call from synchronous config-load code: the connection (and
    /// any failure) surfaces on the first `classify`/`version` call, bounded by
    /// `call_timeout`. Only an invalid endpoint URI fails here.
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
        match tokio::time::timeout(self.timeout, client.classify(request)).await {
            Ok(Ok(resp)) => Ok(resp.into_inner()),
            Ok(Err(status)) => Err(ClassifierClientError::Rpc(status.to_string())),
            Err(_) => Err(ClassifierClientError::Timeout(self.timeout)),
        }
    }

    /// Probe the sidecar's version + served model ids (startup capability check).
    pub async fn version(&self) -> Result<VersionResponse, ClassifierClientError> {
        let mut client = self.inner.clone();
        match tokio::time::timeout(self.timeout, client.version(VersionRequest {})).await {
            Ok(Ok(resp)) => Ok(resp.into_inner()),
            Ok(Err(status)) => Err(ClassifierClientError::Rpc(status.to_string())),
            Err(_) => Err(ClassifierClientError::Timeout(self.timeout)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_classifier_proto::{
        EmbedRequest, EmbedResponse, InferenceService, InferenceServiceServer, Label,
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
            Ok(Response::new(ClassifyResponse {
                labels: vec![Label {
                    name: format!("stub:{model}"),
                    score: 0.99,
                }],
                latency_us: 1,
            }))
        }
        async fn embed(
            &self,
            _req: Request<EmbedRequest>,
        ) -> Result<Response<EmbedResponse>, Status> {
            Err(Status::unimplemented("stub"))
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
    async fn spawn_stub() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(InferenceServiceServer::new(StubService))
                .serve_with_incoming(stream)
                .await
                .unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn classify_round_trips_against_a_stub() {
        let endpoint = spawn_stub().await;
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
    async fn spawn_stub_uds(dir: &std::path::Path) -> std::path::PathBuf {
        let sock = dir.join("classifier.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let stream = tokio_stream::wrappers::UnixListenerStream::new(listener);
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(InferenceServiceServer::new(StubService))
                .serve_with_incoming(stream)
                .await
                .unwrap();
        });
        sock
    }

    #[tokio::test]
    async fn classify_round_trips_over_uds() {
        let dir = tempfile::tempdir().unwrap();
        let sock = spawn_stub_uds(dir.path()).await;
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
                ClassifierClientError::Timeout(_) | ClassifierClientError::Rpc(_)
            ),
            "expected Timeout or Rpc, got {err:?}"
        );
    }
}
