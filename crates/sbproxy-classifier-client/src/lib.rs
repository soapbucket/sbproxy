//! Resilient gRPC client for the classifier sidecar `InferenceService`.
//!
//! The proxy uses this one client to reach whichever sidecar is deployed -- the
//! minimal OSS sidecar or the enterprise rich sidecar -- since both implement
//! the shared proto. This crate owns the connection, a per-call timeout, and
//! typed errors; the per-classifier fail-open/closed policy and the child
//! supervisor are layered on top by the proxy in a later WOR-704 PR.
//!
//! Transport is TCP (`http://host:port`) for now; a Unix-domain-socket
//! connector for a co-located sidecar is a follow-on latency optimization.

use std::time::Duration;

use sbproxy_classifier_proto::{
    ClassifyRequest, ClassifyResponse, InferenceServiceClient, VersionRequest, VersionResponse,
};
use tonic::transport::{Channel, Endpoint};

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
}
