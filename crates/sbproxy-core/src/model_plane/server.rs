use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::{Bytes, BytesMut};
use futures::Stream;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, Sleep};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use sbproxy_mesh::transport::tls::{build_http2_acceptor, MeshTlsConfig};
use sbproxy_mesh::ClusterHandle;

use super::{
    rewrite_engine_model, DispatchReplayFence, DispatchVerifier, ModelPlaneError,
    PreparedWorkerExecution, SignedDispatchEnvelope, WorkerModelExecution,
    MAX_SIGNED_DISPATCH_ENVELOPE_BYTES,
};

/// Versioned internal path prefix reserved for private model dispatch.
pub const MODEL_PLANE_PATH_PREFIX: &str = "/_sbproxy/model-plane/v1";
/// Exact internal request path accepted by the private listener.
pub const MODEL_PLANE_DISPATCH_PATH: &str = "/_sbproxy/model-plane/v1/dispatch";

const MAX_HEADER_COUNT: usize = 16;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const DEFAULT_REPLAY_CAPACITY: usize = 65_536;
const DEFAULT_MAX_CONNECTIONS: usize = 256;
const DEFAULT_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const ERROR_CODE_HEADER: &str = "x-sbproxy-error-code";
const ERROR_RETRYABLE_HEADER: &str = "x-sbproxy-error-retryable";

type ServerBody = UnsyncBoxBody<Bytes, ModelPlaneError>;

trait ModelPlaneIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> ModelPlaneIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedIo = Box<dyn ModelPlaneIo>;

struct IdleTimeoutIo<T> {
    inner: T,
    timeout: Duration,
    idle: Pin<Box<Sleep>>,
}

impl<T> IdleTimeoutIo<T> {
    fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            idle: Box::pin(tokio::time::sleep(timeout)),
        }
    }

    fn reset(&mut self) {
        self.idle.as_mut().reset(Instant::now() + self.timeout);
    }

    fn poll_timeout(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.idle.as_mut().poll(context) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "private model-plane connection idle timeout",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleTimeoutIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled = buffer.filled().len();
        match Pin::new(&mut this.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) if buffer.filled().len() > filled => {
                this.reset();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => this.poll_timeout(context),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleTimeoutIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) if written > 0 => {
                this.reset();
                Poll::Ready(Ok(written))
            }
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => match this.poll_timeout(context) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) | Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(context) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => this.poll_timeout(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(context) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => this.poll_timeout(context),
        }
    }
}

/// Listener bounds and local authenticated audience.
#[derive(Debug, Clone)]
pub struct ModelPlaneServerConfig {
    /// Dedicated private listener address.
    pub bind_addr: SocketAddr,
    /// Installed worker node ID used as the dispatch audience.
    pub node_id: String,
    /// Maximum exact inference request body size.
    pub max_request_body_bytes: usize,
    /// Maximum live replay entries before failing closed.
    pub replay_capacity: usize,
    /// Maximum private TCP connections served concurrently.
    pub max_connections: usize,
    /// Maximum period without connection read or write progress.
    pub connection_idle_timeout: Duration,
    /// Maximum graceful wait for active peer streams.
    pub shutdown_timeout: Duration,
}

impl ModelPlaneServerConfig {
    /// Construct listener config with bounded production defaults.
    pub fn new(
        bind_addr: SocketAddr,
        node_id: impl Into<String>,
        max_request_body_bytes: usize,
    ) -> Self {
        Self {
            bind_addr,
            node_id: node_id.into(),
            max_request_body_bytes,
            replay_capacity: DEFAULT_REPLAY_CAPACITY,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connection_idle_timeout: DEFAULT_CONNECTION_IDLE_TIMEOUT,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
        }
    }

    fn validate(&self) -> Result<(), ModelPlaneError> {
        if self.node_id.is_empty()
            || self.node_id.len() > 128
            || !self
                .node_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            || self.max_request_body_bytes == 0
            || self.max_request_body_bytes > 1024 * 1024 * 1024
            || self.replay_capacity == 0
            || self.max_connections == 0
            || self.connection_idle_timeout.is_zero()
            || self.shutdown_timeout.is_zero()
        {
            return Err(ModelPlaneError::InvalidConfiguration(
                "listener bounds or node ID are invalid".to_string(),
            ));
        }
        Ok(())
    }
}

/// Authentication and transport mode for the private listener.
#[derive(Clone)]
pub enum ModelPlaneServerSecurity {
    /// Production mutual TLS plus enrolled peer-proof verification.
    Mtls {
        /// Installed node certificate, key, and cluster CA.
        tls: MeshTlsConfig,
        /// Cluster identity authenticator used to verify the signed envelope.
        cluster: ClusterHandle,
    },
    /// Explicit development h2c plus HMAC authentication.
    DevelopmentSharedKey {
        /// Development-only secret bytes.
        key: Arc<[u8]>,
    },
}

impl std::fmt::Debug for ModelPlaneServerSecurity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mtls { .. } => formatter.write_str("ModelPlaneServerSecurity::Mtls"),
            Self::DevelopmentSharedKey { .. } => {
                formatter.write_str("ModelPlaneServerSecurity::DevelopmentSharedKey([REDACTED])")
            }
        }
    }
}

#[derive(Clone)]
enum DispatchVerification {
    PeerIdentity(ClusterHandle),
    DevelopmentSharedKey(Arc<[u8]>),
}

struct ServerState {
    node_id: String,
    max_request_body_bytes: usize,
    replay: DispatchReplayFence,
    verification: DispatchVerification,
    execution: WorkerModelExecution,
    upstream: reqwest::Client,
}

/// Factory for one dedicated private HTTP/2 model-plane listener.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModelPlaneServer;

impl ModelPlaneServer {
    /// Bind and start the listener, returning its process-owned handle.
    pub async fn start(
        config: ModelPlaneServerConfig,
        security: ModelPlaneServerSecurity,
        execution: WorkerModelExecution,
    ) -> Result<ModelPlaneServerHandle, ModelPlaneError> {
        config.validate()?;
        let listener = TcpListener::bind(config.bind_addr)
            .await
            .map_err(|error| ModelPlaneError::Transport(error.to_string()))?;
        let local_addr = listener
            .local_addr()
            .map_err(|error| ModelPlaneError::Transport(error.to_string()))?;
        let (acceptor, verification) = match &security {
            ModelPlaneServerSecurity::Mtls { tls, cluster } => (
                Some(
                    build_http2_acceptor(tls)
                        .map_err(|error| ModelPlaneError::Tls(error.to_string()))?,
                ),
                DispatchVerification::PeerIdentity(cluster.clone()),
            ),
            ModelPlaneServerSecurity::DevelopmentSharedKey { key } => {
                if key.len() < 16 {
                    return Err(ModelPlaneError::InvalidConfiguration(
                        "development shared key is too short".to_string(),
                    ));
                }
                (
                    None,
                    DispatchVerification::DevelopmentSharedKey(Arc::clone(key)),
                )
            }
        };
        let upstream = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|error| ModelPlaneError::InvalidConfiguration(error.to_string()))?;
        let state = Arc::new(ServerState {
            node_id: config.node_id,
            max_request_body_bytes: config.max_request_body_bytes,
            replay: DispatchReplayFence::new(config.replay_capacity),
            verification,
            execution,
            upstream,
        });
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let max_connections = config.max_connections;
        let connection_idle_timeout = config.connection_idle_timeout;
        let shutdown_timeout = config.shutdown_timeout;
        let task = tokio::spawn(async move {
            run_listener(
                listener,
                acceptor,
                state,
                task_cancellation,
                max_connections,
                connection_idle_timeout,
                shutdown_timeout,
            )
            .await
        });
        Ok(ModelPlaneServerHandle {
            local_addr,
            cancellation,
            task: Some(task),
        })
    }
}

/// Process-owned running listener and graceful-shutdown control.
pub struct ModelPlaneServerHandle {
    local_addr: SocketAddr,
    cancellation: CancellationToken,
    task: Option<JoinHandle<Result<(), ModelPlaneError>>>,
}

impl std::fmt::Debug for ModelPlaneServerHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ModelPlaneServerHandle")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl ModelPlaneServerHandle {
    /// Actual bound address, including an operating-system selected port.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop accepting and wait for active streams up to the configured deadline.
    pub async fn shutdown(mut self) -> Result<(), ModelPlaneError> {
        self.cancellation.cancel();
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        join_server_task(task).await
    }

    pub(crate) async fn shutdown_on(
        mut self,
        mut shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), ModelPlaneError> {
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        tokio::select! {
            result = &mut task => {
                result.map_err(|error| ModelPlaneError::Transport(error.to_string()))?
            }
            _ = &mut shutdown => {
                self.cancellation.cancel();
                join_server_task(task).await
            }
        }
    }
}

impl Drop for ModelPlaneServerHandle {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn join_server_task(
    task: JoinHandle<Result<(), ModelPlaneError>>,
) -> Result<(), ModelPlaneError> {
    task.await
        .map_err(|error| ModelPlaneError::Transport(error.to_string()))?
}

async fn run_listener(
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
    state: Arc<ServerState>,
    cancellation: CancellationToken,
    max_connections: usize,
    connection_idle_timeout: Duration,
    shutdown_timeout: Duration,
) -> Result<(), ModelPlaneError> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::warn!(%error, "private model-plane connection task failed");
                }
            }
            accepted = listener.accept(), if connections.len() < max_connections => {
                let (tcp, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => return Err(ModelPlaneError::Transport(error.to_string())),
                };
                let acceptor = acceptor.clone();
                let state = Arc::clone(&state);
                let connection_cancellation = cancellation.clone();
                connections.spawn(async move {
                    if let Err(error) = serve_connection(
                        tcp,
                        acceptor,
                        state,
                        connection_cancellation,
                        connection_idle_timeout,
                        shutdown_timeout,
                    ).await {
                        tracing::warn!(code = error.code(), "private model-plane connection failed");
                    }
                });
            }
        }
    }

    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(shutdown_timeout, drain).await.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}

async fn serve_connection(
    tcp: TcpStream,
    acceptor: Option<TlsAcceptor>,
    state: Arc<ServerState>,
    cancellation: CancellationToken,
    connection_idle_timeout: Duration,
    shutdown_timeout: Duration,
) -> Result<(), ModelPlaneError> {
    let tcp = IdleTimeoutIo::new(tcp, connection_idle_timeout);
    let (io, tls_peer_certificate_sha256): (BoxedIo, Option<String>) = match acceptor {
        Some(acceptor) => {
            let tls = acceptor
                .accept(tcp)
                .await
                .map_err(|error| ModelPlaneError::Tls(error.to_string()))?;
            if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                return Err(ModelPlaneError::Tls(
                    "HTTP/2 ALPN was not negotiated".to_string(),
                ));
            }
            let certificate = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .ok_or_else(|| ModelPlaneError::Tls("client certificate is absent".to_string()))?;
            let fingerprint = URL_SAFE_NO_PAD.encode(Sha256::digest(certificate.as_ref()));
            (Box::new(tls), Some(fingerprint))
        }
        None => (Box::new(tcp), None),
    };
    let service = service_fn(move |request| {
        handle_request(
            request,
            Arc::clone(&state),
            tls_peer_certificate_sha256.clone(),
        )
    });
    let connection = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), service);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => {
            result.map_err(|error| ModelPlaneError::Transport(error.to_string()))?;
        }
        _ = cancellation.cancelled() => {
            connection.as_mut().graceful_shutdown();
            tokio::time::timeout(shutdown_timeout, &mut connection)
                .await
                .map_err(|_| ModelPlaneError::Shutdown)?
                .map_err(|error| ModelPlaneError::Transport(error.to_string()))?;
        }
    }
    Ok(())
}

async fn handle_request(
    request: Request<Incoming>,
    state: Arc<ServerState>,
    tls_peer_certificate_sha256: Option<String>,
) -> Result<Response<ServerBody>, Infallible> {
    let response = dispatch_request(request, state, tls_peer_certificate_sha256)
        .await
        .unwrap_or_else(error_response);
    Ok(response)
}

async fn dispatch_request(
    request: Request<Incoming>,
    state: Arc<ServerState>,
    tls_peer_certificate_sha256: Option<String>,
) -> Result<Response<ServerBody>, ModelPlaneError> {
    if request.method() != Method::POST
        || request.uri().path() != MODEL_PLANE_DISPATCH_PATH
        || request.version() != Version::HTTP_2
        || !headers_are_bounded(request.headers())
        || request.headers().contains_key(http::header::AUTHORIZATION)
        || request.headers().contains_key("x-api-key")
    {
        return Err(ModelPlaneError::InvalidRequest);
    }
    let max_wire_bytes = state
        .max_request_body_bytes
        .checked_add(MAX_SIGNED_DISPATCH_ENVELOPE_BYTES + 4)
        .ok_or(ModelPlaneError::BodyTooLarge)?;
    let wire = collect_bounded(request.into_body(), max_wire_bytes).await?;
    let (signed, request_body) = decode_wire_request(&wire, state.max_request_body_bytes)?;
    let now = now_unix_ms()?;
    let verifier = match &state.verification {
        DispatchVerification::PeerIdentity(cluster) => DispatchVerifier::PeerIdentity {
            cluster,
            tls_peer_certificate_sha256: tls_peer_certificate_sha256
                .as_deref()
                .ok_or(ModelPlaneError::InvalidRequest)?,
        },
        DispatchVerification::DevelopmentSharedKey(key) => {
            if tls_peer_certificate_sha256.is_some() {
                return Err(ModelPlaneError::InvalidRequest);
            }
            DispatchVerifier::DevelopmentSharedKey(key)
        }
    };
    let verified = signed.verify(verifier, &state.node_id, now, request_body)?;
    state.replay.check_and_record(
        &verified.envelope.issuer_node_id,
        &verified.envelope.nonce,
        verified.envelope.expires_at_unix_ms,
        now,
    )?;
    let execution = state
        .execution
        .prepare(
            &verified.envelope.deployment,
            verified.envelope.deployment_generation,
            verified.envelope.priority,
        )
        .await?;
    let upstream_body = rewrite_engine_model(
        request_body,
        verified.envelope.content_type.as_deref(),
        &execution.engine_model,
        state.max_request_body_bytes,
    )?;
    let target = format!("{}{}", execution.base_url, verified.envelope.path);
    let mut upstream_request = state.upstream.post(target).body(upstream_body);
    if let Some(content_type) = verified.envelope.content_type.as_deref() {
        upstream_request = upstream_request.header(reqwest::header::CONTENT_TYPE, content_type);
    }
    let upstream = upstream_request
        .send()
        .await
        .map_err(|error| ModelPlaneError::Upstream(error.to_string()))?;
    upstream_response(upstream, execution)
}

fn upstream_response(
    upstream: reqwest::Response,
    execution: PreparedWorkerExecution,
) -> Result<Response<ServerBody>, ModelPlaneError> {
    let status = upstream.status();
    let mut response = Response::builder().status(status);
    for name in [
        http::header::CONTENT_TYPE,
        http::header::CACHE_CONTROL,
        http::header::RETRY_AFTER,
        http::header::WARNING,
    ] {
        if let Some(value) = upstream.headers().get(&name) {
            response = response.header(name, value);
        }
    }
    let stream = GuardedUpstreamStream {
        inner: Box::pin(upstream.bytes_stream()),
        _execution: Arc::new(execution),
    };
    let body = StreamBody::new(stream).boxed_unsync();
    response
        .body(body)
        .map_err(|error| ModelPlaneError::Upstream(error.to_string()))
}

struct GuardedUpstreamStream {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    _execution: Arc<PreparedWorkerExecution>,
}

impl Stream for GuardedUpstreamStream {
    type Item = Result<Frame<Bytes>, ModelPlaneError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(Err(ModelPlaneError::Upstream(error.to_string()))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn collect_bounded(mut body: Incoming, max_bytes: usize) -> Result<Bytes, ModelPlaneError> {
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| ModelPlaneError::Transport(error.to_string()))?;
        let data = frame
            .into_data()
            .map_err(|_| ModelPlaneError::InvalidRequest)?;
        if collected.len().saturating_add(data.len()) > max_bytes {
            return Err(ModelPlaneError::BodyTooLarge);
        }
        collected.extend_from_slice(&data);
    }
    Ok(collected.freeze())
}

fn decode_wire_request(
    wire: &[u8],
    max_request_body_bytes: usize,
) -> Result<(SignedDispatchEnvelope, &[u8]), ModelPlaneError> {
    let length_bytes: [u8; 4] = wire
        .get(..4)
        .ok_or(ModelPlaneError::InvalidRequest)?
        .try_into()
        .map_err(|_| ModelPlaneError::InvalidRequest)?;
    let envelope_length = u32::from_be_bytes(length_bytes) as usize;
    if envelope_length == 0 || envelope_length > MAX_SIGNED_DISPATCH_ENVELOPE_BYTES {
        return Err(ModelPlaneError::InvalidRequest);
    }
    let envelope_end = 4usize
        .checked_add(envelope_length)
        .ok_or(ModelPlaneError::InvalidRequest)?;
    let envelope_bytes = wire
        .get(4..envelope_end)
        .ok_or(ModelPlaneError::InvalidRequest)?;
    let request_body = wire
        .get(envelope_end..)
        .ok_or(ModelPlaneError::InvalidRequest)?;
    if request_body.len() > max_request_body_bytes {
        return Err(ModelPlaneError::BodyTooLarge);
    }
    Ok((
        SignedDispatchEnvelope::parse_json(envelope_bytes)?,
        request_body,
    ))
}

fn headers_are_bounded(headers: &HeaderMap) -> bool {
    let bytes = headers.iter().try_fold(0usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len())?
            .checked_add(value.as_bytes().len())
    });
    headers.len() <= MAX_HEADER_COUNT && matches!(bytes, Some(bytes) if bytes <= MAX_HEADER_BYTES)
}

fn error_response(error: ModelPlaneError) -> Response<ServerBody> {
    sbproxy_observe::metrics::record_model_plane_rejection(
        error.code(),
        error.retry_class().as_str(),
    );
    let status = match &error {
        ModelPlaneError::Envelope(super::DispatchEnvelopeError::ReplayDetected) => {
            StatusCode::CONFLICT
        }
        ModelPlaneError::Envelope(_) => StatusCode::UNAUTHORIZED,
        ModelPlaneError::StaleDeploymentGeneration | ModelPlaneError::DeploymentNotAssigned => {
            StatusCode::CONFLICT
        }
        ModelPlaneError::Admission(_) => StatusCode::TOO_MANY_REQUESTS,
        ModelPlaneError::NoEligibleReplica
        | ModelPlaneError::Runtime(_)
        | ModelPlaneError::Upstream(_) => StatusCode::SERVICE_UNAVAILABLE,
        ModelPlaneError::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ModelPlaneError::Shutdown => StatusCode::SERVICE_UNAVAILABLE,
        ModelPlaneError::InvalidRequest
        | ModelPlaneError::InvalidConfiguration(_)
        | ModelPlaneError::Tls(_)
        | ModelPlaneError::Transport(_)
        | ModelPlaneError::Remote { .. } => StatusCode::BAD_REQUEST,
    };
    let code = error.code().to_string();
    let retryable = error.retryable();
    let payload = serde_json::to_vec(&serde_json::json!({
        "error": { "code": code }
    }))
    .expect("static model-plane error JSON");
    let body = Full::new(Bytes::from(payload))
        .map_err(|never| -> ModelPlaneError { match never {} })
        .boxed_unsync();
    let mut response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .expect("static model-plane error response");
    if let Ok(value) = HeaderValue::from_str(&code) {
        response.headers_mut().insert(ERROR_CODE_HEADER, value);
    }
    response.headers_mut().insert(
        ERROR_RETRYABLE_HEADER,
        HeaderValue::from_static(if retryable { "true" } else { "false" }),
    );
    response
}

fn now_unix_ms() -> Result<u64, ModelPlaneError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| ModelPlaneError::InvalidConfiguration(error.to_string()))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|_| ModelPlaneError::InvalidConfiguration("system clock overflow".to_string()))
}
