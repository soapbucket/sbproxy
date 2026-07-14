use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use http::{HeaderMap, Request, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use sbproxy_mesh::transport::tls::{build_http2_connector, MeshTlsConfig};

use super::{
    ModelPlaneError, SignedDispatchEnvelope, MAX_SIGNED_DISPATCH_ENVELOPE_BYTES,
    MODEL_PLANE_DISPATCH_PATH,
};

const ERROR_CODE_HEADER: &str = "x-sbproxy-error-code";
const ERROR_RETRYABLE_HEADER: &str = "x-sbproxy-error-retryable";
const ESTABLISHMENT_TIMEOUT: Duration = Duration::from_secs(5);

trait ModelPlaneIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> ModelPlaneIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedIo = Box<dyn ModelPlaneIo>;

/// Client transport mode for one authenticated private dispatch.
#[derive(Clone)]
pub enum ModelPlaneClientSecurity {
    /// Production mutual TLS with an explicit certificate SAN.
    Mtls {
        /// Installed node certificate, key, and cluster CA.
        tls: MeshTlsConfig,
        /// Certificate DNS name validated independently from endpoint routing.
        server_name: String,
    },
    /// Explicit development h2c plus HMAC authentication.
    DevelopmentSharedKey {
        /// Development-only secret bytes, retained to prevent mode confusion.
        key: Arc<[u8]>,
    },
}

impl std::fmt::Debug for ModelPlaneClientSecurity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mtls { server_name, .. } => formatter
                .debug_struct("ModelPlaneClientSecurity::Mtls")
                .field("server_name", server_name)
                .finish_non_exhaustive(),
            Self::DevelopmentSharedKey { .. } => {
                formatter.write_str("ModelPlaneClientSecurity::DevelopmentSharedKey([REDACTED])")
            }
        }
    }
}

/// One authenticated private HTTP/2 response stream.
pub struct ModelPlaneResponse {
    /// Engine or internal response status.
    pub status: StatusCode,
    /// Allowlisted engine response headers.
    pub headers: HeaderMap,
    /// Backpressured response bytes; dropping the stream cancels the peer stream.
    pub body: Pin<Box<dyn Stream<Item = Result<Bytes, ModelPlaneError>> + Send>>,
    version: Version,
}

impl std::fmt::Debug for ModelPlaneResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ModelPlaneResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl ModelPlaneResponse {
    /// Negotiated HTTP version, always HTTP/2 on a successful dispatch.
    pub const fn http_version(&self) -> Version {
        self.version
    }
}

impl From<ModelPlaneResponse> for reqwest::Response {
    fn from(response: ModelPlaneResponse) -> Self {
        let ModelPlaneResponse {
            status,
            headers,
            body,
            version,
        } = response;
        let mut response = http::Response::new(reqwest::Body::wrap_stream(body));
        *response.status_mut() = status;
        *response.version_mut() = version;
        *response.headers_mut() = headers;
        response.into()
    }
}

/// Stateless connector for authenticated private model-plane attempts.
#[derive(Debug, Clone)]
pub struct ModelPlaneClient {
    security: ModelPlaneClientSecurity,
}

impl ModelPlaneClient {
    /// Create a client for one configured cluster security mode.
    pub const fn new(security: ModelPlaneClientSecurity) -> Self {
        Self { security }
    }

    /// Send one already-signed dispatch and return its backpressured response.
    pub async fn dispatch(
        &self,
        endpoint: &str,
        signed: &SignedDispatchEnvelope,
        request_body: Bytes,
    ) -> Result<ModelPlaneResponse, ModelPlaneError> {
        let started = std::time::Instant::now();
        let result = self.dispatch_inner(endpoint, signed, request_body).await;
        sbproxy_observe::metrics::record_model_plane_peer_dispatch(
            if result.is_ok() { "success" } else { "error" },
            started.elapsed().as_secs_f64(),
        );
        result
    }

    async fn dispatch_inner(
        &self,
        endpoint: &str,
        signed: &SignedDispatchEnvelope,
        request_body: Bytes,
    ) -> Result<ModelPlaneResponse, ModelPlaneError> {
        let mut url = url::Url::parse(endpoint)
            .map_err(|error| ModelPlaneError::InvalidConfiguration(error.to_string()))?;
        if url.query().is_some() || url.fragment().is_some() || url.host_str().is_none() {
            return Err(ModelPlaneError::InvalidConfiguration(
                "model endpoint must be an absolute origin".to_string(),
            ));
        }
        let host = url.host_str().expect("validated host").to_string();
        let port = url.port_or_known_default().ok_or_else(|| {
            ModelPlaneError::InvalidConfiguration("model endpoint port is absent".to_string())
        })?;
        let (mut sender, connection) = tokio::time::timeout(ESTABLISHMENT_TIMEOUT, async {
            let tcp = TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|error| ModelPlaneError::Transport(error.to_string()))?;
            let io: BoxedIo = match &self.security {
                ModelPlaneClientSecurity::Mtls { tls, server_name } => {
                    if url.scheme() != "https" {
                        return Err(ModelPlaneError::InvalidConfiguration(
                            "mTLS model endpoint must use https".to_string(),
                        ));
                    }
                    let connector = build_http2_connector(tls)
                        .map_err(|error| ModelPlaneError::Tls(error.to_string()))?;
                    let server_name = rustls::pki_types::ServerName::try_from(server_name.clone())
                        .map_err(|error| {
                            ModelPlaneError::InvalidConfiguration(error.to_string())
                        })?;
                    let tls = connector
                        .connect(server_name, tcp)
                        .await
                        .map_err(|error| ModelPlaneError::Tls(error.to_string()))?;
                    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                        return Err(ModelPlaneError::Tls(
                            "HTTP/2 ALPN was not negotiated".to_string(),
                        ));
                    }
                    Box::new(tls)
                }
                ModelPlaneClientSecurity::DevelopmentSharedKey { key } => {
                    if url.scheme() != "http" || key.len() < 16 {
                        return Err(ModelPlaneError::InvalidConfiguration(
                            "development model endpoint requires h2c and a bounded key".to_string(),
                        ));
                    }
                    Box::new(tcp)
                }
            };
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
                .await
                .map_err(|error| ModelPlaneError::Transport(error.to_string()))
        })
        .await
        .map_err(|_| {
            ModelPlaneError::Transport("model-plane establishment timed out".to_string())
        })??;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "private model-plane client connection closed");
            }
        });

        let wire = encode_wire_request(signed, &request_body)?;
        url.set_path(MODEL_PLANE_DISPATCH_PATH);
        url.set_query(None);
        url.set_fragment(None);
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(url.as_str())
            .header(
                http::header::CONTENT_TYPE,
                "application/vnd.sbproxy.model-dispatch",
            )
            .body(Full::new(wire))
            .map_err(|_| ModelPlaneError::InvalidRequest)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| ModelPlaneError::Transport(error.to_string()))?;
        let version = response.version();
        if version != Version::HTTP_2 {
            return Err(ModelPlaneError::Transport(
                "peer did not return HTTP/2".to_string(),
            ));
        }
        let (parts, body) = response.into_parts();
        if let Some(code) = parts
            .headers
            .get(ERROR_CODE_HEADER)
            .and_then(|value| value.to_str().ok())
        {
            let retryable = parts
                .headers
                .get(ERROR_RETRYABLE_HEADER)
                .is_some_and(|value| value == "true");
            return Err(ModelPlaneError::Remote {
                code: code.to_string(),
                retryable,
            });
        }
        let stream = body
            .into_data_stream()
            .map(|result| result.map_err(|error| ModelPlaneError::Transport(error.to_string())));
        Ok(ModelPlaneResponse {
            status: parts.status,
            headers: parts.headers,
            body: Box::pin(ObservedPeerStream {
                inner: Box::pin(stream),
                complete: false,
            }),
            version,
        })
    }
}

struct ObservedPeerStream {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, ModelPlaneError>> + Send>>,
    complete: bool,
}

impl Stream for ObservedPeerStream {
    type Item = Result<Bytes, ModelPlaneError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(context) {
            Poll::Ready(None) => {
                self.complete = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                self.complete = true;
                Poll::Ready(Some(Err(error)))
            }
            result => result,
        }
    }
}

impl Drop for ObservedPeerStream {
    fn drop(&mut self) {
        if !self.complete {
            sbproxy_observe::metrics::record_model_plane_stream_cancellation("peer");
        }
    }
}

fn encode_wire_request(
    signed: &SignedDispatchEnvelope,
    request_body: &[u8],
) -> Result<Bytes, ModelPlaneError> {
    let envelope = signed.to_json()?;
    if envelope.len() > MAX_SIGNED_DISPATCH_ENVELOPE_BYTES {
        return Err(ModelPlaneError::InvalidRequest);
    }
    let envelope_length = u32::try_from(envelope.len())
        .map_err(|_| ModelPlaneError::InvalidRequest)?
        .to_be_bytes();
    let capacity = 4usize
        .checked_add(envelope.len())
        .and_then(|length| length.checked_add(request_body.len()))
        .ok_or(ModelPlaneError::BodyTooLarge)?;
    let mut wire = BytesMut::with_capacity(capacity);
    wire.extend_from_slice(&envelope_length);
    wire.extend_from_slice(&envelope);
    wire.extend_from_slice(request_body);
    Ok(wire.freeze())
}
