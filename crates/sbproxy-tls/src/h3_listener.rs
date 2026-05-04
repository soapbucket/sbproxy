//! HTTP/3 listener using quinn and h3.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use tracing::{debug, info, warn};

use crate::cert_resolver::CertResolver;
use sbproxy_config::Http3Config;

// --- Public types ---

/// HTTP response returned by the pipeline dispatch function.
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers as ordered name/value pairs.
    pub headers: Vec<(String, String)>,
    /// Optional response body bytes.
    pub body: Option<Bytes>,
}

/// Type alias for the transport-agnostic dispatch callback.
pub type DispatchFn = Arc<
    dyn Fn(
            http::Method,
            http::Uri,
            http::HeaderMap,
            Option<Bytes>,
            std::net::IpAddr,
        ) -> Pin<Box<dyn Future<Output = Result<HttpResponse>> + Send>>
        + Send
        + Sync,
>;

// --- Listener entry point ---

/// Start an HTTP/3 listener on `bind_addr`.
///
/// Returns a [`tokio::task::JoinHandle`] that completes when the endpoint is
/// shut down or encounters an unrecoverable error.
pub fn start_h3_listener(
    bind_addr: SocketAddr,
    cert_resolver: Arc<CertResolver>,
    dispatch_fn: DispatchFn,
    config: &Http3Config,
) -> Result<tokio::task::JoinHandle<()>> {
    // --- Build rustls ServerConfig from the resolver ---
    let rustls_config = cert_resolver
        .rustls_server_config()
        .context("building rustls ServerConfig for HTTP/3")?;

    // Wrap in QuicServerConfig (quinn 0.11 requires this adapter).
    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .map_err(|e| anyhow::anyhow!("QuicServerConfig: {e}"))?;

    // --- Quinn transport config ---
    let mut transport = quinn::TransportConfig::default();

    // max_concurrent_bidi_streams uses VarInt.
    let max_streams = quinn::VarInt::from_u32(config.max_streams);
    transport.max_concurrent_bidi_streams(max_streams);

    // idle_timeout is milliseconds encoded as VarInt via IdleTimeout::try_from(Duration).
    let idle = Duration::from_secs(u64::from(config.idle_timeout_secs));
    match quinn::IdleTimeout::try_from(idle) {
        Ok(timeout) => {
            transport.max_idle_timeout(Some(timeout));
        }
        Err(e) => {
            warn!("idle_timeout_secs out of range for QUIC VarInt, using default: {e}");
        }
    }

    // --- Quinn ServerConfig ---
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(transport));

    // --- Endpoint ---
    let endpoint = quinn::Endpoint::server(server_config, bind_addr)
        .with_context(|| format!("binding QUIC endpoint on {bind_addr}"))?;

    info!(addr = %bind_addr, "HTTP/3 listener started");

    let handle = tokio::spawn(run_listener(endpoint, dispatch_fn));
    Ok(handle)
}

// --- Internal loop ---

/// Accept incoming QUIC connections and spawn per-connection tasks.
async fn run_listener(endpoint: quinn::Endpoint, dispatch_fn: DispatchFn) {
    while let Some(incoming) = endpoint.accept().await {
        let dispatch = dispatch_fn.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, dispatch).await {
                warn!("H3 connection error: {e:#}");
            }
        });
    }
    info!("HTTP/3 listener stopped");
}

/// Complete the QUIC handshake, then loop accepting H3 requests.
async fn handle_connection(incoming: quinn::Incoming, dispatch_fn: DispatchFn) -> Result<()> {
    let client_ip = incoming.remote_address().ip();

    // Accept the QUIC connection (completes TLS handshake).
    let quic_conn = incoming
        .accept()
        .map_err(|e| anyhow::anyhow!("QUIC accept error: {e}"))?
        .await
        .context("QUIC handshake failed")?;

    debug!(peer = %client_ip, "QUIC handshake complete");

    // Build the h3 server connection on top of the QUIC connection.
    let h3_quinn_conn = h3_quinn::Connection::new(quic_conn);
    let mut h3_conn = h3::server::builder()
        .build(h3_quinn_conn)
        .await
        .context("building H3 server connection")?;

    // Accept H3 requests in a loop.
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let dispatch = dispatch_fn.clone();
                tokio::spawn(async move {
                    // Resolve the request headers from the QUIC stream.
                    let (req, stream) = match resolver.resolve_request().await {
                        Ok(pair) => pair,
                        Err(e) => {
                            warn!("H3 resolve_request error: {e:#}");
                            return;
                        }
                    };
                    if let Err(e) = handle_request(req, stream, dispatch, client_ip).await {
                        warn!("H3 request handler error: {e:#}");
                    }
                });
            }
            Ok(None) => {
                debug!(peer = %client_ip, "H3 connection closed by peer");
                break;
            }
            Err(e) => {
                warn!(peer = %client_ip, "H3 accept error: {e:#}");
                break;
            }
        }
    }

    Ok(())
}

/// Read the request body, invoke the dispatch function, and write the H3 response.
async fn handle_request<S>(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    dispatch_fn: DispatchFn,
    client_ip: std::net::IpAddr,
) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (parts, _) = req.into_parts();

    // --- Read request body ---
    let mut body_bytes = bytes::BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await.context("recv_data")? {
        use bytes::Buf;
        while chunk.remaining() > 0 {
            let b = chunk.copy_to_bytes(chunk.remaining());
            body_bytes.extend_from_slice(&b);
        }
    }
    let body: Option<Bytes> = if body_bytes.is_empty() {
        None
    } else {
        Some(body_bytes.freeze())
    };

    // --- Dispatch ---
    let resp = dispatch_fn(parts.method, parts.uri, parts.headers, body, client_ip)
        .await
        .context("dispatch_fn failed")?;

    // --- Build http::Response ---
    let mut builder = http::Response::builder().status(resp.status);
    for (name, value) in &resp.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let http_response = builder.body(()).context("building HTTP response")?;

    stream
        .send_response(http_response)
        .await
        .context("send_response")?;

    if let Some(body) = resp.body {
        stream.send_data(body).await.context("send_data")?;
    }

    stream.finish().await.context("finish stream")?;

    Ok(())
}
