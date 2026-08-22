//! HTTP endpoints for health probes and metrics scraping.
//!
//! Ported from the enterprise `sbproxy-classifier` crate's `health.rs`, with
//! the metrics half adapted from `metrics-exporter-prometheus` to the
//! `prometheus` crate (see `crate::metrics` for why). Exposes:
//!
//! - `GET /healthz` - liveness probe. Always 200 once the server is up.
//! - `GET /readyz` - readiness probe. 200 once startup has finished; 503
//!   before that.
//! - `GET /metrics` - Prometheus text exposition of every family in
//!   `crate::metrics`, gathered from the process-global default registry.
//! - `GET /tenants` - JSON array of registered tenant ids, for a quick
//!   operator check without reaching for the TCP `list` command.

use crate::registry::Registry;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::debug;

/// Readiness flag. Starts `false`; flipped to `true` exactly once by the
/// startup driver in `main.rs` once the servers are bound.
#[derive(Clone, Debug, Default)]
pub struct ReadyState {
    flag: Arc<AtomicBool>,
}

impl ReadyState {
    /// Build a fresh `ReadyState` in the not-ready position.
    pub fn new() -> Self {
        Self::default()
    }

    /// Flip the readiness flag to `true`. Idempotent.
    pub fn mark_ready(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// Read the current readiness state.
    pub fn is_ready(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}

/// Serve `/healthz`, `/readyz`, `/metrics`, and `/tenants` on `addr` until
/// the process exits or the listener errors.
pub async fn serve(
    addr: &str,
    registry: Arc<Registry>,
    ready: ReadyState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let registry = Arc::clone(&registry);
        let ready = ready.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_health(stream, &registry, &ready).await {
                debug!(error = %e, "health connection ended");
            }
        });
    }
}

async fn handle_health(
    mut stream: tokio::net::TcpStream,
    registry: &Registry,
    ready: &ReadyState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();

    // Drain the rest of the request headers; nothing here reads a body.
    let mut header = String::new();
    loop {
        header.clear();
        reader.read_line(&mut header).await?;
        if header.trim().is_empty() {
            break;
        }
    }

    let (status, content_type, body): (u16, String, String) = match path.as_str() {
        "/healthz" => (
            200,
            "application/json".to_string(),
            r#"{"status":"ok"}"#.to_string(),
        ),
        "/readyz" => {
            if ready.is_ready() {
                (
                    200,
                    "application/json".to_string(),
                    r#"{"ready":true}"#.to_string(),
                )
            } else {
                (
                    503,
                    "application/json".to_string(),
                    r#"{"ready":false}"#.to_string(),
                )
            }
        }
        "/tenants" => {
            let tenants: Vec<String> = registry.list().into_iter().map(|t| t.id).collect();
            let body = serde_json::to_string(&tenants).unwrap_or_else(|_| "[]".to_string());
            (200, "application/json".to_string(), body)
        }
        "/metrics" => {
            use prometheus::Encoder;
            let encoder = prometheus::TextEncoder::new();
            let content_type = encoder.format_type().to_string();
            let metric_families = prometheus::gather();
            let mut buf = Vec::new();
            match encoder.encode(&metric_families, &mut buf) {
                Ok(()) => (
                    200,
                    content_type,
                    String::from_utf8_lossy(&buf).into_owned(),
                ),
                Err(e) => (500, "text/plain".to_string(), format!("encode error: {e}")),
            }
        }
        _ => (404, "text/plain".to_string(), "not found".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        reason = status_reason(status),
        len = body.len(),
    );
    writer.write_all(response.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_state_starts_false_and_flips_once() {
        let ready = ReadyState::new();
        assert!(!ready.is_ready());
        ready.mark_ready();
        assert!(ready.is_ready());
        // Idempotent: marking again does not panic or change the state.
        ready.mark_ready();
        assert!(ready.is_ready());
    }

    #[tokio::test]
    async fn healthz_returns_ok_before_readiness() {
        let registry = Arc::new(Registry::new_empty());
        let ready = ReadyState::new();
        let addr = "127.0.0.1:0";
        let listener = TcpListener::bind(addr).await.unwrap();
        let bound = listener.local_addr().unwrap();
        let registry_task = Arc::clone(&registry);
        let ready_task = ready.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let registry = Arc::clone(&registry_task);
                let ready = ready_task.clone();
                tokio::spawn(async move {
                    let _ = handle_health(stream, &registry, &ready).await;
                });
            }
        });

        let response = http_get(bound, "/healthz").await;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains(r#"{"status":"ok"}"#));

        let response = http_get(bound, "/readyz").await;
        assert!(response.starts_with("HTTP/1.1 503"));
    }

    async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = String::new();
        stream.read_to_string(&mut buf).await.unwrap();
        buf
    }
}
