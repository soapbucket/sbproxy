//! Size-bounded reads for untrusted HTTP response bodies.

use anyhow::{anyhow, bail, Result};
use bytes::{Bytes, BytesMut};

/// Read at most `maximum` bytes from a remote response.
///
/// The limit is enforced while chunks arrive, rather than after
/// `Response::bytes` has allocated the complete peer-controlled body.
/// Errors intentionally contain no response bytes or transport detail,
/// because DCR/CIMD responses can carry credentials and hostile newlines.
pub(crate) async fn bounded_response_body(
    mut response: reqwest::Response,
    maximum: usize,
    label: &'static str,
) -> Result<Bytes> {
    if maximum == 0 {
        bail!("{label} response body limit is zero");
    }
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        bail!("{label} response body exceeds {maximum} byte limit");
    }

    let mut body = BytesMut::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("{label} response body read failed"))?
    {
        if body.len().saturating_add(chunk.len()) > maximum {
            bail!("{label} response body exceeds {maximum} byte limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn response(raw: &'static [u8], hold_open: Duration) -> reqwest::Response {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            socket.write_all(raw).await.unwrap();
            if !hold_open.is_zero() {
                tokio::time::sleep(hold_open).await;
            }
        });
        sbproxy_httpkit::OutboundClientBuilder::new()
            .request_timeout(Duration::from_millis(75))
            .build()
            .unwrap()
            .get(format!("http://{address}/body"))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn advertised_oversize_is_rejected_before_body_read() {
        let response = response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\nConnection: close\r\n\r\n",
            Duration::ZERO,
        )
        .await;
        assert!(bounded_response_body(response, 32, "test")
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds"));
    }

    #[tokio::test]
    async fn chunked_oversize_is_stopped_incrementally() {
        let response = response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10\r\n0123456789abcdef\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n",
            Duration::ZERO,
        )
        .await;
        assert!(bounded_response_body(response, 24, "test")
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds"));
    }

    #[tokio::test]
    async fn endless_chunked_peer_is_terminated_by_request_deadline() {
        let response = response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n",
            Duration::from_millis(250),
        )
        .await;
        assert!(bounded_response_body(response, 32, "test")
            .await
            .unwrap_err()
            .to_string()
            .contains("read failed"));
    }
}
