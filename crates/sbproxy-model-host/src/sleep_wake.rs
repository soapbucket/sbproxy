// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! vLLM sleep/wake client (WOR-1655 core).
//!
//! Swapping models is far cheaper with vLLM's sleep/wake than a full
//! kill and respawn: level 1 offloads weights to CPU RAM and discards
//! the KV cache (fast wake), level 2 discards weights too (minimal
//! RAM). This is the HTTP client for those dev endpoints, driven over
//! the same dependency-free raw-loopback HTTP the readiness probe uses,
//! so it needs no HTTP-client crate and is testable against a mock
//! server. The endpoints are only registered when the engine runs with
//! `VLLM_SERVER_DEV_MODE=1`, which [`crate::launch::build_launch_spec`]
//! already sets for vLLM, and vLLM's docs say to expose them on trusted
//! networks only (loopback here).
//!
//! Wiring this into the supervisor as the default swap (sleep instead
//! of kill for a model that will be re-summoned) is the runtime half
//! and stays open; this is the client it will call.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How deeply to put an engine to sleep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepLevel {
    /// Level 1: offload weights to CPU RAM, discard KV. Fast wake.
    Weights,
    /// Level 2: discard weights and KV, keep buffers. Minimal RAM.
    Full,
}

impl SleepLevel {
    /// The `level` query value vLLM expects.
    fn as_query(self) -> u8 {
        match self {
            SleepLevel::Weights => 1,
            SleepLevel::Full => 2,
        }
    }
}

/// Default per-request timeout for a sleep/wake call.
pub const SLEEP_WAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Put the engine at `127.0.0.1:port` to sleep. `POST /sleep?level=N`.
pub async fn sleep(port: u16, level: SleepLevel) -> Result<(), String> {
    let path = format!("/sleep?level={}", level.as_query());
    let (status, _) = raw_request(port, "POST", &path, SLEEP_WAKE_TIMEOUT).await?;
    ok_2xx(status, "sleep")
}

/// Wake the engine at `127.0.0.1:port`. `POST /wake_up`, optionally
/// `?tags=weights` to wake only the weights (leaving KV cold).
pub async fn wake_up(port: u16, weights_only: bool) -> Result<(), String> {
    let path = if weights_only {
        "/wake_up?tags=weights"
    } else {
        "/wake_up"
    };
    let (status, _) = raw_request(port, "POST", path, SLEEP_WAKE_TIMEOUT).await?;
    ok_2xx(status, "wake_up")
}

/// Whether the engine at `127.0.0.1:port` is asleep. `GET /is_sleeping`
/// returns a small JSON body; we look for `"is_sleeping": true`.
pub async fn is_sleeping(port: u16) -> Result<bool, String> {
    let (status, body) = raw_request(port, "GET", "/is_sleeping", SLEEP_WAKE_TIMEOUT).await?;
    ok_2xx(status, "is_sleeping")?;
    // Tolerant of whitespace: strip it and match the boolean.
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    Ok(compact.contains("\"is_sleeping\":true") || compact == "true")
}

/// Map a status to Ok for 2xx, else a labeled error.
fn ok_2xx(status: u16, op: &str) -> Result<(), String> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("{op} returned HTTP {status}"))
    }
}

/// Send a bare HTTP/1.1 request to loopback and return `(status, body)`.
/// A minimal client so the crate keeps its no-HTTP-dependency posture,
/// the same approach as the readiness probe.
async fn raw_request(
    port: u16,
    method: &str,
    path: &str,
    timeout: Duration,
) -> Result<(u16, String), String> {
    let addr = format!("127.0.0.1:{port}");
    let fut = async {
        let mut stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("connect {addr}: {e}"))?;
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| format!("read: {e}"))?;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = parse_status(&text).ok_or_else(|| "no status line".to_string())?;
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        Ok::<(u16, String), String>((status, body.to_string()))
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(format!("{method} {path} timed out")),
    }
}

/// Parse the numeric status from an `HTTP/1.1 200 OK` line.
fn parse_status(response: &str) -> Option<u16> {
    let line = response.lines().next()?;
    line.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock vLLM dev endpoint: records the last request line and
    /// answers sleep/wake with 200 and /is_sleeping with a JSON body.
    async fn mock_engine(sleeping: bool) -> Option<(u16, tokio::task::JoinHandle<()>)> {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
        let port = listener.local_addr().ok()?.port();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 512];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first = req.lines().next().unwrap_or("");
                let body = if first.contains("/is_sleeping") {
                    format!("{{\"is_sleeping\": {sleeping}}}")
                } else {
                    "ok".to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        Some((port, handle))
    }

    #[tokio::test]
    async fn sleep_and_wake_hit_the_endpoints() {
        let Some((port, handle)) = mock_engine(false).await else {
            eprintln!("skipping: loopback bind denied");
            return;
        };
        assert!(sleep(port, SleepLevel::Weights).await.is_ok());
        assert!(sleep(port, SleepLevel::Full).await.is_ok());
        assert!(wake_up(port, true).await.is_ok());
        assert!(wake_up(port, false).await.is_ok());
        handle.abort();
    }

    #[tokio::test]
    async fn is_sleeping_parses_the_body() {
        let Some((port, handle)) = mock_engine(true).await else {
            eprintln!("skipping: loopback bind denied");
            return;
        };
        assert!(is_sleeping(port).await.unwrap());
        handle.abort();

        let Some((port2, handle2)) = mock_engine(false).await else {
            return;
        };
        assert!(!is_sleeping(port2).await.unwrap());
        handle2.abort();
    }

    #[tokio::test]
    async fn dead_port_errors_not_hangs() {
        // Nothing listening on port 1: connect fails quickly.
        assert!(sleep(1, SleepLevel::Weights).await.is_err());
    }

    #[test]
    fn sleep_level_query_values() {
        assert_eq!(SleepLevel::Weights.as_query(), 1);
        assert_eq!(SleepLevel::Full.as_query(), 2);
    }

    #[test]
    fn parses_status_line() {
        assert_eq!(parse_status("HTTP/1.1 200 OK\r\n\r\n"), Some(200));
        assert_eq!(parse_status("HTTP/1.1 503 Service Unavailable"), Some(503));
        assert_eq!(parse_status("garbage"), None);
    }
}
