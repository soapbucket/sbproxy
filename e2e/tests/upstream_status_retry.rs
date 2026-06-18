//! End-to-end coverage for action-level retries triggered by upstream
//! response status codes.
//!
//! Status retries are decided before downstream response headers are
//! written. Safe/idempotent methods may be replayed when Pingora's
//! retry buffer still holds the complete request body; unsafe or
//! oversized requests surface `x-sbproxy-retry-skip-reason` and pass
//! the upstream response through unchanged.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::Duration;

fn proxy_retry_config(upstream_url: &str, host: &str, retry_on: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "{host}":
    action:
      type: proxy
      url: {upstream_url}
      retry:
        max_attempts: 2
        retry_on: [{retry_on}]
        backoff_ms: 0
"#
    )
}

struct EarlyStatusUpstream {
    port: u16,
    captured: Arc<AtomicUsize>,
    shutdown: Arc<Mutex<bool>>,
    join: Option<JoinHandle<()>>,
}

impl EarlyStatusUpstream {
    fn start(status: u16) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let captured = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(Mutex::new(false));
        let captured_clone = captured.clone();
        let shutdown_clone = shutdown.clone();

        let join = std::thread::spawn(move || {
            for incoming in listener.incoming() {
                if *shutdown_clone.lock().unwrap() {
                    break;
                }
                let Ok(mut stream) = incoming else {
                    continue;
                };
                let captured = captured_clone.clone();
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut buf = Vec::with_capacity(1024);
                    let mut tmp = [0u8; 256];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        let Ok(n) = stream.read(&mut tmp) else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() > 16 * 1024 {
                            return;
                        }
                    }
                    captured.fetch_add(1, Ordering::SeqCst);
                    let body = br#"{"early":true}"#;
                    let response = format!(
                        "HTTP/1.1 {} Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status,
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.write_all(body);
                    let _ = stream.flush();
                });
            }
        });

        Ok(Self {
            port,
            captured,
            shutdown,
            join: Some(join),
        })
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn captured_len(&self) -> usize {
        self.captured.load(Ordering::SeqCst)
    }
}

impl Drop for EarlyStatusUpstream {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn send_raw_partial_request(port: u16, request: &[u8]) -> anyhow::Result<(u16, Vec<u8>)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(request)?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if response_complete(&buf) {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok((parse_status(&buf), buf))
}

fn response_complete(buf: &[u8]) -> bool {
    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let Ok(headers) = std::str::from_utf8(&buf[..header_end]) else {
        return false;
    };
    let content_length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    buf.len() >= header_end + 4 + content_length
}

fn parse_status(buf: &[u8]) -> u16 {
    let line_end = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(buf.len());
    std::str::from_utf8(&buf[..line_end])
        .ok()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0)
}

#[test]
fn proxy_retries_configured_status_and_returns_later_success() {
    let upstream = MockUpstream::start_sequence(vec![
        (502, json!({"attempt": 1})),
        (200, json!({"attempt": 2})),
    ])
    .expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&proxy_retry_config(
        &upstream.base_url(),
        "retry.localhost",
        "502",
    ))
    .expect("proxy");

    let resp = proxy.get("/", "retry.localhost").expect("GET");

    assert_eq!(resp.status, 200);
    assert_eq!(resp.json().expect("json")["attempt"], 2);
    assert_eq!(
        upstream.captured().len(),
        2,
        "502 must be retried once before returning the later 200"
    );
}

#[test]
fn proxy_passes_through_status_not_listed_in_retry_on() {
    let upstream = MockUpstream::start_sequence(vec![
        (501, json!({"attempt": 1})),
        (200, json!({"attempt": 2})),
    ])
    .expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&proxy_retry_config(
        &upstream.base_url(),
        "pass.localhost",
        "502",
    ))
    .expect("proxy");

    let resp = proxy.get("/", "pass.localhost").expect("GET");

    assert_eq!(resp.status, 501);
    assert_eq!(resp.json().expect("json")["attempt"], 1);
    assert_eq!(
        upstream.captured().len(),
        1,
        "non-retry status must not consume another upstream attempt"
    );
}

#[test]
fn proxy_skips_status_retry_for_non_idempotent_method() {
    let upstream = MockUpstream::start_sequence(vec![
        (502, json!({"attempt": 1})),
        (200, json!({"attempt": 2})),
    ])
    .expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&proxy_retry_config(
        &upstream.base_url(),
        "post.localhost",
        "502",
    ))
    .expect("proxy");

    let resp = proxy
        .post_json("/orders", "post.localhost", &json!({"sku": "abc"}), &[])
        .expect("POST");

    assert_eq!(resp.status, 502);
    assert_eq!(
        resp.headers
            .get("x-sbproxy-retry-skip-reason")
            .map(String::as_str),
        Some("non_idempotent_method")
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "POST must not be replayed after a response status"
    );
}

#[test]
fn proxy_replays_idempotent_request_with_buffered_body() {
    let upstream = MockUpstream::start_sequence(vec![
        (502, json!({"attempt": 1})),
        (200, json!({"attempt": 2})),
    ])
    .expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&proxy_retry_config(
        &upstream.base_url(),
        "put.localhost",
        "502",
    ))
    .expect("proxy");
    let body = br#"{"sku":"abc","qty":2}"#.to_vec();

    let resp = proxy
        .put_bytes(
            "/inventory/abc",
            "put.localhost",
            "application/json",
            body.clone(),
            &[],
        )
        .expect("PUT");

    assert_eq!(resp.status, 200);
    assert_eq!(resp.json().expect("json")["attempt"], 2);
    let captured = upstream.captured();
    assert_eq!(captured.len(), 2, "PUT body should be replayable");
    assert!(captured
        .iter()
        .all(|req| req.method == "PUT" && req.path == "/inventory/abc" && req.body == body));
}

#[test]
fn proxy_skips_status_retry_when_request_body_exceeds_retry_buffer() {
    let upstream = MockUpstream::start_sequence(vec![
        (502, json!({"attempt": 1})),
        (200, json!({"attempt": 2})),
    ])
    .expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&proxy_retry_config(
        &upstream.base_url(),
        "large-put.localhost",
        "502",
    ))
    .expect("proxy");
    let body = vec![b'x'; 70 * 1024];

    let resp = proxy
        .put_bytes(
            "/inventory/bulk",
            "large-put.localhost",
            "application/octet-stream",
            body,
            &[],
        )
        .expect("PUT");

    assert_eq!(resp.status, 502);
    assert_eq!(
        resp.headers
            .get("x-sbproxy-retry-skip-reason")
            .map(String::as_str),
        Some("body_too_large")
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "oversized request body must not be replayed"
    );
}

#[test]
fn proxy_skips_status_retry_while_request_body_is_still_streaming() {
    let upstream = EarlyStatusUpstream::start(502).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&proxy_retry_config(
        &upstream.base_url(),
        "stream-put.localhost",
        "502",
    ))
    .expect("proxy");
    let request = b"PUT /stream HTTP/1.1\r\nHost: stream-put.localhost\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n5\r\nhello\r\n";

    let (status, raw) =
        send_raw_partial_request(proxy.port(), request).expect("partial PUT response");
    let response = String::from_utf8_lossy(&raw);

    assert_eq!(status, 502, "response was:\n{response}");
    assert!(
        response.contains("x-sbproxy-retry-skip-reason: streaming_body"),
        "streaming body skip reason missing from response:\n{response}"
    );
    assert_eq!(
        upstream.captured_len(),
        1,
        "still-streaming request body must not be replayed"
    );
}

#[test]
fn load_balancer_retries_configured_status_on_next_target() {
    let failing = MockUpstream::start_with_status(json!({"target": "failing"}), 502)
        .expect("failing upstream");
    let healthy = MockUpstream::start(json!({"target": "healthy"})).expect("healthy upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "lb-retry.localhost":
    action:
      type: load_balancer
      algorithm: round_robin
      targets:
        - url: "{}"
          weight: 1
        - url: "{}"
          weight: 1
      retry:
        max_attempts: 2
        retry_on: [502]
        backoff_ms: 0
"#,
        failing.base_url(),
        healthy.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("proxy");

    let resp = proxy.get("/", "lb-retry.localhost").expect("GET");

    assert_eq!(resp.status, 200);
    assert_eq!(resp.json().expect("json")["target"], "healthy");
    assert_eq!(failing.captured().len(), 1);
    assert_eq!(healthy.captured().len(), 1);
}
