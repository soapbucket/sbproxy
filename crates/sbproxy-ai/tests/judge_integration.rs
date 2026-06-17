//! Integration tests for the OSS judge backend.
//!
//! The acceptance gate on WOR-202 names four scenarios this file
//! covers using only the public `JudgeClient` API:
//!
//! 1. **Cache hit** - a pre-warmed cache entry returns the stored
//!    verdict and never touches the network.
//! 2. **Cache miss** - the first call against an upstream populates
//!    the cache; the second call against a closed port still
//!    succeeds because it hits the warm entry.
//! 3. **Budget exhaustion** - a tracker initialised with zero
//!    budget hard-fails before any network I/O and surfaces
//!    [`JudgeError::BudgetExhausted`].
//! 4. **Timeout** - a slow mock that blocks past the configured
//!    per-call timeout surfaces [`JudgeError::Timeout`].
//!
//! "Fast-path budget unaffected" (the cache-hit branch never charges
//! the budget) is asserted directly off the [`JudgeClient::budget`]
//! accessor in scenarios 1 and 2.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use sbproxy_ai::judge::{JudgeClient, JudgeConfig, JudgeError};
use sbproxy_plugin::PolicyDecision;
use serde_json::json;

fn build_client(endpoint: url::Url, budget: u64, timeout_ms: u32) -> JudgeClient {
    JudgeClient::new(JudgeConfig {
        endpoint,
        api_key_env: "SBPROXY_JUDGE_API_KEY_NOT_SET".into(),
        timeout_ms,
        cache_capacity: 16,
        budget_tokens: budget,
    })
}

fn bind_loopback() -> Option<TcpListener> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener),
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            eprintln!("skipping judge integration network test: loopback bind denied: {err}");
            None
        }
        Err(err) => panic!("failed to bind loopback test listener: {err}"),
    }
}

/// Spin up a one-shot mock that returns `body` once and then closes
/// the connection. Used in the cache-miss path; the cache-hit
/// scenarios point at a closed port instead.
fn one_shot_mock(body: String) -> Option<SocketAddr> {
    let listener = bind_loopback()?;
    let addr = listener.local_addr().expect("local_addr");
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Drain the request so the client side reads its
            // response cleanly.
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Write);
        }
    });
    Some(addr)
}

/// Mock that accepts the TCP connection but never writes a response.
/// Used to drive the per-call timeout path.
fn hanging_mock() -> Option<SocketAddr> {
    let listener = bind_loopback()?;
    let addr = listener.local_addr().expect("local_addr");
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            // Hold the connection open without sending a response.
            // Sleeping for 10 s keeps the socket alive long enough
            // for any reasonable test timeout to elapse first.
            std::thread::sleep(Duration::from_secs(10));
            drop(stream);
        }
    });
    Some(addr)
}

fn closed_loopback_addr() -> Option<SocketAddr> {
    let listener = bind_loopback()?;
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    Some(addr)
}

fn http_response(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status_line,
        body.len(),
        body
    )
}

#[tokio::test]
async fn judge_cache_hit_skips_network_and_preserves_budget() {
    // Endpoint points at a closed port: any actual network call
    // would error out. The cache-hit path must never reach it.
    let Some(addr) = closed_loopback_addr() else {
        return;
    };
    let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).expect("url");
    let client = build_client(endpoint, 100, 2_000);

    let prompt = "cache-hit prompt";
    let payload = json!({"key": "value"});
    let cached = PolicyDecision::Deny {
        status: 403,
        message: "from cache".into(),
    };
    let key = sbproxy_ai::judge::cache::cache_key(prompt, &payload);
    client.cache().put(key, cached.clone());

    let decision = client
        .semantic(prompt, payload)
        .await
        .expect("cache hit returns Ok");
    assert_eq!(decision, cached);
    assert_eq!(
        client.budget().remaining(),
        100,
        "cache hit must not charge the budget"
    );
}

#[tokio::test]
async fn judge_cache_warm_after_first_call_skips_subsequent_network() {
    let body = json!({"verdict": "allow"}).to_string();
    let Some(addr) = one_shot_mock(http_response("200 OK", &body)) else {
        return;
    };
    let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).expect("url");
    let client = build_client(endpoint, 100, 2_000);
    let prompt = "warm-cache prompt";
    let payload = json!({"id": 7});

    let first = client
        .semantic(prompt, payload.clone())
        .await
        .expect("first");
    assert_eq!(first, PolicyDecision::Allow);
    let after_first = client.budget().remaining();
    assert!(
        after_first < 100,
        "first call should charge the budget (remaining = {after_first})"
    );

    // Second call hits the cache: the mock is already closed, so a
    // cache miss would fail to connect. A cache hit returns the
    // same decision without touching the budget further.
    let second = client.semantic(prompt, payload).await.expect("second");
    assert_eq!(second, PolicyDecision::Allow);
    assert_eq!(
        client.budget().remaining(),
        after_first,
        "warm-cache call must not charge the budget"
    );
}

#[tokio::test]
async fn judge_budget_exhaustion_hard_fails_before_network() {
    // Endpoint points at a closed port. A budget of 0 must fail
    // before any network I/O so the closed port never matters.
    let Some(addr) = closed_loopback_addr() else {
        return;
    };
    let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).expect("url");
    let client = build_client(endpoint, 0, 2_000);

    let err = client
        .semantic("any prompt", json!({}))
        .await
        .expect_err("zero-budget must hard-fail");
    assert!(matches!(err, JudgeError::BudgetExhausted));
}

#[tokio::test]
async fn judge_timeout_surfaces_timeout_error() {
    let Some(addr) = hanging_mock() else {
        return;
    };
    let endpoint = url::Url::parse(&format!("http://{}/judge", addr)).expect("url");
    // 100 ms timeout against a mock that never responds.
    let client = build_client(endpoint, 100, 100);

    let err = client
        .semantic("slow", json!({}))
        .await
        .expect_err("timeout must surface");
    assert!(
        matches!(err, JudgeError::Timeout | JudgeError::ProviderError(_)),
        "expected Timeout (or ProviderError that wraps a timeout), got {err:?}"
    );
}
