// WOR-170 regression test: the OAuth `/token` outbound path must use
// the hardened token-bearing client. A malicious upstream that returns
// `302 Location: https://attacker.example/` must NOT be followed,
// because doing so would forward the `Authorization` header to a
// different origin.
//
// The production `/token` handler (`src/token.rs`) constructs its
// `reqwest::Client` via `sbproxy_httpkit::token_bearing_outbound()`.
// This test exercises that constructor against a TCP listener that
// returns a 302 to a second listener; the second listener must never
// receive the request.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use sbproxy_httpkit::token_bearing_outbound;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn bind_loopback() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    (listener, format!("http://{addr}/"))
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let mut total = 0usize;
    while total < buf.len() {
        match stream.read(&mut buf[total..]).await {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    buf.truncate(total);
    buf
}

/// The hardened `/token` client refuses to follow a 302 to a different
/// host, so the Authorization header cannot leak to the redirected
/// origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_path_refuses_cross_host_redirect() {
    // --- Second hop (attacker origin). Should NEVER be reached. ---
    let (attacker, attacker_url) = bind_loopback().await;
    let leaked = Arc::new(AtomicBool::new(false));
    let leaked_clone = leaked.clone();
    let attacker_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = attacker.accept().await {
            let req = read_request(&mut stream).await;
            // Any inbound request is a leak. If the Authorization header
            // also appears, the redirect rewrote credentials too.
            leaked_clone.store(true, Ordering::SeqCst);
            let _ = req;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });

    // --- First hop (compromised upstream Authorization Server). ---
    let (upstream, upstream_url) = bind_loopback().await;
    let upstream_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = upstream.accept().await {
            let _ = read_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {attacker_url}\r\nContent-Length: 0\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    // Mirror the production /token wiring: the handler builds its
    // reqwest::Client via this exact constructor.
    let http = token_bearing_outbound();
    let resp = http
        .post(&upstream_url)
        .header("Authorization", "Bearer this-must-not-leak")
        .form(&[("grant_type", "authorization_code"), ("code", "abc123")])
        .send()
        .await;

    match resp {
        Ok(r) => assert_eq!(
            r.status().as_u16(),
            302,
            "the hardened client must surface the 302 to its caller, not follow it"
        ),
        Err(e) => panic!("unexpected transport error: {e}"),
    }

    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), attacker_task).await;
    upstream_task.abort();

    assert!(
        !leaked.load(Ordering::SeqCst),
        "/token path leaked Authorization header to the redirect target",
    );
}
