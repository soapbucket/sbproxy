//! Outbound URL policy contracts: private opt-in, address pinning,
//! redirect refusal, the response byte cap, and non-secret errors.

use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use sbproxy_rag::http::{
    bounded_json, build_provider_client, build_provider_client_with_resolved, ProviderHttpError,
};
use sbproxy_rag::{EmbeddingError, RagBuildError};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// One-shot loopback fixture. Reads request headers, then answers with the
/// given status, optional `Location` header, and body.
async fn fixture_server(
    status: &'static str,
    location: Option<String>,
    body: Vec<u8>,
) -> (SocketAddr, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let was_hit = Arc::new(AtomicBool::new(false));
    let request_was_received = Arc::clone(&was_hit);

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0, "client closed before sending complete headers");
            request.extend_from_slice(&chunk[..count]);
            assert!(request.len() <= 16 * 1024, "fixture request is too large");
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        request_was_received.store(true, Ordering::SeqCst);

        let location_header = location
            .as_deref()
            .map(|location| format!("Location: {location}\r\n"))
            .unwrap_or_default();
        let head = format!(
            "HTTP/1.1 {status}\r\n{location_header}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        // The client may hang up early (for example once the byte cap
        // fires), so write errors are expected and ignored.
        let _ = stream.write_all(head.as_bytes()).await;
        let _ = stream.write_all(&body).await;
    });

    (address, was_hit)
}

#[tokio::test]
async fn private_endpoint_requires_explicit_opt_in() {
    let (fixture_addr, was_hit) = fixture_server("200 OK", None, b"{}".to_vec()).await;

    let denied = build_provider_client_with_resolved(
        "http://rag-fixture.invalid",
        false,
        Duration::from_secs(1),
        vec![fixture_addr],
    );
    assert!(matches!(denied, Err(RagBuildError::InvalidConfig(_))));
    assert!(!was_hit.load(Ordering::SeqCst));

    let client = build_provider_client_with_resolved(
        &format!("http://rag-fixture.invalid:{}", fixture_addr.port()),
        true,
        Duration::from_secs(1),
        vec![fixture_addr],
    )
    .unwrap();
    let response = client
        .get(format!(
            "http://rag-fixture.invalid:{}/health",
            fixture_addr.port()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(was_hit.load(Ordering::SeqCst));
}

#[tokio::test]
async fn public_resolution_rejects_any_private_answer() {
    // One public answer must not launder a private one past the policy.
    let error = build_provider_client_with_resolved(
        "http://rag-fixture.invalid",
        false,
        Duration::from_secs(1),
        vec![
            "93.184.216.34:80".parse().unwrap(),
            "10.0.0.1:80".parse().unwrap(),
        ],
    )
    .unwrap_err();
    assert!(matches!(error, RagBuildError::InvalidConfig(_)));

    // The live-resolution path rejects a private IP literal the same way.
    let error = build_provider_client("http://127.0.0.1:8090/v1", false, Duration::from_secs(1))
        .unwrap_err();
    assert!(matches!(error, RagBuildError::InvalidConfig(_)));
}

#[tokio::test]
async fn authenticated_client_does_not_follow_redirects() {
    // Following the redirect would forward the bearer token to the second server.
    let (second_addr, second_was_hit) = fixture_server("204 No Content", None, Vec::new()).await;
    let (first_addr, first_was_hit) = fixture_server(
        "302 Found",
        Some(format!("http://127.0.0.1:{}/next", second_addr.port())),
        Vec::new(),
    )
    .await;

    let client = build_provider_client_with_resolved(
        &format!("http://rag-fixture.invalid:{}", first_addr.port()),
        true,
        Duration::from_secs(2),
        vec![first_addr],
    )
    .unwrap();
    let response = client
        .get(format!(
            "http://rag-fixture.invalid:{}/embeddings",
            first_addr.port()
        ))
        .header("authorization", "Bearer fixture-key")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    assert!(first_was_hit.load(Ordering::SeqCst));
    assert!(!second_was_hit.load(Ordering::SeqCst));
}

#[tokio::test]
async fn bounded_json_stops_above_two_mebibytes() {
    let oversized = vec![b'a'; 2 * 1024 * 1024 + 1];
    let (big_addr, _) = fixture_server("200 OK", None, oversized).await;
    let client = build_provider_client_with_resolved(
        &format!("http://rag-fixture.invalid:{}", big_addr.port()),
        true,
        Duration::from_secs(5),
        vec![big_addr],
    )
    .unwrap();
    let response = client
        .get(format!(
            "http://rag-fixture.invalid:{}/big",
            big_addr.port()
        ))
        .send()
        .await
        .unwrap();
    let error = bounded_json(response).await.unwrap_err();
    assert_eq!(error, ProviderHttpError::ResponseTooLarge);

    // A small valid body under the cap still parses.
    let (small_addr, _) = fixture_server("200 OK", None, br#"{"ok":true}"#.to_vec()).await;
    let client = build_provider_client_with_resolved(
        &format!("http://rag-fixture.invalid:{}", small_addr.port()),
        true,
        Duration::from_secs(5),
        vec![small_addr],
    )
    .unwrap();
    let response = client
        .get(format!(
            "http://rag-fixture.invalid:{}/small",
            small_addr.port()
        ))
        .send()
        .await
        .unwrap();
    let value = bounded_json(response).await.unwrap();
    assert_eq!(value, serde_json::json!({"ok": true}));
}

#[tokio::test]
async fn provider_errors_do_not_include_credentials_or_body() {
    let (fixture_addr, _) = fixture_server(
        "500 Internal Server Error",
        None,
        br#"{"secret":"fixture-credential-value"}"#.to_vec(),
    )
    .await;
    let client = build_provider_client_with_resolved(
        &format!("http://rag-fixture.invalid:{}", fixture_addr.port()),
        true,
        Duration::from_secs(2),
        vec![fixture_addr],
    )
    .unwrap();
    let response = client
        .get(format!(
            "http://rag-fixture.invalid:{}/embeddings",
            fixture_addr.port()
        ))
        .header("authorization", "Bearer fixture-key")
        .send()
        .await
        .unwrap();

    let error = bounded_json(response).await.unwrap_err();
    assert_eq!(error, ProviderHttpError::HttpStatus(500));
    let rendered = format!("{error:?}");
    assert!(!rendered.contains("fixture-key"));
    assert!(!rendered.contains("fixture-credential-value"));
    assert!(!rendered.contains("rag-fixture.invalid"));

    let embedding_error: EmbeddingError = error.into();
    let rendered = format!("{embedding_error:?}");
    assert!(!rendered.contains("fixture-key"));
    assert!(!rendered.contains("fixture-credential-value"));
    assert!(!rendered.contains("rag-fixture.invalid"));
}
