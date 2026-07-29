use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use sbproxy_httpkit::{default_outbound, token_bearing_outbound};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn response_server(
    status: impl Into<String>,
    location: Option<String>,
) -> (String, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let was_hit = Arc::new(AtomicBool::new(false));
    let request_was_received = Arc::clone(&was_hit);
    let status = status.into();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 1024];
        stream.read(&mut request).await.unwrap();
        request_was_received.store(true, Ordering::SeqCst);

        let location_header = location
            .as_deref()
            .map(|location| format!("Location: {location}\r\n"))
            .unwrap_or_default();
        let response = format!(
            "HTTP/1.1 {status}\r\n{location_header}Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });

    (format!("http://{address}"), was_hit)
}

#[tokio::test]
async fn token_bearing_outbound_does_not_follow_redirects() {
    // A redirect policy that follows redirects would send the bearer token to the second server.
    let (second_url, second_was_hit) = response_server("204 No Content", None).await;
    let (first_url, _) = response_server("302 Found", Some(second_url)).await;

    let response = token_bearing_outbound()
        .get(first_url)
        .header("Authorization", "Bearer fixture-secret")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    assert!(!second_was_hit.load(Ordering::SeqCst));
}

#[tokio::test]
async fn default_outbound_follows_at_most_two_redirects() {
    // A policy with the wrong redirect limit would either reject the safe one-hop request or follow all three hops.
    let (success_target_url, success_target_was_hit) =
        response_server("204 No Content", None).await;
    let (success_source_url, _) = response_server("302 Found", Some(success_target_url)).await;

    let response = default_outbound()
        .get(success_source_url)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    assert!(success_target_was_hit.load(Ordering::SeqCst));

    let (fourth_url, fourth_was_hit) = response_server("204 No Content", None).await;
    let (third_url, third_was_hit) = response_server("302 Found", Some(fourth_url)).await;
    let (second_url, second_was_hit) = response_server("302 Found", Some(third_url)).await;
    let (first_url, _) = response_server("302 Found", Some(second_url)).await;

    let error = default_outbound().get(first_url).send().await.unwrap_err();

    assert!(error.is_redirect());
    assert!(second_was_hit.load(Ordering::SeqCst));
    assert!(third_was_hit.load(Ordering::SeqCst));
    assert!(!fourth_was_hit.load(Ordering::SeqCst));
}
