//! Wire and parser contracts for the HTTP vector-store adapters.
//!
//! One loopback fixture captures the exact request each adapter sends
//! and answers with a scripted response, so every assertion here pins
//! the documented provider contract: paths, auth headers, filter
//! shapes, tenant isolation, cosine normalization, and the shared
//! transport policy (non-2xx, malformed JSON, the byte cap, and
//! redirect refusal).

#![cfg(any(
    feature = "vector-chroma",
    feature = "vector-pinecone",
    feature = "vector-qdrant",
    feature = "vector-weaviate"
))]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sbproxy_ai::rag_config::RagVectorStoreConfig;
use sbproxy_rag::{RagBuildMode, RetrievedChunk, VectorQuery, VectorStore, VectorStoreError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The tenant fixture that must stay a data value in every request.
const HOSTILE_TENANT: &str = "tenant-a\"} OR *";

/// One captured HTTP request: the raw head and the body bytes.
struct CapturedRequest {
    head: String,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn path(&self) -> &str {
        self.head
            .split_whitespace()
            .nth(1)
            .expect("request line has a path")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("captured body is json")
    }
}

/// One-shot loopback fixture. Captures the full request, then answers
/// with the given status, optional `Location` header, and body.
async fn fixture_server(
    status: &'static str,
    location: Option<String>,
    response_body: Vec<u8>,
) -> (
    SocketAddr,
    Arc<Mutex<Option<CapturedRequest>>>,
    Arc<AtomicBool>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(None));
    let was_hit = Arc::new(AtomicBool::new(false));
    let captured_task = Arc::clone(&captured);
    let hit_task = Arc::clone(&was_hit);

    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        hit_task.store(true, Ordering::SeqCst);
        let mut request = Vec::new();
        let header_end = loop {
            let mut chunk = [0u8; 4096];
            let Ok(count) = stream.read(&mut chunk).await else {
                return;
            };
            if count == 0 {
                return;
            }
            request.extend_from_slice(&chunk[..count]);
            assert!(request.len() <= 64 * 1024, "fixture request is too large");
            if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let head = String::from_utf8_lossy(&request[..header_end]).into_owned();
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let mut chunk = [0u8; 4096];
            let Ok(count) = stream.read(&mut chunk).await else {
                return;
            };
            if count == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..count]);
        }
        let body = request[header_end..].to_vec();
        *captured_task.lock().unwrap() = Some(CapturedRequest { head, body });

        let location_header = location
            .as_deref()
            .map(|location| format!("Location: {location}\r\n"))
            .unwrap_or_default();
        let response_head = format!(
            "HTTP/1.1 {status}\r\n{location_header}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        // The client may hang up early (for example once the byte cap
        // fires), so write errors are expected and ignored.
        let _ = stream.write_all(response_head.as_bytes()).await;
        let _ = stream.write_all(&response_body).await;
    });

    (address, captured, was_hit)
}

fn fixture_embedding() -> Vec<f32> {
    vec![0.1, 0.2]
}

fn store_config(provider: &str, port: u16) -> RagVectorStoreConfig {
    let base = format!("http://127.0.0.1:{port}");
    let value = match provider {
        "chroma" => serde_json::json!({
            "provider": "chroma",
            "base_url": base,
            "collection_id": "docs",
            "api_key": "fixture-key",
            "allow_private_url": true
        }),
        "pinecone" => serde_json::json!({
            "provider": "pinecone",
            "host": base,
            "api_key": "fixture-key",
            "allow_private_url": true
        }),
        "qdrant" => serde_json::json!({
            "provider": "qdrant",
            "base_url": base,
            "collection": "docs",
            "api_key": "fixture-key",
            "allow_private_url": true
        }),
        "weaviate" => serde_json::json!({
            "provider": "weaviate",
            "base_url": base,
            "collection": "SupportDoc",
            "api_key": "fixture-key",
            "allow_private_url": true
        }),
        _ => unreachable!("unknown provider fixture"),
    };
    serde_json::from_value(value).expect("store fixture config parses")
}

fn build_store(provider: &str, port: u16) -> Arc<dyn VectorStore> {
    sbproxy_rag::vector::build(
        &store_config(provider, port),
        Duration::from_secs(5),
        RagBuildMode::Runtime,
    )
    .expect("store builds")
}

/// Runs one search against a scripted response and returns the result
/// plus the captured request.
async fn run_search_capture(
    provider: &str,
    status: &'static str,
    response_body: Vec<u8>,
    tenant: &str,
    with_static: bool,
) -> (
    Result<Vec<RetrievedChunk>, VectorStoreError>,
    Arc<Mutex<Option<CapturedRequest>>>,
) {
    let (address, captured, _was_hit) = fixture_server(status, None, response_body).await;
    let store = build_store(provider, address.port());
    let statics = if with_static {
        BTreeMap::from([("kind".to_owned(), "policy".to_owned())])
    } else {
        BTreeMap::new()
    };
    let embedding = fixture_embedding();
    let result = store
        .search(VectorQuery {
            embedding: &embedding,
            tenant_id: tenant,
            tenant_field: "tenant_id",
            static_equals: &statics,
            top_k: 5,
        })
        .await;
    (result, captured)
}

async fn run_search(
    provider: &str,
    status: &'static str,
    response_body: Vec<u8>,
) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
    run_search_capture(provider, status, response_body, "tenant-a", true)
        .await
        .0
}

/// Counts occurrences of `needle` as a string value or object key.
fn count_string(value: &serde_json::Value, needle: &str) -> usize {
    match value {
        serde_json::Value::String(text) => usize::from(text == needle),
        serde_json::Value::Array(items) => {
            items.iter().map(|item| count_string(item, needle)).sum()
        }
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(key, item)| usize::from(key == needle) + count_string(item, needle))
            .sum(),
        _ => 0,
    }
}

/// Asserts the shared transport policy: non-2xx, malformed JSON, and
/// the 2 MiB response cap.
async fn assert_transport_contract(provider: &str) {
    let error = run_search(provider, "500 Internal Server Error", b"{}".to_vec())
        .await
        .unwrap_err();
    assert_eq!(error, VectorStoreError::HttpStatus(500));

    let error = run_search(provider, "200 OK", b"not-json".to_vec())
        .await
        .unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));

    let oversized = vec![b'a'; 2 * 1024 * 1024 + 1];
    let error = run_search(provider, "200 OK", oversized).await.unwrap_err();
    assert_eq!(error, VectorStoreError::ResponseTooLarge);
}

/// Asserts a redirect to a second host is refused and the second host
/// is never contacted.
async fn assert_redirect_not_followed(provider: &str) {
    let (second_address, _second_captured, second_was_hit) =
        fixture_server("200 OK", None, b"{}".to_vec()).await;
    let (address, _captured, _was_hit) = fixture_server(
        "302 Found",
        Some(format!("http://127.0.0.1:{}/next", second_address.port())),
        Vec::new(),
    )
    .await;
    let store = build_store(provider, address.port());
    let statics = BTreeMap::new();
    let embedding = fixture_embedding();
    let error = store
        .search(VectorQuery {
            embedding: &embedding,
            tenant_id: "tenant-a",
            tenant_field: "tenant_id",
            static_equals: &statics,
            top_k: 5,
        })
        .await
        .unwrap_err();
    assert_eq!(error, VectorStoreError::HttpStatus(302));
    assert!(!second_was_hit.load(Ordering::SeqCst));
}

#[cfg(any(
    feature = "vector-chroma",
    feature = "vector-pinecone",
    feature = "vector-weaviate"
))]
fn assert_valid_chunk(chunks: &[RetrievedChunk]) {
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].source_id, "doc-1");
    assert_eq!(chunks[0].content, "Refund policy text.");
    assert!((chunks[0].score - 0.8).abs() < 1e-6, "unexpected score");
}

// --- Chroma ---

#[cfg(feature = "vector-chroma")]
fn chroma_body(
    ids: serde_json::Value,
    documents: serde_json::Value,
    distances: serde_json::Value,
) -> Vec<u8> {
    serde_json::json!({
        "ids": ids,
        "documents": documents,
        "distances": distances,
        "metadatas": [[{}]]
    })
    .to_string()
    .into_bytes()
}

#[cfg(feature = "vector-chroma")]
fn chroma_valid_body() -> Vec<u8> {
    chroma_body(
        serde_json::json!([["doc-1"]]),
        serde_json::json!([["Refund policy text."]]),
        serde_json::json!([[0.4]]),
    )
}

#[cfg(feature = "vector-chroma")]
#[tokio::test]
async fn chroma_sends_the_documented_wire_contract() {
    let (result, captured) =
        run_search_capture("chroma", "200 OK", chroma_valid_body(), "tenant-a", true).await;
    result.unwrap();
    let captured = captured.lock().unwrap();
    let request = captured.as_ref().expect("request was captured");
    assert_eq!(
        request.path(),
        "/api/v2/tenants/default_tenant/databases/default_database/collections/docs/query"
    );
    assert_eq!(request.header("x-chroma-token"), Some("fixture-key"));
    assert_eq!(
        request.json(),
        serde_json::json!({
            "query_embeddings": [fixture_embedding()],
            "n_results": 5,
            "where": {"$and": [
                {"tenant_id": {"$eq": "tenant-a"}},
                {"kind": {"$eq": "policy"}}
            ]},
            "include": ["documents", "distances", "metadatas"]
        })
    );
}

#[cfg(feature = "vector-chroma")]
#[tokio::test]
async fn chroma_parses_a_valid_result() {
    let chunks = run_search("chroma", "200 OK", chroma_valid_body())
        .await
        .unwrap();
    assert_valid_chunk(&chunks);
}

#[cfg(feature = "vector-chroma")]
#[tokio::test]
async fn chroma_rejects_missing_content() {
    let body = chroma_body(
        serde_json::json!([["doc-1"]]),
        serde_json::json!([[null]]),
        serde_json::json!([[0.4]]),
    );
    let error = run_search("chroma", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-chroma")]
#[tokio::test]
async fn chroma_rejects_missing_source_id() {
    let body = chroma_body(
        serde_json::json!([[null]]),
        serde_json::json!([["Refund policy text."]]),
        serde_json::json!([[0.4]]),
    );
    let error = run_search("chroma", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-chroma")]
#[tokio::test]
async fn chroma_rejects_misaligned_columns() {
    let body = chroma_body(
        serde_json::json!([["doc-1", "doc-2"]]),
        serde_json::json!([["Refund policy text."]]),
        serde_json::json!([[0.4, 0.5]]),
    );
    let error = run_search("chroma", "200 OK", body).await.unwrap_err();
    assert_eq!(
        error,
        VectorStoreError::MalformedResponse("chroma response columns are misaligned")
    );
}

#[cfg(feature = "vector-chroma")]
#[tokio::test]
async fn chroma_rejects_missing_or_unrepresentable_scores() {
    let body = chroma_body(
        serde_json::json!([["doc-1"]]),
        serde_json::json!([["Refund policy text."]]),
        serde_json::json!([[null]]),
    );
    let error = run_search("chroma", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));

    // JSON cannot carry NaN and serde_json decodes an overflowing float
    // literal as null, so a non-finite wire score always surfaces as a
    // malformed response here; the reachable NonFiniteScore path is
    // covered by the Redis contract, where distances arrive as text.
    let body =
        br#"{"ids":[["doc-1"]],"documents":[["Refund policy text."]],"distances":[[1e309]],"metadatas":[[{}]]}"#
            .to_vec();
    let error = run_search("chroma", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-chroma")]
#[tokio::test]
async fn chroma_rejects_out_of_range_distances() {
    for distance in [2.5, -0.5] {
        let body = chroma_body(
            serde_json::json!([["doc-1"]]),
            serde_json::json!([["Refund policy text."]]),
            serde_json::json!([[distance]]),
        );
        let error = run_search("chroma", "200 OK", body).await.unwrap_err();
        assert_eq!(
            error,
            VectorStoreError::MalformedResponse(
                "cosine distance outside the documented 0.0..=2.0 range"
            )
        );
    }
}

#[cfg(feature = "vector-chroma")]
#[tokio::test]
async fn chroma_rejects_transport_violations() {
    assert_transport_contract("chroma").await;
}

#[cfg(feature = "vector-chroma")]
#[tokio::test]
async fn chroma_does_not_follow_redirects() {
    assert_redirect_not_followed("chroma").await;
}

#[cfg(feature = "vector-chroma")]
#[tokio::test]
async fn chroma_tenant_stays_a_filter_value() {
    let (result, captured) = run_search_capture(
        "chroma",
        "200 OK",
        chroma_valid_body(),
        HOSTILE_TENANT,
        false,
    )
    .await;
    result.unwrap();
    let captured = captured.lock().unwrap();
    let body = captured.as_ref().expect("request was captured").json();
    // Full-body equality proves the request has exactly the documented
    // fields, so no caller-supplied field can override the tenant.
    assert_eq!(
        body,
        serde_json::json!({
            "query_embeddings": [fixture_embedding()],
            "n_results": 5,
            "where": {"tenant_id": {"$eq": HOSTILE_TENANT}},
            "include": ["documents", "distances", "metadatas"]
        })
    );
    assert_eq!(count_string(&body, HOSTILE_TENANT), 1);
}

// --- Pinecone ---

#[cfg(feature = "vector-pinecone")]
fn pinecone_body(matches: serde_json::Value) -> Vec<u8> {
    serde_json::json!({ "matches": matches })
        .to_string()
        .into_bytes()
}

#[cfg(feature = "vector-pinecone")]
fn pinecone_valid_body() -> Vec<u8> {
    pinecone_body(serde_json::json!([
        {"id": "doc-1", "score": 0.6, "metadata": {"content": "Refund policy text."}}
    ]))
}

#[cfg(feature = "vector-pinecone")]
#[tokio::test]
async fn pinecone_sends_the_documented_wire_contract() {
    let (result, captured) = run_search_capture(
        "pinecone",
        "200 OK",
        pinecone_valid_body(),
        "tenant-a",
        true,
    )
    .await;
    result.unwrap();
    let captured = captured.lock().unwrap();
    let request = captured.as_ref().expect("request was captured");
    assert_eq!(request.path(), "/query");
    assert_eq!(request.header("Api-Key"), Some("fixture-key"));
    assert_eq!(request.header("X-Pinecone-Api-Version"), Some("2026-04"));
    assert_eq!(
        request.json(),
        serde_json::json!({
            "vector": fixture_embedding(),
            "topK": 5,
            "includeValues": false,
            "includeMetadata": true,
            "filter": {
                "tenant_id": {"$eq": "tenant-a"},
                "kind": {"$eq": "policy"}
            }
        })
    );
}

#[cfg(feature = "vector-pinecone")]
#[tokio::test]
async fn pinecone_sends_namespace_only_when_configured() {
    let (address, captured, _was_hit) = fixture_server("200 OK", None, pinecone_valid_body()).await;
    let config: RagVectorStoreConfig = serde_json::from_value(serde_json::json!({
        "provider": "pinecone",
        "host": format!("http://127.0.0.1:{}", address.port()),
        "api_key": "fixture-key",
        "namespace": "prod",
        "allow_private_url": true
    }))
    .unwrap();
    let store =
        sbproxy_rag::vector::build(&config, Duration::from_secs(5), RagBuildMode::Runtime).unwrap();
    let statics = BTreeMap::new();
    let embedding = fixture_embedding();
    store
        .search(VectorQuery {
            embedding: &embedding,
            tenant_id: "tenant-a",
            tenant_field: "tenant_id",
            static_equals: &statics,
            top_k: 5,
        })
        .await
        .unwrap();
    let captured = captured.lock().unwrap();
    let body = captured.as_ref().expect("request was captured").json();
    assert_eq!(body["namespace"], serde_json::json!("prod"));
}

#[cfg(feature = "vector-pinecone")]
#[tokio::test]
async fn pinecone_parses_a_valid_result() {
    let chunks = run_search("pinecone", "200 OK", pinecone_valid_body())
        .await
        .unwrap();
    assert_valid_chunk(&chunks);
}

#[cfg(feature = "vector-pinecone")]
#[tokio::test]
async fn pinecone_rejects_missing_content() {
    let body = pinecone_body(serde_json::json!([{"id": "doc-1", "score": 0.6, "metadata": {}}]));
    let error = run_search("pinecone", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-pinecone")]
#[tokio::test]
async fn pinecone_rejects_missing_source_id() {
    let body = pinecone_body(serde_json::json!([
        {"score": 0.6, "metadata": {"content": "Refund policy text."}}
    ]));
    let error = run_search("pinecone", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-pinecone")]
#[tokio::test]
async fn pinecone_rejects_missing_or_unrepresentable_scores() {
    let body = pinecone_body(serde_json::json!([
        {"id": "doc-1", "metadata": {"content": "Refund policy text."}}
    ]));
    let error = run_search("pinecone", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));

    // See the Chroma note: an overflowing float literal decodes as null,
    // so the non-finite wire case surfaces as a malformed response.
    let body =
        br#"{"matches":[{"id":"doc-1","score":1e309,"metadata":{"content":"Refund policy text."}}]}"#
            .to_vec();
    let error = run_search("pinecone", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-pinecone")]
#[tokio::test]
async fn pinecone_rejects_out_of_range_similarities() {
    for similarity in [1.5, -1.5] {
        let body = pinecone_body(serde_json::json!([
            {"id": "doc-1", "score": similarity, "metadata": {"content": "Refund policy text."}}
        ]));
        let error = run_search("pinecone", "200 OK", body).await.unwrap_err();
        assert_eq!(
            error,
            VectorStoreError::MalformedResponse(
                "cosine similarity outside the documented -1.0..=1.0 range"
            )
        );
    }
}

#[cfg(feature = "vector-pinecone")]
#[tokio::test]
async fn pinecone_rejects_transport_violations() {
    assert_transport_contract("pinecone").await;
}

#[cfg(feature = "vector-pinecone")]
#[tokio::test]
async fn pinecone_does_not_follow_redirects() {
    assert_redirect_not_followed("pinecone").await;
}

#[cfg(feature = "vector-pinecone")]
#[tokio::test]
async fn pinecone_tenant_stays_a_filter_value() {
    let (result, captured) = run_search_capture(
        "pinecone",
        "200 OK",
        pinecone_valid_body(),
        HOSTILE_TENANT,
        false,
    )
    .await;
    result.unwrap();
    let captured = captured.lock().unwrap();
    let body = captured.as_ref().expect("request was captured").json();
    assert_eq!(
        body,
        serde_json::json!({
            "vector": fixture_embedding(),
            "topK": 5,
            "includeValues": false,
            "includeMetadata": true,
            "filter": {"tenant_id": {"$eq": HOSTILE_TENANT}}
        })
    );
    assert_eq!(count_string(&body, HOSTILE_TENANT), 1);
}

#[cfg(feature = "vector-pinecone")]
#[tokio::test]
async fn pinecone_rejects_static_filter_colliding_with_tenant_field() {
    let (address, _captured, was_hit) = fixture_server("200 OK", None, pinecone_valid_body()).await;
    let store = build_store("pinecone", address.port());
    let statics = BTreeMap::from([("tenant_id".to_owned(), "tenant-b".to_owned())]);
    let embedding = fixture_embedding();
    let error = store
        .search(VectorQuery {
            embedding: &embedding,
            tenant_id: "tenant-a",
            tenant_field: "tenant_id",
            static_equals: &statics,
            top_k: 5,
        })
        .await
        .unwrap_err();
    assert_eq!(
        error,
        VectorStoreError::MalformedResponse("static filter conflicts with the tenant filter field")
    );
    assert!(!was_hit.load(Ordering::SeqCst));
}

// --- Qdrant ---

#[cfg(feature = "vector-qdrant")]
fn qdrant_body(points: serde_json::Value) -> Vec<u8> {
    serde_json::json!({ "result": { "points": points } })
        .to_string()
        .into_bytes()
}

#[cfg(feature = "vector-qdrant")]
fn qdrant_valid_body() -> Vec<u8> {
    qdrant_body(serde_json::json!([
        {"id": 7, "score": 0.6, "payload": {"content": "Refund policy text."}}
    ]))
}

#[cfg(feature = "vector-qdrant")]
#[tokio::test]
async fn qdrant_sends_the_documented_wire_contract() {
    let (result, captured) =
        run_search_capture("qdrant", "200 OK", qdrant_valid_body(), "tenant-a", true).await;
    result.unwrap();
    let captured = captured.lock().unwrap();
    let request = captured.as_ref().expect("request was captured");
    assert_eq!(request.path(), "/collections/docs/points/query");
    assert_eq!(request.header("api-key"), Some("fixture-key"));
    assert_eq!(
        request.json(),
        serde_json::json!({
            "query": fixture_embedding(),
            "limit": 5,
            "with_vector": false,
            "with_payload": true,
            "filter": {"must": [
                {"key": "tenant_id", "match": {"value": "tenant-a"}},
                {"key": "kind", "match": {"value": "policy"}}
            ]}
        })
    );
}

#[cfg(feature = "vector-qdrant")]
#[tokio::test]
async fn qdrant_parses_valid_numeric_and_string_ids() {
    let body = qdrant_body(serde_json::json!([
        {"id": 7, "score": 0.6, "payload": {"content": "Refund policy text."}},
        {"id": "doc-2", "score": 0.0, "payload": {"content": "Second chunk."}}
    ]));
    let chunks = run_search("qdrant", "200 OK", body).await.unwrap();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].source_id, "7");
    assert_eq!(chunks[0].content, "Refund policy text.");
    assert!((chunks[0].score - 0.8).abs() < 1e-6);
    assert_eq!(chunks[1].source_id, "doc-2");
    assert!((chunks[1].score - 0.5).abs() < 1e-6);
}

#[cfg(feature = "vector-qdrant")]
#[tokio::test]
async fn qdrant_rejects_missing_content() {
    let body = qdrant_body(serde_json::json!([{"id": 7, "score": 0.6, "payload": {}}]));
    let error = run_search("qdrant", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-qdrant")]
#[tokio::test]
async fn qdrant_rejects_missing_source_id() {
    let body = qdrant_body(serde_json::json!([
        {"score": 0.6, "payload": {"content": "Refund policy text."}}
    ]));
    let error = run_search("qdrant", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-qdrant")]
#[tokio::test]
async fn qdrant_rejects_missing_or_unrepresentable_scores() {
    let body = qdrant_body(serde_json::json!([
        {"id": 7, "payload": {"content": "Refund policy text."}}
    ]));
    let error = run_search("qdrant", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));

    // See the Chroma note: an overflowing float literal decodes as null,
    // so the non-finite wire case surfaces as a malformed response.
    let body =
        br#"{"result":{"points":[{"id":7,"score":1e309,"payload":{"content":"Refund policy text."}}]}}"#
            .to_vec();
    let error = run_search("qdrant", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-qdrant")]
#[tokio::test]
async fn qdrant_rejects_out_of_range_similarities() {
    for similarity in [1.5, -1.5] {
        let body = qdrant_body(serde_json::json!([
            {"id": 7, "score": similarity, "payload": {"content": "Refund policy text."}}
        ]));
        let error = run_search("qdrant", "200 OK", body).await.unwrap_err();
        assert_eq!(
            error,
            VectorStoreError::MalformedResponse(
                "cosine similarity outside the documented -1.0..=1.0 range"
            )
        );
    }
}

#[cfg(feature = "vector-qdrant")]
#[tokio::test]
async fn qdrant_rejects_transport_violations() {
    assert_transport_contract("qdrant").await;
}

#[cfg(feature = "vector-qdrant")]
#[tokio::test]
async fn qdrant_does_not_follow_redirects() {
    assert_redirect_not_followed("qdrant").await;
}

#[cfg(feature = "vector-qdrant")]
#[tokio::test]
async fn qdrant_tenant_stays_a_filter_value() {
    let (result, captured) = run_search_capture(
        "qdrant",
        "200 OK",
        qdrant_valid_body(),
        HOSTILE_TENANT,
        false,
    )
    .await;
    result.unwrap();
    let captured = captured.lock().unwrap();
    let body = captured.as_ref().expect("request was captured").json();
    assert_eq!(
        body,
        serde_json::json!({
            "query": fixture_embedding(),
            "limit": 5,
            "with_vector": false,
            "with_payload": true,
            "filter": {"must": [
                {"key": "tenant_id", "match": {"value": HOSTILE_TENANT}}
            ]}
        })
    );
    assert_eq!(count_string(&body, HOSTILE_TENANT), 1);
}

// --- Weaviate ---

/// The plan's contract query for collection `SupportDoc` and content
/// property `content`, compared after whitespace normalization.
#[cfg(feature = "vector-weaviate")]
const WEAVIATE_FIXTURE_QUERY: &str = "query RagSearch($vector: [Float!]!, $tenant: String!, $kind: String!) { Get { SupportDoc(nearVector: { vector: $vector }, limit: 5, where: { operator: And, operands: [{ path: [\"tenant_id\"], operator: Equal, valueText: $tenant }, { path: [\"kind\"], operator: Equal, valueText: $kind }] }) { content _additional { id certainty } } } }";

/// The same query with only the tenant operand.
#[cfg(feature = "vector-weaviate")]
const WEAVIATE_TENANT_ONLY_QUERY: &str = "query RagSearch($vector: [Float!]!, $tenant: String!) { Get { SupportDoc(nearVector: { vector: $vector }, limit: 5, where: { operator: And, operands: [{ path: [\"tenant_id\"], operator: Equal, valueText: $tenant }] }) { content _additional { id certainty } } } }";

#[cfg(feature = "vector-weaviate")]
fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(feature = "vector-weaviate")]
fn weaviate_body(rows: serde_json::Value) -> Vec<u8> {
    serde_json::json!({ "data": { "Get": { "SupportDoc": rows } } })
        .to_string()
        .into_bytes()
}

#[cfg(feature = "vector-weaviate")]
fn weaviate_valid_row() -> serde_json::Value {
    serde_json::json!({
        "content": "Refund policy text.",
        "_additional": {"id": "doc-1", "certainty": 0.8}
    })
}

#[cfg(feature = "vector-weaviate")]
#[tokio::test]
async fn weaviate_sends_the_documented_wire_contract() {
    let (result, captured) = run_search_capture(
        "weaviate",
        "200 OK",
        weaviate_body(serde_json::json!([weaviate_valid_row()])),
        "tenant-a",
        true,
    )
    .await;
    result.unwrap();
    let captured = captured.lock().unwrap();
    let request = captured.as_ref().expect("request was captured");
    assert_eq!(request.path(), "/v1/graphql");
    assert_eq!(request.header("authorization"), Some("Bearer fixture-key"));
    let body = request.json();
    let query = body["query"].as_str().expect("query is a string");
    assert_eq!(
        normalize_whitespace(query),
        normalize_whitespace(WEAVIATE_FIXTURE_QUERY)
    );
    assert_eq!(
        body["variables"],
        serde_json::json!({
            "vector": fixture_embedding(),
            "tenant": "tenant-a",
            "kind": "policy"
        })
    );
}

#[cfg(feature = "vector-weaviate")]
#[tokio::test]
async fn weaviate_parses_a_valid_result() {
    let chunks = run_search(
        "weaviate",
        "200 OK",
        weaviate_body(serde_json::json!([weaviate_valid_row()])),
    )
    .await
    .unwrap();
    assert_valid_chunk(&chunks);
}

#[cfg(feature = "vector-weaviate")]
#[tokio::test]
async fn weaviate_rejects_graphql_errors_beside_data() {
    let body = serde_json::json!({
        "errors": [{"message": "boom"}],
        "data": {"Get": {"SupportDoc": [weaviate_valid_row()]}}
    })
    .to_string()
    .into_bytes();
    let error = run_search("weaviate", "200 OK", body).await.unwrap_err();
    assert_eq!(
        error,
        VectorStoreError::MalformedResponse("weaviate returned graphql errors")
    );
}

#[cfg(feature = "vector-weaviate")]
#[tokio::test]
async fn weaviate_rejects_missing_content() {
    let body = weaviate_body(serde_json::json!([
        {"_additional": {"id": "doc-1", "certainty": 0.8}}
    ]));
    let error = run_search("weaviate", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-weaviate")]
#[tokio::test]
async fn weaviate_rejects_missing_source_id() {
    let body = weaviate_body(serde_json::json!([
        {"content": "Refund policy text.", "_additional": {"certainty": 0.8}}
    ]));
    let error = run_search("weaviate", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-weaviate")]
#[tokio::test]
async fn weaviate_rejects_missing_or_unrepresentable_certainty() {
    let body = weaviate_body(serde_json::json!([
        {"content": "Refund policy text.", "_additional": {"id": "doc-1"}}
    ]));
    let error = run_search("weaviate", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));

    // See the Chroma note: an overflowing float literal decodes as null,
    // so the non-finite wire case surfaces as a malformed response.
    let body =
        br#"{"data":{"Get":{"SupportDoc":[{"content":"Refund policy text.","_additional":{"id":"doc-1","certainty":1e309}}]}}}"#
            .to_vec();
    let error = run_search("weaviate", "200 OK", body).await.unwrap_err();
    assert!(matches!(error, VectorStoreError::MalformedResponse(_)));
}

#[cfg(feature = "vector-weaviate")]
#[tokio::test]
async fn weaviate_rejects_out_of_range_certainty() {
    let body = weaviate_body(serde_json::json!([
        {"content": "Refund policy text.", "_additional": {"id": "doc-1", "certainty": 1.5}}
    ]));
    let error = run_search("weaviate", "200 OK", body).await.unwrap_err();
    assert_eq!(
        error,
        VectorStoreError::MalformedResponse("certainty outside the documented 0.0..=1.0 range")
    );
}

#[cfg(feature = "vector-weaviate")]
#[tokio::test]
async fn weaviate_rejects_transport_violations() {
    assert_transport_contract("weaviate").await;
}

#[cfg(feature = "vector-weaviate")]
#[tokio::test]
async fn weaviate_does_not_follow_redirects() {
    assert_redirect_not_followed("weaviate").await;
}

#[cfg(feature = "vector-weaviate")]
#[tokio::test]
async fn weaviate_tenant_stays_a_graphql_variable() {
    let (result, captured) = run_search_capture(
        "weaviate",
        "200 OK",
        weaviate_body(serde_json::json!([weaviate_valid_row()])),
        HOSTILE_TENANT,
        false,
    )
    .await;
    result.unwrap();
    let captured = captured.lock().unwrap();
    let body = captured.as_ref().expect("request was captured").json();
    let query = body["query"].as_str().expect("query is a string");
    // The query text is byte-identical in structure to the fixture, so
    // the tenant value cannot rewrite operands or add filters.
    assert_eq!(
        normalize_whitespace(query),
        normalize_whitespace(WEAVIATE_TENANT_ONLY_QUERY)
    );
    assert!(!query.contains("OR *"));
    assert_eq!(
        body["variables"],
        serde_json::json!({
            "vector": fixture_embedding(),
            "tenant": HOSTILE_TENANT
        })
    );
    assert_eq!(count_string(&body, HOSTILE_TENANT), 1);
}
