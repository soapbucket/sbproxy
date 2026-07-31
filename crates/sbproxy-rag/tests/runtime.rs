//! Orchestration tests for `RagRuntime` with injected mock providers.
//!
//! These tests exercise call order, the vector-query contract, the
//! three failure policies, and the bounded stale-context cache with a
//! controllable clock. Providers are mocks defined in this file; no
//! network or feature-gated adapter is involved.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sbproxy_ai::rag_config::RagRouteConfig;
use sbproxy_rag::runtime::Clock;
use sbproxy_rag::{
    Embedder, EmbeddingError, RagError, RagRuntime, RetrievalOutcome, RetrievalRequest,
    RetrievedChunk, VectorQuery, VectorStore, VectorStoreError,
};
use serde_json::json;

type Events = Arc<Mutex<Vec<String>>>;

struct MockEmbedder {
    events: Events,
    declared: Option<usize>,
    produced: usize,
}

#[async_trait::async_trait]
impl Embedder for MockEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.events.lock().unwrap().push(format!("embed:{text}"));
        Ok(vec![0.25; self.produced])
    }

    async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        let mut vectors = Vec::with_capacity(texts.len());
        for text in texts {
            vectors.push(self.embed(text).await?);
        }
        Ok(vectors)
    }

    fn dimensions(&self) -> Option<usize> {
        self.declared
    }

    fn provider_name(&self) -> &'static str {
        "mock-embedding"
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CapturedQuery {
    embedding: Vec<f32>,
    tenant_id: String,
    tenant_field: String,
    static_equals: BTreeMap<String, String>,
    top_k: usize,
}

struct MockVectorStore {
    events: Events,
    failing: AtomicBool,
    captured: Mutex<Option<CapturedQuery>>,
    chunks: Vec<RetrievedChunk>,
}

impl MockVectorStore {
    fn new(events: Events, chunks: Vec<RetrievedChunk>) -> Self {
        Self {
            events,
            failing: AtomicBool::new(false),
            captured: Mutex::new(None),
            chunks,
        }
    }

    fn fail(&self) {
        self.failing.store(true, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl VectorStore for MockVectorStore {
    async fn search(
        &self,
        query: VectorQuery<'_>,
    ) -> Result<Vec<RetrievedChunk>, VectorStoreError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("search:{}", query.tenant_id));
        *self.captured.lock().unwrap() = Some(CapturedQuery {
            embedding: query.embedding.to_vec(),
            tenant_id: query.tenant_id.to_owned(),
            tenant_field: query.tenant_field.to_owned(),
            static_equals: query.static_equals.clone(),
            top_k: query.top_k,
        });
        if self.failing.load(Ordering::SeqCst) {
            return Err(VectorStoreError::HttpStatus(503));
        }
        Ok(self.chunks.clone())
    }

    fn provider_name(&self) -> &'static str {
        "mock-vector"
    }
}

#[derive(Clone)]
struct TestClock {
    now: Arc<Mutex<Instant>>,
}

impl TestClock {
    fn new() -> Self {
        Self {
            now: Arc::new(Mutex::new(Instant::now())),
        }
    }

    fn advance(&self, duration: Duration) {
        *self.now.lock().unwrap() += duration;
    }

    fn clock(&self) -> Clock {
        let now = Arc::clone(&self.now);
        Arc::new(move || *now.lock().unwrap())
    }
}

fn rag_config(on_failure: serde_json::Value) -> RagRouteConfig {
    serde_json::from_value(json!({
        "embedding": {
            "provider": "compatible",
            "base_url": "http://127.0.0.1:8090/v1",
            "model": "fixture-embedding",
            "dimensions": 3,
            "allow_private_url": true
        },
        "vector_store": {
            "provider": "qdrant",
            "base_url": "http://127.0.0.1:6333",
            "collection": "support_docs",
            "allow_private_url": true
        },
        "filters": {"static_equals": {"lang": "en"}},
        "on_failure": on_failure
    }))
    .unwrap()
}

fn use_stale(max_age_secs: u64, max_entries: usize) -> serde_json::Value {
    json!({
        "mode": "use_stale",
        "max_age_secs": max_age_secs,
        "max_entries": max_entries
    })
}

fn default_chunks() -> Vec<RetrievedChunk> {
    vec![RetrievedChunk {
        source_id: "doc-1".to_owned(),
        content: "Refunds settle in five business days.".to_owned(),
        score: 0.92,
    }]
}

fn chat_body(text: &str) -> serde_json::Value {
    json!({"messages":[{"role":"user","content":text}]})
}

fn request(body: &serde_json::Value) -> RetrievalRequest<'_> {
    RetrievalRequest {
        body,
        tenant_id: "tenant-a",
    }
}

fn vector_failure() -> RagError {
    RagError::VectorStore {
        provider: "mock-vector",
        source: VectorStoreError::HttpStatus(503),
    }
}

struct Fixture {
    runtime: RagRuntime,
    events: Events,
    vector: Arc<MockVectorStore>,
    clock: TestClock,
}

fn fixture(on_failure: serde_json::Value) -> Fixture {
    fixture_with(on_failure, Some(3), 3, default_chunks())
}

fn fixture_with(
    on_failure: serde_json::Value,
    declared: Option<usize>,
    produced: usize,
    chunks: Vec<RetrievedChunk>,
) -> Fixture {
    let events: Events = Arc::new(Mutex::new(Vec::new()));
    let clock = TestClock::new();
    let embedder = Arc::new(MockEmbedder {
        events: Arc::clone(&events),
        declared,
        produced,
    });
    let vector = Arc::new(MockVectorStore::new(Arc::clone(&events), chunks));
    let runtime = RagRuntime::from_parts(
        &rag_config(on_failure),
        embedder,
        Arc::clone(&vector) as Arc<dyn VectorStore>,
        clock.clock(),
    )
    .unwrap();
    Fixture {
        runtime,
        events,
        vector,
        clock,
    }
}

#[tokio::test]
async fn retrieval_runs_embed_search_render_in_order() {
    let Fixture {
        runtime, events, ..
    } = fixture(json!({"mode": "fail_closed"}));
    let probe_events = Arc::clone(&events);
    let runtime = runtime.with_render_probe(Arc::new(move || {
        probe_events.lock().unwrap().push("render".to_owned());
    }));

    let result = runtime
        .retrieve(RetrievalRequest {
            body: &chat_body("refund policy"),
            tenant_id: "tenant-a",
        })
        .await
        .unwrap();

    assert_eq!(
        events.lock().unwrap().as_slice(),
        ["embed:refund policy", "search:tenant-a", "render"]
    );
    assert_eq!(result.outcome, RetrievalOutcome::Retrieved);
    assert_eq!(result.stats.chunk_count, 1);
    let rendered = result.rendered_context.clone().unwrap();
    assert_eq!(result.stats.context_bytes, rendered.len());
    assert!(rendered.contains("Refunds settle in five business days."));

    let mut body = chat_body("refund policy");
    runtime.inject(&mut body, &result).unwrap();
    assert_eq!(body["messages"][0]["role"], "system");
    assert_eq!(body["messages"][0]["content"], json!(rendered));
    assert_eq!(body["messages"][1]["role"], "user");
}

#[tokio::test]
async fn vector_query_carries_tenant_filters_top_k_and_embedding() {
    let Fixture {
        runtime, vector, ..
    } = fixture(json!({"mode": "fail_closed"}));
    let body = chat_body("refund policy");
    runtime.retrieve(request(&body)).await.unwrap();

    let captured = vector.captured.lock().unwrap().clone().unwrap();
    assert_eq!(captured.embedding, vec![0.25_f32; 3]);
    assert_eq!(captured.tenant_id, "tenant-a");
    assert_eq!(captured.tenant_field, "tenant_id");
    assert_eq!(
        captured.static_equals,
        BTreeMap::from([("lang".to_owned(), "en".to_owned())])
    );
    assert_eq!(captured.top_k, 5);
}

#[tokio::test]
async fn declared_dimension_mismatch_fails_before_search() {
    let Fixture {
        runtime, events, ..
    } = fixture_with(json!({"mode": "fail_closed"}), Some(3), 4, default_chunks());
    let body = chat_body("refund policy");

    let error = runtime.retrieve(request(&body)).await.unwrap_err();
    assert_eq!(
        error,
        RagError::Embedding {
            provider: "mock-embedding",
            source: EmbeddingError::DimensionMismatch {
                expected: 3,
                actual: 4,
            },
        }
    );
    // The vector store is never called after a dimension mismatch.
    assert_eq!(events.lock().unwrap().as_slice(), ["embed:refund policy"]);
}

#[tokio::test]
async fn failure_policy_controls_the_failure_shape() {
    let body = chat_body("refund policy");

    let fail_closed = fixture(json!({"mode": "fail_closed"}));
    fail_closed.vector.fail();
    assert!(fail_closed.runtime.retrieve(request(&body)).await.is_err());

    let continue_fixture = fixture(json!({"mode": "continue_without_context"}));
    continue_fixture.vector.fail();
    let continued = continue_fixture
        .runtime
        .retrieve(request(&body))
        .await
        .unwrap();
    assert_eq!(continued.outcome, RetrievalOutcome::Continued);
    assert!(continued.rendered_context.is_none());
    assert!(continued.chunks.is_empty());

    let stale_fixture = fixture(use_stale(300, 8));
    let first = stale_fixture
        .runtime
        .retrieve(request(&body))
        .await
        .unwrap();
    assert_eq!(first.outcome, RetrievalOutcome::Retrieved);
    stale_fixture.clock.advance(Duration::from_secs(10));
    stale_fixture.vector.fail();
    let stale = stale_fixture
        .runtime
        .retrieve(request(&body))
        .await
        .unwrap();
    assert_eq!(stale.outcome, RetrievalOutcome::Stale);
    assert_eq!(stale.rendered_context, first.rendered_context);
    assert_eq!(stale.chunks, first.chunks);
}

#[tokio::test]
async fn continued_and_no_match_leave_the_body_untouched() {
    let no_match = fixture_with(json!({"mode": "fail_closed"}), Some(3), 3, Vec::new());
    let mut body = chat_body("refund policy");
    let before = body.clone();
    let result = no_match.runtime.retrieve(request(&body)).await.unwrap();
    assert_eq!(result.outcome, RetrievalOutcome::NoMatch);
    assert!(result.rendered_context.is_none());
    no_match.runtime.inject(&mut body, &result).unwrap();
    assert_eq!(body, before);

    let continue_fixture = fixture(json!({"mode": "continue_without_context"}));
    continue_fixture.vector.fail();
    let continued = continue_fixture
        .runtime
        .retrieve(request(&body))
        .await
        .unwrap();
    continue_fixture
        .runtime
        .inject(&mut body, &continued)
        .unwrap();
    assert_eq!(body, before);
}

#[tokio::test]
async fn stale_entries_never_cross_tenants() {
    let Fixture {
        runtime, vector, ..
    } = fixture(use_stale(300, 8));
    let body = chat_body("refund policy");
    runtime
        .retrieve(RetrievalRequest {
            body: &body,
            tenant_id: "tenant-a",
        })
        .await
        .unwrap();

    vector.fail();
    let error = runtime
        .retrieve(RetrievalRequest {
            body: &body,
            tenant_id: "tenant-b",
        })
        .await
        .unwrap_err();
    assert_eq!(error, vector_failure());

    let stale = runtime
        .retrieve(RetrievalRequest {
            body: &body,
            tenant_id: "tenant-a",
        })
        .await
        .unwrap();
    assert_eq!(stale.outcome, RetrievalOutcome::Stale);
}

#[tokio::test]
async fn stale_entries_never_cross_queries() {
    let Fixture {
        runtime, vector, ..
    } = fixture(use_stale(300, 8));
    let primed = chat_body("refund policy");
    runtime.retrieve(request(&primed)).await.unwrap();

    vector.fail();
    let other = chat_body("shipping policy");
    let error = runtime.retrieve(request(&other)).await.unwrap_err();
    assert_eq!(error, vector_failure());

    let stale = runtime.retrieve(request(&primed)).await.unwrap();
    assert_eq!(stale.outcome, RetrievalOutcome::Stale);
}

#[tokio::test]
async fn stale_entries_never_cross_runtime_instances() {
    let primed = fixture(use_stale(300, 8));
    let body = chat_body("refund policy");
    primed.runtime.retrieve(request(&body)).await.unwrap();

    // A second instance of the same route never sees the first
    // instance's cache, even for the identical tenant and query.
    let other = fixture(use_stale(300, 8));
    other.vector.fail();
    let error = other.runtime.retrieve(request(&body)).await.unwrap_err();
    assert_eq!(error, vector_failure());

    primed.vector.fail();
    let stale = primed.runtime.retrieve(request(&body)).await.unwrap();
    assert_eq!(stale.outcome, RetrievalOutcome::Stale);
}

#[tokio::test]
async fn stale_eviction_respects_max_entries() {
    let Fixture {
        runtime, vector, ..
    } = fixture(use_stale(300, 1));
    let first = chat_body("refund policy");
    let second = chat_body("shipping policy");
    runtime.retrieve(request(&first)).await.unwrap();
    // Priming a second query evicts the first from the one-entry cache.
    runtime.retrieve(request(&second)).await.unwrap();

    vector.fail();
    let error = runtime.retrieve(request(&first)).await.unwrap_err();
    assert_eq!(error, vector_failure());
    let stale = runtime.retrieve(request(&second)).await.unwrap();
    assert_eq!(stale.outcome, RetrievalOutcome::Stale);
}

#[tokio::test]
async fn stale_expiry_respects_max_age_secs() {
    let Fixture {
        runtime,
        vector,
        clock,
        ..
    } = fixture(use_stale(60, 8));
    let body = chat_body("refund policy");
    runtime.retrieve(request(&body)).await.unwrap();

    clock.advance(Duration::from_secs(59));
    vector.fail();
    let stale = runtime.retrieve(request(&body)).await.unwrap();
    assert_eq!(stale.outcome, RetrievalOutcome::Stale);

    clock.advance(Duration::from_secs(2));
    let error = runtime.retrieve(request(&body)).await.unwrap_err();
    assert_eq!(error, vector_failure());
}

#[tokio::test]
async fn stale_miss_returns_the_original_provider_error() {
    let Fixture {
        runtime, vector, ..
    } = fixture(use_stale(300, 8));
    vector.fail();
    let body = chat_body("refund policy");
    let error = runtime.retrieve(request(&body)).await.unwrap_err();
    assert_eq!(error, vector_failure());
}
