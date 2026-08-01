//! Retrieval orchestration: extract, embed, search, select, render.
//!
//! [`RagRuntime`] owns the compiled context template, the provider
//! handles, and the optional stale-context cache. The failure policy
//! applies only around extraction, embedding, search, and rendering;
//! injection failures always propagate because the operator enabled
//! RAG and the canonical body cannot accept its context.
//!
//! A route spells its failure behavior either as a posture
//! (`failure_posture: closed | degraded`) or as the wider `on_failure`
//! block, which is the only way to reach `use_stale`. The runtime never
//! reads either field directly: it takes
//! [`RagRouteConfig::resolved_failure_policy`] once at build time.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use sbproxy_ai::rag_config::{
    FailureMode, RagEmbeddingConfig, RagFailurePolicy, RagFilterConfig, RagQueryConfig,
    RagRetrievalConfig, RagRouteConfig, RagVectorStoreConfig,
};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

use crate::error::{EmbeddingError, RagBuildError, RagError, VectorStoreError};
use crate::query::extract_query;
use crate::template::{inject_context, render_context, select_chunks, ContextTemplate};

/// Produces one embedding vector per input text.
///
/// Implementations are pooled at build time and shared behind an
/// [`Arc`]; they must be safe to call concurrently.
#[async_trait::async_trait]
pub trait Embedder: Send + Sync {
    /// Embed a single text.
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError>;
    /// Embed a batch of texts, one vector per input, in input order.
    async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbeddingError>;
    /// The vector dimension this provider is configured to return, when
    /// known ahead of the first call.
    fn dimensions(&self) -> Option<usize>;
    /// Stable provider identifier used in errors and stats, for
    /// example `openai`.
    fn provider_name(&self) -> &'static str;
}

/// Searches a vector index for the chunks nearest a query embedding.
#[async_trait::async_trait]
pub trait VectorStore: Send + Sync {
    /// Run one similarity search with tenant and static filters
    /// applied server-side where the provider supports it.
    async fn search(&self, query: VectorQuery<'_>)
        -> Result<Vec<RetrievedChunk>, VectorStoreError>;
    /// Stable provider identifier used in errors and stats, for
    /// example `qdrant`.
    fn provider_name(&self) -> &'static str;
}

/// One similarity search request handed to a [`VectorStore`].
#[derive(Debug, Clone, Copy)]
pub struct VectorQuery<'a> {
    /// The validated query embedding.
    pub embedding: &'a [f32],
    /// The tenant the request resolved to; never empty for tenant
    /// scoped routes.
    pub tenant_id: &'a str,
    /// Metadata field name that carries the tenant value in the index.
    pub tenant_field: &'a str,
    /// Additional exact-match metadata filters from the route config.
    pub static_equals: &'a BTreeMap<String, String>,
    /// Maximum number of chunks the store may return.
    pub top_k: usize,
}

/// One retrieved chunk: a source identifier, its text, and the
/// similarity score the store reported.
///
/// `Serialize` exists so the chunk can cross into the minijinja
/// context as plain data; chunk content is never evaluated as a
/// template.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RetrievedChunk {
    /// Identifier of the source document or fragment.
    pub source_id: String,
    /// Chunk text, treated strictly as data.
    pub content: String,
    /// Provider-reported similarity score.
    pub score: f32,
}

/// One retrieval request derived from an in-flight proxy request.
#[derive(Debug, Clone, Copy)]
pub struct RetrievalRequest<'a> {
    /// The canonical JSON request body.
    pub body: &'a serde_json::Value,
    /// The tenant identity the proxy resolved for this request.
    pub tenant_id: &'a str,
}

/// The outcome of one retrieval attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrievalOutcome {
    /// Chunks were retrieved and rendered into context.
    Retrieved,
    /// The pipeline succeeded but zero chunks survived selection. The
    /// result carries no rendered context and injection leaves the
    /// body untouched.
    NoMatch,
    /// A stage failed and the route admitted the request anyway, having
    /// waived the retrieval guarantee it advertises. Reached from
    /// `failure_posture: degraded` or the equivalent
    /// `on_failure: {mode: continue_without_context}`. No context is
    /// injected.
    Continued,
    /// A stage failed and an unexpired stale entry was served instead.
    Stale,
}

/// Byte and latency accounting for one retrieval attempt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetrievalStats {
    /// Number of chunks that survived selection.
    pub chunk_count: usize,
    /// Byte length of the rendered context, or zero when none was
    /// produced.
    pub context_bytes: usize,
    /// Wall-clock milliseconds spent in the embedding call.
    pub embedding_ms: u64,
    /// Wall-clock milliseconds spent in the vector search call.
    pub search_ms: u64,
}

/// The result of [`RagRuntime::retrieve`], later consumed by
/// [`RagRuntime::inject`].
#[derive(Debug, Clone, PartialEq)]
pub struct RetrievalResult {
    /// The selected chunks, in deterministic selection order. Empty
    /// for `NoMatch` and `Continued` outcomes.
    pub chunks: Vec<RetrievedChunk>,
    /// The rendered context. `None` for `NoMatch` and `Continued`
    /// outcomes, in which case injection is a no-op.
    pub rendered_context: Option<String>,
    /// How this result was produced.
    pub outcome: RetrievalOutcome,
    /// Accounting for the attempt that produced this result.
    pub stats: RetrievalStats,
}

/// How [`RagRuntime::build`] treats provider construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RagBuildMode {
    /// Create pooled provider clients ready for traffic. No provider
    /// request is made during construction.
    Runtime,
    /// Validate feature availability, endpoint syntax, provider
    /// fields, and template compilation without dialing anything and
    /// without creating a Redis connection.
    Validation,
}

/// Injectable monotonic time source. Production uses
/// [`Instant::now`]; tests substitute a controllable clock.
#[doc(hidden)]
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Test-only observer invoked after a successful render.
#[doc(hidden)]
pub type RenderProbe = Arc<dyn Fn() + Send + Sync>;

/// A fully constructed retrieval pipeline for one route.
pub struct RagRuntime {
    query_source: RagQueryConfig,
    filters: RagFilterConfig,
    retrieval: RagRetrievalConfig,
    /// The failure behavior this route resolved to, with an explicit
    /// `failure_posture` already desugared. `UseStale` is reachable only
    /// through `on_failure`, so it can still appear here.
    on_failure: RagFailurePolicy,
    /// The same decision in the shared vocabulary, for the two postures
    /// it can express. Coherent with `on_failure` by construction:
    /// `FailClosed` pairs with `Closed`, `ContinueWithoutContext` with
    /// `Degraded`. The `UseStale` arm never reads it.
    failure_posture: FailureMode,
    template: ContextTemplate,
    embedder: Arc<dyn Embedder>,
    vector_store: Arc<dyn VectorStore>,
    stale: Option<StaleCache>,
    clock: Clock,
    render_probe: Option<RenderProbe>,
}

impl RagRuntime {
    /// Build the runtime for `config`.
    ///
    /// Both provider factories are feature-gated; a configured provider
    /// whose cargo feature is off fails with
    /// [`RagBuildError::ProviderNotCompiled`]. See [`RagBuildMode`] for
    /// what each mode constructs.
    pub fn build(config: &RagRouteConfig, mode: RagBuildMode) -> Result<Self, RagBuildError> {
        let template = ContextTemplate::compile(&config.injection.template)?;
        let call_timeout = Duration::from_millis(config.retrieval.timeout_ms);
        let embedder = crate::embedding::build(&config.embedding, call_timeout, mode)?;
        let vector_store = crate::vector::build(&config.vector_store, call_timeout, mode)?;
        Ok(Self::assemble(
            config,
            template,
            embedder,
            vector_store,
            Arc::new(Instant::now),
        ))
    }

    /// Assemble a runtime from pre-built parts, bypassing provider
    /// construction. Test seam; production code must use
    /// [`RagRuntime::build`]. Public only so the integration tests can
    /// inject mock providers and a controllable clock.
    #[doc(hidden)]
    pub fn from_parts(
        config: &RagRouteConfig,
        embedder: Arc<dyn Embedder>,
        vector_store: Arc<dyn VectorStore>,
        clock: Clock,
    ) -> Result<Self, RagBuildError> {
        let template = ContextTemplate::compile(&config.injection.template)?;
        Ok(Self::assemble(
            config,
            template,
            embedder,
            vector_store,
            clock,
        ))
    }

    /// Install a probe that fires after each successful render. Test
    /// seam for asserting stage order; never set in production.
    #[doc(hidden)]
    #[must_use]
    pub fn with_render_probe(mut self, probe: RenderProbe) -> Self {
        self.render_probe = Some(probe);
        self
    }

    fn assemble(
        config: &RagRouteConfig,
        template: ContextTemplate,
        embedder: Arc<dyn Embedder>,
        vector_store: Arc<dyn VectorStore>,
        clock: Clock,
    ) -> Self {
        // One read path for both spellings. `failure_posture` desugars
        // to a policy when set; otherwise `on_failure` is taken as
        // written, which is the only way a route reaches `use_stale`.
        // The stale cache is built for exactly that case, so a route
        // that only declares a posture never allocates one.
        let on_failure = config.resolved_failure_policy();
        let stale = match &on_failure {
            RagFailurePolicy::UseStale {
                max_age_secs,
                max_entries,
            } => Some(StaleCache::new(
                *max_age_secs,
                *max_entries,
                config_fingerprint(config),
            )),
            _ => None,
        };
        Self {
            query_source: config.query.clone(),
            filters: config.filters.clone(),
            retrieval: config.retrieval.clone(),
            on_failure,
            failure_posture: config.failure_posture(),
            template,
            embedder,
            vector_store,
            stale,
            clock,
            render_probe: None,
        }
    }

    /// Run the retrieval pipeline for one request.
    ///
    /// The sequence is extract, embed (bounded by the configured
    /// timeout), validate the embedding, search (same timeout bound),
    /// select, render. Failures in any of those stages pass through
    /// the configured failure policy; see [`RetrievalOutcome`] for the
    /// downgraded shapes. A stale-cache miss returns the original
    /// provider error, never a cache error.
    pub async fn retrieve(
        &self,
        request: RetrievalRequest<'_>,
    ) -> Result<RetrievalResult, RagError> {
        let query = match extract_query(
            &self.query_source,
            request.body,
            self.retrieval.max_query_bytes,
        ) {
            Ok(query) => query,
            Err(error) => {
                // No query means no stale-cache key; UseStale degrades
                // to the original error here.
                return self.apply_failure_policy(request.tenant_id, None, RagError::Query(error));
            }
        };
        match self.attempt(&query, request.tenant_id).await {
            Ok(result) => Ok(result),
            Err(error) => self.apply_failure_policy(request.tenant_id, Some(&query), error),
        }
    }

    /// Inject the rendered context into `body`.
    ///
    /// `NoMatch` and `Continued` results carry no context and leave
    /// the body byte-for-byte unchanged. Injection failures always
    /// propagate; the failure policy never applies to them.
    pub fn inject(
        &self,
        body: &mut serde_json::Value,
        result: &RetrievalResult,
    ) -> Result<(), RagError> {
        match result.rendered_context.as_deref() {
            Some(context) => inject_context(body, context),
            None => Ok(()),
        }
    }

    /// Name of the configured embedding provider.
    pub fn embedding_provider(&self) -> &'static str {
        self.embedder.provider_name()
    }

    /// Name of the configured vector-store provider.
    pub fn vector_store_provider(&self) -> &'static str {
        self.vector_store.provider_name()
    }

    async fn attempt(&self, query: &str, tenant_id: &str) -> Result<RetrievalResult, RagError> {
        let call_timeout = Duration::from_millis(self.retrieval.timeout_ms);

        let embed_started = (self.clock)();
        let embedding = match timeout(call_timeout, self.embedder.embed(query)).await {
            Err(_) => Err(EmbeddingError::Timeout),
            Ok(inner) => inner,
        }
        .map_err(|source| RagError::Embedding {
            provider: self.embedder.provider_name(),
            source,
        })?;
        validate_embedding(&embedding, self.embedder.dimensions()).map_err(|source| {
            RagError::Embedding {
                provider: self.embedder.provider_name(),
                source,
            }
        })?;
        let embedding_ms = duration_ms(embed_started, (self.clock)());

        let search_started = (self.clock)();
        let vector_query = VectorQuery {
            embedding: &embedding,
            tenant_id,
            tenant_field: &self.filters.tenant_field,
            static_equals: &self.filters.static_equals,
            top_k: self.retrieval.top_k,
        };
        let chunks = match timeout(call_timeout, self.vector_store.search(vector_query)).await {
            Err(_) => Err(VectorStoreError::Timeout),
            Ok(inner) => inner,
        }
        .map_err(|source| RagError::VectorStore {
            provider: self.vector_store.provider_name(),
            source,
        })?;
        let search_ms = duration_ms(search_started, (self.clock)());

        let selected = select_chunks(
            chunks,
            self.retrieval.min_score,
            self.retrieval.top_k,
            self.retrieval.max_chunk_bytes,
            self.retrieval.max_context_bytes,
        );
        if selected.is_empty() {
            return Ok(RetrievalResult {
                chunks: Vec::new(),
                rendered_context: None,
                outcome: RetrievalOutcome::NoMatch,
                stats: RetrievalStats {
                    chunk_count: 0,
                    context_bytes: 0,
                    embedding_ms,
                    search_ms,
                },
            });
        }

        let rendered = render_context(
            &self.template,
            query,
            &selected,
            self.retrieval.max_context_bytes,
        )?;
        if let Some(probe) = &self.render_probe {
            probe();
        }
        if let Some(stale) = &self.stale {
            stale.store(tenant_id, query, &selected, &rendered, (self.clock)());
        }
        Ok(RetrievalResult {
            stats: RetrievalStats {
                chunk_count: selected.len(),
                context_bytes: rendered.len(),
                embedding_ms,
                search_ms,
            },
            chunks: selected,
            rendered_context: Some(rendered),
            outcome: RetrievalOutcome::Retrieved,
        })
    }

    fn apply_failure_policy(
        &self,
        tenant_id: &str,
        query: Option<&str>,
        error: RagError,
    ) -> Result<RetrievalResult, RagError> {
        // `use_stale` keeps its own arm because it is the one posture
        // the shared four-word vocabulary cannot say: admit with an
        // older guarantee, and refuse when even that is missing. It also
        // owns a cache, which no posture word can carry.
        if matches!(self.on_failure, RagFailurePolicy::UseStale { .. }) {
            let (Some(stale), Some(query)) = (self.stale.as_ref(), query) else {
                return Err(error);
            };
            return match stale.lookup(tenant_id, query, (self.clock)()) {
                Some(entry) => Ok(RetrievalResult {
                    stats: RetrievalStats {
                        chunk_count: entry.chunks.len(),
                        context_bytes: entry.rendered_context.len(),
                        embedding_ms: 0,
                        search_ms: 0,
                    },
                    chunks: entry.chunks,
                    rendered_context: Some(entry.rendered_context),
                    outcome: RetrievalOutcome::Stale,
                }),
                // A miss or an expired entry serves the original
                // provider error, never a cache error.
                None => Err(error),
            };
        }

        // Everything else is a plain posture, read through the shared
        // vocabulary. `Closed` refuses. `Degraded` forwards the original
        // request, which admits it without the retrieval this route
        // advertises, and `RetrievalOutcome::Continued` is what records
        // that the guarantee was waived.
        if self.failure_posture.admits() {
            Ok(RetrievalResult {
                chunks: Vec::new(),
                rendered_context: None,
                outcome: RetrievalOutcome::Continued,
                stats: RetrievalStats::default(),
            })
        } else {
            Err(error)
        }
    }
}

/// Reject an embedding whose length contradicts the provider's
/// declared dimension or that carries a non-finite value.
fn validate_embedding(embedding: &[f32], declared: Option<usize>) -> Result<(), EmbeddingError> {
    if embedding.is_empty() {
        return Err(EmbeddingError::MalformedResponse("empty embedding vector"));
    }
    if let Some(expected) = declared {
        if embedding.len() != expected {
            return Err(EmbeddingError::DimensionMismatch {
                expected,
                actual: embedding.len(),
            });
        }
    }
    if embedding.iter().any(|value| !value.is_finite()) {
        return Err(EmbeddingError::NonFinite);
    }
    Ok(())
}

fn duration_ms(start: Instant, end: Instant) -> u64 {
    u64::try_from(end.saturating_duration_since(start).as_millis()).unwrap_or(u64::MAX)
}

/// A stale entry retained for the `use_stale` failure policy: only the
/// already selected chunks, the rendered context, and the insertion
/// time. The raw key input is never stored.
#[derive(Clone)]
struct StaleEntry {
    chunks: Vec<RetrievedChunk>,
    rendered_context: String,
    inserted_at: Instant,
}

/// Bounded stale-context cache keyed by a salted digest.
///
/// The key is SHA-256 over the per-runtime random salt, then
/// `tenant_id || 0x00 || query || 0x00 || config_fingerprint`, so
/// entries never cross tenants, queries, config revisions, or runtime
/// instances, and a stored key reveals nothing about its inputs.
struct StaleCache {
    salt: [u8; 32],
    fingerprint: String,
    max_age: Duration,
    entries: parking_lot::Mutex<LruCache<[u8; 32], StaleEntry>>,
}

impl StaleCache {
    fn new(max_age_secs: u64, max_entries: usize, fingerprint: String) -> Self {
        // Config validation keeps max_entries >= 1; the clamp only
        // guards a hand-built config from panicking the constructor.
        let capacity = NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::MIN);
        Self {
            salt: sbproxy_security::random_aes256_key(),
            fingerprint,
            max_age: Duration::from_secs(max_age_secs),
            entries: parking_lot::Mutex::new(LruCache::new(capacity)),
        }
    }

    fn key(&self, tenant_id: &str, query: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.salt);
        hasher.update(tenant_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(query.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.fingerprint.as_bytes());
        hasher.finalize().into()
    }

    fn store(
        &self,
        tenant_id: &str,
        query: &str,
        chunks: &[RetrievedChunk],
        rendered_context: &str,
        now: Instant,
    ) {
        let key = self.key(tenant_id, query);
        self.entries.lock().put(
            key,
            StaleEntry {
                chunks: chunks.to_vec(),
                rendered_context: rendered_context.to_owned(),
                inserted_at: now,
            },
        );
    }

    fn lookup(&self, tenant_id: &str, query: &str, now: Instant) -> Option<StaleEntry> {
        let key = self.key(tenant_id, query);
        let mut entries = self.entries.lock();
        let entry = entries.get(&key)?;
        if now.saturating_duration_since(entry.inserted_at) > self.max_age {
            let _ = entries.pop(&key);
            return None;
        }
        Some(entry.clone())
    }
}

/// Derive a stable fingerprint for the retrieval-relevant parts of a
/// route configuration.
///
/// Covers the query source, every retrieval bound (`top_k`,
/// `min_score`, byte caps, timeout), the filter identity, a SHA-256 of
/// the template source, and provider identity fields (provider tag,
/// endpoint, region or project, model, collection or index, dimension
/// overrides). Credentials are deliberately excluded: rotating an API
/// key must not invalidate stale entries, and the fingerprint must
/// never carry secret material. The fingerprint participates in the
/// stale-cache key so entries never survive a config change that could
/// alter retrieval results.
fn config_fingerprint(config: &RagRouteConfig) -> String {
    let query_source = match &config.query {
        RagQueryConfig::LastUserMessage => "last_user_message".to_owned(),
        RagQueryConfig::JsonPointer { pointer } => format!("json_pointer:{pointer}"),
    };
    let static_filters = config
        .filters
        .static_equals
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    let template_sha256 = hex_digest(config.injection.template.as_bytes());
    let embedding = match &config.embedding {
        RagEmbeddingConfig::Openai {
            base_url,
            model,
            dimensions,
            ..
        } => format!("openai|{base_url}|{model}|{dimensions:?}"),
        RagEmbeddingConfig::Compatible {
            base_url,
            model,
            dimensions,
            ..
        } => format!("compatible|{base_url}|{model}|{dimensions:?}"),
        RagEmbeddingConfig::Cohere {
            base_url,
            model,
            output_dimension,
            ..
        } => format!("cohere|{base_url}|{model}|{output_dimension:?}"),
        RagEmbeddingConfig::Bedrock {
            region,
            model,
            dimensions,
            endpoint_override,
            ..
        } => format!("bedrock|{region}|{model}|{dimensions}|{endpoint_override:?}"),
        RagEmbeddingConfig::Vertex {
            project_id,
            location,
            model,
            output_dimensionality,
            endpoint_override,
            ..
        } => format!(
            "vertex|{project_id}|{location}|{model}|{output_dimensionality:?}|{endpoint_override:?}"
        ),
    };
    let vector_store = match &config.vector_store {
        RagVectorStoreConfig::Chroma {
            base_url,
            database_tenant,
            database,
            collection_id,
            ..
        } => format!("chroma|{base_url}|{database_tenant}|{database}|{collection_id}"),
        RagVectorStoreConfig::Pinecone {
            host,
            namespace,
            content_field,
            ..
        } => format!("pinecone|{host}|{namespace:?}|{content_field}"),
        RagVectorStoreConfig::Qdrant {
            base_url,
            collection,
            content_field,
            ..
        } => format!("qdrant|{base_url}|{collection}|{content_field}"),
        RagVectorStoreConfig::Redis {
            url,
            index,
            vector_field,
            content_field,
            ..
        } => format!("redis|{url}|{index}|{vector_field}|{content_field}"),
        RagVectorStoreConfig::Weaviate {
            base_url,
            collection,
            content_field,
            ..
        } => format!("weaviate|{base_url}|{collection}|{content_field}"),
    };
    format!(
        "v1|query={query_source}|top_k={}|min_score={}|max_query_bytes={}|max_chunk_bytes={}|max_context_bytes={}|timeout_ms={}|tenant_field={}|static={static_filters}|template_sha256={template_sha256}|embedding={embedding}|vector={vector_store}",
        config.retrieval.top_k,
        config.retrieval.min_score,
        config.retrieval.max_query_bytes,
        config.retrieval.max_chunk_bytes,
        config.retrieval.max_context_bytes,
        config.retrieval.timeout_ms,
        config.filters.tenant_field,
    )
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_embedding_checks_dimension_and_finiteness() {
        assert_eq!(validate_embedding(&[0.1, 0.2], Some(2)), Ok(()));
        assert_eq!(validate_embedding(&[0.1, 0.2], None), Ok(()));
        assert_eq!(
            validate_embedding(&[0.1, 0.2], Some(3)),
            Err(EmbeddingError::DimensionMismatch {
                expected: 3,
                actual: 2,
            })
        );
        assert_eq!(
            validate_embedding(&[0.1, f32::NAN], Some(2)),
            Err(EmbeddingError::NonFinite)
        );
        assert_eq!(
            validate_embedding(&[], None),
            Err(EmbeddingError::MalformedResponse("empty embedding vector"))
        );
    }

    #[test]
    fn config_fingerprint_excludes_credentials() {
        let config: RagRouteConfig = serde_json::from_value(serde_json::json!({
            "embedding": {
                "provider": "compatible",
                "base_url": "http://127.0.0.1:8090/v1",
                "model": "fixture-embedding",
                "api_key": "embedding-credential",
                "dimensions": 3,
                "allow_private_url": true
            },
            "vector_store": {
                "provider": "qdrant",
                "base_url": "http://127.0.0.1:6333",
                "collection": "support_docs",
                "api_key": "vector-credential",
                "allow_private_url": true
            }
        }))
        .unwrap();
        let fingerprint = config_fingerprint(&config);
        assert!(
            !fingerprint.contains("embedding-credential"),
            "{fingerprint}"
        );
        assert!(!fingerprint.contains("vector-credential"), "{fingerprint}");
        assert!(fingerprint.contains("compatible|http://127.0.0.1:8090/v1"));
        assert!(fingerprint.contains("qdrant|http://127.0.0.1:6333"));
    }
}
